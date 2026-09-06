//! Finding a device again after a reset has taken its handle away.
//!
//! `nusb` is explicit that a reset ends the handle's life — "This `Device` will no
//! longer be usable, and you should drop it and call `list_devices` to find and re-open
//! it" (`nusb-0.2.7/src/device.rs:287-290`) — and equally explicit that it will not do
//! the finding for you. This module is that step, and it has one job beyond calling
//! `open()`: **decide which device on the bus is the same device**.
//!
//! # Why not "the first Ingenic device"
//!
//! Because that is how you flash the wrong camera. The shipped C picks its reset target
//! by Ingenic VID and a positional index into the device list
//! (`libtdfu/src/dfu/dfu.c:383-390`) and, when it re-opens, falls back to "first VID:PID
//! match if address changed" (`libtdfu/src/usb/device.c:268-274`). With two bootroms on
//! one bus — a shared bench is exactly that — that silently
//! adopts the other one. We match on the **physical port** instead, which is what a
//! port path is kept for: a device that re-enumerates comes back on the port it
//! was already plugged into, and nothing else can.
//!
//! # One rule, on every platform
//!
//! Re-scan the bus and adopt the device at the port that was reset. There is no
//! shortcut past the scan, on any platform, because the stored identity names a node
//! and a node carries no port: opening it answers "something is here", which is not the
//! question. The platforms differ only in what a reset does to that identity, and none
//! of those differences buys back the port.
//!
//! * **Linux** keeps the identity valid. `Device::reset` is one `USBDEVFS_RESET` ioctl
//!   on the open fd (`linux_usbfs/device.rs:369-377` → `usbfs.rs:174-179`); the kernel
//!   re-enumerates the device in place, usually keeping its device number, and
//!   `from_device_info` opens `/dev/bus/usb/{busnum:03}/{devnum:03}`
//!   (`linux_usbfs/device.rs:83-110`), usually the same node as before. Usually is not
//!   always, and the exception is this module's whole subject: a device number is kernel
//!   bookkeeping, not a serial, so if the reset device does not come back its number is
//!   free for the next device to enumerate. That is at its most likely in exactly the
//!   moments after a reset. So the node is scanned for, not opened on faith; the scan
//!   costs one bus enumeration and settles which device it is.
//! * **macOS** does not keep it valid. `Device::reset` is `USBDeviceReEnumerate(0)`
//!   (`macos_iokit/iokit_usb.rs:133-135`), which terminates the `IOKit` service the handle
//!   was built on, and `from_device_info` finds a device by **registry id**
//!   (`macos_iokit/device.rs:61-68` → `enumeration.rs:111-115`, `service_by_registry_id`)
//!   and which the re-enumerated device does not have any more. The scan works anyway
//!   because the key we match on survives: macOS derives both `bus_id` and `port_chain`
//!   from `locationID` (`macos_iokit/enumeration.rs:121-129`), which is physical
//!   topology and does not change when a device re-enumerates.
//! * **Windows** never gets here with a re-enumeration to chase. `nusb`'s WinUSB backend
//!   answers `Unsupported` to `reset` — "reset not supported by WinUSB"
//!   (`windows_winusb/device.rs:170-175`) — and WinUSB exposes no host-initiated port
//!   reset for it to call, which libusb states in its own comment while cycling pipes
//!   instead (`libusb/os/windows_winusb.c:4297-4343`). `transport.rs` documents the
//!   host-side recycle that stands in for it. Nothing moved, so the first scan finds the
//!   device where it always was.

use core::time::Duration;
use std::time::Instant;

use nusb::{DeviceInfo, MaybeFuture as _};

use super::error::device_error;
use crate::{Pipe, UsbError, UsbErrorKind};

/// How long a re-open may spend waiting for a reset device to come back.
///
/// The *bound* is the requirement — this module is under the same rule as the transfers
/// (`transport.rs`: every wait is bounded by construction) — and the number is chosen to
/// sit just above the two waits already in the tree that measure the same thing: the C
/// sleeps 1500 ms after a reset to "let the gadget re-enumerate"
/// (`libtdfu/src/dfu/dfu.c:402`), and `tdfu_core::dfu::host::POST_RESET_SETTLE` waits the
/// same 1500 ms after `reset()` returns. A device that has not re-appeared by 2000 ms
/// has not re-appeared.
const REOPEN_WINDOW: Duration = Duration::from_secs(2);

/// How often the bus is re-scanned inside [`REOPEN_WINDOW`].
///
/// A blocking sleep, deliberately, like everything else on this backend's control plane
/// (see the `transport` module docs): it is bounded, it is on the one thread that drives
/// this device, and a re-enumeration takes tens of milliseconds, so a
/// finer poll would only spin.
const REOPEN_POLL: Duration = Duration::from_millis(50);

/// Where a device is plugged in, and what it says it is.
///
/// The whole matching rule in one comparable value, so that the rule itself is a unit
/// test rather than something only a bench run could check. `nusb::DeviceInfo` has no
/// public constructor, so a test cannot build one — it can build this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Location {
    /// The bus the device is on. A port chain is only unique within one.
    bus: String,
    /// The physical port path: stable across the re-enumeration a reset
    /// causes, which is the entire reason it is the key.
    port_chain: Vec<u8>,
    /// The vendor id the device presents. Not identity on its own — every Ingenic
    /// bootrom shares it — but a device that comes back at the same port with a
    /// different one is not the device we reset.
    vendor_id: u16,
    /// The product id, with the same caveat and the same use.
    product_id: u16,
}

impl Location {
    /// Where this device is.
    pub(super) fn of(info: &DeviceInfo) -> Self {
        Self {
            bus: info.bus_id().to_owned(),
            port_chain: info.port_chain().to_vec(),
            vendor_id: info.vendor_id(),
            product_id: info.product_id(),
        }
    }

    /// Can this location name exactly one device?
    ///
    /// An empty port chain cannot: it is what a platform reports when it does not know
    /// the topology, and "somewhere on bus 1" matches every Ingenic device on that bus.
    /// That is why this is a refusal and not a guess.
    fn is_addressable(&self) -> bool {
        !self.port_chain.is_empty()
    }

    /// Is `candidate` the device this location came from?
    pub(super) fn matches(&self, candidate: &Self) -> bool {
        self.is_addressable() && self == candidate
    }
}

/// The device in one bus scan that may be adopted as the one that was reset.
///
/// The whole adoption rule, in one place: the entry on the bus that was reset, at the
/// port that was reset, presenting the ids that were reset. Nothing else, however it
/// answers. Every Ingenic bootrom and every U-Boot DFU gadget presents the same
/// `a108:c309`, so a vendor and product comparison cannot tell two cameras apart; only
/// the port can, and adopting on the ids alone is a flash write to whichever camera
/// happened to answer.
///
/// Split out from the scan so the rule is an ordinary assertion over hand-built
/// [`Location`]s: `nusb::DeviceInfo` has no public constructor, so a rule expressed
/// inline in the scan is a rule only a bench with two cameras on one bus could check.
fn adopt<T>(want: &Location, mut candidates: impl Iterator<Item = (Location, T)>) -> Option<T> {
    candidates.find_map(|(here, device)| want.matches(&here).then_some(device))
}

/// Re-open the device `identity` describes, waiting up to [`REOPEN_WINDOW`] for it.
///
/// `identity` is updated to whatever the device turned out to be, so the *next* re-open
/// starts from where it actually is. The C does the same thing for the same reason
/// (`libtdfu/src/usb/device.c:292-293`).
///
/// # Errors
/// [`UsbErrorKind::Backend`] naming the port it waited at and the last failure it saw,
/// when the device does not come back inside the window. That prose is the point: a bare
/// "no device" sends an operator to look for a cable, when what happened is that a device
/// they can see did not re-enumerate.
pub(super) fn reopen(identity: &mut DeviceInfo) -> Result<nusb::Device, UsbError> {
    let want = Location::of(identity);

    searchable(&want)?;

    // The last thing that went wrong, kept so the window's failure can name a cause
    // rather than only a deadline.
    let mut last: Option<UsbError> = None;
    let started = Instant::now();
    let found = within(
        REOPEN_WINDOW,
        || started.elapsed(),
        || std::thread::sleep(REOPEN_POLL),
        || {
            let devices = nusb::list_devices()
                .wait()
                .inspect_err(|error| last = Some(device_error(error)))
                .ok()?;
            let found = adopt(&want, devices.map(|info| (Location::of(&info), info)))?;
            // Seen but not yet openable: on macOS a service can be in the registry a
            // moment before it will accept an open. Inside the window that is "not
            // yet", not "no".
            let device = found
                .open()
                .wait()
                .inspect_err(|error| last = Some(device_error(error)))
                .ok()?;
            Some((device, found))
        },
    );

    match found {
        Some((device, found)) => {
            *identity = found;
            Ok(device)
        }
        None => Err(never_came_back(&want, last.as_ref())),
    }
}

/// Retry `attempt` until it answers or `window` has passed, resting in between.
///
/// The clock and the sleep are closures so the *policy* can be tested without a device:
/// with the real bus behind `attempt` there is no way to pin that the deadline is
/// checked in the right direction, or that an attempt always precedes it, and both are
/// bugs that would only show up as a reset that never recovers. No knob, no proof.
///
/// The order matters and is pinned: **attempt, then check, then rest.** Checking first
/// would skip the one attempt that might succeed immediately — which on Linux is the
/// normal case, because `USBDEVFS_RESET` returns with the device already back.
fn within<T>(
    window: Duration,
    mut elapsed: impl FnMut() -> Duration,
    mut rest: impl FnMut(),
    mut attempt: impl FnMut() -> Option<T>,
) -> Option<T> {
    loop {
        if let Some(value) = attempt() {
            return Some(value);
        }
        if elapsed() >= window {
            return None;
        }
        rest();
    }
}

/// Refuse a search that could only guess.
///
/// # Errors
/// [`UsbErrorKind::Backend`] when the location names no port. Split out from
/// [`reopen`] so the refusal is reachable from a test: it is the guard that keeps a
/// guess out of the recovery path, and a guard nothing can exercise is a guard nobody
/// knows is inverted.
fn searchable(want: &Location) -> Result<(), UsbError> {
    if want.is_addressable() {
        return Ok(());
    }
    Err(nowhere_to_look())
}

/// The device was reset and never re-appeared where it was plugged in.
fn never_came_back(want: &Location, last: Option<&UsbError>) -> UsbError {
    UsbError::new(
        UsbErrorKind::Backend(format!(
            "the device was reset and did not come back on bus {} at port {:?} within {} ms ({})",
            want.bus,
            want.port_chain,
            REOPEN_WINDOW.as_millis(),
            reason(last)
        )),
        Pipe::Device,
    )
}

/// The device was reset and there is no port path to look for it by.
///
/// Not reachable through `NativeBackend` — Linux, macOS and Windows all report a port
/// chain for a device that is plugged into a port — but it is the honest answer rather
/// than a scan that would have to guess, and it fails in microseconds
/// instead of after the whole window.
fn nowhere_to_look() -> UsbError {
    UsbError::new(
        UsbErrorKind::Backend(
            "the device was reset and cannot be found again: enumeration reports no port path for it, \
             and matching on the Ingenic vendor id alone would risk adopting a different device"
                .to_owned(),
        ),
        Pipe::Device,
    )
}

/// The last thing that went wrong, for a message that would otherwise name no cause.
fn reason(last: Option<&UsbError>) -> String {
    last.map_or_else(
        || "nothing at that location answered".to_owned(),
        |error| format!("last failure: {}", error.kind()),
    )
}

#[cfg(test)]
mod tests {
    use super::{Location, REOPEN_POLL, REOPEN_WINDOW};
    use core::time::Duration;

    /// A [`Location`] built by hand. `nusb::DeviceInfo` has no public constructor, so
    /// this is the only way the matching rule is testable at all — and it is the rule,
    /// not the plumbing around it, that decides whether a reset can adopt the wrong
    /// camera.
    fn at(bus: &str, port_chain: &[u8], vendor_id: u16, product_id: u16) -> Location {
        Location {
            bus: bus.to_owned(),
            port_chain: port_chain.to_vec(),
            vendor_id,
            product_id,
        }
    }

    const INGENIC: u16 = crate::vid::INGENIC;
    const BOOTROM: u16 = crate::pid::BOOTROM;

    #[test]
    fn the_same_port_with_the_same_ids_is_the_same_device() {
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        assert!(want.matches(&at("001", &[1, 4], INGENIC, BOOTROM)));
    }

    #[test]
    fn a_device_with_no_port_path_matches_nothing_at_all() {
        // Including itself: with two bootroms on the bus, "some Ingenic
        // device" is a coin flip, and that coin flip is a flash write to the
        // wrong camera. The C takes the flip
        // (`libtdfu/src/usb/device.c:268-274`); this refuses.
        let unknown = at("001", &[], INGENIC, BOOTROM);
        assert!(!unknown.matches(&unknown));
        assert!(!unknown.matches(&at("001", &[], INGENIC, BOOTROM)));
        // And it is never adopted by a device that *does* have one.
        assert!(!at("001", &[1, 4], INGENIC, BOOTROM).matches(&unknown));
    }

    #[test]
    fn the_same_port_number_on_another_bus_is_another_device() {
        // Port [1, 4] exists on every bus in the machine.
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        assert!(!want.matches(&at("002", &[1, 4], INGENIC, BOOTROM)));
    }

    #[test]
    fn a_longer_or_shorter_port_path_is_a_different_port() {
        // A device behind a hub on port 1 is not the device on port 1.
        let want = at("001", &[1], INGENIC, BOOTROM);
        assert!(!want.matches(&at("001", &[1, 4], INGENIC, BOOTROM)));
        assert!(!at("001", &[1, 4], INGENIC, BOOTROM).matches(&want));
    }

    #[test]
    fn something_else_plugged_into_that_port_is_not_adopted() {
        // The window is up to two seconds long; a device can be unplugged and another
        // plugged in inside it. A reset must not hand the caller whatever is there now.
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        assert!(!want.matches(&at("001", &[1, 4], 0x1234, BOOTROM)), "another vendor");
        assert!(
            !want.matches(&at("001", &[1, 4], INGENIC, crate::pid::DFU_LEGACY)),
            "another product"
        );
    }

    #[test]
    fn a_location_with_a_port_is_searchable_and_one_without_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        // The guard that keeps a guess out of the recovery path. Inverted, it would
        // refuse every real device and send every unlocatable one into a scan that can
        // only match the wrong camera.
        assert!(super::searchable(&at("001", &[1, 4], INGENIC, BOOTROM)).is_ok());

        let refusal = super::searchable(&at("001", &[], INGENIC, BOOTROM)).err();
        let Some(crate::UsbErrorKind::Backend(message)) = refusal.map(|error| error.kind().clone()) else {
            return Err("a device with no port path must be refused, in prose".into());
        };
        assert!(
            message.contains("no port path"),
            "the refusal names no cause: {message}"
        );
        Ok(())
    }

    #[test]
    fn a_retry_window_attempts_before_it_checks_the_clock() {
        // Attempt, then check, then rest - never check first. On Linux `USBDEVFS_RESET`
        // returns with the device already back, so the very first attempt is the one
        // that normally succeeds, and a window that consulted an expired clock first
        // would fail a reset that had already worked.
        let mut attempts = 0;
        let mut rests = 0;
        let found = super::within(
            Duration::ZERO,
            || Duration::from_secs(60),
            || rests += 1,
            || {
                attempts += 1;
                Some(attempts)
            },
        );

        assert_eq!(found, Some(1));
        assert_eq!(attempts, 1);
        assert_eq!(rests, 0, "it rested before it had even tried");
    }

    #[test]
    fn a_retry_window_keeps_trying_until_the_device_answers() {
        // The device comes back on the third scan, well inside the window. A deadline
        // compared the wrong way round returns `None` here after the first miss.
        let mut attempts = 0;
        let mut rests = 0;
        let found = super::within(
            Duration::from_secs(2),
            || Duration::ZERO,
            || rests += 1,
            || {
                attempts += 1;
                (attempts == 3).then_some("back")
            },
        );

        assert_eq!(found, Some("back"));
        assert_eq!(attempts, 3);
        assert_eq!(rests, 2, "one rest between each pair of attempts, and no more");
    }

    #[test]
    fn a_device_that_came_back_where_it_was_is_the_one_adopted() {
        // The ordinary recovery: the reset device re-appears on its own port, alongside
        // whatever else is on the bench.
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        let scan = [
            (at("001", &[2], INGENIC, BOOTROM), "another camera"),
            (at("001", &[1, 4], INGENIC, BOOTROM), "ours"),
        ];

        assert_eq!(super::adopt(&want, scan.into_iter()), Some("ours"));
    }

    #[test]
    fn a_device_that_answers_the_same_from_another_port_is_never_adopted() {
        // The reset device did not come back at its old usbfs node, and inside the
        // window another Ingenic device took the freed device number. Every bootrom and
        // every U-Boot gadget presents `a108:c309`, so the ids agree and say nothing.
        // Adopting on them is a DNLOAD retry into the wrong camera; only the port tells
        // the two apart, so only the port decides.
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        let elsewhere = [
            (at("001", &[2], INGENIC, BOOTROM), "the other camera on this bus"),
            (
                at("002", &[1, 4], INGENIC, BOOTROM),
                "the same port number, another bus",
            ),
            (at("001", &[1, 4, 3], INGENIC, BOOTROM), "behind a hub on that port"),
            (at("001", &[], INGENIC, BOOTROM), "a device with no port path at all"),
        ];

        assert_eq!(super::adopt(&want, elsewhere.into_iter()), None);
    }

    #[test]
    fn an_empty_scan_is_not_yet_rather_than_an_answer() {
        // What the window rests and retries on: nothing found is `None`, which keeps the
        // poll going, not an adoption of the first thing that turns up later.
        let want = at("001", &[1, 4], INGENIC, BOOTROM);
        let nothing: [(Location, &str); 0] = [];

        assert_eq!(super::adopt(&want, nothing.into_iter()), None);
    }

    #[test]
    fn a_failure_message_carries_the_cause_it_was_given() {
        // The window's own message says only that time ran
        // out. What actually went wrong — permission denied, disconnected, the OS's own
        // text — is known here and nowhere else, so it has to survive into the prose.
        let refused = crate::UsbError::new(crate::UsbErrorKind::AccessDenied, crate::Pipe::Device);
        let carried = super::reason(Some(&refused));
        assert!(carried.contains("last failure"), "{carried}");
        assert!(
            carried.contains(&refused.kind().to_string()),
            "the cause was dropped on the way into the message: {carried}"
        );

        let nothing = super::reason(None);
        assert!(!nothing.is_empty(), "a message with no cause still has to say so");
        assert!(!nothing.contains("last failure"), "there was no failure to report");
    }

    #[test]
    fn a_retry_window_gives_up_when_the_clock_runs_out() {
        // And it is the *clock* that stops it, not an attempt count: a device that never
        // comes back must not spin for ever, which is the rule the whole backend is
        // built on (the `transport` module docs).
        let mut attempts = 0;
        let mut elapsed = Duration::ZERO;
        let found = super::within(
            Duration::from_millis(100),
            || {
                elapsed += Duration::from_millis(50);
                elapsed
            },
            || (),
            || {
                attempts += 1;
                None::<()>
            },
        );

        assert_eq!(found, None);
        assert_eq!(attempts, 2, "it stopped at the deadline, not before or long after");
    }

    #[test]
    fn the_wait_is_bounded_and_polled_rather_than_spun() {
        // The bound is the requirement (the `transport` module docs are the rule). The
        // numbers only have to bracket the two 1500 ms settles already in the tree.
        assert!(REOPEN_WINDOW > Duration::from_millis(1500));
        assert!(REOPEN_WINDOW <= Duration::from_secs(5));
        assert!(REOPEN_POLL > Duration::ZERO);
        assert!(REOPEN_POLL < REOPEN_WINDOW);
    }
}
