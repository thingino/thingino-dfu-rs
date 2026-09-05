//! Finding the device a command names, and waiting for the gadget.
//!
//! # Two facts, two answers
//!
//! An earlier implementation's `pick_alt` returned `None` for two different things, "no
//! device appeared in 30 s" and "the device is right here and has no alt by that name",
//! and both became `write failed: Device not found`. One of
//! those means *wait longer or check the cable*; the other means *your `--alt` is
//! wrong*, and the device list to prove it is in hand. [`WaitFailure`] keeps them apart,
//! and the C keeps them apart too, in its own way: `dfu_pick_alt` retries a failed
//! **probe** 120 times but calls `tdfu_dfu_find_alt` exactly once and returns
//! immediately when it answers `-1` (`dfu-remote/main.c:344-352`). A wrong alt name
//! fails at once rather than after 30 s, which is the behaviour worth keeping.

use tdfu_core::clock::Sleeper;
use tdfu_core::dfu::alt;
use tdfu_core::model::{AltSel, DfuInfo, Stage};
use tdfu_core::progress::ProgressSink;
use tdfu_core::{Error, ops};
use tdfu_usb::{DeviceDescriptors, LocalUsbBackend};

use super::state::{Port, Row, Window};

/// A device the client's `idx` names, as enumeration sees it.
#[derive(Debug, Clone)]
pub struct Selected<Id> {
    /// The `idx` byte from the request — the row's position in `DISCOVER`'s list
    /// as it stood then.
    pub index: u8,
    /// The backend's handle, for [`LocalUsbBackend::open`].
    pub id: Id,
    /// What enumeration knows about it.
    pub descriptors: DeviceDescriptors,
    /// Bootrom, gadget, firmware — or `None` for "the descriptors cannot tell".
    pub stage: Option<Stage>,
}

impl<Id> Selected<Id> {
    /// May a bootstrap upload to this device?
    ///
    /// Only a bootrom. The gadget and the bootrom **share** `a108:c309`,
    /// so a device the descriptors cannot classify is genuinely unknown, and treating
    /// unknown as a bootrom would upload a stage-1 image to something that may be
    /// mid-flash. That is an audit's finding, carried here.
    #[must_use]
    pub fn is_bootrom(&self) -> bool {
        self.stage == Some(Stage::Bootrom)
    }

    /// Is this already the U-Boot DFU gadget a transfer needs?
    #[must_use]
    pub fn is_gadget(&self) -> bool {
        self.stage == Some(Stage::Gadget)
    }

    /// How to name it in a refusal.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self.stage {
            Some(Stage::Bootrom) => "in the bootrom",
            Some(Stage::Gadget) => "a U-Boot DFU gadget",
            Some(Stage::Firmware) => "running vendor firmware",
            // `Stage` is `#[non_exhaustive]`: a stage added later opts in to a
            // description rather than inheriting a wrong one.
            _ => "of an unrecognised kind",
        }
    }
}

/// Which physical device a command is about, and how to keep hold of it.
///
/// The `idx` on the wire is a **position in the last `DISCOVER` listing**, so resolving
/// it never asks the bus what is at that position now: the listing the client was last
/// answered with is the client's frame of reference, and the row it holds carries the
/// bus and the port path of the device the client picked. A listing that shrank or
/// reordered between the `DISCOVER` and the command therefore cannot slide a neighbour
/// under the index, which is exactly how one camera's firmware reaches another's flash.
///
/// The wait then follows that bus and that port. Both halves are compared: a port path
/// is the ports under a root hub, so `[4, 3]` exists on every bus in the machine and two
/// cameras on mirrored hubs are one device without the bus number. A port that cannot be
/// followed (no path, or a bus of 0) is refused rather than followed by position.
///
/// The device being **off the bus** is the ordinary case right after a `BOOTSTRAP`, and
/// it is what the window waits through: the row still says where the device was, so
/// there is nothing to guess at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The `idx` byte the client sent.
    pub index: u8,
    /// Where the row said the device was.
    pub port: Port,
    /// What the row said it was, for the refusal's wording.
    pub was: Option<Stage>,
    /// A `BOOTSTRAP` ran against this row, so the device is expected back as a gadget
    /// with a new device number.
    pub expect_gadget: bool,
}

impl Target {
    /// The device a row of the client's own listing names.
    ///
    /// Nothing is enumerated here: the row is the answer. That is the point, because an
    /// enumeration would answer "whatever is at that position now", which is a different
    /// device as soon as a listing shrinks.
    #[must_use]
    pub fn of_row(index: u8, row: &Row) -> Self {
        Self {
            index,
            port: row.port.clone(),
            was: row.stage,
            expect_gadget: row.expect_gadget,
        }
    }

    /// The refusal for a device that cannot be followed across a re-enumeration.
    fn unfollowable(&self) -> Error {
        Error::Invalid(format!(
            "device {} is on {}, which cannot be followed across a re-enumeration; \
             this backend reports no bus and port for it",
            self.index,
            self.port.describe()
        ))
    }
}

/// Why waiting for a gadget ended without one.
#[derive(Debug)]
pub enum WaitFailure {
    /// The window closed and no DFU gadget appeared.
    ///
    /// Carries what was spent so the message can say it: an earlier implementation said only
    /// `Device not found`, which reads identically to a wrong `--alt`.
    NoGadget {
        /// How many times the bus was looked at.
        probes: u32,
        /// How long was slept in total.
        waited: core::time::Duration,
    },
    /// A gadget answered and has no alt by that name — a wrong `--alt`, not a missing
    /// device. The error names the alts the device *does* offer
    /// (`tdfu_core::dfu::alt::resolve`).
    NoSuchAlt(Error),
    /// The bus itself could not be enumerated.
    Bus(Error),
    /// The row names a device the backend gave no bus and port for, so there is nothing
    /// to follow it by and no safe way to pick one out of a listing.
    Unfollowable(Error),
}

impl WaitFailure {
    /// The `tdfu_core::Error` this becomes for the wire mapper.
    ///
    /// `NoGadget` is `Device not found` — the C's class for the same fact
    /// (`dfu-remote/main.c:573`, `:661` turn `dfu_pick_alt`'s `-1` into
    /// `TDFU_ERROR_DEVICE_NOT_FOUND`) — with the window's numbers after the colon so
    /// "wait longer" and "check the cable" can be told apart from "your alt is wrong".
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            Self::NoGadget { probes, waited } => Error::Usb(tdfu_usb::UsbError::new(
                tdfu_usb::UsbErrorKind::NoDevice,
                tdfu_usb::Pipe::Device,
            ))
            .context(format!(
                "no U-Boot DFU gadget appeared within {:.1}s ({probes} probes)",
                waited.as_secs_f32()
            )),
            Self::NoSuchAlt(error) | Self::Bus(error) | Self::Unfollowable(error) => error,
        }
    }
}

/// Add a `doing:` context to an error without changing its class (contracts amendment
/// A3).
trait Contextual {
    fn context(self, doing: String) -> Error;
}

impl Contextual for Error {
    fn context(self, doing: String) -> Error {
        match self {
            Error::Usb(source) => Error::UsbWhile { doing, source },
            other => Error::Protocol(format!("{doing}: {other}")),
        }
    }
}

/// A gadget, opened, probed, and with the requested alt resolved.
#[derive(Debug)]
pub struct Gadget<T> {
    /// The opened transport.
    pub device: T,
    /// What the gadget says about itself.
    pub info: DfuInfo,
    /// The row it was found at, which may differ from the `idx` that was asked for.
    pub index: u8,
}

/// Look for the gadget up to `window.probes` times, `window.interval` apart.
///
/// `alt` is checked **once**, on the first gadget that answers, and its failure ends the
/// wait immediately — see the module docs and `dfu-remote/main.c:346-350`. Pass `None`
/// to wait for any gadget at all, which is what the erase path does: the C passes a
/// `NULL` selector there (`main.c:519`) because `tdfu_dfu_erase` resolves the `erase`
/// alt itself, and [`ops::erase`] does the same.
///
/// `progress` carries the probe's recovery note: when a gadget answers only after a USB
/// reset (a routine post-run wedge), the operator watching a `--host` run is told, rather
/// than left with an unexplained re-enumeration.
///
/// # Errors
/// [`WaitFailure`], which distinguishes the three ways this ends without a device.
pub async fn await_gadget<B: LocalUsbBackend, C: Sleeper>(
    backend: &B,
    clock: &C,
    window: Window,
    target: &Target,
    alt: Option<&AltSel>,
    progress: ProgressSink<'_>,
) -> Result<Gadget<B::Transport>, WaitFailure> {
    if !target.port.is_followable() {
        return Err(WaitFailure::Unfollowable(target.unfollowable()));
    }
    let mut waited = core::time::Duration::ZERO;
    for probe in 0..window.probes {
        if probe > 0 {
            clock.sleep(window.interval).await;
            waited = waited.saturating_add(window.interval);
        }
        let Some(found) = find(backend, target).await.map_err(WaitFailure::Bus)? else {
            continue;
        };
        // An open that fails is the same fact as a device that is not there yet: the
        // gadget's interface is often not bound for a moment after it enumerates. The C
        // folds it in the same way — the open is inside `tdfu_dfu_probe`, and every
        // probe failure retries (`dfu-remote/main.c:345`).
        let Ok(device) = backend.open(&found.id).await else {
            continue;
        };
        // `ops::probe_with_progress` carries the C's reset-and-retry (`dfu.c:501-508`)
        // and, unlike the sinkless `ops::probe`, announces the reset through `progress`:
        // recovering a wedged gadget is otherwise a re-enumeration in dmesg and about
        // 1.5 s of silence with nothing to explain either.
        let Ok(info) = ops::probe_with_progress(&device, clock, &mut *progress).await else {
            continue;
        };
        if found.index != target.index {
            // The row moved, which is ordinary: a device that re-enumerates lands where
            // the host puts it. Said out loud because the number the client is holding
            // and the number this daemon acted on are then different, and the port is
            // what makes them the same device.
            tracing::debug!(
                asked = target.index,
                found = found.index,
                port = %target.port.describe(),
                "the device moved position in the listing"
            );
        }
        if let Some(selection) = alt {
            // Resolved here so a wrong `--alt` is refused before anything is staged or
            // claimed, and resolved again inside the operation. `dfu::alt::resolve` is
            // the rule's one home and its doc blesses the second lookup: it is a scan of
            // at most `MAX_ALTS` entries and the second answer cannot disagree.
            alt::resolve(&info, selection).map_err(WaitFailure::NoSuchAlt)?;
        }
        return Ok(Gadget {
            device,
            info,
            index: found.index,
        });
    }
    Err(WaitFailure::NoGadget {
        probes: window.probes,
        waited,
    })
}

/// One look at the bus for `target`'s gadget.
///
/// The device is adopted only when the bus **and** the port path are the row's, and only
/// when it is a gadget. There is no fallback to the row's position: after a `BOOTSTRAP`
/// the row still carries the bus and port of the device that was bootstrapped, so
/// position buys nothing and costs a neighbour's flash.
async fn find<B: LocalUsbBackend>(backend: &B, target: &Target) -> Result<Option<Selected<B::DeviceId>>, Error> {
    let listing = backend.list().await?;
    for (position, device) in listing.iter().enumerate() {
        if Port::of(&device.descriptors) == target.port && ops::classify(&device.descriptors) == Some(Stage::Gadget) {
            return Ok(Some(select_row(position, device)));
        }
    }
    Ok(None)
}

/// Pick the device a row of the client's listing names, for the commands that act on it
/// where it stands.
///
/// The row says which bus and port the client picked; the enumeration says what is there
/// now. Nothing is resolved by position, so a listing that shrank between the `DISCOVER`
/// and this command is a refusal and not a different camera.
///
/// # Errors
/// [`Error::Usb`] if the bus cannot be enumerated; [`Error::Invalid`] when the row's
/// port cannot be followed, or when nothing is on it any more.
pub async fn select<B: LocalUsbBackend>(backend: &B, index: u8, row: &Row) -> Result<Selected<B::DeviceId>, Error> {
    if !row.port.is_followable() {
        return Err(Target::of_row(index, row).unfollowable());
    }
    let listing = backend.list().await?;
    let found = listing
        .iter()
        .enumerate()
        .find(|(_, device)| Port::of(&device.descriptors) == row.port);
    let Some((position, device)) = found else {
        return Err(Error::Invalid(format!(
            "device {index} ({}) is no longer on the bus; run DISCOVER again",
            row.port.describe()
        )));
    };
    Ok(select_row(position, device))
}

fn select_row<Id: Clone>(position: usize, device: &tdfu_usb::Discovered<Id>) -> Selected<Id> {
    Selected {
        // A listing longer than 256 has no `idx` that can name its tail; report the last
        // addressable index rather than wrapping onto device 0 the way the C's
        // `(uint8_t)` cast does. An audit kept that difference from the C on purpose.
        index: u8::try_from(position).unwrap_or(u8::MAX),
        id: device.id.clone(),
        descriptors: device.descriptors.clone(),
        stage: ops::classify(&device.descriptors),
    }
}

#[cfg(test)]
mod tests {
    use super::{Target, WaitFailure, await_gadget, select};
    use crate::commands::fake::{FakeBackend, TestResult, rows_of, t23_regs};
    use crate::commands::state::{Port, Row, Window};
    use core::time::Duration;
    use tdfu_core::Error;
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::model::{AltSel, Stage};
    use tdfu_core::progress::sink_ignore;
    use tdfu_usb::mock::block_on;

    /// A bus that is empty for `absent` listings and then has a gadget on it.
    fn appears_after(absent: usize) -> FakeBackend {
        let mut listings: Vec<Vec<_>> = (0..absent).map(|_| Vec::new()).collect();
        listings.push(vec![FakeBackend::gadget()]);
        FakeBackend::appearing(listings)
    }

    fn port(bus: u8, path: &[u8]) -> Port {
        Port {
            bus,
            path: path.to_vec(),
        }
    }

    /// The row a `DISCOVER` left for the gadget fixture, which sits on bus 1, port 4.3,
    /// after a bootstrap of the device that was there.
    fn gadget_target() -> Target {
        Target {
            index: 0,
            port: port(1, &[4, 3]),
            was: Some(Stage::Bootrom),
            expect_gadget: true,
        }
    }

    /// The rows the bus would answer a `DISCOVER` with.
    fn rows(backend: &FakeBackend) -> Vec<Row> {
        block_on(rows_of(backend)).unwrap_or_default()
    }

    /// The reason this test exists: an earlier implementation's window
    /// was **unfalsifiable**, its only caller passing `attempts: 1, backoff: 0`, so a
    /// `pick_alt` that never retried would have passed.
    ///
    /// Here the default window is driven against a bus where the gadget appears on the
    /// 120th listing. It is found, and the clock records 119 sleeps of 250 ms — so a
    /// loop that probed once, or slept for the wrong interval, or gave up a probe early,
    /// fails.
    #[test]
    fn fe_daemon_reenum_window() -> TestResult {
        let window = Window::default();
        let backend = appears_after(usize::try_from(window.probes)? - 1);
        let clock = RecordingClock::new();
        let target = gadget_target();
        let found = match block_on(await_gadget(
            &backend,
            &clock,
            window,
            &target,
            None,
            &mut sink_ignore(),
        )) {
            Ok(found) => found,
            Err(failure) => return Err(format!("the gadget appears on the last probe: {failure:?}").into()),
        };
        assert_eq!(found.index, 0);
        assert_eq!(backend.list_calls(), 120, "120 probes");
        assert_eq!(clock.slept().len(), 119, "one sleep between each pair of probes");
        assert!(
            clock.slept().iter().all(|slept| *slept == Duration::from_millis(250)),
            "250 ms: {:?}",
            clock.slept()
        );
        assert_eq!(clock.total(), window.budget());
        Ok(())
    }

    /// One probe past the window is one probe too many: the same bus, one device later,
    /// gives up. Together with the test above this brackets the boundary, so a loop that
    /// ran 119 or 121 times fails one of the two.
    #[test]
    fn the_window_gives_up_one_probe_after_its_last() -> TestResult {
        let window = Window::default();
        let backend = appears_after(usize::try_from(window.probes)?);
        let clock = RecordingClock::new();
        let target = gadget_target();
        let Err(WaitFailure::NoGadget { probes, waited }) = block_on(await_gadget(
            &backend,
            &clock,
            window,
            &target,
            None,
            &mut sink_ignore(),
        )) else {
            return Err("a gadget that appears after the window must not be found".into());
        };
        assert_eq!(probes, 120);
        assert_eq!(waited, window.budget());
        assert_eq!(backend.list_calls(), 120);
        Ok(())
    }

    /// A shorter window really is shorter — the parameter is load-bearing and not
    /// decoration.
    #[test]
    fn the_window_is_a_parameter_and_not_a_constant() {
        let window = Window {
            probes: 4,
            interval: Duration::from_millis(10),
        };
        let backend = appears_after(3);
        let clock = RecordingClock::new();
        let target = gadget_target();
        assert!(
            block_on(await_gadget(
                &backend,
                &clock,
                window,
                &target,
                None,
                &mut sink_ignore()
            ))
            .is_ok()
        );
        assert_eq!(backend.list_calls(), 4);
        assert_eq!(clock.slept(), vec![Duration::from_millis(10); 3]);
    }

    /// The two facts a wait ends on, through the real wait rather than through a
    /// hand-built failure: no device in the window, versus a device that is here and has
    /// no such alt. An earlier implementation returned `None` for both and printed
    /// `write failed: Device not found` for both.
    #[test]
    fn no_device_and_no_such_alt_are_different_outcomes() -> TestResult {
        let window = Window {
            probes: 2,
            interval: Duration::from_millis(1),
        };
        let target = gadget_target();

        let empty = FakeBackend::empty();
        let clock = RecordingClock::new();
        let outcome = block_on(await_gadget(
            &empty,
            &clock,
            window,
            &target,
            Some(&AltSel::Default),
            &mut sink_ignore(),
        ));
        assert!(
            matches!(outcome, Err(WaitFailure::NoGadget { probes: 2, .. })),
            "{outcome:?}"
        );

        let present = FakeBackend::new(vec![FakeBackend::gadget()]);
        let clock = RecordingClock::new();
        let outcome = block_on(await_gadget(
            &present,
            &clock,
            window,
            &target,
            Some(&AltSel::Name("sdcard".to_owned())),
            &mut sink_ignore(),
        ));
        let Err(WaitFailure::NoSuchAlt(error)) = outcome else {
            return Err(format!("a wrong alt is not a missing device: {outcome:?}").into());
        };
        assert!(error.to_string().contains("sdcard"), "{error}");
        // And it did not spend the window waiting: the C answers a wrong alt at once
        // (`dfu-remote/main.c:346-350`), and so does this.
        assert_eq!(present.list_calls(), 1, "no retry for a fact that will not change");
        assert_eq!(clock.slept(), Vec::new());
        Ok(())
    }

    /// The wait follows the row's **bus and port path**, so a gadget that appears at the
    /// same index cannot be adopted.
    #[test]
    fn the_wait_follows_the_port_path_when_it_has_one() {
        let window = Window {
            probes: 2,
            interval: Duration::from_millis(1),
        };
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        // The gadget fixture sits on bus 1, port 4.3; ask for a device on another port.
        let elsewhere = Target {
            port: port(1, &[9, 9]),
            ..gadget_target()
        };
        let outcome = block_on(await_gadget(
            &backend,
            &RecordingClock::new(),
            window,
            &elsewhere,
            None,
            &mut sink_ignore(),
        ));
        assert!(matches!(outcome, Err(WaitFailure::NoGadget { .. })), "{outcome:?}");

        assert!(
            block_on(await_gadget(
                &backend,
                &RecordingClock::new(),
                window,
                &gadget_target(),
                None,
                &mut sink_ignore(),
            ))
            .is_ok()
        );
    }

    /// **The same port number on another bus is another camera.** Two controllers with
    /// mirrored hubs put the identical port path on two buses, and a wait that compared
    /// the path alone would take whichever came first in the listing.
    #[test]
    fn the_wait_does_not_cross_buses() -> TestResult {
        let window = Window {
            probes: 2,
            interval: Duration::from_millis(1),
        };
        // Row 0 is bus 1 port 4.3; row 1 is bus 2 on the same port numbers.
        let backend = FakeBackend::new(vec![
            FakeBackend::gadget_at_port(1, 9, vec![4, 3]),
            FakeBackend::gadget_at_port(2, 9, vec![4, 3]),
        ]);
        let on_bus_two = Target {
            index: 1,
            port: port(2, &[4, 3]),
            was: Some(Stage::Gadget),
            expect_gadget: false,
        };
        let found = block_on(await_gadget(
            &backend,
            &RecordingClock::new(),
            window,
            &on_bus_two,
            None,
            &mut sink_ignore(),
        ))
        .map_err(|failure| format!("the bus-2 gadget is there: {failure:?}"))?;
        assert_eq!(found.index, 1, "the row on bus 2, not the one that came first");

        // And with only the bus-1 camera on the bus, the bus-2 target is not found at
        // all rather than adopting its mirror.
        let only_bus_one = FakeBackend::new(vec![FakeBackend::gadget_at_port(1, 9, vec![4, 3])]);
        let outcome = block_on(await_gadget(
            &only_bus_one,
            &RecordingClock::new(),
            window,
            &on_bus_two,
            None,
            &mut sink_ignore(),
        ));
        assert!(matches!(outcome, Err(WaitFailure::NoGadget { .. })), "{outcome:?}");
        Ok(())
    }

    /// A row with no bus and port is refused outright: there is nothing to follow, and
    /// following the index instead is what adopts a neighbour.
    #[test]
    fn a_device_that_cannot_be_placed_is_refused_not_followed_by_index() -> TestResult {
        let window = Window {
            probes: 2,
            interval: Duration::from_millis(1),
        };
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let nowhere = Target {
            index: 0,
            port: Port::default(),
            was: Some(Stage::Bootrom),
            expect_gadget: true,
        };
        let Err(WaitFailure::Unfollowable(error)) = block_on(await_gadget(
            &backend,
            &RecordingClock::new(),
            window,
            &nowhere,
            None,
            &mut sink_ignore(),
        )) else {
            return Err("a device with no port must not be followed by index".into());
        };
        assert!(error.to_string().contains("cannot be followed"), "{error}");
        assert_eq!(backend.list_calls(), 0, "and the bus was not even listed");
        Ok(())
    }

    /// `select` follows the row's port, and refuses when nothing is on it any more,
    /// rather than handing back whatever slid into that position.
    #[test]
    fn select_follows_the_row_and_refuses_a_device_that_left() -> TestResult {
        let two = FakeBackend::new(vec![
            FakeBackend::bootrom_at_port(1, 7, vec![4, 2], t23_regs()),
            FakeBackend::gadget_at_port(1, 9, vec![4, 3]),
        ]);
        let listing = rows(&two);
        assert_eq!(block_on(select(&two, 0, &listing[0]))?.descriptors.address, 7);
        assert_eq!(block_on(select(&two, 1, &listing[1]))?.descriptors.address, 9);

        // Row 0 is unplugged, so row 1 becomes row 0. The index the client is holding
        // still means the camera it was answered for, which is gone.
        two.remove_row(0);
        let Err(Error::Invalid(message)) = block_on(select(&two, 0, &listing[0])) else {
            return Err("the device that left must be refused, not replaced".into());
        };
        assert!(message.contains("bus 1 port 4.2"), "{message}");
        assert!(message.contains("run DISCOVER again"), "{message}");
        // ... and the survivor is still reachable by its own row.
        assert_eq!(block_on(select(&two, 1, &listing[1]))?.descriptors.address, 9);
        Ok(())
    }

    /// An unclassifiable device is never a bootrom, so nothing bootstraps
    /// it and nothing reads its eFuses.
    ///
    /// Every stage is checked in **both** directions — the predicate that must be true
    /// and the one that must be false — because a predicate only ever tested for `false`
    /// is a predicate that can be replaced with `false`. `cargo mutants` said so about
    /// `is_gadget`, and the two `describe` arms nothing named.
    #[test]
    fn every_stage_is_classified_and_described_in_both_directions() -> TestResult {
        let one_of = |device| {
            let backend = FakeBackend::new(vec![device]);
            let listing = rows(&backend);
            let row = listing.first().cloned().ok_or("one row")?;
            block_on(select(&backend, 0, &row)).map_err(Box::<dyn std::error::Error>::from)
        };

        let unknown = one_of(FakeBackend::opaque())?;
        assert_eq!(unknown.stage, None);
        assert!(!unknown.is_bootrom());
        assert!(!unknown.is_gadget());
        assert_eq!(unknown.describe(), "of an unrecognised kind");

        let gadget = one_of(FakeBackend::gadget())?;
        assert_eq!(gadget.stage, Some(Stage::Gadget));
        assert!(gadget.is_gadget());
        assert!(!gadget.is_bootrom(), "a gadget is not bootstrap-eligible");
        assert_eq!(gadget.describe(), "a U-Boot DFU gadget");

        let bootrom = one_of(FakeBackend::bootrom(t23_regs()))?;
        assert_eq!(bootrom.stage, Some(Stage::Bootrom));
        assert!(bootrom.is_bootrom());
        assert!(!bootrom.is_gadget());
        assert_eq!(bootrom.describe(), "in the bootrom");

        let firmware = one_of(FakeBackend::firmware())?;
        assert_eq!(firmware.stage, Some(Stage::Firmware));
        assert!(!firmware.is_bootrom(), "vendor firmware is not bootstrap-eligible");
        assert!(!firmware.is_gadget());
        assert_eq!(firmware.describe(), "running vendor firmware");
        Ok(())
    }

    /// Selection opens nothing, so naming a target cannot disturb a device
    /// another operator is flashing.
    #[test]
    fn selection_opens_nothing() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let listing = rows(&backend);
        let row = listing.first().ok_or("one row")?;
        let _selected = block_on(select(&backend, 0, row))?;
        let _target = Target::of_row(0, row);
        assert!(backend.opened().is_empty());
        Ok(())
    }
}
