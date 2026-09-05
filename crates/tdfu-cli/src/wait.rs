//! `--wait`: block until there is something to talk to.
//!
//! # The target is **any** Ingenic device, deliberately
//!
//! The narrow rule would be "for a bootrom when bootstrapping/diag, for the gadget
//! otherwise", and the C computes exactly that: `wait_for_device(&manager, !bootstrap &&
//! !diag)` (`cli/main.c:440`), so `-l --wait` takes the `want_gadget = true` branch and
//! waits for `tdfu_dfu_gadget_present` (`cli/main.c:246-248`).
//!
//! **Implementing that literally is a bug**, and it is a bug that has already cost a
//! bench run: waiting for a gadget on a bus that only has a bootrom hangs for ever, and
//! the hang skipped a bench harness's power-off and left a device energised.
//! The resolution: the broad
//! target is **KEPT ON MERIT**, and the C is no longer the reason for it. The two forms
//! differ only when a leftover device is on the bus, where the narrow form waits for
//! ever and the broad form proceeds in seconds and lets the operation say what is
//! actually wrong. The C waits for a gadget here; this waits for any Ingenic device, and
//! that is the deliberate difference.
//!
//! # The poll is safe to run against a live bootrom
//!
//! Enumeration is a pure list scan: no open, no claim, no probe, no reset,
//! so polling it every 500 ms cannot disturb a device that another agent is
//! bootstrapping. [`LocalUsbBackend::list`] carries that obligation in its own doc.
//!
//! # No timeout
//!
//! The C polls indefinitely and Ctrl-C aborts (`cli/main.c:241-265`); so does this. A
//! deadline here would have to be either too short for a T20 (slow to enumerate)
//! or long enough to be indistinguishable from waiting. Tests bound it by scripting
//! the backend instead, and never sleep: the interval goes through the
//! [`Sleeper`](tdfu_core::clock::Sleeper) seam, so
//! [`RecordingClock`](tdfu_core::clock::RecordingClock) records 500 ms and returns.

use core::time::Duration;
use std::io;

use tdfu_core::clock::Sleeper;
use tdfu_core::{Error, Result};
use tdfu_usb::LocalUsbBackend;

use crate::target::{self, Selected};

/// How often the bus is re-listed.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// What is said the first time nothing is there.
pub const WAITING: &str = "Waiting for an Ingenic device to appear (Ctrl-C to abort)...";

/// What is said when one turns up, but only if the wait was announced.
pub const ARRIVED: &str = "Device found.";

/// Poll until at least one Ingenic device is on the bus.
///
/// `narrate` receives the two lines above, and only when there was something to say: a
/// device that is already present produces no output at all, which is what makes
/// `--wait` safe to leave in a wrapper script.
///
/// # Errors
/// [`Error::Usb`](tdfu_core::Error::Usb) if enumeration itself fails, and whatever
/// `narrate` raises.
///
/// A failed enumeration is **not** retried. The C treats it as "no devices" and keeps
/// polling (`cli/main.c:250-252`), which turns a broken bus into an indefinite silent
/// wait: exactly the failure-hiding shape to avoid. On every
/// platform this backend runs on, a listing that fails fails for a structural reason
/// (unreadable sysfs, a missing driver), so reporting it is both more honest and more
/// actionable.
pub async fn wait_for_device<B, C>(
    backend: &B,
    clock: &C,
    narrate: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<()>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    let mut announced = false;
    loop {
        // The backend lists Ingenic VIDs only, so "not empty" already
        // means "an Ingenic device" - any stage, per the module docs.
        let present = backend.list().await?;
        if !present.is_empty() {
            tracing::debug!(devices = present.len(), "the wait is over");
            if announced {
                narrate(ARRIVED)?;
            }
            return Ok(());
        }
        if !announced {
            narrate(WAITING)?;
            announced = true;
        }
        clock.sleep(POLL_INTERVAL).await;
    }
}

/// How many times [`wait_for_gadget`] re-lists the bus.
pub const REENUM_ATTEMPTS: usize = 120;

/// How long between those polls.
pub const REENUM_INTERVAL: Duration = Duration::from_millis(250);

/// What is said while a freshly bootstrapped device re-enumerates.
pub const REENUMERATING: &str = "Waiting for the U-Boot DFU gadget to enumerate...";

/// Poll until the device that was just bootstrapped comes back as a DFU gadget.
///
/// # This wait is bounded, and `--wait` is not
///
/// They are different questions. `--wait` asks "is there anything to talk to yet",
/// which only the operator can answer — they are holding a boot pin — so it waits for
/// ever and Ctrl-C ends it, exactly as the C does. This one asks "did the loader I just
/// started come up", and the answer arrives within seconds or not at all: the loaders
/// that take longest are the MMC/NAND-probing ones at eight to ten seconds, which is why
/// the daemon's window is 120 × 250 ms ≈ 30 s after 5 s proved too short
/// (`c8a2c59`). Waiting for ever here is what the C does (`cli/main.c:511`,
/// `wait_for_device(want_gadget=true)`) and it is a hang with no operator action that
/// can end it: the failure mode that cost a bench run by skipping a harness's
/// power-off. The same window the daemon uses, and then a
/// refusal that says what to check, is strictly better.
///
/// `port_path` is the bootrom's, from before the bootstrap: the physical port is the one
/// identifier that survives re-enumeration, so a second camera plugged in alongside
/// cannot satisfy this wait.
///
/// # Errors
/// [`Error::Usb`](tdfu_core::Error::Usb) if enumeration fails;
/// [`Error::NotDfu`](tdfu_core::Error::NotDfu) if the window closes with no gadget on
/// that port — narrated first, with the window and the port, because the error type has
/// nowhere to carry them; [`Error::Invalid`](tdfu_core::Error::Invalid) on the first
/// attempt when `port_path` is empty, which [`target::find_gadget`] refuses rather than
/// guessing at. That path was read before the bootstrap, so no amount of waiting makes
/// it readable and the window is not spent on it.
pub async fn wait_for_gadget<B, C>(
    backend: &B,
    clock: &C,
    port_path: &[u8],
    narrate: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<Selected<B::DeviceId>>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    narrate(REENUMERATING)?;
    for attempt in 0..REENUM_ATTEMPTS {
        if let Some(gadget) = target::find_gadget(backend, port_path).await? {
            tracing::debug!(attempt, index = gadget.index, "the gadget re-enumerated");
            return Ok(gadget);
        }
        clock.sleep(REENUM_INTERVAL).await;
    }
    let window = REENUM_INTERVAL.saturating_mul(u32::try_from(REENUM_ATTEMPTS).unwrap_or(u32::MAX));
    narrate(&format!(
        "No DFU gadget appeared within {} s. The loader was started but did not reach \
         its DFU entities: check the UART for `DFU entities configuration failed`, and \
         that the loaders in the firmware tree match this SoC.",
        window.as_secs()
    ))?;
    Err(Error::NotDfu)
}

#[cfg(test)]
mod tests {
    use super::{
        ARRIVED, POLL_INTERVAL, REENUM_ATTEMPTS, REENUM_INTERVAL, REENUMERATING, WAITING, wait_for_device,
        wait_for_gadget,
    };
    use crate::fake::{FakeBackend, TestResult};
    use core::cell::RefCell;
    use tdfu_core::clock::RecordingClock;
    use tdfu_usb::mock::block_on;
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// Collect what was narrated.
    fn recorder(lines: &RefCell<Vec<String>>) -> impl FnMut(&str) -> std::io::Result<()> + '_ {
        move |line| {
            lines.borrow_mut().push(line.to_owned());
            Ok(())
        }
    }

    /// A device that is already there is not waited for, and nothing is printed.
    #[test]
    fn a_device_already_present_returns_at_once() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let clock = RecordingClock::new();
        let lines = RefCell::new(Vec::new());

        block_on(wait_for_device(&backend, &clock, &mut recorder(&lines)))?;

        assert_eq!(backend.list_calls(), 1);
        assert_eq!(clock.slept(), Vec::new(), "nothing to wait for, so nothing slept");
        assert_eq!(lines.into_inner(), Vec::<String>::new());
        Ok(())
    }

    /// **The `--wait` pin.** Poll, sleep 500 ms, poll, sleep, poll, done.
    ///
    /// The whole loop runs against a scripted bus and a clock that records rather than
    /// waits, so this test costs microseconds and still asserts the real interval.
    #[test]
    fn fe_cli_wait_polls_every_500ms_until_something_appears() -> TestResult {
        let backend = FakeBackend::appearing(vec![
            Vec::new(),
            Vec::new(),
            vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))],
        ]);
        let clock = RecordingClock::new();
        let lines = RefCell::new(Vec::new());

        block_on(wait_for_device(&backend, &clock, &mut recorder(&lines)))?;

        assert_eq!(backend.list_calls(), 3);
        assert_eq!(clock.slept(), vec![POLL_INTERVAL, POLL_INTERVAL]);
        assert_eq!(lines.into_inner(), vec![WAITING.to_owned(), ARRIVED.to_owned()]);
        Ok(())
    }

    /// **The wait-target pin.** What each wait waits *for*.
    ///
    /// Two waits, two targets, and the difference is deliberate:
    ///
    /// * `--wait` takes **any** Ingenic device, whatever the operation. The narrow rule
    ///   is "a bootrom when bootstrapping/diag, the gadget otherwise", and the
    ///   C computes exactly that (`cli/main.c:440`), and implementing it literally hangs
    ///   for ever on the one bus the auto-bootstrap exists to serve. The broad target
    ///   is kept on merit.
    /// * [`wait_for_gadget`], which runs **after** a bootstrap, takes the gadget on the
    ///   bootrom's own port path and nothing else — a second camera plugged in alongside
    ///   must not satisfy it.
    #[test]
    fn fe_cli_wait_targets() -> TestResult {
        // `--wait` is satisfied by a bootrom.
        let bootrom = FakeBackend::new(vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))]);
        block_on(wait_for_device(&bootrom, &RecordingClock::new(), &mut |_| Ok(())))?;
        assert_eq!(bootrom.list_calls(), 1);

        // ...and by a gadget. Both, from one rule.
        let gadget = FakeBackend::new(vec![FakeBackend::gadget()]);
        block_on(wait_for_device(&gadget, &RecordingClock::new(), &mut |_| Ok(())))?;
        assert_eq!(gadget.list_calls(), 1);

        // The post-bootstrap wait is not satisfied by a bootrom, however long it looks.
        let clock = RecordingClock::new();
        let never = block_on(wait_for_gadget(&bootrom, &clock, &[4, 2], &mut |_| Ok(())));
        assert!(never.is_err(), "a bootrom is not the gadget a bootstrap produces");
        assert_eq!(clock.slept().len(), REENUM_ATTEMPTS, "the window is bounded");

        // And it is satisfied by the gadget on the right port path.
        let reenumerated = FakeBackend::appearing(vec![
            vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))],
            vec![FakeBackend::gadget()],
        ]);
        let found = block_on(wait_for_gadget(
            &reenumerated,
            &RecordingClock::new(),
            &[4, 3],
            &mut |_| Ok(()),
        ))?;
        assert_eq!(found.index, 0);
        Ok(())
    }

    /// The bounded window really is the daemon's 30 s, and it says what to check.
    #[test]
    fn the_reenumeration_window_is_bounded_and_says_so() {
        let bootrom = FakeBackend::new(vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))]);
        let clock = RecordingClock::new();
        let lines = RefCell::new(Vec::new());
        let outcome = block_on(wait_for_gadget(&bootrom, &clock, &[4, 2], &mut recorder(&lines)));

        assert!(outcome.is_err());
        assert_eq!(clock.slept(), vec![REENUM_INTERVAL; REENUM_ATTEMPTS]);
        assert_eq!(clock.total(), REENUM_INTERVAL * 120, "30 s");
        let said = lines.into_inner().join("\n");
        assert!(said.contains(REENUMERATING), "{said}");
        assert!(said.contains("DFU entities configuration failed"), "{said}");
    }

    /// The target is **any** Ingenic device, not a gadget: a bootrom ends the wait.
    ///
    /// This pins the fix for the hang described above. Under the C's `-l --wait` branch
    /// (`cli/main.c:440`) this bus would never satisfy the wait.
    #[test]
    fn fe_cli_wait_accepts_a_bootrom_not_only_a_gadget() -> TestResult {
        let backend = FakeBackend::appearing(vec![
            Vec::new(),
            vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))],
        ]);
        let clock = RecordingClock::new();
        let lines = RefCell::new(Vec::new());

        block_on(wait_for_device(&backend, &clock, &mut recorder(&lines)))?;

        assert_eq!(backend.list_calls(), 2, "the bootrom ended the wait");
        assert_eq!(clock.slept(), vec![POLL_INTERVAL]);
        Ok(())
    }

    /// Nothing is opened while waiting.
    #[test]
    fn disc_the_wait_poll_opens_nothing() -> TestResult {
        let backend = FakeBackend::appearing(vec![Vec::new(), vec![FakeBackend::gadget()]]);
        block_on(wait_for_device(&backend, &RecordingClock::new(), &mut |_| Ok(())))?;
        assert_eq!(backend.opened(), Vec::<usize>::new());
        Ok(())
    }

    /// A bus that cannot be enumerated is reported, not waited on for ever.
    #[test]
    fn a_broken_bus_is_reported_rather_than_waited_out() {
        let backend = FakeBackend::failing(UsbError::new(
            UsbErrorKind::Backend("sysfs is unreadable".into()),
            Pipe::Device,
        ));
        let clock = RecordingClock::new();
        let outcome = block_on(wait_for_device(&backend, &clock, &mut |_| Ok(())));

        assert!(outcome.is_err());
        assert_eq!(backend.list_calls(), 1, "it must not spin on a structural failure");
        assert_eq!(clock.slept(), Vec::new());
    }
}
