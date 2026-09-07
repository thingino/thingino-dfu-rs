//! Boot the device out of DFU.

use tdfu_usb::LocalUsbTransport;

use super::erase::alt_named;
use crate::clock::Sleeper;
use crate::dfu::descriptors::read_info;
use crate::dfu::host::{self, Grace, State};
use crate::dfu::{REBOOT_ALT, REBOOT_TOKEN};
use crate::error::Result;
use crate::model::DfuInfo;
use crate::progress::{Progress, ProgressSink};

/// The line that says the reboot is being armed (`dfu.c:767`).
fn rebooting_note(alt: u8) -> String {
    format!("Rebooting the device (alt {alt})...")
}

/// The line that says the device left the bus (`dfu.c:781`).
///
/// **The C prints this unconditionally**, past a point where its function can no longer
/// fail (`dfu.c:779-782`). Here it is printed only when the token was armed *and* the
/// device stopped answering — which is what a reboot looks like from the host.
const TRIGGERED_NOTE: &str = "Reboot triggered";

/// The line for the case the C cannot distinguish from success.
fn still_here_note(state: State) -> String {
    format!(
        "the device answered the post-reset poll in {state} instead of leaving the bus — \
         the reboot token was accepted but the board may still be sitting in U-Boot"
    )
}

/// Reboot the device out of DFU and into whatever was just flashed.
///
/// The sequence, against the alt named
/// [`reboot`](crate::dfu::REBOOT_ALT): claim it, [`make_idle`](host::make_idle),
/// `DNLOAD` block 0 carrying [`REBOOT_TOKEN`](crate::dfu::REBOOT_TOKEN), poll, the
/// zero-length `DNLOAD`, poll again. Every poll uses
/// [`Grace::None`](crate::dfu::Grace::None), and the last one is meant to fail.
///
/// # The post-ZLP poll is the operation
///
/// `f_dfu`'s manifest state machine only advances while the **host** polls: the
/// `dfuMANIFEST-SYNC` `GETSTATUS` is what arms the deferred flush (`f_dfu.c:484-509`),
/// and the gadget's main loop runs it (`common/dfu.c:70-88`), where
/// `xburst_reboot_flush` calls `do_reset()` and never returns
/// (`arch/mips/mach-xburst/dfu.c:260-268`). Send the ZLP and stop polling and the token
/// is armed, the reset never runs, and the box sits in U-Boot — the bug `6bbedf8` was
/// written to fix. So the poll goes out, **the device drops off the bus mid-answer, and
/// that failure is the success signal**. A grace above 0 here would spend
/// minutes waiting for a device that is already gone, which is why reboot's grace
/// is 0.
///
/// # The ZLP's result is checked, and the C's is not
///
/// `dfu.c:779-782` discards the return of `dfu_dnload(dev, iface, 1, NULL, 0)` *and* of
/// the poll after it, then prints `"Reboot triggered"` and returns `TDFU_SUCCESS`: past
/// line 773 `tdfu_dfu_reboot_device` cannot fail. The two discards are not the same
/// thing. The poll's failure is the reset happening. The **ZLP's** failure means the
/// loader never armed at all — the entity buffer only drains when the block size is zero
/// (`drivers/dfu/dfu.c:431-438`), so `dfu_write_medium_virt` validates the token and
/// sets `xburst_reboot_armed` from *that* request's completion
/// (`arch/mips/mach-xburst/dfu.c:206-215`) and from nothing else. A ZLP that stalled
/// leaves a device that will never reset, and it looks identical to success from the
/// outside: the box simply stays in U-Boot. `"Reboot triggered"` would be a lie the user
/// acts on, so the ZLP's result is checked here (2026-08-23) where the C
/// discards it.
///
/// # Errors
/// [`Error::MissingAlt`](crate::Error::MissingAlt) if the loader has no `reboot` alt
/// (the C answers `INVALID_PARAMETER` at `dfu.c:754-758`, and the daemon's mapper must
/// keep that wire string); the transport's error from the
/// descriptors, the claim, `make_idle`, the token, the first poll, **or the ZLP**.
/// Never from the final poll.
pub async fn reboot<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, progress: ProgressSink<'_>) -> Result<()> {
    // A recoverable comms failure *before* the token is armed gets a bus reset
    // and one more attempt, as the C gives it at `dfu.c:1037-1045`. Once the reset has
    // fired this returns success, so the retry never runs against a device that is
    // already on its way down.
    host::reset_and_retry_once(dev, clock, progress, async |_attempt, progress| {
        reboot_once(dev, clock, progress).await
    })
    .await
}

/// One whole attempt: read the descriptors, claim, arm, pump, release.
async fn reboot_once<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, progress: ProgressSink<'_>) -> Result<()> {
    let info = read_info(dev).await?;
    // Before the claim, so a loader without the alt costs nothing on the bus
    // (`dfu.c:754-759`).
    let alt = alt_named(&info, REBOOT_ALT)?;
    // A claim that failed *part way* still has to be undone: `host::claim` sends
    // `SET_INTERFACE` after `claim_interface`, so a stalled alt select leaves the
    // interface held (over WebUSB a stalled `SET_INTERFACE` is exactly that). Releasing
    // an interface that is not claimed is `Ok(())`, so this costs nothing
    // on the paths where nothing was taken.
    if let Err(error) = host::claim(dev, &info, alt).await {
        drop(host::release(dev, info.interface).await);
        return Err(error);
    }

    let outcome = trigger(dev, clock, &info, alt, progress).await;

    // Release on every path — and **discard what it says**, which is the one place this
    // operation differs from its siblings. On the success path the device is *already
    // gone*: `do_reset()` never returns, so from the flush onwards every call answers
    // `NoDevice`, the release included (pinned on the emulator by
    // `the_reboot_flush_takes_the_device_off_the_bus`). Reporting that as the operation's
    // failure would turn every successful reboot into an error. On the failure path the
    // trigger's own error is the answer and a release failure adds nothing.
    drop(host::release(dev, info.interface).await);
    outcome
}

/// The token, the ZLP, and the poll that drives the reset.
///
/// The token transaction carries the stale-transaction retry, and it is what
/// makes the reset above worth having. **A virt entity's block sequence counter survives
/// a bus reset**: `reset` touches no entity. What cleans it is the
/// `SET_CONFIGURATION` the host sends afterwards — and only on a loader that has
/// `f_dfu_abort_transaction`, where it cleans **the alt that was in force**, because
/// `dfu_get_entity(f_dfu->altsetting)` is read at `f_dfu.c:834` two lines before
/// `altsetting` is overwritten at `:836`, and nothing zeroed it in between
/// (`dfu_disable` clears `f_dfu->config` alone, `:851-860`).
///
/// So on an older loader a reset retry after a failed ZLP re-sends block 0 into an
/// entity that is still expecting block 1, U-Boot refuses it, and the refusal shows up as
/// `dfuERROR` on the poll rather than as a stall on the `DNLOAD`
/// (`drivers/dfu/dfu.c:384-390` then `f_dfu.c:161-166`). That refusal cleans the entity on
/// its way out, so one `make_idle` and one re-sent token recover it — without which the
/// reset is the decoration the C admits it is at `dfu.c:141-145`. On a fixed loader the
/// re-enumeration has already cleaned the `reboot` entity and the re-sent token is taken
/// first time; the retry costs nothing there and is what makes the older generation work.
async fn trigger<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    info: &DfuInfo,
    alt: u8,
    progress: ProgressSink<'_>,
) -> Result<()> {
    host::retry_stale_block0(dev, info.interface, progress, async |transaction, progress| {
        progress(Progress::Note(rebooting_note(alt)));

        host::dnload(dev, info.interface, 0, REBOOT_TOKEN).await?;
        host::poll_until_ready(dev, clock, info.interface, Grace::None).await?;
        // The loader has taken block 0; nothing after this may be re-sent.
        transaction.first_block_done();

        // **Checked**, where the C discards it. This is the request that arms the loader, and a
        // failure here means it never happened.
        host::dnload(dev, info.interface, 1, &[]).await?;

        // And this one is meant to fail. Its error is deliberately not
        // propagated — but its *success* is not silently swallowed either. A poll that
        // comes back `dfuIDLE` proves the reset did not run: the deferred flush is only
        // cleared after `dfu_flush` returns (`common/dfu.c:82-83`) and `do_reset()` does
        // not return, so a device on its way down can never answer this. Saying so costs
        // nothing and is the difference between "it rebooted" and "it said it would".
        match host::poll_until_ready(dev, clock, info.interface, Grace::None).await {
            Err(_) => progress(Progress::Note(TRIGGERED_NOTE.to_owned())),
            Ok(status) => progress(Progress::Note(still_here_note(status.state))),
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use tdfu_usb::gadget::{AltConfig, FakeGadget, Fault, GadgetConfig, When};
    use tdfu_usb::mock::{Call, MockError, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{
        ControlIn, ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind,
        pid, vid,
    };

    use super::{TRIGGERED_NOTE, reboot, rebooting_note, still_here_note};
    use crate::clock::RecordingClock;
    use crate::dfu::host::{
        self, CONTROL_TIMEOUT, DNLOAD_TIMEOUT, GRACE_BACKOFF, Grace, POST_RESET_SETTLE, State, request,
    };
    use crate::dfu::{REBOOT_ALT, REBOOT_TOKEN};
    use crate::error::Error;
    use crate::progress::Progress;

    type Fallible = Result<(), Box<dyn core::error::Error>>;

    /// The bench T32LQ's flash: 16 MiB of SPI-NOR.
    const FLASH_SIZE: u64 = 16 * 1024 * 1024;

    /// What [`rebooting_note`] says for the T32LQ's reboot alt, **as text**.
    ///
    /// Spelt out rather than called: a test that asserts a formatter against itself
    /// pins nothing, and replacing the whole function body with `String::new()`
    /// survived until this constant existed.
    const REBOOTING_ALT_2: &str = "Rebooting the device (alt 2)...";

    /// A pace no test can confuse with [`GRACE_BACKOFF`], and one that does **not** fit
    /// in 16 bits: `bwPollTimeout` is a 24-bit field and every test in an earlier
    /// implementation used a value whose high byte was zero, which made `<< 16` and
    /// `>> 16` indistinguishable.
    const VIRT_PACE_MS: u32 = 0x0001_2345;

    /// The three lines a user actually reads, pinned as text.
    ///
    /// Byte-identical output with the C is no longer a goal, which is exactly why
    /// these are ours to keep stable, and why a test rather than the C is what keeps them.
    /// The second alt is not padding: without one that is not 2, a formatter that ignored
    /// its argument would pass.
    /// A claim that fails **after** `claim_interface` — a stalled `SET_INTERFACE`, which
    /// is the WebUSB case — must not leave the interface held. `AccessDenied` so the
    /// reset cannot paper over it with a second attempt that would release on
    /// its own way out.
    #[test]
    fn a_claim_that_fails_half_way_still_releases() {
        let gadget = FakeGadget::t32lq();
        let clock = RecordingClock::new();
        gadget.inject(When::SetAlt, Fault::AccessDenied);

        let outcome = block_on(reboot(&gadget, &clock, &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(gadget.claimed(), None, "the interface was given back");
        assert_eq!(gadget.reboots(), 0, "and the device is still on the bus");
    }

    #[test]
    fn op_reboot_notes_are_the_lines_the_user_reads() {
        assert_eq!(rebooting_note(2), REBOOTING_ALT_2);
        assert_eq!(rebooting_note(9), "Rebooting the device (alt 9)...");
        assert_eq!(TRIGGERED_NOTE, "Reboot triggered");
        assert_eq!(
            still_here_note(State::DfuIdle),
            "the device answered the post-reset poll in dfuIDLE instead of leaving the bus — \
             the reboot token was accepted but the board may still be sitting in U-Boot"
        );
    }

    /// A U-Boot DFU gadget as enumeration sees it.
    fn gadget_descriptors() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(crate::dfu::descriptors::fixtures::T32LQ_CONFIG)
    }

    /// One `GET_DESCRIPTOR`.
    fn get_descriptor(value: u16, langid: u16, len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x06,
            value,
            index: langid,
            len,
        })
    }

    /// One UTF-16LE string descriptor, as a device answers it.
    fn string_descriptor(text: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8, 0x03];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes[0] = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        bytes
    }

    /// The five descriptor reads `read_info` makes of the captured T32LQ.
    fn script_read_info(mut mock: MockTransport) -> MockTransport {
        let config = crate::dfu::descriptors::fixtures::T32LQ_CONFIG;
        let total = u16::try_from(config.len()).unwrap_or_default();
        mock = mock
            .expecting(get_descriptor(0x0200, 0, 9), Reply::Data(config[..9].to_vec()))
            .expecting(get_descriptor(0x0200, 0, total), Reply::Data(config.to_vec()));
        for (index, name) in [(5_u8, "flash"), (6, "erase"), (7, "reboot")] {
            mock = mock.expecting(
                get_descriptor(0x0300 | u16::from(index), 0x0409, 256),
                Reply::Data(string_descriptor(name)),
            );
        }
        mock
    }

    /// The six bytes a `GETSTATUS` answers.
    fn status_reply(state: State) -> Reply {
        Reply::Data(vec![0, 0, 0, 0, state.code(), 0])
    }

    /// What a device that has left the bus answers: everything, including the release.
    fn gone(request: u8) -> Reply {
        Reply::Fail(UsbError::new(
            UsbErrorKind::NoDevice,
            Pipe::Control {
                direction: tdfu_usb::Direction::In,
                request,
            },
        ))
    }

    /// A class IN request on the DFU interface.
    fn class_in(request: u8, value: u16, len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value,
            index: 0,
            len,
        })
    }

    /// A class OUT request on the DFU interface.
    fn class_out(request: u8, value: u16, data: &[u8]) -> Call {
        Call::control_out(ControlOut {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value,
            index: 0,
            data,
        })
    }

    /// Collect everything an operation says.
    fn record(sink: &mut Vec<Progress>) -> impl FnMut(Progress) {
        move |progress| sink.push(progress)
    }

    /// Every [`Progress::Note`] an operation emitted, in order.
    fn notes(said: &[Progress]) -> Vec<&str> {
        said.iter()
            .filter_map(|step| match step {
                Progress::Note(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// **The pin.** The exact requests a reboot makes, in order, with their deadlines.
    ///
    /// The device stops answering from the post-ZLP poll onwards, which is what a reboot
    /// is, and the operation still succeeds. The release goes out anyway and its
    /// `NoDevice` is discarded.
    #[test]
    fn op_reboot_sequence() -> Result<(), MockError> {
        let mut mock = script_read_info(MockTransport::new(gadget_descriptors()).configured(1));
        mock = mock
            // Claim, and select the `reboot` alt by name (`dfu.c:754-761`).
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 2 }, Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            // The token, then the poll it needs (`dfu.c:768-773`).
            .expecting(class_out(request::DNLOAD, 0, REBOOT_TOKEN), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            // The ZLP that arms the loader, then the poll that drives the reset
            // (`dfu.c:779-780`) — and the device goes away mid-answer.
            .expecting(class_out(request::DNLOAD, 1, &[]), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), gone(request::GETSTATUS))
            .expecting(Call::ReleaseInterface(0), gone(0));

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&mock, &clock, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("a reboot that worked reported a failure: {error}")))?;

        assert_eq!(notes(&said), vec![REBOOTING_ALT_2, TRIGGERED_NOTE]);

        // Both `DNLOAD`s get 30 s, everything else 5 s.
        for Recorded { call, timeout, .. } in mock.calls() {
            let want = match call {
                Call::ControlOut { request, .. } if request == request::DNLOAD => Some(DNLOAD_TIMEOUT),
                Call::ControlIn { .. } | Call::ControlOut { .. } => Some(CONTROL_TIMEOUT),
                _ => None,
            };
            assert_eq!(timeout, want, "wrong deadline on {call:?}");
        }
        // Reboot's grace is 0, so the poll that failed failed at once
        // instead of being forgiven 36 times at 500 ms apiece.
        assert!(clock.slept().is_empty(), "{:?}", clock.slept());
        mock.verify()
    }

    /// **The pin the post-ZLP poll exists for: that poll is what reboots the box.**
    ///
    /// Both halves are asserted, because only the pair says anything. With the poll, the
    /// gadget's flush runs and the device leaves the bus. Without it — the same token,
    /// the same ZLP, and then nothing — the loader is armed and the board sits in U-Boot,
    /// which is the bug this poll was added to fix (`6bbedf8`, HW T40XP).
    #[test]
    fn op_reboot_polls_after_zlp() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_virt_poll_timeout_ms(VIRT_PACE_MS));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.reboots(), 1, "the loader's reboot flush never ran");
        assert!(gadget.is_gone(), "the device is still on the bus");
        assert_eq!(notes(&said), vec![REBOOTING_ALT_2, TRIGGERED_NOTE]);

        // The last thing sent was a `GETSTATUS`, and the reset happened during it — not
        // on the `DNLOAD` before it.
        let requests = gadget.class_requests();
        assert_eq!(
            requests.last().map(|(request, _)| *request),
            Some(request::GETSTATUS),
            "{requests:?}"
        );
        let zlp = requests
            .iter()
            .position(|entry| *entry == (request::DNLOAD, 1))
            .ok_or("no zero-length DNLOAD was sent")?;
        assert!(zlp + 1 < requests.len(), "nothing polled after the ZLP: {requests:?}");

        // The counterfactual: arm it and stop, and nothing happens.
        let unpolled = FakeGadget::t32lq();
        block_on(host::claim(&unpolled, &block_on(crate::dfu::read_info(&unpolled))?, 2))?;
        block_on(host::make_idle(&unpolled, 0))?;
        block_on(host::dnload(&unpolled, 0, 0, REBOOT_TOKEN))?;
        block_on(host::get_status(&unpolled, 0))?;
        block_on(host::dnload(&unpolled, 0, 1, &[]))?;
        assert_eq!(unpolled.entity_armed(2), Some(true), "the ZLP did not arm the loader");
        assert_eq!(unpolled.reboots(), 0, "it reset without being polled");
        assert!(!unpolled.is_gone(), "it left the bus without being polled");
        Ok(())
    }

    /// **A `DNLOAD` ZLP that fails is fatal, and says nothing about a
    /// reboot.**
    ///
    /// The C discards it (`dfu.c:779`) and prints `"Reboot triggered"` two lines later
    /// whatever happened. The ZLP is the request whose completion drains the entity
    /// buffer and validates the token, so a ZLP that never landed leaves the loader
    /// unarmed — and an unarmed loader looks exactly like a successful reboot from the
    /// outside, because both leave the box in U-Boot.
    #[test]
    fn op_reboot_fails_when_the_zlp_fails() -> Fallible {
        let gadget = FakeGadget::t32lq();
        // Twice: once for each of the two reset attempts.
        gadget.inject_times(When::ClassBlock(request::DNLOAD, 1), Fault::Stall, 2);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(reboot(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a stalled ZLP reported a successful reboot")?;

        assert!(matches!(error, Error::Usb(_)), "{error}");
        assert_eq!(gadget.reboots(), 0);
        assert!(!gadget.is_gone(), "nothing reset, and nothing should have");
        assert_eq!(gadget.entity_armed(2), Some(false), "the loader armed without a ZLP");
        assert!(
            !notes(&said).contains(&TRIGGERED_NOTE),
            "it announced a reboot that never happened: {:?}",
            notes(&said)
        );
        assert_eq!(gadget.claimed(), None, "the interface was left claimed after a failure");
        Ok(())
    }

    /// A ZLP that stalls once is still in the recoverable class: reset, retry,
    /// and the box goes down on the second attempt.
    #[test]
    fn op_reboot_retries_a_stalled_zlp_once() -> Fallible {
        let gadget = FakeGadget::t32lq();
        gadget.inject(When::ClassBlock(request::DNLOAD, 1), Fault::Stall);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.resets(), 1);
        assert!(clock.slept().contains(&POST_RESET_SETTLE), "{:?}", clock.slept());
        assert_eq!(gadget.reboots(), 1);
        assert!(
            notes(&said).iter().any(|note| note.contains("USB-reset")),
            "the retry was silent: {:?}",
            notes(&said)
        );
        assert!(notes(&said).contains(&TRIGGERED_NOTE));
        Ok(())
    }

    /// **A device that answers the post-reset poll did not reboot, and is told so.**
    ///
    /// The C cannot distinguish this from success and prints `"Reboot triggered"` either
    /// way. It is distinguishable: the deferred flush is only cleared *after* `dfu_flush`
    /// returns (`common/dfu.c:82-83`) and `do_reset()` does not return, so a device on
    /// its way down can never answer this poll with `dfuIDLE`.
    ///
    /// The operation still succeeds — the token was accepted and the ZLP landed, which is
    /// everything the host can prove, and no bench run has yet shown a loader that
    /// answers here *and* resets. What changes is that the user is told, instead of being
    /// sent to look for a board that never moved.
    #[test]
    fn op_reboot_says_so_when_the_device_stays() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", FLASH_SIZE),
            AltConfig::erase(),
            // A `reboot` alt that takes the token and resets nothing.
            AltConfig::flash("reboot", FLASH_SIZE),
        ]));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.reboots(), 0);
        assert!(!gadget.is_gone());
        let said_notes = notes(&said);
        assert!(
            !said_notes.contains(&TRIGGERED_NOTE),
            "it claimed a reboot that did not happen: {said_notes:?}"
        );
        assert!(
            said_notes
                .iter()
                .any(|note| note.contains("may still be sitting in U-Boot")),
            "it said nothing about a device that never left: {said_notes:?}"
        );
        // Still on the bus, so the release really released.
        assert_eq!(gadget.claimed(), None);
        Ok(())
    }

    /// The `NoDevice` every call answers after a successful reboot — the release
    /// included — is the success path's own footprint and is not reported as a failure.
    #[test]
    fn op_reboot_swallows_the_release_after_the_device_goes() -> Fallible {
        let gadget = FakeGadget::t32lq();
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&gadget, &clock, &mut record(&mut said)))?;

        assert!(gadget.is_gone());
        // The release was attempted, and the device refused it.
        assert!(
            block_on(<FakeGadget as tdfu_usb::LocalUsbTransport>::release_interface(
                &gadget, 0
            ))
            .is_err(),
            "a device off the bus accepted a release"
        );
        assert!(notes(&said).contains(&TRIGGERED_NOTE));
        Ok(())
    }

    /// Reboot's grace is **0**.
    ///
    /// With [`Grace::Erase`] the post-ZLP poll would forgive 36 lost `GETSTATUS`
    /// transfers at [`GRACE_BACKOFF`] apiece before admitting the device had gone —
    /// three minutes of waiting for a board that rebooted immediately. The device's own
    /// pace is set to something that is neither 500 ms nor a 16-bit value, so a
    /// `GRACE_BACKOFF` in the log can only have come from the grace.
    #[test]
    fn op_reboot_grace_is_zero() -> Fallible {
        let gadget = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_virt_poll_timeout_ms(VIRT_PACE_MS)
                .with_manifest_hold_polls(2),
        );
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(reboot(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(Grace::None.retries(), 0);
        let slept = clock.slept();
        assert!(
            !slept.contains(&GRACE_BACKOFF),
            "a lost poll was forgiven where the loss IS the answer: {slept:?}"
        );
        // What it did wait for is the device's own 24-bit `bwPollTimeout`.
        assert!(
            slept
                .iter()
                .all(|waited| *waited == core::time::Duration::from_millis(u64::from(VIRT_PACE_MS))),
            "{slept:?}"
        );
        assert!(gadget.is_gone());
        Ok(())
    }

    /// A loader with no `reboot` alt fails before it touches the bus (`dfu.c:754-758`).
    #[test]
    fn op_reboot_without_the_alt_claims_nothing() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", FLASH_SIZE),
            AltConfig::erase(),
        ]));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(reboot(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a loader with no reboot alt rebooted something")?;

        assert!(matches!(error, Error::MissingAlt(REBOOT_ALT)), "{error}");
        assert_eq!(
            error.to_string(),
            "the loader has no alt named \"reboot\": update the DFU loader firmware"
        );
        assert!(!error.is_recoverable());
        assert_eq!(gadget.resets(), 0);
        assert_eq!(gadget.claimed(), None);
        assert!(said.is_empty(), "it announced a reboot it never started");
        assert_eq!(gadget.reboots(), 0);
        Ok(())
    }

    /// A failure before the token leaves nothing claimed and nothing armed.
    #[test]
    fn op_reboot_releases_on_every_path() -> Fallible {
        let gadget = FakeGadget::t32lq();
        // Four times over: two reset attempts, each with two block-0
        // attempts. Nothing is left to recover with.
        gadget.inject_times(When::ClassBlock(request::DNLOAD, 0), Fault::Stall, 4);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(reboot(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a stalled token reported a successful reboot")?;
        assert!(matches!(error, Error::Usb(_)), "{error}");
        assert_eq!(gadget.claimed(), None, "the interface was left claimed after a failure");
        assert_eq!(gadget.entity_armed(2), Some(false));
        assert_eq!(gadget.reboots(), 0);
        assert!(!notes(&said).contains(&TRIGGERED_NOTE));
        Ok(())
    }

    /// A failure a reset cannot fix is not reset, and the message survives.
    #[test]
    fn op_reboot_does_not_reset_what_a_reset_cannot_fix() -> Fallible {
        let mock = MockTransport::new(gadget_descriptors()).expecting(
            get_descriptor(0x0200, 0, 9),
            Reply::Fail(UsbError::new(
                UsbErrorKind::AccessDenied,
                Pipe::Control {
                    direction: tdfu_usb::Direction::In,
                    request: 0x06,
                },
            )),
        );
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(reboot(&mock, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a refused device rebooted fine")?;
        assert!(!error.is_recoverable(), "{error}");
        assert!(
            !mock.calls().iter().any(|recorded| recorded.call == Call::Reset),
            "a device the OS refused to open was bus-reset"
        );
        assert!(said.is_empty());
        mock.verify().map_err(Box::from)
    }
}
