//! Wipe the whole boot flash.
//!
//! Routing a wipe-token `CMD_WRITE` to this operation rather than to the
//! generic download is the daemon's own decision, and it has its own pin
//! (`fe_daemon_routes_erase_token`). What that decision needs from this
//! file is that
//! [`erase`] is the only way to run the sequence, and it is.

use tdfu_usb::LocalUsbTransport;

use crate::clock::Sleeper;
use crate::dfu::alt::resolve;
use crate::dfu::descriptors::read_info;
use crate::dfu::host::{self, Grace, State, Status};
use crate::dfu::{ERASE_ALT, ERASE_TOKEN};
use crate::error::{Error, Result};
use crate::model::{AltSel, DEFAULT_TRANSFER_SIZE, DfuInfo};
use crate::progress::{Phase, Progress, ProgressSink};

/// The alt the blank check reads back.
///
/// Alt 0 is the boot flash on every loader we ship
/// (`arch/mips/mach-xburst/dfu.c:393-397` builds `dfu_alt_info` as `<ifc>=flash raw 0x0 <size>&virt
/// 0=erase&virt 1=reboot`), which is the same convention the read and write paths' "no `--alt` → the
/// first alt" default rests on. The C names it in the same words at `dfu.c:639-641`.
///
/// **Two rules, one flash, and they agree by construction rather than by assertion.**
/// The transfer ops reach the same entity *by name* through the CLI's alt default —
/// [`dfu::FLASH_ALT`](crate::dfu::FLASH_ALT) first, else the only alt
/// ([`dfu::alt::resolve`](crate::dfu::alt::resolve)) — while the blank check addresses
/// it by index, because it must read the medium the wipe cleared even on a loader whose
/// first alt is not called `flash`. On every shipped loader the two are the same alt.
/// They are allowed to differ: a loader that named its boot flash something else would
/// still blank-check alt 0 and still be right, which is why this is a constant here and
/// a name there. The pairing is recorded rather than enforced because enforcing it would
/// mean this file resolving a name it does not need.
const BOOT_FLASH_ALT: u8 = 0;

/// The most bytes one blank-check probe asks for (`dfu.c:632-634`).
const BLANK_CHECK_MAX: u16 = 4096;

/// What an erased NOR or NAND cell reads back as.
const ERASED_BYTE: u8 = 0xFF;

/// The line that says the wipe is under way (`dfu.c:719`).
fn erasing_note(alt: u8) -> String {
    format!("Erasing the whole flash (alt {alt})... this takes a while")
}

/// The line that says the wipe happened **and was proven** (`dfu.c:742`).
const COMPLETE_NOTE: &str = "Erase complete (verified blank)";

/// Erase the whole boot flash, and prove it.
///
/// The sequence, against the alt named
/// [`erase`](crate::dfu::ERASE_ALT): claim it, [`make_idle`](host::make_idle),
/// `DNLOAD` block 0 carrying [`ERASE_TOKEN`](crate::dfu::ERASE_TOKEN), poll, the
/// zero-length `DNLOAD` that ends the transfer, poll again — both polls with
/// [`Grace::Erase`](crate::dfu::Grace::Erase) — and then the **blank check**.
///
/// # Why the grace tier is the whole difficulty
///
/// The loader validates the token in the `DNLOAD`'s completion and does the wipe in the
/// *manifest* phase, from the deferred flush in the gadget's main loop
/// (`arch/mips/mach-xburst/dfu.c:197-253`). That flush blocks the loop, so
/// EP0 goes silent for as long as the chip takes — seconds on a blank T40XP NAND,
/// three and a half minutes on a programmed 16 MiB NOR — while the fork holds
/// `dfuMANIFEST` and asks the host to re-poll every 500 ms (`f_dfu.c:511-549`).
/// [`Grace::Erase`](crate::dfu::Grace::Erase) forgives 36 consecutive
/// lost polls for exactly this. Failing on the first swallowed poll is not a
/// conservative choice: it drops into the bus reset, whose retry lands on a
/// device that is *still erasing*, and the C documents what that costs at
/// `libtdfu/src/dfu/dfu.c:141-145`.
///
/// # A manifest that returns OK is necessary, not sufficient
///
/// The blank check reads `min(wTransferSize, 4096)` bytes back off alt 0
/// and requires every one of them to be [`0xFF`](ERASED_BYTE). It is not belt-and-braces
/// — the loader has a path that reports a clean manifest having erased **nothing**:
/// `xburst_erase_flush` returns 0 when the arming flag is not set
/// (`arch/mips/mach-xburst/dfu.c:238-239`), the arming is dropped by *any* failed or
/// aborted transaction on the virt entity (`:290-296`), and the manifest's outcome never
/// reaches the host anyway — `f_dfu.c:530-539` flips to `dfuIDLE` and answers
/// `bStatus = OK` as soon as the deferred flush clears, whatever `flush_medium`
/// returned. A write that lands on flash that was never erased is the failure this
/// check exists to prevent.
///
/// # Errors
/// [`Error::MissingAlt`](crate::Error::MissingAlt) if the loader has no `erase` alt
/// (pre-erase builds; the C answers `INVALID_PARAMETER` at `dfu.c:706-708` and the
/// daemon's mapper must keep that wire string);
/// [`Error::Verify`](crate::Error::Verify) naming the first non-`0xFF` offset if the
/// flash is not blank; [`Error::Protocol`](crate::Error::Protocol) if the manifest
/// settles in `dfuERROR` or the probe reads nothing back; otherwise the transport's
/// error.
pub async fn erase<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, progress: ProgressSink<'_>) -> Result<()> {
    // Erase is idempotent, so it gets the reset-and-retry, as
    // the C gives it at `dfu.c:1018-1025`. The two failures it cannot bury are the two
    // that matter: `Error::MissingAlt` and `Error::Verify` are both outside
    // `is_recoverable`, so a loader with no erase alt and a chip that came back
    // non-blank each fail once, without a bus reset and without a second wipe.
    host::reset_and_retry_once(dev, clock, progress, async |_attempt, progress| {
        erase_once(dev, clock, progress).await
    })
    .await
}

/// One whole attempt: read the descriptors, claim, wipe, blank-check, release.
///
/// The claim is inside the attempt because the reset drops the configuration
/// and the claim with it (USB 9.1.1.5), so a retry has to make its own.
async fn erase_once<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, progress: ProgressSink<'_>) -> Result<()> {
    let info = read_info(dev).await?;
    // Before the claim, so a loader without the alt costs nothing on the bus — the C
    // does the same at `dfu.c:705-712`.
    let alt = alt_named(&info, ERASE_ALT)?;
    // A claim that failed *part way* still has to be undone: `host::claim` sends
    // `SET_INTERFACE` after `claim_interface`, so a stalled alt select leaves the
    // interface held (over WebUSB a stalled `SET_INTERFACE` is exactly that). Releasing
    // an interface that is not claimed is `Ok(())`, so this costs nothing
    // on the paths where nothing was taken.
    if let Err(error) = host::claim(dev, &info, alt).await {
        drop(host::release(dev, info.interface).await);
        return Err(error);
    }

    let outcome = wipe(dev, clock, &info, alt, progress).await;
    // Release on **every** path out, including the failing ones: this is stricter than
    // what the C does, deliberately, and an interface
    // still claimed is what makes the next operation's claim fail. The wipe's own error
    // outranks a release failure, which is only interesting when nothing else went
    // wrong.
    let released = host::release(dev, info.interface).await;
    outcome?;
    released
}

/// The token, the two polls and the proof.
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
/// So on an older loader a reset retry after a failure past the token re-sends
/// block 0 into an entity that is still expecting block 1, and U-Boot refuses it — the
/// C's own `dfu.c:141-145`, "re-sent token refused as bad token", the reason it calls
/// that reset harmful. The refusal cleans the entity on its way out
/// (`drivers/dfu/dfu.c:384-390`), so one `make_idle` and one re-sent token recover it.
/// On a fixed loader the re-enumeration has already cleaned the `erase` entity and the
/// re-send is taken first time. Both are pinned:
/// [`op_erase_recovers_a_reset_after_the_token`](tests::op_erase_recovers_a_reset_after_the_token)
/// and its `_on_a_legacy_loader` twin.
async fn wipe<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    info: &DfuInfo,
    alt: u8,
    progress: ProgressSink<'_>,
) -> Result<()> {
    host::retry_stale_block0(dev, info.interface, progress, async |transaction, progress| {
        progress(Progress::Phase(Phase::Erase));
        progress(Progress::Note(erasing_note(alt)));
        // The same shape as a write's opening line, because on the wire it is the same
        // thing: a download to an alt. The remote path drives an erase as exactly that
        // (`dfu.c:567` narrated it the same way), and a token that went to the wrong alt
        // is the failure this line exists to make obvious.
        progress(Progress::Debug(super::write::download_line(
            alt,
            crate::bootrom::as_u64(ERASE_TOKEN.len()),
            usize::from(match info.transfer_size {
                // The 1024 substitution, as `write` makes it: the block size a
                // download would use, not the token's own length.
                0 => DEFAULT_TRANSFER_SIZE,
                size => size,
            }),
        )));

        host::dnload(dev, info.interface, 0, ERASE_TOKEN).await?;
        host::poll_until_ready_narrated(dev, clock, info.interface, Grace::Erase, &mut *progress).await?;
        // The loader has taken block 0. Everything past here is a live wipe, not a
        // stale transaction, and must not be re-sent (an explicit flag —
        // never `block == 0`, which the counter wraps through).
        transaction.first_block_done();

        // The zero-length `DNLOAD` ends the transfer. It is also where the loader first
        // *sees* the token: the entity buffer only drains when the block size is zero
        // (`drivers/dfu/dfu.c:431-438`), so `dfu_write_medium_virt` — and its arming,
        // and its refusal of a garbled token — all run from this request's completion,
        // not from the one that carried the bytes.
        host::dnload(dev, info.interface, 1, &[]).await?;
        // And *this* poll is the one that waits: the manifest flush is armed by the
        // `dfuMANIFEST-SYNC` GETSTATUS (`f_dfu.c:484-509`), so the host's own polling is
        // what drives the erase to completion.
        let status = host::poll_until_ready_narrated(dev, clock, info.interface, Grace::Erase, &mut *progress).await?;
        manifest_settled(status)
    })
    .await?;

    blank_check(dev, info, progress).await?;
    progress(Progress::Note(COMPLETE_NOTE.to_owned()));
    Ok(())
}

/// The device's own verdict on the manifest (`dfu.c:735-738`).
///
/// The C tests `bStatus != OK || bState == dfuERROR`. Only the second half is here,
/// because [`poll_until_ready`](host::poll_until_ready) already refuses a non-zero
/// `bStatus` and names which one it was — repeating the test would add a branch no test
/// could ever take.
///
/// The half that remains is reachable, and not only in theory: `f_dfu`'s per-state
/// default arms set `dfu_state = dfuERROR` **without touching `dfu_status`**
/// (`f_dfu.c:393-396`, `:543-546`, `:584-587`), so a device that stalled a request it
/// was not ready for reports `dfuERROR` with `bStatus` still OK.
fn manifest_settled(status: Status) -> Result<()> {
    if status.state == State::Error {
        return Err(Error::Protocol(format!(
            "the erase manifest ended in {}: the loader refused the wipe token",
            status.state
        )));
    }
    Ok(())
}

/// Read block 0 of the boot flash back and require it erased.
///
/// The upload length is `min(wTransferSize, 4096)` **except** that a `wTransferSize` of
/// 0 means 4096 rather than nothing: the plain arithmetic yields 0 there and
/// `dfu.c:632` substitutes, which is the reading this follows.
/// It is unreachable through the parser, which substitutes 1024 for a missing or
/// zero functional descriptor, so this is the C being right about a case its own
/// caller cannot produce.
///
/// **The probe is wrapped in the stale-transaction retry, which the C does not
/// do here.** `dfu_erase_blank_check` calls `dfu_upload_block` once (`dfu.c:645-646`);
/// if alt 0's entity was left mid-transaction by an earlier read, block 0 is refused as
/// a wrong sequence number, the whole erase returns an error, and the *manager's*
/// fallback is a USB reset — the case the C documents as harmful at
/// `libtdfu/src/dfu/dfu.c:141-145`. One `CLRSTATUS` and one re-read cost nothing and
/// remove the reason to reset.
async fn blank_check<T: LocalUsbTransport>(dev: &T, info: &DfuInfo, progress: ProgressSink<'_>) -> Result<()> {
    let len = probe_len(info.transfer_size);
    // The C re-claims here too (`dfu.c:641`), and the `SET_INTERFACE` is the point: the
    // erase alt is still selected, and reading block 0 off *it* would read the virt
    // entity rather than the flash.
    host::claim(dev, info, BOOT_FLASH_ALT).await?;

    let outcome = host::retry_stale_block0(dev, info.interface, progress, async |transaction, _progress| {
        let block = host::upload(dev, info.interface, 0, len).await?;
        // The device took block 0, so nothing after this is a stale transaction and the
        // verdict below must not be retried. The explicit flag, for the same
        // reason: `block == 0` is a value the counter wraps back through.
        transaction.first_block_done();
        require_blank(&block)
    })
    .await;

    match outcome {
        Ok(()) => {
            close_probe(dev, info.interface, len).await;
            Ok(())
        }
        // `dfu.c:686-687`: a failed check still closes its transaction.
        Err(err) => {
            drop(host::abort(dev, info.interface).await);
            Err(err)
        }
    }
}

/// Every byte `0xFF`, or say where it was not.
///
/// The C logs `flash not blank at offset %d (0x%02X)` and returns a bare
/// `TDFU_ERROR_VERIFY` (`dfu.c:653-658`), so the offset it computed reaches a log line
/// and never the caller. [`Error::Verify`](crate::Error::Verify) carries it.
///
/// An empty answer is [`Error::Protocol`](crate::Error::Protocol), as the C's
/// `got <= 0` is (`dfu.c:648-649`) — a device that returned no bytes has said nothing
/// about the flash, and treating "no evidence" as "blank" is the whole failure this
/// function exists to prevent.
fn require_blank(block: &[u8]) -> Result<()> {
    if block.is_empty() {
        return Err(Error::Protocol(
            "the blank check read no bytes back, so the erase is unproven".to_owned(),
        ));
    }
    // Counted in `u64` from the start rather than cast from a `usize` index: the offset
    // is what a caller acts on, and a fallible conversion with an unreachable arm would
    // be an untestable branch in the one function whose whole job is to be believed.
    for (offset, &actual) in (0_u64..).zip(block) {
        if actual != ERASED_BYTE {
            return Err(Error::Verify {
                offset,
                expected: ERASED_BYTE,
                // Always `Some` here: this branch only runs on a byte the device sent.
                // `None` is the short-answer case, which the blank check reaches as
                // `Error::Protocol` instead — an upload that ended early has said
                // nothing about the flash, not something wrong about one byte of it.
                actual: Some(actual),
            });
        }
    }
    Ok(())
}

/// Leave the loader's entity clean after the probe.
///
/// A one-block upload leaves U-Boot's read transaction inited with the sequence counter
/// at 1, and **that survives `DFU_ABORT` and a USB reset** on older loaders.
/// What `ABORT` does about it is the one difference between the two loader
/// generations, so the close-out asks rather than assumes:
///
/// * a loader with u-boot `3d4848fe0dc` cleans the entity on `ABORT`, so the re-probe
///   reads block 0 of a fresh transaction and succeeds — and a second `ABORT` closes
///   that one too;
/// * an older loader keeps the counter, so the re-probe's block 0 is refused as a wrong
///   sequence number. That refusal is itself the self-heal: `dfu_read` cleans the
///   transaction on a mismatch (`drivers/dfu/dfu.c:508-517`) and the cost is one benign
///   `Wrong sequence number! [1] [0]` line on the loader console. `CLRSTATUS` clears the
///   stall it left on the host side.
///
/// Either way the entity is pristine when this returns, which is what the *next*
/// operation needs — without it a following write or read pays a stale-transaction
/// retry it did not earn. Bench evidence for both branches: a fixed T40XP logged zero
/// wrong-sequence lines, an old T23 logged exactly one, and both flows were green.
///
/// **Every result here is deliberately discarded** (as at `dfu.c:679-688`). These are
/// recovery requests, not commands: the erase has already been proven by the time they
/// run, and failing a verified wipe because a tidy-up `ABORT` stalled would report a
/// disaster where there was none.
async fn close_probe<T: LocalUsbTransport>(dev: &T, interface: u8, len: u16) {
    drop(host::abort(dev, interface).await);
    if host::upload(dev, interface, 0, len).await.is_ok() {
        drop(host::abort(dev, interface).await);
    } else {
        drop(host::clr_status(dev, interface).await);
    }
}

/// How many bytes one blank-check probe asks for (`dfu.c:632-634`).
///
/// `cargo mutants` reports `>` → `>=` here as surviving, and it is an **equivalent
/// mutant, not a hole**: the only input the two operators disagree on is
/// [`BLANK_CHECK_MAX`] itself, where one arm returns `transfer_size` and the other
/// returns `BLANK_CHECK_MAX` — the same 4096. No test can separate them because there is
/// nothing to separate, and the boundary is covered by
/// `op_erase_blank_check_length`. Do not chase the score to zero.
const fn probe_len(transfer_size: u16) -> u16 {
    if transfer_size == 0 || transfer_size > BLANK_CHECK_MAX {
        return BLANK_CHECK_MAX;
    }
    transfer_size
}

/// The `bAlternateSetting` of a **virtual** alt, by the name the loader gives it.
///
/// One call into [`dfu::alt::resolve`](crate::dfu::alt::resolve), which is the single
/// home for the alt selection rules and the same function `write`, `read` and `verify` go
/// through. What differs here is the *failure*, and the mapping is **total**: every error
/// `resolve` can raise becomes [`Error::MissingAlt`](crate::Error::MissingAlt) and its
/// text is discarded, not just the one about a name that is not there. That is
/// deliberate rather than lax, because the name is a compile-time constant: `resolve`
/// answers [`Error::Invalid`](crate::Error::Invalid) naming the alts the device does
/// offer, which is the right answer for an alt a **user typed**, and the wrong one for
/// these two.
/// `erase` and `reboot` are compile-time constants, so a device without them is not a
/// typo — it is a loader built before `a73e4da`, and the actionable half is the C's own
/// `"update the DFU loader firmware"` (`dfu.c:707`, `:756`), which is what
/// [`Error::MissingAlt`](crate::Error::MissingAlt) renders. It also keeps the variant
/// the daemon's wire mapper needs, where both C sites answer
/// `TDFU_ERROR_INVALID_PARAMETER`.
///
/// `resolve`'s decimal fallback (`dfu.c:517-524`) is unreachable from here: neither
/// constant parses as a number.
pub(super) fn alt_named(info: &DfuInfo, name: &'static str) -> Result<u8> {
    resolve(info, &AltSel::Name(name.to_owned())).map_err(|_| Error::MissingAlt(name))
}

#[cfg(test)]
mod tests {
    use tdfu_usb::gadget::{AltConfig, DfuState, Event, FakeGadget, Fault, GadgetConfig, Loader, When};
    use tdfu_usb::mock::{Call, MockError, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{
        ControlIn, ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind,
        pid, vid,
    };

    use super::{
        AltSel, BLANK_CHECK_MAX, COMPLETE_NOTE, ERASED_BYTE, alt_named, erase, erasing_note, manifest_settled,
        probe_len, require_blank, resolve,
    };
    use crate::clock::RecordingClock;
    use crate::dfu::host::{
        self, CONTROL_TIMEOUT, DNLOAD_TIMEOUT, GRACE_BACKOFF, Grace, POST_RESET_SETTLE, State, request,
    };
    use crate::dfu::{ERASE_ALT, ERASE_TOKEN, read_info};
    use crate::error::Error;
    use crate::progress::{Phase, Progress};

    type Fallible = Result<(), Box<dyn core::error::Error>>;

    /// The bench T32LQ's flash: 16 MiB of SPI-NOR.
    const FLASH_SIZE: u64 = 16 * 1024 * 1024;

    /// What [`erasing_note`] says for the T32LQ's erase alt, **as text**.
    ///
    /// Spelt out rather than called, because a test that asserts a formatter against
    /// itself pins nothing: replacing the whole function body with `String::new()`
    /// survived until this constant existed. Byte-identical output with the C is no
    /// longer a goal, which is exactly why these lines are ours to keep stable, and
    /// a test is what keeps them.
    const ERASING_ALT_1: &str = "Erasing the whole flash (alt 1)... this takes a while";

    // -----------------------------------------------------------------
    // Pure helpers — the arithmetic and the verdicts, without a bus.
    // -----------------------------------------------------------------

    /// The two lines a user actually reads, pinned as text.
    ///
    /// Byte-identical output with the C is no longer a goal, which is exactly why
    /// these are ours to keep stable, and why a test rather than the C is what keeps them.
    /// The second case is not padding: without an alt that is not 1, a formatter that
    /// ignored its argument would pass.
    /// A claim that fails **after** `claim_interface` — a stalled `SET_INTERFACE`, which
    /// is the WebUSB case — must not leave the interface held. `AccessDenied` so the
    /// reset cannot paper over it with a second attempt that would release on
    /// its own way out.
    #[test]
    fn a_claim_that_fails_half_way_still_releases() {
        let gadget = FakeGadget::t32lq();
        gadget.preload(0, vec![0x99; 256]);
        let clock = RecordingClock::new();
        gadget.inject(When::SetAlt, Fault::AccessDenied);

        let outcome = block_on(erase(&gadget, &clock, &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(gadget.claimed(), None, "the interface was given back");
        assert_eq!(gadget.erases(), 0, "and nothing was wiped");
    }

    #[test]
    fn op_erase_notes_are_the_lines_the_user_reads() {
        assert_eq!(erasing_note(1), ERASING_ALT_1);
        assert_eq!(erasing_note(7), "Erasing the whole flash (alt 7)... this takes a while");
        assert_eq!(COMPLETE_NOTE, "Erase complete (verified blank)");
    }

    /// The probe length, including the case the plain arithmetic gets wrong.
    ///
    /// `min(wTransferSize, 4096)` yields **0** for a `wTransferSize` of 0 and would read
    /// nothing at all, which is a blank check that can never fail. `dfu.c:632-634`
    /// substitutes 4096 and so does this.
    #[test]
    fn op_erase_blank_check_length() {
        assert_eq!(probe_len(0), BLANK_CHECK_MAX, "wTransferSize 0 must not read nothing");
        assert_eq!(probe_len(1), 1);
        assert_eq!(probe_len(1024), 1024);
        assert_eq!(probe_len(4096), BLANK_CHECK_MAX);
        assert_eq!(probe_len(4097), BLANK_CHECK_MAX);
        assert_eq!(probe_len(u16::MAX), BLANK_CHECK_MAX);
    }

    /// The verdict, and the offset the C computes and then throws away.
    #[test]
    fn op_erase_blank_check_names_the_first_dirty_byte() -> Fallible {
        require_blank(&[ERASED_BYTE; 8])?;

        let error = require_blank(&[0xFF, 0xFF, 0x7E, 0xFF])
            .err()
            .ok_or("a non-blank block passed the blank check")?;
        assert!(
            matches!(
                error,
                Error::Verify {
                    offset: 2,
                    expected: 0xFF,
                    actual: Some(0x7E)
                }
            ),
            "{error}"
        );
        // `Error::Verify` is outside `is_recoverable`, so this can never be buried under
        // a bus reset and a second wipe (`dfu.c:1061-1064` draws the same
        // line for verify).
        assert!(!error.is_recoverable());

        // `got <= 0` is the C's `TDFU_ERROR_PROTOCOL` (`dfu.c:648-649`): a device that
        // returned no bytes has said nothing about the flash, and "no evidence" must
        // never read as "blank".
        let empty = require_blank(&[])
            .err()
            .ok_or("an empty probe passed the blank check")?;
        assert!(matches!(empty, Error::Protocol(_)), "{empty}");
        Ok(())
    }

    /// A `dfuERROR` that carries `bStatus = OK` is still a failure (`dfu.c:735-738`).
    ///
    /// The `Status` is taken from a real device rather than built by hand, because
    /// `Status` is `#[non_exhaustive]` and because the point of the test is that the
    /// combination *occurs*: `f_dfu`'s per-state default arms assign `dfuERROR` without
    /// touching `dfu_status` (`f_dfu.c:393-396`), so one stray request into a state that
    /// does not expect it produces exactly this pair.
    #[test]
    fn op_erase_manifest_error_is_a_failure_even_with_status_ok() -> Fallible {
        let gadget = FakeGadget::t32lq();
        // `dfuIDLE` has no CLRSTATUS case at all, so this stalls *and enters* dfuERROR.
        drop(block_on(host::clr_status(&gadget, 0)));
        assert_eq!(gadget.dfu_state(), DfuState::Error);
        assert_eq!(gadget.dfu_status(), 0, "the default arm left bStatus alone");

        let status = block_on(host::get_status(&gadget, 0))?;
        assert_eq!(status.state, State::Error);
        assert_eq!(status.status, 0);

        let error = manifest_settled(status)
            .err()
            .ok_or("a manifest that ended in dfuERROR was accepted")?;
        assert!(matches!(error, Error::Protocol(_)), "{error}");

        // And a settled, healthy manifest passes.
        let clean = block_on(host::get_status(&FakeGadget::t32lq(), 0))?;
        assert_eq!(clean.state, State::DfuIdle);
        manifest_settled(clean)?;
        Ok(())
    }

    /// A loader may declare its alternate settings in any order, so the lookup returns
    /// `bAlternateSetting`, not the position (`dfu.c:513-516` returns `alts[i].alt`).
    ///
    /// And the failure is deliberately **not** the one
    /// [`resolve`](crate::dfu::alt::resolve) gives: for an alt the user typed, naming the
    /// alts that do exist is the useful answer, and for a compile-time constant it is
    /// not. A device with no `erase` alt is a loader built before `a73e4da`, and the
    /// actionable half is the C's `"update the DFU loader firmware"` (`dfu.c:707`).
    #[test]
    fn op_erase_alt_is_found_by_name_not_by_position() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", FLASH_SIZE),
            AltConfig::erase(),
            AltConfig::reboot(),
        ]));
        let info = block_on(read_info(&gadget))?;
        assert_eq!(alt_named(&info, ERASE_ALT)?, 1);
        assert_eq!(alt_named(&info, "reboot")?, 2);

        let missing = alt_named(&info, "sdcard")
            .err()
            .ok_or("an alt the loader does not have resolved")?;
        assert!(matches!(missing, Error::MissingAlt("sdcard")), "{missing}");

        // The shared resolver would have answered `Invalid` here, and this is the
        // conversion that turns it into advice a user of `--erase` can act on.
        let shared = resolve(&info, &AltSel::Name("sdcard".to_owned()))
            .err()
            .ok_or("the shared resolver found an alt that is not there")?;
        assert!(matches!(shared, Error::Invalid(_)), "{shared}");
        assert!(!shared.is_recoverable() && !missing.is_recoverable());
        Ok(())
    }

    // -----------------------------------------------------------------
    // The wire sequence, with the deadlines.
    // -----------------------------------------------------------------

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

    /// Everything a user sees without asking: [`Progress::Debug`] filtered out.
    fn shown(said: &[Progress]) -> Vec<Progress> {
        said.iter()
            .filter(|step| !matches!(step, Progress::Debug(_)))
            .cloned()
            .collect()
    }

    /// Just the [`Progress::Debug`] lines.
    fn debug_lines(said: &[Progress]) -> Vec<&str> {
        said.iter()
            .filter_map(|step| match step {
                Progress::Debug(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// **The pin.** The exact requests the erase makes, in order, with their deadlines.
    ///
    /// Scripted rather than emulated on purpose: this is where the *host's* choices are
    /// nailed down — that the token goes to block 0 and the trigger to block 1, that the
    /// erase alt is selected by `SET_INTERFACE` and alt 0 re-selected for the probe, that
    /// the interface is released once at the end, and that every `DNLOAD` carries the
    /// 30 s deadline while everything else carries 5 s. A 2 MiB buffer flush
    /// inside a `DNLOAD` outlasts 5 s — a T40XP recorded `errSTALLEDPKT` when it did not
    /// — and no shorter deadline would show up as anything but a flaky erase.
    #[test]
    fn op_erase_sequence() -> Result<(), MockError> {
        let blank = vec![ERASED_BYTE; usize::from(BLANK_CHECK_MAX)];
        let mut mock = script_read_info(MockTransport::new(gadget_descriptors()).configured(1));
        mock = mock
            // Claim, and select the `erase` alt by name (`dfu.c:705-712`).
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 1 }, Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            // The token, then the poll it needs (`dfu.c:720-725`).
            .expecting(class_out(request::DNLOAD, 0, ERASE_TOKEN), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            // The zero-length trigger, then the poll that actually waits (`:729-734`).
            .expecting(class_out(request::DNLOAD, 1, &[]), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            // The blank check on alt 0 (`:641-646`).
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 0 }, Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), status_reply(State::DfuIdle))
            .expecting(class_in(request::UPLOAD, 0, BLANK_CHECK_MAX), Reply::Data(blank.clone()))
            // The close-out on a fixed loader (`:679-685`).
            .expecting(class_out(request::ABORT, 0, &[]), Reply::Done)
            .expecting(class_in(request::UPLOAD, 0, BLANK_CHECK_MAX), Reply::Data(blank))
            .expecting(class_out(request::ABORT, 0, &[]), Reply::Done)
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&mock, &clock, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("erase failed: {error}")))?;

        // The two `DNLOAD`s get 30 s, everything else 5 s.
        for Recorded { call, timeout, .. } in mock.calls() {
            let want = match call {
                Call::ControlOut { request, .. } if request == request::DNLOAD => Some(DNLOAD_TIMEOUT),
                Call::ControlIn { .. } | Call::ControlOut { .. } => Some(CONTROL_TIMEOUT),
                // Claim, release and `SET_INTERFACE` take no `Duration` in the trait.
                _ => None,
            };
            assert_eq!(timeout, want, "wrong deadline on {call:?}");
        }
        // Nothing waited: every poll settled first time and the grace never fired.
        assert!(clock.slept().is_empty(), "{:?}", clock.slept());
        // Filtered, not taken raw: `make_idle` narrates a `Progress::Debug` per poll
        // before the phase, and this pin is about what the *user* is shown first.
        assert_eq!(
            shown(&said).first(),
            Some(&Progress::Phase(Phase::Erase)),
            "the erase phase was never announced"
        );
        assert_eq!(notes(&said), vec![ERASING_ALT_1, COMPLETE_NOTE]);
        mock.verify()
    }

    // -----------------------------------------------------------------
    // Against the emulated device.
    // -----------------------------------------------------------------

    /// **The narration pin.** The wipe token is a download to an alt, and it says so in
    /// the same shape a write's opening line uses (`dfu.c:567`).
    ///
    /// A token that went to the wrong alt is how "dfu erase: bad token" happens on a
    /// T40XP, and this is the line that makes it visible. Revert check: delete the
    /// `Progress::Debug(download_line(..))` call and this fails.
    #[test]
    fn op_erase_narrates_the_token_download() -> Fallible {
        let gadget = FakeGadget::t32lq();
        gadget.preload(0, vec![0x5A; 8192]);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        let opening = debug_lines(&said)
            .into_iter()
            .find(|line| line.starts_with("download:"))
            .ok_or("the token download was never narrated")?;
        // Alt 1 is `erase` on the shipped loaders, the token is the seventeen bytes of
        // `ERASE_TOKEN`, and the block size is the one a real download would use.
        assert_eq!(
            opening,
            format!("download: alt 1, {} bytes in 4096-byte blocks", ERASE_TOKEN.len())
        );
        assert_eq!(notes(&said), vec![ERASING_ALT_1, COMPLETE_NOTE]);
        Ok(())
    }

    /// The whole flow against `FakeGadget`: the chip really is wiped, and said so once.
    #[test]
    fn op_erase_wipes_the_medium() -> Fallible {
        let gadget = FakeGadget::t32lq();
        gadget.preload(0, vec![0x5A; 8192]);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.erases(), 1, "the loader's erase flush never ran");
        assert_eq!(gadget.medium(0), Some(Vec::new()), "the medium still holds bytes");
        assert_eq!(notes(&said), vec![ERASING_ALT_1, COMPLETE_NOTE]);
        assert_eq!(
            said.iter()
                .filter(|step| **step == Progress::Phase(Phase::Erase))
                .count(),
            1
        );
        // Released on the way out, and never bus-reset.
        assert_eq!(gadget.claimed(), None, "the interface was left claimed");
        assert_eq!(gadget.resets(), 0);
        Ok(())
    }

    /// **The pin the blank check exists for: a manifest that answers OK having erased nothing.**
    ///
    /// The device here answers the whole sequence cleanly — the token is
    /// accepted, the trigger is accepted, the manifest settles in `dfuIDLE` with
    /// `bStatus = OK` — and the boot flash is untouched. That is not a hypothetical
    /// shape: `xburst_erase_flush` returns **0** when the arming flag is not set
    /// (`arch/mips/mach-xburst/dfu.c:238-239`), `dfu_error_callback` drops the arming on
    /// any failed or aborted transaction on the virt entity (`:290-296`), and the flush's
    /// result never reaches the host anyway — `f_dfu.c:530-539` goes to `dfuIDLE` and
    /// answers OK as soon as the deferred flush clears, whatever it returned, while a
    /// deferred flush that *fails* ends the gadget's main loop instead
    /// (`common/dfu.c:84-87`).
    ///
    /// It is modelled as an alt named `erase` that is an ordinary medium, because that
    /// reaches the same host-visible state with the emulator's knobs. What it is **not**
    /// modelled as is a garbled token: the C returns `-EINVAL`
    /// (`arch/mips/mach-xburst/dfu.c:219-223`), which fails the drain inside `dfu_write`
    /// and lands as errUNKNOWN in `dfuERROR` on the next poll, so the status does catch it.
    #[test]
    fn op_erase_blank_check() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", FLASH_SIZE),
            // An `erase` alt that takes the token and wipes nothing.
            AltConfig::flash("erase", FLASH_SIZE),
            AltConfig::reboot(),
        ]));
        gadget.preload(0, vec![0xA5; 64]);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(erase(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a chip that was never erased passed the blank check")?;

        assert!(
            matches!(
                error,
                Error::Verify {
                    offset: 0,
                    expected: 0xFF,
                    actual: Some(0xA5)
                }
            ),
            "{error}"
        );
        assert_eq!(gadget.erases(), 0);
        assert_eq!(
            gadget.medium(0).map(|medium| medium.len()),
            Some(64),
            "the medium was touched"
        );
        // It said it was erasing, and never said it had.
        assert_eq!(notes(&said), vec![ERASING_ALT_1]);
        // A data verdict is final: no bus reset, no second wipe (`dfu.c:1061-1064`).
        assert_eq!(gadget.resets(), 0);
        assert_eq!(gadget.claimed(), None);
        Ok(())
    }

    /// **The probe close-out, both loader generations.**
    ///
    /// The one-block probe leaves U-Boot's read transaction inited with the sequence
    /// counter at 1, and whether `DFU_ABORT` clears that is the whole difference between
    /// the two. Both branches must end with a **pristine entity**, because
    /// the next operation's block 0 is what pays for a dirty one.
    #[test]
    fn op_erase_probe_closeout_both_loaders() -> Fallible {
        for (loader, refusals, tail, ended_in) in [
            (
                Loader::Fixed,
                0_usize,
                vec![(request::ABORT, 0_u16), (request::UPLOAD, 0), (request::ABORT, 0)],
                DfuState::DfuIdle,
            ),
            (
                Loader::Legacy,
                1,
                vec![(request::ABORT, 0), (request::UPLOAD, 0), (request::CLRSTATUS, 0)],
                DfuState::Error,
            ),
        ] {
            let gadget = FakeGadget::new(GadgetConfig::t32lq().with_loader(loader));
            let clock = RecordingClock::new();
            let mut said = Vec::new();
            block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

            let requests = gadget.class_requests();
            assert_eq!(
                requests.get(requests.len() - 3..),
                Some(tail.as_slice()),
                "{loader:?} close-out: {requests:?}"
            );
            // The bench evidence: a fixed T40XP logged zero `Wrong sequence number` lines
            // and an old T23 logged exactly one, from the re-probe's deliberate mismatch
            // self-heal.
            assert_eq!(gadget.wrong_sequence_refusals(), refusals, "{loader:?}");
            // The property that matters, and it holds either way.
            assert_eq!(
                gadget.entity_inited(0),
                Some(false),
                "{loader:?} left a transaction open"
            );
            assert_eq!(gadget.entity_sequence(0), Some(0), "{loader:?} left a stale sequence");

            // What the close-out leaves behind, which is not the same thing on both.
            // `CLRSTATUS` is not a case in `dfuUPLOAD-IDLE` (`f_dfu.c:584-587`), so on a
            // legacy loader the C's own close-out ends in `dfuERROR` — harmless, because
            // the next operation opens with `make_idle`, whose first round sends
            // `CLRSTATUS` from `dfuERROR` and returns the device to `dfuIDLE`.
            assert_eq!(gadget.dfu_state(), ended_in, "{loader:?}");
            block_on(host::make_idle(&gadget, 0))?;
            assert_eq!(gadget.dfu_state(), DfuState::DfuIdle, "{loader:?} did not self-heal");
        }
        Ok(())
    }

    /// **The blank-check probe gets the block 0 retry, which the C does not give it.**
    ///
    /// `dfu_erase_blank_check` uploads block 0 once (`dfu.c:645-646`). If alt 0's entity
    /// was left mid-transaction — a browser reload, a killed run, or simply the read that
    /// preceded this erase — that block is refused as a wrong sequence number, the erase
    /// returns an error *after having wiped the chip*, and the manager's fallback is a
    /// USB reset whose retry re-sends the token to a device that is still busy: the case
    /// the C itself documents as harmful at `libtdfu/src/dfu/dfu.c:141-145`. One
    /// `make_idle` and one re-read cost nothing and remove the reason to reset.
    #[test]
    fn op_erase_retries_a_stale_block0() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_loader(Loader::Legacy));
        gadget.preload(0, vec![0x11; 4096]);
        // Leave alt 0 mid-upload: inited, sequence 1. A legacy loader keeps that across
        // `SET_INTERFACE`, `DFU_ABORT` and the bus reset behind `SET_CONFIGURATION`.
        drop(block_on(host::upload(&gadget, 0, 0, 4096))?);
        assert_eq!(gadget.entity_sequence(0), Some(1));
        gadget.forget_events();

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.erases(), 1);
        assert_eq!(gadget.medium(0), Some(Vec::new()));
        // The retry was announced. A retry the user cannot see is a retry they cannot
        // report.
        let said_notes = notes(&said);
        assert!(
            said_notes.iter().any(|note| note.contains("stale DFU transaction")),
            "the stale-block-0 retry was silent: {said_notes:?}"
        );
        assert!(said_notes.contains(&COMPLETE_NOTE));
        // Two refusals: the stale probe, and the close-out's deliberate one.
        assert_eq!(gadget.wrong_sequence_refusals(), 2);
        // And no bus reset — which is the whole point of doing it here.
        assert_eq!(gadget.resets(), 0);
        Ok(())
    }

    /// EP0 goes silent mid-manifest and the erase still completes.
    ///
    /// The wipe runs inside the loader's deferred flush, which blocks the gadget's main
    /// loop, so `GETSTATUS` is simply not answered while it works. Thirty-six consecutive
    /// losses are forgiven at [`GRACE_BACKOFF`] apiece — about three minutes, which is
    /// what a programmed 16 MiB NOR takes.
    ///
    /// The two waits are told apart deliberately, and the device's own pace is set
    /// **above `0xFFFF` ms**: `bwPollTimeout` is a 24-bit field and every test in an
    /// earlier implementation used 250 ms or 500 ms, whose high byte is zero, so `<< 16`
    /// and `>> 16` were indistinguishable while coverage reported the line as covered
    /// throughout. A grace pin that shares the loader's 500 ms cannot tell a
    /// forgiven poll from a paced one either.
    #[test]
    fn op_erase_survives_a_silent_ep0() -> Fallible {
        let silence = 20;
        let pace = 0x0001_2345_u32;
        let gadget = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_flush_silence_polls(silence)
                .with_virt_poll_timeout_ms(pace),
        );
        gadget.preload(0, vec![0x33; 512]);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.erases(), 1);
        let slept = clock.slept();
        assert_eq!(
            slept.iter().filter(|waited| **waited == GRACE_BACKOFF).count(),
            silence,
            "the grace did not pace itself at 500 ms: {slept:?}"
        );
        assert!(
            slept
                .iter()
                .any(|waited| *waited == core::time::Duration::from_millis(u64::from(pace))),
            "the device's own 24-bit bwPollTimeout was not honoured: {slept:?}"
        );
        assert!(notes(&said).contains(&COMPLETE_NOTE));
        Ok(())
    }

    /// More silence than [`Grace::Erase`] forgives is a failure, not an endless wait.
    #[test]
    fn op_erase_gives_up_past_the_grace() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_flush_silence_polls(Grace::Erase.retries() + 1));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(erase(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a device that never came back reported a verified erase")?;
        assert!(
            !notes(&said).contains(&COMPLETE_NOTE),
            "it claimed a wipe it never proved"
        );
        assert!(error.is_recoverable(), "{error}");
        Ok(())
    }

    /// A loader with no `erase` alt fails before it touches the bus (`dfu.c:705-708`).
    #[test]
    fn op_erase_without_the_alt_claims_nothing() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash("flash", FLASH_SIZE)]));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(erase(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a loader with no erase alt erased something")?;

        assert!(matches!(error, Error::MissingAlt(ERASE_ALT)), "{error}");
        assert_eq!(
            error.to_string(),
            "the loader has no alt named \"erase\": update the DFU loader firmware"
        );
        // Not recoverable, so the reset never fires on it — a bus reset does
        // not add an alt to a loader.
        assert!(!error.is_recoverable());
        assert_eq!(gadget.resets(), 0);
        assert_eq!(gadget.claimed(), None);
        assert!(said.is_empty(), "it announced an erase it never started");
        Ok(())
    }

    /// The interface is released on the failing paths too, not only the happy one.
    #[test]
    fn op_erase_releases_on_every_path() -> Fallible {
        let gadget = FakeGadget::t32lq();
        // Every `DNLOAD` stalls, four times over: two reset attempts, each of
        // which gets two block-0 attempts. Nothing is left to recover with.
        gadget.inject_times(When::Class(request::DNLOAD), Fault::Stall, 4);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(erase(&gadget, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a stalled token reported a successful erase")?;
        assert!(matches!(error, Error::Usb(_)), "{error}");
        assert_eq!(gadget.claimed(), None, "the interface was left claimed after a failure");
        assert_eq!(gadget.erases(), 0);
        Ok(())
    }

    /// Erase is idempotent, so a wedged gadget is reset and retried once
    /// (`dfu.c:1018-1025`) — and the retry is announced.
    #[test]
    fn op_erase_resets_and_retries_once() -> Fallible {
        let gadget = FakeGadget::t32lq();
        gadget.preload(0, vec![0x77; 128]);
        // EP0 stops answering for long enough to lose the first attempt outright.
        gadget.silence_ep0(1);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.resets(), 1, "the wedged gadget was never reset");
        assert!(clock.slept().contains(&POST_RESET_SETTLE), "{:?}", clock.slept());
        let said_notes = notes(&said);
        assert!(
            said_notes.iter().any(|note| note.contains("USB-reset")),
            "the reset was silent: {said_notes:?}"
        );
        assert_eq!(gadget.erases(), 1);
        assert_eq!(gadget.medium(0), Some(Vec::new()));
        Ok(())
    }

    /// **A bus reset after the token is recovered, and which recovery does it depends on
    /// the loader.**
    ///
    /// The bus reset does *not* clear a virt entity's block sequence counter:
    /// `reset` touches no entity at all. What cleans it is the
    /// `SET_CONFIGURATION` the host has to send afterwards, and **it cleans the alt that
    /// was in force**: `f_dfu_abort_transaction` reads
    /// `dfu_get_entity(f_dfu->altsetting)` at `f_dfu.c:834`, two lines before
    /// `f_dfu->altsetting = alt` at `:836`, and nothing zeroed `altsetting` in between
    /// (`dfu_disable` clears `f_dfu->config` and nothing else, `:851-860`).
    ///
    /// So on a **fixed** loader the re-enumeration cleans the `erase` entity itself and
    /// the re-sent token is accepted first time. On a **legacy** loader
    /// `f_dfu_abort_transaction` does not exist, nothing is cleaned, and the token
    /// arrives as block 0 at an entity expecting block 1 — the C's own "re-sent token
    /// refused as bad token" (`libtdfu/src/dfu/dfu.c:141-145`), which is why it calls
    /// that reset harmful. The refusal cleans the entity on its way out
    /// (`drivers/dfu/dfu.c:384-390`), so one `make_idle` and one re-send
    /// turn the C's decorative recovery into a working one. That is
    /// [`op_erase_recovers_a_stale_token_on_a_legacy_loader`], and it is why the token
    /// transaction is wrapped in `retry_stale_block0` whatever the loader.
    ///
    /// (An earlier note here said the re-enumeration cleans "only alt 0's entity". It
    /// cleans the one in force. The behaviour that note justified is unchanged and still
    /// needed, for the older loader.)
    ///
    /// Both retries are announced, because a user who sees an erase take two goes needs
    /// to know it did.
    #[test]
    fn op_erase_recovers_a_reset_after_the_token() -> Fallible {
        let gadget = FakeGadget::t32lq();
        gadget.preload(0, vec![0x99; 256]);
        // The zero-length trigger stalls once, after the token has been accepted.
        gadget.inject(When::ClassBlock(request::DNLOAD, 1), Fault::Stall);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.resets(), 1, "the failure after the token was not reset");
        assert_eq!(
            gadget.wrong_sequence_refusals(),
            0,
            "a fixed loader cleans the alt in force on the re-enumeration"
        );
        assert_eq!(gadget.erases(), 1);
        assert_eq!(gadget.medium(0), Some(Vec::new()));

        let said_notes = notes(&said);
        assert!(
            said_notes.iter().any(|note| note.contains("USB-reset")),
            "{said_notes:?}"
        );
        assert!(said_notes.contains(&COMPLETE_NOTE));
        Ok(())
    }

    /// The legacy half of the pin above: nothing cleans the entity, so the re-sent token
    /// is refused once and the block 0 retry is what saves the erase.
    #[test]
    fn op_erase_recovers_a_stale_token_on_a_legacy_loader() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_loader(Loader::Legacy));
        gadget.preload(0, vec![0x99; 256]);
        gadget.inject(When::ClassBlock(request::DNLOAD, 1), Fault::Stall);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        assert_eq!(gadget.resets(), 1, "the failure after the token was not reset");
        // Two: the re-sent token that nothing had cleaned, and the probe close-out,
        // which is deliberate on this loader generation (`op_erase_retries_a_stale_block0`
        // pins the same pair for the same reason).
        assert_eq!(gadget.wrong_sequence_refusals(), 2);
        assert_eq!(gadget.erases(), 1);
        assert_eq!(gadget.medium(0), Some(Vec::new()));

        let said_notes = notes(&said);
        assert!(
            said_notes.iter().any(|note| note.contains("USB-reset")),
            "{said_notes:?}"
        );
        assert!(
            said_notes.iter().any(|note| note.contains("stale DFU transaction")),
            "the refused re-send was recovered silently: {said_notes:?}"
        );
        assert!(said_notes.contains(&COMPLETE_NOTE));
        Ok(())
    }

    /// A failure a reset cannot fix is not reset, and the `AccessDenied` message that
    /// says what to fix survives.
    #[test]
    fn op_erase_does_not_reset_what_a_reset_cannot_fix() -> Fallible {
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
        let error = block_on(erase(&mock, &clock, &mut record(&mut said)))
            .err()
            .ok_or("a refused device erased fine")?;
        assert!(!error.is_recoverable(), "{error}");
        assert!(
            !mock.calls().iter().any(|recorded| recorded.call == Call::Reset),
            "a device the OS refused to open was bus-reset"
        );
        mock.verify().map_err(Box::from)
    }

    /// A `wTransferSize` the loader reports as 1024 is the length the probe asks for.
    #[test]
    fn op_erase_probe_honours_the_transfer_size() -> Fallible {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(1024));
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(erase(&gadget, &clock, &mut record(&mut said)))?;

        // The length off the events: `class_requests` carries `wValue`, which for an
        // `UPLOAD` is the block number, so it cannot tell a probe that asked for
        // `wTransferSize` from one that asked for `BLANK_CHECK_MAX`. Asking a loader for
        // more than it will answer is what turns a blank check into a short answer,
        // which `require_blank` reports as a protocol failure and an operator reads as a
        // failed erase.
        let asked: Vec<u16> = gadget
            .events()
            .into_iter()
            .filter_map(|event| match event {
                Event::ControlIn {
                    control_type: ControlType::Class,
                    request,
                    len,
                    ..
                } if request == request::UPLOAD => Some(len),
                _ => None,
            })
            .collect();
        assert_eq!(asked, vec![1024, 1024], "the probe and its re-probe, at wTransferSize");
        Ok(())
    }
}
