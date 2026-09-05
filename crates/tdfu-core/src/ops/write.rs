//! Write an image to a flash alt.

use tdfu_usb::LocalUsbTransport;

use crate::bootrom::as_u64;
use crate::clock::Sleeper;
use crate::dfu::alt::resolve;
use crate::dfu::descriptors::read_info;
use crate::dfu::host::{self, Grace};
use crate::error::{Error, Result};
use crate::model::{AltSel, DEFAULT_TRANSFER_SIZE, DfuInfo};
use crate::progress::{Phase, Progress, ProgressSink};

/// What core says when the manifest has settled and the image is on the flash
/// (`dfu.c:618`).
///
/// A named constant so the wording is a fixed thing a test can pin rather than whatever
/// the call site happens to say, and **emitted here rather than by
/// each frontend**: an earlier local CLI printed nothing at all on a successful write
/// while its daemon printed two lines, so the remote tool was more informative than the
/// local one.
pub const COMPLETE_NOTE: &str = "DFU download complete";

/// Download `image` to `alt`.
///
/// The sequence is the C's, verified against `tdfu_dfu_write_device` (`dfu.c:547-621`):
/// read the DFU info (`:551`), resolve the alt (`:555-556`), claim and select it
/// (`:557`), then up to two attempts of [`make_idle`](host::make_idle)
/// (`:576`) followed by `DNLOAD` blocks of at most `wTransferSize` bytes (`:585-586`),
/// each answered by a [`Grace::Write`] poll (`:592`); then the zero-length `DNLOAD` that
/// ends the transfer (`:613`) and the manifest poll that commits it (`:615`).
///
/// **The final poll uses the *erase* grace, not the write grace** (pin
/// `op_write_manifest_grace_36`, `dfu.c:615`). The manifest is where the loader's
/// deferred flush runs, and EP0 answers nothing while it does. A T40N NOR 16 MiB write
/// spends around three and a half minutes in `dfuMANIFEST`; [`Grace::Write`]'s twelve
/// forgiven polls are about a minute. A wipe is not driven through here: the wipe token
/// routes to [`erase`](super::erase), which has the blank check that proves a manifest
/// answering OK really did erase something, and this operation has not.
///
/// **"First block" is an explicit flag.** The C tests `block != 0` (`dfu.c:602`), and
/// `block` is a `uint16_t` that wraps through 0 at 65536 blocks — 256 MiB at
/// `wTransferSize` 4096 — so a late failure there reads as a stale block 0
/// and the whole image is re-sent. The same test is in its read (`:855`) and verify
/// (`:955`) loops; none of the three is
/// inherited.
/// [`host::Transaction`] carries the flag, so the rule is a type rather than a
/// convention.
///
/// # Retries
///
/// Both of the C's, and both audible:
/// [`retry_stale_block0`](host::retry_stale_block0) for a stale sequence
/// (`dfu.c:575-605`), inside [`reset_and_retry_once`](host::reset_and_retry_once) for
/// a wedged EP0 (`dfu.c:994-998`). The zero-length trigger and the manifest
/// poll sit **outside** the block-0 loop, exactly as the C's do (`dfu.c:607-619`): by
/// then every block has landed, so a failure there is not a stale sequence.
///
/// # Progress
///
/// [`Phase::Download`] and a [`Progress::Bytes`] per block, then [`Phase::Manifest`]
/// once the device has taken the end-of-transfer trigger, then [`COMPLETE_NOTE`].
///
/// # Errors
/// [`Error::Invalid`] if `image` is empty — see the note below.
/// [`Error::MissingAlt`] or [`Error::Invalid`] if the loader has no such alt
/// ([`dfu::alt::resolve`](crate::dfu::alt::resolve)); otherwise the transport's error
/// after the retries.
///
/// ## An empty image is refused
///
/// A deliberate departure. The C's write would send only the end-of-transfer trigger and
/// report `DFU download complete` for a file with nothing in it, because nothing checks
/// (`dfu.c:561-562` loads the file and `:584`'s loop never runs) — while its *verify*
/// refuses the same input outright (`dfu.c:901-903`, `TDFU_ERROR_INVALID_PARAMETER`).
/// Reporting a successful flash for a write that never happened is the worst failure
/// this tool has, so the sibling's rule wins.
pub async fn write<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    alt: &AltSel,
    image: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    if image.is_empty() {
        return Err(Error::Invalid(
            "the image is empty; there is nothing to write and a zero-length download would report success".into(),
        ));
    }
    host::reset_and_retry_once(dev, clock, progress, async |_attempt, progress| {
        write_once(dev, clock, alt, image, progress).await
    })
    .await
}

/// One whole attempt: info, alt, claim, transfer, release.
///
/// The claim is inside the retry because the bus reset drops it (USB 9.1.1.5), and
/// the release is on **every** path out — the C leaves that to the
/// `dfu_close_device` after its call (`dfu.c:974-976`) and so has one exit to get right;
/// this has several.
async fn write_once<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    alt: &AltSel,
    image: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    let info = read_info(dev).await?;
    let alt = resolve(&info, alt)?;
    // A claim that failed *part way* still has to be undone: `host::claim` sends
    // `SET_INTERFACE` after `claim_interface`, so a stalled alt select leaves the
    // interface held (over WebUSB a stalled `SET_INTERFACE` is exactly that). Releasing
    // an interface that is not claimed is `Ok(())`, so this costs nothing
    // on the paths where nothing was taken.
    if let Err(error) = host::claim(dev, &info, alt).await {
        drop(host::release(dev, info.interface).await);
        return Err(error);
    }

    let outcome = download(dev, clock, &info, alt, image, progress).await;
    let released = host::release(dev, info.interface).await;

    // The download's failure is the one the operator can act on; a release that also
    // failed after it tells them nothing new (the same order `ops::diag` releases in).
    match outcome {
        Ok(()) => released,
        Err(error) => Err(error),
    }
}

/// What a download is about to do, for the debug channel (`dfu.c:567`).
///
/// Three facts, and the shape [`erase`](super::erase) borrows for its token: where the
/// bytes are going, how many there are, and how many requests that is. A write that is
/// slower than expected is nearly always one of the three being different from what the
/// operator assumed.
pub(crate) fn download_line(alt: u8, bytes: u64, block_size: usize) -> String {
    format!("download: alt {alt}, {bytes} bytes in {block_size}-byte blocks")
}

/// The blocks, the end-of-transfer trigger and the manifest, with the interface claimed.
async fn download<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    info: &DfuInfo,
    alt: u8,
    image: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    let total = as_u64(image.len());
    // `read_info` substitutes [`DEFAULT_TRANSFER_SIZE`] for a missing or zero
    // `wTransferSize`, so this is unreachable through it — but `DfuInfo` is
    // public, `chunks(0)` panics, and a flashing tool must not abort mid-write on one.
    // The C would loop for ever here instead: its chunk is
    // `min(len - offset, transfer_size)` (`dfu.c:585`), which is 0 every time round.
    let block_size = match usize::from(info.transfer_size) {
        0 => usize::from(DEFAULT_TRANSFER_SIZE),
        size => size,
    };

    let blocks = host::retry_stale_block0(dev, info.interface, progress, async |transaction, progress| {
        progress(Progress::Phase(Phase::Download));
        progress(Progress::Debug(download_line(alt, total, block_size)));
        let mut block: u16 = 0;
        let mut done: u64 = 0;
        for chunk in image.chunks(block_size) {
            // Narrated on the way out, as the read's loop does: which block died and how
            // much of the image had landed before it. Both requests count, because a
            // block the device took but never finished flushing fails on the poll.
            let sent = host::dnload(dev, info.interface, block, chunk).await;
            // The C polls after every block and treats a lost poll as busy, not gone
            // (`dfu.c:592`): EP0 goes silent while the loader drains its 2 MiB buffer to
            // flash inside the request context.
            let settled = match sent {
                Ok(()) => {
                    host::poll_until_ready_narrated(dev, clock, info.interface, Grace::Write, &mut *progress).await
                }
                Err(err) => Err(err),
            };
            if let Err(err) = settled {
                progress(Progress::Debug(format!(
                    "download: block {block} failed after {done} bytes ({err})"
                )));
                return Err(err);
            }
            // Only now has the device taken the block — the C increments its `block`
            // after the poll, not after the request (`dfu.c:598-599`), so a poll that
            // fails on the first block is still a stale sequence.
            transaction.first_block_done();
            block = block.wrapping_add(1);
            done += as_u64(chunk.len());
            progress(Progress::Bytes {
                phase: Phase::Download,
                done,
                total: Some(total),
            });
        }
        Ok(block)
    })
    .await?;

    // Zero-length `DNLOAD`: end of transfer, and the trigger for the manifest
    // (`dfu.c:613`). It carries the **next** block number, not 0.
    host::dnload(dev, info.interface, blocks, &[]).await?;
    // Announced after the device has taken the trigger, because that request is what
    // ends the transfer: the polls that follow carry the device through
    // `dfuDNLOAD-SYNC` and `dfuMANIFEST-SYNC` into `dfuMANIFEST` (`f_dfu.c:445-482`,
    // `:402-423`, `:484-509`). Before it, nothing is committing.
    progress(Progress::Phase(Phase::Manifest));
    // Narrated: the manifest is where the loader's deferred flush runs and where EP0 goes
    // silent for minutes on a whole-chip write, so the forgiven polls here are the ones an
    // operator most wants to see happening.
    host::poll_until_ready_narrated(dev, clock, info.interface, Grace::Erase, &mut *progress).await?;
    progress(Progress::Note(COMPLETE_NOTE.to_owned()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use tdfu_usb::gadget::{AltConfig, DfuState, FakeGadget, Fault, GadgetConfig, Loader, When, request};
    use tdfu_usb::mock::{Call, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{ControlIn, ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Recipient, pid, vid};

    use super::{COMPLETE_NOTE, write};
    use crate::clock::RecordingClock;
    use crate::dfu::descriptors::fixtures::SINGLE_ALT_CONFIG;
    use crate::dfu::host::{CONTROL_TIMEOUT, DNLOAD_TIMEOUT, State};
    use crate::error::Error;
    use crate::model::AltSel;
    use crate::progress::{Phase, Progress};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Everything an operation said, in order.
    #[derive(Debug, Default)]
    struct Said(RefCell<Vec<Progress>>);

    impl Said {
        fn all(&self) -> Vec<Progress> {
            self.0.borrow().clone()
        }

        /// Everything a user sees without asking: [`Progress::Debug`] filtered out.
        ///
        /// The sequence assertions below are about what a run *shows*, and core's debug
        /// narration is behind every frontend's switch. Filtering rather than deleting
        /// keeps both pinned: the shown sequence here, the narration in
        /// [`a_write_narrates_its_download_on_the_debug_channel`].
        fn shown(&self) -> Vec<Progress> {
            self.0
                .borrow()
                .iter()
                .filter(|step| !matches!(step, Progress::Debug(_)))
                .cloned()
                .collect()
        }

        /// Just the [`Progress::Debug`] lines.
        fn debug(&self) -> Vec<String> {
            self.0
                .borrow()
                .iter()
                .filter_map(|step| match step {
                    Progress::Debug(text) => Some(text.clone()),
                    _ => None,
                })
                .collect()
        }

        fn notes(&self) -> Vec<String> {
            self.0
                .borrow()
                .iter()
                .filter_map(|step| match step {
                    Progress::Note(note) => Some(note.clone()),
                    _ => None,
                })
                .collect()
        }

        fn phases(&self, phase: Phase) -> usize {
            self.0
                .borrow()
                .iter()
                .filter(|step| **step == Progress::Phase(phase))
                .count()
        }
    }

    /// An image whose bytes all differ from `0xFF`, so a byte that never landed is
    /// distinguishable from erased flash.
    fn image(len: usize) -> Vec<u8> {
        (0..len).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect()
    }

    /// A gadget with the three shipped alts, `transfer_size`-byte blocks and a buffer
    /// big enough that nothing drains until the manifest.
    fn gadget(transfer_size: u16) -> FakeGadget {
        FakeGadget::new(
            GadgetConfig::t32lq()
                .with_transfer_size(transfer_size)
                .with_buffer_size(1 << 20),
        )
    }

    /// The `DNLOAD` block numbers a run issued, in order.
    fn downloads(gadget: &FakeGadget) -> Vec<u16> {
        gadget
            .class_requests()
            .into_iter()
            .filter_map(|(request, value)| (request == request::DNLOAD).then_some(value))
            .collect()
    }

    // ---- the scripted half: the wire sequence and its deadlines --------------

    /// `GET_DESCRIPTOR` for the configuration.
    fn get_descriptor(len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x06,
            value: 0x0200,
            index: 0,
            len,
        })
    }

    /// A DFU class request that reads.
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

    /// A DFU class request that writes.
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

    /// The six `GETSTATUS` bytes of a settled device.
    fn settled() -> Reply {
        Reply::Data(vec![0, 0, 0, 0, State::DfuIdle.code(), 0])
    }

    /// The single-alt gadget of `SINGLE_ALT_CONFIG`, unconfigured as a driverless device
    /// is.
    fn scripted() -> MockTransport {
        let mock = MockTransport::new(
            DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_config_descriptor(SINGLE_ALT_CONFIG),
        );
        let total = u16::try_from(SINGLE_ALT_CONFIG.len()).unwrap_or_default();
        mock.expecting(get_descriptor(9), Reply::Data(SINGLE_ALT_CONFIG[..9].to_vec()))
            .expecting(get_descriptor(total), Reply::Data(SINGLE_ALT_CONFIG.to_vec()))
    }

    /// **The sequence pin**: the exact requests a write makes, and the deadline
    /// on each.
    ///
    /// Scripted rather than emulated because [`Recorded::timeout`] is the only surface
    /// that carries a deadline: 30 s belongs to every `DNLOAD` including the
    /// zero-length trigger, and 5 s to everything else. A gadget that answers instantly
    /// would pass either way.
    #[test]
    fn op_write_sequence() -> TestResult {
        // 4096 + 10 bytes: one full block, one short one, then the trigger.
        let payload = image(4106);
        let mock = scripted()
            .expecting(Call::SetConfiguration(1), Reply::Done)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            // `make_idle`'s first poll finds it idle, so no recovery request goes out.
            .expecting(class_in(request::GETSTATUS, 0, 6), settled())
            .expecting(class_out(request::DNLOAD, 0, &payload[..4096]), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), settled())
            .expecting(class_out(request::DNLOAD, 1, &payload[4096..]), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), settled())
            // The end-of-transfer trigger carries the *next* block number (`dfu.c:613`).
            .expecting(class_out(request::DNLOAD, 2, &[]), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), settled())
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(write(&mock, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(mock.remaining(), 0, "every scripted call was made, in order");
        // A single-alt interface gets no `SET_INTERFACE` — it may stall it,
        // and over WebUSB that stall wedges EP0 for everything after.
        assert!(
            !mock
                .calls()
                .iter()
                .any(|recorded| matches!(recorded.call, Call::SetAltSetting { .. })),
            "no SET_INTERFACE on a single-alt gadget"
        );

        let deadlines: Vec<(u8, Option<core::time::Duration>)> = mock
            .calls()
            .iter()
            .filter_map(|Recorded { call, timeout }| match *call {
                Call::ControlOut {
                    control_type: ControlType::Class,
                    request,
                    ..
                }
                | Call::ControlIn {
                    control_type: ControlType::Class,
                    request,
                    ..
                } => Some((request, *timeout)),
                _ => None,
            })
            .collect();
        assert_eq!(
            deadlines,
            [
                (request::GETSTATUS, Some(CONTROL_TIMEOUT)),
                (request::DNLOAD, Some(DNLOAD_TIMEOUT)),
                (request::GETSTATUS, Some(CONTROL_TIMEOUT)),
                (request::DNLOAD, Some(DNLOAD_TIMEOUT)),
                (request::GETSTATUS, Some(CONTROL_TIMEOUT)),
                (request::DNLOAD, Some(DNLOAD_TIMEOUT)),
                (request::GETSTATUS, Some(CONTROL_TIMEOUT)),
            ],
            "30 s on every DNLOAD, the zero-length trigger included"
        );
        // The literal, once, so the constant is pinned against text rather than against
        // itself — every other assertion here compares `COMPLETE_NOTE` with itself and
        // would survive a change to what it says.
        assert_eq!(said.notes(), ["DFU download complete"], "said so, exactly once");
        Ok(())
    }

    /// An image that is an exact multiple of `wTransferSize` sends no short block — only
    /// the zero-length trigger ends it.
    #[test]
    fn an_exact_multiple_ends_on_the_trigger_alone() -> TestResult {
        let device = gadget(64);
        let payload = image(128);
        let clock = RecordingClock::new();

        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |_| {}))?;

        assert_eq!(downloads(&device), [0, 1, 2]);
        assert_eq!(device.medium(0).ok_or("alt 0 exists")?, payload);
        Ok(())
    }

    // ---- the emulated half: what the device does with it ---------------------

    /// **The narration pin.** A write says where the bytes are going, how many there are
    /// and how many requests that is, before the first `DNLOAD` (`dfu.c:567`).
    ///
    /// Three facts, and a write that is slower than the operator expected is nearly always
    /// one of them being different from what they assumed. Revert check: delete the
    /// `Progress::Debug(download_line(..))` call and this fails.
    #[test]
    fn a_write_narrates_its_download_on_the_debug_channel() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        let opening = said
            .debug()
            .into_iter()
            .find(|line| line.starts_with("download:"))
            .ok_or("the download was never narrated")?;
        assert_eq!(opening, "download: alt 0, 200 bytes in 64-byte blocks");
        // And it is a `Debug`, not a `Note`: a user who did not ask for detail sees the
        // phase, the counters and the completion line, and nothing else.
        assert_eq!(said.notes(), [COMPLETE_NOTE]);
        Ok(())
    }

    /// A block that fails names itself and how much of the image had landed, the same
    /// shape the read's loop uses. Both requests count: a block the device took but never
    /// finished flushing fails on the poll, not on the `DNLOAD`.
    #[test]
    fn a_failed_download_block_narrates_where_it_died() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        // Past the first block, so the block 0 retry does not re-run the transfer, and
        // not recoverable, so the bus reset does not either: one attempt, one line.
        device.inject(When::ClassBlock(request::DNLOAD, 2), Fault::AccessDenied);
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));
        assert!(outcome.is_err(), "{outcome:?}");

        let failed = said
            .debug()
            .into_iter()
            .find(|line| line.contains("failed after"))
            .ok_or("the failed block was never narrated")?;
        assert!(failed.contains("download: block 2"), "{failed}");
        assert!(failed.contains("128 bytes"), "{failed}");
        Ok(())
    }

    /// The whole operation against the U-Boot state machine: bytes on the medium, the
    /// phases in order, and the device idle at the end.
    #[test]
    fn a_write_lands_the_image_and_says_so() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.medium(0).ok_or("alt 0 exists")?, payload, "byte for byte");
        assert_eq!(downloads(&device), [0, 1, 2, 3, 4], "four blocks and the trigger");
        assert_eq!(device.dfu_state(), DfuState::DfuIdle);
        assert_eq!(device.claimed(), None, "released on the way out");
        assert_eq!(device.resets(), 0);
        assert_eq!(device.wrong_sequence_refusals(), 0);

        assert_eq!(
            said.shown(),
            [
                Progress::Phase(Phase::Download),
                Progress::Bytes {
                    phase: Phase::Download,
                    done: 64,
                    total: Some(200)
                },
                Progress::Bytes {
                    phase: Phase::Download,
                    done: 128,
                    total: Some(200)
                },
                Progress::Bytes {
                    phase: Phase::Download,
                    done: 192,
                    total: Some(200)
                },
                Progress::Bytes {
                    phase: Phase::Download,
                    done: 200,
                    total: Some(200)
                },
                Progress::Phase(Phase::Manifest),
                Progress::Note(COMPLETE_NOTE.to_owned()),
            ]
        );
        Ok(())
    }

    /// **The manifest grace pin.** The manifest poll forgives `Grace::Erase`'s 36 lost
    /// polls, not `Grace::Write`'s 12.
    ///
    /// Both directions, because one alone pins nothing: the same 20-poll EP0 silence
    /// that the manifest rides out kills a *block* poll. The silence is the emulator's
    /// model of the loader draining its buffer to flash inside the request context
    /// (U-Boot's `common/dfu.c:261-288`, `dfu_write_buffer_drain`), and where it lands is
    /// decided by the buffer size — bigger than the image, and only the manifest flush
    /// drains.
    #[test]
    fn op_write_manifest_grace_36() -> TestResult {
        let payload = image(200);
        let clock = RecordingClock::new();

        let patient = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_transfer_size(64)
                .with_buffer_size(1 << 20)
                .with_flush_silence_polls(20),
        );
        block_on(write(&patient, &clock, &AltSel::Default, &payload, &mut |_| {}))?;
        assert_eq!(
            patient.medium(0).ok_or("alt 0 exists")?,
            payload,
            "20 silent polls in the manifest are inside the erase grace"
        );

        // The same silence, drained per block instead: a 64-byte buffer fills on every
        // block, so it lands on the write poll — which forgives 12.
        let impatient = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_transfer_size(64)
                .with_buffer_size(64)
                .with_flush_silence_polls(20),
        );
        let outcome = block_on(write(&impatient, &clock, &AltSel::Default, &payload, &mut |_| {}));
        assert!(
            outcome.is_err(),
            "20 silent polls are past the write grace: {outcome:?}"
        );
        Ok(())
    }

    /// **The block-wrap pin.** A `DNLOAD` failure on a block whose *number* is 0 but
    /// which is not the first block is not a stale transaction.
    ///
    /// `wValue` is 16 bits, so at 65536 blocks it wraps back to 0 — and the C's
    /// `block != 0` (`dfu.c:602`) reads that as a stale sequence and re-sends the whole
    /// image, which on a 256 MiB NAND alt is the entire chip. The fault is armed from
    /// the progress sink at exactly the wrap, the only way to reach the second block 0;
    /// it is [`AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied) so that the bus reset
    /// cannot retry it either, and any restart at all would be this bug and nothing
    /// else.
    #[test]
    fn op_write_block_wrap_safe() {
        // 64-byte blocks: the smallest that still lets the 45-byte configuration
        // descriptor through, since the emulated EP0 truncates every answer to
        // `wTransferSize` exactly as the gadget does (`f_dfu.c:669`).
        const BLOCK: usize = 64;
        const WRAP_AT: u64 = 65536 * BLOCK as u64;

        let device = FakeGadget::new(
            GadgetConfig::new(vec![
                AltConfig::flash("flash", 8 << 20),
                AltConfig::erase(),
                AltConfig::reboot(),
            ])
            .with_transfer_size(u16::try_from(BLOCK).unwrap_or(64))
            .with_buffer_size(8 << 20),
        );
        let payload = image(65537 * BLOCK);
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            if let Progress::Bytes { done, .. } = step
                && done == WRAP_AT
            {
                // The next `DNLOAD` is block 0 again, 65536 blocks in.
                device.inject(When::ClassBlock(request::DNLOAD, 0), Fault::AccessDenied);
            }
            said.0.borrow_mut().push(step);
        }));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(
            said.phases(Phase::Download),
            1,
            "the transfer was announced once: nothing restarted it"
        );
        assert!(said.notes().is_empty(), "no retry of any kind: {:?}", said.notes());
        assert_eq!(device.resets(), 0);
        assert_eq!(downloads(&device).len(), 65537, "65536 blocks and the refused wrap");
        assert_eq!(device.claimed(), None, "released on the failure path too");
    }

    /// **The block 0 retry end to end, on the loader generation that needs it.**
    ///
    /// A transfer abandoned mid-stream — a browser reload, a killed run — leaves an old
    /// loader's entity expecting the next sequence number. Block 0 is refused once, and
    /// the retry after `make_idle` starts the image again from its first byte.
    #[test]
    fn a_stale_transaction_is_cleared_and_the_write_restarts() -> TestResult {
        let device = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_transfer_size(64)
                .with_buffer_size(1 << 20)
                .with_loader(Loader::Legacy),
        );
        let clock = RecordingClock::new();
        let said = Said::default();

        abandon_a_transfer(&device, &clock)?;
        assert_eq!(device.entity_sequence(0), Some(1), "the entity is stale");
        let resets_before = device.resets();

        let payload = image(100);
        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.medium(0).ok_or("alt 0 exists")?, payload, "from the first byte");
        assert_eq!(
            device.wrong_sequence_refusals(),
            1,
            "exactly one, as the bench T23 logged"
        );
        assert_eq!(
            device.resets(),
            resets_before,
            "the stale retry needs no bus reset of its own"
        );
        assert!(
            said.notes().iter().any(|note| note.contains("stale DFU transaction")),
            "the retry was announced: {:?}",
            said.notes()
        );
        // The restarted transfer re-announces its phase, so a frontend's byte counter
        // goes back to zero with the device rather than carrying on from a count that no
        // longer describes anything.
        assert_eq!(said.phases(Phase::Download), 2);
        Ok(())
    }

    /// The same abandoned transfer costs a fixed loader nothing, so the pin above is
    /// falsifiable in both directions.
    #[test]
    fn a_fixed_loader_needs_no_stale_recovery() -> TestResult {
        let device = gadget(64);
        let clock = RecordingClock::new();
        let said = Said::default();

        abandon_a_transfer(&device, &clock)?;

        let payload = image(100);
        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.wrong_sequence_refusals(), 0);
        assert_eq!(said.notes(), [COMPLETE_NOTE]);
        Ok(())
    }

    /// Leave a transfer part-way and reset the bus, as a browser reload does.
    fn abandon_a_transfer(device: &FakeGadget, clock: &RecordingClock) -> TestResult {
        use crate::dfu::host;
        use tdfu_usb::LocalUsbTransport;

        block_on(async {
            let info = crate::dfu::read_info(device).await?;
            host::claim(device, &info, 0).await?;
            host::dnload(device, info.interface, 0, &[0xAA; 64]).await?;
            host::poll_until_ready(device, clock, info.interface, crate::dfu::Grace::Write).await?;
            device.reset().await.map_err(Error::from)
        })?;
        Ok(())
    }

    /// **The bus reset over a write that already put bytes on the medium.** The retry
    /// rewrites from offset 0 — a device-side offset that carried over would append.
    #[test]
    fn a_recoverable_failure_resets_and_rewrites_the_whole_image() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        let clock = RecordingClock::new();
        let said = Said::default();

        device.inject(When::ClassBlock(request::DNLOAD, 2), Fault::NoDevice);

        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.medium(0).ok_or("alt 0 exists")?, payload, "byte for byte");
        assert_eq!(device.resets(), 1, "exactly one recovery reset");
        assert!(
            said.notes().iter().any(|note| note.contains("USB-reset")),
            "the recovery was announced: {:?}",
            said.notes()
        );
        assert_eq!(said.notes().last().map(String::as_str), Some(COMPLETE_NOTE));
        Ok(())
    }

    /// A failure outside the recoverable set is not reset-retried, and the interface is
    /// still released. `AccessDenied` is the case the rule exists for: a bus reset does
    /// not install a udev rule.
    #[test]
    fn an_unrecoverable_failure_is_not_retried() {
        let device = gadget(64);
        let payload = image(200);
        let clock = RecordingClock::new();
        let said = Said::default();

        device.inject(When::ClassBlock(request::DNLOAD, 2), Fault::AccessDenied);

        let outcome = block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(device.resets(), 0, "no reset for a failure a reset cannot fix");
        assert!(said.notes().is_empty(), "{:?}", said.notes());
        assert_eq!(device.claimed(), None, "released on the failure path");
    }

    /// An empty image is refused before anything reaches the bus, rather than reported
    /// as a completed download (`dfu.c:584`'s loop simply never runs).
    #[test]
    fn an_empty_image_is_refused() {
        let device = gadget(64);
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(write(&device, &clock, &AltSel::Default, &[], &mut |step| {
            said.0.borrow_mut().push(step);
        }));

        assert!(matches!(outcome, Err(Error::Invalid(_))), "{outcome:?}");
        assert!(device.events().is_empty(), "nothing was sent to the device");
        assert!(said.all().is_empty());
    }

    /// An alt the loader does not have fails before the claim, so a refused selection
    /// cannot leave an interface held.
    #[test]
    fn an_unknown_alt_is_refused_before_the_claim() -> TestResult {
        let device = gadget(64);
        let clock = RecordingClock::new();

        let outcome = block_on(write(
            &device,
            &clock,
            &AltSel::Name("rootfs".into()),
            &image(64),
            &mut |_| {},
        ));

        match outcome {
            Err(Error::Invalid(message)) => {
                assert!(message.contains("rootfs"), "{message}");
                assert!(message.contains("0 (flash)"), "{message}");
            }
            other => return Err(format!("expected Error::Invalid, got {other:?}").into()),
        }
        assert_eq!(device.claimed(), None);
        assert!(downloads(&device).is_empty());
        Ok(())
    }

    /// A claim that fails **after** `claim_interface` — a stalled `SET_INTERFACE`, which
    /// is the WebUSB case — must not leave the interface held.
    ///
    /// `AccessDenied` so that the bus reset cannot paper over it with a second
    /// attempt that would release on its own way out.
    #[test]
    fn a_claim_that_fails_half_way_still_releases() {
        let device = gadget(64);
        let clock = RecordingClock::new();

        device.inject(When::SetAlt, Fault::AccessDenied);

        let outcome = block_on(write(&device, &clock, &AltSel::Default, &image(64), &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(device.claimed(), None, "the interface was given back");
        assert!(downloads(&device).is_empty());
    }

    /// A named alt selects it: the `erase` virt alt takes its token through the same
    /// download path the remote erase drives.
    #[test]
    fn a_named_alt_is_the_one_written() -> TestResult {
        let device = gadget(64);
        let clock = RecordingClock::new();

        block_on(write(
            &device,
            &clock,
            &AltSel::Name("erase".into()),
            tdfu_usb::gadget::ERASE_TOKEN,
            &mut |_| {},
        ))?;

        assert_eq!(device.erases(), 1, "the token armed and the flush ran it");
        assert_eq!(device.alt(), 1);
        Ok(())
    }
}
