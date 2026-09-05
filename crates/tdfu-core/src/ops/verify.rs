//! Read back and compare.

use tdfu_usb::LocalUsbTransport;

use crate::bootrom::as_u64;
use crate::clock::Sleeper;
use crate::dfu::alt::resolve;
use crate::dfu::descriptors::read_info;
use crate::dfu::host;
use crate::error::{Error, Result};
use crate::model::{AltSel, DEFAULT_TRANSFER_SIZE, DfuInfo};
use crate::progress::{Phase, Progress, ProgressSink};

/// What core says when the read-back matched, with the byte count (`dfu.c:961`).
///
/// Emitted here rather than by each frontend: an earlier local CLI printed neither
/// this nor `DFU download complete` on success while its daemon printed both.
#[must_use]
pub fn matched_note(bytes: u64) -> String {
    format!("Verify OK: {bytes} bytes match")
}

/// Upload from `alt` and compare against `image`, stopping at the first difference.
///
/// The sequence is the C's, verified against `tdfu_dfu_verify_device`
/// (`dfu.c:875-965`): read the DFU info (`:883`), resolve the alt (`:886-887`), claim
/// and select it (`:888`), then up to two attempts of
/// [`make_idle`](host::make_idle) (`:915`) followed by `UPLOAD` blocks of
/// `wTransferSize` bytes (`:924`), each compared against the image as it arrives
/// (`:930-941`).
///
/// **The comparison stops at the image length, not at the medium's**
/// (`dfu.c:922`, `:930-931`): an 8 MiB image on a 16 MiB part reads 8 MiB and matches. There
/// is no `GETSTATUS` between `UPLOAD`s — an upload needs none, and the device ends one
/// by answering short (`f_dfu.c:566-569`).
///
/// **"First block" is an explicit flag**, as in [`write`](super::write): the C's
/// `block != 0` (`dfu.c:955`) reads a wrapped block number as a stale
/// transaction, and the flag is what replaces it. It is set as soon as the
/// device has answered a block, so a
/// mismatch *on block 0* is not retried either — which is the C's extra
/// `r == TDFU_ERROR_VERIFY` term in the same test.
///
/// # Never reset-retried for a mismatch
///
/// [`Error::Verify`] is [not recoverable](Error::is_recoverable), so the bus reset
/// cannot fire on it (pin `dfu_verify_never_reset_retried`). A *comms* failure during a
/// verify still is retried, exactly as the C's is (`dfu.c:1058-1065`, whose
/// `dfu_err_recoverable` excludes `TDFU_ERROR_VERIFY` at `:408-412`): the reset is for a
/// wedged EP0, and dropping it would lose the recovery the C has — the one
/// functional-parity regression an audit found was exactly that shape.
///
/// # NAND
///
/// A NAND compare is best-effort by nature — ECC and bad-block remap mean a
/// self-read dump cannot be trusted to round-trip — but the code does not soften it. A
/// mismatch is a failure, and the caller decides what that is worth on a NAND part.
///
/// # Errors
/// [`Error::Verify`] with the offset and both bytes on a difference, and
/// [`Error::Verify`] with `actual: None` if the device ends the upload before the image
/// does — see below. [`Error::Invalid`] if `image` is empty (`dfu.c:897-900`).
/// [`Error::MissingAlt`] or [`Error::Invalid`] if the loader has no such alt; otherwise
/// the transport's error after the retries.
///
/// ## A device that answers short is reported without inventing a byte
///
/// The C reports it as `TDFU_ERROR_VERIFY` with `mismatch_off = total` and a *different
/// message* — "device returned only %zu of %zu bytes" (`dfu.c:945-951`). Its error code
/// carries no bytes, so it has nothing to invent; [`Error::Verify`] carries two, and the
/// device sent no byte at that offset to put in `actual`. Fabricating one would print
/// `read back 0xFF` for data the device never sent: a message that misdirects rather
/// than one that says too little.
///
/// **This is settled and the code carries the settlement**:
/// [`Error::Verify::actual`] is an `Option<u8>` and a short device answer is a `Verify`
/// failure with `actual: None`, never an `Error::Invalid` and never a fabricated byte.
/// The offset therefore rides `tdfu_proto::verify_failed_message` for this case as well,
/// which is what the daemon needs from it. (This paragraph used to describe the *unapplied*
/// proposal — "returns `Error::Invalid` … a contract amendment would be better" — and
/// an implementer following the doc rather than the code would have regressed the wire
/// mapping back to where the amendment started.)
pub async fn verify<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    alt: &AltSel,
    image: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    if image.is_empty() {
        return Err(Error::Invalid(
            "the image is empty; there is nothing to compare against".into(),
        ));
    }
    host::reset_and_retry_once(dev, clock, progress, async |_attempt, progress| {
        verify_once(dev, alt, image, progress).await
    })
    .await
}

/// One whole attempt: info, alt, claim, compare, release.
///
/// No clock: an upload is never polled, so nothing here sleeps. A vestigial parameter is
/// a smell applied to ourselves here — `make_idle` and `retry_stale_block0` shed
/// theirs for the same reason.
async fn verify_once<T: LocalUsbTransport>(
    dev: &T,
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

    let outcome = compare(dev, &info, image, progress).await;
    let released = host::release(dev, info.interface).await;

    // The comparison's failure is the one the operator can act on; a release that also
    // failed after it tells them nothing new.
    match outcome {
        Ok(()) => released,
        Err(error) => Err(error),
    }
}

/// The upload loop and the comparison, with the interface claimed.
async fn compare<T: LocalUsbTransport>(
    dev: &T,
    info: &DfuInfo,
    image: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    let total = as_u64(image.len());
    // As in `write`: unreachable through `read_info`, which substitutes for a missing or
    // zero `wTransferSize`, but `DfuInfo` is public and a zero-length
    // `UPLOAD` would be answered for ever.
    let block_size = match info.transfer_size {
        0 => DEFAULT_TRANSFER_SIZE,
        size => size,
    };

    let left_open = host::retry_stale_block0(dev, info.interface, progress, async |transaction, progress| {
        progress(Progress::Phase(Phase::Verify));
        let mut block: u16 = 0;
        let mut done: usize = 0;
        // Whether the device's last answer left its read transaction open, which a full
        // block does and a short one does not.
        let mut left_open = false;
        while done < image.len() {
            // Narrated on the way out (`dfu.c:926`): which block died and how much had
            // already compared equal. A verify that fails at the same offset every run is
            // a bad chip; one that fails at a different offset each time is a bad link,
            // and this line is what tells them apart.
            let chunk = match host::upload(dev, info.interface, block, block_size).await {
                Ok(chunk) => chunk,
                Err(err) => {
                    progress(Progress::Debug(format!(
                        "verify: block {block} failed after {done} bytes compared ({err})"
                    )));
                    return Err(err);
                }
            };
            // The device answered, so from here a failure is not a stale sequence — and
            // neither is the mismatch this block may turn out to be. The C spells the
            // same rule as the extra `r == TDFU_ERROR_VERIFY` term at `dfu.c:955`.
            transaction.first_block_done();

            // Checked rather than trusted. `done < image.len()` is the loop condition
            // and `compared <= chunk.len()` follows from the `min`, so both of these
            // hold — but they hold because of a condition several lines away, and an
            // edit that moved the cursor would turn a wrong answer into a panic in a
            // library crate. `saturating_sub` and `get` cost nothing
            // and make the invariant local.
            let want = image.len().saturating_sub(done);
            let compared = chunk.len().min(want);
            let (Some(read_back), Some(expected)) =
                (chunk.get(..compared), image.get(done..done.saturating_add(compared)))
            else {
                return Err(Error::Protocol(format!(
                    "the verify cursor left the image: {compared} bytes at offset {done} of {}",
                    image.len()
                )));
            };
            if let Some(offset) = first_difference(read_back, expected) {
                let at = done.saturating_add(offset);
                return Err(Error::Verify {
                    offset: as_u64(at),
                    expected: image.get(at).copied().unwrap_or_default(),
                    actual: chunk.get(offset).copied(),
                });
            }
            done += compared;
            block = block.wrapping_add(1);
            progress(Progress::Bytes {
                phase: Phase::Verify,
                done: as_u64(done),
                total: Some(total),
            });

            // A short answer is how an upload ends (`dfu.c:945`). Past the image length
            // it is the expected ending; before it, the medium ran out first.
            if chunk.len() < usize::from(block_size) && done < image.len() {
                // A short device answer is a Verify failure with no read-back byte, not
                // generic invalid input - the offset can then ride
                // `tdfu_proto::verify_failed_message` on the daemon wire.
                return Err(Error::Verify {
                    offset: as_u64(done),
                    expected: image.get(done).copied().unwrap_or_default(),
                    actual: None,
                });
            }
            left_open = chunk.len() >= usize::from(block_size);
        }
        Ok(left_open)
    })
    .await?;

    if left_open {
        // The comparison stops at the image's length, so on a medium bigger than the
        // image the last block was a *full* one and U-Boot's read transaction is still
        // inited, its sequence counter part way along. On a loader without `3d4848fe0dc`
        // that survives an alt switch and a bus reset, so closing it here is what stops
        // the next write, read or verify paying a stale-block-0 retry it did not earn:
        // the shipped flow is write, verify, read back. Best effort, as `erase`'s
        // close-out is: the read-back has already answered, and a tidy-up request that
        // stalled says nothing about the flash.
        drop(host::abort(dev, info.interface).await);
    }

    progress(Progress::Note(matched_note(total)));
    Ok(())
}

/// Where two equal-length runs first differ (`tdfu_first_diff`, `utils.c:294`).
fn first_difference(read_back: &[u8], expected: &[u8]) -> Option<usize> {
    read_back
        .iter()
        .zip(expected)
        .position(|(read_back, expected)| read_back != expected)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use tdfu_usb::gadget::{AltConfig, FakeGadget, Fault, GadgetConfig, Loader, When, request};
    use tdfu_usb::mock::{Call, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{ControlIn, ControlType, DeviceDescriptors, InterfaceSpec, Recipient, pid, vid};

    use super::{matched_note, verify};
    use crate::clock::RecordingClock;
    use crate::dfu::descriptors::fixtures::SINGLE_ALT_CONFIG;
    use crate::dfu::host::{CONTROL_TIMEOUT, State};
    use crate::error::Error;
    use crate::model::AltSel;
    use crate::ops::write;
    use crate::progress::{Phase, Progress};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Everything an operation said, in order.
    #[derive(Debug, Default)]
    struct Said(RefCell<Vec<Progress>>);

    impl Said {
        fn all(&self) -> Vec<Progress> {
            self.0.borrow().clone()
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
    }

    /// An image whose bytes all differ from `0xFF`, so erased flash never matches by
    /// accident.
    fn image(len: usize) -> Vec<u8> {
        (0..len).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect()
    }

    /// A gadget with the three shipped alts and `transfer_size`-byte blocks.
    fn gadget(transfer_size: u16) -> FakeGadget {
        FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(transfer_size))
    }

    /// A gadget whose boot flash holds exactly `size` bytes.
    fn small_gadget(transfer_size: u16, size: u64) -> FakeGadget {
        FakeGadget::new(
            GadgetConfig::new(vec![
                AltConfig::flash("flash", size),
                AltConfig::erase(),
                AltConfig::reboot(),
            ])
            .with_transfer_size(transfer_size),
        )
    }

    /// The `UPLOAD` block numbers a run issued, in order.
    fn uploads(gadget: &FakeGadget) -> Vec<u16> {
        gadget
            .class_requests()
            .into_iter()
            .filter_map(|(request, value)| (request == request::UPLOAD).then_some(value))
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

    /// The six `GETSTATUS` bytes of a settled device.
    fn settled() -> Reply {
        Reply::Data(vec![0, 0, 0, 0, State::DfuIdle.code(), 0])
    }

    /// The single-alt gadget of `SINGLE_ALT_CONFIG` (`wTransferSize` 4096), unconfigured
    /// as a driverless device is.
    fn scripted() -> MockTransport {
        let mock = MockTransport::new(
            DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_config_descriptor(SINGLE_ALT_CONFIG),
        );
        let total = u16::try_from(SINGLE_ALT_CONFIG.len()).unwrap_or_default();
        mock.expecting(get_descriptor(9), Reply::Data(SINGLE_ALT_CONFIG[..9].to_vec()))
            .expecting(get_descriptor(total), Reply::Data(SINGLE_ALT_CONFIG.to_vec()))
    }

    /// A claim that fails **after** `claim_interface` — a stalled `SET_INTERFACE`, which
    /// is the WebUSB case — must not leave the interface held. The branch existed here
    /// from the start; only the pin was missing, which meant deleting the branch cost
    /// nothing.
    ///
    /// `AccessDenied` so that the bus reset cannot paper over it with a second
    /// attempt that would release on its own way out.
    #[test]
    fn a_claim_that_fails_half_way_still_releases() {
        let device = gadget(64);
        device.preload(0, image(64));
        let clock = RecordingClock::new();
        device.inject(When::SetAlt, Fault::AccessDenied);

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &image(64), &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(device.claimed(), None, "the interface was given back");
    }

    /// **The pin, on the wire**: `UPLOAD`s with no `GETSTATUS` between them,
    /// each on the 5 s control deadline, and the read stopping at the image length.
    #[test]
    fn op_verify_sequence() -> TestResult {
        let payload = image(4106);
        let mock = scripted()
            .expecting(Call::SetConfiguration(1), Reply::Done)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(class_in(request::GETSTATUS, 0, 6), settled())
            .expecting(
                class_in(request::UPLOAD, 0, 4096),
                Reply::Data(payload[..4096].to_vec()),
            )
            // The image has 10 bytes left, so the second block is the last one asked
            // for — a 16 MiB part is not read to its end.
            .expecting(
                class_in(request::UPLOAD, 1, 4096),
                Reply::Data(payload[4096..].to_vec()),
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(verify(&mock, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(mock.remaining(), 0, "every scripted call was made, in order");
        let class: Vec<(u8, Option<core::time::Duration>)> = mock
            .calls()
            .iter()
            .filter_map(|Recorded { call, timeout }| match *call {
                Call::ControlIn {
                    control_type: ControlType::Class,
                    request,
                    ..
                } => Some((request, *timeout)),
                _ => None,
            })
            .collect();
        assert_eq!(
            class,
            [
                (request::GETSTATUS, Some(CONTROL_TIMEOUT)),
                (request::UPLOAD, Some(CONTROL_TIMEOUT)),
                (request::UPLOAD, Some(CONTROL_TIMEOUT)),
            ],
            "one make-idle poll, then uploads with nothing between them"
        );
        // The literal, once, so that `matched_note` is pinned against text rather than
        // against itself: an assertion written as `[matched_note(4106)]` compares the
        // function with the function and survives any change to what it says.
        assert_eq!(said.notes(), ["Verify OK: 4106 bytes match"]);
        Ok(())
    }

    // ---- the emulated half ---------------------------------------------------

    /// A verify of what a write just put there, in the same DFU session and on the same
    /// alt — no re-bootstrap, because U-Boot DFU is manifestation-tolerant.
    ///
    /// **The pin is `op_verify_after_write_same_session`**: the state that
    /// makes this work is the device's, so it is asserted through the emulator's entity
    /// rather than through a script that would answer whatever it was told to.
    #[test]
    fn op_verify_after_write_same_session() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(write(&device, &clock, &AltSel::Default, &payload, &mut |_| {}))?;
        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(said.notes(), [matched_note(200)], "said so, exactly once");
        assert_eq!(said.phases(Phase::Verify), 1);
        assert_eq!(uploads(&device), [0, 1, 2, 3], "four blocks cover 200 bytes");
        assert_eq!(device.resets(), 0);
        assert_eq!(device.claimed(), None, "released on the way out");

        // The byte counter runs to the image length, not to the medium's.
        assert_eq!(
            said.all().last(),
            Some(&Progress::Note(matched_note(200))),
            "{:?}",
            said.all()
        );
        assert!(said.all().contains(&Progress::Bytes {
            phase: Phase::Verify,
            done: 200,
            total: Some(200)
        }));
        Ok(())
    }

    /// **The comparison pin, first half**: the first differing byte, with both values.
    #[test]
    fn op_verify_first_diff_and_short_reports_the_difference() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        let mut on_flash = payload.clone();
        on_flash[130] ^= 0xFF;
        device.preload(0, on_flash.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));

        match outcome {
            Err(Error::Verify {
                offset,
                expected,
                actual,
            }) => {
                assert_eq!(offset, 130, "the first difference, not the block it is in");
                assert_eq!(expected, payload[130]);
                assert_eq!(actual, Some(on_flash[130]));
            }
            other => return Err(format!("expected Error::Verify, got {other:?}").into()),
        }
        // It stopped there: block 2 holds offset 130, so block 3 was never asked for.
        assert_eq!(uploads(&device), [0, 1, 2]);
        assert!(said.notes().is_empty(), "{:?}", said.notes());
        assert_eq!(device.claimed(), None, "released on the failure path");
        Ok(())
    }

    /// The first difference is the *first*, even when a later block differs too.
    #[test]
    fn the_reported_offset_is_the_earliest_difference() {
        let device = gadget(64);
        let payload = image(200);
        let mut on_flash = payload.clone();
        on_flash[7] ^= 0xFF;
        on_flash[150] ^= 0xFF;
        device.preload(0, on_flash);
        let clock = RecordingClock::new();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Verify { offset: 7, .. })), "{outcome:?}");
        assert_eq!(uploads(&device), [0], "it stopped inside the first block");
    }

    /// **The comparison pin, second half**: a device that ends the upload before the
    /// image does is a verify failure, and it says where and how far it got.
    ///
    /// The C reports the same case as `TDFU_ERROR_VERIFY` with a message of its own
    /// ("device returned only %zu of %zu bytes", `dfu.c:945-951`). Here it is
    /// [`Error::Verify`] carrying `actual: None`: the device sent no byte at that
    /// offset, and the `Option` is what keeps a read-back byte from being invented for
    /// it. The function's own documentation settles it the same way.
    #[test]
    fn op_verify_first_diff_and_short_reports_a_short_device() -> TestResult {
        // A 100-byte medium under a 200-byte image: the second block comes back short.
        let device = small_gadget(64, 100);
        let payload = image(200);
        device.preload(0, payload[..100].to_vec());
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));

        match outcome {
            // A short device answer is a Verify failure with no read-back byte, so the
            // offset can ride the daemon wire.
            Err(Error::Verify { offset, actual, .. }) => {
                assert_eq!(offset, 100, "how far it got");
                assert_eq!(actual, None, "no byte was read at that offset");
            }
            other => return Err(format!("expected Error::Verify with actual: None, got {other:?}").into()),
        }
        assert_eq!(uploads(&device), [0, 1], "it stopped when the medium did");
        assert!(said.notes().is_empty(), "no completion note: {:?}", said.notes());
        assert_eq!(device.resets(), 0, "a short medium is not a comms failure");
        Ok(())
    }

    /// A short answer *at* the image length is the normal ending, not a failure: the
    /// medium and the image are the same size.
    #[test]
    fn a_short_answer_at_the_image_length_is_the_normal_ending() -> TestResult {
        let device = small_gadget(64, 200);
        let payload = image(200);
        device.preload(0, payload.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(said.notes(), [matched_note(200)]);
        Ok(())
    }

    /// **The `dfu_verify_never_reset_retried` pin, at operation level.**
    ///
    /// A mismatch is final: no bus reset, no second attempt, no stale-transaction retry
    /// — and the mismatch is put on *block 0* so that the block 0 retry's "the first block
    /// failed" rule would fire if the transfer did not mark the block as answered. The C
    /// spells the same exception as the extra `r == TDFU_ERROR_VERIFY` term in its
    /// attempt-loop test (`dfu.c:955`) and by excluding `TDFU_ERROR_VERIFY` from
    /// `dfu_err_recoverable` (`dfu.c:408-412`, used at `:1063`).
    #[test]
    fn dfu_verify_never_reset_retried() {
        let device = gadget(64);
        let payload = image(200);
        let mut on_flash = payload.clone();
        on_flash[0] ^= 0xFF;
        device.preload(0, on_flash);
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));

        assert!(matches!(outcome, Err(Error::Verify { offset: 0, .. })), "{outcome:?}");
        assert_eq!(device.resets(), 0, "must not fire on a mismatch");
        assert_eq!(uploads(&device), [0], "one attempt, one block");
        assert_eq!(said.phases(Phase::Verify), 1, "nothing restarted the comparison");
        assert!(said.notes().is_empty(), "{:?}", said.notes());
    }

    /// **The narration pin.** A block that fails names itself and how many bytes had
    /// already compared equal (`dfu.c:926`).
    ///
    /// A verify that fails at the same offset every run is a bad chip; one that fails at a
    /// different offset each time is a bad link. The offset is the whole diagnosis, and
    /// without this line a comms failure carries none. Revert check: delete the
    /// `Progress::Debug` call in `compare` and this fails.
    #[test]
    fn a_failed_verify_block_narrates_where_it_died() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        device.preload(0, payload.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        // Past the first block, and not recoverable, so neither retry re-runs the
        // comparison: one attempt, one line.
        device.inject(When::ClassBlock(request::UPLOAD, 2), Fault::AccessDenied);

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }));
        assert!(outcome.is_err(), "{outcome:?}");

        let failed = said
            .debug()
            .into_iter()
            .find(|line| line.contains("failed after"))
            .ok_or("the failed block was never narrated")?;
        assert!(failed.contains("verify: block 2"), "{failed}");
        assert!(failed.contains("128 bytes compared"), "{failed}");
        assert!(said.notes().is_empty(), "{:?}", said.notes());
        Ok(())
    }

    /// The other half of the same rule, which the C keeps and an earlier implementation lost
    /// elsewhere: a *comms* failure during a verify **is** reset-retried
    /// (`dfu.c:1058-1065`). Only the data mismatch is final.
    #[test]
    fn a_comms_failure_during_a_verify_is_still_reset_retried() -> TestResult {
        let device = gadget(64);
        let payload = image(200);
        device.preload(0, payload.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        device.inject(When::ClassBlock(request::UPLOAD, 2), Fault::NoDevice);

        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.resets(), 1, "exactly one recovery reset");
        assert!(
            said.notes().iter().any(|note| note.contains("USB-reset")),
            "the recovery was announced: {:?}",
            said.notes()
        );
        assert_eq!(
            said.notes().last().map(String::as_str),
            Some(matched_note(200).as_str())
        );
        Ok(())
    }

    /// **The wrap pin**: a failure on a block whose
    /// *number* is 0 but which is not the first block is not a stale transaction.
    ///
    /// The same 65536-block wrap as `op_write_block_wrap_safe`, on the loop the C also
    /// gets wrong at `dfu.c:955`. `AccessDenied` so that the bus reset cannot retry it
    /// either, and any restart at all would be this bug.
    #[test]
    fn op_verify_block_wrap_safe() {
        const BLOCK: usize = 64;
        const WRAP_AT: u64 = 65536 * BLOCK as u64;

        let device = small_gadget(u16::try_from(BLOCK).unwrap_or(64), 8 << 20);
        let payload = image(65537 * BLOCK);
        device.preload(0, payload.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            if let Progress::Bytes { done, .. } = step
                && done == WRAP_AT
            {
                device.inject(When::ClassBlock(request::UPLOAD, 0), Fault::AccessDenied);
            }
            said.0.borrow_mut().push(step);
        }));

        assert!(matches!(outcome, Err(Error::Usb(_))), "{outcome:?}");
        assert_eq!(said.phases(Phase::Verify), 1, "nothing restarted the comparison");
        assert!(said.notes().is_empty(), "no retry of any kind: {:?}", said.notes());
        assert_eq!(device.resets(), 0);
        assert_eq!(uploads(&device).len(), 65537, "65536 blocks and the refused wrap");
    }

    /// **The block 0 retry in the verify loop, on the loader generation that needs it.** A
    /// genuine block-0 refusal — an entity left mid-sequence by an abandoned transfer —
    /// is cleared and the comparison starts again.
    #[test]
    fn a_stale_transaction_is_cleared_and_the_comparison_restarts() -> TestResult {
        use crate::dfu::host as dfu_host;
        use tdfu_usb::LocalUsbTransport;

        let device = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(64).with_loader(Loader::Legacy));
        let payload = image(100);
        device.preload(0, payload.clone());
        let clock = RecordingClock::new();
        let said = Said::default();

        // Abandon an upload part-way, then reset the bus as a browser reload does.
        block_on(async {
            let info = crate::dfu::read_info(&device).await?;
            dfu_host::claim(&device, &info, 0).await?;
            drop(dfu_host::upload(&device, info.interface, 0, 64).await?);
            device.reset().await.map_err(Error::from)
        })?;
        let resets_before = device.resets();
        assert_eq!(device.entity_sequence(0), Some(1), "the entity is stale");

        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(device.wrong_sequence_refusals(), 1, "exactly one");
        assert_eq!(device.resets(), resets_before, "no bus reset of its own");
        assert!(
            said.notes().iter().any(|note| note.contains("stale DFU transaction")),
            "the retry was announced: {:?}",
            said.notes()
        );
        assert_eq!(said.phases(Phase::Verify), 2, "the comparison restarted from the top");
        assert_eq!(
            said.notes().last().map(String::as_str),
            Some(matched_note(100).as_str())
        );
        Ok(())
    }

    /// An empty image is refused before anything reaches the bus — the one input check
    /// the C's verify already has (`dfu.c:897-900`).
    #[test]
    fn an_empty_image_is_refused() {
        let device = gadget(64);
        let clock = RecordingClock::new();

        let outcome = block_on(verify(&device, &clock, &AltSel::Default, &[], &mut |_| {}));

        assert!(matches!(outcome, Err(Error::Invalid(_))), "{outcome:?}");
        assert!(device.events().is_empty(), "nothing was sent to the device");
    }

    /// An alt the loader does not have fails before the claim.
    #[test]
    fn an_unknown_alt_is_refused_before_the_claim() -> TestResult {
        let device = gadget(64);
        let clock = RecordingClock::new();

        let outcome = block_on(verify(&device, &clock, &AltSel::Index(9), &image(64), &mut |_| {}));

        match outcome {
            Err(Error::Invalid(message)) => assert!(message.contains("alt 9"), "{message}"),
            other => return Err(format!("expected Error::Invalid, got {other:?}").into()),
        }
        assert_eq!(device.claimed(), None);
        assert!(uploads(&device).is_empty());
        Ok(())
    }

    /// Only the bytes the image has are compared: everything past its length on a bigger
    /// medium is not read at all: an 8 MiB image on a 16 MiB part.
    #[test]
    fn a_shorter_image_is_compared_only_as_far_as_it_goes() -> TestResult {
        let device = gadget(64);
        // The medium holds twice the image, and the tail differs from it.
        let payload = image(100);
        let mut on_flash = payload.clone();
        on_flash.extend(std::iter::repeat_n(0xA5, 100));
        device.preload(0, on_flash);
        let clock = RecordingClock::new();
        let said = Said::default();

        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |step| {
            said.0.borrow_mut().push(step);
        }))?;

        assert_eq!(said.notes(), [matched_note(100)]);
        assert_eq!(
            uploads(&device),
            [0, 1],
            "two blocks cover 100 bytes; the tail is not read"
        );
        Ok(())
    }

    /// The read transaction the comparison leaves open is closed before the release.
    ///
    /// An image shorter than the medium ends the compare on a *full* block, which
    /// leaves U-Boot's entity inited with its sequence counter part way along. On a
    /// loader without `3d4848fe0dc` that survives an alt switch and a bus reset, so the
    /// next operation in the shipped write-verify-read-back flow would pay a
    /// stale-block-0 retry it did not earn.
    #[test]
    fn op_verify_closes_the_read_transaction_before_it_releases() -> TestResult {
        let device = gadget(64);
        let payload = image(100);
        let mut on_flash = payload.clone();
        on_flash.extend(std::iter::repeat_n(0xA5, 100));
        device.preload(0, on_flash);
        let clock = RecordingClock::new();

        block_on(verify(&device, &clock, &AltSel::Default, &payload, &mut |_| {}))?;

        assert_eq!(device.entity_inited(0), Some(false), "the transaction was closed");
        assert_eq!(device.entity_sequence(0), Some(0), "and its counter is back at 0");
        assert_eq!(device.claimed(), None, "and the interface was released after it");
        Ok(())
    }
}
