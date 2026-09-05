//! Bring a bootrom up as a U-Boot DFU gadget.

use tdfu_usb::LocalUsbTransport;

use crate::bootrom::{self, SPL_ENTRY_ADDR, SPL_LOAD_ADDR, UBOOT_ADDR, pad_stage1};
use crate::clock::Sleeper;
use crate::error::Result;
use crate::progress::{Phase, Progress, ProgressSink};

/// How long to wait after `PROG_STAGE1` before staging U-Boot.
pub const POST_STAGE1_SETTLE: core::time::Duration = core::time::Duration::from_secs(1);

/// The line that says the sequence finished, as a
/// [`Progress::Note`](crate::progress::Progress).
///
/// The C's one completion line (`libtdfu/src/dfu/dfu.c:1148`, at `LOG_INFO`). It is
/// emitted by core rather than by each frontend: an earlier local CLI printed
/// *nothing* on a successful write while its daemon printed two lines, because the
/// completion lines lived in the frontends. Emitted after `PROG_STAGE2`, which cannot fail, so it is
/// reached on every path that got that far — exactly as the C's is.
///
/// A named constant so the wording is a fixed thing a test can pin, not whatever the
/// call site happens to say.
pub const STARTING_NOTE: &str = "U-Boot starting; the device will re-enumerate in DFU mode";

/// Stage and run the SPL, then stage and run U-Boot.
///
/// The order is exact and pinned (`boot_sequence_order`): claim, upload the
/// [cache-line-padded](crate::bootrom::pad_stage1) stage-1 image to
/// [`SPL_LOAD_ADDR`](crate::bootrom::SPL_LOAD_ADDR), release, `PROG_STAGE1` at
/// [`SPL_ENTRY_ADDR`](crate::bootrom::SPL_ENTRY_ADDR), wait [`POST_STAGE1_SETTLE`],
/// claim, upload the **equally padded** U-Boot image to
/// [`UBOOT_ADDR`](crate::bootrom::UBOOT_ADDR), release, `FLUSH_CACHE`, `PROG_STAGE2`.
///
/// Three rules that look like details and are not:
///
/// * **There is exactly one `FLUSH_CACHE`, and it is before `PROG_STAGE2`.** Not before
///   `PROG_STAGE1`: the C does not
///   (`libtdfu/src/dfu/dfu.c:1129-1150` — load, `prog_stage1` at `:1135`, sleep, load,
///   `flush_cache` at `:1146`, `prog_stage2`) issues one there, and on a capped XBurst1
///   the stage-1 image is executing out of cache-as-RAM, so a flush before it runs could
///   invalidate the very lines it is about to execute. `boot_sequence_order` must assert
///   the **absence** of a flush between the stage-1 upload and `PROG_STAGE1`, not merely
///   the presence of the later one — an extra request is invisible to a pin that only
///   checks that the right ones appear.
/// * **`FLUSH_CACHE`'s failure is fatal** and `PROG_STAGE2` is not sent after it. The C
///   calls it bare (`dfu.c:1146`); jumping into an unflushed cache is undefined
///   behaviour.
/// * **`PROG_STAGE2` failing is success**: the device is already running
///   U-Boot and re-enumerating.
///
/// **Both images take [`pad_stage1`](crate::bootrom::pad_stage1)**, not just the
/// stage-1 one. The C pads inside `bootstrap_load_data_to_memory`
/// (`libtdfu/src/bootstrap.c:36-46`), and both call sites go through it — `dfu.c:1132`
/// for the SPL and `dfu.c:1143` for U-Boot. The name says `stage1` because the rounding
/// matters most in the stage-1 case, where the cache-as-RAM I-cache fill makes it
/// load-bearing; the rounding itself is not stage-specific and the C applies it to both.
///
/// The claim spans one image, not the whole sequence: the C claims inside its transfer
/// helper (`bootstrap.c:77`) and releases at the end of it (`bootstrap.c:173`), and the
/// release is load-bearing — on the T20 an interface left claimed makes the
/// following `FLUSH_CACHE` and `PROG_STAGE2` time out.
/// [`bootrom::load_to_memory`](crate::bootrom::load_to_memory) owns both halves and
/// releases on **every** path out of itself, so this function claims nothing and there
/// is no exit path here that can leak one — including the one where `PROG_STAGE1` fails
/// between the two uploads.
///
/// **Nothing here waits for the gadget to appear.** That is the caller's job — the CLI
/// polls, the daemon has its 120 × 250 ms re-enumeration window.
///
/// # Progress
///
/// A [`Progress::Phase`](crate::progress::Progress) before each upload
/// ([`Phase::Stage1`](crate::progress::Phase::Stage1),
/// [`Phase::UBoot`](crate::progress::Phase::UBoot)), the byte counters
/// `load_to_memory` emits within them, and `STARTING_NOTE` at the end. That constant is
/// not re-exported from [`ops`](crate::ops) — `ops/mod.rs` holds only re-exports
/// so a frontend renders the note as the data it is.
///
/// # Errors
/// [`Error::Invalid`](crate::Error::Invalid) if either image is empty
/// (`bootstrap.c:27-29`). [`Error::Usb`](crate::Error::Usb) for a failed upload, a
/// failed `PROG_STAGE1`, or a failed `FLUSH_CACHE`. Never for `PROG_STAGE2`.
pub async fn bootstrap<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    stage1: &[u8],
    uboot: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    // Padded: **both** images, before anything reaches the wire, so
    // that a padding failure cannot happen halfway through a bootstrap.
    let stage1 = pad_stage1(stage1);
    let uboot = pad_stage1(uboot);

    progress(Progress::Phase(Phase::Stage1));
    // The C's `dfu.c:1131` and `:1142`, after the phase rather than before it: the phase
    // opens the step and this is its detail. The size is the padded one, which is what
    // actually crosses the bus, and the addresses are the two that decide
    // whether a bootstrap can work at all.
    progress(Progress::Debug(format!(
        "stage 1: {} bytes to {SPL_LOAD_ADDR:#010x}, entered at {SPL_ENTRY_ADDR:#010x}",
        stage1.len()
    )));
    bootrom::load_to_memory(dev, clock, SPL_LOAD_ADDR, &stage1, &mut *progress).await?;
    // No FLUSH_CACHE here. The stage-1 image may be executing out of
    // cache-as-RAM on a capped XBurst1, so flushing before it runs could invalidate it.
    bootrom::prog_stage1(dev, clock, SPL_ENTRY_ADDR).await?;

    // Stage 1 brings up clock and DDR and returns to the bootrom. U-Boot
    // DMA'd in before that completes lands in uninitialised DDR (`dfu.c:1139-1140`).
    clock.sleep(POST_STAGE1_SETTLE).await;

    progress(Progress::Phase(Phase::UBoot));
    progress(Progress::Debug(format!(
        "U-Boot: {} bytes to {UBOOT_ADDR:#010x}",
        uboot.len()
    )));
    bootrom::load_to_memory(dev, clock, UBOOT_ADDR, &uboot, &mut *progress).await?;

    // Fatal, and PROG_STAGE2 is not sent after it.
    bootrom::flush_cache(dev, clock).await?;
    // Any failure here *is* success — the device has already jumped.
    // `prog_stage2` swallows it, so this `?` is the shape of its siblings and nothing
    // more.
    bootrom::prog_stage2(dev, clock, UBOOT_ADDR).await?;

    progress(Progress::Note(STARTING_NOTE.to_owned()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use tdfu_usb::mock::{Call, MockError, MockTransport, Reply, block_on};
    use tdfu_usb::{
        ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind, endpoint,
        pid, vid,
    };

    use super::{POST_STAGE1_SETTLE, STARTING_NOTE, bootstrap};
    use crate::bootrom::{
        CONFIGURATION, SETTLE_AFTER_VENDOR_REQUEST, SPL_ENTRY_ADDR, SPL_LOAD_ADDR, STAGE1_ALIGN, UBOOT_ADDR, request,
    };
    use crate::clock::RecordingClock;
    use crate::progress::{Phase, Progress};

    /// A bootrom as enumeration sees it: the product string really does
    /// carry a junk prefix, and is never compared for equality.
    fn bootrom() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("\u{c3}\t USB Boot Device")
    }

    /// What [`bootrom::claim`](crate::bootrom::claim) declares.
    fn interface() -> InterfaceSpec {
        InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT)
    }

    /// The vendor split: `wValue` takes the high half, `wIndex` the low.
    fn halves(value: u32) -> (u16, u16) {
        (
            u16::try_from(value >> 16).unwrap_or_default(),
            u16::try_from(value & 0xFFFF).unwrap_or_default(),
        )
    }

    /// The `Call` one vendor OUT with no data stage makes.
    fn vendor(request: u8, value: u16, index: u16) -> Call {
        Call::control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request,
            value,
            index,
            data: &[],
        })
    }

    /// The `Call` a vendor OUT carrying a 32-bit word makes.
    fn vendor_word(request: u8, word: u32) -> Call {
        let (value, index) = halves(word);
        vendor(request, value, index)
    }

    /// The calls a scripted device saw, without their timeouts.
    fn calls(dev: &MockTransport) -> Vec<Call> {
        dev.calls().into_iter().map(|recorded| recorded.call).collect()
    }

    /// The exact sequence one padded image's upload makes: `SET_DATA_ADDR`,
    /// `SET_DATA_LEN`, claim, one bulk OUT, release (`bootstrap.c:48-66, 77, 173`).
    ///
    /// `image` must already be padded — this mirrors what goes on the wire, and the
    /// padding is the caller's.
    fn upload(addr: u32, image: &[u8]) -> Vec<Call> {
        let len = u32::try_from(image.len()).unwrap_or_default();
        vec![
            vendor_word(request::SET_DATA_ADDR, addr),
            vendor_word(request::SET_DATA_LEN, len),
            Call::ClaimInterface(interface()),
            Call::BulkOut { data: image.to_vec() },
            Call::ReleaseInterface(0),
        ]
    }

    /// Script a whole successful bootstrap of `stage1` + `uboot`, both already padded.
    ///
    /// `configured` starts the device in [`CONFIGURATION`] so the claims can be checked
    /// for the redundant `SET_CONFIGURATION` a differential capture found.
    fn scripted(stage1: &[u8], uboot: &[u8], configured: bool) -> MockTransport {
        let mut mock = MockTransport::new(bootrom());
        if configured {
            mock = mock.configured(CONFIGURATION);
        }
        let mut expected = upload(SPL_LOAD_ADDR, stage1);
        expected.push(vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR));
        expected.extend(upload(UBOOT_ADDR, uboot));
        expected.push(vendor(request::FLUSH_CACHE, 0, 0));
        expected.push(vendor_word(request::PROG_STAGE2, UBOOT_ADDR));

        // An unconfigured device answers the *first* claim's `SET_CONFIGURATION` and is
        // configured from then on, so the second claim sends none. Tracked here rather
        // than read back off the mock: the script is built before anything runs.
        let mut in_configuration = configured;
        for call in expected {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            if matches!(call, Call::ClaimInterface(_)) && !in_configuration {
                mock = mock.expecting(Call::SetConfiguration(CONFIGURATION), Reply::Done);
                in_configuration = true;
            }
            mock = mock.expecting(call, reply);
        }
        mock
    }

    /// Collect everything an operation says.
    fn record(sink: &mut Vec<Progress>) -> impl FnMut(Progress) {
        move |progress| sink.push(progress)
    }

    // -----------------------------------------------------------------
    // The sequence itself.
    // -----------------------------------------------------------------

    /// **The sequence pin.** The exact request sequence, the exact addresses, and —
    /// the half a presence check cannot see — the **absence** of a `FLUSH_CACHE` before
    /// `PROG_STAGE1`.
    ///
    /// The doc this function was written from used to specify a flush there, which
    /// the C (`dfu.c:1129-1150`) does not issue, and on a capped
    /// XBurst1 the stage-1 image is executing out of cache-as-RAM, so a flush before it
    /// runs could invalidate the lines it is about to execute. A pin that
    /// only asserted "a `FLUSH_CACHE` appears" would pass with two of them.
    ///
    /// **The traffic is asserted before the outcome is.** A scripted mock refuses an
    /// unexpected request, so an extra flush would fail the operation and every
    /// assertion below would be skipped in favour of "bootstrap failed" — which is a
    /// pass/fail signal, not a *reason*. Reading the recorded calls first means the
    /// mutation that inserts a flush before `PROG_STAGE1` is reported as exactly that.
    /// The one line a bootstrap prints, **as text**.
    ///
    /// Spelt out rather than compared against itself. `STARTING_NOTE` was pinned only by
    /// `said.last() == Some(&Note(STARTING_NOTE.to_owned()))`, which passes for any value
    /// the constant could hold — including an empty string — while each of its four
    /// siblings (`erasing_note`, `COMPLETE_NOTE`, `rebooting_note`, `TRIGGERED_NOTE`) is
    /// anchored to a literal. Byte-identical output with the C is no longer a goal,
    /// which is exactly why these are ours to keep stable and why a literal is
    /// what keeps them.
    #[test]
    fn boot_note_is_the_line_the_user_reads() {
        assert_eq!(
            STARTING_NOTE,
            "U-Boot starting; the device will re-enumerate in DFU mode"
        );
    }

    /// **The narration pin.** Both stages say their size and where they are going
    /// (`dfu.c:1131`, `:1142`), on the debug channel and after their phase.
    ///
    /// The addresses are the two facts that decide whether a bootstrap can work at all,
    /// and a bootstrap that put U-Boot at the wrong address looks, from outside, exactly
    /// like a device that did not come back. Revert check: delete either
    /// `Progress::Debug` call and this fails.
    #[test]
    fn boot_narrates_both_stages_with_their_sizes_and_addresses() -> Result<(), MockError> {
        // Both already multiples of STAGE1_ALIGN, so the padded length these lines report
        // is the length passed in and the assertion says one thing.
        let stage1 = [0xA5_u8; 32];
        let uboot = [0x5A_u8; 64];
        let mock = scripted(&stage1, &uboot, true);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("the bootstrap failed: {error}")))?;

        let lines: Vec<&str> = said
            .iter()
            .filter_map(|step| match step {
                Progress::Debug(text) => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            lines,
            [
                format!("stage 1: 32 bytes to {SPL_LOAD_ADDR:#010x}, entered at {SPL_ENTRY_ADDR:#010x}"),
                format!("U-Boot: 64 bytes to {UBOOT_ADDR:#010x}"),
            ],
            "the two stage lines, in order, and nothing per data chunk"
        );
        // The phase still opens each step: the narration is the detail behind it, so a
        // frontend with debug off is not left without a stage word.
        assert_eq!(said.first(), Some(&Progress::Phase(Phase::Stage1)));
        mock.verify()
    }

    #[test]
    fn boot_sequence_order() -> Result<(), MockError> {
        // Padded already: 32 and 64 bytes are both multiples of STAGE1_ALIGN, so this
        // test says nothing about padding and `boot_both_images_are_padded` says it all.
        let stage1 = [0xA5_u8; 32];
        let uboot = [0x5A_u8; 64];
        let mock = scripted(&stage1, &uboot, true);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let outcome = block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)));

        // The run-up to PROG_STAGE1 is the stage-1 upload and *nothing else* — the
        // absence that matters, stated as an equality so an inserted request
        // shows up as itself.
        let seen = calls(&mock);
        let run_up = [
            upload(SPL_LOAD_ADDR, &stage1),
            vec![vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR)],
        ]
        .concat();
        assert_eq!(
            seen.get(..run_up.len()),
            Some(run_up.as_slice()),
            "something was issued between the stage-1 upload and PROG_STAGE1"
        );

        outcome.map_err(|error| MockError::Script(format!("bootstrap failed: {error}")))?;

        let position = |wanted: u8| {
            seen.iter()
                .position(|call| matches!(call, Call::ControlOut { request, .. } if *request == wanted))
        };
        let stage1_at =
            position(request::PROG_STAGE1).ok_or_else(|| MockError::Script("PROG_STAGE1 was never sent".to_owned()))?;
        let stage2_at =
            position(request::PROG_STAGE2).ok_or_else(|| MockError::Script("PROG_STAGE2 was never sent".to_owned()))?;
        let flush_at =
            position(request::FLUSH_CACHE).ok_or_else(|| MockError::Script("FLUSH_CACHE was never sent".to_owned()))?;

        // Exactly one flush, and it is between the two.
        let flushes = seen
            .iter()
            .filter(|call| matches!(call, Call::ControlOut { request, .. } if *request == request::FLUSH_CACHE))
            .count();
        assert_eq!(flushes, 1, "the sequence must flush the cache exactly once");
        assert!(stage1_at < flush_at, "a FLUSH_CACHE was issued before PROG_STAGE1");
        assert!(flush_at < stage2_at, "FLUSH_CACHE must precede PROG_STAGE2");

        // Nothing here waits for the gadget. `verify()` proves no request
        // followed PROG_STAGE2, and this says what would have been wrong about it.
        assert_eq!(
            seen.last(),
            Some(&vendor_word(request::PROG_STAGE2, UBOOT_ADDR)),
            "bootstrap must stop at PROG_STAGE2 and leave the waiting to its caller"
        );
        assert!(
            !seen
                .iter()
                .any(|call| matches!(call, Call::Reset | Call::ControlIn { .. })),
            "bootstrap reset or interrogated the device"
        );

        // The phases, and the C's one completion line (`dfu.c:1148`).
        assert_eq!(said.first(), Some(&Progress::Phase(Phase::Stage1)));
        assert!(
            said.contains(&Progress::Phase(Phase::UBoot)),
            "the U-Boot phase was never announced"
        );
        assert_eq!(said.last(), Some(&Progress::Note(STARTING_NOTE.to_owned())));

        mock.verify()
    }

    /// **The settle pin.** The 1000 ms settle happens once, after `PROG_STAGE1` and
    /// before U-Boot is staged.
    ///
    /// Asserted as the exact sleep vector, because that is what places it: entries 0-2
    /// are the vendor request's own 100 ms settle after `SET_DATA_ADDR`, `SET_DATA_LEN` and
    /// `PROG_STAGE1`, so a 1000 ms at index 3 is *after* stage 1 was told to run and
    /// *before* the two vendor requests that stage U-Boot. A bare "it slept for a
    /// second somewhere" would pass with the sleep in the wrong place, and U-Boot DMA'd
    /// into DDR that stage 1 has not finished bringing up is the failure this rule
    /// exists to prevent (`dfu.c:1139-1140`).
    #[test]
    fn boot_settle_after_stage1() -> Result<(), MockError> {
        let stage1 = [0x11_u8; 32];
        let uboot = [0x22_u8; 32];
        let mock = scripted(&stage1, &uboot, true);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("bootstrap failed: {error}")))?;

        let settle = SETTLE_AFTER_VENDOR_REQUEST;
        assert_eq!(
            clock.slept(),
            vec![
                settle, // SET_DATA_ADDR, stage 1
                settle, // SET_DATA_LEN, stage 1
                settle, // PROG_STAGE1
                POST_STAGE1_SETTLE,
                settle, // SET_DATA_ADDR, U-Boot
                settle, // SET_DATA_LEN, U-Boot
                settle, // FLUSH_CACHE
                settle, // PROG_STAGE2
            ],
        );
        assert_eq!(POST_STAGE1_SETTLE, Duration::from_secs(1));
        assert_eq!(
            clock.slept().iter().filter(|d| **d == POST_STAGE1_SETTLE).count(),
            1,
            "the settle must happen exactly once"
        );
        mock.verify()
    }

    /// **`FLUSH_CACHE`'s failure is fatal, and `PROG_STAGE2` is not sent after it.**
    ///
    /// The C calls it bare and ignores the result (`dfu.c:1146`), then jumps anyway.
    /// An earlier implementation copied that; it is fixed here under the no-copied-bugs
    /// against copying the C's bugs. What `PROG_STAGE2` jumps into after an unflushed
    /// cache is undefined, and "the device did not come up" is indistinguishable from a
    /// bad loader — so the flush's error is the one the operator gets.
    #[test]
    fn boot_flush_cache_failure_is_fatal() -> Result<(), MockError> {
        let stage1 = [0x33_u8; 32];
        let uboot = [0x44_u8; 32];

        let mut mock = MockTransport::new(bootrom()).configured(CONFIGURATION);
        for call in upload(SPL_LOAD_ADDR, &stage1) {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            mock = mock.expecting(call, reply);
        }
        mock = mock.expecting(vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR), Reply::Done);
        for call in upload(UBOOT_ADDR, &uboot) {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            mock = mock.expecting(call, reply);
        }
        // `Fault` is outside the vendor-retry class, so this fails on the first
        // attempt; the retry ladder itself is pinned elsewhere.
        let mock = mock.expecting(
            vendor(request::FLUSH_CACHE, 0, 0),
            Reply::Fail(UsbError::new(
                UsbErrorKind::Fault,
                Pipe::Control {
                    direction: tdfu_usb::Direction::Out,
                    request: request::FLUSH_CACHE,
                },
            )),
        );

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("a failed FLUSH_CACHE was reported as success".to_owned()))?;
        // The transport's own account survives, naming the request that failed — the
        // flush and not something later.
        assert_eq!(error.to_string(), "transfer fault: control OUT request 0x03 on EP0");
        assert_eq!(request::FLUSH_CACHE, 0x03);

        assert!(
            !calls(&mock)
                .iter()
                .any(|call| matches!(call, Call::ControlOut { request, .. } if *request == request::PROG_STAGE2)),
            "PROG_STAGE2 was sent after the cache flush failed"
        );
        // And the success line is not printed for a bootstrap that did not happen.
        assert!(
            !said.iter().any(|step| matches!(step, Progress::Note(_))),
            "a failed bootstrap announced itself as started"
        );
        mock.verify()
    }

    /// **`PROG_STAGE2` failing is success**: the device has already jumped
    /// into U-Boot and is re-enumerating, so there is nothing left to ACK.
    ///
    /// `prog_stage2` swallows the error itself; this pins that the
    /// composition does not undo that, and that the completion line is still emitted —
    /// the C reaches its own at `dfu.c:1148` the same way.
    #[test]
    fn boot_stage2_failure_is_still_success() -> Result<(), MockError> {
        let stage1 = [0x55_u8; 32];
        let uboot = [0x66_u8; 32];

        let mut mock = MockTransport::new(bootrom()).configured(CONFIGURATION);
        let mut expected = upload(SPL_LOAD_ADDR, &stage1);
        expected.push(vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR));
        expected.extend(upload(UBOOT_ADDR, &uboot));
        expected.push(vendor(request::FLUSH_CACHE, 0, 0));
        for call in expected {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            mock = mock.expecting(call, reply);
        }
        // A device that has jumped answers nothing at all: NoDevice, five times, since
        // it is in the vendor-retry class.
        let dead = || {
            Reply::Fail(UsbError::new(
                UsbErrorKind::NoDevice,
                Pipe::Control {
                    direction: tdfu_usb::Direction::Out,
                    request: request::PROG_STAGE2,
                },
            ))
        };
        for _ in 0..crate::bootrom::VENDOR_ATTEMPTS {
            mock = mock.expecting(vendor_word(request::PROG_STAGE2, UBOOT_ADDR), dead());
        }

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("a re-enumerating device failed the bootstrap: {error}")))?;
        assert_eq!(said.last(), Some(&Progress::Note(STARTING_NOTE.to_owned())));
        mock.verify()
    }

    // -----------------------------------------------------------------
    // Padding and claims.
    // -----------------------------------------------------------------

    /// **Both images are padded to a cache line.**
    ///
    /// The C pads inside `bootstrap_load_data_to_memory` (`bootstrap.c:36-46`) and both
    /// call sites go through it — `dfu.c:1132` for the SPL and `dfu.c:1143` for U-Boot.
    /// An earlier doc said "the stage-1 image", which is what an implementer follows,
    /// and an unpadded transfer is exactly what the rounding exists to prevent on the
    /// capped XBurst1 parts.
    ///
    /// Asserted on the wire in three places at once: `SET_DATA_LEN` carries the rounded
    /// length, the bulk OUT carries the rounded bytes, and the tail is zero.
    #[test]
    fn boot_both_images_are_padded() -> Result<(), MockError> {
        // Neither length is a multiple of 32, and they round to different sizes.
        let stage1 = [0x77_u8; 33];
        let uboot = [0x88_u8; 65];
        let mut padded_stage1 = stage1.to_vec();
        padded_stage1.resize(64, 0);
        let mut padded_uboot = uboot.to_vec();
        padded_uboot.resize(96, 0);
        assert_eq!(padded_stage1.len() % STAGE1_ALIGN, 0);
        assert_eq!(padded_uboot.len() % STAGE1_ALIGN, 0);

        let mock = scripted(&padded_stage1, &padded_uboot, true);
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(bootstrap(&mock, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("bootstrap failed: {error}")))?;

        let seen = calls(&mock);
        let lengths: Vec<u16> = seen
            .iter()
            .filter_map(|call| match call {
                Call::ControlOut { request, index, .. } if *request == request::SET_DATA_LEN => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(lengths, vec![64, 96], "SET_DATA_LEN did not carry the padded lengths");

        let uploaded: Vec<Vec<u8>> = seen
            .iter()
            .filter_map(|call| match call {
                Call::BulkOut { data } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(uploaded, vec![padded_stage1, padded_uboot]);
        // The padding is zero and the image is intact underneath it.
        assert_eq!(
            uploaded.first().and_then(|image| image.get(33..)),
            Some(&[0_u8; 31][..])
        );
        assert_eq!(uploaded.get(1).and_then(|image| image.get(65..)), Some(&[0_u8; 31][..]));
        mock.verify()
    }

    /// **The configuration is set once per claim at most, and not at all when it is
    /// already in force.**
    ///
    /// A differential USB capture found two extra `SET_CONFIGURATION`
    /// requests the C does not send, from re-configuring on every claim. Bootstrap is
    /// where that shows twice, because it claims twice — once per image
    /// (`bootstrap.c:77`, reached from `dfu.c:1132` and `:1143`). The C guards all three
    /// of its claim sites (`device.c:332-334`, `dfu.c:429`, `protocol.c:212`).
    #[test]
    fn boot_sets_the_configuration_once_for_every_claim() -> Result<(), MockError> {
        let stage1 = [0x99_u8; 32];
        let uboot = [0xAA_u8; 32];

        // A device that enumerated and was never configured: the first
        // claim configures it, the second finds it already configured.
        let fresh = scripted(&stage1, &uboot, false);
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        block_on(bootstrap(&fresh, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("bootstrap failed: {error}")))?;

        let claims = calls(&fresh)
            .iter()
            .filter(|call| matches!(call, Call::ClaimInterface(_)))
            .count();
        let configures = calls(&fresh)
            .iter()
            .filter(|call| matches!(call, Call::SetConfiguration(_)))
            .count();
        assert_eq!(claims, 2, "one claim per image (`bootstrap.c:77`)");
        assert_eq!(configures, 1, "the second claim re-sent SET_CONFIGURATION");
        fresh.verify()?;

        // A device already in the configuration sends none at all — the case the
        // differential capture actually caught.
        let already = scripted(&stage1, &uboot, true);
        let mut said = Vec::new();
        block_on(bootstrap(&already, &clock, &stage1, &uboot, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("bootstrap failed: {error}")))?;
        assert!(
            !calls(&already)
                .iter()
                .any(|call| matches!(call, Call::SetConfiguration(_))),
            "an already-configured device was re-configured"
        );
        already.verify()
    }

    /// An empty image is refused before anything reaches the wire.
    ///
    /// The C refuses the same way (`bootstrap.c:27-29`, `size == 0` →
    /// `TDFU_ERROR_INVALID_PARAMETER`). Padding an empty image leaves it empty —
    /// `next_multiple_of(32)` of 0 is 0 — so this is the guard in
    /// [`bootrom::load_to_memory`](crate::bootrom::load_to_memory) doing its job, and
    /// the pin is that bootstrap does not paper over it.
    #[test]
    fn boot_refuses_an_empty_image() -> Result<(), MockError> {
        let clock = RecordingClock::new();
        let mut said = Vec::new();

        let mock = MockTransport::new(bootrom()).configured(CONFIGURATION);
        let error = block_on(bootstrap(&mock, &clock, &[], &[0_u8; 32], &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("an empty stage 1 bootstrapped fine".to_owned()))?;
        assert_eq!(error.to_string(), "invalid input: nothing to stage at 0x80001000");
        assert!(calls(&mock).is_empty(), "an empty image reached the wire");
        mock.verify()?;

        // And an empty U-Boot fails after stage 1 has run, which is the honest place
        // for it: the C loads and runs stage 1 before it ever looks at U-Boot.
        let stage1 = [0xBB_u8; 32];
        let mut second = MockTransport::new(bootrom()).configured(CONFIGURATION);
        for call in upload(SPL_LOAD_ADDR, &stage1) {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            second = second.expecting(call, reply);
        }
        let second = second.expecting(vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR), Reply::Done);
        let error = block_on(bootstrap(&second, &clock, &stage1, &[], &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("an empty U-Boot bootstrapped fine".to_owned()))?;
        assert_eq!(error.to_string(), "invalid input: nothing to stage at 0x80100000");
        second.verify()
    }

    /// No exit path leaves the interface claimed.
    ///
    /// On the T20 an interface left claimed makes the following `FLUSH_CACHE` and
    /// `PROG_STAGE2` time out, and this is the path where forgetting costs a power
    /// cycle: `PROG_STAGE1` failing *between* the two uploads.
    /// [`bootrom::load_to_memory`](crate::bootrom::load_to_memory) releases on every
    /// path out of itself, so the guarantee is structural — bootstrap claims nothing of
    /// its own — and this asserts it rather than trusting the layering.
    #[test]
    fn boot_releases_the_interface_when_stage1_will_not_run() -> Result<(), MockError> {
        let stage1 = [0xCC_u8; 32];
        let mut mock = MockTransport::new(bootrom()).configured(CONFIGURATION);
        for call in upload(SPL_LOAD_ADDR, &stage1) {
            let reply = match call {
                Call::BulkOut { ref data } => Reply::Transferred(data.len()),
                _ => Reply::Done,
            };
            mock = mock.expecting(call, reply);
        }
        let mock = mock.expecting(
            vendor_word(request::PROG_STAGE1, SPL_ENTRY_ADDR),
            Reply::Fail(UsbError::new(
                UsbErrorKind::Fault,
                Pipe::Control {
                    direction: tdfu_usb::Direction::Out,
                    request: request::PROG_STAGE1,
                },
            )),
        );

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        assert!(block_on(bootstrap(&mock, &clock, &stage1, &[0_u8; 32], &mut record(&mut said))).is_err());

        let seen = calls(&mock);
        let claimed = seen
            .iter()
            .filter(|call| matches!(call, Call::ClaimInterface(_)))
            .count();
        let released = seen.iter().filter(|call| **call == Call::ReleaseInterface(0)).count();
        assert_eq!(claimed, released, "a claim outlived the upload that took it");
        assert_eq!(claimed, 1, "only the stage-1 upload should have claimed");
        // Nothing was staged for U-Boot after stage 1 refused to run.
        assert!(
            !seen
                .iter()
                .any(|call| matches!(call, Call::ControlOut { request, index, .. }
                    if *request == request::SET_DATA_ADDR && *index == halves(UBOOT_ADDR).1)),
            "U-Boot was staged after PROG_STAGE1 failed"
        );
        mock.verify()
    }
}
