//! The DFU host layer driven against the emulated gadget, end to end.
//!
//! `tests/mock_seam.rs` proves the *wiring* — that `tdfu-core`'s generic code composes
//! with a `tdfu-usb` double and a `Sleeper`. This proves the two halves against **each
//! other**: `dfu::host` sending what it decides to send, and
//! `FakeGadget` answering out of `f_dfu.c`'s state machine rather than out of a script.
//!
//! It exists because a script cannot catch a host that is wrong in the same direction
//! the script is: `MockTransport` answers whatever the test author expected, so a
//! `make_idle` that sent `ABORT` where the device needs `CLRSTATUS` would pass against a
//! script written by the same author. Here the device refuses it (`f_dfu.c:593-621`) and
//! the operation fails.
//!
//! What is pinned here is the seam every operation (`ops::write`, `ops::read`,
//! `ops::erase`, …) composes over, and the write half is pinned by driving
//! **`ops::write` itself**. A local copy of its download sequence would pass a build in
//! which the operation had drifted away from it, which is the same failure
//! `ops/mod.rs`'s "no frontend re-implements a sequence" rule names one layer up: the
//! copy and the original go quietly out of step. The hand-written requests that remain
//! are the ones no operation makes: abandoning a transfer part way, and the recovery
//! primitives read on their own.

use core::cell::RefCell;

use tdfu_core::clock::RecordingClock;
use tdfu_core::dfu::host::{self, Grace};
use tdfu_core::dfu::read_info;
use tdfu_core::model::AltSel;
use tdfu_core::ops;
use tdfu_core::progress::Progress;
use tdfu_usb::LocalUsbTransport;
use tdfu_usb::gadget::{AltConfig, DfuState, FakeGadget, Fault, GadgetConfig, Loader, When, request};
use tdfu_usb::mock::block_on;

type Fallible = Result<(), Box<dyn std::error::Error>>;

/// What `ops::write` says when the image is on the flash (`dfu.c:618`).
///
/// A literal rather than `ops::write`'s own constant, which is not re-exported: a
/// fixture built from the value it checks moves with it and pins nothing.
const COMPLETE: &str = "DFU download complete";

/// Drive `ops::write` at alt 0, collecting the notes it emits.
///
/// The operation, not a re-implementation of it. Alt 0 by index rather than by the
/// default rule, because the assertions below read `medium(0)` and the rule itself is
/// `dfu::alt`'s to pin.
async fn write_image(
    gadget: &FakeGadget,
    clock: &RecordingClock,
    image: &[u8],
    notes: &RefCell<Vec<String>>,
) -> Result<(), tdfu_core::Error> {
    let mut sink = |progress: Progress| {
        if let Progress::Note(note) = progress {
            notes.borrow_mut().push(note);
        }
    };
    ops::write(gadget, clock, &AltSel::Index(0), image, &mut sink).await
}

#[test]
fn a_write_transaction_drives_the_host_layer_against_the_gadget() -> Fallible {
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(64)
            .with_buffer_size(128)
            .with_manifest_hold_polls(2),
    );
    let clock = RecordingClock::new();
    let notes = RefCell::new(Vec::new());
    let image: Vec<u8> = (0..200u32).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect();

    block_on(write_image(&gadget, &clock, &image, &notes))?;

    assert_eq!(gadget.medium(0).ok_or("alt 0 exists")?, image, "byte for byte");
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    assert_eq!(gadget.wrong_sequence_refusals(), 0);
    assert_eq!(gadget.resets(), 0);
    // The completion line and nothing else: both retry announcements would be here too,
    // and neither was needed.
    assert_eq!(notes.borrow().as_slice(), [COMPLETE.to_owned()]);
    // Four blocks (64/64/64/8) plus the zero-length trigger.
    let downloads = gadget
        .class_requests()
        .into_iter()
        .filter(|(request, _)| *request == request::DNLOAD)
        .collect::<Vec<_>>();
    assert_eq!(
        downloads,
        [
            (request::DNLOAD, 0),
            (request::DNLOAD, 1),
            (request::DNLOAD, 2),
            (request::DNLOAD, 3),
            (request::DNLOAD, 4)
        ]
    );
    // Every DNLOAD carries the 30 s timeout, the trigger included. The
    // manifest hold cost two `bwPollTimeout` sleeps, which is what `Grace::Erase`'s
    // poll loop is for.
    assert!(
        clock.slept().len() >= 2,
        "the manifest hold made the host wait: {:?}",
        clock.slept()
    );
    Ok(())
}

#[test]
fn a_write_interrupted_mid_transfer_is_rewritten_from_the_beginning() -> Fallible {
    // The bus-reset retry over a write that already put bytes on the medium —
    // **the class an earlier emulator could not express at all**, because its medium
    // offset was monotone, so every retry after a data block landed at the
    // wrong offset.
    //
    // The device end of it is `dfu_transaction_cleanup` zeroing `dfu->offset`
    // (`dfu.c:294`), reached here by the `SET_CONFIGURATION` that follows the recovery
    // reset (`f_dfu.c:829-834`). The assertion that catches a monotone offset is the
    // byte-for-byte one: an offset that carried over would append the retry after the
    // partial write instead of overwriting it.
    //
    // The retry is `ops::write`'s own: it wraps every attempt in
    // `reset_and_retry_once`, so driving the operation drives the recovery.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(64)
            .with_buffer_size(64)
            .with_manifest_hold_polls(0),
    );
    let clock = RecordingClock::new();
    let notes = RefCell::new(Vec::new());
    let image: Vec<u8> = (0..200u32).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect();

    // Block 2 goes missing once — a recoverable failure, so the reset applies.
    gadget.inject(When::ClassBlock(request::DNLOAD, 2), Fault::NoDevice);

    block_on(write_image(&gadget, &clock, &image, &notes))?;

    assert_eq!(gadget.resets(), 1, "one recovery reset, exactly once");
    assert_eq!(
        gadget.medium(0).ok_or("alt 0 exists")?,
        image,
        "the retry rewrote from offset 0, byte for byte — a monotone offset appends here"
    );
    assert!(
        notes.borrow().iter().any(|note| note.contains("USB-reset")),
        "the recovery was reported: {:?}",
        notes.borrow()
    );
    Ok(())
}

#[test]
fn the_host_recovers_an_old_loaders_stale_transaction() -> Fallible {
    // The block 0 retry end to end, on the loader generation that needs it.
    //
    // The gadget is left mid-transfer, bus-reset, and re-claimed — the "browser reload"
    // shape. On a legacy loader nothing cleans the entity, so the host's block 0 is
    // refused once; `retry_stale_block0` sees the failure on the first block, runs
    // `make_idle` (which sends the CLRSTATUS the device needs, not the ABORT it would
    // stall on) and starts again. **This is the class an earlier implementation could
    // not falsify**, because its emulator served ABORT in dfuERROR.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(64)
            .with_buffer_size(128)
            .with_manifest_hold_polls(0)
            .with_loader(Loader::Legacy),
    );
    let clock = RecordingClock::new();
    let notes = RefCell::new(Vec::new());

    // Abandon a transfer part-way. Written out because no operation does this: it is the
    // state a killed run leaves behind, not a sequence anything drives on purpose.
    block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        host::dnload(&gadget, info.interface, 0, &[0xAA; 64]).await?;
        host::poll_until_ready(&gadget, &clock, info.interface, Grace::Write).await?;
        gadget.reset().await.map_err(tdfu_core::Error::from)
    })?;
    assert_eq!(gadget.entity_sequence(0), Some(1), "the entity is stale");

    let image = vec![0x5A; 100];
    block_on(write_image(&gadget, &clock, &image, &notes))?;

    assert_eq!(gadget.medium(0).ok_or("alt 0 exists")?, image);
    assert_eq!(
        gadget.wrong_sequence_refusals(),
        1,
        "exactly one, as the bench T23 logged"
    );
    // The retry announces itself; an earlier implementation's was silent.
    assert!(
        notes.borrow().iter().any(|note| note.contains("stale DFU transaction")),
        "the retry was reported: {:?}",
        notes.borrow()
    );
    Ok(())
}

#[test]
fn a_fixed_loader_needs_no_recovery_for_the_same_reload() -> Fallible {
    // The other half, so the pin above is falsifiable in both directions:
    // the same abandoned transfer costs nothing on a loader with `3d4848fe0dc`.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(64)
            .with_buffer_size(128)
            .with_manifest_hold_polls(0),
    );
    let clock = RecordingClock::new();
    let notes = RefCell::new(Vec::new());

    block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        host::dnload(&gadget, info.interface, 0, &[0xAA; 64]).await?;
        host::poll_until_ready(&gadget, &clock, info.interface, Grace::Write).await?;
        gadget.reset().await.map_err(tdfu_core::Error::from)
    })?;

    let image = vec![0x5A; 100];
    block_on(write_image(&gadget, &clock, &image, &notes))?;
    assert_eq!(gadget.wrong_sequence_refusals(), 0);
    // The completion line and no retry announcement beside it.
    assert_eq!(notes.borrow().as_slice(), [COMPLETE.to_owned()]);
    Ok(())
}

#[test]
fn read_info_reads_the_gadget_the_bench_captured() -> Fallible {
    // The descriptor path the host actually uses, against descriptors generated from
    // `GadgetConfig` and machine-checked against
    // `crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`.
    let gadget = FakeGadget::t32lq();
    let info = block_on(read_info(&gadget))?;

    assert_eq!(info.interface, 0);
    assert_eq!(info.transfer_size, 4096);
    assert!(info.is_multi_alt());
    let names: Vec<&str> = info.alts.iter().map(|alt| alt.name.as_str()).collect();
    assert_eq!(names, ["flash", "erase", "reboot"]);
    Ok(())
}

#[test]
fn make_idle_needs_the_request_the_device_actually_serves() -> Fallible {
    // `make_idle` picks `CLRSTATUS` in dfuERROR and `ABORT` everywhere else because the
    // gadget is not symmetric about them (`f_dfu.c:593-621` versus `:333-400`). Against
    // a scripted double either choice "works"; here the device refuses the wrong one.
    let gadget = FakeGadget::t32lq();
    block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        // Leave it mid-download, which is an ABORT case.
        host::dnload(&gadget, info.interface, 0, &[0x11; 8]).await?;
        host::get_status(&gadget, info.interface).await?;
        assert_eq!(gadget.dfu_state(), DfuState::DnloadIdle);
        host::make_idle(&gadget, info.interface).await?;
        assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);

        // Now the dfuERROR case, which only CLRSTATUS clears.
        drop(host::clr_status(&gadget, info.interface).await);
        assert_eq!(gadget.dfu_state(), DfuState::Error);
        host::make_idle(&gadget, info.interface).await?;
        assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
        Ok::<(), tdfu_core::Error>(())
    })?;

    // One ABORT for the download case, one CLRSTATUS for the error case, and no
    // ABORT sent into dfuERROR (which the device would stall).
    let recovery: Vec<u8> = gadget
        .class_requests()
        .into_iter()
        .map(|(request, _)| request)
        .filter(|request| matches!(*request, request::ABORT | request::CLRSTATUS))
        .collect();
    assert_eq!(recovery, [request::ABORT, request::CLRSTATUS, request::CLRSTATUS]);
    Ok(())
}

#[test]
fn poll_until_ready_rides_out_the_flush_silence_that_grace_exists_for() -> Fallible {
    // EP0 goes quiet while the loader drains its buffer to flash, so
    // a lost poll means busy, not gone. `Grace::Write` forgives 12 consecutive failures
    // with a 500 ms backoff; `Grace::None` forgives none, which is what makes reboot's
    // failing poll the success signal.
    let build = || {
        FakeGadget::new(
            GadgetConfig::t32lq()
                .with_transfer_size(64)
                .with_buffer_size(64)
                .with_flush_silence_polls(3),
        )
    };
    let clock = RecordingClock::new();

    let gadget = build();
    block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        host::dnload(&gadget, info.interface, 0, &[0x11; 64]).await?;
        host::poll_until_ready(&gadget, &clock, info.interface, Grace::Write).await
    })?;

    let gadget = build();
    let strict = block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        host::dnload(&gadget, info.interface, 0, &[0x11; 64]).await?;
        host::poll_until_ready(&gadget, &clock, info.interface, Grace::None).await
    });
    assert!(strict.is_err(), "grace 0 forgives nothing");
    Ok(())
}

#[test]
fn upload_reads_the_medium_back_through_the_host_layer() -> Fallible {
    // The upload's shape: no GETSTATUS between UPLOADs, and a short block ends it.
    //
    // The medium is 100 bytes, so block 1 answers 36 and the loop's `break` is what ends
    // it. On a 16 MiB alt every one of the eight blocks comes back full, and the short
    // half of that claim goes unexercised.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![
            AltConfig::flash("flash", 100),
            AltConfig::erase(),
            AltConfig::reboot(),
        ])
        .with_transfer_size(64),
    );
    let image: Vec<u8> = (0..100u32).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect();
    gadget.preload(0, image.clone());

    let read = block_on(async {
        let info = read_info(&gadget).await?;
        host::claim(&gadget, &info, 0).await?;
        host::make_idle(&gadget, info.interface).await?;
        let mut out = Vec::new();
        for block in 0..8u16 {
            let chunk = host::upload(&gadget, info.interface, block, info.transfer_size).await?;
            let short = chunk.len() < usize::from(info.transfer_size);
            out.extend_from_slice(&chunk);
            if short {
                break;
            }
        }
        Ok::<Vec<u8>, tdfu_core::Error>(out)
    })?;

    assert_eq!(read, image, "two blocks, the second one short, are the whole medium");
    assert_eq!(
        gadget.dfu_state(),
        DfuState::DfuIdle,
        "the short block ended the upload; a full one leaves it in dfuUPLOAD-IDLE"
    );
    assert!(
        !gadget
            .class_requests()
            .windows(2)
            .any(|pair| pair[0].0 == request::UPLOAD && pair[1].0 == request::GETSTATUS),
        "no GETSTATUS between UPLOADs"
    );
    Ok(())
}
