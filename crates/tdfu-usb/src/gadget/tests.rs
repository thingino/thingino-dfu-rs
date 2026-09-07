//! Pins for the emulated gadget, each against `f_dfu.c` / `dfu.c` rather than against
//! what a host expects.
//!
//! Three of them exist because an earlier emulator got the same thing wrong, and
//! they keep the names that recorded it:
//! `gadget_fresh_transaction_restarts_the_medium_offset`,
//! `gadget_block_wrap_is_not_a_new_transaction` and
//! `gadget_transfer_size_reaches_the_descriptor`.

use core::time::Duration;
use std::error::Error;

use super::machine::{STATUS_ERR_UNKNOWN, STATUS_OK, request};
use super::{
    AltConfig, DfuState, ERASE_TOKEN, Event, FakeGadget, Fault, GadgetConfig, Loader, REBOOT_TOKEN, T32LQ_FLASH_SIZE,
    When, descriptors,
};
use crate::error::{UsbError, UsbErrorKind};
use crate::mock::block_on;
use crate::transport::LocalUsbTransport;
use crate::types::{BulkEndpoint, ControlIn, ControlOut, ControlType, Direction, InterfaceSpec, Recipient};

type Fallible = Result<(), Box<dyn Error>>;

/// Anything a test needs a deadline for; the value is irrelevant to the device model,
/// which is why every call records it (`Recorded::timeout`'s reasoning, applied here).
const TIMEOUT: Duration = Duration::from_secs(5);

/// A gadget that is configured, claimed and on alt `alt` — the state every operation
/// starts from (`dfu::host::claim`).
fn ready(gadget: &FakeGadget, alt: u8) -> Fallible {
    block_on(async {
        gadget.set_configuration(1).await?;
        gadget.claim_interface(InterfaceSpec::control_only(0)).await?;
        gadget.set_alt_setting(0, alt).await
    })?;
    Ok(())
}

fn class_out(gadget: &FakeGadget, request: u8, value: u16, data: &[u8]) -> Result<(), UsbError> {
    block_on(gadget.control_out(
        ControlOut {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value,
            index: 0,
            data,
        },
        TIMEOUT,
    ))
}

fn class_in(gadget: &FakeGadget, request: u8, value: u16, len: u16) -> Result<Vec<u8>, UsbError> {
    block_on(gadget.control_in(
        ControlIn {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value,
            index: 0,
            len,
        },
        TIMEOUT,
    ))
}

fn get_descriptor(gadget: &FakeGadget, kind: u8, index: u8, len: u16) -> Result<Vec<u8>, UsbError> {
    block_on(gadget.control_in(
        ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x06,
            value: (u16::from(kind) << 8) | u16::from(index),
            index: 0,
            len,
        },
        TIMEOUT,
    ))
}

/// `(bStatus, bwPollTimeout, bState)` from a `GETSTATUS` reply.
fn status(gadget: &FakeGadget) -> Result<(u8, u32, u8), Box<dyn Error>> {
    let bytes = class_in(gadget, request::GETSTATUS, 0, 6)?;
    let &[bstatus, lo, mid, hi, bstate, _] = bytes.get(..6).ok_or("GETSTATUS answered short")? else {
        return Err("GETSTATUS answered short".into());
    };
    Ok((
        bstatus,
        u32::from(lo) | (u32::from(mid) << 8) | (u32::from(hi) << 16),
        bstate,
    ))
}

fn kind_of(error: &UsbError) -> UsbErrorKind {
    error.kind().clone()
}

/// The transport error from a `GETSTATUS` that must not succeed.
fn poll_error(gadget: &FakeGadget) -> Result<UsbErrorKind, Box<dyn Error>> {
    match class_in(gadget, request::GETSTATUS, 0, 6) {
        Ok(_) => Err("GETSTATUS was answered where it must not be".into()),
        Err(error) => Ok(kind_of(&error)),
    }
}

/// One data block and the `GETSTATUS` that moves the machine on.
fn send_block(gadget: &FakeGadget, block: u16, data: &[u8]) -> Result<(), Box<dyn Error>> {
    class_out(gadget, request::DNLOAD, block, data)?;
    status(gadget)?;
    Ok(())
}

/// A whole one-block write on `alt`, manifest included, so the bytes reach the medium.
///
/// Nothing is written before a drain (`dfu.c:261-288`), and the last drain of a transfer
/// is the one the end-of-transfer `DNLOAD` triggers — so a test that stops at the data
/// block sees an empty medium, correctly. Needs `manifest_hold_polls` at 0.
fn write_one_block(gadget: &FakeGadget, alt: u8, data: &[u8]) -> Result<(), Box<dyn Error>> {
    ready(gadget, alt)?;
    send_block(gadget, 0, data)?;
    class_out(gadget, request::DNLOAD, 1, &[])?;
    status(gadget)?;
    status(gadget)?;
    Ok(())
}

// -------------------------------------------------------------------------------------
// The descriptor set, machine-checked against the bench capture
// -------------------------------------------------------------------------------------

/// The device + configuration descriptors of the bench T32LQ, as captured.
fn t32lq_capture() -> Result<Vec<u8>, Box<dyn Error>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt"
    );
    let text = std::fs::read_to_string(path)?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.len() > 100 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or("no descriptor hex line in the capture")?;
    let mut bytes = Vec::with_capacity(line.len() / 2);
    for pair in line.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(core::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes)
}

#[test]
fn the_default_descriptors_match_the_t32lq_capture() -> Fallible {
    // The fixture is *generated*, so this is the check that keeps the generator and the
    // real device in step — the same discipline an audit asked of the bench
    // tables: parse the capture, do not transcribe it.
    let captured = t32lq_capture()?;
    let config = GadgetConfig::t32lq();

    let device = descriptors::device(&config);
    let configuration = descriptors::configuration(&config);
    assert_eq!(
        device.len() + configuration.len(),
        captured.len(),
        "the capture is a device descriptor followed by a whole configuration"
    );
    assert_eq!(device, captured[..device.len()], "device descriptor");
    assert_eq!(configuration, captured[device.len()..], "configuration descriptor");

    // The values the rest of the model depends on, named rather than implied.
    assert_eq!(u16::from_le_bytes([configuration[2], configuration[3]]), 45);
    assert_eq!(configuration[5], 1, "bConfigurationValue");
    assert_eq!(descriptors::alt_string_index(&config, 0), 5);
    assert_eq!(descriptors::alt_string_index(&config, 2), 7);
    Ok(())
}

#[test]
fn gadget_transfer_size_reaches_the_descriptor() -> Fallible {
    // In an earlier emulator the knob drove the
    // block maths while `read_info` kept seeing the captured 4096, so setting it
    // desynchronised host and device. `wTransferSize` and `DFU_USB_BUFSIZ` are one
    // `#define` on the device (`f_dfu.h:24`, `f_dfu.c:67`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(1024));

    // 1. the cached descriptors the host parses without touching the bus
    let cached = &gadget.descriptors().config_descriptor;
    let functional = cached.len() - 9;
    assert_eq!(
        u16::from_le_bytes([cached[functional + 5], cached[functional + 6]]),
        1024,
        "the cached configuration descriptor"
    );

    // 2. the descriptor served on the wire
    let served = get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 64)?;
    assert_eq!(served, *cached, "served and cached descriptors are the same bytes");

    // 3. the clamp the request goes through
    ready(&gadget, 0)?;
    gadget.preload(0, vec![0xA5; 4096]);
    let block = class_in(&gadget, request::UPLOAD, 0, 4096)?;
    assert_eq!(block.len(), 1024, "the answer is clamped to wTransferSize");
    Ok(())
}

#[test]
fn alt_names_come_back_as_string_descriptors() -> Fallible {
    let gadget = FakeGadget::t32lq();
    let name = |index: u8| -> Result<String, Box<dyn Error>> {
        let bytes = get_descriptor(&gadget, descriptors::STRING, index, 256)?;
        Ok(bytes[2..]
            .chunks_exact(2)
            .map(|pair| char::from(pair[0]))
            .collect::<String>())
    };
    // The exact bytes for one of them, so `bLength` is pinned and not just the text:
    // `read_info`'s decoder sizes the name from `(bLength - 2) / 2` and a wrong length
    // silently truncates or pads it (USB 2.0 §9.6.7).
    assert_eq!(
        get_descriptor(&gadget, descriptors::STRING, 5, 256)?,
        [12, 3, b'f', 0, b'l', 0, b'a', 0, b's', 0, b'h', 0]
    );
    assert_eq!(name(5)?, "flash");
    assert_eq!(name(6)?, "erase");
    assert_eq!(name(7)?, "reboot");
    assert_eq!(name(2)?, "USB download gadget", "the bench iProduct string");

    // Index 0 is the LANGID array, not a string (USB 2.0 §9.6.7).
    assert_eq!(
        get_descriptor(&gadget, descriptors::STRING, 0, 256)?,
        [4, 3, 0x09, 0x04]
    );
    // A string the device does not have stalls; the host turns that into an empty name.
    let missing = get_descriptor(&gadget, descriptors::STRING, 9, 256)
        .err()
        .ok_or("a missing string must not answer")?;
    assert_eq!(kind_of(&missing), UsbErrorKind::Stall);
    Ok(())
}

#[test]
fn the_device_and_functional_descriptors_are_served_on_the_wire() -> Fallible {
    // The composite layer answers `GET_DESCRIPTOR` for device/configuration/string, and
    // `f_dfu` answers one of its own: the DFU functional descriptor, capped at
    // `sizeof dfu_func` (`f_dfu.c:659-664`). Nothing in this tool reads either, but a
    // double that silently had no answer for them would be a device nothing enumerates.
    let gadget = FakeGadget::t32lq();
    let device = get_descriptor(&gadget, descriptors::DEVICE, 0, 18)?;
    assert_eq!(device.len(), 18);
    assert_eq!(device[..2], [18, 1], "bLength, bDescriptorType");
    assert_eq!(u16::from_le_bytes([device[8], device[9]]), 0xA108, "idVendor");
    assert_eq!(u16::from_le_bytes([device[10], device[11]]), 0xC309, "idProduct");

    let functional = get_descriptor(&gadget, descriptors::DFU_FUNCTIONAL, 0, 9)?;
    assert_eq!(functional, [9, 0x21, 0x0F, 0, 0, 0x00, 0x10, 0x10, 0x01]);

    // A descriptor type the device does not have stalls rather than answering rubbish.
    let unknown = get_descriptor(&gadget, 0x0F, 0, 32).err().ok_or("no BOS descriptor")?;
    assert_eq!(kind_of(&unknown), UsbErrorKind::Stall);
    Ok(())
}

#[test]
fn an_over_long_answer_is_truncated_to_what_the_host_asked_for() -> Fallible {
    // The host owns the length of a control IN; the device fills what it can
    // (`f_dfu.c:669`, and the stack caps at `wLength`). The mock's counterpart is the
    // same rule on `bulk_in`.
    let gadget = FakeGadget::t32lq();
    assert_eq!(get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 9)?.len(), 9);
    assert_eq!(get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 4)?.len(), 4);
    Ok(())
}

// -------------------------------------------------------------------------------------
// dfuERROR is a refusing state
// -------------------------------------------------------------------------------------

/// Put the gadget in dfuERROR the way a host reaches it: a `CLRSTATUS` in `dfuIDLE`.
fn into_error(gadget: &FakeGadget) -> Fallible {
    let stalled = class_out(gadget, request::CLRSTATUS, 0, &[])
        .err()
        .ok_or("CLRSTATUS in dfuIDLE must stall")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    assert_eq!(gadget.dfu_state(), DfuState::Error);
    Ok(())
}

#[test]
fn clrstatus_in_dfu_idle_creates_the_error_state() -> Fallible {
    // `state_dfu_idle` (`f_dfu.c:333-400`) has **no** CLRSTATUS case: it falls to the
    // default arm, which stalls AND enters dfuERROR. Getting the `ABORT`/`CLRSTATUS`
    // pair the wrong way round turns a recoverable device into a wedged one, which is
    // why the host picks between them rather than sending both.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    into_error(&gadget)
}

#[test]
fn dfu_error_serves_only_getstatus_getstate_and_clrstatus() -> Fallible {
    // `state_dfu_error` (`f_dfu.c:593-621`). An earlier emulator served ABORT here too,
    // which made the whole recovery class unfalsifiable: deleting the host's
    // CLRSTATUS branch passed all 448 tests.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    into_error(&gadget)?;

    // The two reads are served, and neither moves the state.
    let (_, _, state) = status(&gadget)?;
    assert_eq!(state, DfuState::Error.code());
    assert_eq!(class_in(&gadget, request::GETSTATE, 0, 1)?, [DfuState::Error.code()]);
    assert_eq!(gadget.dfu_state(), DfuState::Error);

    // Everything else stalls and leaves the device in dfuERROR — ABORT included.
    for (name, outcome) in [
        ("ABORT", class_out(&gadget, request::ABORT, 0, &[])),
        ("DNLOAD", class_out(&gadget, request::DNLOAD, 0, &[1, 2, 3, 4])),
        ("DETACH", class_out(&gadget, request::DETACH, 0, &[])),
    ] {
        let error = outcome.err().ok_or(format!("{name} must stall in dfuERROR"))?;
        assert_eq!(kind_of(&error), UsbErrorKind::Stall, "{name}");
        assert_eq!(gadget.dfu_state(), DfuState::Error, "{name} left dfuERROR");
    }
    let upload = class_in(&gadget, request::UPLOAD, 0, 4096)
        .err()
        .ok_or("UPLOAD must stall in dfuERROR")?;
    assert_eq!(kind_of(&upload), UsbErrorKind::Stall);
    assert_eq!(gadget.dfu_state(), DfuState::Error);

    // Only CLRSTATUS gets it out, and it clears bStatus with it.
    class_out(&gadget, request::CLRSTATUS, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    assert_eq!(gadget.dfu_status(), STATUS_OK);
    Ok(())
}

#[test]
fn every_other_state_falls_into_dfu_error_on_an_unexpected_request() -> Fallible {
    // The default arm of `state_dfu_dnload_sync` (`f_dfu.c:416-419`) and of
    // `state_dfu_upload_idle` (`:584-587`): an out-of-turn request does not just stall,
    // it *creates* the error the host then has to clear.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    class_out(&gadget, request::DNLOAD, 0, &[0xAA; 16])?;
    assert_eq!(gadget.dfu_state(), DfuState::DnloadSync);

    let stalled = class_out(&gadget, request::CLRSTATUS, 0, &[])
        .err()
        .ok_or("CLRSTATUS in dfuDNLOAD_SYNC must stall")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    assert_eq!(gadget.dfu_state(), DfuState::Error);
    Ok(())
}

// -------------------------------------------------------------------------------------
// The block machine
// -------------------------------------------------------------------------------------

#[test]
fn a_download_walks_the_states_f_dfu_names() -> Fallible {
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 0)?;

    class_out(&gadget, request::DNLOAD, 0, &[0x11; 8])?;
    assert_eq!(gadget.dfu_state(), DfuState::DnloadSync, "f_dfu.c:352");
    status(&gadget)?;
    assert_eq!(gadget.dfu_state(), DfuState::DnloadIdle, "f_dfu.c:190-193");

    class_out(&gadget, request::DNLOAD, 1, &[0x22; 8])?;
    status(&gadget)?;

    // The zero-length DNLOAD is the end-of-transfer trigger (`f_dfu.c:254-255`).
    class_out(&gadget, request::DNLOAD, 2, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::ManifestSync);

    // This poll moves to dfuMANIFEST and arms the deferred flush *after* answering
    // (`f_dfu.c:492-498`).
    let (_, _, state) = status(&gadget)?;
    assert_eq!(state, DfuState::Manifest.code());

    // With no hold, the next poll runs the flush and reports idle (`f_dfu.c:534-538`).
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_OK, DfuState::DfuIdle.code()));

    assert_eq!(gadget.medium(0).ok_or("alt 0 exists")?, [[0x11; 8], [0x22; 8]].concat());
    Ok(())
}

#[test]
fn a_zero_length_download_from_dfu_idle_is_an_error() -> Fallible {
    // `f_dfu.c:347-351`: a transfer cannot *start* with its own end marker. It is the
    // one place dfuIDLE's DNLOAD arm refuses.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    let error = class_out(&gadget, request::DNLOAD, 0, &[])
        .err()
        .ok_or("a bare ZLP from dfuIDLE must stall")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall);
    assert_eq!(gadget.dfu_state(), DfuState::Error);
    Ok(())
}

#[test]
fn a_wrong_block_number_surfaces_on_the_next_getstatus_not_on_the_download() -> Fallible {
    // `dnload_request_complete` runs after the request is answered (`f_dfu.c:156-167`),
    // so `dfu_write`'s refusal (`dfu.c:384-390`) reaches the host as errUNKNOWN in
    // dfuERROR on the *following* poll. A model that failed the DNLOAD itself would let
    // an operation "handle" an error the device never reports there.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0xAB; 16])?;
    assert_eq!(gadget.entity_inited(0), Some(true), "a transaction is open");

    // Block 2 where the entity expects 1.
    class_out(&gadget, request::DNLOAD, 2, &[0xCD; 16])?;
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!(bstatus, STATUS_ERR_UNKNOWN);
    assert_eq!(state, DfuState::Error.code());
    assert_eq!(gadget.dfu_status(), STATUS_ERR_UNKNOWN, "errUNKNOWN, f_dfu.c:164");
    assert_eq!(gadget.wrong_sequence_refusals(), 1);
    // The refusal cleans the entity itself (`dfu.c:387`), which is what lets the host's
    // retry from block 0 succeed.
    assert_eq!(gadget.entity_sequence(0), Some(0));
    assert_eq!(gadget.entity_inited(0), Some(false));
    Ok(())
}

#[test]
fn an_upload_ends_with_a_short_block_and_returns_to_idle() -> Fallible {
    // `dfu_read` cleans the transaction when it returns less than asked
    // (`dfu.c:527-534`) and `state_dfu_upload_idle` drops to dfuIDLE (`f_dfu.c:568-569`).
    // A short block ends the read.
    let gadget = FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash("flash", 10)]).with_transfer_size(8));
    ready(&gadget, 0)?;
    gadget.preload(0, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    assert_eq!(class_in(&gadget, request::UPLOAD, 0, 8)?, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(gadget.dfu_state(), DfuState::UploadIdle);
    assert_eq!(class_in(&gadget, request::UPLOAD, 1, 8)?, [9, 10]);
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle, "the short block ended it");
    assert_eq!(gadget.entity_inited(0), Some(false));
    Ok(())
}

#[test]
fn an_unwritten_medium_reads_as_erased() -> Fallible {
    let gadget = FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash("flash", 8)]).with_transfer_size(8));
    ready(&gadget, 0)?;
    assert_eq!(class_in(&gadget, request::UPLOAD, 0, 8)?, [0xFF; 8]);
    Ok(())
}

#[test]
fn upload_lifts_a_whole_usb_bufsiz_whatever_the_host_asked_for() -> Fallible {
    // `handle_upload` passes `req->length`, which `composite_setup` re-initialises to
    // `USB_BUFSIZ` on every setup packet (`f_dfu.c:244-245`, `composite.c:1029`,
    // `composite.c:17`). Invisible on hardware because both constants are 4096, and
    // modelled rather than smoothed over: a host that asks for less loses the rest.
    let mut config = GadgetConfig::new(vec![AltConfig::flash("flash", 16)]).with_transfer_size(8);
    config.usb_bufsiz = 8;
    let gadget = FakeGadget::new(config);
    ready(&gadget, 0)?;
    gadget.preload(0, (1..=16).collect::<Vec<u8>>());

    // Ask for 4 of the 8 the device lifts.
    assert_eq!(class_in(&gadget, request::UPLOAD, 0, 4)?, [1, 2, 3, 4]);
    assert_eq!(gadget.entity_offset(0), Some(8), "the cursor advanced by USB_BUFSIZ");
    // 8 is not < 4, so the machine stayed in dfuUPLOAD_IDLE (`f_dfu.c:568`).
    assert_eq!(gadget.dfu_state(), DfuState::UploadIdle);
    assert_eq!(
        class_in(&gadget, request::UPLOAD, 1, 8)?,
        [9, 10, 11, 12, 13, 14, 15, 16]
    );
    Ok(())
}

// -------------------------------------------------------------------------------------
// The medium offset
// -------------------------------------------------------------------------------------

#[test]
fn gadget_fresh_transaction_restarts_the_medium_offset() -> Fallible {
    // `dfu_transaction_cleanup` zeroes `dfu->offset` (`dfu.c:294`). An earlier emulator
    // made it monotone, so **any** retry after a data block landed at the wrong offset and a
    // byte-level bus-reset write pin was unwritable.
    //
    // Three ways in, all of which must restart at 0: the end-of-transfer ZLP, an entity
    // clean, and a bus reset followed by the re-configure.
    let config = || GadgetConfig::t32lq().with_transfer_size(8).with_buffer_size(4);

    // 1. after a completed transfer
    let gadget = FakeGadget::new(config().with_manifest_hold_polls(0));
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 4])?;
    send_block(&gadget, 1, &[0x22; 4])?;
    assert_eq!(gadget.entity_offset(0), Some(8));
    class_out(&gadget, request::DNLOAD, 2, &[])?;
    status(&gadget)?;
    status(&gadget)?;
    assert_eq!(gadget.entity_offset(0), Some(0), "the flush cleaned the transaction");
    send_block(&gadget, 0, &[0x33; 4])?;
    assert_eq!(
        gadget.medium(0).ok_or("alt 0")?,
        [0x33, 0x33, 0x33, 0x33, 0x22, 0x22, 0x22, 0x22],
        "the retry landed at offset 0, not appended"
    );

    // 2. after an ABORT (a fixed loader cleans the entity, `f_dfu.c:466`)
    let gadget = FakeGadget::new(config());
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 4])?;
    send_block(&gadget, 1, &[0x22; 4])?;
    class_out(&gadget, request::ABORT, 0, &[])?;
    assert_eq!(gadget.entity_offset(0), Some(0));

    // 3. after a bus reset and the re-configure that follows it
    let gadget = FakeGadget::new(config());
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 4])?;
    send_block(&gadget, 1, &[0x22; 4])?;
    assert_eq!(gadget.entity_offset(0), Some(8));
    block_on(gadget.reset())?;
    ready(&gadget, 0)?;
    assert_eq!(gadget.entity_offset(0), Some(0));
    send_block(&gadget, 0, &[0x44; 4])?;
    assert_eq!(gadget.medium(0).ok_or("alt 0")?[..4], [0x44; 4]);
    Ok(())
}

#[test]
fn gadget_block_wrap_is_not_a_new_transaction() -> Fallible {
    // DFU's block number is 16 bits and wraps to 0 from 0xFFFF (`dfu.c:392-406`) —
    // every 256 MiB at a 4096-byte transfer size, which is exactly a T40XP whole-chip
    // transfer. Anything that read `block == 0` as "a new transaction" would reset the
    // medium offset there and re-write the chip from the start.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![AltConfig::flash("flash", 70_000)])
            .with_transfer_size(8)
            .with_buffer_size(4096),
    );
    ready(&gadget, 0)?;
    for block in 0..=u16::MAX {
        send_block(&gadget, block, &[0x5A])?;
        if block % 8192 == 0 {
            gadget.forget_events();
        }
    }
    assert_eq!(gadget.entity_sequence(0), Some(0), "the counter wrapped");

    // Block 0 again — a continuation, not a restart.
    send_block(&gadget, 0, &[0x5A])?;
    assert_eq!(gadget.wrong_sequence_refusals(), 0, "the wrap was accepted");
    assert_eq!(
        gadget.entity_offset(0),
        Some(65_536),
        "the medium offset carried through the wrap"
    );
    Ok(())
}

// -------------------------------------------------------------------------------------
// The 2 MiB buffer and its silence
// -------------------------------------------------------------------------------------

#[test]
fn the_buffer_drains_at_the_dfu_bufsiz_boundary() -> Fallible {
    // `dfu_write` drains when the next block would overflow the entity buffer
    // (`dfu.c:409-416`, `:431-438`) — on the shipped loaders 2 MiB / 4096 = every 512th
    // block.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![AltConfig::flash("flash", 64)])
            .with_transfer_size(8)
            .with_buffer_size(16),
    );
    ready(&gadget, 0)?;
    for block in 0..4 {
        send_block(&gadget, block, &[u8::try_from(block).unwrap_or(0); 4])?;
    }
    assert_eq!(gadget.buffer_flushes(), 1, "one drain at the 16-byte boundary");
    assert_eq!(gadget.entity_offset(0), Some(16));
    for block in 4..8 {
        send_block(&gadget, block, &[u8::try_from(block).unwrap_or(0); 4])?;
    }
    assert_eq!(gadget.buffer_flushes(), 2);
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 32);

    // The default is the real one.
    assert_eq!(GadgetConfig::t32lq().buffer_size, 2 * 1024 * 1024);
    assert_eq!(GadgetConfig::t32lq().transfer_size, 4096);
    Ok(())
}

#[test]
fn a_drain_silences_ep0_and_then_recovers() -> Fallible {
    // The drain runs inside the DNLOAD's completion, in interrupt context: EP0 answers
    // nothing until it returns (the T40XP evidence is "DFU download
    // stalled at 2093056"). This is the whole reason `Grace::Write` and `Grace::Erase`
    // exist — a grace pin against a gadget with `flush_silence_polls` at 0 pins nothing.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![AltConfig::flash("flash", 64)])
            .with_transfer_size(8)
            .with_buffer_size(8)
            .with_flush_silence_polls(2),
    );
    ready(&gadget, 0)?;
    class_out(&gadget, request::DNLOAD, 0, &[1; 4])?;
    status(&gadget)?;
    class_out(&gadget, request::DNLOAD, 1, &[2; 4])?;

    for round in 0..2 {
        let error = status(&gadget).err().ok_or("EP0 is flushing")?;
        assert!(error.to_string().contains("timed out"), "round {round}: {error}");
    }
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_OK, DfuState::DnloadIdle.code()));
    Ok(())
}

#[test]
fn a_wedged_gadget_times_out_until_a_reset() -> Fallible {
    // What a `DNLOAD` interrupted mid-data-stage leaves behind — a browser reload, a
    // killed process. The C recovers it by resetting and re-probing (`dfu.c:501-508`),
    // and losing that was the one functional regression an earlier implementation had.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.wedge();
    assert!(gadget.is_wedged());
    let error = status(&gadget).err().ok_or("a wedged EP0 answers nothing")?;
    assert!(error.to_string().contains("timed out"), "{error}");

    block_on(gadget.reset())?;
    assert!(!gadget.is_wedged());
    ready(&gadget, 0)?;
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_OK, DfuState::DfuIdle.code()));
    Ok(())
}

// -------------------------------------------------------------------------------------
// The entity across a reset — both loader generations
// -------------------------------------------------------------------------------------

/// Write two blocks, bus-reset, and come back — the "browser reload mid-transfer" shape.
fn reload_after_two_blocks(loader: Loader) -> Result<FakeGadget, Box<dyn Error>> {
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_loader(loader));
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 4])?;
    send_block(&gadget, 1, &[0x22; 4])?;
    assert_eq!(gadget.entity_sequence(0), Some(2));
    block_on(gadget.reset())?;
    // The entity is untouched by the bus reset itself.
    assert_eq!(
        gadget.entity_sequence(0),
        Some(2),
        "a bus reset does not reach the entity"
    );
    ready(&gadget, 0)?;
    Ok(gadget)
}

#[test]
fn an_old_loader_refuses_the_first_block_zero_after_a_reload() -> Fallible {
    // Without `3d4848fe0dc` nothing between the reset and the next
    // transfer cleans the entity, so the host's block 0 is refused once — the exactly
    // one benign Wrong sequence number console line the bench T23 logged.
    let gadget = reload_after_two_blocks(Loader::Legacy)?;
    assert_eq!(gadget.entity_sequence(0), Some(2), "still stale after the re-configure");

    class_out(&gadget, request::DNLOAD, 0, &[0x33; 4])?;
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_ERR_UNKNOWN, DfuState::Error.code()));
    assert_eq!(gadget.wrong_sequence_refusals(), 1);

    // The refusal itself healed the entity, so the host's CLRSTATUS-and-retry works.
    class_out(&gadget, request::CLRSTATUS, 0, &[])?;
    send_block(&gadget, 0, &[0x33; 4])?;
    assert_eq!(gadget.wrong_sequence_refusals(), 1, "exactly one, not two");
    assert_eq!(gadget.entity_sequence(0), Some(1), "the retry was accepted");
    Ok(())
}

#[test]
fn a_fixed_loader_refuses_nothing_after_a_reload() -> Fallible {
    // The counterpart: the `SET_CONFIGURATION` that follows re-enumeration calls
    // `dfu_set_alt`, which aborts the transaction (`f_dfu.c:834`). Bench evidence: a
    // fixed T40XP logged zero wrong-sequence lines.
    let gadget = reload_after_two_blocks(Loader::Fixed)?;
    assert_eq!(gadget.entity_sequence(0), Some(0), "the re-configure cleaned it");
    send_block(&gadget, 0, &[0x33; 4])?;
    assert_eq!(gadget.wrong_sequence_refusals(), 0);
    Ok(())
}

#[test]
fn abort_cleans_the_entity_only_on_a_fixed_loader() -> Fallible {
    // The erase close-out's two branches, which is why it has two: after the blank
    // check's one-block upload, ABORT is enough on a fixed loader and the old one needs
    // the refused re-probe to heal itself.
    for (loader, sequence_after_abort) in [(Loader::Fixed, 0), (Loader::Legacy, 1)] {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_loader(loader));
        ready(&gadget, 0)?;
        gadget.preload(0, vec![0xFF; 64]);
        class_in(&gadget, request::UPLOAD, 0, 4)?;
        assert_eq!(gadget.entity_sequence(0), Some(1), "{loader:?}");

        class_out(&gadget, request::ABORT, 0, &[])?;
        assert_eq!(gadget.entity_sequence(0), Some(sequence_after_abort), "{loader:?}");
        assert_eq!(gadget.dfu_state(), DfuState::DfuIdle, "{loader:?}");
    }
    Ok(())
}

#[test]
fn clrstatus_cleans_the_entity_only_on_a_fixed_loader() -> Fallible {
    // The same asymmetry on the other recovery request (`f_dfu.c:610`). It is what
    // makes the `make_idle`-then-retry work at all on a fixed loader.
    for (loader, sequence_after) in [(Loader::Fixed, 0), (Loader::Legacy, 1)] {
        let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_loader(loader));
        ready(&gadget, 0)?;
        gadget.preload(0, vec![0xFF; 64]);
        class_in(&gadget, request::UPLOAD, 0, 4)?;
        into_error(&gadget)?;
        class_out(&gadget, request::CLRSTATUS, 0, &[])?;
        assert_eq!(gadget.entity_sequence(0), Some(sequence_after), "{loader:?}");
    }
    Ok(())
}

// -------------------------------------------------------------------------------------
// The manifest phase
// -------------------------------------------------------------------------------------

#[test]
fn manifest_holds_while_the_deferred_flush_is_pending() -> Fallible {
    // The fork's change (`f_dfu.c:519-533`, u-boot `c413453`): stock f_dfu
    // reported dfuIDLE mid-erase and the host let go after 0.6 s calling it success.
    // The real 4096-byte transfer size: the 17-byte token has to fit in one block.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_manifest_hold_polls(3)
            .with_virt_poll_timeout_ms(super::VIRT_POLL_TIMEOUT_MS),
    );
    ready(&gadget, 1)?; // the erase alt, whose entity carries a poll pace
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;

    // The manifest-sync poll: reports dfuMANIFEST, arms the flush afterwards.
    let (_, poll, state) = status(&gadget)?;
    assert_eq!(state, DfuState::Manifest.code());
    assert_eq!(poll, 500, "the entity's own pace, f_dfu.c:198");
    assert_eq!(gadget.erases(), 0, "nothing has flushed yet");

    for round in 0..3 {
        let (_, poll, state) = status(&gadget)?;
        assert_eq!(state, DfuState::Manifest.code(), "hold round {round}");
        assert_eq!(poll, 500, "hold round {round}");
        assert_eq!(gadget.erases(), 0, "hold round {round}");
    }

    let (bstatus, poll, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_OK, DfuState::DfuIdle.code()));
    assert_eq!(poll, 0, "an idle device names no pace");
    assert_eq!(gadget.erases(), 1);
    Ok(())
}

#[test]
fn a_flash_manifest_names_no_poll_pace() -> Fallible {
    // `dfu_get_manifest_timeout` falls back to `DFU_MANIFEST_POLL_TIMEOUT`, which is
    // `DFU_DEFAULT_POLL_TIMEOUT`, which is **0** (`include/dfu.h:121-125`). Only the
    // virt entities install a `poll_timeout` (`arch/mips/mach-xburst/dfu.c:282`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_manifest_hold_polls(1));
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 4])?;
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    let (_, poll, state) = status(&gadget)?;
    assert_eq!(state, DfuState::Manifest.code());
    assert_eq!(poll, 0);
    Ok(())
}

#[test]
fn poll_timeout_is_a_24_bit_field() -> Fallible {
    // `dfu_set_poll_timeout` (`f_dfu.c:141-151`): zero, and anything that does not fit
    // in 24 bits, is reported as three zero bytes. Every test in an earlier
    // implementation used 250 or 500 ms, whose high byte is zero, so `<< 16` and `>> 16`
    // were indistinguishable and coverage called the line covered throughout. This is the
    // device end of `dfu_poll_timeout_above_the_low_word`.
    //
    // The last case has **non-zero low bytes on purpose**. `0x0100_0000` would not do:
    // its low three bytes are zero, so a device that truncated instead of zeroing would
    // answer the same thing, and so would a `||` written as `&&`. Two compensating
    // differences hide a real one — the same shape as the daemon's `|`-versus-`^` token
    // comparison.
    for (ms, expected) in [
        (500, 500),
        (0x0001_0000, 0x0001_0000),
        (0x00FF_FFFF, 0x00FF_FFFF),
        (0x0100_0001, 0),
    ] {
        let gadget = FakeGadget::new(
            GadgetConfig::t32lq()
                .with_manifest_hold_polls(1)
                .with_virt_poll_timeout_ms(ms),
        );
        ready(&gadget, 1)?;
        class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
        status(&gadget)?; // poll between the token and the ZLP
        class_out(&gadget, request::DNLOAD, 1, &[])?;
        let (_, poll, _) = status(&gadget)?;
        assert_eq!(poll, expected, "bwPollTimeout for {ms} ms");
    }
    Ok(())
}

// -------------------------------------------------------------------------------------
// The token-gated virt alts
// -------------------------------------------------------------------------------------

/// Arm `alt` with `token` and poll the manifest through to the flush.
fn arm_and_manifest(gadget: &FakeGadget, alt: u8, token: &[u8]) -> Result<(), Box<dyn Error>> {
    ready(gadget, alt)?;
    class_out(gadget, request::DNLOAD, 0, token)?;
    status(gadget)?; // poll between the token and the ZLP
    class_out(gadget, request::DNLOAD, 1, &[])?;
    status(gadget)?;
    status(gadget)?;
    Ok(())
}

#[test]
fn the_erase_token_arms_in_the_write_and_wipes_in_the_flush() -> Fallible {
    // `dfu_write_medium_virt` validates and arms in interrupt context; the erase itself
    // runs in `xburst_erase_flush` from the gadget's main loop
    // (`arch/mips/mach-xburst/dfu.c:111-118`, `:219-225`, `:233-253`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    write_one_block(&gadget, 0, &[0xAA; 32])?;
    assert!(!gadget.medium(0).ok_or("alt 0")?.is_empty());

    arm_and_manifest(&gadget, 1, ERASE_TOKEN)?;
    assert_eq!(gadget.erases(), 1);
    assert_eq!(gadget.entity_armed(1), Some(false), "the flush spent the arming");
    assert!(
        gadget.medium(0).ok_or("alt 0")?.is_empty(),
        "the whole boot flash, which is alt 0"
    );
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    Ok(())
}

#[test]
fn a_garbled_erase_token_is_refused_and_the_status_says_so() -> Fallible {
    // `arch/mips/mach-xburst/dfu.c:219-223` returns -EINVAL, which fails the drain
    // inside `dfu_write` (`dfu.c:431-437`) and lands as errUNKNOWN/dfuERROR on the next
    // poll. Nothing is erased and the arming is dropped by `dfu_error_callback`.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    write_one_block(&gadget, 0, &[0xAA; 32])?;

    ready(&gadget, 1)?;
    class_out(&gadget, request::DNLOAD, 0, b"XBURST-FLASH-WIPF")?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_ERR_UNKNOWN, DfuState::Error.code()));
    assert_eq!(gadget.erases(), 0);
    assert_eq!(gadget.entity_armed(1), Some(false));
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 32, "nothing was wiped");
    Ok(())
}

#[test]
fn the_token_check_is_a_length_floor_and_a_prefix_compare() -> Fallible {
    // Not an exact-length compare: `*len < strlen(tok) || memcmp(buf, tok, strlen(tok))`
    // (`arch/mips/mach-xburst/dfu.c:219-220`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    let mut longer = ERASE_TOKEN.to_vec();
    longer.extend_from_slice(b" and then some");
    arm_and_manifest(&gadget, 1, &longer)?;
    assert_eq!(gadget.erases(), 1, "a longer buffer starting with the token arms");

    // One byte short of the floor does not.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 1)?;
    class_out(&gadget, request::DNLOAD, 0, &ERASE_TOKEN[..ERASE_TOKEN.len() - 1])?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    let (bstatus, _, _) = status(&gadget)?;
    assert_eq!(bstatus, STATUS_ERR_UNKNOWN);
    assert_eq!(gadget.erases(), 0);
    Ok(())
}

#[test]
fn a_manifest_that_never_armed_reports_success_and_erases_nothing() -> Fallible {
    // `xburst_erase_flush` returns 0 when the arming is not set (`:238-239`). This is the
    // device shape the blank check exists for: the DFU status alone cannot
    // tell "erased" from "did nothing".
    //
    // **On the erase alt**, which is the only place the branch lives. The earlier form
    // of this test sent the token to alt **0** — a plain 17-byte write to the flash
    // entity, whose `flush_medium` is a different arm entirely — so it never reached
    // `xburst_erase_flush` at all and would have passed for any implementation of it.
    // The route in is the one `an_owed_flush_outlives_dfumanifest_…` documents: the
    // flush is the main loop's, and a failing transaction on the *other* virt alt drops
    // both armings (`arch/mips/mach-xburst/dfu.c:290-296`).
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_manifest_hold_polls(2)
            .with_loader(Loader::Legacy),
    );
    gadget.preload(0, [0xAA; 32]);

    ready(&gadget, 1)?;
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    assert_eq!(status(&gadget)?.2, DfuState::Manifest.code());
    assert_eq!(gadget.entity_armed(1), Some(true), "the erase never armed");

    // A refused transaction on `reboot` takes the erase's arming with it.
    block_on(gadget.set_alt_setting(0, 2))?;
    class_out(&gadget, request::DNLOAD, 9, &[0xEE])?;
    assert_eq!(gadget.entity_armed(1), Some(false), "the global disarm");
    class_out(&gadget, request::CLRSTATUS, 0, &[])?;
    block_on(gadget.set_alt_setting(0, 1))?;

    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_OK, DfuState::DfuIdle.code()), "manifest OK");
    assert_eq!(
        gadget.entity_inited(1),
        Some(false),
        "the owed flush never ran: only `dfu_flush` cleans the transaction on this loader"
    );
    assert_eq!(gadget.erases(), 0, "and nothing was erased");
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 32, "the flash survived");
    assert_eq!(gadget.reboots(), 0);
    Ok(())
}

#[test]
fn an_erase_with_no_boot_flash_ends_the_gadget() -> Fallible {
    // `xburst_erase_flush` returns -ENODEV when nothing was detected
    // (`arch/mips/mach-xburst/dfu.c:251-252`), and `common/dfu.c:84-87` leaves the main
    // loop on a failed deferred flush — so the device drops off the bus rather than
    // reporting the failure through DFU status. An operation cannot read this as
    // "erased".
    let gadget =
        FakeGadget::new(GadgetConfig::new(vec![AltConfig::erase(), AltConfig::reboot()]).with_manifest_hold_polls(0));
    ready(&gadget, 0)?;
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    status(&gadget)?;
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    status(&gadget)?;
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::NoDevice);
    assert_eq!(gadget.erases(), 0);
    Ok(())
}

#[test]
fn the_reboot_flush_takes_the_device_off_the_bus() -> Fallible {
    // `xburst_reboot_flush` calls `do_reset()`, which never returns
    // (`arch/mips/mach-xburst/dfu.c:260-268`). The post-ZLP poll failing
    // **is** the reset happening, which is why reboot gets grace 0.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 2)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?;
    assert_eq!(gadget.entity_armed(2), Some(false), "the token is still buffered");
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    assert_eq!(gadget.entity_armed(2), Some(true), "the ZLP's drain armed it");

    // The manifest-sync poll is answered; the one after it runs the flush and vanishes.
    status(&gadget)?;
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::NoDevice);
    assert_eq!(gadget.reboots(), 1);
    assert!(gadget.is_gone());

    // And it stays gone — for every call, a release included. An operation that
    // releases on every exit path will see this after a
    // *successful* reboot, and must not report it as the operation's failure.
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::NoDevice);
    for kind in [
        block_on(gadget.release_interface(0)).err().map(|e| kind_of(&e)),
        block_on(gadget.reset()).err().map(|e| kind_of(&e)),
        block_on(gadget.set_configuration(1)).err().map(|e| kind_of(&e)),
    ] {
        assert_eq!(kind, Some(UsbErrorKind::NoDevice));
    }
    assert_eq!(gadget.resets(), 0, "a device off the bus cannot be reset");
    Ok(())
}

#[test]
fn a_failed_zlp_never_arms_the_reboot() -> Fallible {
    // Ignoring the `DNLOAD(1, ZLP)` result is a C defect. The drain
    // that validates the token only runs from the ZLP's completion (`dfu.c:431-438`), so
    // a ZLP that never reached the device leaves the loader unarmed and
    // "Reboot triggered" would be a lie.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 2)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?;
    gadget.inject(When::ClassBlock(request::DNLOAD, 1), Fault::Stall);

    let error = class_out(&gadget, request::DNLOAD, 1, &[])
        .err()
        .ok_or("the injected stall must fire")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall);
    assert_eq!(gadget.entity_armed(2), Some(false));
    assert_eq!(gadget.reboots(), 0);
    assert!(!gadget.is_gone(), "the device is still there, unrebooted");
    Ok(())
}

#[test]
fn a_reboot_token_on_the_erase_alt_arms_nothing() -> Fallible {
    // Each virt alt checks only its own token (`arch/mips/mach-xburst/dfu.c:206-225`),
    // which is what "armed only for its own alt" means: no bare USB reset
    // and no firmware write can trigger either.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 1)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    let (bstatus, _, _) = status(&gadget)?;
    assert_eq!(bstatus, STATUS_ERR_UNKNOWN);
    assert_eq!((gadget.erases(), gadget.reboots()), (0, 0));
    Ok(())
}

#[test]
fn the_token_must_arrive_at_offset_zero() -> Fallible {
    // `offset != 0` refuses (`arch/mips/mach-xburst/dfu.c:219`). Reachable by filling
    // the entity buffer first, so the token drains at a non-zero offset.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(32)
            .with_buffer_size(32)
            .with_manifest_hold_polls(0),
    );
    ready(&gadget, 1)?;
    send_block(&gadget, 0, ERASE_TOKEN)?; // drains at offset 0 and arms
    assert_eq!(gadget.entity_armed(1), Some(true));
    assert_eq!(gadget.entity_offset(1), Some(17));

    send_block(&gadget, 1, ERASE_TOKEN)?; // drains at offset 17 and is refused
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_ERR_UNKNOWN, DfuState::Error.code()));
    assert_eq!(gadget.entity_armed(1), Some(false), "and the error callback disarmed");
    Ok(())
}

// -------------------------------------------------------------------------------------
// USB device state
// -------------------------------------------------------------------------------------

#[test]
fn detach_puts_the_gadget_back_in_runtime_mode() -> Fallible {
    // `f_dfu.c:377-392`'s proprietary extension, and the two runtime states it leads to
    // (`:264-312`). Nothing in this tool sends `DFU_DETACH` — the C has no call site
    // either — so this exists to keep the model's own runtime half honest rather than
    // because an operation needs it.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    class_out(&gadget, request::DETACH, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::AppIdle);

    // appIDLE serves the two reads and DETACH; everything else stalls (`:271-286`).
    assert_eq!(status(&gadget)?.2, DfuState::AppIdle.code());
    assert_eq!(class_in(&gadget, request::GETSTATE, 0, 1)?, [DfuState::AppIdle.code()]);
    let stalled = class_out(&gadget, request::ABORT, 0, &[])
        .err()
        .ok_or("ABORT is not an appIDLE case")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    // And it does NOT create dfuERROR — runtime mode has no such state.
    assert_eq!(gadget.dfu_state(), DfuState::AppIdle);

    // **A runtime-mode `DETACH` nets dfuIDLE, and appDETACH is never observable.**
    // `f_dfu.c:279` assigns it and `to_dfu_mode` overwrites it on the next line
    // (`:280` -> `:230`) — which is the point of the call, because `DFU_DETACH` in
    // runtime mode is what swaps the function over to its DFU descriptors. The earlier
    // form of this test asserted the intermediate value and so *defended* a model
    // defect: the emulator answered a `GETSTATE` with appDETACH where the device
    // answers dfuIDLE.
    class_out(&gadget, request::DETACH, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    assert_eq!(status(&gadget)?.2, DfuState::DfuIdle.code());
    assert_eq!(
        class_in(&gadget, request::GETSTATE, 0, 1)?,
        [DfuState::DfuIdle.code()],
        "the device never reports appDETACH: to_dfu_mode overwrote it"
    );
    // And it really is DFU mode again: `ABORT` is a dfuIDLE case, where in runtime mode
    // it stalled two lines above.
    class_out(&gadget, request::ABORT, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);

    // A `SET_INTERFACE` also lands in DFU mode (`f_dfu.c:837`).
    block_on(gadget.set_alt_setting(0, 0))?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    Ok(())
}

#[test]
fn a_gadget_comes_up_unconfigured_and_idle() {
    // The driverless gadget often has no active configuration, which is why
    // the host reads configuration *index 0* rather than the active one.
    let gadget = FakeGadget::t32lq();
    assert_eq!(gadget.active_configuration(), None);
    assert_eq!(gadget.claimed(), None);
    // `dfu_bind` ends with `to_dfu_mode` (`f_dfu.c:782`, `:230`).
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
}

#[test]
fn set_configuration_returns_every_interface_to_alt_zero() -> Fallible {
    // USB 9.4.7, and `f_dfu.c:823-841` via the composite layer. An earlier emulator left
    // `current_alt` untouched here, so a test could not
    // tell an erase that left the `erase` alt live from one that did not — the T40XP
    // "dfu erase: bad token" case.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 1)?;
    assert_eq!(gadget.alt(), 1);
    block_on(gadget.set_configuration(1))?;
    assert_eq!(gadget.alt(), 0);
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    Ok(())
}

#[test]
fn a_reset_clears_the_configuration_and_the_claim_but_not_the_alt() -> Fallible {
    // USB 9.1.1.5 puts the device back in the Default state, so the configuration and
    // the claim are gone. `f_dfu->altsetting` is **not**: `composite_disconnect` calls
    // `reset_config` (`composite.c:1318-1326`), which calls `dfu_disable`, which zeroes
    // `f_dfu->config` and nothing else (`f_dfu.c:851-860`). The alt goes back to 0 one
    // request later, from the `SET_CONFIGURATION` the host has to send anyway.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 2)?;
    assert_eq!(gadget.active_configuration(), Some(1));

    block_on(gadget.reset())?;

    assert_eq!(gadget.active_configuration(), None, "USB 9.1.1.5");
    assert_eq!(gadget.claimed(), None);
    assert_eq!(gadget.alt(), 2, "nothing on the device writes the alt on a reset");
    assert_eq!(gadget.resets(), 1);

    // And the request that does write it (`f_dfu.c:829-833`, USB 9.4.7).
    block_on(gadget.set_configuration(1))?;
    assert_eq!(gadget.alt(), 0);
    Ok(())
}

#[test]
fn a_reset_without_a_reconfiguration_leaves_the_sequence_on_the_old_alt() -> Fallible {
    // **The legacy loader, through the seam a reset actually opens.** The entity's block
    // sequence counter survives a bus reset (`reset` touches no entity), and the only
    // thing that cleans it is the `dfu_set_alt(f, intf, 0)` the composite layer runs for
    // `SET_CONFIGURATION`. A model that zeroed `altsetting` inside `reset()` applied
    // half of that request at a moment the device applies none of it, and hid this case:
    // a host that resets and carries on without re-configuring is still addressing the
    // alt it was on, with that alt's counter.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 1)?;
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    status(&gadget)?;
    assert_eq!(gadget.entity_sequence(1), Some(1), "the erase entity advanced");
    assert_eq!(gadget.entity_sequence(0), Some(0), "and the flash entity did not");

    block_on(gadget.reset())?;

    assert_eq!(gadget.alt(), 1, "the reset moved the alt");
    assert_eq!(gadget.entity_sequence(1), Some(1), "the reset cleaned the entity");
    assert_eq!(gadget.entity_inited(1), Some(true));

    // Re-claim without a `SET_CONFIGURATION`, as a host that only needed the pipes
    // cleared would: the next block still goes to entity 1, and it is still expecting 1.
    block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))?;
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    assert_eq!(
        gadget.wrong_sequence_refusals(),
        1,
        "block 0 was accepted, so the reset had cleaned entity 1 after all"
    );

    // Now the request that *does* clean it, on a fixed loader — and note **which**
    // entity it cleans. `f_dfu_abort_transaction` reads `dfu_get_entity(f_dfu->
    // altsetting)` *before* `dfu_set_alt` overwrites the field (`f_dfu.c:834`, `:836`),
    // so the entity cleaned is the one the host was on when the reset happened, not
    // alt 0. Keeping the alt through the reset is what makes that observable.
    block_on(gadget.set_configuration(1))?;
    assert_eq!(gadget.alt(), 0);
    assert_eq!(
        gadget.entity_sequence(1),
        Some(0),
        "the abort cleaned alt 0's entity instead of the one in force"
    );
    assert_eq!(gadget.entity_inited(1), Some(false));
    Ok(())
}

#[test]
fn a_reset_leaves_the_entity_buffer_the_offset_and_the_arming_alone() -> Fallible {
    // The sequence counter is the famous half; the *rest* of the entity survives a reset
    // for the same reason — `reset` touches no entity at all — and none of it had ever
    // been observed across one. The arming is the sharp end: an erase a host armed
    // before a reset is still armed after it, which is why `dfu_error_callback` exists
    // at all (`arch/mips/mach-xburst/dfu.c:286-296`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_buffer_size(ERASE_TOKEN.len()));
    ready(&gadget, 1)?;
    // A block that exactly fills the entity buffer drains at the boundary
    // (`dfu.c:430-438`), so the token reaches `write_medium` and arms without a manifest.
    class_out(&gadget, request::DNLOAD, 0, ERASE_TOKEN)?;
    status(&gadget)?;
    assert_eq!(gadget.entity_armed(1), Some(true));
    assert_eq!(gadget.entity_offset(1), Some(ERASE_TOKEN.len() as u64));

    block_on(gadget.reset())?;

    assert_eq!(gadget.entity_armed(1), Some(true), "the reset disarmed the erase");
    assert_eq!(
        gadget.entity_offset(1),
        Some(ERASE_TOKEN.len() as u64),
        "the reset rewound the medium cursor"
    );
    assert_eq!(gadget.entity_inited(1), Some(true), "the reset closed the transaction");
    assert_eq!(gadget.erases(), 0, "and nothing was flushed on the way");
    Ok(())
}

#[test]
fn a_wedged_ep0_answers_no_setup_packet_at_all() -> Fallible {
    // A wedge is the *endpoint*, not the class handler: `SET_CONFIGURATION` and
    // `SET_INTERFACE` are setup packets on EP0 too (USB 2.0 §9.4.7, §9.4.9), and a UDC
    // whose request context is stuck in a flash write answers none of them. Modelling
    // the wedge as class-requests-only let a recovery path re-configure and re-select an
    // alt on a device that would not have answered either, which is the state
    // `ops::probe`'s reset exists to get out of.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.wedge();

    assert_eq!(poll_error(&gadget)?, UsbErrorKind::Timeout);
    let config = block_on(gadget.set_configuration(1))
        .err()
        .ok_or("a wedged EP0 answered SET_CONFIGURATION")?;
    assert_eq!(kind_of(&config), UsbErrorKind::Timeout);
    let alt = block_on(gadget.set_alt_setting(0, 1))
        .err()
        .ok_or("a wedged EP0 answered SET_INTERFACE")?;
    assert_eq!(kind_of(&alt), UsbErrorKind::Timeout);
    assert_eq!(gadget.alt(), 0, "the alt moved on a request that was never answered");

    // The claim and the release are the host's own bookkeeping and are unaffected, as
    // is the reset that clears the wedge.
    block_on(gadget.release_interface(0))?;
    block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))?;
    block_on(gadget.reset())?;
    assert!(!gadget.is_wedged());
    Ok(())
}

#[test]
fn a_gadget_that_left_the_bus_says_so_on_every_call() -> Fallible {
    // A successful reboot takes the device off the bus mid-request
    // (`arch/mips/mach-xburst/dfu.c:266`), and an operation's release-on-every-path
    // discipline then runs against a device that is gone. Every entry point has to
    // answer `NoDevice`: the three that skipped the gate answered `NotClaimed` instead —
    // the caller's *other* mistake — which reads as "you did not claim" for a device
    // that has been reset out from under the caller.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));
    ready(&gadget, 2)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?;
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    status(&gadget)?;
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::NoDevice);
    assert!(gadget.is_gone());

    let endpoint = BulkEndpoint::new(Direction::In, 1).ok_or("0x81")?;
    for outcome in [
        block_on(gadget.bulk_in(64, TIMEOUT)).err(),
        block_on(gadget.bulk_out(&[0], TIMEOUT)).err(),
        block_on(gadget.clear_halt(endpoint)).err(),
        block_on(gadget.release_interface(0)).err(),
        block_on(gadget.set_configuration(1)).err(),
    ] {
        let error = outcome.ok_or("a gone gadget answered a call")?;
        assert_eq!(kind_of(&error), UsbErrorKind::NoDevice, "{error}");
    }
    Ok(())
}

#[test]
fn a_fault_reaches_the_bulk_calls_and_the_halt() -> Fallible {
    // The other half of routing them through the gate: a test can now put a failure on
    // them. Nothing in this tool sends bulk to a DFU gadget — the interface declares no
    // endpoints — but a double whose calls cannot be made to fail is a double that
    // cannot pin what a caller does about the failure.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    let endpoint = BulkEndpoint::new(Direction::In, 1).ok_or("0x81")?;

    gadget.inject(When::Bulk, Fault::Timeout);
    let timed_out = block_on(gadget.bulk_in(64, TIMEOUT))
        .err()
        .ok_or("the bulk IN fault never fired")?;
    assert_eq!(kind_of(&timed_out), UsbErrorKind::Timeout);

    gadget.inject(When::ClearHalt, Fault::Stall);
    let stalled = block_on(gadget.clear_halt(endpoint))
        .err()
        .ok_or("the clear_halt fault never fired")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);

    // Unarmed, they are still the caller's bug.
    assert_eq!(
        kind_of(&block_on(gadget.bulk_out(&[0], TIMEOUT)).err().ok_or("bulk OUT")?),
        UsbErrorKind::NotClaimed
    );
    Ok(())
}

#[test]
fn a_vendor_request_reaches_the_dfu_state_machine() -> Fallible {
    // `composite_setup` sends everything that is not `USB_TYPE_STANDARD` to `unknown`
    // (`composite.c:1031-1034`), and `dfu_handle` dispatches everything that is not
    // standard through `dfu_state[…]` (`f_dfu.c:659-666`). It never checks for
    // `USB_TYPE_CLASS`, so a vendor `bRequest` of 3 is answered as a `GETSTATUS`.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;

    let reply = block_on(gadget.control_in(
        ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Interface,
            request: request::GETSTATUS,
            value: 0,
            index: 0,
            len: 6,
        },
        TIMEOUT,
    ))?;
    assert_eq!(reply.len(), 6, "a vendor GETSTATUS was stalled, not answered");
    assert_eq!(reply[4], DfuState::DfuIdle.code());

    // And a vendor request the state machine does not know creates dfuERROR, exactly as
    // an unknown class request does.
    let stalled = block_on(gadget.control_out(
        ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Interface,
            request: 0x42,
            value: 0,
            index: 0,
            data: &[],
        },
        TIMEOUT,
    ))
    .err()
    .ok_or("an unknown vendor request was accepted")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    assert_eq!(gadget.dfu_state(), DfuState::Error);
    Ok(())
}

#[test]
fn an_unknown_descriptor_type_is_answered_empty_once_configured() -> Fallible {
    // `composite.c:1095-1096` hands an unknown descriptor type to the function's own
    // `setup`, and `dfu_handle` leaves `value` at 0 for any standard `GET_DESCRIPTOR`
    // that is not `DFU_DT_FUNC` (`f_dfu.c:659-664`) — so EP0 answers an empty data
    // stage rather than stalling (`:668-671`). Unconfigured it is the composite layer
    // that answers, and it bails out with `-EOPNOTSUPP` still in hand
    // (`composite.c:1247-1248`), which is a stall.
    let gadget = FakeGadget::t32lq();
    let unknown = 0x2F; // not DEVICE, CONFIGURATION, STRING or the DFU functional type

    let stalled = get_descriptor(&gadget, unknown, 0, 64)
        .err()
        .ok_or("an unconfigured device answered an unknown descriptor")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);

    ready(&gadget, 0)?;
    assert!(
        get_descriptor(&gadget, unknown, 0, 64)?.is_empty(),
        "a configured device stalls where it answers a ZLP"
    );
    Ok(())
}

#[test]
fn a_descriptor_is_capped_by_usb_bufsiz_and_a_class_reply_by_the_transfer_size() -> Fallible {
    // Two ceilings, two `#define`s, and they had never been held apart: a class answer
    // is built by `dfu_handle` and capped at `DFU_USB_BUFSIZ` (`f_dfu.c:669`), while a
    // descriptor is built by `composite_setup` in `cdev->req->buf`, which is
    // `USB_BUFSIZ` bytes (`composite.c:17`, `:1029`, `:1396`).
    let gadget = FakeGadget::new(GadgetConfig::t32lq()
            .with_transfer_size(8) // also moves usb_bufsiz, as a real loader would
            .with_usb_bufsiz(64));
    ready(&gadget, 0)?;

    // The configuration descriptor is longer than 8 bytes and must not be cut to it.
    let config = get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 64)?;
    assert!(
        config.len() > 8,
        "the descriptor was capped by wTransferSize: {} bytes",
        config.len()
    );
    assert!(config.len() <= 64, "and it must still respect USB_BUFSIZ");

    // A class reply is capped by the transfer size, not by USB_BUFSIZ: a six-byte
    // `GETSTATUS` comes back as eight-or-fewer, and `wLength` still wins under that.
    let status = class_in(&gadget, request::GETSTATUS, 0, 6)?;
    assert_eq!(status.len(), 6);
    Ok(())
}

#[test]
fn a_short_fault_needs_a_data_stage_to_be_short_of() -> Fallible {
    // `When` and `Fault` are independent, so the pair can name a combination no wire
    // produces. `SET_CONFIGURATION` has an empty data stage and a claim never reaches
    // the bus at all, so `Short { want: 0 }` is a value a caller's `got < want`
    // arithmetic reads as nonsense. Those sites answer the backend's catch-all instead.
    let gadget = FakeGadget::t32lq();
    gadget.inject(When::SetConfiguration, Fault::Short { got: 3 });
    let refused = block_on(gadget.set_configuration(1))
        .err()
        .ok_or("the fault never fired")?;
    assert_eq!(kind_of(&refused), UsbErrorKind::Fault, "a Short with no data stage");

    gadget.inject(When::Claim, Fault::Short { got: 3 });
    let claim = block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))
        .err()
        .ok_or("the claim fault never fired")?;
    assert_eq!(kind_of(&claim), UsbErrorKind::Fault);

    // Where there *is* a data stage it is a real short. On an OUT it is an error
    // carrying both numbers — which is the case that separates the guard from "always":
    // a short control IN never reaches `Fault::error` at all, because a read that came
    // back short is not a failure (the trait says so), so it is truncated instead.
    ready(&gadget, 0)?;
    gadget.inject(When::Class(request::DNLOAD), Fault::Short { got: 2 });
    let out = class_out(&gadget, request::DNLOAD, 0, &[0xAA; 9])
        .err()
        .ok_or("a short control OUT is an error")?;
    assert_eq!(kind_of(&out), UsbErrorKind::Short { got: 2, want: 9 });

    gadget.inject(When::Class(request::GETSTATUS), Fault::Short { got: 2 });
    let short = class_in(&gadget, request::GETSTATUS, 0, 6)?;
    assert_eq!(short.len(), 2, "a short control IN truncates rather than failing");
    Ok(())
}

#[test]
fn an_unknown_configuration_value_is_refused() -> Fallible {
    let gadget = FakeGadget::t32lq();
    let error = block_on(gadget.set_configuration(7))
        .err()
        .ok_or("configuration 7 does not exist")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall);
    // Configuration 0 is the "unconfigure me" request and is always legal.
    block_on(gadget.set_configuration(0))?;
    assert_eq!(gadget.active_configuration(), None);
    Ok(())
}

#[test]
fn an_alt_the_interface_does_not_have_is_refused() -> Fallible {
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    let error = block_on(gadget.set_alt_setting(0, 3))
        .err()
        .ok_or("alt 3 does not exist")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall, "USB 9.4.10");
    assert_eq!(gadget.alt(), 0);
    Ok(())
}

// -------------------------------------------------------------------------------------
// The trait obligations an audit pinned on the mock
// -------------------------------------------------------------------------------------

#[test]
fn release_is_idempotent() -> Fallible {
    // Contract §2.4: a double that punished a defensive release punished
    // the release-on-every-path discipline instead of the bug.
    let gadget = FakeGadget::t32lq();
    block_on(gadget.release_interface(0))?;
    ready(&gadget, 0)?;
    assert_eq!(gadget.claimed(), Some(InterfaceSpec::control_only(0)));
    block_on(gadget.release_interface(0))?;
    block_on(gadget.release_interface(0))?;
    assert_eq!(gadget.claimed(), None);
    Ok(())
}

#[test]
fn bulk_transfers_and_clear_halt_are_not_claimed() -> Fallible {
    // DFU 1.1's own shape: the interface declares `bNumEndpoints = 0`
    // (`f_dfu.c:721`), so there is no endpoint for a claim to declare.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    let endpoint = BulkEndpoint::new(Direction::In, 1).ok_or("endpoint 1 IN")?;
    for kind in [
        block_on(gadget.bulk_in(64, TIMEOUT)).err().map(|e| kind_of(&e)),
        block_on(gadget.bulk_out(&[0; 4], TIMEOUT)).err().map(|e| kind_of(&e)),
        block_on(gadget.clear_halt(endpoint)).err().map(|e| kind_of(&e)),
    ] {
        assert_eq!(kind, Some(UsbErrorKind::NotClaimed));
    }
    // And a claim that declares one is refused where the failure is truthful.
    let error = block_on(gadget.claim_interface(InterfaceSpec::with_bulk(
        0,
        endpoint,
        BulkEndpoint::new(Direction::Out, 1).ok_or("endpoint 1 OUT")?,
    )))
    .err()
    .ok_or("a DFU interface has no bulk endpoint")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Fault);
    Ok(())
}

#[test]
fn set_alt_setting_without_the_claim_is_not_claimed() -> Fallible {
    let gadget = FakeGadget::t32lq();
    block_on(gadget.set_configuration(1))?;
    let error = block_on(gadget.set_alt_setting(0, 1))
        .err()
        .ok_or("no claim is in force")?;
    assert_eq!(kind_of(&error), UsbErrorKind::NotClaimed);
    Ok(())
}

#[test]
fn an_interface_the_device_does_not_have_cannot_be_claimed() -> Fallible {
    let gadget = FakeGadget::t32lq();
    let error = block_on(gadget.claim_interface(InterfaceSpec::control_only(3)))
        .err()
        .ok_or("interface 3 does not exist")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Unsupported);
    Ok(())
}

// -------------------------------------------------------------------------------------
// Fault injection
// -------------------------------------------------------------------------------------

#[test]
fn an_injected_fault_fires_only_at_the_site_it_names() -> Fallible {
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.inject(When::ClassBlock(request::DNLOAD, 2), Fault::Timeout);

    send_block(&gadget, 0, &[1; 4])?;
    send_block(&gadget, 1, &[2; 4])?;
    let error = class_out(&gadget, request::DNLOAD, 2, &[3; 4])
        .err()
        .ok_or("block 2 is armed")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Timeout);
    assert_eq!(error.timeout(), Some(TIMEOUT), "the deadline is recorded");
    // Spent: the retry of the same block goes through.
    class_out(&gadget, request::DNLOAD, 2, &[3; 4])?;
    Ok(())
}

#[test]
fn a_repeated_injection_counts_down() -> Fallible {
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.inject_times(When::Class(request::GETSTATUS), Fault::Timeout, 2);
    for round in 0..2 {
        assert_eq!(poll_error(&gadget)?, UsbErrorKind::Timeout, "round {round}");
    }
    status(&gadget)?;
    // Zero repeats arms nothing at all.
    gadget.inject_times(When::Class(request::GETSTATUS), Fault::Stall, 0);
    status(&gadget)?;
    Ok(())
}

#[test]
fn silence_ep0_can_be_armed_on_its_own() -> Fallible {
    // The knob a whole-chip erase needs: `flush_silence_polls` covers a buffer drain,
    // and this covers an erase that runs long inside `flush_medium` where a test wants
    // to say how long without a drain to hang it on.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.silence_ep0(2);
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::Timeout);
    assert_eq!(poll_error(&gadget)?, UsbErrorKind::Timeout);
    assert_eq!(status(&gadget)?.2, DfuState::DfuIdle.code(), "and then it recovers");
    Ok(())
}

#[test]
fn a_descriptor_read_can_be_faulted_on_its_own() -> Fallible {
    // `When::Descriptor` matches the enumeration reads and nothing else, so a test can
    // fail `read_info` without touching the DFU requests that follow it.
    let gadget = FakeGadget::t32lq();
    gadget.inject(When::Descriptor, Fault::Stall);
    let error = get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 9)
        .err()
        .ok_or("the injected stall must fire")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall);
    assert_eq!(get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 9)?.len(), 9);

    // A class request is not a descriptor read, so the arming does not touch it.
    ready(&gadget, 0)?;
    gadget.inject(When::Descriptor, Fault::Stall);
    status(&gadget)?;
    assert!(get_descriptor(&gadget, descriptors::CONFIGURATION, 0, 9).is_err());
    Ok(())
}

#[test]
fn a_standard_request_that_is_not_a_descriptor_read_stalls() -> Fallible {
    // The composite layer answers `GET_DESCRIPTOR` and `f_dfu` answers class requests;
    // nothing here implements `GET_CONFIGURATION`. It matters that the two tests are
    // separate — a device that treated every standard IN as a descriptor read would
    // answer this one with a configuration descriptor.
    let gadget = FakeGadget::t32lq();
    let error = block_on(gadget.control_in(
        ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x08, // GET_CONFIGURATION
            value: 0x0200,
            index: 0,
            len: 64,
        },
        TIMEOUT,
    ))
    .err()
    .ok_or("GET_CONFIGURATION is not implemented here")?;
    assert_eq!(kind_of(&error), UsbErrorKind::Stall);
    Ok(())
}

#[test]
fn a_short_control_in_truncates_rather_than_failing() -> Fallible {
    // The trait: a read "returns exactly what the device sent, which may be shorter
    // than `req.len`". A short GETSTATUS is what the host layer turns into
    // `Error::Protocol`, and it has to be able to see one.
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.inject(When::Class(request::GETSTATUS), Fault::Short { got: 3 });
    assert_eq!(class_in(&gadget, request::GETSTATUS, 0, 6)?.len(), 3);
    assert_eq!(class_in(&gadget, request::GETSTATUS, 0, 6)?.len(), 6);
    Ok(())
}

#[test]
fn faults_reach_the_non_transfer_calls_too() -> Fallible {
    // `Busy` on `SET_CONFIGURATION` is the one failure a claim
    // tolerates, and `AccessDenied` on a claim is the one a bus reset must never
    // bury.
    let gadget = FakeGadget::t32lq()
        .injecting(When::SetConfiguration, Fault::Busy)
        .injecting(When::Claim, Fault::AccessDenied)
        .injecting(When::Reset, Fault::NoDevice);

    let busy = block_on(gadget.set_configuration(1)).err().ok_or("armed")?;
    assert_eq!(kind_of(&busy), UsbErrorKind::Busy);
    let denied = block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))
        .err()
        .ok_or("armed")?;
    assert_eq!(kind_of(&denied), UsbErrorKind::AccessDenied);
    let gone = block_on(gadget.reset()).err().ok_or("armed")?;
    assert_eq!(kind_of(&gone), UsbErrorKind::NoDevice);
    assert_eq!(gadget.resets(), 0, "a refused reset did not happen");
    Ok(())
}

#[test]
fn every_call_is_recorded_in_order_even_when_it_failed() -> Fallible {
    let gadget = FakeGadget::t32lq();
    ready(&gadget, 0)?;
    gadget.forget_events();
    gadget.inject(When::Class(request::GETSTATUS), Fault::Timeout);
    class_out(&gadget, request::DNLOAD, 0, &[1; 4])?;
    drop(status(&gadget));
    status(&gadget)?;

    assert_eq!(
        gadget.class_requests(),
        [(request::DNLOAD, 0), (request::GETSTATUS, 0), (request::GETSTATUS, 0)],
        "the timed-out poll is in the log"
    );
    assert!(matches!(
        gadget.events().first(),
        Some(Event::ControlOut { len: 4, .. })
    ));
    Ok(())
}

// -------------------------------------------------------------------------------------
// The rest of the dispatch table: what each state serves besides the request that
// drives it. A host that polls twice, or reads `GETSTATE`, must not fall into dfuERROR.
// -------------------------------------------------------------------------------------

#[test]
fn getstate_is_served_in_every_state_that_has_a_case_for_it() -> Fallible {
    // `handle_getstate` appears in every state function but `state_dfu_dnbusy`
    // (`f_dfu.c:264-621`). It is the request a host uses when it wants the state without
    // disturbing anything, and a state that fell to the default for it would answer with
    // dfuERROR instead.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_manifest_hold_polls(1));
    let state = |expected: DfuState| -> Result<(), Box<dyn Error>> {
        assert_eq!(class_in(&gadget, request::GETSTATE, 0, 1)?, [expected.code()]);
        assert_eq!(gadget.dfu_state(), expected, "GETSTATE disturbed the state");
        Ok(())
    };

    ready(&gadget, 0)?;
    state(DfuState::DfuIdle)?;

    class_out(&gadget, request::DNLOAD, 0, &[0x11; 8])?;
    state(DfuState::DnloadSync)?;
    status(&gadget)?;
    state(DfuState::DnloadIdle)?;

    class_out(&gadget, request::DNLOAD, 1, &[])?;
    state(DfuState::ManifestSync)?;
    status(&gadget)?;
    state(DfuState::Manifest)?;
    status(&gadget)?;
    status(&gadget)?;
    state(DfuState::DfuIdle)?;

    gadget.preload(0, vec![0xFF; 64]);
    class_in(&gadget, request::UPLOAD, 0, 8)?;
    state(DfuState::UploadIdle)?;
    Ok(())
}

#[test]
fn a_second_poll_before_the_next_block_is_served() -> Fallible {
    // A host polls once per block, from dfuDNLOAD_SYNC — so `state_dfu_dnload_idle`'s
    // own `GETSTATUS` arm (`f_dfu.c:469-471`) is only reached by a host that polls
    // again, which the grace loop does after a forgiven failure. Without the
    // arm the extra poll would answer dfuERROR and the transfer would die on a
    // *recovery*.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8));
    ready(&gadget, 0)?;
    class_out(&gadget, request::DNLOAD, 0, &[0x11; 8])?;
    assert_eq!(status(&gadget)?.2, DfuState::DnloadIdle.code());
    assert_eq!(status(&gadget)?.2, DfuState::DnloadIdle.code(), "a second poll is fine");
    assert_eq!(status(&gadget)?.2, DfuState::DnloadIdle.code());
    send_block(&gadget, 1, &[0x22; 8])?;
    assert_eq!(gadget.dfu_status(), STATUS_OK);
    Ok(())
}

#[test]
fn abort_from_dfu_idle_is_a_plain_acknowledgement() -> Fallible {
    // `state_dfu_idle`'s ABORT arm (`f_dfu.c:366-370`) has no state to leave, so it just
    // abandons the entity's transaction and answers a ZLP. `make_idle` never sends one
    // here (it stops as soon as `GETSTATUS` says dfuIDLE), but the erase close-out
    // does: its second ABORT lands on an already-idle device.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8));
    ready(&gadget, 0)?;
    gadget.preload(0, vec![0xFF; 64]);
    class_in(&gadget, request::UPLOAD, 0, 8)?;
    class_out(&gadget, request::ABORT, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    assert_eq!(gadget.entity_sequence(0), Some(0));

    class_out(&gadget, request::ABORT, 0, &[])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle, "still idle, not dfuERROR");
    Ok(())
}

#[test]
fn a_stale_upload_stalls_and_the_refusal_heals_the_entity() -> Fallible {
    // The read half of the sequence check (`dfu.c:508-517`), which is **not** symmetric
    // with the write half: no error callback, and the failure reaches the host as a
    // stalled `UPLOAD` rather than as dfuERROR. The old-loader close-out
    // depends on exactly that — the refused re-probe is what heals the entity, at the
    // cost of one benign console line.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8).with_loader(Loader::Legacy));
    ready(&gadget, 0)?;
    gadget.preload(0, vec![0xAB; 64]);
    class_in(&gadget, request::UPLOAD, 0, 8)?;
    assert_eq!(gadget.entity_sequence(0), Some(1));
    assert_eq!(gadget.entity_inited(0), Some(true), "a transaction is open");

    // ABORT returns the state machine to dfuIDLE but leaves the old loader's entity at 1.
    class_out(&gadget, request::ABORT, 0, &[])?;
    assert_eq!(gadget.entity_sequence(0), Some(1));

    // dfuIDLE's UPLOAD arm forces block 0 (`f_dfu.c:360`), so the entity refuses it.
    let stalled = class_in(&gadget, request::UPLOAD, 0, 8)
        .err()
        .ok_or("a stale upload must stall")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    assert_eq!(gadget.wrong_sequence_refusals(), 1);
    assert_eq!(gadget.dfu_status(), STATUS_OK, "no error callback on the read path");

    // And the refusal healed it, so the re-probe works.
    assert_eq!(class_in(&gadget, request::UPLOAD, 0, 8)?, [0xAB; 8]);
    assert_eq!(gadget.wrong_sequence_refusals(), 1, "exactly one");

    // The two reads a mid-upload host may make, neither of which disturbs anything.
    assert_eq!(status(&gadget)?.2, DfuState::UploadIdle.code());
    assert_eq!(gadget.dfu_state(), DfuState::UploadIdle);
    Ok(())
}

#[test]
fn a_request_sent_in_the_wrong_direction_does_nothing_at_all() -> Fallible {
    // `f_dfu.c:346` and `:358` guard the `DNLOAD` and `UPLOAD` arms on the direction
    // bit, and a request whose inner `if` fails falls out with `value` still 0 — a bare
    // ZLP, no state change, no data touched. It is neither a stall nor an error, which
    // is the interesting part: three states have an arm that exists only to swallow it.
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_transfer_size(8));
    ready(&gadget, 0)?;
    gadget.preload(0, vec![0xAB; 64]);

    // dfuIDLE: a DNLOAD asked for as an IN transfer, and an UPLOAD as an OUT one.
    assert_eq!(class_in(&gadget, request::DNLOAD, 0, 8)?, Vec::<u8>::new());
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    class_out(&gadget, request::UPLOAD, 0, &[0x11; 8])?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    assert_eq!(gadget.entity_inited(0), Some(false), "no transaction was opened");

    // dfuDNLOAD_IDLE has the same swallow arm (`f_dfu.c:457-462`).
    send_block(&gadget, 0, &[0x11; 8])?;
    assert_eq!(gadget.dfu_state(), DfuState::DnloadIdle);
    assert_eq!(class_in(&gadget, request::DNLOAD, 1, 8)?, Vec::<u8>::new());
    assert_eq!(gadget.dfu_state(), DfuState::DnloadIdle, "and the block did not count");
    assert_eq!(gadget.entity_sequence(0), Some(1));

    // dfuUPLOAD_IDLE likewise (`f_dfu.c:563-570`).
    class_out(&gadget, request::ABORT, 0, &[])?;
    class_in(&gadget, request::UPLOAD, 0, 8)?;
    assert_eq!(gadget.dfu_state(), DfuState::UploadIdle);
    class_out(&gadget, request::UPLOAD, 1, &[0x22; 8])?;
    assert_eq!(gadget.dfu_state(), DfuState::UploadIdle);
    assert_eq!(gadget.entity_sequence(0), Some(1), "and the block did not count");
    Ok(())
}

#[test]
fn a_gadget_with_no_alts_answers_rather_than_falling_over() -> Fallible {
    // `dfu_get_entity` answers NULL for an alt that does not exist, and every caller but
    // `f_dfu_abort_transaction` dereferences it (`f_dfu.c:185`, `:244`, `:327-330`). A
    // loader whose `dfu_alt_info` produced no entity is a real failure mode — a bench
    // A1 prints `DFU entities configuration failed: -22` and comes up with none — so the
    // model must answer, not index out of bounds.
    let gadget = FakeGadget::new(GadgetConfig::new(Vec::new()));
    block_on(gadget.set_configuration(1))?;
    block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))?;

    let (bstatus, poll, state) = status(&gadget)?;
    assert_eq!((bstatus, poll, state), (STATUS_OK, 0, DfuState::DfuIdle.code()));
    assert_eq!(gadget.entity_sequence(0), None, "there is no alt 0");

    // Even alt 0 does not exist, so `SET_INTERFACE` is a request error (USB 9.4.10).
    let refused = block_on(gadget.set_alt_setting(0, 0))
        .err()
        .ok_or("there is no alternate setting to select")?;
    assert_eq!(kind_of(&refused), UsbErrorKind::Stall);

    // A download has no entity to reach, so it fails rather than writing nowhere.
    class_out(&gadget, request::DNLOAD, 0, &[0x11; 8])?;
    assert_eq!(status(&gadget)?.0, STATUS_ERR_UNKNOWN);
    let stalled = class_in(&gadget, request::UPLOAD, 0, 8)
        .err()
        .ok_or("an upload has no entity either")?;
    assert_eq!(kind_of(&stalled), UsbErrorKind::Stall);
    Ok(())
}

#[test]
fn a_block_bigger_than_the_transfer_size_is_truncated_not_accepted_whole() -> Fallible {
    // `cdev->req->buf` is `USB_BUFSIZ` bytes (`composite.c:17`, `:1396`), so there is
    // nowhere for a longer block to go, and a host must not try: a 32 KiB
    // loader was built and its first `DNLOAD` failed. The point of pinning it is that
    // the shortfall is *visible* on the medium rather than silently accepted.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![AltConfig::flash("flash", 64)])
            .with_transfer_size(8)
            .with_buffer_size(8),
    );
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 32])?;
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 8);
    assert_eq!(gadget.entity_offset(0), Some(8));
    Ok(())
}

#[test]
fn writing_past_the_declared_medium_is_refused() -> Fallible {
    // `dfu_sf`/`dfu_mtd` write into the range `dfu_alt_info` gave the entity; past its
    // end there is nothing to write to. The boundary is inclusive — a block that ends
    // exactly at the last byte is fine.
    let gadget = FakeGadget::new(
        GadgetConfig::new(vec![AltConfig::flash("flash", 16)])
            .with_transfer_size(8)
            .with_buffer_size(8),
    );
    ready(&gadget, 0)?;
    send_block(&gadget, 0, &[0x11; 8])?;
    send_block(&gadget, 1, &[0x22; 8])?;
    assert_eq!(gadget.dfu_status(), STATUS_OK, "the last block ends exactly at the end");
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 16);

    send_block(&gadget, 2, &[0x33; 8])?;
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!((bstatus, state), (STATUS_ERR_UNKNOWN, DfuState::Error.code()));
    assert_eq!(gadget.medium(0).ok_or("alt 0")?.len(), 16, "and nothing grew");
    Ok(())
}

#[test]
fn a_nonzero_default_poll_timeout_paces_every_buffer_boundary() -> Fallible {
    // `f_dfu.c:204-207`: when `f_dfu->poll_timeout` is set, the reply carries it on
    // every block that is a multiple of `dfu_get_buf_size() / DFU_USB_BUFSIZ` — the
    // blocks a buffer drain is about to happen on. `DFU_DEFAULT_POLL_TIMEOUT` is 0 on
    // every shipped loader (`include/dfu.h:121-122`) so the branch is dead there, and it
    // is modelled because the divide-by-zero landmine lives in this expression.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(8)
            .with_buffer_size(32)
            .with_default_poll_timeout_ms(750),
    );
    ready(&gadget, 0)?;
    // 32 / 8 = 4 blocks to a buffer.
    for block in 0..6u16 {
        class_out(&gadget, request::DNLOAD, block, &[0x11; 8])?;
        let (_, poll, _) = status(&gadget)?;
        let boundary = block % 4 == 0;
        assert_eq!(poll, if boundary { 750 } else { 0 }, "block {block}");
    }
    Ok(())
}

// -------------------------------------------------------------------------------------
// Values a mutant could quietly change
// -------------------------------------------------------------------------------------

#[test]
fn the_state_codes_are_the_numbers_dfu_1_1_assigns() {
    // `enum dfu_state` (`f_dfu.h:55-66`) is also the dispatch table's index
    // (`f_dfu.c:623-635`) and the `bState` byte a host parses, so these are wire values,
    // not an internal ordering.
    assert_eq!(DfuState::AppIdle.code(), 0);
    assert_eq!(DfuState::AppDetach.code(), 1);
    assert_eq!(DfuState::DfuIdle.code(), 2);
    assert_eq!(DfuState::DnloadSync.code(), 3);
    assert_eq!(DfuState::DnBusy.code(), 4);
    assert_eq!(DfuState::DnloadIdle.code(), 5);
    assert_eq!(DfuState::ManifestSync.code(), 6);
    assert_eq!(DfuState::Manifest.code(), 7);
    assert_eq!(DfuState::ManifestWaitReset.code(), 8);
    assert_eq!(DfuState::UploadIdle.code(), 9);
    assert_eq!(DfuState::Error.code(), 10);
}

#[test]
fn t32lq_is_the_bench_gadget() {
    let config = GadgetConfig::t32lq();
    assert_eq!(config.alts.len(), 3);
    // Spelled out rather than compared against the constant, which would assert nothing.
    assert_eq!(T32LQ_FLASH_SIZE, 16_777_216, "16 MiB of SPI-NOR");
    assert_eq!(super::DEFAULT_TRANSFER_SIZE, 4096);
    assert_eq!(super::DEFAULT_USB_BUFSIZ, 4096, "composite.c:17");
    assert_eq!(super::DEFAULT_BUFFER_SIZE, 2_097_152);
    assert_eq!(super::VIRT_POLL_TIMEOUT_MS, 500);
    assert_eq!(config.alts[0], AltConfig::flash("flash", T32LQ_FLASH_SIZE));
    assert_eq!(config.alts[1], AltConfig::erase());
    assert_eq!(config.alts[2], AltConfig::reboot());
    assert_eq!(config.loader, Loader::Fixed);
    assert_eq!(ERASE_TOKEN.len(), 17);
    assert_eq!(REBOOT_TOKEN.len(), 13);
}

#[test]
fn a_failed_virt_transaction_disarms_every_virt_alt() -> Fallible {
    // `dfu_error_callback` (`arch/mips/mach-xburst/dfu.c:290-296`) is keyed on the
    // failing entity's `dev_type` and then clears **both** module-level flags
    // (`:119`, `:124`). So a bad token on `erase` drops a `reboot` the host has already
    // armed — a device behaviour a per-entity model cannot express at all, and the one
    // that makes an unarmed flush reachable (see the pin below).
    let gadget = FakeGadget::new(GadgetConfig::t32lq().with_manifest_hold_polls(0));

    // Arm the reboot and stop before the poll that would run its flush.
    ready(&gadget, 2)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?; // poll between the token and the ZLP
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    assert_eq!(gadget.entity_armed(2), Some(true), "the reboot never armed");

    // A transaction on the *erase* alt that `dfu_write` refuses. A stale block number
    // needs no ZLP: `dfu.c:384-390` cleans up and calls the error callback on the spot.
    block_on(gadget.set_alt_setting(0, 1))?;
    class_out(&gadget, request::DNLOAD, 9, &[0xEE])?;

    assert_eq!(gadget.wrong_sequence_refusals(), 1);
    assert_eq!(gadget.dfu_state(), DfuState::Error);
    assert_eq!(
        gadget.entity_armed(2),
        Some(false),
        "the erase's failure left the reboot armed: the callback is global on the device"
    );
    assert_eq!(gadget.entity_armed(1), Some(false));
    assert_eq!(gadget.reboots(), 0, "nothing should have rebooted yet");
    Ok(())
}

#[test]
fn an_owed_flush_outlives_dfumanifest_and_runs_having_nothing_to_do() -> Fallible {
    // The `success having done nothing` branch of a virt entity's `flush_medium`
    // (`arch/mips/mach-xburst/dfu.c:238-239`, `:262-263`), reached the way the device
    // reaches it. Three device facts have to hold together, and each is one line of
    // U-Boot:
    //
    // 1. `dfu_set_defer_flush` is the **main loop's** (`common/dfu.c:70-88`), and
    //    `dfu_set_alt` clears the DFU state without clearing it (`f_dfu.c:823-841`).
    // 2. `common/dfu.c:81` pumps the UDC's interrupts one line *before* `dfu_flush`, so
    //    requests the host already sent are serviced first.
    // 3. `dfu_error_callback` drops **both** armings for any failing virt entity
    //    (`:290-296`).
    //
    // Together: arm the reboot, walk out of dfuMANIFEST, fail a transaction on `erase`,
    // and the flush the loop still owes runs with nothing armed — `Ok`, no reset, and a
    // `bStatus` of OK that says nothing about it. The blank check exists
    // because the DFU status cannot tell this apart from a wipe that happened.
    // A legacy loader, so `SET_INTERFACE` does not clean the entity on the way past
    // on this generation — which is what leaves the flush's own `dfu_transaction_cleanup`
    // (`dfu.c:350-370`) as the *observable* evidence that the flush ran at all.
    let gadget = FakeGadget::new(
        GadgetConfig::t32lq()
            .with_manifest_hold_polls(2)
            .with_loader(Loader::Legacy),
    );

    ready(&gadget, 2)?;
    class_out(&gadget, request::DNLOAD, 0, REBOOT_TOKEN)?;
    status(&gadget)?;
    class_out(&gadget, request::DNLOAD, 1, &[])?;
    // The poll that moves to dfuMANIFEST and hands the flush to the main loop.
    assert_eq!(status(&gadget)?.2, DfuState::Manifest.code());
    assert_eq!(gadget.entity_armed(2), Some(true));
    assert_eq!(gadget.entity_inited(2), Some(true), "the transaction is still open");

    // Out of dfuMANIFEST (`SET_INTERFACE` is the only way, `f_dfu.c:837`) and into a
    // transaction the erase entity refuses.
    block_on(gadget.set_alt_setting(0, 1))?;
    assert_eq!(gadget.dfu_state(), DfuState::DfuIdle);
    class_out(&gadget, request::DNLOAD, 9, &[0xEE])?;
    assert_eq!(gadget.entity_armed(2), Some(false), "the global disarm");
    class_out(&gadget, request::CLRSTATUS, 0, &[])?;
    block_on(gadget.set_alt_setting(0, 2))?;

    // The loop's turn. The flush is still owed, and it now has nothing to do.
    let (bstatus, _, state) = status(&gadget)?;
    assert_eq!(
        (bstatus, state),
        (STATUS_OK, DfuState::DfuIdle.code()),
        "an unarmed flush reports success"
    );
    assert_eq!(
        gadget.entity_inited(2),
        Some(false),
        "the owed flush never ran: only `dfu_flush` cleans the transaction here"
    );
    assert_eq!(gadget.entity_offset(2), Some(0));
    assert_eq!(gadget.reboots(), 0, "the disarmed reboot ran anyway");
    assert!(!gadget.is_gone(), "the device left the bus");
    assert_eq!(gadget.erases(), 0);
    Ok(())
}

#[test]
fn gadget_second_claim_releases_the_first_the_way_the_backend_does() -> Fallible {
    // `NativeTransport::claim_interface` calls `release_any()` first, so the bus sees
    // claim, release, claim. A double that overwrote the claim let a test pin the
    // sequence without the release and still call it a match.
    let gadget = FakeGadget::new(GadgetConfig::t32lq());
    ready(&gadget, 0)?;

    block_on(gadget.claim_interface(InterfaceSpec::control_only(0)))?;

    let claims: Vec<Event> = gadget
        .events()
        .into_iter()
        .filter(|event| matches!(*event, Event::ClaimInterface(_) | Event::ReleaseInterface(_)))
        .collect();
    assert_eq!(
        claims,
        vec![
            Event::ClaimInterface(InterfaceSpec::control_only(0)),
            Event::ReleaseInterface(0),
            Event::ClaimInterface(InterfaceSpec::control_only(0)),
        ]
    );
    Ok(())
}
