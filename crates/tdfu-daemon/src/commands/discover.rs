//! `CMD_DISCOVER 0x01` — the device list.
//!
//! No request payload. The OK payload is N × 8 bytes:
//! `[bus u8][addr u8][vendor u16 BE][product u16 BE][stage u8][variant u8]`, with no
//! count prefix — the client divides by 8. Verified against
//! `libtdfu/include/tdfu/protocol.h:69-76` (the packed struct), `dfu-remote/main.c:244`
//! (`resp_len = count * sizeof(entry)`) and `main.c:252-258` (the `tdfu_htons` calls
//! that make the two `u16`s big-endian and leave the four `u8`s raw).
//!
//! # An unknown variant is reported as unknown
//!
//! This is the one place an earlier implementation and the C both reported a guess as a
//! fact. The C
//! initialises **every** enumerated device to ordinal 6, `t31x`
//! (`libtdfu/src/usb/manager.c:138` and `:227`, `dfu-remote/main.c:264`,
//! `libtdfu/src/utils.c:241-242`), so a DFU gadget it has never seen in the bootrom is
//! reported as a T31X, and the shipped CLI then renders that name and will send it back
//! as a `--cpu` value, which is how the wrong loader gets picked.
//! Here a variant that is not known is
//! [`WireVariant::UNKNOWN`] (`0xFF`), which is outside the frozen 59-entry table and
//! renders as `unknown` in every client, and which no client can send back because it
//! has no name.
//!
//! # Detection executes nothing
//!
//! For a bootrom device this runs [`ops::detect`], which is three register reads at
//! kseg1 addresses and **no code upload**. The C uploads a 606-byte
//! hand-assembled MIPS stub through `PROG_STAGE1` to answer the same question, spending
//! the mask ROM's one-shot. An audit called not doing that the single biggest
//! improvement over the C, and required it to survive the rewrite.

use tdfu_core::clock::Sleeper;
use tdfu_core::model::{Detection, Stage, Variant};
use tdfu_core::ops;
use tdfu_proto::{DeviceEntry, WireVariant};
use tdfu_usb::LocalUsbBackend;

use super::Reply;
use super::state::{DaemonState, Identity, Port, Row};
use crate::errors::DaemonError;

/// The `stage` byte.
///
/// `TDFU_STAGE_BOOTROM = 0`, `TDFU_STAGE_FIRMWARE = 1`, `TDFU_STAGE_DFU = 2`
/// (`libtdfu/include/tdfu/tdfu.h:132`). `protocol.h:74`'s comment says only
/// `0=bootrom, 1=firmware`, which is incomplete — the C branches on 2 at
/// `dfu-remote/main.c:272`.
///
/// A device the descriptors **cannot** classify is reported as `1`, never `0`. The
/// re-PID means the gadget and the bootrom share `a108:c309`, so "unknown"
/// there is genuinely unknown, and stage 0 is the one value a client acts on by
/// uploading a stage-1 image in an auto-bootstrap. That is an audit's finding
/// with its frontend half applied to the wire: render an unclassifiable
/// device as something, never as bootstrap-eligible.
const fn stage_byte(stage: Option<Stage>) -> u8 {
    match stage {
        Some(Stage::Bootrom) => 0,
        Some(Stage::Gadget) => 2,
        // `Stage` is `#[non_exhaustive]`; firmware and "cannot tell" share the one
        // value that means "not actionable".
        _ => 1,
    }
}

/// A core [`Variant`] as its frozen wire ordinal.
///
/// [`Variant::loader_dir`] is the name and [`WireVariant::from_name`] is the table; a
/// name that is not in it cannot be put on the wire as an ordinal, so it is
/// [`WireVariant::UNKNOWN`]. All 34 core variants are in the 59-entry table, pinned by
/// `every_core_variant_has_a_wire_ordinal`.
fn wire_variant(variant: Variant) -> WireVariant {
    WireVariant::from_name(variant.loader_dir()).unwrap_or(WireVariant::UNKNOWN)
}

/// Build the device list.
///
/// # Errors
/// Never a [`DaemonError`]: a bus that cannot be enumerated is a `RESP_ERROR` frame,
/// not a dead connection. The signature matches the other handlers so the dispatcher
/// reads uniformly.
pub async fn handle<B, C>(state: &mut DaemonState<B, C>) -> Result<Reply, DaemonError>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    let listing = match state.backend.list().await {
        Ok(listing) => listing,
        Err(error) => {
            return Ok(Reply::Error(crate::errors::wire_message(&error.into())));
        }
    };

    let mut payload = Vec::with_capacity(listing.len() * DeviceEntry::LEN);
    let mut rows = Vec::with_capacity(listing.len());
    for device in &listing {
        let descriptors = &device.descriptors;
        let kind = ops::classify(descriptors);
        rows.push(Row::of(descriptors, kind));
        let port = Port::of(descriptors);
        let identity = Identity::of(descriptors);
        let variant = match kind {
            Some(Stage::Bootrom) => detect(state, &device.id, &port, identity).await,
            // A gadget is past the bootrom and cannot be re-probed for its SoC, so the
            // only honest answer is what was detected on **this** device on this bus and
            // port before it was bootstrapped, or nothing.
            Some(Stage::Gadget) => state.variants.get(&port, identity, true),
            _ => None,
        };
        let entry = DeviceEntry {
            bus: descriptors.bus,
            address: descriptors.address,
            vendor: descriptors.vendor_id,
            product: descriptors.product_id,
            stage: stage_byte(kind),
            variant: variant.map_or(WireVariant::UNKNOWN, wire_variant),
        };
        payload.extend_from_slice(&entry.encode());
    }
    // The listing the client is about to index into. Every later `idx` is a position in
    // **this** answer, so it is kept: without it the daemon would resolve an index
    // against a bus that has moved on since, which is a different device.
    state.remember_listing(rows);
    tracing::debug!(devices = listing.len(), "discover");
    Ok(Reply::Ok(payload))
}

/// Detect the SoC of a bootrom device and remember it for its port.
///
/// Every failure — the open, the reads, an ambiguous grade, a `cpu_id` that is not in
/// the table — answers `None`, and `None` becomes `0xFF` on the wire. There is
/// deliberately no fallback: a T4x whose grade is shared between the T40 and T41 lines
/// resolves to nothing on purpose (decision D4), and inventing a variant
/// for it is the DDR3-loader-on-a-DDR2-part mistake arrived at from the other direction.
async fn detect<B, C>(
    state: &mut DaemonState<B, C>,
    id: &B::DeviceId,
    port: &Port,
    identity: Identity,
) -> Option<Variant>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    let device = match state.backend.open(id).await {
        Ok(device) => device,
        Err(error) => {
            tracing::debug!(%error, "a bootrom device could not be opened for detection");
            return None;
        }
    };
    match ops::detect(&device, &state.clock).await {
        Ok(Detection::Resolved(resolved)) => {
            // Measured on this device, so it is remembered against this device: a
            // bootrom that is still here answers from the entry, and anything else at
            // the port does not.
            state.variants.put(port, identity, false, resolved.variant);
            Some(resolved.variant)
        }
        Ok(unresolved) => {
            tracing::debug!(detection = ?unresolved, "detection did not settle on a variant");
            None
        }
        Err(error) => {
            tracing::debug!(%error, "detection failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{stage_byte, wire_variant};
    use crate::commands::Reply;
    use crate::commands::fake::dispatch;
    use crate::commands::fake::{FakeBackend, LoopbackConn, Sent, TestResult, t23_regs};
    use crate::commands::state::{DaemonState, Identity, Port};
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::model::{Stage, Variant};
    use tdfu_proto::{Command, DeviceEntry, Status, WireVariant};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware")
    }

    /// The byte layout, exactly: 8 bytes per device, the two `u16`s
    /// big-endian, no count prefix (`protocol.h:69-76`, `dfu-remote/main.c:252-258`).
    #[test]
    fn rpc_discover_layout() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;

        let sent = conn.sent();
        let [Sent::Response(status, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        assert_eq!(*status, Status::Ok);
        assert_eq!(payload.len(), DeviceEntry::LEN);
        assert_eq!(
            payload.as_slice(),
            // bus 1, addr 9, a108 BE, c309 BE, stage 2 (gadget), variant 0xFF.
            &[0x01, 0x09, 0xA1, 0x08, 0xC3, 0x09, 0x02, 0xFF]
        );
        Ok(())
    }

    /// A gadget this daemon has never seen in the
    /// bootrom is `0xFF`, **not** the C's ordinal 6.
    #[test]
    fn rpc_an_unknown_gadget_is_not_ordinal_six() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        let sent = conn.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].variant, WireVariant::UNKNOWN);
        assert_eq!(entries[0].variant.0, 0xFF);
        assert_ne!(entries[0].variant.0, 6, "the C's t31x pre-seed");
        // And it has no name, so no client can send it back as a `--cpu` value.
        assert_eq!(entries[0].variant.name(), None);
        assert_eq!(WireVariant(6).name(), Some("t31x"), "which is what 6 would have meant");
        Ok(())
    }

    /// A bootrom is detected, reported, and remembered for its port — and the gadget
    /// that replaces it on that port reports the remembered SoC.
    #[test]
    fn fe_daemon_vcache_reports_the_bootrom_soc_for_the_gadget() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t23_regs())]);
        let mut state = daemon(backend);

        let mut first = LoopbackConn::raw();
        block_on(dispatch(&mut first, &mut state, Command::Discover, &[]))?;
        let sent = first.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].stage, 0, "a bootrom is stage 0");
        assert_eq!(
            entries[0].variant,
            wire_variant(Variant::T23n),
            "detection ran and reported the real SoC"
        );

        // A device that this daemon **bootstrapped** is expected back as a gadget with a
        // new device number, and that is the one change of identity at a port the entry
        // survives. The bootstrap records it; here the same record is made directly, so
        // this test stays about `DISCOVER`.
        let port = Port {
            bus: 1,
            path: vec![4, 2],
        };
        state.variants.put(
            &port,
            Identity {
                address: 7,
                vendor: tdfu_usb::vid::INGENIC,
                product: tdfu_usb::pid::BOOTROM,
            },
            true,
            Variant::T23n,
        );
        state.backend.replace_with_gadget_on_the_same_port(0);
        let mut second = LoopbackConn::raw();
        block_on(dispatch(&mut second, &mut state, Command::Discover, &[]))?;
        let sent = second.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].stage, 2, "a gadget is stage 2");
        assert_eq!(
            entries[0].variant,
            wire_variant(Variant::T23n),
            "and it reports what was on this port before the bootstrap"
        );
        Ok(())
    }

    /// **A gadget nobody bootstrapped here is unknown, even on a remembered port.** A
    /// camera swapped for another at the same port has a different device number, and
    /// answering the first one's SoC for the second is the guess-as-fact the device list
    /// exists to remove.
    #[test]
    fn a_swapped_device_on_a_remembered_port_is_unknown() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t23_regs())]);
        let mut state = daemon(backend);
        let mut first = LoopbackConn::raw();
        block_on(dispatch(&mut first, &mut state, Command::Discover, &[]))?;

        // Nothing bootstrapped it: a different device is simply on that port now.
        state.backend.replace_with_gadget_on_the_same_port(0);
        let mut second = LoopbackConn::raw();
        block_on(dispatch(&mut second, &mut state, Command::Discover, &[]))?;
        let sent = second.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].stage, 2);
        assert_eq!(entries[0].variant, WireVariant::UNKNOWN);
        Ok(())
    }

    /// **The same port number on another bus is another camera.** The detection made on
    /// bus 1 is not answered for the gadget on bus 2, which is a different device on a
    /// mirrored hub.
    #[test]
    fn a_gadget_on_the_same_port_of_another_bus_is_unknown() -> TestResult {
        let backend = FakeBackend::new(vec![
            FakeBackend::bootrom_at_port(1, 7, vec![4, 2], t23_regs()),
            FakeBackend::gadget_at_port(2, 7, vec![4, 2]),
        ]);
        let mut state = daemon(backend);
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        let sent = conn.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].variant, wire_variant(Variant::T23n), "the bus-1 bootrom");
        assert_eq!(
            entries[1].variant,
            WireVariant::UNKNOWN,
            "the same port numbers on bus 2 are another device"
        );
        Ok(())
    }

    /// A gadget on a *different* port than the remembered one is still unknown — the
    /// cache is keyed by the physical port, not by "some bootrom was here once".
    #[test]
    fn a_gadget_on_another_port_is_still_unknown() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t23_regs()), FakeBackend::gadget()]);
        let mut state = daemon(backend);
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        let sent = conn.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].variant, wire_variant(Variant::T23n));
        assert_eq!(entries[1].variant, WireVariant::UNKNOWN, "a different port path");
        Ok(())
    }

    /// A bootrom whose detection does not settle is `0xFF` too. There is no fallback
    /// variant, deliberately: inventing one is how a DDR3 loader reaches a DDR2 part.
    #[test]
    fn a_bootrom_that_will_not_detect_is_unknown_not_guessed() -> TestResult {
        // `soc_id` 0x0000_0099 is in no decode table.
        let backend = FakeBackend::new(vec![FakeBackend::bootrom([0x0000_0099, 0, 0])]);
        let mut state = daemon(backend);
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        let sent = conn.sent();
        let [Sent::Response(_, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        let entries = DeviceEntry::decode_list(payload)?;
        assert_eq!(entries[0].stage, 0);
        assert_eq!(entries[0].variant, WireVariant::UNKNOWN);
        Ok(())
    }

    /// An empty bus is a zero-length OK payload, not an error (`dfu-remote/main.c:244`
    /// with `count == 0`).
    #[test]
    fn an_empty_bus_is_an_empty_ok_payload() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::empty());
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        assert_eq!(conn.sent(), vec![Sent::Response(Status::Ok, Vec::new())]);
        Ok(())
    }

    /// `DISCOVER` attaches no log client on raw TCP, so detection's
    /// diagnostics do not leak into the reply stream.
    #[test]
    fn discover_emits_no_log_frames_on_raw_tcp() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::bootrom(t23_regs())]));
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        assert!(
            conn.sent().iter().all(|frame| matches!(frame, Sent::Response(..))),
            "{:?}",
            conn.sent()
        );
        Ok(())
    }

    /// The same finding on the wire: a device the descriptors cannot classify is never
    /// stage 0, because stage 0 is the value a client auto-bootstraps.
    #[test]
    fn an_unclassifiable_device_is_never_stage_zero() {
        assert_eq!(stage_byte(Some(Stage::Bootrom)), 0);
        assert_eq!(stage_byte(Some(Stage::Firmware)), 1);
        assert_eq!(stage_byte(Some(Stage::Gadget)), 2);
        assert_eq!(stage_byte(None), 1, "unknown must not read as bootstrap-eligible");
    }

    /// Every variant this tool can choose has an ordinal in the frozen
    /// 59-entry table, so `wire_variant` never has to fall back.
    #[test]
    fn every_core_variant_has_a_wire_ordinal() {
        for variant in Variant::ALL {
            let ordinal = wire_variant(variant);
            assert_ne!(
                ordinal,
                WireVariant::UNKNOWN,
                "{} has no ordinal in the frozen table",
                variant.loader_dir()
            );
            assert_eq!(ordinal.name(), Some(variant.loader_dir()), "{variant:?} round-trips");
        }
    }

    /// The handler answers a bus failure with a frame rather than dropping the
    /// connection: a `RESP_ERROR` is a command failure, and the session continues.
    #[test]
    fn a_bus_that_cannot_be_listed_is_a_response_not_a_disconnect() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::empty().listing_fails());
        block_on(dispatch(&mut conn, &mut state, Command::Discover, &[]))?;
        let sent = conn.sent();
        let [Sent::Response(status, payload)] = sent.as_slice() else {
            return Err("one response frame".into());
        };
        assert_eq!(*status, Status::Error);
        assert!(
            String::from_utf8_lossy(payload).contains("access denied"),
            "{payload:?}"
        );
        Ok(())
    }

    /// `Reply::Ok` is what this handler produces — never `Bulk`, which is `READ`'s
    /// exemption from the payload cap alone.
    #[test]
    fn discover_is_capped_like_every_other_reply() -> TestResult {
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        let reply = block_on(super::handle(&mut state))?;
        assert!(matches!(reply, Reply::Ok(_)), "{reply:?}");
        Ok(())
    }
}
