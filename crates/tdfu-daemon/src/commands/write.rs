//! `CMD_WRITE 0x03` — download, verify, and the whole-chip erase.
//!
//! Request: `[idx][vlen u8][variant][alen u8][alt][fw_len u32 BE][fw][crc32 u32 BE]`
//! and an **optional** trailing `[verify u8]`. Read at `dfu-remote/main.c:453-493`:
//! `:472` makes the alt field mandatory (the string is at `:473`), `:483` reads the
//! big-endian firmware length, `:485` tests `p + fw_len + 4 > end` so a payload that
//! stops between the image and its CRC is `"firmware data truncated"` (`:486`), and
//! `:493` reads the verify byte only `if (p < end)`. OK payload is `"OK"` (`:597`).
//!
//! # The erase is a write
//!
//! There is no erase command on the wire. A `CMD_WRITE` whose alt is `erase` and whose
//! payload is the 17-byte `XBURST-FLASH-WIPE` token **is** the whole-chip erase, and it
//! routes to [`ops::erase`] — the grace-and-blank-check path — rather than to a generic
//! download, which could report success for a token the loader refused. The C's own
//! comment says exactly that at `dfu-remote/main.c:500-505`, and the branch is
//! `strcmp(alt_str, "erase") == 0 && fw_len == strlen(TOKEN) && memcmp(...) == 0` at
//! `:506-507`.
//!
//! **Both halves are compared whole here.** The C copies the alt into a 32-byte buffer
//! and `strcmp`s it, so `"erase\0junk"` wipes a chip for it; an earlier implementation
//! reproduced that and thereby *widened* the set of payloads that erase a flash.
//! [`Request::is_erase`](tdfu_proto::Request::is_erase) compares the bytes.
//!
//! # The CRC is checked before the routing
//!
//! `dfu-remote/main.c:496` runs the CRC check at `:495-498`, **above** the erase branch
//! at `:506`, so the token's own CRC is checked too. Same order here: a corrupted
//! payload is refused whichever path it was heading for.
//!
//! # Verify has its own wire string
//!
//! A verify failure is `verify failed at offset 0x%08llX` — uppercase,
//! zero-padded — with **no** `write failed:` prefix. `main.c:588-595` is the `if
//! (result == TDFU_ERROR_VERIFY)` that does it, and the offset is the one the operation
//! reported. `tdfu_proto::verify_failed_message` is the single producer of that text;
//! `tdfu_core::Error::Verify`'s own `Display` is the *local* wording and must not reach
//! the wire.
//!
//! # A streamed write checks its CRC last
//!
//! A daemon that cannot hold the image ([`streamed`]) writes it as it arrives, and the
//! CRC, which follows the image on the wire, can then only be checked once the flash
//! already holds it. A mismatch is still refused, and says what state it left. Its
//! verify has no image to compare with either, so it compares CRCs, and a mismatch has
//! no offset to report: `verify failed: ...` keeps the prefix and says why.

use tdfu_core::clock::Sleeper;
use tdfu_core::model::AltSel;
use tdfu_core::stream::{AsyncSink, AsyncSource};
use tdfu_core::{Error, ops};
use tdfu_proto::{Command, Crc32, Request, crc32, verify_failed_message};
use tdfu_usb::LocalUsbBackend;

use super::device::{Target, await_gadget};
use super::fields::{Fields, Refusal};
use super::report::{Intake, Io, Queue, pump, pump_with};
use super::state::{Activity, DaemonState};
use super::{Reply, Wire, parse_alt, run_whole, variant_field};
use crate::errors::{DaemonError, wire_message};

/// The CRC refusal (`dfu-remote/main.c:498`).
const CRC_MISMATCH: &str = "firmware CRC32 mismatch";

/// Download `image` to `alt`, then verify it if the byte said so.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn handle<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    request: &Request,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    let Request::Write {
        index,
        variant,
        alt,
        image,
        crc32: expected,
        verify,
    } = request
    else {
        return Ok(Reply::Error("unknown command".to_owned()));
    };

    if crc32(image) != *expected {
        return Ok(Reply::Error(CRC_MISMATCH.to_owned()));
    }
    let (alt, _variant) = match parse_fields(variant, alt) {
        Ok(fields) => fields,
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };

    state.arm();
    let busy = state.busy(Activity::Writing);

    let target = match state.row(*index) {
        Ok(row) => Target::of_row(*index, row),
        Err(error) => return Ok(Reply::failed("write", &error)),
    };
    // The queue is opened before the wait so the probe's recovery note (a wedged gadget a
    // USB reset cleared) has somewhere to go; `pump` flushes it before the download's frames.
    let queue = Queue::new();
    let mut sink = queue.sink();
    let gadget = match await_gadget(
        &state.backend,
        &state.clock,
        state.window,
        &target,
        Some(&alt),
        &mut sink,
    )
    .await
    {
        Ok(gadget) => gadget,
        Err(failure) => return Ok(Reply::failed("write", &failure.into_error())),
    };

    let written = pump(
        conn,
        Command::Write,
        &queue,
        ops::write(&gadget.device, &state.clock, &alt, image, &mut sink),
    )
    .await?;
    if let Err(error) = written {
        return Ok(failure_reply(&error));
    }

    // The optional trailing byte. `Option<bool>` keeps "absent" and "present
    // and zero" apart, which the C collapses. An audit kept this on merit.
    if *verify == Some(true) {
        // The C moves `g_state` from `"writing"` to `"verifying"` in place
        // (`dfu-remote/main.c:578`); going through `idle` between the two halves of one
        // operation would let a `CMD_STATUS` see an idle daemon mid-write.
        busy.switch(Activity::Verifying);
        let queue = Queue::new();
        let verified = {
            let mut sink = queue.sink();
            pump(
                conn,
                Command::Write,
                &queue,
                ops::verify(&gadget.device, &state.clock, &alt, image, &mut sink),
            )
            .await?
        };
        if let Err(error) = verified {
            return Ok(failure_reply(&error));
        }
    }
    Ok(Reply::ok())
}

/// The wipe-token write, routed to the real erase.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn erase<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    request: &Request,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    let Request::Write {
        index,
        variant,
        image,
        crc32: expected,
        ..
    } = request
    else {
        return Ok(Reply::Error("unknown command".to_owned()));
    };

    // Above the routing, as `dfu-remote/main.c:496` is above `:506`.
    if crc32(image) != *expected {
        return Ok(Reply::Error(CRC_MISMATCH.to_owned()));
    }
    if let Err(error) = variant_field(Command::Write, variant) {
        return Ok(Reply::Error(wire_message(&error)));
    }

    state.arm();
    let _busy = state.busy(Activity::Erasing);

    let target = match state.row(*index) {
        Ok(row) => Target::of_row(*index, row),
        Err(error) => return Ok(Reply::failed("erase", &error)),
    };
    // No alt selector: the C passes `NULL` here (`dfu-remote/main.c:519`) and discards
    // the returned alt, because `tdfu_dfu_erase` resolves the `erase` alt itself — and
    // so does `ops::erase`. Asking the window to resolve `erase` as well would refuse a
    // loader whose `erase` alt is missing with the wrong error class.
    // The queue is opened before the wait so the probe's recovery note (a wedged gadget a
    // USB reset cleared) has somewhere to go; `pump` flushes it before the erase's frames.
    let queue = Queue::new();
    let mut sink = queue.sink();
    let gadget = match await_gadget(&state.backend, &state.clock, state.window, &target, None, &mut sink).await {
        Ok(gadget) => gadget,
        Err(failure) => return Ok(Reply::failed("erase", &failure.into_error())),
    };

    let outcome = pump(
        conn,
        Command::Write,
        &queue,
        ops::erase(&gadget.device, &state.clock, &mut sink),
    )
    .await?;
    match outcome {
        Ok(()) => Ok(Reply::ok()),
        Err(error) => Ok(Reply::failed("erase", &error)),
    }
}

/// A streamed `WRITE`: the image goes from the socket to the device as it arrives.
///
/// The fields are read with [`Request::decode`]'s checks ([`Fields`]), and every length
/// is checked against the payload before the device is touched, as decoding a whole
/// payload first does. An image small enough to hold after all, at most
/// [`DaemonState::stream_above`], is read whole and takes [`handle`]'s path, the CRC
/// ahead of the flash; that is where the erase token goes too.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn streamed<W, B, C>(conn: &mut W, state: &mut DaemonState<B, C>, len: u64) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    let (head, fields) = match Head::read(conn, len).await {
        Ok(read) => read,
        Err(Refusal::Payload(message)) => return Ok(Reply::Error(message.to_owned())),
        Err(Refusal::Conn(error)) => return Err(error),
    };
    if state.stream_above.is_none_or(|limit| head.image_len <= limit) {
        return run_whole(conn, state, Command::Write, fields.into_read()).await;
    }
    let (alt, _variant) = match parse_fields(&head.variant, &head.alt) {
        Ok(fields) => fields,
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };

    state.arm();
    let busy = state.busy(Activity::Writing);

    let target = match state.row(head.index) {
        Ok(row) => Target::of_row(head.index, row),
        Err(error) => return Ok(Reply::failed("write", &error)),
    };
    let queue = Queue::new();
    let mut sink = queue.sink();
    let gadget = match await_gadget(
        &state.backend,
        &state.clock,
        state.window,
        &target,
        Some(&alt),
        &mut sink,
    )
    .await
    {
        Ok(gadget) => gadget,
        Err(failure) => return Ok(Reply::failed("write", &failure.into_error())),
    };

    let image_len = u64::from(head.image_len);
    let intake = Intake::new();
    let mut crc = Crc32::new();
    let written = {
        let mut source = Crc32Source {
            inner: intake.source(),
            crc: &mut crc,
        };
        let io = Io {
            intake: Some(&intake),
            outbox: None,
        };
        pump_with(
            conn,
            Command::Write,
            &queue,
            io,
            ops::write_from(&gadget.device, &state.clock, &alt, image_len, &mut source, &mut sink),
        )
        .await?
    };
    if let Err(error) = written {
        return Ok(failure_reply(&error));
    }

    // The CRC and the optional verify byte follow the image.
    let mut word = [0_u8; 4];
    conn.payload(&mut word).await?;
    let expected = u32::from_be_bytes(word);
    let mut verify = [0_u8; 1];
    let verify = if head.verify_follows {
        conn.payload(&mut verify).await?;
        verify != [0]
    } else {
        false
    };
    let actual = crc.finalize();
    if actual != expected {
        return Ok(Reply::Error(format!(
            "{CRC_MISMATCH}: the image arrived with CRC32 0x{actual:08X}, not the 0x{expected:08X} sent after \
             it, and was written as it arrived; write it again"
        )));
    }

    if !verify {
        return Ok(Reply::ok());
    }
    busy.switch(Activity::Verifying);
    verify_by_crc(conn, &gadget.device, &state.clock, &alt, image_len, expected).await
}

/// A streamed write's verify: the image is gone, so the read-back is compared with the
/// CRC the image came with, and a mismatch has no offset to name.
async fn verify_by_crc<W, C, T>(
    conn: &mut W,
    device: &T,
    clock: &C,
    alt: &AltSel,
    len: u64,
    expected: u32,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    C: Sleeper,
    T: tdfu_usb::LocalUsbTransport,
{
    let queue = Queue::new();
    let mut read_back = Crc32Sink(Crc32::new());
    let verified = {
        let mut sink = queue.sink();
        pump(
            conn,
            Command::Write,
            &queue,
            ops::verify_with(device, clock, alt, len, &mut read_back, &mut sink),
        )
        .await?
    };
    if let Err(error) = verified {
        return Ok(failure_reply(&error));
    }
    let read = read_back.0.finalize();
    if read != expected {
        return Ok(Reply::Error(format!(
            "verify failed: the flash reads back with CRC32 0x{read:08X}, and the image's is 0x{expected:08X}"
        )));
    }
    conn.log(&ops::matched_note(len)).await?;
    Ok(Reply::ok())
}

/// A streamed `WRITE`'s fields up to its image.
#[derive(Debug)]
struct Head {
    index: u8,
    variant: Vec<u8>,
    alt: Vec<u8>,
    image_len: u32,
    /// Whether the verify byte follows the CRC.
    verify_follows: bool,
}

impl Head {
    /// `[idx][vlen][variant][alen][alt][image_len]`, refused as [`Request::decode`]
    /// refuses it, and the image, its CRC and the verify byte checked against what the
    /// payload has left. The fields read come back too, kept, for [`run_whole`].
    async fn read<W: Wire>(conn: &mut W, len: u64) -> Result<(Self, Fields), Refusal> {
        let mut fields = Fields::keeping(len);
        let (index, variant) = fields.index_and_variant(conn).await?;
        if fields.left() == 0 {
            return Err(Refusal::Payload("missing alt field"));
        }
        let alt = fields.length_prefixed(conn, "bad alt length").await?;
        let image_len = fields.be32(conn, "missing firmware length").await?;
        // The image and its CRC are tested together, as the decoder and the C test them
        // (`dfu-remote/main.c:485`).
        let Some(tail) = fields.left().checked_sub(u64::from(image_len) + 4) else {
            return Err(Refusal::Payload("firmware data truncated"));
        };
        if tail > 1 {
            return Err(Refusal::Payload("trailing bytes"));
        }
        let head = Self {
            index,
            variant,
            alt,
            image_len,
            verify_follows: tail == 1,
        };
        Ok((head, fields))
    }
}

/// A source that keeps the CRC of what passes through it: the image's own, computed on
/// the way to the device, for the CRC that follows it on the wire.
struct Crc32Source<'a, S> {
    inner: S,
    crc: &'a mut Crc32,
}

impl<S: AsyncSource> AsyncSource for Crc32Source<'_, S> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact(buf).await?;
        self.crc.update(buf);
        Ok(())
    }
}

/// A sink that keeps only a CRC: a streamed write's verify read-back.
struct Crc32Sink(Crc32);

impl AsyncSink for Crc32Sink {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.0.update(data);
        Ok(())
    }
}

/// The two failure shapes: a verify has its own string, everything else is
/// `"write failed: <cause>"`.
fn failure_reply(error: &Error) -> Reply {
    match error {
        // `ops::verify` answers `Verify { actual: None }` when the device ended the
        // upload short of the image rather than fabricating a read-back byte (a contracts
        // amendment). The wire string carries the offset either way, which is all
        // the wire string has room for.
        Error::Verify { offset, .. } => Reply::Error(verify_failed_message(*offset)),
        other => Reply::failed("write", other),
    }
}

/// The `variant` and `alt` fields, refused early so nothing is claimed for a request
/// that cannot run.
///
/// The variant is parsed and then dropped: `CMD_WRITE` chooses its device by index and
/// its alt by name, and no loader is built here, so an unrecognised one is accepted and
/// logged rather than refused. The argument, and the C lines
/// that show it doing the same, are on [`variant_selects_a_loader`].
fn parse_fields(variant: &[u8], alt: &[u8]) -> tdfu_core::Result<(AltSel, Option<tdfu_core::model::Variant>)> {
    let variant = variant_field(Command::Write, variant)?;
    let alt = parse_alt(alt)?;
    Ok((alt, variant))
}

/// A `WaitFailure` as it reads on the wire, for the two tests that pin the distinction.
#[cfg(test)]
fn wait_message(doing: &str, failure: super::device::WaitFailure) -> String {
    crate::errors::failed(doing, &failure.into_error())
}

#[cfg(test)]
mod tests {
    use super::{CRC_MISMATCH, wait_message};
    use crate::commands::Wire as _;
    use crate::commands::device::WaitFailure;
    use crate::commands::fake::{FakeBackend, LoopbackConn, Sent, TestResult};
    use crate::commands::fake::{dispatch, dispatch_streamed, seen};
    use crate::commands::state::{Activity, DaemonState, Window};
    use crate::errors::DaemonError;
    use tdfu_core::clock::RecordingClock;
    use tdfu_proto::{Command, ERASE_ALT, ERASE_TOKEN, Request, Status, crc32};
    use tdfu_usb::gadget::{Fault, When};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware").with_window(Window {
            probes: 3,
            interval: core::time::Duration::from_millis(250),
        })
    }

    fn write_request(alt: &[u8], image: &[u8], verify: Option<bool>) -> Request {
        Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: alt.to_vec(),
            image: image.to_vec(),
            crc32: crc32(image),
            verify,
        }
    }

    /// The request layout, byte for byte, and its `"OK"` reply.
    #[test]
    fn rpc_write_layout() -> TestResult {
        let image = b"firmware!".to_vec();
        let payload = write_request(b"flash", &image, Some(true)).encode()?;
        assert_eq!(
            payload,
            [
                &[0x00, 0x00, 0x05][..],
                b"flash",
                &[0, 0, 0, 9][..],
                b"firmware!",
                &crc32(&image).to_be_bytes()[..],
                &[0x01][..],
            ]
            .concat(),
            "[idx][vlen][alen][alt][fw_len BE][fw][crc BE][verify]"
        );

        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(state.activity(), Activity::Idle);

        // ... and the bytes really are on the medium.
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert_eq!(&medium[..image.len()], image.as_slice());
        Ok(())
    }

    /// **The gate, with the shipped browser flasher's own bytes.**
    ///
    /// `writeFirmware` builds `[idx][vlen][variant][alen=0][fw_len BE][fw][crc BE]
    /// [verify?]` at `web/src/remote.js:243-257`, and passes `detectedVariantName` as the
    /// variant. On any gadget the daemon has no cached detection for, that name is the
    /// literal `"unknown"`: DISCOVER answered `0xFF` and the WASM
    /// `tdfu_variant_to_string` renders it through `utils.c:127-128`'s `default:` arm.
    /// Built here the way the browser builds it, not through `Request::encode`, so the
    /// fixture is the client's bytes; the write must run and the medium must hold the
    /// image.
    #[test]
    fn rpc_24_the_browser_s_unknown_variant_writes() -> TestResult {
        let image = vec![0xC7_u8; 512];
        let name = b"unknown";

        let mut payload = vec![0x00_u8, 0x07];
        payload.extend_from_slice(name);
        payload.push(0x00); // alt_len = 0, which the web client always sends
        payload.extend_from_slice(&u32::try_from(image.len())?.to_be_bytes());
        payload.extend_from_slice(&image);
        payload.extend_from_slice(&crc32(&image).to_be_bytes());
        payload.push(0x01); // verify
        assert_eq!(&payload[..10], b"\x00\x07unknown\x00");

        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );

        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert_eq!(&medium[..image.len()], image.as_slice(), "and the bytes landed");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The optional verify byte: absent, present-and-zero, present-and-one. The C
    /// collapses the first two; `Option<bool>` keeps them apart.
    #[test]
    fn rpc_write_verify_byte_is_optional() -> TestResult {
        let image = b"abcd".to_vec();
        for (verify, tail) in [(None, 0), (Some(false), 1), (Some(true), 1)] {
            let payload = write_request(b"flash", &image, verify).encode()?;
            assert_eq!(payload.len(), 3 + 5 + 4 + 4 + 4 + tail, "{verify:?}");
            let decoded = Request::decode(Command::Write, &payload)?;
            assert_eq!(decoded, write_request(b"flash", &image, verify));
        }
        Ok(())
    }

    /// The CRC covers `fw` **only** — not the index, the variant, the alt, the
    /// length field or the verify byte (`dfu-remote/main.c:487-496`).
    #[test]
    fn rpc_write_crc_covers_the_firmware_only() -> TestResult {
        let image = b"firmware!".to_vec();
        let mut request = write_request(b"flash", &image, None);
        if let Request::Write { crc32: value, .. } = &mut request {
            *value = value.wrapping_add(1);
        }
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        block_on(dispatch(&mut conn, &mut state, Command::Write, &request.encode()?))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Response(Status::Error, CRC_MISMATCH.as_bytes().to_vec())]
        );
        // Nothing was opened: a bad CRC is refused before the bus is touched.
        assert!(state.backend.opened().is_empty());

        // The same image under a different alt still passes the CRC, which is what
        // "covers `fw` only" means.
        let elsewhere = write_request(b"1", &image, None);
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        block_on(dispatch(&mut conn, &mut state, Command::Write, &elsewhere.encode()?))?;
        assert_ne!(conn.error_text().as_deref(), Some(CRC_MISMATCH));
        Ok(())
    }

    /// **A listing that shrinks between the `DISCOVER` and the `WRITE` does not slide a
    /// neighbour under the index.**
    ///
    /// Two cameras on one hub: row 0 on port 4.3, row 1 on port 4.4. The client is
    /// answered that listing, row 0 leaves the bus (a bootstrap has it in U-Boot, or
    /// somebody pulled the cable), and row 1 becomes row 0. A `WRITE idx=0` then names a
    /// device that is not there, and this is the test that says so: the image must not
    /// reach the camera that moved into the position.
    #[test]
    fn rpc_write_does_not_follow_an_index_onto_a_neighbour() -> TestResult {
        let image = vec![0xA5_u8; 512];
        let payload = write_request(b"flash", &image, None).encode()?;
        let backend = FakeBackend::new(vec![
            FakeBackend::gadget_at_port_holding(1, 9, vec![4, 3], &[0x11; 512]),
            FakeBackend::gadget_at_port_holding(1, 10, vec![4, 4], &[0x22; 512]),
        ]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;

        // Row 0 leaves; the neighbour is now at position 0.
        state.backend.remove_row(0);
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;

        let message = conn
            .error_text()
            .ok_or("a device that left must be refused, not replaced")?;
        assert!(message.starts_with("write failed: "), "{message}");
        let neighbour = state.backend.gadget_at(0).ok_or("the survivor is row 0 now")?;
        let medium = neighbour.medium(0).ok_or("alt 0 has a medium")?;
        assert!(
            medium.iter().all(|&byte| byte == 0x22),
            "the neighbour's flash was written by a command that named the device that left"
        );
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// **Mirrored hubs on two buses are two cameras.** The identical port path exists on
    /// every bus, so a write to the bus-2 camera must not land on the bus-1 one, which
    /// comes first in the listing.
    #[test]
    fn rpc_write_does_not_cross_buses() -> TestResult {
        let image = vec![0xA5_u8; 512];
        let mut request = write_request(b"flash", &image, None);
        if let Request::Write { index, .. } = &mut request {
            *index = 1;
        }
        let payload = request.encode()?;
        let backend = FakeBackend::new(vec![
            FakeBackend::gadget_at_port_holding(1, 9, vec![4, 3], &[0x11; 512]),
            FakeBackend::gadget_at_port_holding(2, 9, vec![4, 3], &[0x22; 512]),
        ]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );

        let bus_one = state.backend.gadget_at(0).ok_or("row 0")?;
        let untouched = bus_one.medium(0).ok_or("alt 0 has a medium")?;
        assert!(
            untouched.iter().all(|&byte| byte == 0x11),
            "the bus-1 camera was written by a command that named the bus-2 one"
        );
        let bus_two = state.backend.gadget_at(1).ok_or("row 1")?;
        let written = bus_two.medium(0).ok_or("alt 0 has a medium")?;
        assert_eq!(&written[..image.len()], image.as_slice(), "and the named one was");
        Ok(())
    }

    /// The wipe token routes to the erase, and the chip really is wiped —
    /// which a generic download of 17 bytes to alt 1 would not do.
    #[test]
    fn fe_daemon_routes_erase_token() -> TestResult {
        let payload = write_request(ERASE_ALT, ERASE_TOKEN, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));

        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        assert_eq!(gadget.erases(), 1, "the real erase path ran");
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert!(medium.iter().all(|&byte| byte == 0xFF), "the chip is blank");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// ... and an alt that is *nearly* `erase` is not the erase alt. The C copies the
    /// alt into a 32-byte buffer and `strcmp`s it, so `"erase\0junk"` wipes a chip for
    /// it; an earlier implementation reproduced that and thereby widened the set of
    /// payloads that erase a flash.
    #[test]
    fn rpc_write_erase_token_near_miss_alts_are_ordinary_writes() -> TestResult {
        for alt in [b"erase\0junk".to_vec(), b"erase ".to_vec(), b"eras".to_vec()] {
            let request = write_request(&alt, ERASE_TOKEN, None);
            assert!(!request.is_erase(), "{alt:02X?}");

            let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
            let mut state = daemon(backend);
            block_on(seen(&mut state))?;
            let mut conn = LoopbackConn::raw();
            block_on(dispatch(&mut conn, &mut state, Command::Write, &request.encode()?))?;
            let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
            assert_eq!(gadget.erases(), 0, "{alt:02X?} must not wipe a chip");
        }
        Ok(())
    }

    /// A token that is not the token takes the **generic download** path, not the
    /// grace-and-blank-check one — which is what the daemon controls.
    ///
    /// A *longer* buffer whose first 17 bytes are the token is deliberately not in this
    /// list: the loader's own compare is a `strlen`-guarded `memcmp`
    /// (`dfu-remote/main.c:506` for the daemon's copy of the rule, and the same shape in
    /// the loader), so writing `XBURST-FLASH-WIPEX` to the `erase` alt really does wipe
    /// the chip on a real device. That is the **device's** rule and this emulator models
    /// it; the routing question — which host-side code path ran — is the one below.
    #[test]
    fn a_near_miss_token_takes_the_download_path_not_the_erase_path() -> TestResult {
        let short_token = b"XBURST-FLASH-WIP".to_vec();
        let request = write_request(ERASE_ALT, &short_token, None);
        assert!(!request.is_erase(), "sixteen bytes is not the token");

        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &request.encode()?))?;

        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        assert_eq!(gadget.erases(), 0, "no chip was wiped");
        // Which path ran is legible from the prefix: the erase path answers
        // `"erase failed: …"` (`dfu-remote/main.c:531`) and the download path
        // `"write failed: …"` (`:593`). The loader refuses the bad token — its virt
        // entity's flush fails and the device lands in `dfuERROR` — which is precisely
        // the failure the token check exists to keep off the erase path.
        let message = conn.error_text().ok_or("the loader refuses a bad token")?;
        assert!(message.starts_with("write failed: "), "{message}");
        assert!(!message.starts_with("erase failed: "), "{message}");
        assert!(
            !conn.log_lines().iter().any(|line| line.contains("Erase complete")),
            "and nothing claimed an erase: {:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// The erase claims `erasing` and sends the erase
    /// phase — the C sets `g_state = "erasing"` at `dfu-remote/main.c:508` and sends no
    /// progress frame at all.
    #[test]
    fn an_erase_claims_erasing_and_sends_its_phase() -> TestResult {
        let payload = write_request(ERASE_ALT, ERASE_TOKEN, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
        let mut state = daemon(backend);
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(seen(&mut state))?;
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));

        assert!(
            conn.progress_frames().iter().any(|body| body.stage == 7),
            "erase stage: {:?}",
            conn.progress_frames()
        );
        // Every frame but the final response went out while the daemon said `erasing`.
        let during: Vec<_> = conn.activities().into_iter().take(conn.sent().len() - 1).collect();
        assert!(
            during.iter().all(|activity| *activity == Activity::Erasing),
            "{during:?}"
        );
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// A write that verifies moves `writing` → `verifying` **without**
    /// passing through `idle` (`dfu-remote/main.c:578`), and the verify half sends the
    /// verify stage.
    #[test]
    fn a_verifying_write_switches_state_without_going_idle() -> TestResult {
        let image = vec![0x11_u8; 9000];
        let payload = write_request(b"flash", &image, Some(true)).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(seen(&mut state))?;
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));

        let during = conn.activities();
        assert!(during.contains(&Activity::Writing), "{during:?}");
        assert!(during.contains(&Activity::Verifying), "{during:?}");
        // The final response frame is the only one recorded as idle: the guard is
        // dropped when the handler returns, before `dispatch` answers.
        assert_eq!(
            during.iter().filter(|activity| **activity == Activity::Idle).count(),
            1,
            "the state never returned to idle mid-operation: {during:?}"
        );
        assert!(
            conn.progress_frames().iter().any(|body| body.stage == 6),
            "verify stage: {:?}",
            conn.progress_frames()
        );
        assert!(
            conn.log_lines().iter().any(|line| line.starts_with("Verify OK: ")),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// Gap (r)'s **other** citation, end to end: `dfu.c:708` is the `erase` alt, and a
    /// loader without one answers `"Invalid parameter"` and not a new string.
    ///
    /// `reboot.rs` pins `dfu.c:756`, the twin. Both are here because the gap names both,
    /// and because they reach the mapper down different paths — this one through
    /// `ops::erase`'s own alt lookup, which is why the erase wait passes no selector.
    #[test]
    fn gap_r_a_loader_without_an_erase_alt_is_invalid_parameter() -> TestResult {
        let payload = write_request(ERASE_ALT, ERASE_TOKEN, None).encode()?;
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::flash_only_gadget()]));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        let message = conn.error_text().ok_or("a loader with no erase alt must refuse")?;
        assert!(message.starts_with("erase failed: Invalid parameter: "), "{message}");
        assert!(message.contains("erase"), "{message}");
        assert!(message.contains("update the DFU loader firmware"), "{message}");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The erase token's own CRC is checked, because the C checks it above the routing
    /// (`dfu-remote/main.c:496` before `:506`).
    #[test]
    fn a_corrupt_erase_token_is_refused_before_it_is_routed() -> TestResult {
        let mut request = write_request(ERASE_ALT, ERASE_TOKEN, None);
        if let Request::Write { crc32: value, .. } = &mut request {
            *value = 0;
        }
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &request.encode()?))?;
        assert_eq!(conn.error_text().as_deref(), Some(CRC_MISMATCH));
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        assert_eq!(gadget.erases(), 0);
        Ok(())
    }

    /// The verify string: uppercase, zero-padded to eight digits, and with no
    /// `write failed:` prefix (`dfu-remote/main.c:588-595`, read).
    ///
    /// This is the mapping that matters, pinned on the function that
    /// makes the choice: `Error::Verify`'s own `Display` is the *local* wording and
    /// carries the bytes, and it must not reach the wire.
    #[test]
    fn rpc_write_verify_failure_has_its_own_string() {
        for (offset, expected) in [
            (0_u64, "verify failed at offset 0x00000000"),
            (7, "verify failed at offset 0x00000007"),
            (0x00AB_CDEF, "verify failed at offset 0x00ABCDEF"),
            // Wider than eight digits when the offset needs it.
            (0x1_0000_0000, "verify failed at offset 0x100000000"),
        ] {
            let reply = super::failure_reply(&tdfu_core::Error::Verify {
                offset,
                expected: 0xAA,
                actual: Some(0x55),
            });
            assert_eq!(reply, crate::commands::Reply::Error(expected.to_owned()));
        }

        // A device that ended the upload short of the image is the same wire string:
        // `actual: None` has no read-back byte to report and the wire string has nowhere to
        // put one.
        assert_eq!(
            super::failure_reply(&tdfu_core::Error::Verify {
                offset: 9,
                expected: 1,
                actual: None,
            }),
            crate::commands::Reply::Error("verify failed at offset 0x00000009".to_owned())
        );

        // Everything else keeps the C's `"write failed: %s"` shape (`main.c:593`).
        let other = super::failure_reply(&tdfu_core::Error::NotDfu);
        let crate::commands::Reply::Error(message) = other else {
            unreachable!("failure_reply always answers with an error")
        };
        assert!(message.starts_with("write failed: Device not found: "), "{message}");
    }

    /// A blank check that fails is an `Error::Verify` too, and it must **not** take the
    /// write path's string: the C answers `"erase failed: %s"` there (`main.c:531`),
    /// and ours adds the offset the C threw away.
    #[test]
    fn an_erase_blank_check_failure_is_not_a_write_verify_string() {
        let message = crate::errors::failed(
            "erase",
            &tdfu_core::Error::Verify {
                offset: 0x40,
                expected: 0xFF,
                actual: Some(0x00),
            },
        );
        assert!(
            message.starts_with("erase failed: Verify failed (read-back mismatch): "),
            "{message}"
        );
        assert!(message.contains("0x40"), "the offset the C dropped: {message}");
        // It is not the bare wire string: that one starts the payload, has no
        // prefix, and carries no read-back bytes.
        assert!(!message.starts_with("verify failed at offset"), "{message}");
        assert!(
            message.contains("read back 0x00"),
            "the local detail travels too: {message}"
        );
    }

    /// The two facts a wait can end on, told apart. An earlier implementation collapsed
    /// both into `write failed: Device not found`.
    #[test]
    fn a_missing_device_and_a_missing_alt_read_differently() {
        let no_device = wait_message(
            "write",
            WaitFailure::NoGadget {
                probes: 120,
                waited: core::time::Duration::from_millis(29_750),
            },
        );
        assert!(no_device.starts_with("write failed: Device not found: "), "{no_device}");
        assert!(no_device.contains("120 probes"), "{no_device}");
        assert!(no_device.contains("29.8s"), "{no_device}");

        let no_alt = wait_message("write", WaitFailure::NoSuchAlt(tdfu_core::Error::MissingAlt("flash")));
        assert!(no_alt.starts_with("write failed: Invalid parameter: "), "{no_alt}");
        assert!(no_alt.contains("no alt named"), "{no_alt}");
        assert_ne!(
            no_device, no_alt,
            "these are different faults and must not read the same"
        );
    }

    /// An alt the device does not have is refused with the alts it does have — the
    /// list is in hand, and the C's `-1` return threw it away.
    #[test]
    fn a_wrong_alt_names_what_the_device_offers() -> TestResult {
        let image = b"abcd".to_vec();
        let payload = write_request(b"sdcard", &image, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        let message = conn.error_text().ok_or("a wrong alt must be refused")?;
        assert!(message.contains("sdcard"), "{message}");
        assert!(message.contains("flash"), "the alts on offer: {message}");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// **The case where this daemon and the C daemon disagree.**
    ///
    /// An empty alt field is [`AltSel::Default`](tdfu_core::model::AltSel::Default), and
    /// this daemon resolves it through `tdfu_core::dfu::alt::resolve`: the alt named
    /// `flash`, else the only alt, else refuse. The C daemon answers `info.alts[0].alt`
    /// (`dfu-remote/main.c:351`), so on a loader offering `[nor, sdcard, erase, reboot]`
    /// it writes `nor` and we refuse. The refusal is the point of having one resolver:
    /// the alternative is a guessed alt, and a write to the wrong partition reported as
    /// a success is the worst failure this tool has.
    ///
    /// The input is the one the web client always sends (`web/src/remote.js:249`,
    /// `alen = 0`). No shipped loader reaches this: the
    /// fixture is built to.
    ///
    /// The refusal names `flash` and says to update the loader, and it does **not** list
    /// the alts on offer, where a wrong *name* does
    /// (`a_wrong_alt_names_what_the_device_offers`). That asymmetry is
    /// `Error::MissingAlt(&'static str)`'s shape rather than this daemon's choice, and it
    /// is already recorded at `tdfu-cli/src/alt.rs:52`. The second half of this test is
    /// what makes the refusal actionable in the meantime: the same loader writes when the
    /// alt is asked for by name, so the operator is one `--alt` from a working command.
    #[test]
    fn fe_daemon_default_alt_on_a_loader_without_flash() -> TestResult {
        let image = b"firmware!".to_vec();
        let payload = write_request(b"", &image, None).encode()?;
        assert_eq!(&payload[..3], &[0x00, 0x00, 0x00], "[idx][vlen=0][alen=0]");

        let backend = FakeBackend::new(vec![FakeBackend::gadget_without_a_flash_alt()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;

        let message = conn.error_text().ok_or("a flash-less loader must be refused")?;
        assert!(message.starts_with("write failed: Invalid parameter: "), "{message}");
        assert!(message.contains("no alt named \"flash\""), "{message}");
        assert!(message.contains("update the DFU loader firmware"), "{message}");
        // Nothing was written: the refusal is above the download, where the C would have
        // taken `info.alts[0]` and filled `nor`.
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert!(
            medium.iter().all(|&byte| byte == 0xFF),
            "the C would have written alt 0 here"
        );
        assert_eq!(state.activity(), Activity::Idle);

        // ... and an explicit selector still wins on the same loader, so
        // the refusal is about the default rule and not about the device.
        let named = write_request(b"nor", &image, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_without_a_flash_alt()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &named))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert_eq!(&medium[..image.len()], image.as_slice());
        Ok(())
    }

    /// For a write: the download's byte counts leave as progress
    /// frames, and core's completion note as a log line.
    #[test]
    fn a_write_sends_progress_frames_and_the_completion_note() -> TestResult {
        let image = vec![0x11_u8; 9000];
        let payload = write_request(b"flash", &image, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));

        let frames = conn.progress_frames();
        assert!(!frames.is_empty(), "a byte-moving command sends frames");
        assert!(
            frames.iter().any(|body| body.stage == 3),
            "the download phase: {frames:?}"
        );
        assert!(
            frames.iter().any(|body| body.percent == 100),
            "and it reaches 100%: {frames:?}"
        );
        assert!(
            conn.log_lines().iter().any(|line| line == "Write complete"),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// A gadget left wedged by a killed run answers its first descriptor read with a
    /// stall; the probe clears it with a USB reset. That recovery reaches the remote
    /// operator as a log line rather than passing as an unexplained re-enumeration: the
    /// reset happens either way, but the note only travels when the probe is given the
    /// connection's progress sink.
    #[test]
    fn a_probe_that_resets_a_wedged_gadget_tells_the_operator() -> TestResult {
        let image = vec![0x11_u8; 512];
        let payload = write_request(b"flash", &image, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;

        // Stall the next descriptor read: a recoverable failure the probe answers with a
        // reset and one retry.
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        gadget.inject(When::Descriptor, Fault::Stall);

        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );

        assert_eq!(gadget.resets(), 1, "the probe reset the wedged gadget");
        assert!(
            conn.log_lines().iter().any(|line| line.contains("USB-reset")),
            "the operator was told the gadget was reset: {:?}",
            conn.log_lines()
        );
        Ok(())
    }

    // ------------------------------------------------------------ streamed

    /// An image with no pattern a block boundary could hide in.
    fn pattern(len: u32) -> Vec<u8> {
        (0..len).map(|at| (at % 251) as u8).collect()
    }

    /// **A streamed `WRITE` lands the same bytes a whole one does**, with the daemon
    /// never holding more than a block of them.
    #[test]
    fn a_streamed_write_lands_the_image() -> TestResult {
        let image = pattern(20_000);
        let payload = write_request(b"flash", &image, None).encode()?;
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(1024);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(dispatch_streamed(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );
        assert_eq!(conn.drained(), 0, "the handler read the whole payload itself");
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        let medium = gadget.medium(0).ok_or("alt 0 has a medium")?;
        assert_eq!(&medium[..image.len()], image.as_slice());
        assert!(
            conn.log_lines().iter().any(|line| line == "Write complete"),
            "{:?}",
            conn.log_lines()
        );
        assert!(conn.activities().contains(&Activity::Writing));
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// With the verify byte set, the read-back is compared by CRC, the image being gone,
    /// under `verifying`, and the match is announced as a whole write's is.
    #[test]
    fn a_streamed_write_verifies_by_crc() -> TestResult {
        let image = pattern(20_000);
        let payload = write_request(b"flash", &image, Some(true)).encode()?;
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(1024);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(dispatch_streamed(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );
        assert!(conn.activities().contains(&Activity::Verifying));
        assert!(
            conn.log_lines()
                .iter()
                .any(|line| line == "Verify OK: 20000 bytes match"),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// A CRC that does not match the image is refused, after the fact, and the answer
    /// says the flash was written: the image went out as it arrived.
    #[test]
    fn a_streamed_write_with_the_wrong_crc_says_it_was_written() -> TestResult {
        let image = pattern(20_000);
        let mut request = write_request(b"flash", &image, Some(true));
        if let Request::Write { crc32: value, .. } = &mut request {
            *value ^= 1;
        }
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(1024);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch_streamed(
            &mut conn,
            &mut state,
            Command::Write,
            &request.encode()?,
        ))?;
        let message = conn.error_text().ok_or("the write must be refused")?;
        assert!(message.starts_with(CRC_MISMATCH), "{message}");
        assert!(message.contains("written as it arrived"), "{message}");
        assert!(
            !conn.log_lines().iter().any(|line| line.starts_with("Verify OK")),
            "no verify runs against a CRC already refused"
        );
        Ok(())
    }

    /// **Every malformed layout is refused as the decoder refuses it**, in the same
    /// words, before the bus is touched, and the rest of the payload is read and
    /// dropped so the connection stays in step.
    #[test]
    fn a_streamed_write_refuses_what_the_decoder_refuses() -> TestResult {
        let good = write_request(b"flash", &pattern(5000), Some(true)).encode()?;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("payload too short", vec![0]),
            ("bad variant length", [&[0_u8, 250][..], &[0; 10]].concat()),
            ("missing alt field", vec![0, 0]),
            ("bad alt length", [&[0_u8, 0, 200][..], &[0; 10]].concat()),
            (
                "missing firmware length",
                [&[0_u8, 0, 5][..], b"flash", &[0, 0]].concat(),
            ),
            ("firmware data truncated", good[..good.len() - 3].to_vec()),
            ("trailing bytes", [&good[..], &[0, 0]].concat()),
        ];
        for (words, payload) in cases {
            let mut whole = LoopbackConn::raw();
            let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
            block_on(seen(&mut state))?;
            block_on(dispatch(&mut whole, &mut state, Command::Write, &payload))?;
            assert_eq!(whole.error_text().as_deref(), Some(words), "read whole");

            let mut streamed = LoopbackConn::raw();
            let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(0);
            block_on(seen(&mut state))?;
            block_on(dispatch_streamed(&mut streamed, &mut state, Command::Write, &payload))?;
            assert_eq!(streamed.error_text().as_deref(), Some(words), "streamed");
            assert!(state.backend.opened().is_empty(), "{words}: the bus was touched");
            assert_eq!(streamed.payload_left(), 0, "{words}: the rest was not read");
        }
        Ok(())
    }

    /// **An image small enough to hold takes the whole-payload path**, CRC ahead of the
    /// flash: a payload just over the limit because of its fields is not worth giving
    /// that up for.
    #[test]
    fn a_streamed_write_of_a_small_image_checks_its_crc_first() -> TestResult {
        let image = vec![0x11_u8; 1000];
        let mut request = write_request(b"flash", &image, None);
        if let Request::Write { crc32: value, .. } = &mut request {
            *value ^= 1;
        }
        let payload = request.encode()?;
        assert!(payload.len() > 1000, "the payload is over the limit, the image is not");
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(1000);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch_streamed(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Response(Status::Error, CRC_MISMATCH.as_bytes().to_vec())]
        );
        assert!(state.backend.opened().is_empty(), "refused before the bus");
        Ok(())
    }

    /// The wipe token is seventeen bytes, so it always takes that path, and it still
    /// erases however small the limit.
    #[test]
    fn a_streamed_erase_token_still_erases() -> TestResult {
        let payload = write_request(ERASE_ALT, ERASE_TOKEN, None).encode()?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x5A; 4096])]);
        let mut state = daemon(backend).with_stream_above(20);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch_streamed(&mut conn, &mut state, Command::Write, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        assert_eq!(gadget.erases(), 1, "the real erase path ran");
        Ok(())
    }

    /// A client that stops sending part-way through the image ends the connection, and
    /// the daemon is idle and ready for the next one.
    #[test]
    fn a_client_that_stops_mid_image_leaves_the_daemon_idle() -> TestResult {
        let payload = write_request(b"flash", &pattern(20_000), None).encode()?;
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()])).with_stream_above(1024);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().stopping_after(9000);
        let outcome = block_on(dispatch_streamed(&mut conn, &mut state, Command::Write, &payload));
        assert!(matches!(outcome, Err(DaemonError::Truncated { .. })), "{outcome:?}");
        assert!(conn.response().is_none(), "nobody is left to answer");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }
}
