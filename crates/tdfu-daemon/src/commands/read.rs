//! `CMD_READ 0x04` — upload a whole alt.
//!
//! Request: `[idx][vlen u8][variant]` and an **optional** `[alen u8][alt]` — the web
//! client omits the alt entirely (`web/src/remote.js:228`) and the CLI sends `vlen = 0`
//! and an alt. `dfu-remote/main.c:625` is the `if (p < end)` that makes it optional.
//! There is no offset and no length field: the daemon always uploads the whole alt
//! (`main.c:662` passes size 0, and a short block ends the read).
//!
//! OK payload is `[data][crc32 u32 BE]`, assembled big-endian by hand at
//! `main.c:712-724`. It is the one reply allowed to exceed the 64 MiB cap: a NAND
//! alt 0 is 256 MiB and the shipped clients stream it to a file.
//!
//! # The image goes through a file, at 0600
//!
//! [`ops::read`] streams to a `Write` so a 256 MiB alt never buffers, and
//! the sink is a staging file — see [`staging`](super::staging) for the mode, which is
//! the one place the C was safer than us. The CRC is
//! computed **as the bytes stream past**, through `tdfu_proto`'s resumable
//! [`Crc32`](tdfu_proto::Crc32), so the image is not walked a second time.
//!
//! # The reply streams
//!
//! The reply's header carries the image's length, and a DFU upload's length is known
//! only once its short block has arrived; that is what the staging file is for. The
//! reply then goes out from the file a piece at a time ([`Wire::begin_reply`]), so no
//! copy of the image is held in memory at all. A daemon with no disk reads the alt
//! twice instead ([`ReadStaging::TwoPass`]): once for the length and the CRC, with the
//! progress a client watches, and once straight into the reply.

use std::io::{Read, Write};

use tdfu_core::clock::Sleeper;
use tdfu_core::model::AltSel;
use tdfu_core::progress::Progress;
use tdfu_core::stream::AsyncSink;
use tdfu_core::{Error, ops};
use tdfu_proto::{Command, Crc32, Status};
use tdfu_usb::{LocalUsbBackend, LocalUsbTransport};

use super::device::{Target, await_gadget};
use super::report::{Io, Outbox, Queue, pump, pump_with};
use super::staging::Staged;
use super::state::{Activity, DaemonState, ReadStaging};
use super::{Reply, Wire, parse_alt, variant_field};
use crate::errors::{DaemonError, wire_message};

/// How much of a staged image is sent at a time.
const SEND_CHUNK: usize = 16 * 1024;

/// The empty-image refusal (`dfu-remote/main.c:689`).
const EMPTY: &str = "read returned empty data";

/// The most an upload may take, in bytes.
///
/// `CMD_READ`'s OK payload is exempt from the 64 MiB cap, because a NAND alt 0 is
/// 256 MiB, but it is not exempt from the frame header: `payload_len` is a `u32`, and
/// this reply carries the image plus a four-byte CRC. So the image itself can be at most
/// `u32::MAX - 4`, and a device that has not ended the upload by then is answered rather
/// than followed until a disk fills.
///
/// **A guard, not a size.** It is enforced by the sink ([`Tee`]), never handed to
/// `ops::read` as its `limit`: a limit is `--size`, a length the operator asked for, and
/// core reports it as the transfer's total, so every progress frame of a whole-chip read
/// said `N/4294967291 bytes` at 0 %. A DFU upload has no knowable total, and the frames
/// say so now, exactly as a local read does.
const CEILING: u64 = u32::MAX as u64 - 4;

/// Read the whole of `alt` and answer with it plus its CRC.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn handle<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    index: u8,
    variant: &[u8],
    alt: Option<&[u8]>,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    handle_within(conn, state, index, variant, alt, CEILING).await
}

/// [`handle`], with the ceiling as a parameter so a test can reach it with a device a
/// fixture can build; outside tests it is [`CEILING`].
async fn handle_within<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    index: u8,
    variant: &[u8],
    alt: Option<&[u8]>,
    ceiling: u64,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    // An unrecognised name is accepted and dropped here, because
    // nothing below reads it. `variant_selects_a_loader` carries the argument.
    if let Err(error) = variant_field(Command::Read, variant) {
        return Ok(Reply::Error(wire_message(&error)));
    }
    let alt = match parse_alt(alt.unwrap_or_default()) {
        Ok(alt) => alt,
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };

    state.arm();
    let _busy = state.busy(Activity::Reading);

    let target = match state.row(index) {
        Ok(row) => Target::of_row(index, row),
        Err(error) => return Ok(Reply::failed("read", &error)),
    };
    // The queue is opened before the wait so the probe's recovery note (a wedged gadget a
    // USB reset cleared) has somewhere to go; `pump` flushes it before the upload's frames.
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
        Err(failure) => return Ok(Reply::failed("read", &failure.into_error())),
    };

    match state.read_staging {
        ReadStaging::TwoPass => twice(conn, &gadget.device, &state.clock, &alt, &queue, &mut sink, ceiling).await,
        // `ReadStaging` is `#[non_exhaustive]`; the file is the default and the fallback.
        _ => staged(conn, state, &gadget.device, &alt, &queue, &mut sink, ceiling).await,
    }
}

/// Read the alt into a staging file, then send the file.
async fn staged<W, B, C, T>(
    conn: &mut W,
    state: &DaemonState<B, C>,
    device: &T,
    alt: &AltSel,
    queue: &Queue,
    sink: &mut dyn FnMut(Progress),
    ceiling: u64,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    C: Sleeper,
    T: LocalUsbTransport,
{
    let mut staged = match Staged::create(&state.staging_dir, "tdfu-read") {
        Ok(staged) => staged,
        Err(error) => return Ok(Reply::failed("read", &Error::Io(error))),
    };

    let mut crc = Crc32::new();
    let outcome = {
        let Some(file) = staged.file() else {
            return Ok(Reply::failed(
                "read",
                &Error::Io(std::io::Error::other("no staging handle")),
            ));
        };
        let mut tee = Tee::new(file, &mut crc, ceiling);
        let outcome = pump(
            conn,
            Command::Read,
            queue,
            // The request has no length field, so the alt is read to its short block,
            // and no limit is passed: a device that never sends one is stopped by the
            // sink at [`CEILING`], which is what this reply can carry, rather than
            // followed until the filesystem fills with the daemon wholly occupied by it.
            ops::read(device, &state.clock, alt, None, &mut tee, sink),
        )
        .await?;
        (outcome, tee.capped(), tee.written())
    };

    let total = match counted(outcome) {
        Ok(total) => total,
        Err(reply) => return Ok(reply),
    };

    // Opened before the reply begins, so a file that cannot be read back is still an
    // answer rather than a connection cut off mid-reply. The C reads the whole image into
    // memory and then keeps a *second* copy — `read_data` at `dfu-remote/main.c:692` plus
    // `resp` at `:714`, about 512 MiB peak for a 256 MiB T40XP chip. This holds one
    // chunk.
    let path = staged.finish().to_path_buf();
    let mut file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) => return Ok(Reply::failed("read", &Error::Io(error))),
    };
    conn.begin_reply(Status::Ok, total + 4).await?;
    let mut chunk = vec![0_u8; SEND_CHUNK];
    let mut sent = 0_u64;
    while sent < total {
        // **Blocking**, as the staging writes before it are. Safe because everything is
        // serialised: one connection, served to completion on a current-thread runtime
        // with no other task to starve. `spawn_blocking` would need a `Send` future,
        // which decision D1 rules out.
        let got = file.read(&mut chunk)?;
        let take = u64::try_from(got).unwrap_or(u64::MAX).min(total - sent);
        let Some(piece) = chunk
            .get(..usize::try_from(take).unwrap_or(0))
            .filter(|piece| !piece.is_empty())
        else {
            return Err(DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("the staged image ended at {sent} of {total} bytes"),
            )));
        };
        conn.reply_body(piece).await?;
        sent += take;
    }
    conn.reply_body(&crc.finalize().to_be_bytes()).await?;
    conn.end_reply().await?;
    tracing::debug!(total, "read complete");
    Ok(Reply::Sent)
}

/// Read the alt twice: once for its length and CRC, with the progress a client watches,
/// and once into the reply, whose header needs that length before a byte of it.
///
/// The second pass is capped at the first's length, and the CRC sent is the first's: a
/// second read that differs is then a CRC mismatch at the client, which is the truth,
/// rather than a checksum that vouches for whichever read happened last. The second
/// pass sends no progress, being inside the reply.
async fn twice<W, C, T>(
    conn: &mut W,
    device: &T,
    clock: &C,
    alt: &AltSel,
    queue: &Queue,
    sink: &mut dyn FnMut(Progress),
    ceiling: u64,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    C: Sleeper,
    T: LocalUsbTransport,
{
    let mut crc = Crc32::new();
    let outcome = {
        let mut nowhere = std::io::sink();
        let mut tee = Tee::new(&mut nowhere, &mut crc, ceiling);
        let outcome = pump(
            conn,
            Command::Read,
            queue,
            ops::read(device, clock, alt, None, &mut tee, sink),
        )
        .await?;
        (outcome, tee.capped(), tee.written())
    };
    let total = match counted(outcome) {
        Ok(total) => total,
        Err(reply) => return Ok(reply),
    };
    let first = crc.finalize();

    conn.begin_reply(Status::Ok, total + 4).await?;
    let outbox = Outbox::new();
    let (second, again) = {
        let mut out = Crc32Out {
            inner: outbox.sink(),
            crc: Crc32::new(),
        };
        let io = Io {
            intake: None,
            outbox: Some(&outbox),
        };
        let mut quiet = |progress: Progress| {
            if let Progress::Debug(line) = progress {
                tracing::debug!("{line}");
            }
        };
        let second = pump_with(
            conn,
            Command::Read,
            &Queue::new(),
            io,
            ops::read_to(device, clock, alt, Some(total), &mut out, &mut quiet),
        )
        .await?;
        (second, out.crc.finalize())
    };
    match second {
        Ok(read) if read == total => {}
        // The reply's length is on the wire already, so it cannot be completed; the
        // connection ends, which the client sees as a reply cut short.
        Ok(read) => {
            return Err(DaemonError::Io(std::io::Error::other(format!(
                "the second read of the alt ended at {read} of {total} bytes"
            ))));
        }
        Err(error) => {
            return Err(DaemonError::Io(std::io::Error::other(format!(
                "the second read of the alt failed: {error}"
            ))));
        }
    }
    if again != first {
        tracing::warn!(
            "the alt read back differently the second time (CRC32 0x{first:08X}, then 0x{again:08X}); \
             the client's CRC check will refuse it"
        );
    }
    conn.reply_body(&first.to_be_bytes()).await?;
    conn.end_reply().await?;
    tracing::debug!(total, "read complete");
    Ok(Reply::Sent)
}

/// A finished first read as the length to answer with, or the answer itself.
fn counted(outcome: (Result<u64, Error>, bool, u64)) -> Result<u64, Reply> {
    match outcome {
        (Ok(0), _, _) => Err(Reply::Error(EMPTY.to_owned())),
        (Ok(total), _, _) => Ok(total),
        // Refused here, before any of the image is sent: the alternative is to find
        // that the length field cannot describe it only once a reply is on its way.
        (Err(_), true, written) => Err(Reply::Error(format!(
            "read stopped at {written} bytes: this alt is larger than one reply can carry, \
             and the device sent no end of data within it"
        ))),
        (Err(error), false, _) => Err(Reply::failed("read", &error)),
    }
}

/// A sink that passes everything on and keeps its CRC: the second read, checked against
/// the first.
struct Crc32Out<S> {
    inner: S,
    crc: Crc32,
}

impl<S: AsyncSink> AsyncSink for Crc32Out<S> {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(data).await?;
        self.crc.update(data);
        Ok(())
    }
}

/// A sink that writes to the staging file and feeds the CRC at the same time, and
/// refuses the block that would take the image past its ceiling.
///
/// One pass over the image. `Crc32` is resumable precisely so a streaming producer does
/// not have to keep the bytes to check them (contracts F4 amendment).
///
/// Generic over the sink rather than fixed to `File`, so a test can hand it a writer
/// that fails and pin that **the CRC does not advance past a byte the file did not
/// take**. With `&mut File` there was no such writer: `File::flush` is a documented
/// no-op that cannot fail, so replacing this `flush` with `Ok(())` survived every test —
/// a mutant that was equivalent only because the fixture could not express the
/// separating input (contracts, "Amendments to the seam").
struct Tee<'a, W: Write> {
    sink: &'a mut W,
    crc: &'a mut Crc32,
    /// The most the sink may take; [`CEILING`] outside tests.
    ceiling: u64,
    /// Bytes the sink has taken.
    written: u64,
    /// Whether a block was refused for the ceiling, which is the one sink failure the
    /// handler answers in its own words.
    capped: bool,
}

impl<'a, W: Write> Tee<'a, W> {
    fn new(sink: &'a mut W, crc: &'a mut Crc32, ceiling: u64) -> Self {
        Self {
            sink,
            crc,
            ceiling,
            written: 0,
            capped: false,
        }
    }

    /// Was a block refused for the ceiling?
    const fn capped(&self) -> bool {
        self.capped
    }

    /// Bytes the sink has taken.
    const fn written(&self) -> u64 {
        self.written
    }
}

impl<W: Write> Write for Tee<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The ceiling is checked on the whole block: a block that does not fit is not
        // taken in part, so the file holds whole blocks and `written` is where the
        // refusal happened. `ops::read` treats the failure as final, which is the point.
        let after = self
            .written
            .saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        if after > self.ceiling {
            self.capped = true;
            return Err(std::io::Error::other(format!(
                "the reply cannot carry more than {} bytes",
                self.ceiling
            )));
        }
        // `write_all`, not `write`: a short write here would desynchronise the CRC from
        // the file, and `ops::read` treats a sink failure as final
        // rather than restarting the chip read the way `dfu.c:839-842` does.
        //
        // The CRC is updated **after** the write succeeds, and only then, for the same
        // reason: a checksum over bytes that never reached the file would certify an
        // image nobody has.
        self.sink.write_all(buf)?;
        self.crc.update(buf);
        self.written = after;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::EMPTY;
    use crate::commands::fake::Sent;
    use crate::commands::fake::{FakeBackend, LoopbackConn, Scratch, TestResult};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::{Activity, DaemonState, ReadStaging, Window};
    use tdfu_core::clock::RecordingClock;
    use tdfu_proto::{Command, Request, Status, crc32};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend, staging: &std::path::Path) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware")
            .with_staging_dir(staging)
            .with_window(Window {
                probes: 3,
                interval: core::time::Duration::from_millis(250),
            })
    }

    /// The request layout and its `[data][crc32 BE]` reply.
    #[test]
    fn rpc_read_layout() -> TestResult {
        let scratch = Scratch::new("read-layout")?;
        let image: Vec<u8> = (0..4096_u32)
            .map(|byte| u8::try_from(byte % 251).unwrap_or(0))
            .collect();

        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: Some(b"flash".to_vec()),
        }
        .encode()?;
        assert_eq!(payload, [&[0x00, 0x00, 0x05][..], b"flash"].concat());

        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&image)]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;

        let (status, body) = conn.response().ok_or("one response frame")?;
        assert_eq!(status, Status::Ok);
        let (data, crc) = body.split_at(body.len() - 4);
        assert_eq!(data, image.as_slice(), "the whole alt, and nothing else");
        assert_eq!(crc, crc32(&image).to_be_bytes(), "CRC-32 big-endian, over the data");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The alt field is optional — the web client omits it entirely
    /// (`web/src/remote.js:228`, `dfu-remote/main.c:625`).
    #[test]
    fn rpc_read_alt_is_optional() -> TestResult {
        let scratch = Scratch::new("read-noalt")?;
        let image = vec![0x42_u8; 1024];
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        assert_eq!(payload, vec![0x00, 0x00], "just [idx][vlen=0]");

        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&image)]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;
        let (status, body) = conn.response().ok_or("one response frame")?;
        assert_eq!(status, Status::Ok);
        assert_eq!(&body[..image.len()], image.as_slice());
        Ok(())
    }

    /// **The gate, with the shipped browser flasher's own bytes.**
    ///
    /// `readFirmware` sends `_variantPayload(idx, detectedVariantName)`
    /// (`web/src/remote.js:228-229`, `:201-208`), and on any gadget the daemon has no
    /// cached detection for that name is the literal `"unknown"` - DISCOVER answered
    /// `0xFF` and the WASM `tdfu_variant_to_string` renders it through
    /// `utils.c:127-128`'s `default:` arm. This payload is built the way the browser
    /// builds it rather than through `Request::encode`, so it is the client's bytes and
    /// not our paraphrase of them, and the read must run.
    #[test]
    fn rpc_24_the_browser_s_unknown_variant_reads() -> TestResult {
        let scratch = Scratch::new("read-unknown-variant")?;
        let image = vec![0x5E_u8; 2048];

        // `_variantPayload`: [idx][vlen][variant], and no alt field at all.
        let name = b"unknown";
        let mut payload = vec![0x00_u8, 0x07];
        payload.extend_from_slice(name);
        assert_eq!(payload, b"\x00\x07unknown".to_vec());

        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&image)]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;

        let (status, body) = conn.response().ok_or("one response frame")?;
        assert_eq!(status, Status::Ok, "{:?}", conn.error_text());
        assert_eq!(&body[..image.len()], image.as_slice(), "the whole alt came back");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The staging file's mode, at the level of the command: the file the
    /// image passed through is gone by the time the reply is sent, and while it existed
    /// it was 0600 (pinned in `staging.rs`).
    #[test]
    fn the_staging_file_does_not_outlive_the_read() -> TestResult {
        let scratch = Scratch::new("read-staging")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x77; 2048])]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;
        assert_eq!(conn.response().map(|(status, _)| status), Some(Status::Ok));

        let left_behind: Vec<_> = std::fs::read_dir(scratch.root())?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(left_behind.is_empty(), "a flash image was left in {left_behind:?}");
        Ok(())
    }

    /// The refusal for an alt that answers nothing (`dfu-remote/main.c:689`).
    #[test]
    fn rpc_read_empty_data_is_refused() -> TestResult {
        let scratch = Scratch::new("read-empty")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[])]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;
        assert_eq!(conn.error_text().as_deref(), Some(EMPTY));
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// A `READ` streams its reply, so the image is never held whole: the handler has
    /// answered by the time it returns, and the one final frame is the data and its CRC.
    /// The 64 MiB exemption a NAND alt 0 needs is `Conn::begin_reply`'s, pinned on the
    /// wire in `tests/transport.rs`.
    #[test]
    fn rpc_read_streams_its_reply() -> TestResult {
        let scratch = Scratch::new("read-streamed")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x01; 512])]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        let reply = block_on(super::handle(&mut conn, &mut state, 0, &[], None))?;
        assert_eq!(reply, crate::commands::Reply::Sent);
        let mut expected = vec![0x01_u8; 512];
        expected.extend_from_slice(&tdfu_proto::crc32(&expected).to_be_bytes());
        assert_eq!(conn.response(), Some((tdfu_proto::Status::Ok, expected)));
        Ok(())
    }

    /// An upload has no knowable total until the short block ends it, so its
    /// frames carry the count and a percent of 0.
    #[test]
    fn a_read_sends_upload_progress_frames() -> TestResult {
        let scratch = Scratch::new("read-progress")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x33; 9000])]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;

        let frames = conn.progress_frames();
        assert!(!frames.is_empty());
        assert!(
            frames.iter().all(|body| body.stage == 5),
            "the upload phase: {frames:?}"
        );
        assert!(
            frames.iter().all(|body| body.percent == 0),
            "no knowable total: {frames:?}"
        );
        // And the count says so too: `9000 bytes`, never `9000/4294967291 bytes`. The
        // ceiling is the sink's guard, not a total the frames report. Revert check: pass
        // `Some(CEILING)` as `ops::read`'s limit and every message grows a denominator.
        assert!(
            frames.iter().all(|body| !body.message.contains('/')),
            "a read reports no total: {frames:?}"
        );
        assert_eq!(
            frames.last().map(|body| body.message.as_str()),
            Some("9000 bytes"),
            "{frames:?}"
        );
        assert!(
            conn.log_lines().iter().any(|line| line.contains("Read complete")),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// The ceiling is enforced by the tee, on whole blocks: the block that would pass
    /// it is refused, the file holds only whole blocks, the CRC covers exactly those,
    /// and the refusal is marked apart from any other sink failure so the handler can
    /// answer it in its own words.
    #[test]
    fn the_tee_refuses_the_block_that_would_pass_the_ceiling() -> TestResult {
        use std::io::Write as _;

        let mut sink = Vec::new();
        let mut crc = tdfu_proto::Crc32::new();
        let (capped, written) = {
            let mut tee = super::Tee::new(&mut sink, &mut crc, 8);
            assert_eq!(tee.write(b"abcde")?, 5);
            assert!(!tee.capped());
            let refused = tee.write(b"fghij");
            assert!(refused.is_err(), "5 + 5 passes a ceiling of 8");
            assert_eq!(tee.write(b"fgh")?, 3, "a block that fits is still taken");
            assert!(tee.write(b"i").is_err(), "and nothing fits past the ceiling");
            (tee.capped(), tee.written())
        };
        assert!(capped);
        assert_eq!(written, 8);
        assert_eq!(sink, b"abcdefgh");
        assert_eq!(crc.finalize(), crc32(b"abcdefgh"));
        Ok(())
    }

    /// The tee keeps the file and the CRC in step, and **both** of its `Write` methods
    /// carry their sink's failure rather than swallowing it.
    ///
    /// A CRC computed over bytes the file refused would certify an image nobody has, so
    /// the update happens only after the write succeeds. `File::flush` cannot fail,
    /// which is why this drives the tee over a writer that can.
    #[test]
    fn the_tee_keeps_the_crc_in_step_with_the_sink() -> TestResult {
        use std::io::Write as _;

        /// A writer that takes `allow` bytes and then refuses everything, flush too.
        struct Flaky {
            taken: Vec<u8>,
            allow: usize,
        }

        impl std::io::Write for Flaky {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.taken.len() + buf.len() > self.allow {
                    return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
                }
                self.taken.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                if self.taken.len() >= self.allow {
                    return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
                }
                Ok(())
            }
        }

        let mut sink = Flaky {
            taken: Vec::new(),
            allow: 4,
        };
        let mut crc = tdfu_proto::Crc32::new();
        {
            let mut tee = super::Tee::new(&mut sink, &mut crc, super::CEILING);
            assert_eq!(tee.write(b"abcd")?, 4);
            assert!(!tee.capped(), "a sink refusal is not the ceiling");
            assert!(tee.flush().is_err(), "a flush failure must be reported, not swallowed");
            assert!(tee.write(b"efgh").is_err(), "and so must a write failure");
        }
        assert_eq!(sink.taken, b"abcd", "the refused bytes never reached the sink");
        assert_eq!(
            crc.finalize(),
            crc32(b"abcd"),
            "and the CRC covers exactly the bytes that did"
        );
        Ok(())
    }

    /// A device that never ends its upload is stopped at the ceiling and answered, in
    /// the handler's own words, with where it stopped: whole blocks only, so the count
    /// is a block boundary.
    #[test]
    fn a_device_that_never_ends_its_upload_is_answered_at_the_ceiling() -> TestResult {
        let scratch = Scratch::new("read-ceiling")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x33; 9000])]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        let reply = block_on(super::handle_within(&mut conn, &mut state, 0, &[], None, 4096))?;

        let super::Reply::Error(message) = reply else {
            return Err("a read past the ceiling must be refused".into());
        };
        assert_eq!(
            message,
            "read stopped at 4096 bytes: this alt is larger than one reply can carry, and the device \
             sent no end of data within it"
        );
        assert!(
            conn.progress_frames().iter().all(|body| !body.message.contains('/')),
            "no total was ever claimed: {:?}",
            conn.progress_frames()
        );
        Ok(())
    }

    /// The cap and the reply's length field agree exactly.
    ///
    /// The OK payload is the image **plus** its four CRC bytes, and `payload_len` is a
    /// `u32`. A cap four bytes too generous produces a reply the header cannot describe,
    /// which the transport answers by dropping the connection with no error frame: the
    /// client sees a hang after a full-length read. So the arithmetic is the property,
    /// and it is checked here rather than left to a 4 GiB device no fixture can build.
    #[test]
    fn the_read_cap_is_what_one_reply_can_carry() {
        assert_eq!(super::CEILING + 4, u64::from(u32::MAX));
        assert!(u32::try_from(super::CEILING + 4).is_ok(), "exactly the largest reply");
        assert!(
            u32::try_from(super::CEILING + 5).is_err(),
            "and one byte more cannot be described"
        );
    }

    /// A staging directory that cannot be written names the OS's reason rather than the
    /// C's flat `"failed to create temp file"` (`dfu-remote/main.c:645`).
    #[test]
    fn an_unwritable_staging_directory_says_why() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x01; 512])]);
        let mut state = daemon(backend, std::path::Path::new("/definitely/not/a/directory"));
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &payload))?;
        let message = conn.error_text().ok_or("an unwritable staging dir must be refused")?;
        assert!(message.starts_with("read failed: File I/O error: "), "{message}");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    // ------------------------------------------------------------ two passes

    fn read_payload() -> Result<Vec<u8>, tdfu_proto::ProtoError> {
        Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()
    }

    /// **A daemon with no disk answers a `READ` all the same**: the alt is read once for
    /// its length and CRC and once into the reply. The staging directory here does not
    /// exist, so a staging file would have failed the read.
    #[test]
    fn a_two_pass_read_needs_no_staging_file() -> TestResult {
        let image: Vec<u8> = (0..9000_u32).map(|at| (at % 247) as u8).collect();
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&image)]);
        let mut state =
            daemon(backend, std::path::Path::new("/nonexistent-staging-dir")).with_read_staging(ReadStaging::TwoPass);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(dispatch(&mut conn, &mut state, Command::Read, &read_payload()?))?;

        let mut expected = image.clone();
        expected.extend_from_slice(&crc32(&image).to_be_bytes());
        assert_eq!(conn.response(), Some((Status::Ok, expected)), "{:?}", conn.error_text());
        assert!(
            matches!(conn.sent().last(), Some(Sent::Response(..))),
            "nothing follows the reply"
        );
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The progress a client watches is the first pass's, and only the first's: the
    /// second is inside the reply, where no other frame may go. A staged read sends the
    /// same frames.
    #[test]
    fn a_two_pass_read_reports_one_pass_of_progress() -> TestResult {
        let image = vec![0x33_u8; 9000];
        let mut frames = Vec::new();
        for staging in [ReadStaging::File, ReadStaging::TwoPass] {
            let scratch = Scratch::new("read-two-pass-progress")?;
            let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&image)]);
            let mut state = daemon(backend, scratch.root()).with_read_staging(staging);
            block_on(seen(&mut state))?;
            let mut conn = LoopbackConn::raw();
            block_on(dispatch(&mut conn, &mut state, Command::Read, &read_payload()?))?;
            assert!(conn.response().is_some_and(|(status, _)| status == Status::Ok));
            frames.push(conn.progress_frames());
        }
        assert!(!frames[0].is_empty());
        assert_eq!(frames[0], frames[1]);
        Ok(())
    }

    /// An alt that answers nothing is refused after the first pass, before any reply.
    #[test]
    fn a_two_pass_read_of_nothing_is_refused() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[])]);
        let mut state =
            daemon(backend, std::path::Path::new("/nonexistent-staging-dir")).with_read_staging(ReadStaging::TwoPass);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Read, &read_payload()?))?;
        assert_eq!(conn.error_text().as_deref(), Some(EMPTY));
        Ok(())
    }
}
