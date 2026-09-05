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

use std::io::{Read, Write};

use tdfu_core::clock::Sleeper;
use tdfu_core::{Error, ops};
use tdfu_proto::{Command, Crc32};
use tdfu_usb::LocalUsbBackend;

use super::device::{Target, await_gadget};
use super::report::{Queue, pump};
use super::staging::Staged;
use super::state::{Activity, DaemonState};
use super::{Reply, Wire, parse_alt, variant_field};
use crate::errors::{DaemonError, wire_message};

/// The empty-image refusal (`dfu-remote/main.c:689`).
const EMPTY: &str = "read returned empty data";

/// The most an upload may take, in bytes.
///
/// `CMD_READ`'s OK payload is exempt from the 64 MiB cap, because a NAND alt 0 is
/// 256 MiB, but it is not exempt from the frame header: `payload_len` is a `u32`, and
/// this reply carries the image plus a four-byte CRC. So the image itself can be at most
/// `u32::MAX - 4`, and a device that has not ended the upload by then is answered rather
/// than followed until a disk fills.
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
        let mut tee = Tee {
            sink: file,
            crc: &mut crc,
        };
        pump(
            conn,
            Command::Read,
            &queue,
            // The request has no length field, so the alt is read to its short block,
            // but a device that never sends one would stream until the filesystem
            // filled, with the daemon single-threaded and wholly occupied by it. The cap
            // is what this reply can carry: the payload length on the wire is a `u32`
            // and four of those bytes are the CRC.
            ops::read(&gadget.device, &state.clock, &alt, Some(CEILING), &mut tee, &mut sink),
        )
        .await?
    };

    let total = match outcome {
        Ok(total) => total,
        Err(error) => return Ok(Reply::failed("read", &error)),
    };
    if total == 0 {
        return Ok(Reply::Error(EMPTY.to_owned()));
    }
    // Refused here, before the image is read back into memory: the alternative is to
    // stage the whole of it, double it in RAM, and only then find that the length field
    // cannot describe it, which the transport answers by dropping the connection with
    // no error frame at all.
    if total >= CEILING {
        return Ok(Reply::Error(format!(
            "read stopped at {total} bytes: this alt is larger than one reply can carry, \
             and the device sent no end of data within it"
        )));
    }

    // The seam's `respond` takes a slice, so the image is read back into memory to be
    // answered. The C does the same and then keeps a *second* copy — `read_data` at
    // `dfu-remote/main.c:692` plus `resp` at `:714`, about 512 MiB peak for a 256 MiB
    // T40XP chip. This builds one buffer and appends four bytes to it.
    //
    // **The stated baseline is one copy of the image**, and it is what a later streaming
    // `respond` has to be measured against (recorded as Known-open in the
    // contracts). None of the three transports copies it again: `raw.rs:51`, `ws.rs:159`
    // and `http.rs:186` each `write_all` the parts in turn behind a header they size
    // arithmetically. Streaming needs a fifth `Wire` method taking a length and a reader,
    // which is a seam amendment rather than a defect fix; `Staged`'s `Drop` already
    // answers the ownership half of it.
    let path = staged.finish().to_path_buf();
    let mut payload = match read_back(&path, total) {
        Ok(payload) => payload,
        Err(error) => return Ok(Reply::failed("read", &Error::Io(error))),
    };
    payload.extend_from_slice(&crc.finalize().to_be_bytes());
    tracing::debug!(total, "read complete");
    Ok(Reply::Bulk(payload))
}

/// Read the staged image back, with room for the four CRC bytes already reserved.
///
/// **This blocks the runtime thread, deliberately**: up to 256 MiB for a
/// T40XP NAND alt, and `Staged::create`, `Tee::write` and `loader::resolve(…).read()` are
/// blocking too. Safe because everything is serialised: the accept loop
/// handles one connection to completion and the current-thread runtime has no other task
/// to starve. What it does cost is that no timer fires for the duration, so a `Timeouts`
/// deadline armed elsewhere would not tick while this runs. `spawn_blocking` is not the
/// answer: it needs a `Send` future, which decision D1 rules out.
fn read_back(path: &std::path::Path, total: u64) -> std::io::Result<Vec<u8>> {
    let capacity = usize::try_from(total).unwrap_or(usize::MAX).saturating_add(4);
    let mut payload = Vec::with_capacity(capacity);
    std::fs::File::open(path)?.read_to_end(&mut payload)?;
    Ok(payload)
}

/// A sink that writes to the staging file and feeds the CRC at the same time.
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
}

impl<W: Write> Write for Tee<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // `write_all`, not `write`: a short write here would desynchronise the CRC from
        // the file, and `ops::read` treats a sink failure as final
        // rather than restarting the chip read the way `dfu.c:839-842` does.
        //
        // The CRC is updated **after** the write succeeds, and only then, for the same
        // reason: a checksum over bytes that never reached the file would certify an
        // image nobody has.
        self.sink.write_all(buf)?;
        self.crc.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::EMPTY;
    use crate::commands::fake::{FakeBackend, LoopbackConn, Scratch, TestResult};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::{Activity, DaemonState, Window};
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

    /// A `READ` OK payload is exempt from the 64 MiB cap, and the exemption
    /// is expressed as `Reply::Bulk` rather than as a missing check.
    #[test]
    fn rpc_read_answers_with_a_bulk_reply() -> TestResult {
        let scratch = Scratch::new("read-bulk")?;
        let backend = FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x01; 512])]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        let reply = block_on(super::handle(&mut conn, &mut state, 0, &[], None))?;
        assert!(matches!(reply, crate::commands::Reply::Bulk(_)), "{reply:?}");
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
        assert!(
            conn.log_lines().iter().any(|line| line.contains("DFU upload complete")),
            "{:?}",
            conn.log_lines()
        );
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
            let mut tee = super::Tee {
                sink: &mut sink,
                crc: &mut crc,
            };
            assert_eq!(tee.write(b"abcd")?, 4);
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
}
