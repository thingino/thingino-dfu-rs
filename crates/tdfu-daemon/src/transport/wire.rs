//! The timed byte stream all three transports sit on.
//!
//! **This file is where a silent peer stops being able to wedge the daemon.** The C has
//! no timeout of any kind (no `SO_RCVTIMEO`, no `SO_SNDTIMEO`, no `poll`, no
//! `select` and no `alarm` anywhere in `dfu-remote/`) and it pairs that with
//! `listen(server_fd, 1)` (`dfu-remote/main.c:1108`) and an accept loop that serves one
//! client to completion before accepting the next (`:1119-1156`). One connection that
//! opens and sends nothing therefore wedges every other client for ever. That is a C
//! defect and it is fixed here; the bench has hit it.
//!
//! Every read and every write goes through here, so there is no path that can forget.

use core::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::error::DaemonError;

/// How much is read from the socket in one go.
const CHUNK: usize = 16 * 1024;

/// The three deadlines, and what each one is for.
///
/// They are **on by default** (`Timeouts::DEFAULT`). An idle timeout is an *addition*
/// to the C's options, never a changed default that a shipped client
/// relies on, and no client relies on being allowed to stall for ever.
///
/// `None` disables one. `--idle-timeout 0` is how an operator asks for the C's
/// behaviour back; it is not the default, and it is not advisable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Bounds everything in [`Conn::accept`](super::Conn::accept) that is *negotiation*:
    /// the first-byte sniff, the WebSocket upgrade's header block, the HTTP request's
    /// header block, and the token handshake. Every read in those, not just the first —
    /// they are all small, and a peer with nothing to say should not get the deadline a
    /// 64 MiB transfer needs.
    ///
    /// The one thing in `accept` it does **not** bound is the HTTP request body, which is
    /// a transfer like any other and takes [`Timeouts::read`]: the browser flasher POSTs a
    /// whole firmware image in one.
    ///
    /// This is the deadline that matters for bug 18. With one client at a time, a peer
    /// that connects and says nothing holds the listener for exactly this long.
    pub handshake: Option<Duration>,
    /// A no-progress bound on a single read **or write** once a frame is in flight.
    ///
    /// Not a bound on the whole transfer: a 64 MiB `CMD_WRITE` over a slow link is
    /// legitimate and must not be cut off. What is not legitimate is a peer that
    /// announces 64 MiB and then sends nothing for a minute.
    pub read: Option<Duration>,
    /// How long an established connection may sit between commands.
    ///
    /// Generous, because a raw or WebSocket client may hold a connection open across a
    /// human pause: one connection carries many commands.
    pub idle: Option<Duration>,
}

impl Timeouts {
    /// The defaults: 10 s to get established, 60 s of no progress mid-frame, 300 s idle.
    pub const DEFAULT: Self = Self {
        handshake: Some(Duration::from_secs(10)),
        read: Some(Duration::from_secs(60)),
        idle: Some(Duration::from_secs(300)),
    };

    /// Every deadline off — the C's posture, for an operator who asks for it explicitly.
    pub const OFF: Self = Self {
        handshake: None,
        read: None,
        idle: None,
    };
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How much one second of the whole-write budget buys.
///
/// 64 KiB/s is slower than any link a firmware image is pushed over, so the budget cuts
/// off nothing that was making progress; it exists so that some finite number bounds one
/// write, which a per-write no-progress deadline does not.
const WRITE_BUDGET_BYTES_PER_SECOND: u64 = 64 * 1024;

/// The whole-write deadline for `length` bytes: the no-progress deadline as a floor, plus
/// a second for every [`WRITE_BUDGET_BYTES_PER_SECOND`].
///
/// A 256 MiB `CMD_READ` answer, the largest reply there is, comes to a little over an
/// hour, so a working transfer is never cut off; a peer that cannot sustain 64 KiB/s is.
/// `None` when the no-progress deadline is off, because `--read-timeout 0` is an operator
/// asking for the C's posture back and this is one of the deadlines they switch off.
fn write_budget(read: Option<Duration>, length: usize) -> Option<Duration> {
    let length = u64::try_from(length).unwrap_or(u64::MAX);
    read.map(|floor| floor.saturating_add(Duration::from_secs(length.div_ceil(WRITE_BUDGET_BYTES_PER_SECOND))))
}

/// Which deadline applies to which byte of one read.
///
/// Two, because the two cases genuinely differ. Waiting for the *first* byte of the next
/// request on an idle connection is a long, patient wait; waiting for the *rest* of a
/// frame the peer has already begun is a short one. Making both explicit at every call
/// site is what stops a negotiation quietly inheriting the deadline a 64 MiB transfer
/// needs — which it did here until a test that dribbled four bytes and stopped took
/// thirty seconds to notice.
///
/// Each deadline is per read, not for the whole buffer: a slow but progressing transfer
/// must never be cut off. A peer making steady slow progress is not the hung peer these
/// deadlines are about, and is not treated as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Deadlines {
    /// For the first byte.
    pub(crate) first: Option<Duration>,
    /// For every byte after it.
    pub(crate) rest: Option<Duration>,
}

impl Deadlines {
    /// The same deadline throughout — for anything small enough that no part of it has a
    /// reason to stall: a header block, a handshake, a frame header.
    pub(crate) const fn uniform(within: Option<Duration>) -> Self {
        Self {
            first: within,
            rest: within,
        }
    }

    /// A patient wait for the first byte and a brisk one for the rest.
    pub(crate) const fn split(first: Option<Duration>, rest: Option<Duration>) -> Self {
        Self { first, rest }
    }
}

/// How a read that asked for a whole buffer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filled {
    /// Every byte arrived.
    Whole,
    /// The peer closed. `0` means it closed cleanly between frames; anything else is a
    /// half-close part-way through something it had committed to sending.
    Eof(usize),
}

/// A `TcpStream` with deadlines and a read-ahead buffer.
///
/// The read-ahead exists because the HTTP and WebSocket header blocks end in the middle
/// of a stream whose remainder belongs to the body or to the frame codec. Reading a
/// chunk at a time and keeping the tail is how the split stays exact; the C reads those
/// headers one byte at a time to dodge the same problem
/// (`dfu-remote/main.c:908-915`, `ws.c:180-187`).
#[derive(Debug)]
pub(crate) struct Wire {
    stream: TcpStream,
    timeouts: Timeouts,
    buffered: Vec<u8>,
    offset: usize,
}

impl Wire {
    /// Wrap a stream.
    pub(crate) const fn new(stream: TcpStream, timeouts: Timeouts) -> Self {
        Self {
            stream,
            timeouts,
            buffered: Vec::new(),
            offset: 0,
        }
    }

    /// The deadlines in force.
    pub(crate) const fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// Who is on the other end, when the socket can say.
    pub(crate) fn peer(&self) -> Option<core::net::SocketAddr> {
        self.stream.peer_addr().ok()
    }

    /// Bytes already read from the socket and not yet consumed.
    fn ready(&self) -> &[u8] {
        self.buffered.get(self.offset..).unwrap_or(&[])
    }

    /// One read from the socket into the read-ahead buffer. `Ok(0)` is EOF.
    async fn pull(&mut self, within: Option<Duration>, doing: &'static str) -> Result<usize, DaemonError> {
        if self.offset > 0 {
            self.buffered.drain(..self.offset);
            self.offset = 0;
        }
        let start = self.buffered.len();
        self.buffered.resize(start + CHUNK, 0);
        let slot = self.buffered.get_mut(start..).unwrap_or(&mut []);
        let read = match within {
            Some(limit) => {
                let Ok(result) = tokio::time::timeout(limit, self.stream.read(slot)).await else {
                    self.buffered.truncate(start);
                    return Err(DaemonError::TimedOut { doing, after: limit });
                };
                result
            }
            None => self.stream.read(slot).await,
        };
        let got = read.inspect_err(|_| self.buffered.truncate(start))?;
        self.buffered.truncate(start + got);
        // The invariant every caller loops on: a pull that read bytes has bytes ready.
        // `read_exact` and `read_header_block` both call this *because* `ready()` was
        // empty and go straight back round, so a `pull` that reports progress without
        // producing any spins for ever. `cargo mutants` found three mutations here that
        // do exactly that (`ready` emptied, `pull` returning a constant, the `+` in the
        // truncate above), and every one of them **hung** the suite instead of failing
        // it. `report::pump` carries the same `debug_assert` for the same four-mutant
        // reason; a hang burns a slot and reports nothing, which is how a live survivor
        // gets written off as machine load.
        debug_assert!(
            got == 0 || !self.ready().is_empty(),
            "pull read {got} bytes and left nothing ready; the caller's loop would spin"
        );
        Ok(got)
    }

    /// Fill `buf` completely, or say where the peer stopped.
    ///
    /// [`Deadlines`] says which bound applies to the first byte and which to the rest, so
    /// a slow-but-alive transfer is never cut off while a stalled one is.
    pub(crate) async fn read_exact(
        &mut self,
        buf: &mut [u8],
        deadlines: Deadlines,
        doing: &'static str,
    ) -> Result<Filled, DaemonError> {
        let mut done = 0;
        while done < buf.len() {
            let ready = self.ready();
            if ready.is_empty() {
                let within = if done == 0 { deadlines.first } else { deadlines.rest };
                let got = self.pull(within, doing).await?;
                if got == 0 {
                    return Ok(Filled::Eof(done));
                }
                // Checked **here** and not only inside `pull`, because a mutation that
                // replaces `pull`'s whole body takes its own assertions with it and
                // leaves this loop calling a function that reports progress and produces
                // none. That is a spin, and `cargo mutants` produced it.
                debug_assert!(
                    !self.ready().is_empty(),
                    "pull reported {got} bytes and left none ready; this loop would spin"
                );
                continue;
            }
            let take = ready.len().min(buf.len() - done);
            // Both operands are positive here: `ready` is not empty and the loop
            // condition says `done < buf.len()`.
            debug_assert!(take > 0, "read_exact took nothing from a buffer that had bytes");
            let Some(target) = buf.get_mut(done..done + take) else {
                break;
            };
            let Some(source) = ready.get(..take) else { break };
            target.copy_from_slice(source);
            let before = done;
            self.offset += take;
            done += take;
            debug_assert!(
                done > before,
                "read_exact copied {take} bytes without advancing; this loop would spin"
            );
        }
        Ok(Filled::Whole)
    }

    /// Fill `buf` completely or fail: a short read is the peer half-closing mid-request.
    pub(crate) async fn read_all_of(
        &mut self,
        buf: &mut [u8],
        deadlines: Deadlines,
        doing: &'static str,
    ) -> Result<(), DaemonError> {
        let want = buf.len();
        match self.read_exact(buf, deadlines, doing).await? {
            Filled::Whole => Ok(()),
            Filled::Eof(got) => Err(DaemonError::Truncated { doing, got, want }),
        }
    }

    /// Read and discard `count` bytes.
    ///
    /// The connection stays open after an unknown command, and a reader that
    /// means to honour that has to reach the next header. `RequestHeader::decode`
    /// applies the 64 MiB cap *before* the command byte, so `count` is bounded by
    /// construction and a hostile peer cannot turn an unknown command into an unbounded
    /// read.
    pub(crate) async fn discard(&mut self, count: u64, doing: &'static str) -> Result<(), DaemonError> {
        let want = usize::try_from(count).unwrap_or(usize::MAX);
        // On the heap, not in the future: a 16 KiB array here lands in every enclosing
        // async frame (`clippy::large_futures`), and this one is six levels deep.
        let mut scratch = vec![0_u8; want.min(CHUNK)];
        let mut left = count;
        while left > 0 {
            let take = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
            if take == 0 {
                // `CHUNK` at zero, and the loop spins for ever: see the twin in
                // `Conn::discard`. Breaking makes a zeroed constant fail a test rather
                // than hang one.
                break;
            }
            let Some(slot) = scratch.get_mut(..take) else { break };
            match self
                .read_exact(slot, Deadlines::uniform(self.timeouts.read), doing)
                .await?
            {
                Filled::Whole => left -= take as u64,
                Filled::Eof(got) => {
                    return Err(DaemonError::Truncated {
                        doing,
                        got: want.saturating_sub(usize::try_from(left).unwrap_or(0)) + got,
                        want,
                    });
                }
            }
        }
        Ok(())
    }

    /// Read up to and including the first `\r\n\r\n`, leaving anything after it buffered.
    ///
    /// The `limit` is on the header block alone. The C uses `char req[8192]` for both
    /// (`dfu-remote/main.c:906`, `ws.c:178`) and, on overflow, simply stops reading and
    /// parses whatever it has — so a peer that never sends a blank line gets its
    /// truncated headers *interpreted*. Here it is refused.
    /// `within` bounds **every** read here, not just the first. A header block is a few
    /// hundred bytes and there is no legitimate reason for any part of one to stall; the
    /// no-progress deadline that a 64 MiB transfer needs would let a peer dribble one byte
    /// and hold the single-client listener for a minute per byte.
    pub(crate) async fn read_header_block(
        &mut self,
        limit: usize,
        within: Option<Duration>,
    ) -> Result<Vec<u8>, DaemonError> {
        let mut scanned = 0;
        loop {
            if let Some(end) = find_blank_line(self.ready(), scanned) {
                let block = self.ready().get(..end).unwrap_or(&[]).to_vec();
                self.offset += end;
                return Ok(block);
            }
            scanned = self.ready().len().saturating_sub(3);
            if self.ready().len() >= limit {
                return Err(DaemonError::HeadersTooLong { limit });
            }
            let got = self.pull(within, "request headers").await?;
            if got == 0 {
                return Err(DaemonError::Truncated {
                    doing: "request headers",
                    got: self.ready().len(),
                    want: limit,
                });
            }
            // `read_exact`'s guard, for this loop: a `pull` that reports progress and
            // produces none never reaches the blank line or the limit, and spins.
            debug_assert!(
                !self.ready().is_empty(),
                "pull reported {got} bytes and left none ready; this loop would spin"
            );
        }
    }

    /// Write every byte, under two bounds: [`Timeouts::read`] as a **no-progress**
    /// deadline on each `write`, and [`write_budget`] on the whole call.
    ///
    /// A peer that stops reading stalls the daemon's writes exactly as a peer that stops
    /// writing stalls its reads, and the C bounds neither.
    ///
    /// The no-progress deadline alone is not enough, because it starts over on every byte:
    /// a peer that reads one byte just before each deadline drains the response as slowly
    /// as it likes and never trips it, holding the DFU interface claimed and the device
    /// mid-download for as long as it cares to. So the whole write is bounded too, by a
    /// budget scaled to its length. The scaling is why a `CMD_READ` answer (a whole flash,
    /// 256 MiB on a T40XP, exempt from the payload cap precisely so it can be that big) is
    /// not aborted for running longer than one deadline: the budget grows with the
    /// transfer, while a peer that cannot sustain 64 KiB/s is cut off. A single flat
    /// deadline over the whole write was tried first, and `a_read_may_answer_past_the_cap`
    /// failed only when the machine was busy: the shape of a bug that gets dismissed as a
    /// flaky test.
    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> Result<(), DaemonError> {
        let budget = write_budget(self.timeouts.read, bytes.len());
        let started = tokio::time::Instant::now();
        let mut sent = 0;
        while sent < bytes.len() {
            let Some(rest) = bytes.get(sent..) else { break };
            let wrote = match (self.timeouts.read, budget) {
                (Some(floor), Some(budget)) => {
                    // The whole call is bounded by `budget` and each write by the
                    // no-progress `floor`; a write waits for whichever is nearer, so the
                    // total cannot outrun the budget even while every syscall makes just
                    // enough progress to keep the floor from firing.
                    let Some(remaining) = budget.checked_sub(started.elapsed()).filter(|left| !left.is_zero()) else {
                        return Err(DaemonError::TimedOut {
                            doing: "response",
                            after: budget,
                        });
                    };
                    let within = floor.min(remaining);
                    let Ok(result) = tokio::time::timeout(within, self.stream.write(rest)).await else {
                        // Name the bound that fired: the budget when it was the nearer one,
                        // the no-progress floor otherwise.
                        let after = if within == remaining { budget } else { floor };
                        return Err(DaemonError::TimedOut {
                            doing: "response",
                            after,
                        });
                    };
                    result?
                }
                // `--read-timeout 0`: the C's posture, no bound on either.
                _ => self.stream.write(rest).await?,
            };
            if wrote == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            sent += wrote;
        }
        Ok(())
    }
}

/// Where the `\r\n\r\n` ends, searching from `from` so a scan is not quadratic.
fn find_blank_line(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| from + at + 4)
}

#[cfg(test)]
mod tests {
    use super::{CHUNK, Deadlines, Filled, Timeouts, Wire, find_blank_line, write_budget};
    use core::time::Duration;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::{TcpListener, TcpStream};

    type TestResult = Result<(), Box<dyn core::error::Error>>;

    /// Long enough that no legitimate read here can reach it, short enough that a read
    /// which should not have happened **fails** instead of hanging.
    ///
    /// These tests are about bytes, not about deadlines, and they used to pass `None`.
    /// `cargo mutants` then found that widening `read_exact`'s loop bound sends it round
    /// once more with the buffer already full, where it blocks on a socket that owes it
    /// nothing: no assertion can pre-empt a blocking read, but a deadline can. Deadlines
    /// are on by default in the daemon anyway (`Timeouts::DEFAULT`), so a finite one here
    /// is also the truer fixture; `Timeouts::OFF` is pinned separately.
    fn patient() -> Deadlines {
        Deadlines::uniform(Some(Duration::from_secs(10)))
    }

    /// A connected pair on loopback: the `Wire` under test, and the peer's end.
    async fn pair(timeouts: Timeouts) -> Result<(Wire, TcpStream), Box<dyn core::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let client = TcpStream::connect(address).await?;
        let (server, _) = listener.accept().await?;
        Ok((Wire::new(server, timeouts), client))
    }

    /// **The drain pin.** `dfu-remote/ws.c:308-310` reads the first 125 bytes of an
    /// oversize control payload and leaves the rest in the stream, so everything after it
    /// is parsed out of the middle of that payload. `discard` must consume exactly what it
    /// was told to and leave the next byte where the peer put it.
    #[tokio::test]
    async fn the_read_ahead_buffer_is_compacted_as_it_is_consumed() -> TestResult {
        // A raw client may hold one connection open for many commands, so a
        // read-ahead that never drops what it has handed over is an unbounded leak on the
        // daemon's normal case. Found by `cargo mutants`: neutering the compaction guard
        // in `pull` changed no observable byte and survived the whole suite.
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        let bulk = 64 * 1024;
        tokio::spawn(async move {
            let _sent = peer.write_all(&vec![0x7E_u8; bulk]).await;
            peer
        });

        let mut sink = [0_u8; 1024];
        let mut taken = 0;
        while taken < bulk {
            wire.read_all_of(&mut sink, patient(), "bulk").await?;
            taken += sink.len();
            assert!(
                wire.buffered.len() <= 2 * CHUNK,
                "the read-ahead held {} bytes after {taken} consumed; it is not being compacted",
                wire.buffered.len()
            );
        }
        Ok(())
    }

    /// The two deadlines have to reach the bytes they name. Nothing exercised
    /// [`Deadlines::split`] with *differing* halves — the only split call site is the
    /// request header, where the test fixture set idle and read to the same 300 ms — so
    /// swapping them was invisible (`cargo mutants`, `read_exact`'s `done == 0`).
    #[tokio::test]
    async fn the_first_byte_and_the_rest_take_different_deadlines() -> TestResult {
        let timeouts = Timeouts {
            handshake: None,
            read: Some(Duration::from_millis(200)),
            idle: Some(Duration::from_secs(5)),
        };
        let (mut wire, mut peer) = pair(timeouts).await?;
        // Three bytes of a ten-byte header, then silence.
        peer.write_all(b"abc").await?;

        let started = std::time::Instant::now();
        let mut buf = [0_u8; 10];
        let outcome = wire
            .read_exact(
                &mut buf,
                Deadlines::split(timeouts.idle, timeouts.read),
                "request header",
            )
            .await;
        assert!(outcome.is_err(), "the rest of the header never arrived");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the rest of the frame waited on the idle deadline instead of the read one: {:?}",
            started.elapsed()
        );
        Ok(())
    }

    /// A truncated skip reports everything it got through, not just the last chunk.
    ///
    /// The truncation is in the **second** chunk on purpose (the same arithmetic as in
    /// `Conn::discard`): a peer that stops inside the *first* one
    /// leaves `want - left` at zero, so the "everything already skipped" term is zero too
    /// and dropping it changes nothing. Past `CHUNK` the two answers differ by exactly
    /// the 16 KiB that was already consumed.
    #[tokio::test]
    async fn a_truncated_discard_reports_everything_it_skipped() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        tokio::spawn(async move {
            let _sent = peer.write_all(&vec![0x11_u8; 20_000]).await;
            let _closed = peer.shutdown().await;
            peer
        });

        let outcome = wire.discard(40_000, "skipped payload").await;
        let message = match outcome {
            Err(error) => error.to_string(),
            Ok(()) => "expected a truncation".to_owned(),
        };
        assert!(message.contains("after 20000 of 40000 bytes"), "{message}");
        Ok(())
    }

    #[tokio::test]
    async fn discard_consumes_exactly_what_it_was_told_to() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        peer.write_all(&[0xAA_u8; 200]).await?;
        peer.write_all(b"SENTINEL").await?;

        wire.discard(200, "test payload").await?;

        let mut next = [0_u8; 8];
        assert_eq!(wire.read_exact(&mut next, patient(), "sentinel").await?, Filled::Whole);
        assert_eq!(&next, b"SENTINEL", "the drain stopped one byte short or one byte long");
        Ok(())
    }

    /// Draining more than one chunk, and past a write boundary.
    #[tokio::test]
    async fn discard_spans_chunks_and_writes() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        let bulk = 40 * 1024;
        tokio::spawn(async move {
            let _sent = peer.write_all(&vec![0x5A_u8; bulk]).await;
            let _tail = peer.write_all(b"END").await;
            peer
        });

        wire.discard(bulk as u64, "bulk").await?;
        let mut next = [0_u8; 3];
        assert_eq!(wire.read_exact(&mut next, patient(), "sentinel").await?, Filled::Whole);
        assert_eq!(&next, b"END");
        Ok(())
    }

    /// A peer that stops mid-buffer is `Eof(n)`, not a hang and not a lie.
    #[tokio::test]
    async fn a_half_close_reports_how_much_arrived() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        peer.write_all(b"1234").await?;
        peer.shutdown().await?;

        let mut buf = [0_u8; 10];
        assert_eq!(wire.read_exact(&mut buf, patient(), "frame").await?, Filled::Eof(4));
        assert_eq!(&buf[..4], b"1234", "the bytes that did arrive are still there");
        Ok(())
    }

    /// **The wedged listener at the byte level.** A peer that says nothing must
    /// hit the deadline rather than block for ever.
    #[tokio::test]
    async fn a_silent_peer_hits_the_deadline() -> TestResult {
        let timeouts = Timeouts {
            handshake: Some(Duration::from_millis(50)),
            read: Some(Duration::from_millis(50)),
            idle: Some(Duration::from_millis(50)),
        };
        let (mut wire, _peer) = pair(timeouts).await?;
        let mut buf = [0_u8; 1];
        let outcome = wire
            .read_exact(&mut buf, Deadlines::uniform(timeouts.idle), "request header")
            .await;
        let message = match outcome {
            Err(error) => error.to_string(),
            Ok(filled) => format!("expected a timeout, got {filled:?}"),
        };
        assert!(message.contains("nothing arrived for"), "{message}");
        assert!(message.contains("request header"), "{message}");
        Ok(())
    }

    /// The header block ends at the blank line and not a byte later: everything after it
    /// belongs to the body, or to the frame codec.
    #[tokio::test]
    async fn the_header_block_leaves_the_body_alone() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        peer.write_all(b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODY")
            .await?;

        let block = wire.read_header_block(8192, Some(Duration::from_secs(10))).await?;
        assert!(block.ends_with(b"\r\n\r\n"));
        assert!(block.starts_with(b"POST / HTTP/1.1\r\n"));

        let mut body = [0_u8; 4];
        assert_eq!(wire.read_exact(&mut body, patient(), "body").await?, Filled::Whole);
        assert_eq!(&body, b"BODY");
        Ok(())
    }

    /// The C stops reading at 8192 and parses whatever it has
    /// (`dfu-remote/main.c:908-915`), so a peer that never sends a blank line gets its
    /// truncated headers interpreted. Here it is refused.
    #[tokio::test]
    async fn a_header_block_that_never_ends_is_refused() -> TestResult {
        let (mut wire, mut peer) = pair(Timeouts::DEFAULT).await?;
        tokio::spawn(async move {
            let _sent = peer.write_all(&vec![b'x'; 4096]).await;
            peer
        });
        let outcome = wire.read_header_block(1024, Some(Duration::from_secs(10))).await;
        let message = match outcome {
            Err(error) => error.to_string(),
            Ok(block) => format!("expected a refusal, got {} bytes", block.len()),
        };
        assert!(message.contains("did not end within 1024 bytes"), "{message}");
        Ok(())
    }

    /// The timeouts are an addition, on by default. An earlier implementation shipped the C's
    /// `None` here, and a silent peer wedged the listener.
    #[test]
    fn rpc_daemon_timeouts_are_on_by_default() {
        let timeouts = Timeouts::default();
        assert_eq!(timeouts, Timeouts::DEFAULT);
        assert!(timeouts.handshake.is_some(), "a silent peer must not hold the listener");
        assert!(timeouts.read.is_some());
        assert!(timeouts.idle.is_some());

        // The handshake bound is the one that decides how long one silent connection can
        // hold the accept loop, so it is the short one.
        assert!(timeouts.handshake < timeouts.read);
        assert!(timeouts.read < timeouts.idle);
        assert_eq!(timeouts.handshake, Some(Duration::from_secs(10)));

        assert_eq!(Timeouts::OFF.handshake, None, "asked for explicitly, never a default");
        assert_eq!(Timeouts::OFF.read, None);
        assert_eq!(Timeouts::OFF.idle, None);
    }

    /// The write budget is finite, generous, and off only when the no-progress deadline
    /// is. It is what bounds a peer draining the response a byte at a time.
    #[test]
    fn the_write_budget_is_finite_and_grows_with_the_write() {
        let read = Some(Duration::from_secs(60));
        assert_eq!(write_budget(read, 0), Some(Duration::from_secs(60)), "the floor");
        assert_eq!(
            write_budget(read, 64 * 1024),
            Some(Duration::from_secs(61)),
            "a second per 64 KiB"
        );
        // A 256 MiB CMD_READ answer: a little over an hour, which no working transfer
        // reaches and no drained one outlives.
        let at_read = write_budget(read, 256 * 1024 * 1024).unwrap_or_default();
        assert!(
            at_read > Duration::from_secs(4096) && at_read < Duration::from_secs(4200),
            "{at_read:?}"
        );
        assert_eq!(write_budget(None, 256 * 1024 * 1024), None, "--read-timeout 0");
    }

    #[test]
    fn the_blank_line_is_found_where_it_is() {
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n\r\nbody", 0), Some(18));
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n\r\n", 0), Some(18));
        assert_eq!(find_blank_line(b"GET / HTTP/1.1\r\n", 0), None);
        assert_eq!(find_blank_line(b"", 0), None);
        // A lone \n\n is not a header terminator: the peer is still mid-block.
        assert_eq!(find_blank_line(b"GET /\n\n", 0), None);
        // Resuming a scan must not miss a terminator that straddles the resume point.
        assert_eq!(find_blank_line(b"a\r\n\r\nb", 1), Some(5));
    }
}
