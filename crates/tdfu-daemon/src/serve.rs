//! The accept loop, and the seam between the transport and the commands.
//!
//! One client at a time, as the C (`dfu-remote/main.c:1108`, `listen(fd, 1)`): a
//! connection is accepted, every request on it is dispatched, and only then is the
//! next accepted.
//!
//! # What a signal does, and why
//!
//! **The C's rule, with an escape hatch.** `signal_handler` only sets `g_running = 0`
//! and closes the *listening* socket (`main.c:89-98`); `handle_client`'s
//! `while (g_running)` is checked **between** commands (`:888-892`), so the
//! `tdfu_dfu_download` in flight runs to completion and the process exits after it. That
//! is the right shape and it is kept: a SIGINT during a `CMD_WRITE` that tore the DFU
//! download off the device mid-flash would leave a camera that does not boot, and the
//! client would never learn why.
//!
//! So the **first** signal stops accepting and races only the wait for the *next*
//! request; a dispatch already running finishes and the client gets its final frame,
//! after which the connection takes no further request. A **second** signal drops the
//! connection where it stands, which the C has no way to do at all: a device that has
//! stopped answering can hold a bulk transfer for the whole USB timeout, and an operator
//! who has pressed Ctrl-C twice has said what they mean.
//!
//! Dropping the connection is safe in either case, and that is a property the C does not
//! have: it drops whatever the command held, and for `READ` that is the staging file,
//! whose `Drop` removes it (`commands::staging::Staged`). The C's is left in the temp
//! directory, holding a flash image, mode 0600. `Busy` unwinds the same way, so the
//! state cannot stick.
//!
//! A connection that fails is logged and the loop continues. The C `break`s out of the
//! loop on a failed `accept` (`main.c:1123-1125`), which is how a signal ends it and
//! also how running out of file descriptors would; here a failed `accept` waits 100 ms
//! and tries again, and only a signal ends the loop.

use std::pin::pin;
use std::time::Duration;

use tdfu_core::clock::Sleeper;
use tdfu_proto::{Command, ProgressBody, Status};
use tdfu_usb::LocalUsbBackend;
use tokio::net::{TcpListener, TcpStream};

use crate::auth::Auth;
use crate::commands::state::DaemonState;
use crate::commands::{self, Wire};
use crate::transport::{Conn, DaemonError, Origins, Timeouts};

/// The four methods `dispatch` consumes, forwarded to the real connection one to one.
///
/// `commands::Wire` is a trait rather than `Conn` itself so the commands are tested
/// against a loopback double with no socket (`commands::fake::LoopbackConn`); this is
/// the one impl the binary uses. `a_chatty_command_reaches_the_client_through_a_real_conn`
/// drives all four through a socket.
///
/// **`logs_enabled_for` is double-gated here, on purpose, and that makes one mutant of it
/// equivalent.** `report::pump` asks this before it sends anything, and `Conn::log` and
/// `Conn::progress` ask `Conn::logs_enabled_for` again before they frame anything, so
/// forcing this forwarding to `true` changes no byte on the wire: `pump` would offer the
/// frames and the connection would drop them, unencoded. The forwarding is not redundant
/// for all that, because the *double* has no second gate and answers this alone; keeping
/// the transport's own gate is what stops a wrong answer here reaching a client.
impl Wire for Conn {
    async fn respond(&mut self, status: Status, payload: &[u8]) -> Result<(), DaemonError> {
        Conn::respond(self, status, payload).await
    }

    async fn log(&mut self, line: &str) -> Result<(), DaemonError> {
        Conn::log(self, line).await
    }

    async fn progress(&mut self, body: &ProgressBody) -> Result<(), DaemonError> {
        Conn::progress(self, body).await
    }

    fn logs_enabled_for(&self, cmd: Command) -> bool {
        Conn::logs_enabled_for(self, cmd)
    }
}

/// How long a failed `accept` rests before the next, so a host out of file
/// descriptors is a slow daemon rather than a busy loop of warnings.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Where the shutdown signals come from.
///
/// A **stream**, not one future, because the rule in this file's header needs to tell the
/// first signal from the second: one resolves the wait for the next request, the other
/// drops a dispatch in flight. `main.rs` implements it over SIGINT and SIGTERM; a test
/// implements it over a channel it drives by hand.
#[allow(
    async_fn_in_trait,
    reason = "AGENTS.md D1: ?Send is the point, and no async_trait crate"
)]
pub trait Signals {
    /// Wait for the next signal.
    ///
    /// **Must be cancel-safe.** The loops here drop this future every time another branch
    /// of a `select!` wins, and a signal that arrived meanwhile has to be seen by the
    /// call after it. A source that resolves only while it is being polled would let a
    /// Ctrl-C land in the gap between two `select!`s and be lost.
    async fn next(&mut self);
}

/// How a connection ended, as far as the accept loop is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The connection is over; the daemon takes the next client.
    Done,
    /// A signal arrived; the daemon stops.
    Stopped,
}

/// Serve clients until a signal ends it.
pub async fn serve<B, C, S>(
    listener: TcpListener,
    auth: &Auth,
    timeouts: Timeouts,
    origins: &Origins,
    state: &mut DaemonState<B, C>,
    mut signals: S,
) where
    B: LocalUsbBackend,
    C: Sleeper,
    S: Signals,
{
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    // The C's line, on stdout (`dfu-remote/main.c:1131`).
                    say(&format!("Connection from {peer}"));
                    stream
                }
                Err(error) => {
                    tracing::warn!("accept failed: {error}");
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
            },
            () = signals.next() => return,
        };
        if serve_connection(stream, auth, timeouts, origins, state, &mut signals).await == Ending::Stopped {
            return;
        }
        // The listing an index resolves against is the daemon's most recent DISCOVER, and
        // it outlives the connection that asked for it on purpose: the browser flasher
        // reaches this daemon over HTTP, one request per connection, so its DISCOVER,
        // BOOTSTRAP and WRITE each arrive on a fresh socket. What keeps a stale listing
        // from naming the wrong camera is not the connection boundary but the adoption
        // rule: a row is followed by bus and port on the live bus, and a device that has
        // left its port is refused, never replaced by whatever now sits at that index.
    }
}

/// One accepted stream, to its end. Never an error: a connection that fails is the
/// peer's problem, logged here, and the daemon goes on to the next.
pub async fn serve_connection<B, C, S>(
    stream: TcpStream,
    auth: &Auth,
    timeouts: Timeouts,
    origins: &Origins,
    state: &mut DaemonState<B, C>,
    signals: &mut S,
) -> Ending
where
    B: LocalUsbBackend,
    C: Sleeper,
    S: Signals,
{
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "?".to_owned(), |peer| peer.to_string());
    match drive(stream, auth, timeouts, origins, state, signals).await {
        Ok(ending) => ending,
        // A rejection was logged where it was decided (`Auth::check`), and the peer
        // has been answered; there is nothing left to say about it here.
        Err(DaemonError::AuthRejected { .. }) => Ending::Done,
        // A hang-up is not a misbehaviour. `DaemonError::is_peer_gone` states
        // this policy and had no caller, so a client that closed its laptop and a client
        // sending malformed frames were equally loud, and the default quiet level (WARN)
        // filled with three `WARN`s per ordinary probe run. The level is the whole signal
        // an operator has here, so it has to mean something.
        Err(error) if error.is_peer_gone() => {
            tracing::debug!("connection from {peer} ended: {error}");
            Ending::Done
        }
        Err(error) => {
            tracing::warn!("connection from {peer} ended: {error}");
            Ending::Done
        }
    }
}

async fn drive<B, C, S>(
    stream: TcpStream,
    auth: &Auth,
    timeouts: Timeouts,
    origins: &Origins,
    state: &mut DaemonState<B, C>,
    signals: &mut S,
) -> Result<Ending, DaemonError>
where
    B: LocalUsbBackend,
    C: Sleeper,
    S: Signals,
{
    // The handshake is negotiation, not work: a signal ends it at once and the peer sees
    // EOF. Nothing is owed to a client that has not asked for anything yet.
    let accepted = tokio::select! {
        accepted = Conn::accept_with(stream, auth, timeouts, origins) => accepted?,
        () = signals.next() => return Ok(Ending::Stopped),
    };
    let Some(mut conn) = accepted else {
        return Ok(Ending::Done);
    };
    loop {
        // The C's `while (g_running)`, checked between commands (`main.c:888-892`).
        let request = tokio::select! {
            request = conn.next_request() => request?,
            () = signals.next() => return Ok(Ending::Stopped),
        };
        let Some((command, payload)) = request else {
            return Ok(Ending::Done);
        };
        if dispatch_to_its_end(&mut conn, state, command, &payload, signals).await? == Ending::Stopped {
            return Ok(Ending::Stopped);
        }
        if conn.one_shot() {
            return Ok(Ending::Done);
        }
    }
}

/// Run one dispatch to completion, whatever the first signal says.
///
/// See this file's header. The first signal is remembered and the command finishes, so
/// the client gets its final frame and a flash in progress is not torn off the device;
/// the second drops the connection, because a device that has stopped answering can hold
/// a bulk transfer for the whole USB timeout.
async fn dispatch_to_its_end<B, C, S>(
    conn: &mut Conn,
    state: &mut DaemonState<B, C>,
    command: Command,
    payload: &[u8],
    signals: &mut S,
) -> Result<Ending, DaemonError>
where
    B: LocalUsbBackend,
    C: Sleeper,
    S: Signals,
{
    let mut dispatching = pin!(commands::dispatch(conn, state, command, payload));
    let mut signalled = false;
    loop {
        tokio::select! {
            outcome = &mut dispatching => {
                outcome?;
                return Ok(if signalled { Ending::Stopped } else { Ending::Done });
            }
            () = signals.next() => {
                if signalled {
                    tracing::warn!(?command, "dropping the command in flight");
                    return Ok(Ending::Stopped);
                }
                signalled = true;
                say("dfu-remote: finishing the command in flight; signal again to drop it");
            }
        }
    }
}

/// Stdout, without the panic `println!` raises once the reader of a pipe has gone.
pub fn say(line: &str) {
    use std::io::Write as _;
    let _ignored = writeln!(std::io::stdout().lock(), "{line}");
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tdfu_proto::{Blobs, Command, HEADER_LEN, Request, RequestHeader, ResponseHeader, Status};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use super::{Ending, Signals, serve, serve_connection};
    use crate::auth::Auth;
    use crate::clock::TokioClock;
    use crate::commands::fake::{FakeBackend, TestResult};
    use crate::commands::state::DaemonState;
    use crate::transport::{Origins, Timeouts};

    /// What a client half of a test hands back through `join!`.
    type Outcome<T> = Result<T, Box<dyn std::error::Error>>;

    /// How long any client-side read here may block.
    ///
    /// Nothing to do with the daemon's own deadlines: it is so a mutation that stops the
    /// daemon answering makes a test **fail** instead of hanging. `cargo mutants` turned
    /// up four timeouts in this module for want of exactly this, three of them real
    /// defects (a `Wire::respond` that answers nothing, and both `Ending` comparisons
    /// inverted); a hang burns a slot and reports nothing, which is how a live survivor
    /// gets written off as machine load. `tests/transport.rs` carries the same constant
    /// for the same reason.
    const CLIENT_DEADLINE: Duration = Duration::from_secs(10);

    /// The accept loop, bounded by [`CLIENT_DEADLINE`].
    ///
    /// The **server** half needs this as much as the client half does, and for the same
    /// reason: `serve` returns only when a signal reaches it, so a mutation that stops it
    /// noticing one waits on an `accept` that never comes and hangs the whole `join!`
    /// where no client-side deadline can see it. `cargo mutants` produced exactly that,
    /// twice, by inverting either `Ending` comparison.
    async fn bounded(server: impl core::future::Future<Output = ()>) -> Outcome<()> {
        tokio::time::timeout(CLIENT_DEADLINE, server).await?;
        Ok(())
    }

    /// A hand-driven [`Signals`]: every `send` on the other end is one signal.
    ///
    /// A channel rather than a `oneshot` because the rule under test needs **two**, and
    /// `recv` is cancel-safe, which [`Signals::next`] requires.
    #[derive(Debug)]
    struct Stops(mpsc::UnboundedReceiver<()>);

    impl Signals for Stops {
        async fn next(&mut self) {
            if self.0.recv().await.is_none() {
                // Every sender has gone, so no signal will ever arrive. Never resolving
                // is the answer `main.rs` gives when a signal cannot be listened for.
                std::future::pending::<()>().await;
            }
        }
    }

    fn stops() -> (mpsc::UnboundedSender<()>, Stops) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (sender, Stops(receiver))
    }

    /// The shipped origin allow list, as a borrow that outlives the futures it is passed
    /// to. `Origins` owns a `Vec`, so `&Origins::SHIPPED` is a temporary rather than a
    /// promoted constant and every call site would need a local of its own.
    fn shipped() -> &'static Origins {
        static SHIPPED: std::sync::OnceLock<Origins> = std::sync::OnceLock::new();
        SHIPPED.get_or_init(|| Origins::SHIPPED)
    }

    fn daemon() -> DaemonState<FakeBackend, TokioClock> {
        DaemonState::new(FakeBackend::empty(), TokioClock, "firmware")
    }

    /// A daemon whose one device is a bootrom scripted for the whole bootstrap sequence.
    ///
    /// `CMD_BOOTSTRAP` is the command these tests want because it is chatty (logs and
    /// progress are attached for it) **and** slow in a way nothing here controls:
    /// `ops::bootstrap` waits `POST_STAGE1_SETTLE` (1 s) between the two
    /// images, and `TokioClock` really waits. So a signal fired 100 ms in is reliably
    /// mid-dispatch.
    fn bootstrapping_daemon() -> DaemonState<FakeBackend, TokioClock> {
        let backend = FakeBackend::new(vec![FakeBackend::bootstrappable_bootrom(
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        // The blobs travel in the request, so no firmware directory is consulted
        // and nothing is detected.
        DaemonState::new(backend, TokioClock, "/nonexistent-firmware-dir")
    }

    /// The `CMD_BOOTSTRAP` frame those two send: index 0, no variant, both images inline.
    fn bootstrap_frame() -> Outcome<Vec<u8>> {
        let payload = Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: Some(Blobs {
                spl: b"stage-1".to_vec(),
                uboot: b"u-boot".to_vec(),
            }),
        }
        .encode()?;
        let mut frame = RequestHeader {
            command: Command::Bootstrap,
            payload_len: u32::try_from(payload.len())?,
        }
        .encode()
        .to_vec();
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// One response frame, whatever its status, under [`CLIENT_DEADLINE`].
    async fn one_frame(stream: &mut TcpStream) -> Outcome<(Status, Vec<u8>)> {
        let mut bytes = [0u8; HEADER_LEN];
        tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut bytes)).await??;
        let header = ResponseHeader::decode(&bytes)?;
        let mut payload = vec![0u8; usize::try_from(header.payload_len)?];
        tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut payload)).await??;
        Ok((header.status, payload))
    }

    /// Read frames until one is not a log or a progress frame, keeping the count of each.
    ///
    /// `Ok(None)` means the peer **closed** before any final frame arrived, which is what
    /// a dropped connection looks like from here. A stream that goes quiet without
    /// closing is an error rather than a `None`: otherwise a daemon that simply stopped
    /// answering would be indistinguishable from the drop
    /// `a_second_signal_drops_the_command_in_flight` asserts.
    async fn final_frame(stream: &mut TcpStream) -> Outcome<Option<(Status, Vec<u8>, usize, usize)>> {
        let (mut logs, mut bars) = (0, 0);
        loop {
            let mut bytes = [0u8; HEADER_LEN];
            match tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut bytes)).await? {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            let header = ResponseHeader::decode(&bytes)?;
            let mut payload = vec![0u8; usize::try_from(header.payload_len)?];
            tokio::time::timeout(CLIENT_DEADLINE, stream.read_exact(&mut payload)).await??;
            match header.status {
                Status::Log => logs += 1,
                Status::Progress => bars += 1,
                status => return Ok(Some((status, payload, logs, bars))),
            }
        }
    }

    /// A header-only request (`DISCOVER`, `STATUS`) or one with a payload, as bytes.
    fn frame_of(request: &Request) -> Outcome<Vec<u8>> {
        let payload = request.encode()?;
        let mut frame = RequestHeader {
            command: request.command(),
            payload_len: u32::try_from(payload.len())?,
        }
        .encode()
        .to_vec();
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// The listing a client asked for on one connection is the frame of reference for
    /// the commands it sends on the next ones.
    ///
    /// The browser flasher talks to this daemon over HTTP with one request per
    /// connection, so its `DISCOVER` and the `BOOTSTRAP`, `READ` or `WRITE` that follow
    /// never share a socket. A daemon that forgot the listing when a connection ended
    /// answered every one of those follow-ups with "run DISCOVER first", which is what
    /// the browser's remote mode ran into on the bench.
    #[tokio::test]
    async fn a_listing_outlives_the_connection_that_asked_for_it() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = DaemonState::new(FakeBackend::new(vec![FakeBackend::gadget()]), TokioClock, "firmware");
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let client = async {
            // Connection 1: DISCOVER, and nothing else.
            let mut first = TcpStream::connect(address).await?;
            first.write_all(&frame_of(&Request::Discover)?).await?;
            let (status, _) = one_frame(&mut first).await?;
            assert_eq!(status, Status::Ok, "the listing itself");
            drop(first);
            // Connection 2: act on row 0 of that listing without asking again.
            let mut second = TcpStream::connect(address).await?;
            second.write_all(&frame_of(&Request::Reboot { index: 0 })?).await?;
            let last = final_frame(&mut second).await?;
            let _ignored = stop.send(());
            Ok::<_, Box<dyn std::error::Error>>(last)
        };
        let ((), last) = tokio::join!(server, client);
        let Some((status, payload, _, _)) = last? else {
            return Err("the daemon closed the second connection without answering".into());
        };
        assert_eq!(
            status,
            Status::Ok,
            "row 0 of the previous connection's listing was refused: {}",
            String::from_utf8_lossy(&payload)
        );
        Ok(())
    }

    /// A raw `CMD_STATUS` and its reply, over a real socket.
    async fn status_of(stream: &mut TcpStream) -> Outcome<(Status, Vec<u8>)> {
        let header = RequestHeader {
            command: Command::Status,
            payload_len: 0,
        };
        stream.write_all(&header.encode()).await?;
        one_frame(stream).await
    }

    #[tokio::test]
    async fn a_raw_request_is_answered_and_shutdown_ends_the_loop() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = daemon();
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let client = async {
            let mut stream = TcpStream::connect(address).await?;
            let reply = status_of(&mut stream).await?;
            drop(stream);
            let _ignored = stop.send(());
            Ok::<_, Box<dyn std::error::Error>>(reply)
        };
        let (stopped, reply) = tokio::join!(bounded(server), client);
        stopped?;
        assert_eq!(reply?, (Status::Ok, b"idle".to_vec()));
        Ok(())
    }

    /// The loop serves clients in turn: one that connects and says nothing does not
    /// wedge the next, which is the C's failure mode (`main.c:1152-1153`).
    #[tokio::test]
    async fn a_silent_client_does_not_stop_the_next_one() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = daemon();
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let clients = async {
            let silent = TcpStream::connect(address).await?;
            drop(silent);
            let mut talking = TcpStream::connect(address).await?;
            let reply = status_of(&mut talking).await?;
            drop(talking);
            let _ignored = stop.send(());
            Ok::<_, Box<dyn std::error::Error>>(reply)
        };
        let (stopped, reply) = tokio::join!(bounded(server), clients);
        stopped?;
        assert_eq!(reply?, (Status::Ok, b"idle".to_vec()));
        Ok(())
    }

    /// A signal ends a connection **that has asked for nothing**, now, not when its
    /// deadline expires: the client is mid-handshake (it has sent nothing), the handshake
    /// deadline is long, and the loop still returns at once, closing the client's socket.
    #[tokio::test]
    async fn shutdown_drops_a_connection_in_flight() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = daemon();
        let (stop, stops) = stops();
        let timeouts = Timeouts {
            handshake: Some(Duration::from_secs(60)),
            ..Timeouts::DEFAULT
        };

        let server = serve(listener, &auth, timeouts, shipped(), &mut state, stops);
        let client = async {
            let mut stream = TcpStream::connect(address).await?;
            // Let the server accept and start waiting on the first byte.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let asked = Instant::now();
            let _ignored = stop.send(());
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(CLIENT_DEADLINE, stream.read(&mut byte)).await??;
            Ok::<_, Box<dyn std::error::Error>>((read, asked.elapsed()))
        };
        let (stopped, outcome) = tokio::join!(bounded(server), client);
        stopped?;
        let (read, took) = outcome?;
        assert_eq!(read, 0, "the client must see EOF, not a byte");
        assert!(
            took < Duration::from_secs(5),
            "shutdown waited on the handshake deadline: {took:?}"
        );
        Ok(())
    }

    /// The first signal does **not** tear a command off the device: the
    /// dispatch finishes, the client gets its final frame, and only then does the daemon
    /// stop.
    ///
    /// This is the C's shape (`main.c:888-892` checks `while (g_running)` between
    /// commands, so the `tdfu_dfu_download` in flight completes) and it is the one that
    /// matters: a SIGINT during a `CMD_WRITE` that abandoned the download part-way would
    /// leave a camera that does not boot, and the client would never learn why.
    ///
    /// The signal is fired 100 ms into a bootstrap that spends a whole second inside
    /// `POST_STAGE1_SETTLE`, so "mid-dispatch" is not a race: the elapsed time is
    /// asserted, and a daemon that dropped the connection could not have spent it.
    #[tokio::test]
    async fn the_first_signal_lets_the_command_in_flight_finish() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = bootstrapping_daemon();
        crate::commands::fake::seen(&mut state).await?;
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let client = async {
            let mut stream = TcpStream::connect(address).await?;
            let started = Instant::now();
            stream.write_all(&bootstrap_frame()?).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ignored = stop.send(());
            let last = final_frame(&mut stream).await?;
            Ok::<_, Box<dyn std::error::Error>>((last, started.elapsed()))
        };
        let (stopped, outcome) = tokio::join!(bounded(server), client);
        stopped?;
        let (last, took) = outcome?;

        let (status, payload, logs, bars) = last.ok_or("the client never got its final frame")?;
        assert_eq!((status, payload.as_slice()), (Status::Ok, &b"OK"[..]));
        assert!(logs > 0 && bars > 0, "logs {logs}, progress {bars}");
        assert!(
            took >= Duration::from_secs(1),
            "the bootstrap cannot have run its stage-1 settle: {took:?}"
        );
        Ok(())
    }

    /// ... and the **second** signal drops it, which the C has no way to do at all.
    ///
    /// The escape hatch is for the case the C cannot answer: a device that has stopped
    /// answering holds a bulk transfer for the whole USB timeout, and an operator who has
    /// pressed Ctrl-C twice has said what they mean. The client sees EOF instead of a
    /// final frame, well inside the second the bootstrap would have taken.
    #[tokio::test]
    async fn a_second_signal_drops_the_command_in_flight() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = bootstrapping_daemon();
        crate::commands::fake::seen(&mut state).await?;
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let client = async {
            let mut stream = TcpStream::connect(address).await?;
            let started = Instant::now();
            stream.write_all(&bootstrap_frame()?).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _first = stop.send(());
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _second = stop.send(());
            let last = final_frame(&mut stream).await?;
            Ok::<_, Box<dyn std::error::Error>>((last, started.elapsed()))
        };
        let (stopped, outcome) = tokio::join!(bounded(server), client);
        stopped?;
        let (last, took) = outcome?;

        assert!(last.is_none(), "the second signal must drop it: {last:?}");
        assert!(
            took < Duration::from_secs(1),
            "the connection outlived the stage-1 settle, so nothing was dropped: {took:?}"
        );
        Ok(())
    }

    /// A `tracing` sink a test can read back.
    ///
    /// Installed with `set_default`, which is **thread-local**: `#[tokio::test]` builds a
    /// current-thread runtime, so everything this test drives is polled on the thread
    /// that holds it, and the global subscriber `logging::init` may have installed in
    /// another test in this binary is not disturbed. Asserting on stderr instead would
    /// tie the check to whatever else the process happens to be printing.
    #[derive(Clone, Debug, Default)]
    struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            self.0
                .lock()
                .map_or_else(|_| String::new(), |bytes| String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut held) = self.0.lock() {
                held.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self {
            self.clone()
        }
    }

    /// A peer going away is `debug`; a peer misbehaving is `warn`.
    ///
    /// `DaemonError::is_peer_gone` stated that policy and had no caller anywhere in the
    /// workspace, so `serve_connection` logged every ending at `warn` and an ordinary
    /// hang-up was as loud as a framing violation. Both arms are driven here, through a
    /// real socket, and both the level and the absence of the other one are asserted:
    /// checking only that the text appears would pass whatever level it came out at.
    #[tokio::test]
    async fn a_hang_up_is_quieter_than_a_violation() -> TestResult {
        use tracing_subscriber::fmt;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = daemon();

        // (a) A half-close part-way through a payload the peer announced: `Truncated`.
        let hang_up = {
            let captured = Captured::default();
            let subscriber = fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(captured.clone())
                .without_time()
                .finish();
            let _installed = tracing::subscriber::set_default(subscriber);

            let mut client = TcpStream::connect(address).await?;
            let (stream, _) = listener.accept().await?;
            let (_, stops) = stops();
            let mut stops = stops;
            let served = tokio::time::timeout(
                CLIENT_DEADLINE,
                serve_connection(stream, &auth, Timeouts::DEFAULT, shipped(), &mut state, &mut stops),
            );
            let dropped = async {
                let mut header = RequestHeader {
                    command: Command::Write,
                    payload_len: 4096,
                }
                .encode()
                .to_vec();
                header.extend_from_slice(&[0xAB; 10]);
                client.write_all(&header).await?;
                client.shutdown().await?;
                Ok::<(), std::io::Error>(())
            };
            let (ending, dropped) = tokio::join!(served, dropped);
            dropped?;
            assert_eq!(ending?, Ending::Done);
            captured.text()
        };
        assert!(hang_up.contains("the peer stopped after 10 of 4096"), "{hang_up}");
        assert!(hang_up.contains("DEBUG"), "a hang-up is not a warning: {hang_up}");
        assert!(!hang_up.contains("WARN"), "{hang_up}");

        // (b) A frame with the wrong magic: the peer is misbehaving, not leaving.
        let violation = {
            let captured = Captured::default();
            let subscriber = fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(captured.clone())
                .without_time()
                .finish();
            let _installed = tracing::subscriber::set_default(subscriber);

            let mut client = TcpStream::connect(address).await?;
            let (stream, _) = listener.accept().await?;
            let (_, stops) = stops();
            let mut stops = stops;
            let served = tokio::time::timeout(
                CLIENT_DEADLINE,
                serve_connection(stream, &auth, Timeouts::DEFAULT, shipped(), &mut state, &mut stops),
            );
            let spoiled = async {
                let mut header = RequestHeader {
                    command: Command::Status,
                    payload_len: 0,
                }
                .encode()
                .to_vec();
                header[0] = 0x7F;
                client.write_all(&header).await?;
                Ok::<(), std::io::Error>(())
            };
            let (ending, spoiled) = tokio::join!(served, spoiled);
            spoiled?;
            assert_eq!(ending?, Ending::Done);
            captured.text()
        };
        assert!(violation.contains("bad magic"), "{violation}");
        assert!(violation.contains("WARN"), "a protocol violation is loud: {violation}");
        Ok(())
    }

    /// The `impl Wire for Conn` forwarding, through a real socket.
    ///
    /// It is the only place the real transport meets the real dispatcher, and three of
    /// its four methods were exercised by nothing: `commands/` tests use `LoopbackConn`,
    /// `tests/transport.rs` calls the *inherent* `Conn::log`/`Conn::progress`, and the
    /// tests above send only `CMD_STATUS` against a bus with nothing on it, which emits
    /// neither. A wrong `logs_enabled_for` here silences the browser flasher's progress
    /// bar with nothing to catch it.
    #[tokio::test]
    async fn a_chatty_command_reaches_the_client_through_a_real_conn() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let auth = Auth::open();
        let mut state = bootstrapping_daemon();
        crate::commands::fake::seen(&mut state).await?;
        let (stop, stops) = stops();

        let server = serve(listener, &auth, Timeouts::DEFAULT, shipped(), &mut state, stops);
        let client = async {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(&bootstrap_frame()?).await?;

            // Every frame in order, so "before the final one" is checked and not assumed.
            let mut kinds = Vec::new();
            loop {
                let (status, payload) = one_frame(&mut stream).await?;
                kinds.push(status);
                if status == Status::Log {
                    assert!(
                        payload.ends_with(b"\n"),
                        "through the Wire impl: {:?}",
                        String::from_utf8_lossy(&payload)
                    );
                }
                if !matches!(status, Status::Log | Status::Progress) {
                    break;
                }
            }
            let _ignored = stop.send(());
            Ok::<_, Box<dyn std::error::Error>>(kinds)
        };
        let (stopped, kinds) = tokio::join!(bounded(server), client);
        stopped?;
        let kinds = kinds?;

        assert_eq!(kinds.last(), Some(&Status::Ok), "{kinds:?}");
        assert!(kinds.contains(&Status::Log), "no RESP_LOG arrived: {kinds:?}");
        assert!(kinds.contains(&Status::Progress), "no RESP_PROGRESS arrived: {kinds:?}");
        // The two bootstrap stages, so `progress` forwarded the body and not a
        // stub: stage 1 is the SPL upload and stage 2 is U-Boot's.
        assert!(
            kinds.iter().filter(|status| **status == Status::Progress).count() >= 2,
            "{kinds:?}"
        );
        Ok(())
    }
}
