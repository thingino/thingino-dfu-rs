//! One TCP port, three transports, sniffed by the first byte.
//!
//! `'G'` is a WebSocket upgrade, `'P'` an HTTP POST, `'O'` a CORS/Local Network Access
//! preflight, and anything else a raw TDFU stream — the magic starts with `'T'`. The C
//! peeks with `MSG_PEEK` at `dfu-remote/main.c:1136-1154` and this does the same, because
//! the sniffed byte belongs to the transport that follows and must not be consumed.
//!
//! # The four things this layer owes the rest of the daemon
//!
//! * **No connection can wedge the listener.** Every read and write is under a deadline
//!   ([`Timeouts`]), which the C has nowhere at all.
//! * **No state outlives a connection.** The only per-connection state is which command
//!   is in flight, it lives inside the [`Conn`], and dropping the connection drops it.
//!   An earlier implementation kept it in a process global and left it at `writing` for
//!   the life of the process after a client hung up; the C keeps `g_log_client_fd` in one
//!   too and clears it by hand at seven sites.
//! * **Every auth failure is logged**, by [`crate::auth::Auth`] itself so no path can
//!   forget.
//! * **Nothing is refused in silence.** A refusal reaches the peer as a `RESP_ERROR`
//!   frame or an HTTP status *with the CORS headers*, and reaches the daemon as a
//!   [`DaemonError`] that kept its numbers.

mod digest;
mod error;
mod http;
pub mod options;
pub mod origin;
mod raw;
mod wire;
mod ws;

use tdfu_proto::ProgressBody;
use tdfu_proto::{Command, HEADER_LEN, ProtoError, RequestHeader, ResponseHeader, Status, exceeds_payload_cap};
use tokio::net::TcpStream;

use crate::auth::{Auth, AuthOutcome};

pub use error::{DaemonError, Transport};
pub use http::HttpConn;
pub use options::{BindAddr, Options, OptionsError, Parsed};
pub use origin::{Decision, OriginError, Origins};
pub use raw::RawConn;
pub use wire::Timeouts;
pub use ws::WsConn;

use wire::{Deadlines, Filled, Wire};

/// How much is read at a time when skipping a payload we are not going to look at.
const SKIP_CHUNK: usize = 16 * 1024;

/// An accepted client, whatever it speaks.
///
/// An enum rather than a `dyn` trait so the async methods stay inherent and `?Send`
/// (decision D1).
///
/// Deliberately **not** `#[non_exhaustive]`: that rule is about public *error*
/// enums, and the shape here is the frozen seam the commands compile
/// against.
#[derive(Debug)]
pub enum Conn {
    /// Raw TDFU frames.
    Raw(RawConn),
    /// RFC 6455.
    Ws(WsConn),
    /// One command per POST.
    Http(HttpConn),
}

impl Conn {
    /// Sniff the first byte, do any upgrade or preflight, run the token handshake.
    ///
    /// `Ok(None)` means the connection was dealt with and there is nothing to dispatch:
    /// a preflight was answered, or the peer closed before saying anything.
    ///
    /// Uses [`Timeouts::DEFAULT`] and the shipped [`Origins`]. [`Conn::accept_with`]
    /// takes the deadlines and the allow list the daemon was actually started with.
    ///
    /// # Errors
    /// Anything in [`DaemonError`]. A refusal has already reached the peer.
    pub async fn accept(stream: TcpStream, auth: &Auth) -> Result<Option<Self>, DaemonError> {
        Self::accept_with(stream, auth, Timeouts::DEFAULT, &Origins::SHIPPED).await
    }

    /// [`Conn::accept`] with explicit deadlines and origin allow list.
    ///
    /// # Errors
    /// Anything in [`DaemonError`].
    pub async fn accept_with(
        stream: TcpStream,
        auth: &Auth,
        timeouts: Timeouts,
        origins: &Origins,
    ) -> Result<Option<Self>, DaemonError> {
        let Some(first) = peek_first_byte(&stream, timeouts.handshake).await? else {
            // The peer connected and closed without a word. Not an error, and — unlike
            // the C, which falls through to `handle_client` and blocks on a read that
            // will never return (`dfu-remote/main.c:1152-1153`) — not a wedge either.
            return Ok(None);
        };
        let mut wire = Wire::new(stream, timeouts);

        let mut conn = match first {
            b'G' => Self::Ws(WsConn::upgrade(wire, origins).await?),
            b'P' => return Ok(Some(Self::Http(HttpConn::accept(wire, auth, origins).await?))),
            b'O' => {
                HttpConn::preflight(&mut wire, origins).await?;
                return Ok(None);
            }
            _ => Self::Raw(RawConn::new(wire)),
        };

        // The handshake exists only if the daemon was started with
        // `--token`. Without one a client must not send it — it would be parsed as a
        // command header. HTTP does not come through here; its token is a header, and
        // `HttpConn::accept` has already checked it.
        if auth.is_required() {
            conn.token_handshake(auth).await?;
        }
        Ok(Some(conn))
    }

    /// The next request on this connection; `Ok(None)` = the client closed cleanly.
    ///
    /// An unknown command is refused and the connection **continues**: the
    /// announced payload is skipped — bounded by the 64 MiB cap, which
    /// `RequestHeader::decode` applies *before* the command byte — and the next header is
    /// read. A bad magic, a version mismatch or an oversize payload is refused and the
    /// connection **ends**.
    ///
    /// # Errors
    /// [`DaemonError::Refused`] once the peer has been told; [`DaemonError::Truncated`]
    /// if it stopped part-way through a frame it had announced;
    /// [`DaemonError::TimedOut`]; or an I/O failure.
    pub async fn next_request(&mut self) -> Result<Option<(Command, Vec<u8>)>, DaemonError> {
        self.set_current(None);
        loop {
            if let Self::Http(http) = self {
                // Exactly one command per POST.
                if http.spent() {
                    return Ok(None);
                }
            }

            let mut header = [0_u8; HEADER_LEN];
            // Patient for the first byte of the next command, brisk for the rest of it.
            let deadlines = Deadlines::split(self.timeouts().idle, self.timeouts().read);
            match self.read_exact(&mut header, deadlines, "request header").await? {
                Filled::Whole => {}
                Filled::Eof(0) => return Ok(None),
                Filled::Eof(got) => {
                    return Err(DaemonError::Truncated {
                        doing: "request header",
                        got,
                        want: HEADER_LEN,
                    });
                }
            }

            match RequestHeader::decode(&header) {
                Ok(request) => {
                    let mut payload = vec![0_u8; request.payload_len as usize];
                    let want = payload.len();
                    let deadlines = Deadlines::uniform(self.timeouts().read);
                    match self.read_exact(&mut payload, deadlines, "payload").await? {
                        Filled::Whole => {}
                        Filled::Eof(got) => {
                            return Err(DaemonError::Truncated {
                                doing: "payload",
                                got,
                                want,
                            });
                        }
                    }
                    self.set_current(Some(request.command));
                    return Ok(Some((request.command, payload)));
                }
                Err(ProtoError::UnknownCommand) => {
                    // Refuse and keep reading. The skip is what makes that
                    // possible, and it is bounded because the cap was applied first.
                    let skip = RequestHeader::announced_payload_len(&header)?;
                    self.discard(u64::from(skip)).await?;
                    self.respond(Status::Error, b"unknown command").await?;
                }
                Err(refusal) => {
                    let message = refusal.wire_message().unwrap_or("bad frame");
                    self.respond(Status::Error, message.as_bytes()).await?;
                    return Err(DaemonError::Refused { message });
                }
            }
        }
    }

    /// The final OK/ERROR frame for the request just handled.
    ///
    /// On the HTTP transport this also writes the terminating chunk, because a POST
    /// gets exactly one final frame; a second call is
    /// [`DaemonError::AlreadyFinished`] rather than a chunk after the terminator.
    ///
    /// # Errors
    /// [`DaemonError::OversizeResponse`] if the payload is past the 64 MiB cap and the
    /// command in flight is not `CMD_READ`, the one command the cap exempts, because
    /// a NAND alt 0 is 256 MiB. Otherwise an I/O failure.
    pub async fn respond(&mut self, status: Status, payload: &[u8]) -> Result<(), DaemonError> {
        let len = u32::try_from(payload.len()).map_err(|_| DaemonError::OversizeResponse {
            len: payload.len(),
            command: self.current(),
        })?;
        if exceeds_payload_cap(len) && self.current() != Some(Command::Read) {
            return Err(DaemonError::OversizeResponse {
                len: payload.len(),
                command: self.current(),
            });
        }
        let header = ResponseHeader {
            status,
            payload_len: len,
        }
        .encode();
        self.send_message(&[&header, payload]).await?;
        self.set_current(None);
        if let Self::Http(http) = self {
            http.finish().await?;
        }
        Ok(())
    }

    /// A `RESP_LOG` frame; a no-op when logs are not attached for the
    /// command in flight.
    ///
    /// **The frame carries a whole line, newline included.** Every C log
    /// string ends in one (`libtdfu/src/dfu/dfu.c:618`, `:742`, `:781`, `:861`, `:961`)
    /// and `daemon_log_hook` forwards `msg, len` verbatim (`dfu-remote/main.c:181-188`),
    /// so the shipped C CLI prints the body with nothing added
    /// (`cli/remote.c:194-196`, `fprintf(stderr, "%s", data)`). Our core notes carry no
    /// terminator, so a remote `-w --verify` printed
    /// `DFU download completeVerify OK: …` on one line. Terminating it **here** rather
    /// than at each note is the one place that frames a log line at all, so no producer
    /// can forget; a line that already ends in one is not doubled.
    ///
    /// # Errors
    /// An I/O failure.
    pub async fn log(&mut self, line: &str) -> Result<(), DaemonError> {
        if !self.logs_attached() {
            return Ok(());
        }
        let terminator: &[u8] = if line.ends_with('\n') { b"" } else { b"\n" };
        let payload_len = line.len().saturating_add(terminator.len());
        let len = u32::try_from(payload_len).map_err(|_| DaemonError::OversizeResponse {
            len: payload_len,
            command: self.current(),
        })?;
        let header = ResponseHeader {
            status: Status::Log,
            payload_len: len,
        }
        .encode();
        self.send_message(&[&header, line.as_bytes(), terminator]).await
    }

    /// A `RESP_PROGRESS` frame. **Sent**, unlike every C daemon.
    ///
    /// No C daemon ever sent one although both C clients parse them, so remote flashing
    /// showed progress only as log prose.
    /// An earlier implementation inherited the omission at the codec level, shipping a
    /// decoder and no encoder, which is why `ProgressBody::encode` now exists and why
    /// this method does.
    ///
    /// Follows the same attach rule log frames do.
    ///
    /// # Errors
    /// [`DaemonError::Encode`] if the message does not fit its `u16` length prefix, or an
    /// I/O failure.
    pub async fn progress(&mut self, body: &ProgressBody) -> Result<(), DaemonError> {
        if !self.logs_attached() {
            return Ok(());
        }
        let payload = body.encode()?;
        let len = u32::try_from(payload.len()).map_err(|_| DaemonError::OversizeResponse {
            len: payload.len(),
            command: self.current(),
        })?;
        let header = ResponseHeader {
            status: Status::Progress,
            payload_len: len,
        }
        .encode();
        self.send_message(&[&header, &payload]).await
    }

    /// Does this transport emit log frames for this command?
    ///
    /// During `BOOTSTRAP`, `WRITE` (which covers erase and verify) and `READ` on every
    /// transport, and for *every* command on HTTP. Never during
    /// `DISCOVER`/`STATUS`/`CANCEL`/`DIAG`/`REBOOT` on raw TCP or WebSocket.
    ///
    /// Verified against the C's `g_log_client_fd` sets, which are the whole rule:
    /// `dfu-remote/main.c:422` (bootstrap), `:515` and `:526` (the erase branch of
    /// write), `:570` and `:582` (write, spanning verify at `:577-580`), `:658` (read)
    /// and `:977` (HTTP, around the single `process_one_command`). There is no set in
    /// `handle_discover`, `handle_status`, `handle_cancel`, `handle_diag` or
    /// `handle_reboot`.
    ///
    /// **A pure function of the variant and the command**, and the `const fn` is the
    /// proof rather than a test: a `const fn` may not read interior mutability or call
    /// anything that could, so no connection can reach a state where this answers
    /// differently for the same pair. A test that declared a `const fn` wrapper and
    /// asserted nothing was restating that signature, not checking it. What
    /// the rule *is* is pinned on the wire, by `rpc_log_frames_when` and
    /// `the_seam_accessors_answer_for_a_real_connection` in `tests/transport.rs`, which
    /// build real connections of all three kinds and ask all eight commands.
    #[must_use]
    pub const fn logs_enabled_for(&self, cmd: Command) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Raw(_) | Self::Ws(_) => {
                matches!(cmd, Command::Bootstrap | Command::Write | Command::Read)
            }
        }
    }

    /// HTTP carries exactly one command per POST.
    #[must_use]
    pub const fn one_shot(&self) -> bool {
        matches!(self, Self::Http(_))
    }

    /// Which transport this is.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        match self {
            Self::Raw(_) => Transport::Raw,
            Self::Ws(_) => Transport::WebSocket,
            Self::Http(_) => Transport::Http,
        }
    }

    /// Who is on the other end, when the socket can say.
    #[must_use]
    pub fn peer(&self) -> Option<core::net::SocketAddr> {
        match self {
            Self::Raw(raw) => raw.peer(),
            Self::Ws(ws) => ws.peer(),
            Self::Http(http) => http.peer(),
        }
    }

    /// The deadlines in force.
    #[must_use]
    pub const fn timeouts(&self) -> Timeouts {
        match self {
            Self::Raw(raw) => raw.timeouts(),
            Self::Ws(ws) => ws.timeouts(),
            Self::Http(http) => http.timeouts(),
        }
    }

    /// Which command is in flight, or `None` between requests.
    #[must_use]
    pub const fn current(&self) -> Option<Command> {
        match self {
            Self::Raw(raw) => raw.current,
            Self::Ws(ws) => ws.current,
            Self::Http(http) => http.current,
        }
    }

    /// Are log and progress frames attached right now?
    fn logs_attached(&self) -> bool {
        self.current().is_some_and(|cmd| self.logs_enabled_for(cmd))
    }

    fn set_current(&mut self, cmd: Option<Command>) {
        match self {
            Self::Raw(raw) => raw.current = cmd,
            Self::Ws(ws) => ws.current = cmd,
            Self::Http(http) => http.current = cmd,
        }
    }

    /// The token handshake: `[4:magic][1:version][1:token_len][token]`.
    async fn token_handshake(&mut self, auth: &Auth) -> Result<(), DaemonError> {
        let transport = self.transport();
        let peer = self.peer();
        let handshake = self.timeouts().handshake;

        let mut prefix = [0_u8; 6];
        // Uniform: a handshake is six bytes and 255 more, and a peer that has not
        // authenticated has not earned the patience a transfer gets.
        let deadlines = Deadlines::uniform(handshake);
        match self.read_exact(&mut prefix, deadlines, "auth handshake").await? {
            Filled::Whole => {}
            Filled::Eof(got) => {
                // **Not a rejection.** A peer that sent `TDFU` and closed
                // presented nothing to refuse, and calling it one both inflated
                // `Auth::rejections`, the number the auth log exists to make trustworthy,
                // and logged `the handshake magic or version was not ours` when the magic
                // was ours. The `Truncated` error below is the whole true account, and it
                // reaches `serve_connection`; the C prints `Auth: failed to read
                // handshake` here (`dfu-remote/main.c:854`) and counts nothing.
                auth.abandoned(transport, peer);
                return Err(DaemonError::Truncated {
                    doing: "auth handshake",
                    got,
                    want: prefix.len(),
                });
            }
        }
        let token_len = match Auth::parse_handshake_prefix(&prefix) {
            Ok(len) => len,
            Err(reason) => {
                auth.reject(reason, transport, peer);
                auth.pause_after_rejection(peer).await;
                self.respond(Status::Error, reason.wire_message().as_bytes()).await?;
                return Err(DaemonError::AuthRejected { transport, reason });
            }
        };

        let mut token = vec![0_u8; usize::from(token_len)];
        if token_len > 0 {
            let want = token.len();
            match self.read_exact(&mut token, deadlines, "auth token").await? {
                Filled::Whole => {}
                Filled::Eof(got) => {
                    // The same, one field later: a peer that announced twelve token bytes
                    // and sent three was logged `no token was presented` when a token was
                    // announced.
                    auth.abandoned(transport, peer);
                    return Err(DaemonError::Truncated {
                        doing: "auth token",
                        got,
                        want,
                    });
                }
            }
        }

        match auth.check(Some(&token), transport, peer) {
            AuthOutcome::Accepted | AuthOutcome::NotRequired => {
                self.respond(Status::Ok, b"OK").await?;
                Ok(())
            }
            AuthOutcome::Rejected(reason) => {
                // Before the answer, so the guess and its refusal are not a round trip a
                // caller can repeat at connection speed.
                auth.pause_after_rejection(peer).await;
                self.respond(Status::Error, reason.wire_message().as_bytes()).await?;
                Err(DaemonError::AuthRejected { transport, reason })
            }
        }
    }

    /// Read and throw away `count` bytes, whatever the transport.
    async fn discard(&mut self, count: u64) -> Result<(), DaemonError> {
        let want = usize::try_from(count).unwrap_or(usize::MAX);
        // On the heap: a 16 KiB array here would be copied into every enclosing async
        // frame (`clippy::large_futures`).
        let mut scratch = vec![0_u8; want.min(SKIP_CHUNK)];
        let mut count = count;
        while count > 0 {
            let take = usize::try_from(count).unwrap_or(SKIP_CHUNK).min(SKIP_CHUNK);
            if take == 0 {
                // Only reachable with `SKIP_CHUNK` at zero, and then `count -= 0` spins
                // for ever: `read_exact(&mut [])` is `Filled::Whole` and nothing moves.
                // Breaking makes that a **failing** test rather than a hanging one: the
                // skip stops short, the next header is parsed out of the middle of the
                // payload, and `rpc_unknown_command_is_refused_and_the_connection_continues`
                // says so. A hang that looks like machine load is exactly how a real
                // survivor gets waved through.
                break;
            }
            let Some(slot) = scratch.get_mut(..take) else { break };
            match self
                .read_exact(slot, Deadlines::uniform(self.timeouts().read), "skipped payload")
                .await?
            {
                Filled::Whole => count -= take as u64,
                Filled::Eof(got) => {
                    // Everything already skipped, plus the part-chunk that arrived,
                    // not just the last chunk: the number is in hand, so report the
                    // real one.
                    let skipped = want.saturating_sub(usize::try_from(count).unwrap_or(0));
                    return Err(DaemonError::Truncated {
                        doing: "skipped payload",
                        got: skipped.saturating_add(got),
                        want,
                    });
                }
            }
        }
        Ok(())
    }

    async fn read_exact(
        &mut self,
        buf: &mut [u8],
        deadlines: Deadlines,
        doing: &'static str,
    ) -> Result<Filled, DaemonError> {
        match self {
            Self::Raw(raw) => raw.read_exact(buf, deadlines, doing).await,
            Self::Ws(ws) => ws.read_exact(buf, deadlines, doing).await,
            Self::Http(http) => Ok(http.read_exact(buf, deadlines)),
        }
    }

    async fn send_message(&mut self, parts: &[&[u8]]) -> Result<(), DaemonError> {
        match self {
            Self::Raw(raw) => raw.send_message(parts).await,
            Self::Ws(ws) => ws.send_message(parts).await,
            Self::Http(http) => http.send_message(parts).await,
        }
    }
}

/// Peek the first byte without consuming it (`dfu-remote/main.c:1137`, `MSG_PEEK`).
///
/// `Ok(None)` means the peer closed before sending anything. **Under a deadline**, which
/// is what stops a peer that connects and says nothing from holding the accept loop for
/// ever. With `listen(fd, 1)` and one client at a time, that is the whole of the
/// wedged-listener failure.
async fn peek_first_byte(stream: &TcpStream, within: Option<core::time::Duration>) -> Result<Option<u8>, DaemonError> {
    let mut byte = [0_u8; 1];
    let peek = stream.peek(&mut byte);
    let got = match within {
        Some(limit) => match tokio::time::timeout(limit, peek).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(DaemonError::TimedOut {
                    doing: "first byte",
                    after: limit,
                });
            }
        },
        None => peek.await?,
    };
    Ok((got >= 1).then_some(byte[0]))
}
