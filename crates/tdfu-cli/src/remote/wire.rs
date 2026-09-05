//! One TCP conversation with a `dfu-remote` daemon: the client half.
//!
//! # Blocking sockets, on purpose
//!
//! Everything here is `std::net`. The CLI has no async runtime — `runtime::block_on`
//! parks a thread and `nusb` owns its own I/O — and a remote run talks to exactly one
//! daemon over exactly one socket, sequentially. A reactor would be a
//! dependency and a thread pool to schedule one conversation.
//!
//! # What this refuses that the C accepts
//!
//! * **The response version byte is checked.** `cli/remote.c:232` tests the magic and
//!   nothing else, so a daemon speaking a future protocol version produces confusing
//!   garbage — the frames decode, the payload layouts do not, and the failure surfaces
//!   somewhere else entirely. [`ResponseHeader::decode`] checks magic *then* version, and
//!   [`Client::header`] turns the mismatch into one line naming both versions.
//! * **An oversize final response is refused rather than drained.** The C
//!   drains it into a scratch buffer to keep the stream coherent (`cli/remote.c:251-262`)
//!   and then fails anyway; the connection is finished either way, so reading up to
//!   4 GiB to keep a stream nobody will use is work with no purpose.
//! * **`>` not `>=`.** The C's `plen >= TDFU_MAX_PAYLOAD` (`cli/remote.c:247`) made a
//!   payload of exactly 64 MiB legal to send and fatal to receive; the cap is a maximum
//!   ([`exceeds_payload_cap`]).
//! * **An oversize *intermediate* frame is an error.** The C silently drains anything
//!   over 64 KiB and carries on (`cli/remote.c:190`, `:209-217`), which hides a daemon
//!   that has lost frame sync behind a run that looks normal.
//!
//! # And what it keeps
//!
//! The handshake is sent **only when `--token` was given**: a daemon
//! started without one expects no handshake and would read those six bytes as a command
//! header. That is `cli/remote.c:123`'s rule and it is not a defect.
//!
//! # Four deadlines, all of them additions
//!
//! The C has none of these, and its missing timeouts are a recorded C
//! defect on the daemon's side; this is the client's side of the same thing. Each is
//! stated here because "the tool hung" is the report an operator cannot act on.
//!
//! * [`CONNECT_TIMEOUT`] bounds each address's TCP handshake.
//! * [`HANDSHAKE_TIMEOUT`] bounds the token handshake and, new with this audit,
//!   **the first response of the first command when no token was sent**, which is the
//!   same question ("is this peer a daemon at all?") asked on the path where no handshake
//!   proves it. It is lifted the moment one frame arrives, because after that a minutes-
//!   long silence is a whole-chip erase working as designed.
//! * [`SEND_TIMEOUT`] bounds a send that makes no progress, which is the fault the other
//!   three cannot see: the kernel sends no keepalive probes while data is queued, so a
//!   peer that accepts and then stops reading is bounded by nothing else.
//! * [`KEEPALIVE_IDLE`] / [`KEEPALIVE_INTERVAL`] / [`KEEPALIVE_PROBES`] give the kernel
//!   the job no fixed read deadline can do: telling a *silent* peer from a *vanished*
//!   one. A host that is power-cut mid-erase sends no RST and no FIN, so without this the
//!   client blocks in `read` for ever; with it the connection fails in about two minutes
//!   and the failure says the connection dropped. It never fires on a live but slow peer,
//!   which is why it is the right instrument here and a read deadline is not.
//!
//! There is deliberately **no deadline on a command's own response.** See
//! [`HANDSHAKE_TIMEOUT`]. What bounds a command that never ends is therefore not a clock
//! but a count: [`MAX_INTERMEDIATE_FRAMES`] caps how much log and progress one command may
//! be answered with before its final frame, which is the one fault a peer that is alive
//! and talking can commit and none of the four above can see.

use core::time::Duration;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};

use tdfu_proto::{
    HEADER_LEN, ProgressBody, ProtoError, Request, RequestHeader, ResponseHeader, Status, exceeds_payload_cap,
};

use crate::remote::error::{Address, Attempt, RemoteError, connect_failed};
use crate::render::Bar;

/// How long one address gets to complete a TCP handshake.
///
/// **An addition, and a deliberate one.** The C hands `connect(2)` no deadline
/// (`cli/remote.c:108`), so a host that silently drops SYNs — a firewall, a camera that
/// moved subnet — hangs the tool for the kernel's own retry budget, which on Linux is
/// over two minutes per address. Ten seconds is far beyond a working LAN handshake and
/// far below "the operator thinks it has frozen", and the timeout is *reported* as a
/// timeout, which is one of the three faults that must stay distinguishable from each
/// other.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the daemon has to answer the token handshake, or, with no token, the first
/// command.
///
/// **No deadline on commands.** A command may legitimately take minutes with nothing on
/// the socket (a whole-chip erase is a grace poll on the far side), so nothing
/// bounds a response once the conversation has started, exactly as the C does. What is
/// bounded is the *first* answer, which is a different question: it is the one exchange
/// where the peer may not be a daemon at all, and an HTTP server or an `ssh` banner on
/// port 5050 would otherwise leave the tool waiting for bytes that are never coming.
///
/// This originally covered only [`Client::handshake`], which runs only when `--token` was
/// given, so the stated protection covered the minority path and the ordinary
/// `thingino-dfu -l --host cam` had no deadline of any kind. It now covers the first
/// frame either way, and is lifted as soon as one arrives ([`Client::fill_first_frame`]).
///
/// It is not a substitute for [`KEEPALIVE_IDLE`]: a peer that vanishes *after* the first
/// frame is the keepalive's business, and no fixed read deadline could tell that from a
/// long erase.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a send may make **no progress at all** before it is given up on
/// (`SO_SNDTIMEO`).
///
/// The read side has three instruments and the send side had none, so a peer that
/// accepted the connection and then stopped reading blocked a 64 MiB `CMD_WRITE` with no
/// output, no counter and no deadline. Keepalive does not cover it: the kernel sends no
/// probes while there is unacknowledged data queued, so what applies instead is the
/// retransmission budget (about fifteen minutes on Linux) and, against a peer that keeps
/// acknowledging zero-window probes, nothing at all.
///
/// The daemon accepts serially, so a queued client is an ordinary event and not a fault;
/// five minutes is the wait it gets. `SO_SNDTIMEO` bounds each `write` call rather than
/// the whole transfer, so this is five minutes of a peer taking **nothing**, not five
/// minutes of a slow one: a 64 MiB image over a 1 MB/s link keeps moving throughout and
/// never comes near it.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a quiet connection goes before the kernel starts probing it (`TCP_KEEPIDLE`).
///
/// Comfortably longer than anything this client does between frames on a working link,
/// and short enough that a dead host is noticed inside the operator's patience. The
/// probes themselves cost two packets a minute.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);

/// How long between keepalive probes once one has gone unanswered (`TCP_KEEPINTVL`).
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// How many unanswered probes end the connection (`TCP_KEEPCNT`).
///
/// Six at [`KEEPALIVE_INTERVAL`] after [`KEEPALIVE_IDLE`] is about two minutes from "the
/// host went away" to a failed `read` that says the connection dropped, against for ever
/// without it.
pub const KEEPALIVE_PROBES: u32 = 6;

/// The most an interleaved `RESP_LOG` or `RESP_PROGRESS` frame may announce.
///
/// The C's own bound (`cli/remote.c:190`), kept because it is right: a
/// log frame carries **one line**. Anything larger is a daemon that has lost frame sync,
/// and the C's silent drain hides exactly that.
pub const MAX_INTERMEDIATE: u32 = 64 * 1024;

/// How many `RESP_LOG` and `RESP_PROGRESS` frames one command may be answered with
/// before its final frame arrives.
///
/// **The one bound no deadline can supply.** [`HANDSHAKE_TIMEOUT`] is lifted the moment
/// the first frame lands, and the keepalive's job is telling a peer that has *vanished*
/// from one that is merely slow, so a peer that is alive and streaming falls between
/// them, and the frame loop would read and print for as long as it kept talking. That is
/// a desynchronised daemon, or one on a path an attacker holds; either way a command that
/// never ends cannot be waited out.
///
/// A million is far past any real answer. The largest one this client accepts is a
/// 512 MiB read ([`MAX_READ`]), and at the 4096-byte transfer size every shipped loader
/// reports that is 131 072 byte counts, hence that many progress frames: the cap is eight
/// times the largest legitimate command, so reaching it means the daemon was never going
/// to finish.
pub const MAX_INTERMEDIATE_FRAMES: u64 = 1024 * 1024;

/// The most a `CMD_READ` may announce before the answer is refused unread.
///
/// A read is the one payload exempt from the wire's 64 MiB cap, because a NAND alt 0 is
/// 256 MiB. The exemption is not a licence: without a ceiling the announced length is a
/// `u32`, so a daemon that has lost frame sync can make this client write about 4 GiB to
/// the operator's disk before the file error it then reports is anything but a full disk.
/// 512 MiB is twice the largest part in the tree and three orders of magnitude below
/// that, and an absurd announcement is refused before the first byte is written rather
/// than after the last one.
const MAX_READ: u64 = 512 * 1024 * 1024;

/// Bytes moved per `read` while streaming a `CMD_READ` payload to a file.
///
/// The same 64 KiB the C uses (`cli/remote.c:328`). It bounds the client's memory at
/// this, whatever the payload announces — a NAND alt 0 is 256 MiB, four times the
/// payload cap.
const CHUNK: usize = 64 * 1024;

/// The token handshake's two auth refusals, and there are only two.
///
/// The daemon builds both in one place (`tdfu-daemon/src/auth.rs:56-61`) and the wire
/// freezes the pair, which is what makes each of them evidence rather than a guess: an
/// `auth: ` body arriving where **no** handshake was sent says the daemon wants one
/// ([`Client::refusal_for`]), and a handshake answered with *neither* string says the
/// daemon read the handshake as a command ([`Client::handshake`]).
const AUTH_REFUSALS: [&str; 2] = ["auth: invalid token", "auth: bad handshake"];

/// What every one of [`AUTH_REFUSALS`] begins with.
const AUTH_PREFIX: &str = "auth: ";

/// An open conversation with one daemon.
#[derive(Debug)]
pub struct Client {
    /// The socket, blocking, with no read deadline once the handshake is done.
    stream: TcpStream,
    /// Where it goes, for every message that has to name it.
    at: Address,
    /// Whether the token handshake was sent, which is to say whether `--token` was
    /// given. It decides how an `auth: ` refusal is read: see [`Client::refusal_for`].
    sent_token: bool,
    /// Whether the peer has yet to prove it is a daemon by sending one frame.
    ///
    /// True only on the no-token path, where nothing else does: with a token the
    /// handshake has already answered under its own deadline. See
    /// [`Client::fill_first_frame`].
    awaiting_first_frame: bool,
    /// [`HANDSHAKE_TIMEOUT`], or a short one a test injects.
    ///
    /// A field rather than the constant read in place, because 30 s is not a number a
    /// test can wait out: the deadline was previously unreachable by any test at all, and
    /// deleting the whole `set_read_timeout` call left the suite green.
    deadline: Duration,
    /// [`MAX_INTERMEDIATE_FRAMES`], or a small one a test injects.
    ///
    /// A field for the same reason `deadline` is one: a million frames is not a number a
    /// test can send, and a bound nothing can reach is a bound nothing pins.
    intermediate_budget: u64,
}

impl Client {
    /// Resolve, connect, and, if there is a token, run the token handshake.
    ///
    /// # Errors
    /// [`RemoteError::Protocol`] (exit 4) naming the address and the reason: the
    /// resolver's, or **one per resolved address** for a failed connect
    /// ([`connect_failed`]), or the handshake's — which distinguishes a dropped
    /// connection from a rejected token, where the C reports both as `Auth failed`
    /// (`cli/remote.c:138-147`).
    pub fn connect(at: Address, token: Option<&str>) -> Result<Self, RemoteError> {
        Self::connect_with(at, token, HANDSHAKE_TIMEOUT)
    }

    /// [`connect`](Client::connect), with the first-answer deadline as a parameter.
    ///
    /// The one caller outside tests passes [`HANDSHAKE_TIMEOUT`]; tests pass milliseconds,
    /// because a 30 s deadline is one no test can wait out and an untestable deadline is
    /// how this one came to be pinned by nothing at all.
    fn connect_with(at: Address, token: Option<&str>, deadline: Duration) -> Result<Self, RemoteError> {
        let addresses = resolve(&at)?;
        let mut attempts = Vec::with_capacity(addresses.len());
        let mut connected = None;
        for address in addresses {
            // Resolver order is kept: `getaddrinfo` puts IPv6 first under RFC 6724, so a
            // dual-stacked daemon is reached over v6 and v4 is the fallback rather than
            // the default (`cli/remote.c:100-113` says the same and means it).
            match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(reason) => attempts.push(Attempt { address, reason }),
            }
        }
        let Some(stream) = connected else {
            return Err(connect_failed(&at, &attempts));
        };
        tracing::debug!(peer = ?stream.peer_addr().ok(), "connected");
        keepalive(&stream);
        // Armed once, for the life of the connection: every send goes through
        // `write_all`, and a peer that stops reading is the one fault the read deadlines
        // and the keepalive between them cannot see. A platform that refuses the option
        // says so in the diagnostics rather than costing the run.
        if let Err(source) = stream.set_write_timeout(Some(SEND_TIMEOUT)) {
            tracing::debug!(%source, "no send deadline on this platform; a peer that stops reading may block");
        }

        let mut client = Self {
            stream,
            at,
            sent_token: token.is_some(),
            awaiting_first_frame: token.is_none(),
            deadline,
            intermediate_budget: MAX_INTERMEDIATE_FRAMES,
        };
        if let Some(token) = token {
            client.handshake(token)?;
        }
        Ok(client)
    }

    /// Where this client is talking to.
    #[must_use]
    pub const fn at(&self) -> &Address {
        &self.at
    }

    /// The socket, for the one test that reads back what [`keepalive`] set on it.
    #[cfg(test)]
    const fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// The intermediate-frame budget, as a test injects it.
    #[cfg(test)]
    fn with_intermediate_budget(mut self, frames: u64) -> Self {
        self.intermediate_budget = frames;
        self
    }

    /// The token handshake: `[magic][version][len][token]`, then one response frame.
    ///
    /// # The five outcomes are five messages
    ///
    /// The C has two (`cli/remote.c:138-147`): `Auth failed: <payload>` and
    /// `Auth failed`, and a **dropped connection takes the second one** because
    /// `net_recv_all(...) < 0 || resp.status != RESP_OK` is one condition. A user then
    /// debugs a token that was never rejected. Here: a closed socket says so, a
    /// rejection quotes the daemon, a rejection with no payload says the daemon gave no
    /// reason, a frame that is not OK/ERROR names what did arrive, and a rejection that
    /// is neither of [`AUTH_REFUSALS`] says what it really is.
    ///
    /// # `--token` against a daemon that has none
    ///
    /// That daemon never enters the handshake path at all (it gates on
    /// `auth.is_required()`), so the six handshake bytes plus the token are decoded as a
    /// **command header**: `command` is the token's length byte and `payload_len` is the
    /// token's first four bytes. Any printable four-byte run is at least `0x20202020`
    /// (538 M), well past the 64 MiB cap, so the header is refused as `payload too large`
    /// and the connection ends. Reporting that as `rejected the token: payload too large`
    /// sends the operator to check a secret that was never read, so it is reported as
    /// what it is.
    ///
    /// Worth knowing while reading that: for a token of 1 to 8 bytes the length byte is a
    /// **valid command** (3 is `CMD_WRITE`, 8 is `CMD_REBOOT`), and it is only the cap
    /// check on those four payload bytes that stops the daemon dispatching it. Nothing
    /// here depends on that, and it is the reason the wording says "read it as a command
    /// header" rather than "ignored it".
    fn handshake(&mut self, token: &str) -> Result<(), RemoteError> {
        let Ok(len) = u8::try_from(token.len()) else {
            // `(uint8_t)strlen(token)` (`cli/remote.c:124`) truncates, so a 300-byte
            // token authenticates as a *different* 44-byte one and the failure reads as
            // a wrong password. Nothing is truncated here.
            return Err(RemoteError::protocol(format!(
                "--token is {} bytes; the handshake's length field is one byte, so 255 is the maximum",
                token.len()
            )));
        };

        let mut frame = Vec::with_capacity(6 + token.len());
        frame.extend_from_slice(&tdfu_proto::MAGIC.to_be_bytes());
        frame.push(tdfu_proto::VERSION);
        frame.push(len);
        frame.extend_from_slice(token.as_bytes());

        // The deadline covers the whole handshake and is lifted afterwards; see
        // `HANDSHAKE_TIMEOUT`.
        let deadline = self.stream.set_read_timeout(Some(self.deadline));
        if let Err(source) = deadline {
            tracing::debug!(%source, "no read deadline on this platform; the handshake may block");
        }
        self.write_all(&frame, "the token handshake")?;

        let header = self.header("the token handshake")?;
        let payload = self.intermediate_payload(header.payload_len, "the token handshake")?;
        let message = crate::render::sanitise(&String::from_utf8_lossy(&payload));
        let outcome = match header.status {
            Status::Ok => Ok(()),
            Status::Error if message.is_empty() => Err(RemoteError::protocol(format!(
                "the daemon at {} rejected the token, and sent no reason",
                self.at
            ))),
            // **Neither of the two auth strings**, so the auth path did not answer:
            // the peer read the handshake bytes as a command header, which is what a
            // daemon started without `--token` does.
            Status::Error if !AUTH_REFUSALS.contains(&message.as_str()) => Err(RemoteError::protocol(format!(
                "the daemon at {} answered the token handshake with \"{message}\", which is not one of the two \
                 refusals its auth path can send: it read the handshake as a command header, so it was started \
                 without --token. Drop --token, or restart the daemon with one",
                self.at
            ))),
            Status::Error => Err(RemoteError::protocol(format!(
                "the daemon at {} rejected the token: {message}",
                self.at
            ))),
            other => Err(RemoteError::protocol(format!(
                "the daemon at {} answered the token handshake with a {} frame instead of ok or error",
                self.at,
                status_name(other)
            ))),
        };
        let _ignored = self.stream.set_read_timeout(None);
        outcome
    }

    /// Send one command: a 10-byte header, then the payload.
    ///
    /// # Errors
    /// [`RemoteError::Protocol`] if the encode refuses a field (a `--alt` longer than its
    /// one-byte prefix is refused rather than silently becoming a different, valid alt —
    /// the audit's `tdfu-proto` finding), or if the socket fails while sending.
    pub fn send(&mut self, request: &Request, doing: &str) -> Result<(), RemoteError> {
        let payload = request
            .encode()
            .map_err(|source| RemoteError::protocol(format!("this client cannot put {doing} on the wire: {source}")))?;
        let Ok(payload_len) = u32::try_from(payload.len()) else {
            return Err(too_big(doing, payload.len()));
        };
        if exceeds_payload_cap(payload_len) {
            return Err(too_big(doing, payload.len()));
        }
        let header = RequestHeader {
            command: request.command(),
            payload_len,
        };
        self.write_all(&header.encode(), doing)?;
        if !payload.is_empty() {
            self.write_all(&payload, doing)?;
        }
        tracing::debug!(command = ?request.command(), payload_len, "sent");
        Ok(())
    }

    /// Read frames until the final one, rendering everything on the way, and hand back
    /// the `RESP_OK` payload.
    ///
    /// The payload cap applies **here and not in [`read_to`]**: a final response
    /// past the payload cap is refused, because the only payload that may exceed it is a
    /// streamed `CMD_READ`.
    ///
    /// # Errors
    /// [`RemoteError::Refused`] for a `RESP_ERROR` — the operation happened and failed on
    /// the far side, so the exit code is the running operation's class — and
    /// [`RemoteError::Protocol`] for everything else.
    pub fn finish(&mut self, doing: &str, bar: &mut Bar, err: &mut dyn Write) -> Result<Vec<u8>, RemoteError> {
        let header = self.until_final(doing, bar, err)?;
        match header.status {
            Status::Ok => {
                if exceeds_payload_cap(header.payload_len) {
                    return Err(RemoteError::protocol(format!(
                        "the daemon at {} answered {doing} with {} bytes, past the {}-byte payload cap; \
                         only a read is streamed past it",
                        self.at,
                        header.payload_len,
                        tdfu_proto::MAX_PAYLOAD
                    )));
                }
                self.payload(header.payload_len, doing)
            }
            Status::Error => {
                let payload = self.intermediate_payload(header.payload_len, doing)?;
                Err(self.refusal_for(doing, String::from_utf8_lossy(&payload).trim_end()))
            }
            other => Err(self.unexpected_final(doing, other)),
        }
    }

    /// Stream a `CMD_READ` payload (`[data][crc32 BE]`) into `out`.
    ///
    /// **Nothing is buffered.** The payload may be 256 MiB (a NAND alt 0, four times the
    /// cap) and it goes to the file in [`CHUNK`]-sized pieces as it arrives, with the
    /// CRC-32 computed on the way. That is the cap's client-half exemption, and it is
    /// why this and [`finish`](Client::finish) are two functions rather than a flag.
    ///
    /// `limit` is `--size`. The wire has no length field on `CMD_READ`, so the daemon
    /// sends the whole alt either way and the cap is applied here, to the file: the
    /// remaining bytes are still received (the connection is a stream and the CRC covers
    /// all of them) and simply not written. The caller says so before the transfer starts
    /// rather than leaving the operator to wonder why the "sample" took twenty minutes.
    ///
    /// Returns how many bytes reached `out`.
    ///
    /// **A failure part way names the file it left behind.** By the time the connection
    /// can drop, the bytes are already on disk (nothing is buffered), so a `-r` that
    /// stops has produced a real, short file. The local `-r` arm makes saying so the
    /// policy ("the file is short and here is where", `run::Session::read`), and the CRC
    /// arm below already does it for its own case; a dropped connection said nothing at
    /// all, leaving a truncated dump on the operator's disk with no note against it.
    ///
    /// # Errors
    /// [`RemoteError::Refused`] for a `RESP_ERROR`; [`RemoteError::File`] if `out`
    /// refuses the bytes (exit 3, as locally, and it already names the path);
    /// [`RemoteError::Protocol`] for a short payload, a dropped connection or a CRC
    /// mismatch.
    pub fn read_to(
        &mut self,
        doing: &str,
        out: &mut dyn Write,
        path: &std::path::Path,
        limit: Option<u64>,
        bar: &mut Bar,
        err: &mut dyn Write,
    ) -> Result<u64, RemoteError> {
        let header = self.until_final(doing, bar, err)?;
        match header.status {
            Status::Ok => {}
            Status::Error => {
                let payload = self.intermediate_payload(header.payload_len, doing)?;
                return Err(self.refusal_for(doing, String::from_utf8_lossy(&payload).trim_end()));
            }
            other => return Err(self.unexpected_final(doing, other)),
        }

        // The CRC is the last four bytes of the payload, so a payload that cannot hold
        // one is not a read (`cli/remote.c:316-318`).
        if u64::from(header.payload_len) > MAX_READ {
            return Err(RemoteError::protocol(format!(
                "the daemon at {} answered {doing} with {} bytes, and the largest part this build knows of is \
                 {MAX_READ} bytes: the connection has lost frame sync and this client will not write that to a \
                 file",
                self.at, header.payload_len
            )));
        }
        let Some(data_len) = u64::from(header.payload_len).checked_sub(4) else {
            return Err(RemoteError::protocol(format!(
                "the daemon at {} answered {doing} with {} bytes, which is shorter than the 4-byte CRC-32 that ends it",
                self.at, header.payload_len
            )));
        };

        let mut crc = tdfu_proto::Crc32::new();
        let mut buffer = vec![0_u8; CHUNK];
        let mut received = 0_u64;
        let mut written = 0_u64;
        while received < data_len {
            let want = usize::try_from((data_len - received).min(CHUNK as u64)).unwrap_or(CHUNK);
            // `CHUNK` is positive and `received < data_len`, so `want` is positive by
            // construction. Saying so out loud is an audit rule applied to this
            // loop: an iteration that moves no bytes does not fail, it **hangs**, and a
            // hang burns a slot and reports nothing where a failure names itself. Three
            // separate mutations of this loop reach it (`CHUNK` to zero, and both
            // relaxations of the `<`), and every one of them was a timeout rather than a
            // caught mutant until this was here.
            if want == 0 {
                return Err(RemoteError::protocol(format!(
                    "this client asked for a zero-byte chunk {received} bytes into {doing}, \
                     so the read would never finish; this is a bug in thingino-dfu, not in the command"
                )));
            }
            // The first chunk of a streamed read is the first frame's body when nothing
            // was logged before it, so it carries the first-answer deadline; from the
            // second chunk on this is plain [`fill`](Client::fill).
            let filled = self.fill_first_frame(&mut buffer[..want], doing);
            self.first_frame_done();
            filled.map_err(|error| short_file(error, path, written))?;
            crc.update(&buffer[..want]);
            received += want as u64;

            // `--size`: keep the first `limit` bytes and drop the rest on the floor.
            let keep = limit.map_or(want, |limit| {
                usize::try_from(limit.saturating_sub(written)).unwrap_or(want).min(want)
            });
            // `keep > 0` and `keep >= 0` are the same behaviour here and mutation testing
            // says so: `keep` is a `usize`, `write_all` of an empty slice calls `write`
            // not at all, and `written += 0` changes nothing. The guard is kept for what
            // it says, not for what it does.
            if keep > 0 {
                out.write_all(&buffer[..keep])
                    .map_err(|source| RemoteError::file(format!("cannot write to {}", path.display()), &source))?;
                written += keep as u64;
            }
            bar.render(
                &tdfu_core::Progress::Bytes {
                    phase: tdfu_core::progress::Phase::Upload,
                    done: received,
                    total: Some(data_len),
                },
                err,
            );
        }
        out.flush()
            .map_err(|source| RemoteError::file(format!("cannot write to {}", path.display()), &source))?;

        let mut trailer = [0_u8; 4];
        // A different sentence from the loop's: every data byte arrived, so the file is
        // **not** short, it is unchecked. Saying "short" here would be the tool asserting
        // something untrue about a file on the operator's disk.
        self.fill(&mut trailer, doing).map_err(|error| match error {
            RemoteError::Protocol(message) if written > 0 => RemoteError::protocol(format!(
                "{message}; {} holds the {written} bytes that arrived, but the CRC-32 that would check them \
                 never did, so it must not be written back to a device",
                path.display()
            )),
            other => other,
        })?;
        let expected = u32::from_be_bytes(trailer);
        let actual = crc.finalize();
        if expected != actual {
            // The file is **kept**, exactly as a failed local `-r` keeps its partial
            // dump: it is what an operator inspects to find out what went wrong, and the
            // C deleting it (`cli/remote.c:359`) turns a diagnosable failure into a
            // repeat of the same twenty minutes. What the C never does is say the file
            // must not be trusted, and that is the half worth having.
            return Err(RemoteError::protocol(format!(
                "the {received} bytes read from {} hash to CRC-32 {actual:#010X}, but the daemon says {expected:#010X}: \
                 the image arrived corrupted. {} holds what arrived and must not be written back to a device",
                self.at,
                path.display()
            )));
        }
        Ok(written)
    }

    // -----------------------------------------------------------------
    // Frames.
    // -----------------------------------------------------------------

    /// Render `RESP_LOG` and `RESP_PROGRESS` frames until a final one arrives, or until
    /// the peer has sent [`MAX_INTERMEDIATE_FRAMES`] of them without one.
    ///
    /// The budget is per command, because that is the unit the peer has to finish: a run
    /// that erases, writes, verifies and reads sends four commands, and each is answered
    /// under its own count.
    fn until_final(&mut self, doing: &str, bar: &mut Bar, err: &mut dyn Write) -> Result<ResponseHeader, RemoteError> {
        let mut intermediates: u64 = 0;
        loop {
            let header = self.header(doing)?;
            // Counted on the header and refused before the payload, so the frame that
            // breaks the budget is neither read nor rendered.
            if matches!(header.status, Status::Log | Status::Progress) {
                intermediates += 1;
                if intermediates > self.intermediate_budget {
                    return Err(RemoteError::protocol(format!(
                        "the daemon at {} has sent {intermediates} log and progress frames during {doing} and no \
                         final answer; a command that never ends cannot be waited out, so this client is giving up \
                         on it",
                        self.at
                    )));
                }
            }
            match header.status {
                Status::Log => {
                    let payload = self.intermediate_payload(header.payload_len, doing)?;
                    // **Blanking the counter is this client's job.** Byte counts are
                    // `RESP_PROGRESS` frames now, so a live counter may be on the line
                    // when a log line arrives; the counter is blanked first or the two
                    // overwrite each other.
                    bar.clear(err);
                    // The daemon wrote these bytes and they go straight to a terminal, so
                    // the control characters in them are made visible first
                    // ([`crate::render::sanitise`]).
                    let text = crate::render::sanitise(&String::from_utf8_lossy(&payload));
                    let _ignored = err.write_all(text.as_bytes());
                    // Verbatim, plus the newline the daemon may not have sent: a line
                    // that does not end one leaves the next write mid-line.
                    if !text.ends_with('\n') {
                        let _ignored = err.write_all(b"\n");
                    }
                    let _ignored = err.flush();
                }
                // **A malformed progress body does not kill the transfer.** The frame's
                // announced length was honoured, so frame sync is intact and the next
                // frame is readable; what is unreadable is the *body*, which is a
                // counter. Refusing here aborted a write or a read the daemon went on to
                // complete, over a cosmetic frame, and `Status::Log` in the same loop is
                // already lenient (`from_utf8_lossy`). The C ignores one and carries on
                // (`cli/remote.c:197-205` renders only when the inner length fits).
                //
                // A length that is *impossible* is still refused: that is
                // [`intermediate_payload`](Client::intermediate_payload) above, and it is
                // the case where sync really has been lost.
                Status::Progress => {
                    let payload = self.intermediate_payload(header.payload_len, doing)?;
                    match ProgressBody::decode(&payload) {
                        Ok(body) => bar.wire(body.percent, body.stage, &body.message, err),
                        Err(source) => {
                            bar.note(
                                &format!(
                                    "note: the daemon at {} sent a progress frame this client cannot read during \
                                     {doing} ({source}); the operation itself is unaffected",
                                    self.at
                                ),
                                err,
                            );
                            // `percent` and `stage` are the body's first two bytes at
                            // fixed offsets, so whatever did arrive is still drawn rather
                            // than thrown away with the message that spoiled it.
                            if let (Some(percent), Some(stage)) = (payload.first(), payload.get(1)) {
                                bar.wire(*percent, *stage, "", err);
                            }
                        }
                    }
                }
                _ => return Ok(header),
            }
        }
    }

    /// One response header, with magic, **version** and status all checked.
    fn header(&mut self, doing: &str) -> Result<ResponseHeader, RemoteError> {
        let mut bytes = [0_u8; HEADER_LEN];
        self.fill_first_frame(&mut bytes, doing)?;
        ResponseHeader::decode(&bytes).map_err(|source| match source {
            ProtoError::BadMagic => RemoteError::protocol(format!(
                "{} answered {doing} with a frame that does not begin with the TDFU magic: \
                 that port is answering, but not as a dfu-remote daemon",
                self.at
            )),
            // **The check the C never makes** (`cli/remote.c:232` tests the magic only).
            // A daemon one version ahead sends frames whose headers decode and whose
            // payloads do not, so without this the failure lands somewhere else entirely.
            ProtoError::VersionMismatch => RemoteError::protocol(format!(
                "the daemon at {} speaks protocol version {}; this client speaks {}. \
                 The two are not interchangeable — update whichever is older",
                self.at,
                bytes[4],
                tdfu_proto::VERSION
            )),
            ProtoError::UnknownStatus => RemoteError::protocol(format!(
                "the daemon at {} answered {doing} with response kind {}, which protocol version {} does not define",
                self.at,
                bytes[5],
                tdfu_proto::VERSION
            )),
            other => RemoteError::protocol(format!(
                "the daemon at {} sent a frame this client cannot read during {doing}: {other}",
                self.at
            )),
        })
    }

    /// The payload of a final `RESP_OK`, already known to be within the cap.
    fn payload(&mut self, len: u32, doing: &str) -> Result<Vec<u8>, RemoteError> {
        let mut payload = vec![0_u8; len as usize];
        // Every frame's body but a streamed read's comes through here, so this is where
        // the first frame becomes a whole frame and the first-answer deadline is lifted.
        let filled = self.fill_first_frame(&mut payload, doing);
        self.first_frame_done();
        filled?;
        Ok(payload)
    }

    /// The payload of a frame that is supposed to be small: a log line, a progress body,
    /// an error message, the handshake's answer.
    fn intermediate_payload(&mut self, len: u32, doing: &str) -> Result<Vec<u8>, RemoteError> {
        if len > MAX_INTERMEDIATE {
            return Err(RemoteError::protocol(format!(
                "the daemon at {} announced a {len}-byte frame during {doing}, where a line of text was due; \
                 the connection has lost frame sync and this client will not read past it",
                self.at
            )));
        }
        self.payload(len, doing)
    }

    /// A `RESP_ERROR` body, as the failure it actually is.
    ///
    /// Nearly always [`RemoteError::Refused`]: the daemon attempted the operation and it
    /// failed, so the exit code is the running operation's class.
    ///
    /// **The exception is an `auth: ` body arriving when no handshake was sent.** A
    /// daemon started *with* `--token` reads this client's first 10-byte command header
    /// as the token handshake (magic and version pass, the command byte is taken for
    /// the token length and the head of `payload_len` for the token), so it mismatches
    /// and answers one of [`AUTH_REFUSALS`] before closing. Read as an operation's own
    /// refusal that becomes "could not complete the device list: auth: invalid token" at
    /// exit **1**, which tells a wrapper "device error, retry" for something that was
    /// never attempted and never says the word `--token`. The wire freezes those two
    /// strings, so with no handshake sent the prefix is unambiguous: it is the handshake
    /// failing, which is exit **4**.
    fn refusal_for(&self, doing: &str, message: &str) -> RemoteError {
        // A refusal is quoted into a line `main` prints, so the daemon's bytes are made
        // visible before they reach a terminal ([`crate::render::sanitise`]). Neither of
        // [`AUTH_REFUSALS`] contains a control character, so the test below reads the
        // same either way.
        let message = &crate::render::sanitise(message);
        if !self.sent_token && message.starts_with(AUTH_PREFIX) {
            return RemoteError::protocol(format!(
                "the daemon at {} requires a token and none was sent: it read {doing}'s command header as \
                 the handshake and answered \"{message}\". Pass --token with the secret the daemon was \
                 started with",
                self.at
            ));
        }
        RemoteError::refused(&self.at, doing, message)
    }

    /// A final frame that is neither OK nor ERROR — unreachable while
    /// [`Status`] has four members, and named rather than assumed if that changes.
    fn unexpected_final(&self, doing: &str, status: Status) -> RemoteError {
        RemoteError::protocol(format!(
            "the daemon at {} ended {doing} with a {} frame, which is not an answer",
            self.at,
            status_name(status)
        ))
    }

    // -----------------------------------------------------------------
    // The socket.
    // -----------------------------------------------------------------

    /// Fill `buffer` completely, or say exactly how the connection failed to.
    ///
    /// Three outcomes, three messages. `std::io::Read::read_exact` collapses the first
    /// two into `UnexpectedEof` with no count, which is why this is a loop:
    ///
    /// * **nothing at all** — the daemon closed the connection cleanly. That is a
    ///   *dropped connection*, and it is reported as one wherever it happens, including
    ///   during the handshake, where the C calls it `Auth failed`
    ///   (`cli/remote.c:138`);
    /// * **some, then EOF** — it died mid-frame, and how far it got is the difference
    ///   between "it rejected us" and "it crashed halfway through an answer";
    /// * **an OS error**, reported with its own text, except an expired deadline, which
    ///   is reported as the deadline it is.
    ///
    /// That last one is `CONNECT_TIMEOUT`'s rule applied where it was missing: a timeout
    /// must be *reported* as a timeout, one of the three faults that have to stay
    /// distinguishable from each other. `SO_RCVTIMEO` expiring surfaces as
    /// `WouldBlock` on Unix and `TimedOut` on Windows, and the bare `io::Error` reads
    /// `Resource temporarily unavailable (os error 11)`, which names neither the deadline
    /// nor what was being waited for.
    fn fill(&mut self, buffer: &mut [u8], doing: &str) -> Result<(), RemoteError> {
        // The read's borrow of `self.stream` ends with the call, so the message can be
        // built from `&self` afterwards, which is what lets `stopped` be a method a test
        // can call with a `Stopped` a socket cannot be made to produce.
        let outcome = fill_from(&mut self.stream, buffer);
        outcome.map_err(|stopped| self.stopped(stopped, doing))
    }

    /// The message for a read that stopped short of what was asked for.
    ///
    /// Split from [`fill`](Client::fill) so each arm has a caller: `Stopped::Failed`'s
    /// sentence was reachable only through a socket error that cannot be provoked on
    /// loopback, so mutating its wording survived the whole suite.
    fn stopped(&self, stopped: Stopped, doing: &str) -> RemoteError {
        match stopped {
            Stopped::Closed => RemoteError::protocol(format!(
                "the daemon at {} closed the connection during {doing}",
                self.at
            )),
            Stopped::Dropped { got, want } => RemoteError::protocol(format!(
                "the connection to {} dropped after {got} of {want} bytes during {doing}",
                self.at
            )),
            Stopped::Failed(source) if timed_out(&source) => RemoteError::protocol(format!(
                "{} accepted the connection and then sent nothing for {:?} during {doing}: \
                 that deadline covers the handshake and the first answer only, so something is \
                 listening on that port but it is not answering as a dfu-remote daemon",
                self.at, self.deadline
            )),
            Stopped::Failed(source) => {
                RemoteError::protocol(format!("the connection to {} failed during {doing}: {source}", self.at))
            }
        }
    }

    /// [`fill`](Client::fill), with [`HANDSHAKE_TIMEOUT`] armed while the peer has still
    /// sent nothing.
    ///
    /// **Only the first frame, and only without `--token`.** Every header goes through
    /// here, so the first one is the first response of the first command; with a token
    /// the handshake already ran under the same deadline and the flag starts false. Once
    /// a frame has been read the deadline is lifted for the rest of the conversation
    /// ([`first_frame_done`](Client::first_frame_done)), because from then on silence
    /// means a whole-chip erase is running and not that the port is answered by something
    /// that is not a daemon.
    ///
    /// **A header is not a frame.** Ten bytes that decode are not proof of a daemon: a
    /// peer that sends a valid `RESP_LOG` header announcing 4096 bytes and then stops has
    /// answered nothing, and lifting the deadline there left the client blocking on the
    /// payload with no deadline and no keepalive expiry to end it (a peer that is alive
    /// and silent has its kernel answer the probes). So the payload of that first frame is
    /// read under the same deadline, and only a **complete** frame lifts it.
    fn fill_first_frame(&mut self, buffer: &mut [u8], doing: &str) -> Result<(), RemoteError> {
        if !self.awaiting_first_frame {
            return self.fill(buffer, doing);
        }
        if let Err(source) = self.stream.set_read_timeout(Some(self.deadline)) {
            tracing::debug!(%source, "no read deadline on this platform; the first response may block");
        }
        self.fill(buffer, doing)
    }

    /// The first frame is complete, or has failed: lift the deadline.
    ///
    /// Called where a frame ends rather than where its header does, and on the failure
    /// path too: a failure ends the run anyway, and leaving `SO_RCVTIMEO` set on a stream
    /// that outlives it would put a deadline on exactly the commands that must not have
    /// one. A no-op after the first call, and on the `--token` path from the start.
    fn first_frame_done(&mut self) {
        if !self.awaiting_first_frame {
            return;
        }
        self.awaiting_first_frame = false;
        let _ignored = self.stream.set_read_timeout(None);
    }

    /// Write every byte, naming what was being sent if the socket dies.
    fn write_all(&mut self, bytes: &[u8], doing: &str) -> Result<(), RemoteError> {
        self.stream
            .write_all(bytes)
            .map_err(|source| self.send_failed(&source, doing))
    }

    /// The message for a send that could not finish.
    ///
    /// Split from [`write_all`](Client::write_all) so the [`SEND_TIMEOUT`] arm has a
    /// caller a test can reach: filling a socket's send buffer needs a peer that accepts
    /// and never reads plus megabytes of traffic, and an untestable arm is how a wording
    /// goes wrong unnoticed. An expired `SO_SNDTIMEO` surfaces as `WouldBlock` on Unix
    /// and `TimedOut` on Windows, and the bare `io::Error` reads `Resource temporarily
    /// unavailable`, which names neither the deadline nor what was being sent.
    fn send_failed(&self, source: &io::Error, doing: &str) -> RemoteError {
        if timed_out(source) {
            return RemoteError::protocol(format!(
                "{} accepted the connection and then read nothing for {:?} while this client was sending \
                 {doing}: the daemon serves one client at a time, so it is probably busy with another run",
                self.at, SEND_TIMEOUT
            ));
        }
        RemoteError::protocol(format!(
            "the connection to {} failed while sending {doing}: {source}",
            self.at
        ))
    }
}

/// Why a read stopped short of the bytes that were asked for.
///
/// Split from the message it becomes so that the **loop** can be tested against a reader
/// that misbehaves on purpose — a socket cannot be made to return `EINTR` on demand, and
/// mutation testing found all three of that arm's mutants alive because of it.
#[derive(Debug)]
enum Stopped {
    /// Nothing arrived at all: the peer closed cleanly.
    Closed,
    /// Some arrived, then EOF.
    Dropped {
        /// How far it got.
        got: usize,
        /// How much was due.
        want: usize,
    },
    /// The OS refused.
    Failed(io::Error),
}

/// Read exactly `buffer.len()` bytes, retrying only what the OS says to retry.
///
/// `EINTR` is not a failure — the kernel interrupted the call and the read may still
/// succeed — so it loops. `std::io::Read::read_exact` does the same thing but collapses
/// [`Closed`](Stopped::Closed) and [`Dropped`](Stopped::Dropped) into one
/// `UnexpectedEof` with no count, and those two are the difference between "the daemon
/// rejected us" and "the daemon died halfway through an answer".
fn fill_from(reader: &mut dyn io::Read, buffer: &mut [u8]) -> Result<(), Stopped> {
    let want = buffer.len();
    let mut got = 0;
    while got < want {
        match reader.read(&mut buffer[got..]) {
            Ok(0) if got == 0 => return Err(Stopped::Closed),
            Ok(0) => return Err(Stopped::Dropped { got, want }),
            Ok(read) => got += read,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => return Err(Stopped::Failed(source)),
        }
    }
    Ok(())
}

/// Add the file a failed `-r` left behind to the failure that ended it.
///
/// Only when bytes actually reached it, and only for a wire failure: a
/// [`RemoteError::File`] already names the path, and a `RemoteError::Refused` arrives
/// before the first byte does. The wording says *short* rather than *partial*, because
/// what an operator must not do is flash it.
///
/// This is the **payload loop's** wording. A drop while reading the four trailing CRC
/// bytes leaves a file that is complete and unchecked rather than short, and says so at
/// its own call site.
fn short_file(error: RemoteError, path: &std::path::Path, written: u64) -> RemoteError {
    match error {
        RemoteError::Protocol(message) if written > 0 => RemoteError::protocol(format!(
            "{message}; {} holds the {written} bytes that arrived and is short",
            path.display()
        )),
        other => other,
    }
}

/// Did this read run out its `SO_RCVTIMEO` rather than fail?
///
/// Unix reports an expired receive deadline as `EAGAIN`/`EWOULDBLOCK` and Windows as
/// `WSAETIMEDOUT`, so both kinds mean the same thing. Neither is reachable any other way
/// on this socket: it is blocking throughout, and a deadline is armed only for the
/// handshake and the first frame.
fn timed_out(source: &io::Error) -> bool {
    matches!(source.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// Ask the kernel to notice a peer that stops existing.
///
/// **The one thing a read deadline cannot do.** A daemon host that is power-cut, or whose
/// route goes away, sends neither RST nor FIN, so a blocking `read` waits for ever, and
/// no fixed read deadline can be added instead, because a whole-chip erase is minutes of
/// silence by design. Keepalive probes distinguish the two: they never fire
/// on a live but slow peer, and on a dead one the connection fails in about
/// [`KEEPALIVE_IDLE`] plus [`KEEPALIVE_PROBES`] times [`KEEPALIVE_INTERVAL`].
///
/// A failure is logged and swallowed. `SO_KEEPALIVE` is an improvement on the C, which
/// sets nothing at all; refusing to talk to a daemon because a socket option did not take
/// would be trading a real capability for a hypothetical one.
fn keepalive(stream: &TcpStream) {
    // Every target this binary is built for (linux-gnu, windows-gnu, apple-darwin,
    // and the Android build of the library) supports all three setters. socket2 gates
    // them per platform, so an exotic new target names itself here at compile time
    // rather than silently losing the probes.
    let settings = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_PROBES);
    if let Err(source) = socket2::SockRef::from(stream).set_tcp_keepalive(&settings) {
        tracing::debug!(%source, "no TCP keepalive on this socket; a vanished host may block a read");
    }
}

/// Every address `--host` resolves to, in the resolver's order.
fn resolve(at: &Address) -> Result<Vec<SocketAddr>, RemoteError> {
    let addresses: Vec<SocketAddr> = (at.host(), at.port())
        .to_socket_addrs()
        .map_err(|source| {
            RemoteError::protocol(format!(
                "cannot resolve {at}: {source}. Check the name, or give an address"
            ))
        })?
        .collect();
    if addresses.is_empty() {
        // `getaddrinfo` can succeed with an empty list (a name with no A or AAAA
        // record). The C would then fall through its loop and print the same
        // `Failed to connect` as a refused port, which sends the user to the wrong place.
        return Err(RemoteError::protocol(format!(
            "{at} resolved to no addresses at all: the name exists but has no address record"
        )));
    }
    Ok(addresses)
}

/// A request too large to put on the wire.
///
/// The daemon refuses a header announcing more than the cap and ends the connection, so
/// sending it anyway trades a clear local message for `payload too large` and a dead
/// socket. The arithmetic the user needs — how much of the cap the fields took — is in
/// the message.
fn too_big(doing: &str, len: usize) -> RemoteError {
    RemoteError::protocol(format!(
        "{doing} needs a {len}-byte payload and the wire's cap is {} bytes, \
         so it cannot go through a daemon. Run this on the machine the camera is plugged into",
        tdfu_proto::MAX_PAYLOAD
    ))
}

/// What to call a status in a sentence.
fn status_name(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Error => "error",
        Status::Progress => "progress",
        Status::Log => "log",
        // `Status` is `#[non_exhaustive]`: a kind added later has no name here yet, and
        // saying so beats calling it one of the four above.
        _ => "unrecognised",
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, Client, Duration, MAX_INTERMEDIATE, Request, Status};
    use crate::exit::{FILE, OpClass, PROTOCOL};
    use crate::remote::fake::{FakeDaemon, Step};
    use crate::render::Bar;
    use std::io;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A sink that refuses everything, for the one file error a remote run can still
    /// reach after the preflight.
    struct FullDisk;

    impl io::Write for FullDisk {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::StorageFull, "No space left on device"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn client(port: u16) -> Result<Client, Box<dyn std::error::Error>> {
        Ok(Client::connect(Address::new("127.0.0.1", port), None)?)
    }

    /// **The half of the file-error rule the preflight cannot cover.** A `-r` whose
    /// file stops accepting bytes mid-transfer is a **file** error: exit 3, the path
    /// named, the OS reason kept, the same answer a local `-r` gives for the same disk.
    #[test]
    fn a_sink_that_fails_mid_read_is_a_file_error() -> TestResult {
        let mut payload = vec![0_u8; 32];
        payload.extend_from_slice(&tdfu_proto::crc32(&payload).to_be_bytes());
        let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(payload)]])?;

        let mut client = client(daemon.port())?;
        client.send(
            &Request::Read {
                index: 0,
                variant: Vec::new(),
                alt: None,
            },
            "the read",
        )?;
        let outcome = client.read_to(
            "the read",
            &mut FullDisk,
            std::path::Path::new("/tmp/tdfu-full.bin"),
            None,
            &mut Bar::new(),
            &mut io::sink(),
        );
        drop(client);
        daemon.transcript()?;

        let failure = outcome
            .err()
            .ok_or("the write should have failed")?
            .failure(OpClass::Transfer);
        assert_eq!(
            failure.to_string(),
            "cannot write to /tmp/tdfu-full.bin: No space left on device"
        );
        assert_eq!(failure.exit_code(), FILE, "a file error is 3, remotely as locally");
        Ok(())
    }

    /// A token longer than the handshake's one-byte length field is refused rather than
    /// truncated: `(uint8_t)strlen(token)` (`cli/remote.c:124`) would authenticate as a
    /// *different* token and read as a wrong password.
    #[test]
    fn a_token_longer_than_the_length_field_is_refused() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
        let outcome = Client::connect(Address::new("127.0.0.1", daemon.port()), Some(&"x".repeat(256)));
        daemon.transcript()?;

        let failure = outcome.err().ok_or("a 256-byte token must be refused")?;
        assert_eq!(
            failure.to_string(),
            "--token is 256 bytes; the handshake's length field is one byte, so 255 is the maximum"
        );
        assert_eq!(failure.failure(OpClass::Remote).exit_code(), PROTOCOL);
        Ok(())
    }

    /// The intermediate-frame bound is the C's own 64 KiB (`cli/remote.c:190`), and a
    /// frame exactly on it is still read: it is a maximum, not a limit to trip over.
    ///
    /// The length is a **literal**, not `MAX_INTERMEDIATE`: a test that builds its
    /// fixture from the constant it is checking moves with it, and mutation testing found
    /// exactly that — `64 * 1024` mutated to `64 + 1024` and this test still passed.
    #[test]
    fn an_intermediate_frame_of_exactly_the_bound_is_read() -> TestResult {
        assert_eq!(MAX_INTERMEDIATE, 65_536, "`cli/remote.c:190`'s bound");
        let line = "l".repeat(65_536);
        let daemon = FakeDaemon::start(false, vec![vec![Step::Log(line.clone()), Step::Ok(b"OK".to_vec())]])?;
        let mut client = client(daemon.port())?;
        client.send(&Request::Status, "the status request")?;
        let mut rendered = Vec::new();
        let payload = client.finish("the status request", &mut Bar::new(), &mut rendered)?;
        drop(client);
        daemon.transcript()?;

        assert_eq!(payload, b"OK");
        assert_eq!(rendered.len(), line.len() + 1, "the line, plus the newline it lacked");
        Ok(())
    }

    /// **A daemon does not get to drive the terminal.** A log frame's control characters
    /// are made visible instead of being executed.
    ///
    /// The transport is plain TCP and the token authenticates this client to the daemon,
    /// never the daemon to this client, so a peer on the path can put anything in a log
    /// frame. `\x1b[2J\x1b[H` clears the screen and homes the cursor, and a fabricated
    /// transcript after it is indistinguishable from a real one; a bare `\r` silently
    /// discards the line this client has already printed.
    #[test]
    fn a_log_frame_cannot_clear_the_screen() -> TestResult {
        let daemon = FakeDaemon::start(
            false,
            vec![vec![
                Step::Log("\x1b[2J\x1b[Hall good\rnothing to see".to_owned()),
                Step::Ok(b"OK".to_vec()),
            ]],
        )?;
        let mut client = client(daemon.port())?;
        client.send(&Request::Status, "the status request")?;
        let mut rendered = Vec::new();
        client.finish("the status request", &mut Bar::new(), &mut rendered)?;
        drop(client);
        daemon.transcript()?;

        let text = String::from_utf8(rendered)?;
        assert_eq!(text, "^[[2J^[[Hall good^Mnothing to see\n", "{text:?}");
        assert!(!text.contains('\x1b'), "no escape reaches the terminal: {text:?}");
        assert!(!text.contains('\r'), "and no carriage return either: {text:?}");
        Ok(())
    }

    /// **A daemon that never answers is given up on**, and one that merely talks a lot is
    /// not: both directions, because a bound that refused a chatty daemon would be worse
    /// than no bound at all.
    ///
    /// This is the case the deadlines cannot reach. The first-answer deadline is lifted
    /// by the first frame; the keepalive sees a peer that has vanished, and this one is
    /// alive and sending. Without the budget the loop reads and prints for as long as the
    /// peer keeps going.
    ///
    /// The budget is injected at four, because the shipped one is a million frames and a
    /// test cannot send those; the constant itself is pinned as a literal below.
    #[test]
    fn a_daemon_that_never_answers_is_given_up_on() -> TestResult {
        let budget = 4;

        // Exactly the budget, then the answer: a maximum, not a limit to trip over.
        let mut within = vec![Step::Log("still erasing\n".to_owned()); 4];
        within.push(Step::Ok(b"OK".to_vec()));
        let daemon = FakeDaemon::start(false, vec![within])?;
        let mut client =
            Client::connect(Address::new("127.0.0.1", daemon.port()), None)?.with_intermediate_budget(budget);
        client.send(&Request::Status, "the status request")?;
        let payload = client.finish("the status request", &mut Bar::new(), &mut io::sink())?;
        drop(client);
        daemon.transcript()?;
        assert_eq!(payload, b"OK", "a talkative daemon that finishes is still a daemon");

        // One frame past it, and the answer that never comes is refused instead of
        // waited for. The fake's own writes may fail once the client walks away, which is
        // this test's subject rather than trouble in the double.
        let daemon = FakeDaemon::start(false, vec![vec![Step::Log("still erasing\n".to_owned()); 64]])?;
        let mut client =
            Client::connect(Address::new("127.0.0.1", daemon.port()), None)?.with_intermediate_budget(budget);
        client.send(&Request::Status, "the status request")?;
        let outcome = client.finish("the status request", &mut Bar::new(), &mut io::sink());
        drop(client);
        daemon.transcript_raw()?;

        let failure = outcome.err().ok_or("an endless stream must not be read for ever")?;
        let message = failure.to_string();
        assert!(
            message.contains("and no final answer"),
            "the refusal names what is missing: {message}"
        );
        assert!(
            message.contains("5 log and progress frames"),
            "and how far it read: {message}"
        );
        assert_eq!(failure.failure(OpClass::Remote).exit_code(), PROTOCOL);
        Ok(())
    }

    /// The shipped budget, as a literal: eight times the 131 072 progress frames a
    /// 512 MiB read at a 4096-byte transfer size produces, so no real command comes near
    /// it. A fixture built from the constant it checks moves with it and pins nothing.
    #[test]
    fn the_intermediate_budget_is_far_past_any_real_command() {
        assert_eq!(super::MAX_INTERMEDIATE_FRAMES, 1_048_576);
    }

    /// Every response kind has a word, and they are four different words.
    ///
    /// Only `progress` is reachable through a daemon — the other three are consumed
    /// before they can be "unexpected" — so without this the names could all collapse to
    /// one and nothing would notice.
    #[test]
    fn every_status_has_its_own_name() {
        let names: Vec<&str> = Status::ALL.iter().map(|status| super::status_name(*status)).collect();
        assert_eq!(names, vec!["ok", "error", "progress", "log"]);
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "four kinds, four words");
    }

    /// The read loop's three ways of stopping, driven against a reader that misbehaves
    /// on purpose. A socket cannot be asked for an `EINTR`.
    #[test]
    fn the_read_loop_retries_eintr_and_reports_the_rest() -> TestResult {
        /// Hands back scripted results, one per `read`.
        struct Scripted(std::vec::IntoIter<io::Result<Vec<u8>>>);

        impl io::Read for Scripted {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                match self.0.next() {
                    Some(Ok(bytes)) => {
                        let take = bytes.len().min(out.len());
                        out[..take].copy_from_slice(&bytes[..take]);
                        Ok(take)
                    }
                    Some(Err(source)) => Err(source),
                    None => Ok(0),
                }
            }
        }

        fn read(script: Vec<io::Result<Vec<u8>>>, want: usize) -> (Vec<u8>, Result<(), super::Stopped>) {
            let mut buffer = vec![0_u8; want];
            let outcome = super::fill_from(&mut Scripted(script.into_iter()), &mut buffer);
            (buffer, outcome)
        }

        // EINTR is retried, and the bytes that follow it complete the read.
        let (buffer, outcome) = read(
            vec![
                Ok(b"ab".to_vec()),
                Err(io::Error::from(io::ErrorKind::Interrupted)),
                Ok(b"cd".to_vec()),
            ],
            4,
        );
        assert!(outcome.is_ok(), "EINTR is not a failure: {outcome:?}");
        assert_eq!(buffer, b"abcd");

        // Nothing at all: a clean close.
        let (_, outcome) = read(Vec::new(), 4);
        assert!(matches!(outcome, Err(super::Stopped::Closed)), "{outcome:?}");

        // Some, then EOF: how far it got is the message's whole point.
        let (_, outcome) = read(vec![Ok(b"ab".to_vec())], 4);
        assert!(
            matches!(outcome, Err(super::Stopped::Dropped { got: 2, want: 4 })),
            "{outcome:?}"
        );

        // Any other error is reported, not retried — a retry loop on a dead socket is a
        // hang, which is the failure this whole module exists to avoid.
        let (_, outcome) = read(vec![Err(io::Error::from(io::ErrorKind::ConnectionReset))], 4);
        let Err(super::Stopped::Failed(source)) = outcome else {
            return Err("a reset must not be retried".into());
        };
        assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
        Ok(())
    }

    /// A daemon that dies **mid-frame** says how far it got, which is what separates
    /// "it rejected us" from "it crashed halfway through an answer".
    #[test]
    fn a_frame_that_stops_half_way_says_how_far_it_got() -> TestResult {
        let daemon = FakeDaemon::start(
            false,
            vec![vec![
                Step::Header {
                    status: Status::Ok.wire_byte(),
                    len: 1024,
                },
                Step::Raw(vec![0_u8; 100]),
                Step::Close,
            ]],
        )?;
        let mut client = client(daemon.port())?;
        client.send(&Request::Status, "the status request")?;
        let outcome = client.finish("the status request", &mut Bar::new(), &mut io::sink());
        drop(client);
        daemon.transcript()?;

        let failure = outcome.err().ok_or("a half-sent payload must fail")?;
        assert!(
            failure
                .to_string()
                .contains("dropped after 100 of 1024 bytes during the status request"),
            "{failure}"
        );
        Ok(())
    }

    /// **An absurd read is refused before it reaches the disk.** The payload cap does not
    /// apply to a read, so without this the announced `u32` would be written to the
    /// operator's file until the disk filled.
    #[test]
    fn a_read_larger_than_any_part_is_refused_unread() -> TestResult {
        let daemon = FakeDaemon::start(
            false,
            vec![vec![Step::Header {
                status: Status::Ok.wire_byte(),
                len: u32::MAX,
            }]],
        )?;
        let mut client = client(daemon.port())?;
        client.send(
            &Request::Read {
                index: 0,
                variant: Vec::new(),
                alt: None,
            },
            "the read",
        )?;
        let mut written = Vec::new();
        let outcome = client.read_to(
            "the read",
            &mut written,
            std::path::Path::new("/tmp/tdfu-absurd.bin"),
            None,
            &mut Bar::new(),
            &mut io::sink(),
        );
        drop(client);
        daemon.transcript()?;

        let failure = outcome.err().ok_or("4 GiB is not a flash part")?;
        assert!(failure.to_string().contains("lost frame sync"), "{failure}");
        assert!(written.is_empty(), "and nothing reached the file");
        assert_eq!(super::MAX_READ, 536_870_912, "twice the largest part in the tree");
        Ok(())
    }

    /// The streaming chunk is 64 KiB, and that number is the client's whole memory
    /// ceiling for a 256 MiB read. Pinned as a literal because the property
    /// is the *size*, not the expression.
    #[test]
    fn the_read_chunk_bounds_what_a_client_holds() {
        assert_eq!(super::CHUNK, 65_536, "`cli/remote.c:328`'s buffer, and our ceiling");
    }

    /// **At the source.** `resolve` hands back exactly what the system resolver
    /// said, in the order it said it.
    ///
    /// The *order itself* is `getaddrinfo`'s (RFC 6724 puts IPv6 first), and asserting
    /// that would be asserting the C library. What is this client's is that the list is
    /// neither sorted, reversed nor filtered, which is what `connect`'s "resolver order is
    /// kept" comment claims and what makes IPv6 the default rather than the fallback.
    /// Nothing asserted it, so a mutant reversing the vector survived.
    #[test]
    fn the_resolver_keeps_the_systems_order() -> TestResult {
        use std::net::{SocketAddr, ToSocketAddrs as _};

        let expected: Vec<SocketAddr> = ("localhost", 5050).to_socket_addrs()?.collect();
        assert_eq!(super::resolve(&Address::new("localhost", 5050))?, expected);

        // And where this host really is dual-stacked, that order puts v6 first. Read
        // rather than required on a v4-only box: the property belongs to `getaddrinfo`.
        if expected.iter().any(SocketAddr::is_ipv6) && expected.iter().any(SocketAddr::is_ipv4) {
            assert!(
                expected.first().is_some_and(SocketAddr::is_ipv6),
                "a dual-stacked name resolves v6 first: {expected:?}"
            );
        }
        Ok(())
    }

    /// The connected socket carries keepalive, with all three knobs set.
    ///
    /// A `TcpStream` has no getter for any of this, which is the same reason it has no
    /// setter and `socket2` is here at all; the values are read back through the same
    /// crate. The point is not the numbers but that a *vanished* host (power-cut, no
    /// RST, no FIN) stops being indistinguishable from a slow one.
    #[test]
    fn the_socket_carries_keepalive() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
        let client = client(daemon.port())?;
        let socket = socket2::SockRef::from(client.stream());

        assert!(socket.keepalive()?, "SO_KEEPALIVE is on");
        assert_eq!(socket.tcp_keepalive_time()?, super::KEEPALIVE_IDLE);
        assert_eq!(socket.tcp_keepalive_interval()?, super::KEEPALIVE_INTERVAL);
        assert_eq!(socket.tcp_keepalive_retries()?, super::KEEPALIVE_PROBES);

        drop(client);
        daemon.transcript()?;
        Ok(())
    }

    /// **Keepalive and the deadline together.** A peer that accepts and then says nothing is given up
    /// on, and the message names the deadline instead of an errno.
    ///
    /// No `--token`, so before this the only protection was the handshake's, which does
    /// not run on this path, and the client blocked in `read` for ever. The deadline is
    /// injected at 150 ms; shipped it is [`HANDSHAKE_TIMEOUT`], which no test can wait
    /// out, which is why deleting the whole `set_read_timeout` call used to pass.
    #[test]
    fn a_peer_that_accepts_and_says_nothing_is_given_up_on() -> TestResult {
        let daemon = FakeDaemon::start(
            false,
            vec![vec![Step::Pause(Duration::from_secs(3)), Step::Ok(b"OK".to_vec())]],
        )?;
        let deadline = Duration::from_millis(150);
        let mut client = Client::connect_with(Address::new("127.0.0.1", daemon.port()), None, deadline)?;
        client.send(&Request::Status, "the status request")?;
        let outcome = client.finish("the status request", &mut Bar::new(), &mut io::sink());
        drop(client);

        let failure = outcome.err().ok_or("a silent peer must not hang the tool")?;
        let message = failure.to_string();
        assert!(
            message.contains(&format!("sent nothing for {deadline:?}")),
            "the deadline, not an errno: {message}"
        );
        assert!(
            message.contains("not answering as a dfu-remote daemon"),
            "and what to make of it: {message}"
        );
        assert!(
            !message.contains("os error"),
            "`Resource temporarily unavailable` is not a diagnosis: {message}"
        );
        assert_eq!(failure.failure(OpClass::Remote).exit_code(), PROTOCOL);
        Ok(())
    }

    /// The deadline is lifted once a frame has arrived: after that, silence is a
    /// whole-chip erase working as designed and not a peer to give up on.
    #[test]
    fn the_first_answer_deadline_does_not_outlive_the_first_answer() -> TestResult {
        let deadline = Duration::from_millis(150);
        let daemon = FakeDaemon::start(
            false,
            vec![vec![
                Step::Log("erasing\n".to_owned()),
                // Longer than the deadline: if it were still armed this would fail.
                Step::Pause(deadline * 4),
                Step::Ok(b"OK".to_vec()),
            ]],
        )?;
        let mut client = Client::connect_with(Address::new("127.0.0.1", daemon.port()), None, deadline)?;
        client.send(&Request::Status, "the status request")?;
        let payload = client.finish("the status request", &mut Bar::new(), &mut io::sink())?;
        drop(client);
        daemon.transcript()?;

        assert_eq!(payload, b"OK", "a slow daemon is still a daemon");
        Ok(())
    }

    /// **A header is not an answer.** A peer that sends ten valid header bytes and then
    /// stops is given up on, because the deadline covers the whole first frame.
    ///
    /// Keepalive cannot end this one: the peer is alive and its kernel answers the
    /// probes, so the connection stays up and the blocking read never returns. It is the
    /// `ssh` banner on port 5050 case, one step further in.
    #[test]
    fn the_first_answer_deadline_covers_the_payload_too() -> TestResult {
        let deadline = Duration::from_millis(150);
        let daemon = FakeDaemon::start(
            false,
            vec![vec![
                // A log frame announcing 4096 bytes, of which none ever arrive.
                Step::Header {
                    status: Status::Log.wire_byte(),
                    len: 4096,
                },
                Step::Pause(deadline * 8),
                Step::Close,
            ]],
        )?;
        let mut client = Client::connect_with(Address::new("127.0.0.1", daemon.port()), None, deadline)?;
        client.send(&Request::Status, "the status request")?;
        let outcome = client.finish("the status request", &mut Bar::new(), &mut io::sink());
        drop(client);

        let failure = outcome.err().ok_or("a header with no payload must not hang the tool")?;
        let message = failure.to_string();
        assert!(
            message.contains(&format!("sent nothing for {deadline:?}")),
            "the deadline, not a wait for bytes that are not coming: {message}"
        );
        Ok(())
    }

    /// The send side has a deadline too, and it is on the socket from the first byte.
    ///
    /// A peer that accepts and then stops reading is what no read deadline and no
    /// keepalive can see, because the kernel sends no probes while data is queued. There
    /// is no getter for `SO_SNDTIMEO`'s effect, so this reads the option back and drives
    /// the wording directly: filling a send buffer needs megabytes and a peer that never
    /// reads.
    #[test]
    fn the_socket_carries_a_send_deadline() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
        let client = client(daemon.port())?;
        assert_eq!(client.stream().write_timeout()?, Some(super::SEND_TIMEOUT));

        let stalled = io::Error::new(io::ErrorKind::WouldBlock, "Resource temporarily unavailable");
        let refusal = client.send_failed(&stalled, "the write");
        drop(client);
        daemon.transcript()?;

        let message = refusal.to_string();
        assert!(
            message.contains(&format!("read nothing for {:?}", super::SEND_TIMEOUT)),
            "the deadline, named: {message}"
        );
        assert!(
            message.contains("busy with another run"),
            "and what it usually means: {message}"
        );
        assert!(!message.contains("os error"), "not an errno: {message}");
        Ok(())
    }

    /// A status byte outside 0..=3 is named, with the version that does not
    /// define it.
    ///
    /// One line reaches this arm through the fake, and before it nothing did: the wording
    /// had no producer at all, so mutating it survived the suite.
    #[test]
    fn a_status_byte_this_version_does_not_define_is_named() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Header { status: 9, len: 0 }]])?;
        let mut client = client(daemon.port())?;
        client.send(&Request::Status, "the status request")?;
        let outcome = client.finish("the status request", &mut Bar::new(), &mut io::sink());
        drop(client);
        daemon.transcript()?;

        let failure = outcome.err().ok_or("status 9 is not a response kind")?;
        assert!(
            failure.to_string().ends_with(
                "answered the status request with response kind 9, which protocol version 1 does not define"
            ),
            "{failure}"
        );
        Ok(())
    }

    /// **The other arm.** An OS error that is not a timeout is reported with its own
    /// text, and says so in a sentence.
    ///
    /// Driven through [`Client::stopped`] rather than through a socket: `ECONNRESET` on
    /// loopback is a race, and the arm exists precisely for the errors a test cannot
    /// provoke. `fill_from`'s own test covers the value; this covers the sentence.
    #[test]
    fn a_socket_error_is_reported_with_its_own_text() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
        let client = client(daemon.port())?;
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "Connection reset by peer");
        let refusal = client.stopped(super::Stopped::Failed(reset), "the read");
        drop(client);
        daemon.transcript()?;

        assert!(
            refusal
                .to_string()
                .ends_with("failed during the read: Connection reset by peer"),
            "{refusal}"
        );
        Ok(())
    }

    /// A final frame that is neither OK nor ERROR is named rather than assumed.
    ///
    /// Unreachable while [`Status`] has four members — `Progress` and `Log` are consumed
    /// as intermediates — so this drives the message directly rather than pretending a
    /// daemon could send it.
    #[test]
    fn an_unexpected_final_frame_names_what_arrived() -> TestResult {
        let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
        let client = client(daemon.port())?;
        let refusal = client.unexpected_final("the read", Status::Progress);
        drop(client);
        daemon.transcript()?;

        assert!(
            refusal
                .to_string()
                .ends_with("ended the read with a progress frame, which is not an answer"),
            "{refusal}"
        );
        Ok(())
    }
}
