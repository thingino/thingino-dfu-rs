//! The WebSocket server half (RFC 6455).
//!
//! TDFU frames are a **byte stream across WebSocket frames**: frame boundaries carry no
//! meaning and a 10-byte header may straddle two of them. So this file is a
//! codec, not a message layer — it turns frames into bytes and bytes into frames, and
//! the TDFU framing above it never knows.
//!
//! Two places the C is wrong and this is not (the first of them was decided
//! once already):
//!
//! * **Client frames must be masked** (RFC 6455 §5.1). `dfu-remote/ws.c:296-301` zeroes
//!   the key and unmasks with it anyway, so an unmasked frame is accepted verbatim.
//! * **A control frame carries at most 125 payload bytes** (RFC 6455 §5.5).
//!   `dfu-remote/ws.c:308-310` reads the first 125 and leaves the rest in the stream,
//!   so every following frame is parsed out of the middle of this one's payload. Here
//!   the connection is failed with `1002`, which is what §7.1.7 says to do with a
//!   protocol error; the announced payload is never read, because a failed connection
//!   has no next frame to be desynchronised.

use core::time::Duration;

use super::digest::accept_key;
use super::error::DaemonError;
use super::origin::Origins;
use super::wire::{Deadlines, Filled, Wire};

/// The most a control frame may carry (RFC 6455 §5.5).
const CONTROL_MAX: u64 = 125;

/// The cap on the upgrade request's header block. The C uses `char req[8192]`
/// (`dfu-remote/ws.c:178`).
const HEADER_LIMIT: usize = 8192;

/// RFC 6455 §7.4.1: protocol error.
const CLOSE_PROTOCOL_ERROR: u16 = 1002;

/// RFC 6455 §7.4.1: normal closure.
const CLOSE_NORMAL: u16 = 1000;

/// A WebSocket connection, mid-stream.
#[derive(Debug)]
pub struct WsConn {
    wire: Wire,
    /// Payload bytes left in the data frame being consumed.
    remaining: u64,
    /// The current frame's masking key.
    mask: [u8; 4],
    /// How far into the key the next byte is. Runs across reads *within* a frame, and
    /// resets per frame — `dfu-remote/ws.c:302`, `:351`.
    mask_at: usize,
    /// Which command is being served. See [`RawConn::current`](super::RawConn::current)
    /// for why this lives in the connection and not in a global.
    pub(super) current: Option<tdfu_proto::Command>,
}

impl WsConn {
    /// Complete the RFC 6455 upgrade, then hand back a live connection.
    ///
    /// **A request that is not an upgrade is answered**, with a `400` and the CORS
    /// headers. The C checks only for `Sec-WebSocket-Key` (`dfu-remote/ws.c:192-197`) and,
    /// when it is absent, returns `-1` and closes the socket without writing a byte
    /// (`ws.c:198-199`, `main.c:1145-1147`) — so anyone who points a browser at the
    /// daemon's port gets a connection reset and no explanation. The three header checks
    /// added here are RFC 6455 §4.2.1's, in its order, and cost three lines.
    ///
    /// `Connection` is matched as a **token list** (RFC 7230 §6.1), because a browser
    /// sends `Connection: keep-alive, Upgrade` rather than the bare token; requiring an
    /// equality match would refuse Firefox. The sentence above used to claim
    /// §4.2.1 while checking two of its three fields.
    ///
    /// Not a `426 Upgrade Required` for a bad version (RFC 6455 §4.4): this is a daemon
    /// that speaks one protocol version and negotiates nothing, so there is no second
    /// version to advertise, and `400` says the same thing without implying otherwise.
    ///
    /// **The `Origin` is checked here and nowhere else.** A WebSocket handshake is not a
    /// CORS request: a browser sends it cross-origin without asking and hands the socket
    /// to the page whatever headers come back, so RFC 6455 §10.2 leaves the check to the
    /// server. Without it, any page the operator has open can open a TDFU stream to a
    /// daemon on their own network and drive a flash with it.
    ///
    /// # Errors
    /// [`DaemonError::WsHandshake`] if the request is not a version 13 upgrade with a
    /// key, or if it carries an `Origin` that is not allowed.
    pub(super) async fn upgrade(mut wire: Wire, origins: &Origins) -> Result<Self, DaemonError> {
        let handshake = wire.timeouts().handshake;
        let block = wire.read_header_block(HEADER_LIMIT, handshake).await?;

        let decision = origins.decide(header_value(&block, "origin").as_deref());
        if !decision.is_allowed() {
            super::http::refuse_origin(&mut wire, &decision).await?;
            return Err(DaemonError::WsHandshake("the Origin is not on the allow list"));
        }
        if !lists_token(&header_value(&block, "upgrade").unwrap_or_default(), "websocket") {
            super::http::refusal(&mut wire, &decision, "400 Bad Request").await?;
            return Err(DaemonError::WsHandshake("not an `Upgrade: websocket` request"));
        }
        if !lists_token(&header_value(&block, "connection").unwrap_or_default(), "upgrade") {
            super::http::refusal(&mut wire, &decision, "400 Bad Request").await?;
            return Err(DaemonError::WsHandshake("no `Connection: Upgrade` header"));
        }
        let version = header_value(&block, "sec-websocket-version").unwrap_or_default();
        if version != "13" {
            super::http::refusal(&mut wire, &decision, "400 Bad Request").await?;
            return Err(DaemonError::WsHandshake("only Sec-WebSocket-Version 13 is spoken"));
        }
        let Some(key) = websocket_key(&block) else {
            super::http::refusal(&mut wire, &decision, "400 Bad Request").await?;
            return Err(DaemonError::WsHandshake("no Sec-WebSocket-Key header"));
        };
        // The 101 below carries no `Access-Control-Allow-Origin`: CORS does not govern a
        // WebSocket, so the header would say nothing to the browser and the check above
        // is what governs it instead. `Access-Control-Allow-Private-Network` is not a
        // CORS header and does still apply.

        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             Access-Control-Allow-Private-Network: true\r\n\
             \r\n",
            accept_key(&key)
        );
        wire.write_all(response.as_bytes()).await?;
        Ok(Self {
            wire,
            remaining: 0,
            mask: [0; 4],
            mask_at: 0,
            current: None,
        })
    }

    /// Who is on the other end.
    pub(super) fn peer(&self) -> Option<core::net::SocketAddr> {
        self.wire.peer()
    }

    /// The deadlines in force.
    pub(super) const fn timeouts(&self) -> super::Timeouts {
        self.wire.timeouts()
    }

    /// Fill `buf` from the data-frame byte stream, answering control frames on the way.
    pub(super) async fn read_exact(
        &mut self,
        buf: &mut [u8],
        deadlines: Deadlines,
        doing: &'static str,
    ) -> Result<Filled, DaemonError> {
        let mut done = 0;
        while done < buf.len() {
            if self.remaining == 0 {
                let within = if done == 0 { deadlines.first } else { deadlines.rest };
                let Some(len) = self.next_data_frame(within).await? else {
                    return Ok(Filled::Eof(done));
                };
                self.remaining = len;
                continue;
            }
            let want = usize::try_from(self.remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len() - done);
            // Both operands are positive here: `remaining` is not zero (the branch above
            // owns that case) and the loop condition says `done < buf.len()`. Stated so
            // that a mutation which makes either zero **fails** a test instead of
            // spinning this loop: `cargo mutants` produced two that did, and a hang burns
            // a slot and reports nothing.
            debug_assert!(want > 0, "the ws codec asked for nothing from a frame that had bytes");
            let Some(slot) = buf.get_mut(done..done + want) else {
                break;
            };
            self.wire
                .read_all_of(slot, Deadlines::uniform(deadlines.rest), doing)
                .await?;
            for byte in slot.iter_mut() {
                *byte ^= self.mask[self.mask_at & 3];
                self.mask_at = self.mask_at.wrapping_add(1);
            }
            self.remaining -= want as u64;
            done += want;
        }
        Ok(Filled::Whole)
    }

    /// Send one binary frame carrying `parts` end to end.
    ///
    /// One frame per logical TDFU message. The C calls `ws_send` once per `net_send_all`
    /// and so splits every response into a header frame and a payload frame
    /// (`dfu-remote/main.c:164-169`); harmless, since boundaries carry no meaning, but
    /// there is no reason to do it.
    pub(super) async fn send_message(&mut self, parts: &[&[u8]]) -> Result<(), DaemonError> {
        let len: usize = parts.iter().map(|part| part.len()).sum();
        let header = frame_header(0x82, len as u64);
        self.wire.write_all(header_bytes(&header)).await?;
        for part in parts {
            if !part.is_empty() {
                self.wire.write_all(part).await?;
            }
        }
        Ok(())
    }

    /// Read frames until a data frame arrives; `Ok(None)` when the peer closed.
    async fn next_data_frame(&mut self, first: Option<Duration>) -> Result<Option<u64>, DaemonError> {
        let mut first = first;
        loop {
            let mut head = [0_u8; 2];
            let frame_deadline = Deadlines::uniform(first);
            match self
                .wire
                .read_exact(&mut head, frame_deadline, "websocket frame header")
                .await?
            {
                Filled::Whole => {}
                Filled::Eof(0) => return Ok(None),
                Filled::Eof(got) => {
                    return Err(DaemonError::Truncated {
                        doing: "websocket frame header",
                        got,
                        want: 2,
                    });
                }
            }
            first = self.wire.timeouts().read;

            let final_fragment = head[0] & 0x80 != 0;
            if head[0] & 0x70 != 0 {
                self.fail(CLOSE_PROTOCOL_ERROR).await;
                return Err(DaemonError::WsFraming {
                    byte: head[0],
                    why: "reserved bits are set and no extension was negotiated (RFC 6455 §5.2)",
                });
            }
            let opcode = head[0] & 0x0F;
            let masked = head[1] & 0x80 != 0;
            let len = self.read_length(head[1] & 0x7F).await?;

            if !masked {
                self.fail(CLOSE_PROTOCOL_ERROR).await;
                return Err(DaemonError::WsUnmasked { opcode });
            }
            // The **read** deadline, as `read_length` above already uses: `frame_deadline`
            // is built from `first`, which on the first frame of a request is
            // `Timeouts::idle` (300 s by default), and these four bytes are the rest of a
            // header the peer has already begun. Reusing the stale value here bought a
            // peer that sent two bytes and stopped the idle deadline instead of the read
            // one, five times the intended bound, and the wedged listener back in
            // the one file that abstraction exists to keep it out of.
            let mut mask = [0_u8; 4];
            self.wire
                .read_all_of(
                    &mut mask,
                    Deadlines::uniform(self.wire.timeouts().read),
                    "websocket mask",
                )
                .await?;
            self.mask = mask;
            self.mask_at = 0;

            if opcode & 0x08 != 0 {
                // A control frame. Both refusals **fail the connection without reading
                // the announced payload**, per §7.1.7. Draining first would protect
                // nothing: `fail()` writes a Close and the caller returns `Err`, so there
                // is no stream left to resynchronise: the desync `dfu-remote/ws.c:308-310`
                // leaves behind needs a connection that carries on, and this one does not.
                //
                // It also cost the daemon. The announced length is a **64-bit** field and
                // `discard` is bounded only by `Timeouts::read` *per read*, never in
                // total, so one 14-byte header announcing 2^63 bytes plus a byte a minute
                // held the single-client daemon for ever, from an unauthenticated peer:
                // the wedged listener, restored pre-auth from outside. The
                // fragmented case was bounded to 125 by the check above it and is dropped
                // for the same reason rather than for that one.
                if len > CONTROL_MAX {
                    self.fail(CLOSE_PROTOCOL_ERROR).await;
                    return Err(DaemonError::WsControlTooLong { opcode, len });
                }
                if !final_fragment {
                    self.fail(CLOSE_PROTOCOL_ERROR).await;
                    return Err(DaemonError::WsFraming {
                        byte: head[0],
                        why: "a control frame must not be fragmented (RFC 6455 §5.5)",
                    });
                }
            }

            match opcode {
                0x0..=0x2 => return Ok(Some(len)),
                0x8 => {
                    self.fail(CLOSE_NORMAL).await;
                    return Ok(None);
                }
                // These two carry on reading the stream, so their payloads *must* be
                // consumed; both are behind the 125-byte check above.
                0x9 => self.pong(len).await?,
                0xA => self.wire.discard(len, "websocket pong").await?,
                _ => {
                    self.fail(CLOSE_PROTOCOL_ERROR).await;
                    return Err(DaemonError::WsFraming {
                        byte: head[0],
                        why: "reserved opcode (RFC 6455 §5.2)",
                    });
                }
            }
        }
    }

    /// The 7-bit length, or the 16- or 64-bit extension it points at.
    async fn read_length(&mut self, short: u8) -> Result<u64, DaemonError> {
        let read = Deadlines::uniform(self.wire.timeouts().read);
        match short {
            126 => {
                let mut extended = [0_u8; 2];
                self.wire.read_all_of(&mut extended, read, "websocket length").await?;
                Ok(u64::from(u16::from_be_bytes(extended)))
            }
            127 => {
                let mut extended = [0_u8; 8];
                self.wire.read_all_of(&mut extended, read, "websocket length").await?;
                Ok(u64::from_be_bytes(extended))
            }
            other => Ok(u64::from(other)),
        }
    }

    /// Answer a ping with the pong RFC 6455 §5.5.3 requires: same payload, unmasked.
    async fn pong(&mut self, len: u64) -> Result<(), DaemonError> {
        let want = usize::try_from(len).unwrap_or(0);
        let mut payload = vec![0_u8; want];
        if want > 0 {
            self.wire
                .read_all_of(
                    &mut payload,
                    Deadlines::uniform(self.wire.timeouts().read),
                    "websocket ping",
                )
                .await?;
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= self.mask[index & 3];
            }
        }
        let header = frame_header(0x8A, len);
        self.wire.write_all(header_bytes(&header)).await?;
        if want > 0 {
            self.wire.write_all(&payload).await?;
        }
        Ok(())
    }

    /// Send a close frame. Best effort: the connection is ending either way, and a peer
    /// that has already gone is not an error worth replacing the real one with.
    async fn fail(&mut self, code: u16) {
        let header = frame_header(0x88, 2);
        let mut frame = header_bytes(&header).to_vec();
        frame.extend_from_slice(&code.to_be_bytes());
        let _ignored = self.wire.write_all(&frame).await;
    }
}

/// A server frame header: FIN set, never masked (RFC 6455 §5.1 — only clients mask).
///
/// The three length forms of §5.2, chosen by `try_from` rather than by a cast: a
/// truncating `as` here would send a header describing a different frame than the one
/// that follows, which desyncs the peer for the rest of the connection. The C casts
/// (`dfu-remote/ws.c:252`, `:256-257`) and is saved only by its own `if` ladder.
fn frame_header(first: u8, len: u64) -> ([u8; 10], usize) {
    let mut header = [0_u8; 10];
    header[0] = first;
    match (u8::try_from(len), u16::try_from(len)) {
        (Ok(small), _) if small < 126 => {
            header[1] = small;
            (header, 2)
        }
        (_, Ok(medium)) => {
            header[1] = 126;
            header[2..4].copy_from_slice(&medium.to_be_bytes());
            (header, 4)
        }
        _ => {
            header[1] = 127;
            header[2..10].copy_from_slice(&len.to_be_bytes());
            (header, 10)
        }
    }
}

/// The meaningful bytes of a frame header.
fn header_bytes(header: &([u8; 10], usize)) -> &[u8] {
    header.0.get(..header.1).unwrap_or(&[])
}

/// Does a comma-separated header list this token?
///
/// The shape of both `Upgrade` (protocol tokens, RFC 7230 §6.7) and `Connection`
/// (connection options, §6.1), matched case-insensitively and as a **whole token**:
/// `Upgrade: websocket, h2c` is a WebSocket upgrade, `Upgrade: h2c` is not, and
/// `websocketish` is a different protocol. Browsers send `Connection: keep-alive,
/// Upgrade`, so an equality match on that header would refuse them.
fn lists_token(header: &str, token: &str) -> bool {
    header
        .split(',')
        .any(|listed| listed.trim().eq_ignore_ascii_case(token))
}

/// The `Sec-WebSocket-Key` value, matched case-insensitively per RFC 7230 §3.2.
///
/// Parsed **per line**. The C scans every byte position in the whole request for the
/// header name (`dfu-remote/ws.c:192-197`), so a header *value* containing the text
/// would be picked up as the header itself.
fn websocket_key(block: &[u8]) -> Option<String> {
    header_value(block, "sec-websocket-key")
}

/// A header's value, or `None`.
pub(super) fn header_value(block: &[u8], name: &str) -> Option<String> {
    let text = core::str::from_utf8(block).ok()?;
    text.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
}

/// The request line, split into method and target.
pub(super) fn request_line(block: &[u8]) -> Option<(String, String)> {
    let text = core::str::from_utf8(block).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    Some((method.to_owned(), target.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{frame_header, header_bytes, header_value, lists_token, request_line, websocket_key};

    /// RFC 7230 §6.7 and §6.1: a comma-separated token list, case-insensitive.
    #[test]
    fn the_upgrade_header_is_read_as_a_token_list() {
        assert!(lists_token("websocket", "websocket"));
        assert!(lists_token("WebSocket", "websocket"));
        assert!(lists_token(" websocket ", "websocket"));
        assert!(lists_token("h2c, websocket", "websocket"));
        assert!(!lists_token("", "websocket"));
        assert!(!lists_token("h2c", "websocket"));
        // A substring is not a token: `websocketish` is a different protocol.
        assert!(!lists_token("websocketish", "websocket"));

        // The same matcher reads `Connection`, whose value a browser sends
        // as a list. Requiring equality there would refuse Firefox.
        assert!(lists_token("Upgrade", "upgrade"));
        assert!(lists_token("keep-alive, Upgrade", "upgrade"));
        assert!(!lists_token("keep-alive", "upgrade"));
        assert!(!lists_token("", "upgrade"));
    }

    #[test]
    fn a_header_is_found_case_insensitively_and_per_line() {
        let block =
            b"GET /ws HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(websocket_key(block).as_deref(), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(header_value(block, "UPGRADE").as_deref(), Some("websocket"));
        assert_eq!(header_value(block, "missing"), None);

        // The C scans every byte offset, so a *value* that quotes the header name is
        // read as the header. Per-line parsing is not fooled.
        let spoofed = b"GET / HTTP/1.1\r\nX-Note: Sec-WebSocket-Key: not-the-key\r\n\r\n";
        assert_eq!(websocket_key(spoofed), None);

        // Nor is the request line itself a header.
        let in_target = b"GET /?Sec-WebSocket-Key:x HTTP/1.1\r\n\r\n";
        assert_eq!(websocket_key(in_target), None);
    }

    #[test]
    fn the_request_line_splits() {
        assert_eq!(
            request_line(b"POST / HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some(("POST".to_owned(), "/".to_owned()))
        );
        assert_eq!(
            request_line(b"OPTIONS /x HTTP/1.1\r\n\r\n"),
            Some(("OPTIONS".to_owned(), "/x".to_owned()))
        );
        assert_eq!(request_line(b"GARBAGE\r\n\r\n"), None);
    }

    /// The three length forms of RFC 6455 §5.2, and FIN always set on ours.
    #[test]
    fn rpc_ws_server_frames_are_unmasked_binary() {
        fn header(first: u8, len: u64) -> Vec<u8> {
            let built = frame_header(first, len);
            header_bytes(&built).to_vec()
        }

        assert_eq!(header(0x82, 0), vec![0x82, 0]);
        assert_eq!(header(0x82, 125), vec![0x82, 125]);
        // 126 is the escape value, so a 126-byte payload takes the 16-bit form. Casting
        // instead of `try_from` here is how a frame comes to describe itself as 126
        // bytes long and then send 65,662.
        assert_eq!(header(0x82, 126), vec![0x82, 126, 0x00, 0x7E]);
        assert_eq!(header(0x82, 65_535), vec![0x82, 126, 0xFF, 0xFF]);
        assert_eq!(header(0x82, 65_536), vec![0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
        assert_eq!(
            header(0x82, u64::MAX),
            vec![0x82, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );

        // Never the mask bit: only a client masks (RFC 6455 §5.1).
        for len in [0_u64, 125, 126, 65_536] {
            assert_eq!(header(0x82, len).get(1).map(|byte| byte & 0x80), Some(0), "len {len}");
        }
        // FIN is always set: nothing here fragments.
        for (first, len) in [(0x82_u8, 9_u64), (0x8A, 4), (0x88, 2)] {
            assert_eq!(header(first, len).first().map(|byte| byte & 0x80), Some(0x80));
        }
        assert_eq!(header(0x8A, 4), vec![0x8A, 4], "pong");
        assert_eq!(header(0x88, 2), vec![0x88, 2], "close");
    }
}
