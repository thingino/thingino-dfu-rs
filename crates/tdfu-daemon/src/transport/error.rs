//! Why a connection failed.
//!
//! Every variant keeps the values it had in hand. The C's messages are terse because
//! propagating a cause in C is awkward, and an earlier implementation copied the terseness
//! without the necessity: a dropped connection was
//! reported to the user as `Auth failed`, sending them to debug a token that was fine.
//! Nothing here flattens a cause into a category.

use core::time::Duration;

use crate::auth::AuthReason;

/// Which of the three transports a connection is speaking.
///
/// Carried in errors and in auth events because "a rejected token" and "a rejected
/// token *over the browser transport*" are different facts to whoever reads the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Raw TDFU frames back to back. The CLI and Android.
    Raw,
    /// RFC 6455, `ws://` only.
    WebSocket,
    /// One command per `POST`, chunked reply. The browser flasher.
    Http,
}

impl Transport {
    /// A word for a log line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::WebSocket => "websocket",
            Self::Http => "http",
        }
    }
}

impl core::fmt::Display for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Anything that ends a connection, or ends the attempt to establish one.
///
/// **This is not the type a command failure travels in.** A command that fails answers
/// with a `RESP_ERROR` frame through [`Conn::respond`](super::Conn::respond) and the
/// connection continues; the dispatcher returns `Ok(())`. A `DaemonError`
/// means the *connection* is over.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// The socket failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// A frame was refused and the `RESP_ERROR` frame carrying `message` has **already
    /// been written**. The connection ends.
    ///
    /// The caller must not answer again: the peer has its explanation. `message` is one
    /// of `tdfu_proto::ProtoError`'s wire strings, so the log and the wire say the same
    /// words.
    #[error("refused the frame: {message}")]
    Refused {
        /// Exactly what the peer was told.
        message: &'static str,
    },

    /// The peer stopped part-way through something it had committed to sending.
    ///
    /// Distinct from a clean close, which is `Ok(None)` from
    /// [`Conn::next_request`](super::Conn::next_request) and not an error at all. This
    /// one is the half-close-mid-request case: a header promised `want` bytes and the
    /// peer sent `got` and went away.
    #[error("the peer stopped after {got} of {want} bytes while reading the {doing}")]
    Truncated {
        /// What was being read: `"header"`, `"payload"`, `"body"`, …
        doing: &'static str,
        /// How much arrived.
        got: usize,
        /// How much the peer said would.
        want: usize,
    },

    /// Nothing arrived for long enough that the connection is presumed dead.
    ///
    /// **The C has no timeout of any kind** — no `SO_RCVTIMEO`, no `poll`, no `select`,
    /// no `alarm` anywhere in `dfu-remote/` — and with `listen(fd, 1)`
    /// (`dfu-remote/main.c:1108`) and one client served to completion
    /// (`dfu-remote/main.c:1119-1156`) a single silent connection wedges every other
    /// client. The bench has hit it. That is a C defect and this is the
    /// fix, which an earlier implementation had inherited from the C instead.
    #[error("nothing arrived for {after:?} while waiting for the {doing}")]
    TimedOut {
        /// What was being waited for.
        doing: &'static str,
        /// How long we waited.
        after: Duration,
    },

    /// The token handshake failed. The peer has been answered and the event logged.
    ///
    /// An earlier implementation logged these nowhere, not even under
    /// `--debug`. [`Auth::check`](crate::auth::Auth::check) does the logging, so no
    /// caller can forget it.
    #[error("auth rejected over {transport}: {reason}")]
    AuthRejected {
        /// Which transport the attempt came in on.
        transport: Transport,
        /// Why it was refused. Never carries the presented token.
        reason: AuthReason,
    },

    /// A client sent an unmasked frame (RFC 6455 §5.1).
    ///
    /// The C zeroes the key and unmasks anyway (`dfu-remote/ws.c:296-301`), which is a
    /// tolerance that protects nobody: no client of ours speaks WebSocket at all (the
    /// web flasher POSTs), and an unmasked client frame is a protocol violation the RFC
    /// says to fail the connection over. That was decided once already.
    #[error("client frame with opcode 0x{opcode:X} was not masked (RFC 6455 §5.1)")]
    WsUnmasked {
        /// The frame's opcode.
        opcode: u8,
    },

    /// A control frame announced more than 125 payload bytes (RFC 6455 §5.5).
    ///
    /// The C reads the first 125 and **leaves the rest in the stream**
    /// (`dfu-remote/ws.c:308-310`), so every following frame is parsed from the middle
    /// of this one's payload. Here the connection is failed and the announced payload is
    /// never read: there is no following frame to desynchronise, and the length is a
    /// 64-bit field an unauthenticated peer chooses.
    #[error(
        "a control frame with opcode 0x{opcode:X} announced {len} payload bytes; RFC 6455 §5.5 caps a control payload at 125"
    )]
    WsControlTooLong {
        /// The frame's opcode.
        opcode: u8,
        /// What it claimed.
        len: u64,
    },

    /// A client frame's first byte is not allowed where it appeared: reserved bits with
    /// no extension negotiated (RFC 6455 §5.2), a reserved opcode, or a fragmented
    /// control frame (§5.5).
    ///
    /// The C checks none of the three: `dfu-remote/ws.c:280-282` takes the opcode and the
    /// mask bit out of the two header bytes and looks at nothing else.
    #[error("websocket frame byte 0x{byte:02X} is not allowed here: {why}")]
    WsFraming {
        /// The frame's first byte, FIN and reserved bits and all.
        byte: u8,
        /// Which rule it broke.
        why: &'static str,
    },

    /// The WebSocket upgrade request was not one.
    #[error("websocket handshake: {0}")]
    WsHandshake(&'static str),

    /// The HTTP request could not be parsed, or asked for something not offered.
    ///
    /// The peer has already been answered with the matching status line and **the CORS
    /// headers** — including on the `413`, where the C sends none
    /// (`dfu-remote/main.c:934`) while its `403` does (`:954-955`), so a browser sees an
    /// opaque failure instead of the refusal.
    #[error("http: {0}")]
    Http(&'static str),

    /// The peer's header block did not end within the limit.
    #[error("the request headers did not end within {limit} bytes")]
    HeadersTooLong {
        /// The cap.
        limit: usize,
    },

    /// A one-shot connection (HTTP carries exactly one command per POST)
    /// was asked to answer twice.
    #[error("this connection has already sent its final response")]
    AlreadyFinished,

    /// This side refused to put a payload on the wire.
    ///
    /// An audit's carry-forward into the daemon: apply the 64 MiB cap on the **encode**
    /// side too. `CMD_READ` is the one command the cap exempts, a NAND alt 0 being
    /// 256 MiB and streamed, so the command in flight is part of the decision and part of
    /// the message.
    ///
    /// Refusing rather than truncating is the same lesson `ProtoError::FieldTooLong`
    /// carries: a silently truncating encoder is how a write to the wrong
    /// partition came to be reported as a success.
    #[error("refusing to send a {len}-byte payload for {command:?}: over the 64 MiB cap, and only CMD_READ is exempt")]
    OversizeResponse {
        /// What the caller handed us.
        len: usize,
        /// Which command was in flight, if any.
        command: Option<tdfu_proto::Command>,
    },

    /// A frame could not be encoded.
    #[error("could not encode a frame: {0}")]
    Encode(#[from] tdfu_proto::ProtoError),
}

impl DaemonError {
    /// Is this the peer going away rather than the peer misbehaving?
    ///
    /// A daemon logs a hang-up at `debug` and a protocol violation at `warn`; without
    /// this the accept loop has to match on variants it does not own.
    #[must_use]
    pub const fn is_peer_gone(&self) -> bool {
        matches!(self, Self::Truncated { .. } | Self::TimedOut { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::{DaemonError, Transport};
    use crate::auth::AuthReason;
    use core::time::Duration;

    /// Every value that was in hand reaches the message. An earlier implementation
    /// reported a dropped connection as `Auth failed`.
    #[test]
    fn every_message_keeps_the_numbers_it_had() {
        assert_eq!(
            DaemonError::Truncated {
                doing: "payload",
                got: 3,
                want: 4096,
            }
            .to_string(),
            "the peer stopped after 3 of 4096 bytes while reading the payload"
        );
        assert_eq!(
            DaemonError::TimedOut {
                doing: "request header",
                after: Duration::from_secs(30),
            }
            .to_string(),
            "nothing arrived for 30s while waiting for the request header"
        );
        assert_eq!(
            DaemonError::WsControlTooLong { opcode: 0x9, len: 900 }.to_string(),
            "a control frame with opcode 0x9 announced 900 payload bytes; RFC 6455 §5.5 caps a control payload at 125"
        );
        assert_eq!(
            DaemonError::WsUnmasked { opcode: 0x2 }.to_string(),
            "client frame with opcode 0x2 was not masked (RFC 6455 §5.1)"
        );
    }

    /// The transport is part of the fact, not decoration: "a rejected token" and "a
    /// rejected token over the browser transport" send a reader to different places.
    #[test]
    fn an_auth_rejection_names_its_transport_and_never_the_token() {
        let error = DaemonError::AuthRejected {
            transport: Transport::Http,
            reason: AuthReason::WrongToken,
        };
        let text = error.to_string();
        assert!(text.contains("http"), "{text}");
        assert!(text.contains("token did not match"), "{text}");
    }

    #[test]
    fn a_hang_up_is_told_apart_from_a_violation() {
        assert!(
            DaemonError::Truncated {
                doing: "header",
                got: 0,
                want: 10
            }
            .is_peer_gone()
        );
        assert!(
            DaemonError::TimedOut {
                doing: "header",
                after: Duration::from_secs(1)
            }
            .is_peer_gone()
        );
        assert!(!DaemonError::WsUnmasked { opcode: 2 }.is_peer_gone());
        assert!(!DaemonError::Refused { message: "bad magic" }.is_peer_gone());
    }

    #[test]
    fn transports_name_themselves() {
        assert_eq!(Transport::Raw.to_string(), "raw");
        assert_eq!(Transport::WebSocket.to_string(), "websocket");
        assert_eq!(Transport::Http.to_string(), "http");
    }
}
