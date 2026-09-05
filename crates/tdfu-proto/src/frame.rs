//! The 10-byte header.

use crate::error::ProtoError;

/// Bytes in a header, fixed: magic (4) + version (1) + command or status
/// (1) + `payload_len` (4).
pub const HEADER_LEN: usize = 10;

/// The eight commands, at protocol version 1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// List the devices the daemon can see.
    Discover = 1,
    /// Bring a bootrom up as a gadget.
    Bootstrap = 2,
    /// Write an image, optionally verifying.
    Write = 3,
    /// Read an image back. May exceed the payload cap; it is streamed
    /// instead.
    Read = 4,
    /// What is the daemon doing?
    Status = 5,
    /// Accepted and does nothing in the C (`g_cancel` is set and never
    /// read). Real cancellation is a Rust-side improvement, not a C behaviour to
    /// copy.
    Cancel = 6,
    /// Read the eFuse window.
    Diag = 7,
    /// Boot the device out of DFU.
    Reboot = 8,
}

impl Command {
    /// Every command, for exhaustive tests.
    pub const ALL: [Self; 8] = [
        Self::Discover,
        Self::Bootstrap,
        Self::Write,
        Self::Read,
        Self::Status,
        Self::Cancel,
        Self::Diag,
        Self::Reboot,
    ];

    /// The wire byte.
    #[must_use]
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }

    /// Decode a command byte.
    ///
    /// # Errors
    /// [`ProtoError::UnknownCommand`] for anything else. The connection continues
    /// after this one.
    pub const fn from_wire_byte(byte: u8) -> Result<Self, ProtoError> {
        Ok(match byte {
            1 => Self::Discover,
            2 => Self::Bootstrap,
            3 => Self::Write,
            4 => Self::Read,
            5 => Self::Status,
            6 => Self::Cancel,
            7 => Self::Diag,
            8 => Self::Reboot,
            _ => return Err(ProtoError::UnknownCommand),
        })
    }
}

/// The four response kinds.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Status {
    /// Success. The payload is the command's result.
    Ok = 0,
    /// Failure. The payload is a UTF-8 message, **not** NUL-terminated.
    Error = 1,
    /// A byte count: `[percent u8][stage u8][msg_len u16 BE][msg]`.
    ///
    /// **The C daemon never sent one** although both its clients parse them, so remote
    /// flashing showed progress only as log prose. This daemon sends one per byte count
    /// instead. `percent` is `done * 100 / total`
    /// or 0 where there is no knowable total; `stage` is `tdfu_core::Phase::wire_byte`,
    /// so the daemon has no string-to-byte table of its own to keep in step.
    Progress = 2,
    /// One whole line of log text.
    Log = 3,
}

impl Status {
    /// Every status, for exhaustive tests.
    pub const ALL: [Self; 4] = [Self::Ok, Self::Error, Self::Progress, Self::Log];

    /// The wire byte.
    #[must_use]
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }

    /// Decode a status byte.
    ///
    /// # Errors
    /// [`ProtoError::UnknownStatus`] for anything else.
    pub const fn from_wire_byte(byte: u8) -> Result<Self, ProtoError> {
        Ok(match byte {
            0 => Self::Ok,
            1 => Self::Error,
            2 => Self::Progress,
            3 => Self::Log,
            _ => return Err(ProtoError::UnknownStatus),
        })
    }
}

/// A request header: magic, version, command, `payload_len` — big-endian throughout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    /// Which command follows.
    pub command: Command,
    /// How many payload bytes follow.
    pub payload_len: u32,
}

impl RequestHeader {
    /// Exactly [`HEADER_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        encode_header(self.command.wire_byte(), self.payload_len)
    }

    /// Validate magic, then version, then the command — **in that order**.
    ///
    /// The order matters and it is not cosmetic: the C validates magic and version
    /// first (`dfu-remote/main.c:859`) and only then reads the token (`:866`). Reading
    /// a whole `[magic][ver][len][tok]` frame before validating **deadlocks** against a
    /// non-TDFU client, which will never send the 255 token bytes the length claims
    /// (which is why the C's order is the one to follow).
    ///
    /// The payload cap is checked between the version and the command, where the C
    /// checks it (`dfu-remote/main.c:823` sits between `:819` and the dispatch at
    /// `:803`), and for the C's reason: an oversize frame ends the connection (spec
    /// the cap) while an unknown command does **not**, and a daemon that
    /// means to keep the connection has to skip `payload_len` bytes to reach the next
    /// header. Checking the cap first is what makes that skip bounded. The relative
    /// order the deadlock argument is about — magic, then version, then command — is
    /// unchanged, and `rpc_header_validation_order` pins each step against a frame that
    /// fails two.
    ///
    /// Bytes past [`HEADER_LEN`] are the payload's and are ignored here.
    ///
    /// # Errors
    /// [`ProtoError::Truncated`] if `bytes` is shorter than [`HEADER_LEN`];
    /// [`ProtoError::BadMagic`], [`ProtoError::VersionMismatch`],
    /// [`ProtoError::PayloadTooLarge`] or [`ProtoError::UnknownCommand`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (kind, payload_len) = split_header(bytes)?;
        if exceeds_payload_cap(payload_len) {
            return Err(ProtoError::PayloadTooLarge);
        }
        Ok(Self {
            command: Command::from_wire_byte(kind)?,
            payload_len,
        })
    }

    /// How many payload bytes a frame announces, whatever its command byte is.
    ///
    /// The connection stays open after an unknown command, and a reader that
    /// means to honour that has to skip exactly this many bytes to reach the next
    /// header — which [`decode`](RequestHeader::decode)'s `Err(UnknownCommand)` cannot
    /// tell it. The C never faces the question because it reads the payload *before* it
    /// looks at the command byte (`dfu-remote/main.c:827-838`, then `:803`).
    ///
    /// Magic, version and the cap are checked first and in that order, so a length this
    /// returns is never larger than [`MAX_PAYLOAD`](crate::MAX_PAYLOAD): the skip is
    /// bounded by construction, and a hostile peer cannot use an unknown command to ask
    /// for an unbounded read.
    ///
    /// # Errors
    /// As [`decode`](RequestHeader::decode), minus [`ProtoError::UnknownCommand`].
    pub fn announced_payload_len(bytes: &[u8]) -> Result<u32, ProtoError> {
        let (_, payload_len) = split_header(bytes)?;
        if exceeds_payload_cap(payload_len) {
            return Err(ProtoError::PayloadTooLarge);
        }
        Ok(payload_len)
    }
}

/// A response header: magic, version, status, `payload_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseHeader {
    /// What kind of response this is.
    pub status: Status,
    /// How many payload bytes follow.
    pub payload_len: u32,
}

impl ResponseHeader {
    /// Exactly [`HEADER_LEN`] bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        encode_header(self.status.wire_byte(), self.payload_len)
    }

    /// Decode a response header: magic, then version, then the status.
    ///
    /// **The payload cap is not applied here**, and that is deliberate. The cap covers
    /// a *request* in both directions but exempts `CMD_READ`, whose OK payload is a
    /// whole flash — 256 MiB on the T40XP, four times the cap — and is streamed to a
    /// file rather than buffered (`cli/remote.c:284` `recv_read_to_file`, which reads
    /// this same header and never consults the cap). A decoder that refused it would
    /// leave the streaming client with no way to learn `payload_len` and force it to
    /// re-implement this function. The policy belongs to the caller, which knows which
    /// command it sent: apply [`exceeds_payload_cap`] to a *final* response that is not
    /// a `READ`, exactly as the C's `recv_response` does at `cli/remote.c:247` — but
    /// with `>`, since the C's `>=` there made a payload of exactly the cap legal to
    /// send and fatal to receive.
    ///
    /// Bytes past [`HEADER_LEN`] are the payload's and are ignored here.
    ///
    /// # Errors
    /// [`ProtoError::Truncated`] if `bytes` is shorter than [`HEADER_LEN`];
    /// [`ProtoError::BadMagic`], [`ProtoError::VersionMismatch`] or
    /// [`ProtoError::UnknownStatus`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (kind, payload_len) = split_header(bytes)?;
        Ok(Self {
            status: Status::from_wire_byte(kind)?,
            payload_len,
        })
    }
}

/// `[magic BE][version][kind][payload_len BE]` — `protocol.h:47-59`.
fn encode_header(kind: u8, payload_len: u32) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    out[0..4].copy_from_slice(&crate::MAGIC.to_be_bytes());
    out[4] = crate::VERSION;
    out[5] = kind;
    out[6..10].copy_from_slice(&payload_len.to_be_bytes());
    out
}

/// The half of header decoding both directions share: length, magic, version.
///
/// Returns the command-or-status byte and the announced payload length, both
/// unvalidated — each direction judges those for itself.
fn split_header(bytes: &[u8]) -> Result<(u8, u32), ProtoError> {
    let Some(header) = bytes.get(..HEADER_LEN) else {
        return Err(ProtoError::Truncated);
    };
    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&header[0..4]);
    if u32::from_be_bytes(magic) != crate::MAGIC {
        return Err(ProtoError::BadMagic);
    }
    if header[4] != crate::VERSION {
        return Err(ProtoError::VersionMismatch);
    }
    let mut len = [0_u8; 4];
    len.copy_from_slice(&header[6..10]);
    Ok((header[5], u32::from_be_bytes(len)))
}

/// Is `len` over the cap?
///
/// **`>` on both sides.** The C tested `>` on a request (`dfu-remote/main.c:823`) and
/// `>=` on a response (`cli/remote.c:247`), so a payload of exactly 64 MiB was legal to
/// send and fatal to receive. That off-by-one is not reproduced: `MAX_PAYLOAD` is a maximum
/// in both directions.
#[must_use]
pub const fn exceeds_payload_cap(len: u32) -> bool {
    len > crate::MAX_PAYLOAD
}

#[cfg(test)]
mod tests {
    use super::{Command, HEADER_LEN, RequestHeader, ResponseHeader, Status, exceeds_payload_cap};
    use crate::{MAX_PAYLOAD, ProtoError};

    /// A header with the magic and version already right, so a test can spoil exactly
    /// one field.
    fn header(kind: u8, payload_len: u32) -> [u8; HEADER_LEN] {
        super::encode_header(kind, payload_len)
    }

    /// `protocol.h:47-59`: 4 + 1 + 1 + 4, big-endian, no padding.
    #[test]
    fn rpc_frame_header_bytes() -> Result<(), ProtoError> {
        let request = RequestHeader {
            command: Command::Write,
            payload_len: 0x0001_0203,
        };
        assert_eq!(
            request.encode(),
            [b'T', b'D', b'F', b'U', 0x01, 0x03, 0x00, 0x01, 0x02, 0x03]
        );
        let response = ResponseHeader {
            status: Status::Error,
            payload_len: 5,
        };
        assert_eq!(
            response.encode(),
            [b'T', b'D', b'F', b'U', 0x01, 0x01, 0x00, 0x00, 0x00, 0x05]
        );
        assert_eq!(RequestHeader::decode(&request.encode())?, request);
        assert_eq!(ResponseHeader::decode(&response.encode())?, response);
        Ok(())
    }

    #[test]
    fn rpc_frame_roundtrip() -> Result<(), ProtoError> {
        for command in Command::ALL {
            for payload_len in [0, 1, 255, 65_536, MAX_PAYLOAD] {
                let header = RequestHeader { command, payload_len };
                assert_eq!(RequestHeader::decode(&header.encode())?, header);
            }
        }
        for status in Status::ALL {
            for payload_len in [0, 2, MAX_PAYLOAD, 268_435_456] {
                let header = ResponseHeader { status, payload_len };
                assert_eq!(ResponseHeader::decode(&header.encode())?, header);
            }
        }
        Ok(())
    }

    /// The C's own validation order, which is what avoids the deadlock: magic
    /// first, then version, then — after the payload cap — the command. Each frame below
    /// fails more than one check; the one that is reported is the earlier one.
    #[test]
    fn rpc_header_validation_order() {
        let mut frame = header(0xFF, MAX_PAYLOAD + 1);
        frame[0] = b'X'; // bad magic AND bad version AND oversize AND bad command
        frame[4] = 9;
        assert_eq!(RequestHeader::decode(&frame), Err(ProtoError::BadMagic));

        let mut frame = header(0xFF, MAX_PAYLOAD + 1);
        frame[4] = 9; // bad version AND oversize AND bad command
        assert_eq!(RequestHeader::decode(&frame), Err(ProtoError::VersionMismatch));

        // Oversize AND bad command: the cap wins, because it is the one that ends the
        // connection while an unknown command does not.
        let frame = header(0xFF, MAX_PAYLOAD + 1);
        assert_eq!(RequestHeader::decode(&frame), Err(ProtoError::PayloadTooLarge));

        let frame = header(0xFF, 0);
        assert_eq!(RequestHeader::decode(&frame), Err(ProtoError::UnknownCommand));

        // The same order on the response side, with the status last and no cap.
        let mut frame = header(0xFF, 0);
        frame[0] = b'X';
        frame[4] = 9;
        assert_eq!(ResponseHeader::decode(&frame), Err(ProtoError::BadMagic));
        let mut frame = header(0xFF, 0);
        frame[4] = 9;
        assert_eq!(ResponseHeader::decode(&frame), Err(ProtoError::VersionMismatch));
        assert_eq!(ResponseHeader::decode(&header(0xFF, 0)), Err(ProtoError::UnknownStatus));
    }

    /// "The connection continues" needs a length the failed decode does not
    /// carry, and the length is bounded before it is handed out.
    #[test]
    fn an_unknown_command_still_says_how_much_to_skip() -> Result<(), ProtoError> {
        let frame = header(0xFF, 4096);
        assert_eq!(RequestHeader::decode(&frame), Err(ProtoError::UnknownCommand));
        assert_eq!(RequestHeader::announced_payload_len(&frame)?, 4096);

        // Never unbounded: the cap is applied first, so the skip cannot be.
        let over = header(0xFF, MAX_PAYLOAD + 1);
        assert_eq!(
            RequestHeader::announced_payload_len(&over),
            Err(ProtoError::PayloadTooLarge)
        );
        let at_cap = header(0xFF, MAX_PAYLOAD);
        assert_eq!(RequestHeader::announced_payload_len(&at_cap)?, MAX_PAYLOAD);

        // And it is the same number a good frame decodes to.
        let known = header(Command::Write.wire_byte(), 12);
        assert_eq!(
            RequestHeader::announced_payload_len(&known)?,
            RequestHeader::decode(&known)?.payload_len
        );

        // A frame that is not ours at all is refused the same way as in `decode`.
        let mut spoiled = header(Command::Write.wire_byte(), 0);
        spoiled[0] = b'X';
        assert_eq!(
            RequestHeader::announced_payload_len(&spoiled),
            Err(ProtoError::BadMagic)
        );
        spoiled[0] = b'T';
        spoiled[4] = 2;
        assert_eq!(
            RequestHeader::announced_payload_len(&spoiled),
            Err(ProtoError::VersionMismatch)
        );
        assert_eq!(
            RequestHeader::announced_payload_len(&spoiled[..3]),
            Err(ProtoError::Truncated)
        );
        Ok(())
    }

    /// A short buffer is not a bad frame: it is a frame that has not arrived yet, and
    /// saying so is what lets a reader keep the connection.
    #[test]
    fn rpc_header_short_buffer_is_truncated() {
        let full = header(Command::Discover.wire_byte(), 0);
        for len in 0..HEADER_LEN {
            assert_eq!(RequestHeader::decode(&full[..len]), Err(ProtoError::Truncated), "{len}");
            assert_eq!(
                ResponseHeader::decode(&full[..len]),
                Err(ProtoError::Truncated),
                "{len}"
            );
        }
        assert!(RequestHeader::decode(&full).is_ok());
    }

    /// Bytes after the header belong to the payload; a decoder that insisted on exactly
    /// ten would be unusable on a stream.
    #[test]
    fn a_longer_buffer_decodes_the_first_header() -> Result<(), ProtoError> {
        let mut buffer = header(Command::Diag.wire_byte(), 1).to_vec();
        buffer.push(0x07);
        let decoded = RequestHeader::decode(&buffer)?;
        assert_eq!(
            decoded,
            RequestHeader {
                command: Command::Diag,
                payload_len: 1
            }
        );
        Ok(())
    }

    /// `>` on both sides, so exactly 64 MiB is legal to send *and* to
    /// receive. The C tested `>` on a request (`dfu-remote/main.c:823`) and `>=` on a
    /// response (`cli/remote.c:247`), so the cap was legal one way and fatal the other.
    #[test]
    fn rpc_oversize_both_directions() -> Result<(), ProtoError> {
        assert!(!exceeds_payload_cap(MAX_PAYLOAD), "the cap is a maximum");
        assert!(exceeds_payload_cap(MAX_PAYLOAD + 1));

        let at_cap = header(Command::Write.wire_byte(), MAX_PAYLOAD);
        assert_eq!(RequestHeader::decode(&at_cap)?.payload_len, MAX_PAYLOAD);
        let over = header(Command::Write.wire_byte(), MAX_PAYLOAD + 1);
        assert_eq!(RequestHeader::decode(&over), Err(ProtoError::PayloadTooLarge));

        // The receiving side applies the same predicate to a final response...
        let at_cap = ResponseHeader::decode(&header(Status::Ok.wire_byte(), MAX_PAYLOAD))?;
        assert!(!exceeds_payload_cap(at_cap.payload_len));
        let over = ResponseHeader::decode(&header(Status::Ok.wire_byte(), MAX_PAYLOAD + 1))?;
        assert!(exceeds_payload_cap(over.payload_len));
        Ok(())
    }

    /// ...but the header itself still decodes, because a streamed `READ` is exempt: a
    /// T40XP's NAND alt 0 is 256 MiB (`cli/remote.c:280-284`).
    #[test]
    fn rpc_read_response_may_exceed_the_cap() -> Result<(), ProtoError> {
        let nand = 256 * 1024 * 1024;
        let decoded = ResponseHeader::decode(&header(Status::Ok.wire_byte(), nand))?;
        assert_eq!(decoded.payload_len, nand);
        assert!(exceeds_payload_cap(nand), "the caller is the one that must exempt it");
        Ok(())
    }

    #[test]
    fn rpc_command_bytes_round_trip() -> Result<(), crate::ProtoError> {
        for command in Command::ALL {
            assert_eq!(Command::from_wire_byte(command.wire_byte())?, command);
        }
        assert!(Command::from_wire_byte(0).is_err(), "0 is not a command");
        assert!(Command::from_wire_byte(9).is_err(), "9 is not a command yet");
        Ok(())
    }

    #[test]
    fn rpc_status_bytes_round_trip() -> Result<(), crate::ProtoError> {
        for status in Status::ALL {
            assert_eq!(Status::from_wire_byte(status.wire_byte())?, status);
        }
        assert!(Status::from_wire_byte(4).is_err());
        Ok(())
    }

    #[test]
    fn rpc_exactly_the_cap_is_legal_in_both_directions() {
        assert!(!exceeds_payload_cap(MAX_PAYLOAD), "the cap is a maximum");
        assert!(exceeds_payload_cap(MAX_PAYLOAD + 1));
    }
}
