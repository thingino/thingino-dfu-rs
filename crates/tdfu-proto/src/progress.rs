//! The `RESP_PROGRESS` body.
//!
//! **This type has an encoder because the last one deliberately did not.** An earlier
//! implementation shipped a decoder only, which is where the never-sent progress frames
//! were actually blocked, because no C daemon ever sent a progress
//! frame, although both C clients parse one (`cli/remote.c:196-202`,
//! `web/src/remote.js`). The result was that remote flashing showed progress as log
//! prose while a perfectly good frame type sat unused. The layout is the C's
//! (`protocol.h:79-83`); sending it is ours.

use crate::error::ProtoError;

/// `[percent u8][stage u8][msg_len u16 BE][msg]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressBody {
    /// 0-100. `Self::percent_of` is the rule.
    pub percent: u8,
    /// Which phase: 0 unknown, 1 stage1, 2 u-boot, 3 download, 4 manifest, 5 upload,
    /// 6 verify, 7 erase.
    ///
    /// A `u8` rather than an enum on purpose: the discriminants belong to
    /// `tdfu_core::Phase`, whose `wire_byte` is the single definition of them, and a
    /// second copy here is exactly the string-to-byte table the contract (D12) deleted.
    pub stage: u8,
    /// What is happening, in words.
    pub message: String,
}

impl ProgressBody {
    /// The fixed part: percent, stage and the message length.
    pub const HEADER_LEN: usize = 4;

    /// The rule: `done * 100 / total`, or 0 where there is no knowable total —
    /// a DFU upload ends on a short block, so its total is not known until it is over.
    ///
    /// Clamped at 100: a device that sends one block more than the file said is a
    /// surprise worth surviving, and a progress bar is not the place to report it.
    #[must_use]
    pub fn percent_of(done: u64, total: Option<u64>) -> u8 {
        match total {
            Some(total) if total > 0 => {
                let percent = done.saturating_mul(100) / total;
                u8::try_from(percent.min(100)).unwrap_or(100)
            }
            _ => 0,
        }
    }

    /// The wire bytes.
    ///
    /// # Errors
    /// [`ProtoError::FieldTooLong`] if the message does not fit its `u16` length prefix.
    /// Truncating it instead is how an earlier `Request::encode` came to report a
    /// write to the wrong partition as a success; a codec here never shortens anything.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let len = u16::try_from(self.message.len()).map_err(|_| ProtoError::FieldTooLong {
            field: "message",
            len: self.message.len(),
            max: u16::MAX as usize,
        })?;
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.message.len());
        out.push(self.percent);
        out.push(self.stage);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.message.as_bytes());
        Ok(out)
    }

    /// Parse a progress body.
    ///
    /// # Errors
    /// [`ProtoError::Truncated`] if the body is shorter than its own header, and
    /// [`ProtoError::Malformed`] if the message length does not match what follows or
    /// the message is not UTF-8. The C client checks `4 + msg_len <= plen` and silently
    /// prints nothing when it does not hold (`cli/remote.c:199`); saying which frame was
    /// wrong costs one error value.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtoError> {
        let Some(head) = payload.get(..Self::HEADER_LEN) else {
            return Err(ProtoError::Truncated);
        };
        let mut len = [0_u8; 2];
        len.copy_from_slice(&head[2..4]);
        let len = usize::from(u16::from_be_bytes(len));
        let body = &payload[Self::HEADER_LEN..];
        if body.len() != len {
            return Err(ProtoError::Malformed("progress message length"));
        }
        let message = core::str::from_utf8(body).map_err(|_| ProtoError::Malformed("progress message is not UTF-8"))?;
        Ok(Self {
            percent: head[0],
            stage: head[1],
            message: message.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ProgressBody;
    use crate::ProtoError;

    /// `protocol.h:79-83`: percent, stage, `u16` BE length, message.
    #[test]
    fn rpc_progress_write_body() -> Result<(), ProtoError> {
        let body = ProgressBody {
            percent: 42,
            stage: 3,
            message: "writing".to_owned(),
        };
        let bytes = body.encode()?;
        assert_eq!(bytes, [42, 3, 0, 7, b'w', b'r', b'i', b't', b'i', b'n', b'g']);
        assert_eq!(ProgressBody::decode(&bytes)?, body);

        // An empty message is a legal frame: percent and stage carry it.
        let bare = ProgressBody {
            percent: 100,
            stage: 6,
            message: String::new(),
        };
        assert_eq!(bare.encode()?, [100, 6, 0, 0]);
        assert_eq!(ProgressBody::decode(&bare.encode()?)?, bare);
        Ok(())
    }

    #[test]
    fn rpc_progress_percent_rule() {
        assert_eq!(ProgressBody::percent_of(0, Some(100)), 0);
        assert_eq!(ProgressBody::percent_of(50, Some(100)), 50);
        assert_eq!(ProgressBody::percent_of(100, Some(100)), 100);
        assert_eq!(
            ProgressBody::percent_of(1, Some(3)),
            33,
            "integer division, as the C does"
        );
        // No knowable total: a DFU upload ends on a short block.
        assert_eq!(ProgressBody::percent_of(4096, None), 0);
        assert_eq!(ProgressBody::percent_of(4096, Some(0)), 0);
        // More than the file said: clamped, never wrapped.
        assert_eq!(ProgressBody::percent_of(200, Some(100)), 100);
        assert_eq!(ProgressBody::percent_of(u64::MAX, Some(1)), 100);
    }

    #[test]
    fn a_progress_body_that_does_not_add_up_is_refused() {
        assert_eq!(ProgressBody::decode(&[]), Err(ProtoError::Truncated));
        assert_eq!(ProgressBody::decode(&[1, 2, 0]), Err(ProtoError::Truncated));
        assert_eq!(
            ProgressBody::decode(&[1, 2, 0, 4, b'a']),
            Err(ProtoError::Malformed("progress message length"))
        );
        assert_eq!(
            ProgressBody::decode(&[1, 2, 0, 1, 0xFF]),
            Err(ProtoError::Malformed("progress message is not UTF-8"))
        );
    }

    #[test]
    fn a_message_over_the_prefix_is_refused_not_cut() {
        let body = ProgressBody {
            percent: 0,
            stage: 0,
            message: "x".repeat(usize::from(u16::MAX) + 1),
        };
        assert_eq!(
            body.encode(),
            Err(ProtoError::FieldTooLong {
                field: "message",
                len: 65_536,
                max: 65_535
            })
        );
    }
}
