//! Why a frame or a payload was refused.

/// A codec failure.
///
/// **Two audiences, told apart by construction.** Some of these are a *reply*: the
/// daemon puts the text in a `RESP_ERROR` frame and the peer reads it. The rest are
/// *ours*: a buffer that has not filled yet, or a value this side refuses to put on the
/// wire at all. An earlier implementation let one error type serve wire strings,
/// client-side messages and auth alike, with nothing stopping a daemon writing a
/// client-side message onto the wire. [`ProtoError::wire_message`] is that stop:
/// it answers `None` for everything the peer must not be told, and
/// `every_variant_declares_its_audience` pins the split variant by variant.
///
/// The `Display` strings that *are* wire strings are ours now rather than a
/// compatibility fixture, but they stay because two independent implementations already
/// agree on them and changing them is churn.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// The first four bytes are not [`MAGIC`](crate::MAGIC). Ends the connection.
    #[error("bad magic")]
    BadMagic,
    /// The version byte is not [`VERSION`](crate::VERSION). Ends the connection.
    #[error("version mismatch")]
    VersionMismatch,
    /// `payload_len` exceeds [`MAX_PAYLOAD`](crate::MAX_PAYLOAD).
    #[error("payload too large")]
    PayloadTooLarge,
    /// The command byte is not one of the eight. The connection continues.
    #[error("unknown command")]
    UnknownCommand,
    /// The status byte is not one of the four.
    #[error("unknown status")]
    UnknownStatus,
    /// The buffer ended before the frame or the payload did.
    #[error("truncated")]
    Truncated,
    /// The payload does not decode: the wrong length for its layout, a length prefix
    /// that overruns, bytes left over, or — in one case — text that is not UTF-8.
    ///
    /// **Not "the right length but does not parse".** Most of these *are* length checks;
    /// what separates them from [`Truncated`](ProtoError::Truncated) is not the kind of
    /// fault but who is at fault. `Truncated` means the buffer has not filled yet and
    /// nobody is out of sync; `Malformed` means a complete payload arrived and its
    /// contents contradict the command's layout, which is the peer's mistake and the
    /// peer's to hear about.
    ///
    /// **Most of the inner strings are the C daemon's own wording** for the same refusal
    /// (`dfu-remote/main.c:359` … `:627`), so a client sees the message the protocol has
    /// always used. Four are not, and it is worth knowing which:
    ///
    /// * `"trailing bytes"` — this side is stricter than the C, which stops reading at
    ///   the end of a command's layout and ignores the remainder (see
    ///   [`Request::decode`](crate::Request::decode)).
    /// * `"partial device entry"` — a *client*-side `DISCOVER` decode; the shipped web
    ///   client loops `off + 8 <= length` and ignores the tail (`web/src/remote.js:166`).
    /// * `"progress message length"` and `"progress message is not UTF-8"` — client-side
    ///   too, and sourced from `cli/remote.c:199` rather than the daemon.
    ///
    /// **Known-open**: [`wire_message`](ProtoError::wire_message) answers
    /// `Some` for every `Malformed`, so those four client-side strings are currently
    /// declared wire-legal even though no daemon sends them. Nothing emits them from a
    /// daemon today — the split is not wrong on the wire, only unenforced — and tightening
    /// it means splitting the variant or tagging the audience per string, which is a shape
    /// change rather than a doc fix. Recorded here so the next person to touch
    /// `wire_message` sees it rather than rediscovering it.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// A field is longer than the length prefix that has to describe it.
    ///
    /// **This is an encode-side refusal and it exists because the alternative was a
    /// silent flash to the wrong partition.** An earlier `Request::encode` was
    /// infallible and truncated: a 300-byte `--alt` became a *different, valid*
    /// 255-byte alt on the wire, and the write that followed reported success.
    /// Nothing is truncated here; the encode fails and the caller
    /// keeps the number that did not fit.
    #[error("the {field} field is {len} bytes, which does not fit its {max}-byte length prefix")]
    FieldTooLong {
        /// Which field: `variant`, `alt`, `image`, `spl` or `uboot`.
        field: &'static str,
        /// What the caller handed us.
        len: usize,
        /// The most the prefix can describe.
        max: usize,
    },
    /// A `BOOTSTRAP` loader override carries an empty half.
    ///
    /// A `BOOTSTRAP` override is both-or-neither and either length 0 is an error, so the daemon
    /// would refuse the frame (`dfu-remote/main.c:385`, `:393`). Refusing it here names
    /// the half that is missing instead.
    #[error("the {field} override is empty; a bootstrap override must carry both halves")]
    EmptyBlob {
        /// Which half: `spl` or `uboot`.
        field: &'static str,
    },
}

impl ProtoError {
    /// The text the peer is told, or `None` when this failure is not the peer's to hear.
    ///
    /// `Some` means "put exactly this in a `RESP_ERROR` payload": UTF-8, not
    /// NUL-terminated. `None` means the failure is local:
    ///
    /// * [`Truncated`](ProtoError::Truncated) — the peer stopped mid-frame, so there is
    ///   nobody left in sync to tell. The C returns `-2` from `process_one_command` and
    ///   closes (`dfu-remote/main.c:813`, `:836`).
    /// * [`UnknownStatus`](ProtoError::UnknownStatus) — a *client*-side decode; the C
    ///   never validates a status server-side, and a client does not answer frames.
    /// * [`FieldTooLong`](ProtoError::FieldTooLong) and
    ///   [`EmptyBlob`](ProtoError::EmptyBlob) — this side refused to send. There is no
    ///   frame, so there is no reply.
    #[must_use]
    pub const fn wire_message(&self) -> Option<&'static str> {
        match self {
            Self::BadMagic => Some("bad magic"),
            Self::VersionMismatch => Some("version mismatch"),
            Self::PayloadTooLarge => Some("payload too large"),
            Self::UnknownCommand => Some("unknown command"),
            Self::Malformed(text) => Some(*text),
            Self::UnknownStatus | Self::Truncated | Self::FieldTooLong { .. } | Self::EmptyBlob { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProtoError;

    /// The three strings, exactly as `dfu-remote/main.c:815`, `:819` and
    /// `:803` send them, plus the cap refusal from `:824`.
    #[test]
    fn rpc_header_error_strings() {
        assert_eq!(ProtoError::BadMagic.to_string(), "bad magic");
        assert_eq!(ProtoError::VersionMismatch.to_string(), "version mismatch");
        assert_eq!(ProtoError::PayloadTooLarge.to_string(), "payload too large");
        assert_eq!(ProtoError::UnknownCommand.to_string(), "unknown command");
    }

    #[test]
    fn every_variant_declares_its_audience() {
        // Wire: the peer is told, verbatim.
        for (error, text) in [
            (ProtoError::BadMagic, "bad magic"),
            (ProtoError::VersionMismatch, "version mismatch"),
            (ProtoError::PayloadTooLarge, "payload too large"),
            (ProtoError::UnknownCommand, "unknown command"),
            (ProtoError::Malformed("bad variant length"), "bad variant length"),
        ] {
            assert_eq!(error.wire_message(), Some(text));
            // A wire refusal says the same thing in a log as it does on the wire, bar
            // `Malformed`'s prefix - no second wording to diverge.
            assert!(error.to_string().ends_with(text), "{error:?}");
        }

        // Local: never a reply.
        for error in [
            ProtoError::UnknownStatus,
            ProtoError::Truncated,
            ProtoError::FieldTooLong {
                field: "alt",
                len: 300,
                max: 255,
            },
            ProtoError::EmptyBlob { field: "spl" },
        ] {
            assert_eq!(error.wire_message(), None, "{error:?}");
        }
    }

    /// The number that did not fit survives into the message. Discarding it and
    /// truncating instead leaves the caller a symptom with no cause.
    #[test]
    fn a_refused_field_keeps_its_length() {
        let error = ProtoError::FieldTooLong {
            field: "alt",
            len: 300,
            max: 255,
        };
        assert_eq!(
            error.to_string(),
            "the alt field is 300 bytes, which does not fit its 255-byte length prefix"
        );
        assert_eq!(
            ProtoError::EmptyBlob { field: "uboot" }.to_string(),
            "the uboot override is empty; a bootstrap override must carry both halves"
        );
    }
}
