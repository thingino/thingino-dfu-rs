//! The daemon wire protocol, shared by the client and the server.
//!
//! **This protocol is ours now.** It was written to be byte-compatible with the shipped
//! C daemon, that bar was met on hardware — the shipped C client bootstrapped, wrote
//! 16 MiB and verified it through an earlier Rust daemon with no client changes —
//! and the bar was then withdrawn. What survives is a *proven*
//! design: the 10-byte frame, the command layouts and the ordinal table stay because
//! two independent implementations agree on them and changing them is churn, not
//! because anything must still be served. Protocol version stays **1**.
//!
//! What that changes: the C's defects here are **not** reproduced. Its payload-cap
//! off-by-one, its never-sent progress frames, its `t31x` pre-seed for an unknown
//! gadget and its unmasked-frame tolerance are each fixed and each says so at the
//! definition.
//!
//! Transport framing — the WebSocket server, the HTTP-POST-chunked path the browser
//! uses, the first-byte sniff and the auth handshake — lives in `tdfu-daemon`, not
//! here. This crate is the codec.

#![forbid(unsafe_code)]

pub mod crc;
pub mod error;
pub mod frame;
pub mod progress;
pub mod request;
pub mod variant;

pub use crc::{Crc32, crc32};
pub use error::ProtoError;
pub use frame::{Command, HEADER_LEN, RequestHeader, ResponseHeader, Status, exceeds_payload_cap};
pub use progress::ProgressBody;
pub use request::{Blobs, DeviceEntry, ERASE_ALT, ERASE_TOKEN, Request};
pub use variant::WireVariant;

/// `"TDFU"`.
pub const MAGIC: u32 = 0x5444_4655;

/// Protocol version 1.
pub const VERSION: u8 = 1;

/// 64 MiB, in both directions.
pub const MAX_PAYLOAD: u32 = 64 * 1024 * 1024;

/// The port the daemon binds by default.
pub const DEFAULT_PORT: u16 = 5050;

/// The 13 error strings, by index (`utils.c` `tdfu_error_to_string`).
///
/// The daemon maps a `tdfu_core::Error` onto these. Two mappings are not obvious and
/// have already been got wrong once each:
///
/// * `Error::State` → `"Protocol error"`. The C flattens a make-idle failure into
///   `TDFU_ERROR_PROTOCOL`; our clearer local wording must not reach the wire.
/// * `Error::MissingAlt` → `"Invalid parameter"`. `dfu.c:708` and `dfu.c:756` both
///   return `TDFU_ERROR_INVALID_PARAMETER`, not a new string.
pub const ERROR_STRINGS: [&str; 13] = [
    "Success",
    "Initialization failed",
    "Device not found",
    "Failed to open device",
    "Transfer failed",
    "Timeout",
    "Invalid parameter",
    "Memory allocation failed",
    "File I/O error",
    "Protocol error",
    "Transfer timeout",
    "Verify failed (read-back mismatch)",
    "Unknown error",
];

/// The wire wording for a failed verify.
///
/// `verify failed at offset 0x%08llX` — **uppercase hex, zero-padded to eight digits**,
/// and wider than eight for an offset that needs it. The producer is
/// `dfu-remote/main.c:590`; the Android JNI writes the same text at
/// `android-jni/tdfu_jni.c:641`.
///
/// **Not** `tdfu_core::Error::Verify`'s `Display`, which is the local, more detailed
/// wording. The daemon must use this one or the wire string diverges,
/// and the two are pinned apart by
/// `the_wire_verify_string_is_not_a_local_one`.
#[must_use]
pub fn verify_failed_message(offset: u64) -> String {
    format!("verify failed at offset 0x{offset:08X}")
}

#[cfg(test)]
mod tests {
    use super::{ERROR_STRINGS, MAGIC, MAX_PAYLOAD, VERSION};

    #[test]
    fn rpc_constants_are_the_frozen_ones() {
        assert_eq!(MAGIC.to_be_bytes(), *b"TDFU");
        assert_eq!(VERSION, 1);
        assert_eq!(MAX_PAYLOAD, 67_108_864, "64 MiB");
        assert_eq!(ERROR_STRINGS.len(), 13);
        assert_eq!(ERROR_STRINGS[9], "Protocol error");
        assert_eq!(ERROR_STRINGS[6], "Invalid parameter");
    }
}
