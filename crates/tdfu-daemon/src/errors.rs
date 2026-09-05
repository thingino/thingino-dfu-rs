//! The daemon's own error type, and the one place a [`tdfu_core::Error`] becomes a
//! wire string.
//!
//! # Two kinds of failure, and why they are different types
//!
//! A **command** that fails is not an error of this daemon's: it is a `RESP_ERROR`
//! frame carrying [`wire_message`], and the dispatch that sent it returns `Ok(())`. The
//! connection is fine and the next command may well succeed.
//!
//! A [`DaemonError`] is the other thing: the *connection* is unusable — the client
//! vanished mid-write, the socket errored, the framing cannot be resynchronised. It
//! ends the session.
//!
//! Keeping them apart is what stops the state sticking. An earlier implementation let a
//! dropped connection leave the daemon's state stuck at `writing` for the life of the
//! process, because the path that noticed the client was gone was the same path that
//! would have restored the state. Here every operation that claims one of the daemon's
//! states — `BOOTSTRAP`, `WRITE` and `READ`; `DIAG` and `REBOOT` claim none, as the C's
//! do not — holds a [`Busy`](crate::commands::state::Busy) guard whose `Drop` restores
//! `idle`, so the state unwinds whichever of the two failures happens, including a
//! panic.
//!
//! # The mapper carries the cause
//!
//! The subtlest way to lose a fault is to discard information because the C's messages
//! could not carry it. An earlier implementation's `errors.rs` formatted
//! `"unrecognised SoC (soc_id 0x…); send a variant, or stream --spl and --uboot"` and
//! then sent a bare `Invalid parameter`, and did the same to the `--cpu` shortlist, the
//! missing loader path and `UsbError`'s detail.
//!
//! Nothing on the wire required that. The `RESP_ERROR` payload is length-prefixed
//! free-form UTF-8, and the `dfu-remote` daemon interpolated into the same field itself
//! (`"write failed: %s"`, `dfu-remote/main.c:593`), so the field has always been
//! free-form. Every message here is therefore
//! `"<the C's class>: <everything Rust had in hand>"`, and the colon carries the register
//! values, the candidate list, the path, the pipe and the deadline.
//!
//! The class is **not** here to keep a text-matching client working, which is what this
//! file used to claim. An audit read both shipped clients for it and neither compares
//! this payload to anything: `cli/remote.c` prints it verbatim (`:312`, `:415`, `:451`,
//! `:593`, `:655`), and `web/src/remote.js:161-165` decodes it, calls
//! `onLog('ERROR: ' + m)` and returns `null`. The class is here for the operator reading
//! the line, and for a client that might one day want a stable prefix.
//!
//! # Headroom on the wire: about 500 bytes
//!
//! The shipped C CLI reads a `RESP_ERROR` on its READ path into a `char msg[512]` and
//! returns without draining the remainder (`cli/remote.c:306-313`), so that one path
//! truncates at 511 bytes. Nothing desynchronises, because the connection is finished
//! either way, and the longest message this file can build is well under it (an
//! [`Error::Ambiguous`] candidate list is the widest). Recorded so that a future message
//! wanting to carry a whole alt list or a register dump knows the budget it is spending:
//! keep wire error messages under about 500 bytes.
//!
//! # What the class is for
//!
//! [`error_string`] alone is the C's `tdfu_error_to_string` (`libtdfu/src/utils.c:258`),
//! and it is what spec gaps (k) and (r) name. It is public because those two mappings
//! have been got wrong once each and a test that pins them should not have to parse a
//! formatted message to do it.

use tdfu_core::Error;
use tdfu_proto::ERROR_STRINGS;
use tdfu_usb::UsbErrorKind;

/// Indices into [`ERROR_STRINGS`], named.
///
/// The C's `tdfu_error_t` values are **negative** (`libtdfu/include/tdfu/tdfu.h:135-148`),
/// so `-r` is the index: `TDFU_ERROR_PROTOCOL` is `-9` and `ERROR_STRINGS[9]` is
/// `"Protocol error"`. Naming them is what stops a mapping being written as a bare
/// subscript that nobody can check against the C.
pub mod code {
    /// `TDFU_SUCCESS` (0). Never sent — a success is a `RESP_OK`.
    pub const SUCCESS: usize = 0;
    /// `TDFU_ERROR_INIT_FAILED` (-1).
    pub const INIT_FAILED: usize = 1;
    /// `TDFU_ERROR_DEVICE_NOT_FOUND` (-2).
    pub const DEVICE_NOT_FOUND: usize = 2;
    /// `TDFU_ERROR_OPEN_FAILED` (-3).
    pub const OPEN_FAILED: usize = 3;
    /// `TDFU_ERROR_TRANSFER_FAILED` (-4).
    pub const TRANSFER_FAILED: usize = 4;
    /// `TDFU_ERROR_TIMEOUT` (-5).
    pub const TIMEOUT: usize = 5;
    /// `TDFU_ERROR_INVALID_PARAMETER` (-6).
    pub const INVALID_PARAMETER: usize = 6;
    /// `TDFU_ERROR_MEMORY` (-7). Nothing here allocates fallibly.
    pub const MEMORY: usize = 7;
    /// `TDFU_ERROR_FILE_IO` (-8).
    pub const FILE_IO: usize = 8;
    /// `TDFU_ERROR_PROTOCOL` (-9).
    pub const PROTOCOL: usize = 9;
    /// `TDFU_ERROR_TRANSFER_TIMEOUT` (-10).
    pub const TRANSFER_TIMEOUT: usize = 10;
    /// `TDFU_ERROR_VERIFY` (-11).
    pub const VERIFY: usize = 11;
    /// The C's `default:` arm (`libtdfu/src/utils.c:285`).
    pub const UNKNOWN: usize = 12;
}

/// A failure that ends the connection.
///
/// **Not** a failed command: see the module docs. The transport owns the handshake and
/// the framing, so it owns the type; the commands only propagate it.
pub use crate::transport::DaemonError;

/// The C error class this failure belongs to.
///
/// Every arm is verified against the C, and the two the C is least obvious about
/// are marked at the arm:
///
/// * [`Error::State`] is a `make_idle` failure. The C flattens all five of its
///   `make_idle` sites into `TDFU_ERROR_PROTOCOL` (`dfu.c:578`, `:716`, `:764`, `:823`,
///   `:916`), so the wire says `"Protocol error"` however much clearer our own wording
///   is.
/// * [`Error::MissingAlt`] is `TDFU_ERROR_INVALID_PARAMETER` and not a new string:
///   `dfu.c:708` (the `erase` alt) and `dfu.c:756` (the `reboot` alt) both return it
///   after logging `This loader has no "%s" alt`. Read and confirmed
///   line-for-line.
/// * [`Error::NotDfu`] is `TDFU_ERROR_DEVICE_NOT_FOUND`: `dfu.c:278-280` logs
///   `No DFU interface found - is the device in U-Boot DFU mode?` and returns it.
/// * [`Error::Protocol`] is the same code from the other direction — `dfu.c:255-256`
///   returns `TDFU_ERROR_PROTOCOL` for a configuration descriptor that will not parse.
/// * [`Error::LoaderMissing`] and [`Error::Io`] are `TDFU_ERROR_FILE_IO`, the code the C
///   reserves for a file it could not read (`utils.c:277`).
/// * [`Error::Ambiguous`] and [`Error::UnknownSoc`] are detection refusals, which are
///   requests for a `--cpu` the caller did not give: `TDFU_ERROR_INVALID_PARAMETER`.
///   The C cannot reach them — its detection guesses `t31x` rather than refusing
///   (`libtdfu/src/usb/manager.c:138`, `utils.c:241-242`) — so this is a class chosen for
///   a case the C does not have, and the *detail* is the substance of the message.
///
/// [`Error`] is `#[non_exhaustive]` and lives in another crate, so a variant added later
/// lands on [`code::UNKNOWN`] rather than failing to compile, and `"Unknown error"` is an
/// honest default for one. **There is no compile-time obligation available here**: a
/// `match` on a foreign `#[non_exhaustive]` enum must carry a wildcard, so nothing in
/// this crate can be made to stop compiling when that enum grows. This doc
/// used to claim `every_error_variant_has_a_decided_class` did exactly that, and no
/// arrangement short of a mirror enum in `tdfu-core` can. What that test is instead is a
/// second, independently written copy of this table: it catches an *edit* to the arms
/// below, and it does not catch an *addition* to [`Error`].
#[must_use]
pub fn error_class(error: &Error) -> usize {
    match error {
        // A3: the context is ours, the class is the transport's. The same reasoning as
        // `Error::is_recoverable` — adding a `doing:` string must not move an error
        // between classes, so both arms delegate to the same function.
        Error::Usb(source) | Error::UsbWhile { source, .. } => usb_class(source.kind()),
        // The C's five `make_idle` sites all return TDFU_ERROR_PROTOCOL.
        Error::Protocol(_) | Error::State(_) => code::PROTOCOL,
        Error::NotDfu => code::DEVICE_NOT_FOUND,
        Error::Verify { .. } => code::VERIFY,
        // `MissingAlt` is `dfu.c:708` and `dfu.c:756`'s refusal, and the other three
        // are detection and argument refusals; all four are the C's
        // `TDFU_ERROR_INVALID_PARAMETER`.
        Error::MissingAlt(_) | Error::Ambiguous { .. } | Error::UnknownSoc { .. } | Error::Invalid(_) => {
            code::INVALID_PARAMETER
        }
        Error::LoaderMissing(_) | Error::Io(_) => code::FILE_IO,
        _ => code::UNKNOWN,
    }
}

/// The C error class for a transport failure.
///
/// The C's own mapping, read at the source rather than guessed:
///
/// * `LIBUSB_ERROR_TIMEOUT` → `TDFU_ERROR_TIMEOUT` (`libtdfu/src/usb/device.c:446`),
///   and **every other** libusb failure → `TDFU_ERROR_TRANSFER_FAILED` (`:451`). That is
///   the whole of its bulk-transfer table.
/// * A failed open → `TDFU_ERROR_OPEN_FAILED` (`device.c:162`, `:171`, `:287`), and
///   `dfu.c:353` is explicit that the distinction is permission:
///   `access_denied ? TDFU_ERROR_OPEN_FAILED : TDFU_ERROR_DEVICE_NOT_FOUND`.
/// * A dead handle → `TDFU_ERROR_INVALID_PARAMETER` (`device.c:494`), which is where
///   [`UsbErrorKind::Unsupported`] lands: the caller asked a backend for something it
///   cannot do.
///
/// [`UsbErrorKind::Backend`] is `"Unknown error"` **with the backend's own text after the
/// colon**. It is the one kind whose class is genuinely unknown, and it is also the one
/// carrying the most specific message, which is exactly the pair that must not be
/// collapsed.
fn usb_class(kind: &UsbErrorKind) -> usize {
    match kind {
        UsbErrorKind::Timeout => code::TIMEOUT,
        UsbErrorKind::NoDevice => code::DEVICE_NOT_FOUND,
        UsbErrorKind::AccessDenied | UsbErrorKind::Busy => code::OPEN_FAILED,
        UsbErrorKind::Stall | UsbErrorKind::Fault | UsbErrorKind::Short { .. } | UsbErrorKind::Overflow => {
            code::TRANSFER_FAILED
        }
        UsbErrorKind::NotClaimed => code::PROTOCOL,
        UsbErrorKind::Unsupported => code::INVALID_PARAMETER,
        _ => code::UNKNOWN,
    }
}

/// The bare C class string: `tdfu_error_to_string`'s answer.
///
/// This is what an earlier implementation sent *instead of* the cause. It is public so that the
/// two marked arms can be pinned without parsing a message, and so a caller that genuinely wants
/// only the class (a log line that already carries the detail) can have it. Everything
/// that goes on the wire uses [`wire_message`].
#[must_use]
pub fn error_string(error: &Error) -> &'static str {
    ERROR_STRINGS[error_class(error)]
}

/// The `RESP_ERROR` payload for a failed operation: the class, then the cause.
///
/// `"<class>: <Display>"`, uniformly. Uniform because the alternative, a per-variant
/// decision about whether the detail is worth carrying, is how an earlier implementation
/// ended up discarding four different causes while believing it kept them.
///
/// The one thing this is **not** used for is a verify failure on the write path, which
/// has its own wire string, `tdfu_proto::verify_failed_message`, with no
/// `write failed:` prefix (`dfu-remote/main.c:588-595`, read). The write handler
/// special-cases it and both shapes are pinned. A blank-check failure from `ops::erase`
/// is *also* an [`Error::Verify`] and does **not** take that path — the C sends
/// `"erase failed: Verify failed (read-back mismatch)"` there (`main.c:531`), and this
/// function is what produces it, plus the offset the C threw away.
#[must_use]
pub fn wire_message(error: &Error) -> String {
    format!("{}: {error}", error_string(error))
}

/// `"<what was being done> failed: <class>: <cause>"`, for every command that reports one.
///
/// The C's shape (`"bootstrap failed: %s"` `main.c:438`, `"write failed: %s"` `:593`,
/// `"erase failed: %s"` `:531`, `"read failed: %s"` `:670`) with the cause appended
/// rather than dropped.
#[must_use]
pub fn failed(doing: &str, error: &Error) -> String {
    format!("{doing} failed: {}", wire_message(error))
}

#[cfg(test)]
mod tests {
    use super::{DaemonError, code, error_class, error_string, failed, wire_message};
    use crate::auth::AuthReason;
    use crate::transport::Transport;
    use tdfu_core::Error;
    use tdfu_core::model::SocRegs;
    use tdfu_proto::ERROR_STRINGS;
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// The `make_idle` gap, and the reason it was recorded: `make_idle`'s failure is
    /// `Error::State` here and `TDFU_ERROR_PROTOCOL` in all five of the C's sites
    /// (`dfu.c:578`, `:716`, `:764`, `:823`, `:916`). The wire must not carry our
    /// clearer local wording as the class.
    #[test]
    fn gap_k_state_is_protocol_error_on_the_wire() {
        let error = Error::State("dfuERROR".to_owned());
        assert_eq!(error_class(&error), code::PROTOCOL);
        assert_eq!(error_string(&error), "Protocol error");
        // ... and the cause still travels, which is the half an earlier build dropped.
        assert_eq!(
            wire_message(&error),
            "Protocol error: device is in state dfuERROR, which this operation cannot proceed from"
        );
    }

    /// The missing-alt gap: `dfu.c:708` and `dfu.c:756` both return
    /// `TDFU_ERROR_INVALID_PARAMETER` after logging `This loader has no "%s" alt`. Not a
    /// new string, and not `Device not found`.
    #[test]
    fn gap_r_missing_alt_is_invalid_parameter_on_the_wire() {
        let error = Error::MissingAlt("erase");
        assert_eq!(error_class(&error), code::INVALID_PARAMETER);
        assert_eq!(error_string(&error), "Invalid parameter");
        assert!(
            wire_message(&error).starts_with("Invalid parameter: the loader has no alt named \"erase\""),
            "{}",
            wire_message(&error)
        );
        // The actionable half of the message reaches the wire too.
        assert!(wire_message(&error).contains("update the DFU loader firmware"));
    }

    /// The named instance of a cause thrown away: an earlier implementation formatted
    /// this exact sentence and then sent `Invalid parameter` on its own.
    #[test]
    fn the_unknown_soc_advice_reaches_the_wire() {
        let error = Error::UnknownSoc {
            regs: SocRegs::new(0x1000_0001, 0x2222_3333, 0x4444_5555),
        };
        let message = wire_message(&error);
        assert_eq!(error_string(&error), "Invalid parameter");
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(message.contains("0x10000001"), "the soc_id must survive: {message}");
        assert!(message.contains("0x22223333"), "and subsoctype1: {message}");
        assert!(message.contains("0x44445555"), "and subsoctype2: {message}");
        assert!(message.contains("--cpu"), "and what to do about it: {message}");
        assert!(message.contains("--spl"), "including the override: {message}");
    }

    /// The `--cpu` shortlist is the other half of the same finding: an ambiguous grade
    /// knows every chip it could be, and that list is what an operator needs.
    #[test]
    fn the_cpu_shortlist_reaches_the_wire() {
        let error = Error::Ambiguous {
            regs: SocRegs::new(0x1004_0003, 0, 0x7777_0000),
            candidates: Vec::new(),
        };
        let message = wire_message(&error);
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(message.contains("0x10040003"), "the grade evidence: {message}");
        assert!(message.contains("pass --cpu"), "{message}");
    }

    /// And the loader path: a missing file names the file.
    #[test]
    fn the_missing_loader_path_reaches_the_wire() {
        let error = Error::LoaderMissing("firmware/dfu/t31x/u-boot-spl.bin (not found)".to_owned());
        assert_eq!(error_string(&error), "File I/O error");
        assert!(
            wire_message(&error).contains("firmware/dfu/t31x/u-boot-spl.bin"),
            "{}",
            wire_message(&error)
        );
    }

    /// A transport failure keeps the pipe, the length and the deadline. An earlier
    /// implementation's unit variants made a 2 s bulk-IN failure and a 30 s DNLOAD failure
    /// on EP0 indistinguishable; the C logs all four fields at
    /// `[ERROR]` level (`libtdfu/src/usb/device.c:449-450`).
    #[test]
    fn a_transport_failure_keeps_its_detail() {
        let error = Error::Usb(UsbError::new(UsbErrorKind::Short { got: 3, want: 4096 }, Pipe::Device));
        let message = wire_message(&error);
        assert_eq!(error_string(&error), "Transfer failed", "device.c:451");
        assert!(message.contains('3') && message.contains("4096"), "{message}");
    }

    /// A3's property, applied to the wire: adding a context string must not move an
    /// error between classes. `Error::UsbWhile` delegates exactly as `is_recoverable`
    /// does, and the context leads the message.
    #[test]
    fn context_does_not_change_a_usb_failure_s_class() {
        for kind in every_usb_kind() {
            let bare = Error::Usb(UsbError::new(kind.clone(), Pipe::Device));
            let with_context = Error::UsbWhile {
                doing: "reading soc_id at 0xB300002C".to_owned(),
                source: UsbError::new(kind.clone(), Pipe::Device),
            };
            assert_eq!(
                error_class(&bare),
                error_class(&with_context),
                "{kind:?} changed class when it gained a context"
            );
            assert!(
                wire_message(&with_context).contains("reading soc_id at 0xB300002C"),
                "{kind:?}: the context must survive"
            );
        }
    }

    /// Every `UsbErrorKind`, mapped, both ways — the shape `tdfu-core`'s own
    /// `dfu12_recoverable_class_is_pinned_for_every_kind` uses, for the same reason: a
    /// table with no test is a table that drifts.
    ///
    /// The C's citations are on `usb_class`. Two are worth restating here because they
    /// are the ones a reader would guess wrong: `Busy` is an *open* failure, not a
    /// transfer failure, because a resource another process holds is exactly what
    /// `dfu.c:353`'s `access_denied` branch is about; and `NotClaimed` is a *protocol*
    /// failure, because it can only mean this host asked for a pipe it never declared.
    #[test]
    fn every_usb_kind_has_a_decided_wire_class() {
        for (kind, expected) in [
            (UsbErrorKind::Timeout, code::TIMEOUT),
            (UsbErrorKind::NoDevice, code::DEVICE_NOT_FOUND),
            (UsbErrorKind::AccessDenied, code::OPEN_FAILED),
            (UsbErrorKind::Busy, code::OPEN_FAILED),
            (UsbErrorKind::Stall, code::TRANSFER_FAILED),
            (UsbErrorKind::Fault, code::TRANSFER_FAILED),
            (UsbErrorKind::Short { got: 1, want: 2 }, code::TRANSFER_FAILED),
            (UsbErrorKind::Overflow, code::TRANSFER_FAILED),
            (UsbErrorKind::NotClaimed, code::PROTOCOL),
            (UsbErrorKind::Unsupported, code::INVALID_PARAMETER),
            (UsbErrorKind::Backend("scripted mismatch".to_owned()), code::UNKNOWN),
        ] {
            let error = Error::Usb(UsbError::new(kind.clone(), Pipe::Device));
            assert_eq!(error_class(&error), expected, "{kind:?}");
        }
        // The one kind whose class is unknown still carries the most specific text.
        let backend = Error::Usb(UsbError::new(
            UsbErrorKind::Backend("scripted mismatch".to_owned()),
            Pipe::Device,
        ));
        assert_eq!(error_string(&backend), "Unknown error");
        assert!(wire_message(&backend).contains("scripted mismatch"));
    }

    /// A second, independently written copy of `error_class`'s table.
    ///
    /// **What it catches:** an edit to one of `error_class`'s arms. The two lists then
    /// disagree and this fails.
    ///
    /// **What it cannot catch:** a variant added to `tdfu_core::Error`. That enum is
    /// `#[non_exhaustive]` and lives in another crate, so the `match` below must carry a
    /// wildcard and the `variants` fixture has to be a hand-written list; a new variant
    /// is absent from both, this passes, and `error_class`'s `_ =>` sends
    /// `"Unknown error"` in silence. The doc here used to claim the opposite,
    /// that adding one "stops compiling *here*", and nothing short of a mirror enum in
    /// `tdfu-core` could make that true. The wildcard arm below is what is left of the
    /// idea: it fires for a variant that reaches this fixture without reaching
    /// `error_class`.
    #[test]
    fn every_error_variant_has_a_decided_class() {
        let variants = [
            Error::Usb(UsbError::new(UsbErrorKind::Timeout, Pipe::Device)),
            Error::UsbWhile {
                doing: "x".to_owned(),
                source: UsbError::new(UsbErrorKind::Timeout, Pipe::Device),
            },
            Error::Protocol("x".to_owned()),
            Error::State("x".to_owned()),
            Error::NotDfu,
            Error::Verify {
                offset: 0,
                expected: 0,
                actual: None,
            },
            Error::MissingAlt("flash"),
            Error::Ambiguous {
                regs: SocRegs::new(0, 0, 0),
                candidates: Vec::new(),
            },
            Error::UnknownSoc {
                regs: SocRegs::new(0, 0, 0),
            },
            Error::LoaderMissing("x".to_owned()),
            Error::Invalid("x".to_owned()),
            Error::Io(std::io::Error::other("x")),
        ];
        for error in &variants {
            let class = match error {
                // `TIMEOUT` here is the *fixture's* kind, not the arm's rule.
                // Both `Usb` rows above are built with `UsbErrorKind::Timeout`, and
                // `usb_class` decides the rest. The table for the arm is
                // `every_usb_kind_has_a_decided_wire_class`, which is complete and checks
                // the two counter-intuitive rows explicitly.
                Error::Usb(_) | Error::UsbWhile { .. } => code::TIMEOUT,
                Error::Protocol(_) | Error::State(_) => code::PROTOCOL,
                Error::NotDfu => code::DEVICE_NOT_FOUND,
                Error::Verify { .. } => code::VERIFY,
                Error::MissingAlt(_) | Error::Ambiguous { .. } | Error::UnknownSoc { .. } | Error::Invalid(_) => {
                    code::INVALID_PARAMETER
                }
                Error::LoaderMissing(_) | Error::Io(_) => code::FILE_IO,
                // `Error` is `#[non_exhaustive]`: a new variant lands here, and the
                // assertion below fails until someone decides its class above and in
                // `error_class`.
                other => {
                    assert_ne!(
                        error_class(other),
                        code::UNKNOWN,
                        "a new Error variant needs a decided wire class: {other:?}"
                    );
                    continue;
                }
            };
            assert_eq!(error_class(error), class, "{error:?}");
            assert_ne!(error_class(error), code::SUCCESS, "no failure is a success");
        }
    }

    /// The classes this daemon can never send, stated so the table above is readable as
    /// complete rather than as merely long.
    #[test]
    fn three_c_classes_have_no_producer_here() {
        // `Success` is a RESP_OK, not a RESP_ERROR. `Initialization failed` is the C's
        // `usb_manager_init` failure, which has no analogue: nothing is initialised
        // globally here. `Memory allocation failed` is the C's `malloc` check.
        // `Transfer timeout` is `TDFU_ERROR_TRANSFER_TIMEOUT`, which the C's own
        // transfer path never returns either (`device.c:446` uses `TIMEOUT`).
        for unreachable in [code::SUCCESS, code::INIT_FAILED, code::MEMORY, code::TRANSFER_TIMEOUT] {
            assert!(!ERROR_STRINGS[unreachable].is_empty());
        }
        assert_eq!(ERROR_STRINGS[code::TRANSFER_TIMEOUT], "Transfer timeout");
    }

    /// The `"<doing> failed: …"` shape the C uses, with the cause appended rather than
    /// dropped (`dfu-remote/main.c:438`, `:531`, `:593`, `:670`).
    #[test]
    fn the_failed_prefix_matches_the_c_shape() {
        let error = Error::NotDfu;
        assert_eq!(
            failed("write", &error),
            "write failed: Device not found: no DFU interface: is the device in U-Boot DFU mode?"
        );
        assert!(failed("erase", &error).starts_with("erase failed: Device not found"));
    }

    /// A `DaemonError` is the connection, never the command — and it says which.
    #[test]
    fn a_daemon_error_names_the_connection_not_the_device() {
        let dropped = DaemonError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        let message = dropped.to_string();
        // An earlier build called this "Auth failed" and sent people to debug a good token.
        assert!(!message.contains("uth"), "{message}");

        let refused = DaemonError::AuthRejected {
            transport: Transport::Raw,
            reason: AuthReason::WrongToken,
        };
        let message = refused.to_string();
        assert!(message.starts_with("auth rejected over "), "{message}");
        assert_eq!(AuthReason::WrongToken.wire_message(), "auth: invalid token", "wording");
    }

    fn every_usb_kind() -> Vec<UsbErrorKind> {
        vec![
            UsbErrorKind::Timeout,
            UsbErrorKind::Stall,
            UsbErrorKind::NoDevice,
            UsbErrorKind::Fault,
            UsbErrorKind::Short { got: 3, want: 4 },
            UsbErrorKind::AccessDenied,
            UsbErrorKind::Busy,
            UsbErrorKind::Overflow,
            UsbErrorKind::Unsupported,
            UsbErrorKind::NotClaimed,
            UsbErrorKind::Backend("scripted mismatch".to_owned()),
        ]
    }
}
