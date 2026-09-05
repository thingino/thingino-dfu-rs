//! The eight commands, and the one place a request becomes work.
//!
//! # The seam
//!
//! [`dispatch`] is the daemon's command half. Everything about *sockets* — the first-byte
//! sniff, the WebSocket and HTTP transports, the 10-byte header, the token handshake —
//! belongs to the transport half and reaches here as a [`Wire`]: four methods that put
//! frames on whatever the client is speaking.
//!
//! `Wire` is a trait rather than the transport's `Conn` enum for one reason: it is
//! exactly the set of methods `dispatch` consumes, so every command in this directory is
//! tested against a loopback that records frames, with no socket and no runtime. It
//! carries no `accept`, `next_request` or `one_shot` — those belong to the accept loop,
//! which is not this file's.
//!
//! # What a failure means here
//!
//! A command that fails is a `RESP_ERROR` frame and `Ok(())`: the connection is fine.
//! A [`DaemonError`] means the *connection* is gone. See [`crate::errors`], and
//! [`state::Busy`] for why the daemon's state cannot be left behind by either.

pub mod bootstrap;
pub mod device;
pub mod diag;
pub mod discover;
pub mod read;
pub mod reboot;
pub mod report;
pub mod staging;
pub mod state;
pub mod write;

#[cfg(test)]
pub mod fake;

use tdfu_core::clock::Sleeper;
use tdfu_core::model::{AltSel, Variant};
use tdfu_core::{Error, Result as CoreResult};
use tdfu_proto::{Command, ProgressBody, Request, Status, exceeds_payload_cap};
use tdfu_usb::LocalUsbBackend;

use crate::errors::DaemonError;
use state::{Activity, DaemonState};

/// The frames [`dispatch`] can put on a connection.
///
/// Implemented by the transport's `Conn` and, in this crate's tests, by a
/// loopback that records what it was handed.
#[allow(
    async_fn_in_trait,
    reason = "AGENTS.md D1: ?Send is the point, and no async_trait crate"
)]
pub trait Wire {
    /// The final OK/ERROR frame for the request being handled.
    ///
    /// # Errors
    /// [`DaemonError`] when the frame cannot be written.
    async fn respond(&mut self, status: Status, payload: &[u8]) -> Result<(), DaemonError>;

    /// One `RESP_LOG` frame, carrying a whole line.
    ///
    /// # Errors
    /// [`DaemonError`] when the frame cannot be written.
    async fn log(&mut self, line: &str) -> Result<(), DaemonError>;

    /// One `RESP_PROGRESS` frame.
    ///
    /// # Errors
    /// [`DaemonError`] when the frame cannot be written.
    async fn progress(&mut self, body: &ProgressBody) -> Result<(), DaemonError>;

    /// Does this transport emit log and progress frames for this command?
    fn logs_enabled_for(&self, cmd: Command) -> bool;
}

/// What a handler decided, before it reaches the wire.
///
/// The split between [`Ok`](Reply::Ok) and [`Bulk`](Reply::Bulk) is the encode-side
/// payload cap an audit asked for on this side too: every OK payload is
/// checked against the 64 MiB cap **except** `CMD_READ`'s, which the wire
/// explicitly allows to exceed it, a NAND alt 0 being 256 MiB and streamed by the
/// shipped clients.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// A success payload subject to the 64 MiB cap.
    Ok(Vec<u8>),
    /// `CMD_READ`'s success payload, which may exceed the cap.
    Bulk(Vec<u8>),
    /// A `RESP_ERROR` payload: UTF-8, not NUL-terminated.
    Error(String),
}

impl Reply {
    /// The two-byte `"OK"` that bootstrap, write and cancel answer with.
    #[must_use]
    pub fn ok() -> Self {
        Self::Ok(b"OK".to_vec())
    }

    /// A failed operation, worded as the wire does: `"<doing> failed: <cause>"`.
    #[must_use]
    pub fn failed(doing: &str, error: &Error) -> Self {
        Self::Error(crate::errors::failed(doing, error))
    }
}

/// Run one request and answer it.
///
/// Exactly one frame of `RESP_OK` or `RESP_ERROR` leaves per call, after any log and
/// progress frames the operation produced.
///
/// # Errors
/// [`DaemonError`] only when the *connection* failed — the client vanished, the socket
/// errored. A device that refused, a payload that would not parse and an index that
/// names nothing are all `Ok(())` with a `RESP_ERROR` frame.
pub async fn dispatch<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    cmd: Command,
    payload: &[u8],
) -> Result<(), DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    let reply = match Request::decode(cmd, payload) {
        Ok(request) => run(conn, state, request).await?,
        // The decoder's wording is the C daemon's own for the same refusal
        // (`dfu-remote/main.c:359` … `:627`). `wire_message` answers `None` only for
        // failures the peer must not be told — of which the one reachable from a
        // complete payload is `Truncated`, which the C answers as a short payload.
        Err(error) => {
            tracing::debug!(?cmd, %error, "refused a malformed payload");
            Reply::Error(error.wire_message().unwrap_or("payload too short").to_owned())
        }
    };
    // The state cannot stick, as an invariant rather than a comment: whatever a
    // handler did, the guard it took has been dropped by the time it returns. The
    // release build has no check here because there is nothing to check - the guard's
    // `Drop` is the mechanism, and this only catches a future handler that reaches for
    // the state some other way.
    debug_assert_eq!(
        state.activity(),
        Activity::Idle,
        "a command left the daemon busy; see commands::state::Busy"
    );
    respond(conn, reply).await
}

async fn run<W, B, C>(conn: &mut W, state: &mut DaemonState<B, C>, request: Request) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    match request {
        Request::Discover => discover::handle(state).await,
        Request::Bootstrap { index, variant, blobs } => bootstrap::handle(conn, state, index, &variant, blobs).await,
        // The wipe token written to the `erase` alt **is** the whole-chip
        // erase, routed to the grace-and-blank-check path rather than a generic
        // download (`dfu-remote/main.c:500-535`). There is no erase command on the wire.
        // The routing test is `is_erase`, which compares both halves whole — the C
        // `strcmp`s a NUL-terminated copy, so `"erase\0junk"` wipes a chip for it, and
        // an earlier implementation reproduced that and *widened* the set of payloads
        // that erase a flash.
        Request::Write { .. } if request_is_erase(&request) => write::erase(conn, state, &request).await,
        Request::Write { .. } => write::handle(conn, state, &request).await,
        Request::Read { index, variant, alt } => read::handle(conn, state, index, &variant, alt.as_deref()).await,
        // The state string, no NUL, `strlen` bytes
        // (`dfu-remote/main.c:734`).
        Request::Status => Ok(Reply::Ok(state.activity().wire_str().as_bytes().to_vec())),
        // The C sets a `g_cancel` nothing ever reads
        // (`dfu-remote/main.c:60`, `:738`), and **this does not interrupt an operation
        // either**: real cancellation is NOT delivered here. The reason is
        // structural rather than an oversight: commands are sequential on
        // one connection with one client at a time, so a `CANCEL` cannot arrive while an
        // operation is running. There is nothing to interrupt.
        //
        // What is here is the flag and `DaemonState::cancelled`, so that when the
        // transport can deliver an out-of-band cancel the hook is one condition in
        // `report::pump`'s loop — which already drops an operation's future mid-`await`
        // safely, because that is what a vanished client does. **`pump` does not read
        // the flag today**, and nothing else does either. Said plainly rather than
        // implied, because a doc that asserts a gap away is how an earlier
        // implementation licensed the omission next to it. What is promised is exactly
        // what is here: a flag, and no interruption of an operation already in
        // flight.
        Request::Cancel => {
            state.cancel();
            tracing::debug!(activity = %state.activity(), "cancel requested");
            Ok(Reply::ok())
        }
        Request::Diag { index } => diag::handle(state, index).await,
        Request::Reboot { index } => reboot::handle(conn, state, index).await,
        // `Request` is `#[non_exhaustive]` and lives in another crate. A command added
        // to the protocol without a handler here answers `unknown command` rather
        // than being silently ignored.
        _ => Ok(Reply::Error("unknown command".to_owned())),
    }
}

/// [`Request::is_erase`] behind a name, so the `match` guard above reads as the rule it
/// is rather than as a method call on the value being matched.
fn request_is_erase(request: &Request) -> bool {
    request.is_erase()
}

async fn respond<W: Wire>(conn: &mut W, reply: Reply) -> Result<(), DaemonError> {
    match reply {
        Reply::Ok(payload) => {
            // The cap applies to what this side sends, not only to what it
            // accepts. Nothing but a `READ` can approach it, and a `READ` takes the
            // `Bulk` arm, so reaching this is a bug here, and a truthful refusal beats
            // a frame the peer will drop.
            //
            // One comparison, not two: a length that does not fit a `u32` cannot fit a
            // `payload_len` field either, so the failed conversion **is** the refusal.
            // Writing it as a second `> u32::MAX` test would need a 4 GiB payload to
            // tell `>` from `>=`, which is a mutant no test on this planet can kill.
            let oversize = u32::try_from(payload.len()).map_or(true, exceeds_payload_cap);
            if oversize {
                tracing::error!(len = payload.len(), "refusing to send an oversize OK payload");
                return conn.respond(Status::Error, b"payload too large").await;
            }
            conn.respond(Status::Ok, &payload).await
        }
        Reply::Bulk(payload) => conn.respond(Status::Ok, &payload).await,
        Reply::Error(message) => conn.respond(Status::Error, message.as_bytes()).await,
    }
}

/// Does this command turn the `[vlen][variant]` field into a loader?
///
/// `CMD_BOOTSTRAP` alone. It hands the name to `tdfu_core::loader::resolve`, which builds
/// `firmware/dfu/<variant>/…` out of it, exactly as the C hands `variant_str` to
/// `tdfu_bootstrap_device` (`dfu-remote/main.c:426`). A name nobody knows has no loader
/// directory, so refusing it is the honest answer; and the device list needs the
/// refusal: an unknown gadget reports
/// [`WireVariant::UNKNOWN`](tdfu_proto::WireVariant::UNKNOWN) rather than the C's `t31x`
/// guess, so a client must not be able to send that ordinal's rendered name back as the
/// SoC a loader path is built from.
///
/// `CMD_WRITE` and `CMD_READ` carry the same field and **nothing downstream of the parse
/// reads it**: the device is chosen by index and the alt by [`parse_alt`], and neither
/// handler binds the parsed variant to anything. The C is the same shape and says so by
/// omission, having written the field into a buffer it then uses once: `handle_write`
/// passes `variant_str` to a `printf` (`dfu-remote/main.c:539`) and `handle_read` to one
/// more (`:634`, through `force_cpu`). Neither ever validates it.
///
/// Refusing it there was a real break rather than a theoretical strictness, which is
/// why only BOOTSTRAP refuses. The shipped browser flasher resolves
/// DISCOVER's ordinal through the WASM `tdfu_variant_to_string`, whose `default:` arm is
/// the literal `"unknown"` (`libtdfu/src/utils.c:127-128`), keeps it as
/// `detectedVariantName` (`web/src/app.js:1203`) and sends it straight back on READ,
/// WRITE and BOOTSTRAP (`:1347`, `:1376`, `:1299`). Because the device list reports an
/// unrecognised gadget as `0xFF` instead of guessing, that string is what an ordinary
/// bench device produces, so a strict field here refused every read and write the flasher
/// asked for. BOOTSTRAP keeps the refusal because there it names a file.
///
/// `Command` is `#[non_exhaustive]`: a command added to the protocol resolves no loader
/// until someone decides it does, which is the answer that cannot break a client.
#[must_use]
pub const fn variant_selects_a_loader(command: Command) -> bool {
    matches!(command, Command::Bootstrap)
}

/// The `[vlen][variant]` field for one command.
///
/// [`parse_variant`] is the parser; this is the rule about what to do when it refuses,
/// which is [`variant_selects_a_loader`]'s answer. A field the command will not use is
/// logged and dropped, which is the C's behaviour with a level attached.
///
/// # Errors
/// [`Error::Invalid`] naming what was sent, for a name that is not UTF-8 or not a known
/// variant, on a command that resolves a loader from it.
fn variant_field(command: Command, bytes: &[u8]) -> CoreResult<Option<Variant>> {
    match parse_variant(bytes) {
        Ok(variant) => Ok(variant),
        Err(error) if variant_selects_a_loader(command) => Err(error),
        Err(error) => {
            tracing::debug!(?command, %error, "ignoring a variant field this command never reads");
            Ok(None)
        }
    }
}

/// The `[vlen][variant]` field, as a [`Variant`].
///
/// Empty means "auto-detect" and is `Ok(None)`. Whether a refusal from here reaches the
/// client is [`variant_field`]'s decision, not this function's.
///
/// The C's own parse bug is not reproduced: `handle_write` and `handle_read` advance the
/// payload cursor by a **clamped** `variant_len` (`main.c:465-468`, `:617-621`) while
/// `handle_bootstrap` advances by the true one (`:370-373`), so a variant string of 64
/// bytes or more desynchronises every field after it on two of the three commands.
/// `tdfu_proto`'s decoder has one reader and no clamp, pinned by
/// `rpc_a_long_variant_does_not_desync_the_fields`.
///
/// # Errors
/// [`Error::Invalid`] naming what was sent, for a name that is not UTF-8 or not a known
/// variant.
fn parse_variant(bytes: &[u8]) -> CoreResult<Option<Variant>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let name = core::str::from_utf8(bytes)
        .map_err(|_| Error::Invalid(format!("the variant field is not UTF-8: {bytes:02X?}")))?;
    Variant::from_cpu_arg(name).map(Some).ok_or_else(|| {
        Error::Invalid(format!(
            "unknown variant {name:?}; pass one of the names --cpu accepts, or send an empty \
             variant to auto-detect"
        ))
    })
}

/// The `[alen][alt]` field, as an [`AltSel`].
///
/// Empty is [`AltSel::Default`], and `tdfu_core::dfu::alt::resolve` answers it the way
/// the CLI does: the alt named `flash`, else the only alt, else refuse. That is this
/// daemon's rule since an audit; before that it was the **C daemon's**
/// rule, `info.alts[0].alt` (`dfu-remote/main.c:351`), as though it were ours. The two
/// agree on every shipped loader, and
/// `fe_daemon_default_alt_on_a_loader_without_flash` is the constructed case where they do
/// not. There is one resolver, whose doc names this daemon as one of its three callers,
/// and using it is what stops the C's three frontends-three-answers split coming back.
///
/// # Errors
/// [`Error::Invalid`] if the name is not UTF-8. A name that is not *on the device* is
/// not this function's business: that needs the device, and
/// [`device::await_gadget`] answers it with the alts the device does offer.
fn parse_alt(bytes: &[u8]) -> CoreResult<AltSel> {
    if bytes.is_empty() {
        return Ok(AltSel::Default);
    }
    let name =
        core::str::from_utf8(bytes).map_err(|_| Error::Invalid(format!("the alt field is not UTF-8: {bytes:02X?}")))?;
    Ok(AltSel::Name(name.to_owned()))
}

/// Which of the six wire states a command claims while it runs, or `None`.
///
/// The table the handlers implement, in one readable place. `Command::Write` is the one
/// entry that is not the whole story: a wipe-token write claims
/// [`Activity::Erasing`](state::Activity::Erasing) instead, and a write
/// with the verify byte set switches to [`Activity::Verifying`](state::Activity::Verifying)
/// half way through, exactly as `dfu-remote/main.c:578` does.
///
/// `DIAG` and `REBOOT` claim nothing, and neither does the C (`dfu-remote/main.c:744`,
/// `:765` set no `g_state`). The six state strings are frozen and there is no
/// `diagnosing` or `rebooting` among them, so a guard for either would have to invent a
/// wire value. Both are short, and commands are sequential, so nobody can ask during one.
#[must_use]
pub const fn claims_state(command: Command) -> Option<Activity> {
    match command {
        Command::Bootstrap => Some(Activity::Bootstrapping),
        Command::Write => Some(Activity::Writing),
        Command::Read => Some(Activity::Reading),
        // `Command` is `#[non_exhaustive]`: a command added to the protocol claims
        // no state until someone decides which of the six it should hold.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Reply, claims_state, parse_alt, parse_variant};
    use crate::commands::fake::{FakeBackend, LoopbackConn, Sent, TestResult};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::{Activity, DaemonState};
    use tdfu_core::model::{AltSel, Variant};
    use tdfu_core::{Error, clock::RecordingClock};
    use tdfu_proto::{Command, Request, Status};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware")
    }

    /// End to end: `CMD_STATUS` has no payload and answers the state
    /// string with no NUL and no `"OK"` wrapper.
    #[test]
    fn rpc_status_layout() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::empty());
        block_on(dispatch(&mut conn, &mut state, Command::Status, &[]))?;
        assert_eq!(conn.sent(), vec![Sent::Response(Status::Ok, b"idle".to_vec())]);
        Ok(())
    }

    /// No payload in, `"OK"` out, and the flag is set.
    ///
    /// The flag is *set*, not acted on — see the handler's comment. Commands are
    /// sequential, so a `CANCEL` cannot arrive mid-operation, there is nothing for it
    /// to stop, and this test claims no more than that.
    #[test]
    fn rpc_cancel_reply() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::empty());
        assert!(!state.cancelled());
        block_on(dispatch(&mut conn, &mut state, Command::Cancel, &[]))?;
        assert_eq!(conn.sent(), vec![Sent::Response(Status::Ok, b"OK".to_vec())]);
        assert!(state.cancelled());
        Ok(())
    }

    /// A payload that does not parse is answered with the C daemon's own wording for
    /// that refusal, and the connection continues.
    #[test]
    fn a_malformed_payload_is_answered_not_dropped() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let mut state = daemon(FakeBackend::empty());
        // `WRITE` with one byte: shorter than `[idx][vlen]` (`dfu-remote/main.c:454`).
        block_on(dispatch(&mut conn, &mut state, Command::Write, &[0]))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Response(Status::Error, b"payload too short".to_vec())]
        );
        // ... and the state did not move.
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// Every command answers with exactly one final frame, whatever else it sends.
    #[test]
    fn every_command_answers_exactly_once() -> TestResult {
        for (command, payload) in [
            (Command::Discover, Vec::new()),
            (Command::Status, Vec::new()),
            (Command::Cancel, Vec::new()),
            (Command::Diag, vec![0]),
            (Command::Reboot, vec![0]),
            (Command::Bootstrap, vec![0, 0]),
            (Command::Write, vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (Command::Read, vec![0, 0]),
        ] {
            let mut conn = LoopbackConn::raw();
            let mut state = daemon(FakeBackend::empty());
            block_on(dispatch(&mut conn, &mut state, command, &payload))?;
            let finals = conn
                .sent()
                .into_iter()
                .filter(|frame| matches!(frame, Sent::Response(..)))
                .count();
            assert_eq!(finals, 1, "{command:?}");
            assert_eq!(state.activity(), Activity::Idle, "{command:?} left the state behind");
        }
        Ok(())
    }

    /// The other half, at the door: a client cannot send an unrecognised
    /// variant name back as the SoC a loader path is built from.
    #[test]
    fn rpc_an_unknown_variant_name_is_refused() -> TestResult {
        assert_eq!(parse_variant(b"")?, None, "empty means auto-detect");
        assert_eq!(parse_variant(b"t31x")?, Some(Variant::T31x));
        assert_eq!(
            parse_variant(b"T31X")?,
            Some(Variant::T31x),
            "case-insensitive, as the C is"
        );
        // What a client renders for `WireVariant::UNKNOWN`.
        let Err(Error::Invalid(message)) = parse_variant(b"unknown") else {
            return Err("\"unknown\" is not a variant".into());
        };
        assert!(message.contains("unknown variant"), "{message}");
        assert!(message.contains("auto-detect"), "and says what to do: {message}");
        // Not UTF-8 at all.
        assert!(matches!(parse_variant(&[0xFF, 0xFE]), Err(Error::Invalid(_))));
        Ok(())
    }

    /// Which commands that refusal actually reaches.
    ///
    /// `BOOTSTRAP` alone, because it alone turns the name into a loader directory. The
    /// shipped browser flasher sends `"unknown"` on all three (`web/src/app.js:1203`
    /// then `:1299`, `:1347`, `:1376`), so a table that answered `true` anywhere else
    /// would refuse every remote read and write it asks for; one that answered `false`
    /// for `BOOTSTRAP` would look for `firmware/dfu/unknown/`. The end-to-end replays
    /// are `rpc_24_*` in `read.rs`, `write.rs` and `bootstrap.rs`.
    #[test]
    fn rpc_24_only_bootstrap_resolves_a_loader_from_the_variant() -> TestResult {
        assert!(super::variant_selects_a_loader(Command::Bootstrap));
        for lenient in [
            Command::Write,
            Command::Read,
            Command::Discover,
            Command::Status,
            Command::Cancel,
            Command::Diag,
            Command::Reboot,
        ] {
            assert!(!super::variant_selects_a_loader(lenient), "{lenient:?}");
            assert_eq!(
                super::variant_field(lenient, b"unknown")?,
                None,
                "{lenient:?} must accept and drop it"
            );
            assert_eq!(super::variant_field(lenient, &[0xFF, 0xFE])?, None, "{lenient:?}");
        }
        // ... and a name that *is* known still parses on a lenient command.
        assert_eq!(super::variant_field(Command::Write, b"t31x")?, Some(Variant::T31x));
        // The strict one keeps both refusals.
        assert!(super::variant_field(Command::Bootstrap, b"unknown").is_err());
        assert!(super::variant_field(Command::Bootstrap, &[0xFF, 0xFE]).is_err());
        Ok(())
    }

    /// Empty is the default, a name is a name, and the resolver
    /// is `tdfu_core`'s one home.
    #[test]
    fn fe_daemon_default_alt() -> TestResult {
        assert_eq!(parse_alt(b"")?, AltSel::Default);
        assert_eq!(parse_alt(b"flash")?, AltSel::Name("flash".to_owned()));
        assert_eq!(
            parse_alt(b"1")?,
            AltSel::Name("1".to_owned()),
            "the C's decimal fallback"
        );
        assert!(matches!(parse_alt(&[0xFF]), Err(Error::Invalid(_))));
        Ok(())
    }

    /// The three commands that hold a state, and the five that do not.
    #[test]
    fn only_the_long_operations_claim_a_state() {
        assert_eq!(claims_state(Command::Bootstrap), Some(Activity::Bootstrapping));
        assert_eq!(claims_state(Command::Write), Some(Activity::Writing));
        assert_eq!(claims_state(Command::Read), Some(Activity::Reading));
        for quiet in [
            Command::Discover,
            Command::Status,
            Command::Cancel,
            Command::Diag,
            Command::Reboot,
        ] {
            assert_eq!(claims_state(quiet), None, "{quiet:?}");
        }
    }

    /// The payload cap applies to what this side sends too. Nothing but a
    /// `READ` can approach it and a `READ` is exempt, so this is the
    /// belt-and-braces path, and a frame the peer will refuse is worse than a refusal.
    #[test]
    fn an_oversize_ok_payload_is_refused_by_this_side() -> TestResult {
        let mut conn = LoopbackConn::raw();
        block_on(super::respond(
            &mut conn,
            Reply::Ok(vec![0; usize::try_from(tdfu_proto::MAX_PAYLOAD)? + 1]),
        ))?;
        assert_eq!(
            conn.sent(),
            vec![Sent::Response(Status::Error, b"payload too large".to_vec())]
        );

        // ... and `Bulk` is exempt, because a NAND alt 0 is 256 MiB.
        let mut bulk = LoopbackConn::raw();
        let big = vec![7_u8; usize::try_from(tdfu_proto::MAX_PAYLOAD)? + 1];
        block_on(super::respond(&mut bulk, Reply::Bulk(big.clone())))?;
        assert_eq!(bulk.sent(), vec![Sent::Response(Status::Ok, big)]);
        Ok(())
    }

    /// Exactly 64 MiB is legal: `MAX_PAYLOAD` is a maximum. The C tested
    /// `>` on a request and `>=` on a response, so the cap itself was legal to send and
    /// fatal to receive; that off-by-one is not reproduced.
    #[test]
    fn exactly_the_cap_is_legal_to_send() -> TestResult {
        let mut conn = LoopbackConn::raw();
        let at_cap = vec![0_u8; usize::try_from(tdfu_proto::MAX_PAYLOAD)?];
        block_on(super::respond(&mut conn, Reply::Ok(at_cap.clone())))?;
        assert_eq!(conn.sent(), vec![Sent::Response(Status::Ok, at_cap)]);
        Ok(())
    }

    /// **The state cannot stick, end to end.** A client that vanishes mid-write
    /// leaves the daemon idle and ready, not wedged at `writing` for the life of the
    /// process.
    ///
    /// An earlier implementation had no test for this because its harness wrote the whole request and
    /// half-closed **before** the daemon accepted, so the connection was never dropped
    /// *during* an operation. `LoopbackConn::failing_after` is that missing shape: the
    /// write fails part way through, `dispatch` propagates a `DaemonError`, and the
    /// state has already unwound because `Busy`'s `Drop` is the mechanism and not a
    /// comment.
    #[test]
    fn a_client_that_vanishes_mid_write_leaves_the_daemon_idle() -> TestResult {
        let image = vec![0x11_u8; 9000];
        let payload = Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: b"flash".to_vec(),
            image: image.clone(),
            crc32: tdfu_proto::crc32(&image),
            verify: Some(true),
        }
        .encode()?;

        // Fail on the third frame, which is inside the download rather than after it.
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().watching(state.watch()).failing_after(2);
        let outcome = block_on(dispatch(&mut conn, &mut state, Command::Write, &payload));

        assert!(outcome.is_err(), "a dead connection must be reported, not swallowed");
        assert_eq!(
            state.activity(),
            Activity::Idle,
            "the daemon must be ready for the next client"
        );
        // It really was mid-operation: the frames that did go out went out while the
        // daemon said `writing`, and there was no final response.
        assert_eq!(conn.activities(), vec![Activity::Writing; 3]);
        assert!(conn.response().is_none(), "{:?}", conn.sent());

        // ... and the next command on a fresh connection is served normally.
        let mut next = LoopbackConn::raw();
        block_on(dispatch(&mut next, &mut state, Command::Status, &[]))?;
        assert_eq!(next.sent(), vec![Sent::Response(Status::Ok, b"idle".to_vec())]);
        Ok(())
    }

    /// The same for a read, where the guard also has a staging file to take with it:
    /// the state unwinds **and** the flash image is removed.
    #[test]
    fn a_client_that_vanishes_mid_read_leaves_nothing_behind() -> TestResult {
        let scratch = crate::commands::fake::Scratch::new("vanish-read")?;
        let mut state = DaemonState::new(
            FakeBackend::new(vec![FakeBackend::gadget_holding(&[0x33; 9000])]),
            RecordingClock::new(),
            "firmware",
        )
        .with_staging_dir(scratch.root());
        let payload = Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw().watching(state.watch()).failing_after(1);
        let outcome = block_on(dispatch(&mut conn, &mut state, Command::Read, &payload));

        assert!(outcome.is_err());
        assert_eq!(state.activity(), Activity::Idle);
        assert_eq!(conn.activities(), vec![Activity::Reading; 2]);
        let left_behind: Vec<_> = std::fs::read_dir(scratch.root())?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect();
        assert!(left_behind.is_empty(), "a flash image was left in {left_behind:?}");
        Ok(())
    }

    /// And a write that fails on the device — not on the wire — leaves the daemon idle
    /// too, which is the other half of the same invariant.
    #[test]
    fn a_failed_operation_leaves_the_daemon_idle() -> TestResult {
        let image = vec![0x11_u8; 16];
        let payload = Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: b"nosuchalt".to_vec(),
            image: image.clone(),
            crc32: tdfu_proto::crc32(&image),
            verify: None,
        }
        .encode()?;
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        let mut conn = LoopbackConn::raw().watching(state.watch());
        block_on(dispatch(&mut conn, &mut state, Command::Write, &payload))?;
        assert!(conn.error_text().is_some());
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// `Reply::ok` is two bytes, not the empty payload
    /// `REBOOT` gives.
    #[test]
    fn the_ok_payload_is_two_bytes() {
        assert_eq!(Reply::ok(), Reply::Ok(b"OK".to_vec()));
        assert_eq!(
            Reply::failed("write", &Error::NotDfu),
            Reply::Error(
                "write failed: Device not found: no DFU interface: is the device in U-Boot DFU mode?".to_owned()
            )
        );
    }
}
