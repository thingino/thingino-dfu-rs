//! The `--token` handshake.
//!
//! Three properties this module exists to guarantee, two of them things an earlier
//! implementation got wrong and the third the thing all that counting was for:
//!
//! * **Every rejection is logged, from one place.** That implementation logged auth
//!   failures nowhere, not even under `--debug`, so token brute-forcing over the browser
//!   transport left no trace at all. The C is only half guilty: it prints
//!   `Auth: rejected (wrong token)` on the raw path (`dfu-remote/main.c:880`) and prints
//!   **nothing** on the HTTP `403` (`:953-959`), which is the path a browser can hammer.
//!   [`Auth::check`] does the logging itself, so there is no caller left to forget it.
//! * **The comparison cannot be defeated by a transposition.** That implementation
//!   accumulated the per-byte differences with `^` instead of `|`, and every test differed
//!   in exactly one byte or in length, inputs for which the two operators agree, so the
//!   test suite could not fail. Two compensating differences separate them:
//!   under `^` the token `ba` authenticates against the secret `ab`.
//!   `a_transposed_token_is_refused` is that input.
//! * **A guess costs the guesser time.** Counting refusals is not limiting them: every
//!   rejection was answered at once, so an attacker on the network paid one connection
//!   per guess and could work through a word list in minutes. Each consecutive refusal
//!   from an address is now answered later than the last, up to [`MAX_PAUSE`].

use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::transport::Transport;

/// The delay after one consecutive refusal from an address, doubled for each further
/// one up to [`MAX_PAUSE`].
///
/// Small enough that an operator who mistypes a token once does not notice, and large
/// enough to matter: the daemon serves one client at a time, so a guess costs a whole
/// connection plus this, and the second guess from the same address costs twice as much.
const FIRST_PAUSE: Duration = Duration::from_millis(200);

/// The ceiling on that delay. Bounded, because the pause holds the daemon's one
/// connection slot: an unbounded backoff would hand an attacker a way to keep the
/// operator's own client out with nothing but wrong tokens.
const MAX_PAUSE: Duration = Duration::from_secs(2);

/// How many addresses the failure table remembers.
///
/// It is keyed by address and written by anyone who can connect, so it needs a bound.
/// When a new address arrives at a full table the whole table is dropped rather than
/// evicting one entry: no bookkeeping, and the worst it costs is that an attacker who
/// can spoof a thousand source addresses gets their backoff reset, which they could get
/// anyway by using a fresh address each time.
const TRACKED_ADDRESSES: usize = 1024;

/// The byte a missing position compares against.
///
/// Only the timing matters: a short token is refused by the length check whatever this
/// is, and the point of substituting *something* is that the loop keeps doing the same
/// work for a 1-byte guess as for a right-length one. The C substitutes `0xFF` at
/// `dfu-remote/main.c:877` for the same reason.
const ABSENT_BYTE: u8 = 0xFF;

/// Why a handshake was refused.
///
/// The wire is told less than the log is, on purpose: [`AuthReason::wire_message`]
/// collapses to the two frozen strings so a prober learns nothing from *which*
/// refusal it got, while the log keeps the distinction that makes an incident readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthReason {
    /// The `[magic][version]` prefix of the handshake was not ours.
    BadHandshake,
    /// No token was presented at all — an HTTP request with no `X-Auth-Token` header,
    /// or a handshake declaring `token_len = 0`.
    Missing,
    /// A token was presented and it is not the one.
    WrongToken,
}

impl AuthReason {
    /// What the peer is told.
    ///
    /// Bad magic **and** bad version both give the one string, unlike the command header
    /// where they are distinguished: `dfu-remote/main.c:860-863` tests both
    /// in a single `if` and sends `"auth: bad handshake"` for either.
    #[must_use]
    pub const fn wire_message(self) -> &'static str {
        match self {
            Self::BadHandshake => "auth: bad handshake",
            Self::Missing | Self::WrongToken => "auth: invalid token",
        }
    }
}

impl core::fmt::Display for AuthReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::BadHandshake => "the handshake magic or version was not ours",
            Self::Missing => "no token was presented",
            Self::WrongToken => "the token did not match",
        })
    }
}

/// What [`Auth::check`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthOutcome {
    /// The daemon was started without `--token`, so there is nothing to check and no
    /// handshake is expected. A client must not send one unsolicited: it
    /// would be parsed as a command header.
    NotRequired,
    /// The token matched.
    Accepted,
    /// It did not. The event has been logged.
    Rejected(AuthReason),
}

/// What one handshake came to.
///
/// Three, not two, because a peer that **went away** mid-handshake did not fail one.
/// The worked example of a cause thrown away is "a dropped connection was reported
/// as `Auth failed`", and counting a half-close as a refusal put it back inside the
/// module written against it: [`Auth::rejections`] is documented as "how many attempts
/// have been refused", and a flaky client inflated it while the log line stated a reason
/// that was false. The C prints `Auth: failed to read handshake` here
/// (`dfu-remote/main.c:854`) and does not treat it as a rejection either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthEventKind {
    /// The token matched.
    Accepted,
    /// A handshake arrived and was refused.
    Rejected(AuthReason),
    /// The peer half-closed part-way through the handshake, so there was nothing to
    /// judge. Logged at `debug` and counted apart from the refusals.
    Abandoned,
}

/// One handshake outcome, as a line.
///
/// A type rather than a `format!` at the call site so the *content* is testable: the
/// pin `an_auth_log_line_names_the_peer_and_never_the_token` is what keeps bug 22 dead
/// even if the subscriber changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEvent {
    /// Which transport it arrived on.
    pub transport: Transport,
    /// Who, if the socket could say.
    pub peer: Option<SocketAddr>,
    /// What happened.
    pub kind: AuthEventKind,
}

impl AuthEvent {
    /// The line that is logged.
    ///
    /// **Never contains the presented token**, not even a prefix of it: a log that
    /// records guesses is a log that leaks the secret to whoever reads it, and the
    /// near-misses are the half a brute-forcer would most like back.
    #[must_use]
    pub fn log_line(&self) -> String {
        let peer = self
            .peer
            .map_or_else(|| "unknown peer".to_owned(), |addr| addr.to_string());
        match self.kind {
            AuthEventKind::Rejected(reason) => format!("auth rejected: {peer} over {}: {reason}", self.transport),
            AuthEventKind::Accepted => format!("auth accepted: {peer} over {}", self.transport),
            AuthEventKind::Abandoned => format!(
                "auth abandoned: {peer} over {} stopped part-way through the handshake",
                self.transport
            ),
        }
    }
}

/// The daemon's token, or the absence of one.
///
/// The counters are atomics rather than `Cell`s so an `&Auth` is `Send + Sync` and the
/// accept loop may hand a connection to a spawned task. Decision D1's `?Send` rule is
/// about the USB transport traits; nothing about a token comparison needs to inherit it,
/// and a relaxed increment once per connection costs nothing.
#[derive(Debug, Default)]
pub struct Auth {
    token: Option<Vec<u8>>,
    accepted: AtomicU64,
    rejected: AtomicU64,
    abandoned: AtomicU64,
    /// Consecutive refusals per source address, which is what
    /// [`Auth::pause_after_rejection`] charges for. Cleared for an address that
    /// authenticates, so a legitimate client that mistyped once starts again from zero.
    failures: Mutex<HashMap<IpAddr, u32>>,
}

impl Auth {
    /// No `--token`: every client is served and no handshake is expected.
    #[must_use]
    pub fn open() -> Self {
        Self::default()
    }

    /// Require this token.
    ///
    /// Compared as **raw bytes**. The C copies the token into a `char[256]` and measures
    /// it with `strlen` (`dfu-remote/main.c:873`, `:949`), so an embedded NUL truncates
    /// both sides and `secret\0anything` authenticates against `secret`. Bytes have no
    /// such edge.
    #[must_use]
    pub fn with_token(token: impl Into<Vec<u8>>) -> Self {
        Self {
            token: Some(token.into()),
            ..Self::default()
        }
    }

    /// Did the daemon start with `--token`?
    ///
    /// Without one the daemon expects **no** handshake at all, so this is
    /// what decides whether [`Conn::accept`](crate::transport::Conn::accept) reads six
    /// bytes before the first command header.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.token.is_some()
    }

    /// How many attempts have been **refused** since startup.
    ///
    /// Exists so the guarantee in this module's header does not rest entirely on
    /// somebody having installed a `tracing` subscriber: the count is the daemon's own
    /// and survives a missing one.
    ///
    /// A peer that dropped the connection mid-handshake is [`Auth::abandons`], not this:
    /// it presented nothing to refuse, and folding the two together is how a flaky client
    /// turns the one number an incident is read from into noise.
    #[must_use]
    pub fn rejections(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// How many have been accepted.
    #[must_use]
    pub fn acceptances(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// How many peers went away part-way through a handshake.
    #[must_use]
    pub fn abandons(&self) -> u64 {
        self.abandoned.load(Ordering::Relaxed)
    }

    /// Check a presented token, log the outcome, and say what to do.
    ///
    /// `presented` is `None` when the peer offered nothing — an HTTP request with no
    /// `X-Auth-Token` header. That is refused with the same wire string as a wrong
    /// token, and recorded as the distinct thing it is.
    pub fn check(&self, presented: Option<&[u8]>, transport: Transport, peer: Option<SocketAddr>) -> AuthOutcome {
        let Some(expected) = self.token.as_deref() else {
            return AuthOutcome::NotRequired;
        };
        let outcome = match presented {
            None => AuthOutcome::Rejected(AuthReason::Missing),
            Some(presented) if tokens_match(presented, expected) => AuthOutcome::Accepted,
            Some(_) => AuthOutcome::Rejected(AuthReason::WrongToken),
        };
        self.record(transport, peer, kind_of(outcome));
        outcome
    }

    /// Refuse an attempt whose failure was decided before a token was even read — a
    /// handshake prefix that was not ours — so that it is counted and logged like any
    /// other.
    pub fn reject(&self, reason: AuthReason, transport: Transport, peer: Option<SocketAddr>) -> AuthOutcome {
        self.record(transport, peer, AuthEventKind::Rejected(reason));
        AuthOutcome::Rejected(reason)
    }

    /// Record a peer that stopped part-way through the handshake.
    ///
    /// **Not a rejection.** Nothing was presented, so there is nothing to have refused;
    /// the caller's [`DaemonError::Truncated`](crate::transport::DaemonError::Truncated)
    /// already names the byte counts and is the whole account of what happened. This is
    /// here so the event is still *counted*, at `debug` and in its own number.
    pub fn abandoned(&self, transport: Transport, peer: Option<SocketAddr>) {
        self.record(transport, peer, AuthEventKind::Abandoned);
    }

    /// Wait out what this address has earned, before it is told anything.
    ///
    /// **Counting refusals is not limiting them.** The counters above make a brute-force
    /// attempt *visible*; nothing made it *expensive*, and a rejected handshake cost the
    /// attacker one connection, which on a LAN is hundreds of guesses a second against a
    /// token the README's own example wrote as a dictionary word.
    ///
    /// The delay grows per consecutive failure from the same address and is bounded by
    /// [`MAX_PAUSE`], because the daemon serves one client at a time and the pause holds
    /// that slot: an unbounded backoff would let wrong tokens keep the operator's own
    /// client out. It is charged **before** the refusal is written, so the answer itself
    /// is what is late; a caller cannot skip it by hanging up, because the connection is
    /// finished either way.
    pub async fn pause_after_rejection(&self, peer: Option<SocketAddr>) {
        let pause = self.pause_for(peer);
        if pause > Duration::ZERO {
            tokio::time::sleep(pause).await;
        }
    }

    /// What [`Auth::pause_after_rejection`] is about to wait, so the rule is testable
    /// without a clock.
    #[must_use]
    pub fn pause_for(&self, peer: Option<SocketAddr>) -> Duration {
        let consecutive = peer.map_or(1, |peer| {
            self.failures
                .lock()
                .map_or(1, |failures| failures.get(&peer.ip()).copied().unwrap_or(1))
        });
        pause_of(consecutive)
    }

    /// Note a refusal from this address, or forget the address on an acceptance.
    fn score(&self, peer: Option<SocketAddr>, kind: AuthEventKind) {
        let Some(address) = peer.map(|peer| peer.ip()) else {
            return;
        };
        let Ok(mut failures) = self.failures.lock() else {
            // A poisoned lock means a panic inside this map, not a reason to stop
            // serving; the pause then falls back to its first step, which is the
            // behaviour of a fresh address.
            return;
        };
        match kind {
            AuthEventKind::Rejected(_) => {
                if failures.len() >= TRACKED_ADDRESSES && !failures.contains_key(&address) {
                    failures.clear();
                }
                let seen = failures.entry(address).or_insert(0);
                *seen = seen.saturating_add(1);
            }
            // A client that authenticates has said it is not guessing.
            AuthEventKind::Accepted => {
                failures.remove(&address);
            }
            AuthEventKind::Abandoned => {}
        }
    }

    /// The one place an auth event becomes a log line and a number.
    fn record(&self, transport: Transport, peer: Option<SocketAddr>, kind: AuthEventKind) {
        let event = AuthEvent { transport, peer, kind };
        self.score(peer, kind);
        match kind {
            AuthEventKind::Rejected(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("{}", event.log_line());
            }
            AuthEventKind::Accepted => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("{}", event.log_line());
            }
            AuthEventKind::Abandoned => {
                self.abandoned.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("{}", event.log_line());
            }
        }
    }

    /// Validate the fixed part of a raw/WebSocket handshake: `[4:magic][1:version][1:len]`
    /// Returns how many token bytes follow.
    ///
    /// Pure, so the refusal is testable without a socket.
    ///
    /// # Errors
    /// [`AuthReason::BadHandshake`] if the magic or the version is not ours.
    pub fn parse_handshake_prefix(prefix: &[u8; 6]) -> Result<u8, AuthReason> {
        let mut magic = [0_u8; 4];
        magic.copy_from_slice(&prefix[0..4]);
        if u32::from_be_bytes(magic) != tdfu_proto::MAGIC || prefix[4] != tdfu_proto::VERSION {
            return Err(AuthReason::BadHandshake);
        }
        Ok(prefix[5])
    }
}

/// The delay owed after `consecutive` refusals from one address: the first step doubled
/// per further failure, and never past [`MAX_PAUSE`].
///
/// Saturating rather than shifting: 32 consecutive failures would otherwise overflow the
/// shift and hand the attacker a zero.
fn pause_of(consecutive: u32) -> Duration {
    let doublings = consecutive.saturating_sub(1).min(16);
    let scaled = FIRST_PAUSE.saturating_mul(1_u32.checked_shl(doublings).unwrap_or(u32::MAX));
    scaled.min(MAX_PAUSE)
}

/// What [`Auth::check`]'s answer is recorded as. `NotRequired` never reaches here.
const fn kind_of(outcome: AuthOutcome) -> AuthEventKind {
    match outcome {
        AuthOutcome::Rejected(reason) => AuthEventKind::Rejected(reason),
        AuthOutcome::Accepted | AuthOutcome::NotRequired => AuthEventKind::Accepted,
    }
}

/// Constant-time token equality.
///
/// **Accumulate with `|`, never `^`.** The loop folds each byte's difference into one
/// accumulator; under `|` any single difference survives to the end, under `^` a second
/// difference can cancel the first. An earlier implementation shipped `^` and no test
/// could tell, because every case it tried differed in exactly one byte or in length and
/// for those the operators agree.
///
/// The trip count is `expected.len()`, the daemon's own secret, fixed for the process,
/// so a guess of any length costs the same. The length comparison is kept out of the
/// accumulator and combined with `&` rather than `&&`, so neither half short-circuits.
#[must_use]
fn tokens_match(presented: &[u8], expected: &[u8]) -> bool {
    let mut difference: u8 = 0;
    for (index, expected_byte) in expected.iter().enumerate() {
        let presented_byte = presented.get(index).copied().unwrap_or(ABSENT_BYTE);
        difference |= presented_byte ^ expected_byte;
    }
    // Keeps the accumulator opaque to a compiler that would otherwise be free to bail
    // out of the loop the moment `difference` is non-zero.
    let difference = core::hint::black_box(difference);
    let bytes_agree = difference == 0;
    let lengths_agree = presented.len() == expected.len();
    bytes_agree & lengths_agree
}

#[cfg(test)]
mod tests {
    use super::{
        Auth, AuthEvent, AuthEventKind, AuthOutcome, AuthReason, FIRST_PAUSE, MAX_PAUSE, TRACKED_ADDRESSES, pause_of,
        tokens_match,
    };
    use crate::transport::Transport;
    use core::net::SocketAddr;

    fn peer() -> Option<SocketAddr> {
        "127.0.0.1:41234".parse().ok()
    }

    /// **The test an earlier implementation could not write.** `ba` against the secret
    /// `ab` produces two per-byte differences of 0x03; `|` keeps them, `^` cancels them,
    /// and under `^` this token authenticates. Mutating the accumulator in `tokens_match`
    /// must fail here.
    #[test]
    fn a_transposed_token_is_refused() {
        assert!(!tokens_match(b"ba", b"ab"));
        assert!(!tokens_match(b"ab", b"ba"));

        // A longer, more realistic transposition: two bytes swapped inside a real token.
        assert!(!tokens_match(b"9f4c2a1d3b57", b"9f4c2a1d3b75"));

        // And through the public surface, so the pin survives a refactor of the helper.
        let auth = Auth::with_token("ab");
        assert_eq!(
            auth.check(Some(b"ba"), Transport::Raw, peer()),
            AuthOutcome::Rejected(AuthReason::WrongToken)
        );
    }

    /// Every other separation the accumulator has to keep: same length wrong bytes, a
    /// prefix, a superstring, empty, and the one that must pass.
    #[test]
    fn the_comparison_separates_every_near_miss() {
        assert!(tokens_match(b"s3cr3t-token", b"s3cr3t-token"), "the right one");
        assert!(tokens_match(b"", b""), "an empty secret matches an empty token");

        assert!(!tokens_match(b"s3cr3t-tokeN", b"s3cr3t-token"), "one byte");
        assert!(!tokens_match(b"s3cr3t-toke", b"s3cr3t-token"), "a prefix");
        assert!(!tokens_match(b"s3cr3t-token!", b"s3cr3t-token"), "a superstring");
        assert!(!tokens_match(b"", b"s3cr3t-token"), "nothing at all");
        assert!(!tokens_match(b"s3cr3t-token", b""), "everything against nothing");
        // Not `strlen`: the C's `char[256]` + `strlen` pair would accept this one.
        assert!(!tokens_match(b"s3cr3t\0junk", b"s3cr3t"), "an embedded NUL is a byte");
    }

    /// The length check must not be folded into the accumulator, and must not be
    /// replaced by an `or`: a right-length wrong-byte token would then authenticate.
    #[test]
    fn length_and_content_are_both_required() {
        assert!(!tokens_match(b"aaaa", b"bbbb"), "right length, wrong bytes");
        assert!(!tokens_match(b"aaa", b"aaaa"), "right bytes, wrong length");
    }

    /// The count is the daemon's own, so the guarantee does
    /// not rest on a `tracing` subscriber having been installed.
    #[test]
    fn every_rejection_is_counted() {
        let auth = Auth::with_token("secret");
        assert_eq!(auth.rejections(), 0);
        assert_eq!(auth.acceptances(), 0);

        for guess in [&b"a"[..], b"secre", b"secret!", b"SECRET"] {
            assert!(matches!(
                auth.check(Some(guess), Transport::Http, peer()),
                AuthOutcome::Rejected(AuthReason::WrongToken)
            ));
        }
        assert_eq!(auth.rejections(), 4, "four guesses, four records");

        assert_eq!(
            auth.check(None, Transport::Http, peer()),
            AuthOutcome::Rejected(AuthReason::Missing)
        );
        assert_eq!(auth.rejections(), 5, "a missing header is an attempt too");

        assert_eq!(
            auth.check(Some(b"secret"), Transport::Raw, peer()),
            AuthOutcome::Accepted
        );
        assert_eq!(auth.acceptances(), 1);
        assert_eq!(auth.rejections(), 5, "an acceptance is not a rejection");

        // A prefix refused before any token was read counts the same.
        assert_eq!(
            auth.reject(AuthReason::BadHandshake, Transport::WebSocket, peer()),
            AuthOutcome::Rejected(AuthReason::BadHandshake)
        );
        assert_eq!(auth.rejections(), 6);
    }

    #[test]
    fn an_auth_log_line_names_the_peer_and_never_the_token() {
        let event = AuthEvent {
            transport: Transport::Http,
            peer: peer(),
            kind: AuthEventKind::Rejected(AuthReason::WrongToken),
        };
        let line = event.log_line();
        assert!(line.contains("127.0.0.1:41234"), "{line}");
        assert!(line.contains("http"), "{line}");
        assert!(line.contains("the token did not match"), "{line}");

        let accepted = AuthEvent {
            transport: Transport::Raw,
            peer: None,
            kind: AuthEventKind::Accepted,
        };
        assert_eq!(accepted.log_line(), "auth accepted: unknown peer over raw");

        // The third line says the peer stopped, not that it was refused.
        let abandoned = AuthEvent {
            transport: Transport::WebSocket,
            peer: peer(),
            kind: AuthEventKind::Abandoned,
        };
        let line = abandoned.log_line();
        assert!(line.starts_with("auth abandoned: "), "{line}");
        assert!(!line.contains("rejected"), "{line}");
        assert!(line.contains("websocket"), "{line}");
    }

    /// A peer that goes away mid-handshake is counted apart from the
    /// peers that were refused, so `rejections()` still means "refused attempts".
    #[test]
    fn an_abandoned_handshake_is_not_a_rejection() {
        let auth = Auth::with_token("secret");
        auth.abandoned(Transport::Raw, peer());
        auth.abandoned(Transport::WebSocket, None);
        assert_eq!(auth.rejections(), 0, "nothing was presented, so nothing was refused");
        assert_eq!(auth.acceptances(), 0);
        assert_eq!(auth.abandons(), 2);

        // And a real refusal still lands in the number it always did.
        assert_eq!(
            auth.check(Some(b"wrong"), Transport::Raw, peer()),
            AuthOutcome::Rejected(AuthReason::WrongToken)
        );
        assert_eq!(auth.rejections(), 1);
        assert_eq!(auth.abandons(), 2, "a refusal is not an abandonment either");
    }

    /// Without `--token` there is nothing to check and no handshake is
    /// expected.
    #[test]
    fn an_open_daemon_checks_nothing() {
        let auth = Auth::open();
        assert!(!auth.is_required());
        assert_eq!(auth.check(None, Transport::Raw, None), AuthOutcome::NotRequired);
        assert_eq!(
            auth.check(Some(b"anything at all"), Transport::Raw, None),
            AuthOutcome::NotRequired
        );
        assert_eq!(auth.rejections(), 0);
        assert_eq!(auth.acceptances(), 0, "there was nothing to accept");

        assert!(Auth::with_token("x").is_required());
    }

    /// `dfu-remote/main.c:860-863`: bad magic and bad version give the one
    /// string, unlike the command header.
    #[test]
    fn rpc_auth_handshake_prefix() -> Result<(), AuthReason> {
        let mut prefix = [0_u8; 6];
        prefix[0..4].copy_from_slice(&tdfu_proto::MAGIC.to_be_bytes());
        prefix[4] = tdfu_proto::VERSION;
        prefix[5] = 12;
        assert_eq!(Auth::parse_handshake_prefix(&prefix)?, 12);

        let mut bad_magic = prefix;
        bad_magic[0] = b'X';
        assert_eq!(Auth::parse_handshake_prefix(&bad_magic), Err(AuthReason::BadHandshake));

        let mut bad_version = prefix;
        bad_version[4] = 2;
        assert_eq!(
            Auth::parse_handshake_prefix(&bad_version),
            Err(AuthReason::BadHandshake)
        );

        assert_eq!(AuthReason::BadHandshake.wire_message(), "auth: bad handshake");
        assert_eq!(AuthReason::WrongToken.wire_message(), "auth: invalid token");
        assert_eq!(
            AuthReason::Missing.wire_message(),
            "auth: invalid token",
            "a prober must not learn which refusal it got"
        );
        Ok(())
    }

    /// **Guesses get slower.** The counters made brute force visible; this is what makes
    /// it expensive. Consecutive refusals from one address are answered later each time,
    /// another address is unaffected, and an acceptance clears the score.
    #[test]
    fn consecutive_guesses_from_one_address_are_answered_later_each_time() {
        let auth = Auth::with_token("secret");
        let guesser: Option<SocketAddr> = "192.0.2.7:41234".parse().ok();
        let elsewhere: Option<SocketAddr> = "192.0.2.8:41234".parse().ok();

        let mut waits = Vec::new();
        for _ in 0..4 {
            assert!(matches!(
                auth.check(Some(b"wrong"), Transport::Http, guesser),
                AuthOutcome::Rejected(_)
            ));
            waits.push(auth.pause_for(guesser));
        }
        assert_eq!(waits.first(), Some(&FIRST_PAUSE), "{waits:?}");
        for pair in waits.windows(2) {
            let (before, after) = (pair[0], pair[1]);
            assert!(after > before, "the delay did not grow: {waits:?}");
        }

        // Another address has guessed nothing and waits the first step, not the fourth.
        assert_eq!(auth.pause_for(elsewhere), FIRST_PAUSE);

        // And the right token clears the score, so an operator who mistyped once is not
        // punished for the rest of the daemon's life.
        assert_eq!(
            auth.check(Some(b"secret"), Transport::Http, guesser),
            AuthOutcome::Accepted
        );
        assert_eq!(auth.pause_for(guesser), FIRST_PAUSE, "an acceptance forgets");
    }

    /// Bounded, because the pause holds the daemon's one connection slot: an unbounded
    /// backoff is a way to keep the operator's own client out with wrong tokens.
    #[test]
    fn the_delay_doubles_and_stops_at_the_ceiling() {
        assert_eq!(pause_of(0), FIRST_PAUSE, "a fresh address still waits");
        assert_eq!(pause_of(1), FIRST_PAUSE);
        assert_eq!(pause_of(2), FIRST_PAUSE * 2);
        assert_eq!(pause_of(3), FIRST_PAUSE * 4);
        assert_eq!(pause_of(50), MAX_PAUSE, "capped");
        // The shift is saturating: 32 doublings would overflow and hand back a zero,
        // which is the one answer this must never give.
        assert_eq!(pause_of(u32::MAX), MAX_PAUSE);
        assert!(MAX_PAUSE >= FIRST_PAUSE);
    }

    /// The failure table is written by anyone who can connect, so it is bounded.
    #[test]
    fn the_failure_table_does_not_grow_without_bound() {
        let auth = Auth::with_token("secret");
        for index in 0..(TRACKED_ADDRESSES + 10) {
            let octets = u32::try_from(index).unwrap_or(0).to_be_bytes();
            let address = SocketAddr::from((core::net::Ipv4Addr::from(octets), 4444));
            let _refused = auth.check(Some(b"wrong"), Transport::Raw, Some(address));
        }
        let held = auth.failures.lock().map_or(usize::MAX, |failures| failures.len());
        assert!(held <= TRACKED_ADDRESSES, "{held} addresses remembered");
        let counted = u64::try_from(TRACKED_ADDRESSES.saturating_add(10)).unwrap_or(u64::MAX);
        assert_eq!(auth.rejections(), counted, "all counted");
    }

    /// The pause really is awaited, and it is the value the rule computed.
    #[tokio::test]
    async fn the_pause_is_actually_waited_out() {
        let auth = Auth::with_token("secret");
        let peer: Option<SocketAddr> = "192.0.2.9:5000".parse().ok();
        let _refused = auth.check(Some(b"wrong"), Transport::Raw, peer);
        let started = std::time::Instant::now();
        auth.pause_after_rejection(peer).await;
        assert!(started.elapsed() >= FIRST_PAUSE, "{:?}", started.elapsed());
    }

    /// A zero-length token field is a presented token of zero bytes, not an absent one,
    /// and it is wrong unless the secret is empty too.
    #[test]
    fn a_zero_length_token_field_is_a_wrong_token() {
        let auth = Auth::with_token("secret");
        assert_eq!(
            auth.check(Some(b""), Transport::Raw, None),
            AuthOutcome::Rejected(AuthReason::WrongToken)
        );
    }
}
