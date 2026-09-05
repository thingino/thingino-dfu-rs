//! The HTTP POST transport and the CORS preflight.
//!
//! This is the browser flasher's path, and it exists because Chrome's Local Network
//! Access exempts `fetch({targetAddressSpace: 'local'})` from mixed-content blocking
//! while WebSocket is not exempt (`dfu-remote/main.c:75-80`). One command per POST
//! and the reply is a chunked body carrying the TDFU response stream.
//!
//! **Every response carries the CORS headers, including the refusals.** The C's `413`
//! sends `Content-Length: 0` and nothing else (`dfu-remote/main.c:934`) while its `403`
//! sends `Access-Control-Allow-Origin` and `Access-Control-Allow-Private-Network`
//! (`:954-955`) — so a browser that oversteps the payload cap sees an opaque network
//! failure with no status it is allowed to read, instead of the refusal. It has been
//! fixed once already; it stays fixed.
//!
//! **What those headers say is decided by [`Origins`], not by a constant.** An allowed
//! origin is echoed and a refused one gets a `403` carrying no allow header at all; `*`
//! is for a request that carried no `Origin`, which is every non-browser client.
//!
//! **The token is checked from the header block, before the body is read.** The order
//! matters more than the reset it costs: the daemon serves one client at a time, the
//! read deadline is a no-progress bound rather than a bound on a transfer, and a peer
//! that announces 64 MiB and then sends one byte per deadline holds the listener for as
//! long as it likes without ever presenting a token. The body of a peer that did present
//! one is bounded end to end by [`body_budget`].

use core::time::Duration;

use tdfu_proto::{HEADER_LEN, exceeds_payload_cap};

use super::error::{DaemonError, Transport};
use super::origin::{Decision, Origins};
use super::wire::{Deadlines, Filled, Wire};
use super::ws::{header_value, request_line};
use crate::auth::{Auth, AuthOutcome};

/// The cap on the request's header block. The C uses `char req[8192]`
/// (`dfu-remote/main.c:906`).
const HEADER_LIMIT: usize = 8192;

/// How much body one second of the whole-transfer budget buys.
///
/// 64 KiB/s is slower than any link a firmware image is pushed over, so the budget cuts
/// off nothing that was making progress; it exists so that *some* finite number bounds
/// one request, which a per-read no-progress deadline does not.
const BUDGET_BYTES_PER_SECOND: u64 = 64 * 1024;

/// The whole-transfer deadline for a body of `length` bytes.
///
/// The no-progress bound is the floor, so a small body still gets the grace a stalled
/// read gets, and every [`BUDGET_BYTES_PER_SECOND`] adds a second on top: 64 MiB, the
/// cap, comes to about eighteen minutes with the shipped 60 s read deadline.
///
/// `None` when the read deadline is off, because `--read-timeout 0` is an operator
/// asking for the C's posture back and this is one of the deadlines they are switching
/// off.
fn body_budget(read: Option<Duration>, length: u64) -> Option<Duration> {
    read.map(|floor| floor.saturating_add(Duration::from_secs(length.div_ceil(BUDGET_BYTES_PER_SECOND))))
}

/// The `Access-Control-*` headers for a decided request.
///
/// `Vary: Origin` because the answer now depends on the request's `Origin`, and a cache
/// that did not know that could hand one origin's allow header to another.
fn cors(decision: &Decision) -> String {
    let allow = decision.allow_header().unwrap_or("");
    format!(
        "Access-Control-Allow-Origin: {allow}\r\n\
         Vary: Origin\r\n\
         Access-Control-Allow-Private-Network: true\r\n"
    )
}

/// The preflight, `dfu-remote/ws.c:232-239`, with the allow header naming whoever asked.
fn preflight_for(decision: &Decision) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         {headers}\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, X-Auth-Token\r\n\
         Access-Control-Max-Age: 600\r\n\
         Content-Length: 0\r\n\
         \r\n",
        headers = cors(decision)
    )
}

/// The response headers a served POST opens with, `dfu-remote/main.c:962-968`.
fn preamble_for(decision: &Decision) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n\
         {headers}\
         Content-Type: application/octet-stream\r\n\
         Cache-Control: no-store\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n",
        headers = cors(decision)
    )
}

/// One POST, its body already read, its reply streaming as chunks.
#[derive(Debug)]
pub struct HttpConn {
    wire: Wire,
    body: Vec<u8>,
    at: usize,
    finished: bool,
    /// Which command is being served. See [`RawConn::current`](super::RawConn::current)
    /// for why this lives in the connection and not in a global.
    pub(super) current: Option<tdfu_proto::Command>,
}

impl HttpConn {
    /// Answer a CORS / Local Network Access preflight and close.
    ///
    /// A preflight from an origin that is not allowed is refused here rather than
    /// answered `200` without the allow headers: both stop the browser from sending the
    /// POST, and only one of them says why in the daemon's log.
    pub(super) async fn preflight(wire: &mut Wire, origins: &Origins) -> Result<(), DaemonError> {
        let handshake = wire.timeouts().handshake;
        // Drain the request so the response is not written into a peer still sending.
        let block = wire.read_header_block(HEADER_LIMIT, handshake).await?;
        let decision = origins.decide(header_value(&block, "origin").as_deref());
        if !decision.is_allowed() {
            return refuse_origin(wire, &decision).await;
        }
        wire.write_all(preflight_for(&decision).as_bytes()).await
    }

    /// Read one POST: headers, the origin, the token, the `Content-Length` body, then
    /// the preamble.
    ///
    /// # Errors
    /// Every refusal is written to the peer with the CORS headers before it is returned.
    pub(super) async fn accept(mut wire: Wire, auth: &Auth, origins: &Origins) -> Result<Self, DaemonError> {
        let handshake = wire.timeouts().handshake;
        let block = wire.read_header_block(HEADER_LIMIT, handshake).await?;

        let Some((method, _)) = request_line(&block) else {
            return refuse(
                &mut wire,
                &Decision::Absent,
                "400 Bad Request",
                "the request line did not parse",
            )
            .await;
        };
        if !method.eq_ignore_ascii_case("POST") {
            // The C sniffs only the first byte, so `PUT` and `PATCH` are parsed as POSTs
            // (`dfu-remote/main.c:1148`). Saying so costs one status line.
            return refuse(
                &mut wire,
                &Decision::Absent,
                "405 Method Not Allowed",
                "only POST carries a command",
            )
            .await;
        }

        // The origin first, then the token: a page that may not talk to this daemon must
        // not be able to learn whether a token guess was right either.
        let decision = origins.decide(header_value(&block, "origin").as_deref());
        if !decision.is_allowed() {
            refuse_origin(&mut wire, &decision).await?;
            return Err(DaemonError::Http("the Origin is not on the allow list"));
        }

        // **Before the body.** A wrong token here costs the peer its `403` if it is still
        // sending, because the reply arrives on a socket with a body in flight; reading
        // the body first costs the daemon its listener, for as long as an unauthenticated
        // peer cares to dribble.
        let presented = header_value(&block, "x-auth-token");
        let peer = wire.peer();
        if let AuthOutcome::Rejected(reason) =
            auth.check(presented.as_deref().map(str::as_bytes), Transport::Http, peer)
        {
            auth.pause_after_rejection(peer).await;
            let _sent = refusal(&mut wire, &decision, "403 Forbidden").await;
            return Err(DaemonError::AuthRejected {
                transport: Transport::Http,
                reason,
            });
        }

        let length = match content_length(&block) {
            Ok(length) => length,
            Err(why) => return refuse(&mut wire, &decision, "400 Bad Request", why).await,
        };
        let Some(length) = length else {
            return refuse(&mut wire, &decision, "411 Length Required", "no Content-Length header").await;
        };
        let within_cap = u32::try_from(length).is_ok_and(|len| !exceeds_payload_cap(len));
        if !within_cap {
            return refuse(
                &mut wire,
                &decision,
                "413 Payload Too Large",
                "Content-Length is over the cap",
            )
            .await;
        }
        if length < HEADER_LEN as u64 {
            // Refused *before* the `200` preamble, and this is the point of doing it here.
            // A POST carries exactly one command; a body too short to hold even a
            // header carries none, and once the preamble is out the only ways left to say
            // so are a `200` whose chunked body never terminates, or a well-formed empty
            // reply that claims nothing went wrong. The C takes the first: it writes the
            // preamble (`dfu-remote/main.c:969`), `process_one_command` fails to read a
            // header out of the empty buffer and returns -2 (`:814`), and the client is
            // handed a `200 OK` carrying no response frame at all.
            return refuse(
                &mut wire,
                &decision,
                "400 Bad Request",
                "the body is too short to hold a command frame",
            )
            .await;
        }

        // Under a bound on the **whole** body, not only on each read of it: the C's
        // `dfu-remote` has neither, and a per-read deadline alone lets an announced
        // 64 MiB take a byte per deadline for ever.
        let mut body = vec![0_u8; usize::try_from(length).unwrap_or(0)];
        let per_read = Deadlines::uniform(wire.timeouts().read);
        let budget = body_budget(wire.timeouts().read, length);
        let reading = wire.read_all_of(&mut body, per_read, "request body");
        match budget {
            Some(budget) => match tokio::time::timeout(budget, reading).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(DaemonError::TimedOut {
                        doing: "request body",
                        after: budget,
                    });
                }
            },
            None => reading.await?,
        }

        wire.write_all(preamble_for(&decision).as_bytes()).await?;
        Ok(Self {
            wire,
            body,
            at: 0,
            finished: false,
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

    /// Take bytes from the buffered body. Never touches the socket, because the
    /// body holds exactly one command, so running out is the end of the request.
    pub(super) fn read_exact(&mut self, buf: &mut [u8], _deadlines: Deadlines) -> Filled {
        let available = self.body.len().saturating_sub(self.at);
        let take = available.min(buf.len());
        if let (Some(target), Some(source)) = (buf.get_mut(..take), self.body.get(self.at..self.at + take)) {
            target.copy_from_slice(source);
        }
        self.at += take;
        if take == buf.len() {
            Filled::Whole
        } else {
            Filled::Eof(take)
        }
    }

    /// Has this POST no more commands to serve?
    ///
    /// True once the body is consumed **or** the final frame has gone out. The second
    /// half matters: an unknown command is refused and reading continues, and on a
    /// transport where the refusal is also the final response "keep reading"
    /// has to stop here. Without it a body holding an unknown command *and* trailing bytes
    /// would be answered, terminated, and then read from again.
    pub(super) const fn spent(&self) -> bool {
        self.finished || self.at >= self.body.len()
    }

    /// One chunk carrying `parts` end to end.
    ///
    /// The C emits a chunk per `net_send_all`, so every response frame becomes two
    /// (`dfu-remote/main.c:131-140` under `:164-169`). One is enough.
    pub(super) async fn send_message(&mut self, parts: &[&[u8]]) -> Result<(), DaemonError> {
        if self.finished {
            return Err(DaemonError::AlreadyFinished);
        }
        let len: usize = parts.iter().map(|part| part.len()).sum();
        if len == 0 {
            // A zero-length chunk *is* the terminator (RFC 7230 §4.1), so writing one
            // here would end the body early and the client would read the rest of the
            // response as a new one. Unreachable, since every frame carries a 10-byte
            // header, and checked rather than assumed, because the invariant is not
            // local to this function.
            return Err(DaemonError::Http("a response frame cannot be empty"));
        }
        self.wire.write_all(format!("{len:x}\r\n").as_bytes()).await?;
        for part in parts {
            if !part.is_empty() {
                self.wire.write_all(part).await?;
            }
        }
        self.wire.write_all(b"\r\n").await
    }

    /// The terminating chunk (`dfu-remote/main.c:983`).
    ///
    /// Sent by `respond`, because an HTTP connection gets exactly one final
    /// frame. A dispatch that fails *without* responding leaves the chunked body
    /// unterminated, which is the correct signal to the client that the reply is
    /// incomplete — not something to paper over with a well-formed empty ending.
    pub(super) async fn finish(&mut self) -> Result<(), DaemonError> {
        if self.finished {
            return Err(DaemonError::AlreadyFinished);
        }
        self.finished = true;
        self.wire.write_all(b"0\r\n\r\n").await
    }
}

/// Write a refusal — always with the CORS headers — and turn it into an error.
async fn refuse<T>(wire: &mut Wire, decision: &Decision, status: &str, why: &'static str) -> Result<T, DaemonError> {
    refusal(wire, decision, status).await?;
    Err(DaemonError::Http(why))
}

/// The refusal bytes. Separated so the auth path — and the WebSocket upgrade, which is an
/// HTTP request until it is not — can send one and return its own error.
pub(super) async fn refusal(wire: &mut Wire, decision: &Decision, status: &str) -> Result<(), DaemonError> {
    let response = format!("HTTP/1.1 {status}\r\n{}Content-Length: 0\r\n\r\n", cors(decision));
    wire.write_all(response.as_bytes()).await
}

/// Refuse a page that is not on the allow list: `403`, no allow header, and **one** log
/// line naming the origin, so a misconfigured deployment is diagnosable and a page
/// probing in a loop cannot write more than a line per connection.
pub(super) async fn refuse_origin(wire: &mut Wire, decision: &Decision) -> Result<(), DaemonError> {
    let peer = wire
        .peer()
        .map_or_else(|| "unknown peer".to_owned(), |addr| addr.to_string());
    tracing::warn!(
        "refused {peer}: Origin {:?} is not allowed; --allow-origin adds one",
        decision.origin().unwrap_or_default()
    );
    refusal(wire, decision, "403 Forbidden").await
}

/// `Ok(None)` when the header is absent, `Err` when it is present and unusable.
///
/// The C uses `atol` (`dfu-remote/main.c:922`), which answers 0 for `abc` and for a
/// missing header alike, and silently truncates a value past `LONG_MAX`. All three are
/// refusals here: the same reasoning that refuses a nonsense `-p`, applied to a
/// header instead of an argument.
fn content_length(block: &[u8]) -> Result<Option<u64>, &'static str> {
    let text = core::str::from_utf8(block).map_err(|_| "the headers are not UTF-8")?;
    let mut found: Option<u64> = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let parsed = value
            .trim()
            .parse::<u64>()
            .map_err(|_| "Content-Length is not a number")?;
        // RFC 7230 §3.3.2: two different lengths is a request-smuggling shape, not a
        // request. The C reads whichever comes last and asks no questions.
        if found.is_some_and(|first| first != parsed) {
            return Err("two different Content-Length headers");
        }
        found = Some(parsed);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{Decision, body_budget, content_length, cors, preamble_for, preflight_for};

    /// The preflight, `dfu-remote/ws.c:232-239`.
    #[test]
    fn rpc_preflight_headers() {
        let preflight = preflight_for(&Decision::Absent);
        for header in [
            "HTTP/1.1 200 OK\r\n",
            "Access-Control-Allow-Origin: *\r\n",
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n",
            "Access-Control-Allow-Headers: Content-Type, X-Auth-Token\r\n",
            "Access-Control-Allow-Private-Network: true\r\n",
            "Access-Control-Max-Age: 600\r\n",
            "Content-Length: 0\r\n",
        ] {
            assert!(preflight.contains(header), "missing {header:?}");
        }
        assert!(preflight.ends_with("\r\n\r\n"));

        // And for a browser, the origin that asked, never `*`.
        let named = preflight_for(&Decision::Allowed("https://webflash.thingino.com".to_owned()));
        assert!(
            named.contains("Access-Control-Allow-Origin: https://webflash.thingino.com\r\n"),
            "{named}"
        );
        assert!(!named.contains("Allow-Origin: *"), "{named}");
    }

    /// The five response headers, `dfu-remote/main.c:962-968`.
    #[test]
    fn rpc_http_post_preamble() {
        let preamble = preamble_for(&Decision::Absent);
        for header in [
            "Access-Control-Allow-Origin: *\r\n",
            "Access-Control-Allow-Private-Network: true\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Cache-Control: no-store\r\n",
            "Transfer-Encoding: chunked\r\n",
        ] {
            assert!(preamble.contains(header), "missing {header:?}");
        }
        assert!(
            !preamble.contains("Content-Length"),
            "chunked and Content-Length are exclusive"
        );
    }

    /// The C's 413 carries no CORS header at all while its 403 does
    /// (`dfu-remote/main.c:934` vs `:954-955`). Both blocks come from one function here,
    /// so they cannot drift apart again.
    #[test]
    fn rpc_http_refusals_carry_the_cors_headers() {
        let headers = cors(&Decision::Absent);
        assert!(headers.contains("Access-Control-Allow-Origin: *"));
        assert!(headers.contains("Access-Control-Allow-Private-Network: true"));
        for status in [
            "400 Bad Request",
            "403 Forbidden",
            "405 Method Not Allowed",
            "411 Length Required",
            "413 Payload Too Large",
        ] {
            let response = format!("HTTP/1.1 {status}\r\n{headers}Content-Length: 0\r\n\r\n");
            assert!(response.contains("Access-Control-Allow-Origin: *"), "{status}");
            assert!(
                response.contains("Access-Control-Allow-Private-Network: true"),
                "{status}"
            );
        }
    }

    /// An answer that depends on the request's `Origin` has to say so, or a cache in
    /// front of it can hand one origin's allow header to another.
    #[test]
    fn every_answer_varies_on_the_origin_and_a_refusal_allows_nobody() {
        for decision in [
            Decision::Absent,
            Decision::Allowed("http://localhost:5173".to_owned()),
            Decision::Refused("https://evil.example".to_owned()),
        ] {
            assert!(cors(&decision).contains("Vary: Origin\r\n"), "{decision:?}");
        }
        let refused = cors(&Decision::Refused("https://evil.example".to_owned()));
        assert!(refused.contains("Access-Control-Allow-Origin: \r\n"), "{refused}");
        assert!(!refused.contains("evil.example"), "{refused}");
    }

    /// The budget is finite, generous, and off only when the read deadline is.
    #[test]
    fn the_body_budget_is_finite_and_grows_with_the_body() {
        let read = Some(Duration::from_secs(60));
        assert_eq!(body_budget(read, 0), Some(Duration::from_secs(60)), "the floor");
        assert_eq!(
            body_budget(read, 64 * 1024),
            Some(Duration::from_secs(61)),
            "a second per 64 KiB"
        );
        // The cap, 64 MiB: about eighteen minutes, which no working transfer reaches
        // and no stalled one outlives.
        let at_cap = body_budget(read, 64 * 1024 * 1024).unwrap_or_default();
        assert!(
            at_cap > Duration::from_secs(900) && at_cap < Duration::from_secs(1300),
            "{at_cap:?}"
        );
        assert_eq!(body_budget(None, 64 * 1024 * 1024), None, "--read-timeout 0");
    }

    #[test]
    fn content_length_refuses_what_atol_would_swallow() -> Result<(), &'static str> {
        let block = |headers: &str| format!("POST / HTTP/1.1\r\n{headers}\r\n").into_bytes();

        assert_eq!(content_length(&block("Content-Length: 42\r\n"))?, Some(42));
        assert_eq!(content_length(&block("content-length:  7 \r\n"))?, Some(7));
        assert_eq!(content_length(&block("CONTENT-LENGTH: 0\r\n"))?, Some(0));
        assert_eq!(content_length(&block("Host: h\r\n"))?, None, "absent, not zero");

        // `atol("abc")` is 0, and 0 is a legal length, so the C cannot tell these apart.
        assert!(content_length(&block("Content-Length: abc\r\n")).is_err());
        assert!(content_length(&block("Content-Length: -1\r\n")).is_err());
        assert!(content_length(&block("Content-Length: \r\n")).is_err());
        assert!(content_length(&block("Content-Length: 99999999999999999999999\r\n")).is_err());
        assert!(content_length(&block("Content-Length: 5\r\nContent-Length: 9\r\n")).is_err());
        // The same value twice is not a contradiction.
        assert_eq!(
            content_length(&block("Content-Length: 5\r\nContent-Length: 5\r\n"))?,
            Some(5)
        );
        Ok(())
    }
}
