//! Which browser origins may drive this daemon.
//!
//! **A page the operator visits is a client of this daemon.** The two browser-facing
//! transports are reachable from any web page: a POST is a plain cross-origin `fetch`,
//! whose answer this daemon hands back on purpose because the flasher page needs it, and
//! a WebSocket handshake is not subject to CORS at all, so RFC 6455 §10.2 leaves the
//! `Origin` check to the server. With every interface bound and no token by default,
//! "any page" means any page: one POST reads the whole flash back, one writes firmware
//! of its own choosing.
//!
//! So an `Origin` that is present is checked against a list, and a response names the
//! origin it is answering rather than `*`.
//!
//! **An absent `Origin` is allowed.** Every non-browser client sends none: the CLI, the
//! Android library, a shell script. A browser attaches one to every `fetch` it makes, so
//! the absence is not something a page can arrange.

use core::fmt::Write as _;

/// The origin the shipped browser flasher is served from (`README.md`, "The browser
/// flasher": the hosted copy is `webflash.thingino.com`).
const OFFICIAL: &[&str] = &["https://webflash.thingino.com"];

/// The hosts a locally served copy of the page runs on.
///
/// The README's instruction is "unpack it under any document root and open it in Chrome
/// or Edge", with `http://localhost` named as the one plain-HTTP secure context WebUSB
/// accepts, so a loopback origin is the *documented* way to serve the flasher and
/// refusing it by default would refuse the documented flow. The port is not part of the
/// rule because a dev server picks its own.
///
/// A page on the operator's own machine is a far smaller opening than a page anywhere:
/// serving one means already running a server on that machine.
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// What a request's `Origin` header came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// No `Origin` header at all, which is every non-browser client. Served, and
    /// answered with `*`, because there is no origin to name.
    Absent,
    /// An origin on the list. Served, and echoed back.
    Allowed(String),
    /// An origin that is not. Refused.
    Refused(String),
}

impl Decision {
    /// Is this request to be served?
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Absent | Self::Allowed(_))
    }

    /// What `Access-Control-Allow-Origin` says. `None` when nothing may read the answer.
    #[must_use]
    pub fn allow_header(&self) -> Option<&str> {
        match self {
            Self::Absent => Some("*"),
            Self::Allowed(origin) => Some(origin.as_str()),
            Self::Refused(_) => None,
        }
    }

    /// The origin as the peer wrote it, for a log line.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::Allowed(origin) | Self::Refused(origin) => Some(origin.as_str()),
        }
    }
}

/// The origins a browser page may reach this daemon from.
///
/// Cheap to clone and to default: the shipped list is static, and only what
/// `--allow-origin` added is owned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Origins {
    /// What `--allow-origin` added, already lowercased.
    extra: Vec<String>,
    /// `--allow-any-origin`: check nothing, echo whatever arrives.
    any: bool,
}

impl Origins {
    /// The shipped list: the hosted flasher, and a copy served from loopback.
    ///
    /// A `const` rather than a function so that `&Origins::SHIPPED` is a `'static`
    /// borrow: every caller passes the list by reference, and a temporary would have to
    /// be bound to a local at each of them.
    pub const SHIPPED: Self = Self {
        extra: Vec::new(),
        any: false,
    };

    /// Every origin, which is what the daemon did before it checked at all.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            extra: Vec::new(),
            any: true,
        }
    }

    /// The shipped list plus these.
    ///
    /// # Errors
    /// [`OriginError`] for anything that is not a `scheme://host[:port]` origin, so a
    /// misspelled `--allow-origin` is a refusal rather than a list entry that can never
    /// match the header it was meant for.
    pub fn extended<I, S>(origins: I) -> Result<Self, OriginError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut extra = Vec::new();
        for origin in origins {
            extra.push(normalise(origin.as_ref())?);
        }
        Ok(Self { extra, any: false })
    }

    /// Is every origin allowed?
    #[must_use]
    pub const fn allows_any(&self) -> bool {
        self.any
    }

    /// Judge a request's `Origin` header.
    #[must_use]
    pub fn decide(&self, header: Option<&str>) -> Decision {
        let Some(origin) = header.map(str::trim).filter(|value| !value.is_empty()) else {
            return Decision::Absent;
        };
        if self.any {
            return Decision::Allowed(origin.to_owned());
        }
        let folded = origin.to_ascii_lowercase();
        // `null` is what a sandboxed frame, a `file://` page and some redirected requests
        // send. It names nobody, so it can never be on a list of who is trusted.
        if folded == "null" {
            return Decision::Refused(origin.to_owned());
        }
        let listed = OFFICIAL.contains(&folded.as_str()) || self.extra.contains(&folded) || is_loopback(&folded);
        if listed {
            Decision::Allowed(origin.to_owned())
        } else {
            Decision::Refused(origin.to_owned())
        }
    }

    /// The list, for the startup lines and the help text.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.any {
            return "any page, checked nowhere (--allow-any-origin)".to_owned();
        }
        let mut text = String::new();
        for origin in OFFICIAL {
            let _written = write!(text, "{origin}, ");
        }
        for origin in &self.extra {
            let _written = write!(text, "{origin}, ");
        }
        let _written = write!(text, "and http(s) on localhost, 127.0.0.1 or [::1], any port");
        text
    }
}

/// Why an `--allow-origin` value is not an origin.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OriginError {
    /// It is not `scheme://host[:port]`. The value is carried because the one an
    /// operator mistyped is the one they need to see.
    #[error("`{0}` is not an origin; write it as `https://host` or `http://host:port`")]
    NotAnOrigin(String),
    /// It carries a path, a query or a fragment. An origin is a scheme, a host and a
    /// port and nothing else (RFC 6454 §3.2), and that is what a browser sends, so a
    /// trailing `/` would produce a list entry that never matches.
    #[error("`{0}` has a path; an origin ends at the host and port")]
    HasPath(String),
}

/// An origin, lowercased, or a refusal.
///
/// Scheme and host are case-insensitive and a browser sends them lowercased already;
/// folding here is what stops `--allow-origin HTTPS://Webflash.Thingino.Com` from
/// becoming a list entry that never matches the header it was meant for.
fn normalise(value: &str) -> Result<String, OriginError> {
    let trimmed = value.trim();
    let not_an_origin = || OriginError::NotAnOrigin(trimmed.to_owned());
    let (scheme, rest) = trimmed.split_once("://").ok_or_else(not_an_origin)?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return Err(not_an_origin());
    }
    if rest.is_empty() {
        return Err(not_an_origin());
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(OriginError::HasPath(trimmed.to_owned()));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// A loopback origin on any port: `http://localhost:5173`, `https://127.0.0.1`, and the
/// bracketed IPv6 form a URL requires.
fn is_loopback(folded: &str) -> bool {
    let Some((scheme, authority)) = folded.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    let (host, port) = split_port(authority);
    if !LOOPBACK_HOSTS.contains(&host) {
        return false;
    }
    port.is_none_or(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Split `host[:port]`, leaving a bracketed IPv6 literal whole.
fn split_port(authority: &str) -> (&str, Option<&str>) {
    if let Some(end) = authority.rfind(']') {
        let (host, rest) = authority.split_at(end.saturating_add(1));
        return (host, rest.strip_prefix(':'));
    }
    match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    }
}

#[cfg(test)]
mod tests {
    use super::{Decision, OriginError, Origins, normalise};

    /// The shipped list: the hosted page, a locally served copy, and nothing else.
    #[test]
    fn the_shipped_list_is_the_flasher_and_loopback() {
        let origins = Origins::SHIPPED;
        for allowed in [
            "https://webflash.thingino.com",
            "http://localhost",
            "http://localhost:5173",
            "https://localhost:8443",
            "http://127.0.0.1:8000",
            "http://[::1]:3000",
        ] {
            assert_eq!(
                origins.decide(Some(allowed)),
                Decision::Allowed(allowed.to_owned()),
                "{allowed}"
            );
        }

        // The whole point: any other page the operator has open.
        for refused in [
            "https://evil.example",
            "http://webflash.thingino.com",
            "https://webflash.thingino.com.evil.example",
            "https://thingino.com",
            "https://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            // A sandboxed frame, a `file://` page or a redirect. It names nobody.
            "null",
            // A port that is not a number is not an authority this rule can read.
            "http://localhost:abc",
        ] {
            assert_eq!(
                origins.decide(Some(refused)),
                Decision::Refused(refused.to_owned()),
                "{refused}"
            );
        }
    }

    /// Every non-browser client sends no `Origin`, and they are the daemon's ordinary
    /// callers: the CLI, the Android library, a shell script.
    #[test]
    fn an_absent_origin_is_served_and_answered_with_a_star() {
        let origins = Origins::SHIPPED;
        assert_eq!(origins.decide(None), Decision::Absent);
        assert_eq!(origins.decide(Some("   ")), Decision::Absent, "an empty header");
        assert_eq!(origins.decide(None).allow_header(), Some("*"));
        assert_eq!(origins.decide(None).origin(), None);
        assert!(origins.decide(None).is_allowed());
    }

    /// An allowed origin is echoed verbatim, never `*`: `*` would hand the answer to
    /// every other page too.
    #[test]
    fn an_allowed_origin_is_echoed_and_a_refused_one_names_nothing() {
        let origins = Origins::SHIPPED;
        let allowed = origins.decide(Some("https://webflash.thingino.com"));
        assert_eq!(allowed.allow_header(), Some("https://webflash.thingino.com"));
        assert!(allowed.is_allowed());

        let refused = origins.decide(Some("https://evil.example"));
        assert_eq!(refused.allow_header(), None, "nothing may read it");
        assert_eq!(refused.origin(), Some("https://evil.example"), "the log names it");
        assert!(!refused.is_allowed());
    }

    /// `--allow-origin`, and the case folding that makes it work.
    #[test]
    fn an_added_origin_is_allowed_whatever_case_it_was_written_in() -> Result<(), OriginError> {
        let origins = Origins::extended(["HTTPS://Flash.Example.Test"])?;
        assert!(origins.decide(Some("https://flash.example.test")).is_allowed());
        // And the shipped entries survive being extended.
        assert!(origins.decide(Some("https://webflash.thingino.com")).is_allowed());
        assert!(!origins.decide(Some("https://other.example")).is_allowed());

        // A browser sends `scheme://host[:port]` and nothing else, so a value with a
        // path would be a list entry that never matches anything. Every refusal names
        // the value, because that is the one the operator has to fix.
        for value in ["https://a.test/", "https://a.test/page", "https://a.test?x=1"] {
            assert_eq!(
                Origins::extended([value]),
                Err(OriginError::HasPath(value.to_owned())),
                "{value}"
            );
        }
        for value in ["a.test", "ftp://a.test", "https://", ""] {
            assert_eq!(
                Origins::extended([value]),
                Err(OriginError::NotAnOrigin(value.to_owned())),
                "{value}"
            );
        }
        Ok(())
    }

    /// `--allow-any-origin` is the old behaviour, and it is asked for explicitly.
    #[test]
    fn any_origin_allows_and_echoes_whatever_arrives() {
        let origins = Origins::any();
        assert!(origins.allows_any());
        assert_eq!(
            origins.decide(Some("https://evil.example")),
            Decision::Allowed("https://evil.example".to_owned())
        );
        // Still not `*`: naming the one origin that asked keeps the answer out of every
        // other page's reach, which `*` would not.
        assert_eq!(
            origins.decide(Some("https://evil.example")).allow_header(),
            Some("https://evil.example")
        );
        assert_eq!(origins.decide(None), Decision::Absent);
        assert!(!Origins::SHIPPED.allows_any());
    }

    #[test]
    fn normalising_folds_case_and_keeps_the_port() -> Result<(), OriginError> {
        assert_eq!(normalise("HTTPS://Host.Test")?, "https://host.test");
        assert_eq!(normalise(" http://host.test:8080 ")?, "http://host.test:8080");
        Ok(())
    }

    /// The startup line has to name what is allowed, or an operator cannot tell why a
    /// page was refused.
    #[test]
    fn the_description_names_the_list() {
        let text = Origins::SHIPPED.describe();
        assert!(text.contains("https://webflash.thingino.com"), "{text}");
        assert!(text.contains("localhost"), "{text}");
        assert!(Origins::any().describe().contains("any page"));
    }
}
