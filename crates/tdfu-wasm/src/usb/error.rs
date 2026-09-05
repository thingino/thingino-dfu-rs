//! What a WebUSB failure means, in [`UsbErrorKind`] terms.
//!
//! Two tables, both pure functions over strings so they are host-tested and every arm is
//! reachable from a unit test, which matters more here than anywhere else in the crate,
//! because a kind chosen carelessly either retries something that cannot recover or
//! fails something that would have: a bootrom vendor request retries only
//! `{Timeout, Stall, NoDevice}`, and the DFU reset-and-retry class is wider.
//!
//! * [`kind_from_status`] reads `USBTransferStatus`, the *successful* completion of a
//!   transfer that the device answered with a stall or a babble.
//! * [`kind_from_dom`] reads the name of the `DOMException` a rejected WebUSB promise
//!   carries.
//!
//! # The shim mapped these too, and got two of them wrong
//!
//! `web/src/libusb-webusb.js` is the authority on *which* exceptions occur, not on what
//! they mean. It answered `LIBUSB_ERROR_PIPE` for every non-`ok` transfer status
//! (`:356`, `:410`, `:423`), collapsing a babble (the device sent more than was asked
//! for, which is a framing fault) into a stall, which a vendor request retries. And it
//! swallowed failures wholesale: `selectConfiguration` (`:228`), `releaseInterface`
//! (`:262`) and `reset` (`:469`) all `catch(...)  { return 0 }`, so a refused claim
//! reported success. Neither is reproduced.

use tdfu_usb::UsbErrorKind;

use crate::clock::DEADLINE_MARKER;

/// A `USBTransferStatus` string, as a failure. `None` when the transfer succeeded.
///
/// The three values the spec defines are `"ok"`, `"stall"` and `"babble"`
/// (<https://wicg.github.io/webusb/#enumdef-usbtransferstatus>). An unknown fourth is
/// reported as itself rather than guessed at.
///
/// `"babble"` is [`UsbErrorKind::Overflow`], which is the variant that exists **for this
/// backend**: `nusb` cannot tell an overflow from any other hardware fault, so
/// `crates/tdfu-usb/src/native/error.rs:31-34` says outright that `Overflow` is left to
/// backends that can tell, and this is the one that can. Overflow is deliberately not in
/// the vendor-request retry class: a device that sent more than the host asked for did not
/// fail to answer, it answered wrongly, and asking again gets the same answer.
#[must_use]
pub fn kind_from_status(status: &str) -> Option<UsbErrorKind> {
    match status {
        "ok" => None,
        "stall" => Some(UsbErrorKind::Stall),
        "babble" => Some(UsbErrorKind::Overflow),
        other => Some(UsbErrorKind::Backend(format!(
            "the browser reported transfer status {other:?}, which is not one of ok/stall/babble"
        ))),
    }
}

/// A rejected WebUSB promise, as a failure.
///
/// `holds_claim` is what the transport knows about itself, and it is what separates the
/// two readings of `InvalidStateError`. Chromium raises that name both for "the
/// interface must be claimed first" and for "another operation that changes interface
/// state is in progress", which are [`UsbErrorKind::NotClaimed`] (a caller bug) and
/// [`UsbErrorKind::Busy`] (a resource conflict) and are in neither retry class for
/// different reasons. Keying on our own claim state answers it from a fact rather than
/// from a substring of a message the browser is free to re-word.
///
/// | name | kind | why |
/// |---|---|---|
/// | `NotFoundError` | `NoDevice` | the device is gone from the bus, or was never authorized |
/// | `NetworkError` | `Fault` | Chromium's "transfer failed" and "unable to claim"; recoverable, which is the point of the reset-and-retry |
/// | `InvalidStateError` | `NotClaimed` / `Busy` | see above |
/// | `SecurityError`, `NotAllowedError` | `AccessDenied` | the browser or the OS refused; a bus reset installs no udev rule, so it is not recoverable |
/// | `NotSupportedError` | `Unsupported` | this browser cannot make the request at all |
/// | `AbortError` | `Fault` | the transfer was abandoned; nothing says the device is gone |
/// | [`DEADLINE_MARKER`] | `Timeout` | ours, not the browser's; see [`crate::clock::deadline`] |
#[must_use]
pub fn kind_from_dom(name: &str, message: &str, holds_claim: bool) -> UsbErrorKind {
    match name {
        DEADLINE_MARKER => UsbErrorKind::Timeout,
        "NotFoundError" => UsbErrorKind::NoDevice,
        "NetworkError" | "AbortError" => UsbErrorKind::Fault,
        "InvalidStateError" => {
            if holds_claim {
                UsbErrorKind::Busy
            } else {
                UsbErrorKind::NotClaimed
            }
        }
        "SecurityError" | "NotAllowedError" => UsbErrorKind::AccessDenied,
        "NotSupportedError" => UsbErrorKind::Unsupported,
        // The browser's own words, kept. A name nobody mapped is exactly the case where
        // the message is the only thing that will tell whoever reads the bug report what
        // happened, and discarding it is how a diagnosable failure becomes a mystery.
        other => UsbErrorKind::Backend(describe_unmapped(other, message)),
    }
}

/// The prose for an exception nobody mapped.
fn describe_unmapped(name: &str, message: &str) -> String {
    match (name.is_empty(), message.is_empty()) {
        (true, true) => "the browser rejected the request without saying why".to_owned(),
        (true, false) => format!("the browser rejected the request: {message}"),
        (false, true) => format!("the browser raised {name}"),
        (false, false) => format!("the browser raised {name}: {message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{kind_from_dom, kind_from_status};
    use crate::clock::DEADLINE_MARKER;
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// Is this kind in the bootrom vendor-request retry class?
    fn retryable(kind: UsbErrorKind) -> bool {
        UsbError::new(kind, Pipe::Device).is_vendor_retryable()
    }

    /// The prose of a [`UsbErrorKind::Backend`], or a sentence that fails the
    /// `contains` assertion it lands in. `assert!(false, ..)` is
    /// `clippy::assertions_on_constants` and `panic!` is denied outright, so a wrong arm
    /// has to fail through the value rather than through a macro.
    fn backend_text(kind: &UsbErrorKind) -> String {
        match kind {
            UsbErrorKind::Backend(text) => text.clone(),
            other => format!("this is not a Backend kind, it is {other:?}"),
        }
    }

    #[test]
    fn ok_is_not_a_failure() {
        assert_eq!(kind_from_status("ok"), None);
    }

    #[test]
    fn a_stall_and_a_babble_are_different_failures() {
        // The shim answered LIBUSB_ERROR_PIPE for both (`libusb-webusb.js:356`), which
        // put a framing fault into the vendor-request retry class.
        assert_eq!(kind_from_status("stall"), Some(UsbErrorKind::Stall));
        assert_eq!(kind_from_status("babble"), Some(UsbErrorKind::Overflow));
        assert!(retryable(UsbErrorKind::Stall));
        assert!(!retryable(UsbErrorKind::Overflow));
    }

    #[test]
    fn an_unknown_status_keeps_its_own_word() {
        let kind = kind_from_status("weird").unwrap_or(UsbErrorKind::Timeout);
        let text = backend_text(&kind);
        assert!(text.contains("weird"), "{text}");
    }

    #[test]
    fn our_expired_deadline_is_a_timeout_and_nothing_else_is() {
        // The whole reason [`DEADLINE_MARKER`] is not a DOMException name: WebUSB
        // transfers carry no deadline, so every Timeout in this backend is one we set,
        // and a bootrom vendor request retries it.
        assert_eq!(kind_from_dom(DEADLINE_MARKER, "", false), UsbErrorKind::Timeout);
        for name in [
            "NotFoundError",
            "NetworkError",
            "InvalidStateError",
            "SecurityError",
            "NotSupportedError",
            "AbortError",
            "NotAllowedError",
        ] {
            assert_ne!(kind_from_dom(name, "", false), UsbErrorKind::Timeout, "{name}");
        }
    }

    #[test]
    fn the_dom_names_map_where_the_task_table_says() {
        for (name, want) in [
            ("NotFoundError", UsbErrorKind::NoDevice),
            ("NetworkError", UsbErrorKind::Fault),
            ("AbortError", UsbErrorKind::Fault),
            ("SecurityError", UsbErrorKind::AccessDenied),
            ("NotAllowedError", UsbErrorKind::AccessDenied),
            ("NotSupportedError", UsbErrorKind::Unsupported),
        ] {
            assert_eq!(kind_from_dom(name, "whatever", false), want, "{name}");
            assert_eq!(kind_from_dom(name, "whatever", true), want, "{name}");
        }
    }

    #[test]
    fn invalid_state_reads_our_claim_rather_than_the_browsers_wording() {
        // Chromium raises `InvalidStateError` for both "claim it first" and "an
        // interface-state operation is already running". We know which we are in.
        assert_eq!(
            kind_from_dom("InvalidStateError", "The interface must be claimed", false),
            UsbErrorKind::NotClaimed
        );
        assert_eq!(
            kind_from_dom("InvalidStateError", "An operation is in progress", true),
            UsbErrorKind::Busy
        );
        // Neither is retried: a caller bug is not fixed by waiting, and a resource
        // another handle holds is not freed by a bus reset.
        assert!(!retryable(UsbErrorKind::NotClaimed));
        assert!(!retryable(UsbErrorKind::Busy));
    }

    #[test]
    fn an_unmapped_exception_keeps_both_of_the_browsers_words() {
        let text = backend_text(&kind_from_dom("QuotaExceededError", "too much", false));
        assert!(text.contains("QuotaExceededError"), "{text}");
        assert!(text.contains("too much"), "{text}");
    }

    #[test]
    fn a_nameless_wordless_rejection_still_says_something() {
        // A promise rejected with `undefined` is rare and entirely possible; "" is not
        // a diagnosis. Every combination of a missing name and a missing message has to
        // produce a sentence, so all four are walked.
        for (name, message) in [("", ""), ("", "boom"), ("OddError", ""), ("OddError", "boom")] {
            let text = backend_text(&kind_from_dom(name, message, false));
            assert!(!text.is_empty(), "{name}/{message} produced no prose");
            assert!(
                !text.starts_with("this is not a Backend kind"),
                "{name}/{message} was mapped rather than described: {text}"
            );
        }
    }
}
