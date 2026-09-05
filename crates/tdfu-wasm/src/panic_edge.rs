//! The panic edge: how a panic inside the engine reaches the page.
//!
//! A panic must not cross the wasm boundary, and one that happens has to reach the page
//! **as a rejected promise carrying the message, and never as a hung page**. The obvious
//! mechanism is `std::panic::catch_unwind` at every exported
//! entry. It does not work here, and this module is what is done instead.
//!
//! # Why not `catch_unwind`
//!
//! Checked rather than assumed:
//!
//! ```text
//! $ rustc --target wasm32-unknown-unknown --print cfg | grep panic
//! panic="abort"
//! ```
//!
//! On the pinned 1.95.0 toolchain `wasm32-unknown-unknown` is `panic = "abort"`, and
//! there is no stable way to change it (unwinding needs the WebAssembly exception
//! handling proposal, a `-Z build-std` rebuild of `std`, and a nightly compiler).
//! `catch_unwind` still *compiles*, and that is the trap, but it can never observe a
//! payload, because `panic!` never unwinds: it runs the hook and then executes an
//! `unreachable` instruction, which traps the module. `crate`'s
//! `#[cfg(all(target_family = "wasm", panic = "unwind"))] compile_error!` fails the build
//! if that ever stops being true, so this reasoning cannot go stale in silence.
//!
//! A wasm trap **cannot be caught by wasm code**. It is caught by whoever called into the
//! module, which, for the body of an `async` operation, is the microtask that polls it,
//! not the page. The promise the page is awaiting would simply never settle. That is
//! precisely the hung page the seam forbids.
//!
//! # What is done instead
//!
//! The hook runs **before** the trap, on the panicking stack, with the JS heap intact,
//! so it can still settle the promise:
//!
//! 1. Every exported operation builds its promise with [`register`], which stores that
//!    promise's `reject` function in a registry and hands back a [`Ticket`].
//! 2. The operation's future takes the ticket with it and [`Ticket::settle`]s it the
//!    moment it resolves or rejects normally, so the registry holds exactly the
//!    operations that are still in flight.
//! 3. [`install`]'s hook formats the panic, records it for [`last_message`], and
//!    **rejects every promise in the registry** with an `Error` carrying `kind =
//!    "Panic"` and the panic's own message.
//! 4. The runtime then traps. The page sees a settled promise it can act on; the console
//!    additionally sees the trap, which is the honest record that the module is no longer
//!    trustworthy.
//!
//! Rejecting *every* in-flight promise, rather than only the one that panicked, is
//! deliberate: after a trap the module's state is undefined, so an operation that has not
//! failed yet cannot be promised a correct answer, and leaving it pending is the hang.
//!
//! Nothing in the hook can panic in turn: every borrow is a `try_borrow_mut` and every
//! JS call is a `Result` that is discarded. A panic inside a panic hook aborts the
//! process without running anything, which would take the rejection with it.

use core::cell::RefCell;

use js_sys::Function;
use wasm_bindgen::JsValue;

use crate::shape;

/// The `kind` a panic rejects with; part of the frozen JS-facing seam.
pub const PANIC_KIND: &str = "Panic";

thread_local! {
    /// The `reject` function of every promise this crate has handed out and not settled.
    ///
    /// A `Vec` rather than a map: it holds one entry per operation in flight, which is
    /// one or two in practice, and a linear scan over that is cheaper than a hash.
    static PENDING: RefCell<Vec<(u64, Function)>> = const { RefCell::new(Vec::new()) };

    /// The next ticket number. Monotonic, so a settled ticket can never match a later
    /// operation's.
    static NEXT_TICKET: RefCell<u64> = const { RefCell::new(0) };

    /// What the last panic said, for [`last_message`].
    static LAST: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A registered promise, removed from the registry when the operation settles.
///
/// Not `Drop`-based on purpose. A `Drop` impl would settle the ticket when the future is
/// dropped, and a future is dropped *after* its panic has already run the hook, so the
/// registry would still be correct, but the ordering would be an accident of drop glue
/// rather than a statement in the code. [`Ticket::settle`] is called where the operation
/// actually finishes.
#[derive(Debug)]
#[must_use = "an unsettled ticket keeps a resolved promise in the panic registry"]
pub struct Ticket(u64);

/// Remember `reject` until the operation it belongs to settles.
pub fn register(reject: &Function) -> Ticket {
    let id = NEXT_TICKET.with(|next| {
        next.try_borrow_mut().map_or(u64::MAX, |mut next| {
            *next = next.wrapping_add(1);
            *next
        })
    });
    PENDING.with(|pending| {
        if let Ok(mut pending) = pending.try_borrow_mut() {
            pending.push((id, reject.clone()));
        }
    });
    Ticket(id)
}

impl Ticket {
    /// This operation settled on its own; it is no longer the panic edge's problem.
    pub fn settle(self) {
        PENDING.with(|pending| {
            if let Ok(mut pending) = pending.try_borrow_mut() {
                pending.retain(|(id, _)| *id != self.0);
            }
        });
    }
}

/// Install the panic hook. Called once, from the module's `start` function.
///
/// Replaces whatever hook was there (there is none by default beyond the standard
/// message printer, and `std`'s default writes to a stderr that does not exist in a
/// page). Idempotent in effect: installing twice installs the same behaviour.
pub fn install() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map(ToString::to_string);
        report(&format_panic(&payload_of(info), location.as_deref()));
    }));
}

/// The panic's message, as `std` would have printed it.
///
/// `PanicHookInfo::payload` is `&dyn Any`; the two types `panic!` ever produces are
/// `&'static str` (a literal message) and `String` (a formatted one). Anything else came
/// from `panic_any` and has no text at all, which is said rather than guessed at.
fn payload_of(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "a panic with a payload that is not a string".to_owned()
    }
}

/// One line: the message, and where it came from when the panic carried a location.
///
/// Pure, so the shape is host-testable: `PanicHookInfo` has no public constructor, and a
/// formatter that can only be exercised by actually panicking is a formatter nobody
/// checks.
#[must_use]
pub fn format_panic(message: &str, location: Option<&str>) -> String {
    match location {
        Some(location) => format!("panicked at {location}: {message}"),
        None => format!("panicked: {message}"),
    }
}

/// Record `message` and reject every promise still in flight with it.
///
/// Separated from the hook so the rejection path can be exercised without trapping the
/// module: a `wasm-bindgen-test` that really panicked would take the test runner's
/// process with it on the way out, and a mechanism proven only by the thing it is there
/// to survive is a mechanism nobody can regression-test.
pub fn report(message: &str) {
    LAST.with(|last| {
        if let Ok(mut last) = last.try_borrow_mut() {
            *last = Some(message.to_owned());
        }
    });

    // Take the registry rather than iterating it in place: a `reject` callback runs JS,
    // and JS that re-entered this crate would find the borrow held.
    let pending = PENDING.with(|pending| {
        pending
            .try_borrow_mut()
            .map(|mut pending| core::mem::take(&mut *pending))
            .unwrap_or_default()
    });

    let error = shape::error_object(message, PANIC_KIND, false);
    for (_, reject) in pending {
        let _ignored = reject.call1(&JsValue::UNDEFINED, &error);
    }
}

/// What the last panic said, or `None` if none has happened.
///
/// The page has no other way to see it: the trap that follows the hook is reported by the
/// browser as a bare `RuntimeError: unreachable`, with the Rust message nowhere in it.
#[must_use]
pub fn last_message() -> Option<String> {
    LAST.with(|last| last.try_borrow().ok().and_then(|last| last.clone()))
}

/// How many promises are still in flight. Diagnostics, and the pin for [`Ticket`].
#[must_use]
pub fn pending_count() -> usize {
    PENDING.with(|pending| pending.try_borrow().map_or(0, |pending| pending.len()))
}

#[cfg(test)]
mod tests {
    use super::{PANIC_KIND, format_panic};

    #[test]
    fn a_located_panic_names_the_file_and_the_message() {
        assert_eq!(
            format_panic("index out of bounds", Some("src/engine.rs:12:5")),
            "panicked at src/engine.rs:12:5: index out of bounds"
        );
    }

    #[test]
    fn an_unlocated_panic_still_carries_its_message() {
        // `PanicHookInfo::location` is an `Option`, and a message with `panicked at :`
        // in it would be worse than one that simply says what happened.
        assert_eq!(format_panic("boom", None), "panicked: boom");
    }

    #[test]
    fn the_panic_kind_is_the_frozen_spelling() {
        // The seam says a panic inside the engine rejects with `.kind = "Panic"`, and
        // `tdfu.js` switches on this string.
        assert_eq!(PANIC_KIND, "Panic");
    }
}
