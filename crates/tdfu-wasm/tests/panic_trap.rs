//! A **real** panic, end to end: the hook runs, the message is recorded, and the trap
//! reaches the caller as a thrown `RuntimeError` rather than as a hang.
//!
//! # Why this is a test binary of its own
//!
//! Two reasons, both about the fact that a panic here is not simulated.
//!
//! * `wasm-bindgen-test` installs **its own** panic hook to capture a failing test's
//!   message (`wasm_bindgen_test::__rt::Context::new::panic_handling`, visible in any
//!   failure's stack). Installing ours replaces it, so every later test in the same
//!   binary would lose its failure reporting. Alone in a file, there is no later test.
//! * `wasm32-unknown-unknown` is `panic = "abort"`, so the panic ends in an `unreachable`
//!   instruction, which is a wasm trap. A trap cannot be caught by wasm code; it is
//!   whoever called *into* the module. That is what this exercises, and it is why the
//!   panicking code is reached through a `Closure` that JavaScript calls inside a
//!   `try`/`catch`: the throw crosses the boundary the same way a real one would.
//!
//! What this pins that `tests/edge.rs` cannot: that the installed hook really is invoked
//! by a real `panic!` and really does record the message, so
//! [`panic_edge::report`](tdfu_wasm::panic_edge::report)'s rejection path, which
//! `edge.rs` drives directly, is wired to something. In the page the hook is installed by
//! the module's `#[wasm_bindgen(start)]`, which `await init()` runs.

#![cfg(target_family = "wasm")]

use js_sys::Function;
use tdfu_wasm::panic_edge;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen(inline_js = r#"
// Call back into wasm from JavaScript, inside a try/catch. A wasm trap surfaces here as
// a RuntimeError; anything else surfaces as itself.
export function callCatching(f) {
    try { f(); return null; } catch (e) { return String(e); }
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = callCatching)]
    fn call_catching(f: &Function) -> Option<String>;
}

#[wasm_bindgen_test]
fn a_real_panic_records_its_message_and_surfaces_as_a_throw() {
    panic_edge::install();

    let boom = Closure::<dyn FnMut()>::new(|| {
        #[expect(
            clippy::panic,
            reason = "the point of this test is that a panic is handled \
                      in library code, which is what makes a deliberate one here worth pinning"
        )]
        {
            panic!("the edge test's own panic");
        }
    });

    let thrown = call_catching(boom.as_ref().unchecked_ref());

    // 1. It threw. Not a hang, which is the outcome the seam forbids.
    let thrown = thrown.unwrap_or_default();
    assert!(!thrown.is_empty(), "the call returned normally from a panic");
    assert!(
        thrown.contains("RuntimeError") || thrown.contains("unreachable"),
        "{thrown}"
    );

    // 2. The hook ran first and kept the message, which the trap alone would have lost:
    //    the browser reports it as a bare `RuntimeError: unreachable` with no Rust text
    //    in it at all.
    let recorded = panic_edge::last_message().unwrap_or_default();
    assert!(recorded.contains("the edge test's own panic"), "{recorded}");
    assert!(recorded.starts_with("panicked at "), "{recorded}");
    assert!(recorded.contains("panic_trap.rs"), "{recorded}");
}
