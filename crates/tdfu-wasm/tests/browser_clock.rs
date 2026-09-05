//! **`a_browser_clock_drives_the_core`**: the browser's own timer, end to end.
//!
//! The failure it guards against: an earlier implementation made the clock optional, which produced
//! eighteen `_with_clock` twins, several of them not `pub`, so the browser could not reach the
//! forms it had to use. The twins are gone. `every_entry_point_is_public` (in
//! the crate's own `tests` module) proves the entry points are reachable; this proves the
//! other half, that a **real** browser clock, `setTimeout` and nothing else, actually
//! drives a whole write and a whole verify.
//!
//! It has to run under a JS runtime, so it is a `wasm-bindgen-test` under Node rather than
//! a host test. A host stand-in for `setTimeout` would pin the shape of the seam and
//! nothing about whether the browser's timer works, which is the thing that was in doubt.
//!
//! The device is `tdfu_usb::gadget::FakeGadget`, the U-Boot DFU emulator checked against
//! `f_dfu.c` rather than against what the host expects.

#![cfg(target_family = "wasm")]

use core::cell::RefCell;
use core::time::Duration;

use tdfu_core::clock::Sleeper;
use tdfu_core::model::AltSel;
use tdfu_core::{Progress, ops};
use tdfu_usb::gadget::{FakeGadget, GadgetConfig};
use tdfu_wasm::clock::JsSleeper;
use wasm_bindgen_test::wasm_bindgen_test;

/// A [`JsSleeper`] that also records what it was asked to wait for.
///
/// The waiting is still the real one (every `sleep` goes through `setTimeout`), so this
/// observes the seam rather than replacing it. Without it the pin could only say "the
/// operation finished", which a clock that returned immediately would also satisfy.
#[derive(Debug, Default)]
struct Observed {
    inner: JsSleeper,
    slept: RefCell<Vec<Duration>>,
}

impl Observed {
    fn waits(&self) -> Vec<Duration> {
        self.slept.borrow().clone()
    }
}

impl Sleeper for Observed {
    async fn sleep(&self, duration: Duration) {
        // The borrow is taken and dropped before the await: a `RefCell` held across one
        // would be a second borrow the moment two operations overlap.
        {
            self.slept.borrow_mut().push(duration);
        }
        self.inner.sleep(duration).await;
    }
}

/// An image whose bytes all differ from `0xFF`, so a byte that never landed is
/// distinguishable from erased flash.
fn image(len: usize) -> Vec<u8> {
    (0..len).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect()
}

/// A gadget with the three shipped alts and a manifest phase that really goes busy, so
/// the poll loop has something to wait for: the flush to flash is the long pole.
fn gadget() -> FakeGadget {
    FakeGadget::new(
        GadgetConfig::t32lq()
            .with_transfer_size(1024)
            .with_buffer_size(1 << 20)
            .with_manifest_hold_polls(2),
    )
}

#[wasm_bindgen_test]
async fn the_js_timer_really_waits() {
    // Before trusting the clock to drive an operation: prove it is a clock. A `setTimeout`
    // that never fired would make every wait in the protocol instant, and the operations
    // below would still pass.
    let start = js_sys::Date::now();
    JsSleeper::new().sleep(Duration::from_millis(60)).await;
    let elapsed = js_sys::Date::now() - start;
    assert!(elapsed >= 40.0, "a 60 ms sleep took {elapsed} ms");
}

#[wasm_bindgen_test]
async fn a_browser_clock_drives_the_core() {
    let device = gadget();
    let clock = Observed::default();
    let payload = image(4096);
    let mut notes = Vec::new();
    let mut sink = |event: Progress| {
        if let Progress::Note(text) = event {
            notes.push(text);
        }
    };

    // A whole write, through `setTimeout` and nothing else.
    let written = ops::write(&device, &clock, &AltSel::Default, &payload, &mut sink).await;
    assert!(written.is_ok(), "write failed: {written:?}");

    // And a whole verify, which reads the flash back and compares block by block.
    let verified = ops::verify(&device, &clock, &AltSel::Default, &payload, &mut sink).await;
    assert!(verified.is_ok(), "verify failed: {verified:?}");

    // The bytes really landed: the emulator's medium is what a read-back would return.
    assert_eq!(device.medium(0).as_deref(), Some(payload.as_slice()));

    // And the waits went through this clock. `poll_until_ready` sleeps
    // `bwPollTimeout.max(BUSY_POLL_FLOOR)` on every busy poll, and the manifest phase
    // above holds busy for two of them; a core that had reached a different clock, or no
    // clock, would leave this empty.
    let waits = clock.waits();
    assert!(!waits.is_empty(), "the core never asked this clock to wait");

    // Both completion lines came out of core, once each: the notes are
    // emitted there so every frontend gets them from one place.
    assert!(
        notes.iter().any(|note| note.contains("DFU download complete")),
        "{notes:?}"
    );
    assert!(notes.iter().any(|note| note.contains("Verify OK")), "{notes:?}");
}

#[wasm_bindgen_test]
async fn the_clock_carries_a_poll_timeout_above_the_low_word() {
    // `bwPollTimeout` is a 24-bit field, and an earlier implementation's tests all used
    // 250 or 500 ms - values whose high byte is zero, so `<< 16` and `>> 16` were
    // indistinguishable while coverage reported the line covered throughout. The browser
    // clock has to carry the whole field, and `setTimeout` takes an `i32`, so this is
    // where a truncation would show. It is asserted rather than waited out: 0x00FFFFFF ms
    // is 4.6 hours.
    assert_eq!(
        tdfu_wasm::clock::delay_millis(Duration::from_millis(0x00FF_FFFF)),
        0x00FF_FFFF
    );
}
