//! The browser's clock: [`Sleeper`] over `setTimeout`.
//!
//! This protocol is full of load-bearing waits: the 100 ms settle after every bootrom
//! vendor request, the 1000 ms after stage 1 while it brings up clock and DDR, the device's own
//! `bwPollTimeout` and the 500 ms backoff between forgiven status polls, the 1500 ms re-enumeration
//! settle after a reset. Not one of them may park the thread here: the thread is the
//! event loop the WebUSB promises resolve on, so a `std::thread::sleep` would deadlock
//! the very transfer it is waiting for. `tdfu_core::clock::BlockingClock` is not compiled
//! for wasm at all, which is what makes that mistake unrepresentable rather than merely
//! discouraged.
//!
//! # `setTimeout` off the global, not off `window`
//!
//! The lookup goes through `js_sys::global()` and a property read rather than
//! `web_sys::Window::set_timeout_*`. Three runtimes have to work: a page (`window`), a
//! worker (`WorkerGlobalScope`; the flasher does not use one today, and a design that
//! forbids it for no reason is a trap for whoever tries), and **Node**, which is where
//! `wasm-bindgen-test` runs the pins below and has no `window` at all. All three expose
//! `globalThis.setTimeout`. It also drops the `Window` feature from `web-sys`.

use core::time::Duration;

use js_sys::{Function, Promise, Reflect};
use tdfu_core::clock::Sleeper;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// The value a [`deadline`] promise rejects with.
///
/// Not a `DOMException`: the browser never produced it, we did, and giving it a name of
/// its own is what lets [`crate::usb::error`] tell "the deadline this backend set
/// expired" apart from "the browser reported an error", which are different
/// [`UsbErrorKind`](tdfu_usb::UsbErrorKind)s: a bootrom vendor request retries a timeout, and nothing else.
pub const DEADLINE_MARKER: &str = "TdfuDeadlineExpired";

/// A [`Sleeper`] backed by `setTimeout`.
///
/// Zero-sized: the timer is a global, so there is nothing to hold. Cloneable so an
/// operation can hand one to a nested helper without borrowing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsSleeper;

impl JsSleeper {
    /// A clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Sleeper for JsSleeper {
    async fn sleep(&self, duration: Duration) {
        // A rejected timer promise would be a wait that ended early *and* an unhandled
        // rejection; resolving is the only outcome this can have, so the result is
        // deliberately discarded rather than propagated into a signature that has
        // nowhere to put it.
        let _ignored = JsFuture::from(resolving(duration)).await;
    }
}

/// A promise that resolves after `duration`.
pub fn resolving(duration: Duration) -> Promise {
    Promise::new(&mut |resolve, _reject| {
        if schedule(&resolve, duration).is_err() {
            // No usable `setTimeout` in this runtime. Resolving now turns "no timer"
            // into "no wait", which is wrong but bounded; the alternative is a promise
            // that never settles, and a browser flasher that hangs on a 100 ms settle is
            // worse than one that skips it. Unreachable in a page, a worker and Node
            // alike - all three have `setTimeout` - so this is the branch that keeps a
            // fourth runtime from producing a hang instead of a symptom.
            let _ignored = resolve.call0(&JsValue::UNDEFINED);
        }
    })
}

/// A deadline promise and the timer behind it.
///
/// Held rather than dropped so the timer can be **cleared** when the race it is half of
/// settles the other way. Without that, a 16 MiB write left one live timer
/// per `DNLOAD` block for up to that block's own 30 s: bounded and self-draining, no
/// unhandled rejection (`Promise::race` subscribes to both halves), and exactly what the
/// shim did at `libusb-webusb.js:377-379`, but a few thousand pending timers is a cost
/// with nothing on the other side of it.
#[derive(Debug)]
pub struct Deadline {
    promise: Promise,
    /// What `setTimeout` handed back: a number in a browser, a `Timeout` object under
    /// Node. `clearTimeout` takes either, so it is kept as an opaque value rather than
    /// converted. `None` means the runtime had no usable `setTimeout` and the promise has
    /// already rejected.
    timer: Option<JsValue>,
}

impl Deadline {
    /// The promise to race the transfer against.
    pub const fn promise(&self) -> &Promise {
        &self.promise
    }

    /// Cancel the timer, if it has not fired.
    ///
    /// Idempotent from the runtime's side: `clearTimeout` on an id that has already fired
    /// is a no-op in every engine, and a promise that has already rejected stays rejected.
    pub fn clear(self) {
        let Some(timer) = self.timer else { return };
        let global = js_sys::global();
        let Ok(clear_timeout) = Reflect::get(&global, &JsValue::from_str("clearTimeout")) else {
            return;
        };
        let Ok(clear_timeout) = clear_timeout.dyn_into::<Function>() else {
            return;
        };
        let _ignored = clear_timeout.call1(&JsValue::UNDEFINED, &timer);
    }
}

/// A promise that **rejects** with [`DEADLINE_MARKER`] after `duration`.
///
/// This is the timeout half of every transfer race. WebUSB transfers carry no deadline
/// of their own (`USBDevice.controlTransferIn` and friends take no timeout argument and
/// there is no cancel), so the backend owns the deadline, exactly as the trait's doc
/// comment says it must, and races the transfer against this.
#[must_use]
pub fn deadline(duration: Duration) -> Deadline {
    let mut timer = None;
    let promise = Promise::new(&mut |_resolve, reject| {
        // `bind1`, not the bare `reject`: `setTimeout` calls its callback with the timer
        // id, so an unbound `reject` would reject with a number and the mapper would see
        // an unnamed rejection instead of [`DEADLINE_MARKER`]: a `UsbErrorKind::Backend`
        // where a `Timeout` is needed, which is the difference between a retried
        // bootrom request and a failed one. Found by
        // `tests/webusb.rs::a_transfer_that_never_settles_expires_on_our_own_deadline`.
        //
        // The cast erases `bind1`'s arity-tracking type parameter, a compile-time
        // convenience of `js-sys` rather than a runtime property: the value is the same
        // `Function`.
        let expire: Function = reject
            .bind1(&JsValue::UNDEFINED, &JsValue::from_str(DEADLINE_MARKER))
            .unchecked_into();
        match schedule(&expire, duration) {
            Ok(handle) => timer = Some(handle),
            Err(_) => {
                let _ignored = expire.call0(&JsValue::UNDEFINED);
            }
        }
    });
    Deadline { promise, timer }
}

/// `globalThis.setTimeout(callback, ms)`, and the handle it answers with.
///
/// `Err` means the runtime has no callable `setTimeout`; the two callers above each say
/// what they do about it.
fn schedule(callback: &Function, duration: Duration) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let set_timeout = Reflect::get(&global, &JsValue::from_str("setTimeout"))?;
    let set_timeout = set_timeout.dyn_into::<Function>()?;
    let millis = delay_millis(duration);
    set_timeout.call2(&JsValue::UNDEFINED, callback, &JsValue::from_f64(f64::from(millis)))
}

/// The millisecond delay `setTimeout` is asked for, saturating rather than wrapping.
///
/// `setTimeout` takes an `i32` in every engine that matters, and clamps anything larger
/// to 1 ms rather than to the value asked for, which would turn the longest waits in
/// the protocol into the shortest. Saturating at `i32::MAX` (24 days) keeps a long wait
/// long; the DFU status reply's `bwPollTimeout` is 24-bit, so the real ceiling a device
/// can ask for is 4.6 hours and this never binds in practice.
///
/// Split out and called by [`schedule`] rather than inlined there, so the saturation is
/// testable on the host: it is the one arithmetic decision in this module, and the wrong
/// answer (a wrap to a small or negative number) would turn the longest poll a device can
/// ask for into no wait at all. Mutation testing has caught exactly that on `bwPollTimeout`'s
/// high byte before, where coverage reported the line covered throughout.
#[must_use]
pub fn delay_millis(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{DEADLINE_MARKER, delay_millis};
    use core::time::Duration;

    #[test]
    fn a_delay_that_fits_is_passed_through() {
        assert_eq!(delay_millis(Duration::from_millis(0)), 0);
        assert_eq!(delay_millis(Duration::from_millis(100)), 100);
        assert_eq!(delay_millis(Duration::from_millis(1500)), 1500);
        // `bwPollTimeout` is 24 bits: 0xFFFFFF ms is the most a device can
        // ask for, and it must survive the conversion intact. An earlier implementation's
        // tests all used 250 or 500 ms, where the high bytes are zero and nothing could
        // tell a shift from its opposite.
        assert_eq!(delay_millis(Duration::from_millis(0x00FF_FFFF)), 0x00FF_FFFF);
    }

    #[test]
    fn a_delay_that_does_not_fit_saturates_long_rather_than_wrapping() {
        // 25 days: past `i32::MAX` milliseconds. A wrap here would produce a negative
        // delay, which `setTimeout` treats as zero - the longest wait in the protocol
        // becoming the shortest.
        let far = Duration::from_millis(u64::from(u32::MAX) * 2);
        assert_eq!(delay_millis(far), i32::MAX);
        assert_eq!(delay_millis(Duration::MAX), i32::MAX);
    }

    #[test]
    fn the_deadline_marker_is_not_a_dom_exception_name() {
        // `crate::usb::error` tells our own expired deadline from a browser error by
        // this string, so it must never collide with a DOMException name. Every one of
        // those ends in "Error"; this one deliberately does not.
        assert!(!DEADLINE_MARKER.ends_with("Error"), "{DEADLINE_MARKER}");
    }
}
