//! The clock seam.
//!
//! This protocol is full of load-bearing waits: the 100 ms settle after every bootrom
//! vendor request, the 1000 ms after stage 1, the
//! `bwPollTimeout` the device itself asks for and the 500 ms grace backoff,
//! and the 1500 ms re-enumeration settle after a reset. None of
//! them may be `std::thread::sleep` in a browser, where blocking the thread blocks the
//! event loop the USB futures resolve on.
//!
//! **Every operation takes a [`Sleeper`].** An earlier implementation made the clock
//! optional — a plain form that used a built-in clock, and a `_with_clock` form beside
//! it — which produced eighteen duplicated entry points, and then the browser could not
//! reach several of them because they had not been made public, and it was
//! fixed late. One mandatory parameter cannot develop that gap: there is no
//! second form to forget to export.

use core::time::Duration;

/// Something that can wait.
///
/// `?Send` for the same reason [`LocalUsbTransport`](tdfu_usb::LocalUsbTransport) is:
/// the browser's implementation resolves a JS timer and its future is
/// `!Send`.
#[allow(async_fn_in_trait, reason = "?Send is the point; no async_trait")]
pub trait Sleeper {
    /// Wait for `duration`, then return.
    async fn sleep(&self, duration: Duration);
}

/// The clock a native frontend passes: it parks the current thread.
///
/// Correct for the CLI, which drives one device on a current-thread runtime or a
/// `LocalSet`. The daemon serves one client at a time and can use it
/// too, but a runtime timer is the better fit there — implement [`Sleeper`] over
/// `tokio::time::sleep` and pass that instead.
///
/// Not available on wasm: `std::thread::sleep` panics on `wasm32-unknown-unknown`, and
/// a clock that cannot work is worse than no clock at all. The browser frontend
/// implements [`Sleeper`] over `setTimeout`.
#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockingClock;

#[cfg(not(target_family = "wasm"))]
impl Sleeper for BlockingClock {
    async fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// A clock that does not wait, for tests that assert on *what* was slept for rather
/// than living through it.
///
/// It records every duration, so a test can pin the 0.5/1/2/3 s vendor backoff or
/// a device's `bwPollTimeout` without taking that long to run. `bwPollTimeout` is a
/// **24-bit** field, and an earlier implementation's tests all used 250 ms or 500 ms —
/// values whose high byte is zero, so `<< 16` and `>> 16` were indistinguishable and
/// coverage reported the line as covered throughout. Use a value above
/// `0xFFFF` ms in at least one test.
#[derive(Debug, Default)]
pub struct RecordingClock {
    slept: core::cell::RefCell<Vec<Duration>>,
}

impl RecordingClock {
    /// A clock with nothing recorded yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every duration passed to [`Sleeper::sleep`], in order.
    #[must_use]
    pub fn slept(&self) -> Vec<Duration> {
        self.slept.borrow().clone()
    }

    /// The sum of everything slept for.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.slept.borrow().iter().sum()
    }
}

impl Sleeper for RecordingClock {
    async fn sleep(&self, duration: Duration) {
        self.slept.borrow_mut().push(duration);
    }
}
