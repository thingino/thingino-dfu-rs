//! The page's `log(line, level)` callback, as something the backend can hold.
//!
//! One sink for the whole engine, shared by reference: the backend wants to say
//! "assuming a 4096-byte transfer size" and the operations want to relay
//! `tdfu-core`'s [`Progress::Note`](tdfu_core::Progress)s, and both are the same channel
//! to the same operator. An earlier browser path had the shim logging to
//! `console.log` and the C logging through Emscripten's `printErr`, which is why its
//! in-page log and its `DevTools` console disagreed about what happened
//! (`web/src/libusb-webusb.js:17-26`).
//!
//! Debug lines are suppressed unless the page called `setDebug(true)`. That is the CLI's
//! `--debug` and the shipped page's `?debug`, and it matters here for one reason beyond
//! noise: a `write` of a 16 MiB image at 4096 bytes a block is four thousand transfers,
//! and a `log` callback that renders into the DOM for each of them is the difference
//! between a flash that takes a minute and one that takes an hour.

use core::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::Function;
use wasm_bindgen::JsValue;

/// Which channel a line belongs on. The strings are the frozen seam: the page switches on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    /// What `--debug` shows: request-level detail, off by default.
    Debug,
    /// Progress notes and completion lines from `tdfu-core`.
    Info,
    /// Something the operator should act on that is not a failure.
    Warn,
    /// A failure that is also being reported through a rejected promise.
    Error,
}

impl Level {
    /// The string the `log` callback's second argument carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// A handle on the page's `log` callback.
///
/// Cheap to clone (one `Rc`), because the backend, the transport and every operation
/// hold one.
#[derive(Debug, Clone, Default)]
pub struct Logger {
    inner: Rc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// `None` when the page passed no `log`, which is allowed: both callbacks are
    /// optional in the seam, and an engine with neither must still work.
    sink: RefCell<Option<Function>>,
    debug: Cell<bool>,
}

impl Logger {
    /// A logger writing to `sink`, or to nothing when there is none.
    #[must_use]
    pub fn new(sink: Option<Function>) -> Self {
        Self {
            inner: Rc::new(Inner {
                sink: RefCell::new(sink),
                debug: Cell::new(false),
            }),
        }
    }

    /// Turn debug lines on or off (`Engine::setDebug`).
    pub fn set_debug(&self, on: bool) {
        self.inner.debug.set(on);
    }

    /// Are debug lines being emitted?
    #[must_use]
    pub fn debug_enabled(&self) -> bool {
        self.inner.debug.get()
    }

    /// Emit one line.
    ///
    /// A callback that throws is ignored rather than propagated: a page whose logger is
    /// broken must still be able to finish the flash it started, and turning a logging
    /// failure into a transfer failure would be the tail wagging the dog.
    pub fn line(&self, level: Level, text: &str) {
        if level == Level::Debug && !self.debug_enabled() {
            return;
        }
        let sink = self.inner.sink.try_borrow().ok().and_then(|sink| sink.clone());
        if let Some(sink) = sink {
            let _ignored = sink.call2(
                &JsValue::UNDEFINED,
                &JsValue::from_str(text),
                &JsValue::from_str(level.as_str()),
            );
        }
    }

    /// A line only `setDebug(true)` shows.
    ///
    /// The argument is a closure so that formatting a suppressed line costs nothing:
    /// the per-transfer lines are on the hot path of a four-thousand-block write.
    pub fn debug(&self, text: impl FnOnce() -> String) {
        if self.debug_enabled() {
            self.line(Level::Debug, &text());
        }
    }

    /// A progress note or completion line.
    pub fn info(&self, text: &str) {
        self.line(Level::Info, text);
    }

    /// Something to act on.
    pub fn warn(&self, text: &str) {
        self.line(Level::Warn, text);
    }
}

#[cfg(test)]
mod tests {
    use super::{Level, Logger};

    #[test]
    fn the_four_levels_are_the_frozen_spellings() {
        // The seam says level is "debug"|"info"|"warn"|"error", and `tdfu.js` styles
        // the log line by it.
        assert_eq!(Level::Debug.as_str(), "debug");
        assert_eq!(Level::Info.as_str(), "info");
        assert_eq!(Level::Warn.as_str(), "warn");
        assert_eq!(Level::Error.as_str(), "error");
    }

    #[test]
    fn debug_is_off_until_it_is_asked_for() {
        // The default matters: a page that never calls `setDebug` must not pay for
        // per-transfer lines it did not ask for.
        let logger = Logger::new(None);
        assert!(!logger.debug_enabled());
        logger.set_debug(true);
        assert!(logger.debug_enabled());
        logger.set_debug(false);
        assert!(!logger.debug_enabled());
    }

    #[test]
    fn a_suppressed_debug_line_is_never_formatted() {
        // The closure is the point: `format!` of a per-block line, four thousand times,
        // for output nobody asked for.
        let logger = Logger::new(None);
        let mut formatted = 0_u32;
        logger.debug(|| {
            formatted += 1;
            String::new()
        });
        assert_eq!(formatted, 0);
        logger.set_debug(true);
        logger.debug(|| {
            formatted += 1;
            String::new()
        });
        assert_eq!(formatted, 1);
    }
}
