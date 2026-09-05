//! The browser frontend: `tdfu-core` compiled to wasm, driving WebUSB.
//!
//! The web UI stays JavaScript; this crate is the engine underneath it,
//! replacing a 494-line hand-written libusb-to-WebUSB shim with a backend that
//! implements [`LocalUsbTransport`](tdfu_usb::LocalUsbTransport) directly.
//!
//! Two constraints shape everything here:
//!
//! * **The browser cannot block.** Every wait must go through a
//!   [`Sleeper`](tdfu_core::clock::Sleeper) backed by a JS timer, and
//!   [`BlockingClock`](tdfu_core::clock) is not compiled for wasm at all. Because every
//!   operation *takes* a clock, there is no second entry point that could quietly use
//!   the wrong one; an earlier implementation had eighteen `_with_clock` duplicates and
//!   several of them were not public, so the browser could not reach them.
//!   [`clock::JsSleeper`] is that clock, and `tests::clock_seam` pins that a write and a
//!   verify both run on it.
//! * **Panics must not cross the wasm boundary.** `wasm32-unknown-unknown` is
//!   `panic = "abort"` at this toolchain, so `catch_unwind` would catch nothing; see
//!   [`panic_edge`] for what is done instead and how it was checked.
//!
//! WebUSB also constrains the *protocol* surface: raw descriptors are unreadable, so the
//! configuration descriptor is rebuilt from the browser's parsed tree and the alt names
//! come from `interfaceName` rather than from a string read on the wire; the
//! DFU functional descriptor is stripped, so `wTransferSize` is synthesised as 4096, the
//! value every shipped loader advertises; and the port path is empty. `reset` is **not**
//! unsupported here: the browser exposes `USBDevice.reset()`; only Android has none. See [`usb`].
//!
//! # Layout
//!
//! | module | what it owns |
//! |---|---|
//! | [`usb`] | [`WebUsbBackend`]/[`WebUsbTransport`]: the frozen traits over `web-sys` |
//! | [`clock`] | the `setTimeout` [`Sleeper`](tdfu_core::clock::Sleeper) |
//! | [`log`] | the page's `log(line, level)` callback, as something the backend can hold |
//! | [`panic_edge`] | the panic hook, and how a panic becomes a rejected promise |
//! | [`options`] | the rules the JS options objects are parsed under, and the reading |
//! | [`shape`] | the JS-facing value shapes: `DeviceInfo`, `Detection`, the error |
//! | [`engine`] | the `Engine` the page calls, and the device-id table |
//!
//! Everything that can be decided without a JS runtime lives in a pure function that
//! compiles and is tested on the host; everything that touches `js_sys` or `web_sys` is
//! `wasm`-gated and tested under Node with `wasm-bindgen-test`. That split is why the
//! mapping tables, the option rules and the error shape have host tests at all.

// No `forbid(unsafe_code)` here, and it is not an oversight: `#[wasm_bindgen]` expands
// to `unsafe` blocks, so forbidding it would break the crate the moment the bindings
// land. Every hand-written line in this crate is safe; the generated glue is not ours.

// The panic edge is decided against a checked fact: `rustc --target
// wasm32-unknown-unknown --print cfg` prints `panic="abort"` on the pinned 1.95.0
// toolchain, so `catch_unwind` catches nothing there and `panic_edge` uses a hook plus a
// promise registry instead. If a future toolchain gives this target unwinding, that
// reasoning expires and the build says so rather than leaving a stale comment behind.
#[cfg(all(target_family = "wasm", panic = "unwind"))]
compile_error!(
    "wasm32 now unwinds: `panic_edge`'s hook-and-registry design was chosen because it could not. \
     Wrap each exported entry in `std::panic::catch_unwind` instead, or delete this guard after \
     deciding the hook is still the better edge."
);

pub mod clock;
pub mod engine;
pub mod log;
pub mod options;
pub mod panic_edge;
pub mod shape;
pub mod usb;

#[cfg(test)]
mod tests;

pub use engine::Engine;
pub use tdfu_core::{Detection, Error, Progress, Variant, clock::Sleeper, ops};
pub use tdfu_usb::{LocalUsbBackend, LocalUsbTransport, UsbError};
pub use usb::{DeviceTable, WebUsbBackend, WebUsbTransport};

/// The crate version, from [`tdfu_core::build::VERSION`]: one workspace version, one reader of it.
pub const VERSION: &str = tdfu_core::build::VERSION;

/// The revision this module was built from, or `unknown`. From [`tdfu_core::build::HASH`],
/// the one reader of `TDFU_GIT_HASH`, shared with the CLI and the daemon so the three
/// frontends cannot report different builds. That module's doc explains why there is no
/// `build.rs`.
pub const BUILD: &str = tdfu_core::build::HASH;

/// What to tell an operator whose browser or OS refused the device, **once**.
///
/// A constant on one line rather than error text, exactly as
/// [`tdfu_usb::native::ACCESS_DENIED_HINT`] is: an earlier implementation printed the same
/// advice twice in two wordings, one of them carrying a 14-space gap from a `rustfmt`
/// string join. One literal, one line, no join.
///
/// It is emitted through the engine's `log` callback at `warn` the moment a
/// [`UsbErrorKind::AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied) is converted for
/// the page, so the JS `Error.message` stays exactly `tdfu_core::Error`'s `Display` (the
/// frozen seam) and the advice still reaches the operator.
pub const ACCESS_DENIED_HINT: &str = "the browser or the OS refused USB access: on Linux add a udev rule for the Ingenic vendor IDs (SUBSYSTEM==\"usb\", ATTR{idVendor}==\"a108\", MODE=\"0666\", TAG+=\"uaccess\" and SUBSYSTEM==\"usb\", ATTR{idVendor}==\"601a\", MODE=\"0666\", TAG+=\"uaccess\") and replug, on Windows install the WinUSB driver with Zadig, then reconnect";

/// The version line the page shows: `2.0.0-alpha.0 (a1b2c3d)`.
///
/// The banner text without the program name (from [`tdfu_core::build::version_line`]),
/// because the page already knows what it is running.
#[must_use]
pub fn version_line() -> String {
    tdfu_core::build::version_line()
}

/// Every loader name in the frozen 59-entry ordinal table the `DISCOVER` reply indexes.
///
/// Ordinal *n* is at index *n*, so `remote.js` can render a `DISCOVER` entry's variant
/// byte by indexing. `WireVariant::UNKNOWN` (`0xFF`) is outside the table and outside
/// this list by construction: it is not an ordinal, it is the absence of one, and
/// putting a name on it would render a guess as a fact.
///
/// A hole in the table would be a `tdfu-proto` bug rather than something to paper over
/// here, and [`tests::variant_names_cover_the_whole_table`] fails if one appears.
#[must_use]
pub fn variant_name_table() -> Vec<&'static str> {
    (0..tdfu_proto::WireVariant::COUNT)
        .map(|ordinal| tdfu_proto::WireVariant(ordinal).name().unwrap_or_default())
        .collect()
}
