//! [`Engine`]: the object the page calls, and the exported surface around it.
//!
//! The shape is frozen and was agreed in writing before either side
//! was written, so `web/src/tdfu.js` could be built against it while this was being
//! built. Nothing here adds a method or a field to it.
//!
//! ```js
//! import init, { Engine, variantNames, version } from './wasm/tdfu_wasm.js';
//! await init();
//! const engine = new Engine({ log(line, level) {}, progress(phase, done, total) {} });
//! ```
//!
//! # Three properties the seam states and this module has to keep
//!
//! * **Nothing throws synchronously.** Every operation returns a promise, and every
//!   failure (a bad option, a device id that was never issued, a browser without
//!   WebUSB) is a rejection of it. The constructor is the one exception by nature, and
//!   it is total: an options object that is missing, `undefined`, or carries something
//!   that is not a function produces an engine with no callbacks rather than a throw.
//! * **A panic rejects, and never hangs.** See [`crate::panic_edge`]; [`settle`] is where
//!   each promise registers with it.
//! * **`message` is `tdfu_core::Error`'s `Display`, exactly.** Advice that is not part of
//!   the failure (the udev-rule hint, the no-WebUSB hint) goes out on the `log`
//!   callback at `warn` instead of being appended to it, so a page that renders the
//!   message has one wording and it is `tdfu-core`'s.
//!
//! The generated `tdfu_wasm.d.ts` is a **description of** that seam, not the seam itself:
//! every argument crosses as a `JsValue` and [`crate::options`] is what refuses a wrong
//! type at runtime. [`SEAM_TYPES`] writes the frozen shapes into it so an author reading
//! the declarations sees them rather than `any`; `start()` also appears there,
//! one name beyond the seam's three, because `#[wasm_bindgen(start)]` exports it whether or
//! not anyone wants it. It is idempotent and nothing should call it twice.
//!
//! # The device stays open, and it is opened once
//!
//! Handles live in [`Inner::open`] for the page's lifetime. That is the shim's rule and
//! its reason, in its own comment at `web/src/libusb-webusb.js:199-208`: do not actually
//! close the WebUSB device, keep it open for reuse, because closing and reopening races
//! in the browser. (Paraphrased rather than quoted: the source's punctuation is not this
//! tree's, and a quotation that silently re-punctuates is worse than a summary.) It also
//! costs nothing, because `USBDevice.open()` on an already-open device is what the shim
//! short-circuited too.
//!
//! **Opening is single-flight**, and an audit found why it has to be. Every operation is
//! a promise handed straight back to the page, and the `wasmBusy` mutex the
//! shipped page serialised them with is gone, so two operations really can be in flight on
//! one id. Before this, both would find nothing in the map, both would `await
//! backend.open`, and the
//! second `insert` would win: two [`WebUsbTransport`]s over one `USBDevice`, with
//! independent claim and configuration state, only one of them reachable. The first one's
//! `release_interface` would then drop the browser's claim while the second still recorded
//! one, and the second's next transfer would come back `InvalidStateError` with
//! `holds_claim()` true, which reads as `Busy` ("in use by another driver, process or
//! handle") rather than `NotClaimed`, and `Busy` is outside the reset-and-retry
//! recoverable class. So [`Inner::transport`] registers the open in flight and a second caller waits
//! on it.
//!
//! What that does **not** promise is that two operations on one device are safe. The
//! handle is shared correctly; the gadget's own state machine is not re-entrant, and two
//! overlapping `write`s would interleave `DNLOAD` transactions on it. The engine does not
//! serialise operations and does not pretend to: the page owns that, as it always has.

use core::cell::RefCell;
use core::future::Future;
use std::collections::HashMap;
use std::rc::Rc;

use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use tdfu_core::model::{Stage, Variant};
use tdfu_core::{Error, Progress, Result, ops};
use tdfu_usb::{LocalUsbBackend, LocalUsbTransport, UsbErrorKind};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::clock::JsSleeper;
use crate::log::{Level, Logger};
use crate::options;
use crate::usb::{DeviceTable, NO_WEBUSB_HINT, WebUsbBackend, WebUsbTransport};
use crate::{panic_edge, shape};

/// Module initialisation, run by `await init()`.
///
/// The panic hook is installed here rather than in `Engine::new` because a panic can
/// happen in [`version`] or [`variant_names`] too, and because an engine that has to be
/// constructed before panics are handled is an engine whose constructor is the one
/// unprotected call.
///
/// `await init()` calls it: the generated glue's `__wbg_finalize_init` invokes
/// `wasm.__wbindgen_start()` before it returns, so the hook is in place before the page
/// can reach anything. `wasm-bindgen` also re-exports it under this name, which is its
/// convention rather than a seam entry: nothing should call it a second time, and doing
/// so would only reinstall the same hook.
///
/// Private in Rust because nothing in this crate calls it either.
#[wasm_bindgen(start)]
fn start() {
    panic_edge::install();
}

/// `version()`: `"2.0.0-alpha.0 (a1b2c3d)"`.
#[wasm_bindgen(js_name = version)]
#[must_use]
pub fn version() -> String {
    crate::version_line()
}

/// `variantNames()`: the frozen 59-entry ordinal table a `DISCOVER` reply indexes.
///
/// Ordinal *n* at index *n*, for `remote.js` to render a `DISCOVER` entry's variant byte.
#[wasm_bindgen(js_name = variantNames)]
#[must_use]
pub fn variant_names() -> Vec<String> {
    crate::variant_name_table().into_iter().map(ToOwned::to_owned).collect()
}

/// The frozen seam's shapes, written into the generated `.d.ts`.
///
/// `wasm-bindgen` types every `JsValue` argument and every promise's resolution as `any`,
/// so the generated declarations carried none of the seam: not `DeviceInfo`'s five keys,
/// not `Detection`'s, not `{variant, spl, uboot}`, not that `read` resolves a
/// `Uint8Array`. The names and arities were right and the `wasm-bindgen-test` suite pins
/// the shapes, so nothing was broken, but a `.d.ts` that says `any` is a file an author
/// reads instead of the seam. These declarations are the seam, in TypeScript.
///
/// They are **documentation, not enforcement**: the exported methods still take `JsValue`,
/// and `options.rs` is what refuses a wrong type at runtime, naming the field and what
/// arrived. A `.d.ts` cannot check a `Uint8Array` that came out of a `fetch`.
#[wasm_bindgen(typescript_custom_section)]
const SEAM_TYPES: &'static str = r#"
export type Stage = "bootrom" | "dfu" | "firmware" | "unknown";
export type Level = "debug" | "info" | "warn" | "error";

/** One authorised device. `id` is an opaque handle for as long as the device stays
 *  plugged in; a bootstrap re-enumerates it and `discover()` then issues a new one. */
export interface DeviceInfo {
    id: number;
    vid: number;
    pid: number;
    stage: Stage;
    /** The loader name once `detect` has run, else null: never a guess. */
    variant: string | null;
}

/** What three bootrom register reads decided. */
export interface Detection {
    variant: string | null;
    /** The chip as detected, e.g. "T31ZX"; null when detection did not settle. */
    chip: string | null;
    family: string | null;
    dram: string | null;
    evidence: string;
    /** How well the answer is known; non-null whenever it needs saying. */
    caveat: string | null;
}

export interface EngineCallbacks {
    log?(line: string, level: Level): void;
    progress?(phase: string, done: number, total: number | null): void;
}

/** Both or neither for `spl`/`uboot`; `variant` undefined means detect. */
export interface BootstrapOptions {
    variant?: string;
    spl?: Uint8Array;
    uboot?: Uint8Array;
}

/** `alt` as a name or a `bAlternateSetting`; absent is the default alt. */
export interface WriteOptions {
    alt?: string | number;
    image: Uint8Array;
    verify?: boolean;
}

export interface ReadOptions {
    alt?: string | number;
    /** The first `size` bytes; absent reads the whole alt. */
    size?: number;
}

export interface VerifyOptions {
    alt?: string | number;
    image: Uint8Array;
}
"#;

/// What the page holds: one engine per page, driving every authorized device.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Engine {
    inner: Rc<Inner>,
}

/// The engine's state, shared with every in-flight operation.
#[derive(Debug)]
struct Inner {
    backend: WebUsbBackend,
    table: DeviceTable,
    log: Logger,
    progress: Option<Function>,
    clock: JsSleeper,
    /// Open transports, by device id. See the module doc: a device is opened once.
    open: RefCell<HashMap<u32, Rc<WebUsbTransport>>>,
    /// Opens in flight, by device id: a promise that resolves when the open has finished,
    /// whether it worked or not. The single-flight half of the module doc.
    opening: RefCell<HashMap<u32, Promise>>,
    /// What `detect` decided, so `DeviceInfo.variant` can carry it afterwards.
    detected: RefCell<HashMap<u32, Variant>>,
}

impl Inner {
    /// Relay one `tdfu-core` progress event to the page.
    fn on_progress(&self, event: &Progress) {
        relay(&self.log, event, |phase, done, total| {
            self.emit_progress(phase, done, total);
        });
    }

    /// `progress(phase, done, total)`, with `total` as a number or null.
    fn emit_progress(&self, phase: &str, done: u64, total: Option<u64>) {
        let Some(progress) = self.progress.as_ref() else { return };
        let arguments = Array::of3(
            &JsValue::from_str(phase),
            &js_number(done),
            &total.map_or(JsValue::NULL, js_number),
        );
        let _ignored = progress.apply(&JsValue::UNDEFINED, &arguments);
    }

    /// The device, opening it the first time it is asked for, **once**.
    ///
    /// See the module doc for what two concurrent opens cost. The shape is: take the
    /// handle if there is one; otherwise wait out any open already in flight and look
    /// again; otherwise register this call as the open in flight and do it. Every borrow
    /// is taken and dropped before an `.await`, which is what keeps a second caller from
    /// finding the `RefCell` held.
    async fn transport(self: &Rc<Self>, id: u32) -> Result<Rc<WebUsbTransport>> {
        loop {
            if let Some(transport) = self.opened(id) {
                return Ok(transport);
            }
            let Some(in_flight) = self.opening(id) else { break };
            // Resolved by the ticket below, on success and on failure alike: the loop
            // then either finds the handle or takes the open for itself.
            let _ignored = JsFuture::from(in_flight).await;
        }
        let ticket = OpenTicket::register(self, id);
        let transport = Rc::new(self.backend.open(&id).await?);
        if let Ok(mut open) = self.open.try_borrow_mut() {
            open.insert(id, Rc::clone(&transport));
        }
        // **After** the insert, not before: dropping the ticket is what wakes a waiter,
        // and a waiter woken before the handle is in the map would start a second open.
        // The `?` above drops it too, which is the failure path: the waiter wakes, finds
        // nothing, and takes the open for itself rather than inheriting an error it
        // cannot see.
        drop(ticket);
        Ok(transport)
    }

    /// The open handle for `id`, if there is one.
    fn opened(&self, id: u32) -> Option<Rc<WebUsbTransport>> {
        self.open.try_borrow().ok().and_then(|open| open.get(&id).cloned())
    }

    /// The promise of an open already in flight for `id`, if there is one.
    fn opening(&self, id: u32) -> Option<Promise> {
        self.opening
            .try_borrow()
            .ok()
            .and_then(|opening| opening.get(&id).cloned())
    }

    /// Turn a failure into the page's rejection value, saying anything actionable on the
    /// log first.
    fn reject_with(&self, error: &Error) -> JsValue {
        if let Some(hint) = hint_for(error) {
            self.log.warn(hint);
        }
        self.log.line(Level::Error, &error.to_string());
        shape::error_for(error)
    }
}

/// One open in flight, and the promise a second caller is waiting on.
///
/// The clearing is a [`Drop`] rather than a method so that **every** way out of the open
/// wakes the waiters: the `?` on a failed open, and the success path alike. A ticket that
/// leaked would leave a device permanently unopenable, which is worse than the bug it is
/// here to fix.
struct OpenTicket {
    inner: Rc<Inner>,
    id: u32,
    done: Option<Function>,
}

impl OpenTicket {
    /// Register `id` as opening, and hand back the ticket that clears it.
    fn register(inner: &Rc<Inner>, id: u32) -> Self {
        // `Promise::new` runs its executor synchronously and exactly once, so `resolve`
        // is in hand by the time this returns; the `Option` is what lets a once-only
        // body live in the `FnMut` the constructor takes (as [`settle`] does).
        let mut done = None;
        let promise = Promise::new(&mut |resolve, _reject| done = Some(resolve));
        if let Ok(mut opening) = inner.opening.try_borrow_mut() {
            opening.insert(id, promise);
        }
        Self {
            inner: Rc::clone(inner),
            id,
            done,
        }
    }
}

impl Drop for OpenTicket {
    fn drop(&mut self) {
        if let Ok(mut opening) = self.inner.opening.try_borrow_mut() {
            opening.remove(&self.id);
        }
        // The entry goes first: a waiter woken here re-reads the map, and finding the
        // promise still in it would put it straight back to sleep on a promise nobody
        // will resolve again.
        if let Some(done) = self.done.take() {
            let _ignored = done.call0(&JsValue::UNDEFINED);
        }
    }
}

/// The `progress(phase, done, total)` arguments an event carries, or `None` when it is
/// not a progress event.
///
/// Pure, so the frozen seam's progress mapping is host-pinned: `phase` is the
/// `Progress::Phase`'s own name, a bare phase change reports `0` done, and `total` is
/// `None` where core does not know it (an alt whose size the gadget never named).
#[must_use]
pub fn progress_of(event: &Progress) -> Option<(String, u64, Option<u64>)> {
    match event {
        Progress::Phase(phase) => Some((phase.to_string(), 0, None)),
        Progress::Bytes { phase, done, total } => Some((phase.to_string(), *done, *total)),
        _ => None,
    }
}

/// Send one core event to the channel it belongs on.
///
/// Free rather than a method on [`Inner`] so a host test can drive it with a bare
/// [`Logger`]: the `Inner` around it holds a WebUSB backend, which does not exist off the
/// wasm target, and the routing is the part worth pinning.
///
/// Three channels, and the order is the rule: a [`Progress::Debug`] is core's protocol
/// narration and goes to the `debug` channel, which `setDebug(true)` opens and the default
/// drops; a [`Progress::Note`] goes to `info`, which every visitor sees; everything else
/// is the bar. A narration line routed to `info` would put four thousand lines in the page
/// for a 16 MiB write, and one routed to the bar would vanish.
fn relay(log: &Logger, event: &Progress, bar: impl FnOnce(&str, u64, Option<u64>)) {
    if let Some(text) = debug_of(event) {
        // The closure is what keeps a suppressed line free: `Logger::debug` never calls it
        // with debug off.
        log.debug(|| text.to_owned());
    } else if let Some(text) = note_of(event) {
        log.info(text);
    } else if let Some((phase, done, total)) = progress_of(event) {
        bar(&phase, done, total);
    }
}

/// The protocol narration an event carries, or `None`.
///
/// Core narrates its own steps as [`Progress::Debug`] so that every frontend's debug
/// switch shows the same lines (`progress.rs`). Before it did, `setDebug(true)` showed
/// only the handful of lines this crate writes itself.
#[must_use]
pub fn debug_of(event: &Progress) -> Option<&str> {
    match event {
        Progress::Debug(text) => Some(text),
        _ => None,
    }
}

/// The log line an event carries, or `None`.
///
/// Completion lines, both retry announcements and the detection caveat all arrive as
/// [`Progress::Note`], emitted by core so every frontend gets them from one place
/// rather than each one writing its own. They are log lines, not progress: routing them to the progress
/// bar would drop them, and a successful local write that printed nothing at all is the
/// failure this routing exists to prevent.
#[must_use]
pub fn note_of(event: &Progress) -> Option<&str> {
    match event {
        Progress::Note(text) => Some(text),
        _ => None,
    }
}

/// The standing advice a failure earns, or none.
///
/// Hints are about something the operator has to go and do, and none of them is part of
/// the failure: they go out on the `log` callback at `warn` so the JS `Error.message`
/// stays exactly `tdfu_core::Error`'s `Display`.
///
/// **Keyed on the pipe as well as the kind**, which an audit found this crate needed.
/// This backend produces
/// [`UsbErrorKind::Unsupported`] for three different things, and only one of them is a
/// browser that cannot do WebUSB at all:
///
/// | where it came from | pipe | what to tell the operator |
/// |---|---|---|
/// | no `navigator.usb` on the global | [`Pipe::Device`] | [`NO_WEBUSB_HINT`]: use Chromium, over https, or switch to remote mode |
/// | a standard control request WebUSB refuses | a control pipe | [`STANDARD_REQUEST_HINT`]: nothing the operator can do, and the transport has already named the trait method to use |
/// | a `NotSupportedError` from the browser | whichever pipe raised it | the same, because it is the browser refusing one call rather than refusing WebUSB |
///
/// The first is unreachable from `tdfu-core` today (it issues `GET_DESCRIPTOR` for
/// CONFIGURATION and STRING only, both answered locally, and no standard control OUT at
/// all), so this was a coupling rather than a live wrong hint. It is still worth
/// separating: "use a Chromium-based browser" is exactly the wrong thing to print in
/// Chrome.
///
/// Pure and host-tested, because getting it wrong means printing udev advice for a
/// stalled endpoint, or printing nothing for the one failure a udev rule fixes, and
/// a refused open is kept distinct from every other failure precisely so it can be told.
#[must_use]
pub fn hint_for(error: &Error) -> Option<&'static str> {
    let usb = usb_error(error)?;
    match usb.kind() {
        UsbErrorKind::AccessDenied => Some(crate::ACCESS_DENIED_HINT),
        UsbErrorKind::Unsupported if matches!(usb.pipe(), tdfu_usb::Pipe::Device) => Some(NO_WEBUSB_HINT),
        UsbErrorKind::Unsupported => Some(STANDARD_REQUEST_HINT),
        _ => None,
    }
}

/// What to tell an operator whose *request* the browser refused, rather than whose
/// browser has no WebUSB.
///
/// A constant on one line, for the same reason [`crate::ACCESS_DENIED_HINT`] is
/// (one literal, one line, no `rustfmt` join). It names no action because there is none
/// for the operator to take: the transport has already logged which trait method the caller
/// should have used, and this is the line that keeps the operator from being sent to
/// install a different browser.
pub const STANDARD_REQUEST_HINT: &str = "WebUSB refuses standard control requests, so this one could not be sent; the browser itself is fine and this is a bug in the tool rather than something to fix on this machine";

/// The [`UsbError`](tdfu_usb::UsbError) inside a `tdfu_core::Error`, if the failure came
/// from the wire.
///
/// Both wrappers, because `Error::UsbWhile` is A3's context wrapper and adding context
/// must not change what a failure earns.
#[must_use]
pub fn usb_error(error: &Error) -> Option<&tdfu_usb::UsbError> {
    match error {
        Error::Usb(usb) => Some(usb),
        Error::UsbWhile { source, .. } => Some(source),
        _ => None,
    }
}

/// The `UsbErrorKind` inside a `tdfu_core::Error`, if the failure came from the wire.
///
/// Pure and host-tested: it decides which of the standing hints an operator sees, and
/// getting it wrong means either printing udev advice for a stalled endpoint or printing
/// nothing for the one failure a udev rule fixes.
#[must_use]
pub fn usb_kind(error: &Error) -> Option<&UsbErrorKind> {
    usb_error(error).map(tdfu_usb::UsbError::kind)
}

#[wasm_bindgen]
impl Engine {
    /// `new Engine({ log, progress })`, with both callbacks optional.
    ///
    /// A callback given as a method shorthand (`{ log(line, level) {} }`) is bound to the
    /// options object, so `this` inside it is what the author wrote it against. Anything
    /// that is not a function is ignored rather than refused: the constructor is the one
    /// place that could throw synchronously, and the seam says nothing does.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new(callbacks: &JsValue) -> Self {
        let log = callback(callbacks, "log");
        let progress = callback(callbacks, "progress");
        let logger = Logger::new(log);
        let table = DeviceTable::new();
        Self {
            inner: Rc::new(Inner {
                backend: WebUsbBackend::new(table.clone(), logger.clone()),
                table,
                log: logger,
                progress,
                clock: JsSleeper::new(),
                open: RefCell::new(HashMap::new()),
                opening: RefCell::new(HashMap::new()),
                detected: RefCell::new(HashMap::new()),
            }),
        }
    }

    /// `setDebug(true)`: what the CLI's `--debug` shows, through `log(_, "debug")`.
    #[wasm_bindgen(js_name = setDebug)]
    pub fn set_debug(&self, on: bool) {
        self.inner.log.set_debug(on);
        self.inner
            .log
            .debug(|| format!("debug logging on; {}", crate::version_line()));
    }

    /// `requestDevice()`: the browser's chooser, with the Ingenic filters.
    ///
    /// Needs a user gesture. Resolves a `DeviceInfo`, or `null` when the chooser was
    /// dismissed.
    #[wasm_bindgen(js_name = requestDevice)]
    pub fn request_device(&self) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = inner.backend.request_device().await.map_err(Error::from).map(|picked| {
                picked.map_or(JsValue::NULL, |(id, descriptors)| {
                    shape::device_info(id, &descriptors, variant_name(&inner, id))
                })
            });
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `discover()`: every already-authorized Ingenic device, as `DeviceInfo[]`.
    pub fn discover(&self) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = inner.backend.list().await.map_err(Error::from).map(|devices| {
                devices
                    .into_iter()
                    .map(|found| shape::device_info(found.id, &found.descriptors, variant_name(&inner, found.id)))
                    .collect::<Array>()
                    .into()
            });
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `detect(id)`: three bootrom register reads, nothing uploaded and nothing executed.
    pub fn detect(&self, id: u32) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let device = inner.transport(id).await?;
                let detection = ops::detect(&*device, &inner.clock).await?;
                if let (Some(variant), Ok(mut detected)) = (detection.variant(), inner.detected.try_borrow_mut()) {
                    detected.insert(id, variant);
                }
                // The qualification goes out with the answer, always. The
                // page gets it in the value too; putting it on the log as well is what
                // makes it hard to render a resolved variant without the sentence that
                // says how well it is known (pinned by
                // `cli_surfaces_the_detection_caveat`).
                if let Some(caveat) = shape::caveat_text(&detection) {
                    inner.log.info(&caveat);
                } else if let Some(provenance) = detection.caveat() {
                    // A documented-but-unseen row: information about the table, not a
                    // warning about this device, so debug only (decided 2026-09-03).
                    inner.log.debug(|| provenance);
                }
                Ok(shape::detection(&detection))
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `bootstrap(id, { variant, spl, uboot })`: stage 1, a settle, then U-Boot.
    pub fn bootstrap(&self, id: u32, options: JsValue) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let variant = options::variant_of(options::string_field(&options, "variant").as_deref())?;
                let spl = options::bytes_field(&options, "spl")?;
                let uboot = options::bytes_field(&options, "uboot")?;
                let device = inner.transport(id).await?;
                let Some((spl, uboot)) = options::blob_pair(spl, uboot)? else {
                    return Err(Error::Invalid(options::missing_loader_message(
                        naming_variant(&inner, id, variant, &device).await,
                    )));
                };
                if let Some(variant) = variant {
                    inner
                        .log
                        .debug(|| format!("bootstrapping as {} with the loader bytes given", variant.loader_dir()));
                }
                let mut sink = sink(&inner);
                ops::bootstrap(&*device, &inner.clock, &spl, &uboot, &mut sink).await?;
                Ok(JsValue::UNDEFINED)
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `write(id, { alt, image, verify })`.
    ///
    /// `verify` runs `ops::verify` after the download, which is what
    /// `thingino-dfu -w image --verify` does: a second pass that reads the flash back,
    /// not a claim about the first one.
    pub fn write(&self, id: u32, options: JsValue) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let alt = options::alt_selection(options::alt_field(&options, "alt")?)?;
                let image = required_image(&options)?;
                let verify = options::bool_field(&options, "verify");
                let device = inner.transport(id).await?;
                let mut sink = sink(&inner);
                ops::write(&*device, &inner.clock, &alt, &image, &mut sink).await?;
                if verify {
                    ops::verify(&*device, &inner.clock, &alt, &image, &mut sink).await?;
                }
                Ok(JsValue::UNDEFINED)
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `read(id, { alt, size })`: a `Uint8Array` of the whole alt, or its first `size`
    /// bytes.
    pub fn read(&self, id: u32, options: JsValue) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let alt = options::alt_selection(options::alt_field(&options, "alt")?)?;
                let limit = options::size_limit(options::number_field(&options, "size"))?;
                let device = inner.transport(id).await?;
                let mut sink = sink(&inner);
                // `ops::read` streams into a `Write`, so its own peak is one block above
                // whatever the sink holds rather than a second copy of the image (the
                // 256 MiB T40XP case). That is a property of
                // `ops::read` and **not** of this operation: a page that wants a file to
                // save has to have the bytes, and the `Uint8Array` handover below makes a
                // second whole copy in the JS heap, so a 256 MiB read peaks near 512 MiB
                // across the two heaps. Unavoidable without a streaming sink on the JS
                // side, which the frozen seam does not have.
                let mut buffer = Vec::new();
                ops::read(&*device, &inner.clock, &alt, limit, &mut buffer, &mut sink).await?;
                Ok(JsValue::from(Uint8Array::from(buffer.as_slice())))
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `verify(id, { alt, image })`: read the flash back and compare block by block, to the image length.
    pub fn verify(&self, id: u32, options: JsValue) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let alt = options::alt_selection(options::alt_field(&options, "alt")?)?;
                let image = required_image(&options)?;
                let device = inner.transport(id).await?;
                let mut sink = sink(&inner);
                ops::verify(&*device, &inner.clock, &alt, &image, &mut sink).await?;
                Ok(JsValue::UNDEFINED)
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `erase(id)`: the wipe token on the `erase` alt, then a blank check.
    pub fn erase(&self, id: u32) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let device = inner.transport(id).await?;
                let mut sink = sink(&inner);
                ops::erase(&*device, &inner.clock, &mut sink).await?;
                Ok(JsValue::UNDEFINED)
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `reboot(id)`: the reboot token on its own alt, then the post-ZLP poll whose failure is the reset.
    pub fn reboot(&self, id: u32) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let device = inner.transport(id).await?;
                let mut sink = sink(&inner);
                ops::reboot(&*device, &inner.clock, &mut sink).await?;
                Ok(JsValue::UNDEFINED)
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }

    /// `diag(id)`: the eFuse report, as the text `--diag` prints.
    pub fn diag(&self, id: u32) -> Promise {
        let inner = Rc::clone(&self.inner);
        settle(async move {
            let outcome = async {
                let device = inner.transport(id).await?;
                let report = ops::diag(&*device, &inner.clock).await?;
                Ok(JsValue::from_str(&report.to_string()))
            }
            .await;
            outcome.map_err(|error| inner.reject_with(&error))
        })
    }
}

/// Not a `#[wasm_bindgen]` block, on purpose.
///
/// The JS surface is frozen exactly, and a `#[wasm_bindgen] impl` exports
/// every public method in it. This one is for Rust callers (the crate's own
/// `wasm-bindgen-test` suite), so it lives outside, where it cannot become a seam entry
/// `tdfu.js` was never told about.
impl Engine {
    /// How many devices have been issued an id.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.inner.table.len()
    }

    /// The device table this engine issues ids from.
    ///
    /// The only way into it from outside is `requestDevice()` or `discover()`, and both
    /// need a real `navigator.usb`, which Node does not have. Exposing it here is what
    /// lets the suite put a scripted `USBDevice` behind an id and drive whole operations
    /// against it, single-flight opens included. Outside the `#[wasm_bindgen]` block, so it is a
    /// Rust-only accessor and not a seam entry `tdfu.js` was never told about.
    #[must_use]
    pub fn table(&self) -> &DeviceTable {
        &self.inner.table
    }
}

/// A promise that this crate's panic edge knows about.
///
/// Every exported operation goes through here. The `reject` half is registered with
/// [`panic_edge`] before the future is spawned and unregistered the moment it settles, so
/// a panic on any poll after that point still rejects this promise rather than leaving it
/// pending for ever, which, on a `panic = "abort"` target, is what would otherwise
/// happen (see that module for the whole argument).
fn settle<F>(future: F) -> Promise
where
    F: Future<Output = core::result::Result<JsValue, JsValue>> + 'static,
{
    // `Promise::new` takes `&mut dyn FnMut`, and the executor runs exactly once,
    // synchronously; the `Option` is what lets a once-only body live in a `FnMut`.
    let mut slot = Some(future);
    Promise::new(&mut move |resolve, reject| {
        let Some(future) = slot.take() else { return };
        let ticket = panic_edge::register(&reject);
        spawn_local(async move {
            let outcome = future.await;
            ticket.settle();
            let _ignored = match outcome {
                Ok(value) => resolve.call1(&JsValue::UNDEFINED, &value),
                Err(error) => reject.call1(&JsValue::UNDEFINED, &error),
            };
        });
    })
}

/// A progress sink over the engine's callbacks.
fn sink(inner: &Rc<Inner>) -> impl FnMut(Progress) + use<> {
    let inner = Rc::clone(inner);
    move |event| inner.on_progress(&event)
}

/// The loader name to put in a `DeviceInfo`, given what detection has settled so far.
///
/// Pure over the table so the lookup is host-testable: a mutation that answered `None`
/// here would make `DeviceInfo.variant` permanently `null`, the page showing no SoC
/// after a successful detect, and nothing else would notice.
#[must_use]
pub fn remembered_name<S: core::hash::BuildHasher>(
    detected: &HashMap<u32, Variant, S>,
    id: u32,
) -> Option<&'static str> {
    detected.get(&id).map(|variant| variant.loader_dir())
}

/// The loader name `detect` settled on for this device, if it has run.
fn variant_name(inner: &Rc<Inner>, id: u32) -> Option<&'static str> {
    inner
        .detected
        .try_borrow()
        .ok()
        .and_then(|detected| remembered_name(&detected, id))
}

/// What is already known about a device's variant, before any bus traffic.
///
/// `given` is `--cpu`'s equivalent and wins outright: an operator who named a variant is
/// not overruled by a detection. Otherwise whatever a previous `detect` remembered.
/// `None` means nobody knows yet, and only then is a read worth making.
#[must_use]
pub fn known_variant(given: Option<Variant>, remembered: Option<Variant>) -> Option<Variant> {
    given.or(remembered)
}

/// The variant to name in a "bootstrap needs the loader bytes" refusal.
///
/// The one place `variant: undefined` means "auto-detect" and can act on it. Detection
/// is three register reads and executes nothing, so it is safe to run for a
/// better message, but only against a device whose descriptor says it is a bootrom,
/// which is known already and costs no traffic to check. Against anything else the
/// generic message is the honest one.
async fn naming_variant(
    inner: &Rc<Inner>,
    id: u32,
    given: Option<Variant>,
    device: &Rc<WebUsbTransport>,
) -> Option<Variant> {
    let remembered = inner
        .detected
        .try_borrow()
        .ok()
        .and_then(|detected| detected.get(&id).copied());
    if let Some(known) = known_variant(given, remembered) {
        return Some(known);
    }
    if ops::classify(device.descriptors()) != Some(Stage::Bootrom) {
        return None;
    }
    let detection = ops::detect(&**device, &inner.clock).await.ok()?;
    let variant = detection.variant();
    if let (Some(variant), Ok(mut detected)) = (variant, inner.detected.try_borrow_mut()) {
        detected.insert(id, variant);
    }
    variant
}

/// The `image` field, which `write` and `verify` cannot do without.
fn required_image(options: &JsValue) -> Result<Vec<u8>> {
    options::bytes_field(options, "image")?
        .ok_or_else(|| Error::Invalid("image is required: pass the firmware as a Uint8Array".to_owned()))
}

/// One callback out of the constructor's options object, bound to it.
///
/// `Function::bind` is what makes `{ log(line, level) { this.lines.push(line); } }` work:
/// read as a bare property it would be called with `this === undefined`.
fn callback(callbacks: &JsValue, name: &str) -> Option<Function> {
    let value = Reflect::get(callbacks, &JsValue::from_str(name)).ok()?;
    let function = value.dyn_ref::<Function>()?;
    Some(function.bind0(callbacks))
}

/// A byte count as a JS number.
///
/// `f64` rather than `u64`: a `u64` crosses the `wasm-bindgen` boundary as a `BigInt`,
/// and `done / total` in the page's progress bar would then be a `TypeError`, because mixing a
/// `BigInt` with a `Number` throws in JavaScript.
fn js_number(bytes: u64) -> JsValue {
    JsValue::from_f64(byte_count(bytes))
}

/// A byte count as an `f64`, exact for anything a flash image can be.
///
/// Split out because it is the only lossy conversion on the progress path and
/// `JsValue::from_f64` cannot be called on the host, so this is the half a host test can
/// reach. `2^53` bytes is 9 PB; the largest image this tool has moved is 256 MiB.
#[must_use]
pub fn byte_count(bytes: u64) -> f64 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "exact below 2^53, which is 9 PB; the page needs a Number, not a BigInt"
    )]
    let count = bytes as f64;
    count
}

#[cfg(test)]
mod tests {
    use super::{
        byte_count, debug_of, hint_for, known_variant, note_of, progress_of, relay, remembered_name, usb_kind,
    };
    use crate::log::Logger;
    use std::collections::HashMap;
    use tdfu_core::model::Variant;
    use tdfu_core::{Error, Phase, Progress};
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    #[test]
    fn a_phase_change_and_a_byte_count_both_reach_the_progress_callback() {
        // The seam says `progress(phase, done, total)`, where phase is the Progress
        // phase's name and total is a number or null.
        assert_eq!(
            progress_of(&Progress::Phase(Phase::Download)),
            Some(("download".to_owned(), 0, None))
        );
        assert_eq!(
            progress_of(&Progress::Bytes {
                phase: Phase::Verify,
                done: 4096,
                total: Some(16 * 1024 * 1024),
            }),
            Some(("verify".to_owned(), 4096, Some(16 * 1024 * 1024)))
        );
        // A read of an alt whose size the gadget never named: `total` is genuinely
        // unknown, and null is the honest answer rather than a guessed denominator.
        assert_eq!(
            progress_of(&Progress::Bytes {
                phase: Phase::Upload,
                done: 512,
                total: None,
            }),
            Some(("upload".to_owned(), 512, None))
        );
    }

    #[test]
    fn a_note_goes_to_the_log_and_never_to_the_progress_bar() {
        // A note routed to `progress` would be dropped, and a successful write that
        // printed nothing at all is the failure this routing exists to prevent.
        let note = Progress::Note("DFU download complete".to_owned());
        assert_eq!(note_of(&note), Some("DFU download complete"));
        assert_eq!(progress_of(&note), None);
        assert_eq!(note_of(&Progress::Phase(Phase::Erase)), None);
    }

    /// **The narration pin.** Core's [`Progress::Debug`] goes to the `debug` channel, the
    /// one `setDebug(true)` opens, and to neither `info` nor the bar.
    ///
    /// Routed to `info` it would put a line in the page for every visitor; routed to the
    /// bar it would vanish. The switch itself is `Logger`'s, off until the page asks
    /// (`log.rs`, `debug_is_off_until_it_is_asked_for`). Revert check: make `relay` send
    /// `Debug` to `log.info` and the second half fails.
    #[test]
    fn a_debug_line_goes_to_the_debug_channel_and_nowhere_else() {
        let narration = Progress::Debug("claiming alt 0 on interface 0".to_owned());
        assert_eq!(debug_of(&narration), Some("claiming alt 0 on interface 0"));
        assert_eq!(note_of(&narration), None, "never the info channel");
        assert_eq!(progress_of(&narration), None, "never the bar");
        assert_eq!(debug_of(&Progress::Note("done".to_owned())), None);
        assert_eq!(debug_of(&Progress::Phase(Phase::Upload)), None);

        // And the routing itself: the bar is told nothing for a narration line or a note,
        // and is told about a phase.
        let logger = Logger::new(None);
        assert!(!logger.debug_enabled(), "the page has to ask for detail first");
        let mut told: Vec<String> = Vec::new();
        for event in [narration, Progress::Note("done".to_owned())] {
            relay(&logger, &event, |phase, _, _| told.push(phase.to_owned()));
        }
        assert!(told.is_empty(), "{told:?}");
        relay(&logger, &Progress::Phase(Phase::Upload), |phase, done, total| {
            told.push(format!("{phase} {done} {total:?}"));
        });
        assert_eq!(told, ["upload 0 None"]);
    }

    #[test]
    fn each_hint_answers_the_one_failure_it_is_about() {
        // "the OS refused" is kept distinct from everything else because the fix
        // is a udev rule and not another cable. Printing it for a stalled endpoint would
        // send an operator to the wrong place; printing nothing for the real case leaves
        // them with no place at all.
        let denied = Error::Usb(UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device));
        assert_eq!(hint_for(&denied), Some(crate::ACCESS_DENIED_HINT));
        let unsupported = Error::Usb(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device));
        assert_eq!(hint_for(&unsupported), Some(crate::usb::NO_WEBUSB_HINT));

        // The same kind on a *control* pipe is WebUSB refusing one request,
        // not a browser without WebUSB, and "use a Chromium-based browser" is exactly the
        // wrong thing to print in Chrome.
        let refused = Error::Usb(UsbError::new(
            UsbErrorKind::Unsupported,
            Pipe::Control {
                direction: tdfu_usb::Direction::Out,
                request: 0x0B,
            },
        ));
        assert_eq!(hint_for(&refused), Some(super::STANDARD_REQUEST_HINT));
        assert_ne!(hint_for(&refused), hint_for(&unsupported));
        // And the wrapper does not change which one it is (A3).
        let wrapped = Error::UsbWhile {
            doing: "reading the configuration descriptor".to_owned(),
            source: UsbError::new(
                UsbErrorKind::Unsupported,
                Pipe::Control {
                    direction: tdfu_usb::Direction::In,
                    request: 0x06,
                },
            ),
        };
        assert_eq!(hint_for(&wrapped), Some(super::STANDARD_REQUEST_HINT));

        for quiet in [
            Error::Usb(UsbError::new(UsbErrorKind::Stall, Pipe::Device)),
            Error::NotDfu,
            Error::Invalid("no image".to_owned()),
        ] {
            assert_eq!(hint_for(&quiet), None, "{quiet} earned a hint");
        }
    }

    #[test]
    fn a_device_info_carries_the_loader_name_once_detection_has_run() {
        // Before detection there is nothing to say, and inventing a default is the `t31x`
        // guess rendered as a fact. After it, the page shows this string and
        // an operator types it back as `--cpu`.
        let mut detected = HashMap::new();
        assert_eq!(remembered_name(&detected, 0), None);
        detected.insert(0_u32, Variant::T41nq);
        assert_eq!(remembered_name(&detected, 0), Some("t41nq"));
        assert_eq!(
            remembered_name(&detected, 1),
            None,
            "one device's answer is not another's"
        );
    }

    #[test]
    fn a_named_variant_is_not_overruled_by_what_detection_remembered() {
        // `--cpu`'s rule: an operator who named a variant said so on purpose, often
        // because detection was `Ambiguous` about a shared T4x grade code.
        assert_eq!(
            known_variant(Some(Variant::T41lq), Some(Variant::T41nq)),
            Some(Variant::T41lq)
        );
        assert_eq!(known_variant(None, Some(Variant::T41nq)), Some(Variant::T41nq));
        assert_eq!(known_variant(Some(Variant::T31x), None), Some(Variant::T31x));
        assert_eq!(known_variant(None, None), None, "nobody knows yet: worth a read");
    }

    #[test]
    fn the_two_exported_free_functions_are_the_crate_tables() {
        // `version` and `variant_names` are one-line wrappers, and a wrapper is exactly
        // where a table quietly stops being the table: `tests.rs` pins
        // `version_line()` and `variant_name_table()`, and this pins that the exports
        // are still those. It is the only pure-Rust code in this crate that a browser
        // reaches and the host suite otherwise never calls.
        assert_eq!(super::version(), crate::version_line());
        assert_eq!(super::variant_names(), crate::variant_name_table());
        assert_eq!(super::variant_names().len(), 59);
    }

    #[test]
    fn a_byte_count_survives_the_trip_to_javascript() {
        // The progress bar divides `done` by `total`, so both have to arrive as
        // Numbers and both have to be exact at the sizes this tool moves. 256 MiB is the
        // largest read on record; 16 MiB is the usual flash.
        for (bytes, expected) in [
            (0_u64, 0.0_f64),
            (4096, 4096.0),
            (16 * 1024 * 1024, 16_777_216.0),
            (256 * 1024 * 1024, 268_435_456.0),
        ] {
            // `to_bits` rather than `==`: the point is that the conversion is *exact*,
            // and an approximate comparison would pass for a value that had lost a bit.
            assert_eq!(byte_count(bytes).to_bits(), expected.to_bits(), "{bytes}");
        }
    }

    #[test]
    fn a_usb_failure_is_recognised_through_both_wrappers() {
        // `Error::UsbWhile` is the context wrapper, and `is_recoverable` delegates
        // through it so that adding context cannot change a failure's class. The hint
        // this decides has to see through it too, or a claim refused by the OS while
        // "opening the DFU interface" would print no udev advice at all.
        let denied = UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device);
        assert_eq!(usb_kind(&Error::Usb(denied.clone())), Some(&UsbErrorKind::AccessDenied));
        assert_eq!(
            usb_kind(&Error::UsbWhile {
                doing: "claiming the DFU interface".to_owned(),
                source: denied,
            }),
            Some(&UsbErrorKind::AccessDenied)
        );
    }

    #[test]
    fn a_local_failure_has_no_usb_kind() {
        // A missing image or an ambiguous SoC must not print "install a udev rule".
        assert_eq!(usb_kind(&Error::NotDfu), None);
        assert_eq!(usb_kind(&Error::Invalid("no image".to_owned())), None);
    }
}
