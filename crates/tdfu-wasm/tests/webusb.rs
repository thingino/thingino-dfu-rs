//! The WebUSB transport, against a scripted `USBDevice`.
//!
//! Scripted the way `tdfu_usb::mock::MockTransport` is scripted, and for the same reason:
//! a double that models a device rather than replaying a script has to be checked against
//! the device's source. Three defects in an earlier gadget emulator silently removed
//! coverage everywhere downstream, the last of them making a whole recovery class
//! unfalsifiable. This one replays; the device model is `FakeGadget`'s job, one layer
//! up.
//!
//! It runs under Node, where there is no `navigator.usb` at all, which is exactly why
//! [`WebUsbTransport`] takes an already-opened `USBDevice` rather than reaching for the
//! global. The one part that cannot be reached from here is
//! [`WebUsbBackend`](tdfu_wasm::WebUsbBackend)'s `list`/`open`/`request_device`, which
//! need a real `navigator.usb`; they are covered by a WebUSB run on a desktop with a
//! camera attached, which no headless run can do.

#![cfg(target_family = "wasm")]

use core::time::Duration;

use tdfu_core::dfu::alt::resolve;
use tdfu_core::dfu::descriptors::read_info;
use tdfu_core::model::{AltSel, DfuInfo};
use tdfu_usb::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, Direction, InterfaceSpec, LocalUsbTransport, Recipient,
    UsbErrorKind, endpoint,
};
use tdfu_wasm::clock::JsSleeper;
use tdfu_wasm::log::Logger;
use tdfu_wasm::usb::backend::descriptors_and_strings;
use tdfu_wasm::{DeviceTable, LocalUsbBackend, WebUsbBackend, WebUsbTransport};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::UsbDevice;

#[wasm_bindgen(inline_js = r#"
// A scripted USBDevice. Every method records its call; the transfer methods take their
// answers from a queue, in order, and the control-plane methods resolve unless the spec
// says which of them rejects.
export class ScriptedUsbDevice {
    constructor(spec) {
        this.vendorId = spec.vendorId;
        this.productId = spec.productId;
        this.productName = spec.productName === undefined ? null : spec.productName;
        this.configurations = spec.configurations === undefined ? [] : spec.configurations;
        this.configuration = spec.configuration === undefined ? null : spec.configuration;
        // The browser hands back a device that is already `opened` only once something
        // has opened it. A fresh authorisation is `false`, which is the state
        // `WebUsbBackend::open`'s `if !device.opened()` branch exists for.
        this.opened = spec.opened === undefined ? true : spec.opened;
        this.calls = [];
        this.replies = (spec.replies === undefined ? [] : spec.replies).slice();
        this.fail = spec.fail === undefined ? {} : spec.fail;
        this.hang = spec.hang === undefined ? {} : spec.hang;
        // The two pieces of browser-side state a reset really touches (USB 2.0 §9.1.1.5).
        // Kept here rather than only recorded, because a `reset()` that changed nothing
        // could only ever prove our own bookkeeping.
        this.claimed = null;
        this.selected = null;
    }
    _record(name, args) { this.calls.push({ name: name, args: args }); }
    _plane(name, args) {
        this._record(name, args);
        // A control-plane call that never settles: the platform side of the USB service
        // not answering, which is what the control-plane deadlines exist for.
        if (this.hang[name]) return new Promise(function () {});
        if (this.fail[name]) return Promise.reject(this.fail[name]);
        return Promise.resolve();
    }
    _transfer(name, args) {
        this._record(name, args);
        const reply = this.replies.shift();
        if (reply === undefined) {
            return Promise.reject({ name: 'NotFoundError', message: 'the script ran out at ' + name });
        }
        if (reply.reject) return Promise.reject(reply.reject);
        // A promise that never settles: what a wedged EP0 looks like from the page, and
        // the only way to exercise the deadline race, since WebUSB has no cancel.
        if (reply.hang) return new Promise(function () {});
        const value = {};
        value.status = reply.status === undefined ? 'ok' : reply.status;
        if (reply.data !== undefined) {
            value.data = new DataView(new Uint8Array(reply.data).buffer);
        }
        if (reply.bytesWritten !== undefined) value.bytesWritten = reply.bytesWritten;
        if (reply.delay !== undefined) {
            return new Promise(function (r) { setTimeout(function () { r(value); }, reply.delay); });
        }
        return Promise.resolve(value);
    }
    open() {
        const self = this;
        return this._plane('open', []).then(function () { self.opened = true; });
    }
    close() { return this._plane('close', []); }
    selectConfiguration(v) {
        const self = this;
        return this._plane('selectConfiguration', [v]).then(function () { self.selected = v; });
    }
    claimInterface(n) {
        const self = this;
        // Chromium raises `InvalidStateError` for a second claim of an interface it
        // already holds; without this the re-claim after a reset would pass whether or
        // not the reset dropped anything.
        if (this.claimed !== null && !this.fail.claimInterface && !this.hang.claimInterface) {
            this._record('claimInterface', [n]);
            return Promise.reject({ name: 'InvalidStateError', message: 'interface ' + this.claimed + ' is claimed' });
        }
        return this._plane('claimInterface', [n]).then(function () { self.claimed = n; });
    }
    releaseInterface(n) {
        const self = this;
        return this._plane('releaseInterface', [n]).then(function () { self.claimed = null; });
    }
    selectAlternateInterface(i, a) { return this._plane('selectAlternateInterface', [i, a]); }
    clearHalt(dir, n) { return this._plane('clearHalt', [dir, n]); }
    reset() {
        const self = this;
        // USB 2.0 §9.1.1.5: the device is back in the Default state, so the browser holds
        // neither the claim nor the configuration afterwards.
        return this._plane('reset', []).then(function () { self.claimed = null; self.selected = null; });
    }
    controlTransferIn(setup, length) { return this._transfer('controlTransferIn', [setup, length]); }
    controlTransferOut(setup, data) { return this._transfer('controlTransferOut', [setup, data]); }
    transferIn(ep, length) { return this._transfer('transferIn', [ep, length]); }
    transferOut(ep, data) { return this._transfer('transferOut', [ep, data]); }
}

export function scripted(spec) { return new ScriptedUsbDevice(spec); }
export function callNames(device) { return device.calls.map(function (c) { return c.name; }); }
// The browser's own view of the claim and the configuration, as the double models them.
export function browserState(device) {
    return (device.claimed === null ? 'unclaimed' : 'claimed ' + device.claimed) +
        ', ' + (device.selected === null ? 'unconfigured' : 'configuration ' + device.selected);
}
export function callArg(device, index, arg) { return device.calls[index].args[arg]; }

// A watchdog for a test that would otherwise HANG rather than fail. Under Node a promise
// that never settles simply drains the event loop: the process exits 0 with this test and
// every one after it unrun, which reads as a pass. This schedules an unhandled rejection
// instead, which Node turns into a non-zero exit, and hands back the canceller for the
// path where the code under test does give up in time.
export function watchdog(ms, note) {
    const id = setTimeout(function () { Promise.reject(new Error(note)); }, ms);
    return function () { clearTimeout(id); };
}

// Count `clearTimeout` calls while a transfer runs. A deadline that fires is observable
// (the transfer fails); a deadline that is *cancelled* is not, so this is the only way to
// see that a transfer which beat its deadline took the timer down with it.
export function watchClearTimeout() {
    const original = globalThis.clearTimeout;
    const state = { count: 0 };
    globalThis.clearTimeout = function (id) { state.count += 1; return original.call(globalThis, id); };
    state.stop = function () { globalThis.clearTimeout = original; return state.count; };
    return state;
}
export function stopClearTimeoutWatch(state) { return state.stop(); }
"#)]
extern "C" {
    fn scripted(spec: &JsValue) -> JsValue;
    #[wasm_bindgen(js_name = callNames)]
    fn call_names(device: &JsValue) -> Vec<String>;
    #[wasm_bindgen(js_name = callArg)]
    fn call_arg(device: &JsValue, index: u32, arg: u32) -> JsValue;
    #[wasm_bindgen(js_name = browserState)]
    fn browser_state(device: &JsValue) -> String;
    fn watchdog(ms: f64, note: &str) -> js_sys::Function;
    #[wasm_bindgen(js_name = watchClearTimeout)]
    fn watch_clear_timeout() -> JsValue;
    #[wasm_bindgen(js_name = stopClearTimeoutWatch)]
    fn stop_clear_timeout_watch(state: &JsValue) -> u32;
}

/// The three alt names a shipped loader carries, in `bAlternateSetting`
/// order, as `lsusb` read them off a live T32LQ
/// (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`: `i5 flash | i6 erase |
/// i7 reboot`).
const GADGET_ALT_NAMES: [&str; 3] = ["flash", "erase", "reboot"];

/// A DFU gadget's descriptor tree, as the browser exposes it.
///
/// `names` is what `UsbAlternateInterface.interfaceName` answers per alternate; an empty
/// one is written as JS `null`, which is what Chromium gives for a device that carries no
/// `iInterface`.
fn dfu_tree(names: &[&str; 3]) -> JsValue {
    let alternates = js_sys::Array::new();
    for (setting, name) in names.iter().enumerate() {
        let alternate = js_sys::Object::new();
        let setting = u8::try_from(setting).unwrap_or(0);
        set(&alternate, "alternateSetting", &JsValue::from_f64(f64::from(setting)));
        set(&alternate, "interfaceClass", &JsValue::from_f64(254.0));
        set(&alternate, "interfaceSubclass", &JsValue::from_f64(1.0));
        set(&alternate, "interfaceProtocol", &JsValue::from_f64(2.0));
        set(
            &alternate,
            "interfaceName",
            &if name.is_empty() {
                JsValue::NULL
            } else {
                JsValue::from_str(name)
            },
        );
        alternates.push(&alternate);
    }
    let interface = js_sys::Object::new();
    set(&interface, "interfaceNumber", &JsValue::from_f64(0.0));
    set(&interface, "alternates", &alternates);
    let interfaces = js_sys::Array::of1(&interface);
    let configuration = js_sys::Object::new();
    set(&configuration, "configurationValue", &JsValue::from_f64(1.0));
    set(&configuration, "interfaces", &interfaces);
    js_sys::Array::of1(&configuration).into()
}

fn set(object: &js_sys::Object, key: &str, value: &JsValue) {
    let _ignored = js_sys::Reflect::set(object, &JsValue::from_str(key), value);
}

/// Build a scripted device and the transport over it, with the shipped loader's alt
/// names.
fn device(replies: &js_sys::Array, fail: Option<(&str, &str)>) -> (JsValue, WebUsbTransport) {
    named_device(replies, fail, &GADGET_ALT_NAMES)
}

/// [`device`], with the browser's answer for each alternate's `interfaceName` chosen.
fn named_device(replies: &js_sys::Array, fail: Option<(&str, &str)>, names: &[&str; 3]) -> (JsValue, WebUsbTransport) {
    let raw = scripted_device(replies, fail, names);
    let usb: UsbDevice = raw.clone().unchecked_into();
    let (descriptors, strings) = descriptors_and_strings(&usb);
    let transport = WebUsbTransport::new(usb, descriptors, strings, None, Logger::new(None));
    (raw, transport)
}

/// A scripted device the browser has not opened yet, as a fresh authorisation is.
fn unopened_device(replies: &js_sys::Array) -> JsValue {
    let spec = js_sys::Object::new();
    set(&spec, "vendorId", &JsValue::from_f64(f64::from(tdfu_usb::vid::INGENIC)));
    set(
        &spec,
        "productId",
        &JsValue::from_f64(f64::from(tdfu_usb::pid::BOOTROM)),
    );
    set(&spec, "configurations", &dfu_tree(&GADGET_ALT_NAMES));
    set(&spec, "replies", replies);
    set(&spec, "opened", &JsValue::FALSE);
    scripted(&spec.into())
}

/// The scripted `USBDevice` on its own, for the tests that drive the backend's `open`.
fn scripted_device(replies: &js_sys::Array, fail: Option<(&str, &str)>, names: &[&str; 3]) -> JsValue {
    let spec = js_sys::Object::new();
    set(&spec, "vendorId", &JsValue::from_f64(f64::from(tdfu_usb::vid::INGENIC)));
    set(
        &spec,
        "productId",
        &JsValue::from_f64(f64::from(tdfu_usb::pid::BOOTROM)),
    );
    set(&spec, "productName", &JsValue::from_str("USB download gadget"));
    set(&spec, "configurations", &dfu_tree(names));
    set(&spec, "replies", replies);
    if let Some((method, name)) = fail {
        let rejection = js_sys::Object::new();
        set(&rejection, "name", &JsValue::from_str(name));
        set(&rejection, "message", &JsValue::from_str("scripted refusal"));
        let table = js_sys::Object::new();
        set(&table, method, &rejection);
        set(&spec, "fail", &table);
    }
    scripted(&spec.into())
}

/// A transport whose named control-plane method never settles.
fn hanging_plane(method: &str) -> WebUsbTransport {
    let spec = js_sys::Object::new();
    set(&spec, "vendorId", &JsValue::from_f64(f64::from(tdfu_usb::vid::INGENIC)));
    set(
        &spec,
        "productId",
        &JsValue::from_f64(f64::from(tdfu_usb::pid::BOOTROM)),
    );
    set(&spec, "configurations", &dfu_tree(&GADGET_ALT_NAMES));
    let table = js_sys::Object::new();
    set(&table, method, &JsValue::TRUE);
    set(&spec, "hang", &table);
    let usb: UsbDevice = scripted(&spec.into()).unchecked_into();
    let (descriptors, strings) = descriptors_and_strings(&usb);
    WebUsbTransport::new(usb, descriptors, strings, None, Logger::new(None))
}

/// A scripted reply that rejects with a `DOMException`-shaped object.
fn rejecting(name: &str) -> JsValue {
    let inner = js_sys::Object::new();
    set(&inner, "name", &JsValue::from_str(name));
    set(&inner, "message", &JsValue::from_str("scripted refusal"));
    let rejection = js_sys::Object::new();
    set(&rejection, "reject", &inner);
    rejection.into()
}

/// The alt names a `read_info` resolved, or the failure as the only name.
///
/// A value rather than an `assert!(false, ..)` on the `Err` arm: that shape is
/// `clippy::assertions_on_constants` and `panic!` is denied outright, so
/// a read that did not work has to fail through the assertion it lands in. Same reasoning
/// as `src/usb/error.rs:115-125`, in the half of the crate the host gate does not see.
fn alt_names(info: &tdfu_core::Result<DfuInfo>) -> Vec<String> {
    match info {
        Ok(info) => info.alts.iter().map(|alt| alt.name.clone()).collect(),
        Err(error) => vec![format!("read_info failed: {error}")],
    }
}

/// What `dfu::alt::resolve` answered, as a string an assertion can compare.
fn resolved(info: &tdfu_core::Result<DfuInfo>, selection: &AltSel) -> String {
    match info {
        Ok(info) => match resolve(info, selection) {
            Ok(alt) => format!("alt {alt}"),
            Err(error) => format!("refused: {error}"),
        },
        Err(error) => format!("read_info failed: {error}"),
    }
}

/// How the layers above would treat a bulk outcome, as a sentence.
///
/// `retryable` is the bootrom vendor-request class (`bootrom::transfer_chunks` resends on
/// it) and `recoverable` is the wedge-recovery class (`reset_and_retry_once` resets and resends on
/// it). Both have to be false for an abandoned OUT, and reading them off one string keeps
/// the two apart in the failure message.
fn bulk_verdict(outcome: Result<usize, tdfu_usb::UsbError>) -> String {
    match outcome {
        Ok(written) => format!("succeeded with {written} bytes"),
        Err(error) => format!(
            "retryable={} recoverable={} {error}",
            error.is_vendor_retryable(),
            tdfu_core::Error::Usb(error.clone()).is_recoverable()
        ),
    }
}

/// Which class an operation's outcome is in, as a string, so an `Ok` fails the assertion
/// it lands in rather than through a denied macro.
fn outcome_class(outcome: tdfu_core::Result<()>) -> String {
    match outcome {
        Ok(()) => "succeeded".to_owned(),
        Err(tdfu_core::Error::MissingAlt(name)) => format!("MissingAlt({name})"),
        Err(other) => format!("failed: {other}"),
    }
}

/// One transfer reply.
fn reply(status: &str, data: Option<&[u8]>, bytes_written: Option<u32>) -> JsValue {
    let object = js_sys::Object::new();
    set(&object, "status", &JsValue::from_str(status));
    if let Some(data) = data {
        set(&object, "data", &js_sys::Uint8Array::from(data).into());
    }
    if let Some(written) = bytes_written {
        set(&object, "bytesWritten", &JsValue::from_f64(f64::from(written)));
    }
    object.into()
}

/// A DFU `GETSTATUS`: class IN on the interface (`dfu.c:70`).
const GET_STATUS: ControlIn = ControlIn {
    control_type: ControlType::Class,
    recipient: Recipient::Interface,
    request: 0x03,
    value: 0,
    index: 0,
    len: 6,
};

#[wasm_bindgen_test]
async fn a_class_control_in_carries_the_typed_setup_fields() {
    // The typed setup's whole point: WebUSB takes `requestType` and `recipient` as strings,
    // so the typed fields are a rename rather than an unpack of `bmRequestType`, and the
    // "which bits mean recipient" mistake is unrepresentable.
    let replies = js_sys::Array::of1(&reply("ok", Some(&[0, 0, 0, 0, 2, 0]), None));
    let (raw, transport) = device(&replies, None);
    let data = transport.control_in(GET_STATUS, Duration::from_secs(5)).await;
    assert_eq!(data.as_deref(), Ok(&[0, 0, 0, 0, 2, 0][..]), "{data:?}");
    assert_eq!(call_names(&raw), vec!["controlTransferIn".to_owned()]);

    let setup = call_arg(&raw, 0, 0);
    let field = |key: &str| js_sys::Reflect::get(&setup, &JsValue::from_str(key)).ok();
    assert_eq!(
        field("requestType").and_then(|v| v.as_string()).as_deref(),
        Some("class")
    );
    assert_eq!(
        field("recipient").and_then(|v| v.as_string()).as_deref(),
        Some("interface")
    );
    assert_eq!(field("request").and_then(|v| v.as_f64()), Some(3.0));
    assert_eq!(call_arg(&raw, 0, 1).as_f64(), Some(6.0));
}

#[wasm_bindgen_test]
async fn a_stall_and_a_babble_arrive_as_different_kinds() {
    // The shim answered LIBUSB_ERROR_PIPE for both (`libusb-webusb.js:356`), which put a
    // framing fault into the vendor-request retry class.
    for (status, want) in [("stall", UsbErrorKind::Stall), ("babble", UsbErrorKind::Overflow)] {
        let replies = js_sys::Array::of1(&reply(status, None, None));
        let (_raw, transport) = device(&replies, None);
        // The whole failure read off in one value, so a transfer that *succeeded* fails
        // the assertion rather than a denied `assert!(false, ..)` macro
        // (`src/usb/error.rs:115-125` is this crate explaining the rule in the half the
        // host gate does see). A `UsbError` carries the context: what was asked, and by when.
        let seen = transport
            .control_in(GET_STATUS, Duration::from_secs(5))
            .await
            .map_err(|error| (error.kind().clone(), error.requested_len(), error.timeout()));
        assert_eq!(seen, Err((want, Some(6), Some(Duration::from_secs(5)))), "{status}");
    }
}

/// **The browser's own words reach the log.**
#[wasm_bindgen_test]
async fn a_mapped_exception_still_puts_the_browsers_message_on_the_log() {
    // `kind_from_dom` uses the message only on the unmapped arm, so Chromium's "Transfer
    // failed", "Unable to claim interface" and "The device was disconnected" all reached
    // the operator as a bare `transfer fault: control IN request 0x03`. The message cannot
    // go into the error (the seam freezes `Error.message` as `tdfu_core::Error`'s
    // `Display`), so it goes where the rest of the diagnosis goes.
    let lines = js_sys::Array::new();
    let holder = js_sys::Object::new();
    set(&holder, "lines", &lines);
    let sink = js_sys::Function::new_with_args("line, level", "this.lines.push(level + ': ' + line);");
    let logger = Logger::new(Some(sink.bind0(&holder.into()).unchecked_into()));
    logger.set_debug(true);

    let inner = js_sys::Object::new();
    set(&inner, "name", &JsValue::from_str("NetworkError"));
    set(&inner, "message", &JsValue::from_str("Unable to claim interface."));
    let rejection = js_sys::Object::new();
    set(&rejection, "reject", &inner);
    let replies = js_sys::Array::of1(&rejection.into());
    let raw = scripted_device(&replies, None, &GADGET_ALT_NAMES);
    let usb: UsbDevice = raw.unchecked_into();
    let (descriptors, strings) = descriptors_and_strings(&usb);
    let transport = WebUsbTransport::new(usb, descriptors, strings, None, logger);

    let failed = transport.control_in(GET_STATUS, Duration::from_secs(5)).await;
    let message = match failed {
        Err(error) => error.to_string(),
        Ok(data) => format!("it succeeded with {data:?}"),
    };
    // The error itself is `tdfu-core`'s wording and nothing else.
    assert!(!message.contains("Unable to claim"), "{message}");
    let printed: Vec<String> = (0..lines.length())
        .filter_map(|index| lines.get(index).as_string())
        .collect();
    let words = printed
        .iter()
        .find(|line| line.contains("NetworkError"))
        .map_or_else(String::new, ToOwned::to_owned);
    assert!(words.starts_with("debug: "), "{printed:?}");
    assert!(words.contains("Unable to claim interface."), "{words}");
}

#[wasm_bindgen_test]
async fn a_rejected_transfer_keeps_the_dom_exception_name() {
    let rejection = js_sys::Object::new();
    let inner = js_sys::Object::new();
    set(&inner, "name", &JsValue::from_str("NotFoundError"));
    set(&inner, "message", &JsValue::from_str("The device was disconnected."));
    set(&rejection, "reject", &inner);
    let replies = js_sys::Array::of1(&rejection.into());
    let (_raw, transport) = device(&replies, None);
    let error = transport.control_in(GET_STATUS, Duration::from_secs(5)).await;
    assert!(
        matches!(
            error.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NoDevice)
        ),
        "{error:?}"
    );
}

#[wasm_bindgen_test]
async fn a_transfer_that_never_settles_expires_on_our_own_deadline() {
    // WebUSB transfers carry no timeout and cannot be cancelled, so the deadline is the
    // backend's: a race against `setTimeout`. Without it a wedged EP0 hangs the page for
    // ever, which is what the shim's own race existed to prevent
    // (`libusb-webusb.js:376-391`).
    let hang = js_sys::Object::new();
    set(&hang, "hang", &JsValue::TRUE);
    let replies = js_sys::Array::of1(&hang.into());
    let (_raw, transport) = device(&replies, None);
    let start = js_sys::Date::now();
    let error = transport.control_in(GET_STATUS, Duration::from_millis(40)).await;
    let elapsed = js_sys::Date::now() - start;
    assert!(
        matches!(
            error.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::Timeout)
        ),
        "{error:?}"
    );
    assert!(elapsed >= 20.0, "the deadline fired after {elapsed} ms");
    // A vendor request retries a timeout, and this is the only producer of one here.
    assert!(error.is_err_and(|error| error.is_vendor_retryable()));
}

/// **A transfer that beat its deadline takes the timer down with it.**
#[wasm_bindgen_test]
async fn a_transfer_that_beat_its_deadline_clears_the_timer() {
    // A deadline that *fires* is observable, because the transfer fails; a deadline that
    // is cancelled is not, which is why nothing noticed that a 16 MiB write left one live
    // timer per `DNLOAD` block for up to that block's own 30 s. Counting `clearTimeout`
    // is the only way to see it.
    let replies = js_sys::Array::of1(&reply("ok", Some(&[0, 0, 0, 0, 2, 0]), None));
    let (_raw, transport) = device(&replies, None);
    let watch = watch_clear_timeout();
    let data = transport.control_in(GET_STATUS, Duration::from_secs(5)).await;
    let cleared = stop_clear_timeout_watch(&watch);
    assert_eq!(data.as_deref(), Ok(&[0, 0, 0, 0, 2, 0][..]), "{data:?}");
    assert_eq!(cleared, 1, "the deadline's timer was left running");
}

#[wasm_bindgen_test]
async fn a_standard_get_descriptor_is_answered_without_touching_the_bus() {
    // WebUSB refuses standard control requests, so the configuration descriptor is the
    // one synthesised at open time. A device call here would be a
    // request the browser was always going to reject.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let header = transport
        .control_in(
            ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Device,
                request: 0x06,
                value: 0x0200,
                index: 0,
                len: 9,
            },
            Duration::from_secs(5),
        )
        .await;
    let header = header.unwrap_or_default();
    assert_eq!(header.len(), 9, "{header:?}");
    assert_eq!(header[1], 0x02, "bDescriptorType is CONFIGURATION");
    // 9 header + 3 interface descriptors + the synthesised functional descriptor.
    assert_eq!(u16::from_le_bytes([header[2], header[3]]), 9 + 3 * 9 + 9);
    assert!(
        call_names(&raw).is_empty(),
        "the bus was touched: {:?}",
        call_names(&raw)
    );
}

#[wasm_bindgen_test]
async fn a_standard_control_out_is_refused_and_names_its_trait_method() {
    // The shim emulated SET_INTERFACE inside the control path because its caller was
    // libusb (`libusb-webusb.js:342-349`). Contracts v3 gave it a trait method, so this
    // is a caller reaching around the interface.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let refused = transport
        .control_out(
            ControlOut {
                control_type: ControlType::Standard,
                recipient: Recipient::Interface,
                request: 0x0B,
                value: 0,
                index: 0,
                data: &[],
            },
            Duration::from_secs(5),
        )
        .await;
    assert!(
        matches!(
            refused.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::Unsupported)
        ),
        "{refused:?}"
    );
    assert!(call_names(&raw).is_empty());
}

/// **A bulk OUT the deadline beat is never sent again.**
#[wasm_bindgen_test]
async fn a_bulk_out_the_deadline_beat_is_not_retryable_and_latches_the_transport() {
    // The OUT settles 200 ms after a 40 ms deadline, which is the case the whole finding
    // is about: the browser cannot cancel, so those four bytes are still on their way to
    // the bootrom. `transfer_chunks` retries anything `is_vendor_retryable`, so a
    // `Timeout` here would stage the chunk twice under one `SET_DATA_LEN`.
    let late = js_sys::Object::new();
    set(&late, "status", &JsValue::from_str("ok"));
    set(&late, "bytesWritten", &JsValue::from_f64(4.0));
    set(&late, "delay", &JsValue::from_f64(200.0));
    let replies = js_sys::Array::of2(&late.into(), &reply("ok", None, Some(4)));
    let (raw, transport) = device(&replies, None);
    let claimed = transport
        .claim_interface(InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT))
        .await;
    assert!(claimed.is_ok(), "{claimed:?}");

    let expired = bulk_verdict(transport.bulk_out(&[1, 2, 3, 4], Duration::from_millis(40)).await);
    assert!(
        expired.starts_with("retryable=false recoverable=false "),
        "a layer above would resend the chunk: {expired}"
    );
    assert!(expired.contains("cannot cancel"), "{expired}");

    // And the latch: the abandoned bytes may still arrive, so nothing else may go out on
    // either bulk endpoint until the device is back in a known state.
    let before = call_names(&raw).len();
    let again = bulk_verdict(transport.bulk_out(&[1, 2, 3, 4], Duration::from_secs(2)).await);
    assert!(again.contains("cannot cancel"), "a second OUT went out: {again}");
    let read = transport.bulk_in(4, Duration::from_secs(2)).await;
    assert!(read.is_err(), "a bulk IN went out on top of the abandoned OUT");
    assert_eq!(call_names(&raw).len(), before, "{:?}", call_names(&raw));

    // A reset is the one call that puts the device back in a known state, so it is what
    // clears the latch. The second scripted reply is then used.
    assert!(transport.reset().await.is_ok());
    let claimed = transport
        .claim_interface(InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT))
        .await;
    assert!(claimed.is_ok(), "{claimed:?}");
    let after_reset = bulk_verdict(transport.bulk_out(&[1, 2, 3, 4], Duration::from_secs(2)).await);
    assert_eq!(after_reset, "succeeded with 4 bytes");
}

/// **A control-plane call that never settles is a failure, not a hang.**
#[wasm_bindgen_test]
async fn a_control_plane_call_that_never_settles_expires_on_our_own_deadline() {
    // Costs `CONTROL_PLANE_TIMEOUT` in wall clock, once, and there is no cheaper way to
    // see it: the deadline is a real `setTimeout` and the trait gives these calls no
    // timeout parameter to shorten. Unbounded, this awaited a bare `JsFuture` and the
    // test would never return, which is exactly the page hang the seam forbids.
    let transport = hanging_plane("selectConfiguration");
    let bound = tdfu_wasm::usb::transport::CONTROL_PLANE_TIMEOUT.as_millis();
    let bound = f64::from(u32::try_from(bound).unwrap_or(u32::MAX));
    // Without the watchdog a `control_plane` with no deadline does not fail this test, it
    // ends the whole Node run at 0: see the helper's own comment.
    let cancel = watchdog(bound * 3.0, "set_configuration never gave up");
    let start = js_sys::Date::now();
    let outcome = transport.set_configuration(1).await;
    let elapsed = js_sys::Date::now() - start;
    let _ignored = cancel.call0(&JsValue::UNDEFINED);
    assert!(
        matches!(
            outcome.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::Timeout)
        ),
        "{outcome:?}"
    );
    assert!(elapsed >= bound / 2.0, "it gave up after {elapsed} ms");
    // And the configuration is not remembered from a call that did not happen.
    assert_eq!(transport.active_configuration(), None);
}

#[wasm_bindgen_test]
async fn a_bulk_in_that_comes_up_short_is_a_failure_not_a_partial_answer() {
    // `read_memory` asks for four bytes and three is a failure, never three
    // bytes of a register.
    let replies = js_sys::Array::of1(&reply("ok", Some(&[1, 2, 3]), None));
    let (_raw, transport) = device(&replies, None);
    let claimed = transport
        .claim_interface(InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT))
        .await;
    assert!(claimed.is_ok(), "{claimed:?}");
    let seen = transport
        .bulk_in(4, Duration::from_secs(2))
        .await
        .map_err(|error| (error.kind().clone(), error.transferred()));
    assert_eq!(seen, Err((UsbErrorKind::Short { got: 3, want: 4 }, Some(3))));
}

#[wasm_bindgen_test]
async fn a_bulk_transfer_without_a_claim_is_not_claimed_rather_than_a_browser_error() {
    // The claim declares the endpoints, so "there is no such pipe" is
    // answerable here rather than as a `NotFoundError` from the browser three layers on.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let read = transport.bulk_in(4, Duration::from_secs(2)).await;
    assert!(
        matches!(
            read.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "{read:?}"
    );
    // A control-only claim declares no bulk endpoint, and that is the same answer.
    let claimed = transport.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(claimed.is_ok(), "{claimed:?}");
    let written = transport.bulk_out(&[1, 2], Duration::from_secs(2)).await;
    assert!(
        matches!(
            written.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "{written:?}"
    );
    assert_eq!(call_names(&raw), vec!["claimInterface".to_owned()]);
}

#[wasm_bindgen_test]
async fn releasing_an_unclaimed_interface_is_ok_and_silent() {
    // Idempotent by contract: the bootrom path releases on every exit path, which is
    // better than the C's seven scattered call sites, and Chromium raises
    // `InvalidStateError` for a release of something never claimed.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    assert!(transport.release_interface(0).await.is_ok());
    assert!(call_names(&raw).is_empty(), "{:?}", call_names(&raw));
}

#[wasm_bindgen_test]
async fn a_refused_claim_is_reported_rather_than_swallowed() {
    // `libusb-webusb.js:251` printed and returned LIBUSB_ERROR_BUSY; `:228` and `:262`
    // returned success for a refused `selectConfiguration` and `releaseInterface`. A
    // claim that failed and reported success is a transfer that fails later, somewhere
    // else.
    let (_raw, transport) = device(&js_sys::Array::new(), Some(("claimInterface", "SecurityError")));
    let claimed = transport.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(
        matches!(
            claimed.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::AccessDenied)
        ),
        "{claimed:?}"
    );
}

#[wasm_bindgen_test]
async fn clear_halt_goes_out_with_the_endpoint_direction() {
    // The vendor request's five-attempt Stall retry is decorative without it: a halted bulk
    // endpoint latches and keeps returning EPIPE until `CLEAR_FEATURE(ENDPOINT_HALT)`.
    // The C has zero `libusb_clear_halt` call sites in the whole tree, which is exactly
    // why nobody noticed the retry was decorative.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let claimed = transport
        .claim_interface(InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT))
        .await;
    assert!(claimed.is_ok(), "{claimed:?}");
    assert!(transport.clear_halt(endpoint::BOOTROM_IN).await.is_ok());
    assert_eq!(call_arg(&raw, 1, 0).as_string().as_deref(), Some("in"));
    assert_eq!(call_arg(&raw, 1, 1).as_f64(), Some(1.0));

    // An endpoint the claim did not declare is a caller bug, answered here.
    let other = BulkEndpoint::new(Direction::In, 2);
    assert!(other.is_some());
    if let Some(other) = other {
        let refused = transport.clear_halt(other).await;
        assert!(
            matches!(
                refused.as_ref().map_err(tdfu_usb::UsbError::kind),
                Err(UsbErrorKind::NotClaimed)
            ),
            "{refused:?}"
        );
    }
}

#[wasm_bindgen_test]
async fn reset_calls_the_browsers_reset_and_drops_the_claim() {
    // The frozen trait doc once said `Unsupported` here, on a no-reset rule that is
    // Android's alone; the shipped browser path resets through
    // `USBDevice.reset()` (`libusb-webusb.js:462-471`, `dfu.c:394`).
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let claimed = transport.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(claimed.is_ok(), "{claimed:?}");
    let configured = transport.set_configuration(1).await;
    assert!(configured.is_ok(), "{configured:?}");
    assert_eq!(transport.active_configuration(), Some(1));

    assert_eq!(browser_state(&raw), "claimed 0, configuration 1");

    assert!(transport.reset().await.is_ok());
    assert!(call_names(&raw).contains(&"reset".to_owned()), "{:?}", call_names(&raw));
    // USB 2.0 §9.1.1.5: a reset returns the device to the Default state, so the retried
    // operation claims and configures for itself. Both halves are checked:
    // ours, which is the code three lines above the old assertion, and the browser's,
    // which is what decides whether the re-claim below can succeed at all.
    assert_eq!(transport.active_configuration(), None);
    assert_eq!(browser_state(&raw), "unclaimed, unconfigured");
    let read = transport.bulk_in(4, Duration::from_secs(2)).await;
    assert!(
        matches!(
            read.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "the claim survived the reset: {read:?}"
    );

    // The re-claim: it goes out on the wire, and the double accepts it, which it would
    // not if the reset had left the interface claimed (a second claim is
    // `InvalidStateError`, which reads here as `NotClaimed` because we hold none).
    let reclaimed = transport.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(reclaimed.is_ok(), "the re-claim was refused: {reclaimed:?}");
    let reconfigured = transport.set_configuration(1).await;
    assert!(reconfigured.is_ok(), "{reconfigured:?}");
    assert_eq!(browser_state(&raw), "claimed 0, configuration 1");
}

/// **A bulk transfer that works, in both directions.**
#[wasm_bindgen_test]
async fn a_bulk_transfer_reports_the_bytes_the_browser_says_moved() {
    // No wasm test drove a successful bulk transfer at all, so `bulk_out` returning
    // `Ok(data.len())` instead of `Ok(bytesWritten)` passed the whole suite. That mutation
    // turns a partial bootrom chunk write into a complete one: `transfer_chunks` advances
    // `offset` past bytes the device never took and stages a truncated SPL, which the
    // partial-write handling and the cache-line padding both exist to prevent.
    let replies = js_sys::Array::new();
    replies.push(&reply("ok", None, Some(2)));
    replies.push(&reply("ok", None, Some(4)));
    replies.push(&reply("ok", Some(&[9, 8, 7, 6]), None));
    let (_raw, transport) = device(&replies, None);
    let claimed = transport
        .claim_interface(InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT))
        .await;
    assert!(claimed.is_ok(), "{claimed:?}");

    // A partial write is reported as the bytes that moved, not as the bytes asked for.
    let partial = bulk_verdict(transport.bulk_out(&[1, 2, 3, 4], Duration::from_secs(2)).await);
    assert_eq!(partial, "succeeded with 2 bytes");
    // And a complete one as all of them, so the boundary is pinned from both sides.
    let whole = bulk_verdict(transport.bulk_out(&[1, 2, 3, 4], Duration::from_secs(2)).await);
    assert_eq!(whole, "succeeded with 4 bytes");
    // The IN direction's success was protected only incidentally, by the `Short` check.
    let read = transport.bulk_in(4, Duration::from_secs(2)).await;
    assert_eq!(read.as_deref(), Ok(&[9_u8, 8, 7, 6][..]), "{read:?}");
}

#[wasm_bindgen_test]
async fn a_failed_reset_is_reported_rather_than_swallowed() {
    // The shim's `.catch(function () { return 0; })` (`libusb-webusb.js:469`) reported
    // success for a reset that never happened, and `dfu.c:394` discards the result on top
    // of that. `dfu::host::reset_and_retry_once` reads this one and says so through the
    // progress sink before returning the operation's own error (`dfu/host.rs:745-751`).
    let (_raw, transport) = device(&js_sys::Array::new(), Some(("reset", "NetworkError")));
    let reset = transport.reset().await;
    assert!(
        matches!(
            reset.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::Fault)
        ),
        "{reset:?}"
    );
}

/// **A reset that failed does not read as a reset that never existed.**
#[wasm_bindgen_test]
async fn a_reset_that_failed_is_not_reported_as_a_reset_that_was_unavailable() {
    // `USBDevice.reset()` is a real reset here, so this backend
    // is the only one where the call can go out and *fail*. `reset_and_retry_once` said
    // "a USB reset is not available here" for that too, which was true only while WebUSB's
    // reset was `Unsupported`, and the page's log then told the operator to find another
    // machine when what they needed was to unplug the camera.
    let (_raw, transport) = named_device(
        &js_sys::Array::new(),
        Some(("reset", "NetworkError")),
        &GADGET_ALT_NAMES,
    );
    let clock = JsSleeper::new();
    let mut notes: Vec<String> = Vec::new();
    let mut sink = |event: tdfu_core::Progress| {
        if let tdfu_core::Progress::Note(text) = event {
            notes.push(text);
        }
    };
    // `NotDfu` is in the reset-and-retry recoverable class, so the reset is attempted; the
    // closure fails the same way twice, and only the first attempt runs because the reset
    // never succeeds.
    let outcome = tdfu_core::dfu::host::reset_and_retry_once(&transport, &clock, &mut sink, async |_attempt, _sink| {
        Err::<(), tdfu_core::Error>(tdfu_core::Error::NotDfu)
    })
    .await;
    assert!(outcome.is_err(), "a wedged gadget with a failing reset succeeded");

    let note = notes.first().map_or_else(String::new, ToOwned::to_owned);
    assert!(note.contains("the USB reset failed"), "{notes:?}");
    assert!(!note.contains("not available"), "{note}");
    // And the operation's own error is still what comes back, not the reset's
    // (`dfu.c:996` gates the retry the same way).
    let message = outcome.err().map_or_else(String::new, |error| error.to_string());
    assert!(!message.contains("transfer fault"), "{message}");
}

#[wasm_bindgen_test]
async fn the_descriptors_carry_the_product_name_and_no_port_path() {
    // No port path on this backend, and no invented bus or address either -
    // the shim answered bus 1 and "address = list index" (`libusb-webusb.js:156-165`).
    // `productName` is not an invention: the browser really read it, and `classify` falls
    // back to it when a device answers no configuration descriptor.
    let (_raw, transport) = device(&js_sys::Array::new(), None);
    let descriptors = transport.descriptors();
    assert_eq!(descriptors.vendor_id, 0xA108);
    assert_eq!(descriptors.product_id, 0xC309);
    assert_eq!(descriptors.product_string.as_deref(), Some("USB download gadget"));
    assert!(descriptors.port_path.is_empty());
    assert_eq!(descriptors.bus, 0);
    assert_eq!(descriptors.address, 0);
    assert_eq!(
        tdfu_core::ops::classify(descriptors),
        Some(tdfu_core::model::Stage::Gadget)
    );
}

#[wasm_bindgen_test]
async fn a_control_out_that_moved_fewer_bytes_is_short() {
    // `control_out` returns no `usize` by design; that is about the success path.
    // A device that accepted half a DNLOAD block has not accepted the block.
    let replies = js_sys::Array::of1(&reply("ok", None, Some(2)));
    let (_raw, transport) = device(&replies, None);
    let written = transport
        .control_out(
            ControlOut {
                control_type: ControlType::Class,
                recipient: Recipient::Interface,
                request: 0x01,
                value: 0,
                index: 0,
                data: &[1, 2, 3, 4],
            },
            Duration::from_secs(30),
        )
        .await;
    let seen = written.map_err(|error| (error.kind().clone(), error.timeout()));
    assert_eq!(
        seen,
        Err((UsbErrorKind::Short { got: 2, want: 4 }, Some(Duration::from_secs(30))))
    );
}

#[wasm_bindgen_test]
async fn opening_a_gadget_logs_that_the_transfer_size_was_assumed() {
    // The rule is 4096 with a debug-level log saying it was assumed rather than
    // read, and a log line nobody checks is a log line that quietly loses the word
    // "assumed". `WebUsbBackend::open` needs no `navigator.usb` - the device comes from
    // the id table - so the whole open path is reachable from Node.
    let lines = js_sys::Array::new();
    let holder = js_sys::Object::new();
    set(&holder, "lines", &lines);
    let sink = js_sys::Function::new_with_args("line, level", "this.lines.push(level + ': ' + line);");
    let logger = Logger::new(Some(sink.bind0(&holder.into()).unchecked_into()));
    logger.set_debug(true);

    let table = DeviceTable::new();
    let backend = WebUsbBackend::new(table.clone(), logger);
    let (raw, _unused) = device(&js_sys::Array::new(), None);
    let usb: UsbDevice = raw.unchecked_into();
    let id = table.intern(&usb);

    let transport = backend.open(&id).await;
    assert!(transport.is_ok(), "{transport:?}");

    let printed: Vec<String> = (0..lines.length())
        .filter_map(|index| lines.get(index).as_string())
        .collect();
    let assumed = printed
        .iter()
        .find(|line| line.contains("wTransferSize"))
        .map_or_else(String::new, ToOwned::to_owned);
    assert!(assumed.starts_with("debug: "), "{printed:?}");
    assert!(assumed.contains("4096"), "{assumed}");
    assert!(assumed.contains("assuming"), "{assumed}");
    assert!(assumed.contains("rather than reading"), "{assumed}");
}

/// **Two operations on one unopened device open it once.**
#[wasm_bindgen_test]
async fn two_operations_started_together_open_the_device_once() {
    // Both promises are created before either is awaited, which is exactly what the seam
    // hands the page now that the `wasmBusy` mutex is gone. Before the
    // single-flight ticket both operations found nothing in the map, both awaited
    // `backend.open`, and the second `insert` won: two transports over one `USBDevice`
    // with independent claim state, one of them unreachable.
    let lines = js_sys::Array::new();
    let holder = js_sys::Object::new();
    set(&holder, "lines", &lines);
    let sink = js_sys::Function::new_with_args("line, level", "this.lines.push(level + ': ' + line);");
    let callbacks = js_sys::Object::new();
    set(&callbacks, "log", &sink.bind0(&holder.into()));
    let engine = tdfu_wasm::Engine::new(&callbacks.into());
    engine.set_debug(true);

    // `SecurityError` is `AccessDenied`, which is in neither retry class, so each
    // operation stops at its first transfer instead of spending a vendor request's five
    // attempts and their sleeps on a device that was never going to answer.
    let replies = js_sys::Array::new();
    for _ in 0..4 {
        replies.push(&rejecting("SecurityError"));
    }
    let raw = unopened_device(&replies);
    let usb: UsbDevice = raw.clone().unchecked_into();
    let id = engine.table().intern(&usb);

    // A ticket that never cleared would leave the second operation waiting on a promise
    // nobody resolves, and under Node that is not a failure: the event loop drains and
    // the process exits 0 with this test and every one after it unrun. The watchdog turns
    // it into the non-zero exit it deserves.
    let cancel = watchdog(15000.0, "an open ticket was never cleared");

    // Both `JsFuture`s are built before either is awaited: they subscribe on construction,
    // and a rejection nobody has subscribed to yet is an unhandled rejection, which fails
    // the Node run on its own.
    let first = JsFuture::from(engine.detect(id));
    let second = JsFuture::from(engine.diag(id));
    // Both fail at their first transfer. What is being pinned is the open, not the
    // operation.
    let _first = first.await;
    let _second = second.await;
    // And two more, started one after the other rather than together: the handle is in
    // the map by now and has to be *read* out of it.
    let _third = JsFuture::from(engine.detect(id)).await;
    let _fourth = JsFuture::from(engine.diag(id)).await;
    let _ignored = cancel.call0(&JsValue::UNDEFINED);

    let opens = call_names(&raw).into_iter().filter(|name| name == "open").count();
    assert_eq!(opens, 1, "{:?}", call_names(&raw));
    // The browser only opens a device once, so counting `open` calls cannot tell a
    // re-used transport from a second one built over the same already-open handle. The
    // backend's own open-time debug line can: one per `backend.open`, four operations.
    let printed: Vec<String> = (0..lines.length())
        .filter_map(|index| lines.get(index).as_string())
        .collect();
    let opened = printed.iter().filter(|line| line.contains("the browser named")).count();
    assert_eq!(opened, 1, "the transport was rebuilt per operation: {printed:?}");
}

/// **`open` really opens, and the active configuration really is preferred.**
#[wasm_bindgen_test]
async fn an_unopened_device_is_opened_and_its_active_configuration_wins() {
    // The double used to set `opened = true` in its constructor, so `if !device.opened()`
    // and its `dom_failure` mapping were dead in every test, and `configuration` was
    // always `null`, so `config_bytes` only ever took the `configurations[0]` fallback.
    let raw = unopened_device(&js_sys::Array::new());
    let usb: UsbDevice = raw.clone().unchecked_into();
    let table = DeviceTable::new();
    let id = table.intern(&usb);
    let backend = WebUsbBackend::new(table, Logger::new(None));
    let transport = backend.open(&id).await;
    assert!(transport.is_ok(), "{transport:?}");
    assert_eq!(call_names(&raw), vec!["open".to_owned()]);

    // The active configuration is a *different* tree from `configurations[0]`, so the two
    // branches of the `or_else` cannot be told apart by luck: one alt against three, and
    // `bConfigurationValue` 2 against 1.
    let spec = js_sys::Object::new();
    set(&spec, "vendorId", &JsValue::from_f64(f64::from(tdfu_usb::vid::INGENIC)));
    set(
        &spec,
        "productId",
        &JsValue::from_f64(f64::from(tdfu_usb::pid::BOOTROM)),
    );
    set(&spec, "configurations", &dfu_tree(&GADGET_ALT_NAMES));
    let active = js_sys::Object::from(js_sys::Array::from(&dfu_tree(&["nor", "", ""])).get(0));
    set(&active, "configurationValue", &JsValue::from_f64(2.0));
    let interfaces = js_sys::Array::from(&field(&active, "interfaces"));
    let only = js_sys::Object::from(interfaces.get(0));
    let alternates = js_sys::Array::from(&field(&only, "alternates"));
    set(&only, "alternates", &js_sys::Array::of1(&alternates.get(0)));
    set(&spec, "configuration", &active);
    let usb: UsbDevice = scripted(&spec.into()).unchecked_into();

    let (descriptors, strings) = descriptors_and_strings(&usb);
    assert_eq!(strings, vec!["nor".to_owned()], "the active configuration's alt");
    // Byte 5 of a configuration descriptor is `bConfigurationValue`.
    assert_eq!(descriptors.config_descriptor[5], 2);
}

/// A property of a scripted object, as a `JsValue`.
fn field(value: &JsValue, key: &str) -> JsValue {
    js_sys::Reflect::get(value, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

/// **Interning, named for what it proves.**
#[wasm_bindgen_test]
fn two_devices_get_two_ids_and_one_device_gets_one() {
    // Interning is `Object.is` and nothing more: the same object twice is one id, two
    // objects are two ids. The second half is worth a line because an index picks the target:
    // "the first device found is the wrong one" is a flash to the wrong camera.
    //
    // It used to be called `the_same_device_keeps_its_id_across_discoveries` and its
    // comment asserted that an id survived a bootrom-to-gadget re-enumeration, which is
    // a claim this double cannot express and, as the next test shows, is not true either.
    let table = DeviceTable::new();
    assert!(table.is_empty(), "a fresh table has issued no ids");
    let (first, _unused) = device(&js_sys::Array::new(), None);
    let (second, _also_unused) = device(&js_sys::Array::new(), None);
    let first: UsbDevice = first.unchecked_into();
    let second: UsbDevice = second.unchecked_into();

    let id = table.intern(&first);
    assert_eq!(table.intern(&first), id, "the same object got two ids");
    assert_ne!(table.intern(&second), id, "two devices share one id");
    assert_eq!(table.len(), 2);
    assert!(table.get(id).is_some());
    assert!(table.get(99).is_none());
    assert!(!table.is_empty());
}

/// **A re-enumerated device is a new object and a new id.**
#[wasm_bindgen_test]
fn a_device_that_comes_back_after_a_bootstrap_gets_a_new_id() {
    // Chromium caches `USBDevice` by the device service's guid, which is per connection,
    // so the object the page held before a bootstrap is not the object it gets after one.
    // The double expresses that the only way it can be expressed: a second object with
    // the same VID:PID and the same descriptor tree, which is what the bus really offers
    // (bootrom and gadget share `a108:c309`).
    let table = DeviceTable::new();
    let (bootrom, _unused) = device(&js_sys::Array::new(), None);
    let bootrom: UsbDevice = bootrom.unchecked_into();
    let before = table.intern(&bootrom);

    let (gadget, _also_unused) = device(&js_sys::Array::new(), None);
    let gadget: UsbDevice = gadget.unchecked_into();
    assert_eq!(gadget.vendor_id(), bootrom.vendor_id());
    assert_eq!(gadget.product_id(), bootrom.product_id());
    let after = table.intern(&gadget);

    assert_ne!(after, before, "a re-enumerated device kept its id");
    // And the old id still resolves, to the handle that is now dead: nothing prunes it,
    // and the page's way forward is the id `discover()` gives it, not the one it held.
    assert!(table.get(before).is_some());
    assert_eq!(table.len(), 2);
}

#[wasm_bindgen_test]
async fn only_configuration_index_zero_is_served() {
    // `read_config` asks for index 0 and nothing else. Serving another
    // index would mean answering a question the synthesised descriptor cannot answer:
    // the browser exposes one configuration tree, not a numbered set.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let refused = transport
        .control_in(
            ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Device,
                request: 0x06,
                value: 0x0201,
                index: 0,
                len: 9,
            },
            Duration::from_secs(5),
        )
        .await;
    assert!(
        matches!(
            refused.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::Unsupported)
        ),
        "{refused:?}"
    );
    assert!(call_names(&raw).is_empty());
}

/// **The named-alternate pin, end to end through the transport.**
#[wasm_bindgen_test]
async fn read_info_resolves_the_three_alt_names_the_browser_read() {
    // The browser read `iInterface` during enumeration and hands it over as
    // `interfaceName`; the synthesised descriptor gives each name an index and this
    // transport answers `GET_DESCRIPTOR(STRING, index)` from it, so `read_info` comes
    // back with the names a native backend would read off the wire. When every index was
    // 0, every name was "", and `AltSel::Default` (the alt named `flash`) could not
    // resolve on any real three-alt loader.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let info = read_info(&transport).await;
    assert_eq!(alt_names(&info), GADGET_ALT_NAMES.map(ToOwned::to_owned).to_vec());

    // Every descriptor read was answered here: WebUSB refuses standard
    // control requests, so a forwarded one could only fail.
    assert!(
        call_names(&raw).is_empty(),
        "the bus was touched: {:?}",
        call_names(&raw)
    );

    // The three selections the operations make. `AltSel::Default` is `write`, `read` and
    // `verify` with no `alt` in the options object, which is what the page sends
    // (the page's own Write and Read both go out with no `alt`); the two names are what
    // `ops::erase` and `ops::reboot` resolve.
    assert_eq!(resolved(&info, &AltSel::Default), "alt 0");
    assert_eq!(resolved(&info, &AltSel::Name("erase".to_owned())), "alt 1");
    assert_eq!(resolved(&info, &AltSel::Name("reboot".to_owned())), "alt 2");
}

#[wasm_bindgen_test]
async fn a_device_the_browser_named_nothing_on_still_defaults_to_its_first_alt() {
    // `interfaceName` is `null` for a device carrying no `iInterface`, and then the
    // nameless shape is back: index 0, no transfer, an empty name. The first-alt fallback
    // in `dfu::alt` is what keeps that device writable, and it is the C's browser rule
    // (`libtdfu/src/core.c:170-178`) moved into the layer that owns the decision.
    let (raw, transport) = named_device(&js_sys::Array::new(), None, &["", "", ""]);
    let info = read_info(&transport).await;
    assert_eq!(alt_names(&info), vec![String::new(), String::new(), String::new()]);
    assert_eq!(resolved(&info, &AltSel::Default), "alt 0");
    // A name is still a name, and there is nothing on this device to match it.
    assert!(
        resolved(&info, &AltSel::Name("reboot".to_owned())).starts_with("refused: "),
        "{}",
        resolved(&info, &AltSel::Name("reboot".to_owned()))
    );
    assert!(call_names(&raw).is_empty());
}

#[wasm_bindgen_test]
async fn a_string_index_nobody_handed_out_answers_an_empty_string() {
    // Index 0 is the supported-LANGID list rather than a name, and the browser says
    // nothing about which languages the device declares. An empty descriptor is the
    // truthful answer, and `decode_string` reads it as "", rather than a stall that would
    // look like a wedged EP0 and start the reset-and-retry recovery for nothing.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    for value in [0x0300_u16, 0x0309] {
        let answer = transport
            .control_in(
                ControlIn {
                    control_type: ControlType::Standard,
                    recipient: Recipient::Device,
                    request: 0x06,
                    value,
                    index: 0x0409,
                    len: 255,
                },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(answer.as_deref(), Ok(&[2_u8, 3][..]), "{value:#06x}: {answer:?}");
    }
    assert!(call_names(&raw).is_empty());
}

/// **`erase` and `reboot` get past their alt and onto the bus.**
#[wasm_bindgen_test]
async fn erase_and_reboot_resolve_their_own_alt_names_over_webusb() {
    // `ops::erase` and `ops::reboot` each resolve a *named* alt before they claim
    // anything (`erase.rs:116`, `reboot.rs:92`), so on the old nameless descriptor both
    // failed with `MissingAlt` before touching the bus, and the page printed that at
    // `warn`, where it read to the operator as a flake. The scripted device rejects the
    // first real transfer with `SecurityError`, which is `AccessDenied` and outside the
    // reset-and-retry recoverable class, so each operation stops at its first bus call: reaching
    // that failure is the proof that the alt resolved.
    let clock = JsSleeper::new();
    for named in [true, false] {
        let names = if named { GADGET_ALT_NAMES } else { ["", "", ""] };
        for operation in ["erase", "reboot"] {
            let replies = js_sys::Array::of1(&rejecting("SecurityError"));
            let (raw, transport) = named_device(&replies, None, &names);
            let mut sink = tdfu_core::progress::sink_ignore();
            let outcome = if operation == "erase" {
                tdfu_core::ops::erase(&transport, &clock, &mut sink).await
            } else {
                tdfu_core::ops::reboot(&transport, &clock, &mut sink).await
            };
            let reached_the_bus = call_names(&raw).contains(&"controlTransferIn".to_owned());
            let class = outcome_class(outcome);
            if named {
                // Past the alt and onto EP0, where the scripted `SecurityError` stops it.
                assert!(class.starts_with("failed: "), "{operation}: {class}");
                assert!(reached_the_bus, "{operation}: {:?}", call_names(&raw));
            } else {
                // No name to match, and nothing on the bus: the refusal is free, which is
                // why both operations resolve before they claim.
                assert_eq!(class, format!("MissingAlt({operation})"));
                assert!(!reached_the_bus, "{operation}: {:?}", call_names(&raw));
            }
        }
    }
}

#[wasm_bindgen_test]
async fn a_control_out_that_moved_every_byte_succeeds() {
    // The other side of the short-write check. Without this the boundary is untested from
    // one direction only, and a `<` that had become `<=` would report every complete
    // DNLOAD block as short.
    let replies = js_sys::Array::of1(&reply("ok", None, Some(4)));
    let (_raw, transport) = device(&replies, None);
    let written = transport
        .control_out(
            ControlOut {
                control_type: ControlType::Class,
                recipient: Recipient::Interface,
                request: 0x01,
                value: 0,
                index: 0,
                data: &[1, 2, 3, 4],
            },
            Duration::from_secs(30),
        )
        .await;
    assert!(
        written.is_ok(),
        "a complete control OUT was reported short: {written:?}"
    );
}

#[wasm_bindgen_test]
async fn set_alt_setting_goes_out_by_index_and_only_for_the_claimed_interface() {
    // On this backend the index is the selection that always works, and the alt-0 rule
    // decides when the request goes out at all. What is checked here is the other half:
    // the request is refused for an interface this transport never claimed, so a caller
    // bug is answered as `NotClaimed` rather than as a browser error.
    let (raw, transport) = device(&js_sys::Array::new(), None);
    let refused = transport.set_alt_setting(0, 1).await;
    assert!(
        matches!(
            refused.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "{refused:?}"
    );

    let claimed = transport.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(claimed.is_ok(), "{claimed:?}");
    assert!(transport.set_alt_setting(0, 2).await.is_ok());
    assert_eq!(call_arg(&raw, 1, 0).as_f64(), Some(0.0), "interface number");
    assert_eq!(call_arg(&raw, 1, 1).as_f64(), Some(2.0), "alternate setting");

    // A different interface is not the claimed one, even though something is claimed.
    let other = transport.set_alt_setting(1, 0).await;
    assert!(
        matches!(
            other.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "{other:?}"
    );
}

#[wasm_bindgen_test]
async fn invalid_state_is_read_against_our_own_claim_state() {
    // Chromium raises `InvalidStateError` both for "the interface must be claimed first"
    // and for "an interface-state operation is already running". The transport knows
    // which it is in, and answering from that fact rather than from a substring of a
    // message the browser is free to re-word is what keeps `NotClaimed` (a caller bug)
    // apart from `Busy` (a resource conflict).
    let (_raw, unclaimed) = device(&js_sys::Array::new(), Some(("claimInterface", "InvalidStateError")));
    let refused = unclaimed.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(
        matches!(
            refused.as_ref().map_err(tdfu_usb::UsbError::kind),
            Err(UsbErrorKind::NotClaimed)
        ),
        "{refused:?}"
    );

    let rejection = js_sys::Object::new();
    let inner = js_sys::Object::new();
    set(&inner, "name", &JsValue::from_str("InvalidStateError"));
    set(
        &inner,
        "message",
        &JsValue::from_str("An operation that changes state is in progress."),
    );
    set(&rejection, "reject", &inner);
    let replies = js_sys::Array::of1(&rejection.into());
    let (_also_raw, claimed) = device(&replies, None);
    let ok = claimed.claim_interface(InterfaceSpec::control_only(0)).await;
    assert!(ok.is_ok(), "{ok:?}");
    let busy = claimed.control_in(GET_STATUS, Duration::from_secs(5)).await;
    assert!(
        matches!(busy.as_ref().map_err(tdfu_usb::UsbError::kind), Err(UsbErrorKind::Busy)),
        "{busy:?}"
    );
}
