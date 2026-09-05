//! The JS edge: the error shape, the promise shape, the options reader, and the half of
//! the panic edge that can be exercised without trapping the module.
//!
//! The other half, a *real* panic, traps, and that replaces the test harness's own panic
//! hook on the way, so it lives alone in `tests/panic_trap.rs`.

#![cfg(target_family = "wasm")]

use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use tdfu_core::Error;
use tdfu_usb::{Pipe, UsbError, UsbErrorKind};
use tdfu_wasm::options::{self, AltArg};
use tdfu_wasm::{Engine, panic_edge, shape};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;

fn field(value: &JsValue, key: &str) -> JsValue {
    Reflect::get(value, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

fn set(object: &Object, key: &str, value: &JsValue) {
    let _ignored = Reflect::set(object, &JsValue::from_str(key), value);
}

#[wasm_bindgen_test]
fn the_error_shape_is_message_kind_recoverable() {
    // The seam: an Error whose message is tdfu_core::Error's Display, with .kind =
    // the variant's name and .recoverable = Error::is_recoverable().
    let error = Error::NotDfu;
    let value = shape::error_for(&error);
    assert!(value.is_instance_of::<js_sys::Error>(), "not an Error instance");
    assert_eq!(field(&value, "message").as_string(), Some(error.to_string()));
    assert_eq!(field(&value, "kind").as_string().as_deref(), Some("NotDfu"));
    // `NotDfu` is in the reset-and-retry recoverable class (`error.rs:177`): a gadget whose
    // descriptor read failed because EP0 is wedged is exactly what the bus reset is for.
    // Asserted rather than assumed, because `recoverable` is what the page offers a retry
    // from.
    assert_eq!(field(&value, "recoverable").as_bool(), Some(true));
    // The message is the `Display` and nothing else: not prefixed, not re-worded.
    assert!(!error.to_string().is_empty());
}

#[wasm_bindgen_test]
fn a_recoverable_failure_says_so_and_an_unrecoverable_one_does_not() {
    // The page decides whether to offer a retry from this flag, and the reset-and-retry
    // class is what it means. `Verify` is never recoverable: a data mismatch is final.
    let timeout = Error::Usb(UsbError::new(UsbErrorKind::Timeout, Pipe::Device));
    assert_eq!(field(&shape::error_for(&timeout), "recoverable").as_bool(), Some(true));
    let mismatch = Error::Verify {
        offset: 0x100,
        expected: 0xAA,
        actual: Some(0xFF),
    };
    assert_eq!(
        field(&shape::error_for(&mismatch), "recoverable").as_bool(),
        Some(false)
    );
    assert_eq!(
        field(&shape::error_for(&mismatch), "kind").as_string().as_deref(),
        Some("Verify")
    );
}

#[wasm_bindgen_test]
fn a_byte_field_takes_a_uint8array_or_an_arraybuffer() {
    let options = Object::new();
    set(&options, "image", &Uint8Array::from(&[1_u8, 2, 3][..]).into());
    assert_eq!(
        options::bytes_field(&options.clone().into(), "image").ok().flatten(),
        Some(vec![1, 2, 3])
    );

    // `await (await fetch(url)).arrayBuffer()` is the shortest path to a loader image in
    // a browser; refusing it would buy nothing but a puzzled caller.
    let buffer = Uint8Array::from(&[4_u8, 5][..]).buffer();
    let options = Object::new();
    set(&options, "image", &buffer.into());
    assert_eq!(
        options::bytes_field(&options.into(), "image").ok().flatten(),
        Some(vec![4, 5])
    );
}

#[wasm_bindgen_test]
fn a_byte_field_of_the_wrong_type_names_what_arrived() {
    // A `Uint32Array` of 4096 entries is 16 KiB of bytes. Deciding which reading was
    // meant is how a wrong image gets flashed.
    let options = Object::new();
    set(&options, "image", &js_sys::Uint32Array::new_with_length(2).into());
    let refused = options::bytes_field(&options.into(), "image");
    let text = match refused {
        Err(error) => error.to_string(),
        Ok(bytes) => format!("accepted {bytes:?}"),
    };
    assert!(text.contains("image"), "{text}");
    assert!(text.contains("Uint32Array"), "{text}");
}

#[wasm_bindgen_test]
fn an_alt_field_reads_a_name_or_an_index_and_refuses_anything_else() {
    let named = Object::new();
    set(&named, "alt", &JsValue::from_str("erase"));
    assert_eq!(
        options::alt_field(&named.into(), "alt").ok().flatten(),
        Some(AltArg::Name("erase".to_owned()))
    );

    let indexed = Object::new();
    set(&indexed, "alt", &JsValue::from_f64(2.0));
    assert_eq!(
        options::alt_field(&indexed.into(), "alt").ok().flatten(),
        Some(AltArg::Index(2.0))
    );

    let wrong = Object::new();
    set(&wrong, "alt", &Object::new().into());
    assert!(options::alt_field(&wrong.into(), "alt").is_err());
}

#[wasm_bindgen_test]
fn an_absent_options_object_reads_as_every_field_absent() {
    // `engine.erase(id)` and `engine.write(id)` both pass `undefined`; every field is
    // optional by construction so no call site needs a null check first.
    for empty in [JsValue::UNDEFINED, JsValue::NULL] {
        assert!(options::field(&empty, "alt").is_undefined());
        assert_eq!(options::string_field(&empty, "variant"), None);
        assert_eq!(options::number_field(&empty, "size"), None);
        assert!(!options::bool_field(&empty, "verify"));
        assert!(matches!(options::bytes_field(&empty, "image"), Ok(None)));
        assert!(matches!(options::alt_field(&empty, "alt"), Ok(None)));
    }
}

#[wasm_bindgen_test]
fn verify_is_read_as_a_boolean_and_not_as_truthiness() {
    // `verify: "no"` is `true` under JS truthiness, and `verify: 0` is `false`. A silent
    // verify-when-you-meant-not is a slow surprise; the other way round is a wrong result
    // reported as a right one.
    let noisy = Object::new();
    set(&noisy, "verify", &JsValue::from_str("no"));
    assert!(!options::bool_field(&noisy.into(), "verify"));

    let asked = Object::new();
    set(&asked, "verify", &JsValue::TRUE);
    assert!(options::bool_field(&asked.into(), "verify"));
}

/// A promise built the way [`tdfu_wasm::engine`]'s `settle` builds one, with its `reject`
/// registered with the panic edge.
fn registered_promise() -> (Promise, panic_edge::Ticket) {
    let captured: Rc<RefCell<Option<Function>>> = Rc::new(RefCell::new(None));
    let sink = Rc::clone(&captured);
    let promise = Promise::new(&mut move |_resolve, reject| {
        *sink.borrow_mut() = Some(reject);
    });
    let reject = captured.borrow().clone().unwrap_or_else(|| Function::new_no_args(""));
    let ticket = panic_edge::register(&reject);
    (promise, ticket)
}

#[wasm_bindgen_test]
async fn a_panic_rejects_every_promise_in_flight() {
    // The heart of the panic edge. On a `panic = "abort"` target the trap that follows the
    // hook cannot be caught by wasm code, and it lands in the microtask that polls the
    // future rather than in the page's `await`, so the promise would stay pending for
    // ever. The hook runs *before* the trap and rejects it.
    let before = panic_edge::pending_count();
    let (first, _first_ticket) = registered_promise();
    let (second, _second_ticket) = registered_promise();
    assert_eq!(panic_edge::pending_count(), before + 2);

    panic_edge::report("panicked at src/engine.rs:12:5: the sky fell in");
    // Every promise in flight, not only the one that panicked: after a trap the module's
    // state is undefined, so an operation that has not failed yet cannot be promised a
    // correct answer, and leaving it pending is the hang.
    assert_eq!(panic_edge::pending_count(), 0);

    for promise in [first, second] {
        // The rejection is read out of a value rather than out of a `match` arm ending in
        // `assert!(false, ..)`: that is `clippy::assertions_on_constants`, which the
        // wasm-target gate now denies too, and `panic!` is denied outright. So a
        // promise that resolved fails the `is_err` line, naming what it resolved
        // with.
        let outcome = JsFuture::from(promise).await;
        assert!(outcome.is_err(), "the promise resolved with {outcome:?}");
        let value = outcome.err().unwrap_or(JsValue::UNDEFINED);
        assert_eq!(field(&value, "kind").as_string().as_deref(), Some("Panic"));
        assert_eq!(field(&value, "recoverable").as_bool(), Some(false));
        let message = field(&value, "message").as_string().unwrap_or_default();
        assert!(message.contains("the sky fell in"), "{message}");
        assert!(message.contains("src/engine.rs:12:5"), "{message}");
    }

    assert_eq!(
        panic_edge::last_message().as_deref(),
        Some("panicked at src/engine.rs:12:5: the sky fell in")
    );
}

#[wasm_bindgen_test]
fn a_settled_ticket_is_no_longer_the_panic_edges_problem() {
    // Without this the registry would grow for the life of the page and a panic would
    // reject promises that resolved minutes ago - calling `reject` on a settled promise
    // is a no-op, but the leak is not.
    let before = panic_edge::pending_count();
    let (_promise, ticket) = registered_promise();
    assert_eq!(panic_edge::pending_count(), before + 1);
    ticket.settle();
    assert_eq!(panic_edge::pending_count(), before);
}

#[wasm_bindgen_test]
async fn an_engine_rejects_rather_than_throwing_when_there_is_no_webusb() {
    // Node has no `navigator.usb`, which is also Firefox and Safari and any Chromium
    // outside a secure context. The seam's "nothing throws synchronously" has to
    // hold for that too, or the page's `try { await engine.discover() }` misses it.
    let engine = Engine::new(&JsValue::UNDEFINED);
    let outcome = JsFuture::from(engine.discover()).await;
    assert!(outcome.is_err(), "Node answered a device list: {outcome:?}");
    let value = outcome.err().unwrap_or(JsValue::UNDEFINED);
    assert_eq!(field(&value, "kind").as_string().as_deref(), Some("Usb"));
    let message = field(&value, "message").as_string().unwrap_or_default();
    assert!(message.contains("unsupported"), "{message}");
}

#[wasm_bindgen_test]
async fn an_unknown_device_id_is_a_rejection_that_names_it() {
    // The id table is the engine's own, so "that id was never issued" is answerable here
    // rather than as a browser error from three layers on.
    let engine = Engine::new(&JsValue::UNDEFINED);
    assert_eq!(engine.device_count(), 0);
    let outcome = JsFuture::from(engine.detect(7)).await;
    assert!(outcome.is_err(), "detect answered {outcome:?}");
    let value = outcome.err().unwrap_or(JsValue::UNDEFINED);
    let message = field(&value, "message").as_string().unwrap_or_default();
    assert!(message.contains('7'), "{message}");
    assert!(message.contains("never issued"), "{message}");
}

#[wasm_bindgen_test]
async fn a_bad_option_rejects_before_the_bus_is_touched() {
    // An argument error is still a rejection, not a throw, and it carries the `Invalid`
    // kind so `tdfu.js` can tell a caller mistake from a device failure.
    let engine = Engine::new(&JsValue::UNDEFINED);
    let options = Object::new();
    set(&options, "alt", &JsValue::from_f64(256.0));
    set(&options, "image", &Uint8Array::from(&[1_u8][..]).into());
    let outcome = JsFuture::from(engine.write(0, options.into())).await;
    assert!(outcome.is_err(), "write accepted alt 256: {outcome:?}");
    let value = outcome.err().unwrap_or(JsValue::UNDEFINED);
    assert_eq!(field(&value, "kind").as_string().as_deref(), Some("Invalid"));
    let message = field(&value, "message").as_string().unwrap_or_default();
    assert!(message.contains("256"), "{message}");
}

#[wasm_bindgen_test]
async fn the_engine_hands_back_promises_and_never_throws_on_the_way_out() {
    // Every operation, called with arguments that cannot work, on an engine with no
    // callbacks: each returns a `Promise` synchronously. A `throw` here would escape the
    // page's `catch`, because a page awaits.
    let engine = Engine::new(&JsValue::UNDEFINED);
    let empty = JsValue::UNDEFINED;
    let promises = [
        engine.request_device(),
        engine.discover(),
        engine.detect(0),
        engine.bootstrap(0, empty.clone()),
        engine.write(0, empty.clone()),
        engine.read(0, empty.clone()),
        engine.verify(0, empty.clone()),
        engine.erase(0),
        engine.reboot(0),
        engine.diag(0),
    ];
    assert_eq!(promises.len(), 10, "the ten operations of the frozen seam");
    for promise in promises {
        assert!(promise.is_instance_of::<Promise>());
        // Each is awaited rather than dropped: every one of them rejects here (Node has
        // no `navigator.usb`, and id 0 was never issued), and an unhandled rejection
        // fails the Node run on its own.
        let outcome = JsFuture::from(promise).await;
        assert!(outcome.is_err(), "one of them resolved: {outcome:?}");
    }
}

#[wasm_bindgen_test]
fn the_callbacks_are_optional_and_a_non_function_is_ignored() {
    // The constructor is the one call that could throw synchronously, and the seam says
    // nothing does.
    let broken = Object::new();
    set(&broken, "log", &JsValue::from_str("not a function"));
    set(&broken, "progress", &JsValue::from_f64(1.0));
    let engine = Engine::new(&broken.into());
    engine.set_debug(true);
    assert_eq!(engine.device_count(), 0);
}

#[wasm_bindgen_test]
fn the_log_callback_is_bound_to_the_object_it_came_from() {
    // `{ log(line, level) { this.lines.push(line); } }` is how a page writes it; read as
    // a bare property it would be called with `this === undefined`.
    let callbacks = Object::new();
    let lines = js_sys::Array::new();
    set(&callbacks, "lines", &lines);
    let log = Function::new_with_args("line, level", "this.lines.push(line + '/' + level);");
    set(&callbacks, "log", &log);

    let engine = Engine::new(&callbacks.into());
    engine.set_debug(true);
    assert!(lines.length() >= 1, "setDebug(true) says which build is running");
    let first = lines.get(0).as_string().unwrap_or_default();
    assert!(first.ends_with("/debug"), "{first}");
    assert!(first.contains(tdfu_wasm::VERSION), "{first}");
}

#[wasm_bindgen_test]
fn the_level_gate_is_what_set_debug_moves_and_nothing_else() {
    // `Logger::line`'s gate is the only thing between a page that renders one line per
    // block of a 16 MiB write and one that renders none. It is observable only through a
    // real callback, which is why this is here and not in the host tests: with no sink
    // there is nothing to see either way.
    let holder = Object::new();
    let lines = js_sys::Array::new();
    set(&holder, "lines", &lines);
    let sink = Function::new_with_args("line, level", "this.lines.push(level + ':' + line);");
    let logger = tdfu_wasm::log::Logger::new(Some(sink.bind0(&holder.into()).unchecked_into()));

    // Off by default: a debug line is dropped, an info line and a warning are not.
    logger.line(tdfu_wasm::log::Level::Debug, "quiet");
    logger.info("loud");
    logger.warn("careful");
    assert_eq!(lines.length(), 2, "a debug line came through with debug off");
    assert_eq!(lines.get(0).as_string().as_deref(), Some("info:loud"));
    assert_eq!(lines.get(1).as_string().as_deref(), Some("warn:careful"));

    // And on, the same call comes through: the only difference is the flag.
    logger.set_debug(true);
    logger.line(tdfu_wasm::log::Level::Debug, "quiet");
    assert_eq!(lines.length(), 3, "a debug line was dropped with debug on");
    assert_eq!(lines.get(2).as_string().as_deref(), Some("debug:quiet"));
}

#[wasm_bindgen_test]
fn variant_names_reaches_javascript_as_a_string_array() {
    // `remote.js` indexes this by a DISCOVER entry's variant byte.
    let names = tdfu_wasm::engine::variant_names();
    assert_eq!(names.len(), 59);
    assert!(names.iter().all(|name| !name.is_empty()));
    let version = tdfu_wasm::engine::version();
    assert!(version.starts_with(tdfu_wasm::VERSION), "{version}");
}

#[wasm_bindgen_test]
fn a_device_info_has_exactly_the_five_frozen_keys() {
    // The seam: `{ id, vid, pid, stage, variant }`. `tdfu.js` destructures this, so
    // a missing key is `undefined` in the device list and an extra one is surface the
    // page was never told about.
    let descriptors = tdfu_usb::DeviceDescriptors::new(tdfu_usb::vid::INGENIC, tdfu_usb::pid::BOOTROM)
        .with_product_string("\u{c3}\t USB Boot Device");
    let info = shape::device_info(3, &descriptors, Some("t41nq"));
    assert_eq!(field(&info, "id").as_f64(), Some(3.0));
    assert_eq!(field(&info, "vid").as_f64(), Some(f64::from(tdfu_usb::vid::INGENIC)));
    assert_eq!(field(&info, "pid").as_f64(), Some(f64::from(tdfu_usb::pid::BOOTROM)));
    // The bootrom's product string has a junk prefix on every unit seen, so
    // the stage comes from a `contains`, never an equality test.
    assert_eq!(field(&info, "stage").as_string().as_deref(), Some("bootrom"));
    assert_eq!(field(&info, "variant").as_string().as_deref(), Some("t41nq"));
    assert_eq!(keys(&info), vec!["id", "vid", "pid", "stage", "variant"]);

    // Before detection the variant is null, not a guess.
    let fresh = shape::device_info(0, &descriptors, None);
    assert!(field(&fresh, "variant").is_null());
}

#[wasm_bindgen_test]
fn a_detection_has_exactly_the_six_frozen_keys_on_every_arm() {
    // `{ variant, chip, family, dram, evidence, caveat }`. The registers are a real
    // T41NQ's, read on the bench.
    let resolved = tdfu_core::detect::decode(tdfu_core::model::SocRegs::new(0x1004_0003, 0, 0xAAAA_2222));
    let value = shape::detection(&resolved);
    assert_eq!(
        keys(&value),
        vec!["variant", "chip", "family", "dram", "evidence", "caveat"]
    );
    assert_eq!(field(&value, "variant").as_string().as_deref(), Some("t41nq"));
    assert_eq!(field(&value, "chip").as_string().as_deref(), Some("T41NQ"));
    assert_eq!(field(&value, "family").as_string().as_deref(), Some("T4x"));
    assert_eq!(field(&value, "evidence").as_string().as_deref(), Some("bench"));
    // T41NQ is DDR3 16-bit in Ingenic's own U-Boot header, and that
    // string is what an operator reads to choose `--cpu` when detection refuses.
    let dram = field(&value, "dram").as_string().unwrap_or_default();
    assert!(dram.contains("DDR3"), "{dram}");
    // Bench evidence needs no qualification.
    assert!(field(&value, "caveat").is_null());

    // An ambiguous grade: no variant, but the sentence that says what to do is not null -
    // it is the whole answer: the information is in hand, so print it.
    let ambiguous = tdfu_core::detect::decode(tdfu_core::model::SocRegs::new(0x1004_0003, 0, 0x1111_1111));
    let value = shape::detection(&ambiguous);
    assert_eq!(
        keys(&value),
        vec!["variant", "chip", "family", "dram", "evidence", "caveat"]
    );
    assert!(field(&value, "variant").is_null());
    assert!(field(&value, "chip").is_null());
    assert_eq!(field(&value, "family").as_string().as_deref(), Some("T4x"));
    let caveat = field(&value, "caveat").as_string().unwrap_or_default();
    assert!(!caveat.is_empty(), "an ambiguous detection said nothing");
    assert!(caveat.contains("--cpu"), "{caveat}");
}

/// An object's own keys, in insertion order.
fn keys(value: &JsValue) -> Vec<String> {
    Object::keys(&Object::from(value.clone()))
        .iter()
        .filter_map(|key| key.as_string())
        .collect()
}
