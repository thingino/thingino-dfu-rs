//! [`WebUsbBackend`]: discovery and opening, behind the frozen [`LocalUsbBackend`].
//!
//! # An id names a connection, not a camera
//!
//! `DeviceId` is a `u32` index into [`DeviceTable`], which interns `USBDevice` objects by
//! identity (`Object.is`). So an id is stable for as long as the browser keeps handing
//! back the same object, and **that is for as long as the device stays plugged in**, not
//! for the page's lifetime. Chromium caches its `USBDevice` wrappers by the device
//! service's guid, which is created per connection and destroyed on disconnect, so a
//! device that re-enumerates comes back as a *new* object that `Object.is` will not match,
//! and `intern` issues it a *new* id.
//!
//! That is exactly what a bootstrap does: the bootrom disappears and a DFU gadget appears
//! (`a108:c309` in both roles, told apart by the product string). So after `engine.bootstrap(id, ...)` the
//! **page must `discover()` again** and use the id that comes back; the old one names a
//! handle that is gone, and any operation on it fails with the browser's own
//! `NotFoundError`, which reaches the page as `NoDevice`. Two consequences are worth
//! stating rather than leaving to be found:
//!
//! * The engine's remembered variant (`Inner::detected`) is keyed by id, so a `detect`
//!   run against the bootrom does **not** carry over to the gadget's new id, and
//!   `DeviceInfo.variant` is `null` again after a bootstrap. Inventing one would render a
//!   guess as a fact; re-running `detect` is three register reads.
//! * The engine's open-transport entry for the old id stays in its map for the page's
//!   lifetime, holding a `USBDevice` the browser has already dropped the connection to.
//!   It is one dead handle per bootstrap, not a growing leak, and nothing reads it again.
//!
//! The seam's "stable for the page session" is therefore about what an id **is**
//! (an opaque handle the page can hold, not a bus address that shifts under it), not a
//! promise that one survives a re-enumeration. An audit found the claim that it did was
//! uncited, and that the pin carrying it in its name interned two objects in one tick,
//! which is `Object.is` and nothing more. The browser half is settled on hardware:
//! discover, note the id, bootstrap, discover again, compare.
//!
//! Interning is still what the frozen backend trait asks for: an opaque handle carried from
//! [`list`](LocalUsbBackend::list), so `open` never re-enumerates the bus to match a
//! device by its fields.
//!
//! # What is not reproduced from the shim
//!
//! `libusb_get_device_list` retried `getDevices()` **sixteen times at 500 ms** when it
//! found nothing but had found something before (`libusb-webusb.js:82-101`), and merged
//! in a `window._webusb_devices` list that `requestDevice` maintained separately
//! (`:85-88`). Neither is here:
//!
//! * A list is a **pure scan**: no open, no probe, no wait. Waiting eight
//!   seconds inside it would make `discover()` unsafe to poll and would hide the
//!   re-enumeration window from the frontend that owns it: the 30 s a loader that probes MMC or NAND can take, which
//!   `app.js` already implements as a `navigator.usb` `connect` listener.
//! * The side list is unnecessary because [`DeviceTable`] interns whatever
//!   `requestDevice` returned, and an authorized device is returned by `getDevices()`
//!   anyway. The shim needed it because it had nowhere else to keep one.

use core::cell::RefCell;
use std::rc::Rc;

use js_sys::{Object, Reflect};
use tdfu_usb::{DeviceDescriptors, Discovered, LocalUsbBackend, Pipe, UsbError, UsbErrorKind, pid, vid};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Usb, UsbDevice, UsbDeviceFilter, UsbDeviceRequestOptions};

use crate::log::Logger;
use crate::usb::descriptor::{self, Alternate};
use crate::usb::transport::WebUsbTransport;

/// The VID:PID pairs `requestDevice` asks the operator to authorize.
///
/// Eleven, exactly as the shipped C page asks for them (the C's `web/src/app.js:479-489`), and for
/// the reason its own comment gives: permission is granted per VID:PID, and a bootstrap
/// re-enumerates the device, so a page authorized only for the bootrom would need a
/// second chooser click before it could talk to the gadget it just started.
///
/// It is the cross product of the two Ingenic vendor ids with five product ids, plus
/// `601A:4770` on its own. The missing twelfth cell, `A108:4770`, is deliberate and is
/// the shipped list's shape: `0x4770` is the X-series bootrom
/// (`libtdfu/include/tdfu/tdfu.h:52`), no X-series loader exists in `firmware/dfu/`,
/// and a chooser entry for a device nobody can flash is a worse default
/// than a second click if one ever appears.
pub const REQUEST_FILTERS: [(u16, u16); 11] = [
    (vid::INGENIC_X, pid::BOOTROM_X),
    (vid::INGENIC_X, pid::BOOTROM),
    (vid::INGENIC, pid::BOOTROM),
    (vid::INGENIC_X, pid::FIRMWARE),
    (vid::INGENIC, pid::FIRMWARE),
    (vid::INGENIC_X, pid::FIRMWARE_X),
    (vid::INGENIC, pid::FIRMWARE_X),
    (vid::INGENIC_X, pid::BOOTROM_ALT),
    (vid::INGENIC, pid::BOOTROM_ALT),
    (vid::INGENIC_X, pid::DFU_LEGACY),
    (vid::INGENIC, pid::DFU_LEGACY),
];

/// The page's `USBDevice` handles, numbered.
#[derive(Debug, Clone, Default)]
pub struct DeviceTable {
    entries: Rc<RefCell<Vec<UsbDevice>>>,
}

impl DeviceTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The id of `device`, allocating one if it has not been seen.
    ///
    /// Identity is `Object.is`, not a VID:PID comparison: two cameras of the same model
    /// on one bus are two entries, and the same camera seen twice is one. The distinction
    /// is worth a line because an index selects the target: "the first device found is the
    /// wrong one" is a flash to the wrong camera.
    #[must_use]
    pub fn intern(&self, device: &UsbDevice) -> u32 {
        let Ok(mut entries) = self.entries.try_borrow_mut() else {
            return u32::MAX;
        };
        if let Some(index) = entries
            .iter()
            .position(|known| Object::is(known.as_ref(), device.as_ref()))
        {
            return u32::try_from(index).unwrap_or(u32::MAX);
        }
        entries.push(device.clone());
        u32::try_from(entries.len() - 1).unwrap_or(u32::MAX)
    }

    /// The handle behind an id.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<UsbDevice> {
        let entries = self.entries.try_borrow().ok()?;
        entries.get(usize::try_from(id).ok()?).cloned()
    }

    /// How many devices have been issued an id.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.try_borrow().map_or(0, |entries| entries.len())
    }

    /// Has nothing been seen yet?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// WebUSB discovery.
#[derive(Debug, Clone)]
pub struct WebUsbBackend {
    table: DeviceTable,
    log: Logger,
}

impl WebUsbBackend {
    /// A backend over `navigator.usb`, sharing `table` with the engine.
    #[must_use]
    pub fn new(table: DeviceTable, log: Logger) -> Self {
        Self { table, log }
    }

    /// The device table this backend interns into.
    #[must_use]
    pub fn table(&self) -> &DeviceTable {
        &self.table
    }

    /// Show the browser's device chooser, and intern whatever the operator picked.
    ///
    /// `Ok(None)` when the chooser was dismissed: Chromium rejects with `NotFoundError`
    /// ("No device selected"), which is a choice rather than a failure and the seam says
    /// so: `requestDevice` "resolves `DeviceInfo`, or null when the chooser is
    /// dismissed".
    ///
    /// # Errors
    /// [`UsbErrorKind::AccessDenied`] when the call was not made from a user gesture or
    /// the context is not secure, and whatever else the browser raised.
    pub async fn request_device(&self) -> Result<Option<(u32, DeviceDescriptors)>, UsbError> {
        let usb = navigator_usb()?;
        let filters: Vec<UsbDeviceFilter> = REQUEST_FILTERS
            .iter()
            .map(|&(vendor, product)| {
                let filter = UsbDeviceFilter::new();
                filter.set_vendor_id(vendor);
                filter.set_product_id(product);
                filter
            })
            .collect();
        let options = UsbDeviceRequestOptions::new(&filters);
        match JsFuture::from(usb.request_device(&options)).await {
            Ok(device) => {
                let device: UsbDevice = device.unchecked_into();
                let id = self.table.intern(&device);
                Ok(Some((id, descriptors_of(&device))))
            }
            Err(value) => {
                let error = dom_failure(&self.log, &value);
                if matches!(error.kind(), UsbErrorKind::NoDevice) {
                    self.log.debug(|| "the device chooser was dismissed".to_owned());
                    return Ok(None);
                }
                Err(error)
            }
        }
    }
}

impl LocalUsbBackend for WebUsbBackend {
    type Transport = WebUsbTransport;
    type DeviceId = u32;

    async fn list(&self) -> Result<Vec<Discovered<u32>>, UsbError> {
        let usb = navigator_usb()?;
        let devices = JsFuture::from(usb.get_devices())
            .await
            .map_err(|value| dom_failure(&self.log, &value))?;
        let devices: js_sys::Array = devices.unchecked_into();
        let mut found = Vec::new();
        for index in 0..devices.length() {
            let device: UsbDevice = devices.get(index).unchecked_into();
            // Nothing but an Ingenic vendor id is ever opened. The page may
            // hold permission for anything the operator once picked.
            if !vid::is_ingenic(device.vendor_id()) {
                continue;
            }
            found.push(Discovered {
                id: self.table.intern(&device),
                descriptors: descriptors_of(&device),
            });
        }
        self.log.debug(|| {
            format!(
                "navigator.usb.getDevices(): {} authorized Ingenic device(s)",
                found.len()
            )
        });
        Ok(found)
    }

    async fn open(&self, id: &u32) -> Result<WebUsbTransport, UsbError> {
        let device = self.table.get(*id).ok_or_else(|| {
            UsbError::new(
                UsbErrorKind::Backend(format!(
                    "device id {id} was never issued by discover() or requestDevice()"
                )),
                Pipe::Device,
            )
        })?;
        // The shim never closed a device once opened ("Closing and reopening races in
        // the browser", `libusb-webusb.js:199-208`), and the engine keeps the same
        // handle for the page's lifetime for the same reason, so this is usually a
        // no-op on the second and later operations.
        if !device.opened() {
            JsFuture::from(device.open())
                .await
                .map_err(|value| dom_failure(&self.log, &value))?;
        }
        let synthesised = config_bytes(&device);
        if synthesised.config.is_empty() {
            self.log.warn(
                "the browser exposed no configuration for this device, so its stage cannot be told from a \
                 descriptor; a bootrom and a DFU gadget share a108:c309",
            );
        } else if synthesised.has_functional {
            // 4096 is used, and the log says it was assumed rather than read.
            // Asked of the synthesis rather than scanned back out of the bytes, which
            // matched a byte pair an ordinary interface descriptor can carry.
            self.log.debug(descriptor::assumed_transfer_size_note);
        }
        let descriptor::Synthesised { config, strings, .. } = synthesised;
        let descriptors = enumeration_facts(&device).with_config_descriptor(config);
        let configuration = device.configuration().map(|active| active.configuration_value());
        self.log.debug(|| match strings.len() {
            0 => "the browser named no alternate on this device: alt selection is by index".to_owned(),
            named => format!("the browser named {named} alternate(s): {}", strings.join(", ")),
        });
        Ok(WebUsbTransport::new(
            device,
            descriptors,
            strings,
            configuration,
            self.log.clone(),
        ))
    }
}

/// What enumeration can say about a device, without opening it.
///
/// `bus` and `address` stay 0 and `port_path` stays empty: WebUSB exposes none of them
/// (the shim answered bus 1 and "address = list index"
/// (`libusb-webusb.js:156-165`), which are inventions). `product_string` is **not** an
/// invention: `USBDevice.productName` is real, the browser read it during enumeration,
/// and it is what `classify` falls back to when a device answers no configuration
/// descriptor. The shim had no string API at all and therefore could not use it.
#[must_use]
pub fn descriptors_of(device: &UsbDevice) -> DeviceDescriptors {
    descriptors_and_strings(device).0
}

/// The vendor id, product id and product string, with no descriptor yet.
///
/// Split out so [`LocalUsbBackend::open`] can read the synthesis once, use its
/// `has_functional` flag for the assumed-transfer-size log, and move its bytes into the descriptors
/// without a second walk of the browser's tree or a copy of the bytes.
fn enumeration_facts(device: &UsbDevice) -> DeviceDescriptors {
    let descriptors = DeviceDescriptors::new(device.vendor_id(), device.product_id());
    match device.product_name() {
        Some(product) => descriptors.with_product_string(product),
        None => descriptors,
    }
}

/// [`descriptors_of`], plus the alt names the synthesised descriptor's `iInterface`
/// indices point into.
///
/// The two are one artefact and only [`LocalUsbBackend::open`] needs the second half:
/// `list` describes devices it has not opened and has nothing to answer a
/// `GET_DESCRIPTOR(STRING)` with, so it takes the first. See
/// [`descriptor`](super::descriptor) for why the indices are ours rather than the
/// device's.
#[must_use]
pub fn descriptors_and_strings(device: &UsbDevice) -> (DeviceDescriptors, Vec<String>) {
    let synthesised = config_bytes(device);
    (
        enumeration_facts(device).with_config_descriptor(synthesised.config),
        synthesised.strings,
    )
}

/// Rebuild the configuration descriptor from the browser's parsed tree.
fn config_bytes(device: &UsbDevice) -> descriptor::Synthesised {
    // Configuration **index 0**, not the active one: the driverless gadget often has no
    // configuration selected, and a claim needs the descriptor before it can set one.
    // `device.configuration` is preferred when the
    // browser has one because it is the same object.
    let configurations = device.configurations();
    let Some(configuration) = device
        .configuration()
        .or_else(|| (configurations.length() > 0).then(|| configurations.get(0)))
    else {
        return descriptor::Synthesised::default();
    };
    let interfaces = configuration.interfaces();
    let mut alternates = Vec::new();
    for index in 0..interfaces.length() {
        let interface = interfaces.get(index);
        let number = interface.interface_number();
        let settings = interface.alternates();
        for setting in 0..settings.length() {
            let alternate = settings.get(setting);
            alternates.push(Alternate {
                interface: number,
                alternate: alternate.alternate_setting(),
                class: alternate.interface_class(),
                subclass: alternate.interface_subclass(),
                protocol: alternate.interface_protocol(),
                // `interfaceName` is the string the browser read from the device's own
                // `iInterface` during enumeration. `None` is a device that
                // carries none; `""` is a device that carries an empty one, and both mean
                // the same thing to the resolver, so they collapse here.
                name: alternate.interface_name().unwrap_or_default(),
            });
        }
    }
    descriptor::build(
        configuration_value(configuration.configuration_value()),
        usize::try_from(interfaces.length()).unwrap_or(0),
        &alternates,
    )
}

/// `bConfigurationValue` for the synthesised descriptor, defaulting where the browser
/// gives none.
///
/// The same fallback `dfu::descriptors` applies to a real descriptor: configuration 1 is
/// what every shipped loader uses, and a device that reports 0 (the Address state, no
/// configuration selected) still has to be told which one to enter. A
/// descriptor whose `bConfigurationValue` was 0 would make the claim path issue
/// `SET_CONFIGURATION(0)`, which is the request that *removes* a configuration.
///
/// Pure over the byte so the rule is host-tested: `UsbConfiguration` is a `web-sys` type
/// and cannot be built without a JS heap.
#[must_use]
pub const fn configuration_value(reported: u8) -> u8 {
    if reported == 0 { DEFAULT_CONFIGURATION } else { reported }
}

/// The configuration a device with none selected is put into before its interface is claimed.
pub const DEFAULT_CONFIGURATION: u8 = 1;

/// `globalThis.navigator.usb`, or a refusal that says what is missing.
///
/// Read off the global rather than through `web_sys::window()`: it works in a page, in a
/// worker and in the Node runtime the `wasm-bindgen-test` suite uses, and it drops the
/// `Window` feature. The property check is not defensive padding: WebUSB is absent in
/// Firefox and Safari entirely, and absent in Chromium outside a secure context, and
/// calling `undefined.getDevices()` would throw out of a promise callback that nothing
/// catches (see [`crate::panic_edge`] for why that is the one thing to avoid).
///
/// # Errors
/// [`UsbErrorKind::Unsupported`] naming what to do about it.
pub fn navigator_usb() -> Result<Usb, UsbError> {
    let unsupported = || UsbError::new(UsbErrorKind::Unsupported, Pipe::Device);
    let global = js_sys::global();
    let navigator = Reflect::get(&global, &JsValue::from_str("navigator")).map_err(|_| unsupported())?;
    if !navigator.is_object() {
        return Err(unsupported());
    }
    let usb = Reflect::get(&navigator, &JsValue::from_str("usb")).map_err(|_| unsupported())?;
    if !usb.is_object() {
        return Err(unsupported());
    }
    Ok(usb.unchecked_into())
}

/// What to tell an operator whose browser has no WebUSB.
///
/// A constant on one line, for the same reason
/// [`crate::ACCESS_DENIED_HINT`] is: one literal, one line, no `rustfmt` join.
pub const NO_WEBUSB_HINT: &str = "this browser has no WebUSB: use a Chromium-based browser (Chrome, Edge, Opera) over https or on localhost, or switch the page to remote mode and flash through a thingino-dfu daemon";

/// A device-level failure from a rejected promise, when there is no transport to ask
/// about its claim.
///
/// The browser's own words go out on the log at debug before the mapping throws them
/// away: "Unable to claim interface" and "The device
/// was disconnected" are Chromium's, and the seam cannot carry them, because
/// `Error.message` is `tdfu_core::Error`'s `Display` exactly. The log is
/// where the rest of the diagnosis already goes.
fn dom_failure(log: &Logger, value: &JsValue) -> UsbError {
    let (name, message) = describe(value);
    log.debug(|| browser_words(&name, &message));
    UsbError::new(crate::usb::error::kind_from_dom(&name, &message, false), Pipe::Device)
}

/// What the browser said, for the debug log.
///
/// Pure and host-tested, because the whole value of this line is that a bug report
/// carries the exception's own text: a formatter that dropped the message would leave the log saying
/// exactly what the error already says.
#[must_use]
pub fn browser_words(name: &str, message: &str) -> String {
    match (name.is_empty(), message.is_empty()) {
        (true, true) => "the browser rejected the request without saying why".to_owned(),
        (true, false) => format!("the browser said: {message}"),
        (false, true) => format!("the browser raised {name}"),
        (false, false) => format!("the browser raised {name}: {message}"),
    }
}

/// The name and message of a rejected promise's value. See the transport's twin.
fn describe(value: &JsValue) -> (String, String) {
    if let Some(marker) = value.as_string() {
        return (marker, String::new());
    }
    if let Some(exception) = value.dyn_ref::<web_sys::DomException>() {
        return (exception.name(), exception.message());
    }
    let name = Reflect::get(value, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
        .unwrap_or_default();
    let message = Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| format!("{value:?}"));
    (name, message)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CONFIGURATION, NO_WEBUSB_HINT, REQUEST_FILTERS, configuration_value};
    use tdfu_usb::{pid, vid};

    #[test]
    fn a_device_with_no_configuration_selected_is_given_the_default() {
        // The driverless DFU gadget often reports 0, and a synthesised
        // descriptor carrying 0 would make the claim issue `SET_CONFIGURATION(0)` - the
        // request that *removes* a configuration rather than entering one.
        assert_eq!(configuration_value(0), DEFAULT_CONFIGURATION);
        // Anything the device really named is kept, including a value that is not 1.
        assert_eq!(configuration_value(1), 1);
        assert_eq!(configuration_value(2), 2);
        assert_eq!(configuration_value(255), 255);
    }

    #[test]
    fn the_filters_are_the_eleven_the_shipped_page_asks_for() {
        // The C's `web/src/app.js:479-489`. A shorter list means a second chooser click after a
        // bootstrap re-enumerates the device; a longer one means offering the operator a
        // device nobody can flash.
        assert_eq!(REQUEST_FILTERS.len(), 11);
        for &(vendor, _) in &REQUEST_FILTERS {
            assert!(vid::is_ingenic(vendor), "{vendor:#06x} is not an Ingenic VID");
        }
        assert!(REQUEST_FILTERS.contains(&(vid::INGENIC, pid::BOOTROM)));
        assert!(REQUEST_FILTERS.contains(&(vid::INGENIC, pid::DFU_LEGACY)));
        assert!(REQUEST_FILTERS.contains(&(vid::INGENIC_X, pid::BOOTROM_X)));
        // The one cell of the cross product that is deliberately absent.
        assert!(!REQUEST_FILTERS.contains(&(vid::INGENIC, pid::BOOTROM_X)));
    }

    #[test]
    fn no_pair_is_asked_for_twice() {
        // A duplicate filter is a duplicate row in the browser's chooser.
        let mut seen = REQUEST_FILTERS.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), REQUEST_FILTERS.len());
    }

    #[test]
    fn the_browsers_own_words_survive_into_the_debug_line() {
        // Every mapped `DOMException` arm drops the message, so the log line
        // is the only place Chromium's own wording reaches a bug report. All four
        // combinations of a missing name and a missing message have to say something.
        let words = super::browser_words("NetworkError", "Unable to claim interface.");
        assert!(words.contains("NetworkError"), "{words}");
        assert!(words.contains("Unable to claim interface."), "{words}");
        for (name, message) in [("", ""), ("", "boom"), ("OddError", ""), ("OddError", "boom")] {
            let words = super::browser_words(name, message);
            assert!(!words.is_empty(), "{name}/{message} produced no prose");
            assert!(words.starts_with("the browser"), "{words}");
        }
    }

    #[test]
    fn the_no_webusb_hint_is_one_clean_sentence() {
        // A `rustfmt` string join once put a 14-space gap in the middle of the native
        // hint, and nothing noticed because nothing looked.
        assert!(!NO_WEBUSB_HINT.contains("  "), "{NO_WEBUSB_HINT:?}");
        assert!(!NO_WEBUSB_HINT.contains('\n'));
        assert!(!NO_WEBUSB_HINT.ends_with('.'));
        // It must name the way out that does not need WebUSB at all.
        assert!(NO_WEBUSB_HINT.contains("remote mode"), "{NO_WEBUSB_HINT}");
    }
}
