//! The descriptor bytes [`FakeGadget`](super::FakeGadget) serves.
//!
//! Everything here is **generated from [`GadgetConfig`]**, never from a captured blob.
//! An earlier emulator had a configurable `transfer_size` that drove its own block
//! arithmetic while the descriptor the host read stayed the captured T32LQ's 4096, so
//! setting the knob silently desynchronised host and device. One source, two consumers
//! — the served `GET_DESCRIPTOR` and the cached
//! [`DeviceDescriptors`](crate::DeviceDescriptors) — and the default output is
//! machine-checked against the real capture in `crates/tdfu-core/tests/fixtures/results/`.

use super::{AltKind, GadgetConfig};

/// `bDescriptorType` for a device descriptor (USB 2.0 §9.4.3).
pub(super) const DEVICE: u8 = 0x01;
/// `bDescriptorType` for a configuration descriptor.
pub(super) const CONFIGURATION: u8 = 0x02;
/// `bDescriptorType` for a string descriptor.
pub(super) const STRING: u8 = 0x03;
/// `bDescriptorType` for an interface descriptor.
const INTERFACE: u8 = 0x04;
/// `DFU_DT_FUNC`, the DFU functional descriptor (`f_dfu.h`, DFU 1.1 §4.1.3).
pub(super) const DFU_FUNCTIONAL: u8 = 0x21;

/// `bLength` of a device descriptor.
const DEVICE_LEN: u8 = 18;
/// `bLength` of a configuration descriptor header.
const CONFIGURATION_LEN: u8 = 9;
/// `bLength` of an interface descriptor.
const INTERFACE_LEN: u8 = 9;
/// `bLength` of the DFU functional descriptor (`sizeof dfu_func`, `f_dfu.c:59-69`).
const FUNCTIONAL_LEN: u8 = 9;

/// `bInterfaceClass` — application specific (`USB_CLASS_APP_SPEC`, `f_dfu.c:722`).
pub(super) const DFU_CLASS: u8 = 0xFE;
/// `bInterfaceSubClass` — DFU (`f_dfu.c:723`).
pub(super) const DFU_SUBCLASS: u8 = 0x01;
/// `bInterfaceProtocol` — 2 is DFU mode, 1 is runtime mode (`f_dfu.c:724`, `:77`).
pub(super) const DFU_PROTOCOL_DFU_MODE: u8 = 0x02;

/// `iManufacturer`, as the T32LQ capture reports it.
pub(super) const IMANUFACTURER: u8 = 1;
/// `iProduct`, as the T32LQ capture reports it.
pub(super) const IPRODUCT: u8 = 2;
/// `iSerialNumber`, as the T32LQ capture reports it.
pub(super) const ISERIAL: u8 = 3;

/// The device descriptor (USB 2.0 §9.6.1).
pub(super) fn device(config: &GadgetConfig) -> Vec<u8> {
    let mut bytes = vec![
        DEVICE_LEN, DEVICE, 0x00, 0x02, // bcdUSB 2.00
        0x00, // bDeviceClass — per-interface
        0x00, // bDeviceSubClass
        0x00, // bDeviceProtocol
        0x40, // bMaxPacketSize0
    ];
    bytes.extend_from_slice(&config.vendor_id.to_le_bytes());
    bytes.extend_from_slice(&config.product_id.to_le_bytes());
    bytes.extend_from_slice(&config.bcd_device.to_le_bytes());
    bytes.extend_from_slice(&[IMANUFACTURER, IPRODUCT, ISERIAL, 1]);
    bytes
}

/// The whole configuration descriptor: header, one interface descriptor per alt, then
/// the DFU functional descriptor (`f_dfu.c:704-748` builds exactly this shape).
///
/// `wTotalLength` is computed, not stored, so an alt added to the config cannot leave a
/// stale length behind — which is the class of bug a hand-written fixture invites.
pub(super) fn configuration(config: &GadgetConfig) -> Vec<u8> {
    let mut body = Vec::new();
    for (index, alt) in config.alts.iter().enumerate() {
        // `dfu_prepare_function` numbers the alts 0..n and gives each `iInterface` the
        // string id allocated in `dfu_bind` (`f_dfu.c:713-727`, `:773-780`).
        let alternate = u8::try_from(index).unwrap_or(u8::MAX);
        body.extend_from_slice(&[
            INTERFACE_LEN,
            INTERFACE,
            config.interface,
            alternate,
            0, // bNumEndpoints: DFU 1.1 rides EP0 (`f_dfu.c:721`)
            DFU_CLASS,
            DFU_SUBCLASS,
            DFU_PROTOCOL_DFU_MODE,
            config.first_alt_string.saturating_add(alternate),
        ]);
        let _ = alt;
    }
    body.extend_from_slice(&functional(config));

    let total = u16::try_from(usize::from(CONFIGURATION_LEN) + body.len()).unwrap_or(u16::MAX);
    let mut bytes = vec![CONFIGURATION_LEN, CONFIGURATION];
    bytes.extend_from_slice(&total.to_le_bytes());
    bytes.extend_from_slice(&[
        1, // bNumInterfaces — one interface, several alternate settings
        config.configuration_value,
        config.iconfiguration,
        config.bm_attributes,
        config.max_power,
    ]);
    bytes.extend_from_slice(&body);
    bytes
}

/// The DFU functional descriptor (`f_dfu.c:59-69`).
///
/// **`wTransferSize` comes from [`GadgetConfig::transfer_size`]**, which is the same
/// number the block machine clamps to. In `f_dfu.c` they are one `#define` —
/// `wTransferSize = DFU_USB_BUFSIZ` at `:67` and the request clamp at `:342`, `:454`,
/// `:560`, `:648` — so a model in which they can disagree is a model of no device.
pub(super) fn functional(config: &GadgetConfig) -> Vec<u8> {
    let mut bytes = vec![FUNCTIONAL_LEN, DFU_FUNCTIONAL, config.dfu_attributes];
    bytes.extend_from_slice(&config.detach_timeout.to_le_bytes());
    bytes.extend_from_slice(&config.transfer_size.to_le_bytes());
    bytes.extend_from_slice(&config.bcd_dfu.to_le_bytes());
    bytes
}

/// String descriptor `index`, or `None` when the device has no such string.
///
/// Index 0 is the LANGID array (USB 2.0 §9.6.7); the alt names live at
/// [`GadgetConfig::first_alt_string`] upwards, which is where `dfu_bind` puts them.
/// A `None` here becomes a stall on the wire, and the host's `read_string` turns that
/// into an empty name rather than an error, the nameless shape the alt fallback covers.
pub(super) fn string(config: &GadgetConfig, index: u8) -> Option<Vec<u8>> {
    if index == 0 {
        // One LANGID: 0x0409, en-US (`f_dfu.c:99`, `:112`).
        return Some(vec![4, STRING, 0x09, 0x04]);
    }
    let text = match index {
        IMANUFACTURER => config.manufacturer_string.as_str(),
        IPRODUCT => config.product_string.as_str(),
        ISERIAL => config.serial_string.as_str(),
        other => {
            let offset = usize::from(other.checked_sub(config.first_alt_string)?);
            config.alts.get(offset)?.name.as_str()
        }
    };
    Some(encode(text))
}

/// UTF-16LE, with the two-byte header USB 2.0 §9.6.7 requires.
///
/// **`bLength` is one byte, so a string past 126 UTF-16 units cannot describe itself**:
/// `2 + units * 2` passes 255 at 127 units, and this saturates the field at `0xFF`
/// rather than wrapping it — which would announce a two-byte descriptor for a 300-byte
/// answer and send a host parser into the next one. Saturating is not *correct* either;
/// nothing is, because the descriptor cannot say what it is. It is the failure a host
/// can see, and it is unreachable in practice: the longest string any shipped loader
/// serves is the 32-character eFuse serial (`arch/mips/mach-xburst/dfu.c:69-86`), and the
/// alt names come from `dfu_alt_info`, which U-Boot's own environment caps far below
/// this. Recorded so nobody reads the `unwrap_or` as an accident.
fn encode(text: &str) -> Vec<u8> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let len = 2 + units.len() * 2;
    let mut bytes = Vec::with_capacity(len);
    bytes.push(u8::try_from(len).unwrap_or(u8::MAX));
    bytes.push(STRING);
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// The `iInterface` string index of alt `index`, for tests that assert the descriptor.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "an assertion helper for this crate's own pins")
)]
pub(super) fn alt_string_index(config: &GadgetConfig, index: u8) -> u8 {
    config.first_alt_string.saturating_add(index)
}

/// Whether `alt` is a virtual (token-gated) entity, for the descriptor's own sake.
///
/// The descriptor cannot tell: `dfu_prepare_function` emits the same nine bytes for
/// every alt whatever backend is behind it (`f_dfu.c:713-727`). Only the *name* differs,
/// which is why the host selects `erase` and `reboot` by name.
pub(super) const fn is_virtual(kind: &AltKind) -> bool {
    matches!(kind, AltKind::Erase | AltKind::Reboot)
}
