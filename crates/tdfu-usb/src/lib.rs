//! The USB transport seam for `thingino-dfu`.
//!
//! One trait ([`LocalUsbTransport`]) and one discovery trait ([`LocalUsbBackend`]) that
//! every backend implements — native (nusb), WebUSB, and an Android device opened from
//! a Java-supplied file descriptor. `tdfu-core` is generic over them and names no
//! backend, so the bootrom sequence, the DFU state machine and every operation are
//! written once.
//!
//! # What is *not* here
//!
//! No libusb, ever. A spike against real hardware proved `nusb` covers
//! every request this tool issues with no `unsafe`, including the pre-opened-fd path
//! Android needs.
//!
//! # Reading the shapes
//!
//! The traits below are the full surface, and each carries a rationale for
//! how it differs from an earlier implementation. The four that matter most:
//! control transfers carry typed [`ControlType`]/[`Recipient`] instead of a packed
//! `bmRequestType`; bulk endpoints are declared once by a claim
//! ([`InterfaceSpec`]) instead of passed on every call; [`LocalUsbTransport::control_out`]
//! returns nothing; and [`LocalUsbBackend::open`] takes the backend's own
//! [`DeviceId`](LocalUsbBackend::DeviceId) instead of a descriptor set it would have to
//! re-enumerate the bus to match.

// `deny`, not `forbid`: `unsafe` is permitted at the FFI edge of a backend in
// this crate, each block with a `// SAFETY:` comment. Nothing needs it today - the
// `nusb` spike proved nusb covers every request with none, including Android's
// pre-opened fd
// - but `forbid` cannot be relaxed per block, and a backend that needs one line of it
// should not have to argue with the crate root.
#![deny(unsafe_code)]

mod error;
mod transport;
mod types;

#[cfg(any(test, feature = "mock"))]
pub mod gadget;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

// The `nusb` backend, on every target that is not the browser. Target-gated rather than
// feature-gated so `tdfu-wasm` cannot acquire it through `--all-features`; the module's
// own docs carry the rest.
#[cfg(not(target_family = "wasm"))]
pub mod native;

pub use error::{Pipe, UsbError, UsbErrorKind};
pub use transport::{LocalUsbBackend, LocalUsbTransport};
pub use types::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, Discovered, InterfaceSpec,
    Recipient,
};

/// The Ingenic vendor IDs. Nothing else is ever opened.
pub mod vid {
    /// T/A/C series — every current bootrom and the U-Boot DFU gadget.
    pub const INGENIC: u16 = 0xA108;
    /// X series. Also seen as an "alternative bootrom" product ID.
    pub const INGENIC_X: u16 = 0x601A;

    /// Is this a vendor this tool will open?
    #[must_use]
    pub const fn is_ingenic(vendor_id: u16) -> bool {
        matches!(vendor_id, INGENIC | INGENIC_X)
    }
}

/// The product IDs seen on Ingenic devices.
///
/// **A product ID never decides what stage a device is in.** The DFU gadget was
/// re-PID'd to share the bootrom's `0xC309` on 2026-07-24, so a PID check reports
/// "bootrom" for every current gadget — which is exactly what the C's `manager.c:53-68`
/// does, making its own gadget branch dead code. Classification is
/// descriptor-first.
pub mod pid {
    /// The bootrom, and since 2026-07-24 the U-Boot DFU gadget as well.
    pub const BOOTROM: u16 = 0xC309;
    /// The legacy DFU gadget. Still matched; no longer produced.
    pub const DFU_LEGACY: u16 = 0x4D44;
    /// A vestigial "firmware stage" product ID.
    pub const FIRMWARE: u16 = 0x8887;
    /// A vestigial "firmware stage" product ID on the X series.
    pub const FIRMWARE_X: u16 = 0x601E;
    /// The X-series bootrom (`tdfu.h:52`).
    pub const BOOTROM_X: u16 = 0x4770;
    /// The "alternative bootrom" (`tdfu.h:54`) -- the same number as the X-series
    /// VENDOR id, which is why it reads oddly.
    pub const BOOTROM_ALT: u16 = 0x601A;
}

/// The bootrom's two bulk endpoints.
///
/// They are the only two in the tool: the C hardcodes `ENDPOINT_IN 0x81` and
/// `ENDPOINT_OUT 0x01` (`libtdfu/include/tdfu/tdfu.h:71-73`), reads no endpoint
/// descriptor anywhere, and its three bulk call sites (`protocol.c:155`,
/// `protocol.c:565`, `bootstrap.c:116`) use nothing else. The DFU stage uses no bulk
/// endpoint at all — DFU 1.1 rides EP0.
pub mod endpoint {
    use crate::types::BulkEndpoint;

    /// `0x81`, the bootrom's bulk IN.
    ///
    /// The `match` is a compile-time assertion: `from_address` refuses endpoint number
    /// 0, so a typo that made this `0x80` would fail const evaluation rather than
    /// produce a nonsense address at run time.
    pub const BOOTROM_IN: BulkEndpoint = match BulkEndpoint::from_address(0x81) {
        Some(endpoint) => endpoint,
        None => unreachable!(),
    };

    /// `0x01`, the bootrom's bulk OUT.
    pub const BOOTROM_OUT: BulkEndpoint = match BulkEndpoint::from_address(0x01) {
        Some(endpoint) => endpoint,
        None => unreachable!(),
    };
}
