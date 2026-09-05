//! The WebUSB backend: the frozen `tdfu-usb` traits over `web-sys`.
//!
//! `tdfu-core` names no backend, so the whole bootrom sequence, the DFU state machine
//! and every operation are the same code here as in the CLI and the daemon.
//! What is different is only what the browser can and cannot do:
//!
//! | | native (`nusb`) | here |
//! |---|---|---|
//! | descriptors | read from the device | rebuilt from the browser's parsed tree ([`descriptor`]) |
//! | string descriptors | read from the device | answered from `interfaceName`, which the browser read for us |
//! | `wTransferSize` | read from the functional descriptor | assumed 4096, logged as assumed |
//! | port path | `DeviceInfo::port_chain()` | empty; the browser exposes none |
//! | bus / address | real | 0; the browser exposes neither |
//! | transfer deadline | the OS's, cancellable | a `setTimeout` race, not cancellable ([`transport`]) |
//! | `reset` | bus reset plus a re-open | `USBDevice.reset()`; the handle survives |
//! | standard control requests | sent | refused by the browser; `GET_DESCRIPTOR` is answered locally |
//!
//! The 494-line shim this replaces (`web/src/libusb-webusb.js`) is the authority on
//! *which* WebUSB calls the C's browser path made and on which of them the browser
//! refuses. It is not a model for what those calls mean: it collapsed babble into stall,
//! swallowed three classes of failure into success, and invented a bus number, a device
//! address and a detach timeout. Each of those is called out where it was not followed.

pub mod backend;
pub mod descriptor;
pub mod error;
pub mod transport;

pub use backend::{DeviceTable, NO_WEBUSB_HINT, REQUEST_FILTERS, WebUsbBackend, navigator_usb};
pub use transport::WebUsbTransport;
