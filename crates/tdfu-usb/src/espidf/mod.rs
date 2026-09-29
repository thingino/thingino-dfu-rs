//! A backend on the ESP-IDF USB Host Library, for an ESP32-S2, -S3 or -P4 whose OTG port is
//! the camera's USB host (the thingino dev backpack). Run on the S3; the S2 and the P4's
//! high-speed port are untested.
//!
//! The library leaves four things to its caller, and this backend does them:
//!
//! * **Deadlines.** Transfers have no timeout (`usb_transfer_t::timeout_ms` is documented
//!   as unsupported), so every deadline is ours. A transfer we stop waiting for is
//!   abandoned to its completion callback, which frees it whenever it completes. Only a
//!   claimed interface's endpoints can be cancelled (halt and flush): an EP0 transfer the
//!   device never answers stays in flight until the device leaves the bus, which is why
//!   [`reset`](crate::LocalUsbTransport::reset) power-cycles the root port.
//! * **Endpoint state per device.** An interface claim allocates fresh pipes at `DATA0`
//!   while the device's endpoints keep counting, so a device is kept open, with its claim,
//!   from the first open until it leaves: Linux keeps that state per device too.
//! * **Enumeration retries.** A failed enumeration leaves the device attached and never
//!   listed until it is unplugged; a watcher power-cycles the port instead.
//! * **Device reset.** There is no reset call in IDF 5.5; the root port's power is cycled.

mod device;
mod host;
mod transfer;
mod transport;

use core::ffi::CStr;
use core::time::Duration;
use std::thread;

use esp_idf_sys as sys;

use crate::{Pipe, UsbError, UsbErrorKind};

pub use host::UsbHost;
pub use transport::EspTransport;

const OK: sys::esp_err_t = sys::ESP_OK as sys::esp_err_t;
const ERR_NOT_FOUND: sys::esp_err_t = sys::ESP_ERR_NOT_FOUND as sys::esp_err_t;
const ERR_INVALID_STATE: sys::esp_err_t = sys::ESP_ERR_INVALID_STATE as sys::esp_err_t;

/// The stack of every task this backend spawns: none of them do more than wait and log.
const TASK_STACK: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type DevHandle = sys::usb_device_handle_t;
type ClientHandle = sys::usb_host_client_handle_t;

/// A library handle: an opaque token that only the library dereferences.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Raw<T>(T);

// SAFETY: the tokens are dereferenced only by the library, under its own locks; holding or
// passing one between tasks touches no memory.
unsafe impl<T> Send for Raw<T> {}
// SAFETY: as for `Send`: a shared reference to a token can only copy it.
unsafe impl<T> Sync for Raw<T> {}

fn check(err: sys::esp_err_t, pipe: Pipe, what: &str) -> Result<(), UsbError> {
    match err {
        OK => Ok(()),
        ERR_NOT_FOUND => Err(UsbError::new(UsbErrorKind::NoDevice, pipe)),
        _ => Err(UsbError::new(
            UsbErrorKind::Backend(format!("{what}: {}", err_name(err))),
            pipe,
        )),
    }
}

fn err_name(err: sys::esp_err_t) -> String {
    // SAFETY: `esp_err_to_name` returns a static NUL-terminated string for every value,
    // unknown ones included.
    unsafe { CStr::from_ptr(sys::esp_err_to_name(err)) }
        .to_string_lossy()
        .into_owned()
}

fn status_error(status: sys::usb_transfer_status_t, pipe: Pipe) -> Result<(), UsbError> {
    let kind = match status {
        sys::usb_transfer_status_t_USB_TRANSFER_STATUS_COMPLETED => return Ok(()),
        sys::usb_transfer_status_t_USB_TRANSFER_STATUS_STALL => UsbErrorKind::Stall,
        sys::usb_transfer_status_t_USB_TRANSFER_STATUS_NO_DEVICE => UsbErrorKind::NoDevice,
        sys::usb_transfer_status_t_USB_TRANSFER_STATUS_OVERFLOW => UsbErrorKind::Overflow,
        sys::usb_transfer_status_t_USB_TRANSFER_STATUS_TIMED_OUT => UsbErrorKind::Timeout,
        _ => UsbErrorKind::Fault,
    };
    Err(UsbError::new(kind, pipe))
}

fn spawn(name: &str, body: impl FnOnce() + Send + 'static) -> Result<(), UsbError> {
    thread::Builder::new()
        .name(name.to_owned())
        .stack_size(TASK_STACK)
        .spawn(body)
        .map(drop)
        .map_err(|err| UsbError::new(UsbErrorKind::Backend(format!("spawning {name}: {err}")), Pipe::Device))
}

/// Host side only: halting and flushing completes whatever is queued as cancelled.
fn cancel_endpoint(dev: DevHandle, address: u8) {
    // SAFETY: `dev` is a handle this client holds open; the three calls only change the
    // library's pipe state for that endpoint.
    unsafe {
        sys::usb_host_endpoint_halt(dev, address);
        sys::usb_host_endpoint_flush(dev, address);
        sys::usb_host_endpoint_clear(dev, address);
    }
}

/// Releases an IDF interface claim, cancelling first whatever abandoned transfers are
/// still queued on its endpoints, which make the release fail.
fn release_interface(client: ClientHandle, dev: DevHandle, interface: u8, config: &[u8]) {
    // SAFETY: `client` and `dev` are live handles of this client, and it claimed `interface`.
    if unsafe { sys::usb_host_interface_release(client, dev, interface) } == ERR_INVALID_STATE {
        for address in crate::descriptors::interface_endpoints(config, interface) {
            cancel_endpoint(dev, address);
        }
        // SAFETY: as above.
        unsafe { sys::usb_host_interface_release(client, dev, interface) };
    }
}
