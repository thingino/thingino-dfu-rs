//! The native backend: `nusb`, on every target that is not the browser.
//!
//! [`NativeBackend`] enumerates and opens on Linux, macOS and Windows;
//! [`NativeTransport`] drives one open device on those three **and** on Android, where
//! Java owns the file descriptor and `NativeTransport::from_fd` is the only way in.
//!
//! # Why `nusb` and not libusb
//!
//! A libusb C dependency is banned unless the `nusb` spike failed. It did not: on
//! 2026-08-22 the spike read all three SoC registers off a T23N and a T41NQ,
//! byte-identical to the standalone C probe on the same units, with **no
//! `unsafe` and no C**. It also settled the three questions this module depends on —
//! `DeviceInfo::port_chain()` is the physical port path,
//! `Device::from_fd(OwnedFd)` adopts Android's descriptor, and a second open gets
//! `EBUSY` unless interface 0 is released on the first handle first.
//!
//! # Where the bodies are
//!
//! * `transport.rs` — the transfers, and the deadline rule they are built around.
//! * `claim.rs` — the claim state machine, the device slot a reset re-opens through,
//!   and both of its pins.
//! * `reopen.rs` — how a device that has just re-enumerated is found again, and why it
//!   is found by physical port rather than by vendor id.
//! * `backend.rs` — enumeration, and the one place `nusb` is thinner than libusb.
//! * `error.rs` — the two `nusb` error types mapped onto [`UsbError`](crate::UsbError).

mod claim;
mod error;
mod transport;

// Not compiled for Android: `nusb::list_devices` does not exist there, and `reset()` is
// `Unsupported` anyway, so there is nothing to re-open and nothing to re-open it
// with.
#[cfg(not(target_os = "android"))]
mod reopen;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod backend;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use backend::{DeviceId, NativeBackend};
pub use transport::NativeTransport;

/// What to tell an operator whose OS refused the device — **once**.
///
/// [`UsbErrorKind::AccessDenied`](crate::UsbErrorKind::AccessDenied) says what happened;
/// this says what to do about it, and it lives here rather than inside the error because
/// the fix is native-specific and because a frontend must be
/// able to print it exactly once.
///
/// An earlier implementation printed the same advice **twice, in two wordings**, one of
/// them carrying a 14-space gap from a rustfmt string join. Both halves
/// of that are guarded here: there is one constant per platform and it is one string
/// literal on one line, so no join can introduce whitespace, and
/// `tests::the_hint_is_one_clean_sentence` fails if either regresses.
///
/// Both Ingenic vendor IDs get a rule, because the tool opens both
/// ([`vid::is_ingenic`](crate::vid::is_ingenic)) and either can be the one the OS just
/// refused. These are the two lines `README.md` ships, verbatim; an operator who is
/// handed a rule for `a108` after a `601a` device was refused installs it, replugs, and
/// is refused again. `tests::the_hint_names_every_vendor_this_tool_will_open` sweeps the
/// whole vendor space against `is_ingenic`, so a third ID cannot be added without the
/// advice following it.
#[cfg(target_os = "linux")]
pub const ACCESS_DENIED_HINT: &str = "install a udev rule for the Ingenic vendor IDs (SUBSYSTEM==\"usb\", ATTR{idVendor}==\"a108\", MODE=\"0666\", TAG+=\"uaccess\" and SUBSYSTEM==\"usb\", ATTR{idVendor}==\"601a\", MODE=\"0666\", TAG+=\"uaccess\"), replug the device, and retry";

/// What to tell an operator whose OS refused the device — **once**. See the Linux
/// constant for why this is a constant rather than error text.
#[cfg(target_os = "windows")]
pub const ACCESS_DENIED_HINT: &str = "install the WinUSB driver for this device with Zadig, then retry";

/// What to tell an operator whose OS refused the device — **once**. See the Linux
/// constant for why this is a constant rather than error text.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub const ACCESS_DENIED_HINT: &str =
    "check that no other program holds the device and that this user may open USB devices";

#[cfg(test)]
mod tests {
    use super::ACCESS_DENIED_HINT;

    #[test]
    fn the_hint_is_one_clean_sentence() {
        // A rustfmt string join once put a 14-space gap in the middle of this advice,
        // and nothing noticed because nothing looked.
        assert!(!ACCESS_DENIED_HINT.is_empty());
        assert!(
            !ACCESS_DENIED_HINT.contains("  "),
            "a run of spaces means a string join went wrong: {ACCESS_DENIED_HINT:?}"
        );
        assert!(
            !ACCESS_DENIED_HINT.contains('\n'),
            "the hint is one line so a caller can print it anywhere"
        );
        assert!(
            !ACCESS_DENIED_HINT.ends_with('.'),
            "no trailing full stop: the caller decides the sentence it lands in"
        );
    }

    /// Advice that does not cover the device that was refused is advice that wastes a
    /// replug. The sweep is over the whole vendor space rather than a hand-written pair
    /// so that a third Ingenic ID added to `vid::is_ingenic` cannot slip past it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_hint_names_every_vendor_this_tool_will_open() {
        for vendor_id in 0..=u16::MAX {
            assert!(
                !crate::vid::is_ingenic(vendor_id) || ACCESS_DENIED_HINT.contains(&format!("{vendor_id:04x}")),
                "this tool opens {vendor_id:04x} and the udev rule it hands out does not cover it"
            );
        }
    }
}
