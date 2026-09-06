//! `nusb`'s two error types, mapped onto this crate's one.
//!
//! Two mappings, because `nusb` splits its errors the way the OS does:
//!
//! * [`transfer_kind`] for [`nusb::transfer::TransferError`] — what a submitted
//!   transfer came back with.
//! * [`device_kind`] for [`nusb::Error`] — what an open, a claim, a release, a
//!   `SET_CONFIGURATION` or a bus reset came back with. `AccessDenied` is produced
//!   **only** here, never by a transfer.
//!
//! Every mapping decision that is not one-to-one carries its reason inline, because
//! the vendor retry class is `{Timeout, Stall, NoDevice}` and a kind chosen carelessly
//! either retries something that cannot recover or fails something that would have.

use nusb::transfer::TransferError;
use nusb::{Error as NusbError, ErrorKind as NusbErrorKind};

use crate::{Pipe, UsbError, UsbErrorKind};

/// What a completed [`nusb`] transfer's failure means here.
///
/// `Cancelled` becomes [`UsbErrorKind::Timeout`] unconditionally, and that is exact
/// rather than approximate: this backend is the only thing that ever cancels a transfer
/// (it cancels on its own deadline, see [`transport`](super::transport)), and on Linux
/// an `ETIMEDOUT` URB surfaces as `Cancelled` as well. There is no third producer.
pub(crate) fn transfer_kind(error: TransferError) -> UsbErrorKind {
    match error {
        TransferError::Cancelled => UsbErrorKind::Timeout,
        TransferError::Stall => UsbErrorKind::Stall,
        TransferError::Disconnected => UsbErrorKind::NoDevice,
        // `nusb` cannot tell a babble/overflow from any other hardware fault - Linux
        // reports `EOVERFLOW` as `Fault` too. `UsbErrorKind::Overflow` therefore stays
        // for the backends that can tell (WebUSB reports "babble") and is never
        // produced here.
        TransferError::Fault => UsbErrorKind::Fault,
        // Reachable only from a caller or platform mistake: an IN request that is not
        // a multiple of the max packet size, or a request shape this OS refuses. It is
        // deliberately not in the vendor retry class - retrying it changes nothing.
        TransferError::InvalidArgument => UsbErrorKind::Backend(
            "nusb refused the transfer: invalid argument, or the shape is unsupported by this OS".to_owned(),
        ),
        TransferError::Unknown(code) => UsbErrorKind::Backend(format!("unmapped OS transfer error {code}")),
    }
}

/// What a [`nusb`] device-level failure means here.
///
/// `NotFound` keeps its OS text rather than collapsing into a unit variant: "alternate
/// setting not found (EINVAL)" and the rest send an operator to different places, and
/// throwing that distinction away leaves a message that names a symptom and no cause.
///
/// `Busy` is the one that earned a kind of its own: a claim's `SET_CONFIGURATION` on an
/// already-configured Linux device answers `EBUSY` and is not a failure, which is a
/// distinction the C draws too (`libtdfu/src/usb/device.c:336`) and which no caller can
/// express against a `Backend(String)`.
pub(crate) fn device_kind(error: &NusbError) -> UsbErrorKind {
    device_kind_of(error.kind(), || error.to_string())
}

/// [`device_kind`]'s table, split out from the `nusb::Error` it reads.
///
/// `nusb::Error` has no public constructor, so the whole mapping was untestable while it
/// took one; `text` is a closure because the arms that classify never call it.
fn device_kind_of(kind: NusbErrorKind, text: impl FnOnce() -> String) -> UsbErrorKind {
    match kind {
        NusbErrorKind::Disconnected => UsbErrorKind::NoDevice,
        // The one place `AccessDenied` is produced. `super::ACCESS_DENIED_HINT` is the
        // single wording of the fix; it is a constant rather than error text so that
        // exactly one layer prints it; an earlier implementation printed it twice.
        NusbErrorKind::PermissionDenied => UsbErrorKind::AccessDenied,
        NusbErrorKind::Unsupported => UsbErrorKind::Unsupported,
        // A resource someone else holds. The OS's own text is dropped here and that is
        // the one place in this file where that is right: every producer says the same
        // thing in different words ("interface is still in use", "Device or resource
        // busy"), and the caller that acts on it acts on the *kind*.
        NusbErrorKind::Busy => UsbErrorKind::Busy,
        // `nusb::ErrorKind` is `#[non_exhaustive]`, so this arm is both the catch-all
        // and the mapping for `NotFound` and `Other`.
        _ => UsbErrorKind::Backend(text()),
    }
}

/// What a failed [`nusb::Interface::endpoint`] call means here.
///
/// `NotFound` means the interface's current alternate setting does not offer the
/// endpoint the claim declared. The contract spells that [`UsbErrorKind::Fault`], and
/// claim time is the one place it is reachable and true.
pub(crate) fn endpoint_kind(error: &NusbError) -> UsbErrorKind {
    match error.kind() {
        NusbErrorKind::NotFound => UsbErrorKind::Fault,
        _ => device_kind(error),
    }
}

/// A device-level [`UsbError`] on [`Pipe::Device`], with the OS's reason kept.
pub(crate) fn device_error(error: &NusbError) -> UsbError {
    UsbError::new(device_kind(error), Pipe::Device)
}

#[cfg(test)]
mod tests {
    use super::{device_kind_of, transfer_kind};
    use crate::{Pipe, UsbError, UsbErrorKind};
    use nusb::ErrorKind as NusbErrorKind;
    use nusb::transfer::TransferError;

    #[test]
    fn cancelled_is_a_timeout_because_the_backend_is_the_only_canceller() {
        assert_eq!(transfer_kind(TransferError::Cancelled), UsbErrorKind::Timeout);
    }

    #[test]
    fn the_rom2_retry_class_is_exactly_timeout_stall_nodevice() {
        // A mapping change that widened or narrowed this class silently
        // would change how many times a bootrom vendor request is retried.
        for (error, retryable) in [
            (TransferError::Cancelled, true),
            (TransferError::Stall, true),
            (TransferError::Disconnected, true),
            (TransferError::Fault, false),
            (TransferError::InvalidArgument, false),
            (TransferError::Unknown(42), false),
        ] {
            let kind = transfer_kind(error);
            let is_retryable = matches!(
                kind,
                UsbErrorKind::Timeout | UsbErrorKind::Stall | UsbErrorKind::NoDevice
            );
            assert_eq!(is_retryable, retryable, "{error:?} mapped to {kind:?}");
        }
    }

    #[test]
    fn every_device_level_kind_maps_where_the_contract_says() {
        // A1 added the `Busy` row. Without a kind of its own, a claim cannot tell "the
        // configuration is already in force" (`libtdfu/src/usb/device.c:336`) from a
        // refusal that matters, and collapsing the two costs the caller the cause.
        for (kind, want) in [
            (NusbErrorKind::Disconnected, UsbErrorKind::NoDevice),
            (NusbErrorKind::PermissionDenied, UsbErrorKind::AccessDenied),
            (NusbErrorKind::Unsupported, UsbErrorKind::Unsupported),
            (NusbErrorKind::Busy, UsbErrorKind::Busy),
            (
                NusbErrorKind::NotFound,
                UsbErrorKind::Backend("alternate setting not found".to_owned()),
            ),
            (
                NusbErrorKind::Other,
                UsbErrorKind::Backend("alternate setting not found".to_owned()),
            ),
        ] {
            assert_eq!(
                device_kind_of(kind, || "alternate setting not found".to_owned()),
                want,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn busy_is_in_neither_retry_class() {
        // A resource another process holds is not freed by a 500 ms backoff
        // and not by a bus reset (both pinned in `tdfu-core`).
        let failure = UsbError::new(UsbErrorKind::Busy, Pipe::Device);
        assert!(!failure.is_vendor_retryable());
    }

    #[test]
    fn a_transfer_never_produces_access_denied() {
        // `AccessDenied` comes from open and claim only. If a transfer
        // could produce it, the "install a udev rule" advice would be printed
        // for a device that was already open.
        for error in [
            TransferError::Cancelled,
            TransferError::Stall,
            TransferError::Disconnected,
            TransferError::Fault,
            TransferError::InvalidArgument,
            TransferError::Unknown(1),
        ] {
            assert_ne!(transfer_kind(error), UsbErrorKind::AccessDenied);
        }
    }
}
