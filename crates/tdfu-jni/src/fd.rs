//! Adopting Java's USB file descriptor without ever closing it.
//!
//! Android's `UsbDeviceConnection` owns the descriptor and hands the app its integer
//! value; the app must not close it, because the connection will (the C is explicit:
//! `device_close_android` only frees its wrapper struct and never `libusb_close`s,
//! `tdfu_jni.c:184-186`). The Rust equivalent of "use it but do not own it" is to **dup**
//! the incoming descriptor into a fresh [`OwnedFd`] and hand *that* to
//! [`nusb::Device::from_fd`](tdfu_usb::native::NativeTransport::from_fd), which owns and
//! closes the dup on drop while Java's original stays open.

use std::os::fd::{BorrowedFd, OwnedFd, RawFd};

use tdfu_core::Error;
use tdfu_usb::native::NativeTransport;

/// Duplicate `raw` into an [`OwnedFd`] whose closure is independent of Java's descriptor.
///
/// [`try_clone_to_owned`](BorrowedFd::try_clone_to_owned) is a `dup`/`F_DUPFD_CLOEXEC`, so
/// the result is close-on-exec and closing it does not touch `raw`.
pub(crate) fn dup_owned(raw: RawFd) -> std::io::Result<OwnedFd> {
    // A negative descriptor is the "no device" sentinel Android's `UsbHelper.openDevice`
    // returns on failure (`-1`); it is also the one value `BorrowedFd::borrow_raw` panics
    // on, so it is rejected here as an error rather than left to unwind into the guard.
    if raw < 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    // SAFETY: `raw` is a non-negative usbfs descriptor Java opened via `UsbDeviceConnection`
    // and keeps open for the whole call. We borrow it only to duplicate it; a
    // `BorrowedFd` is not closed on drop, so Java's descriptor is left exactly as it was.
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
    borrowed.try_clone_to_owned()
}

/// Open the device Java handed over, on Android.
///
/// The dup is nusb's to close; Java's `raw` is not. On success the returned transport is
/// ready for `ops::*` - the operations claim and configure for themselves.
#[cfg(target_os = "android")]
pub(crate) fn open_transport(raw: RawFd) -> Result<NativeTransport, Error> {
    let owned = dup_owned(raw)?;
    // `from_fd` reads the device and config descriptors; `bus`/`address`/`port_path` stay
    // unset: Android hands over one device, so there is no bus to enumerate and no port path.
    Ok(NativeTransport::from_fd(owned)?)
}

/// Off Android there is no device to open from a bare descriptor.
///
/// The pre-opened-fd path is Android's alone: `nusb::Device::from_fd` is compiled only
/// there, and the process cannot enumerate the bus. The dup still
/// runs, so the ownership seam is exercised wherever this crate is built - the host tests
/// prove it against a pipe - and the failure is an honest error rather than a panic.
#[cfg(not(target_os = "android"))]
pub(crate) fn open_transport(raw: RawFd) -> Result<NativeTransport, Error> {
    let _owned = dup_owned(raw)?;
    Err(Error::Invalid(
        "opening a USB device from a file descriptor is supported only on Android".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    use super::dup_owned;

    /// The dup leaves the original open: the property the whole fd model rests on, since
    /// Java's descriptor must survive the operation.
    ///
    /// A pipe stands in for the USB descriptor. We dup the read end, drop the dup, and
    /// prove the original still carries data written to the write end - which it could not
    /// if dropping the dup had closed the shared pipe.
    #[test]
    fn dropping_the_dup_leaves_the_original_open() -> std::io::Result<()> {
        // A pipe as two owned descriptors, without libc: `std::io::pipe` (stable, 1.87).
        let (mut reader, mut writer) = std::io::pipe()?;
        let original = reader.as_raw_fd();

        // Dup the read end (nusb's dup, in miniature) and immediately drop it.
        let dup = dup_owned(original)?;
        assert_ne!(dup.as_raw_fd(), original, "a dup is a distinct descriptor");
        drop(dup);

        // The original still works: write a byte and read it back through `reader`. If the
        // dropped dup had closed the shared pipe, this read would see EOF, not the byte.
        writer.write_all(b"k")?;
        drop(writer);
        let mut got = Vec::new();
        reader.read_to_end(&mut got)?;
        assert_eq!(got, b"k", "dropping the dup must not close Java's descriptor");
        Ok(())
    }

    /// A negative fd - Android's "open failed" sentinel - is an error, not a panic.
    #[test]
    fn a_negative_fd_is_rejected_rather_than_panicking() {
        let result = dup_owned(-1);
        assert!(result.is_err(), "a negative fd must not dup");
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput)
        );
    }
}
