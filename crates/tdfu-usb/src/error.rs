//! The one error type every backend produces, with the context the C logs and an
//! earlier implementation threw away.
//!
//! That implementation's `UsbError` was a bare enum
//! of unit variants, so a 2 s bulk-IN failure on endpoint `0x81` and a 30 s DNLOAD
//! failure on EP0 were indistinguishable in a bug report. The C does better — it names
//! endpoint, length, timeout and transferred on both bulk-failure paths
//! (`libtdfu/src/usb/device.c:444-445` and `:449-450`) — and Rust had all four values in
//! hand at the failure site.
//!
//! Only the second of those two is a shipped-log line: `:449-450` is
//! `LOG_INFO("[ERROR] …")`, while the *timeout* path at `:444-445` is a `DEBUG_PRINT`
//! and says nothing unless the C was built with debug output. So the C reports the
//! narrower half of what it knows, and here every failure carries the context.
//!
//! So the error is a struct: a [`UsbErrorKind`] that the retry classifiers match on
//! match on, plus the pipe, the length, the deadline and whatever the
//! backend can say about how far the transfer got.

use core::fmt;
use core::time::Duration;

use crate::types::{BulkEndpoint, Direction};

/// What went wrong, stripped of context — the part retry logic matches on.
///
/// Mapping notes (nusb 0.2.7, proven by a spike against real hardware): nusb's
/// `TransferError` is exactly `Cancelled | Stall | Disconnected | Fault |
/// InvalidArgument`. [`Timeout`](UsbErrorKind::Timeout) exists only because the
/// *backend* owns the deadline — it cancels and reports the timeout itself; on Linux
/// `ETIMEDOUT` surfaces as `Cancelled` and `EOVERFLOW` as `Fault`, so
/// [`Overflow`](UsbErrorKind::Overflow) is produced only by backends that can tell
/// (WebUSB reports "babble") and nusb reports [`Fault`](UsbErrorKind::Fault).
/// [`AccessDenied`](UsbErrorKind::AccessDenied) comes from open/claim, never from a
/// transfer.
///
/// The vendor retry class is `{Timeout, Stall, NoDevice}` and nothing else; the
/// bus-reset recoverable class is wider. Both live in `tdfu-core`, which matches on
/// this enum — see [`UsbError::is_vendor_retryable`] for the vendor half, which is a
/// property of the transport layer and is therefore answered here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UsbErrorKind {
    /// The backend's own deadline expired. A vendor request retries this.
    #[error("timed out")]
    Timeout,
    /// The endpoint stalled (`EPIPE`). A vendor request retries this — but a *bulk* endpoint
    /// latches its halt and keeps returning `EPIPE` until
    /// [`LocalUsbTransport::clear_halt`](crate::LocalUsbTransport::clear_halt) is
    /// called, which is why that method exists.
    #[error("endpoint stalled")]
    Stall,
    /// The device disappeared from the bus. A vendor request retries this: a bootrom that
    /// re-enumerates mid-sequence is the normal case, not a failure.
    #[error("device gone")]
    NoDevice,
    /// The OS refused the open or the claim: a missing udev rule on Linux, no WinUSB
    /// driver on Windows. Never produced by a transfer, and kept distinct
    /// from "device not found" because the fix is different).
    #[error("access denied by the OS")]
    AccessDenied,
    /// The device, interface or endpoint is already in use — by another process, by a
    /// kernel driver, or by a handle this process still holds.
    ///
    /// Kept out of [`Backend`](UsbErrorKind::Backend) because one caller needs to act on
    /// it and no other: `SET_CONFIGURATION` on an already-configured Linux device
    /// answers `EBUSY` while everything is fine, and the C's claim helper singles that
    /// case out (`libtdfu/src/usb/device.c:336`). Without a kind for it, "the
    /// configuration is already in force" and "the OS refused for a reason that matters"
    /// arrive as the same opaque string and a caller can only tolerate both or neither.
    ///
    /// In neither the vendor retry class nor the bus-reset recoverable class: a
    /// resource another process holds is not freed by waiting 500 ms or by a bus reset.
    #[error("in use by another driver, process or handle")]
    Busy,
    /// Fewer bytes moved than asked for. A short memory read is a hard
    /// failure; a short *write* that nonetheless reports the full
    /// length a success, which is why `got` is carried rather than assumed smaller.
    #[error("short transfer: {got} of {want} bytes")]
    Short {
        /// Bytes actually moved.
        got: usize,
        /// Bytes the host asked to move.
        want: usize,
    },
    /// The device sent more than the host asked for (WebUSB "babble"). nusb cannot tell
    /// this apart from [`Fault`](UsbErrorKind::Fault).
    #[error("overflow: the device sent more than requested")]
    Overflow,
    /// Any other transfer failure the backend could not classify.
    #[error("transfer fault")]
    Fault,
    /// This backend cannot do it at all. **Android** answers
    /// [`reset`](crate::LocalUsbTransport::reset) this way; WebUSB does
    /// not, and used to be named here: see that method's doc, which says why
    /// the browser's reset is real.
    #[error("unsupported on this backend")]
    Unsupported,
    /// A transfer was issued against an interface that is not claimed, or a bulk
    /// transfer against an endpoint the claim did not declare. This is a caller bug,
    /// and it is an error rather than a panic because a flashing tool must not abort
    /// mid-write.
    #[error("no claimed interface offers this pipe")]
    NotClaimed,
    /// Something the backend can only describe in prose.
    #[error("backend: {0}")]
    Backend(String),
}

/// Which pipe a failed operation was using.
///
/// The `Debug`/`Display` of this is what turns "transfer failed" into a line an
/// operator can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Pipe {
    /// The default control pipe, EP0. `request` is `bRequest` — the bootrom's vendor
    /// requests `0x00..=0x05` or a DFU class request.
    Control {
        /// IN (device to host) or OUT (host to device).
        direction: Direction,
        /// `bRequest`.
        request: u8,
    },
    /// A bulk endpoint declared by the claim.
    Bulk(BulkEndpoint),
    /// Not a transfer at all: open, claim, release, set configuration, reset.
    Device,
}

impl fmt::Display for Pipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Control { direction, request } => {
                write!(f, "control {direction} request {request:#04x} on EP0")
            }
            Self::Bulk(endpoint) => write!(f, "bulk {} on endpoint {endpoint}", endpoint.direction()),
            Self::Device => f.write_str("the device"),
        }
    }
}

/// A USB failure with the context needed to report it.
///
/// Construct with [`UsbError::new`] and add whatever the failure site knows:
///
/// ```
/// use core::time::Duration;
/// use tdfu_usb::{BulkEndpoint, Direction, Pipe, UsbError, UsbErrorKind};
///
/// let ep = BulkEndpoint::new(Direction::In, 1).ok_or("bad endpoint")?;
/// let err = UsbError::new(UsbErrorKind::Timeout, Pipe::Bulk(ep))
///     .with_len(4)
///     .with_timeout(Duration::from_secs(2))
///     .with_transferred(0);
/// assert_eq!(err.to_string(), "timed out: bulk IN on endpoint 0x81, 4 bytes, timeout 2s, 0 transferred");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbError {
    kind: UsbErrorKind,
    pipe: Pipe,
    len: Option<usize>,
    timeout: Option<Duration>,
    transferred: Option<usize>,
}

impl UsbError {
    /// A failure of `kind` on `pipe`, with no further context yet.
    #[must_use]
    pub const fn new(kind: UsbErrorKind, pipe: Pipe) -> Self {
        Self {
            kind,
            pipe,
            len: None,
            timeout: None,
            transferred: None,
        }
    }

    /// Record how many bytes the host asked to move.
    #[must_use]
    pub const fn with_len(mut self, len: usize) -> Self {
        self.len = Some(len);
        self
    }

    /// Record the deadline the caller set. A memory read's 2 s and a download's 30 s look
    /// identical in a log without it.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Record how far the transfer got, when the backend can tell (`device.c:444-450`).
    #[must_use]
    pub const fn with_transferred(mut self, transferred: usize) -> Self {
        self.transferred = Some(transferred);
        self
    }

    /// What went wrong. Retry classifiers match on this and ignore the context.
    #[must_use]
    pub const fn kind(&self) -> &UsbErrorKind {
        &self.kind
    }

    /// Which pipe it happened on.
    #[must_use]
    pub const fn pipe(&self) -> Pipe {
        self.pipe
    }

    /// Bytes the host asked to move, if the failure site said.
    #[must_use]
    pub const fn requested_len(&self) -> Option<usize> {
        self.len
    }

    /// The deadline the caller set, if the failure site said.
    #[must_use]
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Bytes actually moved before the failure, if the backend could tell.
    #[must_use]
    pub const fn transferred(&self) -> Option<usize> {
        self.transferred
    }

    /// The vendor retry class: a bootrom vendor request is retried on
    /// TIMEOUT / PIPE / NO\_DEVICE, and **any other error is an immediate failure**
    /// (`libtdfu/src/usb/device.c:497-530`). Anything this crate adds later is not
    /// retryable until someone decides it is.
    ///
    /// The C's backoff table is `{0.5, 1, 2, 3, 5} s` (`device.c:500`) but only its
    /// first **four** entries are ever slept: the sleep at `device.c:520` is reached
    /// with `retry_count` 1..=4 and indexes `retry_count - 1`, and the fifth failure
    /// returns at `:522-523` instead of sleeping. Five attempts, four waits, 6.5 s of
    /// backoff in total — not the 11.5 s the table reads as.
    #[must_use]
    pub const fn is_vendor_retryable(&self) -> bool {
        matches!(
            self.kind,
            UsbErrorKind::Timeout | UsbErrorKind::Stall | UsbErrorKind::NoDevice
        )
    }
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.pipe)?;
        if let Some(len) = self.len {
            write!(f, ", {len} bytes")?;
        }
        if let Some(timeout) = self.timeout {
            write!(f, ", timeout {timeout:?}")?;
        }
        if let Some(transferred) = self.transferred {
            write!(f, ", {transferred} transferred")?;
        }
        Ok(())
    }
}

impl std::error::Error for UsbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::UsbErrorKind;

    /// Adding a kind is not a silent act.
    ///
    /// A compile gate, not an assertion: `UsbErrorKind` is `#[non_exhaustive]`, so
    /// `tdfu_core`, which is the crate that decides whether a kind is recoverable, can
    /// only match on it with a wildcard and would absorb a new variant without a word.
    /// In-crate the attribute does not apply, so the match below is exhaustive and a new
    /// variant fails to compile *here*, which points whoever added it at
    /// `tdfu_core::error`'s `dfu12_recoverable_class_is_pinned_for_every_kind`.
    ///
    /// The class itself is deliberately not named here. Naming it would be prose that
    /// nothing checks: this crate cannot call `tdfu_core::Error::is_recoverable`, so a
    /// reclassification over there would leave a contradicting word here and every test
    /// would still pass. One statement of the classes, in the crate that owns them.
    #[test]
    fn every_kind_is_accounted_for() {
        fn accounted_for(kind: &UsbErrorKind) -> bool {
            match kind {
                UsbErrorKind::Timeout
                | UsbErrorKind::Stall
                | UsbErrorKind::NoDevice
                | UsbErrorKind::Fault
                | UsbErrorKind::Short { .. }
                | UsbErrorKind::AccessDenied
                | UsbErrorKind::Busy
                | UsbErrorKind::Overflow
                | UsbErrorKind::Unsupported
                | UsbErrorKind::NotClaimed
                | UsbErrorKind::Backend(_) => true,
            }
        }

        assert!(accounted_for(&UsbErrorKind::Timeout));
        assert!(accounted_for(&UsbErrorKind::Backend(String::new())));
    }
}
