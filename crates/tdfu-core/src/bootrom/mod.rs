//! The Ingenic mask ROM's vendor protocol.
//!
//! Six vendor requests and two bulk endpoints. Everything the bootrom can do, this
//! module does; the operations in [`ops`](crate::ops) compose it.
//!
//! These are `pub` because the browser frontend composes them directly, but they are
//! not the surface a frontend should reach for first — prefer [`ops`](crate::ops).
//!
//! # One retry class, one settle, one claim
//!
//! Three rules run through everything here, and each is a place an earlier
//! implementation or the C got something wrong:
//!
//! * **Every vendor request goes through the same retry loop** — [`VENDOR_ATTEMPTS`]
//!   attempts on [`UsbError::is_vendor_retryable`](tdfu_usb::UsbError::is_vendor_retryable),
//!   [`VENDOR_RETRY_BACKOFF`] between them, and any other error is immediate. The C
//!   shares one wrapper for all five (`device.c:488-533`) and so do we.
//! * **A bulk endpoint that stalls latches.** It keeps answering `EPIPE` until
//!   `CLEAR_FEATURE(ENDPOINT_HALT)`, so every bulk retry in this module clears the halt
//!   first. The C never calls `libusb_clear_halt` anywhere, which is why nobody noticed
//!   that its retry class was decorative.
//! * **The configuration is set once, not per claim.** [`claim`] asks
//!   [`active_configuration`](tdfu_usb::LocalUsbTransport::active_configuration) first.
//!   A differential USB capture caught the redundant `SET_CONFIGURATION` as
//!   a real divergence from the C, which guards all three of its claim sites
//!   (`device.c:332-334`, `dfu.c:429`, `protocol.c:212`).

use tdfu_usb::{InterfaceSpec, LocalUsbTransport, UsbError, UsbErrorKind, endpoint};

use crate::error::Result;

#[cfg(test)]
mod fixtures;
mod transfer;
mod vendor;

pub use transfer::{load_to_memory, read_memory};
pub use vendor::{flush_cache, get_cpu_info, prog_stage1, prog_stage2, set_data_addr, set_data_len};

use core::time::Duration;

/// The six vendor requests (`bRequest`), all with recipient *device*.
pub mod request {
    /// Read the 8-byte bootrom identity string. Vendor IN, `bmRequestType 0xC0`.
    pub const GET_CPU_INFO: u8 = 0x00;
    /// Set the address for the next bulk transfer or memory read.
    pub const SET_DATA_ADDR: u8 = 0x01;
    /// Set the length for the next bulk transfer or memory read.
    pub const SET_DATA_LEN: u8 = 0x02;
    /// Flush the caches before executing what was just staged.
    pub const FLUSH_CACHE: u8 = 0x03;
    /// Execute the staged stage-1 image. **One shot per power cycle.**
    pub const PROG_STAGE1: u8 = 0x04;
    /// Execute the staged stage-2 image (U-Boot).
    pub const PROG_STAGE2: u8 = 0x05;
}

/// Every vendor request except `GET_CPU_INFO` is followed by this settle
/// (`CMD_RESPONSE_DELAY_MS`, `constants.h:15`), and `PROG_STAGE2` is not settled after
/// on failure.
///
/// `GET_CPU_INFO` is **not** settled: `device.c` settles on neither its direct nor its
/// claim-fallback path.
pub const SETTLE_AFTER_VENDOR_REQUEST: Duration = Duration::from_millis(100);

/// The backoff between vendor-request attempts: five attempts, four sleeps.
///
/// The fifth entry is **unreachable** — the loop sleeps only *between* attempts, so
/// after the fifth failure it returns. It is listed because the C lists it
/// (`device.c:487-526`); a test that asserts five sleeps would be asserting a bug.
pub const VENDOR_RETRY_BACKOFF: [Duration; 5] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(3),
    Duration::from_secs(5),
];

/// How many times a vendor request is attempted before failing.
pub const VENDOR_ATTEMPTS: usize = 5;

/// The default control timeout (`device.c:384`).
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// The timeout for a register or window read.
pub const READ_MEMORY_TIMEOUT: Duration = Duration::from_secs(2);

/// Bulk uploads are chunked at 64 KiB.
pub const BULK_CHUNK: usize = 64 * 1024;

/// Attempts per bulk chunk, and the wait between them.
pub const CHUNK_ATTEMPTS: usize = 3;

/// The wait between bulk-chunk attempts.
pub const CHUNK_RETRY_DELAY: Duration = Duration::from_millis(50);

/// A 10 ms pause between chunks once the whole transfer exceeds
/// [`INTER_CHUNK_DELAY_THRESHOLD`].
pub const INTER_CHUNK_DELAY: Duration = Duration::from_millis(10);

/// The total size above which [`INTER_CHUNK_DELAY`] applies.
pub const INTER_CHUNK_DELAY_THRESHOLD: usize = 100 * 1024;

/// Stage-1 images are zero-padded up to a multiple of this,
/// **unconditionally**.
///
/// XBurst1 gen-1 mask ROMs (T10/T20/T21/T30) stage stage-1 into cache-as-RAM and prime
/// the I-cache with a fill bounded by the transfer length; a length that is not a
/// cache-line multiple mis-bounds the fill, corrupts the image, and the SPL hangs
/// before its first instruction. Inert on every other SoC, so it is applied to all.
pub const STAGE1_ALIGN: usize = 32;

/// Where a stage-1 (SPL) image is staged.
pub const SPL_LOAD_ADDR: u32 = 0x8000_1000;

/// Where a stage-1 image is entered — past the 0x800 signature.
pub const SPL_ENTRY_ADDR: u32 = 0x8000_1800;

/// Where U-Boot is staged and entered.
pub const UBOOT_ADDR: u32 = 0x8010_0000;

/// The configuration the bootrom is put into before its interface is claimed
/// (`device.c:332-340`).
pub const CONFIGURATION: u8 = 1;

/// The bootrom's one interface and its two bulk endpoints.
///
/// The C reads no endpoint descriptor anywhere — both addresses are `#define`s
/// (`tdfu.h:72-73`) — and declaring them once at claim time is what lets the transfer
/// calls carry no endpoint address at all.
pub const INTERFACE: InterfaceSpec = InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT);

/// The bulk timeout for a chunk of `len` bytes: 5 s plus 1 s per 64 KiB, clamped to
/// 5..=30 s.
///
/// **Ceiling, where the C floors.** `libtdfu/src/bootstrap.c:110` computes
/// `5000 + (size / 65536) * 1000` in integer arithmetic, so a 1-byte chunk gets 5 s and
/// a 65537-byte chunk gets 6 s; `div_ceil` gives 6 s and 7 s. The difference is one
/// second of patience per partial chunk, always in the direction of waiting longer,
/// which is the safe direction for a device that is slow rather than dead. Recorded
/// because "matches the C" would otherwise be read off this line and be wrong.
///
/// **The upper clamp is unreachable from the live caller.** `bulk_out_chunk` is the only
/// one, and it never offers more than [`BULK_CHUNK`], so `len` is at most 64 KiB and the
/// result at most 6 s. The clamp is kept — it is the rule and the function is
/// `pub` — but no chunk this crate sends can hit it, and only the unit test does. The
/// C's *lower* clamp (`bootstrap.c:113-114`) is unreachable for the same shape of
/// reason: its base is already the minimum.
#[must_use]
pub const fn bulk_timeout(len: usize) -> Duration {
    let extra = len.div_ceil(BULK_CHUNK) as u64;
    let secs = 5 + extra;
    Duration::from_secs(if secs > 30 { 30 } else { secs })
}

/// Claim the bootrom's interface, setting the configuration first only if it is not
/// already in force.
///
/// **The kernel-driver detach is the backend's**, not this layer's: the C's own claim
/// helper detaches inside itself (`device.c:342-345`), the extra hand-detach at
/// `bootstrap.c:80` is belt-and-braces on top of it, and
/// [`claim_interface`](tdfu_usb::LocalUsbTransport::claim_interface) is the one place a
/// backend can do it (nusb's `detach_and_claim_interface`). There is nothing to retry
/// here: a claim that failed after the backend already detached will fail again.
///
/// A `SET_CONFIGURATION` that answers [`Busy`](tdfu_usb::UsbErrorKind::Busy) is
/// tolerated and nothing else is — see [`tolerate_busy`].
///
/// # Errors
/// A non-`Busy` `SET_CONFIGURATION` failure, or anything
/// [`claim_interface`](tdfu_usb::LocalUsbTransport::claim_interface) raises.
pub async fn claim<T: LocalUsbTransport>(dev: &T) -> Result<()> {
    if dev.active_configuration() != Some(CONFIGURATION) {
        tolerate_busy(dev.set_configuration(CONFIGURATION).await)?;
    }
    dev.claim_interface(INTERFACE).await?;
    Ok(())
}

/// `Ok(())` for success **and** for [`Busy`](tdfu_usb::UsbErrorKind::Busy); every other
/// failure through unchanged.
///
/// The C's claim helper singles `Busy` out at `libtdfu/src/usb/device.c:336` — it tests
/// `!= LIBUSB_ERROR_BUSY` before it logs — because on Linux a `SET_CONFIGURATION` on an
/// already-configured device answers `EBUSY` while everything is fine.
///
/// We take that distinction and make it load-bearing, which is stricter than the C: it
/// logs at `:337-338` and claims anyway, whatever went wrong. If the request failed for
/// a reason that is *not* "already in force", the claim about to follow will fail too,
/// and this error is the one that says why; discarding it and reporting the claim's
/// throws the cause away.
///
/// `crate::dfu::host::claim` applies the same rule to the same request and carries the
/// same citation; the two are separate because the layers are, and neither may import
/// the other.
fn tolerate_busy(outcome: core::result::Result<(), UsbError>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) if *error.kind() == UsbErrorKind::Busy => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Release the bootrom's interface.
///
/// **This is load-bearing**: on the T20, leaving the interface claimed
/// after the bulk upload makes the following `FLUSH_CACHE` and `PROG_STAGE2` time out.
/// Release on every exit path, including the error paths. That is stricter than what
/// the C does, deliberately.
///
/// # Errors
/// Anything the transport raises. Releasing an unclaimed interface is `Ok(())`.
pub async fn release<T: LocalUsbTransport>(dev: &T) -> Result<()> {
    dev.release_interface(INTERFACE.interface).await?;
    Ok(())
}

/// Zero-pad a stage-1 image up to a multiple of [`STAGE1_ALIGN`].
#[must_use]
pub fn pad_stage1(image: &[u8]) -> Vec<u8> {
    let mut padded = image.to_vec();
    padded.resize(image.len().next_multiple_of(STAGE1_ALIGN), 0);
    padded
}

/// `usize` as `u64` without a cast lint and without a panic on a hypothetical
/// 128-bit target.
///
/// Not `const`: `u64::try_from` is not a `const fn` (the `TryFrom` impls are not yet
/// const-stable), and `value as u64` — which is — is the cast this exists to avoid.
/// Nothing here is used in a const context, so the cost is nil.
pub(crate) fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{BULK_CHUNK, CONFIGURATION, INTERFACE, STAGE1_ALIGN, bulk_timeout, claim, pad_stage1, release};
    use crate::bootrom::fixtures::{TestResult, bootrom, calls};
    use core::time::Duration;
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{BulkEndpoint, Pipe, UsbError, UsbErrorKind};

    #[test]
    fn rom_bulk_timeout_is_five_seconds_plus_one_per_chunk_clamped() {
        assert_eq!(bulk_timeout(0), Duration::from_secs(5));
        assert_eq!(bulk_timeout(1), Duration::from_secs(6));
        assert_eq!(bulk_timeout(BULK_CHUNK), Duration::from_secs(6));
        assert_eq!(bulk_timeout(BULK_CHUNK + 1), Duration::from_secs(7));
        assert_eq!(
            bulk_timeout(64 * BULK_CHUNK),
            Duration::from_secs(30),
            "clamped at 30 s"
        );
    }

    #[test]
    fn rom_stage1_cache_line_pad() {
        assert_eq!(pad_stage1(&[]).len(), 0);
        assert_eq!(pad_stage1(&[1]).len(), STAGE1_ALIGN);
        assert_eq!(
            pad_stage1(&[0; STAGE1_ALIGN]).len(),
            STAGE1_ALIGN,
            "already aligned, no padding"
        );
        assert_eq!(pad_stage1(&[0; STAGE1_ALIGN + 1]).len(), STAGE1_ALIGN * 2);
        let padded = pad_stage1(&[0xAA, 0xBB]);
        assert_eq!(&padded[..2], &[0xAA, 0xBB], "the image is not disturbed");
        assert!(padded[2..].iter().all(|&b| b == 0), "the padding is zero");
    }

    /// The claim, and the differential-capture divergence that motivated
    /// [`active_configuration`](tdfu_usb::LocalUsbTransport::active_configuration):
    /// the configuration is set when it is not in force, and **never twice**.
    #[test]
    fn rom_claim_sets_the_configuration_once() -> TestResult {
        // Enumerated but unconfigured (USB 9.1.1.5): one SET_CONFIGURATION, then none.
        let fresh = MockTransport::new(bootrom())
            .expecting(Call::SetConfiguration(CONFIGURATION), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(Call::ReleaseInterface(0), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done);
        block_on(async {
            claim(&fresh).await?;
            release(&fresh).await?;
            claim(&fresh).await
        })?;
        fresh.verify()?;
        assert_eq!(
            fresh
                .calls()
                .iter()
                .filter(|recorded| matches!(recorded.call, Call::SetConfiguration(_)))
                .count(),
            1,
            "the second claim must not re-issue SET_CONFIGURATION"
        );

        // Already configured: the request is never sent at all.
        let configured = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done);
        block_on(claim(&configured))?;
        configured.verify()?;
        assert_eq!(configured.calls().len(), 1, "claim only");
        Ok(())
    }

    /// The detach lives in the backend's `claim_interface` (the C's own
    /// claim helper detaches at `device.c:342-345`, and the hand-detach at
    /// `bootstrap.c:80` sits on top of that), so this layer issues exactly one claim
    /// and reports its failure rather than retrying blind.
    #[test]
    fn rom_claim_detaches_kernel_driver() -> TestResult {
        let denied = MockTransport::new(bootrom()).configured(CONFIGURATION).expecting(
            Call::ClaimInterface(INTERFACE),
            Reply::Fail(UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device)),
        );
        assert!(
            block_on(claim(&denied)).is_err(),
            "a refused claim is reported, not swallowed"
        );
        denied.verify()?;
        assert_eq!(
            denied.calls().len(),
            1,
            "one claim: the detach-and-retry belongs to the backend, not to core"
        );
        assert_eq!(
            INTERFACE.bulk_in.map(BulkEndpoint::address),
            Some(0x81),
            "the claim declares the bootrom's bulk IN"
        );
        assert_eq!(
            INTERFACE.bulk_out.map(BulkEndpoint::address),
            Some(0x01),
            "and its bulk OUT"
        );
        Ok(())
    }

    /// A `SET_CONFIGURATION` that fails is not fatal (`device.c:335-340`); the claim
    /// decides.
    #[test]
    fn rom_claim_tolerates_a_busy_set_configuration() -> TestResult {
        // A1: `EBUSY` from `SET_CONFIGURATION` means "already in force", which is not a
        // failure. The C draws the same line (`libtdfu/src/usb/device.c:336`).
        let dev = MockTransport::new(bootrom())
            .expecting(
                Call::SetConfiguration(CONFIGURATION),
                Reply::Fail(UsbError::new(UsbErrorKind::Busy, Pipe::Device)),
            )
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done);
        block_on(claim(&dev))?;
        dev.verify()?;
        Ok(())
    }

    #[test]
    fn rom_claim_propagates_a_set_configuration_failure_that_is_not_busy() -> TestResult {
        // The other half of A1, and the change from the C: it logs whatever went wrong
        // and claims anyway (`device.c:337-338`), throwing away the error that says
        // why the claim is about to fail.
        let dev = MockTransport::new(bootrom()).expecting(
            Call::SetConfiguration(CONFIGURATION),
            Reply::Fail(UsbError::new(UsbErrorKind::Fault, Pipe::Device)),
        );

        let Err(crate::Error::Usb(error)) = block_on(claim(&dev)) else {
            return Err("a non-Busy SET_CONFIGURATION failure must propagate".into());
        };
        assert_eq!(*error.kind(), UsbErrorKind::Fault, "and keep its own kind");
        assert!(
            !calls(&dev).iter().any(|call| matches!(call, Call::ClaimInterface(_))),
            "the claim must not go out over a configuration that did not take"
        );
        dev.verify()?;
        Ok(())
    }
}
