//! The six vendor requests and the retry loop they all share.

use tdfu_usb::{ControlIn, ControlOut, ControlType, LocalUsbTransport, Recipient};

use crate::clock::Sleeper;
use crate::error::{Error, Result};

use super::{
    CONTROL_TIMEOUT, SETTLE_AFTER_VENDOR_REQUEST, VENDOR_ATTEMPTS, VENDOR_RETRY_BACKOFF, claim, release, request,
};

/// How many bytes `GET_CPU_INFO` answers with (`device.c:28`, `device.c:56`).
const CPU_INFO_LEN: usize = 8;

/// The same, as `wLength` wants it. The assertion below keeps the two in step without
/// a cast at the call site.
const CPU_INFO_WLENGTH: u16 = 8;
const _: () = assert!(CPU_INFO_WLENGTH as usize == CPU_INFO_LEN);

/// The high half goes in `wValue`, the low half in `wIndex`.
///
/// Done through `to_le_bytes` rather than `as u16` so that no cast lint has to be
/// suppressed and the halves cannot be swapped by a typo that still compiles.
pub(super) const fn split(value: u32) -> (u16, u16) {
    let [low0, low1, high0, high1] = value.to_le_bytes();
    (u16::from_le_bytes([high0, high1]), u16::from_le_bytes([low0, low1]))
}

/// One vendor OUT with no data stage, retried.
///
/// Five attempts, [`VENDOR_RETRY_BACKOFF`] between them, and **only** the
/// `{Timeout, Stall, NoDevice}` class is retried — anything else fails immediately, as
/// `device.c:515-529` does. The fifth backoff entry is never reached because the loop
/// sleeps only between attempts; that is the C's behaviour and it is
/// harmless, so it is kept rather than "fixed" into a sixth attempt.
async fn vendor_out<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    request: u8,
    value: u16,
    index: u16,
) -> Result<()> {
    let mut attempt = 1_usize;
    loop {
        let outcome = dev
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    data: &[],
                },
                CONTROL_TIMEOUT,
            )
            .await;
        match outcome {
            Ok(()) => return Ok(()),
            Err(err) => {
                if !err.is_vendor_retryable() || attempt >= VENDOR_ATTEMPTS {
                    return Err(err.into());
                }
                if let Some(delay) = VENDOR_RETRY_BACKOFF.get(attempt - 1) {
                    clock.sleep(*delay).await;
                }
                attempt += 1;
            }
        }
    }
}

/// [`vendor_out`] plus the 100 ms settle, which the C applies **only after a
/// success** — every one of the five returns early on failure before its
/// `platform_sleep_ms` (`protocol.c:22-32, 47-57, 71-81, 96-106, 121-134`).
async fn vendor_out_settled<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    request: u8,
    value: u16,
    index: u16,
) -> Result<()> {
    vendor_out(dev, clock, request, value, index).await?;
    clock.sleep(SETTLE_AFTER_VENDOR_REQUEST).await;
    Ok(())
}

/// Read the 8-byte bootrom identity string, **without claiming the interface first**;
/// claim-then-request is the fallback.
///
/// The result is a coarse family hint and nothing more: T40, T41
/// and A1 all report `T31V`, and so does this bench's T23N. Never use it to pick a
/// loader.
///
/// Neither path settles afterwards (`device.c:14-59`), and neither is retried: this
/// signature carries no clock, so the vendor backoff cannot apply
/// to the fallback as it does in the C, where the fallback goes through the retrying
/// wrapper (`device.c:41-42`). A bootrom that refuses the request twice is not going to
/// answer on the fifth attempt, and every caller of this is a *hint*.
///
/// The interface is released on both fallback paths, and a release failure is reported
/// only when the transfer itself succeeded — the transfer's error is the interesting
/// one.
///
/// # Errors
/// [`Error::Usb`] if both the direct request and the fallback fail — the *claim's*
/// error when it is the claim that failed, because that is the actionable one (a
/// missing udev rule reads as `AccessDenied`, not as a stalled EP0).
/// [`Error::Protocol`] if fewer than eight bytes come back (`device.c:56-59`).
pub async fn get_cpu_info<T: LocalUsbTransport>(dev: &T) -> Result<[u8; CPU_INFO_LEN]> {
    let query = ControlIn {
        control_type: ControlType::Vendor,
        recipient: Recipient::Device,
        request: request::GET_CPU_INFO,
        value: 0,
        index: 0,
        len: CPU_INFO_WLENGTH,
    };
    if let Ok(data) = dev.control_in(query, CONTROL_TIMEOUT).await {
        return exactly_eight(&data);
    }

    // Fall back to claiming the interface first, as the C does when the direct
    // transfer is refused (`device.c:30-39`).
    claim(dev).await?;
    let fallback = dev.control_in(query, CONTROL_TIMEOUT).await;
    let released = release(dev).await;
    let data = fallback?;
    released?;
    exactly_eight(&data)
}

/// Fewer than eight bytes is a protocol failure, not a short string.
fn exactly_eight(data: &[u8]) -> Result<[u8; CPU_INFO_LEN]> {
    data.get(..CPU_INFO_LEN)
        .and_then(|head| <[u8; CPU_INFO_LEN]>::try_from(head).ok())
        .ok_or_else(|| {
            Error::Protocol(format!(
                "GET_CPU_INFO answered {} bytes, expected {CPU_INFO_LEN}",
                data.len()
            ))
        })
}

/// `SET_DATA_ADDR`: the address is split across `wValue` (high 16) and `wIndex`
/// (low 16). Followed by [`SETTLE_AFTER_VENDOR_REQUEST`].
///
/// # Errors
/// Anything the transport raises, after the five attempts.
pub async fn set_data_addr<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, addr: u32) -> Result<()> {
    let (value, index) = split(addr);
    vendor_out_settled(dev, clock, request::SET_DATA_ADDR, value, index).await
}

/// `SET_DATA_LEN`: same split as [`set_data_addr`].
///
/// # Errors
/// Anything the transport raises, after the five attempts.
pub async fn set_data_len<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, len: u32) -> Result<()> {
    let (value, index) = split(len);
    vendor_out_settled(dev, clock, request::SET_DATA_LEN, value, index).await
}

/// `FLUSH_CACHE`.
///
/// **Its failure is fatal.** The C calls it bare (`dfu.c:1146`) and discards the
/// result; an earlier implementation copied that, and it is fixed here under the
/// no-copied-bugs rule. If the cache is not flushed, what `PROG_STAGE2`
/// jumps into is
/// undefined — so the error propagates, `PROG_STAGE2` is not sent, and the interface is
/// still released.
///
/// # Errors
/// Anything the transport raises, after the five attempts.
pub async fn flush_cache<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<()> {
    vendor_out_settled(dev, clock, request::FLUSH_CACHE, 0, 0).await
}

/// `PROG_STAGE1`: execute what was staged at `entry`.
///
/// **One shot per power cycle.** This is why detection executes nothing:
/// spending the mask ROM's single chance on an identification stub is what left a T10
/// with a dead boot, and it is the biggest single improvement over the C.
///
/// # Errors
/// Anything the transport raises, after the five attempts.
pub async fn prog_stage1<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, entry: u32) -> Result<()> {
    let (value, index) = split(entry);
    vendor_out_settled(dev, clock, request::PROG_STAGE1, value, index).await
}

/// `PROG_STAGE2`: execute U-Boot.
///
/// **Any error is success.** The device is already executing U-Boot and
/// re-enumerating, so the control transfer has nothing left to ACK. The C's comment
/// says "timeout or pipe error" but `protocol.c:121-126` swallows every error, and the
/// code is the authority.
///
/// The request still goes through the retry loop, because in the C all five
/// share one wrapper (`protocol.c:117-119` → `device.c:488`) and the retries only ever
/// run on the failure path — where a device that has *not* jumped gets another chance
/// to receive the request it never saw. On success there is no retry and no cost. The
/// settle is skipped when it fails, exactly as `protocol.c:121-134` does.
///
/// # Errors
/// Never, in practice — the signature keeps the shape of its siblings.
pub async fn prog_stage2<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, entry: u32) -> Result<()> {
    let (value, index) = split(entry);
    if vendor_out(dev, clock, request::PROG_STAGE2, value, index).await.is_ok() {
        clock.sleep(SETTLE_AFTER_VENDOR_REQUEST).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{get_cpu_info, split};
    use crate::bootrom::fixtures::{TestResult, bootrom, calls, timeouts_of, vendor_out};
    use crate::bootrom::{
        CONFIGURATION, CONTROL_TIMEOUT, INTERFACE, SETTLE_AFTER_VENDOR_REQUEST, VENDOR_RETRY_BACKOFF, flush_cache,
        prog_stage1, prog_stage2, request, set_data_addr, set_data_len,
    };
    use crate::clock::RecordingClock;
    use core::time::Duration;
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{ControlIn, ControlType, Direction, Pipe, Recipient, UsbError, UsbErrorKind};

    fn fail(kind: UsbErrorKind, request: u8) -> Reply {
        Reply::Fail(UsbError::new(
            kind,
            Pipe::Control {
                direction: Direction::Out,
                request,
            },
        ))
    }

    fn cpu_info_query() -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: request::GET_CPU_INFO,
            value: 0,
            index: 0,
            len: 8,
        })
    }

    /// `0xB3540238` must go out as `wValue 0xB354`, `wIndex 0x0238` — not
    /// the other way round, which is the mistake this split exists to make impossible.
    #[test]
    fn rom_addr_len_split() -> TestResult {
        assert_eq!(split(0xB354_0238), (0xB354, 0x0238));
        assert_eq!(split(0x8000_1800), (0x8000, 0x1800));
        assert_eq!(split(0), (0, 0));
        assert_eq!(split(u32::MAX), (0xFFFF, 0xFFFF));

        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom())
            .expecting(vendor_out(request::SET_DATA_ADDR, 0xB354, 0x0238), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0x0001, 0x0000), Reply::Done)
            .expecting(vendor_out(request::PROG_STAGE1, 0x8000, 0x1800), Reply::Done);
        block_on(async {
            set_data_addr(&dev, &clock, 0xB354_0238).await?;
            set_data_len(&dev, &clock, 0x0001_0000).await?;
            prog_stage1(&dev, &clock, 0x8000_1800).await
        })?;
        dev.verify()?;
        Ok(())
    }

    /// 100 ms after each of the five, and the control transfer itself gets
    /// the 5 s deadline (`device.c:504`).
    #[test]
    fn rom_settle_after_vendor_request() -> TestResult {
        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom())
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 0x0100), Reply::Done)
            .expecting(vendor_out(request::FLUSH_CACHE, 0, 0), Reply::Done)
            .expecting(vendor_out(request::PROG_STAGE1, 0x8000, 0x1800), Reply::Done)
            .expecting(vendor_out(request::PROG_STAGE2, 0x8010, 0x0000), Reply::Done);
        block_on(async {
            set_data_addr(&dev, &clock, 0x8000_1000).await?;
            set_data_len(&dev, &clock, 0x100).await?;
            flush_cache(&dev, &clock).await?;
            prog_stage1(&dev, &clock, 0x8000_1800).await?;
            prog_stage2(&dev, &clock, 0x8010_0000).await
        })?;
        dev.verify()?;
        assert_eq!(
            clock.slept(),
            vec![SETTLE_AFTER_VENDOR_REQUEST; 5],
            "one 100 ms settle per request, and nothing else"
        );
        assert_eq!(
            timeouts_of(&dev, |call| matches!(call, Call::ControlOut { .. })),
            vec![Some(CONTROL_TIMEOUT); 5],
            "5 s per attempt (device.c:504)"
        );
        Ok(())
    }

    /// The settle from the other side, and the no-copied-bugs rule.
    ///
    /// Four of the five return before their `platform_sleep_ms`, so a failure is not
    /// settled after — and, unlike `PROG_STAGE2`, the failure *propagates*.
    /// `FLUSH_CACHE` is the one that matters: the C calls it bare and discards the
    /// result (`dfu.c:1146`), so it jumps into a cache it never flushed. Here the error
    /// reaches the caller, whose job it then is not to send `PROG_STAGE2`
    /// (`boot_flush_cache_failure_is_fatal`).
    #[test]
    fn a_failed_vendor_request_is_fatal_and_unsettled() -> TestResult {
        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom())
            .expecting(
                vendor_out(request::FLUSH_CACHE, 0, 0),
                fail(UsbErrorKind::Fault, request::FLUSH_CACHE),
            )
            .expecting(
                vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000),
                fail(UsbErrorKind::Fault, request::SET_DATA_ADDR),
            )
            .expecting(
                vendor_out(request::SET_DATA_LEN, 0, 32),
                fail(UsbErrorKind::Fault, request::SET_DATA_LEN),
            )
            .expecting(
                vendor_out(request::PROG_STAGE1, 0x8000, 0x1800),
                fail(UsbErrorKind::Fault, request::PROG_STAGE1),
            );
        assert!(block_on(flush_cache(&dev, &clock)).is_err(), "FLUSH_CACHE is fatal");
        assert!(block_on(set_data_addr(&dev, &clock, 0x8000_1000)).is_err());
        assert!(block_on(set_data_len(&dev, &clock, 32)).is_err());
        assert!(block_on(prog_stage1(&dev, &clock, 0x8000_1800)).is_err());
        dev.verify()?;
        assert!(clock.slept().is_empty(), "no settle after a failure");
        Ok(())
    }

    /// Five attempts, four sleeps, and the fifth backoff
    /// entry is unreachable. A test that asserted five sleeps would be asserting a bug.
    #[test]
    fn rom_vendor_retry_backoff() -> TestResult {
        let clock = RecordingClock::new();
        let mut dev = MockTransport::new(bootrom());
        for _ in 0..5 {
            dev = dev.expecting(
                vendor_out(request::SET_DATA_ADDR, 0, 4),
                fail(UsbErrorKind::Timeout, request::SET_DATA_ADDR),
            );
        }
        assert!(block_on(set_data_addr(&dev, &clock, 4)).is_err());
        dev.verify()?;
        assert_eq!(dev.calls().len(), 5, "five attempts");
        assert_eq!(
            clock.slept(),
            vec![
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(3),
            ],
            "four sleeps between five attempts; no settle, since it never succeeded"
        );
        assert_eq!(
            VENDOR_RETRY_BACKOFF[4],
            Duration::from_secs(5),
            "the fifth entry exists, and is never slept"
        );
        assert!(!clock.slept().contains(&Duration::from_secs(5)));
        Ok(())
    }

    /// The retry class is `{Timeout, Stall, NoDevice}` and nothing else.
    #[test]
    fn a_vendor_request_retries_only_its_own_error_class() -> TestResult {
        for kind in [UsbErrorKind::Timeout, UsbErrorKind::Stall, UsbErrorKind::NoDevice] {
            let clock = RecordingClock::new();
            let dev = MockTransport::new(bootrom())
                .expecting(
                    vendor_out(request::SET_DATA_LEN, 0, 4),
                    fail(kind.clone(), request::SET_DATA_LEN),
                )
                .expecting(vendor_out(request::SET_DATA_LEN, 0, 4), Reply::Done);
            block_on(set_data_len(&dev, &clock, 4))?;
            dev.verify()?;
            assert_eq!(dev.calls().len(), 2, "{kind:?} is retried");
            assert_eq!(
                clock.slept(),
                vec![Duration::from_millis(500), SETTLE_AFTER_VENDOR_REQUEST],
                "the backoff, then the settle for the attempt that worked"
            );
        }

        for kind in [
            UsbErrorKind::Fault,
            UsbErrorKind::AccessDenied,
            UsbErrorKind::Overflow,
            UsbErrorKind::Unsupported,
            UsbErrorKind::NotClaimed,
            UsbErrorKind::Backend("scripted".into()),
        ] {
            let clock = RecordingClock::new();
            let dev = MockTransport::new(bootrom()).expecting(
                vendor_out(request::SET_DATA_LEN, 0, 4),
                fail(kind.clone(), request::SET_DATA_LEN),
            );
            assert!(block_on(set_data_len(&dev, &clock, 4)).is_err(), "{kind:?}");
            dev.verify()?;
            assert_eq!(dev.calls().len(), 1, "{kind:?} fails immediately");
            assert!(clock.slept().is_empty(), "{kind:?} sleeps for nothing");
        }
        Ok(())
    }

    /// The device has jumped into U-Boot and there is nothing left to ACK.
    /// The retries still run — they cost nothing on the success path and give a request
    /// the device never saw another chance — and there is no settle after a failure.
    #[test]
    fn rom_stage2_failure_is_success() -> TestResult {
        for kind in [
            UsbErrorKind::Timeout,
            UsbErrorKind::Stall,
            UsbErrorKind::NoDevice,
            UsbErrorKind::Fault,
            UsbErrorKind::Backend("gone".into()),
        ] {
            let clock = RecordingClock::new();
            let mut dev = MockTransport::new(bootrom());
            let attempts = if matches!(
                kind,
                UsbErrorKind::Timeout | UsbErrorKind::Stall | UsbErrorKind::NoDevice
            ) {
                5
            } else {
                1
            };
            for _ in 0..attempts {
                dev = dev.expecting(
                    vendor_out(request::PROG_STAGE2, 0x8010, 0x0000),
                    fail(kind.clone(), request::PROG_STAGE2),
                );
            }
            block_on(prog_stage2(&dev, &clock, 0x8010_0000))?;
            dev.verify()?;
            assert!(
                !clock.slept().contains(&SETTLE_AFTER_VENDOR_REQUEST),
                "{kind:?}: no settle after a failure"
            );
        }
        Ok(())
    }

    /// One control IN, no claim, no settle.
    #[test]
    fn rom_get_cpu_info_does_not_claim_or_settle() -> TestResult {
        let dev = MockTransport::new(bootrom()).expecting(cpu_info_query(), Reply::Data(b"T31V0001".to_vec()));
        assert_eq!(&block_on(get_cpu_info(&dev))?, b"T31V0001");
        dev.verify()?;
        assert_eq!(calls(&dev), vec![cpu_info_query()], "no claim, no release");
        Ok(())
    }

    /// The fallback: claim, ask again, release on both paths.
    #[test]
    fn rom_get_cpu_info_falls_back_to_claiming() -> TestResult {
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(
                cpu_info_query(),
                Reply::Fail(UsbError::new(
                    UsbErrorKind::Stall,
                    Pipe::Control {
                        direction: Direction::In,
                        request: request::GET_CPU_INFO,
                    },
                )),
            )
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(cpu_info_query(), Reply::Data(b"T21V0001".to_vec()))
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        assert_eq!(&block_on(get_cpu_info(&dev))?, b"T21V0001");
        dev.verify()?;

        // And the release still happens when the second attempt fails too.
        let failing = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(
                cpu_info_query(),
                Reply::Fail(UsbError::new(UsbErrorKind::Timeout, Pipe::Device)),
            )
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(
                cpu_info_query(),
                Reply::Fail(UsbError::new(UsbErrorKind::Timeout, Pipe::Device)),
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        assert!(block_on(get_cpu_info(&failing)).is_err());
        failing.verify()?;
        Ok(())
    }

    /// A short answer is a protocol failure, not a short string (`device.c:56-59`).
    #[test]
    fn a_short_cpu_info_is_a_protocol_error() -> TestResult {
        let dev = MockTransport::new(bootrom()).expecting(cpu_info_query(), Reply::Data(b"T31".to_vec()));
        let err = block_on(get_cpu_info(&dev));
        assert!(matches!(err, Err(crate::Error::Protocol(_))), "{err:?}");
        dev.verify()?;
        Ok(())
    }
}
