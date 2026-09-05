//! The two bulk paths: reading memory and staging an image.

use tdfu_usb::{BulkEndpoint, LocalUsbTransport, UsbError, UsbErrorKind, endpoint};

use crate::addr::Kseg1;
use crate::clock::Sleeper;
use crate::error::{Error, Result};
use crate::progress::{Phase, Progress, ProgressSink};

use super::{
    BULK_CHUNK, CHUNK_ATTEMPTS, CHUNK_RETRY_DELAY, INTER_CHUNK_DELAY, INTER_CHUNK_DELAY_THRESHOLD, READ_MEMORY_TIMEOUT,
    SPL_LOAD_ADDR, UBOOT_ADDR, as_u64, bulk_timeout, claim, release, set_data_addr, set_data_len,
};

/// Read `len` bytes from `addr` — `SET_DATA_ADDR`, `SET_DATA_LEN`, bulk IN, 2000 ms,
/// and **exactly `len` bytes or a failure**.
///
/// The address is a [`Kseg1`], so the kseg1-only rule is enforced by the type system
/// rather than by a guard someone can forget to write — which is exactly what happened
/// to an earlier implementation's second read path. The physical form
/// wedges the bootrom's USB handler until the device is power-cycled, and that hang is
/// the whole reason the C uploads and executes a stub to read three registers.
///
/// The interface must already be claimed: this is the inner primitive, and the C's own
/// `protocol_read_memory` claims nothing either (`protocol.c:141-162`) — `diag.c:114`
/// claims once around all of its reads, and [`ops::detect`](crate::ops::detect) does
/// the same around its three.
///
/// # Errors
/// [`Error::Invalid`] for a zero or unrepresentable length (`protocol.c:142`).
/// [`Error::Usb`](crate::Error::Usb) on transfer failure, including a short read.
pub async fn read_memory<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    addr: Kseg1,
    len: usize,
) -> Result<Vec<u8>> {
    let wire_len = u32::try_from(len).ok().filter(|len| *len != 0).ok_or_else(|| {
        Error::Invalid(format!(
            "cannot read {len} bytes from {addr}: the length must be non-zero and fit in 32 bits"
        ))
    })?;

    set_data_addr(dev, clock, addr.get()).await?;
    set_data_len(dev, clock, wire_len).await?;

    // The transport returns exactly `len` or `Short`, so
    // "a short read is a failure" needs no length check here.
    match dev.bulk_in(len, READ_MEMORY_TIMEOUT).await {
        Ok(data) => Ok(data),
        Err(err) => {
            clear_halt_if_stalled(dev, endpoint::BOOTROM_IN, &err).await;
            Err(err.into())
        }
    }
}

/// Stage `data` at `addr` over bulk OUT: chunked at [`BULK_CHUNK`], with per-chunk
/// retries and partial-write handling and the inter-chunk delay, and
/// the interface **released afterwards**.
///
/// A backend timeout that nonetheless reports the full length is success.
///
/// **The caller pads.** [`pad_stage1`](super::pad_stage1) does the rounding and the
/// C applies it inside this function for *both* images (`bootstrap.c:36-46`, called for
/// the SPL at `dfu.c:1132` and for U-Boot at `dfu.c:1143`); here it is a separate,
/// pinned function so that the length on the wire is always exactly the length the
/// caller asked for. `SET_DATA_LEN` carries `data.len()`, so a caller that skips the
/// padding gets an unpadded transfer — which is the T10/T20/T21/T30 corruption the
/// rounding exists to prevent.
///
/// # Errors
/// [`Error::Invalid`] for empty data (`bootstrap.c:27-29`).
/// [`Error::Usb`](crate::Error::Usb) once the per-chunk retries are exhausted.
pub async fn load_to_memory<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    addr: u32,
    data: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    if data.is_empty() {
        return Err(Error::Invalid(format!("nothing to stage at {addr:#010X}")));
    }
    let wire_len = u32::try_from(data.len())
        .map_err(|_| Error::Invalid(format!("{} bytes is more than the bootrom can stage", data.len())))?;

    set_data_addr(dev, clock, addr).await?;
    set_data_len(dev, clock, wire_len).await?;

    // The C claims here, after the two vendor requests and before the first chunk
    // (`bootstrap.c:77-86`), and releases on every path out (`:151`, `:158`, `:173`).
    claim(dev).await?;
    let transferred = transfer_chunks(dev, clock, addr, data, progress).await;
    // On the T20 a still-claimed interface makes the FLUSH_CACHE and
    // PROG_STAGE2 that follow time out. The transfer's error outranks a release
    // failure, but neither is dropped.
    let released = release(dev).await;
    transferred?;
    released
}

/// The chunk loop of [`load_to_memory`], with the claim already in force.
async fn transfer_chunks<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    addr: u32,
    data: &[u8],
    progress: ProgressSink<'_>,
) -> Result<()> {
    let phase = phase_for(addr);
    let total = data.len();
    let mut offset = 0_usize;

    while offset < total {
        let chunk_end = total.min(offset + BULK_CHUNK);
        // The C never resets this budget, so three partial writes in a row
        // fail a chunk that made progress every time. Progress resets it here.
        let mut attempts_left = CHUNK_ATTEMPTS;

        while offset < chunk_end {
            let Some(chunk) = data.get(offset..chunk_end) else {
                return Err(Error::Protocol(format!(
                    "chunk {offset}..{chunk_end} is outside the {total}-byte image"
                )));
            };
            match bulk_out_chunk(dev, chunk).await {
                Ok(written) if written > 0 => {
                    offset += written;
                    attempts_left = CHUNK_ATTEMPTS;
                }
                Ok(_) => {
                    // No error and no bytes. The C spends an attempt on this too and
                    // gives up on the last one (`bootstrap.c:155-160`).
                    //
                    // `saturating_sub`, not `-= 1`: the loop returns at zero so it cannot
                    // underflow today, but that is an invariant two branches away rather
                    // than a local fact, and a debug-build panic here would abort a
                    // flashing tool mid-write.
                    attempts_left = attempts_left.saturating_sub(1);
                    if attempts_left == 0 {
                        return Err(Error::Protocol(format!(
                            "the bootrom accepted 0 of {} bytes and reported no error",
                            chunk.len()
                        )));
                    }
                    clock.sleep(CHUNK_RETRY_DELAY).await;
                }
                Err(err) => {
                    // A halted bulk endpoint latches until CLEAR_FEATURE(ENDPOINT_HALT),
                    // so without this the retry below is decorative.
                    clear_halt_if_stalled(dev, endpoint::BOOTROM_OUT, &err).await;
                    attempts_left = attempts_left.saturating_sub(1);
                    // The C retries *any* error here (`bootstrap.c:138-148`); this
                    // module has one retry class instead of two, the vendor class
                    // `{Timeout, Stall, NoDevice}`. It is the class the transport
                    // answers for, and it keeps a scripted
                    // `Backend` mismatch — a test double disagreeing with the code —
                    // from being papered over by three retries.
                    if !err.is_vendor_retryable() || attempts_left == 0 {
                        return Err(err.into());
                    }
                    clock.sleep(CHUNK_RETRY_DELAY).await;
                }
            }
        }

        progress(Progress::Bytes {
            phase,
            done: as_u64(offset),
            total: Some(as_u64(total)),
        });

        // `bootstrap.c:164-167`: only above the threshold, and never after
        // the last chunk.
        if total > INTER_CHUNK_DELAY_THRESHOLD && offset < total {
            clock.sleep(INTER_CHUNK_DELAY).await;
        }
    }
    Ok(())
}

/// One bulk-OUT attempt, in bytes the device accepted.
///
/// A backend that reports a missed deadline *and* the full
/// length has succeeded (`device.c:433-443`), and the transport spells that
/// `Short { got >= want }`. A genuinely short write is reported as
/// the bytes it did move, so the caller continues with the remainder rather than
/// re-sending bytes the bootrom has already taken — the C discards the count on that
/// path (`bootstrap.c:119`) and re-sends from the same offset.
async fn bulk_out_chunk<T: LocalUsbTransport>(dev: &T, chunk: &[u8]) -> core::result::Result<usize, UsbError> {
    match dev.bulk_out(chunk, bulk_timeout(chunk.len())).await {
        Ok(written) => Ok(written.min(chunk.len())),
        Err(err) => match *err.kind() {
            // The two `Short` arms are deliberately disjoint. Overlapping them makes
            // the late-completion rule unfalsifiable: with `got < want` widened to `got > 0`,
            // deleting this arm changes nothing any test can see, because the partial
            // arm answers `min(got, len)` — the same value — for `got == want`.
            UsbErrorKind::Short { got, want } if got >= want => Ok(chunk.len()),
            // Some progress is progress; none leaves the error to be reported.
            UsbErrorKind::Short { got, want } if got > 0 && got < want => Ok(got.min(chunk.len())),
            _ => Err(err),
        },
    }
}

/// Clear a latched halt, best effort.
///
/// A bulk endpoint that stalls keeps answering `EPIPE` until
/// `CLEAR_FEATURE(ENDPOINT_HALT)` (USB 2.0 §5.8.5), so a retry without this cannot
/// succeed. The C calls `libusb_clear_halt` nowhere in the tree, which is exactly why
/// nobody noticed. If the clear itself fails there is nothing further to try, and the
/// transfer's own error is the one worth reporting.
async fn clear_halt_if_stalled<T: LocalUsbTransport>(dev: &T, endpoint: BulkEndpoint, err: &UsbError) {
    if matches!(err.kind(), UsbErrorKind::Stall) {
        let _ignored = dev.clear_halt(endpoint).await;
    }
}

/// Which [`Phase`] a staging address belongs to, for the progress frame's stage byte.
///
/// [`load_to_memory`]'s signature carries no phase, and the address is what
/// distinguishes the two images: the C always stages the SPL at `DFU_SPL_ADDR` and
/// U-Boot at `DFU_UBOOT_ADDR` (`dfu.c:1132`, `dfu.c:1143`), including for `--spl` /
/// `--uboot` overrides. Anything else is a caller doing something new, and says so.
const fn phase_for(addr: u32) -> Phase {
    match addr {
        SPL_LOAD_ADDR => Phase::Stage1,
        UBOOT_ADDR => Phase::UBoot,
        _ => Phase::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{load_to_memory, phase_for, read_memory};
    use crate::addr::{EFUSE_WINDOW, EFUSE_WINDOW_LEN, SOC_ID, SUBSOCTYPE1};
    use crate::bootrom::fixtures::{TestResult, bootrom, calls, timeouts_of, vendor_out, vendor_out_word};
    use crate::bootrom::{
        BULK_CHUNK, CHUNK_RETRY_DELAY, CONFIGURATION, INTER_CHUNK_DELAY, INTER_CHUNK_DELAY_THRESHOLD, INTERFACE,
        READ_MEMORY_TIMEOUT, SETTLE_AFTER_VENDOR_REQUEST, SPL_LOAD_ADDR, UBOOT_ADDR, bulk_timeout, request,
    };
    use crate::clock::RecordingClock;
    use crate::progress::{Phase, Progress};
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind, endpoint};

    fn bulk_fail(kind: UsbErrorKind) -> Reply {
        Reply::Fail(UsbError::new(kind, Pipe::Bulk(endpoint::BOOTROM_OUT)))
    }

    fn image(len: usize) -> Vec<u8> {
        (0..len).map(|byte| u8::try_from(byte % 251).unwrap_or(0)).collect()
    }

    /// The two vendor requests plus the chunk expectations a staged image produces.
    fn staging(dev: MockTransport, addr: u32, data: &[u8]) -> MockTransport {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        let mut dev = dev
            .expecting(vendor_out_word(request::SET_DATA_ADDR, addr), Reply::Done)
            .expecting(vendor_out_word(request::SET_DATA_LEN, len), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done);
        for chunk in data.chunks(BULK_CHUNK) {
            dev = dev.expecting(Call::BulkOut { data: chunk.to_vec() }, Reply::Done);
        }
        dev.expecting(Call::ReleaseInterface(0), Reply::Done)
    }

    /// Address, length, one bulk IN of exactly `len` at 2 s.
    #[test]
    fn rom_read_memory_exact_len() -> TestResult {
        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0xB300, 0x002C), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 4), Reply::Done)
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(vec![0x03, 0x30, 0x04, 0x10]))
            .expecting(vendor_out(request::SET_DATA_ADDR, 0xB354, 0x0238), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 4), Reply::Done)
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(vec![0x00, 0x00, 0x11, 0x11]));

        let (soc_id, sub1) = block_on(async {
            crate::bootrom::claim(&dev).await?;
            let soc_id = read_memory(&dev, &clock, SOC_ID, 4).await?;
            let sub1 = read_memory(&dev, &clock, SUBSOCTYPE1, 4).await?;
            Ok::<_, crate::Error>((soc_id, sub1))
        })?;
        dev.verify()?;

        assert_eq!(
            u32::from_le_bytes([soc_id[0], soc_id[1], soc_id[2], soc_id[3]]),
            0x1004_3003
        );
        assert_eq!(sub1, vec![0x00, 0x00, 0x11, 0x11]);
        assert_eq!(
            timeouts_of(&dev, |call| matches!(call, Call::BulkIn { .. })),
            vec![Some(READ_MEMORY_TIMEOUT); 2],
            "2000 ms, not the 5 s control timeout"
        );
        assert_eq!(
            clock.slept(),
            vec![SETTLE_AFTER_VENDOR_REQUEST; 4],
            "two settles per read; the bulk IN itself is not settled after"
        );
        Ok(())
    }

    /// The other half: fewer bytes than asked for is a failure, and the
    /// latched halt is cleared so the *next* read can work.
    #[test]
    fn a_short_memory_read_fails_and_clears_the_halt() -> TestResult {
        let clock = RecordingClock::new();
        let short = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0xB300, 0x002C), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 4), Reply::Done)
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(vec![0x03, 0x30]));
        let outcome = block_on(async {
            crate::bootrom::claim(&short).await?;
            read_memory(&short, &clock, SOC_ID, 4).await
        });
        assert!(outcome.is_err(), "exactly len or a failure");
        short.verify()?;

        let stalled = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0xB354, 0x0200), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 256), Reply::Done)
            .expecting(
                Call::BulkIn { len: EFUSE_WINDOW_LEN },
                Reply::Fail(UsbError::new(UsbErrorKind::Stall, Pipe::Bulk(endpoint::BOOTROM_IN))),
            )
            .expecting(Call::ClearHalt(endpoint::BOOTROM_IN), Reply::Done);
        let outcome = block_on(async {
            crate::bootrom::claim(&stalled).await?;
            read_memory(&stalled, &clock, EFUSE_WINDOW, EFUSE_WINDOW_LEN).await
        });
        assert!(outcome.is_err());
        stalled.verify()?;
        Ok(())
    }

    /// A zero-length read is refused before anything reaches the device
    /// (`protocol.c:142`).
    #[test]
    fn a_zero_length_read_is_refused() -> TestResult {
        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom()).configured(CONFIGURATION);
        assert!(matches!(
            block_on(read_memory(&dev, &clock, SOC_ID, 0)),
            Err(crate::Error::Invalid(_))
        ));
        assert!(dev.calls().is_empty(), "nothing goes to the device");
        dev.verify()?;
        Ok(())
    }

    /// 64 KiB chunks, each with its own `5 s + 1 s/64 KiB` deadline, and
    /// the release afterwards.
    #[test]
    fn rom_bulk_chunking_and_partial_writes() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(BULK_CHUNK + 16);
        let dev = staging(
            MockTransport::new(bootrom()).configured(CONFIGURATION),
            UBOOT_ADDR,
            &data,
        );
        let mut seen = Vec::new();
        block_on(load_to_memory(&dev, &clock, UBOOT_ADDR, &data, &mut |p| seen.push(p)))?;
        dev.verify()?;
        assert_eq!(
            timeouts_of(&dev, |call| matches!(call, Call::BulkOut { .. })),
            vec![Some(bulk_timeout(BULK_CHUNK)), Some(bulk_timeout(16))],
            "one deadline per chunk, sized by the chunk"
        );
        assert_eq!(
            seen,
            vec![
                Progress::Bytes {
                    phase: Phase::UBoot,
                    done: 65536,
                    total: Some(65552)
                },
                Progress::Bytes {
                    phase: Phase::UBoot,
                    done: 65552,
                    total: Some(65552)
                },
            ]
        );

        // A partial write continues with the remainder rather than re-sending what the
        // bootrom already took.
        let data = image(48);
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 48), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(Call::BulkOut { data: data.clone() }, Reply::Transferred(16))
            .expecting(
                Call::BulkOut {
                    data: data[16..].to_vec(),
                },
                Reply::Transferred(16),
            )
            .expecting(
                Call::BulkOut {
                    data: data[32..].to_vec(),
                },
                Reply::Transferred(8),
            )
            .expecting(
                Call::BulkOut {
                    data: data[40..].to_vec(),
                },
                Reply::Transferred(8),
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        Ok(())
    }

    /// **Progress resets the retry budget.** The C decrements it and never
    /// resets, so a chunk that advanced between failures still dies on the third one.
    ///
    /// Fail, advance, fail, fail, finish: four failures in one chunk, none of them
    /// consecutive enough to exhaust a budget that resets. Without the reset the third
    /// failure is fatal and this transfer never completes.
    #[test]
    fn progress_resets_the_chunk_retry_budget() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(32);
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 32), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(Call::BulkOut { data: data.clone() }, bulk_fail(UsbErrorKind::Timeout))
            .expecting(Call::BulkOut { data: data.clone() }, Reply::Transferred(8))
            .expecting(
                Call::BulkOut {
                    data: data[8..].to_vec(),
                },
                bulk_fail(UsbErrorKind::Timeout),
            )
            .expecting(
                Call::BulkOut {
                    data: data[8..].to_vec(),
                },
                bulk_fail(UsbErrorKind::Timeout),
            )
            .expecting(
                Call::BulkOut {
                    data: data[8..].to_vec(),
                },
                Reply::Done,
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        assert_eq!(
            clock.slept().iter().filter(|d| **d == CHUNK_RETRY_DELAY).count(),
            3,
            "one wait after each of the three failures"
        );
        Ok(())
    }

    /// The per-chunk retry budget: three attempts, 50 ms apart, then the
    /// device's own error.
    #[test]
    fn a_chunk_is_attempted_three_times() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(32);
        let mut dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 32), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done);
        for _ in 0..3 {
            dev = dev.expecting(Call::BulkOut { data: data.clone() }, bulk_fail(UsbErrorKind::Timeout));
        }
        dev = dev.expecting(Call::ReleaseInterface(0), Reply::Done);
        let outcome = block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ));
        assert!(outcome.is_err(), "the chunk failed three times");
        dev.verify()?;
        assert_eq!(
            clock.slept(),
            vec![
                SETTLE_AFTER_VENDOR_REQUEST,
                SETTLE_AFTER_VENDOR_REQUEST,
                CHUNK_RETRY_DELAY,
                CHUNK_RETRY_DELAY,
            ],
            "two settles, then two waits between three attempts"
        );
        Ok(())
    }

    /// A bulk `Stall` clears the halt before the retry, or the retry
    /// cannot succeed — the endpoint latches.
    #[test]
    fn rom_stall_clears_the_halt() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(32);
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 32), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(Call::BulkOut { data: data.clone() }, bulk_fail(UsbErrorKind::Stall))
            .expecting(Call::ClearHalt(endpoint::BOOTROM_OUT), Reply::Done)
            .expecting(Call::BulkOut { data: data.clone() }, Reply::Done)
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        let order = calls(&dev);
        let halt = order
            .iter()
            .position(|call| matches!(call, Call::ClearHalt(_)))
            .ok_or("no clear_halt was issued")?;
        let retry = order
            .iter()
            .rposition(|call| matches!(call, Call::BulkOut { .. }))
            .ok_or("no bulk OUT was issued")?;
        assert!(halt < retry, "the halt is cleared before the retry, not after");
        Ok(())
    }

    /// A missed deadline that still reports the full length is success —
    /// the controller completed late, the data is on the bus.
    #[test]
    fn rom_timeout_with_full_length_is_success() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(32);
        let dev = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 32), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(
                Call::BulkOut { data: data.clone() },
                Reply::Fail(
                    UsbError::new(
                        UsbErrorKind::Short { got: 32, want: 32 },
                        Pipe::Bulk(endpoint::BOOTROM_OUT),
                    )
                    .with_transferred(32),
                ),
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        assert!(
            !clock.slept().contains(&CHUNK_RETRY_DELAY),
            "nothing was retried: the chunk is done"
        );
        Ok(())
    }

    /// 10 ms between chunks above 100 KiB, and never after the last one.
    #[test]
    fn rom_inter_chunk_delay_large() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(INTER_CHUNK_DELAY_THRESHOLD + 1);
        let dev = staging(
            MockTransport::new(bootrom()).configured(CONFIGURATION),
            UBOOT_ADDR,
            &data,
        );
        block_on(load_to_memory(
            &dev,
            &clock,
            UBOOT_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        assert_eq!(
            clock.slept().iter().filter(|d| **d == INTER_CHUNK_DELAY).count(),
            1,
            "two chunks, one gap: nothing after the last chunk"
        );

        // Exactly at the threshold, nothing sleeps: `bootstrap.c:164` tests `>`.
        let clock = RecordingClock::new();
        let data = image(INTER_CHUNK_DELAY_THRESHOLD);
        let dev = staging(
            MockTransport::new(bootrom()).configured(CONFIGURATION),
            UBOOT_ADDR,
            &data,
        );
        block_on(load_to_memory(
            &dev,
            &clock,
            UBOOT_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        assert!(
            !clock.slept().contains(&INTER_CHUNK_DELAY),
            "100 KiB exactly is not above 100 KiB"
        );
        Ok(())
    }

    /// The interface is released after the bulk upload — on the success
    /// path *and* on the failure path. On the T20, leaving it claimed makes the
    /// `FLUSH_CACHE` and `PROG_STAGE2` that follow time out.
    #[test]
    fn rom_release_iface_after_bulk() -> TestResult {
        let clock = RecordingClock::new();
        let data = image(64);
        let dev = staging(
            MockTransport::new(bootrom()).configured(CONFIGURATION),
            SPL_LOAD_ADDR,
            &data,
        );
        block_on(load_to_memory(
            &dev,
            &clock,
            SPL_LOAD_ADDR,
            &data,
            &mut crate::progress::sink_ignore(),
        ))?;
        dev.verify()?;
        assert_eq!(
            calls(&dev),
            vec![
                vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000),
                vendor_out(request::SET_DATA_LEN, 0, 64),
                Call::ClaimInterface(INTERFACE),
                Call::BulkOut { data: data.clone() },
                Call::ReleaseInterface(0),
            ],
            "address, length, claim, data, release — in that order"
        );
        assert!(dev.claimed().is_none(), "and nothing stays claimed");

        // The failure path releases too (`bootstrap.c:151`, `:158`).
        let failing = MockTransport::new(bootrom())
            .configured(CONFIGURATION)
            .expecting(vendor_out(request::SET_DATA_ADDR, 0x8000, 0x1000), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 0, 64), Reply::Done)
            .expecting(Call::ClaimInterface(INTERFACE), Reply::Done)
            .expecting(Call::BulkOut { data: data.clone() }, bulk_fail(UsbErrorKind::Fault))
            .expecting(Call::ReleaseInterface(0), Reply::Done);
        assert!(
            block_on(load_to_memory(
                &failing,
                &clock,
                SPL_LOAD_ADDR,
                &data,
                &mut crate::progress::sink_ignore(),
            ))
            .is_err(),
            "a Fault is outside ROM's retry class"
        );
        failing.verify()?;
        assert!(failing.claimed().is_none());
        Ok(())
    }

    /// Nothing is staged for an empty image (`bootstrap.c:27-29`).
    #[test]
    fn an_empty_image_is_refused() -> TestResult {
        let clock = RecordingClock::new();
        let dev = MockTransport::new(bootrom()).configured(CONFIGURATION);
        assert!(matches!(
            block_on(load_to_memory(
                &dev,
                &clock,
                SPL_LOAD_ADDR,
                &[],
                &mut crate::progress::sink_ignore()
            )),
            Err(crate::Error::Invalid(_))
        ));
        assert!(dev.calls().is_empty());
        dev.verify()?;
        Ok(())
    }

    /// The staging address is what says which image this is, so a progress frame
    /// carries a stage byte without the signature carrying a phase.
    #[test]
    fn the_staging_address_names_the_phase() {
        assert_eq!(phase_for(SPL_LOAD_ADDR), Phase::Stage1);
        assert_eq!(phase_for(UBOOT_ADDR), Phase::UBoot);
        assert_eq!(phase_for(0x8020_0000), Phase::Unknown);
        assert_eq!(Phase::Stage1.wire_byte(), 1);
        assert_eq!(Phase::UBoot.wire_byte(), 2);
    }
}
