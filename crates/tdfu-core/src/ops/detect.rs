//! Identify the SoC in the bootrom.

use tdfu_usb::LocalUsbTransport;

use crate::addr::{self, Kseg1};
use crate::bootrom;
use crate::clock::Sleeper;
use crate::detect::{decode, needs_t33_selector};
use crate::error::{Error, Result};
use crate::model::{Detection, SocRegs};

/// Every register is one 32-bit word.
const WORD: usize = 4;

/// A register this operation reads, so a failure can say **which** one failed.
///
/// An earlier implementation could not: a read error carried the endpoint and nothing
/// about the register, so `subsoctype1` timing out and `soc_id` timing out read
/// identically. Even
/// the C logs the address (`protocol.c:157`, `"Memory read failed at 0x%08X"`), and it
/// is the one thing that tells an operator whether the bootrom is unreachable or one
/// particular eFuse window is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Register {
    /// `soc_id`, the family.
    SocId,
    /// `subsoctype1`, the XBurst1 grade.
    SubSocType1,
    /// `subsoctype2`, the T40/T41 and A1 grade.
    SubSocType2,
    /// The T33 selector, read only for a T33.
    T33Selector,
}

impl Register {
    /// The name `--diag` prints for it.
    const fn name(self) -> &'static str {
        match self {
            Self::SocId => "soc_id",
            Self::SubSocType1 => "subsoctype1",
            Self::SubSocType2 => "subsoctype2",
            Self::T33Selector => "the T33 selector",
        }
    }

    /// Its kseg1 address. Never the physical form — that wedges the bootrom's USB
    /// handler until the power relay cycles, and [`Kseg1`] is why it
    /// cannot be written here at all.
    const fn addr(self) -> Kseg1 {
        match self {
            Self::SocId => addr::SOC_ID,
            Self::SubSocType1 => addr::SUBSOCTYPE1,
            Self::SubSocType2 => addr::SUBSOCTYPE2,
            Self::T33Selector => addr::T33_SELECTOR,
        }
    }
}

/// Read the registers and decode them.
///
/// Three [`bootrom::read_memory`](crate::bootrom::read_memory) calls at
/// [`addr::SOC_ID`](crate::addr::SOC_ID),
/// [`addr::SUBSOCTYPE1`](crate::addr::SUBSOCTYPE1) and
/// [`addr::SUBSOCTYPE2`](crate::addr::SUBSOCTYPE2), then a fourth at
/// [`addr::T33_SELECTOR`](crate::addr::T33_SELECTOR) **only** when
/// [`detect::needs_t33_selector`](crate::detect::needs_t33_selector) says so, then
/// [`detect::decode`](crate::detect::decode).
///
/// That fourth read is what makes a T33 in the bootrom auto-bootstrappable. An earlier
/// implementation read three registers, had nowhere to put a fourth, and could only
/// answer `Ambiguous` with seven candidates — for a family whose seven grades all share
/// the one `t33` loader. It costs one read on one family.
///
/// **Nothing is uploaded and nothing is executed.**
/// No stub, no `PROG_STAGE1`, no T10 exception, no per-bootrom bypass address —
/// and the bootrom is left pristine, so a real `-b` on the same unit still works. This
/// is the single biggest improvement over the C and it must survive
/// unchanged. Bench-proven on twelve devices across every mask-ROM
/// generation; results in `crates/tdfu-core/tests/fixtures/results/`.
///
/// The interface is claimed here and released on **every** path, success or failure:
/// [`bootrom::read_memory`](crate::bootrom::read_memory) claims nothing itself, matching
/// the C (`protocol.c:141-162`), and leaving a bootrom interface claimed makes the next
/// operation on the device time out.
///
/// The caller must surface [`Detection::warning`] with the answer and log the rest of
/// [`Detection::caveat`] at debug. The sentence `warning` holds back, "documented but
/// has never been seen on the bench", describes the table's provenance and not this
/// device, and printing it beside a detection that is about to flash correctly is the
/// output a T31ZX run showed to be noise.
///
/// # Errors
/// [`Error::UsbWhile`](crate::Error::UsbWhile) if a register read fails — naming the
/// register and its address, with the transport's own error as the source — or
/// [`Error::Protocol`](crate::Error::Protocol) if `soc_id` reads back 0 or a read comes
/// back the wrong length. Anything [`bootrom::claim`](crate::bootrom::claim) or
/// [`bootrom::release`](crate::bootrom::release) raises, unchanged.
///
/// A failed read keeps its [`UsbErrorKind`](tdfu_usb::UsbErrorKind) and therefore its
/// recoverability class. The earlier form wrapped it in `Protocol` on the grounds that
/// *which register* was the more useful half and nothing retries detection — both true,
/// and both beside the point: `Protocol` is unconditionally recoverable, so the wrapping
/// turned an [`AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied) into a retryable
/// error and inverted the reasoning `Error::is_recoverable` spells out three
/// lines below its own signature.
pub async fn detect<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<Detection> {
    bootrom::claim(dev).await?;
    let outcome = read_and_decode(dev, clock).await;
    let released = bootrom::release(dev).await;

    // The read's failure is the interesting one; a release that also failed after it
    // tells the operator nothing they can act on.
    match outcome {
        Ok(detection) => released.map(|()| detection),
        Err(error) => Err(error),
    }
}

/// The reads themselves, with the claim already in force.
async fn read_and_decode<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<Detection> {
    let soc_id = read_register(dev, clock, Register::SocId).await?;
    if soc_id == 0 {
        return Err(soc_id_read_back_zero());
    }

    let subsoctype1 = read_register(dev, clock, Register::SubSocType1).await?;
    let subsoctype2 = read_register(dev, clock, Register::SubSocType2).await?;
    let mut regs = SocRegs::new(soc_id, subsoctype1, subsoctype2);

    if needs_t33_selector(regs) {
        let selector = read_register(dev, clock, Register::T33Selector).await?;
        regs = regs.with_t33_selector(selector);
    }

    Ok(decode(regs))
}

/// One 32-bit register, little-endian.
///
/// The standalone probe that produced every capture in
/// `crates/tdfu-core/tests/fixtures/results/` read the register this way, little-endian.
async fn read_register<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, register: Register) -> Result<u32> {
    let bytes = bootrom::read_memory(dev, clock, register.addr(), WORD)
        .await
        .map_err(|error| read_failed(register, error))?;

    let word: [u8; WORD] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| short_read(register, bytes.len()))?;
    Ok(u32::from_le_bytes(word))
}

/// The error a failed register read produces: **which** register, at what address, and
/// the transport's own account of the failure.
///
/// [`Error::UsbWhile`] and not [`Error::Protocol`]: the two read alike, but `Protocol`
/// is unconditionally recoverable, so wrapping a transport failure in
/// it **flips the class** — an [`AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied)
/// read failure came back out retryable, inverting the very reasoning
/// [`Error::is_recoverable`] spells out three lines below its own signature. A read that
/// failed for a reason the transport already classified keeps that class;
/// a read that came back the *wrong shape* is genuinely a protocol
/// failure and stays [`Error::Protocol`] — see [`short_read`].
fn read_failed(register: Register, source: Error) -> Error {
    let doing = format!("reading {} at {}", register.name(), register.addr());
    match source {
        Error::Usb(usb) => Error::UsbWhile { doing, source: usb },
        // `read_memory` can also fail its own way; those already carry their class and
        // only need the context, so the wrap must not change it either. The only
        // non-`Usb` failure it produces is `Error::Invalid`, a zero or unrepresentable
        // length, which is **not** recoverable: laundering it through `Protocol` would
        // make it so, which is the flip this function exists to avoid.
        other => Error::Invalid(format!("{doing}: {other}")),
    }
}

/// `soc_id` came back as zero.
///
/// `protocol.c:623-626` refuses the same way, logging `"SoC ID register returned 0"`. A
/// zero is not a chip: either the bootrom answered without reading, or this is not a
/// bootrom — so the message names the register and its address rather than leaving the
/// operator to guess which of the three reads was the empty one.
fn soc_id_read_back_zero() -> Error {
    Error::Protocol(format!(
        "{} at {} read back 0; the device is not answering as a bootrom",
        Register::SocId.name(),
        Register::SocId.addr()
    ))
}

/// A read that returned the wrong number of bytes.
///
/// `read_memory` returns exactly what was asked for or fails,
/// so this is a backend that broke its contract rather than a device fault — and saying
/// so is cheaper than the alternative, which is a silent `from_le_bytes` on whatever
/// arrived.
fn short_read(register: Register, got: usize) -> Error {
    Error::Protocol(format!(
        "reading {} at {} returned {got} bytes, not {WORD}",
        register.name(),
        register.addr()
    ))
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{
        ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind, endpoint,
        pid, vid,
    };

    use super::{Register, WORD, detect, read_failed, short_read, soc_id_read_back_zero};
    use crate::addr::{self, is_kseg1};
    use crate::clock::RecordingClock;
    use crate::error::Error;
    use crate::model::{Detection, Variant};

    // -----------------------------------------------------------------
    // What a failure says. These need no device and no `bootrom` body.
    // -----------------------------------------------------------------

    /// A failed read names the register **and** its address, and keeps the transport's
    /// own account of what went wrong.
    ///
    /// An earlier implementation could not do this: a read error carried the endpoint and nothing
    /// about the register, so a `soc_id` timeout and a `subsoctype1` timeout were the
    /// same message. Even the C logs the address (`protocol.c:157`). The distinction
    /// matters because a failure on the first read means the bootrom is unreachable,
    /// while a failure on the third means one eFuse window is.
    #[test]
    fn det_a_failed_read_names_its_register() {
        let usb = UsbError::new(UsbErrorKind::Timeout, Pipe::Bulk(endpoint::BOOTROM_IN))
            .with_len(WORD)
            .with_timeout(Duration::from_secs(2))
            .with_transferred(0);
        let transport_text = usb.to_string();

        let cases = [
            (Register::SocId, "soc_id", "0xB300002C"),
            (Register::SubSocType1, "subsoctype1", "0xB3540238"),
            (Register::SubSocType2, "subsoctype2", "0xB3540250"),
            (Register::T33Selector, "the T33 selector", "0xB354021C"),
        ];

        let mut messages = Vec::new();
        for (register, name, address) in cases {
            let message = read_failed(register, Error::Usb(usb.clone())).to_string();
            assert!(message.contains(name), "{message:?} does not name {name}");
            assert!(message.contains(address), "{message:?} does not give {address}");
            assert!(
                message.ends_with(&transport_text),
                "{message:?} dropped the transport's own account"
            );
            messages.push(message);
        }

        // And the four are distinguishable, which is the whole point.
        let distinct: std::collections::BTreeSet<&String> = messages.iter().collect();
        assert_eq!(distinct.len(), messages.len(), "two registers produce the same message");
    }

    /// A read failure keeps the transport's recoverability
    /// class. Wrapping it in [`Error::Protocol`] flipped it — `Protocol` is
    /// unconditionally recoverable, so an `AccessDenied` came back out retryable and
    /// the "install a udev rule" advice was buried under a silent reset-retry.
    #[test]
    fn det_a_failed_read_keeps_the_transports_recoverability() {
        for (kind, recoverable) in [
            (UsbErrorKind::AccessDenied, false),
            (UsbErrorKind::NotClaimed, false),
            (UsbErrorKind::Timeout, true),
            (UsbErrorKind::NoDevice, true),
        ] {
            let usb = UsbError::new(kind.clone(), Pipe::Bulk(endpoint::BOOTROM_IN));
            let wrapped = read_failed(Register::SocId, Error::Usb(usb.clone()));
            assert_eq!(
                wrapped.is_recoverable(),
                recoverable,
                "{kind:?} changed class on the way through read_failed"
            );
            assert_eq!(
                wrapped.is_recoverable(),
                Error::Usb(usb).is_recoverable(),
                "{kind:?} must class exactly as the bare transport failure does"
            );
        }

        // A read that came back the wrong *shape* is a protocol failure in its own
        // right, and stays one.
        assert!(short_read(Register::SocId, 2).is_recoverable());
    }

    /// The exact wording, pinned once, so it is a fixed thing rather than whatever the
    /// formatter happens to produce.
    #[test]
    fn det_read_failure_wording_is_pinned() {
        assert_eq!(
            read_failed(
                Register::SubSocType2,
                Error::Usb(UsbError::new(UsbErrorKind::Stall, Pipe::Bulk(endpoint::BOOTROM_IN)))
            )
            .to_string(),
            "reading subsoctype2 at 0xB3540250: endpoint stalled: bulk IN on endpoint 0x81"
        );
        // A non-transport failure from `read_memory` keeps its own class and its own
        // words, and gains the context.
        assert_eq!(
            read_failed(Register::SubSocType2, Error::Invalid("length 0".to_owned())).to_string(),
            "invalid input: reading subsoctype2 at 0xB3540250: invalid input: length 0"
        );
        assert_eq!(
            short_read(Register::SocId, 2).to_string(),
            "protocol: reading soc_id at 0xB300002C returned 2 bytes, not 4"
        );
        assert_eq!(
            soc_id_read_back_zero().to_string(),
            "protocol: soc_id at 0xB300002C read back 0; the device is not answering as a bootrom"
        );
    }

    /// Every address this operation issues is a kseg1 alias, and it is the
    /// one the register table names.
    ///
    /// [`Kseg1`](crate::addr::Kseg1) already makes a physical address unconstructible,
    /// so what is left to get wrong is *which* constant each register uses — a swap of
    /// `SUBSOCTYPE1` and `SUBSOCTYPE2` would decode a T4x grade off the XBurst1 register
    /// and be silent about it.
    #[test]
    fn det_addresses_are_kseg1() {
        let expected = [
            (Register::SocId, addr::SOC_ID, 0xB300_002C_u32),
            (Register::SubSocType1, addr::SUBSOCTYPE1, 0xB354_0238),
            (Register::SubSocType2, addr::SUBSOCTYPE2, 0xB354_0250),
            (Register::T33Selector, addr::T33_SELECTOR, 0xB354_021C),
        ];
        for (register, constant, raw) in expected {
            assert_eq!(register.addr(), constant, "{register:?} uses the wrong constant");
            assert_eq!(register.addr().get(), raw, "{register:?}");
            assert!(is_kseg1(register.addr().get()), "{register:?} is not kseg1");
        }
    }

    // -----------------------------------------------------------------
    // The wire. These drive `bootrom::read_memory`.
    // -----------------------------------------------------------------

    /// A bootrom as the mock sees it: the product string really does have
    /// a junk prefix, and is never compared for equality.
    fn bootrom_descriptors() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("\u{c3}\t USB Boot Device")
    }

    /// What `bootrom::claim` declares. Built here rather than taken from
    /// `bootrom::INTERFACE` so this file compiles before that constant exists.
    fn bootrom_interface() -> InterfaceSpec {
        InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT)
    }

    /// [`WORD`] as the 32-bit length `SET_DATA_LEN` carries; 4 fits by inspection.
    fn word_len() -> u32 {
        u32::try_from(WORD).unwrap_or_default()
    }

    /// A 32-bit value is split across `wValue` (the high half) and `wIndex`
    /// (the low half). Both halves fit a `u16` by construction.
    fn halves(value: u32) -> (u16, u16) {
        (
            u16::try_from(value >> 16).unwrap_or_default(),
            u16::try_from(value & 0xFFFF).unwrap_or_default(),
        )
    }

    /// The two vendor requests and the bulk IN that one register read is:
    /// `SET_DATA_ADDR`, then `SET_DATA_LEN`, then the transfer —
    /// `protocol.c:146-155`, in that order.
    fn one_register_read(mock: MockTransport, address: u32, word: u32) -> MockTransport {
        let addr_request = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: crate::bootrom::request::SET_DATA_ADDR,
            value: halves(address).0,
            index: halves(address).1,
            data: &[],
        };
        let len_request = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: crate::bootrom::request::SET_DATA_LEN,
            value: halves(word_len()).0,
            index: halves(word_len()).1,
            data: &[],
        };
        mock.expecting(Call::control_out(addr_request), Reply::Done)
            .expecting(Call::control_out(len_request), Reply::Done)
            .expecting(Call::BulkIn { len: WORD }, Reply::Data(word.to_le_bytes().to_vec()))
    }

    /// **The pin.** Three reads, in order, and a `Detection` from them —
    /// with nothing uploaded and nothing executed.
    ///
    /// The registers are the T41NQ capture in `crates/tdfu-core/tests/fixtures/results/result-t41nq.txt`,
    /// verbatim.
    #[test]
    fn det_registers_via_read_memory() -> Result<(), tdfu_usb::mock::MockError> {
        let mut mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        mock = one_register_read(mock, addr::SOC_ID.get(), 0x1004_0003);
        mock = one_register_read(mock, addr::SUBSOCTYPE1.get(), 0x0000_0000);
        mock = one_register_read(mock, addr::SUBSOCTYPE2.get(), 0xAAAA_2222);
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let detection = block_on(detect(&mock, &clock))
            .map_err(|error| tdfu_usb::mock::MockError::Script(format!("detect failed: {error}")))?;

        assert_eq!(detection.variant(), Some(Variant::T41nq));
        assert!(matches!(detection, Detection::Resolved(_)));
        mock.verify()
    }

    /// `soc_id` reading back 0 stops the sequence dead.
    ///
    /// `libtdfu/src/usb/protocol.c:623-626` refuses the same way. Neutering the guard
    /// passed the whole suite before this existed — nothing drove `detect()` with a zero
    /// first read, so the two reads that must *not* follow it were never counted, and
    /// `decode(SocRegs::new(0, 0, 0))` answers `Unknown` rather than failing, which
    /// looks close enough to be missed.
    #[test]
    fn det_a_zero_soc_id_stops_before_the_second_read() -> Result<(), tdfu_usb::mock::MockError> {
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        let mock = one_register_read(mock, addr::SOC_ID.get(), 0);
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let Err(error) = block_on(detect(&mock, &clock)) else {
            return Err(tdfu_usb::mock::MockError::Script(
                "a zero soc_id must fail detection".to_owned(),
            ));
        };

        // The exact wording, so the message names the register and its address rather
        // than leaving an operator to guess which of the reads was the empty one.
        assert_eq!(error.to_string(), soc_id_read_back_zero().to_string());
        assert_eq!(
            error.to_string(),
            "protocol: soc_id at 0xB300002C read back 0; the device is not answering as a bootrom"
        );

        // And reads two and three never happen. `verify()` alone would not say so: an
        // extra read would fail as `Unexpected`, but a *missing* guard that still
        // stopped early for some other reason would look identical, so the count is
        // asserted directly.
        let reads = mock
            .calls()
            .iter()
            .filter(|recorded| matches!(recorded.call, Call::BulkIn { .. }))
            .count();
        assert_eq!(reads, 1, "the sequence must stop after the first read");
        let addresses = mock
            .calls()
            .iter()
            .filter(|recorded| {
                matches!(&recorded.call, Call::ControlOut { request, .. }
                    if *request == crate::bootrom::request::SET_DATA_ADDR)
            })
            .count();
        assert_eq!(addresses, 1, "no address was set for subsoctype1 or subsoctype2");

        // The interface is still released on the failure path.
        assert!(
            mock.calls()
                .iter()
                .any(|recorded| recorded.call == Call::ReleaseInterface(0)),
            "the claim must be released even when detection fails"
        );
        mock.verify()
    }

    /// **Detection executes nothing on the device.**
    ///
    /// The mask ROM's `PROG_STAGE1` is one shot per power cycle; spending it on an
    /// identification stub is what left a T10 with a dead boot, and not spending it is
    /// the single biggest improvement over the C. This asserts it
    /// from the recorded traffic rather than from a comment.
    #[test]
    fn det_executes_nothing_on_the_device() -> Result<(), tdfu_usb::mock::MockError> {
        let mut mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        mock = one_register_read(mock, addr::SOC_ID.get(), 0x1003_2004);
        mock = one_register_read(mock, addr::SUBSOCTYPE1.get(), 0x9999_1111);
        mock = one_register_read(mock, addr::SUBSOCTYPE2.get(), 0x0000_0000);
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let detection = block_on(detect(&mock, &clock))
            .map_err(|error| tdfu_usb::mock::MockError::Script(format!("detect failed: {error}")))?;
        assert_eq!(detection.variant(), Some(Variant::T32lq));

        for recorded in mock.calls() {
            if let Call::ControlOut { request, .. } = recorded.call {
                assert_ne!(
                    request,
                    crate::bootrom::request::PROG_STAGE1,
                    "detection fired the one-shot PROG_STAGE1"
                );
                assert_ne!(request, crate::bootrom::request::PROG_STAGE2, "detection ran stage 2");
            }
            assert!(
                !matches!(recorded.call, Call::BulkOut { .. }),
                "detection uploaded something to the device"
            );
        }
        mock.verify()
    }

    /// The fourth read happens for a T33 and for nothing else.
    ///
    /// This plus `decode`'s never-`Ambiguous` answer is what makes a T33 in the bootrom
    /// auto-bootstrappable.
    #[test]
    fn det_reads_the_t33_selector_only_for_a_t33() -> Result<(), tdfu_usb::mock::MockError> {
        let mut mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        mock = one_register_read(mock, addr::SOC_ID.get(), 0x0003_3000);
        mock = one_register_read(mock, addr::SUBSOCTYPE1.get(), 0);
        mock = one_register_read(mock, addr::SUBSOCTYPE2.get(), 0);
        // The fourth: byte 3 of the word at 0xB354021C. 0xAA is a T33N.
        mock = one_register_read(mock, addr::T33_SELECTOR.get(), 0xAA00_0000);
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let detection = block_on(detect(&mock, &clock))
            .map_err(|error| tdfu_usb::mock::MockError::Script(format!("detect failed: {error}")))?;

        assert_eq!(detection.variant(), Some(Variant::T33));
        assert_eq!(detection.regs().t33_grade(), Some(0xAA));
        mock.verify()?;

        // A T31 script that offered no fourth read must still be consumed exactly.
        let mut other = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        other = one_register_read(other, addr::SOC_ID.get(), 0x1003_1003);
        other = one_register_read(other, addr::SUBSOCTYPE1.get(), 0x2222_1111);
        other = one_register_read(other, addr::SUBSOCTYPE2.get(), 0);
        let other = other.expecting(Call::ReleaseInterface(0), Reply::Done);

        block_on(detect(&other, &clock))
            .map_err(|error| tdfu_usb::mock::MockError::Script(format!("detect failed: {error}")))?;
        assert_eq!(other.remaining(), 0, "a fourth read was issued for a T31");
        other.verify()
    }

    /// The interface is released even when a read fails.
    ///
    /// Leaving a bootrom interface claimed makes the next operation on the device time
    /// out, so the release has to survive the error path — this is the path where a
    /// forgotten release costs a power cycle rather than a retry.
    #[test]
    fn det_releases_the_interface_after_a_failed_read() -> Result<(), tdfu_usb::mock::MockError> {
        let addr_request = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: crate::bootrom::request::SET_DATA_ADDR,
            value: halves(addr::SOC_ID.get()).0,
            index: halves(addr::SOC_ID.get()).1,
            data: &[],
        };
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done)
            .expecting(
                Call::control_out(addr_request),
                // Fault is outside the vendor-retry class, so the failure
                // propagates on the first attempt; the retry ladder itself is pinned
                // by `rom_vendor_retry_backoff`.
                Reply::Fail(UsbError::new(
                    UsbErrorKind::Fault,
                    Pipe::Control {
                        direction: tdfu_usb::Direction::Out,
                        request: crate::bootrom::request::SET_DATA_ADDR,
                    },
                )),
            )
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let error = block_on(detect(&mock, &clock))
            .err()
            .ok_or_else(|| tdfu_usb::mock::MockError::Script("a dead device detected fine".to_owned()))?;
        assert!(
            error.to_string().contains("soc_id"),
            "{error} does not name the register"
        );
        assert_eq!(mock.remaining(), 0, "the interface was not released");
        mock.verify()
    }

    /// A read failure that was not the transport's keeps its recoverability class.
    ///
    /// The only non-`Usb` failure `read_memory` produces is `Error::Invalid`, which is
    /// not recoverable; `Error::Protocol` is, so a fallback arm that wrapped in it hands
    /// a caller a retry for an argument no retry can fix, which is the flip
    /// [`read_failed`] exists to prevent.
    #[test]
    fn det_a_non_transport_read_failure_keeps_its_class() {
        let wrapped = read_failed(Register::SocId, Error::Invalid("length 0".to_owned()));

        assert!(!wrapped.is_recoverable(), "{wrapped}");
        assert!(matches!(wrapped, Error::Invalid(_)), "{wrapped:?}");
        assert!(
            wrapped.to_string().contains("soc_id"),
            "the context survived the wrap: {wrapped}"
        );
    }
}
