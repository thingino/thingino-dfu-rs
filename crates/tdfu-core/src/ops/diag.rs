//! Read the eFuse shadow window.

use tdfu_usb::LocalUsbTransport;

use crate::addr::{self, EFUSE_OFFSET_SUBSOCTYPE1, EFUSE_OFFSET_SUBSOCTYPE2, EFUSE_WINDOW_LEN, Kseg1};
use crate::bootrom;
use crate::clock::Sleeper;
use crate::detect::{decode, needs_t33_selector};
use crate::dfu::descriptors::classify;
use crate::error::{Error, Result};
use crate::model::diag::EFUSE_OFFSET_T33_SELECTOR;
use crate::model::{Diag, SocRegs, Stage};

/// `soc_id` is one 32-bit word.
const WORD: usize = 4;

/// What this operation reads, so a failure can say **which** read failed.
///
/// The same reasoning as [`ops::detect`](crate::ops::detect)'s `Register`: an earlier
/// implementation's read errors carried the endpoint and nothing about the target, so a `soc_id` timeout
/// and a window timeout read identically. The C logs the address
/// (`protocol.c:157`, `"Memory read failed at 0x%08X"`), and here the distinction says
/// whether the bootrom is unreachable or one particular window is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// `soc_id`, which decides the eFuse layout.
    SocId,
    /// The 256-byte eFuse shadow window.
    Window,
}

impl Target {
    /// What the operator knows it by.
    const fn name(self) -> &'static str {
        match self {
            Self::SocId => "soc_id",
            Self::Window => "the eFuse window",
        }
    }

    /// Its kseg1 address. The physical form wedges the bootrom's USB handler until the
    /// power relay cycles, and [`Kseg1`] is why it cannot be written here.
    const fn addr(self) -> Kseg1 {
        match self {
            Self::SocId => addr::SOC_ID,
            Self::Window => addr::EFUSE_WINDOW,
        }
    }

    /// How many bytes it is.
    const fn len(self) -> usize {
        match self {
            Self::SocId => WORD,
            Self::Window => EFUSE_WINDOW_LEN,
        }
    }
}

/// Read the eFuse window and `soc_id` from a device in the bootrom.
///
/// **Two reads and zero code execution** (pin `op_diag_no_execution`): the C runs its
/// detect stub here for the precise variant (`diag.c:140-146`), spending the mask ROM's
/// one-shot `PROG_STAGE1` on it, and here there is nothing to run — the
/// [256-byte window](crate::addr::EFUSE_WINDOW_LEN) already contains `subsoctype1` at
/// `+0x38`, `subsoctype2` at `+0x50` and the T33 grade selector at `+0x1C`, so the
/// decode falls out of bytes that are already in hand. So `--diag`, like
/// [`ops::detect`](crate::ops::detect), leaves the bootrom pristine: a real `-b` on the
/// same unit afterwards still brings up the DFU gadget.
///
/// The C's old comment claiming "a stub clears the shadow" (`diag.c:8-9`) was corrected
/// in the bench record: the shadow is stable and re-readable; it is a *stub's own CPU
/// loads* of the eFuse region that read zeros. Moot without a stub.
///
/// The bootrom's CPU-info string is read first and is **best-effort**, as it is in the C
/// (`diag.c:103`, which ignores the result): it is a hint and nothing more,
/// and failing a whole read-only diagnostic because a hint did not answer would be
/// worse than printing the report without it.
///
/// # Deliberate differences from the C
///
/// * **A failed `soc_id` read is fatal here.** `diag.c:124-125` only assigns on success,
///   so a device whose `soc_id` read failed produced a report claiming `id 0x00000000`,
///   an unknown family and — via `diag.c:246` — that the chip has *no secure-boot
///   fuses*. That is a false statement about the silicon derived from a transfer that
///   never happened. Pin
///   `op_diag_a_failed_soc_id_read_is_fatal`.
/// * **A `soc_id` that reads back as zero is reported, not refused.**
///   [`ops::detect`](crate::ops::detect) refuses it (as `protocol.c:623-626` does)
///   because the next thing it does is pick a loader. Diag executes nothing and writes
///   nothing; refusing would throw away the window dump, which is the one artefact that
///   makes such a device diagnosable at all. Pin `op_diag_reports_a_zero_soc_id`.
///
/// The interface is claimed here and released on **every** path, success or failure:
/// [`bootrom::read_memory`] claims nothing itself, matching the C
/// (`protocol.c:141-162`), and leaving a bootrom interface claimed makes the next
/// operation on the device time out.
///
/// # Errors
/// [`Error::Invalid`] **before any traffic** if the device is not in the bootrom — see
/// [`not_a_bootrom`]. [`Error::UsbWhile`] if either read fails — naming the target and
/// its address, with the transport's own error as the source, so the failure keeps its
/// recoverability class. [`Error::Protocol`] if a read comes back the wrong
/// length. Anything [`bootrom::claim`] or [`bootrom::release`] raises, unchanged.
///
/// **A release that fails after both reads landed discards the finished report.** That
/// ordering is the uniform one (`ops`'s own module documentation states it for `write`,
/// `verify` and `erase`), and it costs more here than there: those three have already
/// said what the device did through their sink, while this operation's whole answer is
/// its return value, so a device unplugged between the last bulk IN and the release
/// gives a transport error and no window dump at all.
pub async fn diag<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<Diag> {
    // Nothing on the bus before the stage is checked. Everything below is a *vendor*
    // request, which only the mask ROM answers; sending one to a DFU gadget reaches a
    // device that is very possibly mid-flash, and gets back a stall the report would
    // then have to explain.
    not_a_bootrom(dev)?;

    // Before the claim, exactly as the C does (`diag.c:103` then `:114`); `get_cpu_info`
    // manages its own claim fallback.
    let magic = bootrom::get_cpu_info(dev).await.ok().and_then(clean_magic);

    bootrom::claim(dev).await?;
    let outcome = read_soc_id_and_window(dev, clock).await;
    let released = bootrom::release(dev).await;

    // The read's failure is the interesting one; a release that also failed after it
    // tells the operator nothing they can act on.
    let (soc_id, window) = match outcome {
        Ok(read) => {
            released?;
            read
        }
        Err(error) => return Err(error),
    };

    Ok(assemble(soc_id, window, magic))
}

/// Refuse a device that is not in the bootrom, before anything reaches the bus.
///
/// **The stage gate the C has and this operation did not.** `diag.c:89-93` checks
/// `stage != TDFU_STAGE_BOOTROM` and refuses with `INVALID_PARAMETER`; without it, a
/// `--diag` aimed at a running DFU gadget spent four vendor requests on a device that
/// answers none of them and produced a stall the report could not interpret. Worse than
/// useless: the gadget and the bootrom share `a108:c309`, so "the wrong
/// device" here is the *normal* mistake, and the device on the other end may be halfway
/// through a flash write.
///
/// The stage comes from [`classify`](crate::ops::classify) on the cached descriptors
/// with no traffic, and the same rule `-l` renders, and `None` is refused
/// with the rest: an empty configuration descriptor is a device this tool cannot place,
/// and the honest answer to "is this a bootrom?" is then "unknown", which is not yes.
///
/// # Errors
/// [`Error::Invalid`] naming what the device is and what to do about it. One sentence,
/// as the C's is, because the operator's next action is the whole content of it.
fn not_a_bootrom<T: LocalUsbTransport>(dev: &T) -> Result<()> {
    match classify(dev.descriptors()) {
        Some(Stage::Bootrom) => Ok(()),
        other => Err(Error::Invalid(format!(
            "--diag reads the eFuse shadow through the mask ROM, and this device is {}; \
             power-cycle it into the bootrom (hold the boot pin) and run --diag again",
            other.map_or_else(
                || "not one this tool can place: its configuration descriptor came back empty".to_owned(),
                |stage| format!("a {stage}, which answers no vendor requests")
            )
        ))),
    }
}

/// The two reads, with the claim already in force.
///
/// `soc_id` first and the window second, as `diag.c:124` and `:127` do. The order is not
/// load-bearing, but keeping it means a wire capture of this operation and of the C's
/// line up request for request.
async fn read_soc_id_and_window<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<(u32, Vec<u8>)> {
    let soc_id = read(dev, clock, Target::SocId).await?;
    let word: [u8; WORD] = soc_id
        .as_slice()
        .try_into()
        .map_err(|_| short_read(Target::SocId, soc_id.len()))?;

    let window = read(dev, clock, Target::Window).await?;
    if window.len() != EFUSE_WINDOW_LEN {
        return Err(short_read(Target::Window, window.len()));
    }
    Ok((u32::from_le_bytes(word), window))
}

/// One read, with the target's name attached to any failure.
async fn read<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C, target: Target) -> Result<Vec<u8>> {
    bootrom::read_memory(dev, clock, target.addr(), target.len())
        .await
        .map_err(|error| read_failed(target, error))
}

/// Turn the two reads into a report.
///
/// Pure, and separately testable: given a window, this is the whole eFuse
/// decode. The registers `ops::detect` reads one at a time come out of the window here,
/// which is the substance of the zero-execution claim — `model::diag`'s compile-time
/// assertions pin that these offsets *are* those registers' addresses.
fn assemble(soc_id: u32, window: Vec<u8>, magic: Option<String>) -> Diag {
    let mut regs = SocRegs::new(
        soc_id,
        le32(&window, EFUSE_OFFSET_SUBSOCTYPE1),
        le32(&window, EFUSE_OFFSET_SUBSOCTYPE2),
    );

    // The fourth read, for free: the T33 selector is at `+0x1C`, inside the
    // window that has already been read. `ops::detect` spends a transfer on it; diag
    // spends nothing. The condition is `needs_t33_selector` and not "always", so the
    // field keeps its one meaning everywhere — present only for a T33.
    if needs_t33_selector(regs) {
        regs = regs.with_t33_selector(le32(&window, EFUSE_OFFSET_T33_SELECTOR));
    }

    let detection = decode(regs);
    Diag::new(regs, window, magic, detection)
}

/// A little-endian word out of the window, or zero when it does not fit.
///
/// Zero, not a failure: [`read_soc_id_and_window`] has already checked the window's
/// length, so a short slice here can only mean a caller built a `Diag` by hand, and a
/// report that prints `0x00000000` for a register it could not find is better than one
/// that refuses to print at all.
fn le32(window: &[u8], offset: usize) -> u32 {
    offset
        .checked_add(4)
        .and_then(|end| window.get(offset..end))
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map_or(0, u32::from_le_bytes)
}

/// The bootrom's identity string, reduced to printable non-space ASCII.
///
/// The C applies the same filter twice — `device.c:80-88` keeps `0x20..=0x7E`, then
/// `diag.c:105-110` keeps `c > ' ' && c < 0x7F` of that — so the net rule is
/// `0x21..=0x7E`, in one pass here. `None` for a string with nothing printable in it,
/// which is the case `diag.c:208` handles by leaving the clause out.
fn clean_magic(raw: [u8; 8]) -> Option<String> {
    let cleaned: String = raw
        .iter()
        .filter(|byte| (0x21..=0x7E).contains(*byte))
        .map(|byte| char::from(*byte))
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The error a failed read produces: **which** read, at what address, and the
/// transport's own account of the failure.
///
/// [`Error::UsbWhile`] and not [`Error::Protocol`]: the two read alike, but `Protocol`
/// is unconditionally recoverable, so wrapping a transport failure in
/// it **flips the class** — an [`AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied)
/// would come back out retryable. A read that came back the
/// *wrong shape* is genuinely a protocol failure and stays [`Error::Protocol`] — see
/// [`short_read`].
///
/// **The fallback arm obeys the same rule.** It used to wrap in `Error::Protocol`, which
/// is precisely the flip this function exists to avoid, one arm further down: the only
/// non-`Usb` failure [`bootrom::read_memory`] produces is
/// [`Error::Invalid`](crate::Error::Invalid) — a zero or unrepresentable length
/// (`bootrom/transfer.rs`, `protocol.c:142`) — which is **not** recoverable, and
/// laundering it through `Protocol` made it so. `Invalid` keeps the class and carries the
/// context, and an argument a caller cannot fix by trying again is exactly what it names.
fn read_failed(target: Target, source: Error) -> Error {
    let doing = format!("reading {} at {}", target.name(), target.addr());
    match source {
        Error::Usb(usb) => Error::UsbWhile { doing, source: usb },
        // `read_memory` can also fail its own way; those already carry their class and
        // only need the context — so the wrap must not change it either.
        other => Error::Invalid(format!("{doing}: {other}")),
    }
}

/// A read that returned the wrong number of bytes.
///
/// `read_memory` returns exactly what was asked for or fails,
/// so this is a backend that broke its contract — and saying so is cheaper than decoding
/// the eFuse offsets out of whatever arrived.
fn short_read(target: Target, got: usize) -> Error {
    Error::Protocol(format!(
        "reading {} at {} returned {got} bytes, not {}",
        target.name(),
        target.addr(),
        target.len()
    ))
}

#[cfg(test)]
mod tests {
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{
        ControlIn, ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind,
        endpoint, pid, vid,
    };

    use super::{Target, WORD, assemble, clean_magic, diag, read_failed, short_read};
    use crate::addr::{self, EFUSE_WINDOW_LEN, is_kseg1};
    use crate::bootrom::request;
    use crate::clock::RecordingClock;
    use crate::error::Error;
    use crate::model::diag::{EfuseLayout, SecureBoot};
    use crate::model::{Detection, Diag, Variant};

    /// Anything a test here can fail with.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // -----------------------------------------------------------------
    // The three real bench captures, as fixtures.
    //
    // These are `crates/tdfu-core/tests/fixtures/results/diag-*.txt`, produced on the
    // bench on 2026-08-22 — one per eFuse layout family, which is the whole of the
    // decode. An earlier implementation had no real window dump at all and its diag
    // fixtures were synthetic.
    //
    // `include_str!`, not a path read: a moved or renamed capture must fail the build,
    // not skip the test: a self-skipping check is indistinguishable from a passing one
    // at a terminal.
    // -----------------------------------------------------------------

    /// T20X (Wyze V2) — XBurst1 legacy: a serial and no secure-boot fuses.
    const CAPTURE_T20X: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/diag-t20x.txt");

    /// T32LQ — XBurst1 secure: security word at `+0x10`, key hash at `+0x40`.
    const CAPTURE_T32LQ: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/diag-t32lq.txt");

    /// T40XP — XBurst2: security word at `+0x24`, key hash at `+0x80` OR `+0xC0`.
    const CAPTURE_T40XP: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/diag-t40xp.txt");

    // The register sweeps of the same three bench units, which read each
    // register at its own kseg1 address. They are the independent witness that the one
    // window read replaces those three reads — see
    // `op_diag_window_matches_the_direct_register_reads`.

    /// T20X, register by register.
    const PROBE_T20X: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/result-t20-wyzev2.txt");

    /// T32LQ, register by register.
    const PROBE_T32LQ: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/result-t32lq.txt");

    /// T40XP, register by register.
    const PROBE_T40XP: &str = include_str!("../../../../crates/tdfu-core/tests/fixtures/results/result-t40xp.txt");

    /// What one capture holds: the two reads that produced it, and the C's own rendering
    /// of them.
    #[derive(Debug)]
    struct Capture {
        soc_id: u32,
        magic: Option<String>,
        window: Vec<u8>,
        c_text: &'static str,
    }

    /// Recover the inputs from a capture's text.
    ///
    /// The window comes back out of the C's own hex dump, so the fixture bytes are the
    /// bytes that device really answered with — not a transcription.
    fn parse(c_text: &'static str) -> Option<Capture> {
        let soc_id_hex = c_text.split_once(", id 0x")?.1.get(..8)?;
        let soc_id = u32::from_str_radix(soc_id_hex, 16).ok()?;
        let magic = c_text
            .split_once("bootrom \"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(magic, _)| magic.to_owned());

        // Every dump line is `  <8 hex>: <16 hex bytes>`, so the window comes back out
        // of the C's own rendering: the fixture bytes are the bytes that device really
        // answered with, not a transcription of them.
        let mut window = Vec::new();
        for line in c_text.lines() {
            let Some((address, body)) = line.strip_prefix("  ").and_then(|line| line.split_once(':')) else {
                continue;
            };
            if u32::from_str_radix(address, 16).is_err() {
                continue;
            }
            for byte in body.split_whitespace() {
                window.push(u8::from_str_radix(byte, 16).ok()?);
            }
        }
        Some(Capture {
            soc_id,
            magic,
            window,
            c_text,
        })
    }

    /// The three captures, parsed.
    fn captures() -> Option<[Capture; 3]> {
        Some([parse(CAPTURE_T20X)?, parse(CAPTURE_T32LQ)?, parse(CAPTURE_T40XP)?])
    }

    // -----------------------------------------------------------------
    // One fixture window per family.
    // -----------------------------------------------------------------

    /// **The pin.** The three eFuse layouts, decoded from the three real windows.
    ///
    /// The layout comes from `soc_id` and never from the bootrom magic — which is not a
    /// theoretical distinction here: `diag-t32lq.txt` and `diag-t40xp.txt` both report
    /// the magic `T31V`, and they are the XBurst1-secure and the XBurst2 case
    /// respectively. Decoding by magic would read `t40xp`'s security word at `+0x10`
    /// (which is `0x00000000` there) instead of `+0x24`.
    #[test]
    fn op_diag_layouts() -> TestResult {
        let [t20x, t32lq, t40xp] = captures().ok_or("a capture did not parse")?;

        // Every capture is a full 256-byte window, which is what makes them fixtures for
        // the whole decode rather than for its first few offsets.
        for capture in [&t20x, &t32lq, &t40xp] {
            assert_eq!(capture.window.len(), EFUSE_WINDOW_LEN, "{:#010X}", capture.soc_id);
        }

        // XBurst1 legacy: serial only, no secure-boot fuses (`diag.c:34`, `:181-185`).
        let report = assemble(t20x.soc_id, t20x.window.clone(), t20x.magic.clone());
        assert_eq!(report.layout(), EfuseLayout::Xb1Legacy);
        assert_eq!(report.secure_boot(), None);
        assert_eq!(report.detection.variant(), Some(Variant::T20x));
        assert_eq!(report.regs.subsoctype1, 0x2222_0000, "window +0x38 is subsoctype1");
        assert_eq!(report.regs.subsoctype2, 0x0000_0000, "window +0x50 is subsoctype2");
        assert_eq!(report.serial_words(), vec![0, 0, 0, 0]);

        // XBurst1 secure: security word at +0x10, flags = bits 23:16 (`diag.c:157-166`).
        let report = assemble(t32lq.soc_id, t32lq.window.clone(), t32lq.magic.clone());
        assert_eq!(report.layout(), EfuseLayout::Xb1Secure);
        assert_eq!(report.detection.variant(), Some(Variant::T32lq));
        assert_eq!(report.regs.subsoctype1, 0x9999_1111, "window +0x38 is subsoctype1");
        let secure = report.secure_boot().ok_or("the T32LQ has a secure-boot block")?;
        assert_eq!(secure.register, 0x2100_0000);
        assert_eq!(secure.flags, 0x00, "(0x21000000 >> 16) & 0xFF");
        assert!(!secure.enabled());
        assert_eq!(secure.rsa_exponent(), 65537);
        assert_eq!(secure.provisioned_key_hash(), None);
        assert_eq!(
            report.serial_words(),
            vec![1_918_641_430, 2_499_674_753, 303_038_592, 0]
        );

        // XBurst2: security word at +0x24, flags = ((w >> 8) | w) & 0xFF
        // (`diag.c:167-180`).
        let report = assemble(t40xp.soc_id, t40xp.window.clone(), t40xp.magic.clone());
        assert_eq!(report.layout(), EfuseLayout::Xb2);
        assert_eq!(report.detection.variant(), Some(Variant::T40xp));
        assert_eq!(report.regs.subsoctype2, 0x7777_2222, "window +0x50 is subsoctype2");
        let secure = report.secure_boot().ok_or("the T40XP has a secure-boot block")?;
        assert_eq!(secure.register, 0x0101_0000);
        assert_eq!(secure.flags, 0x00, "((0x01010000 >> 8) | 0x01010000) & 0xFF");
        assert!(!secure.enabled());
        assert_eq!(secure.provisioned_key_hash(), None);
        assert_eq!(
            report.serial_words(),
            vec![2_134_257_460, 285_933_568, 37_781_683, 2_134_257_460]
        );

        // And the magic really is generic: two different layouts, one string.
        assert_eq!(t32lq.magic.as_deref(), Some("T31V"));
        assert_eq!(t40xp.magic.as_deref(), Some("T31V"));
        Ok(())
    }

    /// **The zero-execution claim, cross-checked against separate captures.**
    ///
    /// The registers this operation pulls out of its one window are the same values the
    /// bench sweep read *one register at a time* on the same units
    /// (`crates/tdfu-core/tests/fixtures/results/result-*.txt`, which record each read at its own kseg1
    /// address). The probe tool checked this on-device — every one of those files carries
    /// a `window[+0x38] … == subsoctype1 (match)` line — and this redoes it from the
    /// committed bytes, so the claim stops depending on anybody remembering it.
    ///
    /// It is the assertion the whole design rests on: if the window did *not* contain
    /// these three words, diag would need `ops::detect`'s reads, and the C's reason for
    /// running a stub here would come back.
    #[test]
    fn op_diag_window_matches_the_direct_register_reads() -> TestResult {
        /// One register out of a capture: `  soc_id  @0xB300002C = 0x…`.
        fn probed(text: &str, register: &str) -> Option<u32> {
            let line = text.lines().find(|line| line.trim_start().starts_with(register))?;
            u32::from_str_radix(line.split_once("= 0x")?.1.trim(), 16).ok()
        }

        for (diag_text, probe_text) in [
            (CAPTURE_T20X, PROBE_T20X),
            (CAPTURE_T32LQ, PROBE_T32LQ),
            (CAPTURE_T40XP, PROBE_T40XP),
        ] {
            let capture = parse(diag_text).ok_or("a diag capture did not parse")?;
            let report = assemble(capture.soc_id, capture.window, capture.magic);
            for (register, from_window) in [
                ("soc_id", report.regs.soc_id),
                ("subsoctype1", report.regs.subsoctype1),
                ("subsoctype2", report.regs.subsoctype2),
            ] {
                let directly = probed(probe_text, register).ok_or("the probe capture lacks a register")?;
                assert_eq!(
                    from_window, directly,
                    "{register}: the window says {from_window:#010X}, the direct read said {directly:#010X}"
                );
            }
            // Not vacuous: at least one of the two grade words is non-zero on every
            // one of these devices, so a decode that returned zeros would fail here.
            assert!(report.regs.subsoctype1 | report.regs.subsoctype2 != 0);
        }
        Ok(())
    }

    /// Every fact `tdfu_diag_format` prints is in ours (`diag.c:201-259`).
    ///
    /// Functional parity, checked fact by fact rather than asserted in a comment: the
    /// C's own output for these three devices is the committed capture, so each line of
    /// it is a claim our report has to be able to answer. The *format* is ours
    /// rather than the C's, and the four deliberate differences are listed on
    /// `Diag`'s `Display` and pinned by the golden texts below.
    #[test]
    fn op_diag_carries_every_fact_the_c_prints() -> TestResult {
        for capture in captures().ok_or("a capture did not parse")? {
            let ours = assemble(capture.soc_id, capture.window.clone(), capture.magic.clone()).to_string();
            let theirs = capture.c_text;

            // The identity line: the SoC name the C settled on (through a stub), the
            // bootrom magic, and the raw id.
            let their_soc = theirs
                .lines()
                .find_map(|line| line.strip_prefix("SoC:"))
                .ok_or("no SoC line")?;
            let their_name = their_soc.trim_start().split(' ').next().ok_or("no SoC name")?;
            assert!(ours.contains(their_name), "{ours}\nlost the SoC name {their_name}");
            assert!(
                ours.contains(&format!("soc_id {:#010X}", capture.soc_id)),
                "{ours}\nlost the soc_id"
            );
            if let Some(magic) = &capture.magic {
                assert!(ours.contains(&format!("bootrom {magic:?}")), "{ours}\nlost the magic");
            }

            // The serial, both as words and as bytes.
            if let Some(their_serial) = theirs.lines().find_map(|line| line.strip_prefix("Serial/UID:")) {
                let (words, hex) = their_serial.split_once("  (").ok_or("no serial hex")?;
                let hex = hex.trim_end_matches(')');
                assert!(ours.contains(hex), "{ours}\nlost the serial bytes {hex}");
                for word in words.split_whitespace() {
                    assert!(ours.contains(word), "{ours}\nlost the serial word {word}");
                }
            }

            // The secure-boot block: the raw register and every sub-line's value.
            for line in theirs.lines() {
                if let Some(rest) = line.strip_prefix("Secure boot:") {
                    if let Some(register) = rest
                        .split_once("security reg ")
                        .map(|(_, hex)| hex.trim_end_matches(')'))
                    {
                        assert!(ours.contains(register), "{ours}\nlost the security register");
                    }
                } else if let Some((label, value)) = line.strip_prefix("  ").and_then(|line| line.split_once(':')) {
                    // The sub-labels are ours to reword; the *values* are the facts.
                    assert!(
                        ours.contains(label.trim()) && ours.contains(value.trim()),
                        "{ours}\nlost {label}: {value}"
                    );
                }
            }

            // And the dump, line for line, addresses included.
            for line in theirs.lines().filter(|line| line.starts_with("  1354")) {
                assert!(ours.contains(line.trim_end()), "{ours}\nlost the dump line {line}");
            }
        }
        Ok(())
    }

    /// The rendered text, pinned per family.
    ///
    /// Golden strings, so the report is a fixed thing rather than whatever the formatter
    /// happens to produce. Byte-identical output with the C is no longer a goal,
    /// which makes it *ours*, and ours is pinned.
    #[test]
    fn op_diag_text_is_pinned() -> TestResult {
        let [t20x, t32lq, t40xp] = captures().ok_or("a capture did not parse")?;

        let report = assemble(t20x.soc_id, t20x.window.clone(), t20x.magic).to_string();
        let (head, dump) = report.split_once("eFuse window").ok_or("no dump")?;
        assert_eq!(
            head,
            "=== thingino-dfu diagnostics ===\n\
             SoC:          t20x (T20X), bootrom \"T20V\", soc_id 0x12000002\n\
             Grade regs:   subsoctype1 0x22220000 (+0x38), subsoctype2 0x00000000 (+0x50)\n\
             Serial/UID:   0 0 0 0  (00000000000000000000000000000000)\n\
             Secure boot:  not present  (XBurst1 legacy layout: no secure-boot fuses on this SoC family)\n"
        );
        assert!(
            dump.starts_with(" (phys 0x13540200, 256 bytes):\n  13540200: 00 00"),
            "{dump}"
        );

        let report = assemble(t32lq.soc_id, t32lq.window.clone(), t32lq.magic).to_string();
        let (head, dump) = report.split_once("eFuse window").ok_or("no dump")?;
        assert_eq!(
            head,
            "=== thingino-dfu diagnostics ===\n\
             SoC:          t32lq (T32LQ), bootrom \"T31V\", soc_id 0x10032004\n\
             Grade regs:   subsoctype1 0x99991111 (+0x38), subsoctype2 0x00000000 (+0x50)\n\
             Serial/UID:   1918641430 2499674753 303038592 0  (16255c728102fe948000101200000000)\n\
             Secure boot:  disabled  (XBurst1 secure layout, security register 0x21000000 at +0x10)\n  \
             USB boot:        allowed\n  \
             Extra restrict:  none\n  \
             RSA exponent:    e=65537\n  \
             RSA key hash:    (not provisioned)\n"
        );
        assert!(
            dump.starts_with(" (phys 0x13540200, 256 bytes):\n  13540200: 16 25 5c 72"),
            "{dump}"
        );

        let report = assemble(t40xp.soc_id, t40xp.window.clone(), t40xp.magic).to_string();
        let (head, dump) = report.split_once("eFuse window").ok_or("no dump")?;
        assert_eq!(
            head,
            "=== thingino-dfu diagnostics ===\n\
             SoC:          t40xp (T40XP), bootrom \"T31V\", soc_id 0x10040003\n\
             Grade regs:   subsoctype1 0x00000000 (+0x38), subsoctype2 0x77772222 (+0x50)\n\
             Serial/UID:   2134257460 285933568 37781683 2134257460  (342f367f00000b11b3804002342f367f)\n\
             Secure boot:  disabled  (XBurst2 layout, security register 0x01010000 at +0x24)\n  \
             USB boot:        allowed\n  \
             SD/MMC boot:     allowed\n  \
             NOR USB-write:   allowed\n  \
             RSA exponent:    e=65537\n  \
             RSA key hash:    (not provisioned)\n"
        );
        assert!(
            dump.starts_with(" (phys 0x13540200, 256 bytes):\n  13540200: 34 2f 36 7f"),
            "{dump}"
        );

        // The dump ends the report, with no trailing newline: `println!("{diag}")` is
        // the intended call and a wire payload that wants one appends it.
        assert!(report.ends_with(" 00 00 00 00 00 00 00 00"), "{report}");
        assert!(!report.ends_with('\n'));
        Ok(())
    }

    /// The full 256-byte dump is in the report, every line of it.
    ///
    /// This is the fact that makes a pasted report actionable when the decode is wrong
    /// or incomplete, so it is asserted rather than left to the golden prefix above.
    #[test]
    fn op_diag_keeps_the_whole_window_dump() -> TestResult {
        let capture = parse(CAPTURE_T40XP).ok_or("the T40XP capture did not parse")?;
        let report = assemble(capture.soc_id, capture.window, capture.magic).to_string();
        let dumped: Vec<&str> = report.lines().filter(|line| line.starts_with("  1354")).collect();
        assert_eq!(dumped.len(), EFUSE_WINDOW_LEN / 16, "every line of the window");
        assert_eq!(
            dumped.first().copied(),
            Some("  13540200: 34 2f 36 7f 00 00 0b 11 b3 80 40 02 34 2f 36 7f")
        );
        assert_eq!(
            dumped.last().copied(),
            Some("  135402F0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Decodes with no real capture behind them: the flag bits, and the
    // families the bench has not seen.
    // -----------------------------------------------------------------

    /// Every secure-boot flag bit, on a window built to set it.
    ///
    /// All three bench devices have secure boot **off** and no key burned, so every
    /// `if` in the block is otherwise only ever taken one way — the shape
    /// mutation testing exists to catch, where coverage reports a line covered and the
    /// two branches were never distinguished.
    #[test]
    fn op_diag_decodes_every_secure_boot_flag() -> TestResult {
        // A T31 (XBurst1 secure): flags are bits 23:16, so 0xFF there sets all five.
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        window
            .get_mut(0x10..0x14)
            .ok_or("short window")?
            .copy_from_slice(&[0x00, 0x00, 0xFF, 0x00]);
        window.get_mut(0x40..0x60).ok_or("short window")?.fill(0xAB);
        let report = assemble(0x1003_1003, window, None);
        let secure = report.secure_boot().ok_or("a T31 has a secure-boot block")?;
        assert_eq!(secure.flags, 0xFF);
        assert!(secure.enabled() && secure.usb_boot_blocked() && secure.bit4_set());
        assert_eq!(secure.rsa_exponent(), 3);
        assert_eq!(secure.provisioned_key_hash(), Some([0xAB; 32]));

        let text = report.to_string();
        assert!(text.contains("Secure boot:  ENABLED (all boot sources)"), "{text}");
        assert!(text.contains("USB boot:        disabled under secure boot"), "{text}");
        assert!(
            text.contains("Extra restrict:  yes (a boot source blocked under secure boot)"),
            "{text}"
        );
        assert!(text.contains("RSA exponent:    e=3"), "{text}");
        assert!(text.contains(&"ab".repeat(32)), "{text}");
        // Bit 6 is XBurst2's and has no line on XBurst1 (`diag.c:230-235`).
        assert!(!text.contains("NOR USB-write"), "{text}");

        // XBurst2 (a T41): the fold is `((w >> 8) | w) & 0xFF`, so 0x40 in the *second*
        // byte alone reaches bit 6 — the case a plain `& 0xFF` would miss.
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        window
            .get_mut(0x24..0x28)
            .ok_or("short window")?
            .copy_from_slice(&[0x00, 0x40, 0x00, 0x00]);
        let report = assemble(0x1004_0003, window, None);
        let secure = report.secure_boot().ok_or("a T41 has a secure-boot block")?;
        assert_eq!(secure.flags, 0x40, "the backup byte folds down into the flags");
        assert!(secure.nor_usb_write_blocked() && !secure.enabled());
        let text = report.to_string();
        assert!(text.contains("NOR USB-write:   disabled under secure boot"), "{text}");
        assert!(text.contains("SD/MMC boot:     allowed"), "{text}");
        Ok(())
    }

    /// XBurst2's flag fold is an **OR** of the main and backup bytes, not an XOR
    /// (`diag.c:175`).
    ///
    /// Found by `cargo-mutants`: replacing `|` with `^` survived everything else here,
    /// including all three bench captures, because the two operators agree wherever the
    /// bytes are disjoint — and on every device seen so far one of them is zero
    /// (`t40xp`'s security word is `0x01010000`, whose low byte is `0x00`). This is
    /// exactly that shape, and unlike `dfu/host.rs`'s
    /// unkillable pair it is a real hole: the fold's two operands overlap by
    /// construction, so a redundant fuse that agrees with its backup would report **no
    /// flags at all** under XOR — a chip with secure boot on, reported as off.
    #[test]
    fn op_diag_the_xburst2_flag_fold_is_or_not_xor() -> TestResult {
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        // Main byte 0x05 and backup byte 0x05: SC_EN + RSA e=3, burned in both copies.
        // `|` keeps 0x05; `^` cancels them to 0x00.
        window
            .get_mut(0x24..0x28)
            .ok_or("short window")?
            .copy_from_slice(&[0x05, 0x05, 0x00, 0x00]);
        let report = assemble(0x1004_0003, window, None);
        let secure = report.secure_boot().ok_or("a T41 has a secure-boot block")?;
        assert_eq!(secure.flags, 0x05, "the fold is an OR, not an XOR");
        assert!(secure.enabled(), "a doubly-burned SC_EN must not cancel itself out");
        assert_eq!(secure.rsa_exponent(), 3);
        assert!(
            report.to_string().contains("Secure boot:  ENABLED (all boot sources)"),
            "{report}"
        );
        Ok(())
    }

    /// XBurst2's key hash is the main copy OR the backup (`diag.c:178-179`).
    ///
    /// Either copy alone provisions the key, and the two OR together byte by byte — a
    /// device that burned half of each still reports one whole hash.
    #[test]
    fn op_diag_folds_the_redundant_key_hash() -> TestResult {
        for (main, backup, expected) in [(0xF0_u8, 0x00_u8, 0xF0_u8), (0x00, 0x0F, 0x0F), (0xF0, 0x0F, 0xFF)] {
            let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
            window.get_mut(0x80..0xA0).ok_or("short window")?.fill(main);
            window.get_mut(0xC0..0xE0).ok_or("short window")?.fill(backup);
            let secure = assemble(0x1004_0003, window, None)
                .secure_boot()
                .ok_or("a T41 has a secure-boot block")?;
            assert_eq!(secure.provisioned_key_hash(), Some([expected; 32]));
        }
        Ok(())
    }

    /// A family with no known layout says so, and does not claim the chip has no fuses.
    ///
    /// The C has one sentence for both (`diag.c:246`, reached from `EF_FAM_UNKNOWN`),
    /// which tells an operator holding an unrecognised chip that its silicon has no
    /// secure-boot fuses — something the C does not know and neither do we. A T33 is the
    /// live instance: no `case 0x0033` anywhere in the C, and no layout row here.
    #[test]
    fn op_diag_separates_no_fuses_from_no_layout() -> TestResult {
        // A T33, whose grade selector diag gets for free at window +0x1C.
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        window
            .get_mut(0x1C..0x20)
            .ok_or("short window")?
            .copy_from_slice(&[0x00, 0x00, 0x00, 0xAA]);
        let report = assemble(0x0003_3000, window, None);
        assert_eq!(report.layout(), EfuseLayout::Unknown);
        assert_eq!(report.regs.t33_grade(), Some(0xAA), "the selector is inside the window");
        assert_eq!(report.detection.variant(), Some(Variant::T33));
        let text = report.to_string();
        assert!(
            text.contains("Secure boot:  not decoded  (no eFuse layout is known for soc_id 0x00033000)"),
            "{text}"
        );
        assert!(text.contains("t33 selector 0xAA000000 (+0x1C)"), "{text}");

        // A T20, which really has no secure-boot fuses.
        let text = assemble(0x1200_0002, vec![0_u8; EFUSE_WINDOW_LEN], None).to_string();
        assert!(
            text.contains(
                "Secure boot:  not present  (XBurst1 legacy layout: no secure-boot fuses on this SoC family)"
            ),
            "{text}"
        );
        Ok(())
    }

    /// A grade the table cannot settle names the candidates and says to pass `--cpu`.
    ///
    /// The C prints the family label (`T40/T41`) and stops, so the operator is told the
    /// tool does not know without being told what to do about it. The grade
    /// code is the evidence that would extend the table, and the C's diag never
    /// prints it at all.
    #[test]
    fn op_diag_says_what_to_do_when_the_grade_is_shared() -> TestResult {
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        // A T4x grade that is not one of D4's four auto-picks.
        window
            .get_mut(0x50..0x54)
            .ok_or("short window")?
            .copy_from_slice(&[0x22, 0x22, 0x11, 0x11]);
        let report = assemble(0x1004_0003, window, None);
        assert!(matches!(report.detection, Detection::Ambiguous { .. }));

        let text = report.to_string();
        assert!(text.contains("T40/T41, grade not unique: pass --cpu"), "{text}");
        // The label is on the *first* candidate and the rest continue under it —
        // `cargo-mutants` inverted that test and `contains("Could be:")` did not notice.
        let listed: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("  ") && line.contains("--cpu "))
            .collect();
        assert!(listed.len() >= 2, "{text}\nonly one candidate to align");
        assert!(
            listed
                .first()
                .is_some_and(|line| line.starts_with("  Could be:        ")),
            "{text}\nthe label is not on the first candidate"
        );
        assert!(
            listed
                .get(1)
                .is_some_and(|line| line.starts_with("                   ")),
            "{text}\nthe later candidates are not aligned under the first"
        );
        assert!(text.contains("--cpu "), "{text}\nnames no loader to pass");
        // The grade code itself, which is what a bug report needs.
        assert!(text.contains("subsoctype2 0x11112222"), "{text}");

        // And an unrecognised chip is told the same thing in its own words.
        let text = assemble(0x0BAD_0000, vec![0_u8; EFUSE_WINDOW_LEN], None).to_string();
        assert!(
            text.contains("SoC:          unrecognised: pass --cpu, or stream a loader with --spl and --uboot"),
            "{text}"
        );
        Ok(())
    }

    /// The bootrom magic is filtered to printable non-space ASCII, and its absence just
    /// leaves the clause out (`device.c:80-88`, `diag.c:105-110`, `:208-211`).
    #[test]
    fn op_diag_cleans_the_bootrom_magic() {
        assert_eq!(clean_magic(*b"T20V\0\0\0\0").as_deref(), Some("T20V"));
        assert_eq!(clean_magic(*b"T31V0001").as_deref(), Some("T31V0001"));
        assert_eq!(
            clean_magic(*b"T2 1V\0\0\0").as_deref(),
            Some("T21V"),
            "spaces are dropped"
        );
        assert_eq!(clean_magic([0xFF; 8]), None, "nothing printable is no magic");
        assert_eq!(clean_magic([b' '; 8]), None);

        // The T20X window, minus the magic: the clause is simply absent, and nothing
        // else about the report changes.
        let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
        if let Some(slot) = window.get_mut(0x38..0x3C) {
            slot.copy_from_slice(&0x2222_0000_u32.to_le_bytes());
        }
        let report = assemble(0x1200_0002, window, None).to_string();
        assert!(
            report.contains("SoC:          t20x (T20X), soc_id 0x12000002"),
            "{report}"
        );
        assert!(!report.contains("bootrom"), "{report}");
    }

    // -----------------------------------------------------------------
    // The wire.
    // -----------------------------------------------------------------

    /// A bootrom as the mock sees it: the product string really does have
    /// a junk prefix, and is never compared for equality.
    fn bootrom_descriptors() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("\u{c3}\t USB Boot Device")
    }

    /// What `bootrom::claim` declares.
    fn bootrom_interface() -> InterfaceSpec {
        InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT)
    }

    /// A 32-bit value is split across `wValue` (high half) and `wIndex` (low).
    fn halves(value: u32) -> (u16, u16) {
        (
            u16::try_from(value >> 16).unwrap_or_default(),
            u16::try_from(value & 0xFFFF).unwrap_or_default(),
        )
    }

    /// The `Call` a vendor OUT with no data stage makes.
    fn vendor_out(request: u8, value: u32) -> Call {
        Call::control_out(ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request,
            value: halves(value).0,
            index: halves(value).1,
            data: &[],
        })
    }

    /// The `GET_CPU_INFO` control IN.
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

    /// One `read_memory`: `SET_DATA_ADDR`, `SET_DATA_LEN`, then the bulk IN
    /// (`protocol.c:146-155`).
    fn one_read(mock: MockTransport, address: u32, data: Vec<u8>) -> MockTransport {
        let len = data.len();
        mock.expecting(vendor_out(request::SET_DATA_ADDR, address), Reply::Done)
            .expecting(
                vendor_out(request::SET_DATA_LEN, u32::try_from(len).unwrap_or_default()),
                Reply::Done,
            )
            .expecting(Call::BulkIn { len }, Reply::Data(data))
    }

    /// A scripted device that answers a whole diag from `capture`.
    fn scripted(capture: &Capture) -> MockTransport {
        let magic = capture.magic.clone().unwrap_or_default();
        let mut raw = [0_u8; 8];
        for (slot, byte) in raw.iter_mut().zip(magic.bytes()) {
            *slot = byte;
        }
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(cpu_info_query(), Reply::Data(raw.to_vec()))
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        let mock = one_read(mock, addr::SOC_ID.get(), capture.soc_id.to_le_bytes().to_vec());
        let mock = one_read(mock, addr::EFUSE_WINDOW.get(), capture.window.clone());
        mock.expecting(Call::ReleaseInterface(0), Reply::Done)
    }

    /// **The pin.** The whole operation, over the wire, for a real device.
    #[test]
    fn op_diag_reads_the_window_and_the_soc_id() -> TestResult {
        let capture = parse(CAPTURE_T32LQ).ok_or("the T32LQ capture did not parse")?;
        let mock = scripted(&capture);
        let clock = RecordingClock::new();

        let report = block_on(diag(&mock, &clock))?;
        assert_eq!(report.regs.soc_id, 0x1003_2004);
        assert_eq!(report.window, capture.window);
        assert_eq!(report.magic.as_deref(), Some("T31V"));
        assert_eq!(report.detection.variant(), Some(Variant::T32lq));

        // Exactly two reads: 4 bytes and 256, and nothing else on the bulk pipe.
        let reads: Vec<usize> = mock
            .calls()
            .iter()
            .filter_map(|recorded| match recorded.call {
                Call::BulkIn { len } => Some(len),
                _ => None,
            })
            .collect();
        assert_eq!(reads, vec![WORD, EFUSE_WINDOW_LEN]);
        mock.verify()?;
        Ok(())
    }

    /// **The stage gate, and it costs the bus nothing.**
    ///
    /// The C refuses a non-bootrom before it opens anything (`diag.c:89-93`); this
    /// operation had no gate at all, so `--diag` aimed at a running gadget sent it four
    /// vendor requests it cannot answer. The gadget and the bootrom share `a108:c309`
    /// so this is the ordinary mistake rather than an exotic one.
    ///
    /// Driven through a `MockTransport` with **no expectations at all**: a scripted
    /// double refuses any call it was not told about, so "nothing reached the bus" is
    /// asserted by construction rather than by counting afterwards.
    #[test]
    fn op_diag_refuses_a_device_that_is_not_in_the_bootrom() -> TestResult {
        let gadget = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(Vec::new());
        let mock = MockTransport::new(gadget);
        let clock = RecordingClock::new();

        let Err(Error::Invalid(message)) = block_on(diag(&mock, &clock)) else {
            return Err("--diag must refuse a DFU gadget".into());
        };
        assert!(
            message.contains("gadget"),
            "the refusal does not say what it found: {message}"
        );
        assert!(message.contains("bootrom"), "nor what to do about it: {message}");
        mock.verify()?;

        // A device the descriptors cannot place is refused too, and says which case it
        // is: "unknown" is not "yes".
        let unplaceable = MockTransport::new(DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM));
        let Err(Error::Invalid(unknown)) = block_on(diag(&unplaceable, &clock)) else {
            return Err("--diag must refuse a device it cannot classify".into());
        };
        assert!(unknown.contains("configuration descriptor"), "{unknown}");
        unplaceable.verify()?;
        Ok(())
    }

    /// **The zero-execution pin: `op_diag_no_execution`.**
    ///
    /// The mask ROM's `PROG_STAGE1` is one shot per power cycle. The C spends it here —
    /// `diag.c:145` runs the detect stub purely to refine a name — and spending it on a
    /// *diagnostic* leaves a device that then has to be power-cycled before it can be
    /// flashed. This asserts from the recorded traffic that nothing is executed, nothing
    /// is uploaded, and no `SET_DATA_*` goes out beyond the two the two reads need.
    #[test]
    fn op_diag_no_execution() -> TestResult {
        let capture = parse(CAPTURE_T40XP).ok_or("the T40XP capture did not parse")?;
        let mock = scripted(&capture);
        let clock = RecordingClock::new();
        let report = block_on(diag(&mock, &clock))?;
        assert_eq!(report.detection.variant(), Some(Variant::T40xp));

        let mut addr_sets = 0_usize;
        let mut len_sets = 0_usize;
        for recorded in mock.calls() {
            if let Call::ControlOut { request, .. } = recorded.call {
                assert_ne!(request, request::PROG_STAGE1, "diag fired the one-shot PROG_STAGE1");
                assert_ne!(request, request::PROG_STAGE2, "diag ran stage 2");
                assert_ne!(request, request::FLUSH_CACHE, "diag flushed the cache");
                if request == request::SET_DATA_ADDR {
                    addr_sets += 1;
                }
                if request == request::SET_DATA_LEN {
                    len_sets += 1;
                }
            }
            assert!(
                !matches!(recorded.call, Call::BulkOut { .. }),
                "diag uploaded something to the device"
            );
        }
        // Two reads, two of each — no third SET_DATA_ADDR staging a stub at 0x80001000.
        assert_eq!((addr_sets, len_sets), (2, 2));
        mock.verify()?;
        Ok(())
    }

    /// The interface is released on every path, including a failed read.
    ///
    /// Leaving a bootrom interface claimed makes the next operation on the device time
    /// out, so this is the path where a forgotten release costs a power cycle.
    #[test]
    fn op_diag_releases_the_interface_after_a_failed_read() -> TestResult {
        let failure = UsbError::new(UsbErrorKind::Fault, Pipe::Bulk(endpoint::BOOTROM_IN));
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(cpu_info_query(), Reply::Data(b"T31V\0\0\0\0".to_vec()))
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_ADDR, addr::SOC_ID.get()), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 4), Reply::Done)
            .expecting(Call::BulkIn { len: WORD }, Reply::Fail(failure))
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let error = block_on(diag(&mock, &clock))
            .err()
            .ok_or("a dead device produced a diagnostic")?;
        assert!(error.to_string().contains("soc_id"), "{error} does not name the read");
        assert_eq!(mock.remaining(), 0, "the interface was not released");
        mock.verify()?;
        Ok(())
    }

    /// A failed `soc_id` read is fatal, where `diag.c:124-125` ignores it.
    ///
    /// The C only assigns on success, so the report went out claiming `id 0x00000000`,
    /// an unknown family, and — through `diag.c:246` — that the chip has no secure-boot
    /// fuses. Three statements about silicon, from a transfer that never happened.
    #[test]
    fn op_diag_a_failed_soc_id_read_is_fatal() -> TestResult {
        let failure = UsbError::new(UsbErrorKind::Timeout, Pipe::Bulk(endpoint::BOOTROM_IN));
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(cpu_info_query(), Reply::Data(b"T31V\0\0\0\0".to_vec()))
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_ADDR, addr::SOC_ID.get()), Reply::Done)
            .expecting(vendor_out(request::SET_DATA_LEN, 4), Reply::Done)
            .expecting(Call::BulkIn { len: WORD }, Reply::Fail(failure))
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let error = block_on(diag(&mock, &clock))
            .err()
            .ok_or("a failed soc_id read produced a report")?;
        assert_eq!(
            error.to_string(),
            "reading soc_id at 0xB300002C: timed out: bulk IN on endpoint 0x81"
        );

        // And the window is never even asked for: the layout it would be decoded with
        // is exactly what the failed read was going to decide.
        let reads = mock
            .calls()
            .iter()
            .filter(|recorded| matches!(recorded.call, Call::BulkIn { .. }))
            .count();
        assert_eq!(reads, 1);
        mock.verify()?;
        Ok(())
    }

    /// A `soc_id` that reads back as **zero** is reported, not refused.
    ///
    /// [`ops::detect`](crate::ops::detect) refuses this (`protocol.c:623-626` does too),
    /// because the next thing it does is choose a loader. Diag chooses nothing and
    /// writes nothing, and the window dump is the one artefact that makes such a device
    /// diagnosable — refusing would throw away the evidence for the sake of consistency
    /// with an operation that has a different job.
    #[test]
    fn op_diag_reports_a_zero_soc_id() -> TestResult {
        let mut capture = parse(CAPTURE_T40XP).ok_or("the T40XP capture did not parse")?;
        capture.soc_id = 0;
        let mock = scripted(&capture);
        let clock = RecordingClock::new();

        let report = block_on(diag(&mock, &clock))?;
        assert_eq!(report.regs.soc_id, 0);
        assert_eq!(report.layout(), EfuseLayout::Unknown);
        assert!(matches!(report.detection, Detection::Unknown { .. }));

        let text = report.to_string();
        assert!(text.contains("soc_id 0x00000000"), "{text}");
        assert!(
            text.contains("Secure boot:  not decoded  (no eFuse layout is known for soc_id 0x00000000)"),
            "{text}"
        );
        // The evidence survives.
        assert!(text.contains("13540200: 34 2f 36 7f"), "{text}");
        mock.verify()?;
        Ok(())
    }

    /// The magic is best-effort, exactly as it is in the C (`diag.c:103`).
    ///
    /// A bootrom that refuses `GET_CPU_INFO` still gets a full report; the string is a
    /// hint and nothing decides on it.
    #[test]
    fn op_diag_survives_a_refused_cpu_info() -> TestResult {
        let capture = parse(CAPTURE_T20X).ok_or("the T20X capture did not parse")?;
        let refusal = UsbError::new(
            UsbErrorKind::Stall,
            Pipe::Control {
                direction: tdfu_usb::Direction::In,
                request: request::GET_CPU_INFO,
            },
        );
        // `get_cpu_info` falls back to claiming and asking again, so the
        // refusal has to be scripted twice.
        let mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(cpu_info_query(), Reply::Fail(refusal.clone()))
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done)
            .expecting(cpu_info_query(), Reply::Fail(refusal))
            .expecting(Call::ReleaseInterface(0), Reply::Done)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        let mock = one_read(mock, addr::SOC_ID.get(), capture.soc_id.to_le_bytes().to_vec());
        let mock = one_read(mock, addr::EFUSE_WINDOW.get(), capture.window.clone());
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let clock = RecordingClock::new();
        let report = block_on(diag(&mock, &clock))?;
        assert_eq!(report.magic, None);
        assert_eq!(report.detection.variant(), Some(Variant::T20x));
        assert!(!report.to_string().contains("bootrom"), "{report}");
        mock.verify()?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // What a failure says.
    // -----------------------------------------------------------------

    /// A failed read names **which** read, at what address, and keeps the transport's
    /// own account, and its recoverability class.
    #[test]
    fn op_diag_a_failed_read_names_its_target() {
        let usb = UsbError::new(UsbErrorKind::AccessDenied, Pipe::Bulk(endpoint::BOOTROM_IN));
        for (target, name, address) in [
            (Target::SocId, "soc_id", "0xB300002C"),
            (Target::Window, "the eFuse window", "0xB3540200"),
        ] {
            let wrapped = read_failed(target, Error::Usb(usb.clone()));
            let message = wrapped.to_string();
            assert!(message.contains(name), "{message:?} does not name {name}");
            assert!(message.contains(address), "{message:?} does not give {address}");
            assert!(message.ends_with(&usb.to_string()), "{message:?} lost the transport");
            // Wrapping in `Protocol` would have made this recoverable and buried the
            // "install a udev rule" message under a silent reset-retry.
            assert!(!wrapped.is_recoverable(), "AccessDenied changed class");
            assert_eq!(wrapped.is_recoverable(), Error::Usb(usb.clone()).is_recoverable());
        }

        assert_eq!(
            short_read(Target::Window, 64).to_string(),
            "protocol: reading the eFuse window at 0xB3540200 returned 64 bytes, not 256"
        );
        assert_eq!(
            short_read(Target::SocId, 2).to_string(),
            "protocol: reading soc_id at 0xB300002C returned 2 bytes, not 4"
        );
    }

    /// Both addresses are kseg1, and they are the constants the reads use.
    ///
    /// The physical form wedges the bootrom's USB handler until the power relay cycles,
    /// and [`Kseg1`](crate::addr::Kseg1) makes one unconstructible — what is left to get
    /// wrong is *which* constant each read uses.
    #[test]
    fn op_diag_addresses_are_kseg1() {
        for (target, constant, raw) in [
            (Target::SocId, addr::SOC_ID, 0xB300_002C_u32),
            (Target::Window, addr::EFUSE_WINDOW, 0xB354_0200),
        ] {
            assert_eq!(target.addr(), constant, "{target:?} uses the wrong constant");
            assert_eq!(target.addr().get(), raw, "{target:?}");
            assert!(is_kseg1(target.addr().get()), "{target:?} is not kseg1");
        }
        assert_eq!(Target::Window.len(), EFUSE_WINDOW_LEN);
        assert_eq!(Target::SocId.len(), WORD);
    }

    /// A short window cannot make the decode read past it: no panics in
    /// a library, least of all this one.
    ///
    /// `Diag`'s fields are public, so a caller can build one with any window at all; the
    /// operation itself refuses a short read before it gets here.
    #[test]
    fn op_diag_a_short_window_does_not_panic() {
        for len in [0_usize, 1, 4, 0x10, 0x24, 0x40, 0x51, 0x80, 0xC0, 0xFF] {
            let report = Diag::new(
                crate::model::SocRegs::new(0x1004_0003, 0, 0),
                vec![0x5A; len],
                None,
                Detection::Unknown {
                    regs: crate::model::SocRegs::new(0x1004_0003, 0, 0),
                },
            );
            let text = report.to_string();
            assert!(text.starts_with("=== thingino-dfu diagnostics ==="), "{len}");
            // The secure word is at +0x24 on an XBurst2; below that there is nothing to
            // decode and the report says so rather than reporting secure boot off.
            if len < 0x28 {
                assert!(text.contains("Secure boot:  not decoded"), "{len}: {text}");
                assert_eq!(report.secure_boot(), None, "{len}");
            }
            // The dump ends the report whatever the length, and the newline that
            // separates its lines never becomes a trailing one.
            assert!(!text.ends_with('\n'), "{len}: {text}");
            let dumped = text.lines().filter(|line| line.starts_with("  1354")).count();
            assert_eq!(dumped, len.div_ceil(16), "{len}: wrong number of dump lines");
        }

        // The serial's length boundary, both sides. `cargo-mutants` turned `< 4` into
        // `== 4` and into `<= 4` and nothing here noticed: a four-byte window is the
        // shortest one that *has* a word to print, and the only length the three answer
        // differently for.
        let regs = crate::model::SocRegs::new(0x1004_0003, 0, 0);
        let detection = Detection::Unknown { regs };
        let nothing = Diag::new(regs, Vec::new(), None, detection.clone()).to_string();
        assert!(
            nothing.contains("Serial/UID:   (the window is 0 bytes; the serial needs 16)"),
            "{nothing}"
        );
        let one_word = Diag::new(regs, vec![0x11, 0x22, 0x33, 0x44], None, detection).to_string();
        assert!(one_word.contains("Serial/UID:   1144201745  (11223344)"), "{one_word}");
        // And the flag helpers are total over every byte.
        for flags in 0..=u8::MAX {
            let secure = SecureBoot::decode(EfuseLayout::Xb1Secure, &{
                let mut window = vec![0_u8; EFUSE_WINDOW_LEN];
                if let Some(slot) = window.get_mut(0x12) {
                    *slot = flags;
                }
                window
            });
            let Some(secure) = secure else { continue };
            assert_eq!(secure.flags, flags);
            assert_eq!(secure.enabled(), flags & 1 != 0);
        }
    }
}
