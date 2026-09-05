//! The `--diag` report: what one eFuse window says about a chip.
//!
//! **The window is the whole reading.** One 256-byte read at
//! [`addr::EFUSE_WINDOW`](crate::addr::EFUSE_WINDOW) plus one `soc_id` read is
//! everything this type is built from — no stub, no `PROG_STAGE1`, nothing executed on
//! the device. The C runs its detect stub here to refine
//! the SoC name (`diag.c:140-146`) and spends the mask ROM's one shot doing it; the
//! window already *contains* `subsoctype1`, `subsoctype2` and the T33 selector, so there
//! is nothing left to run. The compile-time assertions at the end of this file are that
//! claim, checked rather than asserted in prose.
//!
//! The C's comment that "a stub clears the shadow" (`diag.c:8-9`) was corrected in the
//! bench record: the shadow is stable and re-readable; it is a *stub's own CPU loads* of
//! the eFuse region that read zeros. Moot without a stub.
//!
//! # Why there is no `serde::Serialize` here
//!
//! `Debug + serde::Serialize` is the obvious shape, and adding
//! `serde` to this crate is a decision to make when there is something to serialise.
//! There is nothing yet, and there are two reasons not to pre-empt it:
//!
//! * **No consumer.** Every surface the C has takes the formatted diagnostics *text*
//!   and nothing else: the daemon (`dfu-remote/main.c:742-759` `handle_diag`,
//!   whose OK payload is `send_ok(…, report, strlen(report))` at `:758`), the browser
//!   and Android (`libtdfu/src/core.c:140-150` `tdfu_web_diag`, which returns the
//!   buffer), and the local CLI (`cli/main.c:268-272` `print_diag`). Nothing carries a
//!   structured `Diag`, so a `Serialize` derive today would be a dependency with no
//!   caller — in the one crate that is `#![forbid(unsafe_code)]` and depends on
//!   `tdfu-usb` and `thiserror` and nothing else.
//! * **It would reach past this file.** Adding the dependency, optional feature or not,
//!   means editing `crates/tdfu-core/Cargo.toml` for a type nothing serialises yet.
//!
//! What this file *does* guarantee is that the derive stays a one-line change: every
//! field is owned and plain — `u32`, `u8`, `bool`, `String`, `Vec<u8>`, fixed arrays,
//! and model types that are themselves plain data. No borrows, no lifetimes, no trait
//! objects, nothing that would need a `serde` attribute to express.

use core::fmt;

use super::detection::{Detection, SocRegs};
use super::variant::Family;
use crate::addr::{
    EFUSE_OFFSET_SUBSOCTYPE1, EFUSE_OFFSET_SUBSOCTYPE2, EFUSE_WINDOW, EFUSE_WINDOW_LEN, SUBSOCTYPE1, SUBSOCTYPE2,
};

/// The T33 grade selector's offset inside [`EFUSE_WINDOW`].
///
/// Defined in [`addr`](crate::addr) and re-exported here, beside the other two window
/// offsets. Its derivation is asserted where it is defined:
/// [`T33_SELECTOR`](crate::addr::T33_SELECTOR) is `0xB354021C` and
/// [`EFUSE_WINDOW`](crate::addr::EFUSE_WINDOW) starts at `0xB3540200`, so the selector
/// has always been inside the window, and that const assertion fails to compile if
/// either constant moves.
pub use crate::addr::EFUSE_OFFSET_T33_SELECTOR;

/// The chip serial / UID: the first 16 bytes of the window, on every family
/// (`diag.c:152-155`).
pub const SERIAL_LEN: usize = 16;

/// The RSA public-key hash length, both layouts (`diag.c:165, 178-179`).
pub const KEY_HASH_LEN: usize = 32;

/// The XBurst1-secure security word's offset (`diag.c:161`).
const XB1_SECURITY_OFFSET: usize = 0x10;

/// The XBurst1-secure key hash's offset (`diag.c:165`).
const XB1_KEY_HASH_OFFSET: usize = 0x40;

/// The XBurst2 security word's offset (`diag.c:174`).
const XB2_SECURITY_OFFSET: usize = 0x24;

/// The XBurst2 key hash's two offsets: the main copy and the redundant backup, read
/// OR-ed together (`diag.c:178-179`).
const XB2_KEY_HASH_OFFSETS: [usize; 2] = [0x80, 0xC0];

/// Which eFuse layout a window follows.
///
/// **From `soc_id`, never from the bootrom magic.** The magic is generic on XBurst2 —
/// T40, T41 and A1 all report `T31V`, and so does this bench's T23N — and a T32LQ
/// reports `T31V` too, which is exactly the pair that would be decoded with each other's
/// layout if the magic were trusted (`diag.c:10-11`; bench 2026-08-22,
/// `crates/tdfu-core/tests/fixtures/results/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EfuseLayout {
    /// T10/T20/T21/T30: a serial in the window and no secure-boot fuses at all
    /// (`diag.c:34`, `:181-185`).
    Xb1Legacy,
    /// T23/T31/T32: security word at `+0x10` with the flags in bits 23:16, key hash at
    /// `+0x40` (`diag.c:35`, `:157-166`).
    Xb1Secure,
    /// T40/T41/A1: security word at `+0x24` with the flags folded
    /// `((w >> 8) | w) & 0xFF`, key hash at `+0x80` OR-redundant with `+0xC0`
    /// (`diag.c:36`, `:167-180`).
    Xb2,
    /// No layout is known for this `soc_id`.
    ///
    /// The C reports this as *"no secure-boot fuses on this SoC family"*
    /// (`diag.c:246`), which is a claim it cannot support: `ef_classify` answers
    /// `EF_FAM_UNKNOWN` both for a family with no fuses and for a `cpu_id` it has never
    /// heard of, and the one message covers both. They are kept apart here — a T33 (no
    /// `case 0x0033` anywhere in the C, and no layout row here either) lands here and
    /// the report says the layout is unknown, not that the silicon has no fuses.
    Unknown,
}

impl EfuseLayout {
    /// The layout for a decoded family, or [`Unknown`](EfuseLayout::Unknown).
    ///
    /// The mapping is `ef_classify`'s (`diag.c:50-61`), family for family. T33 is absent
    /// there *and* from the layout table, so it answers `Unknown` rather than being guessed
    /// into the XBurst1-secure group it superficially resembles.
    #[must_use]
    pub const fn of(family: Option<Family>) -> Self {
        match family {
            Some(Family::T10 | Family::T20 | Family::T21 | Family::T30) => Self::Xb1Legacy,
            Some(Family::T23 | Family::T31 | Family::T32) => Self::Xb1Secure,
            Some(Family::T4x | Family::A1) => Self::Xb2,
            Some(Family::T33) | None => Self::Unknown,
        }
    }

    /// Does this layout have secure-boot fuses to decode at all?
    #[must_use]
    pub const fn has_secure_boot(self) -> bool {
        self.security_offset().is_some()
    }

    /// Where the security word lives in the window, for the layouts that have one.
    #[must_use]
    pub const fn security_offset(self) -> Option<usize> {
        match self {
            Self::Xb1Secure => Some(XB1_SECURITY_OFFSET),
            Self::Xb2 => Some(XB2_SECURITY_OFFSET),
            Self::Xb1Legacy | Self::Unknown => None,
        }
    }

    /// Where the RSA key hash lives — two offsets on XBurst2, which keeps a redundant
    /// copy and reads the two OR-ed together (`diag.c:178-179`).
    #[must_use]
    pub const fn key_hash_offsets(self) -> &'static [usize] {
        match self {
            Self::Xb1Secure => &[XB1_KEY_HASH_OFFSET],
            Self::Xb2 => &XB2_KEY_HASH_OFFSETS,
            Self::Xb1Legacy | Self::Unknown => &[],
        }
    }

    /// Does this layout label bit 4 as an SD/MMC-boot block (XBurst2) rather than as an
    /// unspecified extra restriction (XBurst1)?
    ///
    /// The same bit means different things on the two, which is the only reason the C
    /// carries `is_xburst2` at all (`diag.c:230-235`).
    #[must_use]
    pub const fn is_xburst2(self) -> bool {
        matches!(self, Self::Xb2)
    }

    /// How the report names it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Xb1Legacy => "XBurst1 legacy",
            Self::Xb1Secure => "XBurst1 secure",
            Self::Xb2 => "XBurst2",
            Self::Unknown => "unrecognised",
        }
    }
}

impl fmt::Display for EfuseLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The secure-boot block, decoded from whichever word this chip's layout puts it in.
///
/// The flag *bits* are normalised to one set across both layouts (`diag.h:28-33`); what
/// differs is the word's offset and the fold that produces the byte, both of which
/// [`EfuseLayout`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SecureBoot {
    /// Which layout produced this — bit 4's meaning depends on it.
    pub layout: EfuseLayout,
    /// The raw security word, exactly as it sits in the window.
    pub register: u32,
    /// The normalised flag byte (see the `FLAG_*` constants).
    pub flags: u8,
    /// The RSA public-key hash, all zero when no key is burned.
    pub key_hash: [u8; KEY_HASH_LEN],
}

impl SecureBoot {
    /// Secure boot enabled — `SC_EN` (`diag.h:29`).
    pub const FLAG_ENABLE: u8 = 0x01;
    /// RSA verification exponent is 3; clear means 65537 (`diag.h:30`).
    pub const FLAG_RSA_E3: u8 = 0x04;
    /// USB boot is disabled under secure boot (`diag.h:31`).
    pub const FLAG_USB_OFF: u8 = 0x08;
    /// XBurst2: SD/MMC boot disabled. XBurst1: an extra boot restriction whose source is
    /// not documented further (`diag.h:32`).
    pub const FLAG_SD_OFF: u8 = 0x10;
    /// XBurst2 only: writing NOR over USB is disabled under secure boot (`diag.h:33`).
    pub const FLAG_NOR_WRITE_OFF: u8 = 0x40;

    /// Decode the block for `layout` out of `window`.
    ///
    /// `None` when the layout has no secure-boot fuses, or when the window is too short
    /// to hold the security word — a truncated read must not be reported as a chip with
    /// secure boot off.
    #[must_use]
    pub fn decode(layout: EfuseLayout, window: &[u8]) -> Option<Self> {
        let register = le32(window, layout.security_offset()?)?;
        let flags = fold_flags(layout, register);

        // XBurst2 keeps a redundant copy and reads the two OR-ed together
        // (`diag.c:178-179`); XBurst1 has one copy, so the fold is the identity there. A
        // copy the window is too short for contributes nothing rather than failing the
        // decode: the main copy alone is still the truth about the key.
        let mut key_hash = [0_u8; KEY_HASH_LEN];
        for base in layout.key_hash_offsets() {
            let Some(bytes) = base.checked_add(KEY_HASH_LEN).and_then(|end| window.get(*base..end)) else {
                continue;
            };
            for (slot, byte) in key_hash.iter_mut().zip(bytes) {
                *slot |= *byte;
            }
        }

        Some(Self {
            layout,
            register,
            flags,
            key_hash,
        })
    }

    /// Is secure boot on?
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.flags & Self::FLAG_ENABLE != 0
    }

    /// Is USB boot blocked under secure boot?
    #[must_use]
    pub const fn usb_boot_blocked(self) -> bool {
        self.flags & Self::FLAG_USB_OFF != 0
    }

    /// Bit 4: SD/MMC boot blocked on XBurst2, an unspecified extra restriction on
    /// XBurst1. The two are the same fuse and different sentences.
    #[must_use]
    pub const fn bit4_set(self) -> bool {
        self.flags & Self::FLAG_SD_OFF != 0
    }

    /// XBurst2 only: is writing NOR over USB blocked under secure boot?
    #[must_use]
    pub const fn nor_usb_write_blocked(self) -> bool {
        self.flags & Self::FLAG_NOR_WRITE_OFF != 0
    }

    /// The RSA verification exponent: 3 when the bit is set, 65537 when it is clear.
    #[must_use]
    pub const fn rsa_exponent(self) -> u32 {
        if self.flags & Self::FLAG_RSA_E3 != 0 { 3 } else { 65537 }
    }

    /// The key hash, or `None` when no key is burned (`note_key_hash`, `diag.c:66-73`).
    #[must_use]
    pub fn provisioned_key_hash(self) -> Option<[u8; KEY_HASH_LEN]> {
        self.key_hash.iter().any(|byte| *byte != 0).then_some(self.key_hash)
    }
}

/// One device's `--diag` reading.
///
/// Built by [`ops::diag`](crate::ops::diag) from exactly two reads and rendered by its
/// [`Display`](fmt::Display) impl. The raw [`window`](Diag::window) stays in the report
/// on purpose: every decode above it is an interpretation, and the hex dump is the
/// evidence that makes a user's paste actionable without another bench session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diag {
    /// The registers. `soc_id` is read directly; `subsoctype1`, `subsoctype2` and — for
    /// a T33 — the grade selector all come out of [`window`](Diag::window), which is why
    /// diag needs no second, third or fourth register read.
    pub regs: SocRegs,
    /// The eFuse shadow window, [`EFUSE_WINDOW_LEN`]
    /// bytes from [`EFUSE_WINDOW`].
    pub window: Vec<u8>,
    /// The bootrom's CPU-info string, reduced to printable non-space ASCII, or `None`
    /// when the bootrom did not answer or answered with nothing printable.
    ///
    /// **A hint and nothing more**: it is generic on XBurst2, and this
    /// bench's T32LQ and T40XP both report `T31V`. It is in the report because an
    /// operator reading a paste wants to know what the device said about itself, not
    /// because anything decides on it.
    pub magic: Option<String>,
    /// What [`detect::decode`](crate::detect::decode) makes of [`regs`](Diag::regs).
    ///
    /// This is where the C spends the mask ROM's one-shot `PROG_STAGE1`
    /// (`diag.c:140-146`): it re-runs its detect stub purely to turn "T40/T41" into
    /// "t40xp". Here the same answer falls out of the window that was already read.
    pub detection: Detection,
}

impl Diag {
    /// Assemble a reading.
    #[must_use]
    pub fn new(regs: SocRegs, window: Vec<u8>, magic: Option<String>, detection: Detection) -> Self {
        Self {
            regs,
            window,
            magic,
            detection,
        }
    }

    /// The physical address the window was read from, which is the address a datasheet
    /// or a `devmem` on the running camera uses.
    ///
    /// The *read* goes through the kseg1 alias and must; the *label* is
    /// physical, as the C's is (`diag.c:30`, `EFUSE_WINDOW_PHYS`).
    #[must_use]
    pub const fn window_base(&self) -> u32 {
        EFUSE_WINDOW.get() & 0x1FFF_FFFF
    }

    /// Which layout the window follows, taken from `soc_id`.
    #[must_use]
    pub const fn layout(&self) -> EfuseLayout {
        EfuseLayout::of(self.regs.family())
    }

    /// The chip serial / UID: the first [`SERIAL_LEN`] bytes, present on every family
    /// even where the bootrom itself does not read it (`diag.c:152-155`).
    ///
    /// Short when the window is — the report says so rather than this panicking on a
    /// truncated read.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        let end = SERIAL_LEN.min(self.window.len());
        self.window.get(..end).unwrap_or_default()
    }

    /// The serial as the little-endian 32-bit words the bootrom stores it in.
    #[must_use]
    pub fn serial_words(&self) -> Vec<u32> {
        self.serial()
            .chunks_exact(4)
            .filter_map(|word| <[u8; 4]>::try_from(word).ok())
            .map(u32::from_le_bytes)
            .collect()
    }

    /// The secure-boot block, or `None` for a layout that has none — or a window too
    /// short to hold the word (see [`SecureBoot::decode`]).
    #[must_use]
    pub fn secure_boot(&self) -> Option<SecureBoot> {
        SecureBoot::decode(self.layout(), &self.window)
    }
}

/// How the report names a family when detection could not name a chip.
///
/// `ef_classify`'s labels (`diag.c:51-60`), family for family, plus `T33`, which the C
/// has no case for.
const fn family_label(family: Option<Family>) -> &'static str {
    match family {
        Some(Family::T10) => "T10",
        Some(Family::T20) => "T20",
        Some(Family::T21) => "T21",
        Some(Family::T23) => "T23",
        Some(Family::T30) => "T30",
        Some(Family::T31) => "T31",
        Some(Family::T32) => "T32",
        Some(Family::T33) => "T33",
        Some(Family::T4x) => "T40/T41",
        Some(Family::A1) => "A1",
        None => "unrecognised",
    }
}

/// A little-endian word out of the window, or `None` if it does not fit.
///
/// `get`, never an index: [`Diag`] is a public struct with a public `Vec<u8>`, so a
/// short window is constructible, and a flashing tool does not abort on a
/// slice index.
fn le32(window: &[u8], offset: usize) -> Option<u32> {
    offset
        .checked_add(4)
        .and_then(|end| window.get(offset..end))
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map(u32::from_le_bytes)
}

/// The flag byte, folded the way this layout folds it.
///
/// XBurst1 takes bits 23:16 (`diag.c:162`); XBurst2 ORs the main and backup bytes
/// (`diag.c:175`). Both are lossy on purpose — the raw word is reported alongside.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the mask is the fold: both layouts reduce the word to one byte"
)]
const fn fold_flags(layout: EfuseLayout, register: u32) -> u8 {
    match layout {
        EfuseLayout::Xb1Secure => ((register >> 16) & 0xFF) as u8,
        EfuseLayout::Xb2 => (((register >> 8) | register) & 0xFF) as u8,
        EfuseLayout::Xb1Legacy | EfuseLayout::Unknown => 0,
    }
}

/// The top-level label column.
const LABEL: usize = 14;

/// The indented sub-label column inside the secure-boot block. Two spaces plus this is
/// where a sub-value starts, and the widest label (`Extra restrict:`) fits with one
/// space to spare.
const SUB_LABEL: usize = 17;

/// Bytes per line of the hex dump.
const DUMP_STRIDE: usize = 16;

/// What the report says when secure boot blocks a boot source.
const BLOCKED: &str = "disabled under secure boot";

impl fmt::Display for Diag {
    /// The diagnostics text.
    ///
    /// **Ours, not the C's**, but carrying every fact
    /// `tdfu_diag_format` carries (`diag.c:201-259`), which the golden tests in
    /// `ops::diag` check line by line against the three real bench captures. Four
    /// deliberate differences, each pinned there:
    ///
    /// * The `subsoctype1`/`subsoctype2` words are printed. The C reads them (through a
    ///   stub) and prints only the name they produced, so a report from a chip it could
    ///   not name carried nothing anybody could extend the table with, and the grade
    ///   code is the evidence that promotes a row.
    /// * An unresolved detection says so, and says what to pass to `--cpu`. The C
    ///   silently falls back to a family label.
    /// * "No secure-boot fuses on this family" and "no layout known for this chip" are
    ///   different sentences (see [`EfuseLayout::Unknown`]).
    /// * The serial's words lose the C's leading space, an artifact of a `" %u"` join.
    ///
    /// There is **no trailing newline**: `println!("{diag}")` is the intended call, and
    /// a wire payload that wants one appends it. The C's own surfaces already disagree
    /// about that whitespace — `tdfu_diag_format` ends with one (`diag.c:255`), the
    /// daemon sends exactly that (`dfu-remote/main.c:758`) and the CLI wraps it in two
    /// more (`cli/main.c:271`, `printf("\n%s\n", report)`) — so there is nothing to be
    /// compatible with, and the idiomatic end is the one that composes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== thingino-dfu diagnostics ===")?;
        self.write_soc_line(f)?;
        self.write_grade_line(f)?;
        self.write_serial_line(f)?;
        self.write_secure_block(f)?;
        self.write_window(f)
    }
}

impl Diag {
    /// `SoC:` — what it is, what the bootrom called itself, and the raw `soc_id`; then
    /// the candidates or the caveat, when there are any.
    fn write_soc_line(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<LABEL$}{}", "SoC:", self.identity())?;
        if let Some(magic) = self.magic.as_deref().filter(|magic| !magic.is_empty()) {
            write!(f, ", bootrom {magic:?}")?;
        }
        writeln!(f, ", soc_id {:#010X}", self.regs.soc_id)?;

        if let Detection::Ambiguous { candidates, .. } = &self.detection {
            for (index, candidate) in candidates.iter().enumerate() {
                let label = if index == 0 { "Could be:" } else { "" };
                writeln!(f, "  {label:<SUB_LABEL$}{candidate}")?;
            }
        }
        if let Some(caveat) = self.detection.caveat() {
            writeln!(f, "  {:<SUB_LABEL$}{caveat}", "Note:")?;
        }
        Ok(())
    }

    /// How the chip is named: the loader to pass to `--cpu` and the chip it is, or the
    /// family plus what to do about it when detection could not settle.
    fn identity(&self) -> String {
        match &self.detection {
            Detection::Resolved(resolved) => format!("{} ({})", resolved.variant, resolved.chip),
            Detection::Ambiguous { family, .. } => {
                format!("{}, grade not unique: pass --cpu", family_label(Some(*family)))
            }
            Detection::Unknown { .. } => format!(
                "{}: pass --cpu, or stream a loader with --spl and --uboot",
                family_label(self.regs.family())
            ),
        }
    }

    /// `Grade regs:` — the words the family's grade is decoded from, and where in the
    /// window they were found.
    ///
    /// This is the line that makes the zero-execution claim checkable by eye: these are
    /// the registers `ops::detect` reads one at a time, sitting inside the one window
    /// diag already read.
    fn write_grade_line(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<LABEL$}subsoctype1 {:#010X} (+{:#04X}), subsoctype2 {:#010X} (+{:#04X})",
            "Grade regs:",
            self.regs.subsoctype1,
            EFUSE_OFFSET_SUBSOCTYPE1,
            self.regs.subsoctype2,
            EFUSE_OFFSET_SUBSOCTYPE2
        )?;
        if let Some(selector) = self.regs.t33_selector {
            write!(f, ", t33 selector {selector:#010X} (+{EFUSE_OFFSET_T33_SELECTOR:#04X})")?;
        }
        writeln!(f)
    }

    /// `Serial/UID:` — the little-endian words, then the raw bytes.
    fn write_serial_line(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serial = self.serial();
        if serial.len() < 4 {
            return writeln!(
                f,
                "{:<LABEL$}(the window is {} bytes; the serial needs {SERIAL_LEN})",
                "Serial/UID:",
                self.window.len()
            );
        }
        write!(f, "{:<LABEL$}", "Serial/UID:")?;
        for (index, word) in self.serial_words().into_iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{word}")?;
        }
        f.write_str("  (")?;
        for byte in serial {
            write!(f, "{byte:02x}")?;
        }
        writeln!(f, ")")
    }

    /// `Secure boot:` and its five sub-lines, or the one line that says why there are
    /// none.
    fn write_secure_block(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let layout = self.layout();
        let Some(secure) = self.secure_boot() else {
            return self.write_no_secure_boot(f, layout);
        };

        let state = if secure.enabled() {
            "ENABLED (all boot sources)"
        } else {
            "disabled"
        };
        writeln!(
            f,
            "{:<LABEL$}{state}  ({layout} layout, security register {:#010X} at +{:#04X})",
            "Secure boot:",
            secure.register,
            layout.security_offset().unwrap_or_default()
        )?;

        writeln!(
            f,
            "  {:<SUB_LABEL$}{}",
            "USB boot:",
            if secure.usb_boot_blocked() { BLOCKED } else { "allowed" }
        )?;
        if layout.is_xburst2() {
            writeln!(
                f,
                "  {:<SUB_LABEL$}{}",
                "SD/MMC boot:",
                if secure.bit4_set() { BLOCKED } else { "allowed" }
            )?;
            writeln!(
                f,
                "  {:<SUB_LABEL$}{}",
                "NOR USB-write:",
                if secure.nor_usb_write_blocked() {
                    BLOCKED
                } else {
                    "allowed"
                }
            )?;
        } else {
            writeln!(
                f,
                "  {:<SUB_LABEL$}{}",
                "Extra restrict:",
                if secure.bit4_set() {
                    "yes (a boot source blocked under secure boot)"
                } else {
                    "none"
                }
            )?;
        }
        writeln!(f, "  {:<SUB_LABEL$}e={}", "RSA exponent:", secure.rsa_exponent())?;

        write!(f, "  {:<SUB_LABEL$}", "RSA key hash:")?;
        match secure.provisioned_key_hash() {
            Some(hash) => {
                for byte in hash {
                    write!(f, "{byte:02x}")?;
                }
                writeln!(f)
            }
            None => writeln!(f, "(not provisioned)"),
        }
    }

    /// The three reasons there is no secure-boot block, kept apart.
    ///
    /// The C has one sentence for all of them (`diag.c:246`), and it is the wrong one
    /// for two: an unknown `cpu_id` gets told the family has no fuses, and a window too
    /// short to hold the word would too. Neither is something we know.
    fn write_no_secure_boot(&self, f: &mut fmt::Formatter<'_>, layout: EfuseLayout) -> fmt::Result {
        if layout == EfuseLayout::Unknown {
            return writeln!(
                f,
                "{:<LABEL$}not decoded  (no eFuse layout is known for soc_id {:#010X})",
                "Secure boot:", self.regs.soc_id
            );
        }
        if layout.has_secure_boot() {
            return writeln!(
                f,
                "{:<LABEL$}not decoded  ({layout} layout puts the word at +{:#04X}; the window is {} bytes)",
                "Secure boot:",
                layout.security_offset().unwrap_or_default(),
                self.window.len()
            );
        }
        writeln!(
            f,
            "{:<LABEL$}not present  ({layout} layout: no secure-boot fuses on this SoC family)",
            "Secure boot:"
        )
    }

    /// The raw window, 16 bytes to a line, addressed physically.
    ///
    /// **Kept in the report on purpose.** Every decode above it is an interpretation;
    /// this is the evidence, and it is what lets someone read a pasted report and find a
    /// fact the decoder did not know about.
    fn write_window(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.window.is_empty() {
            return write!(f, "eFuse window (phys {:#010X}): nothing was read", self.window_base());
        }
        writeln!(
            f,
            "eFuse window (phys {:#010X}, {} bytes):",
            self.window_base(),
            self.window.len()
        )?;
        // The newline goes *before* each line but the first, so the report ends without
        // one. Computing a last-index instead needed `(len - 1) / STRIDE`, where
        // `cargo-mutants` showed `/` and `%` were indistinguishable at 256 bytes — the
        // one length every real fixture has.
        for (index, line) in self.window.chunks(DUMP_STRIDE).enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            let offset = u32::try_from(index.saturating_mul(DUMP_STRIDE)).unwrap_or(u32::MAX);
            write!(f, "  {:08X}:", self.window_base().wrapping_add(offset))?;
            for byte in line {
                write!(f, " {byte:02x}")?;
            }
        }
        Ok(())
    }
}

// The zero-execution claim, checked at compile time rather than asserted in prose: the
// three registers `ops::detect` reads one at a time are *inside* the one window
// `ops::diag` reads, at these offsets. If any address constant moves, this stops
// compiling instead of silently decoding the wrong bytes.
const _: () = assert!(EFUSE_OFFSET_SUBSOCTYPE1 == 0x38 && SUBSOCTYPE1.get() - EFUSE_WINDOW.get() == 0x38);
const _: () = assert!(EFUSE_OFFSET_SUBSOCTYPE2 == 0x50 && SUBSOCTYPE2.get() - EFUSE_WINDOW.get() == 0x50);
// And every field the layouts name fits the window this crate reads.
const _: () = assert!(SERIAL_LEN <= EFUSE_WINDOW_LEN);
const _: () = assert!(EFUSE_OFFSET_SUBSOCTYPE2 + 4 <= EFUSE_WINDOW_LEN);
const _: () = assert!(XB1_SECURITY_OFFSET + 4 <= EFUSE_WINDOW_LEN);
const _: () = assert!(XB1_KEY_HASH_OFFSET + KEY_HASH_LEN <= EFUSE_WINDOW_LEN);
const _: () = assert!(XB2_SECURITY_OFFSET + 4 <= EFUSE_WINDOW_LEN);
const _: () = assert!(XB2_KEY_HASH_OFFSETS[0] + KEY_HASH_LEN <= EFUSE_WINDOW_LEN);
const _: () = assert!(XB2_KEY_HASH_OFFSETS[1] + KEY_HASH_LEN <= EFUSE_WINDOW_LEN);
// The dump's label is the physical address of the kseg1 window it was read through
// (`diag.c:29-30`: `0xB3540200` read, `0x13540200` printed).
const _: () = assert!(EFUSE_WINDOW.get() & 0x1FFF_FFFF == 0x1354_0200);
