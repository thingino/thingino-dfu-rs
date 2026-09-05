//! What the three (sometimes four) register reads mean.

use core::fmt;

use super::variant::{Family, Variant};

/// The registers detection reads, raw.
///
/// **Nothing is uploaded and nothing is executed to obtain these.** The C tree uploads
/// a 606-byte hand-assembled MIPS stub and runs it through the bootrom's one-shot
/// `PROG_STAGE1`, spending the mask ROM's single chance to boot; this is three memory
/// reads at kseg1 addresses. Proven on twelve devices across every
/// mask-ROM generation, and the bootrom is left usable afterwards — a real `-b` on the
/// same unit still brings up the DFU gadget. It is the single biggest improvement over
/// the C and it must survive.
///
/// [`t33_selector`](SocRegs::t33_selector) is the fourth read, taken **only** when the
/// family is T33. An earlier implementation had nowhere to put it, so `decode` could
/// only answer `Ambiguous` for a T33 and no T33 in the bootrom could be
/// auto-bootstrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SocRegs {
    /// `0xB300002C`. `cpu_id = (soc_id >> 12) & 0xFFFF`.
    pub soc_id: u32,
    /// `0xB3540238`. `sub1 = (subsoctype1 >> 16) & 0xFFFF`.
    pub subsoctype1: u32,
    /// `0xB3540250`. `sub2 = (subsoctype2 >> 16) & 0xFFFF`.
    pub subsoctype2: u32,
    /// `0xB354021C`, byte 3. `None` when it was not read — which is every family but
    /// T33.
    pub t33_selector: Option<u32>,
}

impl SocRegs {
    /// The three registers every family needs.
    #[must_use]
    pub const fn new(soc_id: u32, subsoctype1: u32, subsoctype2: u32) -> Self {
        Self {
            soc_id,
            subsoctype1,
            subsoctype2,
            t33_selector: None,
        }
    }

    /// Add the T33 selector word.
    #[must_use]
    pub const fn with_t33_selector(mut self, word: u32) -> Self {
        self.t33_selector = Some(word);
        self
    }

    /// `cpu_id = (soc_id >> 12) & 0xFFFF`.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mask is the point: takes the low 16 bits"
    )]
    pub const fn cpu_id(self) -> u16 {
        ((self.soc_id >> 12) & 0xFFFF) as u16
    }

    /// `sub1 = (subsoctype1 >> 16) & 0xFFFF`.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mask is the point: takes the low 16 bits"
    )]
    pub const fn sub1(self) -> u16 {
        ((self.subsoctype1 >> 16) & 0xFFFF) as u16
    }

    /// `sub2 = (subsoctype2 >> 16) & 0xFFFF`.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mask is the point: takes the low 16 bits"
    )]
    pub const fn sub2(self) -> u16 {
        ((self.subsoctype2 >> 16) & 0xFFFF) as u16
    }

    /// The T33 grade byte: `(t33_selector >> 24) & 0xFF`
    /// (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:31-36`).
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the mask is the point: the soc script takes byte 3"
    )]
    pub const fn t33_grade(self) -> Option<u8> {
        match self.t33_selector {
            Some(word) => Some(((word >> 24) & 0xFF) as u8),
            None => None,
        }
    }

    /// The family, or `None` for a `cpu_id` not in the table.
    #[must_use]
    pub const fn family(self) -> Option<Family> {
        Family::from_cpu_id(self.cpu_id())
    }
}

/// The DRAM a loader initialises.
///
/// There is no "unknown" value, deliberately. Six T4x candidates in an earlier
/// implementation reported the literal string `"unknown"` where Ingenic's header is
/// explicit — and that string is what an operator reads to choose `--cpu` when detection
/// refuses. Where the type is genuinely undocumented the field is
/// absent and the frontend prints nothing, rather than printing a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DramKind {
    /// DDR2.
    Ddr2,
    /// DDR3.
    Ddr3,
    /// LPDDR2.
    LpDdr2,
    /// LPDDR3.
    LpDdr3,
}

impl fmt::Display for DramKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ddr2 => "DDR2",
            Self::Ddr3 => "DDR3",
            Self::LpDdr2 => "LPDDR2",
            Self::LpDdr3 => "LPDDR3",
        })
    }
}

/// A memory configuration, as an operator would say it: "DDR3 16-bit".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dram {
    /// The DRAM type.
    pub kind: DramKind,
    /// Bus width in bits, where Ingenic's config documents it: 32
    /// for the T40 line and 16 for the T41 line.
    pub bus_bits: Option<u8>,
}

impl Dram {
    /// A DRAM type with no documented bus width.
    #[must_use]
    pub const fn new(kind: DramKind) -> Self {
        Self { kind, bus_bits: None }
    }

    /// A DRAM type with its bus width.
    #[must_use]
    pub const fn with_bus_bits(mut self, bits: u8) -> Self {
        self.bus_bits = Some(bits);
        self
    }
}

impl fmt::Display for Dram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bus_bits {
            Some(bits) => write!(f, "{} {bits}-bit", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}

/// How well a table row is known.
///
/// Each row carries an evidence column (bench-seen, vendor-documented or
/// by-convention), and a row without a loader of its own resolves to the family's
/// conservative loader *and says so* in the log.
///
/// An earlier implementation had the data and printed none of it, so it was dead
/// weight. The way it
/// stays alive is [`Detection::caveat`]: the qualification is part of the value, not
/// something a frontend has to remember to derive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Evidence {
    /// Read off a real device; the capture is in `crates/tdfu-core/tests/fixtures/results/`.
    Bench,
    /// Documented somewhere trustworthy, and never seen on silicon here.
    ///
    /// **The provenance varies across the rows, which is why neither this name nor
    /// [`Detection::caveat`]'s wording claims a specific source.** At the strong end are
    /// rows from Ingenic's own configs — `isvp_t41.h`, `isvp_t40.h`, the SPL decode. At
    /// the weak end are rows whose only source is thingino's `soc` script, including two
    /// the script itself flags as guesses (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:128` for
    /// T21X, `:98` for A1A) and all eight T33 grades (`:104-113`), which no Ingenic
    /// document in hand covers. Saying "documented by Ingenic" over that range would
    /// have been a claim about the *source* that the weaker rows cannot support, and a
    /// caveat that overstates its own confidence is worse than none.
    ///
    /// What every row does share is the part the caveat states: nobody here has run one.
    Vendor,
    /// No row matched this grade, so the family's conservative loader was chosen.
    Convention,
}

/// A chip a set of registers could belong to.
///
/// Produced in bulk by [`Detection::Ambiguous`], where the operator has to pick with
/// `--cpu` and needs enough to pick correctly: the chip name, the loader that would be
/// used, the DRAM it initialises and how well the row is known.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// The chip, as Ingenic spells it: `"T41ZN"`.
    pub chip: &'static str,
    /// The loader that would serve it, or `None` when no loader exists for it:
    /// T41ZM and T41ZG have none.
    pub variant: Option<Variant>,
    /// What the loader would initialise. **Never `None` for a T4x candidate**: the
    /// whole point of the row is to let an operator avoid running a DDR3 init on a DDR2
    /// part.
    pub dram: Option<Dram>,
    /// How well this row is known.
    pub evidence: Evidence,
}

impl Candidate {
    /// A candidate with everything known.
    #[must_use]
    pub const fn new(chip: &'static str, variant: Option<Variant>, dram: Option<Dram>, evidence: Evidence) -> Self {
        Self {
            chip,
            variant,
            dram,
            evidence,
        }
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.chip)?;
        if let Some(dram) = self.dram {
            write!(f, " ({dram})")?;
        }
        match self.variant {
            Some(variant) => write!(f, " --cpu {variant}"),
            None => f.write_str(" (no loader exists)"),
        }
    }
}

/// The grade code a chip was resolved from, or the absence of one.
///
/// **A type, because one resolution path has no grade at all.** A T33 whose selector
/// register was never read still resolves (every T33 grade shares the one `t33` loader),
/// and a plain `u16` has nothing to put there but `0`, which is a register reading nobody
/// took. Printed as `0x0000` beside a chip name it is a guess rendered as a fact, and the
/// only thing standing between it and a log line was every consumer remembering to repeat
/// [`Detection::caveat`]'s `t33_selector.is_none()` test for itself. The absence is
/// representable here instead, and the field cannot be given a fabricated value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Grade(Option<u16>);

impl Grade {
    /// A grade that was read from the family's grade register.
    #[must_use]
    pub const fn read(code: u16) -> Self {
        Self(Some(code))
    }

    /// No grade register was read on the path that produced this.
    #[must_use]
    pub const fn unread() -> Self {
        Self(None)
    }

    /// The code, or `None` when none was read.
    #[must_use]
    pub const fn code(self) -> Option<u16> {
        self.0
    }
}

/// `{:#06X}` on a grade that was read is the `0x1234` every caller already prints; on one
/// that was never read it says so in words.
///
/// The impl is the point of the newtype: a consumer that formats the field gets a true
/// answer without knowing which path produced the value, so nothing has to remember the
/// special case to avoid printing a number that was never measured. Width and fill are
/// the integer's own on the read path and ignored on the other, because padding cannot
/// make a number out of an absence.
impl fmt::UpperHex for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(code) => fmt::UpperHex::fmt(&code, f),
            None => f.write_str("(not read)"),
        }
    }
}

/// One chip, identified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// What was read.
    pub regs: SocRegs,
    /// The chip: `"T41NQ"`.
    pub chip: &'static str,
    /// The loader to use.
    pub variant: Variant,
    /// The grade code that selected it, for the caveat text, or
    /// [`Grade::unread`] where no grade register was read.
    pub grade: Grade,
    /// The DRAM the loader initialises, where it is documented.
    pub dram: Option<Dram>,
    /// How well this row is known.
    pub evidence: Evidence,
}

/// The result of decoding [`SocRegs`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detection {
    /// One loader, on evidence.
    Resolved(Resolved),
    /// The family is known but the grade is shared across product lines or has never
    /// been seen: the operator must pass `--cpu`.
    ///
    /// In family `0x0040` this is the normal answer for anything but the four
    /// bench-proven codes, because T40 and T41 share the grade space and the same code
    /// means a different DDR setup on each line.
    Ambiguous {
        /// What was read.
        regs: SocRegs,
        /// The family.
        family: Family,
        /// Every chip it could be, each with its DRAM.
        candidates: Vec<Candidate>,
    },
    /// The `cpu_id` is not in the table at all.
    Unknown {
        /// What was read.
        regs: SocRegs,
    },
}

impl Detection {
    /// The registers this was decoded from.
    #[must_use]
    pub const fn regs(&self) -> SocRegs {
        match self {
            Self::Resolved(resolved) => resolved.regs,
            Self::Ambiguous { regs, .. } | Self::Unknown { regs } => *regs,
        }
    }

    /// The loader to use, if detection settled on one.
    #[must_use]
    pub const fn variant(&self) -> Option<Variant> {
        match self {
            Self::Resolved(resolved) => Some(resolved.variant),
            Self::Ambiguous { .. } | Self::Unknown { .. } => None,
        }
    }

    /// The qualification that belongs in front of the user, or `None`.
    ///
    /// The same sentences as [`Detection::caveat`] except the one for
    /// [`Evidence::Vendor`]: "documented but has never been seen on the bench" describes
    /// the table's provenance, not this device, and it was decided (2026-09-03,
    /// after a T31ZX detected and flashed correctly from the T31X loader) that every
    /// frontend prints it as a debug line rather than as a note beside a working
    /// detection. A conservative-loader fallback and an unread T33 selector still speak
    /// up here, because those qualify the loader choice itself.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::Resolved(resolved) if resolved.evidence == Evidence::Vendor => None,
            _ => self.caveat(),
        }
    }

    /// Every qualification the value carries, or `None` when the answer needs none.
    /// Frontends print [`Detection::warning`] and log the rest at debug.
    ///
    /// A row without a loader of its own resolves to the family's
    /// conservative loader *and says so*. This is that sentence. It is computed from
    /// the value rather than left to each frontend, because an earlier implementation
    /// carried the evidence and never printed it.
    #[must_use]
    pub fn caveat(&self) -> Option<String> {
        let Self::Resolved(resolved) = self else {
            return None;
        };
        match resolved.evidence {
            Evidence::Bench => None,
            // No source is named: `Evidence::Vendor` spans Ingenic's own configs down
            // to rows whose only witness is thingino's `soc` script, two of which that
            // script flags as guesses. What is true of every row is that
            // nobody here has run one.
            Evidence::Vendor => Some(format!(
                "{} is documented but has never been seen on the bench; \
                 using the {} loader; pass --cpu if it misbehaves",
                resolved.chip,
                resolved.variant.loader_dir()
            )),
            Evidence::Convention => {
                // A T33 resolved without its selector has no grade to cite: the
                // register was never read, and naming a value that was never fetched
                // is the guess-rendered-as-fact shape this refuses. The loader
                // is right regardless -- every T33 grade shares it.
                if resolved.regs.family() == Some(Family::T33) && resolved.regs.t33_selector.is_none() {
                    Some(format!(
                        "the T33 grade selector was not read; every T33 grade shares \
                         the {} loader",
                        resolved.variant.loader_dir()
                    ))
                } else {
                    Some(format!(
                        "grade {:#06X} is not in the table; using {}'s conservative \
                         loader {}",
                        resolved.grade,
                        resolved.chip,
                        resolved.variant.loader_dir()
                    ))
                }
            }
        }
    }
}
