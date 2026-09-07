//! Turning three or four register words into a chip name and a loader.
//!
//! Pure: no device, no I/O, no clock. [`ops::detect`](crate::ops::detect) does the
//! reads and calls [`decode`].
//!
//! # The table
//!
//! One row per grade code, per family, each carrying the chip name, the loader that
//! serves it, the DRAM that loader initialises where a cited source names it, and how
//! well the row is known. It is the **union** of three sources, and where they disagree
//! the order of authority is: a bench capture in `crates/tdfu-core/tests/fixtures/results/`, then
//! thingino's own `soc` script, then the C.
//!
//! Two properties are structural rather than remembered:
//!
//! * A [`T4xCandidate`] holds a [`Dram`] and not an `Option<Dram>`, so a T4x candidate
//!   that does not name its memory cannot be written down. That deletes a whole class
//!   of defect rather than testing for it: six candidates in an earlier implementation
//!   reported the literal string `"unknown"` where Ingenic's header is explicit, and
//!   that string is what an operator reads to choose `--cpu`.
//! * A row that does not match falls back to the family's conservative loader under the
//!   **family's** name (`"T31"`), never under a specific grade's name (`"T31X"`). A
//!   guess must never be rendered as a fact.
//!
//! `det_table_matches_thingino_soc` parses `crates/tdfu-core/tests/fixtures/thingino-soc.sh` and diffs
//! this table against it in both directions. The C has no such check and decodes the
//! same registers **twice**, into a variant chain (`protocol.c:664-770`) and a chip-name
//! chain (`protocol.c:774-824`) that disagree: a T30A gets the `t30a` loader and is
//! *named* `"T30"`, and a T32NQ gets the `t32nq` loader and is named `"T32"`.

use crate::model::{
    Candidate, Detection, Dram, DramKind, Evidence, Family, Grade, GradeSource, Resolved, SocRegs, Variant,
};

#[cfg(test)]
mod cross_check;
#[cfg(test)]
mod script;
#[cfg(test)]
mod tests;

/// Decode the registers.
///
/// The table is the **union** of the C's and thingino's own `soc` script's, which reads
/// the same three registers on a running camera and carries the newer grade list. Where
/// they disagree the script wins: it knows T33 (which the C cannot decode at all), it
/// knows `t23dn` (whose loader the C ships but never selects), and its `0x40` grade
/// `0x1111` is `t40n` (DDR2) where the C says T41N and picks a DDR3 loader.
///
/// Two rules that are not negotiable:
///
/// * **The T4x rule.** In family `0x0040`, only `0x8888` → `t40n`,
///   `0x7777` → `t40xp`, `0x9999` → `t41lq` and `0xAAAA` → `t41nq` resolve. Every other
///   grade is [`Detection::Ambiguous`] with both product lines' candidates, because
///   T40 and T41 share the grade space and the same code means a different DDR setup on
///   each line. The C's `0x1111 → T41N` and `default → t41nq` rows are not carried.
/// * **A T33 needs its selector word.** With
///   [`SocRegs::t33_selector`](crate::model::SocRegs::t33_selector) present the grade
///   resolves to a chip name; without it the family still resolves to the single `t33`
///   loader, and the caveat says the grade is unresolved. What must **not** happen is
///   an earlier implementation's answer — `Ambiguous` with seven candidates, which makes
///   a T33 in the bootrom impossible to auto-bootstrap.
///
/// The table is machine-checked against `crates/tdfu-core/tests/fixtures/thingino-soc.sh` by a test that
/// parses the script's `case` arms. Keep that test: the C decodes the same registers
/// twice into two chains that disagree, and has no such check.
#[must_use]
pub fn decode(regs: SocRegs) -> Detection {
    let Some(family) = regs.family() else {
        // An id that is not in the table at all.
        return Detection::Unknown { regs };
    };

    if family == Family::T4x {
        return decode_t4x(regs);
    }

    let grade = match family.grade_source() {
        GradeSource::SubSocType1 => regs.sub1(),
        GradeSource::SubSocType2 => regs.sub2(),
        GradeSource::T33Selector => match regs.t33_grade() {
            Some(byte) => u16::from(byte),
            // The fourth read was not taken. All seven T33 grades share the one `t33`
            // loader, so the loader is still right and only the chip name is unknown —
            // which is why this is `Resolved` and not `Ambiguous`.
            None => return t33_without_its_selector(regs),
        },
    };

    let Some(table) = FAMILY_TABLES.iter().find(|table| table.family == family) else {
        // Unreachable: `family_tables_cover_every_family` pins one table per family
        // except T4x, handled above. Total rather than panicking, because a flashing
        // tool must not abort on an internal invariant.
        return Detection::Unknown { regs };
    };

    let resolved = match table.rows.iter().find(|row| row.grade == grade) {
        Some(row) => Resolved {
            regs,
            chip: row.chip,
            variant: row.variant,
            grade: Grade::read(grade),
            dram: row.dram,
            evidence: row.evidence,
        },
        None => Resolved {
            regs,
            chip: table.fallback_chip,
            variant: table.fallback_variant,
            grade: Grade::read(grade),
            dram: table.fallback_dram,
            evidence: Evidence::Convention,
        },
    };
    Detection::Resolved(resolved)
}

/// Does this family need the fourth read?
///
/// Only T33 does. [`ops::detect`](crate::ops::detect) asks this after
/// the first three reads and issues
/// [`addr::T33_SELECTOR`](crate::addr::T33_SELECTOR) only when the answer is yes — one
/// extra read on one family, not a fourth read for everyone.
#[must_use]
pub fn needs_t33_selector(regs: SocRegs) -> bool {
    matches!(regs.family(), Some(Family::T33))
}

/// Family `0x0040`, where T40 and T41 share the grade space.
fn decode_t4x(regs: SocRegs) -> Detection {
    let grade = regs.sub2();

    let Some(entry) = T4X_GRADES.iter().find(|entry| entry.grade == grade) else {
        // Nothing is documented for this code on either product line, so there is
        // nothing to offer. An invented candidate here would be the same defect with
        // the sign flipped: a fabricated row is worse than a short one, because the
        // operator would flash it.
        return Detection::Ambiguous {
            regs,
            family: Family::T4x,
            candidates: Vec::new(),
        };
    };

    if entry.auto_picks
        && let Some(pick) = entry.candidates.first()
        && let Some(variant) = pick.variant
    {
        return Detection::Resolved(Resolved {
            regs,
            chip: pick.chip,
            variant,
            grade: Grade::read(grade),
            dram: Some(pick.dram),
            evidence: pick.evidence,
        });
    }

    Detection::Ambiguous {
        regs,
        family: Family::T4x,
        candidates: entry.candidates.iter().map(T4xCandidate::as_candidate).collect(),
    }
}

/// A T33 whose selector word was never read.
///
/// `Resolved`, not `Ambiguous`: every T33 grade shares the one `t33` loader (confirmed
/// against the fetched tree: one `t33` directory, no per-grade directories), so
/// refusing to bootstrap for want of a *name* is what made a T33 in the bootrom
/// un-flashable in an earlier implementation.
///
/// The grade is [`Grade::unread`] and not a number: nothing read the selector, so there
/// is no code to report, and the chip name is the only thing this path is short of.
fn t33_without_its_selector(regs: SocRegs) -> Detection {
    Detection::Resolved(Resolved {
        regs,
        chip: "T33",
        variant: Variant::T33,
        grade: Grade::unread(),
        dram: None,
        evidence: Evidence::Convention,
    })
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// One graded chip: a grade code, the chip it names, and the loader that serves it.
#[derive(Debug, Clone, Copy)]
struct Row {
    /// The code read from the family's grade register.
    grade: u16,
    /// The chip, spelled as thingino's `soc` script and Ingenic spell it.
    chip: &'static str,
    /// The loader this grade uses — its own where one exists, otherwise the family's.
    variant: Variant,
    /// What that loader initialises, **only** where a cited source names it.
    dram: Option<Dram>,
    /// How well the row is known.
    evidence: Evidence,
}

impl Row {
    const fn new(grade: u16, chip: &'static str, variant: Variant, dram: Option<Dram>, evidence: Evidence) -> Self {
        Self {
            grade,
            chip,
            variant,
            dram,
            evidence,
        }
    }
}

/// One family's rows plus what to do with a grade that has none.
#[derive(Debug, Clone, Copy)]
struct FamilyTable {
    family: Family,
    rows: &'static [Row],
    /// The name for an unmatched grade: the **family**, never a specific chip. Reporting
    /// an unknown part as a named one renders a guess as a fact.
    fallback_chip: &'static str,
    /// The family's conservative loader.
    fallback_variant: Variant,
    /// What that conservative loader initialises, where it is documented.
    fallback_dram: Option<Dram>,
}

/// One chip a T4x grade could name.
///
/// `dram` is a [`Dram`] and not an `Option<Dram>` **on purpose**: the point of this list
/// is to let an operator avoid running a DDR3 init on a DDR2 part, so a row that cannot
/// say which it is has no reason to exist. The pin
/// `det_t4x_candidates_name_their_dram` asserts what this type already makes
/// unwritable.
#[derive(Debug, Clone, Copy)]
struct T4xCandidate {
    chip: &'static str,
    /// The loader that would serve it, or `None` where none exists.
    variant: Option<Variant>,
    dram: Dram,
    evidence: Evidence,
}

impl T4xCandidate {
    const fn new(chip: &'static str, variant: Option<Variant>, dram: Dram, evidence: Evidence) -> Self {
        Self {
            chip,
            variant,
            dram,
            evidence,
        }
    }

    fn as_candidate(&self) -> Candidate {
        Candidate::new(self.chip, self.variant, Some(self.dram), self.evidence)
    }
}

/// One T4x grade code and everything it could be.
#[derive(Debug, Clone, Copy)]
struct T4xGrade {
    grade: u16,
    /// This grade resolves to `candidates[0]`. True for
    /// exactly the four codes that have been read off real silicon.
    auto_picks: bool,
    /// Every documented chip with this code, the auto-picked one first.
    candidates: &'static [T4xCandidate],
}

const DDR2: Dram = Dram::new(DramKind::Ddr2);
const DDR3: Dram = Dram::new(DramKind::Ddr3);
const DDR2_16: Dram = Dram::new(DramKind::Ddr2).with_bus_bits(16);
const DDR2_32: Dram = Dram::new(DramKind::Ddr2).with_bus_bits(32);
const DDR3_16: Dram = Dram::new(DramKind::Ddr3).with_bus_bits(16);
const DDR3_32: Dram = Dram::new(DramKind::Ddr3).with_bus_bits(32);
const LPDDR2: Dram = Dram::new(DramKind::LpDdr2);
const LPDDR3: Dram = Dram::new(DramKind::LpDdr3);

use Evidence::{Bench, Vendor};

/// Every family but T4x, which needs candidate lists rather than rows.
static FAMILY_TABLES: &[FamilyTable] = &[
    // T10 has no grade register to refine the family and only T10L silicon has ever
    // been seen (`dfu.c:1086-1089`), so the one row and the fallback agree.
    FamilyTable {
        family: Family::T10,
        rows: &[
            // Bench 2026-08-22: soc_id 0x10005003, sub1 0x00000000 (`result-t10l.txt`),
            // and a real `-b` afterwards produced the DFU gadget:
            // T10 reads its registers like every other SoC and gets no stub.
            //
            // The `soc` script calls this grade `t10` (soc:119) because it has no grade
            // register to refine with; the C refines it to T10L on the grounds that only
            // T10L silicon has ever been seen (`dfu.c:1086-1089`,
            // `protocol.c:665-668`), and the bench agrees. This is the one place the
            // table is deliberately more specific than the script, and
            // `SCRIPT_NAME_REFINEMENTS` in the tests is where that is recorded.
            Row::new(0x0000, "T10L", Variant::T10l, None, Bench),
        ],
        fallback_chip: "T10",
        fallback_variant: Variant::T10l,
        fallback_dram: None,
    },
    FamilyTable {
        family: Family::T20,
        rows: &[
            Row::new(0x0000, "T20AX", Variant::T20n, None, Vendor), // soc:122 — 64 MB base
            Row::new(0x1111, "T20N", Variant::T20n, None, Vendor),  // soc:123
            // Bench 2026-08-22, Wyze V2: soc_id 0x12000002, sub1 0x22220000.
            Row::new(0x2222, "T20X", Variant::T20x, None, Bench), // soc:124 — 128 MB
            Row::new(0x3333, "T20L", Variant::T20l, None, Vendor), // soc:125
            Row::new(0x6666, "T20Z", Variant::T20n, None, Vendor), // soc:126 — no t20z loader
        ],
        fallback_chip: "T20",
        fallback_variant: Variant::T20n, // the 64 MB base part
        fallback_dram: None,
    },
    // Every T21 grade runs the `t21n` loader (`protocol.c:678-680`).
    // `t21hp` exists in the loader tree and no grade code selects it.
    FamilyTable {
        family: Family::T21,
        rows: &[
            // Bench 2026-08-22: soc_id 0x10021003, sub1 0x11110000.
            Row::new(0x1111, "T21N", Variant::T21n, None, Bench), // soc:127
            Row::new(0x2222, "T21X", Variant::T21n, None, Vendor), // soc:128 — the script itself says "confirm on a t21x chip"
            Row::new(0x3333, "T21L", Variant::T21n, None, Vendor), // soc:129
            Row::new(0x5555, "T21Z", Variant::T21n, None, Vendor), // soc:130
        ],
        fallback_chip: "T21",
        fallback_variant: Variant::T21n,
        fallback_dram: None,
    },
    FamilyTable {
        family: Family::T23,
        rows: &[
            // Bench 2026-08-22: soc_id 0x10023003, sub1 0x11111111. DDR2 64 MB base
            // (`protocol.c:689`).
            Row::new(0x1111, "T23N", Variant::T23n, Some(DDR2), Bench), // soc:131
            Row::new(0x2222, "T23X", Variant::T23x, None, Vendor),      // soc:132
            // DDR2 32 MB (`protocol.c:683`).
            Row::new(0x3333, "T23DL", Variant::T23dl, Some(DDR2), Vendor), // soc:133
            // The C ships a `t23dn` loader and never selects it.
            Row::new(0x5555, "T23DN", Variant::T23dn, None, Vendor), // soc:134
            Row::new(0x6666, "T23ZX", Variant::T23n, None, Vendor),  // soc:135 — no t23zx loader
            Row::new(0x7777, "T23ZN", Variant::T23zn, None, Vendor), // soc:136
        ],
        fallback_chip: "T23",
        fallback_variant: Variant::T23n,
        fallback_dram: Some(DDR2), // the 64 MB base part (`protocol.c:689`)
    },
    FamilyTable {
        family: Family::T30,
        rows: &[
            Row::new(0x1111, "T30N", Variant::T30n, None, Vendor), // soc:137
            // Bench 2026-08-22: soc_id 0x10030005, sub1 0x22221111.
            Row::new(0x2222, "T30X", Variant::T30x, None, Bench), // soc:138 — 128 MB
            Row::new(0x3333, "T30L", Variant::T30l, None, Vendor), // soc:139
            Row::new(0x4444, "T30A", Variant::T30a, None, Vendor), // soc:140 — 128 MB
            Row::new(0x5555, "T30Z", Variant::T30n, None, Vendor), // soc:141 — no t30z loader
        ],
        fallback_chip: "T30",
        fallback_variant: Variant::T30n,
        fallback_dram: None,
    },
    // The DRAM column here is the C's own per-grade note (`protocol.c:713-731`), which
    // is the only source that states it: DDR3 for T31A, DDR2 for everything else.
    FamilyTable {
        family: Family::T31,
        rows: &[
            Row::new(0x1111, "T31N", Variant::T31n, Some(DDR2), Vendor), // soc:142 — 64 MB
            // Bench 2026-08-22 (Z55): soc_id 0x10031003, sub1 0x22221111.
            Row::new(0x2222, "T31X", Variant::T31x, Some(DDR2), Bench), // soc:143
            Row::new(0x3333, "T31L", Variant::T31l, Some(DDR2), Vendor), // soc:144 — 64 MB lite
            Row::new(0x4444, "T31A", Variant::T31a, Some(DDR3), Vendor), // soc:145 — the C100 is this chip
            Row::new(0x5555, "T31ZL", Variant::T31l, Some(DDR2), Vendor), // soc:146
            Row::new(0x6666, "T31ZX", Variant::T31x, Some(DDR2), Bench), // soc:147 — 128 MB; result-t31zx.txt
            Row::new(0xCCCC, "T31AL", Variant::T31x, Some(DDR2), Vendor), // soc:148 — 128 MB
            Row::new(0xDDDD, "T31ZC", Variant::T31n, Some(DDR2), Vendor), // soc:149 — 64 MB
            Row::new(0xEEEE, "T31LC", Variant::T31n, Some(DDR2), Vendor), // soc:150 — 64 MB
        ],
        fallback_chip: "T31",
        fallback_variant: Variant::T31x,
        fallback_dram: Some(DDR2), // t31x is the DDR2 128 MB profile (`protocol.c:721`)
    },
    FamilyTable {
        family: Family::T32,
        rows: &[
            // Bench 2026-08-22: soc_id 0x10032004, sub1 0x99991111. Its bootrom magic
            // reads "T31V" — the ambiguity the C's stub was added to resolve, and why
            // the family comes from `soc_id` and never from the magic.
            Row::new(0x9999, "T32LQ", Variant::T32lq, Some(DDR2), Bench), // soc:151, `protocol.c:706`
            Row::new(0xAAAA, "T32NQ", Variant::T32nq, Some(DDR3), Vendor), // soc:152, `protocol.c:708`
        ],
        fallback_chip: "T32",
        // The conservative @350 DDR3 profile underclocks nq/vn/vx/xq (`dfu.c:1105-1106`).
        fallback_variant: Variant::T32vn,
        fallback_dram: Some(DDR3),
    },
    // T33 alone is graded by byte 3 of the word at `0x1354021C`, not by
    // subsoctype1/subsoctype2 (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:31-36`).
    // All seven grades share the single `t33` loader, so the selector buys
    // a correct *name*, not a different loader. The C has no `case 0x0033` at all and
    // falls through to "Unknown SoC CPU ID" (`protocol.c:767-769`).
    FamilyTable {
        family: Family::T33,
        rows: &[
            Row::new(0x99, "T33L", Variant::T33, None, Vendor), // soc:105
            // 0x33 and 0xAA both name a T33N — the only such collision in the script,
            // and the reading the script's `99/33,AA/44/...` punctuation leaves
            // open; the byte map settles it.
            Row::new(0x33, "T33N", Variant::T33, None, Vendor), // soc:106
            Row::new(0xAA, "T33N", Variant::T33, None, Vendor), // soc:106
            Row::new(0x44, "T33A", Variant::T33, None, Vendor), // soc:107
            Row::new(0x55, "T33ZL", Variant::T33, None, Vendor), // soc:108
            Row::new(0x77, "T33ZN", Variant::T33, None, Vendor), // soc:109
            Row::new(0xCC, "T33VL", Variant::T33, None, Vendor), // soc:110
            Row::new(0xDD, "T33VN", Variant::T33, None, Vendor), // soc:111
        ],
        fallback_chip: "T33",
        fallback_variant: Variant::T33,
        fallback_dram: None,
    },
    // Only the `a1n` loader exists; every A1 grade uses it.
    FamilyTable {
        family: Family::A1,
        rows: &[
            // Bench 2026-08-22: soc_id 0x50001002, sub2 0x11112222.
            Row::new(0x1111, "A1N", Variant::A1n, None, Bench), // soc:95
            Row::new(0x2222, "A1X", Variant::A1n, None, Vendor), // soc:96
            Row::new(0x3333, "A1L", Variant::A1n, None, Vendor), // soc:97
            // The script's own note: a real vendor SKU (`a1a_ddr_para` in U-Boot), but
            // the 0x4444 code is by T-family convention and unconfirmed on silicon.
            Row::new(0x4444, "A1A", Variant::A1n, None, Vendor), // soc:98
            Row::new(0x5555, "A1NT", Variant::A1n, None, Vendor), // soc:99
        ],
        fallback_chip: "A1",
        fallback_variant: Variant::A1n,
        fallback_dram: None,
    },
];

/// Family `0x0040`: the grade table, from Ingenic's `isvp_t40.h` and `isvp_t41.h`.
///
/// The four `auto_picks` rows are the codes read off real silicon, confirmed against
/// the board configs: every
/// T4x camera thingino has ever built is one of these four codes (9× t41nq, 4× t40xp,
/// 2× t40nn, 3× t41lq across 16 configs; zero T40N and zero T41N boards). Anything else
/// names both product lines and requires `--cpu`, because no register distinguishes
/// them and the same code means a different DDR setup on each line.
static T4X_GRADES: &[T4xGrade] = &[
    T4xGrade {
        grade: 0x1111,
        auto_picks: false,
        candidates: &[
            // The `soc` script says t40n and the C says T41N → `t41nq`; that is the one
            // DDR-affecting conflict, and this table refuses to guess between them.
            T4xCandidate::new("T40N", Some(Variant::T40n), DDR2_32, Vendor), // `isvp_t40.h:414-416`, soc:76
            T4xCandidate::new("T41N", Some(Variant::T41nq), DDR3_16, Vendor), // `isvp_t41.h:439-441`, `dfu.c:1113,1117`
        ],
    },
    T4xGrade {
        grade: 0x2222,
        auto_picks: false,
        // No `t41xq` loader exists and the C does not accept the string either.
        candidates: &[T4xCandidate::new("T41XQ", None, DDR3, Vendor)], // `isvp_t41.h:469-471`, soc:87
    },
    T4xGrade {
        grade: 0x3333,
        auto_picks: false,
        candidates: &[T4xCandidate::new("T41L", Some(Variant::T41lq), DDR2, Vendor)], // `isvp_t41.h:444-446`, soc:78
    },
    T4xGrade {
        grade: 0x4444,
        auto_picks: false,
        candidates: &[
            // No `t40a` loader exists (`t30a` is a T30 loader); the C does not accept
            // `--cpu t40a`, so nothing maps this chip to a directory.
            T4xCandidate::new("T40A", None, DDR3_32, Vendor), // `isvp_t40.h:420-422`
            T4xCandidate::new("T41A", Some(Variant::T41nq), DDR3_16, Vendor), // `isvp_t41.h:449-451`, soc:79
        ],
    },
    T4xGrade {
        grade: 0x5555,
        auto_picks: false,
        // **DDR2.** The C groups T41ZL with the DDR3 parts (`protocol.c:757-758`,
        // `dfu.c:1115-1117`); `isvp_t41.h:444-446` puts `CONFIG_T41ZL` with
        // `CONFIG_T41L`/`CONFIG_T41LQ` under `CONFIG_DDR_TYPE_DDR2`, and thingino's
        // `soc/ingenic/t41.mk:13-15` builds it from `isvp_t41lq_sfcnor`.
        candidates: &[T4xCandidate::new("T41ZL", Some(Variant::T41lq), DDR2, Vendor)], // soc:80
    },
    T4xGrade {
        grade: 0x6666,
        auto_picks: false,
        candidates: &[T4xCandidate::new("T41ZX", Some(Variant::T41nq), DDR3, Vendor)], // `isvp_t41.h:464-466`, soc:81
    },
    T4xGrade {
        grade: 0x7777,
        auto_picks: true,
        candidates: &[
            // Bench 2026-08-22: soc_id 0x10040003, sub2 0x77772222 (`result-t40xp.txt`).
            // The only 0x7777 parts ever seen are T40XP — bench plus four
            // thingino boards — and that evidence is why this collision auto-picks. A
            // real T41ZN needs `--cpu t41nq`.
            T4xCandidate::new("T40XP", Some(Variant::T40xp), DDR3_32, Bench), // `isvp_t40.h:427-429`, soc:82
            T4xCandidate::new("T41ZN", Some(Variant::T41nq), DDR3_16, Vendor), // `isvp_t41.h:439-441`, `utils.c:191-192`
        ],
    },
    T4xGrade {
        grade: 0x8888,
        auto_picks: true,
        candidates: &[
            // Bench 2026-08-22: soc_id 0x10040003, sub2 0x88881111 (`result-t40nn.txt`).
            T4xCandidate::new("T40NN", Some(Variant::T40n), DDR2_32, Bench), // = CONFIG_T40N, `isvp_t40.h:414-416`, soc:84
            // Same silicon, different SKU (the script says so at soc:83). No `t41lc`
            // loader and the C does not accept the string.
            T4xCandidate::new("T41LC", None, DDR3_16, Vendor), // `isvp_t41.h:474-475`
        ],
    },
    T4xGrade {
        grade: 0x9999,
        auto_picks: true,
        // Bench 2026-08-22: soc_id 0x10040003, sub2 0x99991111 (`result-t41lq.txt`).
        candidates: &[T4xCandidate::new("T41LQ", Some(Variant::T41lq), DDR2_16, Bench)], // `isvp_t41.h:444-446`, soc:85
    },
    T4xGrade {
        grade: 0xAAAA,
        auto_picks: true,
        // Bench 2026-08-22: soc_id 0x10040003, sub2 0xAAAA2222 (`result-t41nq.txt`).
        candidates: &[T4xCandidate::new("T41NQ", Some(Variant::T41nq), DDR3_16, Bench)], // `isvp_t41.h:439-441`, soc:86
    },
    T4xGrade {
        grade: 0xBBBB,
        auto_picks: false,
        // **LPDDR3, and no loader exists.** That is the reason
        // `--cpu t41_ddr3`'s "any unknown T41 is DDR3" implication is not carried.
        candidates: &[T4xCandidate::new("T41ZM", None, LPDDR3, Vendor)], // `isvp_t41.h:454-456`, soc:88
    },
    T4xGrade {
        grade: 0xCCCC,
        auto_picks: false,
        // **LPDDR2, and no loader exists.**
        candidates: &[T4xCandidate::new("T41ZG", None, LPDDR2, Vendor)], // `isvp_t41.h:459-461`, soc:89
    },
    T4xGrade {
        grade: 0xDDDD,
        auto_picks: false,
        // Not in the `soc` script; Ingenic's headers only.
        candidates: &[T4xCandidate::new("T41ZMC", None, DDR3, Vendor)], // `isvp_t41.h:439`
    },
    T4xGrade {
        grade: 0xEEEE,
        auto_picks: false,
        // Not in the `soc` script; Ingenic's headers only.
        candidates: &[T4xCandidate::new("T41ZGC", None, DDR3, Vendor)], // `isvp_t41.h:464`
    },
];
