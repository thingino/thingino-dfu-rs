//! The decode table's `variant` and `dram` columns, diffed against the C in both
//! dimensions.
//!
//! **Why this exists.** `det_table_matches_thingino_soc` checks the *names* against
//! thingino's `soc` script, and the script carries no DRAM and no size. So until now
//! nothing checked which **loader** a grade picks or what that loader initialises, and
//! `cargo mutants` proved it: three mutations of those two columns survived the whole
//! suite — `T23DL`'s loader changed from `t23dl` to `t23n`, which is a 64 MB profile on
//! a 32 MB part; `T31A`'s DRAM changed from DDR3 to DDR2; and the T32 fallback changed
//! from the conservative DDR3 profile to a DDR2 one. Each is the DDR2-flashed-as-DDR3
//! bug with a different chip's name on it, and every one passed.
//!
//! Two tables make them fail:
//!
//! * [`LOADER_CLASS`] — what each loader directory initialises, DRAM type and size
//!   class, taken from the C's own per-grade notes.
//! * [`C_LOADERS`] — which directory the C's chain lands on for a `(cpu_id, grade)`
//!   pair, one row per arm it actually writes.
//!
//! Composing them is how the C itself answers "what will this flash": grade → variant
//! (`libtdfu/src/usb/protocol.c:664-770`) → directory
//! (`libtdfu/src/dfu/dfu.c:1084-1123` and `libtdfu/src/utils.c:98-126`) → the DDR init
//! that directory's `tpl.bin`/`spl.bin` performs.
//!
//! Everything the two trees deliberately differ about is data —
//! [`C_LOADER_DIVERGENCES`] — and it is asserted to be **fully used**, so a stale
//! exemption fails the test rather than hiding a drift. That is the
//! `NOT_IN_THE_SCRIPT` pattern from [`super::script`], applied to the other two columns.

use std::collections::BTreeSet;

use super::tests::regs_for;
use super::{FAMILY_TABLES, T4X_GRADES, decode};
use crate::model::{DramKind, Family, Variant};

/// What a loader directory initialises: DRAM type and size class.
///
/// The C never puts either in a filename (there is no `_64m` convention — the path is
/// `<root>/dfu/<dir>/{tpl,spl}.bin` and `<root>/dfu/<dir>/uboot.bin`, `dfu.c:1213-1216`).
/// It states them in the comments beside the grade arms that select each directory, and
/// that is the only place either is written down at all.
struct LoaderClass {
    dir: &'static str,
    dram: Option<DramKind>,
    /// Megabytes of DRAM the profile brings up, where the C says.
    megabytes: Option<u16>,
    /// Where the C says it.
    cite: &'static str,
}

/// Every loader directory the C's chain can produce, with what the C says it is.
///
/// A directory the C never names has no row here and is skipped by the checks — being
/// silent is not the same as agreeing.
static LOADER_CLASS: &[LoaderClass] = &[
    LoaderClass {
        dir: "t20x",
        dram: None,
        megabytes: Some(128),
        cite: "protocol.c:672 `TDFU_VARIANT_T20X; /* 128 MB */`",
    },
    LoaderClass {
        dir: "t20n",
        dram: None,
        megabytes: Some(64),
        cite: "protocol.c:676 `TDFU_VARIANT_T20N; /* 64 MB (incl 0x1111, ax, z) */`",
    },
    LoaderClass {
        dir: "t23dl",
        dram: Some(DramKind::Ddr2),
        megabytes: Some(32),
        cite: "protocol.c:683 `TDFU_VARIANT_T23DL; /* DDR2, 32 MB */`; tdfu.h:102",
    },
    LoaderClass {
        dir: "t23n",
        dram: Some(DramKind::Ddr2),
        megabytes: Some(64),
        cite: "protocol.c:689 `TDFU_VARIANT_T23N; /* DDR2 64 MB base (incl 0x1111) */`",
    },
    LoaderClass {
        dir: "t30x",
        dram: None,
        megabytes: Some(128),
        cite: "protocol.c:693 `TDFU_VARIANT_T30X; /* 128 MB */`",
    },
    LoaderClass {
        dir: "t30a",
        dram: None,
        megabytes: Some(128),
        cite: "protocol.c:697 `TDFU_VARIANT_T30A; /* 128 MB */`",
    },
    LoaderClass {
        dir: "t30n",
        dram: None,
        megabytes: Some(64),
        cite: "protocol.c:699 `TDFU_VARIANT_T30N; /* 64 MB base (incl 0x1111, z) */`",
    },
    LoaderClass {
        dir: "t31a",
        dram: Some(DramKind::Ddr3),
        megabytes: None,
        cite: "protocol.c:714, 719 `T31A (0x4444)` under `DDR3`; tdfu.h:89",
    },
    LoaderClass {
        dir: "t31x",
        dram: Some(DramKind::Ddr2),
        megabytes: Some(128),
        cite: "protocol.c:721, 723 `/* DDR2 128M -> t31x */`; dfu.c:1102 `/* DDR2 128 MB */`",
    },
    LoaderClass {
        dir: "t31n",
        dram: Some(DramKind::Ddr2),
        megabytes: Some(64),
        cite: "protocol.c:725 `/* DDR2 64M -> t31n */`, :729 `/* ZC/LC 64M -> t31n */`",
    },
    LoaderClass {
        dir: "t31l",
        dram: Some(DramKind::Ddr2),
        megabytes: Some(64),
        cite: "protocol.c:727 `/* DDR2 64M lite (L/ZL) -> t31l */`",
    },
    LoaderClass {
        dir: "t32lq",
        dram: Some(DramKind::Ddr2),
        megabytes: None,
        cite: "protocol.c:706 `TDFU_VARIANT_T32LQ; /* DDR2 */`; tdfu.h:113",
    },
    LoaderClass {
        dir: "t32nq",
        dram: Some(DramKind::Ddr3),
        megabytes: None,
        cite: "protocol.c:708 `TDFU_VARIANT_T32NQ; /* DDR3 */`",
    },
    LoaderClass {
        dir: "t32vn",
        dram: Some(DramKind::Ddr3),
        megabytes: None,
        cite: "protocol.c:710 `/* other DDR3 -> conservative t32vn */`; dfu.c:1106",
    },
    LoaderClass {
        dir: "t40n",
        dram: Some(DramKind::Ddr2),
        megabytes: None,
        cite: "protocol.c:738, 744 `TDFU_VARIANT_T40; /* T40NN, DDR2 */`",
    },
    LoaderClass {
        dir: "t40xp",
        dram: Some(DramKind::Ddr3),
        megabytes: None,
        cite: "protocol.c:739, 746 `TDFU_VARIANT_T40XP; /* T40XP (or T41ZN), DDR3 */`",
    },
    LoaderClass {
        dir: "t41lq",
        dram: Some(DramKind::Ddr2),
        megabytes: None,
        cite: "protocol.c:748, 750 `/* DDR2 -> \"t41\" */`; dfu.c:1111 `/* DDR2 */`",
    },
    LoaderClass {
        dir: "t41nq",
        dram: Some(DramKind::Ddr3),
        megabytes: None,
        cite: "protocol.c:752-760 `/* DDR3 */`; dfu.c:1117 `return \"t41nq\"; /* DDR3 */`",
    },
];

/// One `(cpu_id, grade)` pair the C decodes, and the directory it lands on.
struct CRow {
    cpu_id: u16,
    grade: u16,
    dir: &'static str,
    /// Both links of the chain: the `protocol.c` arm and the `dfu.c`/`utils.c` arm.
    cite: &'static str,
}

/// A grade code no arm of the C matches, used to exercise a family's `else`.
///
/// `0xF0F0` is in no table on either side, so it reaches every fallback it is given to.
const UNMATCHED: u16 = 0xF0F0;

/// The C's `(cpu_id, grade) → directory` chain, one row per arm it writes plus one
/// `UNMATCHED` row per family for the `else`.
///
/// The T33 family has no row because the C has none: `protocol.c` has no `case 0x0033`
/// and falls through to `LOG_WARN("Unknown SoC CPU ID")` at `:767-769`.
static C_LOADERS: &[CRow] = &[
    // ---- T10: bails before the stub and forces the family to t10l ----
    CRow {
        cpu_id: 0x0005,
        grade: UNMATCHED,
        dir: "t10l",
        cite: "protocol.c:665-668 -> dfu.c:1086-1089 (`only T10L silicon has ever been seen`)",
    },
    // ---- T20 ----
    CRow {
        cpu_id: 0x2000,
        grade: 0x2222,
        dir: "t20x",
        cite: "protocol.c:671-672 -> utils.c:102",
    },
    CRow {
        cpu_id: 0x2000,
        grade: 0x3333,
        dir: "t20l",
        cite: "protocol.c:673-674 -> utils.c:103",
    },
    CRow {
        cpu_id: 0x2000,
        grade: 0x1111,
        dir: "t20n",
        cite: "protocol.c:675-676 (else) -> utils.c:101",
    },
    CRow {
        cpu_id: 0x2000,
        grade: UNMATCHED,
        dir: "t20n",
        cite: "protocol.c:675-676 (else) -> utils.c:101",
    },
    // ---- T21: every grade takes the one loader ----
    CRow {
        cpu_id: 0x0021,
        grade: 0x1111,
        dir: "t21n",
        cite: "protocol.c:678-679 -> utils.c:104",
    },
    CRow {
        cpu_id: 0x0021,
        grade: 0x2222,
        dir: "t21n",
        cite: "protocol.c:678-679 (`n/l/z all -> t21n`)",
    },
    CRow {
        cpu_id: 0x0021,
        grade: UNMATCHED,
        dir: "t21n",
        cite: "protocol.c:678-679",
    },
    // ---- T23 ----
    CRow {
        cpu_id: 0x0023,
        grade: 0x3333,
        dir: "t23dl",
        cite: "protocol.c:682-683 -> utils.c:45",
    },
    CRow {
        cpu_id: 0x0023,
        grade: 0x2222,
        dir: "t23x",
        cite: "protocol.c:684-685 -> utils.c:110",
    },
    CRow {
        cpu_id: 0x0023,
        grade: 0x7777,
        dir: "t23zn",
        cite: "protocol.c:686-687 -> utils.c:111",
    },
    CRow {
        cpu_id: 0x0023,
        grade: 0x1111,
        dir: "t23n",
        cite: "protocol.c:688-689 (else) -> utils.c:106",
    },
    CRow {
        cpu_id: 0x0023,
        grade: 0x5555,
        dir: "t23n",
        cite: "protocol.c:688-689 (else); the C ships a t23dn loader it never selects",
    },
    CRow {
        cpu_id: 0x0023,
        grade: 0x6666,
        dir: "t23n",
        cite: "protocol.c:688-689 (else)",
    },
    CRow {
        cpu_id: 0x0023,
        grade: UNMATCHED,
        dir: "t23n",
        cite: "protocol.c:688-689 (else)",
    },
    // ---- T30 ----
    CRow {
        cpu_id: 0x0030,
        grade: 0x2222,
        dir: "t30x",
        cite: "protocol.c:692-693 -> utils.c:113",
    },
    CRow {
        cpu_id: 0x0030,
        grade: 0x3333,
        dir: "t30l",
        cite: "protocol.c:694-695 -> utils.c:114",
    },
    CRow {
        cpu_id: 0x0030,
        grade: 0x4444,
        dir: "t30a",
        cite: "protocol.c:696-697 -> utils.c:115",
    },
    CRow {
        cpu_id: 0x0030,
        grade: 0x1111,
        dir: "t30n",
        cite: "protocol.c:698-699 (else) -> utils.c:112",
    },
    CRow {
        cpu_id: 0x0030,
        grade: 0x5555,
        dir: "t30n",
        cite: "protocol.c:698-699 (else)",
    },
    CRow {
        cpu_id: 0x0030,
        grade: UNMATCHED,
        dir: "t30n",
        cite: "protocol.c:698-699 (else)",
    },
    // ---- T31: the family whose DDR type the C states per grade ----
    CRow {
        cpu_id: 0x0031,
        grade: 0x4444,
        dir: "t31a",
        cite: "protocol.c:718-719 -> utils.c:54-55 (DDR3)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0xCCCC,
        dir: "t31x",
        cite: "protocol.c:720-721 -> dfu.c:1101-1102 (DDR2 128M)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0x6666,
        dir: "t31x",
        cite: "protocol.c:722-723 -> dfu.c:1100-1102 (DDR2 128M)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0x1111,
        dir: "t31n",
        cite: "protocol.c:724-725 -> utils.c:116 (DDR2 64M)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0x3333,
        dir: "t31l",
        cite: "protocol.c:726-727 -> utils.c:117 (DDR2 64M lite)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0x5555,
        dir: "t31l",
        cite: "protocol.c:726-727 (L/ZL share the arm)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0xDDDD,
        dir: "t31n",
        cite: "protocol.c:728-729 (ZC 64M)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0xEEEE,
        dir: "t31n",
        cite: "protocol.c:728-729 (LC 64M)",
    },
    CRow {
        cpu_id: 0x0031,
        grade: 0x2222,
        dir: "t31x",
        cite: "protocol.c:730-731 (else, `incl 0x2222`) -> utils.c:50-51",
    },
    CRow {
        cpu_id: 0x0031,
        grade: UNMATCHED,
        dir: "t31x",
        cite: "protocol.c:730-731 (else)",
    },
    // ---- T32: the grade code selects the DDR type ----
    CRow {
        cpu_id: 0x0032,
        grade: 0x9999,
        dir: "t32lq",
        cite: "protocol.c:705-706 -> utils.c:118 (DDR2)",
    },
    CRow {
        cpu_id: 0x0032,
        grade: 0xAAAA,
        dir: "t32nq",
        cite: "protocol.c:707-708 -> utils.c:119 (DDR3)",
    },
    CRow {
        cpu_id: 0x0032,
        grade: UNMATCHED,
        dir: "t32vn",
        cite: "protocol.c:709-710 (else) -> dfu.c:1105-1106 (conservative DDR3)",
    },
    // ---- T4x: sub2 is the discriminator ----
    CRow {
        cpu_id: 0x0040,
        grade: 0x8888,
        dir: "t40n",
        cite: "protocol.c:743-744 -> dfu.c:1107-1108 (DDR2)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x7777,
        dir: "t40xp",
        cite: "protocol.c:745-746 -> utils.c:80-81 (DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x9999,
        dir: "t41lq",
        cite: "protocol.c:749-750 -> utils.c:90-91 (DDR2)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0xAAAA,
        dir: "t41nq",
        cite: "protocol.c:753-754 -> utils.c:86-87 (DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x3333,
        dir: "t41lq",
        cite: "protocol.c:747-748 -> dfu.c:1110-1111 (DDR2)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x1111,
        dir: "t41nq",
        cite: "protocol.c:751-752 -> dfu.c:1113,1117 (DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x4444,
        dir: "t41nq",
        cite: "protocol.c:755-756 -> dfu.c:1114,1117 (DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x5555,
        dir: "t41nq",
        cite: "protocol.c:757-758 -> dfu.c:1115,1117 (the C calls T41ZL DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x6666,
        dir: "t41nq",
        cite: "protocol.c:759-760 -> dfu.c:1116,1117 (DDR3)",
    },
    CRow {
        cpu_id: 0x0040,
        grade: 0x2222,
        dir: "t41nq",
        cite: "protocol.c:761-762 (else) -> dfu.c:1112,1117",
    },
    CRow {
        cpu_id: 0x0040,
        grade: UNMATCHED,
        dir: "t41nq",
        cite: "protocol.c:761-762 (else)",
    },
    // ---- A1 ----
    CRow {
        cpu_id: 0x0001,
        grade: 0x1111,
        dir: "a1n",
        cite: "protocol.c:764-765 -> dfu.c:1118-1119",
    },
    CRow {
        cpu_id: 0x0001,
        grade: UNMATCHED,
        dir: "a1n",
        cite: "protocol.c:764-765 (any grade)",
    },
];

/// Why this table lands somewhere else than the C for a `(cpu_id, grade)` pair.
///
/// Asserted fully used. Every entry is a decision recorded elsewhere, restated here in
/// one line so a reader of the diff does not have to go looking.
static C_LOADER_DIVERGENCES: &[(u16, u16, &str)] = &[
    // T40 and T41 share the grade space and the same code
    // means a different DDR setup on each line, so only the four codes read off real
    // silicon auto-pick; every other T4x grade is `Ambiguous` and needs `--cpu`. The C
    // guesses on all of them, and `0x5555` is the guess behind the worst of them.
    (
        0x0040,
        0x1111,
        "0x1111 is T40N (DDR2 32-bit) or T41N (DDR3 16-bit); no register tells them apart",
    ),
    (
        0x0040,
        0x2222,
        "T41XQ, and no t41xq loader exists — the C's else picks t41nq anyway",
    ),
    (
        0x0040,
        0x3333,
        "T41L, the only documented 0x3333 chip and its loader would be t41lq too — but 0x3333 is not one of the four codes read off silicon, so it does not auto-pick",
    ),
    (
        0x0040,
        0x4444,
        "0x4444 is T40A (DDR3 32-bit, no loader) or T41A (DDR3 16-bit)",
    ),
    (
        0x0040,
        0x5555,
        "the C calls T41ZL DDR3 and flashes t41nq; isvp_t41.h:444-446 and thingino's t41.mk:13-15 both make it DDR2",
    ),
    (
        0x0040,
        0x6666,
        "T41ZX; documented, never seen, so it does not auto-pick",
    ),
    (
        0x0040,
        UNMATCHED,
        "an undocumented T4x grade is Ambiguous with no candidates, never the C's t41nq default",
    ),
    // The T33 family, which the C cannot decode at all.
    // (No C row exists for it, so it is checked from this side only — see the T33 test.)
    // T23DN: the C ships the loader and never selects it.
    (
        0x0023,
        0x5555,
        "0x5555 is T23DN and its loader ships in the tree; the C's else sends it to t23n",
    ),
];

/// The loader class for a directory, if the C says anything about it.
fn class_of(dir: &str) -> Option<&'static LoaderClass> {
    LOADER_CLASS.iter().find(|entry| entry.dir == dir)
}

/// **The pin.** Every `(cpu_id, grade)` the C resolves lands on the same loader here, or
/// on a divergence that is written down.
#[test]
fn det_loader_choice_matches_the_c_or_says_why_not() {
    let mut used = BTreeSet::new();

    for row in C_LOADERS {
        let detection = decode(regs_for(row.cpu_id, row.grade));
        let ours = detection.variant().map(Variant::loader_dir);

        if ours == Some(row.dir) {
            assert!(
                !C_LOADER_DIVERGENCES
                    .iter()
                    .any(|(cpu, grade, _)| *cpu == row.cpu_id && *grade == row.grade),
                "cpu {:#06X} grade {:#06X} agrees with the C ({}), so its divergence entry is stale",
                row.cpu_id,
                row.grade,
                row.dir
            );
            continue;
        }

        let excused = C_LOADER_DIVERGENCES
            .iter()
            .find(|(cpu, grade, _)| *cpu == row.cpu_id && *grade == row.grade);
        assert!(
            excused.is_some(),
            "cpu {:#06X} grade {:#06X}: the C flashes {} ({}), this table {}",
            row.cpu_id,
            row.grade,
            row.dir,
            row.cite,
            ours.map_or_else(|| format!("does not resolve ({detection:?})"), str::to_owned)
        );
        used.insert((row.cpu_id, row.grade));
    }

    let declared: BTreeSet<(u16, u16)> = C_LOADER_DIVERGENCES
        .iter()
        .map(|&(cpu, grade, _)| (cpu, grade))
        .collect();
    assert_eq!(used, declared, "an unused entry in C_LOADER_DIVERGENCES");
}

/// **The pin.** No grade is ever handed a loader whose DDR init or size class is wrong
/// for it.
///
/// This is the check that catches the three surviving mutations. A grade's *class* is
/// not carried by the row — it is carried by the directory the row points at, exactly as
/// in the C — so changing a row's `variant` silently changes what DDR init the part gets
/// and how much memory comes up, and nothing else in the suite looks at either.
#[test]
fn det_no_grade_gets_a_loader_of_the_wrong_dram_or_size() {
    for row in C_LOADERS {
        let Some(want) = class_of(row.dir) else {
            continue; // The C says nothing about this directory.
        };
        let detection = decode(regs_for(row.cpu_id, row.grade));
        let Some(variant) = detection.variant() else {
            continue; // Ambiguous or Unknown; the loader-choice pin covers those.
        };
        let dir = variant.loader_dir();
        let Some(got) = class_of(dir) else {
            continue;
        };

        // A divergence excuses a *different directory*, never a different class under
        // the same one.
        let excused = C_LOADER_DIVERGENCES
            .iter()
            .any(|(cpu, grade, _)| *cpu == row.cpu_id && *grade == row.grade);

        if let (Some(want_dram), Some(got_dram)) = (want.dram, got.dram)
            && !excused
        {
            assert_eq!(
                got_dram, want_dram,
                "cpu {:#06X} grade {:#06X}: the C flashes {} ({want_dram:?}, {}), this table flashes {dir} ({got_dram:?}, {}) — a wrong DDR init",
                row.cpu_id, row.grade, row.dir, want.cite, got.cite
            );
        }
        if let (Some(want_mb), Some(got_mb)) = (want.megabytes, got.megabytes)
            && !excused
        {
            assert_eq!(
                got_mb, want_mb,
                "cpu {:#06X} grade {:#06X}: the C flashes {} ({want_mb} MB, {}), this table flashes {dir} ({got_mb} MB, {}) — the wrong size class",
                row.cpu_id, row.grade, row.dir, want.cite, got.cite
            );
        }
    }
}

/// **The pin.** A row that states its DRAM states the DRAM of the loader it picks.
///
/// The other half of the same defect: `T31A`'s `dram` column could be flipped to DDR2
/// while it kept the `t31a` loader, and an operator reading the ambiguity message or the
/// caveat would be told the wrong thing about a part they are choosing `--cpu` for.
#[test]
fn det_every_row_agrees_with_its_loader_about_dram() {
    for table in FAMILY_TABLES {
        for row in table.rows {
            let Some(dram) = row.dram else { continue };
            let Some(class) = class_of(row.variant.loader_dir()) else {
                continue;
            };
            if let Some(want) = class.dram {
                assert_eq!(
                    dram.kind,
                    want,
                    "{} says {:?} and picks {} which is {want:?} ({})",
                    row.chip,
                    dram.kind,
                    row.variant.loader_dir(),
                    class.cite
                );
            }
        }

        let Some(dram) = table.fallback_dram else { continue };
        let Some(class) = class_of(table.fallback_variant.loader_dir()) else {
            continue;
        };
        if let Some(want) = class.dram {
            assert_eq!(
                dram.kind,
                want,
                "the {:?} fallback says {:?} and picks {} which is {want:?} ({})",
                table.family,
                dram.kind,
                table.fallback_variant.loader_dir(),
                class.cite
            );
        }
    }

    for entry in T4X_GRADES {
        for candidate in entry.candidates {
            let Some(variant) = candidate.variant else { continue };
            let Some(class) = class_of(variant.loader_dir()) else {
                continue;
            };
            if let Some(want) = class.dram {
                assert_eq!(
                    candidate.dram.kind,
                    want,
                    "grade {:#06X} candidate {} says {:?} and picks {} which is {want:?} ({})",
                    entry.grade,
                    candidate.chip,
                    candidate.dram.kind,
                    variant.loader_dir(),
                    class.cite
                );
            }
        }
    }
}

/// The C cannot decode a T33 at all, so there is no row to diff — and that absence is
/// itself worth pinning, because it is the reason a T33 in the bootrom is
/// auto-bootstrappable here and is not with the shipped tool.
#[test]
fn det_the_c_has_no_t33_row_and_this_table_does() {
    assert!(
        !C_LOADERS.iter().any(|row| row.cpu_id == Family::T33.cpu_id()),
        "the C has no `case 0x0033` (protocol.c:767-769 warns and returns TDFU_ERROR_PROTOCOL)"
    );
    // Every T33 grade the script names resolves here, to the one loader they all share.
    for grade in [0x33_u16, 0x44, 0x55, 0x77, 0x99, 0xAA, 0xCC, 0xDD] {
        let detection = decode(regs_for(Family::T33.cpu_id(), grade));
        assert_eq!(
            detection.variant().map(Variant::loader_dir),
            Some("t33"),
            "T33 grade {grade:#04X} must resolve to the one t33 loader"
        );
    }
}

/// Neither table is allowed to go quietly empty.
///
/// A cross-check whose data stopped matching anything would report `ok` forever, which
/// is the failure mode this guards against.
#[test]
fn the_cross_check_tables_are_populated_and_consistent() {
    assert!(
        C_LOADERS.len() >= 40,
        "only {} C rows; the table was gutted",
        C_LOADERS.len()
    );
    assert!(LOADER_CLASS.len() >= 18, "only {} loader classes", LOADER_CLASS.len());

    // Every directory a C row names has a class, or the check above is vacuous for it.
    let classed: BTreeSet<&str> = LOADER_CLASS.iter().map(|entry| entry.dir).collect();
    let unclassed: BTreeSet<&str> = C_LOADERS
        .iter()
        .map(|row| row.dir)
        .filter(|dir| !classed.contains(dir))
        .collect();
    assert_eq!(
        unclassed,
        // The C states neither DRAM nor size for these seven, and inventing one would be
        // the guess-rendered-as-fact shape this table refuses.
        ["a1n", "t10l", "t20l", "t21n", "t23x", "t23zn", "t30l"]
            .into_iter()
            .collect(),
        "a C row names a directory with no class, or a class went missing"
    );

    // And no two classes describe the same directory.
    assert_eq!(classed.len(), LOADER_CLASS.len(), "a duplicate row in LOADER_CLASS");

    // The two size classes that make the T23DL mutation catchable really do differ.
    let dl = class_of("t23dl").and_then(|entry| entry.megabytes);
    let n = class_of("t23n").and_then(|entry| entry.megabytes);
    assert_eq!((dl, n), (Some(32), Some(64)), "the 32/64 MB split is the whole point");
}
