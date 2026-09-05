//! The decode table's proof.
//!
//! Three kinds of test live here, in this order: the thirteen device captures decoded
//! verbatim; the rules that are decisions rather than data (D4's T4x auto-pick, T33's
//! never-`Ambiguous`, the fallback that never borrows a chip's name); and the
//! whole-table sweeps that make "table-driven" a fact — every grade of every family,
//! and the table diffed against `crates/tdfu-core/tests/fixtures/thingino-soc.sh` in both directions.

use super::{FAMILY_TABLES, T4X_GRADES, decode, needs_t33_selector};
use crate::model::{Detection, DramKind, Evidence, Family, Grade, GradeSource, SocRegs, Variant};

/// The registers a device of this family and grade would read back.
///
/// `soc_id` is built so that `(soc_id >> 12) & 0xFFFF` is the `cpu_id`;
/// the real captures have low bits set as well, and
/// `det_every_bench_capture_decodes_to_its_device` uses those verbatim.
pub(super) fn regs_for(cpu_id: u16, grade: u16) -> SocRegs {
    let soc_id = u32::from(cpu_id) << 12;
    match Family::from_cpu_id(cpu_id).map(Family::grade_source) {
        Some(GradeSource::SubSocType1) => SocRegs::new(soc_id, u32::from(grade) << 16, 0),
        Some(GradeSource::SubSocType2) => SocRegs::new(soc_id, 0, u32::from(grade) << 16),
        Some(GradeSource::T33Selector) => SocRegs::new(soc_id, 0, 0).with_t33_selector(u32::from(grade) << 24),
        None => SocRegs::new(soc_id, 0, 0),
    }
}

/// Every chip name an answer offers: one for `Resolved`, all of them for `Ambiguous`,
/// none for `Unknown`.
pub(super) fn names(detection: &Detection) -> Vec<&'static str> {
    match detection {
        Detection::Resolved(resolved) => vec![resolved.chip],
        Detection::Ambiguous { candidates, .. } => candidates.iter().map(|candidate| candidate.chip).collect(),
        Detection::Unknown { .. } => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The thirteen device captures, byte for byte
// ---------------------------------------------------------------------------

/// `(file, soc_id, subsoctype1, subsoctype2, chip, loader)` — transcribed from
/// `crates/tdfu-core/tests/fixtures/results/`: the 2026-08-22 bench sweep across every mask-ROM
/// generation, plus a T31ZX read through the Android app on 2026-09-03. These are the
/// rows that earn `Evidence::Bench`.
const BENCH: &[(&str, u32, u32, u32, &str, Variant)] = &[
    ("result-a1n.txt", 0x5000_1002, 0, 0x1111_2222, "A1N", Variant::A1n),
    ("result-t10l.txt", 0x1000_5003, 0, 0, "T10L", Variant::T10l),
    (
        "result-t20-wyzev2.txt",
        0x1200_0002,
        0x2222_0000,
        0,
        "T20X",
        Variant::T20x,
    ),
    ("result-t21n.txt", 0x1002_1003, 0x1111_0000, 0, "T21N", Variant::T21n),
    ("result-t23n.txt", 0x1002_3003, 0x1111_1111, 0, "T23N", Variant::T23n),
    ("result-t30x.txt", 0x1003_0005, 0x2222_1111, 0, "T30X", Variant::T30x),
    ("result-t31-z55.txt", 0x1003_1003, 0x2222_1111, 0, "T31X", Variant::T31x),
    // Read through the Android app on a phone (2026-09-03), with the same three
    // register reads the bench sweep used.
    ("result-t31zx.txt", 0x1003_1003, 0x6666_1111, 0, "T31ZX", Variant::T31x),
    ("result-t32lq.txt", 0x1003_2004, 0x9999_1111, 0, "T32LQ", Variant::T32lq),
    ("result-t40nn.txt", 0x1004_0003, 0, 0x8888_1111, "T40NN", Variant::T40n),
    ("result-t40xp.txt", 0x1004_0003, 0, 0x7777_2222, "T40XP", Variant::T40xp),
    ("result-t41lq.txt", 0x1004_0003, 0, 0x9999_1111, "T41LQ", Variant::T41lq),
    ("result-t41nq.txt", 0x1004_0003, 0, 0xAAAA_2222, "T41NQ", Variant::T41nq),
];

/// Every device a capture has ever identified, decoded from its own capture.
///
/// Thirteen devices across every mask-ROM generation and every family with a loader, and
/// every one of them read with **nothing uploaded and nothing executed**.
/// The T10L row is in here too: it decodes like any other SoC, with no
/// special case and no stub.
#[test]
fn det_every_bench_capture_decodes_to_its_device() {
    for &(file, soc_id, sub1, sub2, chip, variant) in BENCH {
        let detection = decode(SocRegs::new(soc_id, sub1, sub2));
        assert!(
            matches!(detection, Detection::Resolved(_)),
            "{file}: {detection:?} is not Resolved"
        );
        let Detection::Resolved(resolved) = &detection else {
            continue;
        };
        assert_eq!(resolved.chip, chip, "{file}");
        assert_eq!(resolved.variant, variant, "{file}");
        assert_eq!(
            resolved.evidence,
            Evidence::Bench,
            "{file}: a capture exists, so the row is bench evidence"
        );
        assert_eq!(detection.caveat(), None, "{file}: a bench row needs no caveat");
    }
}

/// Where a capture's own `=>` line spells the chip differently from this table.
///
/// `(file, what the capture prints, what the table says)`. Asserted fully used, so a
/// stale entry fails the test rather than hiding a drift — the `NOT_IN_THE_SCRIPT`
/// pattern from `detect/script.rs`.
///
/// Both rows are the capture being *less* specific, never the table being wrong: the
/// loader directory, which is the part that gets flashed, matches exactly in both.
const CAPTURE_NAME_DIFFERS: &[(&str, &str, &str)] = &[
    // The probe printed the family name; the table carries the per-chip name that goes
    // with the `a1n` loader it also printed.
    ("result-a1n.txt", "A1", "A1N"),
    // Grade 0x7777 is shared by T40XP and T41ZN and the probe says so inline.
    // Here the second name lives in the `T4X_GRADES` candidate list instead of
    // being glued into `chip`.
    ("result-t40xp.txt", "T40XP (or T41ZN)", "T40XP"),
];

/// One capture, as parsed off disk.
#[derive(Debug, PartialEq, Eq)]
struct Capture {
    soc_id: u32,
    subsoctype1: u32,
    subsoctype2: u32,
    chip: String,
    loader_dir: String,
}

/// `  soc_id       @0xB300002C = 0x10040003` → `0x10040003`.
fn register_line(text: &str, name: &str) -> Option<u32> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(name) && line.contains('@'))?;
    let value = line.rsplit_once("= 0x")?.1.trim();
    u32::from_str_radix(value, 16).ok()
}

/// `  => T41NQ   (loader dir: t41nq)` → `("T41NQ", "t41nq")`.
fn verdict_line(text: &str) -> Option<(String, String)> {
    let line = text.lines().map(str::trim).find(|line| line.starts_with("=>"))?;
    let rest = line.strip_prefix("=>")?;
    let (chip, tail) = rest.split_once("(loader dir:")?;
    let loader = tail.split_once(')')?.0;
    Some((chip.trim().to_owned(), loader.trim().to_owned()))
}

fn parse_capture(text: &str) -> Option<Capture> {
    let (chip, loader_dir) = verdict_line(text)?;
    Some(Capture {
        soc_id: register_line(text, "soc_id")?,
        subsoctype1: register_line(text, "subsoctype1")?,
        subsoctype2: register_line(text, "subsoctype2")?,
        chip,
        loader_dir,
    })
}

/// **The pin `BENCH` was missing.** The thirteen rows are parsed out of the captures they
/// claim to come from, not transcribed and hoped for.
///
/// `Evidence::Bench` is the strongest thing this table can say about a row — it is what
/// suppresses the caveat entirely — and nothing kept those labels honest: a typo in a
/// register, a row for a device that was never captured, or a capture that stopped
/// matching would all have passed in silence.
#[test]
fn det_bench_rows_are_parsed_out_of_their_captures() -> Result<(), std::io::Error> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/tdfu-core/tests/fixtures/results");

    // ---- forward: every BENCH row matches the file it names ----
    let mut used_exemptions = std::collections::BTreeSet::new();
    for &(file, soc_id, sub1, sub2, chip, variant) in BENCH {
        let text = std::fs::read_to_string(dir.join(file))?;
        let Some(capture) = parse_capture(&text) else {
            return Err(std::io::Error::other(format!("{file}: could not be parsed")));
        };

        assert_eq!(capture.soc_id, soc_id, "{file}: soc_id");
        assert_eq!(capture.subsoctype1, sub1, "{file}: subsoctype1");
        assert_eq!(capture.subsoctype2, sub2, "{file}: subsoctype2");
        assert_eq!(
            capture.loader_dir,
            variant.loader_dir(),
            "{file}: the capture flashed a different loader than this row names"
        );

        if capture.chip != chip {
            let exempt = CAPTURE_NAME_DIFFERS
                .iter()
                .find(|(name, printed, table)| *name == file && *printed == capture.chip && *table == chip);
            assert!(
                exempt.is_some(),
                "{file}: the capture says {:?}, this row says {chip:?}",
                capture.chip
            );
            used_exemptions.insert(file);
        }
    }

    // ---- the floor: thirteen devices, and no capture left out of the table ----
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            // Extension via `Path`, so the check is not a case-sensitive string compare.
            (path.extension()? == "txt").then_some(())?;
            let name = path.file_name()?.to_string_lossy().into_owned();
            name.starts_with("result-").then_some(name)
        })
        .collect();
    on_disk.sort();
    assert!(
        on_disk.len() >= 13,
        "the 2026-08-22 sweep covered twelve devices; {} capture files are on disk",
        on_disk.len()
    );
    for name in &on_disk {
        assert!(
            BENCH.iter().any(|&(file, ..)| file == name),
            "{name} is a capture with no BENCH row; a device was flashed and never pinned"
        );
    }
    assert_eq!(
        BENCH.len(),
        on_disk.len(),
        "BENCH and the captures must be the same set"
    );

    // ---- the exemption list is not allowed to rot ----
    let declared: std::collections::BTreeSet<&str> = CAPTURE_NAME_DIFFERS.iter().map(|(file, ..)| *file).collect();
    assert_eq!(used_exemptions, declared, "an unused entry in CAPTURE_NAME_DIFFERS");
    Ok(())
}

/// The capture parser, on the shapes the test above depends on.
///
/// A parser that quietly reads nothing makes every assertion above vacuous, and this
/// parser *is* the double for the results directory.
#[test]
fn the_capture_parser_reads_the_result_file_shape() {
    let sample = "\
# a header line with 0x00000000 in it
device: a108:c309 \"USB Boot Device\"

[1] registers via kseg1 (0xB3......), the address form --diag uses:
  soc_id       @0xB300002C = 0x10040003
  subsoctype1  @0xB3540238 = 0x00000000
  subsoctype2  @0xB3540250 = 0xAAAA2222

  cpu_id=0x0040  sub1=0x0000  sub2=0xAAAA
  => T40XP (or T41ZN)   (loader dir: t40xp)

  window[+0x38] = 0x00000000  == subsoctype1 (match)
";
    assert_eq!(
        parse_capture(sample),
        Some(Capture {
            soc_id: 0x1004_0003,
            subsoctype1: 0,
            subsoctype2: 0xAAAA_2222,
            chip: "T40XP (or T41ZN)".to_owned(),
            loader_dir: "t40xp".to_owned(),
        }),
        "the register lines, the shared-code verdict and the loader dir must all parse"
    );

    // The `window[+0x38] = 0x…` line also mentions subsoctype1 and must not be mistaken
    // for the register line: only a line *starting* with the name and carrying `@` counts.
    assert_eq!(register_line(sample, "subsoctype1"), Some(0));
    // And a file missing a verdict line is a parse failure, not a silent default.
    assert_eq!(parse_capture("  soc_id @0xB300002C = 0x1"), None);
}

/// The field extraction, checked through `decode` rather than through the
/// accessors: the T32LQ capture's `subsoctype1` is `0x99991111`, so a decoder that took
/// the **low** half would see `0x1111` and answer T31N-shaped nonsense.
#[test]
fn det_decode_fields() {
    let t32 = decode(SocRegs::new(0x1003_2004, 0x9999_1111, 0));
    assert_eq!(names(&t32), ["T32LQ"], "sub1 is the HIGH half of subsoctype1");

    let t41 = decode(SocRegs::new(0x1004_0003, 0, 0xAAAA_2222));
    assert_eq!(names(&t41), ["T41NQ"], "sub2 is the HIGH half of subsoctype2");

    assert_eq!(SocRegs::new(0x1004_0003, 0, 0).cpu_id(), 0x0040);
    assert_eq!(SocRegs::new(0x1200_0002, 0, 0).cpu_id(), 0x2000);
}

// ---------------------------------------------------------------------------
// T4x, where T40 and T41 share the grade space
// ---------------------------------------------------------------------------

/// **The pin.** Exactly four grades resolve in family `0x0040`; every other code —
/// documented or not — is `Ambiguous` and requires `--cpu`.
///
/// T40 and T41 share the SoC id *and* the grade space and no register tells the lines
/// apart, so an auto-pick outside the four codes read off real silicon
/// would eventually run a DDR3 init on a DDR2 part. The C's `0x1111 → T41N` and
/// `default → t41nq` rows (`protocol.c:751-762`) are exactly that, and they are not
/// carried.
#[test]
fn det_t4x_autopick_only_proven() {
    const PROVEN: &[(u16, &str, Variant)] = &[
        (0x7777, "T40XP", Variant::T40xp),
        (0x8888, "T40NN", Variant::T40n),
        (0x9999, "T41LQ", Variant::T41lq),
        (0xAAAA, "T41NQ", Variant::T41nq),
    ];

    for grade in 0..=u16::MAX {
        let detection = decode(regs_for(0x0040, grade));
        if let Some(&(_, chip, variant)) = PROVEN.iter().find(|&&(code, _, _)| code == grade) {
            assert_eq!(
                names(&detection),
                [chip],
                "grade {grade:#06X} must resolve, got {detection:?}"
            );
            assert_eq!(detection.variant(), Some(variant), "grade {grade:#06X}");
        } else {
            assert!(
                matches!(detection, Detection::Ambiguous { .. }),
                "grade {grade:#06X} must be Ambiguous, got {detection:?}"
            );
        }
    }
}

/// **The pin.** Every candidate in family `0x0040` names its DRAM.
///
/// Six candidates in an earlier implementation reported the literal string `"unknown"`
/// where Ingenic's header is explicit, and that string is what an operator reads to
/// choose `--cpu`. The type already makes an unnamed one unwritable —
/// `T4xCandidate::dram` is a `Dram`, not an `Option<Dram>` — and this asserts it
/// survives the conversion to the public `Candidate`.
#[test]
fn det_t4x_candidates_name_their_dram() {
    let mut seen = 0_usize;
    for grade in 0..=u16::MAX {
        if let Detection::Ambiguous { candidates, family, .. } = decode(regs_for(0x0040, grade)) {
            assert_eq!(family, Family::T4x);
            for candidate in &candidates {
                assert!(
                    candidate.dram.is_some(),
                    "grade {grade:#06X}: {} names no DRAM",
                    candidate.chip
                );
                seen += 1;
            }
        }
    }
    assert!(seen >= 12, "only {seen} T4x candidates were produced; the table shrank");
}

/// Every T4x candidate's loader initialises the memory that candidate names.
///
/// **Found by mutation**: flipping the T41ZL candidate from the DDR2 `t41lq` to the DDR3
/// `t41nq` — the DDR2-flashed-as-DDR3 bug, moved from `--cpu` parsing into the candidate
/// table — passed every other test in this file. `det_t4x_candidates_name_their_dram`
/// only asks that a candidate *says* something; nothing asked whether the loader beside
/// it agreed.
///
/// This is the test that closes it, and it is deliberately the same shape as
/// `every_t4x_cpu_arg_picks_a_loader_of_its_own_dram_type`: a candidate list is what an
/// operator flashes from, so a row that names DDR2 and offers the DDR3 loader is the
/// same defect one step further along.
#[test]
fn det_every_t4x_candidate_offers_a_loader_of_its_own_dram_type() {
    // The four T4x loaders and what each initialises: `isvp_t40.h:414-416` / `:427-429`
    // and `isvp_t41.h:444-446` / `:439-441`.
    let loader_dram = [
        (Variant::T40n, DramKind::Ddr2),
        (Variant::T40xp, DramKind::Ddr3),
        (Variant::T41lq, DramKind::Ddr2),
        (Variant::T41nq, DramKind::Ddr3),
    ];

    let mut checked = 0_usize;
    for entry in T4X_GRADES {
        for candidate in entry.candidates {
            let Some(variant) = candidate.variant else {
                // No loader exists for this chip — T41ZM's LPDDR3 and T41ZG's LPDDR2
                // have none at all, and nothing was claimed.
                continue;
            };
            assert_eq!(
                loader_dram.iter().find(|&&(v, _)| v == variant).map(|&(_, kind)| kind),
                Some(candidate.dram.kind),
                "grade {:#06X}: {} is {} but offers the {variant} loader",
                entry.grade,
                candidate.chip,
                candidate.dram.kind
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "only {checked} candidates carry a loader; the table shrank"
    );
}

/// A grade nobody has documented offers **no** candidates rather than plausible ones.
///
/// The list is what an operator flashes from. Inventing a row for an unknown code would
/// be the "unknown" defect with the sign flipped — a fabrication that reads as data.
#[test]
fn det_t4x_unlisted_grade_offers_nothing_to_guess_from() {
    for grade in [0x0000, 0x0001, 0x1234, 0x5A5A, 0xFFFF] {
        let detection = decode(regs_for(0x0040, grade));
        assert!(
            matches!(detection, Detection::Ambiguous { .. }),
            "grade {grade:#06X} must be Ambiguous"
        );
        assert!(
            names(&detection).is_empty(),
            "grade {grade:#06X} offered {:?} for a code nobody has documented",
            names(&detection)
        );
    }
}

/// For T40/T41 `subsoctype2` is the **only** discriminator.
///
/// `soc_id`, `sub1` and `subremark` are identical across the family and `cppsr` is a
/// live clock register that varies per read, so anything that let `sub1` change the
/// answer would be reading noise.
#[test]
fn det_t4x_uses_sub2_only() {
    for sub1 in [0, 0x1111_1111, 0x9999_0000, 0xFFFF_FFFF_u32] {
        let detection = decode(SocRegs::new(0x1004_0003, sub1, 0xAAAA_2222));
        assert_eq!(names(&detection), ["T41NQ"], "sub1 {sub1:#010X} changed the answer");
    }
}

/// `0x7777` is shared with the T41ZN and resolves to the T40XP, which is
/// the only part ever seen with that code.
#[test]
fn det_7777_resolves_t40xp() {
    let detection = decode(SocRegs::new(0x1004_0003, 0, 0x7777_2222));
    assert_eq!(detection.variant(), Some(Variant::T40xp));
    assert_eq!(names(&detection), ["T40XP"]);
}

/// A T4x grade that auto-picks resolves to its first candidate, and that candidate is
/// bench evidence with a loader — the invariant `decode_t4x` relies on.
#[test]
fn det_t4x_autopick_rows_are_bench_evidence() {
    for entry in T4X_GRADES {
        if !entry.auto_picks {
            continue;
        }
        assert!(
            !entry.candidates.is_empty(),
            "grade {:#06X} auto-picks nothing",
            entry.grade
        );
        let Some(pick) = entry.candidates.first() else { continue };
        assert!(
            pick.variant.is_some(),
            "grade {:#06X} picks a chip with no loader",
            entry.grade
        );
        assert_eq!(
            pick.evidence,
            Evidence::Bench,
            "grade {:#06X} auto-picks on something weaker than a capture",
            entry.grade
        );
    }
}

// ---------------------------------------------------------------------------
// T33, graded by its selector byte
// ---------------------------------------------------------------------------

/// **The pin.** A T33 resolves to the `t33` loader with or without its selector, and the
/// selector refines the chip name.
///
/// An earlier implementation answered `Ambiguous` with seven candidates,
/// so a T33 in the bootrom could not be auto-bootstrapped at all. All seven grades share
/// the one `t33` loader, so there was never a loader choice to make. The byte map
/// settles the `soc` script's ambiguous
/// `99/33,AA/44/...` punctuation: `0x33` **and** `0xAA` both mean T33N.
#[test]
fn det_t33_resolves_with_the_selector() {
    const GRADES: &[(u8, &str)] = &[
        (0x99, "T33L"),
        (0x33, "T33N"),
        (0xAA, "T33N"),
        (0x44, "T33A"),
        (0x55, "T33ZL"),
        (0x77, "T33ZN"),
        (0xCC, "T33VL"),
        (0xDD, "T33VN"),
    ];

    for &(byte, chip) in GRADES {
        let regs = SocRegs::new(0x0003_3000, 0, 0).with_t33_selector(u32::from(byte) << 24);
        let detection = decode(regs);
        assert_eq!(names(&detection), [chip], "selector byte {byte:#04X}");
        assert_eq!(
            detection.variant(),
            Some(Variant::T33),
            "every T33 grade shares the one loader"
        );
    }

    // And never `Ambiguous`, for any byte at all.
    for byte in 0..=u8::MAX {
        let regs = SocRegs::new(0x0003_3000, 0, 0).with_t33_selector(u32::from(byte) << 24);
        assert!(
            matches!(decode(regs), Detection::Resolved(_)),
            "selector byte {byte:#04X} did not resolve"
        );
    }
}

/// Without the fourth read a T33 still reaches its loader; only the name is lost.
#[test]
fn det_t33_without_the_selector_still_reaches_the_loader() {
    let regs = SocRegs::new(0x0003_3000, 0, 0);
    assert!(
        needs_t33_selector(regs),
        "the T33 family is what triggers the fourth read"
    );

    let detection = decode(regs);
    assert_eq!(detection.variant(), Some(Variant::T33));
    assert_eq!(names(&detection), ["T33"], "no grade, so no grade's name");

    // Pinned on the wording, because an earlier one was wrong in a way worth guarding
    // against: with no selector there is no grade, and a `caveat()` that formatted
    // `Resolved::grade` unconditionally reported the `0` this module had to put there as
    // though `0x0000` had been read off the device. The loader is right either way — all
    // seven T33 grades share `t33` — but the sentence must not name a register value
    // that was never fetched.
    assert_eq!(
        detection.caveat().as_deref(),
        Some("the T33 grade selector was not read; every T33 grade shares the t33 loader"),
        "the operator is told the grade is unresolved, without a fabricated register value"
    );
}

/// **The value itself carries no fabricated grade**, so a consumer that renders the field
/// without repeating `caveat`'s test cannot print one either.
///
/// The caveat above is one producer's care; this is the property. `Grade` has no way to
/// say `0x0000` unless `0x0000` was read, and formatting it says so in words, which is
/// what the one consumer outside this crate prints for `grade={:#06X}`.
#[test]
fn det_t33_without_the_selector_carries_no_grade() {
    let unread = decode(SocRegs::new(0x0003_3000, 0, 0));
    assert!(matches!(unread, Detection::Resolved(_)), "{unread:?}");
    let Detection::Resolved(unread) = &unread else {
        return;
    };
    assert_eq!(unread.grade, Grade::unread());
    assert_eq!(unread.grade.code(), None, "there is no code, not a code of zero");
    assert_eq!(format!("{:#06X}", unread.grade), "(not read)");

    // And the read path is unchanged: a grade that *was* read formats as the number it is.
    let read = decode(SocRegs::new(0x0003_3000, 0, 0).with_t33_selector(0x0100_0000));
    assert!(matches!(read, Detection::Resolved(_)), "{read:?}");
    let Detection::Resolved(read) = &read else {
        return;
    };
    assert_eq!(read.grade.code(), Some(1));
    assert_eq!(format!("{:#06X}", read.grade), "0x0001");
}

/// Nothing but a T33 asks for the fourth read: one extra read on one family, not a
/// fourth read for everyone.
#[test]
fn det_only_t33_needs_the_selector() {
    for family in Family::ALL {
        let regs = SocRegs::new(u32::from(family.cpu_id()) << 12, 0, 0);
        assert_eq!(
            needs_t33_selector(regs),
            family == Family::T33,
            "{family:?} asked the wrong question"
        );
    }
    assert!(
        !needs_t33_selector(SocRegs::new(0, 0, 0)),
        "an unknown family reads three"
    );
}

// ---------------------------------------------------------------------------
// Whole-table properties
// ---------------------------------------------------------------------------

/// Every family has exactly one table, except T4x which has candidate lists.
#[test]
fn family_tables_cover_every_family() {
    for family in Family::ALL {
        let matched = FAMILY_TABLES.iter().filter(|table| table.family == family).count();
        let expected = usize::from(family != Family::T4x);
        assert_eq!(matched, expected, "{family:?} has {matched} tables");
    }
}

/// No family lists the same grade twice, and no T4x grade appears twice.
///
/// A shadowed row is silent: `find` takes the first, and the second is dead data that
/// reads like a decision.
#[test]
fn no_grade_is_listed_twice() {
    for table in FAMILY_TABLES {
        let mut grades: Vec<u16> = table.rows.iter().map(|row| row.grade).collect();
        let count = grades.len();
        grades.sort_unstable();
        grades.dedup();
        assert_eq!(grades.len(), count, "{:?} lists a grade twice", table.family);
    }

    let mut grades: Vec<u16> = T4X_GRADES.iter().map(|entry| entry.grade).collect();
    let count = grades.len();
    grades.sort_unstable();
    grades.dedup();
    assert_eq!(grades.len(), count, "a T4x grade is listed twice");
}

/// A grade with no row falls back under the **family's** name, never a specific chip's,
/// and always says so.
///
/// A guess must never be rendered as a fact: the C's
/// `detect_variant_from_magic` defaults to T31X on no match and `find_devices`
/// pre-seeds every device with it, so a device whose probe failed reported as a T31X. A
/// fallback that borrowed a real chip's name would do the same thing.
#[test]
fn det_fallback_never_names_a_specific_chip() {
    for table in FAMILY_TABLES {
        // 0x1234 is not a repeated-nibble grade and is not a T33 selector byte, so it
        // matches no row in any family.
        let detection = decode(regs_for(table.family.cpu_id(), 0x1234));
        assert!(
            matches!(detection, Detection::Resolved(_)),
            "{:?} did not resolve an unknown grade",
            table.family
        );
        let Detection::Resolved(resolved) = &detection else {
            continue;
        };
        assert_eq!(resolved.chip, table.fallback_chip, "{:?}", table.family);
        assert_eq!(resolved.variant, table.fallback_variant, "{:?}", table.family);
        assert_eq!(resolved.evidence, Evidence::Convention, "{:?}", table.family);
        assert!(
            !table.rows.iter().any(|row| row.chip == table.fallback_chip),
            "{:?}'s fallback borrows a real chip's name",
            table.family
        );
        assert!(detection.caveat().is_some(), "{:?} must say so", table.family);
    }
}

/// Every grade of every family, decoded: it is either one of that family's rows or the
/// family's fallback. Nothing else is reachable.
///
/// This is the exhaustive direction — 65 536 codes per family — and it is what makes
/// "table-driven" a fact rather than a description.
#[test]
fn det_every_grade_is_a_row_or_the_fallback() {
    for table in FAMILY_TABLES {
        for grade in 0..=u16::MAX {
            // T33 grades are a byte; the widened form above 0xFF cannot occur.
            if table.family == Family::T33 && grade > 0xFF {
                continue;
            }
            let detection = decode(regs_for(table.family.cpu_id(), grade));
            assert!(
                matches!(detection, Detection::Resolved(_)),
                "{:?} grade {grade:#06X} did not resolve",
                table.family
            );
            let Detection::Resolved(resolved) = &detection else {
                continue;
            };
            assert_eq!(resolved.grade, Grade::read(grade), "{:?} lost the grade", table.family);
            if let Some(row) = table.rows.iter().find(|row| row.grade == grade) {
                assert_eq!(resolved.chip, row.chip);
                assert_eq!(resolved.variant, row.variant);
                assert_eq!(resolved.dram, row.dram);
                assert_eq!(resolved.evidence, row.evidence);
            } else {
                assert_eq!(resolved.chip, table.fallback_chip);
                assert_eq!(resolved.variant, table.fallback_variant);
                assert_eq!(resolved.dram, table.fallback_dram);
                assert_eq!(resolved.evidence, Evidence::Convention);
            }
        }
    }
}

/// A `cpu_id` outside the table is `Unknown`, carrying the registers so a bug report can
/// extend the table without another bench session.
#[test]
fn det_unknown_cpu_id_is_unknown() {
    for cpu_id in [0x0000_u16, 0x0002, 0x0022, 0x0034, 0x0041, 0x3000, 0xFFFF] {
        let regs = SocRegs::new(u32::from(cpu_id) << 12, 0x1111_0000, 0x1111_0000);
        let detection = decode(regs);
        assert!(
            matches!(detection, Detection::Unknown { .. }),
            "cpu_id {cpu_id:#06X} decoded to {detection:?}"
        );
        assert_eq!(detection.regs(), regs, "the registers must survive");
        assert_eq!(detection.variant(), None);
        assert_eq!(detection.caveat(), None);
    }
}

/// Every `--cpu` value the answer offers is one `Variant::from_cpu_arg` accepts.
///
/// A candidate list an operator cannot act on is worse than no list: it names a chip,
/// prints a flag, and the flag is refused.
#[test]
fn det_every_offered_cpu_value_is_accepted() {
    for entry in T4X_GRADES {
        for candidate in entry.candidates {
            if let Some(variant) = candidate.variant {
                assert_eq!(
                    Variant::from_cpu_arg(variant.loader_dir()),
                    Some(variant),
                    "{} offers --cpu {variant}, which is refused",
                    candidate.chip
                );
            }
        }
    }
    for table in FAMILY_TABLES {
        for row in table.rows {
            assert_eq!(Variant::from_cpu_arg(row.variant.loader_dir()), Some(row.variant));
        }
        assert_eq!(
            Variant::from_cpu_arg(table.fallback_variant.loader_dir()),
            Some(table.fallback_variant)
        );
    }
}

// ---------------------------------------------------------------------------
// The caveat, and the pin the CLI carries
// ---------------------------------------------------------------------------

/// One pinned caveat per evidence kind, so the sentence a frontend prints is a fixed
/// thing rather than whatever `caveat()` happens to say.
///
/// An earlier implementation carried the evidence and printed none of it; making the
/// sentence part of
/// the value is what stops that, and pinning the text is what stops it drifting.
#[test]
fn det_caveat_is_pinned_for_each_evidence_kind() {
    // Bench: a real capture, so nothing to qualify.
    let bench = decode(SocRegs::new(0x1004_0003, 0, 0xAAAA_2222));
    assert_eq!(bench.caveat(), None);

    // Vendor: documented, never seen here. The wording names no source, because
    // `Evidence::Vendor` spans Ingenic's own configs down to two rows thingino's `soc`
    // script itself flags as guesses.
    let vendor = decode(SocRegs::new(0x0003_1000, 0x4444_0000, 0));
    assert_eq!(names(&vendor), ["T31A"]);
    assert_eq!(
        vendor.caveat().as_deref(),
        Some(
            "T31A is documented but has never been seen on the bench; \
             using the t31a loader; pass --cpu if it misbehaves"
        )
    );
    assert!(
        !vendor.caveat().unwrap_or_default().contains("Ingenic"),
        "the caveat must not claim a source the weaker Vendor rows do not have"
    );

    // Convention: no row matched, so the family's conservative loader was used.
    let convention = decode(SocRegs::new(0x0003_1000, 0xABCD_0000, 0));
    assert_eq!(names(&convention), ["T31"]);
    assert_eq!(
        convention.caveat().as_deref(),
        Some("grade 0xABCD is not in the table; using T31's conservative loader t31x")
    );

    // Ambiguous and Unknown have no caveat: the whole answer is the qualification.
    assert_eq!(decode(SocRegs::new(0x1004_0003, 0, 0x1111_0000)).caveat(), None);
    assert_eq!(decode(SocRegs::new(0, 0, 0)).caveat(), None);
}
