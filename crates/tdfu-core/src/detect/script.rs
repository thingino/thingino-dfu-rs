//! `det_table_matches_thingino_soc` — the decode table, diffed against the shipped
//! `soc` script in both directions.
//!
//! `thingino-firmware/package/thingino-system/files/soc` reads the *same three
//! registers* on a running camera (`devmem 0x1300002C / 0x13540238 / 0x13540250`) and
//! carries the newer grade list, so it is an independent implementation of this table
//! and the thing to stay in sync with, not the C. A committed copy is
//! `crates/tdfu-core/tests/fixtures/thingino-soc.sh`.
//!
//! **Why this test exists.** The C decodes these registers twice, into a variant chain
//! (`protocol.c:664-770`) and a chip-name chain (`protocol.c:774-824`), and the two
//! disagree: a T30A takes the `t30a` loader and is *named* `"T30"`; a T32NQ takes the
//! `t32nq` loader and is named `"T32"`. Nothing in the C tree checks either against
//! anything. Here the table is one thing and a machine compares it with an independent
//! source every run.
//!
//! Everything the script and this table deliberately differ about is written down here
//! as data — `SCRIPT_NAME_REFINEMENTS` and `NOT_IN_THE_SCRIPT` — and both are asserted
//! to be fully used, so a stale exemption fails the test rather than hiding a drift.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{FAMILY_TABLES, T4X_GRADES, decode};
use crate::model::Family;

/// The committed copy of thingino's on-device `soc` script.
fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/tdfu-core/tests/fixtures/thingino-soc.sh")
}

/// One `case` arm: a `cpu_id`, a grade code and the name the script prints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScriptRow {
    cpu_id: u16,
    grade: u16,
    /// Upper-cased, so it compares with a table row's `chip` directly.
    chip: String,
    line: usize,
}

/// Which `case` block a line is inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    /// `if [ "$cpuid" -eq $((0xNN)) ]` — the arms are grade codes for that family.
    Grade(u16),
    /// The final `else`, where the arms are `(cpu_id << 16) | type1` signatures.
    CpuSig,
    None,
}

/// Every `0x…` literal in `text`, in order.
fn hex_literals(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'0' && (bytes[index + 1] == b'x' || bytes[index + 1] == b'X') {
            let start = index + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                if let Ok(value) = u32::from_str_radix(&text[start..end], 16) {
                    found.push(value);
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    found
}

/// Parse the script's three grade blocks and its signature block.
///
/// Commented-out arms are skipped, which is load-bearing: the script deliberately
/// comments out `t41n` (soc:77) and `t41zn` (soc:83) because their codes collide with
/// `t40nn` and `t40xp`, and treating either as live would assert the opposite of the
/// refuse-to-choose rule.
fn parse_script(text: &str) -> Vec<ScriptRow> {
    let mut block = Block::None;
    let mut rows = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.split("-eq $((").nth(1)
            && let Some(&cpu_id) = hex_literals(rest).first()
        {
            block = Block::Grade(u16::try_from(cpu_id).unwrap_or(u16::MAX));
            continue;
        }
        if line.contains("cpu_sig=") {
            block = Block::CpuSig;
            continue;
        }

        let Some((prefix, tail)) = line.split_once("soc=\"") else {
            continue;
        };
        let Some((chip, _)) = tail.split_once('"') else {
            continue;
        };
        for literal in hex_literals(prefix) {
            match block {
                Block::Grade(cpu_id) => rows.push(ScriptRow {
                    cpu_id,
                    grade: u16::try_from(literal).unwrap_or(u16::MAX),
                    chip: chip.to_ascii_uppercase(),
                    line: index + 1,
                }),
                Block::CpuSig => rows.push(ScriptRow {
                    cpu_id: u16::try_from(literal >> 16).unwrap_or(u16::MAX),
                    grade: u16::try_from(literal & 0xFFFF).unwrap_or(u16::MAX),
                    chip: chip.to_ascii_uppercase(),
                    line: index + 1,
                }),
                Block::None => {}
            }
        }
    }
    rows
}

/// Where this table is deliberately more specific than the script.
///
/// One entry, and it is the T10: the script has no grade register to refine with and
/// prints `t10` (soc:119), while the C refines it to T10L because only T10L silicon has
/// ever been seen (`dfu.c:1086-1089`, `protocol.c:665-668`) — and the bench agrees
/// (`result-t10l.txt`).
const SCRIPT_NAME_REFINEMENTS: &[(&str, &str)] = &[("T10", "T10L")];

/// Rows this table carries that the script does not name, all from Ingenic's
/// headers.
///
/// Every one is a T41-line chip whose grade code collides with a T40-line chip, or a
/// grade the script never listed. The script *knows* about the first two — it carries
/// them as commented-out arms (soc:77, soc:83) precisely because the code is shared —
/// the whole rule is that a shared code must name both lines and refuse to
/// choose.
const NOT_IN_THE_SCRIPT: &[&str] = &["T40A", "T41LC", "T41N", "T41ZMC", "T41ZGC", "T41ZN"];

fn refine(chip: &str) -> String {
    SCRIPT_NAME_REFINEMENTS
        .iter()
        .find(|(from, _)| *from == chip)
        .map_or_else(|| chip.to_owned(), |(_, to)| (*to).to_owned())
}

/// Every chip name this table offers for a `(cpu_id, grade)` pair.
fn table_names(cpu_id: u16, grade: u16) -> Vec<&'static str> {
    if cpu_id == Family::T4x.cpu_id() {
        return T4X_GRADES
            .iter()
            .find(|entry| entry.grade == grade)
            .map(|entry| entry.candidates.iter().map(|c| c.chip).collect())
            .unwrap_or_default();
    }
    FAMILY_TABLES
        .iter()
        .filter(|table| table.family.cpu_id() == cpu_id)
        .flat_map(|table| table.rows.iter())
        .filter(|row| row.grade == grade)
        .map(|row| row.chip)
        .collect()
}

/// **The pin.** The decode table and thingino's `soc` script agree, both ways.
#[test]
fn det_table_matches_thingino_soc() -> Result<(), std::io::Error> {
    let text = std::fs::read_to_string(script_path())?;
    let rows = parse_script(&text);

    // A parser that silently matched nothing would make every assertion below vacuous.
    assert!(
        rows.len() >= 60,
        "only {} arms parsed out of the soc script; the parser broke",
        rows.len()
    );
    assert!(
        rows.iter().any(|row| row.chip == "T33N" && row.grade == 0xAA),
        "the T33 block did not parse: `$((0x33)) | $((0xAA)))` is the only two-pattern arm"
    );

    let mut used_refinements = BTreeSet::new();
    let mut used_exemptions = BTreeSet::new();

    // ---- forward: every arm the script decodes, this table names too ----
    for row in &rows {
        // The script's own fallbacks, and emulator signatures that no bootrom produces.
        if row.chip.starts_with("QEMU-") || row.chip.starts_with("UNKNOWN") {
            continue;
        }
        let expected = refine(&row.chip);
        if expected != row.chip {
            used_refinements.insert(row.chip.clone());
        }
        let offered = table_names(row.cpu_id, row.grade);
        assert!(
            offered.iter().any(|name| *name == expected),
            "soc:{} says cpu {:#06X} grade {:#06X} is {expected}; the table offers {offered:?}",
            row.line,
            row.cpu_id,
            row.grade
        );

        // And the answer `decode` actually produces must carry it, not just the table.
        let regs = super::tests::regs_for(row.cpu_id, row.grade);
        let detection = decode(regs);
        let decoded = super::tests::names(&detection);
        assert!(
            decoded.iter().any(|name| *name == expected),
            "soc:{} says {expected}; decode answered {decoded:?}",
            row.line
        );
    }

    // ---- reverse: every row this table carries is one the script names ----
    let mut check_reverse = |cpu_id: u16, grade: u16, chip: &'static str| {
        let named = rows
            .iter()
            .filter(|row| row.cpu_id == cpu_id && row.grade == grade)
            .any(|row| refine(&row.chip) == chip);
        if named {
            return;
        }
        assert!(
            NOT_IN_THE_SCRIPT.contains(&chip),
            "cpu {cpu_id:#06X} grade {grade:#06X} is {chip} here and the soc script does not say so"
        );
        used_exemptions.insert(chip);
    };

    for table in FAMILY_TABLES {
        for row in table.rows {
            check_reverse(table.family.cpu_id(), row.grade, row.chip);
        }
    }
    for entry in T4X_GRADES {
        for candidate in entry.candidates {
            check_reverse(Family::T4x.cpu_id(), entry.grade, candidate.chip);
        }
    }

    // ---- neither exemption list is allowed to rot ----
    let declared: BTreeSet<&str> = SCRIPT_NAME_REFINEMENTS.iter().map(|(from, _)| *from).collect();
    let used: BTreeSet<&str> = used_refinements.iter().map(String::as_str).collect();
    assert_eq!(used, declared, "an unused entry in SCRIPT_NAME_REFINEMENTS");

    let declared: BTreeSet<&str> = NOT_IN_THE_SCRIPT.iter().copied().collect();
    assert_eq!(used_exemptions, declared, "an unused entry in NOT_IN_THE_SCRIPT");

    Ok(())
}

/// The parser itself, on arms whose shape the test depends on.
///
/// A test double that quietly parses nothing is worse than no test at all, and this
/// parser *is* the double for the script.
#[test]
fn the_script_parser_reads_all_four_block_shapes() {
    let sample = "\
if [ \"$cpuid\" -eq $((0x40)) ]; then
    $((0x7777))) soc=\"t40xp\" ;;
    #$((0x7777))) soc=\"t41zn\" ;; # overlap with t40xp
elif [ \"$cpuid\" -eq $((0x33)) ]; then
    $((0x33)) | $((0xAA))) soc=\"t33n\" ;;
    *) soc=\"unknown_t33\" ;;
else
    cpu_sig=$(printf '0x%08X' $(((cpuid << 16) | $type1)))
    0x00312222) soc=\"t31x\" ;;
    0x0031EE00) soc=\"qemu-t31\" ;;
fi";
    let rows = parse_script(sample);

    assert_eq!(
        rows,
        vec![
            ScriptRow {
                cpu_id: 0x0040,
                grade: 0x7777,
                chip: "T40XP".into(),
                line: 2
            },
            ScriptRow {
                cpu_id: 0x0033,
                grade: 0x0033,
                chip: "T33N".into(),
                line: 5
            },
            ScriptRow {
                cpu_id: 0x0033,
                grade: 0x00AA,
                chip: "T33N".into(),
                line: 5
            },
            ScriptRow {
                cpu_id: 0x0031,
                grade: 0x2222,
                chip: "T31X".into(),
                line: 9
            },
            ScriptRow {
                cpu_id: 0x0031,
                grade: 0xEE00,
                chip: "QEMU-T31".into(),
                line: 10
            },
        ],
        "a commented-out arm must be skipped, a two-pattern arm must yield two rows, \
         and a signature arm must split into cpu_id and grade"
    );
}
