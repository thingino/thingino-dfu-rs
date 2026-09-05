//! The `-l` table for a daemon's devices.
//!
//! # It is the local table, minus what the wire does not carry
//!
//! The C's table is `Index | Bus | Addr | Vendor | Product | Stage |
//! Variant` with `0x%04X` columns (`cli/remote.c:429-433`), and that is provenance, not
//! an obligation. What matters is that `thingino-dfu -l` and
//! `thingino-dfu -l --host cam` describe the same bus in the same words: an operator
//! reads one of them to pick the `-i` for the other, and two vocabularies for one fact is
//! how a `-i 1` lands on the wrong camera.
//!
//! So the columns, the gutters, the lowercase `a108:c309` and the stage names are
//! [`render`](crate::render)'s, through the same layout functions. "The same words" is
//! therefore true of the layout and the vocabulary, and **not** of the content: three
//! things the wire cannot carry are missing, and each is named rather than invented.
//!
//! * **No `Port` column.** The port path is the one identifier that survives a
//!   bootrom → gadget re-enumeration, and the wire's eight-byte entry has no room for
//!   it. An invented column is worse than an absent one.
//! * **The SoC column can say `unknown`,** because the daemon may not know: it reports
//!   `0xFF` for a gadget whose port it has no cached detection for (the C
//!   pre-seeded ordinal 6, `t31x`, instead, and every client rendered that
//!   guess as a fact).
//! * **The SoC column carries no qualification.** Locally it is
//!   `T31X (loader t31x, DDR2)`, built by [`render`](crate::render) from
//!   [`Soc::Detected`](crate::list::Soc::Detected)'s whole [`Detection`]; the wire
//!   carries an ordinal and nothing else, so here it is the loader name alone, `t31x`.
//!   The DRAM and the detection caveat are the facts an operator picks a `--cpu` on
//!   when detection refuses, and they are available where the camera is plugged in.
//!
//! [`Detection`]: tdfu_core::model::Detection

use std::io::{self, Write};

use tdfu_proto::DeviceEntry;

use crate::remote::error::Address;
use crate::render;

/// The columns, in order.
const HEADERS: [&str; 6] = ["#", "Bus", "Addr", "VID:PID", "Stage", "SoC"];

/// Which columns are right-aligned: the three numeric ones, as locally.
const RIGHT: [bool; 6] = [true, true, true, false, false, false];

/// Write the daemon's device list.
///
/// # Errors
/// Whatever `out` raises.
pub fn render(at: &Address, entries: &[DeviceEntry], out: &mut dyn Write) -> io::Result<()> {
    if entries.is_empty() {
        // The C prints `Found 0 device(s) (remote):` (`cli/remote.c:423`) and then a
        // table with no rows (`:424-425` are the header and the rule), which reads as a
        // formatting accident. The local tool says it in words (`render::NONE_FOUND`) and
        // this says the same words plus where. [citation corrected 2026-09-03]
        return writeln!(out, "{} on {at}", render::NONE_FOUND);
    }

    let count = entries.len();
    let plural = if count == 1 { "device" } else { "devices" };
    writeln!(out, "Found {count} {plural} on {at}:")?;
    writeln!(out)?;

    let cells: Vec<Vec<String>> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| cells_of(index, *entry))
        .collect();
    let widths = render::widths(&HEADERS, &cells);
    writeln!(out, "{}", render::line(&HEADERS.map(String::from), &widths, &RIGHT))?;
    for row in &cells {
        writeln!(out, "{}", render::line(row, &widths, &RIGHT))?;
    }
    Ok(())
}

/// One row's cells, before padding.
fn cells_of(index: usize, entry: DeviceEntry) -> Vec<String> {
    vec![
        index.to_string(),
        entry.bus.to_string(),
        entry.address.to_string(),
        format!("{:04x}:{:04x}", entry.vendor, entry.product),
        stage_name(entry.stage),
        // `WireVariant`'s own `Display` renders an ordinal outside the frozen table as
        // `unknown`, which is the wire's rule and one this client must not second-guess.
        entry.variant.to_string(),
    ]
}

/// The wire's stage byte, in the local table's vocabulary.
///
/// `2` is `gadget`, not the C's `dfu` (`cli/remote.c:429`): `Stage::Gadget`'s `Display`
/// is what `-l` prints locally, and one word per state is the point.
fn stage_name(stage: u8) -> String {
    match stage {
        0 => "bootrom".to_owned(),
        1 => "firmware".to_owned(),
        2 => "gadget".to_owned(),
        // Never guessed. The C's ternary chain folds every unknown byte into `bootrom`
        // (`cli/remote.c:429`), so a daemon reporting a stage this client does not know
        // would have its devices listed as ready to USB-boot.
        other => format!("stage {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, DeviceEntry, render};
    use tdfu_proto::WireVariant;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn at() -> Address {
        Address::new("camera.invalid", 5050)
    }

    fn text(entries: &[DeviceEntry]) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        render(&at(), entries, &mut out)?;
        Ok(String::from_utf8(out)?)
    }

    fn entry(bus: u8, address: u8, stage: u8, variant: WireVariant) -> DeviceEntry {
        DeviceEntry {
            bus,
            address,
            vendor: 0xA108,
            product: 0xC309,
            stage,
            variant,
        }
    }

    /// **The remote-table pin.** The whole table, exactly, in the local table's shape.
    #[test]
    fn rpc_cli_remote_table() -> TestResult {
        let entries = [
            entry(1, 7, 0, WireVariant(6)),
            entry(1, 9, 2, WireVariant::UNKNOWN),
            entry(2, 11, 1, WireVariant(24)),
        ];
        assert_eq!(
            text(&entries)?,
            "\
Found 3 devices on camera.invalid:5050:

  #  Bus  Addr  VID:PID    Stage     SoC
  0    1     7  a108:c309  bootrom   t31x
  1    1     9  a108:c309  gadget    unknown
  2    2    11  a108:c309  firmware  t41nq
"
        );
        Ok(())
    }

    /// One device is a *device*, as locally.
    #[test]
    fn one_device_reads_as_one_device() -> TestResult {
        let rendered = text(&[entry(1, 7, 0, WireVariant(6))])?;
        assert!(
            rendered.starts_with("Found 1 device on camera.invalid:5050:\n"),
            "{rendered}"
        );
        Ok(())
    }

    /// An empty bus says so in words, and says whose bus.
    #[test]
    fn an_empty_remote_bus_says_so() -> TestResult {
        assert_eq!(text(&[])?, "No Ingenic devices found on camera.invalid:5050\n");
        Ok(())
    }

    /// A stage byte this build does not know is printed, never folded into `bootrom` —
    /// which is what the C's ternary chain does (`cli/remote.c:429`), and `bootrom` is
    /// the one stage a transfer will try to USB-boot.
    #[test]
    fn an_unknown_stage_is_never_guessed() -> TestResult {
        let rendered = text(&[entry(1, 7, 9, WireVariant(6))])?;
        assert!(rendered.contains("stage 9"), "{rendered}");
        assert!(!rendered.contains("bootrom"), "{rendered}");
        Ok(())
    }
}
