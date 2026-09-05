//! The `-l` table.
//!
//! **The format is ours**: byte-identical output is no longer a goal,
//! so this emits what is genuinely useful and is pinned by tests because it is now our
//! contract with whoever pipes it. It is not the C's table, and the differences are
//! deliberate:
//!
//! * **The port path is a column.** It is the one identifier that
//!   survives the bootrom → gadget re-enumeration, and the index-0 bench failure (a
//!   T40XP erased twice instead of a T40N because a leftover device held index 0) is
//!   exactly the case where an operator needs to tell two identical cameras apart. It
//!   is rendered the way Linux names it (`1-4.2`), so it can be pasted into
//!   `/sys/bus/usb/devices/` or grepped out of `dmesg`.
//! * **VID:PID is lowercase and colon-joined**, as `lsusb` prints it, rather than the
//!   C's two `0x%04X` columns. It is the form an operator already has on screen.
//! * **A qualified answer carries its qualification.** [`Detection::caveat`] prints on
//!   the line under the row. An earlier implementation had the evidence and printed none
//!   of it, so the whole mechanism was dead data; the pin
//!   `cli_surfaces_the_detection_caveat` is what keeps it alive.
//! * **Nothing is invented.** A gadget's SoC column is `-`, never the C's pre-seeded
//!   `t31x` (`cli/main.c:213`).
//!
//! The table goes to stdout and the narration ("Scanning...", the banner, `--wait`)
//! goes to stderr, so `thingino-dfu -l > devices.txt` gets data and nothing else.

use core::fmt::Write as _;
use std::io::{self, Write};

use tdfu_core::model::{Candidate, Detection, DfuInfo, Family, GradeSource, Resolved, SocRegs};
use tdfu_core::progress::{Phase, Progress};

use crate::list::{Listing, Row, Soc, Unavailable};

/// Printed to **stderr** before the scan, because opening each bootrom and reading its
/// registers takes a moment and silence reads as a hang.
pub const SCANNING: &str = "Scanning for Ingenic devices...";

/// The whole answer when the bus has none. Exit 0 — see [`list`](crate::list::list).
pub const NONE_FOUND: &str = "No Ingenic devices found";

/// Two spaces between columns, and two before the first.
const GUTTER: &str = "  ";

/// Every [`Phase`] a wire `stage` byte can name.
///
/// `tdfu_core::progress::Phase` defines `wire_byte` and no inverse, so a client that
/// receives one has to search. The **byte values still come from core** — this is a list
/// of variants, not a second copy of the discriminants (a second copy existed once and
/// was deleted), so a discriminant that moved in core moves here with it, and
/// `every_wire_phase_round_trips` is the pin. A byte outside this list renders as itself.
const WIRE_PHASES: [Phase; 8] = [
    Phase::Unknown,
    Phase::Stage1,
    Phase::UBoot,
    Phase::Download,
    Phase::Manifest,
    Phase::Upload,
    Phase::Verify,
    Phase::Erase,
];

/// The phase a wire `stage` byte names, or `None` for one this build does not know.
fn wire_phase(stage: u8) -> Option<Phase> {
    WIRE_PHASES.into_iter().find(|phase| phase.wire_byte() == stage)
}

/// Where a note under a row starts. Fixed rather than derived from the index column, so
/// a bus with ten devices does not reflow every note.
const NOTE_INDENT: &str = "     ";

/// Text from a peer, made safe to put on a terminal.
///
/// Every string a `dfu-remote` daemon sends is written to the operator's screen: log
/// frames, the message inside a progress frame, the body of a refusal, the `--diag`
/// report. The transport is plain TCP with no integrity protection, and the optional
/// token authenticates the *client to the daemon* and never the daemon to the client, so
/// those bytes are not this tool's to trust. Control characters in them do not get read,
/// they get **executed**: `ESC` opens a sequence that can clear the screen or move the
/// cursor, a bare `\r` discards whatever this client has just printed on the line, and a
/// fabricated success line written over the real failure is one an operator has no way to
/// see through. UTF-8 validity is no defence, because every one of those is valid UTF-8.
///
/// So each C0 byte other than `\n` and `\t` becomes its caret form (`^[` for `ESC`, `^M`
/// for `\r`), `DEL` becomes `^?`, and each C1 code point becomes `<U+00XX>`. The
/// introducer is what makes an escape sequence an escape sequence, so replacing it
/// disarms the whole run and leaves the parameters after it as the plain text they always
/// were. Newline and tab survive because a log frame is a line of text and both belong in
/// one.
#[must_use]
pub fn sanitise(text: &str) -> String {
    visible(text, true)
}

/// [`sanitise`], for text that has to stay on **one** line.
///
/// [`Bar`] rewrites its line from column zero and blanks it by the width it last drew, so
/// a message carrying a newline has already moved the cursor down and leaves debris that
/// [`Bar::clear`] cannot reach: the `\r` goes back to the start of the *last* physical
/// line and blanks the wrong text at the wrong width. A progress message is one line by
/// construction on this side; this is what makes it one when a peer wrote it.
#[must_use]
pub fn sanitise_line(text: &str) -> String {
    visible(text, false)
}

/// The replacement itself. `newlines` keeps `\n` as a newline rather than showing it.
fn visible(text: &str, newlines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\t' => out.push('\t'),
            '\n' if newlines => out.push('\n'),
            // `char::is_control` is exactly C0, `DEL` and C1, which is the whole of what
            // a terminal acts on rather than prints.
            control if control.is_control() => {
                let code = control as u32;
                if code < 0x20 || code == 0x7F {
                    out.push('^');
                    // A control byte's caret letter is itself plus 0x40: `ESC` (0x1B) is
                    // `^[`, and `DEL` (0x7F) wraps to `?`. The fallback is unreachable
                    // for those two ranges and is a character rather than a panic.
                    out.push(char::from_u32((code + 0x40) % 0x80).unwrap_or('?'));
                } else {
                    let _ = write!(out, "<U+{code:04X}>");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The columns, in order.
const HEADERS: [&str; 7] = ["#", "Bus", "Addr", "Port", "VID:PID", "Stage", "SoC"];

/// Which columns are right-aligned: the three numeric ones.
const RIGHT: [bool; 7] = [true, true, true, false, false, false, false];

/// Write the listing.
///
/// # Errors
/// Whatever `out` raises.
pub fn render(listing: &Listing, out: &mut dyn Write) -> io::Result<()> {
    if listing.is_empty() {
        return writeln!(out, "{NONE_FOUND}");
    }

    let count = listing.rows.len();
    let plural = if count == 1 { "device" } else { "devices" };
    writeln!(out, "Found {count} {plural}:")?;
    writeln!(out)?;

    let cells: Vec<Vec<String>> = listing.rows.iter().map(cells_of).collect();
    let widths = widths(&HEADERS, &cells);

    writeln!(out, "{}", line(&HEADERS.map(String::from), &widths, &RIGHT))?;
    for (row, cells) in listing.rows.iter().zip(&cells) {
        writeln!(out, "{}", line(cells, &widths, &RIGHT))?;
        for note in notes_of(row) {
            writeln!(out, "{NOTE_INDENT}{note}")?;
        }
    }
    Ok(())
}

/// One row's cells, before padding.
fn cells_of(row: &Row) -> Vec<String> {
    let descriptors = &row.descriptors;
    vec![
        row.index.to_string(),
        descriptors.bus.to_string(),
        descriptors.address.to_string(),
        port_path(descriptors.bus, &descriptors.port_path),
        format!("{:04x}:{:04x}", descriptors.vendor_id, descriptors.product_id),
        row.stage
            .map_or_else(|| "unknown".to_owned(), |stage| stage.to_string()),
        soc_cell(&row.soc),
    ]
}

/// The port path as Linux names the device: `bus-port.port`.
///
/// Empty on Android and wasm, where the platform does not expose it; a
/// bare `-` then, because an invented path is worse than an absent one.
fn port_path(bus: u8, path: &[u8]) -> String {
    if path.is_empty() {
        return "-".to_owned();
    }
    let mut rendered = bus.to_string();
    for (position, port) in path.iter().enumerate() {
        let separator = if position == 0 { '-' } else { '.' };
        // Writing into a String cannot fail; the result is discarded rather than
        // unwrapped because the workspace denies `unwrap` and there is nothing to
        // report.
        let _ = write!(rendered, "{separator}{port}");
    }
    rendered
}

/// The SoC column.
fn soc_cell(soc: &Soc) -> String {
    match soc {
        // A gadget, a firmware-stage device, or an Ingenic VID with no rule. The C
        // would print a variant here for a gadget because it pre-seeds one; we do not
        // guess.
        Soc::NotProbed => "-".to_owned(),
        Soc::Detected(Detection::Resolved(resolved)) => resolved_cell(resolved),
        Soc::Detected(Detection::Ambiguous { .. }) => "ambiguous".to_owned(),
        Soc::Detected(_) => "unknown".to_owned(),
        Soc::Unavailable(_) => "unavailable".to_owned(),
    }
}

/// `T41NQ (loader t41nq, DDR3 16-bit)` — the chip, the loader `--cpu` would name, and
/// what that loader initialises.
///
/// The DRAM is here rather than in a note because it is the fact an operator picks a
/// `--cpu` value on, and an audit found six candidates reporting the literal string
/// `"unknown"` where Ingenic's own header is explicit. Where Ingenic documents nothing,
/// nothing is printed.
fn resolved_cell(resolved: &Resolved) -> String {
    let mut cell = format!("{} (loader {}", resolved.chip, resolved.variant);
    if let Some(dram) = resolved.dram {
        let _ = write!(cell, ", {dram}");
    }
    cell.push(')');
    cell
}

/// A line under a row: a qualification, or a reason the row is thin.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Note {
    /// Something the operator should know about an answer that *is* an answer.
    Note(String),
    /// Something that stopped an answer.
    Error(String),
}

impl core::fmt::Display for Note {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Note(text) => write!(f, "note: {text}"),
            Self::Error(text) => write!(f, "error: {text}"),
        }
    }
}

/// The alts a probed gadget offers.
///
/// The C prints this block after the table when the targeted index is a gadget
/// (`cli/main.c:478-490`), and it is the only way to find out what `--alt` will accept
/// on a loader you have not seen before. Two differences, both additions:
///
/// * **the default is marked.** The rule (the alt named `flash`, else the
///   only alt) is invisible otherwise, and "which alt does `-w` write to" is exactly
///   the question this block is read to answer;
/// * **a nameless alt says so** rather than printing a bare pair of quotes. An alt whose
///   string the backend could not read is nameless, and `""` reads as a bug
///   in the tool.
///
/// # Errors
/// Whatever `out` raises.
pub fn alts(index: u8, info: &DfuInfo, default_alt: Option<u8>, out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        // bcdDFU is binary-coded decimal: 0x0110 renders as 1.10, never 1.16.
        "\nDFU device {index}: {} alt setting(s), transfer size {} bytes, DFU {:x}.{:02x}",
        info.alts.len(),
        info.transfer_size,
        info.bcd_dfu >> 8,
        info.bcd_dfu & 0xFF,
    )?;
    for alt in &info.alts {
        let name = if alt.name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            format!("{:?}", alt.name)
        };
        let marker = if Some(alt.alt) == default_alt {
            "  (default)"
        } else {
            ""
        };
        writeln!(out, "  alt {}: {name}{marker}", alt.alt)?;
    }
    Ok(())
}

/// The lines a detection wants an operator to read, ready for stderr.
///
/// The same [`Note`]s the `-l` table prints under a row, without the table around them,
/// so a bootstrap that cannot pick a loader says exactly what `-l` would have said about
/// the same device — the caveat first, then the candidate list and what to pass.
///
/// Sharing the producer is the point. `Detection::caveat()` exists because an earlier
/// implementation had the evidence and printed none of it; a bootstrap-only
/// wording would be the same mistake with an extra copy to forget to update.
#[must_use]
pub fn detection_advice(detection: &Detection) -> Vec<String> {
    detection_notes(detection).iter().map(ToString::to_string).collect()
}

/// Every line that belongs under `row`.
fn notes_of(row: &Row) -> Vec<Note> {
    match &row.soc {
        Soc::NotProbed => Vec::new(),
        Soc::Unavailable(unavailable) => vec![Note::Error(unavailable_text(unavailable))],
        Soc::Detected(detection) => detection_notes(detection),
    }
}

/// The caveat, plus whatever an unresolved answer needs the operator to do.
fn detection_notes(detection: &Detection) -> Vec<Note> {
    let mut notes = Vec::new();
    // **The pin.** `Detection::warning` is computed from the value so a frontend cannot
    // forget to derive it, only to print it, and `cli_surfaces_the_detection_caveat`
    // is why this line cannot be deleted. The provenance-only
    // sentence (`Detection::caveat` on a documented-but-unseen row) is a debug line,
    // decided 2026-09-03.
    if let Some(caveat) = detection.warning() {
        notes.push(Note::Note(caveat));
    } else if let Some(provenance) = detection.caveat() {
        tracing::debug!("{provenance}");
    }
    match detection {
        Detection::Ambiguous {
            regs,
            family,
            candidates,
        } => notes.push(Note::Note(ambiguous_text(*regs, *family, candidates))),
        Detection::Unknown { regs } => notes.push(Note::Note(unknown_text(*regs))),
        _ => {}
    }
    notes
}

/// What to do about a grade that names more than one chip (decision D4).
fn ambiguous_text(regs: SocRegs, family: Family, candidates: &[Candidate]) -> String {
    let grade = grade_text(regs, family);
    if candidates.is_empty() {
        // An invented row here would be bug 4 with the sign flipped: a fabricated
        // candidate is worse than a short list, because the operator would flash it.
        return format!(
            "{grade} of family {family:?} is documented on neither product line; \
             pass --cpu with the loader for this part, or stream --spl and --uboot"
        );
    }
    let listed: Vec<String> = candidates.iter().map(ToString::to_string).collect();
    format!(
        "{grade} of family {family:?} names more than one chip; pass --cpu: {}",
        listed.join(", ")
    )
}

/// The grade code, read from **the register that family is graded by**.
///
/// Only family `0x0040` produces [`Detection::Ambiguous`] today, and it is graded by
/// `subsoctype2` — but hardcoding `sub2` here would print a value from the wrong
/// register the day another family does. [`Family::grade_source`] is the same answer
/// `decode` itself uses, so the two cannot drift.
fn grade_text(regs: SocRegs, family: Family) -> String {
    let grade = match family.grade_source() {
        GradeSource::SubSocType1 => Some(u32::from(regs.sub1())),
        GradeSource::SubSocType2 => Some(u32::from(regs.sub2())),
        GradeSource::T33Selector => regs.t33_grade().map(u32::from),
        // `GradeSource` is `#[non_exhaustive]`: a register added later has no format
        // here yet, and saying "the grade" is better than printing another one's value.
        _ => None,
    };
    grade.map_or_else(|| "the grade".to_owned(), |grade| format!("grade {grade:#06X}"))
}

/// A `cpu_id` that is not in the table at all.
fn unknown_text(regs: SocRegs) -> String {
    format!(
        "soc_id {:#010X} (cpu_id {:#06X}) is not in the table; pass --cpu, \
         or stream --spl and --uboot",
        regs.soc_id,
        regs.cpu_id()
    )
}

/// Why a row could not be filled in, and the fix where there is one: **once**, in one
/// wording.
fn unavailable_text(unavailable: &Unavailable) -> String {
    match unavailable.hint {
        Some(hint) => format!("{}; {hint}", unavailable.reason),
        None => unavailable.reason.clone(),
    }
}

/// Column widths: the widest cell, never narrower than the header.
///
/// Slices rather than the local table's fixed seven, because the remote table
/// ([`remote::table`](crate::remote::table)) has six — no `Port` column, since the port
/// path that is the one stable identifier is not on the wire.
/// Two layout engines would be two tables that look alike until one of them is edited.
pub(crate) fn widths(headers: &[&str], cells: &[Vec<String>]) -> Vec<usize> {
    let mut widths: Vec<usize> = headers.iter().copied().map(str::len).collect();
    for row in cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    widths
}

/// One padded line, with no trailing whitespace: the last column is never padded.
pub(crate) fn line(cells: &[String], widths: &[usize], right: &[bool]) -> String {
    let mut out = String::new();
    for (position, cell) in cells.iter().enumerate() {
        out.push_str(GUTTER);
        let last = position + 1 == cells.len();
        let pad = widths
            .get(position)
            .copied()
            .unwrap_or_default()
            .saturating_sub(cell.chars().count());
        if right.get(position).copied().unwrap_or_default() {
            for _ in 0..pad {
                out.push(' ');
            }
            out.push_str(cell);
        } else {
            out.push_str(cell);
            if !last {
                for _ in 0..pad {
                    out.push(' ');
                }
            }
        }
    }
    out
}

/// What an operation is saying about itself, on stderr.
///
/// One object for a whole run, because the two kinds of [`Progress`] interleave and the
/// second has to know about the first: [`Progress::Note`] is a line core wants read and
/// kept, and [`Progress::Bytes`] is a counter that should overwrite itself rather than
/// scroll a 256 MiB read off the screen at one line per 4 KiB block.
///
/// # Notes are printed exactly once, verbatim
///
/// Every completion line — `DFU download complete`, `Verify OK: N bytes match`,
/// `DFU upload complete: N bytes`, both retry announcements — is emitted by
/// `tdfu-core`, once, from one place. This renders them and adds
/// none of its own, because a frontend
/// printing its own byte count would double the line.
///
/// # The counter is throttled by what it would say, not by a clock
///
/// A 256 MiB read emits 65 536 [`Progress::Bytes`], and drawing each one is both
/// pointless and slow. Throttling on elapsed time would make the output depend on how
/// fast the machine is, which no test can pin; throttling on the *rendered value*
/// cannot — [`tick`](Bar::tick) is the percentage when the total is known and the
/// megabyte when it is not, so the same transfer always draws the same lines whatever
/// the hardware does. That is what makes [`bar_is_throttled_by_value_not_by_time`] a
/// test rather than a flake.
///
/// # Cursor handling is one carriage return
///
/// No ANSI, no terminal detection, no dependency: the line is rewritten from column
/// zero and padded to cover whatever the previous one left behind, and a note first
/// blanks it. On a captured (non-tty) stderr that leaves the `\r`s in the byte stream,
/// which is why the tests assert on **content**.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Bar {
    /// How wide the line currently on screen is, so the next one can cover it.
    drawn: usize,
    /// The last value drawn, to throttle by — `None` before the first draw of a phase.
    ///
    /// **Two different kinds of number live here**, and neither is ever compared with the
    /// other: [`bytes`](Bar::bytes) stores [`tick`](Bar::tick)'s percentage-or-mebibyte,
    /// and [`wire`](Bar::wire) stores [`tick_of`](Bar::tick_of)'s FNV-1a hash of the whole
    /// rendered line. A local run and a `--host` run never share a `Bar`, so the two
    /// cannot meet; if they ever did, the worst a collision costs is one skipped redraw.
    last: Option<u64>,
}

impl Bar {
    /// A bar with nothing drawn yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { drawn: 0, last: None }
    }

    /// Render one [`Progress`].
    ///
    /// A failed write to `err` is swallowed: a closed pipe is not a reason to abandon a
    /// flash mid-way, which is the reasoning `main` already applies to the banner.
    pub fn render(&mut self, progress: &Progress, err: &mut dyn Write) {
        match progress {
            Progress::Note(text) => self.note(text, err),
            Progress::Phase(phase) => {
                // A new phase restarts the counter: a write's `Download` and its
                // `Manifest` are different scales, and a verify after a write starts
                // from zero again.
                self.last = None;
                tracing::debug!(?phase, "phase");
            }
            Progress::Bytes { phase, done, total } => self.bytes(*phase, *done, *total, err),
            // Core's protocol narration. It goes to `tracing`, which is `-d`'s channel
            // and the bar's business is not: a user who did not ask for detail sees the
            // counter and the notes, and `-d` gets core's lines interleaved with the
            // CLI's own at the same level. Never written to `err` directly, because that
            // is where the bar draws and a line there would blank the counter.
            Progress::Debug(text) => tracing::debug!("{text}"),
            // `Progress` is `#[non_exhaustive]`; a kind added later is logged rather
            // than dropped, and never printed, because only the two above are known to
            // be user-facing.
            other => tracing::debug!(?other, "progress"),
        }
    }

    /// A line the user keeps. Blanks the counter first so the two never collide.
    pub fn note(&mut self, text: &str, err: &mut dyn Write) {
        self.clear(err);
        let _ignored = writeln!(err, "{text}");
    }

    /// Blank whatever the counter last drew, leaving the cursor at column zero.
    ///
    /// Call it before writing anything else to stderr, and once at the end of a run.
    pub fn clear(&mut self, err: &mut dyn Write) {
        if self.drawn == 0 {
            return;
        }
        let _ignored = write!(err, "\r{:width$}\r", "", width = self.drawn);
        self.drawn = 0;
        self.last = None;
    }

    /// Draw the counter, if it would say something new.
    fn bytes(&mut self, phase: Phase, done: u64, total: Option<u64>, err: &mut dyn Write) {
        let tick = Self::tick(done, total);
        if self.last == Some(tick) {
            return;
        }
        self.last = Some(tick);
        // The line is built *after* the throttle, not before: a 256 MiB read emits 65 536
        // of these and only ~100 of them are drawn.
        self.paint(&Self::line(phase, done, total), err);
    }

    /// Draw a `RESP_PROGRESS` frame from a daemon.
    ///
    /// The remote counter is the same counter: `--host` should look like the local run
    /// it stands in for, and the frame carries the same three facts in a smaller form —
    /// a percentage the daemon already computed, the phase byte
    /// ([`Phase::wire_byte`](tdfu_core::progress::Phase::wire_byte)) and a line of text.
    /// There are no byte counts on the wire, so this cannot use
    /// [`render`](Bar::render)'s [`Progress::Bytes`] arm; what it must **not** do is
    /// print the C client's `\r[%3d%%] %s` (`cli/remote.c:203`) beside a local run that
    /// prints something else entirely.
    ///
    /// "The same counter" is a claim, so it is a test: `a_wire_progress_frame_draws_the_local_counter`
    /// renders one transfer both ways and compares the two lines. It holds because the
    /// count itself has one producer
    /// ([`progress::bytes_line`](tdfu_core::progress::bytes_line)) that the daemon also
    /// calls, and because [`wire_line`](Bar::wire_line) drops a message that is only the
    /// phase's own name.
    ///
    /// # The throttle is on the whole line, not on the percentage
    ///
    /// The progress frame's `percent` is **0** for a transfer with no knowable total (a
    /// DFU upload ends on a short block, an erase has no total at all), so throttling on
    /// the number would silence every frame of a whole-chip erase after the first. The
    /// tick is a hash of the rendered line instead, which is the same rule
    /// [`tick`](Bar::tick) applies (redraw when the *output* would differ) generalised to
    /// text. A hash collision costs one skipped redraw and nothing else.
    pub fn wire(&mut self, percent: u8, stage: u8, message: &str, err: &mut dyn Write) {
        let line = Self::wire_line(percent, stage, message);
        let tick = Self::tick_of(&line);
        if self.last == Some(tick) {
            return;
        }
        self.last = Some(tick);
        self.paint(&line, err);
    }

    /// Write `line` over whatever the counter last drew, and remember its width.
    ///
    /// A failed write is swallowed for the reason [`render`](Bar::render) documents: a
    /// closed pipe is not a reason to abandon a flash mid-way.
    fn paint(&mut self, line: &str, err: &mut dyn Write) {
        let pad = self.drawn.saturating_sub(line.chars().count());
        let _ignored = write!(err, "\r{line}{:pad$}", "", pad = pad);
        let _ignored = err.flush();
        self.drawn = line.chars().count();
    }

    /// `download   45%  4718592/10485760 bytes`, in the wire's smaller vocabulary:
    /// `download   45%  writing block 1152`.
    ///
    /// **A message that is only the phase's own name is dropped.** The daemon sends
    /// `message: phase.to_string()` for a [`Progress::Phase`] frame (the frame needs a
    /// body and the name is the honest one to put in it), and this already prints the
    /// phase resolved from the same `stage` byte, so keeping both rendered every phase
    /// transition as `download    0%  download`.
    fn wire_line(percent: u8, stage: u8, message: &str) -> String {
        let phase = wire_phase(stage).map_or_else(
            // An unknown byte is reported as itself. A daemon newer than this client can
            // name a phase this build has never heard of, and inventing a label for it —
            // or dropping the frame — would be worse than saying which byte arrived.
            || format!("stage {stage}"),
            |phase| phase.to_string(),
        );
        // The daemon wrote this message; the counter draws it in place, on one line.
        let message = sanitise_line(message);
        if message.is_empty() || message == phase {
            return format!("{phase}  {percent:>3}%");
        }
        format!("{phase}  {percent:>3}%  {message}")
    }

    /// FNV-1a over the rendered line: "would this redraw say anything new?".
    fn tick_of(line: &str) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in line.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// The value a redraw is worth: the percentage, or the megabyte.
    ///
    /// `total: Some(0)` cannot arise — an empty image is refused by `ops::write` and
    /// `ops::verify`, and `ops::read`'s `Some(0)` cap issues no `UPLOAD` at all — but it
    /// is answered rather than divided by, because a panic here would abort a flash
    /// mid-transfer.
    const fn tick(done: u64, total: Option<u64>) -> u64 {
        match total {
            Some(total) if total > 0 => done.saturating_mul(100) / total,
            // One redraw per mebibyte, which is 256 lines for the largest part in the
            // tree rather than 65 536.
            _ => done >> 20,
        }
    }

    /// `download   45%  4718592/10485760 bytes`, or `upload  8388608 bytes`.
    ///
    /// The count itself comes from
    /// [`progress::bytes_line`](tdfu_core::progress::bytes_line), which the daemon also
    /// puts in its `RESP_PROGRESS` message: the remote counter is the same counter only
    /// if the two are the same string, and while they were two `format!`s they were not.
    fn line(phase: Phase, done: u64, total: Option<u64>) -> String {
        let counted = tdfu_core::progress::bytes_line(done, total);
        match total {
            Some(total) if total > 0 => {
                let percent = done.saturating_mul(100) / total;
                format!("{phase:>8}  {percent:>3}%  {counted}")
            }
            // A DFU upload ends on a short block, so a whole-chip read genuinely does
            // not know its length until it has finished. Printing a
            // percentage against a guessed total would be an invented fact.
            _ => format!("{phase:>8}  {counted}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bar, NONE_FOUND, Phase, Progress, render};
    use crate::fake::{FakeBackend, TestResult, bootrom_descriptors, t31_regs};
    use crate::list::{Listing, Row, Soc, Unavailable, list};
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::detect::decode;
    use tdfu_core::model::{Detection, Evidence, Family, SocRegs, Stage};
    use tdfu_usb::mock::block_on;
    use tdfu_usb::{DeviceDescriptors, Pipe, UsbError, UsbErrorKind, pid, vid};

    /// Render to a `String` for comparison.
    fn text(listing: &Listing) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        render(listing, &mut out)?;
        Ok(String::from_utf8(out)?)
    }

    /// A T31 whose grade byte the caller chooses.
    fn t31(subsoctype1: u32) -> Detection {
        let [soc_id, sub1, sub2] = t31_regs(subsoctype1);
        decode(SocRegs::new(soc_id, sub1, sub2))
    }

    /// A row built by hand, for the render-level pins.
    fn row(index: usize, descriptors: DeviceDescriptors, stage: Option<Stage>, soc: Soc) -> Row {
        Row {
            index,
            descriptors,
            stage,
            soc,
        }
    }

    #[test]
    fn an_empty_bus_says_so_and_nothing_else() -> TestResult {
        assert_eq!(text(&Listing::empty())?, format!("{NONE_FOUND}\n"));
        Ok(())
    }

    /// The whole table, exactly.
    #[test]
    fn the_table_is_this_table() -> TestResult {
        let listing = Listing {
            rows: vec![
                row(
                    0,
                    bootrom_descriptors(1, 7),
                    Some(Stage::Bootrom),
                    Soc::Detected(t31(0x2222_1111)),
                ),
                row(
                    1,
                    DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
                        .with_bus_address(1, 9)
                        .with_port_path(vec![4, 3]),
                    Some(Stage::Gadget),
                    Soc::NotProbed,
                ),
            ],
        };

        assert_eq!(
            text(&listing)?,
            "\
Found 2 devices:

  #  Bus  Addr  Port   VID:PID    Stage    SoC
  0    1     7  1-4.2  a108:c309  bootrom  T31X (loader t31x, DDR2)
  1    1     9  1-4.3  a108:c309  gadget   -
"
        );
        Ok(())
    }

    /// One device is a *device*, not "1 devices".
    #[test]
    fn one_device_reads_as_one_device() -> TestResult {
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(t31(0x2222_1111)),
            )],
        };
        assert!(text(&listing)?.starts_with("Found 1 device:\n"));
        Ok(())
    }

    /// **The caveat pin.** A qualified answer prints its qualification.
    ///
    /// Both evidence levels that produce one are covered: `Vendor` (documented by
    /// Ingenic, never seen here) and `Convention` (no row matched, so the family's
    /// conservative loader was chosen). Without this test the whole `Evidence` →
    /// `caveat()` mechanism is dead data again, which is exactly what happened in an
    /// earlier implementation.
    #[test]
    fn cli_surfaces_the_detection_caveat() -> TestResult {
        // Vendor: T31 grade 0x4444 is T31A, from Ingenic's config, never on the bench.
        let vendor = t31(0x4444_1111);
        let Detection::Resolved(resolved) = &vendor else {
            assert_eq!(format!("{vendor:?}"), "Resolved(..)");
            return Ok(());
        };
        assert_eq!(resolved.evidence, Evidence::Vendor, "fixture must exercise Vendor");

        // The value still carries the provenance sentence (it is information), but the
        // listing does not print it: a documented-but-unseen row is a debug line,
        // decided 2026-09-03, so the row stands alone.
        assert!(vendor.caveat().is_some(), "the information is kept on the value");
        assert_eq!(
            vendor.warning(),
            None,
            "and it is not a note beside a working detection"
        );
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(vendor.clone()),
            )],
        };
        assert_eq!(
            text(&listing)?,
            "\
Found 1 device:

  #  Bus  Addr  Port   VID:PID    Stage    SoC
  0    1     7  1-4.2  a108:c309  bootrom  T31A (loader t31a, DDR3)
"
        );

        // Convention: grade 0x1234 matches no T31 row, so the family's conservative
        // loader is used - and the row says so.
        let convention = t31(0x1234_1111);
        let Detection::Resolved(resolved) = &convention else {
            assert_eq!(format!("{convention:?}"), "Resolved(..)");
            return Ok(());
        };
        assert_eq!(
            resolved.evidence,
            Evidence::Convention,
            "fixture must exercise Convention"
        );

        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(convention.clone()),
            )],
        };
        assert_eq!(
            text(&listing)?,
            "\
Found 1 device:

  #  Bus  Addr  Port   VID:PID    Stage    SoC
  0    1     7  1-4.2  a108:c309  bootrom  T31 (loader t31x, DDR2)
     note: grade 0x1234 is not in the table; using T31's conservative loader t31x
"
        );

        // And the sentence really is the value's own, not a copy that could drift.
        assert!(vendor.caveat().is_some());
        assert!(convention.caveat().is_some());
        Ok(())
    }

    /// A bench-proven answer needs no qualification, so none is printed.
    #[test]
    fn a_bench_proven_row_carries_no_note() -> TestResult {
        let bench = t31(0x2222_1111);
        assert_eq!(bench.caveat(), None);
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(bench),
            )],
        };
        assert!(!text(&listing)?.contains("note:"));
        Ok(())
    }

    /// A refused device keeps its row, its VID:PID and the one hint that fixes it.
    #[test]
    fn a_refused_row_shows_its_identity_and_the_fix() -> TestResult {
        let hint = "install a udev rule";
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(2, 4),
                Some(Stage::Bootrom),
                Soc::Unavailable(Unavailable {
                    reason: "access denied by the OS: the device".to_owned(),
                    hint: Some(hint),
                }),
            )],
        };
        assert_eq!(
            text(&listing)?,
            "\
Found 1 device:

  #  Bus  Addr  Port   VID:PID    Stage    SoC
  0    2     4  2-4.2  a108:c309  bootrom  unavailable
     error: access denied by the OS: the device; install a udev rule
"
        );
        Ok(())
    }

    /// An ambiguous grade lists what to choose between, with each candidate's DRAM.
    #[test]
    fn an_ambiguous_grade_says_what_to_pass() -> TestResult {
        // Family 0x40, grade 0x1111: T40N (DDR2 32-bit) or T41N (DDR3 16-bit).
        let detection = decode(SocRegs::new(0x1004_0000, 0, 0x1111_0000));
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(detection),
            )],
        };
        let rendered = text(&listing)?;
        assert!(rendered.contains("  bootrom  ambiguous\n"), "{rendered}");
        assert!(rendered.contains("note: grade 0x1111 of family T4x names more than one chip; pass --cpu: "));
        assert!(rendered.contains("--cpu t40n"), "{rendered}");
        assert!(rendered.contains("DDR3 16-bit"), "{rendered}");
        Ok(())
    }

    /// A T4x grade documented on neither product line offers no candidates — and says
    /// so, rather than inventing one.
    ///
    /// A fabricated row here is the `"unknown"` DRAM bug with the sign flipped: the
    /// operator would flash it.
    #[test]
    fn an_undocumented_grade_offers_no_candidates() -> TestResult {
        let detection = decode(SocRegs::new(0x1004_0000, 0, 0x1234_0000));
        assert!(matches!(&detection, Detection::Ambiguous { candidates, .. } if candidates.is_empty()));

        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(detection),
            )],
        };
        let rendered = text(&listing)?;
        assert!(
            rendered.contains(
                "note: grade 0x1234 of family T4x is documented on neither product line; \
                 pass --cpu with the loader for this part, or stream --spl and --uboot"
            ),
            "{rendered}"
        );
        Ok(())
    }

    /// A `cpu_id` outside the table says what it read and what to do.
    #[test]
    fn an_unknown_soc_says_what_it_read() -> TestResult {
        let detection = decode(SocRegs::new(0x0BAD_0000, 0, 0));
        assert!(matches!(detection, Detection::Unknown { .. }));
        let listing = Listing {
            rows: vec![row(
                0,
                bootrom_descriptors(1, 7),
                Some(Stage::Bootrom),
                Soc::Detected(detection),
            )],
        };
        let rendered = text(&listing)?;
        assert!(rendered.contains("  bootrom  unknown\n"), "{rendered}");
        // `cpu_id = (soc_id >> 12) & 0xFFFF`: 0x0BAD0000 -> 0xBAD0.
        assert!(
            rendered.contains("note: soc_id 0x0BAD0000 (cpu_id 0xBAD0) is not in the table"),
            "{rendered}"
        );
        Ok(())
    }

    /// A device this tool cannot classify is listed with its identity and **no stage
    /// claim** — never as a bootrom, and so never as something to bootstrap.
    ///
    /// Classification is core's answer, not this crate's: whatever
    /// `tdfu_core::ops::classify` decides arrives here as `Row::stage`, and `None` is
    /// the case that matters. A descriptor read can fail on macOS and Windows (see
    /// `NativeBackend::list`, which then lists the device with an empty
    /// `config_descriptor`), and a device with nothing but a shared PID to go on is not
    /// evidence of a bootrom: the U-Boot DFU gadget has answered `a108:c309` since
    /// 2026-07-24. So `unknown`, and a SoC column of `-`: the row still
    /// tells an operator what is on the bus and where.
    #[test]
    fn an_unclassified_device_is_listed_without_a_stage_claim() -> TestResult {
        let listing = Listing {
            rows: vec![row(
                0,
                DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
                    .with_bus_address(1, 7)
                    .with_port_path(vec![4, 2]),
                None,
                Soc::NotProbed,
            )],
        };
        assert_eq!(
            text(&listing)?,
            "\
Found 1 device:

  #  Bus  Addr  Port   VID:PID    Stage    SoC
  0    1     7  1-4.2  a108:c309  unknown  -
"
        );
        Ok(())
    }

    /// The grade comes from **each family's own** register.
    ///
    /// Only family `0x0040` reaches `ambiguous_text` through `decode` today, so the
    /// other two arms of `grade_text` are unreachable from the public path and
    /// mutation testing found them unfalsifiable. They are the reason the function
    /// exists — a hardcoded `sub2` would print the wrong register the day another
    /// family becomes ambiguous — so they are tested here directly.
    #[test]
    fn a_grade_is_read_from_its_family_register() {
        // XBurst1: subsoctype1. A T31X, whose sub2 is deliberately a decoy.
        let xburst1 = SocRegs::new(0x1003_1003, 0x2222_1111, 0xFFFF_0000);
        assert_eq!(super::grade_text(xburst1, Family::T31), "grade 0x2222");

        // T40/T41 and A1: subsoctype2, with sub1 the decoy this time.
        let xburst2 = SocRegs::new(0x1004_0000, 0xFFFF_0000, 0x1111_0000);
        assert_eq!(super::grade_text(xburst2, Family::T4x), "grade 0x1111");

        // T33: byte 3 of the selector word, the map thingino-soc.sh uses.
        let t33 = SocRegs::new(0x1003_3000, 0, 0).with_t33_selector(0x9900_0000);
        assert_eq!(super::grade_text(t33, Family::T33), "grade 0x0099");

        // And a T33 whose fourth read was never taken has no grade to name, so it
        // says so rather than printing another register's value.
        let unread = SocRegs::new(0x1003_3000, 0xFFFF_0000, 0xFFFF_0000);
        assert_eq!(super::grade_text(unread, Family::T33), "the grade");
    }

    /// A device with no port path prints `-`, not a fabricated one.
    #[test]
    fn a_missing_port_path_is_a_dash() -> TestResult {
        let listing = Listing {
            rows: vec![row(
                0,
                DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_bus_address(0, 0),
                None,
                Soc::NotProbed,
            )],
        };
        let rendered = text(&listing)?;
        assert!(
            rendered.contains("  0    0     0  -     a108:c309  unknown  -\n"),
            "{rendered}"
        );
        Ok(())
    }

    /// No line ends in whitespace, at any width.
    #[test]
    fn no_line_has_trailing_whitespace() -> TestResult {
        let listing = Listing {
            rows: vec![
                row(
                    0,
                    bootrom_descriptors(1, 7),
                    Some(Stage::Bootrom),
                    Soc::Detected(t31(0x2222_1111)),
                ),
                row(1, bootrom_descriptors(200, 250), Some(Stage::Gadget), Soc::NotProbed),
            ],
        };
        for line in text(&listing)?.lines() {
            assert_eq!(line.trim_end(), line, "trailing whitespace: {line:?}");
        }
        Ok(())
    }

    /// End to end: the fake bus, the real list path, this renderer, one string.
    ///
    /// The render-level pins above build their rows by hand; this one proves the same
    /// text comes out of an actual `list()` over a scripted device, so a change in
    /// either half is caught.
    #[test]
    fn the_caveat_survives_the_whole_path() -> TestResult {
        // A grade the table does not have: the conservative fallback is a warning the
        // user must see, and it has to survive the whole path (the Vendor provenance
        // sentence does not: it is a debug line, `cli_surfaces_the_detection_caveat`).
        let backend = FakeBackend::new(vec![FakeBackend::bootrom_at(
            bootrom_descriptors(1, 7),
            t31_regs(0x1234_1111),
        )]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;
        let rendered = text(&listing)?;
        assert!(rendered.contains("T31 (loader t31x, DDR2)"), "{rendered}");
        assert!(
            rendered.contains("     note: grade 0x1234 is not in the table; using T31's conservative loader t31x"),
            "{rendered}"
        );
        Ok(())
    }

    /// And the open failure survives it too, hint included.
    #[test]
    fn a_refusal_survives_the_whole_path() -> TestResult {
        let denied = UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device);
        let backend = FakeBackend::new(vec![FakeBackend::refusing(bootrom_descriptors(1, 7), denied)]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;
        let rendered = text(&listing)?;
        assert!(rendered.contains("bootrom  unavailable"), "{rendered}");
        assert!(
            rendered.contains(tdfu_usb::native::ACCESS_DENIED_HINT),
            "the platform's one hint must reach the row: {rendered}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // The progress bar.
    // -----------------------------------------------------------------

    /// Drive a bar over a sequence and hand back what stderr saw.
    fn drawn(steps: &[Progress]) -> Result<String, Box<dyn std::error::Error>> {
        let mut bar = Bar::new();
        let mut err = Vec::new();
        for step in steps {
            bar.render(step, &mut err);
        }
        bar.clear(&mut err);
        Ok(String::from_utf8(err)?)
    }

    /// A byte counter says the phase, the percentage and both counts.
    ///
    /// Content, not cursor codes: the `\r` is an implementation detail of drawing in
    /// place and pinning it would make the bar unchangeable for no gain.
    #[test]
    fn a_byte_counter_says_the_phase_and_the_percentage() -> TestResult {
        let text = drawn(&[
            Progress::Phase(Phase::Download),
            Progress::Bytes {
                phase: Phase::Download,
                done: 4096,
                total: Some(8192),
            },
            Progress::Bytes {
                phase: Phase::Download,
                done: 8192,
                total: Some(8192),
            },
        ])?;
        assert!(text.contains("download"), "{text:?}");
        assert!(text.contains(" 50%"), "{text:?}");
        assert!(text.contains("100%"), "{text:?}");
        assert!(text.contains("4096/8192 bytes"), "{text:?}");
        Ok(())
    }

    /// A read has no knowable total, so it counts rather than guessing.
    #[test]
    fn an_unknown_total_counts_bytes_instead_of_inventing_a_percentage() -> TestResult {
        let text = drawn(&[Progress::Bytes {
            phase: Phase::Upload,
            done: 3 << 20,
            total: None,
        }])?;
        assert!(text.contains("upload"), "{text:?}");
        assert!(text.contains("3145728 bytes"), "{text:?}");
        assert!(!text.contains('%'), "nothing to take a percentage of: {text:?}");
        Ok(())
    }

    /// **The throttle pin.** 65 536 blocks do not become 65 536 lines, and which lines
    /// are drawn depends on the values, not on how fast the machine is.
    #[test]
    fn bar_is_throttled_by_value_not_by_time() -> TestResult {
        // A 16 MiB write at `wTransferSize` 4096: 4096 blocks, 101 percentages.
        let total = 16 * 1024 * 1024;
        let steps: Vec<Progress> = (1_u32..=4096)
            .map(|block| Progress::Bytes {
                phase: Phase::Download,
                done: u64::from(block) * 4096_u64,
                total: Some(total),
            })
            .collect();
        let text = drawn(&steps)?;
        let redraws = text.matches('\r').count();
        assert!(
            (1..=110).contains(&redraws),
            "4096 blocks must not be 4096 redraws, got {redraws}"
        );
        // Deterministic: the same sequence draws the same thing every time.
        assert_eq!(text, drawn(&steps)?);
        Ok(())
    }

    /// A note is printed verbatim, on its own line, and the bar does not eat it.
    #[test]
    fn a_note_survives_the_bar_that_was_drawing() -> TestResult {
        let text = drawn(&[
            Progress::Bytes {
                phase: Phase::Download,
                done: 4096,
                total: Some(8192),
            },
            Progress::Note("DFU download complete".to_owned()),
        ])?;
        assert!(
            text.ends_with("DFU download complete\n"),
            "the note must be the last thing said, on its own line: {text:?}"
        );
        assert_eq!(text.matches("DFU download complete").count(), 1, "{text:?}");
        Ok(())
    }

    /// **The narration pin.** Core's [`Progress::Debug`] goes to `tracing`, which is
    /// `-d`'s channel, and the bar writes nothing for it.
    ///
    /// The bar is what a user who did not ask for detail sees, and a narration line
    /// written to stderr here would also blank the counter it is drawn over. Revert check:
    /// route `Debug` to `note` and both halves of this fail.
    #[test]
    fn a_debug_line_is_narration_and_never_reaches_the_bar() -> TestResult {
        assert_eq!(
            drawn(&[Progress::Debug("claiming alt 0 on interface 0".to_owned())])?,
            "",
            "a narration line must not be printed"
        );

        // And it does not disturb a counter mid-draw: the bar after it is the bar before
        // it, byte for byte.
        let counting = Progress::Bytes {
            phase: Phase::Download,
            done: 4096,
            total: Some(8192),
        };
        assert_eq!(
            drawn(&[
                counting.clone(),
                Progress::Debug("download: alt 0, 8192 bytes in 4096-byte blocks".to_owned()),
            ])?,
            drawn(&[counting])?
        );
        Ok(())
    }

    /// A phase change restarts the throttle, so a verify after a write draws again from
    /// zero rather than being suppressed by the write's last percentage.
    #[test]
    fn a_new_phase_redraws_from_zero() -> TestResult {
        let text = drawn(&[
            Progress::Bytes {
                phase: Phase::Download,
                done: 8192,
                total: Some(8192),
            },
            Progress::Phase(Phase::Verify),
            Progress::Bytes {
                phase: Phase::Verify,
                done: 8192,
                total: Some(8192),
            },
        ])?;
        assert!(text.contains("verify"), "{text:?}");
        assert!(text.contains("download"), "{text:?}");
        Ok(())
    }

    /// **A counter with no total is throttled per mebibyte**, which is the whole reason
    /// `tick` shifts: a 256 MiB DFU upload emits 65 536 byte counts and does not know its
    /// length until it ends, so it draws 256 lines rather than 65 536.
    ///
    /// Mutation testing found this untested: `done >> 20` could become `done << 20` and
    /// nothing failed, because every no-total fixture was under a mebibyte and both
    /// operators agree on the *first* value. Two counts inside one mebibyte and one past
    /// it separate them — under `<<` the first two redraw, and under `>>` they do not.
    #[test]
    fn a_counter_with_no_total_redraws_once_a_mebibyte() -> TestResult {
        let steps: Vec<Progress> = [4096_u64, 8192, 1024 * 1024, 1024 * 1024 + 4096]
            .into_iter()
            .map(|done| Progress::Bytes {
                phase: Phase::Upload,
                done,
                total: None,
            })
            .collect();
        let text = drawn(&steps)?;
        assert_eq!(
            text.matches("upload").count(),
            2,
            "one draw below the mebibyte and one above it: {text:?}"
        );
        assert!(text.contains("upload  4096 bytes"), "{text:?}");
        assert!(text.contains("upload  1048576 bytes"), "{text:?}");
        assert!(
            !text.contains("8192 bytes"),
            "the second count says nothing new: {text:?}"
        );
        Ok(())
    }

    /// A zero total is answered rather than divided by.
    #[test]
    fn a_zero_total_does_not_divide() -> TestResult {
        let text = drawn(&[Progress::Bytes {
            phase: Phase::Upload,
            done: 0,
            total: Some(0),
        }])?;
        assert!(text.contains("0 bytes"), "{text:?}");
        Ok(())
    }

    /// **The wire stage byte, both ways.** The table this client searches is the
    /// list of variants; the byte values are still `Phase::wire_byte`'s.
    #[test]
    fn every_wire_phase_round_trips() {
        for phase in super::WIRE_PHASES {
            assert_eq!(super::wire_phase(phase.wire_byte()), Some(phase));
        }
        assert_eq!(super::WIRE_PHASES.len(), 8, "defines eight stages");
        assert_eq!(super::wire_phase(8), None, "8 is not a stage yet");
        assert_eq!(super::wire_phase(0xFF), None);
    }

    /// A daemon's progress frame draws the *same bytes* a local transfer does,
    /// and an identical frame does not redraw.
    ///
    /// Not "the same shape": the two rendered lines are compared to each other. The
    /// frame is built the way `tdfu-daemon`'s `report::send` builds it (the percentage
    /// from `ProgressBody::percent_of`, the message from `progress::bytes_line`), so a
    /// change on either side that made the two differ fails here rather than being
    /// invisible behind a fixture written by hand in the local spelling.
    #[test]
    fn a_wire_progress_frame_draws_the_local_counter() -> TestResult {
        let done = 4_718_592_u64;
        let total = Some(10_485_760_u64);

        let mut local = Vec::new();
        Bar::new().render(
            &Progress::Bytes {
                phase: Phase::Download,
                done,
                total,
            },
            &mut local,
        );

        let mut err = Vec::new();
        let mut bar = Bar::new();
        let message = tdfu_core::progress::bytes_line(done, total);
        let percent = tdfu_proto::ProgressBody::percent_of(done, total);
        bar.wire(percent, Phase::Download.wire_byte(), &message, &mut err);
        bar.wire(percent, Phase::Download.wire_byte(), &message, &mut err);
        let text = String::from_utf8(err)?;

        assert_eq!(
            text.trim_end_matches([' ', '\r']),
            String::from_utf8(local)?.trim_end_matches([' ', '\r']),
            "the remote counter is the local counter, byte for byte"
        );
        assert!(text.contains("download   45%  4718592/10485760 bytes"), "{text:?}");
        assert_eq!(text.matches('\r').count(), 1, "an identical frame is not redrawn");
        Ok(())
    }

    /// The other half of the same pin. A phase frame does not print the phase twice.
    ///
    /// The daemon's `Progress::Phase` frame carries `message: phase.to_string()` (the
    /// frame wants a body and the name is the honest thing to put in it) and this client
    /// already prints the phase resolved from the same `stage` byte, so every phase
    /// transition read `download    0%  download`.
    #[test]
    fn a_phase_frame_does_not_say_the_phase_twice() -> TestResult {
        let mut err = Vec::new();
        let mut bar = Bar::new();
        // Exactly what `report::send` sends for `Progress::Phase(Phase::Download)`.
        bar.wire(0, Phase::Download.wire_byte(), &Phase::Download.to_string(), &mut err);
        let text = String::from_utf8(err)?;
        assert_eq!(text.matches("download").count(), 1, "{text:?}");
        assert!(text.contains("download    0%"), "{text:?}");

        // A message that merely *contains* the phase name is still a message.
        let mut err = Vec::new();
        Bar::new().wire(0, Phase::Download.wire_byte(), "download stalled", &mut err);
        let text = String::from_utf8(err)?;
        assert!(text.contains("download    0%  download stalled"), "{text:?}");
        Ok(())
    }

    /// **The throttle is on the line, not the number.** The daemon sends `percent = 0`
    /// for a transfer with no knowable total, so throttling on the percentage would
    /// silence every frame of a whole-chip erase after the first.
    #[test]
    fn a_wire_counter_at_a_fixed_percent_still_redraws() -> TestResult {
        let mut err = Vec::new();
        let mut bar = Bar::new();
        for block in 1_u32..=3 {
            bar.wire(0, Phase::Erase.wire_byte(), &format!("{block} blocks erased"), &mut err);
        }
        let text = String::from_utf8(err)?;
        assert_eq!(
            text.matches('\r').count(),
            3,
            "three different lines, three draws: {text:?}"
        );
        assert!(text.contains("erase    0%  3 blocks erased"), "{text:?}");
        Ok(())
    }

    /// A stage byte this build does not know prints as itself, and a frame with no
    /// message prints without a trailing gap.
    #[test]
    fn a_wire_frame_never_invents_a_phase_or_a_message() -> TestResult {
        let mut err = Vec::new();
        let mut bar = Bar::new();
        bar.wire(9, 42, "", &mut err);
        let text = String::from_utf8(err)?;
        assert!(text.contains("stage 42    9%"), "{text:?}");
        assert!(!text.contains("42%  "), "no message means no separator: {text:?}");
        Ok(())
    }

    /// **A progress message is one line, whoever wrote it.** The counter blanks by the
    /// width it drew and rewrites from column zero, so a newline in a daemon's message
    /// leaves debris [`Bar::clear`] cannot reach, and an escape sequence in one would be
    /// executed by the terminal rather than printed.
    #[test]
    fn a_wire_message_cannot_break_the_line_it_is_drawn_on() -> TestResult {
        let mut err = Vec::new();
        let mut bar = Bar::new();
        bar.wire(50, Phase::Erase.wire_byte(), "erasing\nblock 1\x1b[2J", &mut err);
        let text = String::from_utf8(err)?;
        assert!(text.contains("erase   50%  erasing^Jblock 1^[[2J"), "{text:?}");
        assert!(!text.contains('\n'), "the counter stays on its line: {text:?}");
        assert!(!text.contains('\x1b'), "and paints no escape: {text:?}");

        // The tab is text in a line of text, and survives.
        assert_eq!(super::sanitise("a\tb\nc"), "a\tb\nc");
        assert_eq!(super::sanitise_line("a\tb\nc"), "a\tb^Jc");
        // C1 has no caret form, so it is named rather than shown.
        assert_eq!(super::sanitise("\u{9b}2J"), "<U+009B>2J");
        Ok(())
    }

    /// A log line after a counter blanks it first: the remote client's
    /// job, since byte counts stopped being log text.
    #[test]
    fn a_wire_counter_is_blanked_before_a_note() -> TestResult {
        let mut err = Vec::new();
        let mut bar = Bar::new();
        bar.wire(50, Phase::Download.wire_byte(), "halfway", &mut err);
        bar.note("careful: bad block", &mut err);
        let text = String::from_utf8(err)?;
        let note = text.find("careful").ok_or("the note was lost")?;
        assert!(
            text[..note].contains("\r    "),
            "the counter must be blanked, not written over: {text:?}"
        );
        Ok(())
    }
}
