//! What an operation tells its caller while it runs.
//!
//! Every frontend renders these: the CLI draws a bar, the daemon turns them into
//! `RESP_PROGRESS` and `RESP_LOG` frames, the browser updates the
//! page.
//!
//! # Three kinds of line, and who shows which
//!
//! | kind | what it is | who shows it |
//! |---|---|---|
//! | [`Progress::Phase`], [`Progress::Bytes`] | where an operation is and how far | every frontend, always: the CLI's bar, the daemon's `RESP_PROGRESS`, the page's bar, the app's bar |
//! | [`Progress::Note`] | a line for the user: a completion, a retry, a caveat | every frontend, always: stderr, `RESP_LOG`, the page's `info` log, `onLog` |
//! | [`Progress::Debug`] | one protocol step, narrated | only behind the frontend's debug switch: the CLI's `-d`, the daemon's `-d`, the page's `setDebug(true)`, the app's Settings toggle |
//!
//! The third row is why this enum has a debug variant at all. The C gated a `LOG_DEBUG`
//! stream behind its debug switch and every frontend showed it; the Rust core had no such
//! channel, so each frontend's switch showed only the handful of lines that frontend
//! wrote itself. Turning debug on in the app before a 32 MiB read added one line to the
//! log (observed 2026-09-03). Core narrates its own protocol steps now, once, and every
//! frontend routes them to the switch it already has.
//!
//! Two things an earlier implementation got wrong here are designed out:
//!
//! * **A successful local write printed nothing** — no `DFU download complete`, no
//!   `Verify OK`. The daemon had both, so the *remote* tool was more informative than
//!   the local one. Completion lines are
//!   [`Progress::Note`]s emitted by core, so every frontend gets them once, from one
//!   place.
//! * **Both retries were silent.** The recovery bus reset and the
//!   stale-transaction retry announced nothing, and a retry the user cannot see is a
//!   retry they cannot report. Both emit a [`Progress::Note`].

/// The phase an operation is in.
///
/// The discriminants are the `stage` byte of the wire progress frame, so
/// the daemon does not have to keep a string-to-byte table in step with this enum —
/// which is what "0 unknown, 1 stage1, 2 u-boot, 3 download, 4 manifest, 5 upload,
/// 6 verify, 7 erase" was in an earlier implementation, where core emitted
/// `&'static str` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Phase {
    /// Not one of the below.
    Unknown = 0,
    /// Uploading and starting the stage-1 image.
    Stage1 = 1,
    /// Uploading and starting U-Boot.
    UBoot = 2,
    /// DFU `DNLOAD` data blocks.
    Download = 3,
    /// The DFU manifest phase after the zero-length `DNLOAD`.
    Manifest = 4,
    /// DFU `UPLOAD` data blocks.
    Upload = 5,
    /// Reading back and comparing.
    Verify = 6,
    /// Erasing.
    Erase = 7,
}

impl Phase {
    /// The `stage` byte of a wire progress frame.
    #[must_use]
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "working",
            Self::Stage1 => "stage1",
            Self::UBoot => "u-boot",
            Self::Download => "download",
            Self::Manifest => "manifest",
            Self::Upload => "upload",
            Self::Verify => "verify",
            Self::Erase => "erase",
        })
    }
}

/// One thing worth telling the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Progress {
    /// A phase started.
    Phase(Phase),
    /// A byte counter within a phase.
    ///
    /// The phase travels with the count so that a frontend never has to remember which
    /// phase it is in: the progress frame needs both in the same message.
    /// `total` is `None` where there is no knowable total: a DFU upload ends on a short
    /// block, so a whole-chip read does not know its length until it
    /// finishes.
    Bytes {
        /// Which phase.
        phase: Phase,
        /// Bytes done.
        done: u64,
        /// Bytes expected, when that is knowable.
        total: Option<u64>,
    },
    /// A line for the user: a completion, a retry, a caveat from
    /// [`Detection::caveat`](crate::model::Detection::caveat).
    Note(String),
    /// A protocol-level narration line, shown only behind a frontend's debug switch.
    ///
    /// One line per protocol *step*, never per data block: a 16 MiB write is 4096 blocks,
    /// and the browser renders its log into the DOM. What earns a line is a decision or a
    /// fact an operator reading a log would otherwise have to infer: the descriptors a
    /// device answered with, which alt was claimed and why, the block a transfer died on
    /// and how far it had got.
    ///
    /// **Never a completion and never a retry announcement.** Those are [`Note`](Self::Note)s,
    /// which every user sees whether or not they asked for detail; moving one here would
    /// hide it from everybody who has not turned debug on.
    ///
    /// Nothing parses these. They are prose for a human reading a log, so no test may
    /// depend on their exact text beyond the pins written for them, and the wording is
    /// ours rather than the C's.
    Debug(String),
}

/// The byte-count half of a counter line: `4718592/10485760 bytes`, or `8388608 bytes`.
///
/// **One producer, two callers, on purpose.** The CLI's local bar draws this directly and
/// the daemon puts it in a `RESP_PROGRESS` message that the CLI's *remote*
/// bar draws, so two copies of the same `format!` meant `--host` spelled a byte count
/// differently from the run it stands in for, and the test that asserted the remote
/// counter was "the local counter's shape" was doing it against a fixture written by hand
/// in a spelling the daemon never sent.
///
/// The spelling is the compact one, which is what the C put down its log stream
/// (`\r  N/M bytes (P%)`, where this daemon sends a frame) and which keeps the message
/// short: the shipped C CLI prints a progress body with `\r[%3d%%] %s` and no padding
/// (`cli/remote.c:203`), so a character saved is a stale character not left behind when a
/// shorter frame follows a longer one.
///
/// `total` is `None` where there is no knowable total (a DFU upload ends on a short
/// block), and `Some(0)` is answered the same way rather than printed as
/// `N/0`, which reads as a division nobody made.
#[must_use]
pub fn bytes_line(done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) if total > 0 => format!("{done}/{total} bytes"),
        _ => format!("{done} bytes"),
    }
}

/// Where an operation sends its [`Progress`].
///
/// `&mut dyn FnMut` rather than a trait so that a closure is enough and no frontend has
/// to declare a type to receive progress.
pub type ProgressSink<'a> = &'a mut dyn FnMut(Progress);

/// A sink that drops everything, for callers that do not want progress.
///
/// ```
/// use tdfu_core::progress::{Progress, ProgressSink, sink_ignore};
///
/// let mut ignore = sink_ignore();
/// let sink: ProgressSink<'_> = &mut ignore;
/// sink(Progress::Note("dropped".into()));
/// ```
pub fn sink_ignore() -> impl FnMut(Progress) {
    |_| {}
}

#[cfg(test)]
mod tests {
    use super::{Phase, bytes_line};

    /// **The eight stages, as words.** Every phase's name, pinned here because
    /// this is where it is defined and because three separate things read it.
    ///
    /// The daemon puts `phase.to_string()` in a `RESP_PROGRESS` message; the CLI's remote
    /// bar resolves the same `stage` byte back to a `Phase` and drops the message when the
    /// two strings are equal; the local bar prints it directly. A mutant replacing
    /// this `Display` with the empty string survived every test in this crate, because
    /// nothing here read it: the coverage was all one crate away.
    #[test]
    fn every_phase_has_its_own_word() {
        let named = [
            (Phase::Unknown, "working"),
            (Phase::Stage1, "stage1"),
            (Phase::UBoot, "u-boot"),
            (Phase::Download, "download"),
            (Phase::Manifest, "manifest"),
            (Phase::Upload, "upload"),
            (Phase::Verify, "verify"),
            (Phase::Erase, "erase"),
        ];
        for (phase, word) in named {
            assert_eq!(phase.to_string(), word, "{phase:?}");
            assert_eq!(phase.wire_byte(), phase as u8);
        }
        let mut words: Vec<&str> = named.iter().map(|(_, word)| *word).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), named.len(), "eight stages, eight words");
    }

    /// The one place the byte count is spelled, pinned as a literal.
    ///
    /// The producer exists so the local bar and the daemon's `RESP_PROGRESS` message
    /// cannot disagree; a test that built its expectation by calling the producer would
    /// pin the agreement and not the spelling, so this one writes the strings out.
    #[test]
    fn the_byte_count_is_spelled_one_way() {
        assert_eq!(bytes_line(4_718_592, Some(10_485_760)), "4718592/10485760 bytes");
        assert_eq!(bytes_line(0, Some(1)), "0/1 bytes");
        // No knowable total: the count alone, never a percentage against a guess.
        assert_eq!(bytes_line(8_388_608, None), "8388608 bytes");
        // `Some(0)` cannot arise (an empty image is refused, and a `--size 0` read issues
        // no `UPLOAD`) and is answered rather than printed as `0/0`.
        assert_eq!(bytes_line(0, Some(0)), "0 bytes");
    }
}
