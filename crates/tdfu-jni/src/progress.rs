//! Turning [`ops::Progress`](tdfu_core::progress::Progress) into the app's callback.
//!
//! The Kotlin callback has two entry points, and this decides which each kind of progress
//! reaches:
//!
//! * A [`Progress::Note`] is a line for the user - a completion, a retry, a detection
//!   caveat - so it goes to `onLog`, the same place the C's free-form `jni_log` lines go.
//! * A [`Progress::Phase`] and a [`Progress::Bytes`] are a running operation's state, so
//!   they go to `onProgress(percent, stage, message)`, which drives the app's bar and
//!   status line (`DfuActivity.onProgress`).
//! * A [`Progress::Debug`] is core's protocol narration, so it goes to `onLog` **behind
//!   the Settings toggle** - `nativeSetDebug`, which is the C's `g_debug_enabled` gating
//!   libtdfu's `LOG_DEBUG` stream into the app's log. Before core had this channel, the
//!   toggle showed only this bridge's own handful of lines: with it on, a 32 MiB flash
//!   used to produce one extra line (2026-09-03).
//!
//! **The words are the user's, not the DFU protocol's.** The core names its phases in
//! DFU terms (an `upload` moves bytes from the device to the host, a `download` the other
//! way), and those names are right for the wire frame and the CLI's debug output. Shown
//! raw in the app they read backwards: a read said `[upload]`. The C bridge spoke the
//! user's language (`tdfu_jni.c:508,547,597,633`: `bootstrap`, `read`, `write`, `verify`),
//! so [`stage_word`] maps each phase to that vocabulary and [`activity`] spells out what
//! is happening (`Reading flash`, `Writing flash`, ...). The page made the same correction
//! for its bar (`web/src/app.js`, `PHASE_LABELS`).
//!
//! **An unknown total is reported as [`UNKNOWN`] (-1), never as a made-up percent.** The
//! percent is per-phase (`done`/`total`), the only fraction the operation actually knows.
//! A DFU read ends on a short block, so a whole-chip read has no total until it finishes;
//! a write and a verify know their image length and report a true percent.
//! The app draws an indeterminate bar for a negative percent and prints the status line
//! without the number, which is what the page does with its striped bar and byte count
//! (decided 2026-09-03, after an app run showed a read stuck at `0%`).
//! The C bridge had the same limit and hid it: its `dfu.c:844` byte counter went to the
//! log only, so its bar sat at 0 through every read. The completion line
//! (`exports::complete`) ends the indeterminate state with a real 100.

use tdfu_core::progress::{Phase, Progress, bytes_line};

use crate::callback::{self, Sink};

/// The `percent` that means "no total is knowable": the app shows an indeterminate bar.
///
/// Part of the callback contract with `TdfuBridge.kt` (`NativeCallback.onProgress`). An
/// app built before the contract said so clamps it to an empty bar and prints `(-1%)`,
/// which at least does not claim a progress nobody measured.
pub(crate) const UNKNOWN: i32 = -1;

/// Send one [`Progress`] to the right half of the callback.
pub(crate) fn route(sink: &dyn Sink, progress: Progress) {
    match progress {
        Progress::Note(text) => sink.log(&text),
        Progress::Phase(phase) => {
            // A read is indeterminate from its first block, not from its first byte
            // count: the bridge only ever reads to the short block (no `--size` slot in
            // the JNI signature), so the total is unknown before a byte moves.
            let percent = if phase == Phase::Upload { UNKNOWN } else { 0 };
            sink.progress(percent, stage_word(phase), &format!("{}...", activity(phase)));
        }
        Progress::Bytes { phase, done, total } => {
            sink.progress(
                percent(done, total),
                stage_word(phase),
                &format!("{}: {}", activity(phase), bytes_line(done, total)),
            );
        }
        // Core's protocol narration, behind the app's Settings toggle: it reaches `onLog`
        // like any other line, but only when `nativeSetDebug(true)` has been called. It is
        // deliberately not a bar update - the bar shows where an operation is, and these
        // are the steps behind that.
        Progress::Debug(text) => callback::debug_log_to(sink, || text),
        // `Progress` is `#[non_exhaustive]`: a variant added to core later is forwarded as
        // nothing rather than crossing the boundary as a surprise.
        _ => {}
    }
}

/// The `[stage]` word the app shows: the C bridge's vocabulary, which is the user's.
///
/// Both bootstrap phases are one stage to the user (the C had one `bootstrap` stage for
/// the whole of it), and the manifest phase after the last `DNLOAD` is still the write.
/// `Phase` is `#[non_exhaustive]`, so a phase added to core later is `working` rather
/// than a protocol word leaking through.
pub(crate) fn stage_word(phase: Phase) -> &'static str {
    match phase {
        Phase::Stage1 | Phase::UBoot => "bootstrap",
        Phase::Download | Phase::Manifest => "write",
        Phase::Upload => "read",
        Phase::Verify => "verify",
        Phase::Erase => "erase",
        _ => "working",
    }
}

/// What the operation is doing, for the status line.
fn activity(phase: Phase) -> &'static str {
    match phase {
        Phase::Stage1 => "Loading stage 1",
        Phase::UBoot => "Loading U-Boot",
        Phase::Download => "Writing flash",
        Phase::Manifest => "Finishing the write",
        Phase::Upload => "Reading flash",
        Phase::Verify => "Verifying flash",
        Phase::Erase => "Erasing flash",
        _ => "Working",
    }
}

/// The per-phase percent, clamped to `0..=100`, or [`UNKNOWN`] when there is no total.
///
/// No total (a DFU upload ends on a short block, so a whole-chip read does not know its
/// length until it finishes) or a zero total is answered with [`UNKNOWN`]
/// rather than divided by or reported as `0`; the message still carries the live count.
fn percent(done: u64, total: Option<u64>) -> i32 {
    match total {
        Some(total) if total > 0 => {
            // In `u128` so the `* 100` cannot overflow even for a whole-flash count, and
            // so equal `done`/`total` is a true 100; `min(100)` clamps a counter that
            // briefly overshoots rather than trusting it.
            let pct = u128::from(done) * 100 / u128::from(total);
            i32::try_from(pct.min(100)).unwrap_or(100)
        }
        _ => UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tdfu_core::progress::{Phase, Progress};

    use super::{UNKNOWN, activity, percent, route, stage_word};
    use crate::callback::{Sink, debug_switch_lock, set_debug};

    /// A sink that records exactly what the bridge asked it to do.
    #[derive(Default)]
    struct Recording {
        logs: RefCell<Vec<String>>,
        progress: RefCell<Vec<(i32, String, String)>>,
    }

    impl Sink for Recording {
        fn log(&self, message: &str) {
            self.logs.borrow_mut().push(message.to_owned());
        }

        fn progress(&self, percent: i32, stage: &str, message: &str) {
            self.progress
                .borrow_mut()
                .push((percent, stage.to_owned(), message.to_owned()));
        }
    }

    #[test]
    fn a_note_goes_to_the_log_and_not_the_bar() {
        let sink = Recording::default();
        route(&sink, Progress::Note("DFU download complete".to_owned()));
        assert_eq!(sink.logs.borrow().as_slice(), ["DFU download complete"]);
        assert!(sink.progress.borrow().is_empty());
    }

    /// **The narration pin.** Core's [`Progress::Debug`] reaches `onLog` only when the
    /// app's Settings toggle is on, and never the bar.
    ///
    /// Both halves matter. Unswitched it would put the `make_idle` polls and every
    /// forgiven busy poll into the log of a user who asked for none of it; switched off
    /// entirely it would leave the toggle showing what it showed before core had a channel,
    /// which was almost nothing. Revert check: send it to `sink.log` unconditionally and
    /// the first assertion fails; drop the arm and the second does.
    ///
    /// The switch is global and this test moves it, so it is put back before returning:
    /// `the_debug_switch_stores_and_reads_back` leaves it `false` for the same reason.
    #[test]
    fn a_debug_line_reaches_the_log_only_behind_the_switch() {
        let _guard = debug_switch_lock();
        let line = || Progress::Debug("claiming alt 0 on interface 0".to_owned());

        let off = Recording::default();
        set_debug(false);
        route(&off, line());
        assert!(off.logs.borrow().is_empty(), "{:?}", off.logs.borrow());
        assert!(off.progress.borrow().is_empty());

        let on = Recording::default();
        set_debug(true);
        route(&on, line());
        set_debug(false);
        assert_eq!(on.logs.borrow().as_slice(), ["claiming alt 0 on interface 0"]);
        assert!(on.progress.borrow().is_empty(), "narration is not a bar update");
    }

    #[test]
    fn a_phase_updates_the_stage_and_resets_the_bar() {
        let sink = Recording::default();
        route(&sink, Progress::Phase(Phase::UBoot));
        assert_eq!(
            sink.progress.borrow().as_slice(),
            [(0, "bootstrap".to_owned(), "Loading U-Boot...".to_owned())]
        );
        assert!(sink.logs.borrow().is_empty());
    }

    /// A read has no knowable total, so its bar is indeterminate from the phase start,
    /// before any byte count arrives. Revert check: send `0` for every phase start and the
    /// app draws an empty determinate bar until the first block.
    #[test]
    fn a_read_starts_indeterminate() {
        let sink = Recording::default();
        route(&sink, Progress::Phase(Phase::Upload));
        assert_eq!(
            sink.progress.borrow().as_slice(),
            [(UNKNOWN, "read".to_owned(), "Reading flash...".to_owned())]
        );
    }

    #[test]
    fn a_byte_counter_becomes_a_percent_stage_and_message() {
        let sink = Recording::default();
        route(
            &sink,
            Progress::Bytes {
                phase: Phase::Download,
                done: 4_718_592,
                total: Some(10_485_760),
            },
        );
        assert_eq!(
            sink.progress.borrow().as_slice(),
            [(
                45,
                "write".to_owned(),
                "Writing flash: 4718592/10485760 bytes".to_owned()
            )]
        );
    }

    /// No total means `UNKNOWN`, with the live count in the message: the app shows an
    /// indeterminate bar and the count, never a `0%` that claims a measurement (the first
    /// app run showed exactly that, stuck through a whole read). Revert check: report `0`
    /// for an unknown total and this fails.
    #[test]
    fn an_unknown_total_is_reported_as_unknown_with_the_live_count() {
        let sink = Recording::default();
        route(
            &sink,
            Progress::Bytes {
                phase: Phase::Upload,
                done: 8_388_608,
                total: None,
            },
        );
        assert_eq!(
            sink.progress.borrow().as_slice(),
            [(UNKNOWN, "read".to_owned(), "Reading flash: 8388608 bytes".to_owned())]
        );
        assert_eq!(UNKNOWN, -1, "the contract with TdfuBridge.kt");
    }

    /// The app shows the stage and message raw, so they are the user's words: a read is a
    /// `read`, never the protocol's `upload`, and the same the other way for a write. The
    /// C bridge's own stage words are the fixture (`tdfu_jni.c:508,547,597,633`). Revert
    /// check: make `stage_word` return `phase.to_string()` and every line here fails.
    #[test]
    fn the_stage_words_are_the_users_not_the_protocols() {
        assert_eq!(stage_word(Phase::Upload), "read");
        assert_eq!(stage_word(Phase::Download), "write");
        assert_eq!(stage_word(Phase::Manifest), "write");
        assert_eq!(stage_word(Phase::Stage1), "bootstrap");
        assert_eq!(stage_word(Phase::UBoot), "bootstrap");
        assert_eq!(stage_word(Phase::Verify), "verify");
        assert_eq!(stage_word(Phase::Erase), "erase");
        assert_eq!(stage_word(Phase::Unknown), "working");
        for phase in [
            Phase::Unknown,
            Phase::Stage1,
            Phase::UBoot,
            Phase::Download,
            Phase::Manifest,
            Phase::Upload,
            Phase::Verify,
            Phase::Erase,
        ] {
            for text in [stage_word(phase), activity(phase)] {
                let lower = text.to_ascii_lowercase();
                assert!(
                    !lower.contains("upload") && !lower.contains("download"),
                    "{phase:?}: {text:?} is protocol wording"
                );
            }
        }
        assert_eq!(activity(Phase::Upload), "Reading flash");
        assert_eq!(activity(Phase::Download), "Writing flash");
    }

    #[test]
    fn percent_is_clamped_and_defended() {
        assert_eq!(percent(0, Some(10)), 0);
        assert_eq!(percent(10, Some(10)), 100);
        assert_eq!(percent(5, Some(10)), 50);
        // Unknown or zero total is answered as unknown, not divided by or called 0%.
        assert_eq!(percent(5, None), UNKNOWN);
        assert_eq!(percent(5, Some(0)), UNKNOWN);
        // A counter that overshoots cannot push the bar past full.
        assert_eq!(percent(20, Some(10)), 100);
        // A very large but honest ratio does not overflow the multiply.
        assert_eq!(percent(u64::MAX, Some(u64::MAX)), 100);
    }
}
