//! `-d`/`--debug`: the diagnostics, on stderr, with the level in front.
//!
//! The shape is settled: `tracing` carries the diagnostics, "where the level
//! prefix *is* the information", while the operation's own narration — core's
//! [`Progress::Note`](tdfu_core::Progress::Note)s and this crate's tables — goes through
//! one renderer with no prefix at all. An earlier implementation mixed the two and had
//! the CLI's own lines wearing an ` INFO ` prefix beside core's raw ones.
//!
//! Everything here goes to **stderr**, so `-d` never contaminates a piped `-l`.
//!
//! # What is deliberately not here
//!
//! No `env-filter`: it pulls a regex engine and a matcher crate to interpret a variable
//! this build has no levels to select between. `-d` is the one knob, and when the flag
//! surface grows a reason for more, `RUST_LOG` support is an additive change in this
//! file.

use tracing::Level;
use tracing_subscriber::fmt;

/// The level a quiet run reports at: warnings and errors only.
pub const QUIET: Level = Level::WARN;

/// The level `-d` selects.
pub const VERBOSE: Level = Level::DEBUG;

/// The level for a given `--debug` state.
#[must_use]
pub const fn level(debug: bool) -> Level {
    if debug { VERBOSE } else { QUIET }
}

/// The subscriber [`init`] installs.
///
/// Built apart from installing it so that what it *is* can be checked without deciding
/// what the whole process logs: [`tracing::subscriber::set_global_default`] is per process
/// and irreversible, so a test that calls it hands its configuration to every test that
/// runs after it in the same binary.
fn subscriber(debug: bool) -> impl tracing::Subscriber + Send + Sync + 'static {
    fmt()
        .with_max_level(level(debug))
        .with_writer(std::io::stderr)
        // The module path is noise until it is not: with `-d` it says which layer a
        // line came from, which is the whole reason to turn it on.
        .with_target(debug)
        // No timestamps. A run is seconds long and the lines are already ordered;
        // a wall clock in front of every one of them only makes them harder to read.
        .without_time()
        .finish()
}

/// Install the process-wide subscriber.
///
/// Idempotent by omission: a second call is ignored rather than reported, because
/// nothing a caller could do about it is better than carrying on, and a flashing tool
/// must not abort on a logging detail. `main` calls it once, before anything else.
pub fn init(debug: bool) {
    let _ignored = tracing::subscriber::set_global_default(subscriber(debug));
}

#[cfg(test)]
mod tests {
    use super::{QUIET, VERBOSE, level};
    use tracing::Level;

    #[test]
    fn debug_raises_the_level_and_nothing_else_does() {
        assert_eq!(level(false), QUIET);
        assert_eq!(level(true), VERBOSE);
        assert!(VERBOSE > QUIET, "DEBUG must be more verbose than WARN");
    }

    /// `-d` is the whole knob, and it reaches the subscriber that is installed.
    ///
    /// **Scoped, never global.** `set_global_default` is per process and irreversible, so
    /// a test that installs one decides what every other test in the binary logs from
    /// then on, and `init` anywhere else becomes a call that reports nothing: a `DEBUG`
    /// subscriber would write every other test's diagnostics to a stderr the harness does
    /// not capture, and a quiet one would silence a future test that asserts on `-d`
    /// output. `set_default` is the thread-local form and its guard undoes it here, which
    /// is what lets the level be read off a real dispatcher instead of a builder.
    #[test]
    fn the_installed_subscriber_carries_the_level_the_flag_asks_for() {
        use tracing::level_filters::LevelFilter;

        {
            let _scoped = tracing::subscriber::set_default(super::subscriber(false));
            assert_eq!(LevelFilter::current(), LevelFilter::WARN, "a quiet run");
            assert!(!tracing::enabled!(Level::DEBUG), "and no diagnostics in it");
        }
        {
            let _scoped = tracing::subscriber::set_default(super::subscriber(true));
            assert_eq!(LevelFilter::current(), LevelFilter::DEBUG, "-d");
            assert!(tracing::enabled!(Level::DEBUG));
        }
    }

    /// A quiet run still reports problems: `tracing::warn!` and `error!` are not
    /// filtered out by the default level.
    #[test]
    fn a_quiet_run_still_shows_warnings() {
        assert!(QUIET >= Level::WARN);
        assert!(QUIET < Level::INFO, "INFO is narration, and narration is not logging");
    }
}
