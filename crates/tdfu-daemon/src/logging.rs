//! `-d`/`--debug`: the same subscriber, levels and format `tdfu-cli` installs
//! (`crates/tdfu-cli/src/logging.rs`), so a `-d` run of either binary reads alike.
//!
//! Quiet is `WARN`, not `INFO`: the daemon's narration (the startup lines, `Connection
//! from`) is printed on stdout as the C does, and a warning is something an operator
//! should see without having asked. Auth rejections are `warn!` (`auth.rs`), so a token
//! being guessed at shows up in a quiet log.

use tracing::Level;
use tracing_subscriber::fmt;

/// Without `-d`.
pub const QUIET: Level = Level::WARN;
/// With `-d`.
pub const VERBOSE: Level = Level::DEBUG;

/// The level `debug` selects.
#[must_use]
pub const fn level(debug: bool) -> Level {
    if debug { VERBOSE } else { QUIET }
}

/// Install the global subscriber. Installing twice is not an error: the first one
/// stays, which is what a test that calls this more than once wants.
pub fn init(debug: bool) {
    let subscriber = fmt()
        .with_max_level(level(debug))
        .with_writer(std::io::stderr)
        .with_target(debug)
        .without_time()
        .finish();
    let _ignored = tracing::subscriber::set_global_default(subscriber);
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::{QUIET, VERBOSE, level};

    #[test]
    fn debug_raises_the_level_and_nothing_else_does() {
        assert_eq!(level(false), QUIET);
        assert_eq!(level(true), VERBOSE);
        assert!(VERBOSE > QUIET, "DEBUG must be more verbose than WARN");
    }

    #[test]
    fn installing_the_subscriber_twice_is_not_an_error() {
        super::init(false);
        assert!(
            tracing::dispatcher::has_been_set(),
            "init must install a subscriber, not merely build one"
        );
        super::init(false);
        assert!(tracing::dispatcher::has_been_set());
    }

    /// The daemon's quiet level and the CLI's are the same level, on purpose.
    #[test]
    fn a_quiet_run_still_shows_warnings() {
        assert!(QUIET >= Level::WARN);
        assert!(QUIET < Level::INFO, "INFO is narration, and narration is stdout's job");
    }
}
