//! The `dfu-remote` binary: the command line, logging and the signals that end it.
//! Everything else is the library's, where it is tested without a process (`serve`,
//! `listen`, `transport`, `commands`).
//!
//! Exit status: 0 after `-h` or a signal, 1 for a command line the daemon cannot use
//! or a socket it cannot open: the C's `return 1` (`dfu-remote/main.c:1076` for the
//! socket, `:1105` for the bind, `:1111` for the listen).
//!
//! # The banner
//!
//! `dfu-remote 2.0.0-alpha.1 (a1b2c3d)` on **stderr**, before anything else, for the
//! reason [`tdfu_core::build`] gives: a pasted log that does not say which build wrote it
//! costs a round trip. The version and the hash are that module's, shared with the CLI and
//! the page, so the three cannot disagree and the `TDFU_GIT_HASH` rule lives once;
//! `cargo xtask package` and the release workflow set it for the whole workspace in
//! one build.
//!
//! Stderr rather than stdout, unlike the daemon's other startup lines: those are
//! something a wrapper reads to learn the port, and a build identity line does
//! not belong in front of them.

use std::io::{self, Write};
use std::process::ExitCode;

use tdfu_daemon::TokioClock;
use tdfu_daemon::commands::state::DaemonState;
use tdfu_daemon::listen::bind;
use tdfu_daemon::logging;
use tdfu_daemon::serve::{Signals, say, serve};
use tdfu_daemon::transport::{Options, Parsed};
use tdfu_usb::native::NativeBackend;

/// The name the binary is invoked by.
const NAME: &str = "dfu-remote";

/// The banner line, without its newline.
///
/// The version and the hash are [`tdfu_core::build`]'s, the one reader of
/// `TDFU_GIT_HASH`, shared with the CLI and the page.
fn banner() -> String {
    tdfu_core::build::banner(NAME)
}

fn main() -> ExitCode {
    // First thing, before parsing, as the CLI does: a `-h` or a refused argument should
    // still say which build refused it. A banner that cannot be written is not a reason
    // to refuse to serve.
    let _ignored = writeln!(io::stderr(), "{}", banner());

    let options = match Options::from_env() {
        Ok(Parsed::Help(text)) => {
            say(text.trim_end_matches('\n'));
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Run(options)) => *options,
        Err(error) => {
            eprintln!("dfu-remote: {error}");
            eprintln!("Try `dfu-remote --help`.");
            return ExitCode::FAILURE;
        }
    };
    logging::init(options.debug);

    // Decision D1: the core is `?Send` and the daemon serves one client at a time, so
    // one thread is the whole runtime.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("dfu-remote: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run(options))
}

async fn run(options: Options) -> ExitCode {
    let listener = match bind(&options.socket_addrs()) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("dfu-remote: {error}");
            return ExitCode::FAILURE;
        }
    };
    let bound = match listener.local_addr() {
        Ok(bound) => bound,
        Err(error) => {
            eprintln!("dfu-remote: cannot tell what address was bound: {error}");
            return ExitCode::FAILURE;
        }
    };
    for line in options.startup_lines(bound) {
        say(&line);
    }

    let auth = options.auth();
    let origins = options.origins();
    let mut state = DaemonState::new(NativeBackend, TokioClock, options.firmware_dir.clone());
    serve(
        listener,
        &auth,
        options.timeouts,
        &origins,
        &mut state,
        Interrupts::open(),
    )
    .await;
    say("dfu-remote: shutting down");
    ExitCode::SUCCESS
}

/// SIGINT and SIGTERM, as a **stream**, which is the C's `signal_handler`
/// (`dfu-remote/main.c:89-98`), installed at `:1057` and `:1059`.
///
/// A stream rather than one future because [`Signals`] needs to tell the first signal
/// from the second: the first finishes the command in flight, the second
/// drops it. The two `Signal` handles are opened **once** and kept, because tokio latches
/// a delivery in the handle: rebuilding them per call would lose a signal that arrived
/// between two waits, which is exactly the second Ctrl-C an operator is pressing.
///
/// A signal that cannot be listened for is not a reason to stop: `next` then never
/// resolves, and the daemon runs until the socket closes.
#[derive(Debug, Default)]
struct Interrupts {
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
}

impl Interrupts {
    fn open() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Self {
                interrupt: signal(SignalKind::interrupt()).ok(),
                terminate: signal(SignalKind::terminate()).ok(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }
}

impl Signals for Interrupts {
    async fn next(&mut self) {
        #[cfg(unix)]
        {
            match (self.interrupt.as_mut(), self.terminate.as_mut()) {
                (Some(interrupt), Some(terminate)) => {
                    tokio::select! {
                        _ = interrupt.recv() => {}
                        _ = terminate.recv() => {}
                    }
                }
                (Some(only), None) | (None, Some(only)) => {
                    let _delivered = only.recv().await;
                }
                (None, None) => std::future::pending::<()>().await,
            }
        }
        #[cfg(not(unix))]
        {
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// The banner's shape, on every platform (the signal tests below are unix-only).
#[cfg(test)]
mod banner_tests {
    use tdfu_core::build::HASH;

    use super::{NAME, banner};

    /// The shape is pinned; the hash value deliberately is not, so this passes whether or
    /// not `TDFU_GIT_HASH` was set for the build. The twin of
    /// `tdfu_cli::banner`'s `the_banner_names_the_build_without_depending_on_it`.
    #[test]
    fn the_banner_names_the_build_without_depending_on_it() {
        let line = banner();
        assert!(
            line.starts_with(&format!("{NAME} {} (", env!("CARGO_PKG_VERSION"))),
            "{line}"
        );
        assert!(line.ends_with(')'), "{line}");
        assert!(!HASH.is_empty(), "an empty build id would render as `()`");
        assert!(!line.contains('\n'), "the banner is one line: {line}");
    }

    /// The two binaries report the same version and the same build, because they share
    /// `tdfu_core::build`, built from one tree with one `TDFU_GIT_HASH`. Only the name
    /// differs.
    #[test]
    fn it_differs_from_the_cli_banner_only_in_the_name() {
        assert_eq!(NAME, "dfu-remote");
        assert_eq!(banner(), format!("dfu-remote {} ({HASH})", env!("CARGO_PKG_VERSION")));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use core::time::Duration;

    use tdfu_daemon::serve::Signals as _;

    use super::Interrupts;

    /// How long a `next()` that should not resolve is given to prove it.
    const SETTLE: Duration = Duration::from_millis(50);

    /// An audit found `main.rs` with no test at all, and the two-signal handling here is
    /// new code. These two are what a unit test can honestly reach: the
    /// handles are opened, and waiting for a signal that has not arrived does not resolve.
    ///
    /// **Not tested here: that a delivered SIGINT resolves `next`.** Proving that means
    /// raising a real signal in the test binary, and the one thing that would have to go
    /// wrong for that to kill the runner is `signal()` failing to register, which is the
    /// same failure the first test below rules out. The recv itself is tokio's.
    #[tokio::test]
    async fn both_signals_are_listened_for() {
        // `signal()` registers with the runtime's signal driver, so it needs one.
        let interrupts = Interrupts::open();
        assert!(interrupts.interrupt.is_some(), "SIGINT, `dfu-remote/main.c:1057`");
        assert!(interrupts.terminate.is_some(), "SIGTERM, `:1059`");
    }

    /// A `next()` with no signal delivered must wait, or the daemon stops the moment it
    /// starts.
    #[tokio::test]
    async fn nothing_resolves_without_a_signal() {
        let mut interrupts = Interrupts::open();
        let waited = tokio::time::timeout(SETTLE, interrupts.next()).await;
        assert!(waited.is_err(), "next() resolved with no signal delivered");
    }

    /// And a daemon that could listen for **neither** signal keeps running rather than
    /// stopping at once, which is what the doc on [`Interrupts`] promises.
    #[tokio::test]
    async fn a_daemon_that_cannot_listen_does_not_stop() {
        let mut deaf = Interrupts {
            interrupt: None,
            terminate: None,
        };
        let waited = tokio::time::timeout(SETTLE, deaf.next()).await;
        assert!(waited.is_err(), "a signal that cannot be listened for stopped it");
    }
}
