//! The `thingino-dfu` binary.
//!
//! This file is the only place that names a concrete backend or a concrete clock.
//! Everything it calls is generic over [`LocalUsbBackend`](tdfu_usb::LocalUsbBackend)
//! and [`Sleeper`](tdfu_core::clock::Sleeper) and is tested against a scripted double.
//! An earlier implementation hard-wired `NativeBackend` into `main` and left it at 6%
//! coverage, so the wiring is deliberately the only thing here.

use std::io::{self, Write as _};
use std::process::ExitCode;

use clap::Parser as _;
use tdfu_cli::cli::Cli;
use tdfu_cli::{banner, exit, logging, run, runtime};
use tdfu_core::clock::BlockingClock;
use tdfu_usb::native::NativeBackend;

fn main() -> ExitCode {
    let mut err = io::stderr();

    // First thing, before parsing, exactly as the C does (`cli/main.c:296`): a `-h` or a
    // refused argument should still say which build refused it. A banner that cannot be
    // written is not a reason to refuse to flash a camera.
    let _ignored = banner::print(&mut err);

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_usage(&error),
    };
    logging::init(cli.debug);

    let plan = match cli.into_plan() {
        Ok(plan) => plan,
        Err(error) => {
            let _ignored = writeln!(err, "{error}");
            // The C prints `No action specified. Use -h for help.` and returns 1
            // (`cli/main.c:424-428`).
            return ExitCode::from(exit::DEVICE);
        }
    };

    let mut out = io::stdout();
    match runtime::block_on(run::run(&NativeBackend, &BlockingClock, &plan, &mut out, &mut err)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ignored = writeln!(err, "{failure}");
            ExitCode::from(failure.exit_code())
        }
    }
}

/// Print `clap`'s own message and pick an exit code that does not collide with
/// this tool's own.
///
/// `clap` exits **2** for a usage error by default, and 2 is this tool's *transfer
/// error* — the code a wrapper checks to find out whether a flash failed. A typo'd flag
/// must not look like a failed write. The C returns **1** from a bad argument
/// (`cli/main.c:325-327`) and `exit(0)` from `-h` (`cli/main.c:90-92`); both are kept,
/// with `clap`'s much better message text.
fn report_usage(error: &clap::Error) -> ExitCode {
    // `print` writes help and `--version` to stdout and real errors to stderr.
    let _ignored = error.print();
    if error.use_stderr() {
        ExitCode::from(exit::DEVICE)
    } else {
        ExitCode::SUCCESS
    }
}
