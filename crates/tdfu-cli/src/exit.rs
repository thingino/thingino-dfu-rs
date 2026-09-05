//! Exit codes: 0, 1, 2, 3, 4, each from the thing that produces it.

use tdfu_core::Error;

/// Everything worked.
pub const OK: u8 = 0;
/// A device error: init, bootstrap, probe, diag, no alt.
pub const DEVICE: u8 = 1;
/// A transfer error: write, read, erase, reboot, verify.
pub const TRANSFER: u8 = 2;
/// A file error.
pub const FILE: u8 = 3;
/// A protocol error, including a failed remote connect.
pub const PROTOCOL: u8 = 4;

/// Which operation was running when the error happened.
///
/// The class decides between [`DEVICE`] and [`TRANSFER`] for errors that could be
/// either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpClass {
    /// Init, bootstrap, probe, diag, list.
    Device,
    /// Write, read, erase, reboot, verify.
    Transfer,
    /// Anything over the network.
    Remote,
}

/// The exit code for `error`, given what was running.
///
/// **A file error exits 3, whichever operation was running.** `EXIT_FILE_ERROR = 3` is
/// defined in the C's `protocol.h:22`, asserted in one of its unit tests, and returned
/// by **nothing**: a missing `-w` image exits 2 and a missing loader exits 1. The C
/// defined the code and then never returned it, so what is implemented here is the C's
/// stated behaviour rather than its actual one, and the divergence is deliberate: a file
/// error is a file error whatever the tool happened to be doing at the time.
///
/// The same code must come back from remote mode. An earlier implementation could never
/// exit 3 remotely, so a file error exited 2 over the network and 3 locally, the tool
/// contradicting itself.
#[must_use]
pub fn exit_code(error: &Error, class: OpClass) -> u8 {
    match error {
        Error::Io(_) | Error::LoaderMissing(_) => FILE,
        _ => match class {
            OpClass::Device => DEVICE,
            OpClass::Transfer => TRANSFER,
            OpClass::Remote => PROTOCOL,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{DEVICE, FILE, OpClass, TRANSFER, exit_code};
    use tdfu_core::Error;

    #[test]
    fn fe_cli_file_errors_exit_three_whatever_was_running() {
        let io = Error::Io(std::io::Error::other("no such file"));
        assert_eq!(exit_code(&io, OpClass::Device), FILE);
        assert_eq!(exit_code(&io, OpClass::Transfer), FILE);
        assert_eq!(exit_code(&io, OpClass::Remote), FILE);

        let missing = Error::LoaderMissing("t41nq/u-boot-lzo-with-spl.bin".into());
        assert_eq!(exit_code(&missing, OpClass::Device), FILE);
    }

    #[test]
    fn fe_cli_other_errors_take_their_operation_class() {
        let not_dfu = Error::NotDfu;
        assert_eq!(exit_code(&not_dfu, OpClass::Device), DEVICE);
        assert_eq!(exit_code(&not_dfu, OpClass::Transfer), TRANSFER);
    }
}
