//! Why a remote run stopped — and, in every case, what actually happened.
//!
//! # This module exists because the C's messages could not carry a cause
//!
//! An audit of `cli/remote.c` found three places where a cause was in hand and thrown
//! away:
//!
//! * **A dropped connection was reported as `Auth failed`.**
//!   `remote_connect` tests `net_recv_all(...) < 0 || resp.status != RESP_OK`
//!   (`cli/remote.c:138`): one branch for "the daemon closed the socket" and "the daemon
//!   rejected the token", which send a user to two completely different places.
//!   [`RemoteError`] keeps them apart, and `an_auth_drop_is_not_an_auth_failure` pins it.
//! * **`Failed to connect to host:port`** (`cli/remote.c:118`), printed after a loop
//!   that tries every address `getaddrinfo` returned (`:104-113`) and discards every
//!   errno. "Connection refused", "no route to host" and a timeout are three different
//!   faults; [`connect_failed`] names each address with the reason that address gave.
//! * **Two remote failure paths printed nothing at all**
//!   and exited non-zero in silence. Nothing here can be constructed without a message.
//!
//! # The exit code comes from `exit.rs`, not from a second table
//!
//! The exit codes are one mapping ([`exit_code`](crate::exit::exit_code)) and this
//! feeds it rather than reimplementing it, which is what stops remote and local
//! contradicting each other. An earlier implementation could never exit **3** remotely,
//! so a file error exited 2 over the network and 3 locally.
//!
//! The [`tdfu_core::Error`] each variant carries is chosen for that mapping and for
//! [`source`](std::error::Error::source); it is **not** what the user reads. The wording
//! is this module's, handed to [`Failure::stating`].

use core::fmt::{self, Write as _};
use std::io;
use std::net::SocketAddr;

use tdfu_core::Error;

use crate::exit::OpClass;
use crate::run::Failure;

/// Where the daemon is, for the messages that have to name it.
///
/// The C formats `%s:%d` at each site (`cli/remote.c:118`); one type means a message
/// cannot name the host and forget the port, and it renders an IPv6 literal the way the
/// rest of the world writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// `--host`, as typed.
    host: String,
    /// `--port`.
    port: u16,
}

impl Address {
    /// The address `--host` and `--port` name.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The host as the user typed it, for [`std::net::ToSocketAddrs`].
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A bracketed literal (`[::1]:5050`) is how an IPv6 address and its port are
        // written everywhere else; a bare `::1:5050` cannot be pasted anywhere.
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// A remote run that stopped, and why.
///
/// Three constructors rather than thirty variants: what a caller must decide is which
/// **class** the failure belongs to, and the wording belongs at the site that has the
/// values (Type 3 again — the C's messages are terse because C makes carrying a cause
/// awkward, and copying the terseness without the necessity is the mistake).
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteError {
    /// The conversation with the daemon failed: resolve, connect, handshake, framing,
    /// a version mismatch, a dropped socket. Exit **4**.
    Protocol(String),
    /// The daemon answered `RESP_ERROR`: the operation was attempted and failed on the
    /// far side. Exit code is the running operation's class — **1** for a device error
    /// and **2** for a transfer — exactly as it would be locally.
    Refused(String),
    /// **This client** refused, about the device rather than about the wire: an empty
    /// bus, an index past the end of the daemon's list, a target in the wrong stage, an
    /// SoC the daemon could not identify, or this crate disagreeing with itself.
    ///
    /// Same exit code as [`Refused`](RemoteError::Refused), and for the same reason: the
    /// identical refusal made without `--host` comes out of
    /// [`class_of`](crate::run::class_of) as **1** or **2**, so answering **4** here
    /// would make the code depend on where the tool ran, which is the local-versus-remote
    /// contradiction one column over. Nothing about the socket failed; the *device* is not what
    /// the command needs.
    Refusal(String),
    /// A local file failed after the preflight: the `-r` output could not be written.
    /// Exit **3**, whatever was running.
    File(io::Error),
}

impl RemoteError {
    /// A wire-level failure: exit 4.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// This client's own refusal about the device, in the running operation's class.
    ///
    /// Use this and not [`protocol`](RemoteError::protocol) for anything that is not the
    /// conversation failing: the socket is fine, and an operator or a wrapper reading
    /// **4** would go looking at the network.
    #[must_use]
    pub fn refusal(message: impl Into<String>) -> Self {
        Self::Refusal(message.into())
    }

    /// The daemon's own `RESP_ERROR`, rendered with what was being attempted.
    ///
    /// `message` is the wire payload: one of the daemon's thirteen terse strings, or a
    /// `"… failed: <err>"` built from one. It is quoted rather than paraphrased: it is
    /// the far side's account and the operator may have to match it against the daemon's
    /// own log.
    #[must_use]
    pub fn refused(at: &Address, doing: &str, message: &str) -> Self {
        if message.is_empty() {
            // The C prints `"unknown"` for a missing payload (`cli/remote.c:655`), which
            // reads as a diagnosis. This says which side went quiet.
            return Self::Refused(format!(
                "the daemon at {at} could not complete {doing}, and sent no reason with the refusal"
            ));
        }
        Self::Refused(format!("the daemon at {at} could not complete {doing}: {message}"))
    }

    /// A local file failure, with what was being attempted already in `what`.
    ///
    /// The same shape [`images`](crate::images) uses: `io::Error` carries no path, so
    /// printing it bare gives `No such file or directory` and nothing else. The caller
    /// has the path — or knows it was stdout — so it goes in the message, and the
    /// `ErrorKind` is preserved so "missing" stays distinguishable from "permission
    /// denied".
    #[must_use]
    pub fn file(what: impl fmt::Display, source: &io::Error) -> Self {
        Self::File(io::Error::new(source.kind(), format!("{what}: {source}")))
    }

    /// Pair this with the operation that was running, for its exit code.
    ///
    /// `class` is used by [`Refused`](RemoteError::Refused) and
    /// [`Refusal`](RemoteError::Refusal): a wire failure is always the protocol class (4)
    /// and a file failure is always 3, whatever was running. That is the half of bug 15
    /// that matters: the code must not depend on whether the tool was pointed at a
    /// daemon.
    #[must_use]
    pub fn failure(self, class: OpClass) -> Failure {
        match self {
            Self::Protocol(message) => Failure::stating(Error::Protocol(message.clone()), OpClass::Remote, message),
            // `Error::Protocol` is the carrier, not the wording: `exit_code` only ever
            // asks whether an error is `Io`/`LoaderMissing`, so any other variant gives
            // the class its code, and this one is at least true for `Refused` (the
            // message did arrive over the protocol) and harmless for `Refusal`, which
            // never reaches `Display` through the error.
            Self::Refused(message) | Self::Refusal(message) => {
                Failure::stating(Error::Protocol(message.clone()), class, message)
            }
            Self::File(source) => {
                let message = source.to_string();
                Failure::stating(Error::Io(source), class, message)
            }
        }
    }
}

impl std::error::Error for RemoteError {
    /// The `io::Error` behind a file failure, and nothing behind the other two: their
    /// message *is* the whole account, built where the values were.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::File(source) => Some(source),
            _ => None,
        }
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(message) | Self::Refused(message) | Self::Refusal(message) => f.write_str(message),
            Self::File(source) => write!(f, "{source}"),
        }
    }
}

/// One address `getaddrinfo` offered, and what it said when it was tried.
#[derive(Debug)]
pub struct Attempt {
    /// The address, as `127.0.0.1:5050` or `[::1]:5050`.
    pub address: SocketAddr,
    /// Why it did not connect.
    pub reason: io::Error,
}

/// Every resolved address failed — say which, and what each one said.
///
/// **This is the worked example of a cause thrown away.** The C prints
/// `Failed to connect to %s:%d` (`cli/remote.c:118`) after a loop that has just seen an
/// errno per address and thrown all of them away (`:104-113`). "Connection refused" means
/// nothing is listening, "no route to host" means the network is wrong and a timeout
/// means a firewall is dropping packets — three different next actions.
#[must_use]
pub fn connect_failed(at: &Address, attempts: &[Attempt]) -> RemoteError {
    let mut message = format!("cannot connect to {at}; every address it resolves to was tried:");
    for attempt in attempts {
        // `io::Error`'s Display for an OS error already reads `Connection refused (os
        // error 111)`, which names the fault and the number to look up. Writing into a
        // String cannot fail; the result is discarded rather than unwrapped because
        // the workspace denies `unwrap` and there is nothing to report.
        let _ = write!(message, "\n  {}: {}", attempt.address, attempt.reason);
    }
    RemoteError::protocol(message)
}

#[cfg(test)]
mod tests {
    use super::{Address, Attempt, RemoteError, connect_failed};
    use crate::exit::{DEVICE, FILE, OpClass, PROTOCOL, TRANSFER};
    use std::io;
    use std::net::SocketAddr;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn at() -> Address {
        Address::new("camera.invalid", 5050)
    }

    /// An IPv6 host keeps its brackets, so the address can be pasted back.
    #[test]
    fn an_address_renders_the_way_it_is_typed() {
        assert_eq!(at().to_string(), "camera.invalid:5050");
        assert_eq!(Address::new("::1", 5050).to_string(), "[::1]:5050");
        assert_eq!(Address::new("10.0.0.2", 1).to_string(), "10.0.0.2:1");
        assert_eq!(at().host(), "camera.invalid");
        assert_eq!(at().port(), 5050);
    }

    /// **Both halves of the exit-code table.** The class decides 1 vs 2; a
    /// wire failure is always 4 and a file failure always 3, whatever was running.
    ///
    /// The end-to-end half of this, the same failure driven locally and remotely with
    /// the two codes side by side, is `fe_cli_remote_exit_codes_match_the_local_ones`
    /// in `remote/tests.rs`. This one pins the mapping; that one pins the pair.
    #[test]
    fn fe_cli_remote_exit_codes() {
        for class in [OpClass::Device, OpClass::Transfer, OpClass::Remote] {
            assert_eq!(
                RemoteError::protocol("dropped").failure(class).exit_code(),
                PROTOCOL,
                "a wire failure is 4 whatever was running"
            );
            assert_eq!(
                RemoteError::File(io::Error::other("disk full"))
                    .failure(class)
                    .exit_code(),
                FILE,
                "a file error is 3 whatever was running — remotely exactly as locally"
            );
        }
        assert_eq!(
            RemoteError::refused(&at(), "the write", "Transfer failed")
                .failure(OpClass::Transfer)
                .exit_code(),
            TRANSFER
        );
        assert_eq!(
            RemoteError::refused(&at(), "the bootstrap", "Device not found")
                .failure(OpClass::Device)
                .exit_code(),
            DEVICE
        );
        // A refusal *this client* made about the device takes the class too,
        // because the identical refusal made without `--host` does.
        assert_eq!(
            RemoteError::refusal("device 0 is not on the daemon's bus")
                .failure(OpClass::Device)
                .exit_code(),
            DEVICE
        );
        assert_eq!(
            RemoteError::refusal("-r reached the wire with no path behind it")
                .failure(OpClass::Transfer)
                .exit_code(),
            TRANSFER
        );
    }

    /// Nothing is silent: every failure renders as the
    /// sentence it was built with, and the `Failure` prints the same thing.
    #[test]
    fn every_failure_says_what_happened() {
        let refused = RemoteError::refused(&at(), "the write", "Device not found");
        assert_eq!(
            refused.to_string(),
            "the daemon at camera.invalid:5050 could not complete the write: Device not found"
        );
        assert_eq!(
            RemoteError::refused(&at(), "the reboot", "")
                .failure(OpClass::Transfer)
                .to_string(),
            "the daemon at camera.invalid:5050 could not complete the reboot, and sent no reason with the refusal"
        );
        assert_eq!(
            RemoteError::protocol("the socket died")
                .failure(OpClass::Remote)
                .to_string(),
            "the socket died"
        );
    }

    /// A file failure names the path and keeps the OS reason and its kind.
    #[test]
    fn a_file_failure_names_the_path_and_the_reason() -> TestResult {
        let error = RemoteError::file(
            "cannot write to /tmp/dump.bin",
            &io::Error::new(io::ErrorKind::StorageFull, "No space left on device"),
        );
        assert_eq!(
            error.to_string(),
            "cannot write to /tmp/dump.bin: No space left on device"
        );
        let RemoteError::File(inner) = &error else {
            return Err("a file failure must stay a file failure".into());
        };
        assert_eq!(inner.kind(), io::ErrorKind::StorageFull, "the kind survives");
        Ok(())
    }

    /// **Type 3's second example.** Every address that was tried, with its own errno.
    #[test]
    fn a_failed_connect_names_every_address_and_its_reason() -> TestResult {
        let attempts = vec![
            Attempt {
                address: "[::1]:5050".parse::<SocketAddr>()?,
                reason: io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused (os error 111)"),
            },
            Attempt {
                address: "127.0.0.1:5050".parse::<SocketAddr>()?,
                reason: io::Error::new(io::ErrorKind::TimedOut, "timed out after 10s"),
            },
        ];
        assert_eq!(
            connect_failed(&at(), &attempts).to_string(),
            "cannot connect to camera.invalid:5050; every address it resolves to was tried:\n  \
             [::1]:5050: Connection refused (os error 111)\n  \
             127.0.0.1:5050: timed out after 10s"
        );
        Ok(())
    }

    /// The cause is reachable, so `anyhow`-style chain printers and `source()` walkers
    /// see something rather than a dead end.
    #[test]
    fn the_cause_survives_into_the_failure() {
        let failure = RemoteError::protocol("version mismatch").failure(OpClass::Remote);
        assert!(std::error::Error::source(&failure).is_some());
    }

    /// A file failure keeps the `io::Error` underneath it; the other two are their own
    /// whole account and have nothing below.
    #[test]
    fn only_a_file_failure_has_a_cause_beneath_it() {
        let file = RemoteError::file("cannot write to /tmp/x", &io::Error::other("disk"));
        let source = std::error::Error::source(&file);
        assert!(
            source.is_some_and(|source| source.to_string().contains("cannot write to /tmp/x")),
            "the io::Error is the cause, and it carries the path"
        );
        assert!(std::error::Error::source(&RemoteError::protocol("dropped")).is_none());
        assert!(std::error::Error::source(&RemoteError::refused(&at(), "the read", "boom")).is_none());
        assert!(std::error::Error::source(&RemoteError::refusal("no devices")).is_none());
    }

    /// A refusal renders as the sentence it was built with, like the other two.
    #[test]
    fn a_client_refusal_says_what_it_refused() {
        assert_eq!(
            RemoteError::refusal("device 3 is not on the daemon's bus").to_string(),
            "device 3 is not on the daemon's bus"
        );
    }
}
