//! `CMD_REBOOT 0x08` — reset the SoC.
//!
//! Request: `[idx u8]`, empty meaning 0 (`dfu-remote/main.c:766`). The OK payload is
//! **empty** — `send_ok(client_fd, NULL, 0)` at `:776`, and `send_response` skips the
//! body entirely when the length is 0 (`:166-169`). It is the only success in the whole
//! daemon that does not carry `"OK"`, and a client that reads two bytes here would hang.
//! The ERROR payload is the bare error string with no prefix (`:775`), as `DIAG`'s is.
//!
//! # No re-enumeration window
//!
//! Unlike `WRITE` and `READ`, this does not wait for a gadget: the C calls
//! `tdfu_dfu_reboot` straight through with no `dfu_pick_alt` (`main.c:772`), and the
//! CLI sends `REBOOT` last, after a transfer that has already brought the
//! gadget up. Adding a 30 s wait here would turn "there is nothing to reboot" into half
//! a minute of silence.
//!
//! # The ZLP's failure is fatal; the poll's is the success signal
//!
//! That distinction lives in [`ops::reboot`], and it is a deliberate divergence:
//! the C discards the return of both the zero-length `DNLOAD`
//! and the poll after it (`libtdfu/src/dfu/dfu.c:779-782`), so past that line
//! `tdfu_dfu_reboot_device` cannot fail and `"Reboot triggered"` can be a lie the user
//! acts on. Nothing here re-implements it — the operation is composed, never copied.

use tdfu_core::clock::Sleeper;
use tdfu_core::{Error, ops};
use tdfu_proto::Command;
use tdfu_usb::LocalUsbBackend;

use super::report::{Queue, pump};
use super::state::DaemonState;
use super::{Reply, Wire, device};
use crate::errors::{DaemonError, wire_message};

/// Reboot the device at `index`.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn handle<W, B, C>(conn: &mut W, state: &mut DaemonState<B, C>, index: u8) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    let row = match state.row(index) {
        Ok(row) => row.clone(),
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };
    let selected = match device::select(&state.backend, index, &row).await {
        Ok(selected) => selected,
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };
    // Only the loader has a `reboot` alt, so a device that is not one is refused before
    // it is opened, as `BOOTSTRAP` and `DIAG` refuse theirs. Opening first and letting
    // the alt lookup fail answers a transport-class error for a device that was never
    // eligible, and on a host where opening vendor firmware needs privileges it answers
    // an access-denied instead.
    if !selected.is_gadget() {
        return Ok(Reply::Error(wire_message(&Error::Invalid(format!(
            "device {index} is {}, and only a U-Boot DFU gadget can be rebooted",
            selected.describe()
        )))));
    }
    let device = match state.backend.open(&selected.id).await {
        Ok(device) => device,
        Err(error) => return Ok(Reply::Error(wire_message(&Error::from(error)))),
    };

    let queue = Queue::new();
    let outcome = {
        let mut sink = queue.sink();
        pump(
            conn,
            Command::Reboot,
            &queue,
            ops::reboot(&device, &state.clock, &mut sink),
        )
        .await?
    };
    match outcome {
        // Empty, not `"OK"`.
        Ok(()) => Ok(Reply::Ok(Vec::new())),
        Err(error) => Ok(Reply::Error(wire_message(&error))),
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::fake::{FakeBackend, LoopbackConn, Sent, TestResult, t23_regs};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::{Activity, DaemonState};
    use tdfu_core::clock::RecordingClock;
    use tdfu_proto::{Command, Request, Status};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware")
    }

    /// The OK payload is **empty**, the one success in the protocol that
    /// does not carry `"OK"` (`dfu-remote/main.c:776`).
    #[test]
    fn rpc_reboot_empty_ok() -> TestResult {
        assert_eq!(Request::Reboot { index: 0 }.encode()?, vec![0x00]);
        assert_eq!(Request::decode(Command::Reboot, &[])?, Request::Reboot { index: 0 });

        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Reboot, &[0x00]))?;
        assert_eq!(conn.response(), Some((Status::Ok, Vec::new())));
        assert_ne!(conn.response(), Some((Status::Ok, b"OK".to_vec())));

        let gadget = state.backend.gadget_at(0).ok_or("row 0 is the emulator")?;
        assert_eq!(gadget.reboots(), 1, "the loader really reset");
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// The ERROR payload is bare, like `DIAG`'s (`dfu-remote/main.c:775`).
    #[test]
    fn rpc_reboot_errors_are_bare() -> TestResult {
        let mut state = daemon(FakeBackend::empty());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Reboot, &[0x00]))?;
        let message = conn.error_text().ok_or("an empty bus has no device 0")?;
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(!message.contains("failed:"), "no prefix: {message}");
        Ok(())
    }

    /// A device that is not the loader is refused **before it is opened**, as `DIAG` and
    /// `BOOTSTRAP` refuse theirs. Only U-Boot has a `reboot` alt, so opening a bootrom
    /// and letting the alt lookup fail answers a transport-class error for a device that
    /// was never eligible.
    #[test]
    fn only_a_gadget_is_rebooted() -> TestResult {
        for (row, expected) in [
            (FakeBackend::bootrom(t23_regs()), "in the bootrom"),
            (FakeBackend::firmware(), "running vendor firmware"),
            (FakeBackend::opaque(), "of an unrecognised kind"),
        ] {
            let mut state = daemon(FakeBackend::new(vec![row]));
            block_on(seen(&mut state))?;
            let mut conn = LoopbackConn::raw();
            block_on(dispatch(&mut conn, &mut state, Command::Reboot, &[0x00]))?;
            let message = conn.error_text().ok_or("must be refused")?;
            assert!(message.starts_with("Invalid parameter: "), "{message}");
            assert!(message.contains(expected), "{message}");
            assert!(state.backend.opened().is_empty(), "and nothing was opened");
        }
        Ok(())
    }

    /// A loader with no `reboot` alt takes the C's mapping, end to end:
    /// `Error::MissingAlt` becomes `"Invalid parameter"` and not a new string
    /// (`dfu.c:756`).
    #[test]
    fn gap_r_a_loader_without_a_reboot_alt_is_invalid_parameter() -> TestResult {
        // A single-alt gadget: `flash` only, no `reboot`.
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::flash_only_gadget()]));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Reboot, &[0x00]))?;
        let message = conn.error_text().ok_or("a loader with no reboot alt must refuse")?;
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(message.contains("reboot"), "{message}");
        assert!(message.contains("update the DFU loader firmware"), "{message}");
        Ok(())
    }

    /// No `"OK"`, and no progress either: `REBOOT` attaches no
    /// log client on raw TCP, so core's two notes stay local.
    #[test]
    fn reboot_is_quiet_on_raw_tcp_and_speaks_over_http() -> TestResult {
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        let mut raw = LoopbackConn::raw();
        block_on(dispatch(&mut raw, &mut state, Command::Reboot, &[0x00]))?;
        assert_eq!(raw.sent(), vec![Sent::Response(Status::Ok, Vec::new())]);

        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        let mut http = LoopbackConn::http();
        block_on(dispatch(&mut http, &mut state, Command::Reboot, &[0x00]))?;
        assert!(
            http.log_lines().iter().any(|line| line.contains("Reboot triggered")),
            "attaches every command over HTTP: {:?}",
            http.log_lines()
        );
        Ok(())
    }
}
