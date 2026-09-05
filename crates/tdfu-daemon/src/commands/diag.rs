//! `CMD_DIAG 0x07` — the eFuse and secure-boot report.
//!
//! Request: `[idx u8]`, and an empty payload means index 0 (`dfu-remote/main.c:745`:
//! `(len >= 1) ? payload[0] : 0`). OK payload is the formatted report; the ERROR payload
//! is the **bare** error string with no prefix (`:755`) — the only two commands that do
//! that are this one and `REBOOT` (`:775`).
//!
//! # The payload is our report, not the C's
//!
//! The payload used to be `tdfu_diag_format`'s text byte for byte. It is
//! not, and has not been since byte-identical output stopped being a goal:
//! it is [`Diag`](tdfu_core::model::Diag)'s `Display`, which keeps the C's banner and its
//! four sections, adds a `Grade regs:` line, rewords the SoC and secure-boot lines and
//! states the eFuse window's length. `tdfu-core/src/ops/diag.rs` is where that document
//! is built and `op_diag_text_is_pinned` is where it is pinned, per family, against bench
//! captures. The C's format is provenance and nothing more.
//!
//! # The trailing newline: we do not send one
//!
//! **The C's payload ends with exactly one `'\n'`.** `tdfu_diag_format` builds the report
//! with `snprintf` appends whose every terminal fragment ends in a newline
//! (`libtdfu/src/diag.c:207`, `:209`, `:211`, `:223`, `:228`-`:246`, `:250`, `:255`),
//! and `main.c:757-759` sends `strlen(report)` bytes of it, so the newline is on the
//! wire. The contracts left the decision here: our `Diag` `Display`
//! deliberately ends without one, and "the daemon appends it if it wants that shape".
//!
//! It does not, because **the report is a document and the wire should carry the
//! document**. The two frontends then render it identically: the local arm prints it
//! through `writeln!` (`tdfu-cli/src/run.rs:359`) and the remote arm trims and re-adds
//! exactly one (`tdfu-cli/src/remote/mod.rs:230-232`), so each renderer supplies its own
//! line ending and the two outputs can be compared as data. A remote tool being *more*
//! informative than its local one is the class of omission this project exists not to
//! repeat, and a one-byte divergence between our own two frontends is the same mistake in
//! miniature.
//!
//! # Zero code executed
//!
//! [`ops::diag`] is one eFuse-window read and one `soc_id` read — no `PROG_STAGE1`, no
//! stub, pinned by `op_diag_no_execution`. The C uploads and runs a
//! hand-assembled MIPS stub to answer the same question.

use tdfu_core::clock::Sleeper;
use tdfu_core::{Error, ops};
use tdfu_usb::LocalUsbBackend;

use super::state::DaemonState;
use super::{Reply, device};
use crate::errors::{DaemonError, wire_message};

/// Read the diagnostics of the device at `index`.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn handle<B, C>(state: &mut DaemonState<B, C>, index: u8) -> Result<Reply, DaemonError>
where
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
    // The ERROR payload is `"Invalid parameter"` when the device is not a
    // bootrom. Refusing here rather than letting the register reads fail keeps that
    // class right *and* says which device and what it is — the reads would have failed
    // as a transport error, which is a different class and a worse message.
    if !selected.is_bootrom() {
        return Ok(Reply::Error(wire_message(&Error::Invalid(format!(
            "device {index} is {}, and diagnostics can only be read from a device in the bootrom",
            selected.describe()
        )))));
    }

    let device = match state.backend.open(&selected.id).await {
        Ok(device) => device,
        Err(error) => return Ok(Reply::Error(wire_message(&Error::from(error)))),
    };
    match ops::diag(&device, &state.clock).await {
        // No trailing newline: see the module docs.
        Ok(diag) => Ok(Reply::Ok(diag.to_string().into_bytes())),
        Err(error) => Ok(Reply::Error(wire_message(&error))),
    }
}

#[cfg(test)]
mod tests {
    use crate::commands::fake::{FakeBackend, LoopbackConn, TestResult};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::{Activity, DaemonState};
    use tdfu_core::clock::RecordingClock;
    use tdfu_proto::{Command, Request, Status};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), "firmware")
    }

    /// A 256-byte eFuse window with a recognisable serial, so the report has something
    /// to decode.
    fn window() -> Vec<u8> {
        let mut window = vec![0_u8; 256];
        window[..16].copy_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ]);
        window
    }

    /// The request layout: one index byte, and an empty payload means 0
    /// (`dfu-remote/main.c:745`).
    #[test]
    fn rpc_diag_index_is_optional() -> TestResult {
        assert_eq!(Request::Diag { index: 0 }.encode()?, vec![0x00]);
        assert_eq!(Request::decode(Command::Diag, &[])?, Request::Diag { index: 0 });
        assert_eq!(Request::decode(Command::Diag, &[3])?, Request::Diag { index: 3 });

        for payload in [Vec::new(), vec![0x00]] {
            let backend = FakeBackend::new(vec![FakeBackend::diagnosable_bootrom(0x1002_3000, window())]);
            let mut state = daemon(backend);
            block_on(seen(&mut state))?;
            let mut conn = LoopbackConn::raw();
            block_on(dispatch(&mut conn, &mut state, Command::Diag, &payload))?;
            assert_eq!(
                conn.response().map(|(status, _)| status),
                Some(Status::Ok),
                "{payload:02X?}"
            );
        }
        Ok(())
    }

    /// The decision this file documents: the payload is exactly the report, with **no**
    /// trailing newline. It is the same document the local `--diag` prints, less the line
    /// ending each renderer supplies itself, which is what makes the two *outputs*
    /// byte-identical.
    #[test]
    fn rpc_diag_payload_has_no_trailing_newline() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::diagnosable_bootrom(0x1002_3000, window())]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Diag, &[0x00]))?;

        let (status, payload) = conn.response().ok_or("one response frame")?;
        assert_eq!(status, Status::Ok);
        let text = String::from_utf8(payload)?;
        assert!(text.starts_with("=== thingino-dfu diagnostics ===\n"), "{text}");
        assert!(
            !text.ends_with('\n'),
            "the wire carries the document, not a line ending"
        );
        assert!(text.contains("eFuse window (phys 0x13540200"), "{text}");
        Ok(())
    }

    /// The ERROR payload is the **bare** error string with no `"diag failed:"`
    /// prefix — this and `REBOOT` are the only two commands that do that
    /// (`dfu-remote/main.c:755`, `:775`).
    #[test]
    fn rpc_diag_errors_are_bare() -> TestResult {
        // An index that names nothing.
        let mut state = daemon(FakeBackend::empty());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Diag, &[0x00]))?;
        let message = conn.error_text().ok_or("an empty bus has no device 0")?;
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(!message.contains("failed:"), "no prefix: {message}");
        Ok(())
    }

    /// A device that is not a bootrom is `"Invalid parameter"` — and it
    /// says which device and what it is, which the C's bare class cannot.
    #[test]
    fn rpc_diag_refuses_a_gadget_as_invalid_parameter() -> TestResult {
        let mut state = daemon(FakeBackend::new(vec![FakeBackend::gadget()]));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Diag, &[0x00]))?;
        let message = conn.error_text().ok_or("a gadget has no eFuse window to read")?;
        assert!(message.starts_with("Invalid parameter: "), "{message}");
        assert!(message.contains("a U-Boot DFU gadget"), "{message}");
        assert!(state.backend.opened().is_empty(), "and nothing was opened");
        Ok(())
    }

    /// `DIAG` attaches no log client on raw TCP, and it claims no state
    /// (`dfu-remote/main.c:744` sets neither).
    #[test]
    fn diag_is_quiet_and_stateless() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::diagnosable_bootrom(0x1002_3000, window())]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Diag, &[0x00]))?;
        assert!(conn.log_lines().is_empty(), "{:?}", conn.log_lines());
        assert!(conn.progress_frames().is_empty());
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// Zero code executed. The scripted double refuses any request that is
    /// not the next expectation, so a `PROG_STAGE1` would fail this rather than pass
    /// quietly — which is the property a scripted double has and prose does not.
    #[test]
    fn op_diag_no_execution() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::diagnosable_bootrom(0x1002_3000, window())]);
        let mut state = daemon(backend);
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Diag, &[0x00]))?;
        assert_eq!(conn.response().map(|(status, _)| status), Some(Status::Ok));
        Ok(())
    }
}
