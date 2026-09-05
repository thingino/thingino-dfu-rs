//! Running an operation to completion and collapsing it for the JNI boundary.
//!
//! Every device-touching export is one of two shapes: an operation whose result becomes
//! `0`/`-1` ([`finish`]), or detection, which returns the variant name the app displays
//! and feeds back into the next call ([`drive_detect`]). Both log the detail of a failure
//! and let the operation's own progress reach the callback, so the return carries only
//! success or failure, as the app's fixed signatures require, and the *why* goes to
//! `onLog`.
//!
//! The future is built by the caller (an export, where the transport, clock, image and
//! progress relay are all in scope with concrete lifetimes) and handed here already
//! formed. Taking a ready future rather than a closure over the progress sink sidesteps
//! the borrowed-argument async-closure wall, and matches how the CLI and daemon call
//! `ops::*`: build the sink, call the op, block on it.

use core::future::Future;

use tdfu_core::Result;
use tdfu_core::clock::BlockingClock;
use tdfu_core::model::Detection;
use tdfu_core::ops::detect;
use tdfu_usb::LocalUsbTransport;

use crate::callback::{Sink, debug_enabled, debug_log};
use crate::exec::block_on;

/// Drive `operation` to completion and collapse it to `0` (success) or `-1` (failure).
///
/// The `Ok` payload is ignored - `read` returns a byte count that the app does not need at
/// the boundary - and only a failure is logged, prefixed with `failure`: the operation's
/// own completion notes (`DFU download complete`, `Verify OK`, ...) come through the
/// progress sink from core. The one thing success adds is the C bridge's 100% progress
/// line, which the exports send after this returns (`exports::complete`).
pub(crate) fn finish<T>(sink: &dyn Sink, failure: &str, operation: impl Future<Output = Result<T>>) -> i32 {
    match block_on(operation) {
        Ok(_) => 0,
        Err(error) => {
            sink.log(&format!("{failure}: {error}"));
            -1
        }
    }
}

/// Detect the SoC and return the app-facing variant name, or an empty string on failure.
///
/// The name is [`Variant::loader_dir`](tdfu_core::model::Variant::loader_dir), a canonical
/// wire spelling: the app displays it (`SoC: T41NQ`) and passes it straight back into
/// `nativeBootstrap`, where [`asset_dir`](crate::variant::asset_dir) resolves to its
/// bundled directory. An empty string is the app's "detection failed" signal, and its
/// Kotlin side then defaults to `t31x` with a note (`DfuActivity.detectSoc`).
pub(crate) fn drive_detect<T: LocalUsbTransport>(sink: &dyn Sink, dev: &T) -> String {
    match block_on(detect(dev, &BlockingClock)) {
        Ok(detection) => render_detection(sink, &detection),
        Err(error) => {
            sink.log(&format!("SoC detection failed: {error}"));
            String::new()
        }
    }
}

/// Turn a [`Detection`] into the returned name, logging the qualification that belongs
/// with it.
fn render_detection(sink: &dyn Sink, detection: &Detection) -> String {
    // What the CLI's `-d` logs as "identified": the registers and the row they matched,
    // which is what a wrong or surprising answer needs in a report.
    debug_log(|| match detection {
        Detection::Resolved(resolved) => format!(
            "identified: chip={} grade={:#06X} evidence={:?} loader={} regs={:?}",
            resolved.chip,
            resolved.grade,
            resolved.evidence,
            resolved.variant.loader_dir(),
            resolved.regs
        ),
        other => format!("not resolved: regs={:?}", other.regs()),
    });
    // Debug logging shows the full caveat (including a "documented, never bench-seen" note
    // that `warning` suppresses beside a working detection); otherwise the user-facing
    // subset. This is what `nativeSetDebug` gates on this side of the boundary.
    let note = if debug_enabled() {
        detection.caveat()
    } else {
        detection.warning()
    };
    if let Some(note) = note {
        sink.log(&note);
    }

    if let Some(variant) = detection.variant() {
        let name = variant.loader_dir();
        sink.log(&format!("Detected SoC: {name}"));
        name.to_owned()
    } else {
        // Ambiguous or unknown: no single loader is safe to pick, so the app is told and
        // falls back to its own default rather than us flashing a guess.
        sink.log("SoC grade could not be resolved uniquely; select a CPU to override");
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use tdfu_core::Error;
    use tdfu_core::progress::{Phase, Progress};
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on as mock_block_on};
    use tdfu_usb::{ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Recipient, endpoint, pid, vid};

    use super::{drive_detect, finish};
    use crate::callback::Sink;
    use crate::progress::route;

    /// A sink that records everything, for asserting what reached the callback.
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

    /// A successful operation returns 0 and logs no failure.
    #[test]
    fn success_returns_zero() {
        let sink = Recording::default();
        let code = finish(&sink, "DFU write failed", async { Ok::<(), Error>(()) });
        assert_eq!(code, 0);
        assert!(sink.logs.borrow().is_empty());
    }

    /// A failing operation returns -1 and logs the detail behind the prefix.
    #[test]
    fn failure_returns_minus_one_and_logs_the_detail() {
        let sink = Recording::default();
        let code = finish(&sink, "DFU write failed", async {
            Err::<(), _>(Error::Invalid("the image is empty".to_owned()))
        });
        assert_eq!(code, -1);
        assert_eq!(
            sink.logs.borrow().as_slice(),
            ["DFU write failed: invalid input: the image is empty"]
        );
    }

    /// The progress a driven operation reports reaches the callback through the relay the
    /// export builds - the wiring an export uses, exercised end to end on the host.
    #[test]
    fn progress_reaches_the_callback_through_the_relay() {
        let sink = Recording::default();
        let relay = |progress: Progress| route(&sink, progress);
        let operation = async {
            relay(Progress::Bytes {
                phase: Phase::Download,
                done: 5,
                total: Some(10),
            });
            relay(Progress::Note("DFU download complete".to_owned()));
            Ok::<(), Error>(())
        };
        assert_eq!(finish(&sink, "DFU write failed", operation), 0);
        assert_eq!(
            sink.progress.borrow().as_slice(),
            [(50, "write".to_owned(), "Writing flash: 5/10 bytes".to_owned())]
        );
        assert_eq!(sink.logs.borrow().as_slice(), ["DFU download complete"]);
    }

    // --- detection against a scripted bootrom: the real op through the driver ---

    fn bootrom_descriptors() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("\u{c3}\t USB Boot Device")
    }

    fn bootrom_interface() -> InterfaceSpec {
        InterfaceSpec::with_bulk(0, endpoint::BOOTROM_IN, endpoint::BOOTROM_OUT)
    }

    fn halves(value: u32) -> (u16, u16) {
        (
            u16::try_from(value >> 16).unwrap_or_default(),
            u16::try_from(value & 0xFFFF).unwrap_or_default(),
        )
    }

    /// One register read: `SET_DATA_ADDR`, `SET_DATA_LEN`, bulk IN; address and length split across wValue and wIndex.
    fn one_register_read(mock: MockTransport, address: u32, word: u32) -> MockTransport {
        let addr = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: tdfu_core::bootrom::request::SET_DATA_ADDR,
            value: halves(address).0,
            index: halves(address).1,
            data: &[],
        };
        let len = ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: tdfu_core::bootrom::request::SET_DATA_LEN,
            value: halves(4).0,
            index: halves(4).1,
            data: &[],
        };
        mock.expecting(Call::control_out(addr), Reply::Done)
            .expecting(Call::control_out(len), Reply::Done)
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(word.to_le_bytes().to_vec()))
    }

    /// A scripted T41NQ bootrom drives detection through `drive_detect` and comes back as
    /// the app-facing name, logged the way the app expects.
    #[test]
    fn detection_returns_the_app_facing_name() {
        let mut mock = MockTransport::new(bootrom_descriptors())
            .configured(1)
            .expecting(Call::ClaimInterface(bootrom_interface()), Reply::Done);
        mock = one_register_read(mock, tdfu_core::addr::SOC_ID.get(), 0x1004_0003);
        mock = one_register_read(mock, tdfu_core::addr::SUBSOCTYPE1.get(), 0x0000_0000);
        mock = one_register_read(mock, tdfu_core::addr::SUBSOCTYPE2.get(), 0xAAAA_2222);
        let mock = mock.expecting(Call::ReleaseInterface(0), Reply::Done);

        let sink = Recording::default();
        let name = mock_block_on(async { drive_detect(&sink, &mock) });
        assert_eq!(name, "t41nq");
        assert!(
            sink.logs.borrow().iter().any(|line| line == "Detected SoC: t41nq"),
            "detection did not log the app-facing name: {:?}",
            sink.logs.borrow()
        );
    }

    /// A device that is not answering as a bootrom comes back empty - the app's
    /// "defaulting" signal - with the failure logged.
    #[test]
    fn a_failed_detection_returns_empty_and_logs() {
        // No script: the claim the detect op issues first is unexpected, so the mock fails
        // it, `ops::detect` errors, and the driver reports empty.
        let mock = MockTransport::new(bootrom_descriptors());
        let sink = Recording::default();
        let name = mock_block_on(async { drive_detect(&sink, &mock) });
        assert!(name.is_empty(), "a non-bootrom must not resolve to a name");
        assert!(
            sink.logs
                .borrow()
                .iter()
                .any(|line| line.starts_with("SoC detection failed")),
            "the failure was not logged: {:?}",
            sink.logs.borrow()
        );
    }
}
