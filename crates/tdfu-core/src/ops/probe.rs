//! Ask a DFU gadget what it offers.

use tdfu_usb::LocalUsbTransport;

use crate::clock::Sleeper;
use crate::dfu::descriptors::read_info;
use crate::dfu::host::reset_and_retry_once;
use crate::error::Result;
use crate::model::DfuInfo;
use crate::progress::{ProgressSink, sink_ignore};

/// Read the DFU interface, its alts and its functional descriptor.
///
/// **This retries.** A recoverable failure gets a USB reset and one more
/// attempt (`dfu.c:501-508`). An earlier implementation dropped that, so a standalone
/// `-l` or a daemon probe reported `NotDfu` where the C recovered a wedged gadget — **the
/// only functional-parity regression an audit found**. It is
/// not optional: a gadget left mid-transaction by a killed run is a routine bench
/// state, and the reset is what clears it.
///
/// **This form announces nothing**, because it has no sink to announce into: the note
/// [`reset_and_retry_once`] emits goes into a discarding one. A bus reset the operator
/// cannot see is a re-enumeration in `dmesg` and about 1.5 s of silence with nothing to
/// explain either, so a caller with somewhere to put a line should call
/// [`probe_with_progress`] and pass the sink it already has.
///
/// **The stage check is the caller's.** [`Error::NotDfu`](crate::Error::NotDfu) is
/// recoverable and a bootrom answers exactly that, so a probe aimed at one bus-resets it
/// before answering honestly; the bootrom and the gadget share `a108:c309`, which makes
/// that the normal mistake rather than an exotic one. [`diag`](super::diag) refuses the
/// mirror-image case itself; this operation does not, and both shipped callers gate on
/// the stage before calling it.
///
/// # Errors
/// [`Error::NotDfu`](crate::Error::NotDfu) if there is still no DFU interface after the
/// retry, or [`Error::Protocol`](crate::Error::Protocol) for a configuration descriptor
/// that will not parse (recoverable too, so it is a second way the reset fires);
/// otherwise the transport's error.
pub async fn probe<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<DfuInfo> {
    let mut ignore = sink_ignore();
    probe_with_progress(dev, clock, &mut ignore).await
}

/// [`probe`], with somewhere to say that it had to reset the gadget.
///
/// **The form to call.** Every other operation that retries takes a sink
/// ([`reboot`](super::reboot) takes one directly and has no sinkless twin), and this one
/// retries too: [`reset_and_retry_once`] emits a
/// [`Progress::Note`](crate::progress::Progress) naming the failure it recovered from
/// and whether the reset was even available. [`probe`] exists for callers with nowhere
/// to put that line, and it is the lesser of the two for exactly that reason.
///
/// # Errors
/// As [`probe`].
pub async fn probe_with_progress<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    progress: ProgressSink<'_>,
) -> Result<DfuInfo> {
    reset_and_retry_once(dev, clock, progress, async |_attempt, _progress| read_info(dev).await).await
}

#[cfg(test)]
mod tests {
    use tdfu_usb::mock::{Call, MockError, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{ControlIn, ControlType, DeviceDescriptors, Pipe, Recipient, UsbError, UsbErrorKind, pid, vid};

    use super::{probe, probe_with_progress};
    use crate::clock::RecordingClock;
    use crate::dfu::descriptors::fixtures::{BOOTROM_CONFIG, T32LQ_CONFIG};
    use crate::dfu::host::{CONTROL_TIMEOUT, POST_RESET_SETTLE};
    use crate::error::Error;
    use crate::progress::Progress;

    /// `GET_DESCRIPTOR`, the only standard request a probe makes.
    const GET_DESCRIPTOR: u8 = 0x06;
    /// `bDescriptorType` CONFIGURATION, in the high byte of `wValue`.
    const CONFIGURATION_VALUE: u16 = 0x0200;
    /// `bDescriptorType` STRING, likewise.
    const STRING_VALUE: u16 = 0x0300;
    /// US English, as the C asks for (`dfu.c:210`).
    const LANGID_EN_US: u16 = 0x0409;

    /// A U-Boot DFU gadget as enumeration sees it.
    ///
    /// It keeps the bootrom's `a108:c309` and is told apart by its product
    /// string and its DFU-class interface, never by the product ID alone.
    fn gadget() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(T32LQ_CONFIG)
    }

    /// The `Call` one `GET_DESCRIPTOR` makes.
    fn get_descriptor(value: u16, langid: u16, len: u16) -> Call {
        Call::control_in(ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: GET_DESCRIPTOR,
            value,
            index: langid,
            len,
        })
    }

    /// One UTF-16LE string descriptor, as a device answers it.
    fn string_descriptor(text: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8, 0x03];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        bytes[0] = len;
        bytes
    }

    /// Script one whole successful `read_info` of the captured T32LQ gadget: the 9-byte
    /// header, the 45-byte configuration, then one string read per alt.
    fn script_read_info(mut mock: MockTransport) -> MockTransport {
        let total = u16::try_from(T32LQ_CONFIG.len()).unwrap_or_default();
        mock = mock
            .expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, 9),
                Reply::Data(T32LQ_CONFIG[..9].to_vec()),
            )
            .expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, total),
                Reply::Data(T32LQ_CONFIG.to_vec()),
            );
        // `iInterface` 5, 6 and 7 — the three alts the capture carries.
        for (index, name) in [(5_u8, "flash"), (6, "erase"), (7, "reboot")] {
            mock = mock.expecting(
                get_descriptor(STRING_VALUE | u16::from(index), LANGID_EN_US, 256),
                Reply::Data(string_descriptor(name)),
            );
        }
        mock
    }

    /// The failure a wedged gadget's EP0 gives: it stops answering control transfers
    /// entirely until a bus reset re-inits the endpoints (`dfu.c:368-373`).
    fn wedged() -> Reply {
        Reply::Fail(
            UsbError::new(
                UsbErrorKind::Timeout,
                Pipe::Control {
                    direction: tdfu_usb::Direction::In,
                    request: GET_DESCRIPTOR,
                },
            )
            .with_timeout(CONTROL_TIMEOUT),
        )
    }

    /// Collect everything an operation says.
    fn record(sink: &mut Vec<Progress>) -> impl FnMut(Progress) {
        move |progress| sink.push(progress)
    }

    /// The alts a successful probe of the captured gadget must find.
    fn expected_alts(info: &crate::model::DfuInfo) -> Vec<(u8, String)> {
        info.alts.iter().map(|alt| (alt.alt, alt.name.clone())).collect()
    }

    // -----------------------------------------------------------------
    // The clean path.
    // -----------------------------------------------------------------

    /// **A clean probe issues no reset** — and no claim, and no `SET_CONFIGURATION`.
    ///
    /// The recovery below is a real bus reset on a real device, which costs a
    /// re-enumeration and 1.5 s; firing it on a healthy gadget would be a bug that
    /// nothing else would notice, because the retry succeeds and the answer is right
    /// either way. So the absence is asserted, not inferred.
    ///
    /// The traffic is the C's exactly: `dfu_probe_impl` opens the device, calls
    /// `dfu_read_info` and closes it (`dfu.c:487-495`), claiming nothing — descriptor
    /// reads are control transfers on the device and need no interface.
    /// The same is asserted for `SET_CONFIGURATION`, because the driverless gadget
    /// often has none set and a probe that configured it would be
    /// changing device state to answer a question.
    #[test]
    fn dfu_probe_clean_run_issues_no_reset() -> Result<(), MockError> {
        let mock = script_read_info(MockTransport::new(gadget()));
        let clock = RecordingClock::new();
        let mut said = Vec::new();

        let info = block_on(probe_with_progress(&mock, &clock, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("probe failed: {error}")))?;

        assert_eq!(info.interface, 0);
        assert_eq!(info.transfer_size, 4096);
        assert_eq!(
            expected_alts(&info),
            vec![
                (0, "flash".to_owned()),
                (1, "erase".to_owned()),
                (2, "reboot".to_owned())
            ]
        );

        for recorded in mock.calls() {
            assert!(
                !matches!(
                    recorded.call,
                    Call::Reset | Call::ClaimInterface(_) | Call::SetConfiguration(_)
                ),
                "a healthy gadget was reset, claimed or reconfigured: {:?}",
                recorded.call
            );
        }
        assert!(clock.slept().is_empty(), "a clean probe waited for something");
        assert!(said.is_empty(), "a clean probe announced a recovery");
        mock.verify()
    }

    /// Every descriptor read carries the 5 s control timeout.
    ///
    /// Asserted from `Recorded.timeout`, which `MockTransport` has carried since its
    /// first commit for exactly this: an earlier double retrofitted it, so the tests written
    /// before the retrofit could not tell a memory read's 2 s from a
    /// download's 30 s.
    #[test]
    fn dfu_probe_reads_carry_the_control_timeout() -> Result<(), MockError> {
        let mock = script_read_info(MockTransport::new(gadget()));
        let clock = RecordingClock::new();
        block_on(probe(&mock, &clock)).map_err(|error| MockError::Script(format!("probe failed: {error}")))?;

        let timeouts: Vec<Option<core::time::Duration>> = mock
            .calls()
            .iter()
            .filter(|Recorded { call, .. }| matches!(call, Call::ControlIn { .. }))
            .map(|recorded| recorded.timeout)
            .collect();
        assert_eq!(timeouts.len(), 5, "two configuration reads and three string reads");
        assert!(
            timeouts.iter().all(|timeout| *timeout == Some(CONTROL_TIMEOUT)),
            "{timeouts:?}"
        );
        mock.verify()
    }

    // -----------------------------------------------------------------
    // The recovery reset.
    // -----------------------------------------------------------------

    /// **The pin this module exists for.** A wedged gadget is USB-reset and probed again.
    ///
    /// An interrupted control-OUT — a browser reload mid-write, a killed bench run —
    /// leaves the dwc2 UDC's EP0 stuck so it stops answering control transfers at all,
    /// and a bus reset re-inits the gadget's endpoints (verified on A1/T31,
    /// `dfu.c:368-373`). The C recovers this at `dfu.c:501-508`; an earlier
    /// implementation dropped the retry and reported `NotDfu` instead, which is the
    /// **only** functional-parity regression an audit found.
    ///
    /// Three things are asserted, not one: the reset happened, the settle was waited
    /// out before the second attempt, and the retry was **announced**. The last one is
    /// not decoration — both of that implementation's retries were silent, and a retry
    /// the user cannot see is a retry they cannot report.
    #[test]
    fn dfu_probe_resets_and_retries_a_wedged_gadget() -> Result<(), MockError> {
        let mock = MockTransport::new(gadget())
            .expecting(get_descriptor(CONFIGURATION_VALUE, 0, 9), wedged())
            .expecting(Call::Reset, Reply::Done);
        let mock = script_read_info(mock);

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let info = block_on(probe_with_progress(&mock, &clock, &mut record(&mut said)))
            .map_err(|error| MockError::Script(format!("the recovery did not recover: {error}")))?;
        assert_eq!(expected_alts(&info).len(), 3);

        // The reset, and the 1500 ms re-enumeration settle after it.
        assert_eq!(clock.slept(), vec![POST_RESET_SETTLE]);

        // And it said so, naming the failure it recovered from.
        let notes: Vec<&String> = said
            .iter()
            .filter_map(|step| match step {
                Progress::Note(text) => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(notes.len(), 1, "the retry was silent: {said:?}");
        let note = notes.first().ok_or_else(|| MockError::Script("no note".to_owned()))?;
        assert!(note.contains("USB-reset"), "{note}");
        assert!(
            note.contains("timed out"),
            "the note drops what actually failed: {note}"
        );
        mock.verify()
    }

    /// A gadget that is still not a gadget after the reset reports [`Error::NotDfu`] —
    /// after **two** full attempts, not one.
    ///
    /// `Error::NotDfu` is in the recoverable class, matching the C: its
    /// `dfu_read_info` answers `DEVICE_NOT_FOUND` when no alt is found
    /// (`dfu.c:278-281`) and `dfu_err_recoverable` lists that code (`dfu.c:408-411`).
    /// So a bootrom probed by mistake — a real case, since the bootrom and the gadget
    /// share `a108:c309` — costs one reset before the honest answer, and the answer is
    /// the honest one rather than a transport error.
    #[test]
    fn dfu_probe_still_not_a_gadget_after_the_reset() -> Result<(), MockError> {
        // A bootrom's configuration: read cleanly, and carrying no DFU interface.
        let total = u16::try_from(BOOTROM_CONFIG.len()).unwrap_or_default();
        let read_config = |mock: MockTransport| {
            mock.expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, 9),
                Reply::Data(BOOTROM_CONFIG[..9].to_vec()),
            )
            .expecting(
                get_descriptor(CONFIGURATION_VALUE, 0, total),
                Reply::Data(BOOTROM_CONFIG.to_vec()),
            )
        };
        // Read, reset, read again — and then no more.
        let mock = read_config(MockTransport::new(DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)));
        let mock = read_config(mock.expecting(Call::Reset, Reply::Done));

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(probe_with_progress(&mock, &clock, &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("a bootrom probed as a DFU gadget".to_owned()))?;
        assert!(matches!(error, Error::NotDfu), "{error}");
        assert_eq!(error.to_string(), "no DFU interface: is the device in U-Boot DFU mode?");

        let resets = mock.calls().iter().filter(|r| r.call == Call::Reset).count();
        assert_eq!(resets, 1, "resets once, not in a loop");
        mock.verify()
    }

    /// A failure a reset cannot fix is **not** retried, and the message that says what
    /// to do survives.
    ///
    /// A deliberate difference from the C, and the one place this class is decided:
    /// `AccessDenied` is the C's `OPEN_FAILED`, which *is* in its recoverable set
    /// (`dfu.c:408-411`) — so the C bus-resets a device the OS refused to open and
    /// tries again. A bus reset does not install a udev rule, and a silent retry buries
    /// the one message that says what to fix. The
    /// departure is flagged there for a bench run to confirm; this is the pin that
    /// makes it visible if it is ever reversed.
    #[test]
    fn dfu_probe_does_not_reset_what_a_reset_cannot_fix() -> Result<(), MockError> {
        let refused = UsbError::new(
            UsbErrorKind::AccessDenied,
            Pipe::Control {
                direction: tdfu_usb::Direction::In,
                request: GET_DESCRIPTOR,
            },
        );
        let mock = MockTransport::new(gadget())
            .expecting(get_descriptor(CONFIGURATION_VALUE, 0, 9), Reply::Fail(refused.clone()));

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(probe_with_progress(&mock, &clock, &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("a refused device probed fine".to_owned()))?;

        assert!(!error.is_recoverable());
        assert_eq!(error.to_string(), Error::Usb(refused).to_string());
        assert!(
            !mock.calls().iter().any(|r| r.call == Call::Reset),
            "a device the OS refused to open was bus-reset"
        );
        assert!(said.is_empty(), "a failure that was never retried announced a retry");
        assert!(clock.slept().is_empty());
        mock.verify()
    }

    /// A backend that cannot reset leaves the **operation's** error intact and says why
    /// separately.
    ///
    /// On Android `reset` is [`Unsupported`](tdfu_usb::UsbErrorKind::Unsupported),
    /// on Windows `nusb`'s WinUSB backend answers the same, and on
    /// WebUSB it is a real reset. The user needs to see what the
    /// probe hit, not that a recovery they never asked for was unavailable — the C
    /// gates its retry on `dfu_reset_device` having returned true (`dfu.c:996`) and
    /// keeps the original error the same way.
    #[test]
    fn dfu_probe_keeps_its_own_error_when_the_reset_is_unavailable() -> Result<(), MockError> {
        let mock = MockTransport::new(gadget())
            .expecting(get_descriptor(CONFIGURATION_VALUE, 0, 9), wedged())
            .expecting(
                Call::Reset,
                Reply::Fail(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device)),
            );

        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let error = block_on(probe_with_progress(&mock, &clock, &mut record(&mut said)))
            .err()
            .ok_or_else(|| MockError::Script("a wedged gadget with no reset probed fine".to_owned()))?;

        // The probe's failure, not the reset's.
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(!error.to_string().contains("unsupported"), "{error}");
        // And the unavailable reset is said through the sink instead of being lost.
        let notes: Vec<&String> = said
            .iter()
            .filter_map(|step| match step {
                Progress::Note(text) => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(notes.len(), 1);
        assert!(
            notes.first().is_some_and(|note| note.contains("not available")),
            "{notes:?}"
        );
        assert!(clock.slept().is_empty(), "nothing settled after a reset that never ran");
        mock.verify()
    }

    /// The sinkless [`probe`] behaves identically — it only drops what it says.
    ///
    /// The frozen signature is what every other task compiles
    /// against, so it has to be the same operation and not a lesser one.
    #[test]
    fn dfu_probe_without_a_sink_still_recovers() -> Result<(), MockError> {
        let mock = MockTransport::new(gadget())
            .expecting(get_descriptor(CONFIGURATION_VALUE, 0, 9), wedged())
            .expecting(Call::Reset, Reply::Done);
        let mock = script_read_info(mock);

        let clock = RecordingClock::new();
        let info = block_on(probe(&mock, &clock))
            .map_err(|error| MockError::Script(format!("the recovery did not recover: {error}")))?;
        assert_eq!(expected_alts(&info).len(), 3);
        assert_eq!(clock.slept(), vec![POST_RESET_SETTLE]);
        mock.verify()
    }
}
