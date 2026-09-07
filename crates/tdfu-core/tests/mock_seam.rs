//! The seam everything else builds on: `tdfu-core` generic code driven by
//! `tdfu_usb::mock::MockTransport` and a `Sleeper`, with no device and no runtime.
//!
//! It asserts the wiring — the `mock` feature reaching the dev build, the `?Send` traits
//! composing, `block_on` driving them — and nothing about the
//! protocol, which each operation's own tests cover.

use core::time::Duration;

use tdfu_core::clock::{RecordingClock, Sleeper};
use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
use tdfu_usb::{DeviceDescriptors, InterfaceSpec, LocalUsbTransport};

/// Something shaped like a `tdfu-core` operation: generic over both seams, `?Send`.
async fn a_generic_operation<T: LocalUsbTransport, C: Sleeper>(dev: &T, clock: &C) -> Result<u8, tdfu_core::Error> {
    dev.claim_interface(InterfaceSpec::control_only(0)).await?;
    // The settle, which is why an operation needs a clock at all.
    clock.sleep(tdfu_core::bootrom::SETTLE_AFTER_VENDOR_REQUEST).await;
    dev.release_interface(0).await?;
    Ok(dev.descriptors().bus)
}

#[test]
fn core_generic_code_runs_against_the_mock_and_a_recording_clock() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = DeviceDescriptors::new(tdfu_usb::vid::INGENIC, tdfu_usb::pid::BOOTROM)
        .with_product_string("\u{c3}\t USB Boot Device")
        .with_bus_address(3, 11);

    let dev = MockTransport::new(descriptors)
        .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
        .expecting(Call::ReleaseInterface(0), Reply::Done);
    let clock = RecordingClock::new();

    let bus = block_on(a_generic_operation(&dev, &clock))?;

    assert_eq!(bus, 3);
    dev.verify()?;
    assert_eq!(
        clock.slept(),
        vec![Duration::from_millis(100)],
        "settle, not lived through"
    );
    Ok(())
}

#[test]
fn a_usb_error_reaches_the_caller_as_a_core_error_with_its_context() -> Result<(), Box<dyn std::error::Error>> {
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    let failure = UsbError::new(UsbErrorKind::Timeout, Pipe::Bulk(tdfu_usb::endpoint::BOOTROM_IN))
        .with_len(4)
        .with_timeout(Duration::from_secs(2))
        .with_transferred(0);

    let dev = MockTransport::new(DeviceDescriptors::new(tdfu_usb::vid::INGENIC, tdfu_usb::pid::BOOTROM)).expecting(
        Call::ClaimInterface(InterfaceSpec::control_only(0)),
        Reply::Fail(failure),
    );
    let clock = RecordingClock::new();

    let err = block_on(a_generic_operation(&dev, &clock))
        .err()
        .ok_or("the scripted failure must propagate")?;

    // The whole point of the contract's D9: the context survives the conversion, so a
    // 2 s bulk-IN on 0x81 does not read like a 30 s DNLOAD on EP0.
    let rendered = err.to_string();
    assert!(rendered.contains("0x81"), "{rendered}");
    assert!(rendered.contains("2s"), "{rendered}");
    // A timeout is in the reset-and-retry class.
    assert!(err.is_recoverable());
    Ok(())
}
