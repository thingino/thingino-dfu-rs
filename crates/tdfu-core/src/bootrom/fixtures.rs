//! What the bootrom tests in this module share: a device to script and an error type
//! that carries both a [`MockError`](tdfu_usb::mock::MockError) and a
//! [`crate::Error`].
//!
//! Tests return `Result` and use `?` rather than `unwrap`, because the no-panic rule
//! denies `unwrap`/`expect`/`panic` in library crates and this is one.

use tdfu_usb::mock::{Call, MockTransport, Recorded};
use tdfu_usb::{ControlOut, ControlType, DeviceDescriptors, Recipient};

/// Anything a bootrom test can fail with.
pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A bootrom as enumeration sees it.
///
/// The product string really does start with junk (`U+00C3`, TAB) on every
/// bootrom seen, and it is never compared for equality.
pub(crate) fn bootrom() -> DeviceDescriptors {
    DeviceDescriptors::new(tdfu_usb::vid::INGENIC, tdfu_usb::pid::BOOTROM)
        .with_product_string("\u{c3}\t USB Boot Device")
        .with_bus_address(1, 7)
}

/// The `Call` a vendor OUT with no data stage makes, split included.
pub(crate) fn vendor_out(request: u8, value: u16, index: u16) -> Call {
    Call::control_out(ControlOut {
        control_type: ControlType::Vendor,
        recipient: Recipient::Device,
        request,
        value,
        index,
        data: &[],
    })
}

/// The `Call` a vendor OUT carrying a 32-bit word makes, high half then low.
pub(crate) fn vendor_out_word(request: u8, word: u32) -> Call {
    let (value, index) = super::vendor::split(word);
    vendor_out(request, value, index)
}

/// The calls a scripted device saw, without their timeouts.
pub(crate) fn calls(dev: &MockTransport) -> Vec<Call> {
    dev.calls().into_iter().map(|recorded| recorded.call).collect()
}

/// Every recorded call whose shape matches `wanted`, with its timeout.
pub(crate) fn timeouts_of(dev: &MockTransport, wanted: fn(&Call) -> bool) -> Vec<Option<core::time::Duration>> {
    dev.calls()
        .iter()
        .filter(|Recorded { call, .. }| wanted(call))
        .map(|recorded| recorded.timeout)
        .collect()
}
