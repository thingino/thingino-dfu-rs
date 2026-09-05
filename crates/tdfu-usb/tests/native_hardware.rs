//! The one test that needs a real device, and skips itself cleanly when there is none.
//!
//! **It is read-only by construction.** It enumerates, opens, and reads what
//! enumeration already cached. It issues no transfer, claims no interface, sets no
//! configuration and never resets — nothing may be executed on a
//! bootrom, and a device on a shared bench may belong to someone else's run right
//! now. Everything that *can* be checked without a device is a unit test in
//! `src/native/`; what is left here is the
//! part only a bus can answer: that enumeration finds the device, that the descriptors
//! come back populated, and that opening needs no second scan.
//!
//! A skip prints why. A test that says nothing when it does nothing is indistinguishable
//! from one that passed for the wrong reason.

// Enumeration is desktop-only; on Android a device arrives as a pre-opened fd and this
// file has nothing to say.
#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll};
use std::error::Error;
use std::sync::Arc;
use std::task::Wake;

use tdfu_usb::native::{ACCESS_DENIED_HINT, NativeBackend};
use tdfu_usb::{LocalUsbBackend, LocalUsbTransport, UsbErrorKind, vid};

/// A waker that does nothing, built with no `unsafe` (the crate denies it).
struct Inert;

impl Wake for Inert {
    fn wake(self: Arc<Self>) {}
}

/// Poll one future exactly once.
///
/// Every path this test drives — enumerate, open, release an unclaimed interface —
/// resolves on the first poll, because `nusb` performs each of them synchronously and
/// the backend calls them through `.wait()`. So one poll is not a shortcut: `Pending`
/// here would mean the backend had grown a suspension point, which is a finding rather
/// than something to spin on. Spinning would also be the very shape this backend exists
/// to avoid.
fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let waker = Arc::new(Inert).into();
    let mut context = Context::from_waker(&waker);
    match pin!(future).poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

/// The message for a future that did not resolve on its first poll.
const PENDED: &str = "the backend suspended where it never has: this test drives it without a runtime";

#[test]
fn an_ingenic_device_lists_and_opens() -> Result<(), Box<dyn Error>> {
    let backend = NativeBackend;

    // Enumeration failing is a real failure, not a skip: the bus is always there.
    let listed = poll_once(backend.list()).ok_or(PENDED)??;

    let Some(first) = listed.first() else {
        println!(
            "skipping: no Ingenic device on this host (nothing with vendor {:#06x} or {:#06x} is on the bus)",
            vid::INGENIC,
            vid::INGENIC_X
        );
        return Ok(());
    };

    // This backend lists nothing else, so everything returned is ours.
    for device in &listed {
        assert!(
            vid::is_ingenic(device.descriptors.vendor_id),
            "the listing returned a foreign vendor: {:#06x}",
            device.descriptors.vendor_id
        );
    }
    println!("found {} Ingenic device(s); using {:?}", listed.len(), first.id);

    // The listing carries the configuration descriptor at index 0, and on
    // Linux reads it without opening anything. A host that would not give it up is
    // worth naming rather than asserting away - that is the difference between "the
    // backend is wrong" and "this host would not let us read it".
    let config = &first.descriptors.config_descriptor;
    if config.len() < 4 {
        println!("note: the listing could not read the configuration descriptor");
    } else {
        assert_eq!(config[1], 0x02, "descriptor type is not CONFIGURATION");
        let total = usize::from(u16::from_le_bytes([config[2], config[3]]));
        assert_eq!(
            config.len(),
            total,
            "the config descriptor is not exactly wTotalLength bytes"
        );
    }

    // Opening takes the handle the listing produced and rescans nothing.
    let transport = match poll_once(backend.open(&first.id)).ok_or(PENDED)? {
        Ok(transport) => transport,
        Err(error) => {
            println!("skipping the open leg: {error}");
            if matches!(error.kind(), UsbErrorKind::AccessDenied) {
                // Printed exactly once, from the one constant that holds this advice.
                println!("hint: {ACCESS_DENIED_HINT}");
            }
            return Ok(());
        }
    };

    let descriptors = transport.descriptors();
    assert_eq!(descriptors.vendor_id, first.descriptors.vendor_id);
    assert_eq!(descriptors.product_id, first.descriptors.product_id);
    assert!(
        !descriptors.config_descriptor.is_empty(),
        "an opened device always has its configuration descriptor"
    );

    // The active configuration is answered from a cache, with no bus
    // traffic. `None` is the normal answer for a driverless gadget, not a failure.
    println!(
        "open: {transport:?}, active configuration {:?}, port path {:?}",
        transport.active_configuration(),
        descriptors.port_path
    );

    // The `usb_release_is_idempotent` pin, against a real device: nothing is claimed,
    // so every release must be `Ok(())` and must reach no OS call.
    for interface in 0u8..3 {
        let released = poll_once(transport.release_interface(interface)).ok_or(PENDED)?;
        assert!(
            released.is_ok(),
            "releasing unclaimed interface {interface} must be Ok(())"
        );
    }

    Ok(())
}
