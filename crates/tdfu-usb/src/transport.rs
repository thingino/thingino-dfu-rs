//! The two traits every backend implements.
//!
//! `tdfu-core` is generic over [`LocalUsbTransport`] and names no backend, so the whole
//! bootrom sequence, the DFU state machine and every operation are compiled once and
//! exercised against [`MockTransport`](crate::mock::MockTransport) in tests.
//!
//! **`?Send` by design.** WebUSB futures are `!Send`, so neither trait
//! carries a `Send` bound. Native backends may additionally be `Send` — nusb's are,
//! verified by the `nusb` spike — and binaries drive each device on a
//! `tokio::task::LocalSet` or a current-thread runtime. Do not add `trait_variant`.
//!
//! All methods take `&self`. A backend whose handles need `&mut` (nusb's `Endpoint`
//! and its owned `Interface`) keeps them behind a `RefCell`, which is fine precisely
//! because the trait is `?Send`.

use core::time::Duration;

use crate::error::UsbError;
use crate::types::{BulkEndpoint, ControlIn, ControlOut, DeviceDescriptors, Discovered, InterfaceSpec};

/// One open device.
///
/// Timeouts are the caller's, not the backend's: a memory read uses 2000 ms,
/// a `DNLOAD` data block uses 30 000 ms and everything else uses
/// 5000 ms. A backend owns the *enforcement* of the deadline — on Linux, nusb reports
/// an expired deadline as `Cancelled`, so the backend cancels and reports
/// [`UsbErrorKind::Timeout`](crate::UsbErrorKind::Timeout) itself.
#[allow(async_fn_in_trait, reason = "?Send is the point; no async_trait, no trait_variant")]
pub trait LocalUsbTransport {
    /// A control transfer that reads. Returns exactly what the device sent, which may
    /// be shorter than `req.len`.
    ///
    /// # Errors
    /// Any [`UsbError`]; the pipe in the error is
    /// [`Pipe::Control`](crate::Pipe::Control).
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError>;

    /// A control transfer that writes.
    ///
    /// Returns no length. An earlier version returned a `usize` that **nothing read** —
    /// the C fills an `int *transferred` out-parameter at `device.c:387-389` and every one of
    /// its control-OUT call sites passes `NULL` or leaves the value dead
    /// (`dfu.c:83, 87, 100, 415`; `protocol.c:17-21` and its four siblings), and nusb
    /// cannot produce one at all, so the backend had to fabricate it.
    ///
    /// # Errors
    /// Any [`UsbError`]. A backend that can detect a short data stage reports
    /// [`UsbErrorKind::Short`](crate::UsbErrorKind::Short).
    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError>;

    /// Write `data` to the bulk OUT endpoint declared by the current claim.
    ///
    /// Returns the number of bytes the device accepted. A backend timeout
    /// that nonetheless reports the full length is *success*, so this may legitimately
    /// return `Ok(n)` with `n == data.len()` from a timed-out transfer; a backend that
    /// cannot report the length reports
    /// [`UsbErrorKind::Short`](crate::UsbErrorKind::Short) with what it knows and the
    /// bootrom layer treats both the same way.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`](crate::UsbErrorKind::NotClaimed) if no claim is in
    /// force or the claim declared no bulk OUT endpoint; otherwise any transfer error.
    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError>;

    /// Read exactly `len` bytes from the bulk IN endpoint declared by the current claim.
    ///
    /// **Exactly `len` or an error**: a short memory read is a failure.
    /// Backends that require an IN request to be a nonzero multiple of the endpoint's
    /// max packet size — nusb does, and it is 512 on every bootrom seen — round the
    /// *request* up internally and still return exactly `len` bytes.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`](crate::UsbErrorKind::NotClaimed) if no claim is in
    /// force or the claim declared no bulk IN endpoint;
    /// [`UsbErrorKind::Short`](crate::UsbErrorKind::Short) if the device sent less.
    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError>;

    /// `SET_CONFIGURATION`.
    ///
    /// # Errors
    /// Any [`UsbError`], with [`Pipe::Device`](crate::Pipe::Device).
    async fn set_configuration(&self, value: u8) -> Result<(), UsbError>;

    /// The `bConfigurationValue` in force. `None` means *unconfigured* **or** *this
    /// backend cannot tell*, and both mean "set it".
    ///
    /// **Unpinned after a [`reset`](LocalUsbTransport::reset), and the two doubles
    /// disagree there.** USB 2.0 §9.1.1.5 returns a reset device to the Default state,
    /// so [`MockTransport`](crate::mock::MockTransport) answers `None` afterwards; the
    /// Linux kernel re-applies configuration 1 as part of its own post-reset handling,
    /// so the native backend answers `Some(1)`. A caller that claims after a recovery
    /// reset therefore emits a `SET_CONFIGURATION` under the mock that a real Linux host
    /// never sends. Nothing here is wrong — they model different layers — but no mock
    /// test can pin that request's presence or absence honestly. The differential USB
    /// capture against the C is the arbiter, and the re-open seam above is when to
    /// revisit it.
    ///
    /// Cached; no bus traffic. Claim paths read this first and skip a
    /// redundant `SET_CONFIGURATION`, which is what all three C sites do
    /// (`dfu.c:429`, `device.c:332`, `protocol.c:212`) — a differential USB capture
    /// caught two extra `SET_CONFIGURATION` requests without it.
    fn active_configuration(&self) -> Option<u8>;

    /// Claim an interface and open the bulk endpoints it declares.
    ///
    /// The endpoints are opened **here**, once, rather than looked up per transfer: it
    /// is the only place where "this interface has no such endpoint" is a reachable,
    /// truthful error.
    ///
    /// The C's version of this detaches a kernel driver if one is
    /// attached and then claims (`libtdfu/src/usb/device.c:341-351` — a detach, not a
    /// detach-and-retry; there is no retry in the C either), having first set
    /// configuration 1 if it was not already set (`device.c:330-339`).
    ///
    /// **Only the detach is an obligation here.** Setting the configuration is the
    /// *caller's*: it reads
    /// [`active_configuration`](LocalUsbTransport::active_configuration) and issues
    /// [`set_configuration`](LocalUsbTransport::set_configuration) only if it must, so a
    /// redundant `SET_CONFIGURATION` never goes out — a differential capture of an
    /// earlier implementation caught two. A backend that set it here as well would put
    /// both back on the wire. Written out because a future backend author reading a
    /// shorter version of this paragraph would reintroduce exactly that.
    ///
    /// # Errors
    /// [`UsbErrorKind::AccessDenied`](crate::UsbErrorKind::AccessDenied) when the OS
    /// refuses; this is distinct from "not found" because the fix is a
    /// udev rule, not another cable); [`UsbErrorKind::Fault`](crate::UsbErrorKind::Fault)
    /// when a declared endpoint is not present on the interface.
    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError>;

    /// Release the interface and drop its endpoints.
    ///
    /// **Idempotent**: releasing an interface that is not claimed is `Ok(())`. That is
    /// deliberate — the bootrom path releases on every exit path, which is better than
    /// what the C does, and a defensive
    /// release must not manufacture an error. This is load-bearing: on
    /// the T20, leaving the interface claimed makes the following `FLUSH_CACHE` and
    /// `PROG_STAGE2` time out.
    ///
    /// # Errors
    /// Any [`UsbError`] the OS raises while releasing.
    async fn release_interface(&self, interface: u8) -> Result<(), UsbError>;

    /// `SET_INTERFACE`: select an alternate setting.
    ///
    /// Issued for alt ≠ 0 always, and for alt 0 **only** on a multi-alt
    /// gadget — a single-alt interface may STALL it (USB 9.4.10) and over WebUSB that
    /// stall wedges EP0 for every later request. That rule lives in `tdfu-core`; this
    /// method just issues the request.
    ///
    /// Any bulk endpoints the claim declared are re-opened against the new alternate
    /// setting. For the DFU interface there are none.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`](crate::UsbErrorKind::NotClaimed) if `interface` is
    /// not the claimed one; otherwise any [`UsbError`].
    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError>;

    /// `CLEAR_FEATURE(ENDPOINT_HALT)` on a bulk endpoint.
    ///
    /// **The C never calls this — zero call sites in the whole tree — and neither did
    /// an earlier implementation**, which made the five-attempt `Stall` retry
    /// decorative: a halted bulk endpoint latches and returns `EPIPE` until the halt is
    /// cleared, so every retry after the first hit the same wall.
    ///
    /// Not needed for EP0: a control-pipe stall is a protocol stall and the next setup
    /// packet clears it (USB 2.0 §8.5.3.4). The DFU host's equivalent is
    /// `CLRSTATUS`.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`](crate::UsbErrorKind::NotClaimed) if the endpoint is
    /// not one the claim declared; [`UsbErrorKind::Unsupported`](crate::UsbErrorKind::Unsupported)
    /// on a backend that cannot issue it.
    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError>;

    /// USB bus reset, and the fix for a wedged EP0.
    ///
    /// Releases any claimed interface and **drops its endpoints** before resetting.
    /// An earlier version wrote `let _dropped = …take()`, which *binds* the value and
    /// keeps the interface and both endpoint vectors alive across the reset — the exact
    /// opposite of what its own comment said. Making the claim state the transport's
    /// own removes the chance to get that wrong.
    ///
    /// # The handle does not survive, so a backend that has one re-opens it
    ///
    /// A bus reset makes the host's handle stale — `nusb` says so outright: "This
    /// `Device` will no longer be usable, and you should drop it and call
    /// `list_devices` to find and re-open it" (`nusb-0.2.7/src/device.rs:287-290`).
    /// **Re-opening is therefore part of this method**, not something the caller does
    /// afterwards: when `reset` returns `Ok(())` the transport is usable again, and
    /// `tdfu_core::dfu::host::reset_and_retry_once` may go on using the same `&self`.
    /// A backend that cannot re-open reports the failure rather than handing back a
    /// handle the OS has invalidated.
    ///
    /// The claim does **not** come back with it. A reset returns the device to the
    /// Default state (USB 2.0 §9.1.1.5), so the retried operation claims for itself —
    /// which every operation does anyway, because its first attempt needed a claim too.
    ///
    /// ## What "reset" means per platform
    ///
    /// | platform | what happens | handle |
    /// |---|---|---|
    /// | Linux | `USBDEVFS_RESET` on the open fd (`nusb-0.2.7/src/platform/linux_usbfs/device.rs:369-377`) | survives in practice; re-opened anyway |
    /// | macOS | `USBDeviceReEnumerate(0)` (`macos_iokit/iokit_usb.rs:133-135`) | destroyed — the `IOKit` service is terminated and its registry id is gone |
    /// | Windows | `nusb` answers **`Unsupported`** — "reset not supported by WinUSB" (`windows_winusb/device.rs:170-175`) — and WinUSB exposes no host-initiated port reset to call; a host-side handle recycle instead | dropped and re-opened |
    /// | Android | nothing: the fd belongs to Java | untouched |
    /// | WebUSB | `USBDevice.reset()` | survives; the browser owns it and re-acquires it across the re-enumeration |
    ///
    /// **Windows is honest about being weaker.** libusb has a WinUSB `reset_device`, but
    /// it is not a port reset either: `winusbx_reset_device`
    /// (`libusb/os/windows_winusb.c:4297-4343`) cycles the pipes of each *claimed*
    /// interface with `AbortPipe`/`FlushPipe`/`ResetPipe` and returns success
    /// unconditionally, because — its own comment — "WinUSB does not support
    /// host-initiated reset port and cycle port operations". And the shipped C calls it
    /// through a handle it opens fresh and never claims on
    /// (`libtdfu/src/dfu/dfu.c:391-397`), so on Windows the C's DFU recovery performs no
    /// pipe operation at all. That reads at first like a parity loss; it is the
    /// opposite. A native backend on Windows releases the claim, drops every WinUSB
    /// handle and re-opens, which is strictly more than the C does there — but it is a
    /// **host-side recycle, not a bus reset**: it does not re-initialise the device's
    /// endpoints, so a UDC-side EP0 wedge is not cleared by it, and the value of
    /// returning `Ok` is that the caller's one retry happens at all.
    ///
    /// [`set_configuration`](LocalUsbTransport::set_configuration) is
    /// [`Unsupported`](crate::UsbErrorKind::Unsupported) on WinUSB as well
    /// (`windows_winusb/device.rs:139-147`). That one costs nothing in practice: the
    /// WinUSB driver binds to a configured device and
    /// [`active_configuration`](LocalUsbTransport::active_configuration) reports it, so
    /// callers never ask.
    ///
    /// # Errors
    /// [`UsbErrorKind::Unsupported`](crate::UsbErrorKind::Unsupported) on **Android**:
    /// the fd is owned by Java and a close-and-reopen wedges the gadget's controller for
    /// minutes. Otherwise whatever the reset raised, or whatever the
    /// re-open raised: a reset that went out but left the device unreachable is a
    /// failure, because the transport is not usable afterwards.
    ///
    /// **WebUSB is not in that sentence, and used to be.** An earlier note read "reset
    /// is `Unsupported` on Android and WebUSB"; that short-circuit is about Android
    /// alone (`libtdfu/src/usb/device.c:219-227, :309-313` are its two `#ifdef ANDROID`
    /// short-circuits, and there is no `__EMSCRIPTEN__` branch beside them), and the
    /// shipped browser flasher has always issued a real `USBDevice.reset()`:
    /// `libtdfu/src/dfu/dfu.c:394` through `web/src/libusb-webusb.js:462-471`. Keeping
    /// the old line would have deleted the bus-reset recovery from the one frontend
    /// where its cause, a page reload mid-`DNLOAD`, is the everyday accident. It is a
    /// real reset in the browser.
    ///
    /// **A failure still leaves the claim released.** The teardown is the first step and
    /// it cannot be otherwise — macOS refuses the reset outright while an interface is
    /// claimed (`macos_iokit/device.rs:171-176`) — so by the time anything can go wrong
    /// the interface and its endpoints are already gone. A caller that sees `Err` is
    /// holding an unclaimed device, which on the two platforms that refuse the request
    /// without touching the bus is the only thing that changed. It costs nothing here,
    /// because every caller claims per attempt; it is stated because "the operation
    /// failed" is otherwise read as "nothing happened".
    async fn reset(&self) -> Result<(), UsbError>;

    /// What enumeration read about this device.
    fn descriptors(&self) -> &DeviceDescriptors;
}

/// Discovery.
///
/// On WebUSB this lists the devices the page has already been authorized for; on
/// Android it lists the single fd Java handed over.
#[allow(async_fn_in_trait, reason = "?Send is the point; no async_trait, no trait_variant")]
pub trait LocalUsbBackend {
    /// The open device this backend produces.
    type Transport: LocalUsbTransport;

    /// The backend's own handle for a device it listed.
    ///
    /// An earlier `open(&DeviceDescriptors)` forced every backend to re-enumerate
    /// the whole bus and match a device by its fields — which is literally what the C
    /// does (`manager.c:166` frees the device list, then `manager.c:259` calls
    /// `usb_device_init(bus, address)`, which re-scans at `device.c:137-159`) and is
    /// residue worth deleting. An opaque handle carried from
    /// [`list`](LocalUsbBackend::list) removes the rescan and the "the device moved
    /// between listing and opening" failure mode with it.
    type DeviceId: Clone + core::fmt::Debug;

    /// Every device this backend can see.
    ///
    /// A pure list scan — no open, no probe, no reset — so it is safe to poll every
    /// 500 ms for `--wait` without disturbing a bootrom that is also on the bus.
    /// Filtering to the Ingenic VIDs is the caller's job.
    ///
    /// # Errors
    /// Any [`UsbError`] the enumeration raises.
    async fn list(&self) -> Result<Vec<Discovered<Self::DeviceId>>, UsbError>;

    /// Open a device this backend listed.
    ///
    /// # Errors
    /// [`UsbErrorKind::NoDevice`](crate::UsbErrorKind::NoDevice) if it has gone;
    /// [`UsbErrorKind::AccessDenied`](crate::UsbErrorKind::AccessDenied) if the OS
    /// refuses.
    async fn open(&self, id: &Self::DeviceId) -> Result<Self::Transport, UsbError>;
}
