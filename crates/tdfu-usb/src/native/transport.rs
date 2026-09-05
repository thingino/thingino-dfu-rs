//! [`NativeTransport`] — one open device, driven through `nusb`.
//!
//! # Every transfer is bounded by its `Duration`, by construction
//!
//! This is the rule the module is built around, because an earlier implementation broke
//! it and the break was invisible: it used `nusb`'s `Endpoint::transfer_blocking`,
//! whose timeout path cancels the transfer and then loops
//! `while wait_next_complete(1s) is None { warn }` — **for ever**, until a wedged
//! device chooses to give the transfer back. Neither `async fn` contained an `.await`,
//! so nothing in the type system said so either.
//!
//! Here the deadline is the backend's own:
//!
//! * **Control transfers** carry the caller's timeout into the OS. `nusb` submits them
//!   with it (Linux sets the URB timeout, macOS uses `IOUSBDevRequestTO`, Windows
//!   passes it to WinUSB), and an expired deadline comes back as
//!   `TransferError::Cancelled`, which maps to [`UsbErrorKind::Timeout`].
//! * **Bulk transfers** are submitted, waited for exactly once with the caller's
//!   timeout, and on expiry cancelled and given a **bounded** grace window
//!   (`CANCEL_GRACE`) to come back. If it does not come back in that window the call
//!   reports a timeout and *keeps* the endpoint handle: the next attempt drains the
//!   straggler first and only then submits, so this transfer's answer can never be
//!   read as the next one's. Dropping the handle instead would be worse than useless —
//!   the outstanding transfer holds the endpoint open inside `nusb` either way, so a
//!   re-open would fail `Busy` until the OS returns it, and the endpoint would be
//!   unusable for exactly as long as draining it would have taken.
//!
//!   One thing this does **not** promise: the *device* may still have a reply queued in
//!   its own IN FIFO. Cancelling unlinks the host-side URB, nothing more. Clearing that
//!   is `clear_halt` or a bus reset, and both are the caller's to
//!   decide.
//!
//! Both waits park the calling thread rather than yielding, which has a consequence
//! worth stating plainly: a `DNLOAD` at 30 000 ms holds its runtime for the
//! whole 30 s, and an outer `tokio::time::timeout` wrapped around one of these calls
//! **cannot fire**, because the future never returns `Pending`. One device is
//! driven on one `LocalSet`, so nothing else is waiting on that thread; do not
//! add an async timeout on top and believe in it.
//!
//! # Blocking, deliberately, and only where it is bounded
//!
//! `nusb`'s control-plane calls (open, claim, release, `SET_CONFIGURATION`,
//! `SET_INTERFACE`, `clear_halt`, reset, enumeration) return a `MaybeFuture` backed by
//! `Blocking`, and **awaiting one panics** unless `nusb`'s `smol` or `tokio` feature is
//! on:
//!
//! ```text
//! panic!("Awaiting blocking syscall without an async runtime: enable the `smol` or
//!         `tokio` feature of nusb.")
//! ```
//!
//! A flashing tool must not abort on a lazy `.await` any more than on a lazy `unwrap`,
//! so those calls use `.wait()`. Each is a single bounded `ioctl` or syscall, and each device is driven from one `LocalSet` or
//! current-thread runtime. The unbounded wait — the one that mattered — is the transfer
//! wait, and that one is bounded above by hand.

#[cfg(not(target_os = "android"))]
use core::cell::RefCell;
use core::fmt;
use core::time::Duration;

use nusb::MaybeFuture as _;
use nusb::transfer::{
    Buffer, Bulk, Completion, ControlType as NusbControlType, EndpointDirection, In, Out, Recipient as NusbRecipient,
};

use super::claim::{CANCEL_GRACE, ClaimSlot, DeviceSlot, Handles};
use super::error::{device_error, device_kind, endpoint_kind, transfer_kind};
use crate::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, InterfaceSpec, LocalUsbTransport,
    Pipe, Recipient, UsbError, UsbErrorKind,
};

/// The largest bulk transfer this backend will hand to `nusb`.
///
/// Two aborts sit above it, and neither is a `Result`: `Buffer::new` panics past
/// `u32::MAX`, and well before that its `Vec::with_capacity` reaches
/// `handle_alloc_error`, which aborts the process. A flashing tool does neither.
/// 16 MiB is the ceiling Linux usbfs itself enforces on one URB, so a
/// request above it was going to be refused anyway — better as an honest error here
/// than as an `EINVAL` from the kernel or an abort from the allocator. The tool's real
/// transfers are far below it: uploads are chunked at 64 KiB and a register read takes
/// registers 4 bytes at a time.
const MAX_TRANSFER: usize = 16 * 1024 * 1024;

/// The largest data stage a control transfer can carry: `wLength` is 16 bits.
///
/// `ControlIn::len` is a `u16` so IN is safe by construction; OUT takes a slice, and
/// every platform `expect()`s the `u16` conversion — `transfer/control.rs:85` on Linux,
/// `windows_winusb/device.rs:563`, `macos_iokit/device.rs:315`. This is the guard that
/// keeps a mis-sized `DNLOAD` block an error rather than an abort.
const MAX_CONTROL_DATA: usize = u16::MAX as usize;

/// One open Ingenic device.
///
/// Produced by `NativeBackend::open` on a desktop, and by `NativeTransport::from_fd`
/// on Android, where Java owns the file descriptor and enumeration is not available at
/// all.
///
/// All methods take `&self` and the claim, the handle and the identity live behind
/// `RefCell`s, which the contract anticipates: the traits are `?Send` by design, so a
/// backend whose handles need `&mut` keeps them behind interior
/// mutability. A consequence worth stating: `NativeTransport` is `Send` but not `Sync`,
/// so its futures are `!Send` and belong on a `LocalSet` — which is what D1 asks for
/// anyway.
///
/// # The handle is replaceable, because a reset destroys it
///
/// [`reset`](LocalUsbTransport::reset) drops the handle and re-opens from the identity
/// enumeration gave it. Everything that touches the device asks the slot
/// for a handle first, so there is no field holding one a reset has already killed —
/// the state that made an earlier `reset()` correct on Linux by accident and wrong
/// everywhere else.
pub struct NativeTransport {
    device: DeviceSlot<NusbHandles>,
    /// What a re-open starts from, refreshed by every re-open.
    ///
    /// Not compiled for Android: Java owns the fd, `nusb::list_devices` does not exist
    /// there, and `reset()` is [`UsbErrorKind::Unsupported`]. There is
    /// nothing to re-open from and nothing that would re-open.
    #[cfg(not(target_os = "android"))]
    identity: RefCell<nusb::DeviceInfo>,
    descriptors: DeviceDescriptors,
    claim: ClaimSlot<NusbHandles>,
}

impl fmt::Debug for NativeTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeTransport")
            .field(
                "vendor_id",
                &format_args!("{:#06x}", self.descriptors.vendor_id),
            )
            .field(
                "product_id",
                &format_args!("{:#06x}", self.descriptors.product_id),
            )
            .field("bus", &self.descriptors.bus)
            .field("address", &self.descriptors.address)
            .field("claimed", &self.claim.claimed())
            // The `nusb` handle itself has no useful `Debug` and nothing to say here.
            .finish_non_exhaustive()
    }
}

impl NativeTransport {
    /// Wrap an opened `nusb` device, the identity it was opened from, and the
    /// descriptors enumeration read for it.
    ///
    /// The identity is kept rather than dropped because a `reset()` needs it: the handle
    /// does not survive one, and re-deriving an identity from `descriptors` would be
    /// the `open(&DeviceDescriptors)` rescan under another name.
    #[cfg(not(target_os = "android"))]
    pub(super) const fn new(device: nusb::Device, identity: nusb::DeviceInfo, descriptors: DeviceDescriptors) -> Self {
        Self {
            device: DeviceSlot::new(device),
            identity: RefCell::new(identity),
            descriptors,
            claim: ClaimSlot::new(),
        }
    }

    /// Adopt a `usbdevfs` file descriptor Java has already opened.
    ///
    /// Android is the reason this exists: an app receives the fd from
    /// `UsbDeviceConnection.getFileDescriptor()`, and the process may not enumerate the
    /// bus at all — `nusb::list_devices` is not compiled for Android and its
    /// `from_device_info` is `unimplemented!()` there. So this is the *only* way an
    /// Android build gets a device, and `NativeBackend` does not exist on that
    /// target.
    ///
    /// It needs no `unsafe`: `nusb::Device::from_fd` takes an `OwnedFd`, which the
    /// `nusb` spike proved on hardware. Java must have released interface
    /// 0 on its own handle first, or the adoption fails with `EBUSY` — the same spike
    /// found that too.
    ///
    /// `bus`, `address` and `port_path` stay unset, which is allowed: Java never
    /// tells us and the fd does not carry them. `product_string` stays unset too —
    /// reading it costs a control transfer, and stage classification is
    /// descriptor-first anyway, which the config descriptor answers.
    ///
    /// There is no identity to carry and nothing that would use one: `reset()` on
    /// Android is [`UsbErrorKind::Unsupported`], so the handle in the slot is the only
    /// one this transport will ever have.
    ///
    /// # Errors
    /// [`UsbErrorKind::AccessDenied`] if the fd is not usable
    /// ([`ACCESS_DENIED_HINT`](super::ACCESS_DENIED_HINT) is the one wording of the
    /// fix); [`UsbErrorKind::NoDevice`] if the device has gone.
    #[cfg(target_os = "android")]
    pub fn from_fd(fd: std::os::fd::OwnedFd) -> Result<Self, UsbError> {
        let device = nusb::Device::from_fd(fd).wait().map_err(|error| device_error(&error))?;
        let raw = device.device_descriptor();
        let descriptors = DeviceDescriptors::new(raw.vendor_id(), raw.product_id())
            .with_config_descriptor(config_descriptor(&device));
        Ok(Self {
            device: DeviceSlot::new(device),
            descriptors,
            claim: ClaimSlot::new(),
        })
    }
}

/// Compile-time assertions that the `cfg` gates leave the right surface on each target.
///
/// The Android leg of CI exists to catch a backend that compiles everywhere else
/// (`.github/workflows/ci.yml`, failure 4), and a `cfg` typo would hide `from_fd`
/// without failing anything — the crate would still build, and `tdfu-jni` would be the
/// one to discover it. These name each item, so the target that must have it says so.
const _: () = {
    const fn is_transport<T: LocalUsbTransport>() {}
    is_transport::<NativeTransport>();

    /// Android reaches a device only through the pre-opened fd.
    #[cfg(target_os = "android")]
    const _ADOPTS_A_JAVA_FD: fn(std::os::fd::OwnedFd) -> Result<NativeTransport, UsbError> = NativeTransport::from_fd;
};

/// The configuration descriptor at **index 0**, or empty if the device reports none.
///
/// Index 0, not the active configuration: a driverless gadget often has no
/// configuration set at all, and `libusb_get_active_config_descriptor` fails exactly
/// where `libusb_get_config_descriptor(dev, 0)` succeeds. `nusb`'s
/// `configurations()` iterates descriptors the OS cached at enumeration, so this costs
/// no bus traffic.
pub(super) fn config_descriptor(device: &nusb::Device) -> Vec<u8> {
    device
        .configurations()
        .next()
        .map(|configuration| configuration.as_bytes().to_vec())
        .unwrap_or_default()
}

/// `nusb`'s handles, bound to the claim state machine.
pub(super) struct NusbHandles;

impl Handles for NusbHandles {
    type Interface = nusb::Interface;
    type BulkIn = nusb::Endpoint<Bulk, In>;
    type BulkOut = nusb::Endpoint<Bulk, Out>;
    type Device = nusb::Device;
    #[cfg(not(target_os = "android"))]
    type Identity = nusb::DeviceInfo;

    fn open_bulk_in(interface: &nusb::Interface, endpoint: BulkEndpoint) -> Result<Self::BulkIn, UsbError> {
        interface
            .endpoint::<Bulk, In>(endpoint.address())
            .map_err(|error| UsbError::new(endpoint_kind(&error), Pipe::Bulk(endpoint)))
    }

    fn open_bulk_out(interface: &nusb::Interface, endpoint: BulkEndpoint) -> Result<Self::BulkOut, UsbError> {
        interface
            .endpoint::<Bulk, Out>(endpoint.address())
            .map_err(|error| UsbError::new(endpoint_kind(&error), Pipe::Bulk(endpoint)))
    }

    fn set_alt_setting(interface: &nusb::Interface, alt: u8) -> Result<(), UsbError> {
        interface
            .set_alt_setting(alt)
            .wait()
            .map_err(|error| device_error(&error))
    }

    fn release(interface: nusb::Interface) -> Result<(), UsbError> {
        interface.release().wait().map_err(|error| device_error(&error))
    }

    fn drain_bulk_in(endpoint: &mut Self::BulkIn, grace: Duration) -> bool {
        drain(endpoint, grace)
    }

    fn drain_bulk_out(endpoint: &mut Self::BulkOut, grace: Duration) -> bool {
        drain(endpoint, grace)
    }

    /// The bus reset itself — on three platforms with three different answers.
    ///
    /// **Linux and macOS** have one, and `nusb` issues it: `USBDEVFS_RESET`
    /// (`linux_usbfs/device.rs:369-377`) and `USBDeviceReEnumerate(0)`
    /// (`macos_iokit/iokit_usb.rs:133-135`) respectively. Both invalidate the handle,
    /// which is why the caller re-opens.
    ///
    /// **Windows has none available**, and this returns `Ok(())` there without touching
    /// the bus.
    /// That is not a success we did not earn, and the reasoning is worth writing down
    /// because the opposite reads at first like a parity loss:
    ///
    /// * `nusb`'s WinUSB backend answers `Unsupported` — "reset not supported by
    ///   WinUSB" (`windows_winusb/device.rs:170-175`). The refusal is `nusb`'s, but the
    ///   absence is WinUSB's: there is no host-initiated port reset to call.
    /// * libusb *has* a `reset_device` on WinUSB, but it is not a port reset either. It
    ///   is `winusbx_reset_device` (`libusb/os/windows_winusb.c:4297-4343`), which walks
    ///   the endpoints of each **claimed** interface calling `AbortPipe`, `FlushPipe`
    ///   and `ResetPipe`, and returns `LIBUSB_SUCCESS` unconditionally. Its own comment
    ///   says why: "WinUSB does not support host-initiated reset port and cycle port
    ///   operations", so "the best we can do is cycle the pipes (and even then, the
    ///   control pipe can not be reset using WinUSB)".
    /// * And the shipped C reaches it through a handle it opens *fresh* and never claims
    ///   on (`libtdfu/src/dfu/dfu.c:391-397`: `libusb_open`, `libusb_reset_device`,
    ///   `libusb_close`). The loop is guarded by `HANDLE_VALID(api_handle)`, and
    ///   `api_handle` is only ever assigned by `winusbx_claim_interface`
    ///   (`windows_winusb.c:3186`, via `WinUsb_Initialize`). **On Windows the C's DFU
    ///   recovery therefore performs no pipe operation at all** — it opens a handle,
    ///   does nothing, closes it, sleeps 1500 ms and retries.
    ///
    /// So the parity target on Windows is the retry, not the reset. What the caller does
    /// around this — release the claim, drop every WinUSB handle, re-open — is strictly
    /// more than the C manages there, because dropping the claim is what actually frees
    /// the pipes (`WinUsb_Free`, `windows_winusb/device.rs:488-501`). It is a **host-side
    /// recycle, not a bus reset**: it abandons queued transfers and re-opens the pipes,
    /// and it does *not* re-initialise the device's own endpoints, so a UDC-side EP0
    /// wedge — the case a bus reset exists for — is not cleared by it. `reset()`'s
    /// doc on the trait says so in those words.
    ///
    /// **Android** does not have this method at all: `reset()` there is
    /// [`UsbErrorKind::Unsupported`] and the whole seam is `cfg`'d out.
    #[cfg(not(target_os = "android"))]
    fn bus_reset(device: &nusb::Device) -> Result<(), UsbError> {
        #[cfg(target_os = "windows")]
        {
            let _ = device;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            device.reset().wait().map_err(|error| device_error(&error))
        }
    }

    /// A fresh handle for the device `identity` describes.
    ///
    /// The policy — try the stored identity where a reset leaves it valid, then a
    /// bounded re-scan keyed on the physical port — lives in
    /// [`reopen`](super::reopen), with the per-platform citations that justify it.
    ///
    /// Not compiled for Android, which is also why nothing here can ever reach `nusb`'s
    /// `Device::from_device_info` — `unimplemented!()` on that target, and a panic a
    /// flashing tool does not take even on a path nothing walks.
    #[cfg(not(target_os = "android"))]
    fn open(identity: &mut nusb::DeviceInfo) -> Result<nusb::Device, UsbError> {
        super::reopen::reopen(identity)
    }
}

/// What a bounded transfer did.
enum Transfer {
    /// The transfer completed — successfully or not — inside its deadline, or its
    /// cancellation came back inside the grace window.
    Completed(Completion),
    /// A transfer this endpoint had already given up on has still not come back, so
    /// nothing was submitted. The next attempt drains it again.
    Blocked,
    /// The deadline expired, the cancellation was issued, and the transfer had still
    /// not come back when the grace window closed.
    Abandoned,
}

/// Reclaim every transfer the OS has finished with, up to `grace` each.
///
/// `false` means one is still outstanding. This is the recovery path, not tidying: a
/// cancellation only *asks* the OS to return a transfer, and until it does that transfer
/// owns the endpoint. `nusb` refuses to open an endpoint whose address bit is still set
/// (`platform/linux_usbfs/device.rs:705`), and only the completion handler clears that
/// bit — so **dropping the handle does not free the endpoint**, and re-opening it would
/// fail `Busy` for as long as the straggler lives. Keeping the handle and draining it is
/// the only route back, and it is also what lets `release_interface` succeed, since
/// `Interface::release` is an `Arc::into_inner` that a straggler defeats.
fn drain<D: EndpointDirection>(endpoint: &mut nusb::Endpoint<Bulk, D>, grace: Duration) -> bool {
    while endpoint.pending() > 0 {
        if endpoint.wait_next_complete(grace).is_none() {
            return false;
        }
    }
    true
}

/// Submit one transfer and wait for it, bounded by `timeout` plus two [`CANCEL_GRACE`]
/// windows.
///
/// Never waits unbounded, which is the whole point (see the module docs).
fn bounded<D: EndpointDirection>(
    endpoint: &mut nusb::Endpoint<Bulk, D>,
    buffer: Buffer,
    timeout: Duration,
) -> Transfer {
    // Anything left over from a previous attempt is reclaimed first. Submitting on top
    // of it would queue this transfer behind a reply that is not ours, and
    // `wait_next_complete` pops in order.
    if !drain(endpoint, CANCEL_GRACE) {
        return Transfer::Blocked;
    }
    endpoint.submit(buffer);
    if let Some(completion) = endpoint.wait_next_complete(timeout) {
        return Transfer::Completed(completion);
    }
    endpoint.cancel_all();
    endpoint
        .wait_next_complete(CANCEL_GRACE)
        .map_or(Transfer::Abandoned, Transfer::Completed)
}

/// Round an IN request up to a nonzero multiple of `packet`.
///
/// `nusb` fails an IN transfer whose `requested_len` is not one — the device answers
/// with a short packet of exactly the bytes asked for, which is why the *request* may
/// be larger than the *answer* (verified on hardware for 4-byte and
/// 256-byte reads by the `nusb` spike).
fn round_up(len: usize, packet: usize) -> Option<usize> {
    if packet == 0 {
        return None;
    }
    len.div_ceil(packet).checked_mul(packet)
}

impl LocalUsbTransport for NativeTransport {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let request = nusb::transfer::ControlIn {
            control_type: control_type(req.control_type),
            recipient: recipient(req.recipient),
            request: req.request,
            value: req.value,
            index: req.index,
            length: req.len,
        };
        // A claimed interface handle carries control transfers on every platform.
        // Cloning it out of the slot first is deliberate: a `RefCell` borrow must never
        // be held across an `.await`.
        let outcome = match self.claim.interface() {
            Some(interface) => interface.control_in(request, timeout).await.map_err(transfer_kind),
            None => {
                // Unclaimed control transfers are a real path, not a fallback: the
                // bootrom's `GET_CPU_INFO` is read before any claim.
                #[cfg(not(target_os = "windows"))]
                {
                    // The kind is taken apart and re-decorated below with this call's
                    // length and deadline, so `NoDevice` from an empty slot - a re-open
                    // that failed - carries the same context as a transfer failure
                    // does.
                    match self.device.handle() {
                        Ok(device) => device.control_in(request, timeout).await.map_err(transfer_kind),
                        Err(error) => Err(error.kind().clone()),
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    Err(windows_needs_a_claim())
                }
            }
        };
        outcome.map_err(|kind| {
            UsbError::new(
                kind,
                Pipe::Control {
                    direction: Direction::In,
                    request: req.request,
                },
            )
            .with_len(usize::from(req.len))
            .with_timeout(timeout)
        })
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::Out,
            request: req.request,
        };
        // `wLength` is 16 bits and every platform `expect()`s the conversion, so an
        // oversized data stage aborts inside `nusb` rather than returning. A flashing
        // tool does not abort, and `ControlIn::len` being a `u16` means
        // only this direction can reach it.
        if req.data.len() > MAX_CONTROL_DATA {
            return Err(UsbError::new(
                UsbErrorKind::Backend(format!(
                    "control data stage of {} bytes exceeds the {MAX_CONTROL_DATA} that wLength can carry",
                    req.data.len()
                )),
                pipe,
            )
            .with_len(req.data.len())
            .with_timeout(timeout));
        }
        let request = nusb::transfer::ControlOut {
            control_type: control_type(req.control_type),
            recipient: recipient(req.recipient),
            request: req.request,
            value: req.value,
            index: req.index,
            data: req.data,
        };
        let outcome = match self.claim.interface() {
            Some(interface) => interface.control_out(request, timeout).await.map_err(transfer_kind),
            None => {
                #[cfg(not(target_os = "windows"))]
                {
                    match self.device.handle() {
                        Ok(device) => device.control_out(request, timeout).await.map_err(transfer_kind),
                        Err(error) => Err(error.kind().clone()),
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    Err(windows_needs_a_claim())
                }
            }
        };
        outcome.map_err(|kind| UsbError::new(kind, pipe).with_len(req.data.len()).with_timeout(timeout))
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        if data.len() > MAX_TRANSFER {
            return Err(too_large(data.len(), None).with_timeout(timeout));
        }
        self.claim
            .with_bulk_out(|endpoint| {
                let pipe = pipe_of(endpoint.endpoint_address());

                // One copy, which the trait's `&[u8]` makes unavoidable: `nusb` must own
                // the buffer for as long as the OS might read from it, and an abandoned
                // transfer outlives this call.
                match bounded(endpoint, Buffer::from(data), timeout) {
                    // Both are timeouts, deliberately: `Timeout` is in the vendor retry
                    // class, so the caller's backoff gets another go - and the straggler
                    // that caused it is very likely reaped by then, which makes the retry
                    // a real recovery instead of a repeated failure.
                    Transfer::Blocked | Transfer::Abandoned => Err(UsbError::new(UsbErrorKind::Timeout, pipe)),
                    Transfer::Completed(completion) => {
                        let moved = completion.actual_len;
                        match completion.status {
                            // A short OUT is not an error here: the chunk loop continues the
                            // chunk with the remainder rather than restarting it, and that
                            // decision belongs to the bootrom layer.
                            Ok(()) => Ok(moved),
                            // A controller that times out but reports the full
                            // length transferred has done the write. The C learnt this the
                            // hard way (`device.c:433-441`).
                            Err(error) if is_timeout(error) && moved >= data.len() => Ok(moved),
                            Err(error) => Err(UsbError::new(transfer_kind(error), pipe).with_transferred(moved)),
                        }
                    }
                }
            })
            // Length and deadline are attached once, here, so the claim's own failures -
            // `NotClaimed`, or an endpoint that will not open - carry them too. Contract
            // D9 wants them on every failure path.
            .and_then(|result| result)
            .map_err(|error| error.with_len(data.len()).with_timeout(timeout))
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        if len > MAX_TRANSFER {
            return Err(too_large(len, None).with_timeout(timeout));
        }
        self.claim
            .with_bulk_in(|endpoint| {
                let address = BulkEndpoint::from_address(endpoint.endpoint_address());
                let pipe = pipe_of(endpoint.endpoint_address());

                // A zero-length IN is not a transfer - `nusb` refuses a request of 0
                // outright, and there is nothing to ask the device for. The check is
                // *inside* the claim so that an unclaimed `bulk_in(0, ..)` still answers
                // `NotClaimed`, which is what the trait promises and what
                // `MockTransport` does; short-circuiting above would have made the two
                // disagree on the unclaimed case.
                //
                // On the *claimed* case they still differ, and deliberately: this
                // answers `Ok(vec![])` with no bus traffic, while the mock takes it as a
                // scripted `Call::BulkIn { len: 0 }` like any other call. No caller
                // issues one - it is a caller bug either way - and making the mock
                // special-case it would cost a script entry that says nothing.
                if len == 0 {
                    return Ok(Vec::new());
                }

                let Some(request) = round_up(len, endpoint.max_packet_size()) else {
                    return Err(too_large(len, address));
                };
                if request > MAX_TRANSFER {
                    return Err(too_large(request, address));
                }

                match bounded(endpoint, Buffer::new(request), timeout) {
                    // As in `bulk_out`: retryable, so the vendor backoff can clear it.
                    Transfer::Blocked | Transfer::Abandoned => Err(UsbError::new(UsbErrorKind::Timeout, pipe)),
                    Transfer::Completed(completion) => {
                        let moved = completion.actual_len;
                        match completion.status {
                            // Exactly `len` or a failure. The request was
                            // rounded up to a packet multiple, so the device may answer
                            // with more than `len` and the surplus is dropped; it may never
                            // answer with less.
                            Ok(()) if completion.buffer.len() >= len => Ok(completion.buffer[..len].to_vec()),
                            Ok(()) => Err(UsbError::new(
                                UsbErrorKind::Short {
                                    got: completion.buffer.len(),
                                    want: len,
                                },
                                pipe,
                            )
                            .with_transferred(moved)),
                            Err(error) => Err(UsbError::new(transfer_kind(error), pipe).with_transferred(moved)),
                        }
                    }
                }
            })
            .and_then(|result| result)
            .map_err(|error| error.with_len(len).with_timeout(timeout))
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        let device = self.device.handle()?;
        device
            .set_configuration(value)
            .wait()
            .map_err(|error| device_error(&error))
    }

    fn active_configuration(&self) -> Option<u8> {
        // Cached, no bus traffic: `nusb` answers from the descriptors it
        // read at enumeration and, on Linux, the sysfs `bConfigurationValue` attribute.
        //
        // This reports what the OS believes and never what this transport last asked
        // for. `None` means unconfigured - the normal state of a driverless gadget
        // - or that the platform cannot tell, and both mean "set it", which is
        // the caller's job.
        //
        // After a `reset()` that makes this answer `Some(1)` on Linux, where the kernel
        // re-applies the configuration, while `MockTransport` answers `None` per USB
        // 9.1.1.5. See the trait's own note: a mock test cannot pin whether
        // a post-recovery claim emits `SET_CONFIGURATION`, and the differential
        // capture is what settles it. Remembering a `SET_CONFIGURATION` we issued would be the
        // dangerous direction: a value reported but not in force makes the claim paths
        // *skip* a request the device needs, where the honest `None` costs at worst one
        // redundant request.
        let device = self.device.handle().ok()?;
        device
            .active_configuration()
            .ok()
            .map(|configuration| configuration.configuration_value())
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        // Any previous claim goes first: the OS refuses a second claim of an interface
        // this process already holds, and a stale claim would keep endpoints open on an
        // interface nobody is using.
        self.claim.release_any()?;
        // `detach_and_claim_interface` is both steps in one call: on Linux it detaches
        // whatever kernel driver holds the interface, claims it, and re-attaches the
        // driver on release; on the other platforms it is exactly `claim_interface`.
        //
        // The C's claim helper open-codes the same two steps and nothing more:
        // `kernel_driver_active` then `detach_kernel_driver`
        // (`libtdfu/src/usb/device.c:342-345`), then one `claim_interface` whose failure
        // it returns (`:347-351`). No retry. The earlier wording here cited those lines
        // for a "detach-and-retry" they do not contain: the C's one retry
        // lives somewhere else entirely, at `libtdfu/src/bootstrap.c:79-81`, where the
        // bootstrap transfer path hand-detaches and claims a second time on top of the
        // helper that already detached. That is belt-and-braces, not a rule - a claim
        // that failed after the backend already detached fails again.
        //
        // Setting the configuration is *not* done here. That is the caller's decision,
        // taken from `active_configuration()` so a redundant `SET_CONFIGURATION` never
        // goes out - a differential USB capture caught two of them.
        let device = self.device.handle()?;
        let interface = device
            .detach_and_claim_interface(spec.interface)
            .wait()
            .map_err(|error| device_error(&error))?;
        self.claim.install(spec, interface)
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        self.claim.release(interface)
    }

    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        self.claim.set_alt(interface, alt)
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        // By address, not by direction: the claim may declare `0x81` while the caller
        // asks for `0x82`, and clearing the halt on the wrong endpoint would look like
        // it had worked.
        if !self.claim.declares(endpoint) {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Bulk(endpoint)));
        }
        // `with_open_bulk_*`, not `with_bulk_*`: it drains the endpoint first, which
        // `nusb` requires ("should not be called when transfers are pending on the
        // endpoint", `nusb-0.2.7/src/device.rs:898`) and which matters here because the
        // one caller — the vendor `Stall` retry — arrives from a transfer that just
        // failed. And it does not *open* a closed endpoint: there is no pending transfer
        // to rescue, and the next one re-opens it anyway.
        let outcome = match endpoint.direction() {
            Direction::In => self.claim.with_open_bulk_in(|open| open.clear_halt().wait())?,
            Direction::Out => self.claim.with_open_bulk_out(|open| open.clear_halt().wait())?,
        };
        // `None` — the endpoint was not open — is success with nothing to do.
        outcome
            .unwrap_or(Ok(()))
            .map_err(|error| UsbError::new(device_kind(&error), Pipe::Bulk(endpoint)))
    }

    /// Android never resets: the fd belongs to Java, and a close-and-reopen
    /// before a DFU operation churns the gadget's controller and wedges EP0 for minutes
    /// with nothing on the UART.
    ///
    /// This reports [`UsbErrorKind::Unsupported`] where the C returns silent success
    /// (`device.c:309-313` makes `usb_device_reset` a no-op there, and `device.c:220-226`
    /// does the same for `usb_device_reopen`). The contract asks
    /// for the truthful answer, and it is the better one: the caller retries
    /// *because* a reset happened, so a success it did not earn turns one failure into
    /// two.
    #[cfg(target_os = "android")]
    async fn reset(&self) -> Result<(), UsbError> {
        Err(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device))
    }

    /// The claim is torn down first, then the bus reset goes out, then the handle it
    /// killed is dropped and a fresh one opened from the stored identity — all of it
    /// inside `reset_and_reopen`, where each step is pinned.
    ///
    /// The re-open is **transparent**: the caller keeps the same `&self` and the next
    /// operation works, which is what `tdfu_core::dfu::host::reset_and_retry_once` has
    /// always assumed and what was only true on Linux before this. See
    /// `NusbHandles::bus_reset` for what "reset" means on each platform, and note that
    /// on Windows it means a host-side handle recycle and not a bus reset.
    ///
    /// The *other* order costs exactly this: `let _dropped = …take()` binds the value
    /// and keeps the interface and both endpoint vectors alive across the reset.
    #[cfg(not(target_os = "android"))]
    async fn reset(&self) -> Result<(), UsbError> {
        self.device.reset_and_reopen(&self.claim, &self.identity)
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        &self.descriptors
    }
}

/// Is this the error an expired deadline produces? See [`transfer_kind`].
fn is_timeout(error: nusb::transfer::TransferError) -> bool {
    transfer_kind(error) == UsbErrorKind::Timeout
}

/// The pipe an open endpoint handle is on.
///
/// `from_address` refuses endpoint number 0, which an open bulk endpoint can never be —
/// `Pipe::Device` is the unreachable arm, and it is an arm rather than an `unreachable!`
/// because a flashing tool does not abort to report a pipe.
fn pipe_of(address: u8) -> Pipe {
    BulkEndpoint::from_address(address).map_or(Pipe::Device, Pipe::Bulk)
}

/// A length this backend cannot hand to `nusb` without it panicking.
fn too_large(len: usize, endpoint: Option<BulkEndpoint>) -> UsbError {
    UsbError::new(
        UsbErrorKind::Backend(format!(
            "transfer of {len} bytes exceeds the {MAX_TRANSFER} byte maximum"
        )),
        endpoint.map_or(Pipe::Device, Pipe::Bulk),
    )
    .with_len(len)
}

/// WinUSB has no device-wide control pipe: every control transfer rides a claimed
/// interface handle, and `nusb` does not compile `Device::control_in` for Windows at
/// all. The message says which, because "unsupported" alone sends someone to look for a
/// driver problem that is not there.
#[cfg(target_os = "windows")]
fn windows_needs_a_claim() -> UsbErrorKind {
    UsbErrorKind::Backend(
        "a control transfer on Windows needs a claimed interface: WinUSB has no device-wide control pipe".to_owned(),
    )
}

/// `bmRequestType` bits 6:5, as `nusb` spells them.
const fn control_type(control_type: ControlType) -> NusbControlType {
    match control_type {
        ControlType::Standard => NusbControlType::Standard,
        ControlType::Class => NusbControlType::Class,
        ControlType::Vendor => NusbControlType::Vendor,
    }
}

/// `bmRequestType` bits 4:0, as `nusb` spells them.
const fn recipient(recipient: Recipient) -> NusbRecipient {
    match recipient {
        Recipient::Device => NusbRecipient::Device,
        Recipient::Interface => NusbRecipient::Interface,
        Recipient::Endpoint => NusbRecipient::Endpoint,
        Recipient::Other => NusbRecipient::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{CANCEL_GRACE, MAX_CONTROL_DATA, MAX_TRANSFER, control_type, pipe_of, recipient, round_up};
    use crate::endpoint::{BOOTROM_IN, BOOTROM_OUT};
    use crate::{ControlType, Pipe, Recipient};

    #[test]
    fn an_in_request_is_rounded_up_to_a_nonzero_packet_multiple() {
        // The `nusb` spike: 512 bytes on every bootrom seen. A 4-byte
        // register read asks for 512 and the device answers with 4.
        assert_eq!(round_up(4, 512), Some(512));
        assert_eq!(round_up(512, 512), Some(512));
        assert_eq!(round_up(513, 512), Some(1024));
        assert_eq!(round_up(256, 512), Some(512));
        // 64-byte endpoints exist; nothing here assumes 512.
        assert_eq!(round_up(4, 64), Some(64));
    }

    #[test]
    fn a_packet_size_of_zero_is_refused_rather_than_divided_by() {
        assert_eq!(round_up(4, 0), None);
    }

    #[test]
    fn a_rounded_request_that_overflows_is_refused_rather_than_wrapping() {
        assert_eq!(round_up(usize::MAX, 512), None);
    }

    #[test]
    fn the_control_request_fields_map_one_to_one() {
        // The six `(direction, type, recipient)` triples the C uses.
        // Typed fields exist so none of them can be mistyped as a packed byte.
        use nusb::transfer::{ControlType as N, Recipient as R};
        assert_eq!(control_type(ControlType::Standard), N::Standard);
        assert_eq!(control_type(ControlType::Class), N::Class);
        assert_eq!(control_type(ControlType::Vendor), N::Vendor);
        assert_eq!(recipient(Recipient::Device), R::Device);
        assert_eq!(recipient(Recipient::Interface), R::Interface);
        assert_eq!(recipient(Recipient::Endpoint), R::Endpoint);
        assert_eq!(recipient(Recipient::Other), R::Other);
    }

    #[test]
    fn a_failure_names_the_endpoint_it_happened_on() {
        // A 2 s bulk IN on `0x81` and a 30 s EP0 `DNLOAD` must not read
        // alike in a bug report.
        assert_eq!(pipe_of(0x81), Pipe::Bulk(BOOTROM_IN));
        assert_eq!(pipe_of(0x01), Pipe::Bulk(BOOTROM_OUT));
        assert_eq!(pipe_of(0x00), Pipe::Device);
    }

    #[test]
    fn the_cancel_grace_is_bounded_and_short() {
        // The number is a compromise; that it is finite is the requirement. `nusb`'s
        // own `transfer_blocking` loops here without a bound, and a wedged device
        // freezes the runtime.
        assert!(CANCEL_GRACE > core::time::Duration::ZERO);
        assert!(CANCEL_GRACE < core::time::Duration::from_secs(2));
    }

    #[test]
    fn the_transfer_ceiling_is_below_where_nusb_stops_returning_errors() {
        // Two aborts sit above this line and neither is a `Result`: `Buffer::new`
        // panics past `u32::MAX`, and long before that its `Vec::with_capacity` reaches
        // `handle_alloc_error`, which aborts the process. A flashing tool does
        // neither, so the ceiling is the one Linux usbfs enforces on a single URB
        // rather than the one the type happens to allow.
        assert_eq!(MAX_TRANSFER, 16 * 1024 * 1024);
        assert!(MAX_TRANSFER < u32::MAX as usize);
        // Every transfer the tool actually issues clears it by orders of magnitude:
        // uploads are chunked at 64 KiB, a register read takes 4 bytes.
        assert_eq!(MAX_TRANSFER / (64 * 1024), 256);
    }

    #[test]
    fn a_control_data_stage_is_capped_at_what_wlength_can_carry() {
        // `ControlIn::len` is a `u16`, so only OUT can overflow it - and every platform
        // `expect()`s that conversion rather than returning an error.
        assert_eq!(MAX_CONTROL_DATA, usize::from(u16::MAX));
    }
}
