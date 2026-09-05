//! The claim state machine: one interface, the endpoints it declared, and every
//! transition the trait pins.
//!
//! This is a separate module, and generic over its handle types, for one reason: the
//! trait's two obligations —
//! `release_interface` is idempotent, and `reset` drops the endpoints **before** the
//! reset goes out — are properties of a state machine, not of a device. An earlier
//! implementation wrote them into the transport where the only way to check them was a
//! bench run, and `reset()`'s `let _dropped = …take()` (which *binds* the value and
//! keeps the interface and both endpoint vectors alive across the reset, the exact
//! opposite of the comment above it) survived unnoticed until an audit found it.
//!
//! Here both are ordinary unit tests: [`tests`] substitutes handles that count their
//! own drops, so `usb_reset_drops_the_claim` fails if a handle outlives the reset and
//! `usb_release_is_idempotent` fails if a second release manufactures an error.

use core::cell::RefCell;
use core::time::Duration;

use crate::{BulkEndpoint, InterfaceSpec, Pipe, UsbError, UsbErrorKind};

/// How long the OS is given to hand back a transfer that has been cancelled.
///
/// A cancellation the kernel has accepted returns in microseconds, so 250 ms is many
/// orders of magnitude of slack; a device that has not returned it by then is wedged
/// rather than slow. The *bound* is the requirement, not the number — `nusb`'s own
/// `Endpoint::transfer_blocking` waits here without one.
pub(super) const CANCEL_GRACE: Duration = Duration::from_millis(250);

/// What the state machine needs from a backend's handles.
///
/// The real implementation is `nusb`'s `Interface` and two `Endpoint`s; the test one is
/// three counters. Nothing else about a backend leaks in here.
pub(crate) trait Handles {
    /// A claimed interface. `Clone` because a control transfer must take a handle out
    /// of the slot and drop the borrow before awaiting (`nusb`'s is an `Arc`).
    type Interface: Clone;
    /// An open bulk IN endpoint.
    type BulkIn;
    /// An open bulk OUT endpoint.
    type BulkOut;
    /// An open device handle. **A bus reset invalidates it**, which `nusb` says
    /// outright: "This `Device` will no longer be usable, and you should drop it and
    /// call `list_devices` to find and re-open it"
    /// (`nusb-0.2.7/src/device.rs:287-290`).
    ///
    /// `Clone` for the reason [`Handles::Interface`] is: a transfer takes a handle out
    /// of the slot and drops the borrow before it awaits. `nusb`'s is an `Arc` and "the
    /// device is closed when all clones and all associated `Interface`s are dropped"
    /// (`nusb-0.2.7/src/device.rs:45-47`) — which is the other half of why the claim is
    /// torn down *before* a reset rather than after: an `Interface` that outlived it
    /// would keep the dead device open.
    type Device: Clone;
    /// What a device is re-opened *from* once its handle is dead. `nusb`'s is a
    /// `DeviceInfo`.
    ///
    /// Absent on Android along with the two operations that use it, and the reason is
    /// the **re-open**, not the reset: the fd comes from Java's `UsbManager` and
    /// `nusb::list_devices` is not compiled on that target at all, so there is nothing
    /// to re-open *from*. A reset is the half that would be possible; without a re-open
    /// it would leave a handle the OS has invalidated, which is the state this type
    /// exists to make unreachable — so `reset()` is `Unsupported` there.
    /// `cfg` rather than an unreachable arm, so the absence stays visible — the same
    /// choice [`ClaimSlot::reset_with`] makes.
    #[cfg(not(target_os = "android"))]
    type Identity;

    /// Open the bulk IN endpoint at `endpoint` on `interface`.
    ///
    /// # Errors
    /// [`UsbErrorKind::Fault`] when the interface's current alternate setting does not
    /// offer it. Claim time is the one place that failure is reachable.
    fn open_bulk_in(interface: &Self::Interface, endpoint: BulkEndpoint) -> Result<Self::BulkIn, UsbError>;

    /// Open the bulk OUT endpoint at `endpoint` on `interface`.
    ///
    /// # Errors
    /// As [`Handles::open_bulk_in`].
    fn open_bulk_out(interface: &Self::Interface, endpoint: BulkEndpoint) -> Result<Self::BulkOut, UsbError>;

    /// `SET_INTERFACE`. Called with no endpoints open — both `nusb`'s Linux and WinUSB
    /// paths refuse an alternate-setting change while any endpoint is in use.
    ///
    /// # Errors
    /// Whatever the OS raises.
    fn set_alt_setting(interface: &Self::Interface, alt: u8) -> Result<(), UsbError>;

    /// Release the interface, consuming the handle. Called with no endpoints open.
    ///
    /// # Errors
    /// Whatever the OS raises.
    fn release(interface: Self::Interface) -> Result<(), UsbError>;

    /// Reclaim any transfer still outstanding on the bulk IN endpoint, waiting at most
    /// `grace`. `true` when the endpoint is clear afterwards.
    ///
    /// This is not housekeeping — it is what makes a timed-out transfer recoverable.
    /// Cancelling a transfer only *asks* the OS to return it; until it does, that
    /// transfer still owns the endpoint (`nusb` refuses to open it again while its
    /// address bit is set, and only the completion handler clears that bit) **and**,
    /// through it, the interface (`Interface::release` is an `Arc::into_inner`, so a
    /// straggler makes it fail `Busy`). Draining is the only way back.
    ///
    /// `#[must_use]`: the `false` is the reason a later release or alternate-setting
    /// change fails, and it is the one thing the OS's own text cannot say. Discarding
    /// it throws away the only cause a later failure has.
    #[must_use]
    fn drain_bulk_in(endpoint: &mut Self::BulkIn, grace: Duration) -> bool;

    /// Reclaim any transfer still outstanding on the bulk OUT endpoint.
    ///
    /// As [`Handles::drain_bulk_in`], for the OUT direction.
    #[must_use]
    fn drain_bulk_out(endpoint: &mut Self::BulkOut, grace: Duration) -> bool;

    /// Reset the bus, on a handle that is still live and with nothing claimed.
    ///
    /// Called from inside [`ClaimSlot::reset_with`], so by the time it runs the claim
    /// is gone. That is not tidiness: libusb's Linux backend releases every claimed
    /// interface before its own `IOCTL_USBFS_RESET` for the same reason, spelled out at
    /// `libusb/os/linux_usbfs.c:1817-1823` — "Doing a device reset will cause the usbfs
    /// driver to get unbound from any interfaces it is bound to. By voluntarily
    /// unbinding the usbfs driver ourself, we stop the kernel from rebinding the
    /// interface after reset" — and `nusb`'s macOS backend refuses the call outright
    /// while any interface is claimed (`macos_iokit/device.rs:171-176`, `Busy`,
    /// "cannot perform this operation while interfaces are claimed").
    ///
    /// That macOS check has a **side effect worth knowing about**: it lives at the end of
    /// `require_open_exclusive` (`macos_iokit/device.rs:155-179`), which first opens the
    /// device for exclusive access and latches `is_open_exclusive`. So reaching the
    /// refusal has already taken an exclusive open — the claim count is checked *after*
    /// it, not before. It changes nothing here (the claim is gone by the time this is
    /// called, so the check passes), but a reader chasing "why did a refused reset change
    /// anything" should know the open happened.
    ///
    /// # Errors
    /// [`UsbErrorKind::Unsupported`] on a platform with no bus reset; otherwise
    /// whatever the OS raises. A failure here means the reset **did not happen**, so
    /// the caller keeps the handle it has.
    #[cfg(not(target_os = "android"))]
    fn bus_reset(device: &Self::Device) -> Result<(), UsbError>;

    /// Open a fresh handle, called with **no** other handle to this device alive.
    ///
    /// `identity` is `&mut` because a device that re-enumerated may be somewhere else:
    /// whatever this leaves behind is what the *next* re-open starts from, so a device
    /// that moved is not chased from the address it had two resets ago.
    ///
    /// # Errors
    /// Whatever the OS raises, or the backend's own "it never came back".
    #[cfg(not(target_os = "android"))]
    fn open(identity: &mut Self::Identity) -> Result<Self::Device, UsbError>;
}

/// One interface claim and the endpoints it declared.
///
/// `spec` is what the caller *asked for* and never changes; `bulk_in`/`bulk_out` are
/// what is *open right now*, which is a smaller thing: an alternate-setting change
/// closes them across the request.
///
/// **Field order is load-bearing.** Drop glue runs in declaration order, so the
/// endpoints are declared *before* the interface and therefore die first — the same
/// order [`Claim::close_endpoints`] and [`ClaimSlot::release_any`] enforce explicitly.
/// With `nusb` the release is refcount-driven so the inverse order would still work by
/// accident; a future `Handles` whose interface drop performs a real release would not
/// be so lucky, and an invariant that is only true on the explicit paths is not one.
struct Claim<H: Handles> {
    spec: InterfaceSpec,
    bulk_in: Option<H::BulkIn>,
    bulk_out: Option<H::BulkOut>,
    interface: H::Interface,
}

impl<H: Handles> Claim<H> {
    /// Reclaim any outstanding transfer, then drop both endpoint handles.
    ///
    /// The drain comes first and it is not politeness: a transfer the OS has not
    /// returned keeps the endpoint *and* the interface alive no matter who drops what,
    /// so a release or an alternate-setting change issued over the top of one fails
    /// `Busy`. Draining is what makes those succeed.
    ///
    /// Then `drop(…take())`, never `let _name = …take()`. The second form binds the
    /// value to a live local and keeps the endpoint open for the rest of the scope,
    /// which is the mistake an earlier implementation made here.
    ///
    /// Returns `false` when a drain gave up on a straggler — the reason the release or
    /// the alternate-setting change that follows is about to fail, and a reason only
    /// this code knows. Both endpoints are drained whatever the first one reports:
    /// stopping early would leave the other one holding the interface as well.
    fn close_endpoints(&mut self) -> bool {
        let mut drained = true;
        if let Some(endpoint) = self.bulk_in.as_mut() {
            drained &= H::drain_bulk_in(endpoint, CANCEL_GRACE);
        }
        if let Some(endpoint) = self.bulk_out.as_mut() {
            drained &= H::drain_bulk_out(endpoint, CANCEL_GRACE);
        }
        drop(self.bulk_in.take());
        drop(self.bulk_out.take());
        drained
    }

    /// Open every endpoint `spec` declares, against the current alternate setting.
    fn open_endpoints(&mut self) -> Result<(), UsbError> {
        if let Some(endpoint) = self.spec.bulk_in {
            self.bulk_in = Some(H::open_bulk_in(&self.interface, endpoint)?);
        }
        if let Some(endpoint) = self.spec.bulk_out {
            self.bulk_out = Some(H::open_bulk_out(&self.interface, endpoint)?);
        }
        Ok(())
    }
}

/// The transport's claim, or the absence of one.
///
/// Interior mutability because every [`LocalUsbTransport`](crate::LocalUsbTransport)
/// method takes `&self` while `nusb`'s endpoint handles need `&mut` — which the
/// trait anticipates and permits, because it is `?Send` by design.
pub(crate) struct ClaimSlot<H: Handles> {
    claim: RefCell<Option<Claim<H>>>,
}

impl<H: Handles> ClaimSlot<H> {
    /// An empty slot: nothing claimed.
    pub(crate) const fn new() -> Self {
        Self {
            claim: RefCell::new(None),
        }
    }

    /// The claimed interface number, if any. Never performs I/O.
    pub(crate) fn claimed(&self) -> Option<u8> {
        self.claim.borrow().as_ref().map(|claim| claim.spec.interface)
    }

    /// A clone of the claimed interface handle, for a caller that must drop the borrow
    /// before it awaits. Holding a `RefCell` borrow across an `await` is the bug this
    /// exists to prevent.
    pub(crate) fn interface(&self) -> Option<H::Interface> {
        self.claim.borrow().as_ref().map(|claim| claim.interface.clone())
    }

    /// Does the claim in force declare `endpoint`?
    ///
    /// The transfer calls carry no endpoint address, so this exists for
    /// `clear_halt`, which does: clearing the halt on `0x81` when the caller asked for
    /// `0x82` would silently do the wrong thing.
    pub(crate) fn declares(&self, endpoint: BulkEndpoint) -> bool {
        self.claim
            .borrow()
            .as_ref()
            .is_some_and(|claim| claim.spec.bulk_in == Some(endpoint) || claim.spec.bulk_out == Some(endpoint))
    }

    /// Take ownership of a freshly claimed `interface` and open the endpoints `spec`
    /// declares.
    ///
    /// # Errors
    /// The first endpoint that will not open. The interface handle is dropped on that
    /// path — which releases it — and the slot is left empty, so a failed claim never
    /// leaves a half-claim behind.
    pub(crate) fn install(&self, spec: InterfaceSpec, interface: H::Interface) -> Result<(), UsbError> {
        let mut claim = Claim {
            spec,
            bulk_in: None,
            bulk_out: None,
            interface,
        };
        claim.open_endpoints()?;
        *self.claim.borrow_mut() = Some(claim);
        Ok(())
    }

    /// Release `interface` if it is the one in force.
    ///
    /// **Idempotent**: releasing an interface that is not claimed is `Ok(())`, which is
    /// what makes the release-on-every-exit-path discipline clean rather than noisy.
    /// Pinned by `usb_release_is_idempotent`.
    ///
    /// # Errors
    /// Whatever the OS raises while releasing a claim that *was* in force.
    pub(crate) fn release(&self, interface: u8) -> Result<(), UsbError> {
        let matches = self
            .claim
            .borrow()
            .as_ref()
            .is_some_and(|claim| claim.spec.interface == interface);
        if matches { self.release_any() } else { Ok(()) }
    }

    /// Release whatever is claimed, dropping its endpoints first. Idempotent.
    ///
    /// # Errors
    /// Whatever the OS raises while releasing.
    /// The slot is emptied *before* the release is attempted, and it stays empty even if
    /// the release reports an error. That is forced rather than chosen: `nusb`'s
    /// `Interface::release` consumes the handle and drops it whatever it returns, so
    /// there is nothing left to retry with and claiming to still hold the interface
    /// would be the lie. An error here means the OS has not finished letting go — the
    /// drain above is what makes that rare — and the interface is freed for real when
    /// the last outstanding transfer is reaped.
    pub(crate) fn release_any(&self) -> Result<(), UsbError> {
        let Some(mut claim) = self.claim.borrow_mut().take() else {
            return Ok(());
        };
        // Drain, then drop the endpoints, and only then release: an outstanding transfer
        // holds a reference to the interface, and `Interface::release` is an
        // `Arc::into_inner` that fails `Busy` while one exists.
        let drained = claim.close_endpoints();
        match H::release(claim.interface) {
            Ok(()) => Ok(()),
            // When the drain already gave up, we know *why* the release failed, and the
            // OS does not: on Linux `Interface::release` can fail exactly one way —
            // `ErrorKind::Busy`, "interface is still in use"
            // (`nusb-0.2.7/src/platform/linux_usbfs/device.rs:723-733`) — which restates
            // the symptom and names no cause. Reporting only that discards what this
            // code knows, the way the C's messages had to because they could not carry
            // it. The OS's own text is kept inside the message, so nothing is lost.
            Err(error) if !drained => Err(straggler(&error)),
            Err(error) => Err(error),
        }
    }

    /// The `reset()` sequence: tear the claim down, **then** run `reset`.
    ///
    /// The ordering is the point, and it is why this takes a closure instead of leaving
    /// the two steps at the call site where they can be swapped or the first one
    /// weakened into a binding. By the time `reset` runs, the slot is empty and every
    /// handle has been dropped. Pinned by `usb_reset_drops_the_claim`.
    ///
    /// A release failure here is deliberately discarded: the handles are gone either
    /// way, and a bus reset returns the device to the Default state (USB 2.0 §9.1.1.5),
    /// which supersedes whatever the interface's claim state was. Reporting it would
    /// mask the reset's own result, which is the one the caller acts on.
    ///
    /// **The claim is gone even when `reset` fails**, and that is not an accident to be
    /// tidied up later: the teardown has to happen first (macOS refuses a reset outright
    /// while an interface is claimed, `macos_iokit/device.rs:171-176`), so by the time
    /// anything can fail the claim is already released. A caller that sees `Err` here
    /// holds a device with **no claim** — on Android and WinUSB, where the reset is
    /// refused without touching the bus, that is the whole of the change — and its next
    /// attempt must claim for itself. Every caller in the tree does, because its first
    /// attempt needed a claim too.
    ///
    /// # Errors
    /// Whatever `reset` returns.
    ///
    /// Not compiled for Android, which has no reset sequence at all: the fd belongs to
    /// Java and `reset()` there is [`UsbErrorKind::Unsupported`]. `cfg`
    /// rather than a lint allowance, so the absence stays visible.
    #[cfg(any(test, not(target_os = "android")))]
    pub(crate) fn reset_with(&self, reset: impl FnOnce() -> Result<(), UsbError>) -> Result<(), UsbError> {
        let _ = self.release_any();
        reset()
    }

    /// `SET_INTERFACE`, re-opening the declared endpoints against the new alternate
    /// setting.
    ///
    /// Contract §2.2: "`set_alt_setting` re-opens whatever the claim declared against
    /// the new alternate setting". The DFU interface declares none, so the DFU path
    /// closes and re-opens nothing; the rule exists so a future bulk-carrying alt
    /// cannot silently keep a stale endpoint.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`] if `interface` is not the claimed one; otherwise
    /// whatever the OS raises. If the request itself fails the endpoints stay closed
    /// and the next transfer re-opens them.
    pub(crate) fn set_alt(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        let mut slot = self.claim.borrow_mut();
        let Some(claim) = slot.as_mut().filter(|claim| claim.spec.interface == interface) else {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device));
        };
        // The drain's verdict is deliberately not folded into this failure the way
        // `release_any` folds it: `SET_INTERFACE` goes out on EP0 and fails for reasons
        // that have nothing to do with a straggler (a nonexistent alternate setting,
        // above all), so attributing it to one would be a guess. The endpoints are shut
        // either way, which is the part that must happen first.
        let _straggler = claim.close_endpoints();
        H::set_alt_setting(&claim.interface, alt)?;
        claim.open_endpoints()
    }

    /// Run `f` against the claimed bulk IN endpoint, opening it first if it is closed.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`] if no claim is in force or the claim declared no
    /// bulk IN endpoint; otherwise whatever opening the endpoint raises.
    pub(crate) fn with_bulk_in<R>(&self, f: impl FnOnce(&mut H::BulkIn) -> R) -> Result<R, UsbError> {
        let mut slot = self.claim.borrow_mut();
        let Some(claim) = slot.as_mut() else {
            return Err(not_claimed());
        };
        let Some(address) = claim.spec.bulk_in else {
            return Err(not_claimed());
        };
        let endpoint = match claim.bulk_in {
            Some(ref mut endpoint) => endpoint,
            None => claim.bulk_in.insert(H::open_bulk_in(&claim.interface, address)?),
        };
        Ok(f(endpoint))
    }

    /// Run `f` against the claimed bulk OUT endpoint, opening it first if it is closed.
    ///
    /// # Errors
    /// As [`ClaimSlot::with_bulk_in`], for the OUT direction.
    pub(crate) fn with_bulk_out<R>(&self, f: impl FnOnce(&mut H::BulkOut) -> R) -> Result<R, UsbError> {
        let mut slot = self.claim.borrow_mut();
        let Some(claim) = slot.as_mut() else {
            return Err(not_claimed());
        };
        let Some(address) = claim.spec.bulk_out else {
            return Err(not_claimed());
        };
        let endpoint = match claim.bulk_out {
            Some(ref mut endpoint) => endpoint,
            None => claim.bulk_out.insert(H::open_bulk_out(&claim.interface, address)?),
        };
        Ok(f(endpoint))
    }

    /// Reclaim any outstanding transfer on the claimed bulk IN endpoint, then run `f`
    /// against it — but only if it is **already open**. `Ok(None)` says it was not.
    ///
    /// This is what `clear_halt` needs, and what [`ClaimSlot::with_bulk_in`] is wrong
    /// for on both counts:
    ///
    /// * `nusb` documents `clear_halt` as "should not be called when transfers are
    ///   pending on the endpoint" (`nusb-0.2.7/src/device.rs:898`), and the caller that
    ///   wants it — the vendor `Stall` retry — arrives straight from a failed
    ///   transfer, which is precisely when one may still be outstanding.
    /// * Opening a closed endpoint to clear a halt on it buys nothing: nothing is using
    ///   it, and the next transfer opens it anyway. `with_bulk_in` would open it, clear
    ///   it and leave it open — a side effect on a path meant to have none.
    ///
    /// # Errors
    /// [`UsbErrorKind::NotClaimed`] if no claim is in force or the claim declared no
    /// bulk IN endpoint.
    pub(crate) fn with_open_bulk_in<R>(&self, f: impl FnOnce(&mut H::BulkIn) -> R) -> Result<Option<R>, UsbError> {
        let mut slot = self.claim.borrow_mut();
        let Some(claim) = slot.as_mut() else {
            return Err(not_claimed());
        };
        if claim.spec.bulk_in.is_none() {
            return Err(not_claimed());
        }
        let Some(endpoint) = claim.bulk_in.as_mut() else {
            return Ok(None);
        };
        let _straggler = H::drain_bulk_in(endpoint, CANCEL_GRACE);
        Ok(Some(f(endpoint)))
    }

    /// As [`ClaimSlot::with_open_bulk_in`], for the OUT direction.
    ///
    /// # Errors
    /// As [`ClaimSlot::with_open_bulk_in`].
    pub(crate) fn with_open_bulk_out<R>(&self, f: impl FnOnce(&mut H::BulkOut) -> R) -> Result<Option<R>, UsbError> {
        let mut slot = self.claim.borrow_mut();
        let Some(claim) = slot.as_mut() else {
            return Err(not_claimed());
        };
        if claim.spec.bulk_out.is_none() {
            return Err(not_claimed());
        }
        let Some(endpoint) = claim.bulk_out.as_mut() else {
            return Ok(None);
        };
        let _straggler = H::drain_bulk_out(endpoint, CANCEL_GRACE);
        Ok(Some(f(endpoint)))
    }
}

/// One open device handle, and the seam a reset re-opens it through.
///
/// Separate from [`ClaimSlot`] because the two answer to different lifetimes: a claim
/// comes and goes many times over one handle, and a handle is replaced exactly once per
/// reset. Generic over [`Handles`] for the reason the claim is — the ordering it
/// enforces is a property of a state machine, so [`tests`] substitutes handles that
/// count their own opens and drops, and every step of it is an ordinary unit test.
///
/// # Why the transport needs this at all
///
/// An earlier `reset()` called `Device::reset()` and then went on using the same
/// handle. `nusb` documents that handle as dead (`nusb-0.2.7/src/device.rs:287-290`),
/// and the three platforms differ in how much they mind:
///
/// * **Linux** does not, by accident. The reset is one `USBDEVFS_RESET` ioctl on the
///   open fd (`linux_usbfs/device.rs:369-377` → `usbfs.rs:174-179`); the kernel
///   re-enumerates the same device in place and the fd stays valid.
/// * **macOS** does. The reset is `USBDeviceReEnumerate(0)`
///   (`macos_iokit/iokit_usb.rs:133-135`), which terminates the `IOKit` service the handle
///   is built on, and a re-open looks the device up by *registry id*
///   (`macos_iokit/device.rs:61-68` → `enumeration.rs:111-115`) — which the
///   re-enumerated device does not have any more.
/// * **Windows** has none available to it: `nusb`'s WinUSB backend answers `Unsupported`
///   (`windows_winusb/device.rs:170-175`) because WinUSB exposes no host-initiated port
///   reset — libusb says so in its own comment and cycles pipes instead
///   (`libusb/os/windows_winusb.c:4297-4343`).
///
/// One mechanism, three answers, and the transport's job is to make all three end in the
/// same place: a live handle and an empty claim.
pub(crate) struct DeviceSlot<H: Handles> {
    /// `None` only while a re-open is under way, and after one that failed. There is no
    /// state in which this holds a handle a reset has already killed — which is the
    /// entire point of the type.
    device: RefCell<Option<H::Device>>,
}

impl<H: Handles> DeviceSlot<H> {
    /// A slot holding an already-open handle.
    pub(crate) const fn new(device: H::Device) -> Self {
        Self {
            device: RefCell::new(Some(device)),
        }
    }

    /// A clone of the open handle, for a caller that must drop the borrow before it
    /// awaits — the same rule, for the same reason, as [`ClaimSlot::interface`].
    ///
    /// # Errors
    /// [`UsbErrorKind::NoDevice`] when a re-open failed and left nothing open. *Why* it
    /// failed was reported once, by the [`reset`](Self::reset_and_reopen) that hit it;
    /// every call afterwards says only that there is no device, because that is all
    /// that is still true.
    pub(crate) fn handle(&self) -> Result<H::Device, UsbError> {
        self.device
            .borrow()
            .clone()
            .ok_or_else(|| UsbError::new(UsbErrorKind::NoDevice, Pipe::Device))
    }

    /// The whole `reset()` sequence: tear the claim down, reset the bus, drop the handle
    /// the reset killed, and re-open from `identity`.
    ///
    /// The order is the entire content of this function, and each step is pinned:
    ///
    /// 1. [`ClaimSlot::reset_with`] releases the claim and drops its endpoints **before**
    ///    the reset goes out (`usb_reset_drops_the_claim`).
    /// 2. The reset runs on a handle that is still live — it has to; there is no other
    ///    way to ask for one.
    /// 3. Every reference to that handle dies **before** anything is opened
    ///    (`usb_reset_drops_the_dead_handle_before_re_opening`). `nusb`'s `Device` is an
    ///    `Arc`, so both the clone taken here and the slot's own have to go.
    /// 4. The fresh handle is installed and the refreshed `identity` kept
    ///    (`a_reset_re_opens_the_device_from_its_identity`).
    ///
    /// A failure at step 2 leaves the handle in place: the reset did not happen, so
    /// nothing invalidated it, and throwing it away would turn a refusal into a lost
    /// device. A failure at step 4 leaves the slot **empty** rather than holding the
    /// dead handle — the one state this type exists to make unreachable.
    ///
    /// The claim is not restored, and that is the contract: a bus reset returns the
    /// device to the Default state (USB 2.0 §9.1.1.5), so the interface it re-opens with
    /// is not the one that was claimed. libusb re-claims here
    /// (`libusb/os/linux_usbfs.c:1839-1854`) and downgrades its own return to
    /// `LIBUSB_ERROR_NOT_FOUND` when it cannot; our callers claim for themselves on
    /// every attempt, so there is nothing to restore and nothing to downgrade.
    ///
    /// # Errors
    /// Whatever the bus reset raises, or whatever the re-open raises.
    ///
    /// Not compiled for Android, which has no reset sequence at all: the fd belongs to
    /// Java, `nusb::list_devices` is not compiled there, and `reset()` is
    /// [`UsbErrorKind::Unsupported`]. `cfg` rather than a lint allowance,
    /// so the absence stays visible.
    #[cfg(not(target_os = "android"))]
    pub(crate) fn reset_and_reopen(
        &self,
        claim: &ClaimSlot<H>,
        identity: &RefCell<H::Identity>,
    ) -> Result<(), UsbError> {
        let device = self.handle()?;
        claim.reset_with(|| H::bus_reset(&device))?;
        // This clone first, then the slot's, and only then the open. Assigning a fresh
        // handle over the slot instead would drop the dead one *after* the new one
        // exists — the ordering `nusb` tells you not to rely on, and the one macOS does
        // not survive.
        drop(device);
        // Take, release the borrow, *then* open. The re-open blocks for up to
        // `REOPEN_WINDOW` (2 s) while it polls the bus, and a `RefCell` borrow held
        // across it turns any re-entrant [`handle`](Self::handle) — a progress sink that
        // looks at the transport, a fault fixture, anything a caller wires in — into a
        // panic, which a flashing tool does not take. The **ordering is
        // unchanged**, because it is the ordering and not the borrow that matters: the
        // dead handle is dropped inside this statement, before `H::open` is called at
        // all, which is what `usb_reset_drops_the_dead_handle_before_re_opening` asserts
        // from inside the re-open.
        drop(self.device.borrow_mut().take());
        let fresh = H::open(&mut identity.borrow_mut())?;
        *self.device.borrow_mut() = Some(fresh);
        Ok(())
    }
}

/// A `NotClaimed` failure.
///
/// The pipe is [`Pipe::Device`] rather than a bulk endpoint, and truthfully so: the
/// transfer calls carry no address, so when the claim declares no such
/// endpoint there is no address to name. "No claimed interface offers this pipe" is
/// exactly what happened.
fn not_claimed() -> UsbError {
    UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device)
}

/// A release failure the drain already explained, with the OS's own text kept.
///
/// [`UsbErrorKind::Backend`] is "something the backend can only describe in prose", and
/// this is one: the cause is a transfer the OS never returned, which no kind names. No
/// classification is lost on the way — the only failure `Interface::release` produces is
/// `Busy`, which is in neither the vendor retry class nor the bus-reset recoverable
/// class either.
fn straggler(error: &UsbError) -> UsbError {
    UsbError::new(
        UsbErrorKind::Backend(format!(
            "{}: a transfer was still outstanding after the {} ms drain, so the interface was never free",
            error.kind(),
            CANCEL_GRACE.as_millis()
        )),
        error.pipe(),
    )
}

#[cfg(test)]
mod tests {
    use super::{ClaimSlot, DeviceSlot, Handles};
    use crate::endpoint::{BOOTROM_IN, BOOTROM_OUT};
    use crate::{BulkEndpoint, Direction, InterfaceSpec, Pipe, UsbError, UsbErrorKind};
    use core::time::Duration;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// A handle that reports its own destruction. The two pins are assertions about
    /// *drops*, and a drop is only observable if something counts it.
    #[derive(Debug)]
    struct Tracked {
        live: Rc<Cell<usize>>,
    }

    impl Tracked {
        fn new(live: &Rc<Cell<usize>>) -> Self {
            live.set(live.get() + 1);
            Self { live: Rc::clone(live) }
        }
    }

    /// Hand-written, **not** derived. A derived `Clone` copies the counter handle
    /// without counting the copy, so every clone would decrement on drop a count it
    /// never incremented — the fixture would under-report live handles and, once the
    /// count reached zero, panic on the subtraction. `ClaimSlot::interface()` returns a
    /// clone, so the first test to route a control transfer found it.
    impl Clone for Tracked {
        fn clone(&self) -> Self {
            Self::new(&self.live)
        }
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.live.set(self.live.get() - 1);
        }
    }

    /// Everything the fixture can be told to do or count.
    #[derive(Default)]
    struct Log {
        interfaces: Rc<Cell<usize>>,
        endpoints: Rc<Cell<usize>>,
        /// Live device handles. The re-open pin is an assertion about this being zero
        /// at one specific instant.
        devices: Rc<Cell<usize>>,
        releases: Cell<usize>,
        /// How many bus resets went out.
        resets: Cell<usize>,
        /// How many times a fresh device handle was opened.
        device_opens: Cell<usize>,
        /// How many device handles were still live when the re-open ran. A reset that
        /// kept the handle it just killed, or one that opened before dropping it, leaves
        /// this nonzero — which is the whole of `usb_reset_drops_the_dead_handle_…`.
        live_devices_at_open: Cell<usize>,
        /// When set, the platform refuses the bus reset — Android and WinUSB are the
        /// live cases (`windows_winusb/device.rs:170-175`).
        reset_fails: Cell<bool>,
        /// When set, the device never comes back after the reset.
        reopen_fails: Cell<bool>,
        alt_settings: Cell<Vec<u8>>,
        /// When set, every endpoint open fails with this kind.
        refuse_endpoints: RefCell<Option<UsbErrorKind>>,
        /// How many times an endpoint was drained.
        drains: Cell<usize>,
        /// What the **IN** drain reports. `false` models a straggler the OS has not
        /// returned.
        ///
        /// Per direction, and that is the point: with one flag for both,
        /// `close_endpoints`' two `&=` accumulate values that always agree, and `&=` and
        /// `|=` are then the same operation there. `cargo mutants` reported both as
        /// surviving, and the 2026-08-23 audit refuted the "equivalent mutant" reading:
        /// they were live holes, and separating the knobs is what makes the two tests
        /// below able to see them.
        drain_in_succeeds: Cell<bool>,
        /// What the **OUT** drain reports. See [`Log::drain_in_succeeds`].
        drain_out_succeeds: Cell<bool>,
        /// When set, the OS refuses the release. Without a knob for this the fixture
        /// could not fail a release at all, and the test that says a reset survives one
        /// asserted nothing.
        release_fails: Cell<bool>,
        /// When set, the OS refuses `SET_INTERFACE`. That is the one reachable way to
        /// leave a claim in force with its endpoints closed, which is the state
        /// `with_open_bulk_in` exists for.
        set_alt_fails: Cell<bool>,
        /// Run from inside [`Fixture::open`], so a test can observe the transport
        /// *during* the re-open. The real one blocks for up to two seconds there, which
        /// is where a `RefCell` borrow held across it does its damage.
        during_open: RefCell<Option<Rc<dyn Fn()>>>,
    }

    impl std::fmt::Debug for Log {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Log")
                .field("live_interfaces", &self.interfaces.get())
                .field("live_endpoints", &self.endpoints.get())
                .field("live_devices", &self.devices.get())
                .field("releases", &self.releases.get())
                .field("resets", &self.resets.get())
                .field("device_opens", &self.device_opens.get())
                .finish_non_exhaustive()
        }
    }

    thread_local! {
        static LOG: Rc<Log> = Rc::new(Log::default());
    }

    fn log() -> Rc<Log> {
        LOG.with(Rc::clone)
    }

    /// Reset the shared fixture. Each test starts from a known state; they run on
    /// separate threads, and `LOG` is thread-local, but a test that ran two slots would
    /// otherwise share counters.
    fn fresh() -> Rc<Log> {
        let log = log();
        log.releases.set(0);
        log.alt_settings.set(Vec::new());
        *log.refuse_endpoints.borrow_mut() = None;
        log.drains.set(0);
        log.drain_in_succeeds.set(true);
        log.drain_out_succeeds.set(true);
        log.release_fails.set(false);
        log.set_alt_fails.set(false);
        log.resets.set(0);
        log.device_opens.set(0);
        log.live_devices_at_open.set(0);
        log.reset_fails.set(false);
        log.reopen_fails.set(false);
        *log.during_open.borrow_mut() = None;
        log
    }

    struct Fixture;

    impl Handles for Fixture {
        type Interface = Tracked;
        type BulkIn = Tracked;
        type BulkOut = Tracked;
        type Device = Tracked;
        /// A generation counter standing in for `nusb`'s `DeviceInfo`: the re-open
        /// bumps it, so a test can tell the identity the transport *kept* from the one
        /// it started with.
        type Identity = u32;

        fn open_bulk_in(_interface: &Tracked, endpoint: BulkEndpoint) -> Result<Tracked, UsbError> {
            open(endpoint)
        }

        fn open_bulk_out(_interface: &Tracked, endpoint: BulkEndpoint) -> Result<Tracked, UsbError> {
            open(endpoint)
        }

        fn set_alt_setting(_interface: &Tracked, alt: u8) -> Result<(), UsbError> {
            let log = log();
            let mut seen = log.alt_settings.take();
            seen.push(alt);
            log.alt_settings.set(seen);
            if log.set_alt_fails.get() {
                return Err(UsbError::new(UsbErrorKind::Fault, Pipe::Device));
            }
            Ok(())
        }

        fn release(interface: Tracked) -> Result<(), UsbError> {
            let log = log();
            log.releases.set(log.releases.get() + 1);
            // Consumed and dropped whatever the answer, exactly as `nusb`'s
            // `Interface::release` does: there is nothing left to retry with.
            drop(interface);
            if log.release_fails.get() {
                // The one error the real call produces
                // (`nusb-0.2.7/src/platform/linux_usbfs/device.rs:730`).
                return Err(UsbError::new(
                    UsbErrorKind::Backend("interface is still in use".to_owned()),
                    Pipe::Device,
                ));
            }
            Ok(())
        }

        fn drain_bulk_in(_endpoint: &mut Tracked, _grace: Duration) -> bool {
            let log = log();
            log.drains.set(log.drains.get() + 1);
            log.drain_in_succeeds.get()
        }

        fn drain_bulk_out(_endpoint: &mut Tracked, _grace: Duration) -> bool {
            let log = log();
            log.drains.set(log.drains.get() + 1);
            log.drain_out_succeeds.get()
        }

        fn bus_reset(_device: &Tracked) -> Result<(), UsbError> {
            let log = log();
            log.resets.set(log.resets.get() + 1);
            if log.reset_fails.get() {
                // What Android and WinUSB answer — the two platforms where no bus reset
                // is available to `nusb`
                // (`windows_winusb/device.rs:170-175`).
                return Err(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device));
            }
            Ok(())
        }

        fn open(identity: &mut u32) -> Result<Tracked, UsbError> {
            let log = log();
            log.device_opens.set(log.device_opens.get() + 1);
            // Recorded rather than asserted, so the failure is reported by the pin that
            // cares rather than as a panic from inside a fixture.
            log.live_devices_at_open.set(log.devices.get());
            // Cloned out of the slot before it runs: the hook may touch the transport,
            // and holding this borrow across it would be the very bug it exists to find.
            let hook = log.during_open.borrow().clone();
            if let Some(hook) = hook {
                hook();
            }
            if log.reopen_fails.get() {
                return Err(UsbError::new(UsbErrorKind::NoDevice, Pipe::Device));
            }
            // The device came back, possibly somewhere else: the caller keeps this.
            *identity += 1;
            Ok(Tracked::new(&log.devices))
        }
    }

    fn open(endpoint: BulkEndpoint) -> Result<Tracked, UsbError> {
        let log = log();
        if let Some(kind) = log.refuse_endpoints.borrow().clone() {
            return Err(UsbError::new(kind, Pipe::Bulk(endpoint)).with_len(4));
        }
        Ok(Tracked::new(&log.endpoints))
    }

    /// Make every endpoint open fail with `kind`.
    fn refuse_with(log: &Log, kind: UsbErrorKind) {
        *log.refuse_endpoints.borrow_mut() = Some(kind);
    }

    fn claimed_slot(spec: InterfaceSpec) -> (Rc<Log>, ClaimSlot<Fixture>) {
        let log = fresh();
        let slot = ClaimSlot::<Fixture>::new();
        let interface = Tracked::new(&log.interfaces);
        assert!(slot.install(spec, interface).is_ok());
        (log, slot)
    }

    /// The identity a re-open starts from. Any value; what matters is telling it apart
    /// from what a re-open leaves behind.
    const IDENTITY: u32 = 7;

    /// An open device, an empty claim, and the identity to re-open from.
    fn open_device() -> (Rc<Log>, DeviceSlot<Fixture>, ClaimSlot<Fixture>, RefCell<u32>) {
        let log = fresh();
        let device = DeviceSlot::<Fixture>::new(Tracked::new(&log.devices));
        (log, device, ClaimSlot::<Fixture>::new(), RefCell::new(IDENTITY))
    }

    /// The failure kind of a result, or `None` if it succeeded. `expect_err` would be
    /// shorter and is denied crate-wide (`clippy::expect_used`).
    fn failure<T>(result: Result<T, UsbError>) -> Option<UsbErrorKind> {
        result.err().map(|error| error.kind().clone())
    }

    const BOOTROM: InterfaceSpec = InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT);

    /// An IN endpoint the bootrom claim does not declare.
    const OTHER_IN: BulkEndpoint = match BulkEndpoint::new(Direction::In, 2) {
        Some(endpoint) => endpoint,
        None => unreachable!(),
    };

    // ---- the idempotent-release pin ------------------------------------------------

    #[test]
    fn usb_release_is_idempotent() {
        let (log, slot) = claimed_slot(BOOTROM);

        assert_eq!(slot.claimed(), Some(0));
        assert!(slot.release(0).is_ok(), "the real release must succeed");
        assert_eq!(slot.claimed(), None);
        assert_eq!(log.releases.get(), 1);

        // The property: every later release is `Ok(())` and reaches no OS call. The
        // bootrom path releases on every exit path and must not
        // be punished for it.
        assert!(slot.release(0).is_ok(), "a second release must be Ok(())");
        assert!(slot.release(0).is_ok(), "and a third");
        assert_eq!(log.releases.get(), 1, "no further OS release was issued");

        // An interface that was never claimed at all is also `Ok(())`.
        let empty = ClaimSlot::<Fixture>::new();
        assert!(empty.release(0).is_ok());
        assert!(empty.release_any().is_ok());
    }

    #[test]
    fn releasing_a_different_interface_leaves_the_claim_alone() {
        let (log, slot) = claimed_slot(InterfaceSpec::control_only(3));

        assert!(slot.release(0).is_ok(), "interface 0 is not claimed");
        assert_eq!(slot.claimed(), Some(3), "interface 3 still is");
        assert_eq!(log.releases.get(), 0);
    }

    // ---- the reset-drops-the-claim pin ---------------------------------------------

    #[test]
    fn usb_reset_drops_the_claim() {
        let (log, slot) = claimed_slot(BOOTROM);
        assert_eq!(log.interfaces.get(), 1);
        assert_eq!(log.endpoints.get(), 2, "both bulk endpoints are open");

        // The assertion runs *inside* the reset, which is what makes this a test of the
        // ordering rather than of the end state: the bug this replaced left the
        // interface and both endpoint vectors alive **across** the reset, and an
        // end-state check after the call would pass for that code too.
        let checked = Cell::new(false);
        let outcome = slot.reset_with(|| {
            assert_eq!(log.endpoints.get(), 0, "an endpoint survived into the reset");
            assert_eq!(log.interfaces.get(), 0, "the interface survived the reset");
            assert_eq!(slot.claimed(), None, "the slot still holds a claim");
            checked.set(true);
            Ok(())
        });

        assert!(outcome.is_ok());
        assert!(checked.get(), "the reset body never ran");
        assert_eq!(log.releases.get(), 1, "the interface was released, not leaked");
    }

    #[test]
    fn reset_runs_even_when_the_release_fails() {
        // The device is being reset because something is wedged; a release that fails
        // on the way out must not swallow the recovery.
        //
        // Driven through a *claimed* slot with a failing release. The earlier form used
        // an empty slot, where `release_any` short-circuits on `None` before it can
        // fail — so it asserted nothing about a failing release, and would have passed
        // just as happily for a `reset_with` that propagated one.
        let (log, slot) = claimed_slot(BOOTROM);
        log.release_fails.set(true);

        let ran = Cell::new(false);
        let outcome = slot.reset_with(|| {
            assert_eq!(log.endpoints.get(), 0, "an endpoint survived into the reset");
            assert_eq!(slot.claimed(), None, "the slot still holds a claim");
            ran.set(true);
            Ok(())
        });

        assert_eq!(log.releases.get(), 1, "the release was attempted");
        assert!(ran.get(), "the reset body never ran");
        assert!(outcome.is_ok(), "the release failure masked the reset's own result");
    }

    // ---- the re-open seam ---------------------------------------------------------

    #[test]
    fn a_reset_re_opens_the_device_from_its_identity() {
        // The gap an audit found: an earlier `reset()` reset the bus and
        // carried on with the handle `nusb` had just declared dead
        // (`nusb-0.2.7/src/device.rs:287-290`).
        let (log, device, claim, identity) = open_device();

        assert!(device.reset_and_reopen(&claim, &identity).is_ok());

        assert_eq!(log.resets.get(), 1, "the bus reset never went out");
        assert_eq!(log.device_opens.get(), 1, "the device was not re-opened");
        assert_eq!(log.devices.get(), 1, "exactly one handle is live: the fresh one");
        assert!(device.handle().is_ok(), "and the slot hands it out");
        assert_eq!(
            identity.into_inner(),
            IDENTITY + 1,
            "the refreshed identity was thrown away"
        );
    }

    #[test]
    fn usb_reset_drops_the_dead_handle_before_re_opening() {
        // The ordering, not the end state: the count is taken *inside* the re-open, so
        // this fails both for a reset that keeps the handle it killed and for
        // one that opens the replacement first and drops the old one afterwards. An
        // end-state check would pass for both.
        //
        // It is a real requirement, not hygiene: `nusb`'s device "is closed when all
        // clones and all associated `Interface`s are dropped"
        // (`nusb-0.2.7/src/device.rs:45-47`), and on macOS the re-open goes through an
        // IOKit service that `USBDeviceReEnumerate` has already terminated.
        let (log, device, claim, identity) = open_device();
        assert_eq!(log.devices.get(), 1);

        assert!(device.reset_and_reopen(&claim, &identity).is_ok());

        assert_eq!(log.device_opens.get(), 1, "the re-open never ran, so it saw nothing");
        assert_eq!(
            log.live_devices_at_open.get(),
            0,
            "a handle the reset had already killed was still alive at the re-open"
        );
    }

    #[test]
    fn a_re_open_does_not_hold_the_slot_borrowed_while_it_blocks() {
        // The real re-open polls the bus for up to two seconds (`reopen::REOPEN_WINDOW`).
        // A `RefCell` borrow held across it makes every re-entrant `handle()` a panic
        // rather than an error — a progress sink that inspects the transport, a fault
        // fixture, anything a caller wires in — and a flashing tool does not abort on
        // one. The borrow must therefore end before `H::open` starts,
        // which is *also* what makes the drop-before-open ordering above true, so the
        // two requirements are the same requirement.
        let log = fresh();
        let device = Rc::new(DeviceSlot::<Fixture>::new(Tracked::new(&log.devices)));
        let claim = ClaimSlot::<Fixture>::new();
        let identity = RefCell::new(IDENTITY);

        let answered: Rc<Cell<Option<bool>>> = Rc::new(Cell::new(None));
        let watched = Rc::downgrade(&device);
        let recorded = Rc::clone(&answered);
        *log.during_open.borrow_mut() = Some(Rc::new(move || {
            if let Some(slot) = watched.upgrade() {
                // A held borrow panics here instead of answering.
                recorded.set(Some(slot.handle().is_ok()));
            }
        }));

        assert!(device.reset_and_reopen(&claim, &identity).is_ok());
        *log.during_open.borrow_mut() = None;

        assert_eq!(
            answered.get(),
            Some(false),
            "a call during the re-open must answer 'no device', not panic and not a stale handle"
        );
        assert!(device.handle().is_ok(), "and the fresh handle is in place afterwards");
    }

    #[test]
    fn a_re_opened_device_carries_no_claim() {
        // The other half: the reset drops the claim (`usb_reset_drops_the_claim`), and
        // the re-open must not put it back. A resurrected claim would hand a caller
        // endpoint handles opened against an interface the reset returned to the Default
        // state (USB 2.0 §9.1.1.5).
        let (log, device, claim, identity) = open_device();
        let interface = Tracked::new(&log.interfaces);
        assert!(claim.install(BOOTROM, interface).is_ok());
        assert_eq!(log.endpoints.get(), 2);

        assert!(device.reset_and_reopen(&claim, &identity).is_ok());

        assert_eq!(claim.claimed(), None, "the re-open resurrected the claim");
        assert_eq!(log.interfaces.get(), 0, "and its interface handle with it");
        assert_eq!(log.endpoints.get(), 0, "and its endpoints");
        assert_eq!(
            failure(claim.with_bulk_in(|_| ())),
            Some(UsbErrorKind::NotClaimed),
            "a transfer after a reset must ask for a claim of its own"
        );
    }

    #[test]
    fn a_bus_reset_that_fails_keeps_the_handle_and_re_opens_nothing() {
        // The reset did not happen, so nothing invalidated the handle. Discarding it
        // would turn a platform that merely refuses the request - Android, WinUSB - into
        // one that loses the device.
        let (log, device, claim, identity) = open_device();
        let interface = Tracked::new(&log.interfaces);
        assert!(claim.install(BOOTROM, interface).is_ok());
        log.reset_fails.set(true);

        assert_eq!(
            failure(device.reset_and_reopen(&claim, &identity)),
            Some(UsbErrorKind::Unsupported)
        );

        assert_eq!(log.device_opens.get(), 0, "nothing should have been re-opened");
        assert_eq!(log.devices.get(), 1, "the handle was thrown away anyway");
        assert!(device.handle().is_ok());
        assert_eq!(identity.into_inner(), IDENTITY, "the identity was touched");
        // **The claim is gone all the same.** The teardown runs before the reset can
        // fail — it has to, because macOS refuses a reset while an interface is claimed
        // — so a caller that sees this error is holding an unclaimed device. That is
        // what `reset_with`'s doc and the trait's now say, and it was true and
        // undocumented before.
        assert_eq!(claim.claimed(), None, "a failed reset left the claim in force");
        assert_eq!(log.interfaces.get(), 0, "and its interface handle alive");
        assert_eq!(log.endpoints.get(), 0);
    }

    #[test]
    fn a_re_open_that_fails_leaves_no_handle_rather_than_a_dead_one() {
        // The device did not come back. The honest state is "nothing is open", and every
        // call afterwards says so - the alternative is a handle that answers requests
        // the OS will fail in a way nobody can explain.
        let (log, device, claim, identity) = open_device();
        log.reopen_fails.set(true);

        assert_eq!(
            failure(device.reset_and_reopen(&claim, &identity)),
            Some(UsbErrorKind::NoDevice)
        );

        assert_eq!(log.devices.get(), 0, "the dead handle was kept");
        assert_eq!(
            failure(device.handle()),
            Some(UsbErrorKind::NoDevice),
            "and a transfer would have been issued on it"
        );
    }

    #[test]
    fn the_next_reset_starts_from_where_the_device_actually_is() {
        // `Handles::open` takes `&mut` for this: a device that re-enumerated somewhere
        // else is re-opened from where it is now, not chased forever from the address it
        // had before the first reset. The C rebuilds `device->info.bus/address` from the
        // device it found for the same reason (`libtdfu/src/usb/device.c:292-293`).
        let (log, device, claim, identity) = open_device();

        assert!(device.reset_and_reopen(&claim, &identity).is_ok());
        assert!(device.reset_and_reopen(&claim, &identity).is_ok());

        assert_eq!(log.device_opens.get(), 2);
        assert_eq!(log.devices.get(), 1, "one handle per reset, and only the last is live");
        assert_eq!(
            identity.into_inner(),
            IDENTITY + 2,
            "the second reset started from the stale identity"
        );
    }

    #[test]
    fn a_reset_with_nothing_open_is_an_error_and_not_a_second_reset() {
        // After a re-open that failed there is no handle to reset *with*. Trying anyway
        // would be a reset of whatever the OS now has at that address.
        let (log, device, claim, identity) = open_device();
        log.reopen_fails.set(true);
        assert!(device.reset_and_reopen(&claim, &identity).is_err());
        assert_eq!(log.resets.get(), 1);

        assert_eq!(
            failure(device.reset_and_reopen(&claim, &identity)),
            Some(UsbErrorKind::NoDevice)
        );

        assert_eq!(log.resets.get(), 1, "a second reset went out with no device open");
        assert_eq!(log.device_opens.get(), 1, "and a re-open with it");
    }

    #[test]
    fn a_release_a_straggler_defeated_says_so() -> Result<(), Box<dyn std::error::Error>> {
        // The OS says "interface is still in use", which
        // restates the symptom and names no cause. The drain already knows the cause,
        // and this is the only place that knowledge exists.
        let (log, slot) = claimed_slot(BOOTROM);
        log.drain_in_succeeds.set(false);
        log.drain_out_succeeds.set(false);
        log.release_fails.set(true);

        let Some(UsbErrorKind::Backend(message)) = failure(slot.release(0)) else {
            return Err("a straggler-defeated release must fail with prose".into());
        };
        assert!(
            message.contains("still outstanding after the"),
            "the drain's verdict is missing from {message:?}"
        );
        assert!(
            message.contains("interface is still in use"),
            "the OS's own text was thrown away: {message:?}"
        );
        Ok(())
    }

    #[test]
    fn a_release_that_fails_with_the_endpoints_clear_reports_only_the_os() -> Result<(), Box<dyn std::error::Error>> {
        // The other direction: with nothing outstanding we have no cause to add, so the
        // OS's answer passes through untouched and keeps whatever kind it had.
        let (log, slot) = claimed_slot(BOOTROM);
        log.release_fails.set(true);

        let Some(UsbErrorKind::Backend(message)) = failure(slot.release(0)) else {
            return Err("the release must still fail".into());
        };
        assert_eq!(message, "interface is still in use", "nothing was added");
        Ok(())
    }

    #[test]
    fn a_straggler_on_the_in_endpoint_alone_defeats_the_close() -> Result<(), Box<dyn std::error::Error>> {
        // `close_endpoints` accumulates with `&=`, so **either** direction failing is
        // enough: one outstanding transfer holds the interface no matter which endpoint
        // it is on. With one drain knob for both directions the two accumulators always
        // saw the same value, `&=` and `|=` agreed, and `cargo mutants` reported both as
        // surviving — read as equivalent mutants until the 2026-08-23 audit refuted
        // that reading. This is the IN half of the refutation.
        let (log, slot) = claimed_slot(BOOTROM);
        log.drain_in_succeeds.set(false);
        log.release_fails.set(true);

        let Some(UsbErrorKind::Backend(message)) = failure(slot.release(0)) else {
            return Err("a straggler-defeated release must fail with prose".into());
        };
        assert_eq!(log.drains.get(), 2, "the OUT endpoint was drained too");
        assert!(
            message.contains("still outstanding after the"),
            "an IN straggler alone did not defeat the close: {message:?}"
        );
        Ok(())
    }

    #[test]
    fn a_straggler_on_the_out_endpoint_alone_defeats_the_close() -> Result<(), Box<dyn std::error::Error>> {
        // The OUT half. Both are needed: a mutant on one accumulator is invisible to a
        // test where the other one already reports the same thing.
        let (log, slot) = claimed_slot(BOOTROM);
        log.drain_out_succeeds.set(false);
        log.release_fails.set(true);

        let Some(UsbErrorKind::Backend(message)) = failure(slot.release(0)) else {
            return Err("a straggler-defeated release must fail with prose".into());
        };
        assert_eq!(log.drains.get(), 2, "the IN endpoint was drained too");
        assert!(
            message.contains("still outstanding after the"),
            "an OUT straggler alone did not defeat the close: {message:?}"
        );
        Ok(())
    }

    #[test]
    fn clearing_a_halt_drains_the_endpoint_first() -> Result<(), Box<dyn std::error::Error>> {
        // `nusb-0.2.7/src/device.rs:898`: `clear_halt` "should not be called when
        // transfers are pending on the endpoint" — and the vendor `Stall` retry
        // arrives straight from a failed transfer, which is exactly when one may be.
        let (log, slot) = claimed_slot(BOOTROM);
        assert_eq!(log.drains.get(), 0);

        assert_eq!(slot.with_open_bulk_in(|_| ())?, Some(()), "the open endpoint was used");
        assert_eq!(log.drains.get(), 1, "the IN endpoint was drained first");

        assert_eq!(slot.with_open_bulk_out(|_| ())?, Some(()));
        assert_eq!(log.drains.get(), 2, "and so was the OUT endpoint");
        assert_eq!(log.endpoints.get(), 2, "neither was closed on the way through");
        Ok(())
    }

    #[test]
    fn a_halt_on_a_closed_endpoint_does_not_open_one() -> Result<(), Box<dyn std::error::Error>> {
        // A failed `SET_INTERFACE` leaves the claim in force with both endpoints shut
        // (`set_alt`'s own doc). `with_bulk_in` would open one purely to clear a halt
        // nothing is waiting on, and leave it open; `Ok(None)` says there was nothing
        // to do.
        let (log, slot) = claimed_slot(BOOTROM);
        log.set_alt_fails.set(true);
        assert_eq!(failure(slot.set_alt(0, 1)), Some(UsbErrorKind::Fault));
        assert_eq!(log.endpoints.get(), 0, "the endpoints are shut but the claim stands");
        assert_eq!(slot.claimed(), Some(0));

        let drains = log.drains.get();
        assert_eq!(slot.with_open_bulk_in(|_| ())?, None, "nothing was open to clear");
        assert_eq!(log.endpoints.get(), 0, "and nothing was opened to clear it");
        assert_eq!(log.drains.get(), drains, "nor drained");
        Ok(())
    }

    #[test]
    fn an_undeclared_endpoint_has_no_halt_to_clear() {
        let (_log, slot) = claimed_slot(InterfaceSpec::control_only(0));
        assert_eq!(
            failure(slot.with_open_bulk_in(|_| ())),
            Some(UsbErrorKind::NotClaimed),
            "a control-only claim has no bulk IN"
        );
        assert_eq!(failure(slot.with_open_bulk_out(|_| ())), Some(UsbErrorKind::NotClaimed));

        let empty = ClaimSlot::<Fixture>::new();
        assert_eq!(failure(empty.with_open_bulk_in(|_| ())), Some(UsbErrorKind::NotClaimed));
    }

    #[test]
    fn a_transfer_on_an_undeclared_endpoint_is_not_claimed() {
        // Claim time is the one place "this interface has no such
        // endpoint" is reachable, so a transfer against one the claim did not declare
        // is a caller bug - and an error, never a panic.
        let (_log, slot) = claimed_slot(InterfaceSpec::control_only(0));

        assert_eq!(
            failure(slot.with_bulk_in(|_| ())),
            Some(UsbErrorKind::NotClaimed),
            "a control-only claim has no bulk IN"
        );
        assert_eq!(
            failure(slot.with_bulk_out(|_| ())),
            Some(UsbErrorKind::NotClaimed),
            "nor a bulk OUT"
        );
    }

    #[test]
    fn a_transfer_with_no_claim_at_all_is_not_claimed() {
        let _log = fresh();
        let slot = ClaimSlot::<Fixture>::new();
        assert_eq!(
            failure(slot.with_bulk_in(|_| ())),
            Some(UsbErrorKind::NotClaimed),
            "nothing is claimed"
        );
    }

    #[test]
    fn set_alt_setting_reopens_the_declared_endpoints() {
        let (log, slot) = claimed_slot(BOOTROM);
        assert_eq!(log.endpoints.get(), 2);

        assert!(slot.set_alt(0, 1).is_ok());

        assert_eq!(log.alt_settings.take(), vec![1]);
        assert_eq!(
            log.endpoints.get(),
            2,
            "the endpoints were re-opened against the new alt"
        );
    }

    #[test]
    fn set_alt_setting_on_an_unclaimed_interface_is_not_claimed() {
        let (_log, slot) = claimed_slot(InterfaceSpec::control_only(0));
        assert_eq!(
            failure(slot.set_alt(1, 0)),
            Some(UsbErrorKind::NotClaimed),
            "interface 1 is not the claim"
        );
    }

    #[test]
    fn a_clean_close_drains_before_it_drops() {
        // The ordering an audit finding turned on: a transfer the OS has not
        // returned keeps the endpoint AND the interface alive whoever drops what, so
        // `set_alt` and `release` must reclaim it before they let go. Dropping first and
        // draining never was the bug.
        let (log, slot) = claimed_slot(BOOTROM);
        assert_eq!(log.drains.get(), 0);

        assert!(slot.set_alt(0, 1).is_ok());

        assert_eq!(log.drains.get(), 2, "both endpoints were drained");
    }

    #[test]
    fn a_release_drains_both_endpoints_first() {
        let (log, slot) = claimed_slot(BOOTROM);

        assert!(slot.release(0).is_ok());

        assert_eq!(log.drains.get(), 2, "both endpoints were drained");
        assert_eq!(log.releases.get(), 1, "and only then was the interface released");
        assert_eq!(log.endpoints.get(), 0);
    }

    #[test]
    fn a_claim_that_cannot_open_its_endpoints_leaves_nothing_behind() {
        let log = fresh();
        refuse_with(&log, UsbErrorKind::Fault);
        let slot = ClaimSlot::<Fixture>::new();
        let interface = Tracked::new(&log.interfaces);

        let outcome = slot.install(BOOTROM, interface);

        assert_eq!(failure(outcome), Some(UsbErrorKind::Fault), "the endpoint was refused");
        assert_eq!(slot.claimed(), None, "no half-claim was installed");
        assert_eq!(log.interfaces.get(), 0, "the interface handle was dropped");
        assert_eq!(log.endpoints.get(), 0);
    }

    #[test]
    fn the_interface_handle_is_lent_out_only_while_a_claim_is_in_force() {
        // This is what routes a control transfer: `Some` sends it down the claimed
        // interface, `None` down the device (the pre-claim `GET_CPU_INFO`).
        // A handle that went missing would silently reroute every DFU class request to
        // the device pipe, and `nusb` says of that pipe: "Not supported on Windows. You
        // must claim an interface and use the interface handle to submit transfers"
        // (`nusb-0.2.7/src/device.rs:324-325`, and the method is `cfg`'d off that target
        // entirely, `:326-333`). So the misroute is not a slow path on Windows — it does
        // not compile there, and on the platforms where it does it reaches a pipe the
        // gadget answers class requests on only before a claim exists.
        let slot = ClaimSlot::<Fixture>::new();
        assert!(slot.interface().is_none(), "nothing is claimed yet");

        let (_log, slot) = claimed_slot(InterfaceSpec::control_only(0));
        assert!(slot.interface().is_some(), "the claim lends its handle out");

        assert!(slot.release(0).is_ok());
        assert!(slot.interface().is_none(), "and takes it back on release");
    }

    #[test]
    fn declares_answers_by_address_not_by_direction() {
        let (_log, slot) = claimed_slot(BOOTROM);

        assert!(slot.declares(BOOTROM_IN));
        assert!(slot.declares(BOOTROM_OUT));
        assert!(!slot.declares(OTHER_IN), "0x82 is an IN endpoint, but not this claim's");
    }

    #[test]
    fn dropping_the_slot_drops_every_handle() {
        let log = fresh();
        {
            let slot = ClaimSlot::<Fixture>::new();
            let interface = Tracked::new(&log.interfaces);
            assert!(slot.install(BOOTROM, interface).is_ok());
            assert_eq!(log.endpoints.get(), 2);
        }
        assert_eq!(log.interfaces.get(), 0);
        assert_eq!(log.endpoints.get(), 0);
    }
}
