//! The installed library, its one client, and what outlives a single transport: handles
//! kept open between operations, closes deferred behind stuck control transfers, and the
//! watcher that retries an abandoned enumeration.

use core::ffi::c_void;
use core::fmt;
use core::ptr;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::Instant;

use esp_idf_sys as sys;

use super::device::describe;
use super::transport::EspTransport;
use super::{ClientHandle, DevHandle, OK, Raw, check, release_interface, spawn};
use crate::{DeviceDescriptors, Discovered, LocalUsbBackend, Pipe, UsbError};

/// How many device addresses one listing reads. There is one root port and no hub
/// support, so one is the most there can be.
const ADDRESS_SLOTS: usize = 16;
/// The ESP32-S3's host port control and status register (HPRT): the USB OTG controller is
/// at `0x6008_0000` (`esp32s3.peripherals.ld`) and HPRT at `0x440` in it (`usb_dwc_struct.h`).
const HPRT: usize = 0x6008_0440;
const HPRT_ATTACHED: u32 = 1 << 0;
const HPRT_POWERED: u32 = 1 << 12;
/// How long a device may sit attached to a powered port with nothing enumerated before its
/// enumeration counts as abandoned. A healthy one is listed within about a second.
const ABANDONED_AFTER: Duration = Duration::from_secs(2);
const LONGEST_RETRY: Duration = Duration::from_secs(60);
const WATCH_EVERY: Duration = Duration::from_millis(250);
const PORT_OFF_FOR: Duration = Duration::from_millis(500);

pub(super) struct Shared {
    client: OnceLock<Raw<ClientHandle>>,
    state: Mutex<HostState>,
    changed: Condvar,
}

#[derive(Default)]
pub(super) struct HostState {
    /// Handles the library reported gone that are not closed yet.
    pub(super) gone: Vec<Raw<DevHandle>>,
    /// Devices whose close waits for abandoned EP0 transfers: IDF asserts when a device is
    /// closed with a control transfer in flight, and such a transfer only completes once
    /// the device leaves the bus.
    deferred: Vec<Deferred>,
    /// The library refuses a second open from the same client, so `list` answers for the
    /// devices open right now from here.
    open: HashMap<u8, DeviceDescriptors>,
    /// Handles kept open between operations, by address, still holding their IDF claim.
    /// Reopening means a new claim, and a new claim means fresh pipes at `DATA0` while the
    /// device's endpoints keep counting, so a handle stays until its device leaves: Linux
    /// likewise keeps endpoint state per device rather than per open.
    parked: HashMap<u8, Handle>,
}

/// A device handle and what goes with it, between operations or inside a transport.
pub(super) struct Handle {
    pub(super) dev: Raw<DevHandle>,
    pub(super) address: u8,
    pub(super) descriptors: DeviceDescriptors,
    pub(super) mps0: usize,
    pub(super) configuration: u8,
    /// The interface claimed from IDF, which outlives any logical claim.
    pub(super) idf_claimed: Option<u8>,
    /// The device's count of abandoned EP0 transfers.
    pub(super) ep0_inflight: Arc<AtomicUsize>,
}

pub(super) struct Deferred {
    pub(super) dev: Raw<DevHandle>,
    pub(super) address: u8,
    pub(super) ep0_inflight: Arc<AtomicUsize>,
}

impl Shared {
    pub(super) fn client(&self) -> ClientHandle {
        // `install` sets it before a `UsbHost`, the only way here, exists. A null handle
        // would be refused by every library call rather than dereferenced.
        self.client.get().map_or(ptr::null_mut(), |client| client.0)
    }

    pub(super) fn state(&self) -> MutexGuard<'_, HostState> {
        // A task that panicked while holding the lock left the state as one step leaves
        // it, and the handles in it still need closing.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn is_gone(&self, dev: DevHandle) -> bool {
        self.state().gone.contains(&Raw(dev))
    }

    pub(super) fn wait_until(&self, timeout: Duration, mut done: impl FnMut(&HostState) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        loop {
            if done(&state) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    pub(super) fn opened(&self, address: u8, descriptors: DeviceDescriptors) {
        self.state().open.insert(address, descriptors);
    }

    pub(super) fn forget(&self, dev: DevHandle, address: u8) {
        let mut state = self.state();
        state.gone.retain(|&gone| gone != Raw(dev));
        state.open.remove(&address);
    }

    pub(super) fn park(&self, handle: Handle) {
        self.state().parked.insert(handle.address, handle);
    }

    pub(super) fn defer(&self, deferred: Deferred) {
        self.state().deferred.push(deferred);
    }

    /// Closes deferred devices whose abandoned transfers have all completed, and parked
    /// ones whose device has left.
    fn reap(&self) {
        let client = self.client();
        let mut state = self.state();
        let HostState {
            gone,
            deferred,
            open,
            parked,
        } = &mut *state;
        deferred.retain(|entry| {
            if entry.ep0_inflight.load(Ordering::SeqCst) > 0 {
                return true;
            }
            // SAFETY: the handle is open and nothing is in flight on it any more.
            unsafe { sys::usb_host_device_close(client, entry.dev.0) };
            gone.retain(|&handle| handle != entry.dev);
            open.remove(&entry.address);
            false
        });
        parked.retain(|&address, entry| {
            if !gone.contains(&entry.dev) {
                return true;
            }
            if let Some(interface) = entry.idf_claimed {
                release_interface(client, entry.dev.0, interface, &entry.descriptors.config_descriptor);
            }
            // SAFETY: a parked handle is open, has no transfer in flight, and no longer
            // holds an interface.
            unsafe { sys::usb_host_device_close(client, entry.dev.0) };
            gone.retain(|&handle| handle != entry.dev);
            open.remove(&address);
            false
        });
    }
}

/// Runs on the client task, for the one client this backend registers.
unsafe extern "C" fn client_event(msg: *const sys::usb_host_client_event_msg_t, arg: *mut c_void) {
    // SAFETY: `arg` is the `Arc<Shared>` reference `install` leaked for the client's
    // lifetime, and `msg` is valid for the duration of the callback.
    let (shared, msg) = unsafe { (&*arg.cast::<Shared>().cast_const(), &*msg) };
    let mut state = shared.state();
    match msg.event {
        sys::usb_host_client_event_t_USB_HOST_CLIENT_EVENT_NEW_DEV => {
            // SAFETY: a NEW_DEV message carries the `new_dev` member.
            let address = unsafe { msg.__bindgen_anon_1.new_dev.address };
            tracing::info!("usb: new device at address {address}");
        }
        sys::usb_host_client_event_t_USB_HOST_CLIENT_EVENT_DEV_GONE => {
            tracing::info!("usb: an open device is gone");
            // SAFETY: a DEV_GONE message carries the `dev_gone` member.
            state.gone.push(Raw(unsafe { msg.__bindgen_anon_1.dev_gone.dev_hdl }));
        }
        _ => {}
    }
    shared.changed.notify_all();
}

/// The installed ESP-IDF USB Host Library, with this program's one client: the
/// [`LocalUsbBackend`] for the OTG port.
pub struct UsbHost {
    shared: Arc<Shared>,
}

impl fmt::Debug for UsbHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsbHost").finish_non_exhaustive()
    }
}

impl UsbHost {
    /// Installs the library on the internal PHY, registers the client, and starts the
    /// tasks that run the library's events and retry abandoned enumerations. Call once.
    ///
    /// # Errors
    /// A library refusal (a second install, most likely), or a task that could not be
    /// spawned.
    pub fn install() -> Result<Self, UsbError> {
        // SAFETY: all-zero is the library's documented default configuration.
        let mut config: sys::usb_host_config_t = unsafe { core::mem::zeroed() };
        config.intr_flags = i32::try_from(sys::ESP_INTR_FLAG_LEVEL1).unwrap_or_default();
        // SAFETY: `config` outlives the call, which copies it.
        check(
            unsafe { sys::usb_host_install(&raw const config) },
            Pipe::Device,
            "usb_host_install",
        )?;
        spawn("usb-lib", || {
            loop {
                let mut flags = 0;
                // SAFETY: the library is installed and never uninstalled.
                unsafe { sys::usb_host_lib_handle_events(u32::MAX, &raw mut flags) };
            }
        })?;

        let shared = Arc::new(Shared {
            client: OnceLock::new(),
            state: Mutex::default(),
            changed: Condvar::new(),
        });
        // SAFETY: all-zero is a valid starting point; every field used is set below.
        let mut client_config: sys::usb_host_client_config_t = unsafe { core::mem::zeroed() };
        client_config.max_num_event_msg = 8;
        // The `async_` member is the one an event-driven client fills in.
        client_config.__bindgen_anon_1.async_.client_event_callback = Some(client_event);
        // The client is never deregistered, so this reference is never released.
        client_config.__bindgen_anon_1.async_.callback_arg = Arc::into_raw(Arc::clone(&shared)).cast_mut().cast();
        let mut client = ptr::null_mut();
        // SAFETY: both pointers outlive the call, which copies the configuration.
        let got = unsafe { sys::usb_host_client_register(&raw const client_config, &raw mut client) };
        check(got, Pipe::Device, "usb_host_client_register")?;
        let client = Raw(client);
        let _ = shared.client.set(client);
        spawn("usb-client", move || {
            let client = client;
            loop {
                // SAFETY: the client is registered and never deregistered.
                unsafe { sys::usb_host_client_handle_events(client.0, u32::MAX) };
            }
        })?;
        if is_esp32s3() {
            spawn("usb-watch", retry_abandoned_enumerations)?;
        } else {
            tracing::warn!("usb: not an ESP32-S3, so abandoned enumerations are not retried");
        }
        Ok(Self { shared })
    }
}

/// The watcher reads a register at the ESP32-S3's address, the one chip it has run on.
fn is_esp32s3() -> bool {
    sys::CONFIG_IDF_TARGET.as_slice() == b"esp32s3\0"
}

/// When an enumeration stage fails (`CHECK_ADDR`, or `CHECK_SHORT_DEV_DESC` while a camera
/// powers up), IDF gives the device up: it stays attached and the port stays enabled,
/// because the failed device's pipes make the library's own port disable fail, but nothing
/// is listed and nothing looks at the port again until the device is unplugged. A device
/// attached to a powered port with nothing enumerated is power-cycled, which enumerates it
/// afresh.
fn retry_abandoned_enumerations() {
    let hprt = ptr::with_exposed_provenance::<u32>(HPRT);
    let mut since: Option<Instant> = None;
    let mut wait = ABANDONED_AFTER;
    loop {
        thread::sleep(WATCH_EVERY);
        // SAFETY: HPRT is a status register of the S3's USB controller, which the library
        // has clocked since `install`; reading it has no side effects.
        let port = unsafe { ptr::read_volatile(hprt) };
        let listed = !addresses().is_empty();
        if listed {
            wait = ABANDONED_AFTER;
        }
        if listed || port & (HPRT_ATTACHED | HPRT_POWERED) != HPRT_ATTACHED | HPRT_POWERED {
            since = None;
            continue;
        }
        if since.get_or_insert_with(Instant::now).elapsed() < wait {
            continue;
        }
        tracing::warn!("usb: a device is attached but was never enumerated; power-cycling the port");
        // SAFETY: the library is installed; the pair returns the port to the state it was in.
        unsafe { sys::usb_host_lib_set_root_port_power(false) };
        thread::sleep(PORT_OFF_FOR);
        // SAFETY: as above.
        unsafe { sys::usb_host_lib_set_root_port_power(true) };
        since = None;
        wait = (wait * 2).min(LONGEST_RETRY);
    }
}

/// The addresses of the devices that finished enumerating.
pub(super) fn addresses() -> Vec<u8> {
    let mut addresses = [0_u8; ADDRESS_SLOTS];
    let mut count = 0;
    let slots = i32::try_from(ADDRESS_SLOTS).unwrap_or(i32::MAX);
    // SAFETY: the buffer holds `slots` addresses and both outlive the call.
    let got = unsafe { sys::usb_host_device_addr_list_fill(slots, addresses.as_mut_ptr(), &raw mut count) };
    if got != OK {
        return Vec::new();
    }
    addresses[..usize::try_from(count).unwrap_or(0).min(ADDRESS_SLOTS)].to_vec()
}

impl LocalUsbBackend for UsbHost {
    type Transport = EspTransport;
    type DeviceId = u8;

    async fn list(&self) -> Result<Vec<Discovered<u8>>, UsbError> {
        self.shared.reap();
        let client = self.shared.client();
        let mut found = Vec::new();
        for address in addresses() {
            let cached = self.shared.state().open.get(&address).cloned();
            if let Some(descriptors) = cached {
                found.push(Discovered {
                    id: address,
                    descriptors,
                });
                continue;
            }
            let mut dev = ptr::null_mut();
            // A device that left between the listing and the open is not a listing error.
            // SAFETY: `dev` outlives the call.
            if unsafe { sys::usb_host_device_open(client, address, &raw mut dev) } != OK {
                continue;
            }
            let described = describe(dev, address);
            // SAFETY: `dev` was opened just above and nothing was submitted on it.
            unsafe { sys::usb_host_device_close(client, dev) };
            if let Ok(described) = described {
                found.push(Discovered {
                    id: address,
                    descriptors: described.descriptors,
                });
            }
        }
        Ok(found)
    }

    async fn open(&self, id: &u8) -> Result<EspTransport, UsbError> {
        self.shared.reap();
        let parked = self.shared.state().parked.remove(id);
        if let Some(parked) = parked {
            return Ok(EspTransport::new(Arc::clone(&self.shared), parked));
        }
        let client = self.shared.client();
        let mut dev = ptr::null_mut();
        // SAFETY: `dev` outlives the call.
        let got = unsafe { sys::usb_host_device_open(client, *id, &raw mut dev) };
        check(got, Pipe::Device, "usb_host_device_open")?;
        let described = match describe(dev, *id) {
            Ok(described) => described,
            Err(err) => {
                // SAFETY: `dev` was opened just above and nothing was submitted on it.
                unsafe { sys::usb_host_device_close(client, dev) };
                return Err(err);
            }
        };
        self.shared.opened(*id, described.descriptors.clone());
        Ok(EspTransport::new(
            Arc::clone(&self.shared),
            Handle {
                dev: Raw(dev),
                address: *id,
                descriptors: described.descriptors,
                mps0: described.mps0,
                configuration: described.configuration,
                idf_claimed: None,
                ep0_inflight: Arc::new(AtomicUsize::new(0)),
            },
        ))
    }
}
