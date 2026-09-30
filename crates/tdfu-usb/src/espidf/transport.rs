//! One open device, driven through the library's transfers with deadlines of our own.

use core::cell::{Cell, RefCell};
use core::fmt;
use core::future::poll_fn;
use core::ptr;
use core::task::Poll;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use esp_idf_sys as sys;

use super::device::describe;
use super::host::{Deferred, Handle, Shared, addresses};
use super::transfer::Transfer;
use super::{
    DevHandle, ERR_INVALID_STATE, OK, REQUEST_TIMEOUT, Raw, cancel_endpoint, check, err_name, release_interface,
    status_error,
};
use crate::descriptors::{endpoint_mps, request_type};
use crate::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, InterfaceSpec, LocalUsbTransport,
    Pipe, Recipient, UsbError, UsbErrorKind,
};

const SETUP_LEN: usize = 8;
/// The largest single transfer buffer. It is DMA memory, which the S3 has little of, and a
/// multiple of every bulk max packet size so that splitting never inserts a short packet.
/// A streamed image arrives through the daemon 4 KiB at a time, so a bigger buffer would
/// sit mostly empty.
const CHUNK: usize = 4 * 1024;
const DEVICE_GONE_TIMEOUT: Duration = Duration::from_secs(2);
const REENUMERATE_TIMEOUT: Duration = Duration::from_secs(10);

/// `SET_INTERFACE`.
const SET_INTERFACE: u8 = 0x0b;
/// `CLEAR_FEATURE`, with `ENDPOINT_HALT` (0) as its value.
const CLEAR_FEATURE: u8 = 0x01;

#[derive(Clone, Copy)]
struct Claim {
    interface: u8,
    bulk_in: Option<(BulkEndpoint, usize)>,
    bulk_out: Option<(BulkEndpoint, usize)>,
}

impl Claim {
    fn endpoints(self) -> impl Iterator<Item = BulkEndpoint> {
        [self.bulk_in, self.bulk_out]
            .into_iter()
            .flatten()
            .map(|(endpoint, _)| endpoint)
    }
}

/// A setup packet, less its length.
#[derive(Clone, Copy)]
struct Setup {
    direction: Direction,
    control_type: ControlType,
    recipient: Recipient,
    request: u8,
    value: u16,
    index: u16,
}

/// One device opened through [`UsbHost`](super::UsbHost). Dropping it keeps the device
/// open, with its interface claim, until the device leaves: see the module docs.
pub struct EspTransport {
    shared: Arc<Shared>,
    dev: Cell<Raw<DevHandle>>,
    address: Cell<u8>,
    descriptors: DeviceDescriptors,
    mps0: usize,
    configuration: u8,
    claim: RefCell<Option<Claim>>,
    /// The interface claimed from IDF, which outlives the logical `claim`: see
    /// `claim_interface`.
    idf_claimed: Cell<Option<u8>>,
    /// Replaced on `reset`, so a deferred old handle keeps its own count.
    ep0_inflight: RefCell<Arc<AtomicUsize>>,
    /// The bulk transfer, allocated at the first bulk call and kept until `close`. Its
    /// buffer is a [`CHUNK`] of DMA memory in one block: allocated once per opening, a
    /// heap too fragmented for another block that size cannot fail an image halfway.
    bulk: RefCell<Option<Transfer>>,
}

impl fmt::Debug for EspTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspTransport")
            .field("address", &self.address.get())
            .field("descriptors", &self.descriptors)
            .finish_non_exhaustive()
    }
}

impl EspTransport {
    pub(super) fn new(shared: Arc<Shared>, handle: Handle) -> Self {
        Self {
            shared,
            dev: Cell::new(handle.dev),
            address: Cell::new(handle.address),
            descriptors: handle.descriptors,
            mps0: handle.mps0,
            configuration: handle.configuration,
            claim: RefCell::new(None),
            idf_claimed: Cell::new(handle.idf_claimed),
            ep0_inflight: RefCell::new(handle.ep0_inflight),
            bulk: RefCell::new(None),
        }
    }

    fn dev(&self) -> DevHandle {
        self.dev.get().0
    }

    fn control(&self, setup: Setup, out: &[u8], in_len: u16, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let pipe = Pipe::Control {
            direction: setup.direction,
            request: setup.request,
        };
        if self.shared.is_gone(self.dev()) {
            return Err(UsbError::new(UsbErrorKind::NoDevice, pipe));
        }
        // IDF wants an IN data stage rounded up to the packet size, and an OUT one exact.
        let (w_length, data_len) = match setup.direction {
            Direction::In => (in_len, usize::from(in_len).div_ceil(self.mps0) * self.mps0),
            Direction::Out => (
                u16::try_from(out.len()).map_err(|_| UsbError::new(UsbErrorKind::Fault, pipe).with_len(out.len()))?,
                out.len(),
            ),
        };
        let inflight = Arc::clone(&self.ep0_inflight.borrow());
        let mut transfer = Transfer::alloc(SETUP_LEN + data_len, pipe, Some(inflight))?;
        let buffer = transfer.buffer();
        buffer[0] = request_type(setup.direction, setup.control_type, setup.recipient);
        buffer[1] = setup.request;
        buffer[2..4].copy_from_slice(&setup.value.to_le_bytes());
        buffer[4..6].copy_from_slice(&setup.index.to_le_bytes());
        buffer[6..8].copy_from_slice(&w_length.to_le_bytes());
        if setup.direction == Direction::Out {
            buffer[SETUP_LEN..SETUP_LEN + out.len()].copy_from_slice(out);
        }
        transfer.prepare(self.dev(), 0, SETUP_LEN + data_len, pipe)?;
        let client = self.shared.client();
        transfer.submit_and_wait(
            // SAFETY: the transfer is prepared, owned, and not in flight; the library takes
            // it until the completion callback runs.
            |raw| unsafe { sys::usb_host_transfer_submit_control(client, raw) },
            timeout,
            pipe,
        )?;
        status_error(transfer.status(), pipe)?;
        // `actual_num_bytes` counts the setup packet.
        let got = transfer.actual().saturating_sub(SETUP_LEN);
        match setup.direction {
            Direction::In => {
                let got = got.min(usize::from(in_len));
                Ok(transfer.buffer()[SETUP_LEN..SETUP_LEN + got].to_vec())
            }
            Direction::Out if got < out.len() => Err(UsbError::new(UsbErrorKind::Short { got, want: out.len() }, pipe)),
            Direction::Out => Ok(Vec::new()),
        }
    }

    fn cancel(&self, endpoint: BulkEndpoint) {
        cancel_endpoint(self.dev(), endpoint.address());
    }

    /// The kept bulk transfer, or the first one.
    fn take_bulk(&self, pipe: Pipe) -> Result<Transfer, UsbError> {
        match self.bulk.borrow_mut().take() {
            Some(transfer) => Ok(transfer),
            None => Transfer::alloc(CHUNK, pipe, None),
        }
    }

    /// Keeps `transfer` for the next bulk call, unless it was abandoned in flight.
    fn keep_bulk(&self, transfer: Transfer) {
        if transfer.owned() {
            *self.bulk.borrow_mut() = Some(transfer);
        }
    }

    async fn bulk_out_with(
        &self,
        transfer: &mut Transfer,
        endpoint: BulkEndpoint,
        data: &[u8],
        timeout: Duration,
    ) -> Result<usize, UsbError> {
        let pipe = Pipe::Bulk(endpoint);
        let mut sent = 0;
        for chunk in data.chunks(CHUNK) {
            yield_now().await;
            transfer.buffer()[..chunk.len()].copy_from_slice(chunk);
            transfer.prepare(self.dev(), endpoint.address(), chunk.len(), pipe)?;
            // SAFETY: the transfer is prepared, owned, and not in flight; the library takes
            // it until the completion callback runs.
            let submitted =
                transfer.submit_and_wait(|raw| unsafe { sys::usb_host_transfer_submit(raw) }, timeout, pipe);
            if let Err(err) = submitted {
                self.cancel(endpoint);
                // Progress already made is reported as such, so the retry resumes after it.
                return Err(if sent > 0 {
                    UsbError::new(
                        UsbErrorKind::Short {
                            got: sent,
                            want: data.len(),
                        },
                        pipe,
                    )
                } else {
                    err
                });
            }
            status_error(transfer.status(), pipe).map_err(|err| err.with_transferred(sent))?;
            sent += transfer.actual();
            if transfer.actual() < chunk.len() {
                return Err(UsbError::new(
                    UsbErrorKind::Short {
                        got: sent,
                        want: data.len(),
                    },
                    pipe,
                ));
            }
        }
        Ok(sent)
    }

    async fn bulk_in_with(
        &self,
        transfer: &mut Transfer,
        (endpoint, mps): (BulkEndpoint, usize),
        len: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, UsbError> {
        let pipe = Pipe::Bulk(endpoint);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            yield_now().await;
            let want = (len - out.len()).min(CHUNK);
            // At most CHUNK, which is a multiple of every bulk max packet size.
            let request = want.div_ceil(mps) * mps;
            transfer.prepare(self.dev(), endpoint.address(), request, pipe)?;
            // SAFETY: as in `bulk_out_with`.
            let submitted =
                transfer.submit_and_wait(|raw| unsafe { sys::usb_host_transfer_submit(raw) }, timeout, pipe);
            if let Err(err) = submitted {
                self.cancel(endpoint);
                return Err(err);
            }
            status_error(transfer.status(), pipe)?;
            let got = transfer.actual().min(want);
            out.extend_from_slice(&transfer.buffer()[..got]);
            if got < want {
                break;
            }
        }
        if out.len() < len {
            return Err(UsbError::new(
                UsbErrorKind::Short {
                    got: out.len(),
                    want: len,
                },
                pipe,
            ));
        }
        Ok(out)
    }

    fn claim_idf(&self, interface: u8) -> Result<(), UsbError> {
        // SAFETY: the handle is open for this client.
        let err = unsafe { sys::usb_host_interface_claim(self.shared.client(), self.dev(), interface, 0) };
        if err == ERR_INVALID_STATE {
            return Err(UsbError::new(UsbErrorKind::Busy, Pipe::Device));
        }
        check(err, Pipe::Device, "usb_host_interface_claim")?;
        self.idf_claimed.set(Some(interface));
        Ok(())
    }

    fn release_idf(&self) {
        if let Some(interface) = self.idf_claimed.take() {
            release_interface(
                self.shared.client(),
                self.dev(),
                interface,
                &self.descriptors.config_descriptor,
            );
        }
    }

    fn claimed(&self) -> Option<Claim> {
        *self.claim.borrow()
    }

    fn not_claimed(pipe: Pipe) -> UsbError {
        UsbError::new(UsbErrorKind::NotClaimed, pipe)
    }

    /// Parks the handle for the next open while the device is here and nothing is stuck on
    /// it; otherwise closes it, now or once its abandoned control transfers complete.
    fn close(&self) {
        let dev = self.dev();
        let ep0_inflight = Arc::clone(&self.ep0_inflight.borrow());
        self.claim.borrow_mut().take();
        self.bulk.borrow_mut().take();
        if ep0_inflight.load(Ordering::SeqCst) == 0 && !self.shared.is_gone(dev) {
            self.shared.park(Handle {
                dev: Raw(dev),
                address: self.address.get(),
                descriptors: self.descriptors.clone(),
                mps0: self.mps0,
                configuration: self.configuration,
                idf_claimed: self.idf_claimed.take(),
                ep0_inflight,
            });
            return;
        }
        self.release_idf();
        if ep0_inflight.load(Ordering::SeqCst) > 0 {
            tracing::warn!(
                "address {}: a control transfer is still in flight; closing once it completes",
                self.address.get()
            );
            self.shared.defer(Deferred {
                dev: Raw(dev),
                address: self.address.get(),
                ep0_inflight,
                since: Instant::now(),
            });
            return;
        }
        // SAFETY: the handle is open, holds no interface, and has nothing in flight.
        let err = unsafe { sys::usb_host_device_close(self.shared.client(), dev) };
        self.shared.forget(dev, self.address.get());
        if err != OK {
            tracing::warn!("closing address {}: {}", self.address.get(), err_name(err));
        }
    }

    /// Opens the first device matching `want` that the library lists, until `deadline`.
    fn reopen(&self, want: (u16, u16), deadline: Instant) -> Result<(), UsbError> {
        let client = self.shared.client();
        loop {
            for address in addresses() {
                let mut dev = ptr::null_mut();
                // SAFETY: `dev` outlives the call.
                if unsafe { sys::usb_host_device_open(client, address, &raw mut dev) } != OK {
                    continue;
                }
                match describe(dev, address) {
                    Ok(described) if (described.descriptors.vendor_id, described.descriptors.product_id) == want => {
                        self.shared.opened(address, described.descriptors);
                        self.dev.set(Raw(dev));
                        self.address.set(address);
                        return Ok(());
                    }
                    // SAFETY: `dev` was opened just above and nothing was submitted on it.
                    _ => unsafe {
                        sys::usb_host_device_close(client, dev);
                    },
                }
            }
            if Instant::now() >= deadline {
                return Err(UsbError::new(UsbErrorKind::NoDevice, Pipe::Device));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for EspTransport {
    fn drop(&mut self) {
        self.close();
    }
}

/// Let the executor run once. A transfer here blocks the calling thread until the device
/// answers, so without this an operation's whole transfer loop would run inside a single
/// poll, and whatever drives it (the daemon's progress pump) could send nothing until the
/// loop ended, while every progress event piled up in its queue.
async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

impl LocalUsbTransport for EspTransport {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let setup = Setup {
            direction: Direction::In,
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
        };
        let answer = self.control(setup, &[], req.len, timeout);
        yield_now().await;
        answer
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        let setup = Setup {
            direction: Direction::Out,
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
        };
        let answer = self.control(setup, req.data, 0, timeout);
        yield_now().await;
        answer.map(drop)
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        let Some((endpoint, _)) = self.claimed().and_then(|claim| claim.bulk_out) else {
            return Err(Self::not_claimed(Pipe::Device));
        };
        let mut transfer = self.take_bulk(Pipe::Bulk(endpoint))?;
        let sent = self.bulk_out_with(&mut transfer, endpoint, data, timeout).await;
        self.keep_bulk(transfer);
        sent
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let Some((endpoint, mps)) = self.claimed().and_then(|claim| claim.bulk_in) else {
            return Err(Self::not_claimed(Pipe::Device));
        };
        let mut transfer = self.take_bulk(Pipe::Bulk(endpoint))?;
        let got = self.bulk_in_with(&mut transfer, (endpoint, mps), len, timeout).await;
        self.keep_bulk(transfer);
        got
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        // The library configures every device while enumerating it.
        if value == self.configuration {
            Ok(())
        } else {
            Err(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device))
        }
    }

    fn active_configuration(&self) -> Option<u8> {
        Some(self.configuration).filter(|&value| value != 0)
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        let locate = |endpoint: Option<BulkEndpoint>| -> Result<Option<(BulkEndpoint, usize)>, UsbError> {
            endpoint
                .map(|endpoint| {
                    endpoint_mps(&self.descriptors.config_descriptor, spec.interface, endpoint.address())
                        .map(|mps| (endpoint, mps))
                        .ok_or_else(|| UsbError::new(UsbErrorKind::Fault, Pipe::Bulk(endpoint)))
                })
                .transpose()
        };
        let claim = Claim {
            interface: spec.interface,
            bulk_in: locate(spec.bulk_in)?,
            bulk_out: locate(spec.bulk_out)?,
        };
        // An IDF claim allocates fresh pipes whose data toggles start at DATA0, while the
        // device's endpoints keep theirs; only SET_CONFIGURATION, SET_INTERFACE or a cleared
        // halt resets them. thingino-dfu claims and releases around every operation, which
        // on Linux leaves the toggles alone. Mapped literally onto IDF, the bootrom drops the
        // first packet after every re-claim as a retransmission. So the IDF claim is taken
        // once and kept, `release_interface` only ends the logical claim, and closing parks
        // the handle with its claim until the device leaves.
        if self.idf_claimed.get() != Some(spec.interface) {
            self.release_idf();
            self.claim_idf(spec.interface)?;
        }
        *self.claim.borrow_mut() = Some(claim);
        Ok(())
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        if self.claimed().is_some_and(|claim| claim.interface == interface) {
            *self.claim.borrow_mut() = None;
        }
        Ok(())
    }

    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        if self.claimed().is_none_or(|claim| claim.interface != interface) {
            return Err(Self::not_claimed(Pipe::Device));
        }
        // The claim stays on alt 0's endpoints: DFU alts declare none.
        let setup = Setup {
            direction: Direction::Out,
            control_type: ControlType::Standard,
            recipient: Recipient::Interface,
            request: SET_INTERFACE,
            value: u16::from(alt),
            index: u16::from(interface),
        };
        self.control(setup, &[], 0, REQUEST_TIMEOUT).map(drop)
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        let Some(claim) = self
            .claimed()
            .filter(|claim| claim.endpoints().any(|declared| declared == endpoint))
        else {
            return Err(Self::not_claimed(Pipe::Bulk(endpoint)));
        };
        // CLEAR_FEATURE(ENDPOINT_HALT) puts the device's toggle back to DATA0, and IDF can
        // only do the same for the host by re-claiming, which resets every endpoint of the
        // interface. So every endpoint is cleared on both sides, keeping the pairs in step.
        claim.endpoints().for_each(|declared| self.cancel(declared));
        for declared in claim.endpoints() {
            let setup = Setup {
                direction: Direction::Out,
                control_type: ControlType::Standard,
                recipient: Recipient::Endpoint,
                request: CLEAR_FEATURE,
                value: 0,
                index: u16::from(declared.address()),
            };
            self.control(setup, &[], 0, REQUEST_TIMEOUT)?;
        }
        self.release_idf();
        self.claim_idf(claim.interface)
    }

    async fn reset(&self) -> Result<(), UsbError> {
        let client = self.shared.client();
        let old = self.dev();
        self.claim.borrow_mut().take();
        self.release_idf();
        // No device-reset call exists in IDF 5.5. Powering the root port off and on bus-resets
        // and re-enumerates the device without cutting VBUS, and it is also the only thing
        // that completes an EP0 transfer the device stopped answering. The handle is closed
        // only once the library reports it gone: before that, such a transfer blocks the close.
        // SAFETY: the library is installed.
        check(
            unsafe { sys::usb_host_lib_set_root_port_power(false) },
            Pipe::Device,
            "root port off",
        )?;
        self.shared
            .wait_until(DEVICE_GONE_TIMEOUT, |state| state.gone.contains(&Raw(old)));
        let ep0_inflight = self.ep0_inflight.replace(Arc::new(AtomicUsize::new(0)));
        let drained = Instant::now() + DEVICE_GONE_TIMEOUT;
        while ep0_inflight.load(Ordering::SeqCst) > 0 && Instant::now() < drained {
            thread::sleep(Duration::from_millis(10));
        }
        if ep0_inflight.load(Ordering::SeqCst) == 0 {
            // SAFETY: the old handle holds no interface and has nothing in flight.
            unsafe { sys::usb_host_device_close(client, old) };
            self.shared.forget(old, self.address.get());
        } else {
            self.shared.defer(Deferred {
                dev: Raw(old),
                address: self.address.get(),
                ep0_inflight,
                since: Instant::now(),
            });
        }
        // SAFETY: the library is installed.
        check(
            unsafe { sys::usb_host_lib_set_root_port_power(true) },
            Pipe::Device,
            "root port on",
        )?;
        let want = (self.descriptors.vendor_id, self.descriptors.product_id);
        self.reopen(want, Instant::now() + REENUMERATE_TIMEOUT)
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        &self.descriptors
    }
}
