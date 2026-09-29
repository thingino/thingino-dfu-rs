//! One library transfer, and the handshake with its completion callback that lets a
//! waiter give up on it without freeing memory the library still owns.

use core::ffi::c_void;
use core::ptr;
use core::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use esp_idf_sys as sys;

use super::{DevHandle, OK, check};
use crate::{Pipe, UsbError, UsbErrorKind};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Waiting,
    Done,
    Abandoned,
}

struct Completion {
    slot: Mutex<Slot>,
    done: Condvar,
    /// The device's count of abandoned EP0 transfers, for control transfers only.
    ep0_inflight: Option<Arc<AtomicUsize>>,
}

impl Completion {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs on the client task. An in-flight transfer owns one reference to its completion.
unsafe extern "C" fn transfer_done(transfer: *mut sys::usb_transfer_t) {
    // SAFETY: `submit_and_wait` put an `Arc<Completion>` into `context` with
    // `Arc::into_raw` before submitting, and the library calls this exactly once per
    // submission, so this takes back that one reference.
    let completion = unsafe { Arc::from_raw((*transfer).context.cast::<Completion>().cast_const()) };
    let mut slot = completion.slot();
    if *slot == Slot::Abandoned {
        // SAFETY: the waiter gave the transfer up, so nothing else refers to it now.
        unsafe { sys::usb_host_transfer_free(transfer) };
        if let Some(count) = &completion.ep0_inflight {
            count.fetch_sub(1, Ordering::SeqCst);
        }
    } else {
        *slot = Slot::Done;
        completion.done.notify_all();
    }
}

pub(super) struct Transfer {
    raw: *mut sys::usb_transfer_t,
    completion: Arc<Completion>,
    /// Cleared when the transfer is abandoned; its callback frees it from then on.
    owned: bool,
}

impl Transfer {
    pub(super) fn alloc(len: usize, pipe: Pipe, ep0_inflight: Option<Arc<AtomicUsize>>) -> Result<Self, UsbError> {
        let mut raw = ptr::null_mut();
        // SAFETY: `raw` outlives the call, which sets it to a transfer this struct now owns.
        let got = unsafe { sys::usb_host_transfer_alloc(len, 0, &raw mut raw) };
        check(got, pipe, "usb_host_transfer_alloc")?;
        Ok(Self {
            raw,
            completion: Arc::new(Completion {
                slot: Mutex::new(Slot::Waiting),
                done: Condvar::new(),
                ep0_inflight,
            }),
            owned: true,
        })
    }

    pub(super) fn buffer(&mut self) -> &mut [u8] {
        // SAFETY: the transfer is owned and not in flight, and its buffer is
        // `data_buffer_size` bytes long.
        unsafe { core::slice::from_raw_parts_mut((*self.raw).data_buffer, (*self.raw).data_buffer_size) }
    }

    pub(super) fn prepare(&mut self, dev: DevHandle, endpoint: u8, len: usize, pipe: Pipe) -> Result<(), UsbError> {
        let num_bytes = i32::try_from(len).map_err(|_| UsbError::new(UsbErrorKind::Fault, pipe).with_len(len))?;
        // SAFETY: the transfer is owned and not in flight, so its fields are ours to set.
        unsafe {
            (*self.raw).device_handle = dev;
            (*self.raw).bEndpointAddress = endpoint;
            (*self.raw).num_bytes = num_bytes;
            (*self.raw).callback = Some(transfer_done);
        }
        Ok(())
    }

    /// `Ok` once the transfer completed, whatever its status; `Timeout` once abandoned.
    pub(super) fn submit_and_wait(
        &mut self,
        submit: impl FnOnce(*mut sys::usb_transfer_t) -> sys::esp_err_t,
        timeout: Duration,
        pipe: Pipe,
    ) -> Result<(), UsbError> {
        let context = Arc::into_raw(Arc::clone(&self.completion));
        // SAFETY: the transfer is owned and not yet in flight.
        unsafe { (*self.raw).context = context.cast_mut().cast::<c_void>() };
        let err = submit(self.raw);
        if err != OK {
            // SAFETY: the library refused the transfer, so the callback will never take
            // this reference back; it is taken back here instead.
            drop(unsafe { Arc::from_raw(context) });
            return check(err, pipe, "transfer submit");
        }
        let deadline = Instant::now() + timeout;
        let mut slot = self.completion.slot();
        while *slot != Slot::Done {
            let now = Instant::now();
            if now >= deadline {
                *slot = Slot::Abandoned;
                if let Some(count) = &self.completion.ep0_inflight {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                self.owned = false;
                return Err(UsbError::new(UsbErrorKind::Timeout, pipe).with_timeout(timeout));
            }
            slot = self
                .completion
                .done
                .wait_timeout(slot, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Ok(())
    }

    pub(super) fn status(&self) -> sys::usb_transfer_status_t {
        // SAFETY: the transfer completed, so the library no longer writes it.
        unsafe { (*self.raw).status }
    }

    pub(super) fn actual(&self) -> usize {
        // SAFETY: as for `status`.
        usize::try_from(unsafe { (*self.raw).actual_num_bytes }).unwrap_or(0)
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: an owned transfer is not in flight, and nothing else refers to it.
            unsafe { sys::usb_host_transfer_free(self.raw) };
        }
    }
}
