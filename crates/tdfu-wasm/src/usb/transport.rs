//! [`WebUsbTransport`]: one open `USBDevice`, behind the frozen
//! [`LocalUsbTransport`] trait.
//!
//! # What a deadline means on this backend
//!
//! **It means "stop waiting", never "stop transferring".** WebUSB transfers carry no
//! timeout of their own: `controlTransferIn`, `transferOut` and the rest take no deadline
//! argument, and there is **no cancel** anywhere in the API. So every call here is raced
//! against [`clock::deadline`](crate::clock::deadline), exactly as the shim did
//! (`web/src/libusb-webusb.js:376-391`, `:431-445`), and when the deadline wins the
//! transfer is still queued in the browser and its bytes will still reach the device.
//! Nothing this code can do changes that. The native backend answers the same problem by
//! cancelling and then draining the straggler before the next submit
//! (`crates/tdfu-usb/src/native/transport.rs:16-31`); no WebUSB API can do either half.
//!
//! So the deadline's meaning has to be decided per direction, and it is:
//!
//! * **EP0.** A late reply is delivered to the promise that asked for it, and nobody is
//!   awaiting that promise any more, so it cannot be read as the next transfer's answer;
//!   the request/response pairing is the setup packet's own. Expiry is
//!   [`UsbErrorKind::Timeout`], which a bootrom vendor request retries, and that is safe: the worst a
//!   repeated `GETSTATUS` costs is a wasted round trip.
//! * **Bulk IN has the OUT problem in the other direction.** The abandoned `transferIn`
//!   stays queued on the endpoint and stays hungry, because there is no cancel, and the
//!   next `transferIn` sits behind it. If the device sent nothing for the abandoned
//!   request, the orphan takes the *next* request's payload and the new read waits for
//!   bytes that will never come: the pipe is one reply behind for good. Whether a
//!   `releaseInterface` between two operations cancels the orphan is not stated by
//!   WebUSB and is not relied on here. So an expired bulk IN latches exactly as an
//!   expired bulk OUT does, and for the same reason: what is queued cannot be taken
//!   back, so the only honest answer is to stop using this transport. Expiry is
//!   [`UsbErrorKind::Backend`], outside both retry classes, and the way out is the same
//!   unplug.
//! * **Bulk OUT is different, and an audit found it needed saying.** The bytes are the
//!   payload. A 64 KiB chunk whose 6 s deadline expires
//!   (`bootrom::bulk_timeout(65536)`) is still on its way to the bootrom, and
//!   `bootrom::transfer_chunks` retrying it would stage that chunk **twice** under a
//!   `SET_DATA_LEN` that promised it once, which is a silently truncated or shifted SPL:
//!   exactly what the chunking and the cache-line padding exist to prevent. The C has the identical hazard at
//!   the identical timeout (`bootstrap.c:110`, `libusb-webusb.js:431-445`), and it is not
//!   copied. Expiry on a bulk OUT is [`UsbErrorKind::Backend`] naming the reason, which is
//!   in neither the vendor-request retry class nor the reset-and-retry recoverable class, so nothing
//!   resends the chunk. And the transport **latches** it: every later bulk transfer, in
//!   either direction, is refused with the same reason until [`reset`](LocalUsbTransport::reset),
//!   because the abandoned bytes may still arrive and would then land in the middle of
//!   whatever came next. The operator's way out is to unplug the device, which
//!   re-enumerates it into a new `USBDevice`, a new id and a new transport.
//!
//! The alternative considered and rejected was **reconciliation**: keep the losing
//! promise, and when the retry arrives, await the old one instead of submitting a second
//! transfer, answering `Ok(bytesWritten)` if the bytes turn out to have gone. It is
//! strictly better in the one case where the device is merely slow, and it was rejected
//! for what it costs elsewhere: it has to hold the chunk to compare against the retry, it
//! has to decide what a *different* next transfer means (the abandoned bytes landed
//! somewhere the caller has already moved past), and it turns a rare timeout into a state
//! machine with no way to test the half that matters, because no test can make the
//! browser deliver a transfer this host has stopped waiting for. Refusing is the answer
//! that cannot be wrong.
//!
//! # The control plane has deadlines too
//!
//! Claim, release, `selectConfiguration`, `selectAlternateInterface`, `clearHalt` and
//! `reset` take no timeout in the trait, and an audit found they were awaited here with
//! none either, on the strength of one out-of-scope note that was about
//! `set_alt_setting` alone. They are
//! bounded now: [`CONTROL_PLANE_TIMEOUT`] for the five, [`RESET_TIMEOUT`] for `reset`,
//! which is generous because a reset is a re-enumeration and because it is issued exactly
//! when the gadget is wedged, which is the state most likely to make the platform call
//! slow. A promise that never settles is the one outcome the JS seam forbids, and
//! `reset` sits on the wedge-recovery path where that would strand
//! `engine.write()`'s promise for ever.
//!
//! # Standard requests are answered here, not sent
//!
//! WebUSB refuses standard control transfers. `tdfu-core` issues exactly one kind,
//! `GET_DESCRIPTOR`, from `dfu::descriptors::get_descriptor`, and it is answered from
//! the descriptor [`descriptor::build`](super::descriptor::build) synthesised at open
//! time. That covers both descriptor types core asks for: `CONFIGURATION`, and
//! `STRING` for the `iInterface` of each alt, whose names the browser already read
//! during enumeration and handed over as `UsbAlternateInterface.interfaceName`
//! themselves. Answering the string read here rather than forwarding it is not a
//! shortcut: the index core asks for is one **we** chose when synthesising the
//! descriptor and does not name the same string on the device (a live T32LQ numbers
//! `flash`, `erase`, `reboot` as 5, 6, 7), and WebUSB would refuse the standard request
//! anyway.
//!
//! `SET_INTERFACE` and `SET_CONFIGURATION` are **not** emulated in the control
//! path the way the shim emulated them (`libusb-webusb.js:342-349`): the frozen trait
//! gives both a method of their own ([`set_alt_setting`](LocalUsbTransport::set_alt_setting),
//! [`set_configuration`](LocalUsbTransport::set_configuration)), so a control transfer
//! that meant one would be a caller reaching around the interface. It is refused with a
//! message that says which method to use instead.

use core::cell::{Cell, RefCell};
use core::time::Duration;

use js_sys::{Array, Promise, Reflect, Uint8Array};
use tdfu_usb::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, InterfaceSpec, LocalUsbTransport,
    Pipe, Recipient, UsbError, UsbErrorKind,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{UsbControlTransferParameters, UsbDevice, UsbDirection, UsbRecipient, UsbRequestType};

use crate::clock::deadline;
use crate::log::Logger;
use crate::usb::error::{kind_from_dom, kind_from_status};

/// How long a control-plane call may take before it is a failure.
///
/// The five that are not `reset`. The trait gives them no timeout and the native backend
/// uses 5 s for the same set, where no test can observe it; this is that number, made
/// observable, because a browser promise that never settles hangs the page. A hang is the
/// one failure mode the page cannot report or recover from.
pub const CONTROL_PLANE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `USBDevice.reset()` may take.
///
/// Six times [`CONTROL_PLANE_TIMEOUT`], on purpose: a reset re-enumerates the device, and
/// it is issued precisely when the gadget has stopped answering, which is
/// the state most likely to make the platform call slow. Long enough that expiry means
/// the browser is not coming back, short enough that the page is not hung.
pub const RESET_TIMEOUT: Duration = Duration::from_secs(30);

/// What an abandoned bulk OUT costs, in the words the operator gets.
///
/// One literal for both the expiry itself and every transfer refused after it, so the two
/// cannot drift apart, and on one line for the reason `crate::ACCESS_DENIED_HINT` is:
/// one literal, one line, no `rustfmt` join.
pub const ABANDONED_OUT: &str = "a bulk OUT deadline expired and WebUSB cannot cancel a transfer, so the browser may still deliver those bytes: re-sending them would stage the chunk twice, and any later transfer could be overtaken by them. Unplug the device and start again";

/// What an abandoned bulk IN costs, in the words the operator gets.
///
/// The IN twin of [`ABANDONED_OUT`], and latched the same way: the read that was given up
/// on is still queued on the endpoint, so the next one queues behind it and is answered
/// with bytes the device sent for the first. Same shape, same single line.
pub const ABANDONED_IN: &str = "a bulk IN deadline expired and WebUSB cannot cancel a transfer, so the read is still queued on the endpoint: the next read would sit behind it and take its bytes. Unplug the device and start again";

/// Which note a failed bulk transfer latches, if it latches one.
///
/// Only our own deadline leaves a transfer queued; every other rejection is the browser
/// saying the transfer is over, and there is nothing outstanding to protect the next one
/// from. The direction picks the words, not the rule.
fn abandonment_note(kind: &UsbErrorKind, outbound: bool) -> Option<&'static str> {
    matches!(kind, UsbErrorKind::Timeout).then(|| if outbound { ABANDONED_OUT } else { ABANDONED_IN })
}

/// `bRequest` for `GET_DESCRIPTOR` (USB 2.0 §9.4.3).
const GET_DESCRIPTOR: u8 = 0x06;

/// `bRequest` for `SET_CONFIGURATION`; only ever seen here as a caller mistake.
const SET_CONFIGURATION: u8 = 0x09;

/// `bRequest` for `SET_INTERFACE`; likewise.
const SET_INTERFACE: u8 = 0x0B;

/// One open device over WebUSB.
///
/// `RefCell`/`Cell` rather than `&mut`: the trait takes `&self` everywhere, which is
/// what lets a `?Send` future hold one across an `.await`. No borrow is
/// ever held across an `.await` in this file: each one is taken, read or written, and
/// dropped on the same line.
#[derive(Debug)]
pub struct WebUsbTransport {
    device: UsbDevice,
    descriptors: DeviceDescriptors,
    /// The alt names behind the synthesised descriptor's `iInterface` indices, from
    /// [`descriptor::build`](super::descriptor::build). Immutable for the transport's
    /// life: the descriptor it indexes is.
    strings: Vec<String>,
    claim: RefCell<Option<InterfaceSpec>>,
    configuration: Cell<Option<u8>>,
    /// Set when a bulk OUT's deadline expired, cleared by a reset. See the module doc's
    /// second bullet: the transfer is still in flight and no API can stop it.
    abandoned_bulk: Cell<Option<&'static str>>,
    log: Logger,
}

impl WebUsbTransport {
    /// Wrap an already-opened `USBDevice`.
    ///
    /// `strings` is [`Synthesised::strings`](super::descriptor::Synthesised::strings) for
    /// the descriptor in `descriptors`; the two travel together or the `iInterface`
    /// indices in one name nothing in the other.
    ///
    /// `configuration` is what `USBDevice.configuration` said at open time: `None` for
    /// the driverless gadget, which often has none selected, and the reason a claim asks
    /// before it sets one.
    #[must_use]
    pub fn new(
        device: UsbDevice,
        descriptors: DeviceDescriptors,
        strings: Vec<String>,
        configuration: Option<u8>,
        log: Logger,
    ) -> Self {
        Self {
            device,
            descriptors,
            strings,
            claim: RefCell::new(None),
            configuration: Cell::new(configuration),
            abandoned_bulk: Cell::new(None),
            log,
        }
    }

    /// The underlying handle, for the engine's device table.
    #[must_use]
    pub fn device(&self) -> &UsbDevice {
        &self.device
    }

    /// Is any interface claimed right now?
    ///
    /// Read by the error mapper: it is what separates `InvalidStateError`'s two meanings
    /// (see [`kind_from_dom`]).
    fn holds_claim(&self) -> bool {
        self.claim.try_borrow().is_ok_and(|claim| claim.is_some())
    }

    /// The claim, if it covers `interface`.
    fn claim_of(&self, interface: u8) -> Option<InterfaceSpec> {
        self.claim
            .try_borrow()
            .ok()
            .and_then(|claim| *claim)
            .filter(|spec| spec.interface == interface)
    }

    /// Turn a rejected WebUSB promise into a [`UsbError`] with this call's context.
    ///
    /// The browser's own words go out on the log at debug first. Every mapped arm
    /// throws the message away, so
    /// Chromium's "Transfer failed" and "The device was disconnected" would otherwise
    /// reach the operator as a bare `transfer fault: control OUT request 0x01`. They
    /// cannot go into the error: the seam says `Error.message` is `tdfu_core::Error`'s
    /// `Display` exactly, which is the same reason the two standing hints
    /// go out on `log` rather than being appended to it.
    fn failure(&self, value: &JsValue, pipe: Pipe, len: Option<usize>, timeout: Option<Duration>) -> UsbError {
        let (name, message) = describe(value);
        // Not for our own expired deadline: the browser did not raise it, we did, and the
        // error already says `timeout`.
        if name != crate::clock::DEADLINE_MARKER {
            self.log.debug(|| super::backend::browser_words(&name, &message));
        }
        let mut error = UsbError::new(kind_from_dom(&name, &message, self.holds_claim()), pipe);
        if let Some(len) = len {
            error = error.with_len(len);
        }
        if let Some(timeout) = timeout {
            error = error.with_timeout(timeout);
        }
        error
    }

    /// Await `promise`, but no longer than `timeout`.
    ///
    /// The deadline's timer is cleared once the race has settled. It is not
    /// needed for correctness (`Promise::race` subscribes to both halves, so a late
    /// rejection is handled either way), only so a 16 MiB write does not leave one live
    /// timer per `DNLOAD` block for up to that block's own 30 s.
    async fn within(&self, promise: &JsValue, timeout: Duration) -> Result<JsValue, JsValue> {
        let deadline = deadline(timeout);
        let racers = Array::of2(promise, deadline.promise().as_ref());
        let outcome = JsFuture::from(Promise::race(racers.as_ref())).await;
        deadline.clear();
        outcome
    }

    /// Await a control-plane promise, bounded by `timeout`.
    ///
    /// `call` is the WebUSB method name, for the debug line an expiry produces: the
    /// [`UsbError`] carries [`Pipe::Device`] and the deadline, which does not say *which*
    /// of the six did not settle, and on the recovery path that is the question.
    async fn control_plane(
        &self,
        promise: &Promise<js_sys::Undefined>,
        call: &str,
        timeout: Duration,
    ) -> Result<(), UsbError> {
        match self.within(promise.as_ref(), timeout).await {
            Ok(_) => Ok(()),
            Err(value) => {
                let error = self.failure(&value, Pipe::Device, None, Some(timeout));
                if matches!(error.kind(), UsbErrorKind::Timeout) {
                    self.log
                        .debug(|| format!("USBDevice.{call}() did not settle within {timeout:?}"));
                }
                Err(error)
            }
        }
    }

    /// The refusal every bulk transfer gets once an OUT has been abandoned.
    ///
    /// `None` while the transport is in step. See the module doc: the abandoned bytes are
    /// still on their way, so anything sent after them can be overtaken.
    fn abandoned(&self, pipe: Pipe, len: usize, timeout: Duration) -> Option<UsbError> {
        self.abandoned_bulk
            .get()
            .map(|note| abandoned_error(note, pipe, len, timeout))
    }

    /// Answer a standard `GET_DESCRIPTOR` from what the browser already told us.
    fn standard_in(&self, req: ControlIn, pipe: Pipe) -> Result<Vec<u8>, UsbError> {
        if req.request != GET_DESCRIPTOR {
            return Err(UsbError::new(UsbErrorKind::Unsupported, pipe));
        }
        let descriptor_type = u8::try_from(req.value >> 8).unwrap_or(0);
        let index = u8::try_from(req.value & 0xFF).unwrap_or(0);
        let bytes = match (descriptor_type, index) {
            (super::descriptor::DESCRIPTOR_CONFIGURATION, 0) => self.descriptors.config_descriptor.clone(),
            // The names the browser read, behind the indices `descriptor::build` handed
            // out. `wIndex` is the LANGID and is ignored: the browser exposes
            // one string per alternate with no language attached, so answering only 0x0409
            // would refuse a caller that asked for the same name in the only language
            // there is.
            (super::descriptor::DESCRIPTOR_STRING, _) => super::descriptor::string_descriptor(&self.strings, index),
            _ => {
                self.log.debug(|| {
                    format!(
                        "WebUSB exposes no descriptor type {descriptor_type:#04x} index {index}; \
                         refusing the read rather than inventing one"
                    )
                });
                return Err(UsbError::new(UsbErrorKind::Unsupported, pipe));
            }
        };
        // `wLength` is the ceiling, exactly as a device applies it: `read_config` asks
        // for 9 bytes first to learn `wTotalLength`, then for the whole thing.
        let wanted = usize::from(req.len);
        Ok(bytes.into_iter().take(wanted).collect())
    }
}

impl LocalUsbTransport for WebUsbTransport {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::In,
            request: req.request,
        };
        if matches!(req.control_type, ControlType::Standard) {
            return self.standard_in(req, pipe);
        }
        let setup = setup_of(req.control_type, req.recipient, req.request, req.value, req.index);
        let promise = self.device.control_transfer_in(&setup, req.len);
        let len = usize::from(req.len);
        let result = self
            .within(promise.as_ref(), timeout)
            .await
            .map_err(|value| self.failure(&value, pipe, Some(len), Some(timeout)))?;
        if let Some(kind) = kind_from_status(&status_of(&result)) {
            return Err(UsbError::new(kind, pipe).with_len(len).with_timeout(timeout));
        }
        let data = data_of(&result);
        self.log.debug(|| {
            format!(
                "control IN request {:#04x} value {:#06x} index {:#06x}: {} of {len} bytes",
                req.request,
                req.value,
                req.index,
                data.len()
            )
        });
        Ok(data)
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::Out,
            request: req.request,
        };
        if matches!(req.control_type, ControlType::Standard) {
            // WebUSB refuses standard control requests outright, so `Unsupported` is
            // literally true. The shim emulated two of them from inside the control path
            // (`libusb-webusb.js:342-349`) because its caller was libusb and had no other
            // spelling; the frozen trait gives both a method, so a control transfer that
            // means one is a caller reaching around the interface. Say which method.
            self.log.warn(&match req.request {
                SET_INTERFACE => "a standard SET_INTERFACE cannot be sent over WebUSB: use \
                                  LocalUsbTransport::set_alt_setting, which calls selectAlternateInterface"
                    .to_owned(),
                SET_CONFIGURATION => "a standard SET_CONFIGURATION cannot be sent over WebUSB: use \
                                      LocalUsbTransport::set_configuration, which calls selectConfiguration"
                    .to_owned(),
                other => format!("WebUSB refuses standard control requests; {other:#04x} cannot be sent"),
            });
            return Err(UsbError::new(UsbErrorKind::Unsupported, pipe).with_len(req.data.len()));
        }
        let setup = setup_of(req.control_type, req.recipient, req.request, req.value, req.index);
        let data = Uint8Array::from(req.data);
        let promise = self
            .device
            .control_transfer_out_with_u8_array(&setup, &data)
            .map_err(|value| self.failure(&value, pipe, Some(req.data.len()), Some(timeout)))?;
        let result = self
            .within(promise.as_ref(), timeout)
            .await
            .map_err(|value| self.failure(&value, pipe, Some(req.data.len()), Some(timeout)))?;
        if let Some(kind) = kind_from_status(&status_of(&result)) {
            return Err(UsbError::new(kind, pipe)
                .with_len(req.data.len())
                .with_timeout(timeout)
                .with_transferred(bytes_written_of(&result)));
        }
        // A control OUT's data stage is all-or-nothing on the wire, but the browser
        // reports `bytesWritten` and a short one would mean the device NAKed part of it.
        // This method returns no length by design; that is about the *success*
        // path, not about hiding a partial write.
        let written = bytes_written_of(&result);
        if written < req.data.len() {
            return Err(UsbError::new(
                UsbErrorKind::Short {
                    got: written,
                    want: req.data.len(),
                },
                pipe,
            )
            .with_len(req.data.len())
            .with_timeout(timeout)
            .with_transferred(written));
        }
        Ok(())
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        let endpoint = self
            .claim
            .try_borrow()
            .ok()
            .and_then(|claim| claim.and_then(|spec| spec.bulk_out))
            .ok_or_else(|| {
                UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device)
                    .with_len(data.len())
                    .with_timeout(timeout)
            })?;
        let pipe = Pipe::Bulk(endpoint);
        if let Some(refusal) = self.abandoned(pipe, data.len(), timeout) {
            return Err(refusal);
        }
        let payload = Uint8Array::from(data);
        let promise = self
            .device
            .transfer_out_with_u8_array(endpoint.number(), &payload)
            .map_err(|value| self.failure(&value, pipe, Some(data.len()), Some(timeout)))?;
        let result = match self.within(promise.as_ref(), timeout).await {
            Ok(result) => result,
            Err(value) => {
                let error = self.failure(&value, pipe, Some(data.len()), Some(timeout));
                // The module doc's second bullet. Our own deadline expired,
                // so the transfer is still queued and its bytes are still coming; every
                // other rejection is the browser saying the transfer is over.
                if let Some(note) = abandonment_note(error.kind(), true) {
                    self.abandoned_bulk.set(Some(note));
                    self.log.warn(note);
                    return Err(abandoned_error(note, pipe, data.len(), timeout));
                }
                return Err(error);
            }
        };
        if let Some(kind) = kind_from_status(&status_of(&result)) {
            return Err(UsbError::new(kind, pipe)
                .with_len(data.len())
                .with_timeout(timeout)
                .with_transferred(bytes_written_of(&result)));
        }
        Ok(bytes_written_of(&result))
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let endpoint = self
            .claim
            .try_borrow()
            .ok()
            .and_then(|claim| claim.and_then(|spec| spec.bulk_in))
            .ok_or_else(|| {
                UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device)
                    .with_len(len)
                    .with_timeout(timeout)
            })?;
        let pipe = Pipe::Bulk(endpoint);
        // An abandoned OUT is still on its way to the device, and the bootrom's read
        // sequence is `SET_DATA_ADDR`/`SET_DATA_LEN` on EP0 and then this: bytes arriving
        // in the middle of it would be staged as payload. Refused in both directions for
        // that reason, not only in the one where the duplicate would be written.
        if let Some(refusal) = self.abandoned(pipe, len, timeout) {
            return Err(refusal);
        }
        // Unlike `nusb`, WebUSB does not require the request to be a multiple of the
        // endpoint's max packet size: Chromium rounds the buffer up itself and returns
        // what arrived. So the "round the REQUEST up internally" obligation a native backend
        // carries is met by the platform here, and asking for exactly `len` is correct.
        let wanted = u32::try_from(len).map_err(|_| {
            UsbError::new(
                UsbErrorKind::Backend(format!("a bulk IN of {len} bytes does not fit WebUSB's 32-bit length")),
                pipe,
            )
            .with_len(len)
        })?;
        let promise = self.device.transfer_in(endpoint.number(), wanted);
        let result = match self.within(promise.as_ref(), timeout).await {
            Ok(result) => result,
            Err(value) => {
                let error = self.failure(&value, pipe, Some(len), Some(timeout));
                // The module doc's IN bullet. Our own deadline expired, so the read is
                // still queued and hungry; the next one would queue behind it and be
                // answered with what the device sent for this one.
                if let Some(note) = abandonment_note(error.kind(), false) {
                    self.abandoned_bulk.set(Some(note));
                    self.log.warn(note);
                    return Err(abandoned_error(note, pipe, len, timeout));
                }
                return Err(error);
            }
        };
        if let Some(kind) = kind_from_status(&status_of(&result)) {
            return Err(UsbError::new(kind, pipe).with_len(len).with_timeout(timeout));
        }
        let data = data_of(&result);
        if data.len() != len {
            // A short memory read is a hard failure, never a partial answer.
            return Err(UsbError::new(
                UsbErrorKind::Short {
                    got: data.len(),
                    want: len,
                },
                pipe,
            )
            .with_len(len)
            .with_timeout(timeout)
            .with_transferred(data.len()));
        }
        Ok(data)
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        self.control_plane(
            &self.device.select_configuration(value),
            "selectConfiguration",
            CONTROL_PLANE_TIMEOUT,
        )
        .await?;
        self.configuration.set(Some(value));
        Ok(())
    }

    fn active_configuration(&self) -> Option<u8> {
        self.configuration.get()
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        self.control_plane(
            &self.device.claim_interface(spec.interface),
            "claimInterface",
            CONTROL_PLANE_TIMEOUT,
        )
        .await?;
        if let Ok(mut claim) = self.claim.try_borrow_mut() {
            *claim = Some(spec);
        }
        self.log
            .debug(|| format!("claimed interface {} over WebUSB", spec.interface));
        Ok(())
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        // Idempotent, and answered from our own state rather than from the browser's:
        // Chromium raises `InvalidStateError` for releasing an interface that was never
        // claimed, and the bootrom path releases on every exit path deliberately.
        // A defensive release must not manufacture an error.
        if self.claim_of(interface).is_none() {
            return Ok(());
        }
        let outcome = self
            .control_plane(
                &self.device.release_interface(interface),
                "releaseInterface",
                CONTROL_PLANE_TIMEOUT,
            )
            .await;
        // The claim is gone either way. A release that failed did not leave the interface
        // usable, and remembering it would make the next `bulk_in` report `Busy` from a
        // stale fact instead of `NotClaimed` from a true one.
        if let Ok(mut claim) = self.claim.try_borrow_mut() {
            *claim = None;
        }
        outcome
    }

    /// `selectAlternateInterface(interface, alt)`: **by index**, because that is what the
    /// WebUSB call takes.
    ///
    /// This is the *request*, not the selection. `dfu::alt::resolve` has already turned an
    /// `AltSel` into a `bAlternateSetting` by the time anything reaches here, and on this
    /// backend it can do that by name as well as by number: the browser read the
    /// `iInterface` strings during enumeration and
    /// [`descriptor::build`](super::descriptor::build) carries them into the synthesised
    /// descriptor, so `read_info` resolves `flash`, `erase` and `reboot` the way it does
    /// natively. What still needs a rule is the *fallback*: a device
    /// the browser named no alternate on has empty names, and the resolver's default is
    /// then the first alt rather than a refusal.
    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        if self.claim_of(interface).is_none() {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device));
        }
        self.control_plane(
            &self.device.select_alternate_interface(interface, alt),
            "selectAlternateInterface",
            CONTROL_PLANE_TIMEOUT,
        )
        .await
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        let declared = self.claim.try_borrow().ok().and_then(|claim| {
            claim.and_then(|spec| {
                [spec.bulk_in, spec.bulk_out]
                    .into_iter()
                    .flatten()
                    .find(|declared| *declared == endpoint)
            })
        });
        if declared.is_none() {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Bulk(endpoint)));
        }
        let direction = match endpoint.direction() {
            Direction::In => UsbDirection::In,
            Direction::Out => UsbDirection::Out,
        };
        self.control_plane(
            &self.device.clear_halt(direction, endpoint.number()),
            "clearHalt",
            CONTROL_PLANE_TIMEOUT,
        )
        .await
        .map_err(|error| UsbError::new(error.kind().clone(), Pipe::Bulk(endpoint)))
    }

    /// A real USB reset, over `USBDevice.reset()`.
    ///
    /// The frozen trait doc once said `reset` is `Unsupported` on Android *and* WebUSB.
    /// The no-reset rule is **Android's** (the fd is owned by Java and a
    /// close-and-reopen wedges the gadget's controller, `device.c:219-227, :309-313`)
    /// and says nothing about the browser. The shipped browser path does reset: the C's
    /// `dfu_reset_device` calls `libusb_reset_device` (`libtdfu/src/dfu/dfu.c:394`) and
    /// the shim maps that straight onto `device.reset()`
    /// (`web/src/libusb-webusb.js:462-471`). The wedge recovery, the wedged-EP0 case
    /// the C documents as "verified on A1/T31" (`dfu.c:368-373`), is therefore something
    /// the browser really could do and an `Unsupported` would have taken away.
    ///
    /// Two deliberate differences from the shim:
    ///
    /// * **A failure is reported, not swallowed.** The shim's
    ///   `.catch(function() { return 0 })` reported success for a reset that never
    ///   happened, and `dfu.c:394` discards the return value on top of that. Here it
    ///   comes back as an error, and `dfu::host::reset_and_retry_once` already does the
    ///   right thing with it: it says so through the progress sink and returns the
    ///   *operation's* error, not the reset's (`dfu/host.rs:745-751`).
    /// * **The claim is dropped.** A reset returns the device to the Default state (USB
    ///   2.0 §9.1.1.5), so the retried operation claims for itself, which every
    ///   operation does anyway. `active_configuration()` answers `None` afterwards, so
    ///   the claim path re-issues `SET_CONFIGURATION` rather than assuming one.
    ///
    /// It is also what clears an abandoned bulk OUT (see the module doc): a
    /// reset is the one call that returns the device to a known state, so it is the only
    /// thing that can put this transport back in step. The reset is issued whether or not
    /// the latch is set and the latch is cleared whether or not it succeeded, for the same
    /// reason the claim is: a caller holding `Err` is holding a device this transport can
    /// make no promises about either way.
    ///
    /// The deadline is [`RESET_TIMEOUT`] rather than [`CONTROL_PLANE_TIMEOUT`]: this call
    /// re-enumerates the device and is made when the gadget is already wedged.
    /// Expiry is a [`UsbErrorKind::Timeout`] like any other, which
    /// `reset_and_retry_once` reports rather than waiting on.
    ///
    /// There is nothing to re-open. The trait requires a backend whose handle the reset
    /// invalidates to re-open it (`nusb` documents its `Device` as dead afterwards), but
    /// WebUSB's `reset()` resolves with the same `USBDevice` still `opened`, because the
    /// browser owns the handle and re-acquires it across the re-enumeration itself. That
    /// is why the shim could `libusb_close` into a no-op and keep using the device
    /// (`libusb-webusb.js:199-208`).
    ///
    /// # Errors
    /// Whatever the browser raised, with [`Pipe::Device`].
    async fn reset(&self) -> Result<(), UsbError> {
        // Teardown first, as on every other backend: the claim is gone whether or not
        // the reset succeeds, and a caller holding `Err` is holding an unclaimed device.
        if let Ok(mut claim) = self.claim.try_borrow_mut() {
            *claim = None;
        }
        self.configuration.set(None);
        self.abandoned_bulk.set(None);
        self.control_plane(&self.device.reset(), "reset", RESET_TIMEOUT).await
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        &self.descriptors
    }
}

/// The failure a bulk transfer gets while an abandoned transfer is still in flight.
///
/// Free rather than a method so the shape is one expression at both call sites: the
/// expiry that sets the latch, and every transfer refused after it.
/// [`UsbErrorKind::Backend`] on purpose, and that is the whole point: it is
/// in neither the vendor-retry class nor the reset-and-retry recoverable class, so no
/// layer above re-sends the chunk.
fn abandoned_error(note: &str, pipe: Pipe, len: usize, timeout: Duration) -> UsbError {
    UsbError::new(UsbErrorKind::Backend(note.to_owned()), pipe)
        .with_len(len)
        .with_timeout(timeout)
}

/// A `USBControlTransferParameters` from the typed fields the trait carries instead of a
/// packed `bmRequestType`.
///
/// The whole point of those fields: WebUSB takes the same two, so this is a rename
/// rather than an unpack, and the "which bits mean recipient" question that made the
/// packed form fallible does not arise.
fn setup_of(
    control_type: ControlType,
    recipient: Recipient,
    request: u8,
    value: u16,
    index: u16,
) -> UsbControlTransferParameters {
    let request_type = match control_type {
        ControlType::Standard => UsbRequestType::Standard,
        ControlType::Class => UsbRequestType::Class,
        ControlType::Vendor => UsbRequestType::Vendor,
    };
    let recipient = match recipient {
        Recipient::Device => UsbRecipient::Device,
        Recipient::Interface => UsbRecipient::Interface,
        Recipient::Endpoint => UsbRecipient::Endpoint,
        Recipient::Other => UsbRecipient::Other,
    };
    UsbControlTransferParameters::new(index, recipient, request, request_type, value)
}

/// A transfer result's `status`, read as a string.
///
/// **Deliberately not `web_sys`'s typed getter**, for two reasons, neither of which is
/// the one this comment used to give before an audit checked it. It said the typed getter
/// would `throw_str("invalid enum value passed")` on a fourth status and hang the page; that is
/// the *numeric* enum path (`wasm-bindgen-macro-support-0.2.127/src/codegen.rs:2947`) and
/// cannot be reached from here. `UsbTransferStatus` is a **string** enum, and the
/// string-enum codegen silently accepts an unknown JS string as a hidden `__Invalid`
/// variant (`:1643-1646`, `from_abi` at `:1738`). The real reasons:
///
/// * **`__Invalid` loses the word.** A fourth status read through the typed getter
///   arrives as a variant with no name, so the
///   [`UsbErrorKind::Backend`](tdfu_usb::UsbErrorKind::Backend) it becomes could not say
///   what the browser actually reported, which is the whole value of that arm.
/// * **The typed getter is not compiled.** It is gated on a `UsbTransferStatus` feature
///   the workspace does not enable, so reaching for it would mean adding a `web-sys`
///   feature to get a worse answer.
fn status_of(result: &JsValue) -> String {
    Reflect::get(result, &JsValue::from_str("status"))
        .ok()
        .and_then(|status| status.as_string())
        .unwrap_or_default()
}

/// The bytes of a `USBInTransferResult`.
///
/// `data` is a `DataView` over the browser's own buffer; the copy out is one
/// `Uint8Array::to_vec`. `None`, which the spec allows for a transfer with no data
/// stage, is an empty slice, and the caller decides whether that is short.
fn data_of(result: &JsValue) -> Vec<u8> {
    let Ok(view) = Reflect::get(result, &JsValue::from_str("data")) else {
        return Vec::new();
    };
    let Some(view) = view.dyn_ref::<js_sys::DataView>() else {
        return Vec::new();
    };
    Uint8Array::new_with_byte_offset_and_length(
        &view.buffer(),
        u32::try_from(view.byte_offset()).unwrap_or(0),
        u32::try_from(view.byte_length()).unwrap_or(0),
    )
    .to_vec()
}

/// `bytesWritten` of a `USBOutTransferResult`, or 0 when it is absent.
///
/// Clamped to `u32`, which is WebUSB's own length type, and floored at 0. A `NaN`, a
/// negative or an absent field all read as 0: "the browser did not say how much moved",
/// which the caller turns into [`UsbErrorKind::Short`] rather than into a silent success.
fn bytes_written_of(result: &JsValue) -> usize {
    let written = Reflect::get(result, &JsValue::from_str("bytesWritten"))
        .ok()
        .and_then(|written| written.as_f64())
        .filter(|written| written.is_finite() && *written > 0.0)
        .map_or(0.0, |written| written.min(f64::from(u32::MAX)));
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to 0.0..=u32::MAX and checked finite on the lines above"
    )]
    let bytes = written as u32;
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// The name and message of a rejected promise's value.
///
/// Three shapes reach here: our own [`DEADLINE_MARKER`](crate::clock::DEADLINE_MARKER),
/// which is a bare string; a `DOMException`, which is what the browser raises; and
/// anything else with a `name`, which covers `Error` subclasses and the scripted
/// `USBDevice` double the `wasm-bindgen-test` suite rejects with.
fn describe(value: &JsValue) -> (String, String) {
    if let Some(marker) = value.as_string() {
        return (marker, String::new());
    }
    if let Some(exception) = value.dyn_ref::<web_sys::DomException>() {
        return (exception.name(), exception.message());
    }
    let name = Reflect::get(value, &JsValue::from_str("name"))
        .ok()
        .and_then(|name| name.as_string())
        .unwrap_or_default();
    let message = Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .unwrap_or_else(|| format!("{value:?}"));
    (name, message)
}

#[cfg(test)]
mod tests {
    use super::{ABANDONED_IN, ABANDONED_OUT, CONTROL_PLANE_TIMEOUT, RESET_TIMEOUT, abandoned_error, abandonment_note};
    use core::time::Duration;
    use tdfu_usb::{Pipe, UsbErrorKind, endpoint};

    #[test]
    fn the_control_plane_deadlines_are_finite_and_the_reset_is_the_generous_one() {
        // Zero would fail every call before it started; unbounded is the page
        // hang the seam forbids; and a `reset` held to the other five's 5 s would
        // give up on a re-enumeration that was going to work. Only the ordering and the
        // bounds are pinned, because the exact seconds are a judgement.
        assert!(CONTROL_PLANE_TIMEOUT > Duration::ZERO);
        assert!(
            RESET_TIMEOUT > CONTROL_PLANE_TIMEOUT,
            "a reset re-enumerates the device"
        );
        assert!(RESET_TIMEOUT < Duration::from_secs(120), "a page may not wait minutes");
        // The native backend's figure for the same five calls.
        assert_eq!(CONTROL_PLANE_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn an_abandoned_bulk_out_is_outside_both_retry_classes() {
        // The reason the kind is `Backend` rather than `Timeout`: a bootrom vendor request
        // resends a `Timeout` and the wedge recovery resets and resends it, and either one
        // stages the chunk a second time behind a transfer the browser cannot cancel.
        let error = abandoned_error(
            ABANDONED_OUT,
            Pipe::Bulk(endpoint::BOOTROM_OUT),
            65536,
            Duration::from_secs(6),
        );
        assert!(matches!(error.kind(), UsbErrorKind::Backend(_)));
        assert!(!error.is_vendor_retryable());
        assert!(!tdfu_core::Error::Usb(error.clone()).is_recoverable());
        // The context a `UsbError` carries: what was asked, and by when.
        assert_eq!(error.requested_len(), Some(65536));
        assert_eq!(error.timeout(), Some(Duration::from_secs(6)));
        assert!(error.to_string().contains("cannot cancel"), "{error}");
    }

    #[test]
    fn an_expired_bulk_latches_in_either_direction_and_nothing_else_does() {
        // WebUSB has no cancel, so an expired transfer is still queued whichever way it
        // was going: an OUT's bytes are still on their way to the device, and an IN's
        // read is still on the endpoint waiting to eat the next reply. Only our own
        // deadline leaves one behind; a stall or a disconnect is the browser saying the
        // transfer is over, and there is nothing left to protect the next one from.
        assert_eq!(abandonment_note(&UsbErrorKind::Timeout, true), Some(ABANDONED_OUT));
        assert_eq!(abandonment_note(&UsbErrorKind::Timeout, false), Some(ABANDONED_IN));
        assert_eq!(abandonment_note(&UsbErrorKind::Stall, false), None);
        assert_eq!(abandonment_note(&UsbErrorKind::NoDevice, false), None);
        assert_eq!(abandonment_note(&UsbErrorKind::Overflow, true), None);

        // And the refusal an abandoned IN hands out is the same class as the OUT's:
        // outside both retry classes, so no layer above re-issues the read into a pipe
        // that is one reply behind.
        let error = abandoned_error(
            ABANDONED_IN,
            Pipe::Bulk(endpoint::BOOTROM_IN),
            4096,
            Duration::from_secs(2),
        );
        assert!(matches!(error.kind(), UsbErrorKind::Backend(_)));
        assert!(!error.is_vendor_retryable());
        assert!(!tdfu_core::Error::Usb(error.clone()).is_recoverable());
        assert_eq!(error.requested_len(), Some(4096));
        assert_eq!(error.timeout(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn the_abandoned_note_is_one_clean_sentence() {
        // A `rustfmt` string join once put a 14-space gap in the middle of the native
        // hint and nothing noticed because nothing looked.
        for note in [ABANDONED_OUT, ABANDONED_IN] {
            assert!(!note.contains("  "), "{note:?}");
            assert!(!note.contains('\n'));
            // It has to say what to do, not only what went wrong.
            assert!(note.contains("Unplug the device"), "{note}");
        }
    }
}
