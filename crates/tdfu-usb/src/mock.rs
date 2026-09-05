//! A scripted [`LocalUsbTransport`] for tests.
//!
//! Behind `#[cfg(any(test, feature = "mock"))]`. It is a *scripted* double, not a
//! device model: you queue the exact calls you expect and the replies they get, and any
//! deviation is a failure. The emulated U-Boot DFU gadget — the one that models a
//! device's state machine — is a separate deliverable, and when
//! it lands it must be checked against `f_dfu.c`, not against what the host expects
//! (three defects in an earlier emulator silently removed coverage, the worst of them
//! making an entire recovery class unfalsifiable).
//!
//! Three properties are deliberate and load-bearing:
//!
//! * **The builder is [`expecting`](MockTransport::expecting), never `expect`.** A
//!   `grep '\.expect('` over the tree stays a valid no-panic audit.
//! * **Where the trait states an obligation, the double honours it rather than
//!   scripting it.** `release_interface` is idempotent, an over-long bulk IN answer is
//!   truncated, and `set_alt_setting`/`clear_halt` refuse with
//!   [`UsbErrorKind::NotClaimed`] exactly where the native backend does. A double that
//!   is stricter *or* laxer than the backend it stands in for removes coverage in
//!   silence, which is the failure mode this is guarding against.
//! * **Every call records its timeout** ([`Recorded::timeout`]) from the first commit.
//!   An earlier double retrofitted it, which meant the tests written before the
//!   retrofit could not tell a memory read's 2 s from a download's 30 s.
//!
//! Nothing here panics: a mismatch is an [`UsbError`] to the caller *and* a recorded
//! failure that [`verify`](MockTransport::verify) returns, so a test that swallows the
//! error still fails at the end.

use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::VecDeque;

use crate::error::{Pipe, UsbError, UsbErrorKind};
use crate::transport::LocalUsbTransport;
use crate::types::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, InterfaceSpec, Recipient,
};

/// One call the device could receive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Call {
    /// [`LocalUsbTransport::control_in`].
    ControlIn {
        /// `bmRequestType` bits 6:5.
        control_type: ControlType,
        /// `bmRequestType` bits 4:0.
        recipient: Recipient,
        /// `bRequest`.
        request: u8,
        /// `wValue`.
        value: u16,
        /// `wIndex`.
        index: u16,
        /// `wLength`.
        len: u16,
    },
    /// [`LocalUsbTransport::control_out`].
    ControlOut {
        /// `bmRequestType` bits 6:5.
        control_type: ControlType,
        /// `bmRequestType` bits 4:0.
        recipient: Recipient,
        /// `bRequest`.
        request: u8,
        /// `wValue`.
        value: u16,
        /// `wIndex`.
        index: u16,
        /// The data stage.
        data: Vec<u8>,
    },
    /// [`LocalUsbTransport::bulk_in`].
    BulkIn {
        /// Bytes asked for.
        len: usize,
    },
    /// [`LocalUsbTransport::bulk_out`].
    BulkOut {
        /// Bytes offered.
        data: Vec<u8>,
    },
    /// [`LocalUsbTransport::set_configuration`].
    SetConfiguration(u8),
    /// [`LocalUsbTransport::claim_interface`].
    ClaimInterface(InterfaceSpec),
    /// [`LocalUsbTransport::release_interface`].
    ReleaseInterface(u8),
    /// [`LocalUsbTransport::set_alt_setting`].
    SetAltSetting {
        /// `bInterfaceNumber`.
        interface: u8,
        /// `bAlternateSetting`.
        alt: u8,
    },
    /// [`LocalUsbTransport::clear_halt`].
    ClearHalt(BulkEndpoint),
    /// [`LocalUsbTransport::reset`].
    Reset,
}

impl Call {
    /// The call a [`ControlIn`] makes.
    #[must_use]
    pub const fn control_in(req: ControlIn) -> Self {
        Self::ControlIn {
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
            len: req.len,
        }
    }

    /// The call a [`ControlOut`] makes.
    #[must_use]
    pub fn control_out(req: ControlOut<'_>) -> Self {
        Self::ControlOut {
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
            data: req.data.to_vec(),
        }
    }

    /// The pipe this call uses, for the error a mismatch produces.
    fn pipe(&self) -> Pipe {
        match *self {
            Self::ControlIn { request, .. } => Pipe::Control {
                direction: Direction::In,
                request,
            },
            Self::ControlOut { request, .. } => Pipe::Control {
                direction: Direction::Out,
                request,
            },
            Self::ClearHalt(endpoint) => Pipe::Bulk(endpoint),
            // Bulk transfers name their endpoint through the claim, not through the
            // call, so a mismatch on one is not attributable to a pipe.
            Self::BulkIn { .. }
            | Self::BulkOut { .. }
            | Self::SetConfiguration(_)
            | Self::ClaimInterface(_)
            | Self::ReleaseInterface(_)
            | Self::SetAltSetting { .. }
            | Self::Reset => Pipe::Device,
        }
    }
}

/// What the scripted device answers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// Bytes the device returns — control IN and bulk IN.
    Data(Vec<u8>),
    /// Bytes the device accepted — bulk OUT; this may equal the full
    /// length even on a timeout.
    Transferred(usize),
    /// Success with no value.
    Done,
    /// The call fails.
    Fail(UsbError),
}

/// One call as it actually happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// What was asked.
    pub call: Call,
    /// The deadline the caller set, for the calls that have one — the four transfer
    /// methods. `None` for every call the trait takes no `Duration` for: claim,
    /// release, `set_configuration`, `set_alt_setting`, `clear_halt` and `reset`. (The
    /// 5 s a backend applies to `SET_INTERFACE` lives inside the backend and no test
    /// can observe it through this trait.)
    pub timeout: Option<Duration>,
}

/// Why a scripted run failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MockError {
    /// A call arrived that the script did not expect.
    #[error("unexpected call {got:?}; expected {expected:?}")]
    Unexpected {
        /// What arrived.
        got: Box<Call>,
        /// What was next in the script, or `None` if the script had run out.
        expected: Option<Box<Call>>,
    },
    /// The script still had expectations when [`MockTransport::verify`] was called.
    #[error("{remaining} expectation(s) unused; next was {next:?}")]
    Unused {
        /// How many are left.
        remaining: usize,
        /// The next one.
        next: Box<Call>,
    },
    /// The script paired a call with a reply shape it cannot use — a `Transferred`
    /// answer to a `control_in`, say.
    #[error("script error: {0}")]
    Script(String),
}

#[derive(Debug)]
struct State {
    script: VecDeque<(Call, Reply)>,
    calls: Vec<Recorded>,
    configuration: Option<u8>,
    claim: Option<InterfaceSpec>,
    failure: Option<MockError>,
}

/// A [`LocalUsbTransport`] that answers from a script.
#[derive(Debug)]
pub struct MockTransport {
    descriptors: DeviceDescriptors,
    state: RefCell<State>,
}

impl MockTransport {
    /// A device that has been enumerated but not configured — the state a real
    /// driverless gadget is in (USB 9.1.1.5).
    #[must_use]
    pub fn new(descriptors: DeviceDescriptors) -> Self {
        Self {
            descriptors,
            state: RefCell::new(State {
                script: VecDeque::new(),
                calls: Vec::new(),
                configuration: None,
                claim: None,
                failure: None,
            }),
        }
    }

    /// Start out already in configuration `value`, so a claim path can be checked for
    /// *not* re-issuing `SET_CONFIGURATION` (the cached value and the differential capture
    /// finding that motivated [`LocalUsbTransport::active_configuration`]).
    #[must_use]
    pub fn configured(self, value: u8) -> Self {
        self.state.borrow_mut().configuration = Some(value);
        self
    }

    /// Queue one expectation.
    ///
    /// Named `expecting` and not `expect` so that `grep '\.expect('` stays a valid
    /// audit for panics.
    #[must_use]
    pub fn expecting(self, call: Call, reply: Reply) -> Self {
        self.state.borrow_mut().script.push_back((call, reply));
        self
    }

    /// Every call that arrived, in order, with its timeout.
    #[must_use]
    pub fn calls(&self) -> Vec<Recorded> {
        self.state.borrow().calls.clone()
    }

    /// How many expectations are still queued.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.state.borrow().script.len()
    }

    /// The interface currently claimed, if any.
    #[must_use]
    pub fn claimed(&self) -> Option<InterfaceSpec> {
        self.state.borrow().claim
    }

    /// The first failure, or the leftover expectations, or `Ok(())`.
    ///
    /// # Errors
    /// [`MockError`], which a test propagates with `?`. Tests return `Result` and use
    /// `?` rather than unwrapping, because the workspace denies `unwrap`/`expect`/
    /// `panic` in library crates and this module is one.
    pub fn verify(&self) -> Result<(), MockError> {
        let state = self.state.borrow();
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        if let Some((next, _)) = state.script.front() {
            return Err(MockError::Unused {
                remaining: state.script.len(),
                next: Box::new(next.clone()),
            });
        }
        Ok(())
    }

    /// Match `call` against the next expectation and return its reply.
    fn take(&self, call: Call, timeout: Option<Duration>) -> Result<Reply, UsbError> {
        let pipe = call.pipe();
        let mut state = self.state.borrow_mut();
        state.calls.push(Recorded {
            call: call.clone(),
            timeout,
        });
        let expected = state.script.pop_front();
        match expected {
            Some((want, reply)) if want == call => Ok(reply),
            other => {
                let failure = MockError::Unexpected {
                    got: Box::new(call),
                    expected: other.map(|(want, _)| Box::new(want)),
                };
                let message = failure.to_string();
                if state.failure.is_none() {
                    state.failure = Some(failure);
                }
                // `Backend` is in neither the vendor retry class nor the bus-reset
                // recoverable class, so a mismatch cannot be papered over by a retry.
                Err(UsbError::new(UsbErrorKind::Backend(message), pipe))
            }
        }
    }

    /// Note a script error — a reply shape the call cannot use — and fail the call.
    fn script_error(&self, what: &str, pipe: Pipe) -> UsbError {
        let mut state = self.state.borrow_mut();
        if state.failure.is_none() {
            state.failure = Some(MockError::Script(what.to_owned()));
        }
        UsbError::new(UsbErrorKind::Backend(what.to_owned()), pipe)
    }

    fn data_reply(&self, reply: Reply, pipe: Pipe) -> Result<Vec<u8>, UsbError> {
        match reply {
            Reply::Data(data) => Ok(data),
            Reply::Fail(err) => Err(err),
            other => Err(self.script_error(&format!("{other:?} cannot answer a read"), pipe)),
        }
    }

    /// The release the backend issues on its own before a second claim.
    ///
    /// Not [`LocalUsbTransport::release_interface`] itself: that one is entered by a
    /// caller who decided to release, so a claim in force makes the call scripted and a
    /// missing expectation is a test failure. This one is the backend's own doing, so it
    /// consumes an expectation when a test scripted one and is otherwise only recorded.
    fn release_before_claiming(&self, interface: u8) -> Result<(), UsbError> {
        let scripted = matches!(
            self.state.borrow().script.front(),
            Some((Call::ReleaseInterface(number), _)) if *number == interface
        );
        if scripted {
            let reply = self.take(Call::ReleaseInterface(interface), None)?;
            self.done_reply(reply, Pipe::Device)?;
        } else {
            self.state.borrow_mut().calls.push(Recorded {
                call: Call::ReleaseInterface(interface),
                timeout: None,
            });
        }
        self.state.borrow_mut().claim = None;
        Ok(())
    }

    fn done_reply(&self, reply: Reply, pipe: Pipe) -> Result<(), UsbError> {
        match reply {
            Reply::Done => Ok(()),
            Reply::Fail(err) => Err(err),
            other => Err(self.script_error(&format!("{other:?} cannot answer a void call"), pipe)),
        }
    }
}

impl LocalUsbTransport for MockTransport {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::In,
            request: req.request,
        };
        let want = usize::from(req.len);
        let reply = self.take(Call::control_in(req), Some(timeout))?;
        let mut data = self.data_reply(reply, pipe)?;
        // **Truncated to `wLength`, as every other transport in the tree is.** The host
        // controller stops the data stage at the byte count the setup packet asked for
        // (USB 2.0 §8.5.3), and the native backend caps at it explicitly; the emulated
        // gadget caps at `min(wLength, USB_BUFSIZ)`. Only this one used to hand back
        // whatever the script named, which meant a script could quietly return more than
        // the caller asked for and a parser that read past its own request still passed.
        // A short answer is *not* an error here — the trait says a control IN "returns
        // what the device sent, which may be shorter" — so this only ever removes bytes.
        data.truncate(want);
        Ok(data)
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::Out,
            request: req.request,
        };
        let reply = self.take(Call::control_out(req), Some(timeout))?;
        self.done_reply(reply, pipe)
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        let endpoint = self
            .claimed()
            .and_then(|spec| spec.bulk_out)
            .ok_or_else(|| UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device).with_len(data.len()))?;
        let pipe = Pipe::Bulk(endpoint);
        let reply = self.take(Call::BulkOut { data: data.to_vec() }, Some(timeout))?;
        match reply {
            Reply::Transferred(n) => Ok(n),
            Reply::Done => Ok(data.len()),
            Reply::Fail(err) => Err(err),
            other => Err(self.script_error(&format!("{other:?} cannot answer a bulk OUT"), pipe)),
        }
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let endpoint = self
            .claimed()
            .and_then(|spec| spec.bulk_in)
            .ok_or_else(|| UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device).with_len(len))?;
        let pipe = Pipe::Bulk(endpoint);
        let reply = self.take(Call::BulkIn { len }, Some(timeout))?;
        let data = self.data_reply(reply, pipe)?;
        if data.len() >= len {
            // Truncate, exactly as the native backend does
            // (`native/transport.rs`'s `completion.buffer[..len]`). `nusb` requires the
            // IN *request* to be a nonzero multiple of the endpoint's max packet size,
            // so a 4-byte read of a bootrom register goes out as a 512-byte request and
            // a real bootrom answers with a full 512-byte packet. Calling that `Short`
            // made the double disagree with every device it stands in for, and a defect
            // in a double silently removes coverage downstream.
            Ok(data[..len].to_vec())
        } else {
            // Exactly `len` or a failure. Only a genuinely *short* answer
            // is one.
            Err(UsbError::new(
                UsbErrorKind::Short {
                    got: data.len(),
                    want: len,
                },
                pipe,
            )
            .with_len(len)
            .with_timeout(timeout)
            .with_transferred(data.len()))
        }
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        let reply = self.take(Call::SetConfiguration(value), None)?;
        self.done_reply(reply, Pipe::Device)?;
        self.state.borrow_mut().configuration = Some(value);
        Ok(())
    }

    fn active_configuration(&self) -> Option<u8> {
        self.state.borrow().configuration
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        // Any claim in force goes first, because the native backend does exactly that:
        // `NativeTransport::claim_interface` opens with `self.claim.release_any()?`,
        // which drains both endpoints, drops them and issues a real `Interface::release`
        // before the new claim goes out. A double that quietly overwrote the claim let a
        // test pin a call sequence one release short of the one the bus sees.
        //
        // Recorded on the same terms `release_interface` uses: a scripted release is
        // taken as any other call, and an unscripted one is recorded without consuming
        // an expectation, so the implicit release cannot fail a test that did not ask
        // for it.
        let held = self.state.borrow().claim;
        if let Some(held) = held {
            self.release_before_claiming(held.interface)?;
        }
        let reply = self.take(Call::ClaimInterface(spec), None)?;
        self.done_reply(reply, Pipe::Device)?;
        self.state.borrow_mut().claim = Some(spec);
        Ok(())
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        // Contract §2.4: `release_interface` is **idempotent** — releasing an interface
        // that is not claimed is `Ok(())`. That obligation is what makes the
        // release-on-every-exit-path discipline clean rather than noisy, and a double
        // that punished a defensive release with an `Unexpected` failure punished the
        // discipline instead of the bug.
        //
        // An unscripted release while nothing is claimed is recorded — a test can still
        // assert it happened — but it consumes no expectation and cannot fail
        // `verify()`. A *scripted* release is taken as any other call, so a test that
        // wants to observe or fail one still can.
        let (holds, scripted) = {
            let state = self.state.borrow();
            let holds = state.claim.is_some_and(|spec| spec.interface == interface);
            let scripted =
                matches!(state.script.front(), Some((Call::ReleaseInterface(number), _)) if *number == interface);
            (holds, scripted)
        };
        if !holds && !scripted {
            self.state.borrow_mut().calls.push(Recorded {
                call: Call::ReleaseInterface(interface),
                timeout: None,
            });
            return Ok(());
        }
        let reply = self.take(Call::ReleaseInterface(interface), None)?;
        self.done_reply(reply, Pipe::Device)?;
        self.state.borrow_mut().claim = None;
        Ok(())
    }

    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        // The native backend answers `NotClaimed` when `interface` is not the claim in
        // force (`native/claim.rs`'s `set_alt`). A double that accepted the request
        // anyway let a test pin a `SET_INTERFACE` the real backend refuses outright.
        let holds = self
            .state
            .borrow()
            .claim
            .is_some_and(|spec| spec.interface == interface);
        if !holds {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device));
        }
        let reply = self.take(Call::SetAltSetting { interface, alt }, None)?;
        self.done_reply(reply, Pipe::Device)
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        // By address and not by direction, as the native backend does: a claim that
        // declares `0x81` must not answer for `0x82`, or clearing the halt on the wrong
        // endpoint would look like it had worked.
        let declares = self
            .state
            .borrow()
            .claim
            .is_some_and(|spec| spec.bulk_in == Some(endpoint) || spec.bulk_out == Some(endpoint));
        if !declares {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Bulk(endpoint)));
        }
        let reply = self.take(Call::ClearHalt(endpoint), None)?;
        self.done_reply(reply, Pipe::Bulk(endpoint))
    }

    async fn reset(&self) -> Result<(), UsbError> {
        let reply = self.take(Call::Reset, None)?;
        self.done_reply(reply, Pipe::Device)?;
        // USB 9.1.1.5: a bus reset returns the device to the Default state, so the
        // configuration is cleared and any claim is gone. An earlier double left both
        // untouched here and in SET_CONFIGURATION.
        //
        // This is the one place the double and the native backend disagree on purpose:
        // the Linux kernel re-applies configuration 1 after a reset, so the native
        // backend answers `Some(1)` where this answers `None`, and a claim scripted
        // against this mock therefore carries a `SET_CONFIGURATION` a real Linux host
        // never emits. The spec is on this side; the OS is on the other. The
        // differential capture against the C is the arbiter, and the re-open seam is
        // when to revisit it.
        let mut state = self.state.borrow_mut();
        state.configuration = None;
        state.claim = None;
        Ok(())
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        &self.descriptors
    }
}

/// Drive a future to completion on the current thread.
///
/// Enough for the mock, which never returns `Poll::Pending`, and it keeps the tests
/// free of a runtime dependency. Not a general executor: it does not park, so a future
/// that genuinely waits on I/O would spin.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::yield_now();
    }
}

#[cfg(test)]
mod tests {
    use super::{Call, MockError, MockTransport, Reply, block_on};
    use crate::endpoint::{BOOTROM_IN, BOOTROM_OUT};
    use crate::error::{UsbError, UsbErrorKind};
    use crate::transport::LocalUsbTransport;
    use crate::types::{ControlIn, ControlOut, ControlType, DeviceDescriptors, InterfaceSpec, Recipient};
    use core::time::Duration;

    /// A bootrom as enumeration sees it: junk prefix, never compared for
    /// equality.
    fn bootrom() -> DeviceDescriptors {
        DeviceDescriptors::new(crate::vid::INGENIC, crate::pid::BOOTROM)
            .with_product_string("\u{c3}\t USB Boot Device")
            .with_bus_address(1, 7)
    }

    fn set_data_addr(addr: u32) -> ControlOut<'static> {
        // The address is split into two u16 halves.
        ControlOut {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: 0x01,
            value: (addr >> 16) as u16,
            index: (addr & 0xFFFF) as u16,
            data: &[],
        }
    }

    #[test]
    fn a_scripted_sequence_replays_in_order_and_records_every_timeout() -> Result<(), MockError> {
        let addr = 0xB300_002C;
        let dev = MockTransport::new(bootrom())
            .expecting(
                Call::ClaimInterface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT)),
                Reply::Done,
            )
            .expecting(Call::control_out(set_data_addr(addr)), Reply::Done)
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(vec![0x03, 0x30, 0x04, 0x10]))
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        block_on(async {
            dev.claim_interface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT))
                .await?;
            dev.control_out(set_data_addr(addr), Duration::from_secs(5)).await?;
            let word = dev.bulk_in(4, Duration::from_secs(2)).await?;
            assert_eq!(word, vec![0x03, 0x30, 0x04, 0x10]);
            dev.release_interface(0).await
        })
        .map_err(|err| MockError::Script(err.to_string()))?;

        dev.verify()?;
        assert_eq!(dev.remaining(), 0);

        // The timeouts are recorded from the first commit, so a test can tell a
        // memory read's 2 s from a download's 30 s.
        let calls = dev.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].timeout, None, "a claim is not timed");
        assert_eq!(calls[1].timeout, Some(Duration::from_secs(5)));
        assert_eq!(calls[2].timeout, Some(Duration::from_secs(2)), "ROM's 2 s");
        assert_eq!(calls[3].timeout, None);
        Ok(())
    }

    #[test]
    fn an_unexpected_call_fails_the_call_and_the_run() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(bootrom()).expecting(Call::Reset, Reply::Done);

        let err = block_on(dev.set_configuration(1))
            .err()
            .ok_or("a script mismatch must fail the call")?;
        // The mismatch must be in neither retry class, or a retry could bury it.
        assert!(matches!(err.kind(), UsbErrorKind::Backend(_)));
        assert!(!err.is_vendor_retryable(), "a script mismatch must not be retried");

        // And it is still a failure even if the code under test swallowed the error.
        assert!(matches!(dev.verify(), Err(MockError::Unexpected { .. })));
        Ok(())
    }

    #[test]
    fn unused_expectations_fail_verify() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(bootrom()).expecting(Call::Reset, Reply::Done);
        let Err(MockError::Unused { remaining, .. }) = dev.verify() else {
            return Err("verify must report the unused expectation".into());
        };
        assert_eq!(remaining, 1);
        Ok(())
    }

    #[test]
    fn configured_starts_in_a_configuration_so_a_claim_can_skip_set_configuration() {
        let dev = MockTransport::new(bootrom()).configured(1);
        assert_eq!(dev.active_configuration(), Some(1));

        let fresh = MockTransport::new(bootrom());
        assert_eq!(fresh.active_configuration(), None, "enumerated, not configured");
    }

    #[test]
    fn a_bulk_transfer_the_claim_did_not_declare_is_not_claimed() {
        let dev =
            MockTransport::new(bootrom()).expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done);

        let claimed = block_on(dev.claim_interface(InterfaceSpec::control_only(0)));
        assert!(claimed.is_ok());

        // The DFU claim declares no bulk endpoints, so a bulk read has no pipe to use.
        let err = block_on(dev.bulk_in(4, Duration::from_secs(2)));
        assert_eq!(err.err().map(|e| e.kind().clone()), Some(UsbErrorKind::NotClaimed));
    }

    #[test]
    fn reset_clears_the_configuration_and_the_claim() -> Result<(), UsbError> {
        let dev = MockTransport::new(bootrom())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::Reset, Reply::Done);

        block_on(async {
            dev.claim_interface(InterfaceSpec::control_only(0)).await?;
            dev.reset().await
        })?;

        // USB 9.1.1.5. An earlier double left both untouched.
        assert_eq!(dev.active_configuration(), None);
        assert_eq!(dev.claimed(), None);
        Ok(())
    }

    // ---- `release_interface` is idempotent -----------------------------------------

    #[test]
    fn releasing_an_unclaimed_interface_is_ok_and_consumes_no_expectation() -> Result<(), MockError> {
        // The release-on-every-exit-path discipline
        // issues a release on paths that never claimed. The double must not turn that
        // into an `Unexpected` failure that poisons `verify()`.
        let dev = MockTransport::new(bootrom());

        let outcome = block_on(dev.release_interface(0));
        assert!(outcome.is_ok(), "an unscripted release while unclaimed must be Ok(())");

        dev.verify()?;
        // Recorded all the same, so a test can still assert the discipline was followed.
        assert_eq!(dev.calls().len(), 1);
        assert_eq!(dev.calls()[0].call, Call::ReleaseInterface(0));
        Ok(())
    }

    #[test]
    fn a_second_release_after_a_scripted_one_is_free() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(bootrom())
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        block_on(async {
            dev.claim_interface(InterfaceSpec::control_only(0)).await?;
            dev.release_interface(0).await?;
            // The claim is gone; this one is the defensive repeat.
            dev.release_interface(0).await
        })?;

        dev.verify()?;
        assert_eq!(dev.remaining(), 0, "the one scripted release was consumed");
        assert_eq!(dev.calls().len(), 3, "and the repeat was still recorded");
        Ok(())
    }

    #[test]
    fn releasing_an_interface_that_is_not_the_claim_is_free() -> Result<(), Box<dyn std::error::Error>> {
        let dev =
            MockTransport::new(bootrom()).expecting(Call::ClaimInterface(InterfaceSpec::control_only(3)), Reply::Done);

        block_on(async {
            dev.claim_interface(InterfaceSpec::control_only(3)).await?;
            dev.release_interface(0).await
        })?;

        dev.verify()?;
        assert_eq!(
            dev.claimed().map(|spec| spec.interface),
            Some(3),
            "interface 3 still is"
        );
        Ok(())
    }

    #[test]
    fn an_over_long_bulk_in_answer_is_truncated_the_way_the_native_backend_truncates()
    -> Result<(), Box<dyn std::error::Error>> {
        // A 4-byte register read goes out as a 512-byte request (`nusb` requires a
        // multiple of the max packet size) and a real bootrom answers with a full
        // 512-byte packet. The native backend keeps `[..len]`; the double must agree,
        // or it rejects the answer every device gives.
        let mut reply = vec![0xAA; 512];
        reply[..4].copy_from_slice(&[0x03, 0x30, 0x04, 0x10]);
        let dev = MockTransport::new(bootrom())
            .expecting(
                Call::ClaimInterface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT)),
                Reply::Done,
            )
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(reply));

        let word = block_on(async {
            dev.claim_interface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT))
                .await?;
            dev.bulk_in(4, Duration::from_secs(2)).await
        })?;

        assert_eq!(word, vec![0x03, 0x30, 0x04, 0x10]);
        dev.verify()?;
        Ok(())
    }

    #[test]
    fn an_over_long_control_in_answer_is_truncated_to_wlength() -> Result<(), Box<dyn std::error::Error>> {
        // The third transport in the tree to be given this rule, and the last: the host
        // controller ends a data stage at `wLength` (USB 2.0 §8.5.3), the native backend
        // caps at it explicitly and the emulated gadget caps at
        // `min(wLength, USB_BUFSIZ)`. Left uncapped here, a script could hand back more
        // than the caller asked for and a parser that read past its own request would
        // still pass — the three-way divergence the 2026-08-23 audit found, and the
        // shape to watch for: a defect in a double removes coverage silently.
        let dev = MockTransport::new(bootrom()).expecting(
            Call::ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Device,
                request: 0x06,
                value: 0x0200,
                index: 0,
                len: 9,
            },
            Reply::Data(vec![0x5A; 64]),
        );

        let answer = block_on(dev.control_in(
            ControlIn {
                control_type: ControlType::Standard,
                recipient: Recipient::Device,
                request: 0x06,
                value: 0x0200,
                index: 0,
                len: 9,
            },
            Duration::from_secs(5),
        ))?;

        assert_eq!(answer.len(), 9, "the mock handed back more than wLength asked for");
        dev.verify()?;
        Ok(())
    }

    #[test]
    fn set_alt_setting_without_the_claim_is_not_claimed() {
        // `native/claim.rs`'s `set_alt` refuses; the double must too, or a test can pin
        // a `SET_INTERFACE` the real backend never issues.
        let dev = MockTransport::new(bootrom()).expecting(Call::SetAltSetting { interface: 0, alt: 1 }, Reply::Done);

        let err = block_on(dev.set_alt_setting(0, 1));
        assert_eq!(err.err().map(|e| e.kind().clone()), Some(UsbErrorKind::NotClaimed));
        assert_eq!(dev.remaining(), 1, "the refusal consumed no expectation");
    }

    #[test]
    fn clear_halt_on_an_endpoint_the_claim_did_not_declare_is_not_claimed() {
        // `native/transport.rs`'s `clear_halt` checks `claim.declares(endpoint)` by
        // address. A control-only claim declares neither bulk endpoint.
        let dev = MockTransport::new(bootrom())
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::ClearHalt(BOOTROM_IN), Reply::Done);

        assert!(block_on(dev.claim_interface(InterfaceSpec::control_only(0))).is_ok());

        let err = block_on(dev.clear_halt(BOOTROM_IN));
        assert_eq!(err.err().map(|e| e.kind().clone()), Some(UsbErrorKind::NotClaimed));
        assert_eq!(dev.remaining(), 1, "the refusal consumed no expectation");
    }

    #[test]
    fn a_short_bulk_in_is_an_error_with_the_context() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(bootrom())
            .expecting(
                Call::ClaimInterface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT)),
                Reply::Done,
            )
            .expecting(Call::BulkIn { len: 4 }, Reply::Data(vec![0x03, 0x30]));

        block_on(dev.claim_interface(InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT)))?;

        // Exactly `len` or a failure.
        let err = block_on(dev.bulk_in(4, Duration::from_secs(2)))
            .err()
            .ok_or("a short read must not succeed")?;
        assert_eq!(*err.kind(), UsbErrorKind::Short { got: 2, want: 4 });
        assert_eq!(err.requested_len(), Some(4));
        assert_eq!(err.timeout(), Some(Duration::from_secs(2)));
        assert_eq!(err.transferred(), Some(2));
        Ok(())
    }

    #[test]
    fn a_second_claim_releases_the_first_the_way_the_backend_does() -> Result<(), Box<dyn std::error::Error>> {
        // `NativeTransport::claim_interface` calls `release_any()` first, so the bus
        // sees claim, release, claim. A double that overwrote the claim let a test pin
        // the sequence without the release and still call it a match.
        let control = InterfaceSpec::control_only(0);
        let with_bulk = InterfaceSpec::with_bulk(0, BOOTROM_IN, BOOTROM_OUT);
        let dev = MockTransport::new(bootrom())
            .expecting(Call::ClaimInterface(control), Reply::Done)
            .expecting(Call::ClaimInterface(with_bulk), Reply::Done);

        block_on(dev.claim_interface(control))?;
        block_on(dev.claim_interface(with_bulk))?;

        let calls: Vec<Call> = dev.calls().into_iter().map(|recorded| recorded.call).collect();
        assert_eq!(
            calls,
            vec![
                Call::ClaimInterface(control),
                Call::ReleaseInterface(0),
                Call::ClaimInterface(with_bulk),
            ]
        );
        // The implicit release is the backend's own, so it consumed no expectation and
        // a test that did not script one is not failed by it.
        dev.verify()?;
        Ok(())
    }
}
