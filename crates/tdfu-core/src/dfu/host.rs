//! The DFU 1.1 host state machine.
//!
//! Six class requests on EP0 and the rules for driving them. Every operation composes
//! this layer.
//!
//! # What the device on the other end actually does
//!
//! The gadget is U-Boot's `f_dfu`, and the loaders are built from mainline, so its
//! state machine is the authority on what a request does *here*, not DFU 1.1's prose,
//! which is more permissive. Three of its rules shape this file:
//!
//! * **In `dfuERROR` it serves `GETSTATUS`, `GETSTATE` and `CLRSTATUS` and stalls
//!   everything else, `ABORT` included** (`f_dfu.c:593-617`, `state_dfu_error`). An
//!   `ABORT` sent there stalls *and* re-enters `dfuERROR`, so [`make_idle`]'s branch is
//!   not a nicety.
//! * **`dfuIDLE` has no `CLRSTATUS` case at all** (`f_dfu.c:333-400`, `state_dfu_idle`)
//!   — it falls to the default, which stalls and *sets* `dfuERROR`. Sending `CLRSTATUS`
//!   outside `dfuERROR` therefore creates the state it was meant to clear.
//! * **`GETSTATUS` is what advances the machine.** `dfuMANIFEST_SYNC` becomes
//!   `dfuMANIFEST` on a poll, and `dfuMANIFEST` reports itself with the entity's own
//!   `poll_timeout` while the deferred flush runs (`f_dfu.c:484-548`). The whole-chip
//!   erase happens inside that flush, which is why the erase grace tier exists.

use core::cell::Cell;
use core::time::Duration;

use tdfu_usb::{
    ControlIn, ControlOut, ControlType, InterfaceSpec, LocalUsbTransport, Recipient, UsbError, UsbErrorKind,
};

use super::descriptors::configuration_value;
use crate::clock::Sleeper;
use crate::error::{Error, Result};
use crate::model::DfuInfo;
use crate::progress::{Progress, ProgressSink};

/// The DFU class requests (`bRequest`), recipient *interface*.
pub mod request {
    /// `DFU_DETACH`.
    pub const DETACH: u8 = 0;
    /// `DFU_DNLOAD`. `wValue` is the block number.
    pub const DNLOAD: u8 = 1;
    /// `DFU_UPLOAD`. `wValue` is the block number.
    pub const UPLOAD: u8 = 2;
    /// `DFU_GETSTATUS`, six bytes back.
    pub const GETSTATUS: u8 = 3;
    /// `DFU_CLRSTATUS`.
    pub const CLRSTATUS: u8 = 4;
    /// `DFU_GETSTATE`.
    pub const GETSTATE: u8 = 5;
    /// `DFU_ABORT`.
    pub const ABORT: u8 = 6;
}

/// The DFU state machine's states (DFU 1.1 §6.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum State {
    /// `appIDLE`.
    AppIdle,
    /// `appDETACH`.
    AppDetach,
    /// `dfuIDLE`.
    DfuIdle,
    /// `dfuDNLOAD-SYNC`.
    DnloadSync,
    /// `dfuDNBUSY` — busy; sleep `bwPollTimeout` and poll again.
    DnBusy,
    /// `dfuDNLOAD-IDLE`.
    DnloadIdle,
    /// `dfuMANIFEST-SYNC`.
    ManifestSync,
    /// `dfuMANIFEST` — busy.
    Manifest,
    /// `dfuMANIFEST-WAIT-RESET`.
    ManifestWaitReset,
    /// `dfuUPLOAD-IDLE`.
    UploadIdle,
    /// `dfuERROR`. **Serves only GETSTATUS, GETSTATE and CLRSTATUS and stalls
    /// everything else, including ABORT** (`f_dfu.c:593-617`). Any emulator must
    /// reproduce that refusal or the whole block 0 recovery class becomes
    /// unfalsifiable.
    Error,
    /// A state number this host does not know.
    Other(u8),
}

impl State {
    /// The `bState` byte a device reports.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::AppIdle,
            1 => Self::AppDetach,
            2 => Self::DfuIdle,
            3 => Self::DnloadSync,
            4 => Self::DnBusy,
            5 => Self::DnloadIdle,
            6 => Self::ManifestSync,
            7 => Self::Manifest,
            8 => Self::ManifestWaitReset,
            9 => Self::UploadIdle,
            10 => Self::Error,
            other => Self::Other(other),
        }
    }

    /// Back to the byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::AppIdle => 0,
            Self::AppDetach => 1,
            Self::DfuIdle => 2,
            Self::DnloadSync => 3,
            Self::DnBusy => 4,
            Self::DnloadIdle => 5,
            Self::ManifestSync => 6,
            Self::Manifest => 7,
            Self::ManifestWaitReset => 8,
            Self::UploadIdle => 9,
            Self::Error => 10,
            Self::Other(code) => code,
        }
    }

    /// Is the device still working on the last request?
    ///
    /// `dfuDNBUSY` and `dfuMANIFEST` only. Everything else has settled, including
    /// `dfuERROR` — which is settled *and* wrong, and is caught by `bStatus` rather
    /// than by polling forever.
    #[must_use]
    pub const fn is_busy(self) -> bool {
        matches!(self, Self::DnBusy | Self::Manifest)
    }
}

impl core::fmt::Display for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AppIdle => f.write_str("appIDLE"),
            Self::AppDetach => f.write_str("appDETACH"),
            Self::DfuIdle => f.write_str("dfuIDLE"),
            Self::DnloadSync => f.write_str("dfuDNLOAD-SYNC"),
            Self::DnBusy => f.write_str("dfuDNBUSY"),
            Self::DnloadIdle => f.write_str("dfuDNLOAD-IDLE"),
            Self::ManifestSync => f.write_str("dfuMANIFEST-SYNC"),
            Self::Manifest => f.write_str("dfuMANIFEST"),
            Self::ManifestWaitReset => f.write_str("dfuMANIFEST-WAIT-RESET"),
            Self::UploadIdle => f.write_str("dfuUPLOAD-IDLE"),
            Self::Error => f.write_str("dfuERROR"),
            Self::Other(code) => write!(f, "state {code}"),
        }
    }
}

/// The six bytes `DFU_GETSTATUS` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status {
    /// `bStatus`. Anything but 0 is a protocol failure.
    pub status: u8,
    /// `bwPollTimeout`, a **24-bit** little-endian field.
    ///
    /// Twenty-four bits, and every test in an earlier implementation used 250 ms or
    /// 500 ms — values whose high byte is zero, so `<< 16` and `>> 16` were
    /// indistinguishable and coverage reported the line as covered throughout. Mutation
    /// testing caught it; coverage never could. At least one test must use a value
    /// above `0xFFFF` ms.
    pub poll_timeout: Duration,
    /// `bState`.
    pub state: State,
    /// `iString`.
    pub string_index: u8,
}

/// How many bytes `DFU_GETSTATUS` returns; fewer is a protocol failure
/// (`dfu.c:73-74`).
const STATUS_LEN: usize = 6;

/// `bStatus` when nothing is wrong (DFU 1.1 §6.1.2, `dfu.c:49`).
const STATUS_OK: u8 = 0;

impl Status {
    /// Parse the six bytes.
    ///
    /// `bwPollTimeout` is bytes 1..=3, little-endian, **24 bits** — the field that
    /// mutation testing caught because every test value fitted in the low word.
    fn parse(bytes: &[u8]) -> Result<Self> {
        let Some(&[status, poll_lo, poll_mid, poll_hi, state, string_index]) = bytes.get(..STATUS_LEN) else {
            return Err(Error::Protocol(format!(
                "GETSTATUS returned {} bytes, need {STATUS_LEN}",
                bytes.len()
            )));
        };
        let poll_timeout = u32::from(poll_lo) | (u32::from(poll_mid) << 8) | (u32::from(poll_hi) << 16);
        Ok(Self {
            status,
            poll_timeout: Duration::from_millis(u64::from(poll_timeout)),
            state: State::from_code(state),
            string_index,
        })
    }
}

/// The DFU 1.1 §6.1.2 `bStatus` names, so a failure says which one it was rather than
/// "protocol error".
///
/// `errSTALLEDPKT` is the one that mattered on hardware: it is what a T40XP recorded
/// when a 2 MiB buffer flush outlasted the old 5 s `DNLOAD` timeout.
fn status_name(status: u8) -> &'static str {
    match status {
        0 => "OK",
        1 => "errTARGET",
        2 => "errFILE",
        3 => "errWRITE",
        4 => "errERASE",
        5 => "errCHECK_ERASED",
        6 => "errPROG",
        7 => "errVERIFY",
        8 => "errADDRESS",
        9 => "errNOTDONE",
        10 => "errFIRMWARE",
        11 => "errVENDOR",
        12 => "errUSBR",
        13 => "errPOR",
        14 => "errUNKNOWN",
        15 => "errSTALLEDPKT",
        _ => "unknown status",
    }
}

/// The default control timeout for every DFU request except a `DNLOAD` data
/// block.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// A `DNLOAD` data block gets 30 s.
///
/// Crossing the loader's 2 MiB `dfu_bufsiz` boundary flushes the whole buffer to flash
/// *inside the request context* and NAKs the next setup past 5 s. With the default the
/// host abandoned the transfer mid-data-stage, the device recorded `errSTALLEDPKT`, and
/// every NAND write died at exactly 2 MiB. Seen on a T40XP.
pub const DNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How many **recovery requests** [`make_idle`] sends.
///
/// The poll count is one higher: each recovery is preceded by a `GETSTATUS` that decides
/// which one to send, and a final `GETSTATUS` observes the last one. Three CLRSTATUS or
/// ABORT requests, four polls.
pub const MAKE_IDLE_ROUNDS: usize = 3;

/// The shortest wait between two polls of a device that says it is busy.
///
/// `bwPollTimeout` is in milliseconds, so 1 ms is the smallest interval the field can
/// name and this floor can never lengthen a wait the device asked for. It only replaces
/// the *zero* case, which is a busy-spin — see [`poll_until_ready`].
pub const BUSY_POLL_FLOOR: core::time::Duration = core::time::Duration::from_millis(1);

/// How many `GETSTATUS` rounds [`poll_until_ready`] tries.
pub const POLL_ROUNDS: usize = 1000;

/// The backoff after a forgiven `GETSTATUS` failure.
pub const GRACE_BACKOFF: Duration = Duration::from_millis(500);

/// How long to wait for re-enumeration after a USB reset.
pub const POST_RESET_SETTLE: Duration = Duration::from_millis(1500);

/// Attempts for a failure on block 0: a stale transaction, retried once after make-idle.
pub const BLOCK0_ATTEMPTS: usize = 2;

/// How many consecutive failed `GETSTATUS` transfers a phase forgives.
///
/// Each lost poll costs the 5 s control timeout plus [`GRACE_BACKOFF`], so 36 is about
/// three minutes of EP0 silence. A T40XP's 256 MiB whole-chip erase outlasts anything
/// shorter; the old fail-fast path reset mid-manifest and re-sent the token, which the
/// loader refused while the first erase completed anyway.
///
/// **Reboot must be 0**: its post-ZLP poll *failing* is the reset
/// happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Grace {
    /// 36 — erase, and the manifest phase at the end of a write.
    Erase,
    /// 12 — a per-block write poll.
    Write,
    /// 0 — read, verify and reboot.
    None,
}

impl Grace {
    /// How many consecutive failures this grace forgives.
    #[must_use]
    pub const fn retries(self) -> usize {
        match self {
            Self::Erase => 36,
            Self::Write => 12,
            Self::None => 0,
        }
    }
}

/// Set the configuration if it differs, claim the DFU interface, and issue
/// `SET_INTERFACE`.
///
/// The configuration value comes from the descriptor and is set **only if it differs
/// from the current one** — a differential USB capture caught two extra
/// `SET_CONFIGURATION` requests the C does not send, from re-configuring on every
/// claim. A [`Busy`](tdfu_usb::UsbErrorKind::Busy) answer to it is tolerated and nothing
/// else is; see [`tolerate_busy`].
///
/// `SET_INTERFACE` goes out for any alt other than 0, and for alt 0 **only** when the
/// gadget has more than one alt. Both halves are load-bearing: a
/// single-alt interface may stall it (USB 9.4.10) and over WebUSB that stall wedges EP0
/// for every later request, while skipping it on a multi-alt gadget after an erase
/// leaves the `erase` alt live and the next image's first block lands there
/// ("dfu erase: bad token", seen on a T40XP).
///
/// A claim refused by the OS keeps its own
/// [`UsbErrorKind::AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied), which is
/// [not recoverable](crate::Error::is_recoverable) and so never gets buried under the
/// reset and retry: a bus reset does not install a udev rule. The C
/// flattens the same failure to its `OPEN_FAILED` (`dfu.c:432-435`) and a
/// `SET_INTERFACE` stall to `PROTOCOL` (`dfu.c:448-451`); both keep their transport
/// detail here, with the same recoverability.
///
/// # Errors
/// [`Error::Usb`](crate::Error::Usb) from any of the three requests.
pub async fn claim<T: LocalUsbTransport>(dev: &T, info: &DfuInfo, alt: u8) -> Result<()> {
    let configuration = configuration_value(dev.descriptors());
    if dev.active_configuration() != Some(configuration) {
        tolerate_busy(dev.set_configuration(configuration).await)?;
    }
    // DFU 1.1 rides EP0 entirely: the claim declares no bulk endpoint.
    dev.claim_interface(InterfaceSpec::control_only(info.interface)).await?;
    if alt != 0 || info.is_multi_alt() {
        dev.set_alt_setting(info.interface, alt).await?;
    }
    Ok(())
}

/// `Ok(())` for success **and** for [`Busy`](tdfu_usb::UsbErrorKind::Busy); every other
/// failure through unchanged.
///
/// The C's claim helper singles `Busy` out at `libtdfu/src/usb/device.c:336` — it tests
/// `!= LIBUSB_ERROR_BUSY` before it logs — because on Linux a `SET_CONFIGURATION` on an
/// already-configured device answers `EBUSY` while everything is fine.
///
/// We take that distinction and make it load-bearing, which is stricter than the C: it
/// logs at `:337-338` and claims anyway, whatever went wrong. If the request failed for
/// a reason that is *not* "already in force", the claim about to follow will fail too,
/// and this error is the one that says why; discarding it and reporting the claim's
/// throws the cause away.
///
/// `crate::bootrom::claim` applies the same rule to the same request and carries the
/// same citation; the two are separate because the layers are, and neither may import
/// the other.
fn tolerate_busy(outcome: core::result::Result<(), UsbError>) -> Result<()> {
    match outcome {
        Ok(()) => Ok(()),
        Err(error) if *error.kind() == UsbErrorKind::Busy => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// `DFU_GETSTATUS`.
///
/// # Errors
/// Anything the transport raises, or [`Error::Protocol`](crate::Error::Protocol) if
/// fewer than six bytes come back.
pub async fn get_status<T: LocalUsbTransport>(dev: &T, interface: u8) -> Result<Status> {
    let bytes = dev
        .control_in(class_in(request::GETSTATUS, 0, interface, 6), CONTROL_TIMEOUT)
        .await?;
    Status::parse(&bytes)
}

/// `DFU_DNLOAD` — one data block, or the zero-length end-of-transfer trigger.
///
/// **Every `DNLOAD` gets [`DNLOAD_TIMEOUT`], the zero-length one included**. That is
/// not an oversight carried from the C's single wrapper
/// (`dfu.c:99-102`, used for the data blocks at `:586` and for the manifest trigger at
/// `:613`): the manifest is exactly where the loader's final buffer flush — and, on the
/// `erase` alt, the whole-chip erase — runs inside the request context.
///
/// # Errors
/// [`Error::Usb`](crate::Error::Usb).
pub async fn dnload<T: LocalUsbTransport>(dev: &T, interface: u8, block: u16, data: &[u8]) -> Result<()> {
    let request = ControlOut {
        control_type: ControlType::Class,
        recipient: Recipient::Interface,
        request: request::DNLOAD,
        value: block,
        index: u16::from(interface),
        data,
    };
    dev.control_out(request, DNLOAD_TIMEOUT).await?;
    Ok(())
}

/// `DFU_UPLOAD` — ask for up to `len` bytes of block `block`.
///
/// Returns what the device actually sent, which may be **shorter than `len`**: a short
/// block is how a DFU upload says "that was the end", and the gadget
/// drops back to `dfuIDLE` when it happens (`f_dfu.c:566-569`). Callers must not treat
/// a short reply as an error.
///
/// # Errors
/// [`Error::Usb`](crate::Error::Usb).
pub async fn upload<T: LocalUsbTransport>(dev: &T, interface: u8, block: u16, len: u16) -> Result<Vec<u8>> {
    Ok(dev
        .control_in(class_in(request::UPLOAD, block, interface, len), CONTROL_TIMEOUT)
        .await?)
}

/// One class IN request on the DFU interface.
fn class_in(request: u8, value: u16, interface: u8, len: u16) -> ControlIn {
    ControlIn {
        control_type: ControlType::Class,
        recipient: Recipient::Interface,
        request,
        value,
        index: u16::from(interface),
        len,
    }
}

/// `DFU_ABORT`.
///
/// Returns the device to `dfuIDLE` from any of the download/upload/manifest-wait states.
/// In `dfuERROR` it stalls and leaves the state alone (`f_dfu.c:593-617`), which is why
/// [`make_idle`] picks between this and [`clr_status`] rather than sending both.
///
/// Public because the erase close-out needs it as a step of its own —
/// `ABORT`, probe, then `ABORT` or `CLRSTATUS` depending on what the probe says — and
/// [`class_out`] is private. Without it the erase operation would hand-roll the control
/// transfer and quietly re-derive `bmRequestType`.
///
/// # Errors
/// Anything the transport raises, including the `Stall` a device in `dfuERROR` answers
/// with. Callers that are recovering, rather than commanding, may discard it — see
/// [`make_idle`]'s reasoning.
pub async fn abort<T: LocalUsbTransport>(dev: &T, interface: u8) -> Result<()> {
    class_out(dev, request::ABORT, interface).await
}

/// `DFU_CLRSTATUS`.
///
/// Clears `dfuERROR` back to `dfuIDLE`. Sent in any other state it is not a case in the
/// gadget's dispatch at all: it falls to the default, which stalls **and enters**
/// `dfuERROR` (`f_dfu.c:333-400`). That asymmetry is why this and [`abort`] are separate
/// primitives rather than one "recover" call.
///
/// Public for the erase close-out, as [`abort`] is.
///
/// # Errors
/// Anything the transport raises.
pub async fn clr_status<T: LocalUsbTransport>(dev: &T, interface: u8) -> Result<()> {
    class_out(dev, request::CLRSTATUS, interface).await
}

/// Release the DFU interface.
///
/// The counterpart to [`claim`], and it exists so the release-on-every-exit-path
/// discipline has a home instead of being a rule every operation has to remember.
/// Releasing an interface that is not claimed is `Ok(())`, so a
/// defensive release on an error path costs nothing.
///
/// # Errors
/// Anything the transport raises while releasing a claim that was in force.
pub async fn release<T: LocalUsbTransport>(dev: &T, interface: u8) -> Result<()> {
    dev.release_interface(interface).await?;
    Ok(())
}

/// One class OUT request on the DFU interface, with no data stage.
async fn class_out<T: LocalUsbTransport>(dev: &T, request: u8, interface: u8) -> Result<()> {
    let out = ControlOut {
        control_type: ControlType::Class,
        recipient: Recipient::Interface,
        request,
        value: 0,
        index: u16::from(interface),
        data: &[],
    };
    dev.control_out(out, CONTROL_TIMEOUT).await?;
    Ok(())
}

/// Bring the device to `dfuIDLE`.
///
/// Up to [`MAKE_IDLE_ROUNDS`] recovery requests, each preceded by a `GETSTATUS`, **plus
/// a final `GETSTATUS` that observes the last one**: `dfuIDLE` is done, `dfuERROR` gets
/// `CLRSTATUS`, anything else gets `ABORT`. So four polls and three recoveries, not
/// three of each.
///
/// That last poll is the fix for a real cost. The earlier shape sent the third recovery
/// and returned `Error::State` without ever looking at what it did, so a device the
/// third `CLRSTATUS` had just recovered still failed — and the caller's answer to a
/// make-idle failure is a bus reset, which re-enumerates a device that was
/// already idle. One control transfer to avoid a reset.
///
/// **If `GETSTATUS` itself fails, bail immediately with that error** — an unreadable
/// status means a wedged EP0 and the caller's USB reset is the fix; more 5 s timeouts on
/// `ABORT`s that also hang help nobody.
///
/// The two branches are not interchangeable, because the gadget is not symmetric about
/// them: `ABORT` in `dfuERROR` stalls and stays in `dfuERROR` (`f_dfu.c:593-617`), and
/// `CLRSTATUS` in `dfuIDLE` is not a case at all — it falls to the default that stalls
/// and *enters* `dfuERROR` (`f_dfu.c:333-400`). Getting the pair the wrong way round
/// turns a recoverable device into a wedged one.
///
/// The recovery request's own result is deliberately not propagated (as at
/// `dfu.c:127-129`): the next `GETSTATUS` is ground truth, and it is the thing that
/// decides. A stall on a request sent into a state that moved under us is not a reason
/// to fail an operation that the following poll will show as idle.
///
/// # Errors
/// [`Error::State`](crate::Error::State) when the device will not reach `dfuIDLE`. The
/// C flattens the same failure into its `PROTOCOL` code; the daemon's mapper must send
/// `"Protocol error"` for it.
pub async fn make_idle<T: LocalUsbTransport>(dev: &T, interface: u8) -> Result<()> {
    let mut quiet = crate::progress::sink_ignore();
    make_idle_narrated(dev, interface, &mut quiet).await
}

/// [`make_idle`], narrating each `GETSTATUS` on the debug channel.
///
/// The pair exists because [`make_idle`] has callers with no sink to hand it (an
/// operation's own tests, `ops::reboot`'s polls) and one that is the whole reason the
/// narration is worth having: [`retry_stale_block0`] runs this before every transfer
/// attempt, so a device that took three recovery requests to come back says so in a log
/// the operator already has open. `sink_ignore` costs nothing on the quiet path.
///
/// Three lines, the C's coverage (`dfu.c:120`, `:123`, `:131`) in our words: what each
/// poll saw, a `GETSTATUS` that failed outright, and the state it gave up in.
///
/// # Errors
/// [`make_idle`]'s.
pub async fn make_idle_narrated<T: LocalUsbTransport>(
    dev: &T,
    interface: u8,
    progress: ProgressSink<'_>,
) -> Result<()> {
    for round in 0..MAKE_IDLE_ROUNDS {
        let status = polled(dev, interface, &mut *progress).await?;
        progress(Progress::Debug(idle_poll_line(round, &status)));
        match status.state {
            State::DfuIdle => return Ok(()),
            State::Error => drop(clr_status(dev, interface).await),
            _ => drop(abort(dev, interface).await),
        }
    }
    // The recovery above was the last one, and nothing has looked at it yet. One more
    // `GETSTATUS` is what turns "we gave up" into "we checked".
    let status = polled(dev, interface, &mut *progress).await?;
    progress(Progress::Debug(idle_poll_line(MAKE_IDLE_ROUNDS, &status)));
    if status.state == State::DfuIdle {
        return Ok(());
    }
    progress(Progress::Debug(format!(
        "make idle: still {} after {MAKE_IDLE_ROUNDS} recovery requests, so the transfer cannot start",
        status.state
    )));
    Err(Error::State(format!(
        "{} after {MAKE_IDLE_ROUNDS} attempts to return it to dfuIDLE",
        status.state
    )))
}

/// [`get_status`], saying so on the debug channel when the request itself fails.
///
/// An unreadable status is not one of the states below: it is a wedged EP0, and the
/// caller's answer is a bus reset. Worth a line, because from the outside
/// that reset looks like the operation gave up for no stated reason.
async fn polled<T: LocalUsbTransport>(dev: &T, interface: u8, progress: ProgressSink<'_>) -> Result<Status> {
    match get_status(dev, interface).await {
        Ok(status) => Ok(status),
        Err(err) => {
            progress(Progress::Debug(format!(
                "make idle: the GETSTATUS itself failed ({err}), so the device is wedged rather than busy"
            )));
            Err(err)
        }
    }
}

/// What one `GETSTATUS` on the way to `dfuIDLE` saw.
fn idle_poll_line(round: usize, status: &Status) -> String {
    format!(
        "make idle: poll {round} found {}, status {} ({:#04x})",
        status.state,
        status_name(status.status),
        status.status
    )
}

/// Poll `GETSTATUS` until the device settles.
///
/// Up to [`POLL_ROUNDS`] rounds; `bStatus != 0` is a protocol failure; `dfuDNBUSY` and
/// `dfuMANIFEST` are busy, so sleep the device's own `bwPollTimeout` and poll again.
/// Up to `grace.retries()` *consecutive* failed `GETSTATUS` transfers are forgiven with
/// a [`GRACE_BACKOFF`] wait, and the counter resets on any success.
///
/// The grace is not paranoia about flaky USB: **EP0 genuinely goes silent** while the
/// loader flushes its DFU buffer to flash or runs a whole-chip erase inside the
/// manifest phase, because the flush happens in the gadget's own main loop
/// (`f_dfu.c:511-548`). A poll lost there means busy, not gone — and the fail-fast path
/// it replaced reset the device mid-manifest, whose retry then landed on a device still
/// erasing.
///
/// # Errors
/// [`Error::Protocol`](crate::Error::Protocol) on a bad `bStatus` or after
/// [`POLL_ROUNDS`] rounds without settling, or the transport error once the grace is
/// exhausted.
pub async fn poll_until_ready<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    interface: u8,
    grace: Grace,
) -> Result<Status> {
    let mut quiet = crate::progress::sink_ignore();
    poll_until_ready_narrated(dev, clock, interface, grace, &mut quiet).await
}

/// [`poll_until_ready`], narrating each forgiven poll on the debug channel.
///
/// One line, the C's `dfu.c:155` in our words: a `GETSTATUS` swallowed while the loader
/// is flushing to flash, and the fact that this is being answered with a wait rather than
/// with a bus reset. That distinction is the whole of the grace, and without
/// a line for it a write that spent a minute inside a forgiven poll is indistinguishable
/// from one that hung.
///
/// The quiet [`poll_until_ready`] remains for the callers that pass [`Grace::None`], where
/// nothing is ever forgiven and this line cannot fire.
///
/// # Errors
/// [`poll_until_ready`]'s.
pub async fn poll_until_ready_narrated<T: LocalUsbTransport, C: Sleeper>(
    dev: &T,
    clock: &C,
    interface: u8,
    grace: Grace,
    progress: ProgressSink<'_>,
) -> Result<Status> {
    let mut failures = 0;
    let mut last = State::Other(0xFF);
    for _ in 0..POLL_ROUNDS {
        let status = match get_status(dev, interface).await {
            Ok(status) => status,
            Err(err) => {
                if failures >= grace.retries() {
                    return Err(err);
                }
                failures += 1;
                progress(Progress::Debug(format!(
                    "poll: GETSTATUS lost while the device is busy ({failures} of {} forgiven, {err}); \
                     waiting rather than resetting",
                    grace.retries()
                )));
                clock.sleep(GRACE_BACKOFF).await;
                continue;
            }
        };
        failures = 0;
        if status.status != STATUS_OK {
            return Err(Error::Protocol(format!(
                "device reported {} ({:#04x}) in {}",
                status_name(status.status),
                status.status,
                status.state
            )));
        }
        if !status.state.is_busy() {
            return Ok(status);
        }
        last = status.state;
        // The device sets its own pace, with a floor. `bwPollTimeout` 0 while busy is
        // the gadget saying "ask again now", and the C obliges literally
        // (`libtdfu/src/dfu/dfu.c:167-168` sleeps only when the field is non-zero) — up
        // to 1000 back-to-back `GETSTATUS` requests at an EP0 that is busy precisely
        // because the loader is flushing to flash. Every one of them costs the device a
        // setup packet it has to answer instead of writing.
        //
        // A 1 ms floor bounds that at ~1 s of polling instead of a hot loop, and cannot
        // slow a device that names a real timeout: the field is in milliseconds, so 1 ms
        // is the smallest non-zero value it can express.
        clock.sleep(status.poll_timeout.max(BUSY_POLL_FLOOR)).await;
    }
    Err(Error::Protocol(format!(
        "device stayed busy ({last}) for {POLL_ROUNDS} status polls"
    )))
}

/// Which attempt a retried closure is on.
///
/// **Both of an earlier implementation's retries were silent** — the recovery bus reset
/// and the stale-transaction retry announced nothing, and a retry the user cannot see
/// is a retry they cannot report.
///
/// **The note is emitted by the helpers, not by the closure.**
/// [`reset_and_retry_once`] and [`retry_stale_block0`] each say what they are about to
/// do before they do it, which is why every one of the six closures in `ops` binds this
/// as `_attempt`: the audibility requirement is met one level up, where it cannot be
/// forgotten by an operation that did not think to say anything. This value is passed
/// anyway so a closure that *wants* to vary its own progress by attempt can — a bar that
/// resets its byte counter, say — and because this is the helpers' published
/// signature.
/// An unused binding here is not a vestigial parameter; it is an extension
/// point with a live producer and no consumer yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attempt {
    /// 0 for the first try.
    pub index: usize,
    /// Why the retry happened, for the note.
    pub reason: RetryReason,
}

impl Attempt {
    /// The first attempt: nothing has gone wrong yet.
    #[must_use]
    pub const fn first() -> Self {
        Self {
            index: 0,
            reason: RetryReason::First,
        }
    }

    /// Is this a retry rather than the first go?
    #[must_use]
    pub const fn is_retry(self) -> bool {
        self.index > 0
    }
}

/// What caused a retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryReason {
    /// The first attempt.
    First,
    /// The device was USB-reset and the whole operation is being retried.
    BusReset,
    /// Block 0 failed, `CLRSTATUS` was sent, and the transfer restarts.
    StaleTransaction,
}

/// What a transfer being driven by [`retry_stale_block0`] is told, and tells back.
///
/// The "tells back" half is the point: the retry is for a failure **on block 0
/// only**, and the transfer is the only code that knows whether it got that far.
/// Marking it with [`first_block_done`](Transaction::first_block_done) is what makes
/// "first block" an explicit fact instead of the C's `block != 0` test — which is a bug
/// in all three of its transfer loops (`dfu.c:602` write, `:855` read, `:955` verify),
/// because `block` is a `uint16_t` and wraps back through 0 at 65536 blocks: 256 MiB at
/// `wTransferSize` 4096, i.e. exactly a T40XP whole-chip read, where a late error reads
/// as "stale block 0" and re-reads the entire chip.
#[derive(Debug)]
pub struct Transaction {
    attempt: Cell<Attempt>,
    past_first_block: Cell<bool>,
}

impl Transaction {
    /// Which attempt this is, and why (for the transfer's own progress lines).
    #[must_use]
    pub fn attempt(&self) -> Attempt {
        self.attempt.get()
    }

    /// Record that the first block has been transferred and accepted.
    ///
    /// Call it once the device has taken a block, not when one has been prepared: from
    /// here on a failure is genuine mid-stream trouble and the block 0 retry is
    /// wrong.
    pub fn first_block_done(&self) {
        self.past_first_block.set(true);
    }

    /// Has [`first_block_done`](Transaction::first_block_done) been called this
    /// attempt?
    #[must_use]
    pub fn is_past_first_block(&self) -> bool {
        self.past_first_block.get()
    }

    fn begin(&self, attempt: Attempt) {
        self.attempt.set(attempt);
        self.past_first_block.set(false);
    }
}

/// Run `op`; on a *recoverable* error, USB-reset the device and run it once
/// more.
///
/// Recoverable is [`Error::is_recoverable`](crate::Error::is_recoverable) — never
/// [`Error::Verify`](crate::Error::Verify), because a data mismatch is final. The reset
/// waits [`POST_RESET_SETTLE`] for re-enumeration. On **Android** the reset is
/// [`UsbErrorKind::Unsupported`](tdfu_usb::UsbErrorKind::Unsupported) and there is
/// nothing to retry; WebUSB used to be in that sentence and is not, because
/// `USBDevice.reset()` is a real reset, so the browser can fail
/// this call as well as refuse it. The sink below says which happened.
///
/// **A reset that does not happen leaves the operation's own error intact.** The C
/// gates its retry on `dfu_reset_device` having returned true (`dfu.c:996`), and the
/// reset's failure must not become the reported cause — the user needs to see what the
/// operation hit, not that a recovery they never asked for was unavailable. It is said
/// through the sink instead.
///
/// The reset drops the configuration and the claim (USB 9.1.1.5), so `op` must do its
/// own claim; every operation does, because the first attempt needs one too.
///
/// The retry announces itself through the sink.
///
/// # Errors
/// The second attempt's error, or the first if it was not recoverable.
pub async fn reset_and_retry_once<T, C, R, F>(dev: &T, clock: &C, progress: ProgressSink<'_>, mut op: F) -> Result<R>
where
    T: LocalUsbTransport,
    C: Sleeper,
    F: AsyncFnMut(Attempt, ProgressSink<'_>) -> Result<R>,
{
    let first = match op(Attempt::first(), &mut *progress).await {
        Ok(value) => return Ok(value),
        Err(err) => err,
    };
    if !first.is_recoverable() {
        return Err(first);
    }
    if let Err(reset) = dev.reset().await {
        // Two different facts, and an operator acts on them differently. A backend that
        // cannot reset at all (Android) is telling them to try another
        // machine; a reset that went out and failed is telling them the device is further
        // gone than a wedged EP0, and that unplugging it is the next thing to try. This
        // said "not available here" for both, which was true only while WebUSB's reset
        // was `Unsupported` too; `USBDevice.reset()` is a real reset now.
        let sink_says = if matches!(reset.kind(), UsbErrorKind::Unsupported) {
            format!("a USB reset is not available here ({reset})")
        } else {
            format!("the USB reset failed ({reset})")
        };
        progress(Progress::Note(format!(
            "the DFU gadget stopped answering ({first}), and {sink_says}"
        )));
        return Err(first);
    }
    clock.sleep(POST_RESET_SETTLE).await;
    progress(Progress::Note(format!(
        "the DFU gadget stopped answering ({first}); USB-reset it and retrying once"
    )));
    op(
        Attempt {
            index: 1,
            reason: RetryReason::BusReset,
        },
        &mut *progress,
    )
    .await
}

/// Retry a transfer that failed on **block 0** exactly once, after
/// `make_idle`.
///
/// A reload mid-transfer leaves U-Boot expecting a stale block sequence, and the first
/// block-0 request trips its cleanup and STALLs. A failure on any later block is
/// genuine and is not retried this way.
///
/// Every attempt begins with [`make_idle`], as all three of the C's transfer loops do
/// (`dfu.c:576`, `:822`, `:915`) — it is what sends the `CLRSTATUS` that clears the
/// stall the stale sequence caused. A device that will not go idle is **not** retried
/// here: that is a wedged EP0, and the bus reset is the layer that answers
/// it.
///
/// **"First block" is tracked explicitly, never as `block == 0`**: `op` calls
/// [`Transaction::first_block_done`]. See [`Transaction`] for the 256 MiB read that
/// makes the difference.
///
/// # Errors
/// The retried operation's error, or [`make_idle`]'s.
pub async fn retry_stale_block0<T, R, F>(dev: &T, interface: u8, progress: ProgressSink<'_>, mut op: F) -> Result<R>
where
    T: LocalUsbTransport,
    F: AsyncFnMut(&Transaction, ProgressSink<'_>) -> Result<R>,
{
    let transaction = Transaction {
        attempt: Cell::new(Attempt::first()),
        past_first_block: Cell::new(false),
    };
    for index in 0..BLOCK0_ATTEMPTS {
        make_idle_narrated(dev, interface, &mut *progress).await?;
        transaction.begin(Attempt {
            index,
            reason: if index == 0 {
                RetryReason::First
            } else {
                RetryReason::StaleTransaction
            },
        });
        match op(&transaction, &mut *progress).await {
            Ok(value) => return Ok(value),
            // A block landed, or there is nothing left to try: this is the answer.
            Err(err) if transaction.is_past_first_block() || index + 1 == BLOCK0_ATTEMPTS => return Err(err),
            Err(err) => progress(Progress::Note(format!(
                "block 0 failed ({err}) — clearing a stale DFU transaction (a reload mid-transfer?) \
                 and retrying from the first block"
            ))),
        }
    }
    // Only reachable if BLOCK0_ATTEMPTS were 0, which would mean no transfer ever runs.
    Err(Error::State(format!(
        "no transfer attempt ran; BLOCK0_ATTEMPTS is {BLOCK0_ATTEMPTS}"
    )))
}

#[cfg(test)]
mod tests {
    use super::super::descriptors::fixtures::T32LQ_CONFIG;
    use super::{
        Attempt, BLOCK0_ATTEMPTS, BUSY_POLL_FLOOR, CONTROL_TIMEOUT, DNLOAD_TIMEOUT, GRACE_BACKOFF, Grace,
        MAKE_IDLE_ROUNDS, POLL_ROUNDS, POST_RESET_SETTLE, RetryReason, State, Status, Transaction, abort, claim,
        clr_status, dnload, get_status, make_idle, make_idle_narrated, poll_until_ready, poll_until_ready_narrated,
        release, request, reset_and_retry_once, retry_stale_block0, status_name, upload,
    };
    use crate::clock::RecordingClock;
    use crate::error::{Error, Result};
    use crate::model::{DfuAlt, DfuInfo};
    use crate::progress::{Progress, ProgressSink};
    use core::cell::{Cell, RefCell};
    use core::time::Duration;
    use tdfu_usb::mock::{Call, MockTransport, Recorded, Reply, block_on};
    use tdfu_usb::{
        ControlType, DeviceDescriptors, Direction, InterfaceSpec, Pipe, Recipient, UsbError, UsbErrorKind, pid, vid,
    };

    fn gadget() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(T32LQ_CONFIG)
    }

    fn info(alts: &[(u8, &str)]) -> DfuInfo {
        DfuInfo {
            interface: 0,
            transfer_size: 4096,
            bcd_dfu: 0x0110,
            attributes: 0x0F,
            alts: alts.iter().map(|&(alt, name)| DfuAlt::new(alt, name)).collect(),
        }
    }

    fn getstatus() -> Call {
        Call::ControlIn {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request: request::GETSTATUS,
            value: 0,
            index: 0,
            len: 6,
        }
    }

    fn class_out(request: u8) -> Call {
        Call::ControlOut {
            control_type: ControlType::Class,
            recipient: Recipient::Interface,
            request,
            value: 0,
            index: 0,
            data: Vec::new(),
        }
    }

    /// Six status bytes: `bStatus`, 24-bit `bwPollTimeout`, `bState`, `iString`.
    fn status_bytes(status: u8, poll_ms: u32, state: State) -> Vec<u8> {
        let poll = poll_ms.to_le_bytes();
        vec![status, poll[0], poll[1], poll[2], state.code(), 0]
    }

    fn idle() -> Reply {
        Reply::Data(status_bytes(0, 0, State::DfuIdle))
    }

    fn wedged() -> UsbError {
        UsbError::new(
            UsbErrorKind::Timeout,
            Pipe::Control {
                direction: Direction::In,
                request: request::GETSTATUS,
            },
        )
        .with_timeout(CONTROL_TIMEOUT)
    }

    /// `MockTransport::verify` as a core error, so tests can `?` on both.
    fn verified(dev: &MockTransport) -> Result<()> {
        dev.verify().map_err(|err| Error::Protocol(err.to_string()))
    }

    fn timeouts(calls: &[Recorded]) -> Vec<Option<Duration>> {
        calls.iter().map(|call| call.timeout).collect()
    }

    #[test]
    fn dfu_poll_timeout_above_the_low_word() -> Result<()> {
        // `bwPollTimeout` is 24 bits. Every earlier test used a value under 256 ms,
        // so `<< 16` and `>> 16` were indistinguishable while coverage called the line
        // covered. 0x123456 ms puts a distinct byte in each of
        // the three positions, so any wrong shift, order or truncation changes it.
        let parsed = Status::parse(&[0x00, 0x56, 0x34, 0x12, State::Manifest.code(), 0x00])?;
        assert_eq!(parsed.poll_timeout, Duration::from_millis(0x0012_3456));
        assert_ne!(
            parsed.poll_timeout,
            Duration::from_millis(0x3456),
            "the high byte must not be dropped"
        );

        // And the value has to reach the clock, not just the struct.
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0x0012_3456, State::Manifest)))
            .expecting(getstatus(), idle());
        let clock = RecordingClock::new();

        let settled = block_on(poll_until_ready(&dev, &clock, 0, Grace::None))?;
        verified(&dev)?;
        assert_eq!(settled.state, State::DfuIdle);
        assert_eq!(
            clock.slept(),
            vec![Duration::from_millis(0x0012_3456)],
            "the device's own pace, all 24 bits of it"
        );
        Ok(())
    }

    #[test]
    fn get_status_parses_the_six_bytes_and_refuses_anything_shorter() -> Result<()> {
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 250, State::DnBusy)))
            .expecting(getstatus(), Reply::Data(vec![0, 0, 0, 0, 2]));

        let status = block_on(get_status(&dev, 0))?;
        assert_eq!(status.status, 0);
        assert_eq!(status.poll_timeout, Duration::from_millis(250));
        assert_eq!(status.state, State::DnBusy);
        assert_eq!(status.string_index, 0);
        assert_eq!(timeouts(&dev.calls()), vec![Some(CONTROL_TIMEOUT)]);

        // Five bytes is a protocol failure, as `dfu.c:73-74` decides.
        assert!(matches!(block_on(get_status(&dev, 0)), Err(Error::Protocol(_))));
        Ok(())
    }

    #[test]
    fn dfu_make_idle_state_machine() -> Result<()> {
        // Already idle: one GETSTATUS, nothing else.
        let already = MockTransport::new(gadget()).expecting(getstatus(), idle());
        block_on(make_idle(&already, 0))?;
        verified(&already)?;

        // dfuERROR gets CLRSTATUS — never ABORT, which the real gadget stalls in that
        // state while staying in it (`f_dfu.c:593-617`).
        let errored = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)))
            .expecting(class_out(request::CLRSTATUS), Reply::Done)
            .expecting(getstatus(), idle());
        block_on(make_idle(&errored, 0))?;
        verified(&errored)?;

        // Any other state gets ABORT — never CLRSTATUS, which `dfuIDLE` does not even
        // have a case for and answers by *entering* dfuERROR (`f_dfu.c:333-400`).
        let busy = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::DnloadIdle)))
            .expecting(class_out(request::ABORT), Reply::Done)
            .expecting(getstatus(), idle());
        block_on(make_idle(&busy, 0))?;
        verified(&busy)?;
        Ok(())
    }

    #[test]
    fn make_idle_is_bounded_and_names_the_state_it_gave_up_in() -> Result<()> {
        let mut dev = MockTransport::new(gadget());
        for _ in 0..MAKE_IDLE_ROUNDS {
            dev = dev
                .expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)))
                .expecting(class_out(request::CLRSTATUS), Reply::Done);
        }

        // The final observing poll: the device is still in dfuERROR, so
        // this is the one that decides to give up.
        let dev = dev.expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)));

        let Err(Error::State(message)) = block_on(make_idle(&dev, 0)) else {
            return Err(Error::Protocol("make_idle must give up with Error::State".into()));
        };
        verified(&dev)?;
        assert!(message.contains("dfuERROR"), "the message names the state: {message}");
        assert_eq!(
            dev.calls().len(),
            MAKE_IDLE_ROUNDS * 2 + 1,
            "{MAKE_IDLE_ROUNDS} recoveries, each polled first, and one poll to observe the last"
        );
        Ok(())
    }

    /// A device the last recovery fixed is not reported as unrecoverable.
    ///
    /// The earlier shape sent the third `CLRSTATUS` and returned `Error::State` without
    /// ever looking at what it did. The caller's answer to a make-idle failure is a bus
    /// reset, so a device that was already idle got re-enumerated for
    /// nothing — one control transfer's worth of not-checking, paid for with a reset.
    #[test]
    fn make_idle_observes_the_last_recovery_it_sends() -> Result<()> {
        let mut dev = MockTransport::new(gadget());
        for _ in 0..MAKE_IDLE_ROUNDS {
            dev = dev
                .expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)))
                .expecting(class_out(request::CLRSTATUS), Reply::Done);
        }
        // The third CLRSTATUS worked.
        let dev = dev.expecting(getstatus(), idle());

        block_on(make_idle(&dev, 0))?;
        verified(&dev)?;
        assert_eq!(dev.calls().len(), MAKE_IDLE_ROUNDS * 2 + 1);
        Ok(())
    }

    /// Just the [`Progress::Debug`] lines an operation narrated.
    fn debug_lines(said: &[Progress]) -> Vec<&str> {
        said.iter()
            .filter_map(|step| match step {
                Progress::Debug(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// **The narration pin for make-idle.** A device that is not idle first go says what
    /// each poll saw and what it gave up in, on the debug channel and nowhere else.
    ///
    /// The C had the same three lines behind its debug switch (`dfu.c:120,123,131`) and
    /// the Rust core had none, so `-d` on a stuck gadget printed nothing about the four
    /// polls it made. Revert check: drop the `Progress::Debug` calls in
    /// [`make_idle_narrated`] and every assertion here fails.
    #[test]
    fn make_idle_narrates_every_poll_and_the_state_it_gave_up_in() -> Result<()> {
        let mut dev = MockTransport::new(gadget());
        for _ in 0..MAKE_IDLE_ROUNDS {
            dev = dev
                .expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)))
                .expecting(class_out(request::CLRSTATUS), Reply::Done);
        }
        let dev = dev.expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)));

        let mut said = Vec::new();
        let mut sink = |progress: Progress| said.push(progress);
        let outcome = block_on(make_idle_narrated(&dev, 0, &mut sink));
        assert!(matches!(outcome, Err(Error::State(_))), "{outcome:?}");
        verified(&dev)?;

        let lines = debug_lines(&said);
        assert_eq!(
            lines.len(),
            MAKE_IDLE_ROUNDS + 2,
            "one line per poll plus the giving-up line: {lines:?}"
        );
        for (round, line) in lines.iter().take(MAKE_IDLE_ROUNDS + 1).enumerate() {
            assert!(line.contains(&format!("poll {round}")), "{line}");
            // The state and the status the poll saw, which is what makes the line worth
            // reading: `errSTALLEDPKT` in `dfuERROR` is a different fault from `OK`.
            assert!(line.contains("dfuERROR"), "{line}");
            assert!(line.contains(status_name(0x0F)), "{line}");
        }
        let gave_up = lines.last().copied().unwrap_or_default();
        assert!(gave_up.contains("dfuERROR"), "{gave_up}");
        assert!(gave_up.contains(&MAKE_IDLE_ROUNDS.to_string()), "{gave_up}");

        // Nothing else: a narration line the user did not ask for must not arrive as a
        // `Note`, which every frontend prints unconditionally.
        assert!(said.iter().all(|step| matches!(step, Progress::Debug(_))), "{said:?}");
        Ok(())
    }

    /// An unreadable `GETSTATUS` says so before the caller's bus reset makes it look like
    /// the operation simply stopped (`dfu.c:120`).
    #[test]
    fn make_idle_narrates_a_getstatus_that_failed_outright() -> Result<()> {
        let dev = MockTransport::new(gadget()).expecting(getstatus(), Reply::Fail(wedged()));
        let mut said = Vec::new();
        let mut sink = |progress: Progress| said.push(progress);
        assert!(block_on(make_idle_narrated(&dev, 0, &mut sink)).is_err());
        verified(&dev)?;

        let lines = debug_lines(&said);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("GETSTATUS"), "{}", lines[0]);
        Ok(())
    }

    /// **The narration pin for the grace.** A forgiven poll says it is waiting rather than
    /// resetting (`dfu.c:155`), which is the only outward difference between the grace
    /// working and the operation having hung.
    #[test]
    fn a_forgiven_poll_says_it_is_waiting_rather_than_resetting() -> Result<()> {
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Fail(wedged()))
            .expecting(getstatus(), Reply::Fail(wedged()))
            .expecting(getstatus(), idle());
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = |progress: Progress| said.push(progress);
        block_on(poll_until_ready_narrated(&dev, &clock, 0, Grace::Write, &mut sink))?;

        let lines = debug_lines(&said);
        assert_eq!(lines.len(), 2, "one line per forgiven poll: {lines:?}");
        for (forgiven, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("{} of ", forgiven + 1)), "{line}");
            assert!(line.contains(&Grace::Write.retries().to_string()), "{line}");
        }
        assert_eq!(clock.slept(), vec![GRACE_BACKOFF; 2]);
        Ok(())
    }

    /// A poll that settles first time narrates nothing: the debug channel carries steps
    /// that are worth a line, not a line per poll of a 4096-block write.
    #[test]
    fn a_poll_that_settles_narrates_nothing() -> Result<()> {
        let dev = MockTransport::new(gadget()).expecting(getstatus(), idle());
        let clock = RecordingClock::new();
        let mut said = Vec::new();
        let mut sink = |progress: Progress| said.push(progress);
        block_on(poll_until_ready_narrated(&dev, &clock, 0, Grace::Write, &mut sink))?;
        assert!(said.is_empty(), "{said:?}");
        Ok(())
    }

    /// The primitives the erase close-out and the release discipline need exist and put the
    /// right bytes on the wire.
    #[test]
    fn abort_clr_status_and_release_are_callable_primitives() -> Result<()> {
        let dev = MockTransport::new(gadget())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(class_out(request::ABORT), Reply::Done)
            .expecting(getstatus(), idle())
            .expecting(class_out(request::CLRSTATUS), Reply::Done)
            .expecting(Call::ReleaseInterface(0), Reply::Done);

        block_on(async {
            // The erase close-out shape: ABORT, probe, then ABORT or CLRSTATUS.
            claim(&dev, &info(&[(0, "flash")]), 0).await?;
            abort(&dev, 0).await?;
            let status = get_status(&dev, 0).await?;
            assert_eq!(status.state, State::DfuIdle);
            clr_status(&dev, 0).await?;
            release(&dev, 0).await
        })?;
        verified(&dev)?;

        // Releasing an unclaimed interface is Ok(()), which is what
        // makes a defensive release on an error path free.
        let fresh = MockTransport::new(gadget());
        block_on(release(&fresh, 0))?;
        verified(&fresh)?;
        Ok(())
    }

    #[test]
    fn make_idle_bails_on_the_first_unreadable_status() -> Result<()> {
        // An unreadable status is a wedged EP0. More 5 s timeouts on
        // ABORTs that also hang help nobody — the caller's USB reset is the fix.
        let dev = MockTransport::new(gadget()).expecting(getstatus(), Reply::Fail(wedged()));

        let Err(Error::Usb(err)) = block_on(make_idle(&dev, 0)) else {
            return Err(Error::Protocol("the transport error must surface".into()));
        };
        assert_eq!(*err.kind(), UsbErrorKind::Timeout);
        assert_eq!(dev.calls().len(), 1, "no ABORT after an unreadable status");
        Ok(())
    }

    #[test]
    fn make_idle_does_not_wait_between_rounds() -> Result<()> {
        // Structural: `make_idle` takes no clock, so it cannot sleep. The C does not
        // either (`dfu.c:115-133`) — the device answers or it does not.
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::UploadIdle)))
            .expecting(class_out(request::ABORT), Reply::Done)
            .expecting(getstatus(), idle());
        block_on(make_idle(&dev, 0))?;
        assert!(dev.calls().iter().all(|call| call.timeout != Some(GRACE_BACKOFF)));
        Ok(())
    }

    #[test]
    fn dfu_poll_states_and_grace() -> Result<()> {
        // Busy states sleep the device's pace; a settled state returns it.
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 40, State::DnBusy)))
            .expecting(getstatus(), Reply::Data(status_bytes(0, 60, State::Manifest)))
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::DnloadIdle)));
        let clock = RecordingClock::new();
        let settled = block_on(poll_until_ready(&dev, &clock, 0, Grace::None))?;
        verified(&dev)?;
        assert_eq!(settled.state, State::DnloadIdle);
        assert_eq!(
            clock.slept(),
            vec![Duration::from_millis(40), Duration::from_millis(60)]
        );

        // A bad bStatus is a protocol failure that names the DFU status.
        let failed =
            MockTransport::new(gadget()).expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)));
        let clock = RecordingClock::new();
        let Err(Error::Protocol(message)) = block_on(poll_until_ready(&failed, &clock, 0, Grace::None)) else {
            return Err(Error::Protocol("a non-zero bStatus must fail".into()));
        };
        assert!(message.contains("errSTALLEDPKT"), "{message}");
        assert!(clock.slept().is_empty(), "a failed status is not waited on");
        Ok(())
    }

    #[test]
    fn poll_grace_forgives_consecutive_silence_and_backs_off() -> Result<()> {
        // Grace::Write forgives 12. Twelve lost polls, then a good one, is a success —
        // and each lost poll costs exactly one 500 ms backoff.
        let mut dev = MockTransport::new(gadget());
        for _ in 0..Grace::Write.retries() {
            dev = dev.expecting(getstatus(), Reply::Fail(wedged()));
        }
        dev = dev.expecting(getstatus(), idle());
        let clock = RecordingClock::new();

        block_on(poll_until_ready(&dev, &clock, 0, Grace::Write))?;
        verified(&dev)?;
        assert_eq!(clock.slept(), vec![GRACE_BACKOFF; Grace::Write.retries()]);

        // One more consecutive failure than the grace allows propagates the transport
        // error itself, not a rewritten one.
        let mut dev = MockTransport::new(gadget());
        for _ in 0..=Grace::Write.retries() {
            dev = dev.expecting(getstatus(), Reply::Fail(wedged()));
        }
        let clock = RecordingClock::new();
        let Err(Error::Usb(err)) = block_on(poll_until_ready(&dev, &clock, 0, Grace::Write)) else {
            return Err(Error::Protocol(
                "an exhausted grace propagates the transport error".into(),
            ));
        };
        assert_eq!(*err.kind(), UsbErrorKind::Timeout);
        assert_eq!(err.timeout(), Some(CONTROL_TIMEOUT), "the pipe context survives");
        Ok(())
    }

    #[test]
    fn poll_grace_counts_consecutive_failures_only() -> Result<()> {
        // The counter resets on any success. Grace 12 therefore survives
        // 12 + 12 losses as long as a poll lands between them.
        let mut dev = MockTransport::new(gadget());
        for _ in 0..Grace::Write.retries() {
            dev = dev.expecting(getstatus(), Reply::Fail(wedged()));
        }
        dev = dev.expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::Manifest)));
        for _ in 0..Grace::Write.retries() {
            dev = dev.expecting(getstatus(), Reply::Fail(wedged()));
        }
        dev = dev.expecting(getstatus(), idle());
        let clock = RecordingClock::new();

        block_on(poll_until_ready(&dev, &clock, 0, Grace::Write))?;
        verified(&dev)?;
        assert_eq!(
            clock.slept().len(),
            Grace::Write.retries() * 2 + 1,
            "one grace backoff per loss, plus the busy poll's own floor"
        );
        // The extra wait is the `BUSY_POLL_FLOOR` under the `dfuMANIFEST` reply, whose
        // `bwPollTimeout` is 0. Everything else is `GRACE_BACKOFF`.
        assert_eq!(clock.slept().iter().filter(|wait| **wait == BUSY_POLL_FLOOR).count(), 1);
        Ok(())
    }

    /// A busy device that names no poll timeout does not get a hot loop.
    ///
    /// `bwPollTimeout` 0 while busy means "ask again now", and the C obliges literally
    /// (`libtdfu/src/dfu/dfu.c:167-168` sleeps only when the field is non-zero) — up to
    /// [`POLL_ROUNDS`] back-to-back `GETSTATUS` requests at an EP0 that is busy because
    /// the loader is flushing to flash. Every one of them is a setup packet the device
    /// answers instead of writing.
    #[test]
    fn poll_floors_the_wait_when_a_busy_device_names_no_timeout() -> Result<()> {
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::DnBusy)))
            .expecting(getstatus(), Reply::Data(status_bytes(0, 0, State::Manifest)))
            .expecting(getstatus(), idle());
        let clock = RecordingClock::new();

        block_on(poll_until_ready(&dev, &clock, 0, Grace::None))?;
        verified(&dev)?;

        assert_eq!(
            clock.slept(),
            vec![BUSY_POLL_FLOOR, BUSY_POLL_FLOOR],
            "every busy round waits at least the floor"
        );
        // And a device that names a real timeout still sets its own pace: the floor is
        // 1 ms, the smallest value the millisecond field can express, so it can never
        // shorten or lengthen one.
        let paced = MockTransport::new(gadget())
            .expecting(getstatus(), Reply::Data(status_bytes(0, 250, State::Manifest)))
            .expecting(getstatus(), idle());
        let clock = RecordingClock::new();
        block_on(poll_until_ready(&paced, &clock, 0, Grace::None))?;
        assert_eq!(clock.slept(), vec![Duration::from_millis(250)]);
        Ok(())
    }

    #[test]
    fn poll_with_no_grace_fails_on_the_first_lost_status() {
        // Reboot MUST be 0 — its post-ZLP poll failing *is* the reset
        // happening. Anything that forgives one poll breaks reboot.
        let dev = MockTransport::new(gadget()).expecting(getstatus(), Reply::Fail(wedged()));
        let clock = RecordingClock::new();
        assert!(matches!(
            block_on(poll_until_ready(&dev, &clock, 0, Grace::None)),
            Err(Error::Usb(_))
        ));
        assert_eq!(dev.calls().len(), 1);
        assert!(clock.slept().is_empty(), "no backoff when nothing is forgiven");
    }

    #[test]
    fn dfu_grace_constants() {
        // `dfu.c:186-187`: 36 for erase and the write's manifest, 12 for
        // a per-block write poll, 0 everywhere else.
        assert_eq!(Grace::Erase.retries(), 36);
        assert_eq!(Grace::Write.retries(), 12);
        assert_eq!(Grace::None.retries(), 0);
        assert_eq!(GRACE_BACKOFF, Duration::from_millis(500));
        assert_eq!(CONTROL_TIMEOUT, Duration::from_secs(5));
        assert_eq!(POLL_ROUNDS, 1000);
        assert_eq!(MAKE_IDLE_ROUNDS, 3);
        assert_eq!(POST_RESET_SETTLE, Duration::from_millis(1500));
        assert_eq!(BLOCK0_ATTEMPTS, 2);
    }

    #[test]
    fn poll_is_bounded_by_the_round_count() -> Result<()> {
        let mut dev = MockTransport::new(gadget());
        for _ in 0..POLL_ROUNDS {
            dev = dev.expecting(getstatus(), Reply::Data(status_bytes(0, 1, State::Manifest)));
        }
        let clock = RecordingClock::new();

        let Err(Error::Protocol(message)) = block_on(poll_until_ready(&dev, &clock, 0, Grace::Erase)) else {
            return Err(Error::Protocol("a device that never settles must fail".into()));
        };
        verified(&dev)?;
        assert!(message.contains("dfuMANIFEST"), "{message}");
        assert_eq!(dev.calls().len(), POLL_ROUNDS);
        Ok(())
    }

    #[test]
    fn dfu_dnload_timeout_30s() -> Result<()> {
        // A DNLOAD data block gets 30 s, and so does the zero-length
        // end-of-transfer trigger — the manifest is where the final flush runs.
        // Everything else keeps 5 s.
        let dev = MockTransport::new(gadget())
            .expecting(
                Call::ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: request::DNLOAD,
                    value: 0,
                    index: 0,
                    data: vec![0xAA, 0xBB],
                },
                Reply::Done,
            )
            .expecting(
                Call::ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: request::DNLOAD,
                    value: 1,
                    index: 0,
                    data: Vec::new(),
                },
                Reply::Done,
            )
            .expecting(getstatus(), idle())
            .expecting(
                Call::ControlIn {
                    control_type: ControlType::Class,
                    recipient: Recipient::Interface,
                    request: request::UPLOAD,
                    value: 0,
                    index: 0,
                    len: 4096,
                },
                Reply::Data(vec![0xFF; 16]),
            );

        block_on(async {
            dnload(&dev, 0, 0, &[0xAA, 0xBB]).await?;
            dnload(&dev, 0, 1, &[]).await?;
            get_status(&dev, 0).await?;
            let short = upload(&dev, 0, 0, 4096).await?;
            // A short block is the end of an upload, not an error.
            assert_eq!(short.len(), 16);
            Ok::<(), Error>(())
        })?;
        verified(&dev)?;

        assert_eq!(
            timeouts(&dev.calls()),
            vec![
                Some(DNLOAD_TIMEOUT),
                Some(DNLOAD_TIMEOUT),
                Some(CONTROL_TIMEOUT),
                Some(CONTROL_TIMEOUT)
            ]
        );
        assert_eq!(DNLOAD_TIMEOUT, Duration::from_secs(30));
        Ok(())
    }

    #[test]
    fn dfu_claim_sets_config_first() -> Result<()> {
        // Configuration, then claim, then SET_INTERFACE — the driverless
        // gadget often has no configuration set and claiming without one fails.
        let dev = MockTransport::new(gadget())
            .expecting(Call::SetConfiguration(1), Reply::Done)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 1 }, Reply::Done);

        block_on(claim(&dev, &info(&[(0, "flash"), (1, "erase")]), 1))?;
        verified(&dev)?;
        assert_eq!(
            dev.calls().into_iter().map(|call| call.call).collect::<Vec<_>>(),
            vec![
                Call::SetConfiguration(1),
                Call::ClaimInterface(InterfaceSpec::control_only(0)),
                Call::SetAltSetting { interface: 0, alt: 1 },
            ]
        );
        Ok(())
    }

    #[test]
    fn dfu_claim_sets_the_configuration_once() -> Result<()> {
        // A device already in the configuration the descriptor names gets no
        // SET_CONFIGURATION at all — the two extra requests a differential USB capture
        // found.
        let dev = MockTransport::new(gadget())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 0 }, Reply::Done);

        block_on(claim(&dev, &info(&[(0, "flash"), (1, "erase")]), 0))?;
        verified(&dev)?;
        assert!(
            !dev.calls()
                .iter()
                .any(|call| matches!(call.call, Call::SetConfiguration(_))),
            "already configured"
        );

        // A device in the *wrong* configuration is still set.
        let dev = MockTransport::new(gadget())
            .configured(2)
            .expecting(Call::SetConfiguration(1), Reply::Done)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done);
        block_on(claim(&dev, &info(&[(0, "flash")]), 0))?;
        verified(&dev)?;
        Ok(())
    }

    #[test]
    fn dfu_claim_tolerates_a_busy_set_configuration_and_nothing_else() -> Result<()> {
        // A1. `EBUSY` means the configuration is already in force, which the C singles
        // out at `libtdfu/src/usb/device.c:336`; it is not a failure and the claim
        // proceeds.
        let busy = MockTransport::new(gadget())
            .expecting(
                Call::SetConfiguration(1),
                Reply::Fail(UsbError::new(UsbErrorKind::Busy, Pipe::Device)),
            )
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done);
        block_on(claim(&busy, &info(&[(0, "flash")]), 0))?;
        verified(&busy)?;

        // Anything else propagates, and the claim never goes out over a configuration
        // that did not take. The C logs and claims anyway (`device.c:337-338`), which
        // throws away the error that says why.
        let refused = MockTransport::new(gadget()).expecting(
            Call::SetConfiguration(1),
            Reply::Fail(UsbError::new(UsbErrorKind::Fault, Pipe::Device)),
        );
        let Err(Error::Usb(error)) = block_on(claim(&refused, &info(&[(0, "flash")]), 0)) else {
            return Err(Error::Protocol(
                "a non-Busy SET_CONFIGURATION failure must propagate".to_owned(),
            ));
        };
        assert_eq!(*error.kind(), UsbErrorKind::Fault, "and keep its own kind");
        assert!(
            !refused
                .calls()
                .iter()
                .any(|call| matches!(call.call, Call::ClaimInterface(_))),
            "the claim must not go out over a configuration that did not take"
        );
        verified(&refused)?;
        Ok(())
    }

    #[test]
    fn dfu_set_interface_alt0_rule() -> Result<()> {
        // Branch one: single alt, alt 0 — no SET_INTERFACE. USB 9.4.10 lets a
        // single-alt interface stall it, and over WebUSB that stall wedges EP0 for
        // every later request.
        let single = MockTransport::new(gadget())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done);
        block_on(claim(&single, &info(&[(0, "flash")]), 0))?;
        verified(&single)?;
        assert!(
            !single
                .calls()
                .iter()
                .any(|call| matches!(call.call, Call::SetAltSetting { .. }))
        );

        // Branch two: multi-alt, alt 0 — SET_INTERFACE goes out. Skipping it after an
        // erase leaves the `erase` alt live and the next image's first block lands
        // there ("dfu erase: bad token", T40XP).
        let multi = MockTransport::new(gadget())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 0 }, Reply::Done);
        block_on(claim(&multi, &info(&[(0, "flash"), (1, "erase"), (2, "reboot")]), 0))?;
        verified(&multi)?;

        // And a non-zero alt always gets it, single-alt device or not.
        let odd = MockTransport::new(gadget())
            .configured(1)
            .expecting(Call::ClaimInterface(InterfaceSpec::control_only(0)), Reply::Done)
            .expecting(Call::SetAltSetting { interface: 0, alt: 3 }, Reply::Done);
        block_on(claim(&odd, &info(&[(3, "flash")]), 3))?;
        verified(&odd)?;
        Ok(())
    }

    #[test]
    fn dfu_open_access_denied_is_distinct() -> Result<()> {
        // An OS refusal is not "no DFU interface" and not something a bus
        // reset can clear. It keeps its kind, and `is_recoverable` says no, so the
        // retry never buries the one message that tells the user to add a udev rule.
        let denied = UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device);
        let dev = MockTransport::new(gadget()).configured(1).expecting(
            Call::ClaimInterface(InterfaceSpec::control_only(0)),
            Reply::Fail(denied),
        );

        let Err(err) = block_on(claim(&dev, &info(&[(0, "flash")]), 0)) else {
            return Err(Error::Protocol("a refused claim must fail".into()));
        };
        assert!(matches!(&err, Error::Usb(usb) if *usb.kind() == UsbErrorKind::AccessDenied));
        assert!(!matches!(err, Error::NotDfu));
        assert!(!err.is_recoverable(), "must not retry an access failure");
        Ok(())
    }

    #[test]
    fn dfu_reset_retry_once() -> Result<()> {
        // One recoverable failure, one reset, one retry — and the retry
        // is audible.
        let dev = MockTransport::new(gadget()).expecting(Call::Reset, Reply::Done);
        let clock = RecordingClock::new();
        let attempts = RefCell::new(Vec::new());
        let notes = RefCell::new(Vec::new());
        let mut sink = |progress: Progress| notes.borrow_mut().push(progress);

        let value = block_on(reset_and_retry_once(
            &dev,
            &clock,
            &mut sink,
            async |attempt: Attempt, _: ProgressSink<'_>| {
                attempts.borrow_mut().push(attempt);
                if attempt.is_retry() {
                    Ok(42)
                } else {
                    Err(Error::Usb(wedged()))
                }
            },
        ))?;

        assert_eq!(value, 42);
        assert_eq!(
            *attempts.borrow(),
            vec![
                Attempt::first(),
                Attempt {
                    index: 1,
                    reason: RetryReason::BusReset
                }
            ]
        );
        assert_eq!(
            clock.slept(),
            vec![POST_RESET_SETTLE],
            "the re-enumeration wait after the reset"
        );
        let notes = notes.borrow();
        assert_eq!(notes.len(), 1, "a silent retry is a retry nobody can report");
        assert!(
            matches!(&notes[0], Progress::Note(text) if text.contains("USB-reset")),
            "{notes:?}"
        );
        Ok(())
    }

    #[test]
    fn dfu_verify_never_reset_retried() -> Result<()> {
        // A data mismatch is final: no reset, no second attempt, and the error the
        // caller sees is the one that happened.
        let dev = MockTransport::new(gadget());
        let clock = RecordingClock::new();
        let calls = Cell::new(0);
        let mut sink = crate::progress::sink_ignore();

        let Err(Error::Verify { offset, .. }) = block_on(reset_and_retry_once(
            &dev,
            &clock,
            &mut sink,
            async |_: Attempt, _: ProgressSink<'_>| {
                calls.set(calls.get() + 1);
                Err::<(), _>(Error::Verify {
                    offset: 0x40,
                    expected: 0xAA,
                    actual: Some(0xFF),
                })
            },
        )) else {
            return Err(Error::Protocol("a verify mismatch must be final".into()));
        };

        assert_eq!(offset, 0x40);
        assert_eq!(calls.get(), 1, "exactly one attempt");
        assert!(dev.calls().is_empty(), "no USB reset was issued");
        assert!(clock.slept().is_empty());
        Ok(())
    }

    #[test]
    fn dfu_android_no_reset_reopen() -> Result<()> {
        // On Android and WebUSB the reset is Unsupported — the fd is
        // owned by Java and a close-and-reopen wedges the gadget's controller for
        // minutes. This is the host half of that rule (the transport half is the
        // backend's, and is what the mock is standing in for here): a reset that
        // cannot happen means no retry, and the C gates its retry on the reset having
        // happened (`dfu.c:996`). The recovery's own failure must not become the
        // reported cause.
        let unsupported = UsbError::new(UsbErrorKind::Unsupported, Pipe::Device);
        let dev = MockTransport::new(gadget()).expecting(Call::Reset, Reply::Fail(unsupported));
        let clock = RecordingClock::new();
        let calls = Cell::new(0);
        let notes = RefCell::new(Vec::new());
        let mut sink = |progress: Progress| notes.borrow_mut().push(progress);

        let Err(Error::Usb(err)) = block_on(reset_and_retry_once(
            &dev,
            &clock,
            &mut sink,
            async |_: Attempt, _: ProgressSink<'_>| {
                calls.set(calls.get() + 1);
                Err::<(), _>(Error::Usb(wedged()))
            },
        )) else {
            return Err(Error::Protocol("the operation's own error must survive".into()));
        };

        assert_eq!(*err.kind(), UsbErrorKind::Timeout, "not the reset's Unsupported");
        assert_eq!(calls.get(), 1, "nothing was retried");
        assert!(clock.slept().is_empty(), "and nothing waited for a re-enumeration");
        assert_eq!(notes.borrow().len(), 1, "but the user is told why");
        Ok(())
    }

    #[test]
    fn dfu_block0_retry_only() -> Result<()> {
        // A failure before any block landed gets make_idle and one more
        // go from the top.
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), idle())
            .expecting(getstatus(), Reply::Data(status_bytes(0x0F, 0, State::Error)))
            .expecting(class_out(request::CLRSTATUS), Reply::Done)
            .expecting(getstatus(), idle());
        let attempts = RefCell::new(Vec::new());
        let notes = RefCell::new(Vec::new());
        let mut sink = |progress: Progress| notes.borrow_mut().push(progress);

        let value = block_on(retry_stale_block0(
            &dev,
            0,
            &mut sink,
            async |transaction: &Transaction, _: ProgressSink<'_>| {
                attempts.borrow_mut().push(transaction.attempt());
                if transaction.attempt().is_retry() {
                    transaction.first_block_done();
                    Ok(7)
                } else {
                    Err(Error::Usb(wedged()))
                }
            },
        ))?;

        assert_eq!(value, 7);
        assert_eq!(
            attempts.borrow().iter().map(|a| a.reason).collect::<Vec<_>>(),
            vec![RetryReason::First, RetryReason::StaleTransaction]
        );
        verified(&dev)?;
        // Filtered, not counted whole: `make_idle` narrates a `Progress::Debug` per poll
        // and this pin is about the retry the *user* is told about.
        let notes = notes.borrow();
        let notes: Vec<&Progress> = notes
            .iter()
            .filter(|step| !matches!(step, Progress::Debug(_)))
            .collect();
        assert_eq!(notes.len(), 1, "the stale-transaction retry announces itself");
        Ok(())
    }

    #[test]
    fn a_failure_past_the_first_block_is_never_retried() -> Result<()> {
        // The other half of the block 0 retry, and the reason "first block" is a flag and
        // not `block == 0`: at 65536 blocks the C's counter wraps back through 0 and
        // it re-reads a whole 256 MiB chip.
        let dev = MockTransport::new(gadget()).expecting(getstatus(), idle());
        let calls = Cell::new(0);
        let mut sink = crate::progress::sink_ignore();

        let Err(Error::Usb(_)) = block_on(retry_stale_block0(
            &dev,
            0,
            &mut sink,
            async |transaction: &Transaction, _: ProgressSink<'_>| {
                calls.set(calls.get() + 1);
                // The wrapped block number is 0 again; the flag is not.
                transaction.first_block_done();
                Err::<(), _>(Error::Usb(wedged()))
            },
        )) else {
            return Err(Error::Protocol("a mid-stream failure must propagate".into()));
        };

        assert_eq!(calls.get(), 1, "one attempt, no restart from the top");
        verified(&dev)?;
        Ok(())
    }

    #[test]
    fn a_block0_retry_that_fails_again_reports_the_second_failure() -> Result<()> {
        let dev = MockTransport::new(gadget())
            .expecting(getstatus(), idle())
            .expecting(getstatus(), idle());
        let calls = Cell::new(0);
        let mut sink = crate::progress::sink_ignore();

        let Err(Error::Protocol(message)) = block_on(retry_stale_block0(
            &dev,
            0,
            &mut sink,
            async |_: &Transaction, _: ProgressSink<'_>| {
                calls.set(calls.get() + 1);
                Err::<(), _>(Error::Protocol(format!("attempt {}", calls.get())))
            },
        )) else {
            return Err(Error::Protocol("the second failure must surface".into()));
        };

        assert_eq!(calls.get(), BLOCK0_ATTEMPTS);
        assert_eq!(message, "attempt 2", "the last error, not the first");
        verified(&dev)?;
        Ok(())
    }

    #[test]
    fn a_device_that_will_not_go_idle_is_not_block0_retried() -> Result<()> {
        // make_idle failing is a wedged EP0, which the bus reset answers — not
        // another transfer attempt.
        let dev = MockTransport::new(gadget()).expecting(getstatus(), Reply::Fail(wedged()));
        let calls = Cell::new(0);
        let mut sink = crate::progress::sink_ignore();

        let Err(Error::Usb(_)) = block_on(retry_stale_block0(
            &dev,
            0,
            &mut sink,
            async |_: &Transaction, _: ProgressSink<'_>| {
                calls.set(calls.get() + 1);
                Ok::<(), Error>(())
            },
        )) else {
            return Err(Error::Protocol("make_idle's error must propagate".into()));
        };
        assert_eq!(calls.get(), 0, "the transfer never started");
        Ok(())
    }

    #[test]
    fn the_status_table_is_dfu_1_1s() {
        // These names are what an operator reads instead of "protocol error", so they
        // have to be the class's own spelling (DFU 1.1 §6.1.2, table 6.1).
        const NAMES: [&str; 16] = [
            "OK",
            "errTARGET",
            "errFILE",
            "errWRITE",
            "errERASE",
            "errCHECK_ERASED",
            "errPROG",
            "errVERIFY",
            "errADDRESS",
            "errNOTDONE",
            "errFIRMWARE",
            "errVENDOR",
            "errUSBR",
            "errPOR",
            "errUNKNOWN",
            "errSTALLEDPKT",
        ];
        for (code, name) in NAMES.iter().enumerate() {
            let code = u8::try_from(code).unwrap_or(0xFF);
            assert_eq!(status_name(code), *name, "bStatus {code}");
        }
        assert_eq!(status_name(16), "unknown status");
        assert_eq!(status_name(0xFF), "unknown status");
    }

    #[test]
    fn the_state_table_round_trips_every_byte() {
        for code in 0..=u8::MAX {
            assert_eq!(State::from_code(code).code(), code);
        }
        assert_eq!(State::from_code(10), State::Error);
        assert_eq!(State::DfuIdle.to_string(), "dfuIDLE");
        assert_eq!(State::Other(0x42).to_string(), "state 66");
        // The busy set, and nothing else.
        for state in (0..=u8::MAX).map(State::from_code) {
            assert_eq!(
                state.is_busy(),
                matches!(state, State::DnBusy | State::Manifest),
                "{state} classified wrongly"
            );
        }
    }
}
