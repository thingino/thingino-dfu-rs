//! An emulated U-Boot DFU gadget: a **device model**, not a script.
//!
//! Behind `#[cfg(any(test, feature = "mock"))]`, beside
//! [`MockTransport`](crate::mock::MockTransport) and deliberately unlike it.
//! `MockTransport` replays a queue of expected calls; [`FakeGadget`] runs the state
//! machine in `drivers/usb/gadget/f_dfu.c` and the transaction model in
//! `drivers/dfu/dfu.c` and answers whatever those two decide. An operation tested
//! against the mock proves it sends what its author expected; an operation tested
//! against this proves it survives what the device actually does.
//!
//! # The authority is `f_dfu.c`, never the host
//!
//! That is the rule here, and an earlier emulator is the
//! record of what it costs when the rule is not followed: **a defect in a
//! test double is worse than a defect in code, because it silently removes coverage
//! everywhere downstream.** That emulator carried three such defects,
//! and the worst of them made the block 0 retry's entire
//! recovery class unfalsifiable — deleting the host's `CLRSTATUS` branch passed all 448
//! tests. Every behaviour in [`machine`] therefore carries the `file:line` it was read
//! from, and the three defects are dead here by construction:
//!
//! * **the medium offset.** `dfu_transaction_cleanup` zeroes `dfu->offset`
//!   (`dfu.c:294`), so every fresh transaction restarts at the beginning of the medium.
//!   A `Vec<u8>` medium plus a per-entity `offset` makes a retry after a partial write
//!   observable at byte level, which the earlier emulator could not express at all.
//! * **`transfer_size`.** [`GadgetConfig::transfer_size`] is the *only* source
//!   of `wTransferSize`: it drives the served functional descriptor, the cached
//!   [`DeviceDescriptors`], and the request clamp, because in `f_dfu.c` they are one
//!   `#define` (`f_dfu.h:24`, `f_dfu.c:67`, `:342`).
//! * **the alt and the configuration.** `SET_CONFIGURATION` runs `dfu_set_alt`
//!   with alt 0 for every interface (USB 9.4.7, `f_dfu.c:823-841`) and `reset()` returns
//!   the device to the unconfigured Default state (USB 9.1.1.5).
//!
//! And **"a new transaction" is an explicit flag, never `block == 0`**: DFU's block
//! number is 16 bits and wraps through 0 every 256 MiB (`dfu.c:392-406`), which is
//! exactly a T40XP whole-chip read.
//!
//! # What it models that the ops need
//!
//! * the `dfuERROR` refusal class — `GETSTATUS`, `GETSTATE`, `CLRSTATUS`, and a stall
//!   for everything else including `ABORT` (`f_dfu.c:593-621`);
//! * `dfuIDLE` having **no** `CLRSTATUS` case, so a stray one stalls and *creates*
//!   `dfuERROR` (`f_dfu.c:333-400`);
//! * the download/upload block machine with wrong-sequence detection, in **both loader
//!   generations** ([`Loader`]);
//! * `dfuMANIFEST` held while the deferred flush is pending, advanced by `GETSTATUS`
//!   (`f_dfu.c:511-549`);
//! * the 2 MiB `dfu_bufsiz` drain and the EP0 silence it causes
//!   ([`GadgetConfig::flush_silence_polls`]);
//! * token-gated `erase` and `reboot` virt alts, armed in the write and executed in the
//!   flush (`arch/mips/mach-xburst/dfu.c:203-296`);
//! * fault injection: [`Fault`] at a [`When`], [`FakeGadget::silence_ep0`] and
//!   [`FakeGadget::wedge`].
//!
//! # Trait obligations
//!
//! The three an audit pinned on `MockTransport` hold here
//! too: [`release_interface`](LocalUsbTransport::release_interface) is idempotent,
//! transfers on undeclared endpoints refuse with
//! [`NotClaimed`](UsbErrorKind::NotClaimed), and an over-long answer is the device's
//! business — the host truncates. A control transfer does **not** require a claim, which
//! is what the real EP0 does and what `MockTransport` does.

mod descriptors;
pub mod machine;

#[cfg(test)]
mod tests;

use core::cell::RefCell;
use core::time::Duration;

pub use machine::{DfuState, request};

use crate::error::{Pipe, UsbError, UsbErrorKind};
use crate::transport::LocalUsbTransport;
use crate::types::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Direction, InterfaceSpec, Recipient,
};
use machine::{Answer, Ctrl, Device};

/// `USB_REQ_GET_DESCRIPTOR` (USB 2.0 §9.4.3).
const GET_DESCRIPTOR: u8 = 0x06;

/// `DFU_USB_BUFSIZ` (`f_dfu.h:24`) and `wTransferSize` — one number on the device.
///
/// It cannot be raised. DFU rides EP0 and Linux usbfs `proc_control()`
/// rejects `wLength > PAGE_SIZE`; a 32 KiB loader was built and its first `DNLOAD`
/// failed.
pub const DEFAULT_TRANSFER_SIZE: u16 = 4096;

/// `USB_BUFSIZ` (`composite.c:17`), the control request buffer. Equal to
/// [`DEFAULT_TRANSFER_SIZE`] on the device; separate here because
/// [`GadgetConfig::transfer_size`] is a knob and this is not the same `#define`.
pub const DEFAULT_USB_BUFSIZ: u16 = 4096;

/// `dfu_bufsiz`, set to `0x200000` by the loader's `board_late_init`
/// (`arch/mips/mach-xburst/dfu.c:345`). The drain at each boundary is what
/// the 30 s `DNLOAD` timeout rides out.
pub const DEFAULT_BUFFER_SIZE: usize = 2 * 1024 * 1024;

/// `xburst_erase_poll_timeout` (`arch/mips/mach-xburst/dfu.c:129-132`): the pace a virt
/// entity asks the host to re-poll at while its flush runs.
pub const VIRT_POLL_TIMEOUT_MS: u32 = 500;

/// The boot flash of the bench T32LQ: 16 MiB of SPI-NOR.
pub const T32LQ_FLASH_SIZE: u64 = 16 * 1024 * 1024;

/// What sits behind one alternate setting.
///
/// The configuration descriptor cannot tell them apart — `dfu_prepare_function` emits a
/// nine-byte interface descriptor per alt from one template (`f_dfu.c:713-727`), and the
/// only fields that vary are `bAlternateSetting` and `iInterface`: the class, subclass,
/// protocol and endpoint count are identical, and **nothing in those nine bytes says
/// what is behind the alt**. So an `erase` alt and a 16 MiB flash alt are
/// indistinguishable until the `iInterface` string is read, which is why the host selects
/// them by **name** and why the `iInterface` string read is not
/// optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AltKind {
    /// A real medium: `sf`, `mtd` or `mmc`. Alt 0 is always the boot flash on
    /// every shipped loader.
    ///
    /// **Reading costs nothing.** The medium is stored as the bytes actually written;
    /// everything past them reads as `0xFF`, so a `size` of 256 MiB — a T40XP whole-chip
    /// read, the case the streaming read exists for — allocates nothing until
    /// something writes to it. A *write* does allocate up to its highest byte.
    Flash {
        /// How many bytes the entity spans, which is what `get_medium_size` reports at
        /// the start of an upload (`dfu.c:338`).
        size: u64,
    },
    /// `virt 0`: downloading [`ERASE_TOKEN`] wipes the whole boot flash
    /// (`arch/mips/mach-xburst/dfu.c:217-225`).
    Erase,
    /// `virt 1`: downloading [`REBOOT_TOKEN`] calls `do_reset()` from the manifest flush
    /// (`arch/mips/mach-xburst/dfu.c:206-216`, `:260-268`).
    Reboot,
}

/// The token that arms an erase (`arch/mips/mach-xburst/dfu.c:108`).
pub const ERASE_TOKEN: &[u8] = machine::ERASE_TOKEN;
/// The token that arms a reboot (`arch/mips/mach-xburst/dfu.c:109`).
pub const REBOOT_TOKEN: &[u8] = machine::REBOOT_TOKEN;

/// One alternate setting: the name the host matches on, and what is behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltConfig {
    /// `iInterface`'s string, which is the entity name from `dfu_alt_info`
    /// (`f_dfu.c:693-696`).
    pub name: String,
    /// The backend behind it.
    pub kind: AltKind,
}

impl AltConfig {
    /// A named alt over a medium of `size` bytes.
    #[must_use]
    pub fn flash(name: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            kind: AltKind::Flash { size },
        }
    }

    /// The `erase` virt alt.
    #[must_use]
    pub fn erase() -> Self {
        Self {
            name: "erase".to_owned(),
            kind: AltKind::Erase,
        }
    }

    /// The `reboot` virt alt.
    #[must_use]
    pub fn reboot() -> Self {
        Self {
            name: "reboot".to_owned(),
            kind: AltKind::Reboot,
        }
    }
}

/// Which generation of loader this gadget is.
///
/// The difference is one function call — `f_dfu_abort_transaction` at `f_dfu.c:367`,
/// `:466`, `:574`, `:610` and `:834` — and it decides whether the entity's block
/// sequence counter survives `DFU_ABORT`, `DFU_CLRSTATUS`, an alt switch and (through
/// the `SET_CONFIGURATION` that follows it) a bus reset. It is the whole of the
/// stale-transaction case and of the erase close-out's two branches, and
/// both were seen on the bench: a fixed T40XP logged zero `Wrong sequence number` lines
/// and an old T23 logged exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// Carries u-boot `3d4848fe0dc`: the entity is cleaned whenever the state machine
    /// returns to `dfuIDLE`.
    Fixed,
    /// Older: the entity is cleaned only by a completed transaction or by the in-band
    /// sequence-mismatch refusal itself.
    Legacy,
}

/// Everything about the emulated device that a test may vary.
///
/// `#[non_exhaustive]`: build one with [`GadgetConfig::t32lq`] (the bench capture) or
/// [`GadgetConfig::new`] and adjust it with the `with_*` setters, so a field added later
/// cannot break a caller.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GadgetConfig {
    /// The alternate settings, in descriptor order. Alt 0 is the boot flash.
    pub alts: Vec<AltConfig>,
    /// `wTransferSize`, and the clamp every request length passes through.
    pub transfer_size: u16,
    /// `USB_BUFSIZ`: how much an `UPLOAD` lifts off the medium whatever `wLength` says
    /// (`composite.c:17`, `:1029`).
    pub usb_bufsiz: u16,
    /// `dfu_bufsiz`, the entity buffer that drains to flash when it fills.
    pub buffer_size: usize,
    /// Which loader generation.
    pub loader: Loader,
    /// How many `GETSTATUS` answers see the deferred flush still pending — the test
    /// double's stand-in for however long the gadget's main loop takes
    /// (`common/dfu.c:70-88`).
    /// Model note: `manifest_sync`'s own reply already reports
    /// dfuMANIFEST, so the hold this counts starts one GETSTATUS later than a
    /// first reading of the field name suggests.
    pub manifest_hold_polls: usize,
    /// How many control requests EP0 answers nothing to after a buffer drain.
    ///
    /// **Zero by default**, so an ordinary test is not slowed by silence it did not ask
    /// for. Set it to model the 2 MiB stall, which is the reason `Grace::Write`
    /// and `Grace::Erase` exist.
    ///
    /// **It is a request count, not a duration.** The gadget's silence lasts as long as
    /// the chip does; this counts *requests* instead, because the double has no clock.
    /// So a test that drives a grace through it pins how many lost polls the host
    /// forgives — the retry budget — and **not** the deadline the host is working to. The
    /// deadline is pinned where it is written, in `dfu::host`'s constants. Saying a grace
    /// pin needs this knob is true; saying this knob pins the grace is not.
    pub flush_silence_polls: usize,
    /// `f_dfu->poll_timeout` (`f_dfu.c:880`). `DFU_DEFAULT_POLL_TIMEOUT` is **0** on
    /// every shipped loader (`include/dfu.h:121-122`), which makes `f_dfu.c:204-207`
    /// dead code there.
    pub default_poll_timeout_ms: u32,
    /// What a virt entity asks the host to re-poll at during its flush
    /// ([`VIRT_POLL_TIMEOUT_MS`]).
    pub virt_poll_timeout_ms: u32,
    /// `idVendor`.
    pub vendor_id: u16,
    /// `idProduct`. **Never the basis for stage classification**: the
    /// gadget was re-PID'd to the bootrom's `0xC309` in July 2026.
    pub product_id: u16,
    /// `bcdDevice`.
    pub bcd_device: u16,
    /// `bcdDFUVersion` (`f_dfu.c:68`).
    pub bcd_dfu: u16,
    /// The functional descriptor's `bmAttributes` (`f_dfu.c:62-65`).
    pub dfu_attributes: u8,
    /// `wDetachTimeOut` (`f_dfu.c:66`).
    pub detach_timeout: u16,
    /// The configuration descriptor's `bmAttributes`.
    pub bm_attributes: u8,
    /// `bMaxPower`, in 2 mA units.
    pub max_power: u8,
    /// `bConfigurationValue`.
    pub configuration_value: u8,
    /// `iConfiguration`.
    pub iconfiguration: u8,
    /// `bInterfaceNumber` — one interface, several alternate settings.
    pub interface: u8,
    /// The string index of alt 0; alt *n* is at `first_alt_string + n`.
    pub first_alt_string: u8,
    /// `iManufacturer`'s string.
    pub manufacturer_string: String,
    /// `iProduct`'s string.
    pub product_string: String,
    /// `iSerialNumber`'s string — the eFuse chip serial the loader publishes so WebUSB
    /// can persist a permission across the re-enumeration
    /// (`arch/mips/mach-xburst/dfu.c:69-86`).
    pub serial_string: String,
}

impl GadgetConfig {
    /// A gadget with the given alts and every other value at the shipped loader's.
    #[must_use]
    pub fn new(alts: Vec<AltConfig>) -> Self {
        Self {
            alts,
            transfer_size: DEFAULT_TRANSFER_SIZE,
            usb_bufsiz: DEFAULT_USB_BUFSIZ,
            buffer_size: DEFAULT_BUFFER_SIZE,
            loader: Loader::Fixed,
            manifest_hold_polls: 1,
            flush_silence_polls: 0,
            default_poll_timeout_ms: 0,
            virt_poll_timeout_ms: VIRT_POLL_TIMEOUT_MS,
            vendor_id: crate::vid::INGENIC,
            product_id: crate::pid::BOOTROM,
            bcd_device: 0x7EA7,
            bcd_dfu: 0x0110,
            dfu_attributes: 0x0F,
            detach_timeout: 0,
            bm_attributes: 0xC0,
            max_power: 1,
            configuration_value: 1,
            iconfiguration: 2,
            interface: 0,
            first_alt_string: 5,
            manufacturer_string: "Ingenic".to_owned(),
            product_string: "USB download gadget".to_owned(),
            serial_string: "00000000000000000000000000000000".to_owned(),
        }
    }

    /// The bench T32LQ, byte for byte.
    ///
    /// Its device and configuration descriptors are machine-checked against
    /// `crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt` by
    /// `the_default_descriptors_match_the_t32lq_capture`, so a change to the generator
    /// or to any default above fails a test rather than drifting a fixture. The product
    /// string and the three alt names come from the same bench run
    /// (a descriptor sweep of the same unit read `iProduct 2 USB download
    /// gadget; iInterface 5 flash; iInterface 6 erase; iInterface 7 reboot`); the
    /// manufacturer and serial strings are **not** attested by any capture and are
    /// placeholders.
    #[must_use]
    pub fn t32lq() -> Self {
        Self::new(vec![
            AltConfig::flash("flash", T32LQ_FLASH_SIZE),
            AltConfig::erase(),
            AltConfig::reboot(),
        ])
    }

    /// Set `wTransferSize` — which reaches the served descriptor, the cached
    /// descriptors and the request clamp together.
    #[must_use]
    pub const fn with_transfer_size(mut self, size: u16) -> Self {
        self.transfer_size = size;
        self.usb_bufsiz = size;
        self
    }

    /// Set `USB_BUFSIZ` alone, leaving `wTransferSize` where it is.
    ///
    /// They are one number on the shipped loader and two `#define`s in two files
    /// (`f_dfu.h:24`, `composite.c:17`), and they cap different answers — see
    /// [`FakeGadget::truncate`]. [`with_transfer_size`](Self::with_transfer_size) moves
    /// both, because that is what changing `DFU_USB_BUFSIZ` on a real loader does; this
    /// exists so a test can hold them apart and see which one a path is really using.
    #[must_use]
    pub const fn with_usb_bufsiz(mut self, size: u16) -> Self {
        self.usb_bufsiz = size;
        self
    }

    /// Set the entity buffer size — the boundary a drain happens at.
    #[must_use]
    pub const fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Choose the loader generation.
    #[must_use]
    pub const fn with_loader(mut self, loader: Loader) -> Self {
        self.loader = loader;
        self
    }

    /// How many `GETSTATUS` answers report `dfuMANIFEST` before the flush completes.
    #[must_use]
    pub const fn with_manifest_hold_polls(mut self, polls: usize) -> Self {
        self.manifest_hold_polls = polls;
        self
    }

    /// How many control requests EP0 swallows after each buffer drain.
    #[must_use]
    pub const fn with_flush_silence_polls(mut self, polls: usize) -> Self {
        self.flush_silence_polls = polls;
        self
    }

    /// Set `f_dfu->poll_timeout`, which is 0 on every shipped loader.
    #[must_use]
    pub const fn with_default_poll_timeout_ms(mut self, ms: u32) -> Self {
        self.default_poll_timeout_ms = ms;
        self
    }

    /// Set the pace a virt entity asks for during its flush.
    ///
    /// Values above `0xFFFF` are the point of it: `bwPollTimeout` is a **24-bit** field
    /// and every test in an earlier implementation used 250 ms or 500 ms, whose high
    /// byte is zero, so `<< 16` and `>> 16` were indistinguishable.
    #[must_use]
    pub const fn with_virt_poll_timeout_ms(mut self, ms: u32) -> Self {
        self.virt_poll_timeout_ms = ms;
        self
    }

    /// Set `idVendor` and `idProduct`.
    #[must_use]
    pub const fn with_ids(mut self, vendor_id: u16, product_id: u16) -> Self {
        self.vendor_id = vendor_id;
        self.product_id = product_id;
        self
    }
}

/// What a [`Fault`] replaces a request's real answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fault {
    /// The endpoint stalls: [`UsbErrorKind::Stall`].
    Stall,
    /// The deadline expires: [`UsbErrorKind::Timeout`].
    Timeout,
    /// The device is gone: [`UsbErrorKind::NoDevice`].
    NoDevice,
    /// The OS refuses: [`UsbErrorKind::AccessDenied`] — not recoverable, so a
    /// bus reset must never bury it.
    AccessDenied,
    /// The resource is in use: [`UsbErrorKind::Busy`]. It is the one
    /// failure a claim tolerates on `SET_CONFIGURATION`.
    Busy,
    /// The transfer moves fewer bytes than asked for.
    ///
    /// A short control **IN** is not an error — the trait says a read "returns exactly
    /// what the device sent, which may be shorter" — so this truncates the answer. A
    /// short control **OUT** is [`UsbErrorKind::Short`].
    Short {
        /// How many bytes move.
        got: usize,
    },
}

impl Fault {
    /// The error this fault raises on `pipe`, for a call whose data stage is `want`
    /// bytes long.
    ///
    /// # `Short` needs a data stage to be short of
    ///
    /// [`When`] and [`Fault`] are independent, so the pair can name a combination no
    /// wire produces: a `Short` armed on a `SET_CONFIGURATION`, a `SET_INTERFACE`, a
    /// claim, a release or a reset. None of those moves a byte — the first two are
    /// eight-byte setup packets with an empty data stage, the last three are host-side
    /// operations that never reach the bus — so `want` there is 0, and
    /// `Short { got, want: 0 }` is a value a caller's `got < want` arithmetic reads as
    /// nonsense.
    ///
    /// Those sites therefore answer [`Fault`](UsbErrorKind::Fault) — the backend's
    /// "something went wrong that no kind names", which is exactly what this is.
    /// Arming a `Short` there is a test bug, and an honest catch-all is a better answer
    /// to it than a fabricated wire value that reads as a real measurement.
    ///
    /// The same applies to a control transfer whose own data stage is empty: the
    /// manifest's zero-length `DNLOAD` cannot come back short of nothing.
    fn error(self, pipe: Pipe, want: usize, timeout: Option<Duration>) -> UsbError {
        let kind = match self {
            Self::Stall => UsbErrorKind::Stall,
            Self::Timeout => UsbErrorKind::Timeout,
            Self::NoDevice => UsbErrorKind::NoDevice,
            Self::AccessDenied => UsbErrorKind::AccessDenied,
            Self::Busy => UsbErrorKind::Busy,
            Self::Short { got: _ } if want == 0 => UsbErrorKind::Fault,
            Self::Short { got } => UsbErrorKind::Short { got, want },
        };
        let error = UsbError::new(kind, pipe).with_len(want);
        match timeout {
            Some(timeout) => error.with_timeout(timeout),
            None => error,
        }
    }
}

/// Which call a [`Fault`] attaches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum When {
    /// The next control transfer of any kind, descriptor reads included.
    NextControl,
    /// The next `GET_DESCRIPTOR`.
    Descriptor,
    /// The next DFU class request with this `bRequest` (see [`request`]).
    Class(u8),
    /// The next DFU class request with this `bRequest` and this `wValue` — for
    /// `DNLOAD` and `UPLOAD`, the block number.
    ClassBlock(u8, u16),
    /// The next `SET_INTERFACE`.
    SetAlt,
    /// The next `SET_CONFIGURATION`.
    SetConfiguration,
    /// The next interface claim.
    Claim,
    /// The next interface release.
    Release,
    /// The next USB reset.
    Reset,
    /// The next bulk transfer, either direction.
    ///
    /// The DFU gadget declares `bNumEndpoints = 0` (`f_dfu.c:721`), so a bulk transfer
    /// against it is always the caller's bug and always answers
    /// [`NotClaimed`](UsbErrorKind::NotClaimed). This exists so that the *earlier*
    /// refusals — a device that has left the bus, an armed fault — reach it as well,
    /// rather than the caller's bug hiding them.
    Bulk,
    /// The next `CLEAR_FEATURE(ENDPOINT_HALT)`.
    ClearHalt,
}

/// One armed fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Injection {
    when: When,
    fault: Fault,
    times: usize,
}

/// Where a call happened, for matching a [`When`].
#[derive(Debug, Clone, Copy)]
enum Site {
    Control {
        class: bool,
        descriptor: bool,
        request: u8,
        value: u16,
    },
    SetAlt,
    SetConfiguration,
    Claim,
    Release,
    Reset,
    Bulk,
    ClearHalt,
}

impl When {
    fn matches(self, site: Site) -> bool {
        match (self, site) {
            (Self::NextControl, Site::Control { .. })
            | (Self::SetAlt, Site::SetAlt)
            | (Self::SetConfiguration, Site::SetConfiguration)
            | (Self::Claim, Site::Claim)
            | (Self::Release, Site::Release)
            | (Self::Reset, Site::Reset)
            | (Self::Bulk, Site::Bulk)
            | (Self::ClearHalt, Site::ClearHalt) => true,
            (Self::Descriptor, Site::Control { descriptor, .. }) => descriptor,
            (Self::Class(want), Site::Control { class, request, .. }) => class && want == request,
            (
                Self::ClassBlock(want, block),
                Site::Control {
                    class, request, value, ..
                },
            ) => class && want == request && block == value,
            _ => false,
        }
    }
}

/// One thing the host did to the device, in order.
///
/// The data stage of a control OUT is recorded as a **length**, not as bytes: a 16 MiB
/// write is 4097 blocks, and keeping them all would make the log larger than the medium.
/// What was written is asserted through [`FakeGadget::medium`], which is the honest
/// surface for it anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A control transfer that read.
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
    /// A control transfer that wrote.
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
        /// How many bytes the data stage carried.
        len: usize,
    },
    /// A bulk IN was attempted. The DFU gadget has no bulk endpoint.
    BulkIn {
        /// Bytes asked for.
        len: usize,
    },
    /// A bulk OUT was attempted.
    BulkOut {
        /// Bytes offered.
        len: usize,
    },
    /// `SET_CONFIGURATION`.
    SetConfiguration(u8),
    /// An interface claim.
    ClaimInterface(InterfaceSpec),
    /// An interface release.
    ReleaseInterface(u8),
    /// `SET_INTERFACE`.
    SetAltSetting {
        /// `bInterfaceNumber`.
        interface: u8,
        /// `bAlternateSetting`.
        alt: u8,
    },
    /// `CLEAR_FEATURE(ENDPOINT_HALT)`.
    ClearHalt(BulkEndpoint),
    /// A USB bus reset.
    Reset,
}

impl Event {
    /// `(bRequest, wValue)` if this was a DFU class request, else `None`.
    ///
    /// Turns a sequence assertion into one readable line:
    /// `[(DNLOAD, 0), (GETSTATUS, 0), (DNLOAD, 1), …]`.
    #[must_use]
    pub const fn class_request(&self) -> Option<(u8, u16)> {
        match self {
            Self::ControlIn {
                control_type: ControlType::Class,
                request,
                value,
                ..
            }
            | Self::ControlOut {
                control_type: ControlType::Class,
                request,
                value,
                ..
            } => Some((*request, *value)),
            _ => None,
        }
    }
}

/// The emulated gadget.
///
/// Every method takes `&self` — the trait is `?Send` and all state lives behind a
/// `RefCell`, as [`MockTransport`](crate::mock::MockTransport) does — so faults can be
/// armed and state inspected from inside a running operation.
#[derive(Debug)]
pub struct FakeGadget {
    descriptors: DeviceDescriptors,
    state: RefCell<Device>,
    injections: RefCell<Vec<Injection>>,
}

impl FakeGadget {
    /// A gadget from `config`.
    ///
    /// It comes up **unconfigured**, as a device does at enumeration, and
    /// in `dfuIDLE`, because `dfu_bind` ends with `to_dfu_mode` (`f_dfu.c:782`, `:230`).
    #[must_use]
    pub fn new(config: GadgetConfig) -> Self {
        let descriptors = DeviceDescriptors::new(config.vendor_id, config.product_id)
            .with_product_string(config.product_string.clone())
            .with_bus_address(1, 2)
            .with_port_path(vec![1])
            .with_config_descriptor(descriptors::configuration(&config));
        Self {
            descriptors,
            state: RefCell::new(Device::new(config)),
            injections: RefCell::new(Vec::new()),
        }
    }

    /// The bench T32LQ: `flash`, `erase`, `reboot`, `wTransferSize` 4096.
    #[must_use]
    pub fn t32lq() -> Self {
        Self::new(GadgetConfig::t32lq())
    }

    /// Arm `fault` on the next call matching `when`.
    pub fn inject(&self, when: When, fault: Fault) {
        self.inject_times(when, fault, 1);
    }

    /// Arm `fault` on the next `times` calls matching `when`.
    pub fn inject_times(&self, when: When, fault: Fault, times: usize) {
        if times == 0 {
            return;
        }
        self.injections.borrow_mut().push(Injection { when, fault, times });
    }

    /// [`inject`](Self::inject), for a construction chain.
    #[must_use]
    pub fn injecting(self, when: When, fault: Fault) -> Self {
        self.inject(when, fault);
        self
    }

    /// EP0 answers nothing for the next `requests` control transfers.
    ///
    /// This is what a buffer drain or a whole-chip erase does to a real gadget: the work
    /// runs in the request context and no setup packet is answered until it returns
    /// It is the reason `Grace::Write` and `Grace::Erase` exist.
    ///
    /// A **request count**, as [`GadgetConfig::flush_silence_polls`] explains: what a
    /// test drives through it is the host's retry budget, not its deadline.
    pub fn silence_ep0(&self, requests: usize) {
        self.state.borrow_mut().silent += requests;
    }

    /// Wedge EP0: every control transfer times out until a [`reset`](Self::reset).
    ///
    /// The state a gadget is left in by a `DNLOAD` interrupted mid-data-stage — a
    /// browser reload, a killed process. The C recovers it by resetting the device and
    /// re-probing (`dfu.c:501-508`), and `ops::probe` losing that was the one functional
    /// regression an audit of an earlier implementation found.
    pub fn wedge(&self) {
        self.state.borrow_mut().wedged = true;
    }

    /// Is EP0 wedged?
    #[must_use]
    pub fn is_wedged(&self) -> bool {
        self.state.borrow().wedged
    }

    /// Has the gadget left the bus?
    ///
    /// Set by a reboot flush reaching `do_reset()`
    /// (`arch/mips/mach-xburst/dfu.c:266`) and by a deferred flush that failed
    /// (`common/dfu.c:84-87`). **Every later call answers
    /// [`NoDevice`](UsbErrorKind::NoDevice), a release included** — which is what usbfs
    /// does for a disconnected device, and what an operation's release-on-every-path
    /// discipline has to expect after a successful reboot.
    #[must_use]
    pub fn is_gone(&self) -> bool {
        self.state.borrow().gone
    }

    /// The DFU state machine's current state.
    #[must_use]
    pub fn dfu_state(&self) -> DfuState {
        self.state.borrow().dfu.state
    }

    /// `bStatus`.
    #[must_use]
    pub fn dfu_status(&self) -> u8 {
        self.state.borrow().dfu.status
    }

    /// The alternate setting in force.
    #[must_use]
    pub fn alt(&self) -> u8 {
        self.state.borrow().dfu.altsetting
    }

    /// The claim in force, if any.
    #[must_use]
    pub fn claimed(&self) -> Option<InterfaceSpec> {
        self.state.borrow().claim
    }

    /// The entity's block sequence counter — the number that **survives a USB reset**
    /// on a legacy loader and refuses a stale block 0.
    #[must_use]
    pub fn entity_sequence(&self, alt: u8) -> Option<u16> {
        let state = self.state.borrow();
        state.entities.get(usize::from(alt)).map(|entity| entity.sequence)
    }

    /// The entity's medium offset — zeroed by every transaction cleanup
    /// (`dfu.c:294`).
    #[must_use]
    pub fn entity_offset(&self, alt: u8) -> Option<u64> {
        let state = self.state.borrow();
        state.entities.get(usize::from(alt)).map(|entity| entity.offset)
    }

    /// Whether the entity has an open transaction (`dfu->inited`).
    #[must_use]
    pub fn entity_inited(&self, alt: u8) -> Option<bool> {
        let state = self.state.borrow();
        state.entities.get(usize::from(alt)).map(|entity| entity.inited)
    }

    /// Whether a virt entity's token has been accepted and not yet spent.
    #[must_use]
    pub fn entity_armed(&self, alt: u8) -> Option<bool> {
        let state = self.state.borrow();
        state.entities.get(usize::from(alt)).map(|entity| entity.armed)
    }

    /// What has been written to `alt`'s medium, as far as it has been written.
    ///
    /// Bytes past the end read as `0xFF` (erased), and an erase empties it.
    #[must_use]
    pub fn medium(&self, alt: u8) -> Option<Vec<u8>> {
        let state = self.state.borrow();
        state.entities.get(usize::from(alt)).map(|entity| entity.medium.clone())
    }

    /// Fill `alt`'s medium with `data`, as if it had been flashed already — the
    /// starting point for a read or a verify.
    pub fn preload(&self, alt: u8, data: impl Into<Vec<u8>>) {
        let mut state = self.state.borrow_mut();
        if let Some(entity) = state.entities.get_mut(usize::from(alt)) {
            entity.medium = data.into();
        }
    }

    /// Every call the host made, in order.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.state.borrow().events.clone()
    }

    /// Drop the recorded calls, so a test can set a device up and then assert only what
    /// the part it is pinning did.
    pub fn forget_events(&self) {
        self.state.borrow_mut().events.clear();
    }

    /// `(bRequest, wValue)` for every DFU class request, in order.
    #[must_use]
    pub fn class_requests(&self) -> Vec<(u8, u16)> {
        self.state
            .borrow()
            .events
            .iter()
            .filter_map(Event::class_request)
            .collect()
    }

    /// How many USB bus resets the host issued.
    #[must_use]
    pub fn resets(&self) -> usize {
        self.state.borrow().resets
    }

    /// How many blocks were refused with `Wrong sequence number!`.
    ///
    /// The bench evidence is a count: a fixed T40XP logged zero and
    /// an old T23 logged exactly one.
    #[must_use]
    pub fn wrong_sequence_refusals(&self) -> usize {
        self.state.borrow().wrong_sequence
    }

    /// How many times the entity buffer drained to the medium (`dfu.c:261-288`).
    #[must_use]
    pub fn buffer_flushes(&self) -> usize {
        self.state.borrow().flushes
    }

    /// How many whole-chip erases ran.
    #[must_use]
    pub fn erases(&self) -> usize {
        self.state.borrow().erases
    }

    /// How many times `do_reset()` was reached from a reboot flush.
    #[must_use]
    pub fn reboots(&self) -> usize {
        self.state.borrow().reboots
    }

    /// The first fault armed for `site`, consuming one of its repeats.
    fn fire(&self, site: Site) -> Option<Fault> {
        let mut injections = self.injections.borrow_mut();
        let at = injections.iter().position(|armed| armed.when.matches(site))?;
        let fault = injections[at].fault;
        injections[at].times -= 1;
        if injections[at].times == 0 {
            injections.remove(at);
        }
        Some(fault)
    }

    /// Everything that can refuse a request before the device is consulted, in the
    /// order the device would apply it.
    ///
    /// **Every entry point goes through this**, transfers and host-side operations
    /// alike, so that a gadget which has left the bus answers
    /// [`NoDevice`](UsbErrorKind::NoDevice) everywhere rather than whatever local
    /// objection the call would have raised on its own.
    ///
    /// [`wedge`](Self::wedge) and [`silence_ep0`](Self::silence_ep0) apply to **EP0**,
    /// which is more than the class requests: `SET_CONFIGURATION` and `SET_INTERFACE`
    /// are setup packets on the same endpoint (USB 2.0 §9.4.7, §9.4.9), and a UDC whose
    /// request context is inside a flash write does not answer them either. A claim, a
    /// release and a `clear_halt` are the *host's* business — usbfs settles them without
    /// asking the device — so they are not silenced; a bulk transfer never reaches a
    /// gadget that declares no endpoints, so neither is it.
    fn gate(&self, site: Site, pipe: Pipe, want: usize, timeout: Option<Duration>) -> Result<Option<Fault>, UsbError> {
        if self.state.borrow().gone {
            return Err(UsbError::new(UsbErrorKind::NoDevice, pipe).with_len(want));
        }
        if let Some(fault) = self.fire(site) {
            return Ok(Some(fault));
        }
        if matches!(site, Site::Control { .. } | Site::SetConfiguration | Site::SetAlt) {
            let mut state = self.state.borrow_mut();
            if state.wedged {
                return Err(Fault::Timeout.error(pipe, want, timeout));
            }
            if state.silent > 0 {
                state.silent -= 1;
                return Err(Fault::Timeout.error(pipe, want, timeout));
            }
        }
        Ok(None)
    }

    /// The device's answer to a `GET_DESCRIPTOR`, or `None` for one it does not have —
    /// which stalls, as a real device does.
    fn descriptor(&self, value: u16) -> Option<Vec<u8>> {
        let state = self.state.borrow();
        let kind = u8::try_from(value >> 8).ok()?;
        let index = u8::try_from(value & 0xFF).ok()?;
        match kind {
            descriptors::DEVICE => Some(descriptors::device(&state.config)),
            descriptors::CONFIGURATION => Some(descriptors::configuration(&state.config)),
            descriptors::STRING => descriptors::string(&state.config, index),
            // `f_dfu.c:659-664`: the function serves its own functional descriptor to a
            // standard `GET_DESCRIPTOR`, capped at `sizeof dfu_func`.
            descriptors::DFU_FUNCTIONAL => Some(descriptors::functional(&state.config)),
            _ => None,
        }
    }

    /// Truncate a data stage to `min(wLength, ceiling)`, where the ceiling is the buffer
    /// the answer was built in.
    ///
    /// **The two answers have different ceilings, because they are built by different
    /// layers.** A DFU class reply goes out of `dfu_handle`, which caps at
    /// `DFU_USB_BUFSIZ` (`f_dfu.c:669`); a descriptor goes out of `composite_setup`,
    /// which caps at `USB_BUFSIZ` — `cdev->req->buf` is that big (`composite.c:17`,
    /// `:1396`) and `req->length` is reset to it on every setup packet (`:1029`). They
    /// are both 4096 on the shipped loader, which is why one number stood in for both
    /// until the 2026-08-23 audit; they are separate `#define`s in separate files, and
    /// [`GadgetConfig::transfer_size`] is a knob while [`GadgetConfig::usb_bufsiz`] is a
    /// second one. A test that moves only `transfer_size` was silently shrinking the
    /// device's descriptors with it.
    fn truncate(mut data: Vec<u8>, requested: u16, ceiling: u16) -> Vec<u8> {
        data.truncate(usize::from(ceiling.min(requested)));
        data
    }

    /// `DFU_USB_BUFSIZ` — the ceiling on a DFU class answer (`f_dfu.c:669`).
    fn transfer_size(&self) -> u16 {
        self.state.borrow().config.transfer_size
    }

    /// `USB_BUFSIZ` — the ceiling on a descriptor the composite layer builds
    /// (`composite.c:17`, `:1029`).
    fn usb_bufsiz(&self) -> u16 {
        self.state.borrow().config.usb_bufsiz
    }

    /// A DFU class request through the state machine.
    ///
    /// The OUT data stage is truncated to `USB_BUFSIZ`, because that is how big
    /// `cdev->req->buf` is (`composite.c:17`, `:1396`). A host that sends more than
    /// `wTransferSize` in one `DNLOAD` is a host bug — see above for why the size
    /// cannot be raised — and the device would overrun that buffer. Truncating is the
    /// least-wrong model of an overrun and it is *visible*: the medium comes up short.
    fn class(&self, request: u8, value: u16, len: u16, data: &[u8], dir_in: bool) -> Answer {
        let mut state = self.state.borrow_mut();
        // Every state function starts with the same clamp (`f_dfu.c:342`, `:454`,
        // `:560`, `:648`).
        let len = len.min(state.config.transfer_size);
        let data = &data[..data.len().min(usize::from(state.config.usb_bufsiz))];
        machine::dispatch(
            &mut state,
            &Ctrl {
                request,
                value,
                len,
                data,
                dir_in,
            },
        )
    }
}

impl LocalUsbTransport for FakeGadget {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::In,
            request: req.request,
        };
        let want = usize::from(req.len);
        let class = req.control_type == ControlType::Class;
        let descriptor = req.control_type == ControlType::Standard && req.request == GET_DESCRIPTOR;
        self.state.borrow_mut().events.push(Event::ControlIn {
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
            len: req.len,
        });
        let site = Site::Control {
            class,
            descriptor,
            request: req.request,
            value: req.value,
        };
        let short = match self.gate(site, pipe, want, Some(timeout))? {
            Some(Fault::Short { got }) => Some(got),
            Some(fault) => return Err(fault.error(pipe, want, Some(timeout))),
            None => None,
        };

        let (answer, ceiling) = if descriptor {
            match self.descriptor(req.value) {
                Some(bytes) => (Answer::Data(bytes), self.usb_bufsiz()),
                // **A descriptor type the composite layer does not know is answered,
                // not stalled.** `composite_setup`'s `default: goto unknown`
                // (`composite.c:1095-1096`) hands the request to the function's own
                // `setup`, and `dfu_handle` leaves `value` at 0 for any standard
                // `GET_DESCRIPTOR` that is not `DFU_DT_FUNC` (`f_dfu.c:659-664`) — so
                // `value >= 0` holds, `req->length` is 0, and EP0 answers an empty data
                // stage (`:668-671`). A host reads it as "zero bytes", never as a pipe
                // error. It is the unconfigured case that stalls, because
                // `composite.c:1247-1248` bails out with `value` still `-EOPNOTSUPP`.
                None if self.state.borrow().configuration.is_some() => (Answer::Zlp, self.usb_bufsiz()),
                None => (Answer::Stall, self.usb_bufsiz()),
            }
        } else if class {
            (
                self.class(req.request, req.value, req.len, &[], true),
                self.transfer_size(),
            )
        } else if req.control_type == ControlType::Vendor {
            // **A vendor request reaches the DFU state machine.** `composite_setup`
            // sends anything that is not `USB_TYPE_STANDARD` straight to `unknown`
            // (`composite.c:1031-1034`), and `dfu_handle` dispatches everything that is
            // not standard through `dfu_state[…]` (`f_dfu.c:659-666`) — it never checks
            // for `USB_TYPE_CLASS`. So on the real gadget a vendor `bRequest` of 3 is
            // answered as a `GETSTATUS`. Stalling it here made the emulator kinder than
            // the device: an operation that sent a vendor request by mistake would fail
            // cleanly against the double and get a DFU answer on the bench.
            (
                self.class(req.request, req.value, req.len, &[], true),
                self.transfer_size(),
            )
        } else {
            // A standard request the composite layer implements elsewhere (the trait
            // has dedicated methods for those) or does not implement at all.
            (Answer::Stall, self.transfer_size())
        };

        let mut data = match answer {
            Answer::Data(data) => Self::truncate(data, req.len, ceiling),
            // `RET_ZLP` on an IN request is an empty data stage.
            Answer::Zlp => Vec::new(),
            Answer::Stall => return Err(UsbError::new(UsbErrorKind::Stall, pipe).with_len(want)),
            Answer::Gone => return Err(UsbError::new(UsbErrorKind::NoDevice, pipe).with_len(want)),
        };
        if let Some(got) = short {
            data.truncate(got);
        }
        Ok(data)
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        let pipe = Pipe::Control {
            direction: Direction::Out,
            request: req.request,
        };
        let want = req.data.len();
        let class = req.control_type == ControlType::Class;
        self.state.borrow_mut().events.push(Event::ControlOut {
            control_type: req.control_type,
            recipient: req.recipient,
            request: req.request,
            value: req.value,
            index: req.index,
            len: want,
        });
        let site = Site::Control {
            class,
            descriptor: false,
            request: req.request,
            value: req.value,
        };
        if let Some(fault) = self.gate(site, pipe, want, Some(timeout))? {
            return Err(fault.error(pipe, want, Some(timeout)));
        }
        // A vendor OUT reaches the state machine for the reason `control_in` explains:
        // `dfu_handle` dispatches everything that is not `USB_TYPE_STANDARD` through
        // `dfu_state[…]` (`f_dfu.c:659-666`). A *standard* OUT does not: the composite
        // layer serves those itself, and the trait has dedicated methods for the two
        // this device answers.
        if !class && req.control_type != ControlType::Vendor {
            return Err(UsbError::new(UsbErrorKind::Stall, pipe).with_len(want));
        }
        // `wLength` is the data stage's own length on an OUT transfer.
        let len = u16::try_from(want).unwrap_or(u16::MAX);
        match self.class(req.request, req.value, len, req.data, false) {
            Answer::Zlp | Answer::Data(_) => Ok(()),
            Answer::Stall => Err(UsbError::new(UsbErrorKind::Stall, pipe).with_len(want)),
            Answer::Gone => Err(UsbError::new(UsbErrorKind::NoDevice, pipe).with_len(want)),
        }
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        let want = data.len();
        self.state.borrow_mut().events.push(Event::BulkOut { len: want });
        if let Some(fault) = self.gate(Site::Bulk, Pipe::Device, want, Some(timeout))? {
            return Err(fault.error(Pipe::Device, want, Some(timeout)));
        }
        // DFU 1.1 rides EP0 entirely and the gadget's interface declares
        // `bNumEndpoints = 0` (`f_dfu.c:721`), so no claim can ever declare one.
        // The gate runs first all the same: a device that has left the bus
        // is `NoDevice` whatever the caller asked for, and answering the caller's bug
        // instead would hide a successful reboot behind a `NotClaimed`.
        Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device).with_len(want))
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        self.state.borrow_mut().events.push(Event::BulkIn { len });
        if let Some(fault) = self.gate(Site::Bulk, Pipe::Device, len, Some(timeout))? {
            return Err(fault.error(Pipe::Device, len, Some(timeout)));
        }
        Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device).with_len(len))
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        self.state.borrow_mut().events.push(Event::SetConfiguration(value));
        if let Some(fault) = self.gate(Site::SetConfiguration, Pipe::Device, 0, None)? {
            return Err(fault.error(Pipe::Device, 0, None));
        }
        let mut state = self.state.borrow_mut();
        if value == 0 {
            state.configuration = None;
            return Ok(());
        }
        if value != state.config.configuration_value {
            return Err(UsbError::new(UsbErrorKind::Stall, Pipe::Device));
        }
        state.configuration = Some(value);
        // USB 9.4.7: `SET_CONFIGURATION` puts every interface back on alternate setting
        // 0, and the composite layer does that by calling each function's `set_alt`
        // (`f_dfu.c:829-833`). That is what reaches the entity after a bus reset on a
        // fixed loader. An earlier emulator left both the alt and the configuration
        // untouched here.
        machine::set_alt(&mut state, 0);
        Ok(())
    }

    fn active_configuration(&self) -> Option<u8> {
        self.state.borrow().configuration
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        {
            // Any claim in force goes first, because the native backend does exactly
            // that: `NativeTransport::claim_interface` opens with `release_any()`, which
            // issues a real `Interface::release` before the new claim. A double that
            // overwrote the claim let a test pin an event sequence one release short of
            // the one the bus sees. Before the claim's own fault gate, and outside it: a
            // scripted `Site::Claim` fault is about the claim, and the release the
            // backend issues on its own happens whether or not the claim then fails.
            let mut state = self.state.borrow_mut();
            if let Some(held) = state.claim.take() {
                state.events.push(Event::ReleaseInterface(held.interface));
            }
        }
        self.state.borrow_mut().events.push(Event::ClaimInterface(spec));
        if let Some(fault) = self.gate(Site::Claim, Pipe::Device, 0, None)? {
            return Err(fault.error(Pipe::Device, 0, None));
        }
        let mut state = self.state.borrow_mut();
        if spec.interface != state.config.interface {
            return Err(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device));
        }
        if let Some(endpoint) = spec.bulk_in.or(spec.bulk_out) {
            // The trait says a declared endpoint that is not on the interface is
            // `Fault`; a DFU interface has none at all.
            return Err(UsbError::new(UsbErrorKind::Fault, Pipe::Bulk(endpoint)));
        }
        state.claim = Some(spec);
        Ok(())
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        self.state.borrow_mut().events.push(Event::ReleaseInterface(interface));
        if let Some(fault) = self.gate(Site::Release, Pipe::Device, 0, None)? {
            return Err(fault.error(Pipe::Device, 0, None));
        }
        // Contract §2.4: releasing an interface that is not claimed is `Ok(())`. It is
        // what makes the release-on-every-exit-path discipline clean rather than noisy.
        let mut state = self.state.borrow_mut();
        if state.claim.is_some_and(|held| held.interface == interface) {
            state.claim = None;
        }
        Ok(())
    }

    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        self.state
            .borrow_mut()
            .events
            .push(Event::SetAltSetting { interface, alt });
        if let Some(fault) = self.gate(Site::SetAlt, Pipe::Device, 0, None)? {
            return Err(fault.error(Pipe::Device, 0, None));
        }
        let mut state = self.state.borrow_mut();
        // The native backend answers `NotClaimed` for an interface it does not hold,
        // and so does `MockTransport`.
        if state.claim.is_none_or(|held| held.interface != interface) {
            return Err(UsbError::new(UsbErrorKind::NotClaimed, Pipe::Device));
        }
        if usize::from(alt) >= state.entities.len() {
            // USB 9.4.10: a request for an alternate setting the interface does not have
            // is a request error.
            return Err(UsbError::new(UsbErrorKind::Stall, Pipe::Device));
        }
        machine::set_alt(&mut state, alt);
        Ok(())
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        let pipe = Pipe::Bulk(endpoint);
        self.state.borrow_mut().events.push(Event::ClearHalt(endpoint));
        if let Some(fault) = self.gate(Site::ClearHalt, pipe, 0, None)? {
            return Err(fault.error(pipe, 0, None));
        }
        // No claim here can declare a bulk endpoint, so this is always the caller's bug
        // — the same refusal the native backend and the mock give. As in
        // the bulk calls, the gate runs first so a gone device is not reported as one.
        Err(UsbError::new(UsbErrorKind::NotClaimed, pipe))
    }

    async fn reset(&self) -> Result<(), UsbError> {
        self.state.borrow_mut().events.push(Event::Reset);
        if let Some(fault) = self.gate(Site::Reset, Pipe::Device, 0, None)? {
            return Err(fault.error(Pipe::Device, 0, None));
        }
        let mut state = self.state.borrow_mut();
        state.resets += 1;
        // USB 9.1.1.5: a bus reset returns the device to the Default state, so the
        // configuration and every claim are gone, and alt 0 is what the next
        // `SET_CONFIGURATION` will select.
        //
        // The one place this double and the native backend disagree on purpose: the
        // Linux kernel re-applies configuration 1 after a reset and the native backend
        // reports it, so a claim scripted against this carries a `SET_CONFIGURATION` a
        // real Linux host never emits. The spec is on this side, the OS on the other;
        // the differential capture against the C is the arbiter.
        state.configuration = None;
        state.claim = None;
        state.wedged = false;
        state.silent = 0;
        // **The entity is not touched, and neither is `f_dfu->altsetting`.**
        // The block sequence counter and the buffer survive a bus reset, and only the
        // `SET_CONFIGURATION` that follows re-enumeration reaches them — and only on a
        // fixed loader. That asymmetry is the block 0 retry's whole reason for existing.
        //
        // Nothing on the device writes `altsetting` on a reset. `composite_disconnect`
        // calls `reset_config` (`composite.c:1318-1326`), which calls each function's
        // `disable`; `dfu_disable` zeroes `f_dfu->config` and nothing else
        // (`f_dfu.c:851-860`). The alt goes back to 0 one request later, when
        // `SET_CONFIGURATION` runs `dfu_set_alt(f, intf, 0)` — which is where this model
        // does it too. Zeroing it here as well applied half of `dfu_set_alt` (the alt,
        // not the transaction cleanup or the state) at a moment the device applies none
        // of it, and hid the legacy loader's case from any test that reset without
        // re-configuring.
        Ok(())
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        &self.descriptors
    }
}
