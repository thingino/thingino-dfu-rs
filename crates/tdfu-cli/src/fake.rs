//! A bus that does not exist, for tests that must not need one.
//!
//! [`FakeBackend`] implements [`LocalUsbBackend`] over canned
//! [`Discovered`](tdfu_usb::Discovered) lists and hands out
//! [`MockTransport`](tdfu_usb::mock::MockTransport)s scripted with exactly the requests
//! [`ops::detect`](tdfu_core::ops::detect) makes. Nothing here reaches a USB device, a
//! clock or a process.
//!
//! It exists because an earlier implementation's `main.rs` hard-wired `NativeBackend`
//! and reached 6% coverage. Every rule in [`list`](crate::list),
//! [`render`](crate::render) and [`wait`](crate::wait) is pinned through this.
//!
//! **The script is exact.** `MockTransport` refuses any request that is not the next
//! expectation, so a listing that opened a gadget, reset a bootrom or claimed twice
//! would fail the test rather than pass quietly, which is the property a scripted
//! double has and a permissive one does not.

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::rc::Rc;

use tdfu_core::addr::{self, Kseg1};
use tdfu_core::bootrom;
use tdfu_core::model::{DfuAlt, DfuInfo};
use tdfu_usb::gadget::{AltConfig, FakeGadget, GadgetConfig};
use tdfu_usb::mock::{Call, MockTransport, Reply};
use tdfu_usb::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Discovered, InterfaceSpec, LocalUsbBackend,
    LocalUsbTransport, Pipe, Recipient, UsbError, UsbErrorKind, endpoint, pid, vid,
};

/// Anything a test in this crate can fail with.
pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A private directory for one test, removed when it is done.
///
/// No `tempfile` dependency: `cargo deny`'s `multiple-versions = "deny"` makes every
/// added crate a standing liability (`Cargo.toml`), and this is fifteen lines.
#[derive(Debug)]
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// Make one. `name` distinguishes concurrent tests within a process.
    ///
    /// # Errors
    /// Whatever `create_dir_all` raises.
    pub fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("tdfu-cli-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.0
    }

    /// A path inside it, which need not exist.
    #[must_use]
    pub fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }

    /// Write a file inside it and hand back its path.
    ///
    /// # Errors
    /// Whatever `write` raises.
    pub fn write(&self, name: &str, bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
        let path = self.path(name);
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// Lay out a `dfu/<variant>/` loader tree with a stage-1 and a U-Boot image in it.
    ///
    /// # Errors
    /// Whatever `create_dir_all` or `write` raises.
    pub fn loader_tree(&self, variant: tdfu_core::model::Variant) -> std::io::Result<()> {
        let dir = self.0.join("dfu").join(variant.loader_dir());
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("spl.bin"), b"stage-1")?;
        std::fs::write(dir.join("uboot.bin"), b"u-boot")?;
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

/// A bootrom as enumeration sees it.
///
/// The product string really does begin with junk (`U+00C3`, TAB) on every
/// bootrom seen, and it is never compared for equality.
///
/// It carries a configuration descriptor as well as the product string, on purpose:
/// both are evidence `classify` can use, so this fixture does not depend on which
/// branch of the classifier answers. A double that classifies for only one reason silently
/// stops testing the moment that reason changes.
pub fn bootrom_descriptors(bus: u8, address: u8) -> DeviceDescriptors {
    DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
        .with_product_string("\u{c3}\t USB Boot Device")
        .with_bus_address(bus, address)
        .with_port_path(vec![4, 2])
        .with_config_descriptor(vendor_config())
}

/// The bootrom's configuration: one vendor-class interface (`0xFF`) with the two bulk
/// endpoints the bootrom talks over. **No DFU interface**: that is what tells it
/// apart from the gadget it shares a PID with.
fn vendor_config() -> Vec<u8> {
    let mut config = vec![9, 0x02, 32, 0, 1, 1, 0, 0x80, 0x32];
    config.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xFF, 0x00, 0x00, 0]);
    config.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
    config.extend_from_slice(&[7, 0x05, 0x01, 0x02, 0x00, 0x02, 0]);
    config
}

/// A U-Boot DFU gadget, sharing the bootrom's PID as every current one does,
/// so only the configuration descriptor tells them apart.
pub fn gadget_descriptors(bus: u8, address: u8) -> DeviceDescriptors {
    DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
        .with_product_string("USB download gadget")
        .with_bus_address(bus, address)
        .with_port_path(vec![4, 3])
        .with_config_descriptor(dfu_config())
}

/// A minimal configuration descriptor with one DFU interface: `bInterfaceClass 0xFE`,
/// `bInterfaceSubClass 0x01`.
pub fn dfu_config() -> Vec<u8> {
    let mut config = vec![9, 0x02, 18, 0, 1, 1, 0, 0xC0, 0x32];
    config.extend_from_slice(&[9, 0x04, 0, 0, 0, 0xFE, 0x01, 0x02, 4]);
    config
}

/// A three-alt gadget configuration descriptor, the shape every shipped loader has
/// (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`).
///
/// Three DFU interface descriptors under one `bInterfaceNumber`, then the functional
/// descriptor captured byte-for-byte from a live T32LQ: `09 21 0F 00 00 00 10 10 01` —
/// `wTransferSize` 4096, DFU 1.10. Forty-five bytes in total, as the real one is.
#[must_use]
pub fn three_alt_config() -> Vec<u8> {
    let mut config = vec![9, 0x02, 45, 0, 1, 1, 0, 0xC0, 0x32];
    for (alt, iinterface) in [(0_u8, 4_u8), (1, 5), (2, 6)] {
        config.extend_from_slice(&[9, 0x04, 0, alt, 0, 0xFE, 0x01, 0x02, iinterface]);
    }
    config.extend_from_slice(&[9, 0x21, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01]);
    config
}

/// One USB string descriptor, UTF-16LE, as a device sends it.
#[must_use]
pub fn string_descriptor(text: &str) -> Vec<u8> {
    let mut bytes = vec![0, 0x03];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let len = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
    if let Some(first) = bytes.first_mut() {
        *first = len;
    }
    bytes
}

/// A [`DfuInfo`] with the alts named, built through the **real** parser.
///
/// `DfuInfo` is `#[non_exhaustive]`, so a struct literal is not available outside
/// `tdfu-core` — and that is the better outcome: a fixture here goes through
/// [`parse_config`](tdfu_core::dfu::parse_config) on the same descriptor bytes a device
/// sends, so the `interface`, `transfer_size` and `bcd_dfu` a test sees are ones a
/// device could actually have produced. Only the names are substituted, because
/// `parse_config` leaves them empty by design (they are `iInterface` *indices* until a
/// string read resolves them).
///
/// # Errors
/// Whatever `parse_config` raises for [`dfu_config`], which is nothing today — it is a
/// `Result` so that a fixture failure is a test failure rather than an `unwrap`
/// (which the workspace denies).
pub fn dfu_info(alts: &[(u8, &str)]) -> tdfu_core::Result<DfuInfo> {
    let mut info = tdfu_core::dfu::parse_config(&dfu_config())?;
    info.alts = alts.iter().map(|&(alt, name)| DfuAlt::new(alt, name)).collect();
    Ok(info)
}

/// The three registers of a T31, with `subsoctype1` supplied by the caller.
///
/// `soc_id 0x1003_1003` is the real Z55 bench capture (`detect/mod.rs`, the T31X row):
/// `cpu_id = (soc_id >> 12) & 0xFFFF` is `0x0031`.
#[must_use]
pub const fn t31_regs(subsoctype1: u32) -> [u32; 3] {
    [0x1003_1003, subsoctype1, 0]
}

/// How a fake device answers an open.
enum Opens {
    /// Into a transport this closure builds fresh, so a second open is a fresh script.
    Script(Box<dyn Fn(&DeviceDescriptors) -> MockTransport>),
    /// Into the U-Boot gadget emulator, **shared**: state survives the open, so a test
    /// can read back the medium a write left behind.
    Gadget(Rc<FakeGadget>),
    /// Not at all.
    Refuse(UsbError),
}

/// One open device on the fake bus: either a script or the emulator.
///
/// Two doubles because they answer different questions, and neither can answer the
/// other's. [`MockTransport`] is exact — it refuses any request that is not the next
/// expectation, which is how `-l` is pinned never to reset a bootrom.
/// A whole `ops::write` is 4097 requests whose shape belongs to the DFU state machine
/// rather than to this crate, so scripting one here would pin `tdfu-core`'s internals
/// into `tdfu-cli`'s tests and break on every legitimate change to them.
/// [`FakeGadget`] answers those the way the loader does, so a CLI test asserts what the
/// operator sees — bytes on the medium, notes on stderr, the exit code — and stays true
/// when the sequence beneath it changes.
///
/// It is an enum rather than two backends because [`LocalUsbBackend::Transport`] is one
/// associated type, and a bus with a bootrom *and* the gadget it turns into is exactly
/// what the auto-bootstrap path has to be tested against.
#[derive(Debug)]
pub enum FakeTransport {
    /// A scripted transport, for the paths whose exact wire shape is the point.
    Scripted(MockTransport),
    /// The emulator, shared with the test that armed it.
    Gadget(Rc<FakeGadget>),
}

impl FakeTransport {
    /// The script behind this transport, for a test that wants to verify it was
    /// exhausted. `None` for the emulator, which has no script to exhaust.
    #[must_use]
    pub const fn scripted(&self) -> Option<&MockTransport> {
        match self {
            Self::Scripted(mock) => Some(mock),
            Self::Gadget(_) => None,
        }
    }
}

/// Forward every method to whichever double is behind it.
///
/// Written out rather than generated: the trait is eleven methods, a macro would hide
/// which ones exist, and a method added to the trait must fail to compile here rather
/// than be silently defaulted.
impl LocalUsbTransport for FakeTransport {
    async fn control_in(&self, req: ControlIn, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        match self {
            Self::Scripted(mock) => mock.control_in(req, timeout).await,
            Self::Gadget(gadget) => gadget.control_in(req, timeout).await,
        }
    }

    async fn control_out(&self, req: ControlOut<'_>, timeout: Duration) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.control_out(req, timeout).await,
            Self::Gadget(gadget) => gadget.control_out(req, timeout).await,
        }
    }

    async fn bulk_out(&self, data: &[u8], timeout: Duration) -> Result<usize, UsbError> {
        match self {
            Self::Scripted(mock) => mock.bulk_out(data, timeout).await,
            Self::Gadget(gadget) => gadget.bulk_out(data, timeout).await,
        }
    }

    async fn bulk_in(&self, len: usize, timeout: Duration) -> Result<Vec<u8>, UsbError> {
        match self {
            Self::Scripted(mock) => mock.bulk_in(len, timeout).await,
            Self::Gadget(gadget) => gadget.bulk_in(len, timeout).await,
        }
    }

    async fn set_configuration(&self, value: u8) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.set_configuration(value).await,
            Self::Gadget(gadget) => gadget.set_configuration(value).await,
        }
    }

    fn active_configuration(&self) -> Option<u8> {
        match self {
            Self::Scripted(mock) => mock.active_configuration(),
            Self::Gadget(gadget) => gadget.active_configuration(),
        }
    }

    async fn claim_interface(&self, spec: InterfaceSpec) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.claim_interface(spec).await,
            Self::Gadget(gadget) => gadget.claim_interface(spec).await,
        }
    }

    async fn release_interface(&self, interface: u8) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.release_interface(interface).await,
            Self::Gadget(gadget) => gadget.release_interface(interface).await,
        }
    }

    async fn set_alt_setting(&self, interface: u8, alt: u8) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.set_alt_setting(interface, alt).await,
            Self::Gadget(gadget) => gadget.set_alt_setting(interface, alt).await,
        }
    }

    async fn clear_halt(&self, endpoint: BulkEndpoint) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.clear_halt(endpoint).await,
            Self::Gadget(gadget) => gadget.clear_halt(endpoint).await,
        }
    }

    async fn reset(&self) -> Result<(), UsbError> {
        match self {
            Self::Scripted(mock) => mock.reset().await,
            Self::Gadget(gadget) => gadget.reset().await,
        }
    }

    fn descriptors(&self) -> &DeviceDescriptors {
        match self {
            Self::Scripted(mock) => mock.descriptors(),
            Self::Gadget(gadget) => gadget.descriptors(),
        }
    }
}

/// One device on the fake bus.
pub struct FakeDevice {
    descriptors: DeviceDescriptors,
    opens: Opens,
}

/// A canned USB bus.
pub struct FakeBackend {
    /// Successive answers to `list()`; the last one repeats for ever, which is what
    /// makes a `--wait` test terminate without a timeout.
    listings: Vec<Vec<FakeDevice>>,
    /// A failure every `list()` returns instead.
    failure: Option<UsbError>,
    list_calls: Cell<usize>,
    opened: RefCell<Vec<usize>>,
}

impl FakeBackend {
    /// A bus whose contents never change.
    #[must_use]
    pub fn new(devices: Vec<FakeDevice>) -> Self {
        Self::appearing(vec![devices])
    }

    /// A bus that answers each `list()` with the next entry, repeating the last.
    #[must_use]
    pub fn appearing(listings: Vec<Vec<FakeDevice>>) -> Self {
        Self {
            listings,
            failure: None,
            list_calls: Cell::new(0),
            opened: RefCell::new(Vec::new()),
        }
    }

    /// A bus that cannot be enumerated at all.
    #[must_use]
    pub fn failing(error: UsbError) -> Self {
        Self {
            listings: vec![Vec::new()],
            failure: Some(error),
            list_calls: Cell::new(0),
            opened: RefCell::new(Vec::new()),
        }
    }

    /// How many times `list()` has been called.
    #[must_use]
    pub fn list_calls(&self) -> usize {
        self.list_calls.get()
    }

    /// Which device indices were opened, in order. Empty is the assertion a listing
    /// wants for a gadget.
    #[must_use]
    pub fn opened(&self) -> Vec<usize> {
        self.opened.borrow().clone()
    }

    /// A bootrom that answers [`ops::detect`](tdfu_core::ops::detect) with `regs`.
    #[must_use]
    pub fn bootrom(regs: [u32; 3]) -> FakeDevice {
        Self::bootrom_at(bootrom_descriptors(1, 7), regs)
    }

    /// A bootrom with descriptors of the caller's choosing.
    #[must_use]
    pub fn bootrom_at(descriptors: DeviceDescriptors, regs: [u32; 3]) -> FakeDevice {
        FakeDevice {
            descriptors,
            opens: Opens::Script(Box::new(move |descriptors| detect_script(descriptors.clone(), regs))),
        }
    }

    /// A bootrom scripted for a whole `--diag`: the CPU-info hint, then the two reads.
    ///
    /// `window` is the 256-byte eFuse shadow the device answers with, so a test can hand
    /// in a real bench capture and see what the report makes of it.
    #[must_use]
    pub fn diagnosable_bootrom(soc_id: u32, window: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7),
            opens: Opens::Script(Box::new(move |descriptors| {
                diag_script(descriptors.clone(), soc_id, window.clone())
            })),
        }
    }

    /// A bootrom scripted for a whole `--cpu`-forced bootstrap of the two images.
    #[must_use]
    pub fn bootstrappable_bootrom(stage1: Vec<u8>, uboot: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7),
            opens: Opens::Script(Box::new(move |descriptors| {
                bootstrap_script(descriptors.clone(), &stage1, &uboot)
            })),
        }
    }

    /// A U-Boot DFU gadget. Opening it would fail the test, which is the point: a
    /// listing must never open one.
    #[must_use]
    pub fn gadget() -> FakeDevice {
        FakeDevice {
            descriptors: gadget_descriptors(1, 9),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                MockTransport::new(descriptors.clone())
            })),
        }
    }

    /// A device the OS refuses.
    #[must_use]
    pub fn refusing(descriptors: DeviceDescriptors, error: UsbError) -> FakeDevice {
        FakeDevice {
            descriptors,
            opens: Opens::Refuse(error),
        }
    }

    /// A bootrom that opens and claims, then never answers the first register read.
    #[must_use]
    pub fn mute_bootrom() -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7),
            opens: Opens::Script(Box::new(|descriptors| {
                claim(MockTransport::new(descriptors.clone()))
                    .expecting(
                        vendor_word(bootrom::request::SET_DATA_ADDR, addr::SOC_ID.get()),
                        Reply::Done,
                    )
                    .expecting(vendor_word(bootrom::request::SET_DATA_LEN, WORD_LEN), Reply::Done)
                    .expecting(
                        Call::BulkIn { len: 4 },
                        Reply::Fail(
                            UsbError::new(UsbErrorKind::Timeout, Pipe::Bulk(endpoint::BOOTROM_IN))
                                .with_len(4)
                                .with_timeout(core::time::Duration::from_secs(2)),
                        ),
                    )
                    .expecting(Call::ReleaseInterface(0), Reply::Done)
            })),
        }
    }

    /// A bootrom the OS lets you open and then refuses to claim.
    ///
    /// Real on Linux: `open` succeeds while `claim_interface` answers `EACCES` or
    /// `EBUSY` because a kernel driver holds the interface. The failure then arrives as
    /// `Error::Usb` from inside `ops::detect` rather than from `open`, and the hint must
    /// still reach the row - a gap mutation testing found.
    #[must_use]
    pub fn unclaimable_bootrom() -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                MockTransport::new(descriptors.clone())
                    .expecting(Call::SetConfiguration(bootrom::CONFIGURATION), Reply::Done)
                    .expecting(
                        Call::ClaimInterface(bootrom::INTERFACE),
                        Reply::Fail(UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device)),
                    )
            })),
        }
    }

    /// An X-series device, on the **second** Ingenic vendor ID.
    ///
    /// It carries a DFU configuration descriptor so that whatever `classify` decides is
    /// decided on evidence rather than on its product ID.
    #[must_use]
    pub fn x_series() -> FakeDevice {
        FakeDevice {
            descriptors: DeviceDescriptors::new(vid::INGENIC_X, pid::BOOTROM_X)
                .with_bus_address(2, 5)
                .with_port_path(vec![1])
                .with_config_descriptor(dfu_config()),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                MockTransport::new(descriptors.clone())
            })),
        }
    }

    /// An Ingenic VID this tool has no rule for: no DFU interface, no bootrom PID, no
    /// product string.
    #[must_use]
    pub fn opaque() -> FakeDevice {
        FakeDevice {
            descriptors: DeviceDescriptors::new(vid::INGENIC, 0x1234).with_bus_address(3, 2),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                MockTransport::new(descriptors.clone())
            })),
        }
    }

    /// A gadget that answers `dfu::read_info`: three alts, named.
    ///
    /// The script is `read_config`'s two `GET_DESCRIPTOR` reads (the 9-byte header for
    /// `wTotalLength`, then the whole 45 bytes) followed by one string read per alt
    /// (`descriptors.rs`, `read_config` and `read_string`).
    ///
    /// The script has no `ClaimInterface` line, because `ops::probe` reads descriptors
    /// without claiming. If that ever changes, the claim belongs at the front of this
    /// script, and the tests that drive it will say so by failing.
    #[must_use]
    pub fn probeable_gadget() -> FakeDevice {
        FakeDevice {
            descriptors: gadget_descriptors(1, 9).with_config_descriptor(three_alt_config()),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                probe_script(descriptors.clone())
            })),
        }
    }

    /// [`Self::probeable_gadget`], at a caller-chosen port: the socket the bootrom it
    /// replaced was on. A real gadget keeps its port, and
    /// `wait_for_gadget` matches on exactly that.
    #[must_use]
    pub fn probeable_gadget_at(port_path: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: gadget_descriptors(1, 9).with_port_path(port_path),
            opens: Opens::Script(Box::new(|descriptors: &DeviceDescriptors| {
                probe_script(descriptors.clone())
            })),
        }
    }

    /// A device that opens into `gadget`, the U-Boot gadget emulator.
    ///
    /// The **enumerated** descriptors are this module's ([`gadget_descriptors`] with a
    /// three-alt configuration), not the emulator's, because they answer a different
    /// question: enumeration is what `ops::classify` reads to decide the row is a
    /// gadget, while the emulator serves its own configuration descriptor
    /// over EP0 when `read_info` asks. Keeping them separate is what lets a gadget sit
    /// on the bootrom's port path, which a real one keeps and
    /// `wait_for_gadget` matches on.
    #[must_use]
    pub fn emulated_gadget(gadget: &Rc<FakeGadget>) -> FakeDevice {
        Self::emulated_gadget_at(gadget, vec![4, 3])
    }

    /// [`Self::emulated_gadget`], on a caller-chosen port path.
    #[must_use]
    pub fn emulated_gadget_at(gadget: &Rc<FakeGadget>, port_path: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: gadget_descriptors(1, 9)
                .with_config_descriptor(three_alt_config())
                .with_port_path(port_path),
            opens: Opens::Gadget(Rc::clone(gadget)),
        }
    }

    /// The listing an `open` resolves against: the one the most recent `list()`
    /// returned, so an `appearing` bus opens the device the caller actually saw.
    /// Before any `list()`, the steady state (the last listing) stands in - a
    /// caller that never listed cannot have a stale view.
    fn table(&self) -> &[FakeDevice] {
        let calls = self.list_calls.get();
        let index = if calls == 0 {
            self.listings.len().saturating_sub(1)
        } else {
            (calls - 1).min(self.listings.len().saturating_sub(1))
        };
        self.listings.get(index).map_or(&[], Vec::as_slice)
    }
}

/// Four bytes, the width of every register detection reads.
const WORD_LEN: u32 = 4;

/// The `set_configuration` + `claim_interface` pair `bootrom::claim` issues against a
/// device that enumeration left unconfigured.
fn claim(device: MockTransport) -> MockTransport {
    device
        .expecting(Call::SetConfiguration(bootrom::CONFIGURATION), Reply::Done)
        .expecting(Call::ClaimInterface(bootrom::INTERFACE), Reply::Done)
}

/// A vendor OUT carrying a 32-bit word, split into `wValue`/`wIndex`.
fn vendor_word(request: u8, word: u32) -> Call {
    Call::control_out(ControlOut {
        control_type: ControlType::Vendor,
        recipient: Recipient::Device,
        request,
        #[allow(clippy::cast_possible_truncation, reason = "splits the word in half")]
        value: (word >> 16) as u16,
        #[allow(clippy::cast_possible_truncation, reason = "splits the word in half")]
        index: (word & 0xFFFF) as u16,
        data: &[],
    })
}

/// One register read: `SET_DATA_ADDR`, `SET_DATA_LEN`, then four bytes little-endian
/// (the byte order the register captures were produced with).
fn read_register(device: MockTransport, address: Kseg1, word: u32) -> MockTransport {
    device
        .expecting(vendor_word(bootrom::request::SET_DATA_ADDR, address.get()), Reply::Done)
        .expecting(vendor_word(bootrom::request::SET_DATA_LEN, WORD_LEN), Reply::Done)
        .expecting(Call::BulkIn { len: 4 }, Reply::Data(word.to_le_bytes().to_vec()))
}

/// The requests `dfu::read_info` makes against a three-alt gadget.
fn probe_script(descriptors: DeviceDescriptors) -> MockTransport {
    /// `bRequest` for `GET_DESCRIPTOR` (USB 2.0 table 9-4).
    const GET_DESCRIPTOR: u8 = 0x06;
    /// `bDescriptorType` for a configuration descriptor (USB 2.0 table 9-5).
    const CONFIGURATION: u16 = 0x02;
    /// `bDescriptorType` for a string descriptor.
    const STRING: u16 = 0x03;
    /// `wIndex` for a string read; `descriptors.rs` hardcodes it.
    const LANGID_EN_US: u16 = 0x0409;
    /// `wLength` for a string read; `descriptors.rs` asks for the maximum.
    const STRING_LEN: u16 = 256;

    let config = three_alt_config();
    let header = config.get(..9).unwrap_or_default().to_vec();
    let descriptor_read = |value: u16, index: u16, len: u16| Call::ControlIn {
        control_type: ControlType::Standard,
        recipient: Recipient::Device,
        request: GET_DESCRIPTOR,
        value,
        index,
        len,
    };
    let total = u16::try_from(config.len()).unwrap_or(u16::MAX);

    let device = MockTransport::new(descriptors)
        .expecting(descriptor_read(CONFIGURATION << 8, 0, 9), Reply::Data(header))
        .expecting(descriptor_read(CONFIGURATION << 8, 0, total), Reply::Data(config));
    [(4_u16, "flash"), (5, "erase"), (6, "reboot")]
        .into_iter()
        .fold(device, |device, (index, name)| {
            device.expecting(
                descriptor_read((STRING << 8) | index, LANGID_EN_US, STRING_LEN),
                Reply::Data(string_descriptor(name)),
            )
        })
}

/// The whole of `ops::diag`: the CPU-info hint (best-effort, before the
/// claim), then `soc_id` and the 256-byte eFuse window, then the release.
fn diag_script(descriptors: DeviceDescriptors, soc_id: u32, window: Vec<u8>) -> MockTransport {
    let device = MockTransport::new(descriptors).expecting(
        Call::control_in(ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: bootrom::request::GET_CPU_INFO,
            value: 0,
            index: 0,
            len: 8,
        }),
        Reply::Data(b"T31V\0\0\0\0".to_vec()),
    );
    let device = claim(device);
    let device = read_register(device, addr::SOC_ID, soc_id);
    let length = u32::try_from(window.len()).unwrap_or_default();
    let device = device
        .expecting(
            vendor_word(bootrom::request::SET_DATA_ADDR, addr::EFUSE_WINDOW.get()),
            Reply::Done,
        )
        .expecting(vendor_word(bootrom::request::SET_DATA_LEN, length), Reply::Done)
        .expecting(Call::BulkIn { len: window.len() }, Reply::Data(window));
    device.expecting(Call::ReleaseInterface(0), Reply::Done)
}

/// The whole of `ops::detect` for a non-T33 family: claim, three reads, release.
fn detect_script(descriptors: DeviceDescriptors, regs: [u32; 3]) -> MockTransport {
    let device = claim(MockTransport::new(descriptors));
    let device = read_register(device, addr::SOC_ID, regs[0]);
    let device = read_register(device, addr::SUBSOCTYPE1, regs[1]);
    let device = read_register(device, addr::SUBSOCTYPE2, regs[2]);
    device.expecting(Call::ReleaseInterface(0), Reply::Done)
}

/// One padded image's upload, exactly as `ops::bootstrap` puts it on the wire
/// (`bootstrap.c:48-66, 77, 173`; the shape `boot_sequence_order` pins).
/// The first claim of an unconfigured device carries the one `SET_CONFIGURATION`.
fn upload_script(mut device: MockTransport, in_configuration: &mut bool, address: u32, image: &[u8]) -> MockTransport {
    device = device
        .expecting(vendor_word(bootrom::request::SET_DATA_ADDR, address), Reply::Done)
        .expecting(
            vendor_word(
                bootrom::request::SET_DATA_LEN,
                u32::try_from(image.len()).unwrap_or_default(),
            ),
            Reply::Done,
        );
    if !*in_configuration {
        device = device.expecting(Call::SetConfiguration(bootrom::CONFIGURATION), Reply::Done);
        *in_configuration = true;
    }
    device
        .expecting(Call::ClaimInterface(bootrom::INTERFACE), Reply::Done)
        .expecting(Call::BulkOut { data: image.to_vec() }, Reply::Transferred(image.len()))
        .expecting(Call::ReleaseInterface(0), Reply::Done)
}

/// A whole successful `--cpu`-forced bootstrap of `stage1` + `uboot` (raw; the
/// script pads with the op's own rule, so it mirrors the wire, not the files).
fn bootstrap_script(descriptors: DeviceDescriptors, stage1: &[u8], uboot: &[u8]) -> MockTransport {
    let stage1 = bootrom::pad_stage1(stage1);
    let uboot = bootrom::pad_stage1(uboot);
    let mut in_configuration = false;
    let mut device = MockTransport::new(descriptors);
    device = upload_script(device, &mut in_configuration, bootrom::SPL_LOAD_ADDR, &stage1);
    device = device.expecting(
        vendor_word(bootrom::request::PROG_STAGE1, bootrom::SPL_ENTRY_ADDR),
        Reply::Done,
    );
    device = upload_script(device, &mut in_configuration, bootrom::UBOOT_ADDR, &uboot);
    device
        .expecting(vendor_word(bootrom::request::FLUSH_CACHE, 0), Reply::Done)
        .expecting(
            vendor_word(bootrom::request::PROG_STAGE2, bootrom::UBOOT_ADDR),
            Reply::Done,
        )
}

/// A shipped-loader gadget with a boot flash of `size` bytes: `flash`, `erase`,
/// `reboot`, `wTransferSize` 4096.
///
/// `Rc` because a test hands one copy to the bus and keeps one to inspect afterwards —
/// `medium(0)` after a write, `erases()` after an `--erase`, `is_gone()` after a
/// reboot. All the emulator's state is behind a `RefCell` and the trait is `?Send`, so
/// sharing it is the intended use.
#[must_use]
pub fn loader_gadget(size: u64) -> Rc<FakeGadget> {
    Rc::new(FakeGadget::new(GadgetConfig::new(vec![
        AltConfig::flash("flash", size),
        AltConfig::erase(),
        AltConfig::reboot(),
    ])))
}

impl LocalUsbBackend for FakeBackend {
    type Transport = FakeTransport;
    /// The row's position in the listing — the same number `-i` takes.
    type DeviceId = usize;

    async fn list(&self) -> Result<Vec<Discovered<usize>>, UsbError> {
        let call = self.list_calls.get();
        self.list_calls.set(call + 1);
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let listing = self
            .listings
            .get(call)
            .or_else(|| self.listings.last())
            .map_or(&[][..], Vec::as_slice);
        Ok(listing
            .iter()
            .enumerate()
            .map(|(id, device)| Discovered {
                id,
                descriptors: device.descriptors.clone(),
            })
            .collect())
    }

    async fn open(&self, id: &usize) -> Result<FakeTransport, UsbError> {
        self.opened.borrow_mut().push(*id);
        match self.table().get(*id) {
            Some(FakeDevice {
                descriptors,
                opens: Opens::Script(build),
            }) => Ok(FakeTransport::Scripted(build(descriptors))),
            Some(FakeDevice {
                opens: Opens::Gadget(gadget),
                ..
            }) => Ok(FakeTransport::Gadget(Rc::clone(gadget))),
            Some(FakeDevice {
                opens: Opens::Refuse(error),
                ..
            }) => Err(error.clone()),
            None => Err(UsbError::new(UsbErrorKind::NoDevice, Pipe::Device)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FakeBackend, TestResult, gadget_descriptors, t31_regs};
    use tdfu_core::bootrom;
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::model::Detection;
    use tdfu_core::ops;
    use tdfu_usb::mock::{Call, block_on};
    use tdfu_usb::{LocalUsbBackend, LocalUsbTransport};

    /// The script really is what `ops::detect` issues — checked by running it and
    /// asking the mock whether anything was left over.
    ///
    /// A double that accepts more than the code sends silently removes coverage
    /// everywhere downstream, so this is the double checking
    /// itself before anything is built on it.
    #[test]
    fn the_bootrom_script_matches_what_detect_sends() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        let device = block_on(backend.open(&0))?;
        let detection = block_on(ops::detect(&device, &RecordingClock::new()))?;

        let script = device.scripted().ok_or("a bootrom opens into a scripted transport")?;
        script.verify()?;
        assert_eq!(script.remaining(), 0, "the script must be exhausted");
        assert!(matches!(detection, Detection::Resolved(_)));

        // The actual worry, asserted where the calls are visible: listing a
        // device must never reset it. `ops::probe` recovers a wedged gadget with a bus
        // reset (`dfu.c:501-508`), and doing that to a device somebody else is
        // mid-flash is the reason a listing does not probe.
        let issued: Vec<Call> = script.calls().into_iter().map(|recorded| recorded.call).collect();
        assert!(
            !issued
                .iter()
                .any(|call| matches!(call, Call::Reset | Call::ClearHalt(_))),
            "identification must be read-only on the bus: {issued:?}"
        );
        // And nothing was executed: no PROG_STAGE1, no PROG_STAGE2, no FLUSH_CACHE
        // at all. The mask ROM's one shot is still there.
        let executed = [
            bootrom::request::PROG_STAGE1,
            bootrom::request::PROG_STAGE2,
            bootrom::request::FLUSH_CACHE,
        ];
        assert!(
            !issued.iter().any(|call| matches!(
                call,
                Call::ControlOut { request, .. } | Call::ControlIn { request, .. } if executed.contains(request)
            )),
            "detection executes nothing on the device: {issued:?}"
        );
        Ok(())
    }

    /// The gadget's transport is scripted with **nothing**, so any request at all fails
    /// -- except a release of an unclaimed interface, which the trait requires to be
    /// idempotent `Ok(())`. A claim is the request
    /// that proves the refusal.
    #[test]
    fn the_gadget_double_refuses_every_request() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let device = block_on(backend.open(&0))?;
        assert!(
            block_on(device.release_interface(0)).is_ok(),
            "releasing an unclaimed interface is idempotent, never a script event"
        );
        assert!(block_on(device.claim_interface(tdfu_usb::InterfaceSpec::control_only(0))).is_err());
        let script = device.scripted().ok_or("this gadget is the scripted double")?;
        assert!(script.verify().is_err(), "an unexpected call must be recorded");
        Ok(())
    }

    /// The emulator-backed device really is one, and it is **shared**: what an
    /// operation leaves on the medium is visible to the test afterwards.
    ///
    /// Without this the whole write/read/verify layer below would be asserting against
    /// a private copy of a gadget and proving nothing.
    #[test]
    fn an_emulated_gadget_is_shared_with_the_test_that_made_it() -> TestResult {
        let gadget = super::loader_gadget(4096);
        gadget.preload(0, b"on the medium".to_vec());
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);

        let device = block_on(backend.open(&0))?;
        assert!(device.scripted().is_none(), "this one is the emulator, not a script");
        // The same object, reached through the bus.
        let info = block_on(tdfu_core::dfu::descriptors::read_info(&device))?;
        assert_eq!(info.alts.len(), 3, "the shipped three-alt shape");
        assert_eq!(gadget.medium(0).as_deref().and_then(|m| m.get(..2)), Some(&b"on"[..]));
        Ok(())
    }

    /// And it enumerates as a gadget, which is what `ops::classify` decides a row on.
    #[test]
    fn an_emulated_gadget_classifies_as_one() -> TestResult {
        let gadget = super::loader_gadget(4096);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget_at(&gadget, vec![4, 2])]);
        let listing = block_on(backend.list())?;
        let row = listing.first().ok_or("one device")?;
        assert_eq!(ops::classify(&row.descriptors), Some(tdfu_core::model::Stage::Gadget));
        assert_eq!(
            row.descriptors.port_path,
            vec![4, 2],
            "it can sit on the bootrom's port"
        );
        Ok(())
    }

    /// The fake serves the descriptors it was given, unchanged.
    #[test]
    fn a_listing_carries_the_descriptors() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let listing = block_on(backend.list())?;
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].descriptors, gadget_descriptors(1, 9));
        assert_eq!(listing[0].id, 0);
        Ok(())
    }
}
