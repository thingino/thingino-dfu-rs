//! Doubles for both halves of a command: the wire and the bus.
//!
//! [`LoopbackConn`] records every frame [`dispatch`](super::dispatch) writes, so the
//! byte-exact request/response pins in this directory need no socket, no runtime and no
//! transport implementation: the commands are written against the frozen seam and nothing
//! else.
//!
//! [`FakeBackend`] is the bus, and it hands out one of two doubles per device.
//! [`MockTransport`] is **scripted**: it refuses any request that is not the next
//! expectation, which is how "detection executes nothing" is pinned rather
//! than asserted. [`FakeGadget`] is a **model** of the U-Boot loader, checked against
//! `f_dfu.c` rather than against what a host expects, which is how a whole `ops::write`
//! can be driven without pinning `tdfu-core`'s internals into this crate's tests
//! (a defect in a double silently removes coverage everywhere downstream).

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::rc::Rc;

use tdfu_core::addr::{self, Kseg1};
use tdfu_core::bootrom;
use tdfu_proto::{Command, ProgressBody, Status};
use tdfu_usb::gadget::{AltConfig, FakeGadget, GadgetConfig};
use tdfu_usb::mock::{Call, MockTransport, Reply};
use tdfu_usb::{
    BulkEndpoint, ControlIn, ControlOut, ControlType, DeviceDescriptors, Discovered, InterfaceSpec, LocalUsbBackend,
    LocalUsbTransport, Pipe, Recipient, UsbError, UsbErrorKind, pid, vid,
};

use super::Wire;
use super::state::{Activity, ActivityWatch};
use crate::errors::DaemonError;

/// Anything a test in this crate can fail with.
pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A private directory for one test, removed when it is done.
#[derive(Debug)]
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// Make one. `name` distinguishes concurrent tests within a process.
    ///
    /// # Errors
    /// Whatever `create_dir_all` raises.
    pub fn new(name: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("tdfu-daemon-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.0
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

// ---------------------------------------------------------------- the wire

/// One frame that left the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sent {
    /// The final `RESP_OK`/`RESP_ERROR`.
    Response(Status, Vec<u8>),
    /// A `RESP_LOG` line.
    Log(String),
    /// A `RESP_PROGRESS` body.
    Progress(ProgressBody),
}

/// A connection that keeps what it was handed.
///
/// The transcript is behind an `Rc` so a test can watch it while `dispatch` holds the
/// connection mutably — which is how "the frames interleave with the work" is pinned
/// rather than assumed.
#[derive(Debug)]
pub struct LoopbackConn {
    sent: Rc<RefCell<Vec<Sent>>>,
    /// HTTP attaches logs for every command, raw and WebSocket only for the
    /// three long ones.
    http: bool,
    /// Which command is in flight, as the real `Conn` keeps it
    /// (`transport/mod.rs:330-336`). `None` between requests, and then `log` and
    /// `progress` put nothing on the wire.
    current: Cell<Option<Command>>,
    /// Frames the attach gate refused, in order.
    ///
    /// Instrumentation, not wire: `sent()` is what a client would have seen. This list
    /// is what keeps [`report::pump`](super::report::pump)'s *own* gate observable now
    /// that the connection has one too. A `pump` that stopped consulting
    /// [`Wire::logs_enabled_for`] would still put nothing on the wire, because this gate
    /// would catch what it let through, and only this list would change.
    suppressed: RefCell<Vec<Sent>>,
    /// Frames left before writes start failing, modelling a client that went away.
    budget: Cell<Option<usize>>,
    /// What the daemon said it was doing as each frame went out, so a
    /// test can see the state *during* an operation and not only after it.
    watch: Option<ActivityWatch>,
    seen: RefCell<Vec<Activity>>,
}

impl LoopbackConn {
    /// A raw TCP or WebSocket client, with no command in flight.
    #[must_use]
    pub fn raw() -> Self {
        Self {
            sent: Rc::new(RefCell::new(Vec::new())),
            http: false,
            current: Cell::new(None),
            suppressed: RefCell::new(Vec::new()),
            budget: Cell::new(None),
            watch: None,
            seen: RefCell::new(Vec::new()),
        }
    }

    /// Put `cmd` in flight, as `Conn::next_request` does for the real connection
    /// (`transport/mod.rs:166`), and take it out again with `None`, as `Conn::respond`
    /// does (`:212`).
    ///
    /// Tests reach this through [`dispatch`]; a test that drives something narrower, a
    /// bare [`pump`](super::report::pump) or a bare `conn.log()`, uses [`during`] or this.
    ///
    /// [`during`]: LoopbackConn::during
    pub fn serving(&self, cmd: Option<Command>) {
        self.current.set(cmd);
    }

    /// The same as a builder, for a test that drives less than a whole [`dispatch`].
    #[must_use]
    pub fn during(self, cmd: Command) -> Self {
        self.current.set(Some(cmd));
        self
    }

    /// Frames the attach gate refused, in order. See the field.
    #[must_use]
    pub fn suppressed(&self) -> Vec<Sent> {
        self.suppressed.borrow().clone()
    }

    /// The attach gate, exactly as the real `Conn` applies it
    /// (`transport/mod.rs:339-341`): a command in flight, and logs enabled for it.
    fn logs_attached(&self) -> bool {
        self.current.get().is_some_and(|cmd| self.logs_enabled_for(cmd))
    }

    /// Record the daemon's [`Activity`] alongside every frame.
    #[must_use]
    pub fn watching(mut self, watch: ActivityWatch) -> Self {
        self.watch = Some(watch);
        self
    }

    /// The activity the daemon reported as each frame left, in order.
    #[must_use]
    pub fn activities(&self) -> Vec<Activity> {
        self.seen.borrow().clone()
    }

    /// The browser's HTTP POST transport.
    #[must_use]
    pub fn http() -> Self {
        Self {
            http: true,
            ..Self::raw()
        }
    }

    /// A client that vanishes after `frames` more frames: the precondition for a stuck
    /// state, which an earlier implementation's harness could not produce because it wrote
    /// the whole request and half-closed *before* the daemon accepted.
    #[must_use]
    pub fn failing_after(self, frames: usize) -> Self {
        self.budget.set(Some(frames));
        self
    }

    /// Everything written, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.borrow().clone()
    }

    /// A handle on the transcript that outlives the mutable borrow `dispatch` takes.
    #[must_use]
    pub fn transcript(&self) -> Rc<RefCell<Vec<Sent>>> {
        Rc::clone(&self.sent)
    }

    /// The final response frame, if one was sent.
    #[must_use]
    pub fn response(&self) -> Option<(Status, Vec<u8>)> {
        self.sent.borrow().iter().find_map(|frame| match frame {
            Sent::Response(status, payload) => Some((*status, payload.clone())),
            _ => None,
        })
    }

    /// The `RESP_ERROR` payload as text, if the response was one.
    #[must_use]
    pub fn error_text(&self) -> Option<String> {
        match self.response()? {
            (Status::Error, payload) => Some(String::from_utf8_lossy(&payload).into_owned()),
            _ => None,
        }
    }

    /// Every `RESP_PROGRESS` body, in order.
    #[must_use]
    pub fn progress_frames(&self) -> Vec<ProgressBody> {
        self.sent
            .borrow()
            .iter()
            .filter_map(|frame| match frame {
                Sent::Progress(body) => Some(body.clone()),
                _ => None,
            })
            .collect()
    }

    /// Every `RESP_LOG` line, in order.
    #[must_use]
    pub fn log_lines(&self) -> Vec<String> {
        self.sent
            .borrow()
            .iter()
            .filter_map(|frame| match frame {
                Sent::Log(line) => Some(line.trim_end_matches('\n').to_owned()),
                _ => None,
            })
            .collect()
    }

    fn record(&self, frame: Sent) -> Result<(), DaemonError> {
        if let Some(watch) = &self.watch {
            self.seen.borrow_mut().push(watch.get());
        }
        match self.budget.get() {
            Some(0) => {
                // A client that has gone: the write fails and the operation's future is
                // dropped mid-`await`, which is the precondition for a stuck state.
                return Err(DaemonError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
            }
            Some(left) => self.budget.set(Some(left.saturating_sub(1))),
            None => {}
        }
        self.sent.borrow_mut().push(frame);
        Ok(())
    }
}

impl Wire for LoopbackConn {
    /// The final frame, which is never gated: every command is answered.
    async fn respond(&mut self, status: Status, payload: &[u8]) -> Result<(), DaemonError> {
        self.record(Sent::Response(status, payload.to_vec()))
    }

    /// Gated, as `Conn::log` is (`transport/mod.rs:225-227`). Without this
    /// the double was *permissive*: every attach assertion in this directory
    /// exercised `report::pump`'s gate alone, so a handler writing a frame outside
    /// `pump` would have emitted one in every test here and none in production.
    ///
    /// Terminated as `Conn::log` terminates it: the frame on the wire ends in
    /// exactly one newline, and this double records what the wire would carry.
    /// [`LoopbackConn::log_lines`] hands the lines back without it.
    async fn log(&mut self, line: &str) -> Result<(), DaemonError> {
        let line = if line.ends_with('\n') {
            line.to_owned()
        } else {
            format!("{line}\n")
        };
        if !self.logs_attached() {
            self.suppressed.borrow_mut().push(Sent::Log(line));
            return Ok(());
        }
        self.record(Sent::Log(line))
    }

    /// Gated, as `Conn::progress` is (`transport/mod.rs:254-256`).
    async fn progress(&mut self, body: &ProgressBody) -> Result<(), DaemonError> {
        if !self.logs_attached() {
            self.suppressed.borrow_mut().push(Sent::Progress(body.clone()));
            return Ok(());
        }
        self.record(Sent::Progress(body.clone()))
    }

    /// The rule, exactly: `BOOTSTRAP`, `WRITE` (which carries erase and verify) and
    /// `READ` on every transport, and every command over HTTP
    /// (`dfu-remote/main.c:422`, `:515`, `:570`, `:658` set `g_log_client_fd` per
    /// operation; `:977` sets it for the whole HTTP request).
    fn logs_enabled_for(&self, cmd: Command) -> bool {
        self.http || matches!(cmd, Command::Bootstrap | Command::Write | Command::Read)
    }
}

/// [`commands::dispatch`](super::dispatch), with the connection put in the state the
/// transport puts the real one in.
///
/// `Conn::next_request` records the command in flight (`transport/mod.rs:166`) and
/// `Conn::respond` clears it (`:212`); `Conn::log` and `Conn::progress` then refuse early
/// unless the attach rule allows it. [`LoopbackConn`] models that gate, so it needs the
/// same fact, and [`Wire`] deliberately carries no `next_request` for it to learn from.
///
/// **Every test in this directory dispatches through here** rather than through
/// `commands::dispatch`, and that matters: with no gate on the double, a handler that
/// wrote a frame outside [`pump`](super::report::pump) emitted one in every test here and
/// none in production, and nothing would have noticed. A test that reaches for
/// `commands::dispatch` instead gets a connection with nothing in flight and no log or
/// progress frames, which fails its own assertions rather than passing quietly.
///
/// # Errors
/// Whatever [`dispatch`](super::dispatch) returns: a connection that is gone.
pub async fn dispatch<B, C>(
    conn: &mut LoopbackConn,
    state: &mut super::state::DaemonState<B, C>,
    cmd: Command,
    payload: &[u8],
) -> Result<(), DaemonError>
where
    B: LocalUsbBackend,
    C: tdfu_core::clock::Sleeper,
{
    conn.serving(Some(cmd));
    let outcome = super::dispatch(conn, state, cmd, payload).await;
    conn.serving(None);
    outcome
}

/// The frame of reference a `DISCOVER` leaves behind, without running one.
///
/// Every command that names a device resolves its `idx` against the listing this
/// connection was answered with, so a test that is about the *command* still has to have
/// asked. This seeds that listing from the bus as it stands, and opens nothing: a real
/// `DISCOVER` also detects every bootrom it finds, which would spend a scripted double's
/// expectations on a question the test is not asking.
///
/// # Errors
/// Whatever the backend's `list()` returns.
pub async fn seen<B, C>(state: &mut super::state::DaemonState<B, C>) -> Result<(), UsbError>
where
    B: LocalUsbBackend,
{
    let rows = rows_of(&state.backend).await?;
    state.remember_listing(rows);
    Ok(())
}

/// The rows a `DISCOVER` would answer with for the bus as it stands.
///
/// # Errors
/// Whatever the backend's `list()` returns.
pub async fn rows_of<B: LocalUsbBackend>(backend: &B) -> Result<Vec<super::state::Row>, UsbError> {
    let listing = backend.list().await?;
    Ok(listing
        .iter()
        .map(|device| super::state::Row::of(&device.descriptors, tdfu_core::ops::classify(&device.descriptors)))
        .collect())
}

// ---------------------------------------------------------------- the bus

/// A bootrom as enumeration sees it (the product string really does begin
/// with junk, and it is never compared for equality).
#[must_use]
pub fn bootrom_descriptors(bus: u8, address: u8, port_path: Vec<u8>) -> DeviceDescriptors {
    DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
        .with_product_string("\u{c3}\t USB Boot Device")
        .with_bus_address(bus, address)
        .with_port_path(port_path)
        .with_config_descriptor(vendor_config())
}

/// The bootrom's configuration: one vendor-class interface, **no DFU interface** — which
/// is what tells it apart from the gadget it shares a PID with.
fn vendor_config() -> Vec<u8> {
    let mut config = vec![9, 0x02, 32, 0, 1, 1, 0, 0x80, 0x32];
    config.extend_from_slice(&[9, 0x04, 0, 0, 2, 0xFF, 0x00, 0x00, 0]);
    config.extend_from_slice(&[7, 0x05, 0x81, 0x02, 0x00, 0x02, 0]);
    config.extend_from_slice(&[7, 0x05, 0x01, 0x02, 0x00, 0x02, 0]);
    config
}

/// The three registers of a T23N, from the bench capture in `detect/`.
#[must_use]
pub const fn t23_regs() -> [u32; 3] {
    [0x1002_3000, 0, 0]
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

/// One device on the fake bus.
pub struct FakeDevice {
    descriptors: DeviceDescriptors,
    opens: Opens,
}

impl core::fmt::Debug for FakeDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeDevice")
            .field("descriptors", &self.descriptors)
            .finish_non_exhaustive()
    }
}

/// Either double, behind one associated type.
#[derive(Debug)]
pub enum FakeTransport {
    /// A scripted transport, for the paths whose exact wire shape is the point.
    Scripted(MockTransport),
    /// The emulator, shared with the test that armed it.
    Gadget(Rc<FakeGadget>),
}

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

/// A canned USB bus.
#[derive(Debug)]
pub struct FakeBackend {
    /// Successive answers to `list()`; the last one repeats for ever, which is what
    /// makes a re-enumeration-window test terminate.
    listings: RefCell<Vec<Vec<FakeDevice>>>,
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

    /// A bus with nothing on it.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// A bus that answers each `list()` with the next entry, repeating the last.
    ///
    /// This is how the re-enumeration window is made falsifiable: a device that appears on
    /// the *n*th listing pins how many probes actually happened, where an earlier
    /// implementation's only caller passed `attempts: 1` and could not tell a retry from
    /// no retry.
    #[must_use]
    pub fn appearing(listings: Vec<Vec<FakeDevice>>) -> Self {
        Self {
            listings: RefCell::new(listings),
            failure: None,
            list_calls: Cell::new(0),
            opened: RefCell::new(Vec::new()),
        }
    }

    /// A bus that cannot be enumerated at all.
    #[must_use]
    pub fn listing_fails(self) -> Self {
        Self {
            failure: Some(UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device)),
            ..self
        }
    }

    /// How many times `list()` has been called — the window's probe count.
    #[must_use]
    pub fn list_calls(&self) -> usize {
        self.list_calls.get()
    }

    /// Which device indices were opened, in order.
    #[must_use]
    pub fn opened(&self) -> Vec<usize> {
        self.opened.borrow().clone()
    }

    /// Swap row `index` for a DFU gadget on the same physical port — the
    /// bootrom → gadget re-enumeration the port cache is about.
    ///
    /// The device number changes, as it does on a real re-enumeration: the host assigns
    /// a fresh one, and that is why an entry cannot be bound to the address alone.
    pub fn replace_with_gadget_on_the_same_port(&self, index: usize) {
        let mut listings = self.listings.borrow_mut();
        for listing in listings.iter_mut() {
            if let Some(device) = listing.get_mut(index) {
                let port_path = device.descriptors.port_path.clone();
                let bus = device.descriptors.bus;
                let address = device.descriptors.address.wrapping_add(1);
                *device = gadget_on(bus, address, port_path);
            }
        }
    }

    /// Take row `index` off the bus, from the next `list()` on.
    ///
    /// The shape no fixture here could express: a listing that **shrinks**. Unplug row 0
    /// and row 1 becomes row 0, which is how an index the client is holding comes to
    /// name a different camera.
    pub fn remove_row(&self, index: usize) {
        let mut listings = self.listings.borrow_mut();
        for listing in listings.iter_mut() {
            if index < listing.len() {
                listing.remove(index);
            }
        }
    }

    /// A U-Boot DFU gadget on a bus and port of the caller's choosing.
    ///
    /// Mirrored hubs on two controllers put the identical port path on two buses, and
    /// this is how a test says so.
    #[must_use]
    pub fn gadget_at_port(bus: u8, address: u8, port_path: Vec<u8>) -> FakeDevice {
        gadget_on(bus, address, port_path)
    }

    /// The same, holding `image` on its `flash` alt.
    #[must_use]
    pub fn gadget_at_port_holding(bus: u8, address: u8, port_path: Vec<u8>, image: &[u8]) -> FakeDevice {
        let device = gadget_sized(bus, address, port_path, image.len() as u64);
        if let Opens::Gadget(gadget) = &device.opens {
            gadget.preload(0, image.to_vec());
        }
        device
    }

    /// A bootrom on a bus and port of the caller's choosing, answering `regs`.
    #[must_use]
    pub fn bootrom_at_port(bus: u8, address: u8, port_path: Vec<u8>, regs: [u32; 3]) -> FakeDevice {
        Self::bootrom_at(bootrom_descriptors(bus, address, port_path), regs)
    }

    /// A bootrom that answers [`ops::detect`](tdfu_core::ops::detect) with `regs`.
    #[must_use]
    pub fn bootrom(regs: [u32; 3]) -> FakeDevice {
        Self::bootrom_at(bootrom_descriptors(1, 7, vec![4, 2]), regs)
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
    #[must_use]
    pub fn diagnosable_bootrom(soc_id: u32, window: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7, vec![4, 2]),
            opens: Opens::Script(Box::new(move |descriptors| {
                diag_script(descriptors.clone(), soc_id, window.clone())
            })),
        }
    }

    /// A bootrom scripted for a whole forced bootstrap of the two images.
    #[must_use]
    pub fn bootstrappable_bootrom(stage1: Vec<u8>, uboot: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7, vec![4, 2]),
            opens: Opens::Script(Box::new(move |descriptors| {
                bootstrap_script(descriptors.clone(), &stage1, &uboot)
            })),
        }
    }

    /// A bootrom scripted for detection **and then** a bootstrap, which is what an
    /// auto-detecting `CMD_BOOTSTRAP` does on one open transport.
    #[must_use]
    pub fn detectable_bootstrappable_bootrom(regs: [u32; 3], stage1: Vec<u8>, uboot: Vec<u8>) -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7, vec![4, 2]),
            opens: Opens::Script(Box::new(move |descriptors| {
                let device = detect_script(descriptors.clone(), regs);
                // `ops::detect` released the interface, so the bootstrap's first upload
                // claims again — but the configuration is already set, and contracts
                // D14 skips a `SET_CONFIGURATION` that would be a no-op.
                bootstrap_after(device, &stage1, &uboot)
            })),
        }
    }

    /// A U-Boot DFU gadget backed by the emulator, on the default port `[4, 3]`.
    #[must_use]
    pub fn gadget() -> FakeDevice {
        gadget_on(1, 9, vec![4, 3])
    }

    /// A gadget whose loader offers only `flash` — no `erase`, no `reboot`. The shape
    /// `Error::MissingAlt` comes from (`dfu.c:708`, `:756`).
    #[must_use]
    pub fn flash_only_gadget() -> FakeDevice {
        let gadget = Rc::new(FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash(
            "flash",
            64 * 1024,
        )])));
        let descriptors = gadget
            .descriptors()
            .clone()
            .with_bus_address(1, 9)
            .with_port_path(vec![4, 3]);
        FakeDevice {
            descriptors,
            opens: Opens::Gadget(gadget),
        }
    }

    /// A loader whose boot flash is **not** called `flash`, so this daemon and the C
    /// daemon disagree about its default alt.
    ///
    /// The C daemon writes `info.alts[0].alt` (`dfu-remote/main.c:351`) and would take
    /// `nor`; this daemon refuses, because there is one resolver and it does not guess.
    /// No shipped loader looks like this - every one names its boot flash `flash`
    /// - and the fixture exists only to drive the disagreement.
    #[must_use]
    pub fn gadget_without_a_flash_alt() -> FakeDevice {
        let config = GadgetConfig::new(vec![
            AltConfig::flash("nor", 64 * 1024),
            AltConfig::flash("sdcard", 64 * 1024),
            AltConfig::erase(),
            AltConfig::reboot(),
        ]);
        let gadget = Rc::new(FakeGadget::new(config));
        let descriptors = gadget
            .descriptors()
            .clone()
            .with_bus_address(1, 9)
            .with_port_path(vec![4, 3]);
        FakeDevice {
            descriptors,
            opens: Opens::Gadget(gadget),
        }
    }

    /// A gadget whose `flash` alt **is** `image`: the medium holds it and the alt is
    /// declared exactly that long.
    ///
    /// Both halves matter. `entity.left` comes from the alt's declared size and bytes
    /// past the medium read back as `0xFF` (`gadget/machine.rs:604`), exactly as a real
    /// flash does — so an alt declared longer than its contents is read to its declared
    /// length, and "the whole alt" would not be the image. Sizing them together is what
    /// lets a read test compare against the bytes it put there.
    #[must_use]
    pub fn gadget_holding(image: &[u8]) -> FakeDevice {
        let device = gadget_sized(1, 9, vec![4, 3], image.len() as u64);
        if let Opens::Gadget(gadget) = &device.opens {
            gadget.preload(0, image.to_vec());
        }
        device
    }

    /// The emulator behind row `index`, so a test can read the medium back.
    #[must_use]
    pub fn gadget_at(&self, index: usize) -> Option<Rc<FakeGadget>> {
        let listings = self.listings.borrow();
        let listing = listings.last()?;
        match &listing.get(index)?.opens {
            Opens::Gadget(gadget) => Some(Rc::clone(gadget)),
            _ => None,
        }
    }

    /// A device the OS refuses to open.
    #[must_use]
    pub fn refusing() -> FakeDevice {
        FakeDevice {
            descriptors: bootrom_descriptors(1, 7, vec![4, 2]),
            opens: Opens::Refuse(UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device)),
        }
    }

    /// A device running vendor firmware: the Ingenic VID, the firmware PID, and a
    /// configuration with no DFU interface: the classifier's third answer.
    #[must_use]
    pub fn firmware() -> FakeDevice {
        FakeDevice {
            descriptors: DeviceDescriptors::new(vid::INGENIC, pid::FIRMWARE)
                .with_product_string("Ingenic camera")
                .with_bus_address(1, 12)
                .with_port_path(vec![4, 8])
                .with_config_descriptor(vendor_config()),
            opens: Opens::Refuse(UsbError::new(UsbErrorKind::Unsupported, Pipe::Device)),
        }
    }

    /// A device whose descriptors classify as nothing at all: neither bootrom nor
    /// gadget.
    #[must_use]
    pub fn opaque() -> FakeDevice {
        FakeDevice {
            descriptors: DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
                .with_bus_address(1, 11)
                .with_port_path(vec![4, 9]),
            opens: Opens::Refuse(UsbError::new(UsbErrorKind::NoDevice, Pipe::Device)),
        }
    }
}

/// A three-alt U-Boot DFU gadget — `flash`, `erase`, `reboot` — as every shipped loader
/// presents itself.
fn gadget_on(bus: u8, address: u8, port_path: Vec<u8>) -> FakeDevice {
    gadget_sized(bus, address, port_path, 64 * 1024)
}

/// The same, with the `flash` alt declared `size` bytes long.
fn gadget_sized(bus: u8, address: u8, port_path: Vec<u8>, size: u64) -> FakeDevice {
    let config = GadgetConfig::new(vec![
        AltConfig::flash("flash", size),
        AltConfig::erase(),
        AltConfig::reboot(),
    ]);
    let gadget = Rc::new(FakeGadget::new(config));
    let descriptors = gadget
        .descriptors()
        .clone()
        .with_bus_address(bus, address)
        .with_port_path(port_path);
    FakeDevice {
        descriptors,
        opens: Opens::Gadget(gadget),
    }
}

const WORD_LEN: u32 = 4;

/// The bootrom claim: `SET_CONFIGURATION` then the interface (the first is skipped
/// when the device is already configured; a fresh mock is not).
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

/// One register read: `SET_DATA_ADDR`, `SET_DATA_LEN`, then four bytes little-endian.
fn read_register(device: MockTransport, address: Kseg1, word: u32) -> MockTransport {
    device
        .expecting(vendor_word(bootrom::request::SET_DATA_ADDR, address.get()), Reply::Done)
        .expecting(vendor_word(bootrom::request::SET_DATA_LEN, WORD_LEN), Reply::Done)
        .expecting(Call::BulkIn { len: 4 }, Reply::Data(word.to_le_bytes().to_vec()))
}

/// The whole of `ops::detect` for a non-T33 family: claim, three reads, release.
///
/// **No `PROG_STAGE1` anywhere in it**, which is detection's whole point and the
/// property this scripted double pins rather than merely permits: the C uploads a
/// 606-byte MIPS stub to answer the same question.
fn detect_script(descriptors: DeviceDescriptors, regs: [u32; 3]) -> MockTransport {
    let device = claim(MockTransport::new(descriptors));
    let device = read_register(device, addr::SOC_ID, regs[0]);
    let device = read_register(device, addr::SUBSOCTYPE1, regs[1]);
    let device = read_register(device, addr::SUBSOCTYPE2, regs[2]);
    device.expecting(Call::ReleaseInterface(0), Reply::Done)
}

/// The whole of `ops::diag`: the CPU-info hint (best-effort, before the claim), then
/// `soc_id` and the eFuse window, then the release.
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

/// One padded image's upload, exactly as `ops::bootstrap` puts it on the wire.
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

/// A whole successful bootstrap of `stage1` + `uboot` (raw; the script pads with the
/// op's own rule, so it mirrors the wire rather than the files).
fn bootstrap_script(descriptors: DeviceDescriptors, stage1: &[u8], uboot: &[u8]) -> MockTransport {
    bootstrap_onto(MockTransport::new(descriptors), false, stage1, uboot)
}

/// The same, appended to a script that has already configured the device — the
/// detect-then-bootstrap case.
fn bootstrap_after(device: MockTransport, stage1: &[u8], uboot: &[u8]) -> MockTransport {
    bootstrap_onto(device, true, stage1, uboot)
}

fn bootstrap_onto(mut device: MockTransport, configured: bool, stage1: &[u8], uboot: &[u8]) -> MockTransport {
    let stage1 = bootrom::pad_stage1(stage1);
    let uboot = bootrom::pad_stage1(uboot);
    let mut in_configuration = configured;
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
            // The device is already running U-Boot and never answers.
            // A failure here is the success path.
            Reply::Fail(UsbError::new(UsbErrorKind::NoDevice, Pipe::Device)),
        )
}
impl LocalUsbBackend for FakeBackend {
    type Transport = FakeTransport;
    /// The row's position in the listing — the same number `idx` takes.
    type DeviceId = usize;

    async fn list(&self) -> Result<Vec<Discovered<usize>>, UsbError> {
        let call = self.list_calls.get();
        self.list_calls.set(call.saturating_add(1));
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let listings = self.listings.borrow();
        let listing = listings.get(call).or_else(|| listings.last());
        Ok(listing
            .map(Vec::as_slice)
            .unwrap_or_default()
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
        let listings = self.listings.borrow();
        // The row the *current* listing has, which is the one `list()` just handed out.
        let call = self.list_calls.get().saturating_sub(1);
        let listing = listings
            .get(call)
            .or_else(|| listings.last())
            .ok_or_else(|| UsbError::new(UsbErrorKind::NoDevice, Pipe::Device))?;
        match listing.get(*id) {
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
    use super::{Command, LoopbackConn, ProgressBody, TestResult, Wire as _};
    use tdfu_usb::mock::block_on;

    fn body() -> ProgressBody {
        ProgressBody {
            percent: 50,
            stage: 3,
            message: "2048/4096 bytes".to_owned(),
        }
    }

    /// **The double carries the real `Conn`'s attach gate.**
    ///
    /// `Conn::log` and `Conn::progress` both begin `if !self.logs_attached()`
    /// (`transport/mod.rs:225-227`, `:254-256`); this recorded unconditionally, so every
    /// attach assertion in this directory exercised `report::pump`'s gate and nothing
    /// else. Correct today only because every handler that writes frames goes through
    /// `pump`; a handler that called `conn.log()` directly would have emitted a frame in
    /// every test here and none in production. A defect in a double in its quiet form:
    /// the double was not wrong, it was permissive.
    #[test]
    fn a_direct_write_obeys_the_attach_rule() -> TestResult {
        // A quiet command on raw TCP: nothing reaches the wire, and the double says so.
        let mut quiet = LoopbackConn::raw().during(Command::Discover);
        block_on(quiet.log("this must not reach a raw DISCOVER client"))?;
        block_on(quiet.progress(&body()))?;
        assert_eq!(quiet.sent(), Vec::new());
        assert_eq!(quiet.suppressed().len(), 2, "{:?}", quiet.suppressed());

        // The same two on a command that attaches.
        let mut writing = LoopbackConn::raw().during(Command::Write);
        block_on(writing.log("a write attaches"))?;
        block_on(writing.progress(&body()))?;
        assert_eq!(writing.sent().len(), 2);
        assert!(writing.suppressed().is_empty());

        // ... and over HTTP every command attaches (`dfu-remote/main.c:977`).
        let mut http = LoopbackConn::http().during(Command::Discover);
        block_on(http.log("visible over HTTP"))?;
        assert_eq!(http.sent().len(), 1);

        // With nothing in flight the connection is silent, which is what the real one is
        // between requests (`transport/mod.rs:339-341`, `:212`).
        let mut idle = LoopbackConn::raw();
        block_on(idle.log("between requests"))?;
        block_on(idle.progress(&body()))?;
        assert_eq!(idle.sent(), Vec::new());
        assert_eq!(idle.suppressed().len(), 2);
        Ok(())
    }

    /// The double records log frames the way `Conn::log` puts them on the wire, ending in
    /// exactly one newline, and `log_lines` hands them back as lines.
    #[test]
    fn a_log_frame_is_recorded_as_the_wire_carries_it() -> TestResult {
        let mut writing = LoopbackConn::raw().during(Command::Write);
        block_on(writing.log("DFU download complete"))?;
        block_on(writing.log("already terminated\n"))?;
        assert_eq!(
            writing.sent(),
            vec![
                super::Sent::Log("DFU download complete\n".to_owned()),
                super::Sent::Log("already terminated\n".to_owned()),
            ]
        );
        assert_eq!(writing.log_lines(), vec!["DFU download complete", "already terminated"]);
        Ok(())
    }

    /// The final frame is never gated: every command is answered, attached or not.
    #[test]
    fn the_final_frame_is_not_gated() -> TestResult {
        let mut conn = LoopbackConn::raw().during(Command::Discover);
        block_on(conn.respond(tdfu_proto::Status::Ok, b"payload"))?;
        assert_eq!(conn.sent().len(), 1);
        assert!(conn.suppressed().is_empty());
        Ok(())
    }
}
