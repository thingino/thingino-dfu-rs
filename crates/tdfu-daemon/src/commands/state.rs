//! What the daemon remembers between commands.
//!
//! # The state cannot stick, by construction
//!
//! An earlier implementation let a dropped connection mid-operation leave
//! the state at `writing` for the life of the process, a client Ctrl-C being enough, and
//! the file it lived in "documented in detail that this could not happen". A comment is
//! not a mechanism.
//!
//! The mechanism here is [`Busy`]: a guard whose `Drop` restores [`Activity::Idle`].
//! Every path out of an operation runs it — the success, the device failure, the
//! `?` on a socket write to a client that has gone, and a panic. There is no way to
//! *forget* it, because the only way to set the state is to take one, and nothing but
//! `Drop` ever clears it. That is the `Scratch` pattern, whose Drop-based cleanup an
//! audit cleared, applied to the one place an earlier implementation needed it and did
//! not have it.
//!
//! The C leaves `g_state` stuck on **six** early failures of its own, each a `return`
//! after a state was set and before the matching `g_state = "idle"`. Counted at the
//! `return`, which is the line that leaves it behind (an audit found this note saying
//! four, having missed the erase branch and one of the write's three temp-file guards):
//!
//! * the bootstrap's `usb_manager_init` guard, `dfu-remote/main.c:419`, set at `:408`;
//! * the erase branch's, `:514`, set at `:508`, with the resets at `:522` and `:528`
//!   never reached;
//! * the write's three temp-file guards, `:549`, `:555` and `:559`, and its own
//!   `usb_manager_init` guard, `:567`, all four of them set at `:537`.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use tdfu_core::Error;
use tdfu_core::model::{Stage, Variant};
use tdfu_usb::DeviceDescriptors;

/// The six strings `CMD_STATUS` can answer with.
///
/// `dfu-remote/main.c:64` declares `g_state` and the five busy values are set at `:408`,
/// `:508`, `:537`, `:578` and `:656`. It is cleared back to `"idle"` at **eleven**
/// separate sites, which is the count that made [`Busy`] worth having.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Activity {
    /// Nothing is running.
    #[default]
    Idle,
    /// `CMD_BOOTSTRAP` is uploading a loader pair.
    Bootstrapping,
    /// A wipe-token `CMD_WRITE` is erasing the chip.
    Erasing,
    /// `CMD_WRITE` is downloading.
    Writing,
    /// `CMD_WRITE`'s optional verify pass.
    Verifying,
    /// `CMD_READ` is uploading from the device.
    Reading,
}

impl Activity {
    /// The exact bytes `CMD_STATUS` puts in its OK payload.
    #[must_use]
    pub const fn wire_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Bootstrapping => "bootstrapping",
            Self::Erasing => "erasing",
            Self::Writing => "writing",
            Self::Verifying => "verifying",
            Self::Reading => "reading",
        }
    }
}

impl core::fmt::Display for Activity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.wire_str())
    }
}

/// Holds an [`Activity`] for as long as it lives, and restores [`Activity::Idle`] when
/// it dies.
///
/// See the module docs: this is the whole of the fix. It is
/// deliberately not `Clone` and carries no way to release early. A caller that wants
/// the state back drops it, and a caller that wants a different state takes another
/// (see [`Busy::switch`], which is how a write becomes a verify).
#[derive(Debug)]
pub struct Busy {
    slot: Rc<Cell<Activity>>,
}

impl Busy {
    /// Claim `activity` until this value is dropped.
    fn claim(slot: &Rc<Cell<Activity>>, activity: Activity) -> Self {
        slot.set(activity);
        Self { slot: Rc::clone(slot) }
    }

    /// Move to another activity without ever passing through `idle`.
    ///
    /// `CMD_WRITE` with the verify byte set is one operation in two phases, and the C
    /// switches `g_state` from `"writing"` to `"verifying"` in place
    /// (`dfu-remote/main.c:578`). Going through `idle` between them would let a
    /// `CMD_STATUS` on another connection see an idle daemon mid-write.
    pub fn switch(&self, activity: Activity) {
        self.slot.set(activity);
    }

    /// What is being held right now.
    #[must_use]
    pub fn activity(&self) -> Activity {
        self.slot.get()
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.slot.set(Activity::Idle);
    }
}

/// A handle that answers "what is the daemon doing right now".
///
/// Read-only by construction: it can observe [`Activity`] but never set one, so it
/// cannot become a second way to leave the state behind.
#[derive(Debug, Clone)]
pub struct ActivityWatch(Rc<Cell<Activity>>);

impl ActivityWatch {
    /// What the daemon is doing.
    #[must_use]
    pub fn get(&self) -> Activity {
        self.0.get()
    }
}

/// Where a device sits on the host: the bus it enumerated on and the ports it hangs
/// off under that bus's root hub.
///
/// **Both halves, always.** A port path is the port numbers below the root hub, so
/// `[4, 3]` exists on every bus in the machine and two cameras on mirrored hubs are
/// indistinguishable by path alone. The bus number is what separates them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Port {
    /// The bus the device enumerated on. `0` means the backend does not report one.
    pub bus: u8,
    /// The port numbers under the root hub. Empty on Android and WebUSB.
    pub path: Vec<u8>,
}

impl Port {
    /// Where enumeration says this device is.
    #[must_use]
    pub fn of(descriptors: &DeviceDescriptors) -> Self {
        Self {
            bus: descriptors.bus,
            path: descriptors.port_path.clone(),
        }
    }

    /// Can a device be followed here across a re-enumeration?
    ///
    /// Only when both halves are known. An empty path names every device the backend
    /// cannot place, and a bus of `0` names every bus, so either one turns "the device
    /// that was here" into "some device", which is how a flash reaches the wrong camera.
    #[must_use]
    pub fn is_followable(&self) -> bool {
        self.bus != 0 && !self.path.is_empty()
    }

    /// How to name it in a message: `bus 1 port 4.3`.
    #[must_use]
    pub fn describe(&self) -> String {
        let path = self.path.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
        match (self.bus, path.is_empty()) {
            (0, true) => "an unknown port".to_owned(),
            (0, false) => format!("port {path}"),
            (bus, true) => format!("bus {bus}"),
            (bus, false) => format!("bus {bus} port {path}"),
        }
    }
}

/// What enumeration says the device at a [`Port`] *is*.
///
/// The device number plus the two descriptor ids. A camera swapped for another at the
/// same port changes the ids or the number or both, and a re-plug of the same camera
/// changes the number, so an identity that moved means the thing at that port is not
/// the thing that was measured there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// The device number the host assigned.
    pub address: u8,
    /// `idVendor`.
    pub vendor: u16,
    /// `idProduct`.
    pub product: u16,
}

impl Identity {
    /// The identity of an enumerated device.
    #[must_use]
    pub const fn of(descriptors: &DeviceDescriptors) -> Self {
        Self {
            address: descriptors.address,
            vendor: descriptors.vendor_id,
            product: descriptors.product_id,
        }
    }
}

/// One row of the listing a `DISCOVER` answered with.
///
/// This is the client's frame of reference: an `idx` on the wire names a row of the
/// listing the client was given, not a position in the bus as it stands when the next
/// command arrives. Keeping the row is what lets the daemon say "the device you named
/// is gone" instead of acting on whatever slid into its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Where the device was.
    pub port: Port,
    /// What it was.
    pub identity: Identity,
    /// Bootrom, gadget, firmware, or `None` for "the descriptors cannot tell".
    pub stage: Option<Stage>,
    /// A `BOOTSTRAP` acted on this row, so the device at [`Row::port`] is expected back
    /// as a DFU gadget with a new device number. Nothing else licenses an identity
    /// change at a port.
    pub expect_gadget: bool,
}

impl Row {
    /// The row an enumerated device makes.
    #[must_use]
    pub fn of(descriptors: &DeviceDescriptors, stage: Option<Stage>) -> Self {
        Self {
            port: Port::of(descriptors),
            identity: Identity::of(descriptors),
            stage,
            expect_gadget: false,
        }
    }
}

/// The listing the daemon's most recent `DISCOVER` answered with.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Listing {
    rows: Vec<Row>,
}

impl Listing {
    /// The listing of these rows.
    #[must_use]
    pub fn new(rows: Vec<Row>) -> Self {
        Self { rows }
    }

    /// The row an `idx` names, or `None` when the listing was shorter than that.
    #[must_use]
    pub fn row(&self, index: u8) -> Option<&Row> {
        self.rows.get(usize::from(index))
    }

    /// How many rows the client was given.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Was the listing empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Record that a bootstrap was run against `index`, so its device is expected back
    /// as a gadget on the same port with a different device number.
    pub fn expect_gadget_at(&mut self, index: u8) {
        if let Some(row) = self.rows.get_mut(usize::from(index)) {
            row.expect_gadget = true;
        }
    }
}

/// The SoC detected at bootrom stage, remembered per physical port.
///
/// A DFU gadget cannot be re-probed for its SoC — it is past the bootrom — so the only
/// way to answer `DISCOVER`'s `variant` byte for one is to remember what was on that
/// physical port before the bootstrap. The port survives the re-enumeration; the device
/// number does not, and neither does the index.
///
/// **The key is the bus and the port path together, and the entry carries the identity
/// it was measured on.** A detection is a fact about one piece of silicon: answering it
/// for whatever is at those port numbers now reports camera A's SoC for camera B, on a
/// mirrored hub or after a swap. The one identity change an entry survives is the
/// re-enumeration this daemon itself caused, which [`VariantCache::put`]'s
/// `expect_gadget` records and [`VariantCache::get`] consumes exactly once.
///
/// Sixteen entries, cleared only by a restart, exactly as `dfu-remote/main.c:201-231`.
/// Two differences from the C, both deliberate:
///
/// * **A miss is a miss.** The C pre-seeds every device with ordinal 6 (`t31x`) at
///   `libtdfu/src/usb/manager.c:138` and `:227`, so a gadget it knows nothing about is
///   reported as a T31X — a guess rendered as a fact, which a client will then send back
///   as a `--cpu` value. Here a miss is `None` and the wire byte
///   is [`WireVariant::UNKNOWN`](tdfu_proto::WireVariant::UNKNOWN).
/// * **Eviction is least-recently-used, not "always slot 0"** (`main.c:220`, `if (slot < 0) slot = 0;`). Sixteen
///   ports is more than any bench has, so this is not load-bearing; it is one line and
///   it stops a seventeenth device evicting the entry for the one being flashed.
#[derive(Debug, Default)]
pub struct VariantCache {
    entries: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    port: Port,
    /// The device the variant was measured on.
    identity: Identity,
    /// One re-enumeration is expected at this port, because this daemon bootstrapped
    /// the device. Consumed by the first lookup that finds a gadget there.
    expect_gadget: bool,
    variant: Variant,
    /// Monotonic use counter; the smallest is evicted.
    used: u64,
}

impl VariantCache {
    /// Sixteen, as the C has (`dfu-remote/main.c:201`, `#define VCACHE_N 16`).
    pub const CAPACITY: usize = 16;

    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `variant` for the device that is `identity` at `port`.
    ///
    /// `expect_gadget` says a bootstrap has just been run on it, so the one identity
    /// change that follows is this daemon's own doing.
    ///
    /// A port that cannot be followed is not remembered, as the C refuses an empty one
    /// at `main.c:213`: without a bus and a path there is nothing to correlate the
    /// gadget back to, and a key that names several devices hands the next unrelated
    /// gadget somebody else's SoC. Android and WebUSB have no port path.
    pub fn put(&mut self, port: &Port, identity: Identity, expect_gadget: bool, variant: Variant) {
        if !port.is_followable() {
            return;
        }
        let used = self.next_tick();
        if let Some(entry) = self.entries.iter_mut().find(|entry| entry.port == *port) {
            entry.identity = identity;
            entry.expect_gadget = expect_gadget;
            entry.variant = variant;
            entry.used = used;
            return;
        }
        if self.entries.len() >= Self::CAPACITY
            && let Some(oldest) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(at, _)| at)
        {
            self.entries.swap_remove(oldest);
        }
        self.entries.push(Entry {
            port: port.clone(),
            identity,
            expect_gadget,
            variant,
            used,
        });
    }

    /// What was detected on the device that is `identity` at `port`.
    ///
    /// A different identity at the same port is a different device, and the answer is
    /// `None` with the stale entry dropped: the detection belongs to the silicon it was
    /// measured on and not to a set of port numbers. The single exception is the
    /// re-enumeration a `BOOTSTRAP` here caused, and the entry then rebinds to the
    /// gadget it finds, once, so a camera swapped in afterwards is a miss like any other.
    pub fn get(&mut self, port: &Port, identity: Identity, is_gadget: bool) -> Option<Variant> {
        if !port.is_followable() {
            return None;
        }
        let used = self.next_tick();
        let at = self.entries.iter().position(|entry| entry.port == *port)?;
        let entry = self.entries.get_mut(at)?;
        if entry.identity != identity {
            if !(entry.expect_gadget && is_gadget) {
                self.entries.swap_remove(at);
                return None;
            }
            // The device this daemon bootstrapped, back as the gadget it was told to
            // become. Bind the entry to it, so the next swap at this port is a miss.
            entry.identity = identity;
            entry.expect_gadget = false;
        }
        entry.used = used;
        Some(entry.variant)
    }

    /// How many ports are remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is nothing remembered?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn next_tick(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.used)
            .max()
            .unwrap_or(0)
            .wrapping_add(1)
    }
}

/// The post-bootstrap re-enumeration window.
///
/// 120 probes at 250 ms. The local CLI's `--wait` waits for ever; a daemon cannot block
/// a client for ever, and 30 s covers the ~8-10 s MMC/NAND-probing loaders that made the
/// old 5 s window emit spurious `Device not found` (`c8a2c59`, 2026-07-23).
///
/// **A parameter, not a constant**, because an earlier implementation's version was
/// unfalsifiable: its only caller passed `attempts: 1, backoff: 0`, so a `pick_alt` that
/// never retried would have passed every test. Here the window travels
/// in [`DaemonState`] and the tests drive the real default through a
/// [`RecordingClock`](tdfu_core::clock::RecordingClock), which records what was slept
/// for without living through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// How many times to look for the gadget.
    pub probes: u32,
    /// How long to wait between two looks.
    pub interval: Duration,
}

impl Window {
    /// 120 probes (`dfu-remote/main.c:344`).
    pub const PROBES: u32 = 120;
    /// 250 ms apart (`dfu-remote/main.c:353`, `usleep(250000)`).
    pub const INTERVAL: Duration = Duration::from_millis(250);

    /// The longest this window can sleep for.
    ///
    /// `(probes - 1) * interval` — **119** intervals, not 120, because the sleep is
    /// *between* probes. The C sleeps after every failed probe including the last one
    /// (`main.c:344-354`), which spends a final 250 ms and then returns `-1` regardless;
    /// that quarter-second buys nothing. The same "the last backoff entry is
    /// unreachable" note is already on `bootrom::VENDOR_RETRY_BACKOFF` for the identical
    /// reason.
    #[must_use]
    pub fn budget(self) -> Duration {
        self.interval.saturating_mul(self.probes.saturating_sub(1))
    }
}

impl Default for Window {
    fn default() -> Self {
        Self {
            probes: Self::PROBES,
            interval: Self::INTERVAL,
        }
    }
}

/// Everything one daemon process carries across commands.
///
/// Generic over the backend and the clock for the reason the CLI is: nothing in this
/// crate names `NativeBackend`, so every command is testable against
/// [`FakeGadget`](tdfu_usb::gadget::FakeGadget) with no bus. The audit's note on attempt
/// one's CLI was that `main.rs` was 6% covered because the backend was hard-wired, and
/// that *"the daemon next door had already solved this with a default type parameter
/// plus a fake backend"* — this is that shape, kept.
#[derive(Debug)]
#[non_exhaustive]
pub struct DaemonState<B, C> {
    /// The bus.
    pub backend: B,
    /// The clock every operation and the re-enumeration window wait on.
    pub clock: C,
    /// Where `BOOTSTRAP` looks for a variant's loader pair.
    pub firmware_dir: PathBuf,
    /// Where `READ` stages the image it is about to send. The C uses
    /// `/tmp` on unix and `%TEMP%` on Windows (`dfu-remote/main.c:637-648`).
    pub staging_dir: PathBuf,
    /// The re-enumeration window, injectable so it can be pinned.
    pub window: Window,
    /// The port → SoC memory.
    pub variants: VariantCache,
    /// The listing the last `DISCOVER` answered with, which is what every `idx` on the
    /// wire is a position in. `None` until a client has asked for one.
    listing: Option<Listing>,
    activity: Rc<Cell<Activity>>,
    cancel: Rc<Cell<bool>>,
}

impl<B, C> DaemonState<B, C> {
    /// A fresh daemon: idle, remembering nothing.
    pub fn new(backend: B, clock: C, firmware_dir: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            clock,
            firmware_dir: firmware_dir.into(),
            staging_dir: std::env::temp_dir(),
            window: Window::default(),
            variants: VariantCache::new(),
            listing: None,
            activity: Rc::new(Cell::new(Activity::Idle)),
            cancel: Rc::new(Cell::new(false)),
        }
    }

    /// Keep `rows` as the frame of reference every later `idx` is resolved against.
    ///
    /// `CMD_DISCOVER` calls this with the rows it just answered with, so the numbers the
    /// client is looking at and the numbers the daemon resolves are the same numbers.
    pub fn remember_listing(&mut self, rows: Vec<Row>) {
        self.listing = Some(Listing::new(rows));
    }

    /// Drop the frame of reference; a client then has to run `DISCOVER` again before it
    /// can name a device.
    ///
    /// One client's listing is not another's: the indexes in it were answered to the
    /// client that asked, and a client that has not run `DISCOVER` has no device
    /// numbering of its own to be held to.
    pub fn forget_listing(&mut self) {
        self.listing = None;
    }

    /// The row `index` names in the last listing.
    ///
    /// # Errors
    /// [`Error::Invalid`] when no `DISCOVER` has been answered yet, or
    /// when the listing was shorter than `index`. Both are parameter faults in the
    /// request and neither touches the bus: the client is naming a device by a number
    /// that means nothing here, and the fix in both cases is to run `DISCOVER`.
    pub fn row(&self, index: u8) -> Result<&Row, Error> {
        let Some(listing) = self.listing.as_ref() else {
            return Err(Error::Invalid(format!(
                "device {index}: no device list has been requested yet; run DISCOVER first"
            )));
        };
        listing.row(index).ok_or_else(|| {
            Error::Invalid(match listing.len() {
                0 => "no Ingenic devices were found by the last DISCOVER".to_owned(),
                1 => format!("device {index}: the last DISCOVER found 1 Ingenic device, index 0"),
                count => format!(
                    "device {index}: the last DISCOVER found {count} Ingenic devices, indexes 0-{}",
                    count - 1
                ),
            })
        })
    }

    /// Record that a bootstrap ran against `index`, so the device at that row's port is
    /// expected back as a DFU gadget with a new device number.
    pub fn expect_gadget_at(&mut self, index: u8) {
        if let Some(listing) = self.listing.as_mut() {
            listing.expect_gadget_at(index);
        }
    }

    /// Stage `READ` somewhere other than the system temp directory.
    #[must_use]
    pub fn with_staging_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.staging_dir = dir.into();
        self
    }

    /// Use a different re-enumeration window. Tests only, in practice.
    #[must_use]
    pub const fn with_window(mut self, window: Window) -> Self {
        self.window = window;
        self
    }

    /// What `CMD_STATUS` answers right now.
    #[must_use]
    pub fn activity(&self) -> Activity {
        self.activity.get()
    }

    /// A read-only handle on the state that outlives a borrow of the daemon.
    ///
    /// Nothing needs to read the state concurrently *today* — one
    /// client at a time, commands sequential. It exists because the alternative for
    /// observing the state **during** an operation is not to observe it at all, and
    /// the stuck-state bug is precisely a bug about what the state is while a
    /// command is running. An earlier implementation had a file documenting that the
    /// state could not stick and no way to watch it.
    #[must_use]
    pub fn watch(&self) -> ActivityWatch {
        ActivityWatch(Rc::clone(&self.activity))
    }

    /// Claim an activity for the duration of an operation. See [`Busy`].
    #[must_use]
    pub fn busy(&self, activity: Activity) -> Busy {
        Busy::claim(&self.activity, activity)
    }

    /// Record that a cancel was asked for.
    ///
    /// **This does not stop anything, and neither does the C's** (`main.c:60`, `:738`).
    /// The difference between the two is only that this one could: commands are
    /// serialised on a single connection with one client at a time, so a
    /// `CMD_CANCEL` cannot reach the daemon while an operation is running, and there is
    /// nothing for the flag to interrupt. A real cancellation waits on a
    /// transport that can deliver an out-of-band frame; the hook for it is one condition
    /// in `report::pump`'s loop.
    ///
    /// Stated flatly rather than dressed up, because a doc that reads as though a gap
    /// were closed is what an audit caught an earlier implementation doing next to the
    /// two bugs those docs sat beside.
    pub fn cancel(&self) {
        self.cancel.set(true);
    }

    /// Has a cancel arrived since the current operation started?
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.cancel.get()
    }

    /// Clear the cancel flag, which every operation does before it starts — the same
    /// four places the C clears `g_cancel` (`main.c:409`, `:509`, `:538`, `:657`).
    pub fn arm(&self) {
        self.cancel.set(false);
    }

    /// Where a variant's loaders live.
    #[must_use]
    pub fn firmware_dir(&self) -> &Path {
        &self.firmware_dir
    }
}

#[cfg(test)]
mod tests {
    use super::{Activity, DaemonState, Identity, Port, Row, VariantCache, Window};
    use core::time::Duration;
    use tdfu_core::Error;
    use tdfu_core::model::{Stage, Variant};

    fn state() -> DaemonState<(), ()> {
        DaemonState::new((), (), "firmware")
    }

    /// The six strings, byte for byte. `dfu-remote/main.c:734` sends
    /// `strlen(g_state)` bytes with no NUL.
    #[test]
    fn rpc_status_strings() {
        for (activity, text) in [
            (Activity::Idle, "idle"),
            (Activity::Bootstrapping, "bootstrapping"),
            (Activity::Erasing, "erasing"),
            (Activity::Writing, "writing"),
            (Activity::Verifying, "verifying"),
            (Activity::Reading, "reading"),
        ] {
            assert_eq!(activity.wire_str(), text);
            assert_eq!(activity.to_string(), text);
        }
        assert_eq!(Activity::default(), Activity::Idle);
    }

    /// The stuck state, at the level of the mechanism: the guard restores
    /// `idle` when it is dropped, whatever dropped it.
    #[test]
    fn the_state_returns_to_idle_when_the_guard_dies() {
        let state = state();
        assert_eq!(state.activity(), Activity::Idle);
        {
            let busy = state.busy(Activity::Writing);
            assert_eq!(state.activity(), Activity::Writing);
            assert_eq!(busy.activity(), Activity::Writing);
        }
        assert_eq!(state.activity(), Activity::Idle, "a dropped guard restores idle");
    }

    /// And through a panic, which is the case a `defer`-by-hand cannot cover.
    ///
    /// A `Drop` guard is the only construct that survives an unwind, and that is the
    /// argument for it over "remember to reset the state on every path": an earlier
    /// implementation had twelve reset sites and still lost one.
    #[expect(
        clippy::panic,
        reason = "the unwind is the subject: a guard that survives it is the whole claim"
    )]
    #[test]
    fn the_state_returns_to_idle_through_a_panic() {
        let state = state();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _busy = state.busy(Activity::Reading);
            assert_eq!(state.activity(), Activity::Reading);
            panic!("the operation blew up");
        }));
        assert!(unwound.is_err());
        assert_eq!(state.activity(), Activity::Idle);
    }

    /// A write that verifies is one operation in two phases and never passes through
    /// `idle` between them (`dfu-remote/main.c:578`).
    #[test]
    fn a_write_switches_to_verifying_without_going_idle() {
        let state = state();
        let busy = state.busy(Activity::Writing);
        busy.switch(Activity::Verifying);
        assert_eq!(state.activity(), Activity::Verifying);
        drop(busy);
        assert_eq!(state.activity(), Activity::Idle);
    }

    fn port(bus: u8, path: &[u8]) -> Port {
        Port {
            bus,
            path: path.to_vec(),
        }
    }

    fn ident(address: u8) -> Identity {
        Identity {
            address,
            vendor: 0xA108,
            product: 0xC309,
        }
    }

    /// By bus and port path, sixteen entries, and a miss is a miss.
    #[test]
    fn fe_daemon_vcache_by_port() {
        let mut cache = VariantCache::new();
        cache.put(&port(1, &[4, 2]), ident(7), false, Variant::T23n);
        cache.put(&port(1, &[4, 3]), ident(8), false, Variant::T41nq);

        assert_eq!(cache.get(&port(1, &[4, 2]), ident(7), false), Some(Variant::T23n));
        assert_eq!(cache.get(&port(1, &[4, 3]), ident(8), false), Some(Variant::T41nq));
        // A different port is not this device.
        assert_eq!(cache.get(&port(1, &[4, 4]), ident(9), false), None);
        // A prefix is not the same port either.
        assert_eq!(cache.get(&port(1, &[4]), ident(7), false), None);
        // Re-detection on the same port replaces rather than duplicates.
        cache.put(&port(1, &[4, 2]), ident(7), false, Variant::T31x);
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(7), false), Some(Variant::T31x));
        assert_eq!(cache.len(), 2);
        // Both directions: a cache with entries is not empty. Only ever asserting the
        // `true` case lets `is_empty` be replaced with `true`, which `cargo mutants`
        // duly did.
        assert!(!cache.is_empty());
        assert!(VariantCache::new().is_empty());
    }

    /// **The same port number on another bus is another device.** Port `[4, 2]` exists
    /// on every bus in the machine, and a bench with two controllers and mirrored hubs
    /// has two cameras with the identical path.
    #[test]
    fn the_same_port_number_on_another_bus_is_another_device() {
        let mut cache = VariantCache::new();
        cache.put(&port(1, &[4, 2]), ident(7), false, Variant::T23n);
        assert_eq!(
            cache.get(&port(2, &[4, 2]), ident(7), false),
            None,
            "bus 2 is not bus 1"
        );
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(7), false), Some(Variant::T23n));
        // Both buses can be remembered at once, and they do not overwrite each other.
        cache.put(&port(2, &[4, 2]), ident(7), false, Variant::T31x);
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(7), false), Some(Variant::T23n));
        assert_eq!(cache.get(&port(2, &[4, 2]), ident(7), false), Some(Variant::T31x));
        assert_eq!(cache.len(), 2);
    }

    /// **A detection is reported only for the device it was measured on.** A camera
    /// swapped for another at the same port, or the same camera re-plugged, has a
    /// different device number, and the entry goes rather than answering for it.
    #[test]
    fn a_different_device_at_the_same_port_is_not_the_cached_one() {
        let mut cache = VariantCache::new();
        cache.put(&port(1, &[4, 2]), ident(7), false, Variant::T23n);
        assert_eq!(
            cache.get(&port(1, &[4, 2]), ident(11), true),
            None,
            "another device number at the same port is another device"
        );
        assert!(cache.is_empty(), "and the stale entry is gone");

        // The one licensed identity change: the gadget this daemon's own bootstrap
        // asked for. It is consumed, so a swap after it is a miss.
        cache.put(&port(1, &[4, 2]), ident(7), true, Variant::T23n);
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(11), true), Some(Variant::T23n));
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(11), true), Some(Variant::T23n));
        assert_eq!(
            cache.get(&port(1, &[4, 2]), ident(12), true),
            None,
            "the expectation is spent on the first gadget that used it"
        );

        // And a bootstrap's expectation does not excuse something that is not a gadget.
        cache.put(&port(1, &[4, 2]), ident(7), true, Variant::T23n);
        assert_eq!(cache.get(&port(1, &[4, 2]), ident(11), false), None);
    }

    /// A device with no followable port is not remembered: there is nothing to correlate
    /// the gadget back to, and a key that names several devices would hand the next
    /// gadget somebody else's SoC (`dfu-remote/main.c:213`).
    #[test]
    fn a_device_with_no_port_path_is_not_cached() {
        let mut cache = VariantCache::new();
        cache.put(&port(1, &[]), ident(7), false, Variant::T31x);
        assert!(cache.is_empty());
        assert_eq!(cache.get(&port(1, &[]), ident(7), false), None);
        // A bus of 0 is "the backend does not know", and is refused the same way.
        cache.put(&port(0, &[4, 2]), ident(7), false, Variant::T31x);
        assert!(cache.is_empty());
        assert_eq!(cache.get(&port(0, &[4, 2]), ident(7), false), None);
    }

    /// Sixteen entries, and the seventeenth evicts the least recently used rather than
    /// the C's unconditional slot 0.
    #[test]
    fn the_cache_holds_sixteen_and_evicts_the_least_recently_used() {
        let mut cache = VariantCache::new();
        for path in 0..16_u8 {
            cache.put(&port(1, &[1, path]), ident(7), false, Variant::T31x);
        }
        assert_eq!(cache.len(), VariantCache::CAPACITY);
        // Touch the oldest so it is no longer the eviction candidate.
        assert_eq!(cache.get(&port(1, &[1, 0]), ident(7), false), Some(Variant::T31x));
        cache.put(&port(1, &[1, 99]), ident(7), false, Variant::T40n);
        assert_eq!(cache.len(), VariantCache::CAPACITY);
        assert_eq!(
            cache.get(&port(1, &[1, 0]), ident(7), false),
            Some(Variant::T31x),
            "the touched entry survived"
        );
        assert_eq!(
            cache.get(&port(1, &[1, 1]), ident(7), false),
            None,
            "the least recently used went"
        );
        assert_eq!(cache.get(&port(1, &[1, 99]), ident(7), false), Some(Variant::T40n));
    }

    /// The frame of reference: an `idx` names a row of the listing the client was last
    /// given, and a command that arrives before any `DISCOVER` has nothing to name.
    #[test]
    fn an_index_names_a_row_of_the_last_listing() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = state();
        let Err(Error::Invalid(unasked)) = state.row(0) else {
            return Err("a command before any DISCOVER must be refused".into());
        };
        assert!(unasked.contains("run DISCOVER first"), "{unasked}");

        let rows = vec![
            Row {
                port: port(1, &[4, 3]),
                identity: ident(7),
                stage: Some(Stage::Bootrom),
                expect_gadget: false,
            },
            Row {
                port: port(2, &[4, 3]),
                identity: ident(9),
                stage: Some(Stage::Gadget),
                expect_gadget: false,
            },
        ];
        state.remember_listing(rows.clone());
        assert_eq!(state.row(0)?, &rows[0]);
        assert_eq!(state.row(1)?, &rows[1]);
        let Err(Error::Invalid(past_the_end)) = state.row(2) else {
            return Err("an index past the listing must be refused".into());
        };
        assert!(past_the_end.contains("indexes 0-1"), "{past_the_end}");

        // A bootstrap marks its row, and only its row.
        state.expect_gadget_at(0);
        assert!(state.row(0)?.expect_gadget);
        assert!(!state.row(1)?.expect_gadget);

        // Forgetting leaves nothing to index until the next DISCOVER.
        state.forget_listing();
        assert!(state.row(0).is_err());
        Ok(())
    }

    /// A port names itself the way a refusal has to read.
    #[test]
    fn a_port_says_where_it_is() {
        assert_eq!(port(1, &[4, 3]).describe(), "bus 1 port 4.3");
        assert_eq!(port(2, &[]).describe(), "bus 2");
        assert_eq!(port(0, &[4]).describe(), "port 4");
        assert_eq!(port(0, &[]).describe(), "an unknown port");
        assert!(port(1, &[4, 3]).is_followable());
        assert!(!port(0, &[4, 3]).is_followable());
        assert!(!port(1, &[]).is_followable());
    }

    /// The window's numbers, and the budget the loop actually spends.
    #[test]
    fn fe_daemon_reenum_window_constants() {
        let window = Window::default();
        assert_eq!(window.probes, 120, "dfu-remote/main.c:344");
        assert_eq!(window.interval, Duration::from_millis(250), "main.c:353");
        // 119 gaps between 120 probes: the C's 120th sleep buys nothing.
        assert_eq!(window.budget(), Duration::from_millis(29_750));
        assert_eq!(Window::PROBES, 120);
        assert_eq!(Window::INTERVAL, Duration::from_millis(250));
    }

    /// A window of one probe never sleeps: the shape an earlier implementation's only
    /// caller used (`attempts: 1, backoff: 0`), kept expressible so a test can say so out
    /// loud rather than pass by accident.
    #[test]
    fn a_single_probe_window_has_no_budget() {
        let window = Window {
            probes: 1,
            interval: Duration::from_millis(250),
        };
        assert_eq!(window.budget(), Duration::ZERO);
        assert_eq!(Window { probes: 0, ..window }.budget(), Duration::ZERO);
    }

    /// The flag is set and cleared. **Nothing reads it**: see `DaemonState::cancel` and
    /// `commands::dispatch`'s `Request::Cancel` arm, which say why an operation already
    /// in flight is not interrupted.
    #[test]
    fn cancel_is_armed_and_cleared_per_operation() {
        let state = state();
        assert!(!state.cancelled());
        state.cancel();
        assert!(state.cancelled());
        state.arm();
        assert!(!state.cancelled(), "every operation clears it before it starts");
    }
}
