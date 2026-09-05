//! Executing a [`Plan`], against any backend and any clock.
//!
//! This is the whole of what `main` does, minus the process: `main` chooses
//! [`NativeBackend`](tdfu_usb::native::NativeBackend) and
//! [`BlockingClock`](tdfu_core::clock::BlockingClock), and everything below is driven in
//! tests against a scripted bus and a clock that records rather than waits.
//!
//! # The order of a run
//!
//! 1. **What this build can do at all** (`unsupported`) — before a file is opened, a
//!    device is listed or a wait begins. An operation this build cannot perform must not
//!    first bootstrap a camera and then refuse: a USB-boot is not free, and on most of
//!    these boards it costs the operator a boot pin and a power cycle to set up.
//! 2. **Every local file** ([`images::preflight`]) — the C claims the interface first
//!    (`dfu.c:1186` claims, `dfu.c:1219` loads), so a path typo costs bus work there and
//!    nothing here.
//! 3. **`--wait`**, if asked for.
//! 4. **The actions**, in the fixed order, which [`Plan::new`] already fixed.
//!
//! # Failures carry the operation that produced them
//!
//! [`Failure`] pairs the error with its [`OpClass`], so the exit code is the *running
//! operation's* class rather than a single global guess. The codes split 1 (device)
//! from 2 (transfer) exactly along that line, and `exit::exit_code` already overrides
//! both with 3 for a file error whatever was running.

use std::io::Write;

use tdfu_core::clock::Sleeper;
use tdfu_core::model::{AltSel, Detection, Stage, Variant};
use tdfu_core::{Error, Progress, ops};
use tdfu_usb::LocalUsbBackend;

use crate::alt;
use crate::exit::{self, OpClass};
use crate::images::{self, Blobs, Loaded};
use crate::list::{self, Listing};
use crate::loaders;
use crate::plan::{Action, BootstrapTrigger, Plan};
use crate::render;
use crate::target::{self, Selected};
use crate::wait;

/// An error, and what was running when it happened.
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure {
    /// What went wrong.
    pub error: Error,
    /// Which operation was running.
    pub class: OpClass,
    /// A frontend-level wording that replaces the error's own.
    ///
    /// `tdfu_core::Error` has no variant for "this *build* cannot do that": the nearest
    /// is `Error::Invalid`, whose `Display` begins `invalid input:` — and the input was
    /// not invalid, the tool is incomplete. Rather than mislead the user or add a
    /// variant to a crate this task does not own, the refusal carries its own sentence
    /// and the `Error` behind it stays available for the exit code and for `source()`.
    stated: Option<String>,
}

impl Failure {
    /// Pair an error with the operation that raised it.
    #[must_use]
    pub const fn new(error: Error, class: OpClass) -> Self {
        Self {
            error,
            class,
            stated: None,
        }
    }

    /// A refusal this frontend is making, in its own words.
    #[must_use]
    pub fn refused(stated: String, class: OpClass) -> Self {
        Self {
            error: Error::Invalid(stated.clone()),
            class,
            stated: Some(stated),
        }
    }

    /// A failure whose **wording** is this frontend's and whose **exit code** comes from
    /// `error` and `class`.
    ///
    /// [`refused`](Failure::refused) always carries `Error::Invalid`, which decides the
    /// code by the class alone. Remote mode needs the other half of
    /// [`exit_code`](exit::exit_code)'s table as well: a failed write to the `-r` output
    /// must exit **3** because it is a file error, whatever operation was running and
    /// whether or not there was a `--host`. So the error is
    /// chosen for the mapping while the sentence stays [`remote`](crate::remote)'s.
    #[must_use]
    pub fn stating(error: Error, class: OpClass, stated: String) -> Self {
        Self {
            error,
            class,
            stated: Some(stated),
        }
    }

    /// The process exit code for this failure.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        exit::exit_code(&self.error, self.class)
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.stated {
            Some(stated) => f.write_str(stated),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Run every action in the plan, in order.
///
/// `out` takes the data — the `-l` table — and `err` the narration: the scan line, the
/// `--wait` announcements, the bootstrap's own account of itself. The split is what
/// makes `thingino-dfu -l > devices.txt` yield a file with nothing in it but devices.
///
/// # Errors
/// [`Failure`], carrying the class of whatever was running.
pub async fn run<B, C>(
    backend: &B,
    clock: &C,
    plan: &Plan,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Failure>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    // Everything this build cannot do, decided before anything is touched.
    if let Some(refusal) = unsupported(plan) {
        return Err(Failure::refused(refusal, OpClass::Device));
    }

    // Every local file, before the bus **and before the socket**. A missing image is a
    // file error (exit 3) and it costs nothing on the device, and running it on both
    // paths from one place is what makes the remote exit code identical to the local one
    // rather than nearly identical.
    let loaded = images::preflight(&plan.images).map_err(|error| Failure::new(error, OpClass::Device))?;

    // `--host`: the same plan, in the same order, through a daemon. The
    // local bus is not touched at all, so `--wait` is the remote wait and `backend` goes
    // unused.
    if let Some(remote) = &plan.remote {
        return crate::remote::run(remote, plan, clock, loaded, out, err).await;
    }

    if plan.wait {
        let mut narrate = |line: &str| writeln!(err, "{line}");
        wait::wait_for_device(backend, clock, &mut narrate)
            .await
            .map_err(|error| Failure::new(error, OpClass::Device))?;
    }

    let mut session = Session {
        backend,
        clock,
        plan,
        loaded,
        gadget: None,
        transport: None,
        alt: None,
        bar: render::Bar::new(),
    };
    let outcome = session.act_all(out, err).await;
    // Whatever happened, the counter does not get to leave a half-drawn line behind the
    // failure message `main` is about to print.
    session.bar.clear(err);
    outcome
}

/// What this build has no implementation for, decided before anything happens.
///
/// The alternative — refusing at the point of use — would let `thingino-dfu -w img.bin`
/// select a device, USB-boot it and *then* say the write is not implemented, leaving a
/// camera in U-Boot for no reason. Each arm of [`not_implemented`] disappears as its
/// operation lands.
///
/// `Some` is the sentence to print; `None` means the plan is runnable.
fn unsupported(plan: &Plan) -> Option<String> {
    plan.actions.iter().find_map(|action| {
        not_implemented(action).map(|owner| {
            format!(
                "{action} is not available in this build: {owner} exists, but this frontend has no arm \
                 wired to it yet. Nothing was touched"
            )
        })
    })
}

/// Which operations this frontend has not wired yet, and which `ops` function each
/// awaits.
///
/// One arm per operation, so landing one is deleting one line. Everything that reaches
/// `None` is executed below.
///
/// **Every arm is `None` now.** The last one — `Diag` — landed with the stage gate in
/// `ops::diag`, so this function has nothing left to refuse and is kept as the shape the
/// refusal takes: the next operation that arrives half-built names itself here rather
/// than failing at the point of use, which is what stops a `-w` selecting a device,
/// USB-booting it, and *then* saying it cannot write.
const fn not_implemented(action: &Action) -> Option<&'static str> {
    match action {
        Action::List
        | Action::Bootstrap(_)
        | Action::Erase
        | Action::Write
        | Action::Verify
        | Action::Read
        | Action::Reboot
        | Action::Diag => None,
    }
}

/// Which half of the 1-or-2 split an action falls on.
///
/// **1** for init, bootstrap, probe, diag and no-alt; **2** for
/// write, read, erase, reboot and verify. The line is "did any byte of flash move" —
/// a device error means nothing was changed, and a wrapper can retry on it.
///
/// **[`remote`](crate::remote) uses this same function**, so a failed auto-bootstrap
/// under `-w` exits 1 with `--host` exactly as it does without. The C's remote path
/// contradicts its local one here — every remote transfer branch normalises to
/// `EXIT_TRANSFER_ERROR` (`cli/main.c:384`), so the same bootstrap failure is 2
/// remotely and 1 locally. Being told a
/// different thing depending on where the tool ran is the shape of bug 15.
pub(crate) const fn class_of(action: &Action) -> OpClass {
    match action {
        // `exit.rs` already documents listing as a device-class operation, alongside
        // init, bootstrap, probe and diag.
        Action::List | Action::Diag | Action::Bootstrap(_) => OpClass::Device,
        Action::Erase | Action::Write | Action::Verify | Action::Read | Action::Reboot => OpClass::Transfer,
    }
}

/// One run's mutable state.
///
/// A struct rather than eight parameters, and the fields are what an operation after a
/// bootstrap needs: the images already read, and the gadget the bootstrap produced —
/// which is **not** necessarily at the index `-i` named, because a device that
/// re-enumerates can move in the listing.
struct Session<'a, B: LocalUsbBackend, C: Sleeper> {
    backend: &'a B,
    clock: &'a C,
    plan: &'a Plan,
    loaded: Loaded,
    /// Set by a bootstrap; the transfers that follow it use this rather than re-reading
    /// `-i`, and [`Session::prepare`] opens it.
    gadget: Option<Selected<B::DeviceId>>,
    /// The open gadget, shared by every transfer in the run.
    ///
    /// One handle for the whole transfer phase rather than one per operation. Each
    /// operation claims and releases the interface for itself (the ops all do), so what
    /// is shared is the *file descriptor*, not the claim — and reopening between an
    /// erase and the write that lands on it would only add two chances for the device
    /// to be gone. It also survives the stall recovery: `reset()` re-opens and hands
    /// the same `&T` back through the same seam, so core never sees a
    /// stale handle.
    transport: Option<B::Transport>,
    /// The resolved alt, worked out once for the run.
    alt: Option<u8>,
    /// Where an operation's account of itself goes.
    bar: render::Bar,
}

impl<B, C> Session<'_, B, C>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    /// Every action in the plan, in the fixed order.
    ///
    /// # Why the gadget is prepared here rather than inside each arm
    ///
    /// [`prepare`](Self::prepare) opens the gadget and resolves the alt **once**, before
    /// the first operation that needs either, and that placement decides two things the
    /// arms could not decide for themselves:
    ///
    /// * **"No alt" is in the *device* class (exit 1), not the transfer
    ///   class (exit 2)**: nothing has been written when the alt cannot be found, and
    ///   the C agrees (`cli/main.c:551-555` returns `EXIT_DEVICE_ERROR`). Resolving
    ///   inside the write arm would inherit the write's class and exit 2 for a device
    ///   that was never touched.
    /// * **A bad `--alt` must not cost an erase.** The C probes and resolves *after* its
    ///   erase (`cli/main.c:527-556`), so `--erase -w img --alt typo` wipes the chip and
    ///   then refuses, leaving a camera with no firmware and the write it was refused
    ///   for still undone. Nothing forces that order — the gadget is up by then either
    ///   way — and this is the same "read first, touch the device second" rule
    ///   [`images`] already applies to files: the C's bugs are not
    ///   inherited.
    async fn act_all(&mut self, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Failure> {
        for action in &self.plan.actions {
            if action.needs_the_gadget() {
                self.prepare(err)
                    .await
                    .map_err(|error| failed(error, OpClass::Device))?;
            }
            let class = class_of(action);
            self.act(action, out, err).await.map_err(|error| failed(error, class))?;
        }
        Ok(())
    }

    /// One action.
    async fn act(&mut self, action: &Action, out: &mut dyn Write, err: &mut dyn Write) -> tdfu_core::Result<()> {
        match action {
            Action::List => self.list(out, err).await,
            Action::Bootstrap(trigger) => self.bootstrap(*trigger, err).await,
            Action::Erase => self.erase(err).await,
            Action::Write => self.write(err).await,
            Action::Verify => self.verify(err).await,
            Action::Read => self.read(err).await,
            Action::Reboot => self.reboot(err).await,
            Action::Diag => self.diag(out, err).await,
        }
    }

    /// `--diag`: the eFuse shadow dump.
    ///
    /// **The report goes to stdout and nothing else does**, because it is the artefact:
    /// an operator pastes it into a bug report, and a line of ours mixed into it would
    /// travel with it. `ops::diag`'s [`Display`](std::fmt::Display) is the whole of the
    /// rendering, the same text every frontend gets, from one place.
    /// This adds the trailing newline a terminal wants, which the `Display` itself
    /// deliberately does not carry.
    ///
    /// **No bootstrap, and no gadget.** `--diag` reads the mask ROM through vendor
    /// requests, so [`Action::needs_the_gadget`] is false for it and
    /// [`Plan`](crate::plan::Plan) refuses it beside anything that does need one. The
    /// stage check itself is `ops::diag`'s — it refuses a non-bootrom before a byte
    /// reaches the bus, in one sentence that says what the device is and what to do —
    /// and this arm renders that refusal like any other error rather than pre-empting it
    /// with a second opinion. The gadget and the bootrom share `a108:c309`,
    /// which is why the check exists at all.
    ///
    /// It is in the **device** class: exit 1, because nothing was
    /// written.
    async fn diag(&self, out: &mut dyn Write, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = target::select(self.backend, self.plan.target.index).await?;
        writeln!(err, "Reading the eFuse shadow of device {}.", device.index)?;
        let transport = self.backend.open(&device.id).await?;

        let report = ops::diag(&transport, self.clock).await?;

        writeln!(out, "{report}")?;
        out.flush()?;
        Ok(())
    }

    /// `-l`: the inventory, and the targeted gadget's alts.
    async fn list(&mut self, out: &mut dyn Write, err: &mut dyn Write) -> tdfu_core::Result<()> {
        // On stderr: identifying each bootrom costs three register reads per device, and
        // silence for a second reads as a hang.
        writeln!(err, "{}", render::SCANNING)?;
        let listing = list::list(self.backend, self.clock).await?;
        render::render(&listing, out)?;
        self.list_alts(&listing, out, err).await;
        out.flush()?;
        Ok(())
    }

    /// The alt block under the table, for the targeted device and only if it is a gadget.
    ///
    /// **The whole point is the "only if".** `ops::probe` recovers a wedged
    /// gadget with a USB bus reset (`dfu.c:501-508`), and doing that to a *bootrom*,
    /// which shares the gadget's `a108:c309`, would disturb a device that
    /// may be mid-bootstrap for somebody else. So the stage decides, from the
    /// descriptors, and `list::list` has already refused to open a gadget at all.
    ///
    /// **A probe failure is not a listing failure.** The table has already been printed
    /// and is correct; a gadget that will not answer is one line of context, not a reason
    /// to return non-zero for a report that succeeded. The C draws the same line — its
    /// probe is inside an `if (… == TDFU_SUCCESS)` with no else (`cli/main.c:481-489`) —
    /// but says nothing at all when it fails, which is a silence with nothing to grep
    /// for; this says what happened.
    async fn list_alts(&mut self, listing: &Listing, out: &mut dyn Write, err: &mut dyn Write) {
        let index = self.plan.target.index;
        let Some(row) = listing.rows.get(usize::from(index)) else {
            return;
        };
        if row.stage != Some(Stage::Gadget) {
            return;
        }
        if let Err(error) = self.probe_and_render(index, out, err).await {
            let _ignored = writeln!(err, "note: device {index} would not answer a DFU probe: {error}");
        }
    }

    /// Open the gadget, probe it, and print what it offers.
    ///
    /// The probe takes the bar as its sink because it can *recover*: a gadget left wedged
    /// by a killed run gets a USB bus reset and one more attempt, and the note naming
    /// what was recovered from is the only account of a re-enumeration and about 1.5 s of
    /// waiting the operator would otherwise have to find in `dmesg`.
    async fn probe_and_render(&mut self, index: u8, out: &mut dyn Write, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = target::select(self.backend, index).await?;
        let transport = self.backend.open(&device.id).await?;
        let info = {
            let clock = self.clock;
            let bar = &mut self.bar;
            let mut sink = |progress: Progress| bar.render(&progress, err);
            ops::probe_with_progress(&transport, clock, &mut sink).await?
        };
        // The default-alt rule, made visible. `None` when the loader offers no `flash`
        // and more than one alt — the case where `--alt` is mandatory, and the block is
        // then exactly the list the operator needs to choose from.
        let default_alt = alt::resolve(&info, &AltSel::Default).ok();
        render::alts(index, &info, default_alt, out)?;
        Ok(())
    }

    /// `-b`, and the implicit form in front of every transfer.
    async fn bootstrap(&mut self, trigger: BootstrapTrigger, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = target::select(self.backend, self.plan.target.index).await?;

        // Already a gadget: there is nothing to do, and saying so is not the same as
        // doing it silently. `-b` twice in a row is a routine bench sequence, and the
        // postcondition an operator cares about — "there is a DFU gadget on that port" —
        // already holds.
        if device.is_gadget() {
            writeln!(
                err,
                "Device {} is already {}; nothing to bootstrap.",
                device.index,
                device.describe()
            )?;
            self.gadget = Some(device);
            return Ok(());
        }

        // Anything that is not a bootrom is refused, whichever way the bootstrap got
        // here. An unclassifiable device is included on purpose: the gadget and the
        // bootrom share `a108:c309`, so "unknown" is genuinely unknown and
        // uploading a stage-1 image to it could hit a device mid-flash, which is
        // a misclassification an audit found in `classify` and fixed.
        if !device.is_bootrom() {
            return Err(Error::Invalid(format!(
                "device {} is {}, and only a device in the bootrom can be USB-booted{}. \
                 Power-cycle it into the bootrom and try again",
                device.index,
                device.describe(),
                match trigger {
                    BootstrapTrigger::Requested => "",
                    BootstrapTrigger::Auto => ", which is what this transfer needs first",
                }
            )));
        }

        let transport = self.backend.open(&device.id).await?;
        let blobs = self.loaders_for(&transport, err).await?;
        writeln!(err, "Bootstrapping device {} with {}", device.index, blobs.source)?;

        {
            let bar = &mut self.bar;
            let mut sink = |progress: Progress| bar.render(&progress, err);
            ops::bootstrap(&transport, self.clock, &blobs.stage1, &blobs.uboot, &mut sink).await?;
        }

        // Nothing in `ops::bootstrap` waits for the gadget; that is the
        // caller's job, and this is the caller.
        let mut narrate = |line: &str| writeln!(err, "{line}");
        let gadget =
            wait::wait_for_gadget(self.backend, self.clock, &device.descriptors.port_path, &mut narrate).await?;
        writeln!(
            err,
            "The U-Boot DFU gadget is up at index {} (was {}).",
            gadget.index, device.index
        )?;
        self.gadget = Some(gadget);
        Ok(())
    }

    /// Which stage-1 and U-Boot images this bootstrap will upload.
    ///
    /// Three cases, in the C's own precedence (`dfu.c:1191-1214`):
    /// an explicit `--spl` + `--uboot` pair skips detection *and* the tree; `--cpu`
    /// skips detection; otherwise the registers are read.
    async fn loaders_for<T>(&self, transport: &T, err: &mut dyn Write) -> tdfu_core::Result<Blobs>
    where
        T: tdfu_usb::LocalUsbTransport,
    {
        if let Some(blobs) = &self.loaded.loaders {
            return Ok(blobs.clone());
        }
        let variant = match self.plan.target.cpu {
            Some(forced) => {
                tracing::debug!(variant = forced.loader_dir(), "--cpu skipped detection");
                forced
            }
            None => self.detect_variant(transport, err).await?,
        };
        let root = loaders::firmware_root(self.plan.images.firmware_dir.as_deref());
        images::loaders(&root, variant)
    }

    /// Read the registers and turn the answer into a loader choice.
    ///
    /// **Whatever the answer, its qualification is printed.** A resolved-by-convention
    /// row, an ambiguous grade and an unknown chip each carry the sentence an operator
    /// needs, and it is the same sentence `-l` prints
    /// ([`render::detection_advice`]) — one producer, so a bootstrap cannot be quieter
    /// about a guess than a listing was, with
    /// `cli_surfaces_the_detection_caveat` as the pin.
    async fn detect_variant<T>(&self, transport: &T, err: &mut dyn Write) -> tdfu_core::Result<Variant>
    where
        T: tdfu_usb::LocalUsbTransport,
    {
        let detection = ops::detect(transport, self.clock).await?;
        for line in render::detection_advice(&detection) {
            writeln!(err, "{line}")?;
        }
        detection.variant().ok_or_else(|| refuse_detection(&detection))
    }

    // -----------------------------------------------------------------
    // The transfer phase.
    // -----------------------------------------------------------------

    /// Open the gadget and resolve the alt, once, before the first transfer.
    ///
    /// Idempotent: every gadget-needing action calls it and only the first does
    /// anything. The alt half is skipped entirely when nothing in the plan targets one
    /// (`--erase` and `--reboot` address the loader's own `virt` alts by token,
    /// and `ops::erase`/`ops::reboot` find those for themselves), so an
    /// erase-only or reboot-only run costs no probe at all. The C probes for a
    /// reboot-only run (`cli/main.c:538-556`) and then never uses the answer.
    async fn prepare(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        if self.transport.is_none() {
            let device = match &self.gadget {
                // The bootstrap already found it — possibly at a different index, because
                // a device that re-enumerates moves in the listing.
                Some(gadget) => gadget.clone(),
                None => target::select(self.backend, self.plan.target.index).await?,
            };
            if !device.is_gadget() {
                return Err(no_gadget(&device));
            }
            self.transport = Some(self.backend.open(&device.id).await?);
            self.gadget = Some(device);
        }
        if self.alt.is_none() && self.plan.actions.iter().any(Action::takes_an_alt) {
            self.resolve_alt(err).await?;
        }
        Ok(())
    }

    /// Probe the gadget and apply the alt rules to what it offers.
    ///
    /// The probe writes into the bar for the same reason [`Session::probe_and_render`]'s
    /// does: it recovers a wedged gadget with a bus reset, and the operator is owed the
    /// line that says so before a transfer starts.
    async fn resolve_alt(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let info = {
            let clock = self.clock;
            let bar = &mut self.bar;
            let mut sink = |progress: Progress| bar.render(&progress, err);
            ops::probe_with_progress(device, clock, &mut sink).await?
        };
        let alt = alt::resolve(&info, &self.plan.target.alt)?;

        // Which alt a transfer is about to write to is the one fact `-w` never states,
        // and the default rule makes it a *choice* rather than a constant:
        // `flash` first, else the only alt. Saying it costs one line and turns "it wrote
        // somewhere" into "it wrote to alt 0".
        let named = info
            .alts
            .iter()
            .find(|entry| entry.alt == alt)
            .filter(|entry| !entry.name.is_empty())
            .map_or_else(String::new, |entry| format!(" ({:?})", entry.name));
        writeln!(err, "Targeting alt {alt}{named}.")?;

        self.alt = Some(alt);
        Ok(())
    }

    /// `--erase`: wipe the whole flash and prove it blank.
    ///
    /// First of the byte-moving operations in the fixed order, because an erase
    /// must precede the write that lands on it — a NAND UBI image needs an erased chip.
    async fn erase(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let clock = self.clock;
        let bar = &mut self.bar;
        let mut sink = |progress: Progress| bar.render(&progress, err);
        ops::erase(device, clock, &mut sink).await
    }

    /// `-w`: download the image to the resolved alt.
    async fn write(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let image = self.loaded.write.as_deref().ok_or_else(|| missing_preflight("-w"))?;
        let alt = AltSel::Index(self.alt.ok_or_else(no_alt)?);
        let clock = self.clock;
        let bar = &mut self.bar;
        let mut sink = |progress: Progress| bar.render(&progress, err);
        ops::write(device, clock, &alt, image, &mut sink).await
    }

    /// `--verify`: read back and compare against the image `-w` just wrote.
    ///
    /// **The same image and the same alt as the write**, which is what makes this a
    /// check rather than a second opinion: the order puts it immediately after
    /// the write, and the C passes the same `input_file` and `alt`
    /// (`cli/main.c:558-563`). There is no standalone form: `--verify` without `-w` is
    /// refused at parse time ([`PlanError::VerifyWithoutWrite`]), and the C has no such
    /// form either — its `options.verify` is only ever read inside the write branch.
    ///
    /// [`PlanError::VerifyWithoutWrite`]: crate::plan::PlanError::VerifyWithoutWrite
    async fn verify(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let image = self
            .loaded
            .write
            .as_deref()
            .ok_or_else(|| missing_preflight("--verify"))?;
        let alt = AltSel::Index(self.alt.ok_or_else(no_alt)?);
        let clock = self.clock;
        let bar = &mut self.bar;
        let mut sink = |progress: Progress| bar.render(&progress, err);
        ops::verify(device, clock, &alt, image, &mut sink).await
    }

    /// `-r`: upload the flash into the file the preflight created.
    ///
    /// **The byte count is not printed here.** `ops::read` emits
    /// `DFU upload complete: N bytes` as a [`Progress::Note`] and this renders every
    /// note verbatim, so a line of our own would print it twice, which is exactly the
    /// trap whoever wires this arm has to check for. Completion lines
    /// live in core so that every frontend gets them once, from one place
    /// and nothing downstream adds another.
    ///
    /// # A failed read leaves the bytes it got, and says the file is short
    ///
    /// The destination [`images::preflight`] opened is emptied by the first byte of the
    /// upload ([`images::Output`]) and not before, so a run that stops in front of the
    /// transfer leaves an earlier dump whole. Once bytes are arriving the old content is
    /// gone, and the file is **not** deleted and **not** re-truncated when the read then
    /// fails part way. `ops::read` streams into it — a 256 MiB NAND alt is
    /// four times the daemon's payload cap and never buffers, so by the
    /// time anything can fail the bytes are already on disk, and there is no version of
    /// this that ends with an empty file and a full one having existed.
    ///
    /// Keeping it is the useful half of the choice: a dump that stopped at 12 MiB of 16
    /// is what an operator inspects to find out *why* it stopped, and deleting it would
    /// turn a diagnosable failure into a repeat of the same twenty minutes. The C keeps
    /// it too, and for a worse reason — it has no cleanup at all (`dfu.c:839-842` breaks
    /// out and the caller closes the file) — but it never says so, which is the half we
    /// do not copy. The failure message names the offset the read stopped at
    /// (`Error::Io` from `ops::read` carries it), so "the file is short and here is
    /// where" is on the operator's screen rather than inferable from a byte count.
    ///
    /// The exit code is **2**: `-r` is a transfer.
    async fn read(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let alt = AltSel::Index(self.alt.ok_or_else(no_alt)?);
        let limit = self.plan.target.size;
        let clock = self.clock;
        // Disjoint fields: the transport is borrowed shared, the output file and the bar
        // mutably, and no two of them are the same field.
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let out = self.loaded.read.as_mut().ok_or_else(|| missing_preflight("-r"))?;
        let bar = &mut self.bar;
        let mut sink = |progress: Progress| bar.render(&progress, err);
        let _total = ops::read(device, clock, &alt, limit, out, &mut sink).await?;
        Ok(())
    }

    /// `--reboot`: boot the box into whatever was just flashed.
    ///
    /// Last in the fixed order, because it ends the session: the loader's reboot
    /// flush calls `do_reset()` and never returns, so the device is off the bus from
    /// that moment and no operation can follow it.
    async fn reboot(&mut self, err: &mut dyn Write) -> tdfu_core::Result<()> {
        let device = self.transport.as_ref().ok_or_else(no_transport)?;
        let clock = self.clock;
        let bar = &mut self.bar;
        let mut sink = |progress: Progress| bar.render(&progress, err);
        ops::reboot(device, clock, &mut sink).await
    }
}

/// Pair an error with the operation that raised it, keeping this frontend's wording.
///
/// `Error::Invalid`'s `Display` begins `invalid input:`, and almost nothing that reaches
/// here with that variant is the operator's input: an empty bus, a `-i` past the end of
/// the listing, a device that is not the gadget, a port path the platform would not
/// report. Printed with the prefix, the tool blames the command line for the state of
/// the bench, and the same fault reads one way locally and another through `--host`,
/// where [`remote`](crate::remote) already prints these as the sentence they are. The
/// error itself is kept, so the exit code is the one the class and the variant decide,
/// unchanged.
fn failed(error: Error, class: OpClass) -> Failure {
    match error {
        Error::Invalid(message) => Failure::refused(message, class),
        other => Failure::new(other, class),
    }
}

/// A transfer whose target is not the DFU gadget.
///
/// Unreachable through the real parser: an auto-bootstrap goes in front
/// of every transfer, and that arm has already refused anything that is neither a
/// bootrom nor a gadget. It is reachable from a hand-built [`Plan`], and it says which
/// device and what it is rather than failing inside a claim.
fn no_gadget<Id>(device: &Selected<Id>) -> Error {
    let remedy = if device.is_bootrom() {
        // It is in the bootrom, so telling it to power-cycle into the bootrom would be
        // nonsense. What is missing is the bootstrap, which a transfer normally
        // supplies.
        "add -b to USB-boot it first; every transfer normally gets that automatically"
    } else {
        "power-cycle it into the bootrom and run this again; the transfer will USB-boot it first"
    };
    Error::Invalid(format!(
        "device {} is {}, and a transfer needs the U-Boot DFU gadget: {remedy}",
        device.index,
        device.describe()
    ))
}

/// The gadget was not opened before an operation that needs it.
fn no_transport() -> Error {
    Error::Invalid(
        "a transfer ran without an open device; run::Session::prepare and run::Session::act disagree".to_owned(),
    )
}

/// The alt was not resolved before an operation that targets one.
fn no_alt() -> Error {
    Error::Invalid(
        "a transfer ran without a resolved alt; run::Session::prepare and plan::Action::takes_an_alt disagree"
            .to_owned(),
    )
}

/// An operation reached the bus without the file its flag names.
///
/// [`images::preflight`] reads every path in the plan before anything is opened, and
/// [`Cli::into_plan`](crate::cli::Cli::into_plan) only adds an action when its path is
/// present, so this is a disagreement between the two rather than a user error — and it
/// says so, instead of reporting a device failure for a file that was never asked for.
fn missing_preflight(flag: &str) -> Error {
    Error::Invalid(format!(
        "{flag} reached the device with no file behind it; cli::actions and images::preflight disagree"
    ))
}

/// The error a detection that chose nothing should raise.
///
/// Both variants already carry the register words and the candidates, and both messages
/// already end in "pass `--cpu`" — what matters here is that a bug report needs
/// the grade code that produced the ambiguity, so this hands the value on rather than
/// flattening it to a sentence.
fn refuse_detection(detection: &Detection) -> Error {
    match detection {
        Detection::Ambiguous { regs, candidates, .. } => Error::Ambiguous {
            regs: *regs,
            candidates: candidates.clone(),
        },
        Detection::Unknown { regs } => Error::UnknownSoc { regs: *regs },
        // `Resolved` always has a variant, so this is unreachable by construction; the
        // wildcard is required because `Detection` is `#[non_exhaustive]`, and a
        // variant added later must not silently inherit one of the arms above. An
        // error rather than a `panic!`, because a flashing tool does not abort on a
        // case it did not expect.
        _ => Error::Invalid(format!(
            "detection produced no loader variant from {detection:?}; this is a bug in tdfu-core"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, run};
    use crate::exit::{DEVICE, FILE, OpClass, PROTOCOL, TRANSFER};
    use crate::fake::{FakeBackend, Scratch, TestResult, loader_gadget, t31_regs};
    use crate::plan::{Action, BootstrapTrigger, Images, Plan, Remote, Target};
    use clap::Parser as _;
    use std::rc::Rc;
    use tdfu_core::Error;
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::dfu::host::request;
    use tdfu_core::model::{AltSel, Variant};
    use tdfu_usb::gadget::{AltConfig, FakeGadget, Fault, GadgetConfig, When};
    use tdfu_usb::mock::block_on;
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// A target that names device 0 and asks for nothing special.
    fn target() -> Target {
        Target {
            index: 0,
            alt: AltSel::Default,
            cpu: None,
            size: None,
        }
    }

    fn plan(actions: Vec<Action>) -> Result<Plan, crate::plan::PlanError> {
        Plan::new(actions, target(), Images::default(), None, false, false)
    }

    /// Run a plan and hand back (stdout, stderr).
    fn drive(backend: &FakeBackend, plan: &Plan) -> Result<(String, String), Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        let mut err = Vec::new();
        block_on(run(backend, &RecordingClock::new(), plan, &mut out, &mut err))?;
        Ok((String::from_utf8(out)?, String::from_utf8(err)?))
    }

    /// Run a plan that is expected to fail, and hand back (failure, stdout, stderr).
    fn drive_err(backend: &FakeBackend, plan: &Plan) -> Result<(Failure, String, String), Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = block_on(run(backend, &RecordingClock::new(), plan, &mut out, &mut err));
        let failure = outcome.err().ok_or("the run was expected to fail")?;
        Ok((failure, String::from_utf8(out)?, String::from_utf8(err)?))
    }

    #[test]
    fn a_list_run_puts_the_table_on_stdout_and_the_scan_line_on_stderr() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        let (out, err) = drive(&backend, &plan(vec![Action::List])?)?;

        assert!(out.starts_with("Found 1 device:\n"), "{out}");
        assert!(out.contains("T31X (loader t31x, DDR2)"), "{out}");
        assert_eq!(err, "Scanning for Ingenic devices...\n");
        Ok(())
    }

    /// Zero devices is exit 0 with a line that says so, matching the C's semantics
    /// (`cli/main.c:205-208` returns success, `:495` turns it into 0).
    #[test]
    fn fe_cli_an_empty_bus_is_a_successful_run() -> TestResult {
        let backend = FakeBackend::new(Vec::new());
        let (out, _) = drive(&backend, &plan(vec![Action::List])?)?;
        assert_eq!(out, "No Ingenic devices found\n");
        Ok(())
    }

    /// `--wait` runs before the action, and its narration lands on stderr.
    #[test]
    fn wait_precedes_the_action() -> TestResult {
        let backend = FakeBackend::appearing(vec![Vec::new(), vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]]);
        let waiting = Plan::new(vec![Action::List], target(), Images::default(), None, true, false)?;
        let (out, err) = drive(&backend, &waiting)?;

        assert_eq!(
            err,
            "Waiting for an Ingenic device to appear (Ctrl-C to abort)...\n\
             Device found.\n\
             Scanning for Ingenic devices...\n"
        );
        assert!(out.contains("T31X"), "{out}");
        Ok(())
    }

    /// A failed enumeration exits 1 — the device class, not the transfer class.
    #[test]
    fn fe_cli_a_failed_listing_exits_one() -> TestResult {
        let backend = FakeBackend::failing(UsbError::new(
            UsbErrorKind::Backend("sysfs is unreadable".into()),
            Pipe::Device,
        ));
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::List])?)?;
        assert_eq!(failure.class, OpClass::Device);
        assert_eq!(failure.exit_code(), DEVICE);
        assert!(failure.to_string().contains("sysfs is unreadable"), "{failure}");
        // The cause is reachable, so `{:?}`-style chain printers and `anyhow` see it.
        assert!(
            std::error::Error::source(&failure).is_some(),
            "the cause must be reachable"
        );
        Ok(())
    }

    /// And a file error still exits 3 whatever was running (`exit.rs`).
    #[test]
    fn fe_cli_a_file_error_exits_three_from_a_list_run() {
        let failure = Failure::new(Error::Io(std::io::Error::other("stdout is gone")), OpClass::Device);
        assert_eq!(failure.exit_code(), FILE);
    }

    /// **`-l` beside an action does not swallow it.**
    ///
    /// The C printed the device list and returned **0** without writing
    /// (`cli/main.c:475-495`). Here `-l` is one action among several, so the write is
    /// still in the plan and still runs — and in this build it is still unimplemented,
    /// which is why the run **fails** rather than exiting 0. Either way the one outcome
    /// that must never happen is "success, and the write did not happen".
    #[test]
    fn fe_cli_bug13_list_never_swallows_the_action() -> TestResult {
        // Through the real parser, because the auto-bootstrap a transfer gets is
        // part of what `-l -w` has to mean.
        let combined =
            crate::cli::Cli::try_parse_from(["thingino-dfu", "-l", "-w", "/nonexistent/tdfu/fw.bin"])?.into_plan()?;
        assert_eq!(
            combined.actions,
            vec![Action::List, Action::Bootstrap(BootstrapTrigger::Auto), Action::Write],
            "the write must survive into the plan"
        );

        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let (failure, out, _) = drive_err(&backend, &combined)?;
        assert_ne!(failure.exit_code(), 0, "a write that did not happen is never a success");
        assert!(failure.to_string().contains("-w"), "{failure}");
        assert!(
            out.is_empty(),
            "and nothing was listed either: the refusal came first, {out:?}"
        );
        Ok(())
    }

    /// **`--diag` renders core's report and nothing else, on stdout.**
    ///
    /// The last arm this frontend was missing. The report is the artefact an operator
    /// pastes into a bug report, so stdout carries it alone and the one line of context
    /// goes to stderr — the same split `-l` uses.
    #[test]
    fn the_diag_arm_prints_cores_report_on_stdout() -> TestResult {
        // A T32LQ-shaped window: `subsoctype1` at +0x38 and `subsoctype2` at +0x50 are
        // what the decode reads, and the rest is the dump.
        let mut window = vec![0_u8; 256];
        window[0x38..0x3C].copy_from_slice(&0x2222_u32.to_le_bytes());
        window[0x50..0x54].copy_from_slice(&0x1111_u32.to_le_bytes());
        let backend = FakeBackend::new(vec![FakeBackend::diagnosable_bootrom(0x1003_2004, window)]);

        let (out, err) = drive(&backend, &plan(vec![Action::Diag])?)?;

        assert!(out.contains("1003"), "the report is not on stdout: {out:?}");
        assert!(out.ends_with('\n'), "a terminal wants the trailing newline");
        assert!(err.contains("eFuse"), "the one context line is not on stderr: {err:?}");
        assert!(!err.contains("1003"), "the report leaked onto stderr: {err:?}");
        assert_eq!(backend.opened(), vec![0], "exactly one device was opened");
        Ok(())
    }

    /// `--diag` at a device that is not in the bootrom is refused by `ops::diag`, and the
    /// CLI renders the refusal like any other error — device class, exit 1.
    ///
    /// The gadget and the bootrom share `a108:c309`, so aiming `--diag` at
    /// the wrong one is the ordinary mistake rather than an exotic one.
    #[test]
    fn the_diag_arm_surfaces_the_stage_gate() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let (failure, out, _) = drive_err(&backend, &plan(vec![Action::Diag])?)?;

        assert!(
            failure.to_string().contains("bootrom"),
            "the refusal must say what to do: {failure}"
        );
        assert_eq!(
            failure.exit_code(),
            DEVICE,
            "--diag wrote nothing, so it is not a transfer error"
        );
        assert!(out.is_empty(), "a refused diag must print no report: {out:?}");
        Ok(())
    }

    /// **A local refusal is not blamed on the operator's command line.**
    ///
    /// An empty bus is a fact about the bench, and `Error::Invalid`'s `Display` opens
    /// `invalid input:`, which says the command was wrong. Through `--host` the same
    /// fault already prints as the sentence it is, and an operator reading one message
    /// and then the other must not be told two different things about one fault. The
    /// exit code is untouched by the wording.
    #[test]
    fn fe_cli_a_device_refusal_is_not_called_invalid_input() -> TestResult {
        let backend = FakeBackend::new(Vec::new());
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Erase])?)?;
        let said = failure.to_string();

        assert!(said.starts_with("no Ingenic devices on the bus"), "{said}");
        assert!(
            !said.contains("invalid input"),
            "the bus is not the command line: {said}"
        );
        assert!(said.contains(crate::target::EMPTY_BUS_ADVICE), "{said}");
        assert_eq!(failure.exit_code(), DEVICE, "and the code is the one it always was");
        Ok(())
    }

    /// **`--host` goes to the daemon, and the local bus is not touched on the way.**
    ///
    /// The whole remote conversation is pinned in [`remote::tests`](crate::remote); what
    /// belongs at this level is the dispatch itself: a plan with a `--host` in it must
    /// reach [`remote::run`](crate::remote::run), reported here by the connect failing
    /// with exit **4**, and must never enumerate the bus in front of it.
    #[test]
    fn a_remote_plan_is_dispatched_to_the_daemon() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let remote = Plan::new(
            vec![Action::List],
            target(),
            Images::default(),
            Some(Remote {
                // `.invalid` is reserved by RFC 2606 and never resolves, so this test
                // needs no socket and no listener.
                host: "camera.invalid".to_owned(),
                port: 5051,
                token: None,
            }),
            false,
            false,
        )?;
        let (failure, out, _) = drive_err(&backend, &remote)?;
        assert!(failure.to_string().contains("camera.invalid:5051"), "{failure}");
        assert_eq!(failure.class, OpClass::Remote);
        assert_eq!(failure.exit_code(), PROTOCOL, "a failed connect is 4");
        assert_eq!(backend.list_calls(), 0, "a remote run does not scan the local bus");
        assert!(out.is_empty(), "and prints no table for a daemon it never reached");
        Ok(())
    }

    /// A `-w` whose image is missing is a **file** error, and costs no bus work.
    ///
    /// This is the audit's carried rule at the run level: the C claims the interface
    /// before it looks at the path (`dfu.c:1186` versus `:1219`).
    #[test]
    fn fe_cli_a_missing_image_costs_no_bus_work() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        // `Action::Bootstrap` alone, so `supported` does not refuse first: the point is
        // that the *file* stops it.
        let bootstrapping = Plan::new(
            vec![Action::Bootstrap(BootstrapTrigger::Requested)],
            target(),
            Images {
                spl: Some("/nonexistent/tdfu/spl.bin".into()),
                uboot: Some("/nonexistent/tdfu/uboot.bin".into()),
                ..Images::default()
            },
            None,
            false,
            false,
        )?;
        let (failure, _, _) = drive_err(&backend, &bootstrapping)?;
        assert_eq!(failure.exit_code(), FILE, "a missing loader is exit 3: {failure}");
        assert!(failure.to_string().contains("spl.bin"), "{failure}");
        assert_eq!(backend.list_calls(), 0, "nothing was enumerated");
        assert_eq!(backend.opened(), Vec::<usize>::new(), "nothing was opened");
        Ok(())
    }

    /// **A zero-length `-w` image never costs a USB-boot.**
    ///
    /// `ops::write` refuses an empty image as the library's invariant, but it does so at
    /// the download: against a bootrom the camera has by then been USB-booted for a
    /// transfer that could never have moved a byte, and the refusal exits 2, telling a
    /// wrapper a flash was attempted. The preflight refuses it as what it is, a file
    /// problem, before anything is enumerated.
    #[test]
    fn fe_cli_an_empty_write_image_is_refused_before_the_bus() -> TestResult {
        let scratch = Scratch::new("empty-write-image")?;
        let source = scratch.write("fw.bin", b"")?;
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        let plan = plan_with(
            vec![Action::Bootstrap(BootstrapTrigger::Auto), Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert_eq!(failure.exit_code(), FILE, "an empty image is a file problem: {failure}");
        assert!(failure.to_string().contains("is empty"), "{failure}");
        assert_eq!(backend.list_calls(), 0, "nothing was enumerated");
        assert_eq!(backend.opened(), Vec::<usize>::new(), "and nothing was USB-booted");
        Ok(())
    }

    /// A bootstrap against a device that is already a gadget says so and stops.
    #[test]
    fn fe_cli_bootstrapping_a_gadget_is_a_noop_that_says_so() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let (_, err) = drive(&backend, &plan(vec![Action::Bootstrap(BootstrapTrigger::Requested)])?)?;
        assert!(err.contains("already a U-Boot DFU gadget"), "{err}");
        assert_eq!(backend.opened(), Vec::<usize>::new(), "a no-op opens nothing");
        Ok(())
    }

    /// **The audit's carried rule.** An unclassifiable device is never USB-booted.
    #[test]
    fn fe_cli_an_unclassifiable_device_is_never_bootstrapped() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::opaque()]);
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Bootstrap(BootstrapTrigger::Requested)])?)?;
        assert!(failure.to_string().contains("unrecognised kind"), "{failure}");
        assert_eq!(failure.exit_code(), DEVICE);
        assert_eq!(backend.opened(), Vec::<usize>::new(), "nothing was uploaded to it");
        Ok(())
    }

    /// An auto-bootstrap says that the transfer is what needed it.
    #[test]
    fn an_auto_bootstrap_explains_itself_when_it_cannot_run() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::opaque()]);
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Bootstrap(BootstrapTrigger::Auto)])?)?;
        assert!(failure.to_string().contains("this transfer needs first"), "{failure}");
        Ok(())
    }

    /// **The `--cpu`-refused flow.** A bootstrap that cannot pick a loader prints the
    /// same advice `-l` prints, and refuses with the register words in hand.
    ///
    /// This is `cli_surfaces_the_detection_caveat` extended past the table: the caveat
    /// mechanism is dead data again the moment one frontend path forgets it, and the
    /// bootstrap path is the one where forgetting it costs a wrong loader on a live
    /// board.
    #[test]
    fn cli_surfaces_the_detection_caveat_when_cpu_is_needed() -> TestResult {
        // A T4x grade that is not one of the four proven auto-picks (decision D4).
        let ambiguous = [0x1004_0123, 0, 0x1234_0000];
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(ambiguous)]);
        let (failure, _, err) = drive_err(&backend, &plan(vec![Action::Bootstrap(BootstrapTrigger::Requested)])?)?;

        assert!(err.contains("note:"), "the advice must reach stderr: {err:?}");
        assert!(err.contains("--cpu"), "and it must say what to pass: {err:?}");
        assert!(
            matches!(failure.error, Error::Ambiguous { .. }),
            "the candidates must survive into the error: {failure:?}"
        );
        assert_eq!(failure.exit_code(), DEVICE);
        Ok(())
    }

    /// An unknown chip refuses with the registers, not with a guess.
    #[test]
    fn an_unknown_soc_refuses_rather_than_guessing_a_loader() -> TestResult {
        // `cpu_id` 0x9999 is in no family table.
        let backend = FakeBackend::new(vec![FakeBackend::bootrom([0x0999_9000, 0, 0])]);
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Bootstrap(BootstrapTrigger::Requested)])?)?;
        assert!(matches!(failure.error, Error::UnknownSoc { .. }), "{failure:?}");
        assert!(failure.to_string().contains("--cpu"), "{failure}");
        Ok(())
    }

    /// `--cpu` skips detection, so a bootrom is never opened for a register read.
    ///
    /// Here the loader tree is absent, so the run stops at the tree
    /// lookup — which is exactly the assertion: it got that far without reading a
    /// register, and the fake's script would have refused an unexpected one.
    #[test]
    fn det_overrides_bypass_probe() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget()]);
        let forced = Plan::new(
            vec![Action::Bootstrap(BootstrapTrigger::Requested)],
            Target {
                cpu: Some(Variant::T31x),
                ..target()
            },
            Images {
                firmware_dir: Some("/nonexistent/tdfu-firmware".into()),
                ..Images::default()
            },
            None,
            false,
            false,
        )?;
        // The gadget short-circuits before the loader lookup, so use a bootrom whose
        // detect script would fail the test if it were consulted.
        let _ignored = backend;
        let bootrom = FakeBackend::new(vec![FakeBackend::mute_bootrom()]);
        let (failure, _, _) = drive_err(&bootrom, &forced)?;
        assert_eq!(failure.exit_code(), FILE, "it reached the tree lookup: {failure}");
        assert!(failure.to_string().contains("t31x"), "{failure}");
        Ok(())
    }

    /// **The exit-code pin**: 0, 1, 2, 3, 4, each from the thing that produces it.
    #[test]
    fn fe_cli_exit_codes() -> TestResult {
        // 0: a run that did what it was asked.
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        assert!(drive(&backend, &plan(vec![Action::List])?).is_ok());

        // 1: a device error, which is every report and every bootstrap.
        for device in [Action::List, Action::Diag, Action::Bootstrap(BootstrapTrigger::Auto)] {
            let failure = Failure::new(Error::NotDfu, super::class_of(&device));
            assert_eq!(failure.exit_code(), DEVICE, "{device}");
        }

        // 2: a transfer error, which is every operation that moves bytes.
        for transfer in [
            Action::Erase,
            Action::Write,
            Action::Verify,
            Action::Read,
            Action::Reboot,
        ] {
            let failure = Failure::new(Error::NotDfu, super::class_of(&transfer));
            assert_eq!(failure.exit_code(), TRANSFER, "{transfer}");
        }

        // 3: a file error, whichever operation was running. `EXIT_FILE_ERROR = 3` is
        // defined in the C's `protocol.h` and returned by nothing in the C tree, and
        // returning it here is a deliberate divergence.
        for class in [OpClass::Device, OpClass::Transfer, OpClass::Remote] {
            let failure = Failure::new(Error::Io(std::io::Error::other("disk")), class);
            assert_eq!(failure.exit_code(), FILE, "{class:?}");
        }

        // 4: the protocol class, which only remote mode reaches, so no local path can
        // produce it. Asserted through the class so the mapping stays pinned where the
        // remote client depends on it.
        assert_eq!(
            Failure::new(Error::NotDfu, OpClass::Remote).exit_code(),
            crate::exit::PROTOCOL
        );
        Ok(())
    }

    /// **The listing pin.** `-l` never probes, and so never resets, a bootrom.
    ///
    /// `ops::probe` recovers a wedged gadget with a USB bus reset (`dfu.c:501-508`).
    /// The bootrom shares the gadget's `a108:c309`, so a listing that
    /// probed by PID would reset a device that may be mid-bootstrap for somebody else.
    ///
    /// The bootrom's transport is scripted with exactly `ops::detect`'s requests and
    /// nothing else, so a probe would fail the run rather than pass quietly; and the
    /// device is opened **once**, for detection, not twice.
    #[test]
    fn fe_cli_list_no_reset_on_bootrom() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        let (out, _) = drive(&backend, &plan(vec![Action::List])?)?;

        assert!(out.contains("T31X"), "{out}");
        assert!(
            !out.contains("alt setting(s)"),
            "a bootrom has no alts to show, and asking would reset it: {out}"
        );
        assert_eq!(
            backend.opened(),
            vec![0],
            "opened once, for the three register reads, and not again for a probe"
        );
        Ok(())
    }

    /// `-l` prints the targeted gadget's alts, with the default marked.
    ///
    /// The second half of the listing (`cli/main.c:478-490`), and the one integration
    /// in this crate that needs a body another task owns.
    #[test]
    fn fe_cli_list_shows_the_targeted_gadgets_alts() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::probeable_gadget()]);
        let (out, _) = drive(&backend, &plan(vec![Action::List])?)?;

        assert!(out.contains("DFU device 0: 3 alt setting(s)"), "{out}");
        assert!(out.contains("transfer size 4096 bytes, DFU 1.10"), "{out}");
        assert!(out.contains("alt 0: \"flash\"  (default)"), "{out}");
        assert!(out.contains("alt 1: \"erase\""), "{out}");
        assert!(out.contains("alt 2: \"reboot\""), "{out}");
        Ok(())
    }

    /// **A recovery the operator can see.** `-l` against a gadget left wedged by a killed
    /// run costs a USB bus reset and about 1.5 s of waiting; both are announced.
    ///
    /// A wedged gadget is a routine bench state, and the reset that clears it is a
    /// re-enumeration in `dmesg` with nothing on stderr to explain it unless the probe is
    /// given somewhere to say so.
    #[test]
    fn fe_cli_list_says_it_reset_a_wedged_gadget() -> TestResult {
        let gadget = loader_gadget(8192);
        gadget.wedge();
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let (out, err) = drive(&backend, &plan(vec![Action::List])?)?;

        assert_eq!(gadget.resets(), 1, "the wedge cost a bus reset");
        assert!(
            err.contains("USB-reset it and retrying once"),
            "the reset is announced, not silent: {err}"
        );
        assert!(
            out.contains("DFU device 0: 3 alt setting(s)"),
            "and the retry answered: {out}"
        );
        Ok(())
    }

    /// The same, on the transfer path: the alt is resolved through a probe, and a wedged
    /// gadget costs the same reset there.
    #[test]
    fn fe_cli_a_transfer_says_it_reset_a_wedged_gadget() -> TestResult {
        let scratch = Scratch::new("wedged-write")?;
        let payload = image(4200);
        let source = scratch.write("fw.bin", &payload)?;
        let gadget = loader_gadget(8192);
        gadget.wedge();
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (_, err) = drive(&backend, &plan)?;

        assert_eq!(gadget.resets(), 1, "the wedge cost a bus reset");
        assert!(
            err.contains("USB-reset it and retrying once"),
            "the reset is announced, not silent: {err}"
        );
        assert_eq!(
            gadget.medium(0).as_deref().map(|medium| &medium[..payload.len()]),
            Some(&payload[..]),
            "and the write went through afterwards"
        );
        Ok(())
    }

    /// A bootstrap runs the sequence and comes back with the gadget it produced.
    ///
    /// `--cpu` skips detection, so the only body this needs is `ops::bootstrap`'s.
    /// The bus answers with a bootrom first and a gadget afterwards, which is what a
    /// real re-enumeration looks like to `wait::wait_for_gadget`.
    #[test]
    fn fe_cli_a_bootstrap_waits_for_the_gadget_it_created() -> TestResult {
        let scratch = crate::fake::Scratch::new("bootstrap-integration")?;
        scratch.loader_tree(Variant::T31x)?;
        let backend = FakeBackend::appearing(vec![
            vec![FakeBackend::bootstrappable_bootrom(
                b"stage-1".to_vec(),
                b"u-boot".to_vec(),
            )],
            // The gadget comes back on the bootrom's own port, as hardware does.
            vec![FakeBackend::probeable_gadget_at(vec![4, 2])],
        ]);
        let forced = Plan::new(
            vec![Action::Bootstrap(BootstrapTrigger::Requested)],
            Target {
                cpu: Some(Variant::T31x),
                ..target()
            },
            Images {
                firmware_dir: Some(scratch.root().to_path_buf()),
                ..Images::default()
            },
            None,
            false,
            false,
        )?;
        let (_, err) = drive(&backend, &forced)?;
        assert!(err.contains("Bootstrapping device 0"), "{err}");
        assert!(err.contains("The U-Boot DFU gadget is up"), "{err}");
        Ok(())
    }

    // -----------------------------------------------------------------
    // The transfer operations, against the U-Boot gadget emulator.
    //
    // The double is `FakeGadget`, not a request script: a whole `ops::write` is
    // thousands of control transfers whose shape belongs to `tdfu-core`'s DFU state
    // machine, and pinning them here would make this crate's tests fail on every
    // legitimate change to that machine while proving nothing about the CLI. What is
    // asserted instead is what the operator sees — bytes on the medium, notes on
    // stderr, the file on disk, the exit code.
    // -----------------------------------------------------------------

    /// A plan with images and a target of the caller's choosing.
    fn plan_with(actions: Vec<Action>, target: Target, images: Images) -> Result<Plan, crate::plan::PlanError> {
        Plan::new(actions, target, images, None, false, false)
    }

    /// A recognisable image: never all-`0xFF`, so an erase cannot be mistaken for it.
    fn image(len: usize) -> Vec<u8> {
        (0..len).map(|at| u8::try_from(at % 251).unwrap_or(0)).collect()
    }

    /// Where `needle` starts in `text`, for asserting one line came before another.
    fn at(text: &str, needle: &str) -> Result<usize, String> {
        text.find(needle)
            .ok_or_else(|| format!("{needle:?} is not in the narration:\n{text}"))
    }

    /// **The operation-order pin, at the execution level.**
    ///
    /// [`fe_cli_op_order`](crate::plan::tests::fe_cli_op_order) pins the *plan*: typed
    /// backwards, the actions come out in order. That is only half of it — an executor
    /// that ignored the list would pass it — so this drives the whole chain against the
    /// emulator and asserts the order each operation *announced itself* in.
    ///
    /// The order is load-bearing every step of the way: the erase must precede the
    /// write that lands on it, the verify must follow the write it checks, the read must
    /// not see a half-written chip, and the reboot must be last because the loader's
    /// reboot flush calls `do_reset()` and the device leaves the bus.
    #[test]
    fn fe_cli_op_order_is_the_order_operations_run_in() -> TestResult {
        let scratch = Scratch::new("op-order")?;
        let payload = image(4200);
        let source = scratch.write("fw.bin", &payload)?;
        let destination = scratch.path("readback.bin");
        let gadget = loader_gadget(8192);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);

        // Typed backwards, through the real parser, with `-l` in the middle of it.
        let combined = crate::cli::Cli::try_parse_from([
            "thingino-dfu",
            "--reboot",
            "-r",
            &destination.display().to_string(),
            "--verify",
            "-w",
            &source.display().to_string(),
            "--erase",
            "-l",
        ])?
        .into_plan()?;
        let (out, err) = drive(&backend, &combined)?;

        // Every operation ran, and each one said so — in this order and no other.
        let erase = at(&err, "Erase complete (verified blank)")?;
        let write = at(&err, "DFU download complete")?;
        let verify = at(&err, "Verify OK: 4200 bytes match")?;
        let read = at(&err, "DFU upload complete: 8192 bytes")?;
        let reboot = at(&err, "Reboot triggered")?;
        assert!(
            erase < write && write < verify && verify < read && read < reboot,
            "order is erase, write, verify, read, reboot:\n{err}"
        );

        // And the effects are real, not just the narration.
        assert_eq!(gadget.erases(), 1, "the flash was wiped once");
        assert_eq!(
            gadget.medium(0).as_deref().map(|medium| &medium[..payload.len()]),
            Some(&payload[..]),
            "the image is on the flash"
        );
        assert_eq!(
            std::fs::read(&destination)?.len(),
            8192,
            "the whole 8 KiB alt came back"
        );
        assert!(gadget.is_gone(), "the reboot took the device off the bus");

        // Bug 13's other half: `-l` printed its table *and* the operations still ran.
        assert!(out.contains("Found 1 device:"), "{out}");
        Ok(())
    }

    /// **`-w` success.** The image lands, and core's completion line is printed once.
    #[test]
    fn op_write_puts_the_image_on_the_flash() -> TestResult {
        let scratch = Scratch::new("write-arm")?;
        let payload = image(4200);
        let source = scratch.write("fw.bin", &payload)?;
        let gadget = loader_gadget(8192);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (_, err) = drive(&backend, &plan)?;

        assert_eq!(
            gadget.medium(0).as_deref().map(|medium| &medium[..payload.len()]),
            Some(&payload[..])
        );
        assert_eq!(
            err.matches("DFU download complete").count(),
            1,
            "core emits the completion line; the CLI must not add a second: {err:?}"
        );
        // And the counter drew something on the way.
        assert!(err.contains("download"), "the byte counter must be visible: {err:?}");
        Ok(())
    }

    /// **`-w` failure.** A device that stalls the download exits **2**, the transfer
    /// class.
    #[test]
    fn op_write_a_stalled_download_is_a_transfer_error() -> TestResult {
        let scratch = Scratch::new("write-stall")?;
        let source = scratch.write("fw.bin", &image(4200))?;
        let gadget = loader_gadget(8192);
        // Every `DNLOAD`, so the one reset-and-retry cannot rescue it either.
        gadget.inject_times(When::Class(request::DNLOAD), Fault::Stall, 64);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert_eq!(failure.class, OpClass::Transfer);
        assert_eq!(failure.exit_code(), TRANSFER, "{failure}");
        assert!(
            gadget.medium(0).is_none_or(|medium| medium.is_empty()),
            "nothing was written"
        );
        Ok(())
    }

    /// **`--verify` success, chained.** It runs on the write's session, against the
    /// same image and the same alt, and says how many bytes matched.
    #[test]
    fn op_verify_follows_the_write_it_belongs_to() -> TestResult {
        let scratch = Scratch::new("verify-arm")?;
        let source = scratch.write("fw.bin", &image(4200))?;
        let gadget = loader_gadget(8192);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Write, Action::Verify],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (_, err) = drive(&backend, &plan)?;

        assert_eq!(err.matches("Verify OK: 4200 bytes match").count(), 1, "{err:?}");
        assert!(at(&err, "DFU download complete")? < at(&err, "Verify OK")?, "{err}");
        // One probe, one resolution: the verify inherits the write's alt rather than
        // asking again.
        assert_eq!(err.matches("Targeting alt 0").count(), 1, "{err:?}");
        Ok(())
    }

    /// **`--verify` failure.** A flash that does not match the image is a transfer
    /// error naming the offset.
    ///
    /// Driven from a hand-built plan so the medium can differ from the image — through
    /// the parser a verify always follows the write that just made them equal, and
    /// `--verify` alone is refused before the plan exists
    /// ([`PlanError::VerifyWithoutWrite`](crate::plan::PlanError::VerifyWithoutWrite)).
    #[test]
    fn op_verify_a_mismatch_is_a_transfer_error() -> TestResult {
        let scratch = Scratch::new("verify-mismatch")?;
        let source = scratch.write("fw.bin", &image(4200))?;
        let gadget = loader_gadget(8192);
        // The chip holds something else entirely.
        gadget.preload(0, vec![0x5A; 4200]);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Verify],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert!(matches!(failure.error, Error::Verify { .. }), "{failure:?}");
        assert_eq!(failure.exit_code(), TRANSFER, "{failure}");
        Ok(())
    }

    /// **`-r` success, and the double-printing trap.**
    ///
    /// `ops::read` emits `DFU upload complete: N bytes` itself, and this arm prints no
    /// completion line of its own, so the line appears **exactly once**. An audit was
    /// filed against precisely this pair, and the count is the whole assertion.
    #[test]
    fn op_read_writes_the_file_and_says_the_count_once() -> TestResult {
        let scratch = Scratch::new("read-arm")?;
        // Over a longer earlier dump, so a transfer that replaces one leaves no tail of
        // it behind: the file is emptied by the first byte that arrives.
        let destination = scratch.write("dump.bin", &vec![0x5A; 20_000])?;
        let gadget = loader_gadget(8192);
        gadget.preload(0, image(8192));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Read],
            target(),
            Images {
                read: Some(destination.clone()),
                ..Images::default()
            },
        )?;
        let (out, err) = drive(&backend, &plan)?;

        assert_eq!(std::fs::read(&destination)?, image(8192), "the flash is in the file");
        assert_eq!(
            err.matches("DFU upload complete: 8192 bytes").count(),
            1,
            "core says it once and the CLI must not say it again: {err:?}"
        );
        assert!(out.is_empty(), "a read puts nothing on stdout: {out:?}");
        Ok(())
    }

    /// `--size` caps the read, exactly.
    #[test]
    fn op_read_size_caps_the_file() -> TestResult {
        let scratch = Scratch::new("read-size")?;
        let destination = scratch.path("head.bin");
        let gadget = loader_gadget(8192);
        gadget.preload(0, image(8192));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Read],
            Target {
                size: Some(100),
                ..target()
            },
            Images {
                read: Some(destination.clone()),
                ..Images::default()
            },
        )?;
        let (_, err) = drive(&backend, &plan)?;

        assert_eq!(std::fs::read(&destination)?, image(8192)[..100], "exactly 100 bytes");
        assert!(err.contains("DFU upload complete: 100 bytes"), "{err:?}");
        Ok(())
    }

    /// **A `-r` that never reaches a device leaves the earlier dump where it was.**
    ///
    /// The preflight opens the destination early so that an unwritable path is refused
    /// before a camera is bootstrapped, and it stops there: emptying it as well would
    /// mean an empty bus, or an operator who aborts a `--wait`, costs a dump that took
    /// twenty minutes to take, for a transfer that never started.
    #[test]
    fn fe_cli_a_read_that_finds_no_device_keeps_the_earlier_dump() -> TestResult {
        let scratch = Scratch::new("read-no-device")?;
        let destination = scratch.write("dump.bin", b"an earlier dump")?;
        let backend = FakeBackend::new(Vec::new());
        let plan = plan_with(
            vec![Action::Read],
            target(),
            Images {
                read: Some(destination.clone()),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert!(failure.to_string().contains("no Ingenic devices"), "{failure}");
        assert_eq!(
            std::fs::read(&destination)?,
            b"an earlier dump",
            "nothing was transferred, so nothing may be destroyed"
        );
        Ok(())
    }

    /// **`-r` failure.** A device that stalls the upload exits 2, and the file the
    /// preflight created is still there — short, which is what the C leaves too.
    #[test]
    fn op_read_a_stalled_upload_is_a_transfer_error() -> TestResult {
        let scratch = Scratch::new("read-stall")?;
        let destination = scratch.path("dump.bin");
        let gadget = loader_gadget(8192);
        gadget.inject_times(When::Class(request::UPLOAD), Fault::Stall, 64);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Read],
            target(),
            Images {
                read: Some(destination.clone()),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert_eq!(failure.exit_code(), TRANSFER, "{failure}");
        assert!(
            destination.is_file(),
            "the preflight's file is not cleaned up behind it"
        );
        Ok(())
    }

    /// **`--erase` success.** The chip is wiped and *proved* blank.
    #[test]
    fn op_erase_wipes_and_proves_it() -> TestResult {
        let gadget = loader_gadget(8192);
        gadget.preload(0, image(8192));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let (_, err) = drive(&backend, &plan(vec![Action::Erase])?)?;

        assert_eq!(gadget.erases(), 1);
        assert!(
            gadget.medium(0).is_none_or(|medium| medium.is_empty()),
            "the medium is gone"
        );
        assert!(err.contains("Erasing the whole flash (alt 1)"), "{err:?}");
        assert_eq!(err.matches("Erase complete (verified blank)").count(), 1, "{err:?}");
        // No probe: `--erase` uses the loader's own `virt` alt by token, so nothing
        // here resolves `--alt`.
        assert!(!err.contains("Targeting alt"), "an erase needs no --alt: {err:?}");
        Ok(())
    }

    /// **`--erase` failure.** A loader with no `erase` alt fails the *erase*, so it is
    /// a transfer error (exit 2) — which is what the C returns from the same branch
    /// (`cli/main.c:527-533`), and it is not the "no alt" case: that one is
    /// `--alt` resolution, which happens before any byte moves and exits 1.
    #[test]
    fn op_erase_without_the_alt_says_what_to_do() -> TestResult {
        let bare = Rc::new(FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash(
            "flash", 8192,
        )])));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&bare)]);
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Erase])?)?;

        assert!(matches!(failure.error, Error::MissingAlt(_)), "{failure:?}");
        assert_eq!(failure.exit_code(), TRANSFER, "{failure}");
        assert!(failure.to_string().contains("DFU loader firmware"), "{failure}");
        assert_eq!(bare.erases(), 0, "nothing was wiped");
        Ok(())
    }

    /// **`--reboot` success.** The device leaves the bus, which is the operation.
    #[test]
    fn op_reboot_takes_the_device_off_the_bus() -> TestResult {
        let gadget = loader_gadget(8192);
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let (_, err) = drive(&backend, &plan(vec![Action::Reboot])?)?;

        assert_eq!(gadget.reboots(), 1);
        assert!(gadget.is_gone(), "a reboot that left it on the bus did not happen");
        assert!(err.contains("Rebooting the device (alt 2)"), "{err:?}");
        assert_eq!(err.matches("Reboot triggered").count(), 1, "{err:?}");
        Ok(())
    }

    /// **`--reboot` failure.** A loader with no `reboot` alt exits 2 and never arms it.
    #[test]
    fn op_reboot_without_the_alt_is_a_transfer_error() -> TestResult {
        let bare = Rc::new(FakeGadget::new(GadgetConfig::new(vec![AltConfig::flash(
            "flash", 8192,
        )])));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&bare)]);
        let (failure, _, _) = drive_err(&backend, &plan(vec![Action::Reboot])?)?;

        assert!(matches!(failure.error, Error::MissingAlt(_)), "{failure:?}");
        assert_eq!(failure.exit_code(), TRANSFER, "{failure}");
        assert_eq!(bare.reboots(), 0);
        assert!(!bare.is_gone(), "it is still there");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Choosing the alt.
    // -----------------------------------------------------------------

    /// **"No alt" is a device error (exit 1), not a transfer error.**
    ///
    /// Nothing has been written when the alt cannot be found, so a wrapper checking for
    /// 2 must not see one. The C agrees (`cli/main.c:551-555` → `EXIT_DEVICE_ERROR`),
    /// and the reason it falls out here rather than needing a special case is that the
    /// resolution happens in `prepare`, outside the operation.
    #[test]
    fn fe_cli_no_alt_is_a_device_error() -> TestResult {
        let scratch = Scratch::new("no-alt")?;
        let source = scratch.write("fw.bin", &image(64))?;
        // Two alts and neither is `flash`, which is the refusal case.
        let odd = Rc::new(FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("nor", 8192),
            AltConfig::flash("nand", 8192),
        ])));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&odd)]);
        let plan = plan_with(
            vec![Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert!(matches!(failure.error, Error::MissingAlt(_)), "{failure:?}");
        assert_eq!(failure.class, OpClass::Device);
        assert_eq!(failure.exit_code(), DEVICE, "{failure}");
        assert!(
            odd.medium(0).is_none_or(|medium| medium.is_empty()),
            "nothing was written"
        );
        Ok(())
    }

    /// **A bad `--alt` must not cost an erase.**
    ///
    /// The C probes and resolves the alt *after* running the erase
    /// (`cli/main.c:527-556`), so `--erase -w img --alt typo` wipes the chip and then
    /// refuses — leaving a camera with no firmware and the write it was refused for
    /// still undone. Nothing forces that order, and functional parity is not a reason
    /// to copy it.
    #[test]
    fn a_refused_alt_never_costs_an_erase() -> TestResult {
        let scratch = Scratch::new("bad-alt")?;
        let source = scratch.write("fw.bin", &image(64))?;
        let gadget = loader_gadget(8192);
        gadget.preload(0, image(8192));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&gadget)]);
        let plan = plan_with(
            vec![Action::Erase, Action::Write],
            Target {
                alt: AltSel::Name("rootfs".into()),
                ..target()
            },
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert_eq!(failure.exit_code(), DEVICE, "{failure}");
        assert!(failure.to_string().contains("rootfs"), "{failure}");
        assert_eq!(gadget.erases(), 0, "the chip must still hold its firmware");
        assert_eq!(
            gadget.medium(0).as_deref().map(<[u8]>::len),
            Some(8192),
            "and all of it"
        );
        Ok(())
    }

    /// `--alt` by name reaches the operation that uses it.
    #[test]
    fn an_explicit_alt_is_the_one_written_to() -> TestResult {
        let scratch = Scratch::new("explicit-alt")?;
        let payload = image(64);
        let source = scratch.write("fw.bin", &payload)?;
        let two = Rc::new(FakeGadget::new(GadgetConfig::new(vec![
            AltConfig::flash("flash", 8192),
            AltConfig::flash("spare", 8192),
        ])));
        let backend = FakeBackend::new(vec![FakeBackend::emulated_gadget(&two)]);
        let plan = plan_with(
            vec![Action::Write],
            Target {
                alt: AltSel::Name("spare".into()),
                ..target()
            },
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (_, err) = drive(&backend, &plan)?;

        assert!(err.contains(r#"Targeting alt 1 ("spare")"#), "{err:?}");
        assert_eq!(two.medium(1).as_deref(), Some(&payload[..]), "alt 1 took the bytes");
        assert!(
            two.medium(0).is_none_or(|medium| medium.is_empty()),
            "and alt 0 did not"
        );
        Ok(())
    }

    /// A transfer against a device that is neither a bootrom nor a gadget is refused
    /// before anything is claimed, and says which it is.
    #[test]
    fn a_transfer_needs_the_gadget() -> TestResult {
        let scratch = Scratch::new("no-gadget")?;
        let source = scratch.write("fw.bin", &image(64))?;
        let backend = FakeBackend::new(vec![FakeBackend::opaque()]);
        let plan = plan_with(
            vec![Action::Write],
            target(),
            Images {
                write: Some(source),
                ..Images::default()
            },
        )?;
        let (failure, _, _) = drive_err(&backend, &plan)?;

        assert!(failure.to_string().contains("unrecognised kind"), "{failure}");
        assert_eq!(failure.exit_code(), DEVICE, "{failure}");
        Ok(())
    }

    /// **The auto-bootstrap pin, at the execution level.** `-w` against a bootrom
    /// USB-boots it, waits for the gadget it created, and writes to *that* — in one
    /// shot, through the real parser.
    #[test]
    fn fe_cli_autobootstrap_writes_to_the_gadget_it_created() -> TestResult {
        let scratch = Scratch::new("autobootstrap-write")?;
        scratch.loader_tree(Variant::T31x)?;
        let payload = image(4200);
        let source = scratch.write("fw.bin", &payload)?;
        let gadget = loader_gadget(8192);
        let backend = FakeBackend::appearing(vec![
            vec![FakeBackend::bootstrappable_bootrom(
                b"stage-1".to_vec(),
                b"u-boot".to_vec(),
            )],
            // The gadget comes up on the bootrom's own port, as hardware does
            // and only that port satisfies the wait.
            vec![FakeBackend::emulated_gadget_at(&gadget, vec![4, 2])],
        ]);
        let combined = crate::cli::Cli::try_parse_from([
            "thingino-dfu",
            "-w",
            &source.display().to_string(),
            "--cpu",
            "t31x",
            "--firmware-dir",
            &scratch.root().display().to_string(),
        ])?
        .into_plan()?;
        let (_, err) = drive(&backend, &combined)?;

        assert!(err.contains("Bootstrapping device 0"), "{err}");
        assert!(
            at(&err, "The U-Boot DFU gadget is up")? < at(&err, "DFU download complete")?,
            "the write must follow the bootstrap that made it possible:\n{err}"
        );
        assert_eq!(
            gadget.medium(0).as_deref().map(|medium| &medium[..payload.len()]),
            Some(&payload[..]),
            "and it landed on the gadget the bootstrap produced"
        );
        Ok(())
    }
}
