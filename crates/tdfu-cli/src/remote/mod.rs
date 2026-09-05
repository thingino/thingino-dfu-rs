//! `--host`: the same [`Plan`], run through a `dfu-remote` daemon.
//!
//! # The plan is the plan
//!
//! The operation order is fixed (bootstrap → erase → write → verify → read →
//! reboot) and [`Plan::new`](crate::plan::Plan::new) has already applied it. This module
//! executes **the same ordered list** the local run executes, against a socket instead of
//! a bus. The C could not: its remote mode is a chain of mutually exclusive `else if`
//! branches (`cli/main.c:372-415`), so `-w` there means "write, and maybe erase first,
//! and maybe reboot after" as one hard-coded shape, while `-r --reboot` and `-l -w` mean
//! something else again. One list, one order, one meaning per flag — and, notably, the
//! *same* meaning as without `--host`.
//!
//! # Two things the wire does not have, and how each is answered
//!
//! * **There is no verify command.** `--verify` is the optional trailing byte of
//!   `CMD_WRITE`, so [`Action::Verify`] is folded into the write it belongs
//!   to and its own arm does nothing. [`Plan`] already refuses `--verify` without `-w`.
//! * **There is no erase command.** `--erase` is a `CMD_WRITE` of the 17-byte wipe token
//!   to the loader's `erase` alt, which the daemon routes to the real erase path
//!   (`dfu-remote/main.c:506`). That is not a trick this client invented; it is
//!   the protocol.
//!
//! # Exit codes are `exit.rs`'s, unchanged
//!
//! An earlier implementation could never exit **3** remotely, so a missing file exited 2
//! over the network and 3 locally, the tool contradicting itself.
//! It cannot happen here by construction: [`images::preflight`](crate::images::preflight)
//! runs **before** this module is reached, in [`run`](crate::run::run), so every file
//! error on either path is produced by the same code. What is left, a failed write to
//! the `-r` output, goes through [`RemoteError::File`], which
//! [`exit_code`](crate::exit::exit_code) maps to 3 whatever was running.

pub mod error;
pub mod table;
pub mod wire;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use std::io::Write;

use tdfu_core::clock::Sleeper;
use tdfu_core::model::AltSel;
use tdfu_proto::{DeviceEntry, ERASE_ALT, ERASE_TOKEN, Request, WireVariant, crc32};

use crate::exit::OpClass;
use crate::images::Loaded;
use crate::plan::{Action, BootstrapTrigger, Plan, Remote};
use crate::remote::error::{Address, RemoteError};
use crate::remote::wire::Client;
use crate::render::Bar;
use crate::run::{Failure, class_of};
use crate::wait;

/// What each command is called in a message.
///
/// **Noun phrases, not verbs.** The same string has to read correctly in "the daemon at
/// cam:5050 could not complete …", "… closed the connection during …" and "the connection
/// failed while sending …"; a verb phrase works in the first and reads as a typo in the
/// other two, and a message that reads as a typo is one an operator distrusts.
mod doing {
    /// `CMD_DISCOVER`.
    pub const LIST: &str = "the device list";
    /// `CMD_DIAG`.
    pub const DIAG: &str = "the diagnostics";
    /// `CMD_BOOTSTRAP`.
    pub const BOOTSTRAP: &str = "the bootstrap";
    /// The wipe-token `CMD_WRITE`, which is named for what it does rather than for the
    /// command it rides on: an operator who typed `--erase` should not have to know that
    /// the wire has no erase command to read the failure.
    pub const ERASE: &str = "the erase";
    /// `CMD_WRITE`.
    pub const WRITE: &str = "the write";
    /// `CMD_WRITE` with its trailing verify byte set.
    ///
    /// There is no verify command on this wire, so one refusal may be about either half
    /// and a verify mismatch happens *after* a write that succeeded. Calling that "the
    /// write" told the operator the flash never took, which is the opposite of true; the
    /// daemon's own payload (`verify failed at offset 0x…`, frozen by the wire) says
    /// which half, and this says there were two.
    pub const WRITE_AND_VERIFY: &str = "the write and its verify";
    /// `CMD_READ`.
    pub const READ: &str = "the read";
    /// `CMD_REBOOT`.
    pub const REBOOT: &str = "the reboot";
}

/// How many times [`Session::settle`] re-asks the daemon what the target is.
///
/// The daemon's re-enumeration window, in [`wait::POLL_INTERVAL`]s. The daemon re-probes for the
/// gadget 120 times, 250 ms apart, before giving up (`dfu-remote/main.c:344-353`), which is
/// 30 s, and 30 s of 500 ms polls is 60. Written out rather than divided out of the two
/// `Duration`s, because a `const` division of those needs the casts `clippy::pedantic`
/// warns about; `the_settle_window_is_fe_d_1s` pins the arithmetic against
/// [`wait::REENUM_ATTEMPTS`] and [`wait::REENUM_INTERVAL`], so the pair cannot drift.
const SETTLE_POLLS: u32 = 60;

/// Run `plan` against the daemon `remote` names.
///
/// # Errors
/// [`Failure`], carrying the operation's class: **4** for anything that went wrong on the
/// wire, **3** for a file, and the running operation's own class — 1 or 2, exactly as
/// locally — for an operation the daemon attempted and could not finish.
pub async fn run<C: Sleeper>(
    remote: &Remote,
    plan: &Plan,
    clock: &C,
    loaded: Loaded,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Failure> {
    let at = Address::new(remote.host.clone(), remote.port);
    let client = Client::connect(at.clone(), remote.token.as_deref()).map_err(|error| {
        // Everything before the first command is the protocol class: there is no
        // operation yet to take the blame.
        error.failure(OpClass::Remote)
    })?;

    let mut session = Session {
        client,
        at,
        plan,
        loaded,
        devices: None,
        chosen: Chosen::Operator,
        bar: Bar::new(),
    };
    // One line, on stderr, saying which machine did this. A pasted terminal that does not
    // say where a flash happened costs a round trip, and the local run's banner makes the
    // same trade.
    session.say(&format!("Talking to the dfu-remote daemon at {}.", session.at), err);

    let outcome = session.run_plan(clock, out, err).await;
    // Whatever happened, the counter does not get to leave a half-drawn line behind the
    // failure message `main` is about to print.
    session.bar.clear(err);
    outcome
}

/// One remote run's state.
struct Session<'a> {
    /// The open conversation.
    client: Client,
    /// Where it goes, for the messages that name it.
    at: Address,
    /// What to do, in the fixed order.
    plan: &'a Plan,
    /// The files the preflight read and created, before anything was connected.
    loaded: Loaded,
    /// The last `CMD_DISCOVER` answer. The C sends one per question — `remote_device_stage`
    /// and `remote_detect_variant` are two round trips for two fields of the same row
    /// (`cli/remote.c:493`, `:462`), and this asks once and reads the row twice.
    ///
    /// **A listing is not stable and must not be assumed to be.** The bus is what changes
    /// it: a bootstrap takes one device off and puts it back at another address, a second
    /// operator's camera can arrive, and neither end sorts the rows (the daemon's listing
    /// is `nusb`'s enumeration order, which on Linux is an unsorted read of
    /// `/sys/bus/usb/devices/`). Dropped after a bootstrap, which is the one thing this
    /// client itself does that changes a device's stage.
    devices: Option<Vec<DeviceEntry>>,
    /// Which row of that listing this run is talking about. See [`Chosen`].
    chosen: Chosen,
    /// Where an operation's account of itself goes.
    bar: Bar,
}

/// A row of the daemon's listing, and the identity that listing gave it.
///
/// The wire carries a **position**, never a device. The daemon resolves that position
/// against the listing it last sent this connection: it keeps that listing as the
/// client's frame of reference, reads the bus and port path stored in the row the
/// position names, and adopts only the device sitting at that bus and port: after a
/// `CMD_BOOTSTRAP`, the device expected back at that port. So a position means the device
/// the operator picked only for as long as the listing behind it is the one they picked
/// from, and every fresh `CMD_DISCOVER` replaces that listing on both sides.
///
/// The bus and the address are the whole of a row's identity on this wire: the port path
/// that would survive a re-enumeration is not a field of `DeviceEntry`, which is why the
/// daemon, holding both, is the side that resolves the position.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    /// The position that row held, which is what goes on the wire.
    index: u8,
    /// The bus it was on ...
    bus: u8,
    /// ... and the address it answered at.
    address: u8,
}

impl Anchor {
    /// Is `entry`, read at this anchor's position in a newer listing, the device this run
    /// picked?
    ///
    /// Same bus and same address is the row itself, unmoved. A **gadget** on the same bus
    /// at another address is accepted as well, because a bootstrap is precisely what
    /// changes a device's address: the bootrom disconnects and U-Boot's DFU gadget
    /// enumerates afresh. That leaves one case this side cannot decide (a *second*
    /// gadget that moved into the position while ours was away is a match by bus alone),
    /// and it is the daemon, which stored the port path, that decides it.
    ///
    /// Anything else is a different device: another camera's bootrom that took the
    /// position over, or a row on another bus entirely.
    const fn matches(self, entry: DeviceEntry) -> bool {
        entry.bus == self.bus && (entry.address == self.address || entry.stage == 2)
    }
}

/// What this run is pointing at, as far as the daemon's listing is concerned.
#[derive(Debug, Clone, Copy)]
enum Chosen {
    /// No listing has been read yet, so the number to send is the operator's own `-i`.
    Operator,
    /// A row read out of the listing the daemon holds for this connection.
    Row(Anchor),
    /// A newer listing does not hold that row, so no position on this connection names
    /// the device the operator picked, and none is sent.
    Gone(Anchor),
}

impl Session<'_> {
    /// `--wait`, then every action in the plan, in order.
    async fn run_plan<C: Sleeper>(
        &mut self,
        clock: &C,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<(), Failure> {
        // Said before anything is sent, because it is about what the number the operator
        // typed will mean on the far side, and after a write it is too late to be worth
        // reading. See [`alt_bytes`].
        if let AltSel::Index(index) = self.plan.target.alt {
            self.say(
                &format!(
                    "--alt {index} goes on the wire as the text \"{index}\", and the daemon tries an alt \
                     *named* \"{index}\" before falling back to alt number {index}. Locally the number is \
                     the number and nothing else.",
                ),
                err,
            );
        }
        if self.plan.wait {
            self.wait_for_a_device(clock, err)
                .await
                .map_err(|error| error.failure(OpClass::Device))?;
        }
        for action in &self.plan.actions {
            let class = class_of(action);
            self.act(action, clock, out, err)
                .await
                .map_err(|error| error.failure(class))?;
        }
        Ok(())
    }

    /// `--wait`, over the wire: poll until the daemon can see something.
    ///
    /// The C ignores `--wait` in remote mode entirely — `main.c:346`'s remote branch
    /// returns before the local `wait_for_device` is reached — so a wrapper that passes
    /// it gets a flag accepted and dropped, which leaves nothing to grep for.
    /// `CMD_DISCOVER` is the remote form of the local bus scan, and a pure list scan makes
    /// polling it safe, so the flag means here what it means locally: wait, at the same
    /// interval, for ever, with Ctrl-C to abort. The two announcement lines are the local
    /// ones, from [`wait`](crate::wait), because it is the same wait.
    async fn wait_for_a_device<C: Sleeper>(&mut self, clock: &C, err: &mut dyn Write) -> Result<(), RemoteError> {
        let mut announced = false;
        loop {
            // Fresh every time: a cached list is exactly what a wait must not have.
            self.devices = None;
            if !self.discover(err)?.is_empty() {
                if announced {
                    self.say(wait::ARRIVED, err);
                }
                return Ok(());
            }
            if !announced {
                self.say(wait::WAITING, err);
                announced = true;
            }
            clock.sleep(wait::POLL_INTERVAL).await;
        }
    }

    /// One action.
    ///
    /// The clock reaches only [`bootstrap`](Session::bootstrap), which is the one arm that
    /// may have to wait for the target to stop being two things at once
    /// ([`settle`](Session::settle)). Every other arm is a round trip and nothing else.
    async fn act<C: Sleeper>(
        &mut self,
        action: &Action,
        clock: &C,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> Result<(), RemoteError> {
        match action {
            Action::List => self.list(out, err),
            Action::Diag => self.diag(out, err),
            Action::Bootstrap(trigger) => self.bootstrap(*trigger, clock, err).await,
            Action::Erase => self.erase(err),
            Action::Write => self.write(err),
            Action::Verify => Self::verify(self.plan),
            Action::Read => self.read(err),
            Action::Reboot => self.reboot(err),
        }
    }

    /// `-l`: the daemon's inventory.
    ///
    /// **No alt block.** The listing's second half prints the targeted gadget's alts,
    /// which locally costs one `ops::probe`; there is no probe command on this wire, and
    /// the nearest thing — a `CMD_READ` or `CMD_WRITE` — moves bytes. So the table is the
    /// whole answer remotely, and the alts come from running `-l` where the camera is.
    fn list(&mut self, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), RemoteError> {
        let at = self.at.clone();
        let entries = self.discover(err)?.to_vec();
        table::render(&at, &entries, out)
            .and_then(|()| out.flush())
            .map_err(|source| RemoteError::file("cannot write the device list to stdout", &source))
    }

    /// `--diag`: the daemon's formatted eFuse report.
    ///
    /// The payload is text and it goes to **stdout alone**, for the reason the local arm
    /// does it: the report is the artefact an operator pastes into a bug report, and a
    /// line of ours mixed into it would travel with it.
    fn diag(&mut self, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), RemoteError> {
        let index = self.wire_index()?;
        self.send(&Request::Diag { index }, doing::DIAG)?;
        let payload = self.finish(doing::DIAG, err)?;
        // The daemon wrote the report and it goes to a terminal, so its control
        // characters are made visible first ([`crate::render::sanitise`]); the report is
        // several lines, so the newlines in it are kept.
        let report = crate::render::sanitise(&String::from_utf8_lossy(&payload));
        // The daemon's text may or may not end in a newline; a terminal wants exactly
        // one, and the local arm's `writeln!` produces exactly one.
        writeln!(out, "{}", report.trim_end_matches('\n'))
            .and_then(|()| out.flush())
            .map_err(|source| RemoteError::file("cannot write the diagnostics to stdout", &source))
    }

    /// `-b`, and the implicit form in front of every transfer.
    ///
    /// The daemon does **not** wait for the gadget afterwards; the next command's 30 s
    /// re-enumeration window does (`dfu-remote/main.c:342-355`). So unlike
    /// the local arm there is nothing to wait for here, and an `-b -w` pair is two
    /// commands with the wait inside the second one.
    ///
    /// That covers a `-b -w` in **one** invocation. Across two, the second one decides
    /// what to do from a `DISCOVER` taken before it has sent anything, and a device that
    /// is still mid-boot answers that `DISCOVER` as a bootrom it cannot name.
    /// [`settle`](Session::settle) is the wait for that, and it runs first.
    async fn bootstrap<C: Sleeper>(
        &mut self,
        trigger: BootstrapTrigger,
        clock: &C,
        err: &mut dyn Write,
    ) -> Result<(), RemoteError> {
        let index = self.wire_index()?;
        let entry = self.settle(index, clock, err).await?;
        // From here the wire's number means **this row**: the position the device held in
        // the listing the daemon is holding for this connection. Every command after this
        // one names it, and a `CMD_DISCOVER` that replaced that listing would have to find
        // the row again by its bus and address before another number could be sent.
        self.chosen = Chosen::Row(Anchor {
            index,
            bus: entry.bus,
            address: entry.address,
        });

        match entry.stage {
            // Already the gadget: nothing to do, and saying so is not the same as doing
            // it silently. `-b` twice is a routine bench sequence and the postcondition
            // the operator wants already holds.
            2 => {
                self.say(
                    &format!(
                        "Device {index} on {} is already the U-Boot DFU gadget; nothing to bootstrap.",
                        self.at
                    ),
                    err,
                );
                return Ok(());
            }
            0 => {}
            // Anything else is refused, whichever way the bootstrap got here. The gadget
            // and the bootrom share `a108:c309`, so a device that is
            // neither is genuinely unknown and uploading a stage-1 image to it could hit
            // a device mid-flash.
            other => {
                return Err(RemoteError::refusal(format!(
                    "device {index} on {} is {}, and only a device in the bootrom can be USB-booted{}. \
                     Power-cycle it into the bootrom and try again",
                    self.at,
                    describe(other),
                    match trigger {
                        BootstrapTrigger::Requested => "",
                        BootstrapTrigger::Auto => ", which is what this transfer needs first",
                    }
                )));
            }
        }

        // **Cloned, where `write` takes.** A loader pair is two files of a few hundred
        // kilobytes and this is the only place they are needed, so the copy is not worth
        // restructuring `Loaded` around; `write` deliberately `take`s its image instead,
        // because that one is up to 64 MiB. The asymmetry is on purpose and is stated
        // here so it does not read as an oversight beside `write`'s explicit note.
        let blobs = self.loaded.loaders.as_ref().map(|blobs| tdfu_proto::Blobs {
            spl: blobs.stage1.clone(),
            uboot: blobs.uboot.clone(),
        });
        let variant = if let Some(loaders) = self.loaded.loaders.as_ref() {
            // A streamed pair skips detection *and* the daemon's firmware
            // tree, so there is no variant to name (`cli/main.c:357-359`).
            //
            // Matched rather than `map_or_else`'d: the branch is already inside "there are
            // loaders", so an empty-string fallback was an arm nothing could reach.
            let source = loaders.source.clone();
            self.say(
                &format!("Streaming {source} to the daemon in place of its firmware tree."),
                err,
            );
            Vec::new()
        } else {
            self.variant_for(index, entry.variant, err)?
        };

        self.send(&Request::Bootstrap { index, variant, blobs }, doing::BOOTSTRAP)?;
        self.finish(doing::BOOTSTRAP, err)?;
        // The stage this device reports has just changed, so the cached answer is stale.
        self.devices = None;
        self.say(
            &format!("The daemon has USB-booted device {index}; the DFU gadget is coming up."),
            err,
        );
        Ok(())
    }

    /// What the target *is*, once it has stopped being two things at once.
    ///
    /// # The re-enumeration gap has three phases, and only the last is an answer
    ///
    /// A remote bootstrap answers the moment U-Boot starts (`dfu-remote/main.c:442`; the C
    /// daemon and ours both do). For the next one to three seconds, longer on a NAND
    /// board, a `DISCOVER` catches the target in one of three states:
    ///
    /// 1. **The bootrom is still enumerated** at the same USB address, but the SoC is
    ///    executing our stage 1, so it no longer answers the register reads and the
    ///    daemon reports it truthfully as `bootrom` with variant `0xFF` (a detection
    ///    that does not settle is `0xFF` on the wire, never a guess).
    /// 2. **The bootrom has disconnected and the gadget has not enumerated yet**, so the
    ///    daemon lists nothing, or lists other devices without this index among them.
    ///    This is the phase that reads as a failure and is not one: the device is between
    ///    two identities, not off the bus. The daemon's own wait says the same thing from
    ///    the other side, counting an index its listing does not have as a retry rather
    ///    than an error (`tdfu-daemon`'s `commands::device::find`, and
    ///    `dfu-remote/main.c:344-353`, whose comment at `:334-341` names the "spurious
    ///    `Device not found`" this avoids).
    /// 3. **The gadget has enumerated** and answers `dfu`, which is what the operation
    ///    behind this needs.
    ///
    /// A bootrom that answers those reads is live; one that does not is either mid-boot or a
    /// part this build has no loader name for, and **only time tells the two apart**. A
    /// missing row is the same shape of question: inside the window it is phase 2, and
    /// outside it, it is a bus with nothing to talk to. So once phase 1 has been seen,
    /// this waits the window the daemon's own read and write handlers already wait for the
    /// gadget (`dfu-remote/main.c:344-353`) and hands back whatever the device
    /// settled into: a gadget, which the caller then has nothing to bootstrap; a bootrom
    /// with a name, which it bootstraps as always; or the state it was already in, whose
    /// refusal is by then a true one, from [`variant_for`](Session::variant_for) for a
    /// bootrom still reporting `0xFF` and from [`entry`](Session::entry) for a row that
    /// never came back. That window is **one budget for the whole settle**, not one per
    /// phase: a device may pass through 1 and 2 and still be counted out at 30 s.
    ///
    /// This is a **bench bug**, found on a T32LQ with the Rust daemon: `-b` then `-r` as
    /// two invocations about 300 ms apart, where `-b` reported success, `-l` reported
    /// `bootrom`/`unknown`, and `-r` refused in zero seconds asking for `--cpu`. The same
    /// pair passes locally because `-b` there does not return until the gadget is up
    /// ([`wait::wait_for_gadget`], called by `run::bootstrap`); the daemon cannot block a
    /// client that long (`dfu-remote/main.c:335-341`), so remotely the wait has to be on
    /// this side. Phase 2 was the same bench one run later: waiting only through phase 1
    /// turned the `--cpu` refusal into `no Ingenic devices on the daemon's bus`
    /// one second in, which is a different sentence for the same non-event.
    ///
    /// # `--cpu` and a streamed pair are deliberately not waited for
    ///
    /// Both answer "which loader" without asking the device, so neither can reach the
    /// refusal this exists to defer. `--cpu` is also the documented escape hatch for a
    /// part detection cannot name, and making it wait 30 s for a detection
    /// it was told to skip would turn the escape hatch into a delay.
    ///
    /// The cost is stated rather than hidden: `-b` and then `-w --cpu <part>` fired inside
    /// the same one to three seconds re-sends a bootstrap to a device that is already
    /// running one, and the daemon answers `bootstrap failed: …`. That is the same thing a
    /// named bootrom does (it bootstraps at once, as it always has), the C does it too, and
    /// the alternative penalises the flag whose entire purpose is not waiting on detection.
    ///
    /// Phase 2 rides on the same decision, because the wait is only ever *entered* from
    /// phase 1: with `--cpu` or a streamed pair, a device that has already left the bootrom
    /// is the empty-bus refusal at once, exactly as it was before any of this.
    ///
    /// # Errors
    /// Whatever [`entry`](Session::entry) raises on the first `DISCOVER`, and whatever the
    /// wire raises on every re-ask: a daemon that goes away mid-wait is reported, not
    /// waited out. The two refusals that mean "not yet" inside the window, an unnamed
    /// bootrom and a missing row, are the ones held back until it closes.
    async fn settle<C: Sleeper>(
        &mut self,
        index: u8,
        clock: &C,
        err: &mut dyn Write,
    ) -> Result<DeviceEntry, RemoteError> {
        let entry = self.entry(index, err)?;
        if !self.mid_boot(entry) {
            return Ok(entry);
        }
        // The device the operator picked, as this connection's own `CMD_DISCOVER`
        // described it. Every re-ask below re-reads the same position out of a **new**
        // listing, and the bus is what reorders one, so each answer is checked against
        // this before it is taken for the target.
        let anchor = Anchor {
            index,
            bus: entry.bus,
            address: entry.address,
        };
        let window = wait::POLL_INTERVAL * SETTLE_POLLS;
        self.say(
            &format!(
                "Device {index} on {} is between the bootrom and the DFU gadget; \
                 waiting up to {} s for it to re-enumerate.",
                self.at,
                window.as_secs()
            ),
            err,
        );
        for _ in 0..SETTLE_POLLS {
            clock.sleep(wait::POLL_INTERVAL).await;
            // The cached answer is what is being waited out, so it goes before every
            // re-ask; `discover` sends a fresh `CMD_DISCOVER` once it is `None`.
            self.devices = None;
            // `lookup` rather than `entry`, which is the whole point: a row that is
            // not in this answer is phase 2, and `entry`'s refusal for it would end the
            // wait one poll after it started. So `None` falls through to the next poll,
            // exactly as an unnamed bootrom does.
            //
            // A row that is there but is **not this device** falls through too: another
            // camera's bootrom that moved into the position while ours was off the bus is
            // not something to bootstrap, and the window is still the right place to wait
            // for ours to come back rather than to refuse at once.
            if let Some(settled) = self.lookup(index, err)?
                && anchor.matches(settled)
                && !self.mid_boot(settled)
            {
                tracing::debug!(index, stage = settled.stage, "the target settled");
                return Ok(settled);
            }
        }
        // The window has closed, so the last answer is the true one and gets to make its
        // own refusal: `variant_for`'s for a bootrom still reporting `0xFF`, `entry`'s own
        // for a row that never came back. The list the last poll cached is that answer, so
        // reading it costs no further round trip.
        let last = self.entry(index, err)?;
        if anchor.matches(last) {
            return Ok(last);
        }
        Err(RemoteError::refusal(format!(
            "device {index} on {} was bus {} address {} when this run picked it, and the row at that \
             position is now bus {} address {}: another device took the position over while ours was \
             re-enumerating, and this client will not bootstrap a device the operator did not pick. \
             Run -l against {} and name the row it reports now",
            self.at, anchor.bus, anchor.address, last.bus, last.address, self.at
        )))
    }

    /// Is this row the one state waiting can resolve?
    ///
    /// Stage `bootrom` **and** variant exactly `0xFF` **and** nothing on the command line
    /// that already names a loader. A variant that is some *other* byte this build has no
    /// name for is not this case: the daemon's detection settled, it simply settled on
    /// something newer than this client's table, and no amount of waiting changes that.
    fn mid_boot(&self, entry: DeviceEntry) -> bool {
        entry.stage == 0
            && entry.variant == WireVariant::UNKNOWN
            && self.plan.target.cpu.is_none()
            && self.loaded.loaders.is_none()
    }

    /// Which loader the daemon should use, as a name it will accept.
    ///
    /// An empty variant field means "detect it yourself", and this client never
    /// sends it for a bootrom the daemon has already failed to identify: the daemon's
    /// `DISCOVER` runs detection, so a `0xFF` there means detection did not
    /// resolve, and asking again produces the same answer wrapped in one of the daemon's
    /// thirteen terse strings. The local run refuses the same case with the same advice
    /// (`run::refuse_detection`).
    fn variant_for(&mut self, index: u8, reported: WireVariant, err: &mut dyn Write) -> Result<Vec<u8>, RemoteError> {
        if let Some(forced) = self.plan.target.cpu {
            // Every `Variant::loader_dir` is a name in the frozen wire table
            // (`every_cpu_value_has_a_wire_name` pins it), so `--cpu` needs no
            // translation and cannot become a name the daemon will not recognise.
            return Ok(forced.loader_dir().as_bytes().to_vec());
        }
        let Some(name) = reported.name() else {
            return Err(RemoteError::refusal(format!(
                "the daemon at {} does not know what SoC device {index} is, so this client cannot choose a loader: \
                 pass --cpu with the part's loader name, or stream your own with --spl and --uboot",
                self.at
            )));
        };
        // **The auto-detect line**, and only here: the C prints it under
        // `need_variant = options.bootstrap && !dfu_custom_blobs` (`cli/main.c:360-364`),
        // which is exactly this branch — a bare transfer detects silently.
        self.say(&format!("Auto-detected remote device: {name}"), err);
        Ok(name.as_bytes().to_vec())
    }

    /// `--erase`: the wipe token, written to the loader's `erase` alt.
    ///
    /// There is no erase command on this wire. The daemon recognises the token and routes
    /// it to the grace-and-blank-check path (`dfu-remote/main.c:506`) rather than a
    /// generic download, which is what makes a remote erase a *verified* erase.
    fn erase(&mut self, err: &mut dyn Write) -> Result<(), RemoteError> {
        self.say(
            &format!(
                "Erasing the whole flash on {}: this takes minutes; the daemon reports progress.",
                self.at
            ),
            err,
        );
        let index = self.wire_index()?;
        self.send(
            &Request::Write {
                index,
                variant: Vec::new(),
                alt: ERASE_ALT.to_vec(),
                image: ERASE_TOKEN.to_vec(),
                crc32: crc32(ERASE_TOKEN),
                verify: None,
            },
            doing::ERASE,
        )?;
        self.finish(doing::ERASE, err)?;
        self.say("Erase completed and blank-checked (remote).", err);
        Ok(())
    }

    /// `-w`, with `--verify` folded in as `CMD_WRITE`'s trailing byte.
    ///
    /// **The failure names both halves when `--verify` is set.** The daemon runs the
    /// write and then the verify under one `CMD_WRITE`, so `verify failed at offset 0x…`
    /// comes back on the command that was labelled "the write", and rendering it as
    /// "could not complete the write" reports a write that in fact succeeded as having
    /// failed. Locally the two are separate [`Action`]s and the failure names the verify
    /// (`tdfu_core::Error::Verify`); the exit code already agrees (2 both ways), and this
    /// makes the account agree too.
    fn write(&mut self, err: &mut dyn Write) -> Result<(), RemoteError> {
        // Taken, not borrowed: the image is up to 64 MiB and `Request::Write` owns its
        // payload, so moving it saves one whole copy. Nothing reads it afterwards —
        // `--verify` is this same command's trailing byte, not a second pass.
        let Some(image) = self.loaded.write.take() else {
            return Err(disagreement("-w reached the wire with no file behind it"));
        };
        let index = self.wire_index()?;
        let verify = self.plan.does(&Action::Verify);
        let doing = if verify { doing::WRITE_AND_VERIFY } else { doing::WRITE };
        self.say(
            &format!(
                "Sending {} bytes to {} for device {}{}{}.",
                image.len(),
                self.at,
                index,
                alt_phrase(&self.plan.target.alt),
                if verify { ", to be verified after writing" } else { "" }
            ),
            err,
        );
        self.send(
            &Request::Write {
                index,
                // No variant: the target is already a DFU gadget by now, and a gadget has
                // no SoC to detect (`cli/main.c:353`). The daemon resolves the alt.
                variant: Vec::new(),
                alt: alt_bytes(&self.plan.target.alt),
                crc32: crc32(&image),
                image,
                // `Some(false)` and `None` are different bytes on the wire and the daemon
                // reads them the same way; `None` is "the client said nothing about
                // verifying", which is what a run without `--verify` means.
                verify: verify.then_some(true),
            },
            doing,
        )?;
        self.finish(doing, err)?;
        Ok(())
    }

    /// `--verify`: nothing of its own to do.
    ///
    /// The wire has no verify command — it is [`write`](Session::write)'s trailing byte —
    /// so this arm exists to keep the plan's shape identical to the local one. If it is
    /// ever reached without a write in the plan, that is this client disagreeing with
    /// [`Plan`], which refuses `--verify` without `-w` at parse time, and it says so
    /// rather than reporting a verify that never happened as a success.
    fn verify(plan: &Plan) -> Result<(), RemoteError> {
        if plan.does(&Action::Write) {
            tracing::debug!("--verify rode along as CMD_WRITE's trailing byte");
            return Ok(());
        }
        Err(disagreement(
            "--verify reached the wire with no -w beside it; cli::actions and remote::run disagree",
        ))
    }

    /// `-r`: the whole alt, streamed to the file the preflight created.
    fn read(&mut self, err: &mut dyn Write) -> Result<(), RemoteError> {
        let index = self.wire_index()?;
        let alt = &self.plan.target.alt;
        let limit = self.plan.target.size;
        let Some(path) = self.plan.images.read.clone() else {
            return Err(disagreement("-r reached the wire with no path behind it"));
        };
        if let Some(limit) = limit {
            // Said **before** the transfer, because the whole point of `--size` is to
            // avoid a twenty-minute read and remotely it cannot: `CMD_READ`'s payload has
            // no length field, so the daemon uploads the whole alt whatever this asks for.
            self.say(
                &format!(
                    "--size {limit} is a client-side cap here: the wire's read has no length field, \
                     so the daemon sends the whole alt and the first {limit} bytes are kept."
                ),
                err,
            );
        }
        self.say(
            &format!(
                "Reading device {index}{} from {} into {}.",
                alt_phrase(alt),
                self.at,
                path.display()
            ),
            err,
        );
        self.send(
            &Request::Read {
                index,
                variant: Vec::new(),
                // `None` is "no alt field at all", which the wire allows and which
                // says exactly what `--alt` being absent means. The daemon then uses its
                // own default, the first alt.
                alt: match alt {
                    AltSel::Default => None,
                    other => Some(alt_bytes(other)),
                },
            },
            doing::READ,
        )?;

        let Some(out) = self.loaded.read.as_mut() else {
            return Err(disagreement("-r reached the wire with no open file behind it"));
        };
        let written = self
            .client
            .read_to(doing::READ, out, &path, limit, &mut self.bar, err)?;
        // **Not a duplicate of the daemon's own count.** The daemon's core emits
        // `DFU upload complete: N bytes` into the log stream and this client renders it
        // verbatim, and a second line here is exactly the double-printing trap. What is
        // added here is what only this side knows: where the bytes landed, and that the
        // CRC-32 the daemon sent matched them.
        self.say(
            &format!("Saved {written} bytes to {} (CRC-32 checked).", path.display()),
            err,
        );
        Ok(())
    }

    /// `--reboot`: its own command, and last.
    fn reboot(&mut self, err: &mut dyn Write) -> Result<(), RemoteError> {
        let index = self.wire_index()?;
        self.send(&Request::Reboot { index }, doing::REBOOT)?;
        // The only OK whose payload is empty. Nothing is read from it, and
        // a daemon that sends something anyway is not worth failing a completed reboot
        // over.
        self.finish(doing::REBOOT, err)?;
        self.say(&format!("Reboot triggered on device {index} (remote)."), err);
        Ok(())
    }

    // -----------------------------------------------------------------
    // The conversation.
    // -----------------------------------------------------------------

    /// The daemon's device list, fetched at most once between bootstraps.
    fn discover(&mut self, err: &mut dyn Write) -> Result<&[DeviceEntry], RemoteError> {
        if self.devices.is_none() {
            self.send(&Request::Discover, doing::LIST)?;
            let payload = self.finish(doing::LIST, err)?;
            let entries = DeviceEntry::decode_list(&payload).map_err(|source| {
                RemoteError::protocol(format!(
                    "the daemon at {} sent a device list this client cannot read: {source}",
                    self.at
                ))
            })?;
            tracing::debug!(devices = entries.len(), "discovered");
            self.devices = Some(entries);
            self.reanchor();
        }
        Ok(self.devices.as_deref().unwrap_or_default())
    }

    /// Find the chosen row again in a listing that has just replaced the one it came from.
    ///
    /// A fresh `CMD_DISCOVER` is the daemon's new frame of reference for this connection,
    /// so the position that named the target a moment ago names whatever is at that
    /// position now. The row is looked up again by the only identity the wire gave it, and
    /// a row that is not in the new listing leaves this run with no number to send
    /// ([`wire_index`](Session::wire_index)) rather than with the old one.
    fn reanchor(&mut self) {
        let anchor = match self.chosen {
            Chosen::Operator => return,
            Chosen::Row(anchor) | Chosen::Gone(anchor) => anchor,
        };
        let found = self
            .devices
            .as_deref()
            .unwrap_or_default()
            .iter()
            .position(|entry| anchor.matches(*entry))
            .and_then(|position| u8::try_from(position).ok());
        self.chosen = found.map_or(Chosen::Gone(anchor), |index| Chosen::Row(Anchor { index, ..anchor }));
    }

    /// The device number to put on the wire.
    ///
    /// The operator's own `-i` until a listing has been read, and after that the position
    /// the chosen row holds in the listing the daemon is holding for this connection.
    ///
    /// # Errors
    /// A refusal once a newer listing has replaced that one without the chosen row in it:
    /// the old number would then name whatever moved into the position, and this client
    /// sends nothing rather than a number that means a different camera.
    fn wire_index(&self) -> Result<u8, RemoteError> {
        match self.chosen {
            Chosen::Operator => Ok(self.plan.target.index),
            Chosen::Row(anchor) => Ok(anchor.index),
            Chosen::Gone(anchor) => Err(RemoteError::refusal(format!(
                "device {} on {} was bus {} address {} when this run picked it, and the daemon's newest \
                 device list no longer has it: any number sent now would name whatever took its place. \
                 Run -l against {} to see the bus as it is",
                self.plan.target.index, self.at, anchor.bus, anchor.address, self.at
            ))),
        }
    }

    /// The row `-i` names, if the daemon listed one for it.
    ///
    /// `Ok(None)` is a daemon that answered with no such row: an empty list, or one whose
    /// devices stop short of this index. That is the same fact [`entry`](Session::entry)
    /// refuses on, handed back instead of raised, because [`settle`](Session::settle) has
    /// one window in which it means "not yet" rather than "no". Everything that can go
    /// wrong on the **wire** is still an `Err`, so a daemon that dies mid-wait is reported
    /// rather than mistaken for a device that has not come back yet.
    fn lookup(&mut self, index: u8, err: &mut dyn Write) -> Result<Option<DeviceEntry>, RemoteError> {
        Ok(self.discover(err)?.get(usize::from(index)).copied())
    }

    /// The row `-i` names, or a refusal that says how many rows there are.
    ///
    /// **An empty bus is the local sentence**, advice included. It is the same fault on
    /// either side of the socket, `--wait` works here too
    /// ([`wait_for_a_device`](Session::wait_for_a_device)), and dropping the advice
    /// because the bus is a daemon's would be a difference with nothing behind it. The
    /// tail comes from [`target::EMPTY_BUS_ADVICE`](crate::target::EMPTY_BUS_ADVICE) so
    /// the two cannot drift apart.
    fn entry(&mut self, index: u8, err: &mut dyn Write) -> Result<DeviceEntry, RemoteError> {
        if let Some(entry) = self.lookup(index, err)? {
            return Ok(entry);
        }
        // The lookup has just cached the daemon's answer, so counting the rows it did send
        // is a read of that cache and not a second `CMD_DISCOVER`.
        let count = self.discover(err)?.len();
        if count == 0 {
            return Err(RemoteError::refusal(format!(
                "no Ingenic devices on the daemon's bus at {}: {}",
                self.at,
                crate::target::EMPTY_BUS_ADVICE
            )));
        }
        Err(RemoteError::refusal(format!(
            "device {index} is not on the daemon's bus: {} reports {count} device(s). \
             Run the same command with -l instead of an operation to see them",
            self.at
        )))
    }

    /// Send one request.
    fn send(&mut self, request: &Request, doing: &str) -> Result<(), RemoteError> {
        self.client.send(request, doing)
    }

    /// Pump log and progress frames, and hand back the OK payload.
    fn finish(&mut self, doing: &str, err: &mut dyn Write) -> Result<Vec<u8>, RemoteError> {
        self.client.finish(doing, &mut self.bar, err)
    }

    /// One line of this client's own narration, on stderr.
    ///
    /// Through the [`Bar`], never straight to `err`: a daemon's `RESP_PROGRESS` frame may
    /// have a counter on the current line, and terminating it is the
    /// client's job now that byte counts are frames rather than log text.
    fn say(&mut self, line: &str, err: &mut dyn Write) {
        self.bar.note(line, err);
    }
}

/// The wire's stage byte, in a sentence.
fn describe(stage: u8) -> String {
    match stage {
        1 => "running firmware".to_owned(),
        2 => "the U-Boot DFU gadget".to_owned(),
        other => format!("in a stage this client does not know ({other})"),
    }
}

/// The alt selector as the wire spells it.
///
/// A number goes as its decimal text, because that is the only spelling the field has:
/// the write and read commands freeze it as one "name or number" string, which the daemon
/// turns back into an `AltSel::Name` and hands to `alt::by_name`.
///
/// # `--alt <number>` is resolved name-first remotely and index-only locally
///
/// A number typed locally is `AltSel::Index` and matches a `bAlternateSetting` and
/// nothing else (`cli::parse_alt`); the same number sent over the wire arrives as a
/// *name*, and `alt::by_name` tries a name match before falling back to the decimal
/// (`tdfu_core::dfu::alt::by_name`, which is the C's own order, `dfu.c:512-524`). So a
/// loader with an alt literally **named** `1` at `bAlternateSetting 3` would make
/// `--alt 1` mean alt 1 locally and alt 3 remotely, which is a write to a different
/// partition.
///
/// The code stands: no shipped loader names an alt in digits (`flash`, `erase`,
/// `reboot`, `sdcard`), the wire field cannot express the difference without
/// a protocol change, and the daemon would have to guess anyway. What does not stand is
/// claiming the two agree; this says where they do not, so the day a loader does name
/// an alt `1` the answer is written down rather than discovered on a flashed board.
fn alt_bytes(alt: &AltSel) -> Vec<u8> {
    match alt {
        AltSel::Name(name) => name.as_bytes().to_vec(),
        AltSel::Index(index) => index.to_string().into_bytes(),
        // `AltSel::Default` is an empty field, which is how the wire spells "the daemon
        // picks". `AltSel` is also `#[non_exhaustive]` in `tdfu-core`: a
        // selector added later has no spelling here yet, and the daemon's default is the
        // safe reading of "we do not know".
        _ => Vec::new(),
    }
}

/// The alt as a phrase for a narration line: empty, or ` alt "flash"`.
fn alt_phrase(alt: &AltSel) -> String {
    match alt {
        AltSel::Name(name) => format!(" alt {name:?}"),
        AltSel::Index(index) => format!(" alt {index}"),
        // Nothing to say for the default, and nothing invented for a selector this build
        // does not know.
        _ => String::new(),
    }
}

/// Two parts of this crate contradicting each other, said out loud.
///
/// The same shape [`run::missing_preflight`](crate::run) uses: it is not a user error, so
/// it must not be reported as a device failure, and it must certainly not be reported as
/// a success.
///
/// It is a [`RemoteError::Refusal`] and not a `Protocol`, so it takes the running
/// operation's class: `missing_preflight` raises `Error::Invalid`, which
/// [`exit_code`](crate::exit::exit_code) turns into the class's own code, and the same
/// disagreement must not exit **4** here and **2** locally.
fn disagreement(what: &str) -> RemoteError {
    RemoteError::refusal(format!("{what}: this is a bug in thingino-dfu, not in the command"))
}
