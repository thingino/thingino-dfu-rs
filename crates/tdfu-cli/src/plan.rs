//! What the arguments *mean*, as a value — with no bus, no process and no I/O.
//!
//! [`Cli`](crate::cli::Cli) is the surface a user types at; [`Plan`] is what the tool
//! then does. Keeping them apart is what lets every ordering and precedence rule be
//! unit-tested, and it is the seam every operation
//! lands on: an operation is an [`Action`] variant plus its position in
//! [`Action::order`], and it inherits the ordering test for free.
//!
//! # The shape exists because of a silent no-op
//!
//! `thingino-dfu -l -w fw.bin` printed the device list and **exited 0 without writing**:
//! success reported for a flash that did not happen,
//! the worst failure this tool has. It happened because the C treats `-l` as a mode
//! that returns (`cli/main.c:475-495`) rather than as one action among several.
//!
//! [`Plan::actions`] is an ordered list, so "list *and* write" is the only way to spell
//! `-l -w`. There is no early return to forget. The same reasoning is why `--diag`
//! beside an operation is a refusal rather than a silent preference
//! ([`PlanError::DiagIsStandalone`]): the C returns out of `main` for that one too
//! (`cli/main.c:446-457`).

use core::fmt;
use std::path::{Path, PathBuf};

use tdfu_core::model::{AltSel, Variant};

/// One user-visible operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// `-l` / `--list`: report every Ingenic device on the bus.
    List,
    /// `--diag`: read-only eFuse / serial / secure-boot dump.
    Diag,
    /// `-b`, or the auto-bootstrap that goes in front of every transfer.
    Bootstrap(BootstrapTrigger),
    /// `--erase`: wipe the whole flash.
    Erase,
    /// `-w` / `--write`.
    Write,
    /// `--verify`: read back and compare after the write it belongs to.
    Verify,
    /// `-r` / `--read`.
    Read,
    /// `--reboot`: last, so the box boots into what was just flashed.
    Reboot,
}

/// Why a [`Bootstrap`](Action::Bootstrap) is in the plan.
///
/// The distinction is not cosmetic: a *requested* bootstrap is the user's whole reason
/// for running the tool, while an *auto* one is scaffolding for the transfer behind it.
/// Both are skipped against a device that is already a gadget, and the note the run
/// prints differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapTrigger {
    /// `-b`, or a `--spl` + `--uboot` pair with no other action.
    Requested,
    /// Put there so a transfer against a bootrom works in one shot.
    Auto,
}

impl Action {
    /// Position in the fixed operation order.
    ///
    /// The C's order is bootstrap-if-bootrom → erase → write → verify → read → reboot
    /// (`cli/main.c:334-340, 470-569`), and it is right: an erase must precede the write
    /// that lands on it, a verify must follow the write it checks, a read must not see a
    /// half-written chip, and a reboot must be last because it ends the session.
    ///
    /// [`List`](Action::List) and [`Diag`](Action::Diag) sort first because they are
    /// reports, not changes, and must not displace the operations beside them.
    ///
    /// Gaps are left between the numbers so a later operation can be inserted without
    /// renumbering the ones already pinned.
    const fn order(&self) -> u8 {
        match self {
            Self::List => 0,
            Self::Diag => 5,
            Self::Bootstrap(_) => 10,
            Self::Erase => 20,
            Self::Write => 30,
            Self::Verify => 40,
            Self::Read => 50,
            Self::Reboot => 60,
        }
    }

    /// The flag that asks for it, for a message that has to name one.
    ///
    /// Both bootstrap triggers render as `-b`: an auto-bootstrap is invisible in the
    /// argument list, and every message that reaches this arm is about a *conflict*
    /// with something the user typed, where the transfer is always found first.
    const fn flag(&self) -> &'static str {
        match self {
            Self::List => "-l",
            Self::Diag => "--diag",
            Self::Bootstrap(_) => "-b",
            Self::Erase => "--erase",
            Self::Write => "-w",
            Self::Verify => "--verify",
            Self::Read => "-r",
            Self::Reboot => "--reboot",
        }
    }

    /// Does this operation need the U-Boot DFU gadget to be running?
    ///
    /// Exactly this list: `-w`, `-r`, `--erase`, `--reboot`
    /// (`cli/main.c:491`) — plus `--verify`, which rides on the write's session. These
    /// are the operations that auto-bootstrap a bootrom target.
    #[must_use]
    pub const fn needs_the_gadget(&self) -> bool {
        matches!(
            self,
            Self::Erase | Self::Write | Self::Verify | Self::Read | Self::Reboot
        )
    }

    /// Does `--alt` mean anything for this operation?
    ///
    /// Only the three that move bytes through a named entity. Erase and reboot target
    /// the loader's own `virt` alts by token, which
    /// `ops::erase` and `ops::reboot` find for themselves and which `--alt` must not be
    /// able to redirect.
    #[must_use]
    pub const fn takes_an_alt(&self) -> bool {
        matches!(self, Self::Write | Self::Verify | Self::Read)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.flag())
    }
}

/// Which device, and how to address what is on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Target {
    /// `-i`: the row number `-l` printed. Bounded to one byte at parse time, so it can
    /// never wrap onto device 0 the way the C's `(uint8_t)` cast does.
    pub index: u8,
    /// `--alt`, or [`AltSel::Default`] for the default-alt rules.
    pub alt: AltSel,
    /// `--cpu`: skip detection and use this variant's loaders.
    pub cpu: Option<Variant>,
    /// `--size`: stop a read after this many bytes.
    pub size: Option<u64>,
}

/// Every path the run may need to open.
///
/// Paths, not contents: [`Plan`] is a value with no I/O in it. Reading them is
/// [`images`](crate::images)' job, and it happens **before** the bus is touched.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Images {
    /// `-w`: the image to write.
    pub write: Option<PathBuf>,
    /// `-r`: where to put what is read.
    pub read: Option<PathBuf>,
    /// `--spl`: a custom stage-1 image.
    pub spl: Option<PathBuf>,
    /// `--uboot`: a custom U-Boot image.
    pub uboot: Option<PathBuf>,
    /// `--firmware-dir`: the root of the loader tree.
    pub firmware_dir: Option<PathBuf>,
}

impl Images {
    /// The `--spl` + `--uboot` pair, when both are present.
    ///
    /// An explicit pair skips detection **and** the firmware-dir lookup
    /// (`dfu.c:1173, 1191-1195`). Only one of them is refused at parse time
    /// ([`PlanError::LoaderPairIncomplete`]), so this is `Some` exactly when the
    /// override is in force.
    #[must_use]
    pub fn custom_loaders(&self) -> Option<(&Path, &Path)> {
        match (&self.spl, &self.uboot) {
            (Some(spl), Some(uboot)) => Some((spl.as_path(), uboot.as_path())),
            _ => None,
        }
    }
}

/// Where a remote run would go.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Remote {
    /// `--host`.
    pub host: String,
    /// `--port`, defaulted to `tdfu_proto::DEFAULT_PORT`.
    pub port: u16,
    /// `--token`.
    pub token: Option<String>,
}

/// Everything the run will do, in the order it will do it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Plan {
    /// The operations, already in the fixed order. Never empty: an empty plan is
    /// [`PlanError::NoAction`] instead.
    pub actions: Vec<Action>,
    /// Which device, which alt, which variant.
    pub target: Target,
    /// The paths the run may open.
    pub images: Images,
    /// `--host` and friends. `Some` means the run is a remote one.
    pub remote: Option<Remote>,
    /// Block until an Ingenic device is on the bus before starting.
    pub wait: bool,
    /// Verbose diagnostics on stderr.
    pub debug: bool,
}

impl Plan {
    /// Sort `actions` into the fixed order and refuse an empty list.
    ///
    /// # Errors
    /// [`PlanError::NoAction`] when nothing was asked for. The C prints `No action
    /// specified. Use -h for help.` and returns **1** (`cli/main.c:424-428`); the exit
    /// code is kept, the wording is ours.
    pub fn new(
        mut actions: Vec<Action>,
        target: Target,
        images: Images,
        remote: Option<Remote>,
        wait: bool,
        debug: bool,
    ) -> Result<Self, PlanError> {
        if actions.is_empty() {
            return Err(PlanError::NoAction);
        }
        // Stable, so two operations that ever share an ordinal keep the order the user
        // typed rather than an arbitrary one.
        actions.sort_by_key(Action::order);
        Ok(Self {
            actions,
            target,
            images,
            remote,
            wait,
            debug,
        })
    }

    /// Is this action part of the plan?
    #[must_use]
    pub fn does(&self, action: &Action) -> bool {
        self.actions.contains(action)
    }

    /// Does the plan contain an operation that needs the gadget?
    #[must_use]
    pub fn needs_the_gadget(&self) -> bool {
        self.actions.iter().any(Action::needs_the_gadget)
    }
}

/// Why a set of arguments does not describe a run.
///
/// Every variant is a rule that would otherwise have been applied **silently**. The C
/// applies most of them silently, and each message below says what was dropped rather
/// than leaving the user to infer it from a result that did not happen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Flags were accepted, but none of them asks for anything to happen.
    #[error("no action requested: pass -l to list the Ingenic devices on the bus, or -h for every option")]
    NoAction,

    /// `--diag` was given beside an operation. The C would have run the diag and
    /// silently skipped the rest (`cli/main.c:446-457`).
    #[error(
        "--diag is a standalone read-only dump and cannot run with {with}: \
         it needs a device in the bootrom, and {with} needs the U-Boot DFU gadget. \
         Run them as two commands"
    )]
    DiagIsStandalone {
        /// The flag it collided with.
        with: String,
    },

    /// `--verify` with nothing to verify against.
    #[error("--verify compares the flash against the image -w wrote; there is no -w in this command")]
    VerifyWithoutWrite,

    /// `--size` with no read to cap.
    #[error("--size caps how much -r reads back; there is no -r in this command")]
    SizeWithoutRead,

    /// `--alt` with no operation that targets an alt.
    #[error(
        "--alt names the DFU alt-setting -w, -r and --verify target; \
         nothing in this command targets one (--erase and --reboot use the loader's own virt alts)"
    )]
    AltWithoutTransfer,

    /// `--port` or `--token` with no `--host`.
    #[error("{option} configures the connection --host makes; there is no --host in this command")]
    RemoteOptionWithoutHost {
        /// Which one was given.
        option: &'static str,
    },

    /// A flag that names something on *this* machine, given with `--host`.
    ///
    /// The C accepts `--firmware-dir` with `--host` and throws it away — `remote_bootstrap`
    /// opens with `(void)firmware_dir;` (`cli/remote.c:533`) — so the daemon quietly
    /// USB-boots out of *its* loader tree while the operator believes they chose one.
    /// That is a wrong-loader hazard dressed as a convenience, and it is the worst shape
    /// a defect can take: a flag accepted and ignored leaves nothing to grep for.
    #[error(
        "{option} points at a loader tree on this machine, and --host runs the bootstrap on the daemon's, \
         out of the tree that daemon was started with. Drop it, or stream the pair you want with --spl and --uboot"
    )]
    RemoteOptionIsLocal {
        /// Which one was given.
        option: &'static str,
    },

    /// `--cpu`, `--spl`, `--uboot` or `--firmware-dir` with nothing to bootstrap.
    #[error(
        "{option} chooses the loaders a bootstrap uploads; nothing in this command bootstraps. \
         Add -b, or an operation that needs the DFU gadget"
    )]
    BootstrapOptionWithoutBootstrap {
        /// Which one was given.
        option: &'static str,
    },

    /// One of `--spl`/`--uboot` without the other. The C ignores the one it was given
    /// and silently uses the firmware tree's pair (`dfu.c:1173, 1191-1214`).
    #[error(
        "{given} needs {missing} too: USB-booting takes a stage-1 image and a U-Boot image, and mixing a custom one with the firmware tree's is never what was meant"
    )]
    LoaderPairIncomplete {
        /// The one that was given.
        given: &'static str,
        /// The one that was not.
        missing: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::{Action, BootstrapTrigger, Images, Plan, PlanError, Remote, Target};
    use tdfu_core::model::AltSel;

    /// A target that names device 0 and asks for nothing special.
    fn target() -> Target {
        Target {
            index: 0,
            alt: AltSel::Default,
            cpu: None,
            size: None,
        }
    }

    fn plan(actions: Vec<Action>) -> Result<Plan, PlanError> {
        Plan::new(actions, target(), Images::default(), None, false, false)
    }

    #[test]
    fn a_plan_needs_an_action() {
        assert_eq!(plan(Vec::new()), Err(PlanError::NoAction));
        assert_eq!(
            PlanError::NoAction.to_string(),
            "no action requested: pass -l to list the Ingenic devices on the bus, or -h for every option"
        );
    }

    /// **The operation-order pin.** Whatever order they are typed in, they run in this
    /// one: bootstrap → erase → write → verify → read → reboot, with the reports first.
    #[test]
    fn fe_cli_op_order() -> Result<(), PlanError> {
        // Typed backwards, on purpose.
        let typed = vec![
            Action::Reboot,
            Action::Read,
            Action::Verify,
            Action::Write,
            Action::Erase,
            Action::Bootstrap(BootstrapTrigger::Requested),
            Action::List,
        ];
        assert_eq!(
            plan(typed)?.actions,
            vec![
                Action::List,
                Action::Bootstrap(BootstrapTrigger::Requested),
                Action::Erase,
                Action::Write,
                Action::Verify,
                Action::Read,
                Action::Reboot,
            ]
        );

        // And the ordinals really are strictly increasing, so no two operations can
        // quietly share a slot and be reordered by the sort's stability instead.
        let ordinals: Vec<u8> = [
            Action::List,
            Action::Diag,
            Action::Bootstrap(BootstrapTrigger::Requested),
            Action::Erase,
            Action::Write,
            Action::Verify,
            Action::Read,
            Action::Reboot,
        ]
        .iter()
        .map(Action::order)
        .collect();
        let mut sorted = ordinals.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ordinals, sorted, "every action needs its own place");
        Ok(())
    }

    /// **The auto-bootstrap pin, ordering half.** An auto-bootstrap sorts into the same
    /// slot a requested one does.
    ///
    /// It has to: the auto-bootstrap goes in front of the transfer, and the C runs it at
    /// exactly the point `-b` would have (`cli/main.c:491-511`). The other half — that
    /// every transfer *gets* one — is
    /// [`fe_cli_autobootstrap`](crate::cli::tests::fe_cli_autobootstrap), where the
    /// flags are.
    #[test]
    fn fe_cli_autobootstrap_takes_the_bootstrap_slot() -> Result<(), PlanError> {
        let plan = plan(vec![Action::Write, Action::Bootstrap(BootstrapTrigger::Auto)])?;
        assert_eq!(
            plan.actions,
            vec![Action::Bootstrap(BootstrapTrigger::Auto), Action::Write]
        );
        assert_eq!(
            Action::Bootstrap(BootstrapTrigger::Auto).order(),
            Action::Bootstrap(BootstrapTrigger::Requested).order()
        );
        Ok(())
    }

    /// Which operations need the gadget is a fixed list, asserted in both
    /// directions so an added variant has to choose.
    #[test]
    fn fe_cli_the_gadget_operations_are_the_transfers() {
        for needs in [
            Action::Erase,
            Action::Write,
            Action::Verify,
            Action::Read,
            Action::Reboot,
        ] {
            assert!(needs.needs_the_gadget(), "{needs} needs the gadget");
        }
        for does_not in [
            Action::List,
            Action::Diag,
            Action::Bootstrap(BootstrapTrigger::Requested),
        ] {
            assert!(!does_not.needs_the_gadget(), "{does_not} does not need the gadget");
        }
    }

    /// `--alt` belongs to the three operations that address a named entity.
    #[test]
    fn only_a_byte_moving_operation_takes_an_alt() {
        for takes in [Action::Write, Action::Verify, Action::Read] {
            assert!(takes.takes_an_alt(), "{takes} takes an alt");
        }
        for does_not in [
            Action::List,
            Action::Diag,
            Action::Bootstrap(BootstrapTrigger::Auto),
            Action::Erase,
            Action::Reboot,
        ] {
            assert!(!does_not.takes_an_alt(), "{does_not} takes no alt");
        }
    }

    #[test]
    fn a_plan_reports_what_it_will_do() -> Result<(), PlanError> {
        let built = Plan::new(
            vec![Action::List],
            target(),
            Images::default(),
            Some(Remote {
                host: "camera.invalid".to_owned(),
                port: 5050,
                token: None,
            }),
            true,
            true,
        )?;
        assert!(built.does(&Action::List));
        assert!(!built.does(&Action::Write));
        assert!(!built.needs_the_gadget());
        assert!(built.wait);
        assert!(built.debug);
        assert_eq!(
            built.remote.map(|remote| remote.host),
            Some("camera.invalid".to_owned())
        );
        assert_eq!(Action::List.to_string(), "-l");
        assert_eq!(Action::Bootstrap(BootstrapTrigger::Auto).to_string(), "-b");
        Ok(())
    }

    #[test]
    fn a_plan_with_a_transfer_needs_the_gadget() -> Result<(), PlanError> {
        assert!(plan(vec![Action::Write])?.needs_the_gadget());
        assert!(plan(vec![Action::Reboot])?.needs_the_gadget());
        assert!(!plan(vec![Action::Diag])?.needs_the_gadget());
        Ok(())
    }

    /// The `--spl`/`--uboot` pair is only an override when it is a pair.
    #[test]
    fn custom_loaders_needs_both_halves() {
        let mut images = Images::default();
        assert_eq!(images.custom_loaders(), None);
        images.spl = Some("spl.bin".into());
        assert_eq!(images.custom_loaders(), None);
        images.uboot = Some("u.bin".into());
        assert_eq!(
            images.custom_loaders(),
            Some((std::path::Path::new("spl.bin"), std::path::Path::new("u.bin")))
        );
    }
}
