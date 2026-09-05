//! The argument surface, as a `clap` derive type.
//!
//! Parsing is a **pure function**: [`Cli`] comes out of `argv`, [`Cli::into_plan`]
//! turns it into a [`Plan`], and neither touches a bus, a file or a process. Every test
//! in this module runs with no USB and no `main`.
//!
//! # Spellings are the C's
//!
//! Functional parity means every flag a user could type at the
//! shipped tool still works here, with the same spelling. The whole surface is below,
//! read off `cli/main.c:87-186` — the `strcmp` chain *is* the C's parser, so it is the
//! authority on what exists:
//!
//! | C | here |
//! |---|---|
//! | `-h`/`--help`, `-d`/`--debug`, `-l`/`--list` | same |
//! | `-i`/`--index <num>` | same, bounded (see [`parse_index`]) |
//! | `-b`/`--bootstrap` | same |
//! | `-r`/`--read <file>`, `-w`/`--write <file>` | same |
//! | `--diag`, `--verify`, `--erase`, `--reboot`, `--wait` | same |
//! | `--cpu <variant>` | same, resolved at parse time (see [`parse_cpu`]) |
//! | `--spl <file>`, `--uboot <file>`, `--firmware-dir <dir>` | same |
//! | `--alt <name\|num>` | same, bounded (see [`parse_alt`]) |
//! | `--host <addr>`, `--port <port>`, `--token <secret>` | same |
//!
//! Two entries in that table are easy to get wrong, and both were checked against the C
//! rather than assumed:
//!
//! * **The long spelling of `-i` is `--index`, not `--device`** (`cli/main.c:168`).
//!   `--device` is accepted by nothing in the C tree.
//! * **`--firmware-dir` exists** (`cli/main.c:123`) and is the only way to point the
//!   loader lookup at a firmware tree that is not beside the binary.
//!
//! One flag here is **not** the C's: [`Cli::size`]. See the comment beside it.
//!
//! # Repetition is legal, and that is deliberate
//!
//! `thingino-dfu -l -l` must work. Wrapper scripts build argument lists by appending,
//! and an earlier implementation broke them by refusing a repeated flag. The C is
//! last-wins by construction, its parser being a `for` loop of
//! `strcmp`s that assigns on every match (`cli/main.c:87-186`), and `overrides_with`
//! (for the switches) plus [`ArgAction::Set`] (for the value flags) is how `clap` spells
//! the same thing. Pinned by
//! [`fe_cli_repeated_flags_are_last_wins`](tests::fe_cli_repeated_flags_are_last_wins).

use std::path::PathBuf;

use clap::{ArgAction, Parser};
use tdfu_core::model::{AltSel, MAX_ALTS, Variant};

use crate::plan::{Action, BootstrapTrigger, Images, Plan, PlanError, Remote, Target};

/// The default remote port, from the one place that defines it.
///
/// `tdfu_proto::DEFAULT_PORT` is 5050, which is the C's `TDFU_DEFAULT_PORT`
/// (`protocol.h`) and what `cli/main.c:337` falls back to. Importing it rather than
/// writing `5050` here is what stops the client and the wire disagreeing.
const DEFAULT_PORT: u16 = tdfu_proto::DEFAULT_PORT;

/// `thingino-dfu` — flash Ingenic XBurst devices over USB using DFU.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "thingino-dfu",
    version,
    // `-V`/`--version` on stdout, alongside the banner's version on stderr: a script
    // that wants the version should not have to parse stderr, and the C offers no
    // spelling of its own to conflict with (`cli/main.c:87-186`).
    disable_version_flag = false,
    about = "Flash Ingenic XBurst devices over USB using DFU",
    long_about = "Flash Ingenic XBurst devices over USB using DFU.\n\n\
                  Operations run in a fixed order whatever order they are typed in: \
                  bootstrap, erase, write, verify, read, reboot."
)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the bools ARE the surface: -l -b --verify --erase --reboot --diag --wait -d are eight \
              independent switches the C accepts (`cli/main.c:87-186`), and functional parity \
              fixes both their number and their independence. Folding them into \
              state enums would invent combinations the C has no spelling for. The state machine the \
              lint asks for exists — it is `Plan` — and this type is only its argument surface"
)]
pub struct Cli {
    /// List every Ingenic device on the bus.
    #[arg(short = 'l', long = "list", action = ArgAction::SetTrue, overrides_with = "list")]
    pub list: bool,

    /// Bootstrap a bootrom device into U-Boot DFU mode.
    #[arg(short = 'b', long = "bootstrap", action = ArgAction::SetTrue, overrides_with = "bootstrap")]
    pub bootstrap: bool,

    /// Write this image to the device (bootstrapping first if needed).
    #[arg(short = 'w', long = "write", value_name = "FILE", action = ArgAction::Set, overrides_with = "write")]
    pub write: Option<PathBuf>,

    /// Read the device's flash into this file.
    #[arg(short = 'r', long = "read", value_name = "FILE", action = ArgAction::Set, overrides_with = "read")]
    pub read: Option<PathBuf>,

    /// After `-w`, read the flash back and compare.
    #[arg(long = "verify", action = ArgAction::SetTrue, overrides_with = "verify")]
    pub verify: bool,

    /// Erase the whole flash (on its own, or before `-w`).
    #[arg(long = "erase", action = ArgAction::SetTrue, overrides_with = "erase")]
    pub erase: bool,

    /// Reboot the SoC when everything else is done.
    #[arg(long = "reboot", action = ArgAction::SetTrue, overrides_with = "reboot")]
    pub reboot: bool,

    /// Dump eFuse / serial / secure-boot state from a bootrom device (read-only).
    #[arg(long = "diag", action = ArgAction::SetTrue, overrides_with = "diag")]
    pub diag: bool,

    /// Which device to operate on, as numbered by `-l`.
    #[arg(
        short = 'i',
        long = "index",
        value_name = "NUM",
        default_value_t = 0,
        value_parser = parse_index,
        // `-i -1` must reach `parse_index` and be told what the range is, rather than
        // being refused by `clap` as an unexpected argument. The C refuses a negative
        // index by name too (`cli/main.c:173-176`).
        allow_negative_numbers = true,
        action = ArgAction::Set,
        overrides_with = "index"
    )]
    pub index: u8,

    /// DFU alt-setting to target, by name or decimal number.
    #[arg(long = "alt", value_name = "NAME|NUM", value_parser = parse_alt, action = ArgAction::Set, overrides_with = "alt")]
    pub alt: Option<AltSel>,

    /// Force the SoC variant instead of detecting it.
    #[arg(long = "cpu", value_name = "VARIANT", value_parser = parse_cpu, action = ArgAction::Set, overrides_with = "cpu")]
    pub cpu: Option<Variant>,

    /// Custom stage-1 image, in place of the one in the firmware tree.
    #[arg(long = "spl", value_name = "FILE", action = ArgAction::Set, overrides_with = "spl")]
    pub spl: Option<PathBuf>,

    /// Custom U-Boot image, in place of the one in the firmware tree.
    #[arg(long = "uboot", value_name = "FILE", action = ArgAction::Set, overrides_with = "uboot")]
    pub uboot: Option<PathBuf>,

    /// Firmware root holding `dfu/<variant>/` (default: `firmware/` beside the binary).
    #[arg(long = "firmware-dir", value_name = "DIR", action = ArgAction::Set, overrides_with = "firmware_dir")]
    pub firmware_dir: Option<PathBuf>,

    /// Stop a `-r` after this many bytes, instead of reading the whole alt.
    //
    // A `//` comment and not a doc comment: clap prints doc comments as `--help` text,
    // and the rest of this is not the operator's business.
    //
    // The flag is an addition rather than a shared spelling: the older C CLI has no
    // `--size` and always asks the upload for the whole alt. The capability underneath is
    // not new, since the size argument is on the upload itself and `ops::read` carries it
    // as `limit: Option<u64>`, so this adds a way to reach it rather than changing what
    // any existing flag does, and it is what makes a 256 MiB NAND alt samplable without
    // reading the whole chip.
    #[arg(long = "size", value_name = "BYTES", value_parser = parse_size, allow_negative_numbers = true, action = ArgAction::Set, overrides_with = "size")]
    pub size: Option<u64>,

    /// Operate through a `dfu-remote` daemon at this address.
    #[arg(long = "host", value_name = "ADDR", action = ArgAction::Set, overrides_with = "host")]
    pub host: Option<String>,

    /// Port of the remote daemon (default 5050).
    //
    // `Option<u16>` rather than a defaulted `u16`, so that "not given" survives to
    // `Cli::remote`: with a default baked in, `self.port != DEFAULT_PORT` was the only
    // test available and it cannot tell `--port 5050` from no `--port` at all, so
    // `thingino-dfu -l --port 5051` was refused while `--port 5050` was accepted and
    // ignored, which is the Type-2 shape that rule exists to prevent. `--token` beside it
    // uses `is_some()` and never had the hole. A `//` comment and not a doc comment:
    // clap prints doc comments as `--help` text, and this is not the operator's business.
    #[arg(
        long = "port",
        value_name = "PORT",
        value_parser = parse_port,
        allow_negative_numbers = true,
        action = ArgAction::Set,
        overrides_with = "port"
    )]
    pub port: Option<u16>,

    /// Auth token for the remote daemon.
    #[arg(long = "token", value_name = "SECRET", action = ArgAction::Set, overrides_with = "token")]
    pub token: Option<String>,

    /// Wait for an Ingenic device to appear before starting.
    #[arg(long = "wait", action = ArgAction::SetTrue, overrides_with = "wait")]
    pub wait: bool,

    /// Verbose diagnostics on stderr.
    #[arg(short = 'd', long = "debug", action = ArgAction::SetTrue, overrides_with = "debug")]
    pub debug: bool,
}

/// `-i`: a device index that can never wrap.
///
/// The C parses it with `atoi` and refuses negatives (`cli/main.c:168-176`), then its
/// remote path casts the result to `uint8_t`, so `-i 256` silently targets **device
/// 0** and flashes the wrong camera. The wire's `device_idx` is
/// one byte, so 0–255 is the honest range and anything above it is refused by name
/// rather than folded into it.
fn parse_index(raw: &str) -> Result<u8, String> {
    raw.parse::<u8>().map_err(|_| {
        format!(
            "device index must be 0-{}, got `{raw}` (the number `-l` shows)",
            u8::MAX
        )
    })
}

/// `--alt`: a name or a decimal number, both bounded.
///
/// A string of decimal digits is an alt **number**; anything else is a **name**. The C
/// resolves the other way round — `tdfu_dfu_find_alt` matches the name first and only
/// then falls back to `strtol` (`dfu.c:510-525`) — which matters only for a loader that
/// named an alt in digits, and none does (`flash`, `erase`, `reboot`, `sdcard` are the
/// shipped names). The order is stated here rather than left to be discovered.
///
/// Both forms are bounded, which the C's are not:
///
/// * a number must fit the 32 alts the parser accepts, so `--alt 200` is refused instead
///   of being carried to a device that has no such alt;
/// * a name must fit the wire's one-byte length field. `remote_read_firmware` builds its
///   payload in a fixed stack buffer and `memcpy`s the name into it with no bound
///   (`uint8_t payload[3 + 64]` at `cli/remote.c:737`, the unbounded `memcpy` at `:742`),
///   which is a stack smash the bound here avoids. [citation corrected 2026-09-03]
fn parse_alt(raw: &str) -> Result<AltSel, String> {
    if !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        let index: u8 = raw
            .parse()
            .map_err(|_| format!("alt number must be 0-{}, got `{raw}`", MAX_ALTS - 1))?;
        if usize::from(index) >= MAX_ALTS {
            return Err(format!(
                "alt number must be 0-{}, got `{raw}` (parses at most {MAX_ALTS} alts)",
                MAX_ALTS - 1
            ));
        }
        return Ok(AltSel::Index(index));
    }
    if raw.is_empty() {
        return Err("alt name is empty; pass a name or a number, or use -l to list them".to_owned());
    }
    if raw.len() > usize::from(u8::MAX) {
        return Err(format!(
            "alt name is {} bytes; the wire's length field is one byte, so {} is the maximum",
            raw.len(),
            u8::MAX
        ));
    }
    Ok(AltSel::Name(raw.to_owned()))
}

/// `--cpu`: resolved to a [`Variant`] at parse time, so a typo costs nothing.
///
/// Resolution is [`Variant::from_cpu_arg`], which accepts all 34 loader directory names
/// and the C's family aliases (`utils.c`, `dfu.c:1084-1123`). Doing it here rather than
/// at bootstrap time is the point: the C resolves it inside `tdfu_dfu_bootstrap`, after
/// it has opened and **claimed** the device (`dfu.c:1186, 1197`), so an unrecognised
/// spelling costs a claim before it is reported.
fn parse_cpu(raw: &str) -> Result<Variant, String> {
    Variant::from_cpu_arg(raw).ok_or_else(|| {
        let mut known: Vec<&str> = Variant::ALL.iter().map(|variant| variant.loader_dir()).collect();
        known.sort_unstable();
        format!(
            "unknown SoC variant `{raw}`; accepted: {} (bare family names such as t31 and t40 work too)",
            known.join(", ")
        )
    })
}

/// `--size`: a byte cap on `-r`, never zero.
///
/// Zero would mean "read nothing", which is never what was meant; in the C's upload it
/// means the opposite — "no limit" (`dfu.c:797`) — so accepting it here would be the one
/// value guaranteed to be misread. Absent is how "no limit" is spelled.
fn parse_size(raw: &str) -> Result<u64, String> {
    let size: u64 = raw
        .parse()
        .map_err(|_| format!("--size takes a number of bytes, got `{raw}`"))?;
    if size == 0 {
        return Err("--size 0 would read nothing; leave it out to read the whole alt".to_owned());
    }
    Ok(size)
}

/// `--port`: a real port, never zero.
///
/// The C uses `atoi`, so its daemon turned `-p abc` into port 0 and bound an ephemeral
/// port while printing `listening on port 0`, and `-p 70000` silently became 4464.
/// Both are refused here by parsing rather than coercing.
fn parse_port(raw: &str) -> Result<u16, String> {
    let port: u16 = raw
        .parse()
        .map_err(|_| format!("--port takes a number in 1-{}, got `{raw}`", u16::MAX))?;
    if port == 0 {
        return Err("--port 0 asks the OS to choose; name the daemon's port".to_owned());
    }
    Ok(port)
}

impl Cli {
    /// Turn the flags into the ordered [`Plan`] the run will follow.
    ///
    /// This is where every combination rule lives, and every one of them either does
    /// something or says why not. **Nothing is accepted and then ignored**, the shape
    /// that let `-l -w fw.bin` print a device list and exit 0 without writing.
    ///
    /// # Errors
    /// [`PlanError`], one variant per rule. See each variant's message.
    pub fn into_plan(self) -> Result<Plan, PlanError> {
        let remote = self.remote()?;
        let actions = self.actions()?;
        let images = self.images()?;

        let target = Target {
            index: self.index,
            alt: self.alt.unwrap_or(AltSel::Default),
            cpu: self.cpu,
            size: self.size,
        };
        Plan::new(actions, target, images, remote, self.wait, self.debug)
    }

    /// `--host`/`--port`/`--token`, and the rule that they go together.
    fn remote(&self) -> Result<Option<Remote>, PlanError> {
        let Some(host) = self.host.clone() else {
            // Silently ignoring a `--port` that cannot do anything is the worst shape a
            // defect can take: an omission leaves nothing to grep for, and the
            // user believes they configured something. The C ignores both
            // (`cli/main.c:341` gates everything on `remote_host`).
            //
            // `is_some()`, not a comparison against the default: `--port 5050` is a
            // `--port` that was given, and refusing it is the whole rule.
            if self.port.is_some() {
                return Err(PlanError::RemoteOptionWithoutHost { option: "--port" });
            }
            if self.token.is_some() {
                return Err(PlanError::RemoteOptionWithoutHost { option: "--token" });
            }
            return Ok(None);
        };
        // `--firmware-dir` is a path on *this* machine and the bootstrap happens on the
        // daemon's. The C takes it and discards it (`cli/remote.c:533`), so the loaders
        // that get uploaded are whichever tree the daemon was started with — a wrong
        // loader chosen silently, which is the one class of mistake `--cpu`'s whole
        // careful surface exists to avoid.
        if self.firmware_dir.is_some() {
            return Err(PlanError::RemoteOptionIsLocal {
                option: "--firmware-dir",
            });
        }
        Ok(Some(Remote {
            host,
            // The default is resolved here rather than by clap, so that "given" is still
            // knowable above.
            port: self.port.unwrap_or(DEFAULT_PORT),
            token: self.token.clone(),
        }))
    }

    /// The operations, unordered: [`Plan::new`] puts them in the fixed order.
    fn actions(&self) -> Result<Vec<Action>, PlanError> {
        let mut actions = Vec::new();
        if self.list {
            actions.push(Action::List);
        }
        if self.diag {
            actions.push(Action::Diag);
        }
        if self.erase {
            actions.push(Action::Erase);
        }
        if self.write.is_some() {
            actions.push(Action::Write);
            if self.verify {
                actions.push(Action::Verify);
            }
        } else if self.verify {
            return Err(PlanError::VerifyWithoutWrite);
        }
        if self.read.is_some() {
            actions.push(Action::Read);
        } else if self.size.is_some() {
            return Err(PlanError::SizeWithoutRead);
        }
        if self.reboot {
            actions.push(Action::Reboot);
        }

        self.push_bootstrap(&mut actions);
        self.check_alt(&actions)?;
        self.check_bootstrap_options(&actions)?;
        self.check_diag(&actions)?;
        Ok(actions)
    }

    /// Everything that only configures a bootstrap needs there to be one.
    ///
    /// `thingino-dfu -l --cpu t31x` is accepted by the C and does nothing with the
    /// `--cpu`: the flag is read into `options.force_cpu` and the `-l` branch returns
    /// before anything consults it (`cli/main.c:475-495`). Same for `--spl` + `--uboot`,
    /// which the C's implied-bootstrap rule explicitly skips when `-l` is present
    /// (`cli/main.c:330-334`), and for `--firmware-dir`. Each is a setting the user
    /// believes they applied.
    fn check_bootstrap_options(&self, actions: &[Action]) -> Result<(), PlanError> {
        if actions.iter().any(|action| matches!(action, Action::Bootstrap(_))) {
            return Ok(());
        }
        let given = [
            ("--cpu", self.cpu.is_some()),
            ("--spl", self.spl.is_some()),
            ("--uboot", self.uboot.is_some()),
            ("--firmware-dir", self.firmware_dir.is_some()),
        ];
        match given.into_iter().find(|&(_, present)| present) {
            Some((option, _)) => Err(PlanError::BootstrapOptionWithoutBootstrap { option }),
            None => Ok(()),
        }
    }

    /// `-b`, and the two implicit forms of it.
    fn push_bootstrap(&self, actions: &mut Vec<Action>) {
        if self.bootstrap {
            actions.push(Action::Bootstrap(BootstrapTrigger::Requested));
            return;
        }
        // A custom `--spl` + `--uboot` pair with no action means "USB-boot these", which
        // is the only thing a pair of boot blobs on its own can mean — the
        // `t31-usbboot.py` ergonomics the C kept (`cli/main.c:330-334`).
        if actions.is_empty() && self.spl.is_some() && self.uboot.is_some() {
            actions.push(Action::Bootstrap(BootstrapTrigger::Requested));
            return;
        }
        // Every transfer auto-bootstraps a bootrom target, so
        // `thingino-dfu -w img` works in one shot (`cli/main.c:491-511`).
        if actions.iter().any(Action::needs_the_gadget) {
            actions.push(Action::Bootstrap(BootstrapTrigger::Auto));
        }
    }

    /// `--alt` selects the alt a transfer targets, and nothing else has an alt.
    fn check_alt(&self, actions: &[Action]) -> Result<(), PlanError> {
        if self.alt.is_some() && !actions.iter().any(Action::takes_an_alt) {
            return Err(PlanError::AltWithoutTransfer);
        }
        Ok(())
    }

    /// `--diag` is standalone.
    ///
    /// The C makes it standalone by *returning* — `if (options.diag) { …; return 0; }`
    /// at `cli/main.c:446-457`, before bootstrap and before every transfer — so
    /// `thingino-dfu --diag -w fw.bin` printed an eFuse dump, exited **0**, and wrote
    /// nothing. That is bug 13 with a different flag, and the answer is the same one:
    /// say so instead of picking silently.
    ///
    /// `-l` is the exception, because it is the other read-only report and the two
    /// compose: both want a bootrom, neither changes anything.
    fn check_diag(&self, actions: &[Action]) -> Result<(), PlanError> {
        if !self.diag {
            return Ok(());
        }
        if let Some(other) = actions
            .iter()
            .find(|action| !matches!(action, Action::Diag | Action::List))
        {
            return Err(PlanError::DiagIsStandalone {
                with: other.to_string(),
            });
        }
        Ok(())
    }

    /// `--spl`, `--uboot`, `--firmware-dir` and the images a transfer needs.
    fn images(&self) -> Result<Images, PlanError> {
        // The C treats the override as present only when **both** are non-empty
        // (`dfu.c:1173`); given one, it silently ignores it and looks the pair up in the
        // firmware tree anyway. A user who passed `--spl` and got the tree's SPL has
        // been told nothing at all.
        match (&self.spl, &self.uboot) {
            (Some(_), None) => {
                return Err(PlanError::LoaderPairIncomplete {
                    given: "--spl",
                    missing: "--uboot",
                });
            }
            (None, Some(_)) => {
                return Err(PlanError::LoaderPairIncomplete {
                    given: "--uboot",
                    missing: "--spl",
                });
            }
            _ => {}
        }
        Ok(Images {
            write: self.write.clone(),
            read: self.read.clone(),
            spl: self.spl.clone(),
            uboot: self.uboot.clone(),
            firmware_dir: self.firmware_dir.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, DEFAULT_PORT, Parser as _};
    use crate::plan::{Action, BootstrapTrigger, PlanError};
    use clap::CommandFactory as _;
    use tdfu_core::model::{AltSel, MAX_ALTS, Variant};

    /// Parse an argument list the way the binary will, minus the process.
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(core::iter::once("thingino-dfu").chain(args.iter().copied()))
    }

    /// The message `clap` would print for a refused argument list.
    fn refusal(args: &[&str]) -> String {
        parse(args).err().map(|error| error.to_string()).unwrap_or_default()
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn list_alone_is_a_plan() -> TestResult {
        let plan = parse(&["-l"])?.into_plan()?;
        assert_eq!(plan.actions, vec![Action::List]);
        assert!(!plan.wait);
        assert!(!plan.debug);
        Ok(())
    }

    #[test]
    fn the_long_spelling_is_the_same_plan() -> TestResult {
        assert_eq!(parse(&["-l"])?.into_plan()?, parse(&["--list"])?.into_plan()?);
        Ok(())
    }

    #[test]
    fn wait_and_debug_ride_along() -> TestResult {
        let plan = parse(&["-l", "--wait", "--debug"])?.into_plan()?;
        assert!(plan.wait);
        assert!(plan.debug);

        // The C's short spelling for debug, `cli/main.c:93`.
        assert!(parse(&["-l", "-d"])?.into_plan()?.debug);
        Ok(())
    }

    /// **Every spelling the C accepts, accepted here.**
    ///
    /// The list is transcribed from the C's `strcmp` chain (`cli/main.c:87-186`), which
    /// is its parser, and each entry is parsed on its own so a missing declaration
    /// fails by name rather than being masked by a neighbour. This is the functional
    /// parity check for the flag surface: a flag a user could type at
    /// the shipped tool and cannot type here is a bug.
    #[test]
    fn fe_cli_every_c_spelling_parses() {
        // Switches, and the value flags with a value that parses.
        let surface: &[&[&str]] = &[
            &["-d"],
            &["--debug"],
            &["-l"],
            &["--list"],
            &["-b"],
            &["--bootstrap"],
            &["-i", "3"],
            &["--index", "3"],
            &["-r", "out.bin"],
            &["--read", "out.bin"],
            &["-w", "in.bin"],
            &["--write", "in.bin"],
            &["--diag"],
            &["--cpu", "t31x"],
            &["--spl", "spl.bin"],
            &["--uboot", "uboot.bin"],
            &["--firmware-dir", "/tmp/fw"],
            &["--host", "camera.invalid"],
            &["--port", "5051"],
            &["--token", "s3cret"],
            &["--alt", "flash"],
            &["--verify"],
            &["--erase"],
            &["--reboot"],
            &["--wait"],
        ];
        for args in surface {
            assert!(parse(args).is_ok(), "the C accepts {args:?}: {}", refusal(args));
        }

        // `-h`/`--help` are `clap`'s early exit, not a parse into `Cli`.
        for help in ["-h", "--help"] {
            assert_eq!(
                parse(&[help]).err().map(|error| error.kind()),
                Some(clap::error::ErrorKind::DisplayHelp)
            );
        }
    }

    /// A value flag with no value is refused, as the C refuses it.
    ///
    /// `cli/main.c:99-102` and its fourteen siblings all check `i + 1 >= argc` and
    /// return `TDFU_ERROR_INVALID_PARAMETER`. The failure mode this rules out is a flag
    /// that swallows the *next flag* as its value.
    #[test]
    fn a_value_flag_without_a_value_is_refused() {
        for flag in [
            "-w",
            "-r",
            "--spl",
            "--uboot",
            "--firmware-dir",
            "--alt",
            "--host",
            "--port",
            "--token",
            "--cpu",
            "-i",
            "--size",
        ] {
            let rendered = refusal(&[flag]);
            assert!(
                rendered.contains(flag),
                "{flag} must be refused by name; got {rendered:?}"
            );
        }
    }

    /// A wrapper that appends `-l` twice must not be told off for it.
    ///
    /// This is the pin for the attempt-one regression: repetition was refused, which
    /// broke callers that build argument lists by concatenation. The C assigns on every
    /// match (`cli/main.c:96-98`), so repeating a flag is a no-op there — and a
    /// *repeated value* takes the last one, which is what `ArgAction::Set` does.
    #[test]
    fn fe_cli_repeated_flags_are_last_wins() -> TestResult {
        let once = parse(&["-l", "--wait", "--debug"])?.into_plan()?;
        let thrice = parse(&["-l", "-l", "-l", "--wait", "--wait", "--debug", "--debug"])?.into_plan()?;
        assert_eq!(once, thrice);

        // Interleaved, and with the long and short spellings mixed - still one plan.
        let mixed = parse(&["--list", "-d", "-l", "--debug", "--wait", "--wait"])?.into_plan()?;
        assert_eq!(mixed, once);

        // A repeated value flag keeps the LAST value, exactly as the C's assignment
        // loop does.
        let cli = parse(&["-w", "first.bin", "-w", "second.bin", "-i", "1", "-i", "2"])?;
        assert_eq!(cli.write, Some(std::path::PathBuf::from("second.bin")));
        assert_eq!(cli.index, 2);
        assert_eq!(parse(&["--cpu", "t20", "--cpu", "t31x"])?.cpu, Some(Variant::T31x));
        Ok(())
    }

    #[test]
    fn no_action_is_refused_with_something_to_do_about_it() -> TestResult {
        assert_eq!(parse(&[])?.into_plan(), Err(PlanError::NoAction));
        // `--wait` on its own is not an action either: waiting for a device and then
        // doing nothing to it is never what was meant.
        assert_eq!(parse(&["--wait"])?.into_plan(), Err(PlanError::NoAction));
        assert_eq!(parse(&["--debug"])?.into_plan(), Err(PlanError::NoAction));
        // Nor is naming a device without saying what to do to it.
        assert_eq!(parse(&["-i", "2"])?.into_plan(), Err(PlanError::NoAction));
        Ok(())
    }

    /// A flag this build does not know is refused **by name**, not ignored.
    ///
    /// The C's own daemon ignored unknown arguments in silence, which an audit recorded
    /// as a bug. The C CLI does refuse them
    /// (`cli/main.c:181-185`), and so does this.
    #[test]
    fn an_unknown_flag_is_refused_by_name() {
        for arg in ["--devise", "--flash", "--no-verify", "-z"] {
            let rendered = refusal(&[arg]);
            assert!(
                rendered.contains(arg),
                "{arg} must be refused by name; got {rendered:?}"
            );
        }
    }

    /// `-i 256` is refused, never wrapped to device 0.
    ///
    /// The C's remote path casts to `uint8_t`, so `-i 256` flashes device **0**.
    /// A tool that silently retargets a flash is the one thing this must never do.
    #[test]
    fn fe_cli_an_index_that_would_wrap_is_refused() -> TestResult {
        assert_eq!(parse(&["-l", "-i", "255"])?.index, 255);
        for wrapping in ["256", "512", "-1", "4294967296", "abc"] {
            let rendered = refusal(&["-l", "-i", wrapping]);
            assert!(
                rendered.contains("device index must be 0-255"),
                "-i {wrapping} must be refused: {rendered:?}"
            );
        }
        Ok(())
    }

    /// `--alt` is bounded in both of its forms.
    #[test]
    fn fe_cli_alt_is_bounded_by_name_and_by_number() -> TestResult {
        assert_eq!(
            parse(&["-w", "f.bin", "--alt", "flash"])?.alt,
            Some(AltSel::Name("flash".into()))
        );
        assert_eq!(parse(&["-w", "f.bin", "--alt", "0"])?.alt, Some(AltSel::Index(0)));
        assert_eq!(parse(&["-w", "f.bin", "--alt", "31"])?.alt, Some(AltSel::Index(31)));

        // One past the parser's table.
        let too_high = refusal(&["-w", "f.bin", "--alt", &MAX_ALTS.to_string()]);
        assert!(too_high.contains("alt number must be 0-31"), "{too_high:?}");
        // Past a byte, so `atoi`-style truncation would have wrapped it.
        let wrapping = refusal(&["-w", "f.bin", "--alt", "256"]);
        assert!(wrapping.contains("alt number must be 0-31"), "{wrapping:?}");

        // A name the C's fixed stack buffer would have overrun: `payload[3 + 64]` at
        // `cli/remote.c:737`, `memcpy`d into at `:742`. [citation corrected 2026-09-03]
        let long = "x".repeat(usize::from(u8::MAX) + 1);
        let smash = refusal(&["-w", "f.bin", "--alt", &long]);
        assert!(smash.contains("one byte"), "{smash:?}");
        // And the longest name that does fit is accepted.
        let longest = "x".repeat(usize::from(u8::MAX));
        assert!(parse(&["-w", "f.bin", "--alt", &longest]).is_ok());
        Ok(())
    }

    /// `--cpu` resolves at parse time, and an unknown spelling names the alternatives.
    #[test]
    fn fe_cli_cpu_resolves_before_anything_is_opened() -> TestResult {
        assert_eq!(parse(&["-b", "--cpu", "t31x"])?.cpu, Some(Variant::T31x));
        // Case-insensitive and alias-aware, both from `Variant::from_cpu_arg`.
        assert_eq!(parse(&["-b", "--cpu", "T31X"])?.cpu, Some(Variant::T31x));
        assert_eq!(parse(&["-b", "--cpu", "t31"])?.cpu, Some(Variant::T31n));

        let rendered = refusal(&["-b", "--cpu", "t99"]);
        assert!(rendered.contains("unknown SoC variant `t99`"), "{rendered:?}");
        assert!(
            rendered.contains("t31x"),
            "the refusal must list what is accepted: {rendered:?}"
        );
        Ok(())
    }

    /// `--port` and `--size` refuse the values the C's `atoi` would have coerced.
    #[test]
    fn a_number_that_cannot_mean_what_was_typed_is_refused() -> TestResult {
        assert_eq!(parse(&["-l"])?.port, None, "no --port is no --port, not 5050");
        assert_eq!(parse(&["--host", "h", "--port", "5051"])?.port, Some(5051));
        for bad in ["abc", "0", "70000"] {
            let rendered = refusal(&["--host", "h", "--port", bad]);
            assert!(rendered.contains("--port"), "--port {bad}: {rendered:?}");
        }
        for bad in ["abc", "0"] {
            let rendered = refusal(&["-r", "out.bin", "--size", bad]);
            assert!(rendered.contains("--size"), "--size {bad}: {rendered:?}");
        }
        assert_eq!(parse(&["-r", "out.bin", "--size", "1048576"])?.size, Some(1_048_576));
        Ok(())
    }

    /// `clap`'s own wiring, asserted once so a derive typo cannot ship.
    #[test]
    fn the_command_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// **`--help` is the operator's, not the implementation's.**
    ///
    /// clap renders a field's doc comment as its long help, so a note written for the
    /// next person to read the source is printed on a terminal instead: markdown
    /// emphasis, and paths into a tree the operator does not have. `-h` shows only the
    /// first line, so nothing catches it there. Every flag's rationale belongs in a `//`
    /// comment beside it, which is the choice `--port` and `--size` both make.
    #[test]
    fn fe_cli_help_carries_no_source_rationale() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("Stop a `-r` after this many bytes"),
            "--size must still say what it does: {help}"
        );
        for internal in ["cli/main.c", "dfu.c:", "ops::read", "**"] {
            assert!(!help.contains(internal), "{internal:?} reached --help:\n{help}");
        }
    }

    /// `-h` and `--version` are `clap`'s own early exits, and both are successes.
    #[test]
    fn help_and_version_are_clean_exits() {
        for (arg, kind) in [
            ("--help", clap::error::ErrorKind::DisplayHelp),
            ("-h", clap::error::ErrorKind::DisplayHelp),
            ("--version", clap::error::ErrorKind::DisplayVersion),
        ] {
            assert_eq!(parse(&[arg]).err().map(|error| error.kind()), Some(kind), "for {arg}");
        }
    }

    /// Flags that cannot do anything on their own say so.
    #[test]
    fn a_modifier_without_its_operation_is_refused() -> TestResult {
        assert_eq!(parse(&["--verify"])?.into_plan(), Err(PlanError::VerifyWithoutWrite));
        assert_eq!(
            parse(&["-r", "out.bin", "--verify"])?.into_plan(),
            Err(PlanError::VerifyWithoutWrite)
        );
        assert_eq!(parse(&["--size", "16"])?.into_plan(), Err(PlanError::SizeWithoutRead));
        assert_eq!(
            parse(&["-l", "--alt", "flash"])?.into_plan(),
            Err(PlanError::AltWithoutTransfer)
        );
        assert_eq!(
            parse(&["--erase", "--alt", "flash"])?.into_plan(),
            Err(PlanError::AltWithoutTransfer),
            "erase targets the loader's own virt alt, not a named one"
        );
        Ok(())
    }

    /// A loader option with nothing to bootstrap is refused, not quietly dropped.
    #[test]
    fn a_bootstrap_option_without_a_bootstrap_is_refused() -> TestResult {
        for (args, option) in [
            (vec!["-l", "--cpu", "t31x"], "--cpu"),
            (vec!["-l", "--spl", "s.bin", "--uboot", "u.bin"], "--spl"),
            (vec!["-l", "--firmware-dir", "/tmp/fw"], "--firmware-dir"),
            (vec!["--diag", "--cpu", "t31x"], "--cpu"),
        ] {
            assert_eq!(
                parse(&args)?.into_plan(),
                Err(PlanError::BootstrapOptionWithoutBootstrap { option }),
                "for {args:?}"
            );
        }

        // With something that bootstraps, each is accepted.
        assert!(parse(&["-b", "--cpu", "t31x"])?.into_plan().is_ok());
        assert!(parse(&["-w", "f.bin", "--cpu", "t31x"])?.into_plan().is_ok());
        assert!(
            parse(&["--erase", "--firmware-dir", "/tmp/fw"])?.into_plan().is_ok(),
            "an auto-bootstrap is a bootstrap"
        );
        Ok(())
    }

    /// `--port`/`--token` with no `--host` are refused rather than quietly dropped.
    #[test]
    fn a_remote_option_without_a_host_is_refused() -> TestResult {
        assert_eq!(
            parse(&["-l", "--port", "5051"])?.into_plan(),
            Err(PlanError::RemoteOptionWithoutHost { option: "--port" })
        );
        assert_eq!(
            parse(&["-l", "--token", "s"])?.into_plan(),
            Err(PlanError::RemoteOptionWithoutHost { option: "--token" })
        );
        // `--port 5050` is a `--port` that was given, and the rule is about
        // being given, not about the value: accepting it because it happens to equal the
        // default was the one hole in a check whose whole purpose is that nothing is
        // accepted and then ignored.
        assert_eq!(
            parse(&["-l", "--port", &DEFAULT_PORT.to_string()])?.into_plan(),
            Err(PlanError::RemoteOptionWithoutHost { option: "--port" })
        );
        // With no `--port` at all there is nothing to refuse.
        assert!(parse(&["-l"])?.into_plan().is_ok());
        // And with a host, an absent `--port` still means the default.
        assert_eq!(
            parse(&["-l", "--host", "cam"])?.into_plan()?.remote.map(|r| r.port),
            Some(DEFAULT_PORT)
        );
        Ok(())
    }

    /// `--firmware-dir` names a tree on **this** machine, so it cannot mean anything with
    /// `--host` — and being ignored is how a daemon's own loaders get uploaded while the
    /// operator believes they chose the ones in that directory.
    #[test]
    fn a_local_only_option_is_refused_with_a_host() -> TestResult {
        assert_eq!(
            parse(&["-b", "--host", "cam", "--firmware-dir", "/opt/fw"])?.into_plan(),
            Err(PlanError::RemoteOptionIsLocal {
                option: "--firmware-dir"
            })
        );
        // Without `--host` it is exactly as useful as it was.
        assert!(parse(&["-b", "--firmware-dir", "/opt/fw"])?.into_plan().is_ok());
        assert!(
            PlanError::RemoteOptionIsLocal {
                option: "--firmware-dir"
            }
            .to_string()
            .contains("stream the pair you want with --spl and --uboot"),
            "the refusal has to say what to do instead"
        );
        Ok(())
    }

    /// Half a loader pair is refused; the C silently ignores it and uses the tree's.
    #[test]
    fn half_a_loader_pair_is_refused() -> TestResult {
        assert_eq!(
            parse(&["-b", "--spl", "spl.bin"])?.into_plan(),
            Err(PlanError::LoaderPairIncomplete {
                given: "--spl",
                missing: "--uboot"
            })
        );
        assert_eq!(
            parse(&["-b", "--uboot", "u.bin"])?.into_plan(),
            Err(PlanError::LoaderPairIncomplete {
                given: "--uboot",
                missing: "--spl"
            })
        );
        Ok(())
    }

    /// **The auto-bootstrap pin.** Every operation that needs the gadget gets a bootstrap
    /// in front of it, so `thingino-dfu -w img` works against a bootrom in one shot.
    ///
    /// The C's list is `-w`, `-r`, `--erase`, `--reboot` (`cli/main.c:491`); `--verify`
    /// rides on the write's session. `-b` given explicitly is a *requested* bootstrap and
    /// is not duplicated, and an operation that does not need the gadget gets none.
    #[test]
    fn fe_cli_autobootstrap() -> TestResult {
        for args in [
            vec!["-w", "fw.bin"],
            vec!["-r", "out.bin"],
            vec!["--erase"],
            vec!["--reboot"],
            vec!["-w", "fw.bin", "--verify"],
        ] {
            let plan = parse(&args)?.into_plan()?;
            assert!(
                plan.does(&Action::Bootstrap(BootstrapTrigger::Auto)),
                "{args:?} must auto-bootstrap"
            );
            assert_eq!(
                plan.actions.first(),
                Some(&Action::Bootstrap(BootstrapTrigger::Auto)),
                "and it must run first: {args:?}"
            );
        }

        // `-b -w` is one bootstrap, and it is the requested one.
        let explicit = parse(&["-b", "-w", "fw.bin"])?.into_plan()?;
        assert_eq!(
            explicit.actions,
            vec![Action::Bootstrap(BootstrapTrigger::Requested), Action::Write]
        );

        // A report needs no gadget, so it gets no bootstrap.
        assert_eq!(parse(&["-l"])?.into_plan()?.actions, vec![Action::List]);
        assert_eq!(parse(&["--diag"])?.into_plan()?.actions, vec![Action::Diag]);
        Ok(())
    }

    /// A `--spl` + `--uboot` pair with no action means "USB-boot these".
    ///
    /// The C's `t31-usbboot.py` ergonomics, kept (`cli/main.c:330-334`).
    #[test]
    fn fe_cli_a_loader_pair_alone_implies_bootstrap() -> TestResult {
        let plan = parse(&["--spl", "spl.bin", "--uboot", "u.bin"])?.into_plan()?;
        assert_eq!(plan.actions, vec![Action::Bootstrap(BootstrapTrigger::Requested)]);
        Ok(())
    }

    /// `--diag` beside an operation is refused, never silently preferred.
    #[test]
    fn fe_cli_diag_is_standalone() -> TestResult {
        assert_eq!(parse(&["--diag"])?.into_plan()?.actions, vec![Action::Diag]);
        for (args, with) in [
            (vec!["--diag", "-w", "f.bin"], "-w"),
            (vec!["--diag", "-b"], "-b"),
            (vec!["--diag", "--erase"], "--erase"),
            (vec!["--diag", "--reboot"], "--reboot"),
            (vec!["--diag", "-r", "o.bin"], "-r"),
        ] {
            assert_eq!(
                parse(&args)?.into_plan(),
                Err(PlanError::DiagIsStandalone { with: with.to_owned() }),
                "for {args:?}"
            );
        }
        // `-l` is the one thing it composes with: two read-only reports.
        let both = parse(&["-l", "--diag"])?.into_plan()?;
        assert_eq!(both.actions, vec![Action::List, Action::Diag]);
        Ok(())
    }
}
