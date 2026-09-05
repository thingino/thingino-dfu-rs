//! Every remote path, driven end to end against [`FakeDaemon`].
//!
//! These go through [`run::run`](crate::run::run) rather than
//! [`remote::run`](super::run), so each one also covers the dispatch, the shared file
//! preflight and the exit-code mapping — and the backend handed in is one that **fails on
//! any use**, so a remote run that touches the local bus fails loudly instead of passing.

use super::fake::{FakeDaemon, Step, closed_port};
use crate::cli::Cli;
use crate::exit::{DEVICE, FILE, PROTOCOL, TRANSFER};
use crate::fake::{FakeBackend, Scratch, TestResult};
use crate::plan::Plan;
use crate::run::{self, Failure};
use clap::Parser as _;
use tdfu_proto::{Command, DeviceEntry, Status, WireVariant};
use tdfu_usb::mock::block_on;
use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

/// What one run produced.
struct Outcome {
    /// `Ok(())`, or the failure `main` would print and exit on.
    result: Result<(), Failure>,
    /// stdout: the data.
    out: String,
    /// stderr: the narration.
    err: String,
    /// Every duration the run slept for, in order.
    ///
    /// The clock was previously created and dropped inside `drive`, so `--wait`'s poll
    /// interval was observed by nothing and deleting the `sleep` turned the remote wait
    /// into a hot loop hammering the daemon while the test still passed. The local
    /// twin has always asserted it (`wait::tests`).
    slept: Vec<core::time::Duration>,
}

impl Outcome {
    /// The failure, or an error saying the run unexpectedly succeeded.
    fn failure(&self) -> Result<&Failure, String> {
        self.result
            .as_ref()
            .err()
            .ok_or_else(|| format!("the run was expected to fail; stdout {:?}", self.out))
    }

    /// The message `main` would print, and the code it would exit with.
    fn refusal(&self) -> Result<(String, u8), String> {
        let failure = self.failure()?;
        Ok((failure.to_string(), failure.exit_code()))
    }
}

/// Parse a real command line into a plan, with `--host` pointed at `port`.
fn plan_for(port: u16, args: &[&str]) -> Result<Plan, Box<dyn std::error::Error>> {
    let port = port.to_string();
    let mut line = vec!["thingino-dfu", "--host", "127.0.0.1", "--port", &port];
    line.extend_from_slice(args);
    Ok(Cli::try_parse_from(line)?.into_plan()?)
}

/// Run a plan the way `main` does.
///
/// The backend fails on every call: a remote run must not enumerate the local bus, and
/// this turns "it quietly did" into a failed test rather than a passing one.
fn drive(plan: &Plan) -> Outcome {
    drive_on(
        &FakeBackend::failing(UsbError::new(
            UsbErrorKind::Backend("a remote run must not touch the local bus".into()),
            Pipe::Device,
        )),
        plan,
    )
}

/// Run a plan against a bus of the caller's choosing.
///
/// Only `fe_cli_remote_exit_codes_match_the_local_ones` wants this: every other test
/// here is remote and takes [`drive`]'s refusing backend, but a *matched* pair has to
/// run the same refusal locally, which needs devices on the bus.
fn drive_on(backend: &FakeBackend, plan: &Plan) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let clock = PatientClock::default();
    let result = block_on(run::run(backend, &clock, plan, &mut out, &mut err));
    Outcome {
        result,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
        slept: clock.slept.take(),
    }
}

/// A recording clock that gives up instead of spinning for ever.
///
/// `--wait` polls until the daemon can see something and sleeps between polls, and a test
/// clock that returns instantly turns "it never sees anything" into a hot infinite loop.
/// `cargo mutants` then reports a **timeout** rather than a caught mutant, which is a
/// slot burned and nothing learned: `Session::discover -> Ok(&[])` is exactly that
/// mutation, and `fake::PATIENCE` and the daemon's `pump` both record the same trade.
/// The bound turns the hang into a named failure.
///
/// A hundred polls is two orders of magnitude past what any test here needs; the real
/// clock is `BlockingClock` and no bound applies to it.
#[derive(Debug, Default)]
struct PatientClock {
    slept: core::cell::RefCell<Vec<core::time::Duration>>,
}

impl tdfu_core::clock::Sleeper for PatientClock {
    async fn sleep(&self, duration: core::time::Duration) {
        let mut slept = self.slept.borrow_mut();
        assert!(
            slept.len() < 100,
            "a remote wait polled 100 times without progress; this run would never end"
        );
        slept.push(duration);
    }
}

/// A `DISCOVER` payload with one row per `(stage, variant)` pair, in that order.
///
/// The rows are given consecutive addresses, because two devices at one bus address is a
/// bus that cannot exist, and a double describing an impossible bus is the trap that a
/// defect in a test double sets, in miniature.
fn discovered_rows(rows: &[(u8, WireVariant)]) -> Vec<u8> {
    rows.iter()
        .enumerate()
        .flat_map(|(position, &(stage, variant))| {
            DeviceEntry {
                bus: 1,
                address: 7_u8.saturating_add(u8::try_from(position).unwrap_or(u8::MAX)),
                vendor: 0xA108,
                product: 0xC309,
                stage,
                variant,
            }
            .encode()
        })
        .collect()
}

/// A `DISCOVER` payload with one device in it.
fn discovered(stage: u8, variant: WireVariant) -> Vec<u8> {
    discovered_rows(&[(stage, variant)])
}

/// The two-byte `"OK"` payload every command but `REBOOT` answers with.
fn ok() -> Vec<u8> {
    b"OK".to_vec()
}

/// A daemon script that answers `DISCOVER` with the same row `count` times over.
///
/// [`Session::settle`](super::Session) re-asks for as long as a bootrom keeps reporting
/// variant `0xFF`, so a test about that window needs a script as long as the window is.
fn discovered_repeatedly(count: usize, stage: u8, variant: WireVariant) -> Vec<Vec<Step>> {
    vec![vec![Step::Ok(discovered(stage, variant))]; count]
}

/// How many `POLL_INTERVAL`s the settle window is, as a `usize` for the scripts.
fn settle_polls() -> Result<usize, core::num::TryFromIntError> {
    usize::try_from(super::SETTLE_POLLS)
}

// ---------------------------------------------------------------------------
// The flow.
// ---------------------------------------------------------------------------

/// **The flow pin.** Every operation, in the fixed order, over one
/// connection.
///
/// The C cannot do this: its remote mode is a chain of mutually exclusive branches
/// (`cli/main.c:372-415`), so `-w` there is a fixed shape and `-l -w` runs the list and
/// returns. Here the plan is the plan, and this asserts the exact commands it produces.
#[test]
fn rpc_cli_remote_flow_runs_the_whole_plan_in_order() -> TestResult {
    let scratch = Scratch::new("remote-flow")?;
    let image = scratch.write("fw.bin", b"firmware")?;
    let dump = scratch.path("dump.bin");

    let daemon = FakeDaemon::start(
        false,
        vec![
            // The bootstrap's DISCOVER: a bootrom, so it is USB-booted first.
            vec![Step::Ok(discovered(0, WireVariant(6)))],
            vec![Step::Ok(ok())],                         // BOOTSTRAP
            vec![Step::Ok(ok())],                         // WRITE, the wipe token
            vec![Step::Ok(ok())],                         // WRITE, the image
            vec![Step::Ok(vec![0x00, 0x00, 0x00, 0x00])], // READ: no data, CRC of nothing
            vec![Step::Ok(Vec::new())],                   // REBOOT: empty OK
        ],
    )?;

    let plan = plan_for(
        daemon.port(),
        &[
            "--reboot",
            "-r",
            &dump.display().to_string(),
            "-w",
            &image.display().to_string(),
            "--verify",
            "--erase",
        ],
    )?;
    let outcome = drive(&plan);
    // `transcript_raw` and an explicit check, because this test's subject *is* the whole
    // conversation: it names what the fake could not do rather than only that it could
    // not. Everywhere else `transcript()` makes the same check for free.
    let transcript = daemon.transcript_raw()?;

    assert!(transcript.trouble.is_empty(), "{:?}", transcript.trouble);
    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    let commands: Vec<u8> = transcript.requests.iter().map(|(command, _)| *command).collect();
    assert_eq!(
        commands,
        vec![
            Command::Discover.wire_byte(),
            Command::Bootstrap.wire_byte(),
            Command::Write.wire_byte(), // --erase
            Command::Write.wire_byte(), // -w, with --verify's trailing byte
            Command::Read.wire_byte(),
            Command::Reboot.wire_byte(),
        ],
        "bootstrap → erase → write(+verify) → read → reboot"
    );
    assert!(transcript.token.is_none(), "no --token, so no handshake");
    Ok(())
}

/// `--erase` is a `CMD_WRITE` of the wipe token to the `erase` alt, byte for byte
/// (`dfu-remote/main.c:506`).
#[test]
fn rpc_write_erase_token_over_the_wire() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))], // already a gadget
            vec![Step::Ok(ok())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["--erase"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;
    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());

    let mut expected = vec![0_u8, 0, 5];
    expected.extend_from_slice(b"erase");
    expected.extend_from_slice(&17_u32.to_be_bytes());
    expected.extend_from_slice(b"XBURST-FLASH-WIPE");
    expected.extend_from_slice(&tdfu_proto::crc32(b"XBURST-FLASH-WIPE").to_be_bytes());
    let (command, payload) = transcript.requests.get(1).ok_or("the erase never reached the wire")?;
    assert_eq!(*command, Command::Write.wire_byte());
    assert_eq!(payload, &expected, "the whole payload, field by field");
    Ok(())
}

/// `-w --verify` is one command with `CMD_WRITE`'s optional trailing byte set, and `-w`
/// alone omits the byte entirely. *Absent* and *present zero* are different things and
/// an audit kept them apart on purpose.
#[test]
fn rpc_write_layout_and_the_optional_verify_byte() -> TestResult {
    for verify in [false, true] {
        let scratch = Scratch::new("remote-write")?;
        let image = scratch.write("fw.bin", b"\x01\x02\x03\x04")?;
        let daemon = FakeDaemon::start(
            false,
            vec![
                vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
                vec![Step::Ok(ok())],
            ],
        )?;
        let path = image.display().to_string();
        let mut argv = vec!["-w", path.as_str(), "--alt", "flash"];
        if verify {
            argv.push("--verify");
        }
        let plan = plan_for(daemon.port(), &argv)?;
        let outcome = drive(&plan);
        let transcript = daemon.transcript()?;
        assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());

        let mut expected = vec![0_u8, 0, 5];
        expected.extend_from_slice(b"flash");
        expected.extend_from_slice(&4_u32.to_be_bytes());
        expected.extend_from_slice(b"\x01\x02\x03\x04");
        expected.extend_from_slice(&tdfu_proto::crc32(b"\x01\x02\x03\x04").to_be_bytes());
        if verify {
            expected.push(1);
        }
        let (_, payload) = transcript.requests.get(1).ok_or("the write never reached the wire")?;
        assert_eq!(payload, &expected, "verify={verify}");
    }
    Ok(())
}

/// A device at the firmware stage is refused, and the refusal says what it *is*.
///
/// The bootrom and the gadget share `a108:c309`, so a device that is neither
/// is genuinely unknown, and uploading a stage-1 image to it could hit a camera mid-flash.
/// The refusal names the stage rather than the byte, and the auto-bootstrap case adds why
/// the transfer needed one.
#[test]
fn a_device_that_is_neither_a_bootrom_nor_a_gadget_is_refused() -> TestResult {
    let scratch = Scratch::new("remote-stage")?;
    let image = scratch.write("fw.bin", b"x")?;
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discovered(1, WireVariant(6)))]])?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.contains("is running firmware, and only a device in the bootrom can be USB-booted"),
        "{message}"
    );
    assert!(
        message.contains(", which is what this transfer needs first"),
        "an auto-bootstrap says why it was there: {message}"
    );
    assert!(message.contains("Power-cycle it into the bootrom"), "{message}");
    assert_eq!(code, DEVICE, "the same refusal is a device error locally");

    // A stage byte this build has never heard of is printed, not folded into a guess.
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discovered(7, WireVariant(6)))]])?;
    let plan = plan_for(daemon.port(), &["-b"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, _) = outcome.refusal()?;
    assert!(
        message.contains("is in a stage this client does not know (7)"),
        "{message}"
    );
    assert!(
        !message.contains("which is what this transfer needs first"),
        "a requested -b was not put there by a transfer: {message}"
    );
    Ok(())
}

/// The alt a transfer targets is named in the line that announces it — for a name and
/// for a number — because "it wrote somewhere" is not a thing an operator can check.
#[test]
fn the_narration_names_the_alt_it_targets() -> TestResult {
    let scratch = Scratch::new("remote-alt-phrase")?;
    let image = scratch.write("fw.bin", b"xy")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(ok())],
        ],
    )?;
    let plan = plan_for(
        daemon.port(),
        &["-w", &image.display().to_string(), "--alt", "sdcard", "--verify"],
    )?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(outcome.err.contains("Sending 2 bytes to 127.0.0.1:"), "{}", outcome.err);
    assert!(
        outcome.err.contains("alt \"sdcard\", to be verified after writing."),
        "{}",
        outcome.err
    );

    // And a numeric `--alt`, on a read.
    let dump = scratch.path("dump.bin");
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(tdfu_proto::crc32(b"").to_be_bytes().to_vec())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string(), "--alt", "1"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome.err.contains("Reading device 0 alt 1 from 127.0.0.1:"),
        "{}",
        outcome.err
    );
    // And it says what that number will mean on the far side: the wire's alt field is one
    // "name or number" string, so the daemon matches a *name* first. Nothing on the local
    // path does, and an operator with a loader whose alt is literally named `1` has
    // nothing else to go on.
    assert!(
        outcome
            .err
            .contains("the daemon tries an alt *named* \"1\" before falling back to alt number 1"),
        "{}",
        outcome.err
    );

    // With no `--alt` there is nothing to name, and nothing is invented.
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(tdfu_proto::crc32(b"").to_be_bytes().to_vec())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    // The line is printed *before* the request goes out, so without this the whole read
    // could fail and the leg would still pass, which its two siblings above guard
    // against and this one did not.
    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome.err.contains("Reading device 0 from 127.0.0.1:"),
        "{}",
        outcome.err
    );
    Ok(())
}

/// `--verify` with no `-w` beside it is this crate disagreeing with itself, and it says
/// so rather than reporting a verify that never happened as a success.
///
/// Unreachable through the parser — [`Plan`] refuses the pair — so the plan is built by
/// hand, which is the only way to reach the guard at all.
///
/// **The daemon is given a script.** With an empty one, `serve`'s loop never
/// iterates, `read_request` is never called and `requests` is empty whatever the client
/// did, so "and nothing was sent" was the test restating its own premise. One entry is
/// enough for a request to be recorded if one arrives.
#[test]
fn a_verify_with_no_write_is_a_disagreement_not_a_success() -> TestResult {
    use crate::plan::{Action, Images, Remote, Target};
    use tdfu_core::model::AltSel;

    let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
    let plan = Plan::new(
        vec![Action::Verify],
        Target {
            index: 0,
            alt: AltSel::Default,
            cpu: None,
            size: None,
        },
        Images::default(),
        Some(Remote {
            host: "127.0.0.1".to_owned(),
            port: daemon.port(),
            token: None,
        }),
        false,
        false,
    )?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.starts_with("--verify reached the wire with no -w beside it"),
        "{message}"
    );
    assert!(
        message.ends_with("this is a bug in thingino-dfu, not in the command"),
        "{message}"
    );
    // The class of what was running, exactly as `run::missing_preflight` gives locally:
    // `--verify` is a transfer, so **2**.
    assert_eq!(code, TRANSFER);
    assert!(
        transcript.requests.is_empty(),
        "and nothing was sent: {:?}",
        transcript.requests
    );
    Ok(())
}

/// A bootrom target is detected and USB-booted first, and the
/// auto-detect line is printed: the C prints it only when it is about to
/// bootstrap (`cli/main.c:360-364`), and so does this.
#[test]
fn fe_cli_autobootstrap_over_the_wire() -> TestResult {
    let scratch = Scratch::new("remote-autoboot")?;
    let image = scratch.write("fw.bin", b"x")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant(50)))], // t32lq in the bootrom
            vec![Step::Ok(ok())],
            vec![Step::Ok(ok())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome.err.contains("Auto-detected remote device: t32lq"),
        "{}",
        outcome.err
    );
    let (_, payload) = transcript.requests.get(1).ok_or("no bootstrap")?;
    assert_eq!(payload, &b"\x00\x05t32lq".to_vec(), "index, then the variant name");
    // **The mid-boot wait, third pin.** A bootrom the daemon *can* name is live, so nothing waits:
    // the bootstrap goes out on the answer the first `DISCOVER` already gave.
    assert_eq!(
        outcome.slept,
        Vec::new(),
        "a named bootrom answers, so there is nothing to settle"
    );
    assert!(
        !outcome.err.contains("is between the bootrom and the DFU gadget"),
        "{}",
        outcome.err
    );
    Ok(())
}

/// A target that is already the gadget is not bootstrapped — and is told so, because
/// silence and success look identical.
#[test]
fn a_gadget_target_is_not_bootstrapped_again() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(Vec::new())], // REBOOT
        ],
    )?;
    let plan = plan_for(daemon.port(), &["--reboot"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome
            .err
            .contains("is already the U-Boot DFU gadget; nothing to bootstrap"),
        "{}",
        outcome.err
    );
    let commands: Vec<u8> = transcript.requests.iter().map(|(command, _)| *command).collect();
    assert_eq!(
        commands,
        vec![Command::Discover.wire_byte(), Command::Reboot.wire_byte()],
        "no BOOTSTRAP for a device that is already the gadget"
    );
    Ok(())
}

/// **The mid-boot wait's pin, and the bench case it comes from.** A device caught between the
/// bootrom and the gadget is waited for, and the operation behind it then runs.
///
/// On the bench (T32LQ, Rust daemon, `--host` from another host) `-b` and then `-r` as two
/// invocations about 300 ms apart gave: bootstrap exit 0, `-l` reporting
/// `bootrom`/`unknown`, and `-r` refusing in **zero seconds** with "pass --cpu". A remote
/// bootstrap answers the moment U-Boot starts (`dfu-remote/main.c:442`), and for a second
/// or three after that the bootrom is still enumerated but no longer answers the register
/// reads, so the daemon reports it truthfully as a bootrom it cannot name. The
/// daemon's own read handler waits that out; the client was deciding before
/// it sent anything.
#[test]
fn a_bootrom_that_is_still_booting_is_waited_for_rather_than_refused() -> TestResult {
    let scratch = Scratch::new("remote-settle")?;
    let dump = scratch.path("dump.bin");
    let data = b"settled".to_vec();
    let mut payload = data.clone();
    payload.extend_from_slice(&tdfu_proto::crc32(&data).to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))], // mid-boot
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))], // still mid-boot
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))], // the gadget is up
            vec![Step::Ok(payload)],                             // and the read runs
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(std::fs::read(&dump)?, data, "the read ran, once the device settled");
    assert_eq!(
        outcome.slept,
        vec![crate::wait::POLL_INTERVAL; 2],
        "one poll interval per re-ask, and none after the answer that settled it"
    );
    let commands: Vec<u8> = transcript.requests.iter().map(|(command, _)| *command).collect();
    assert_eq!(
        commands,
        vec![
            Command::Discover.wire_byte(),
            Command::Discover.wire_byte(),
            Command::Discover.wire_byte(),
            Command::Read.wire_byte(),
        ],
        "three asks, then the read; and no BOOTSTRAP, because the wait found a gadget"
    );
    // The whole sentence, once. The number in it is asserted here and nowhere else: with
    // it unpinned, `POLL_INTERVAL * SETTLE_POLLS` mutated to `/` still waited the full
    // window and told the operator it was waiting **0 s**, which is the shape of message
    // this tree exists not to print.
    assert_eq!(
        outcome
            .err
            .matches("is between the bootrom and the DFU gadget; waiting up to 30 s for it to re-enumerate.")
            .count(),
        1,
        "the wait announces itself once: {}",
        outcome.err
    );
    assert!(!outcome.err.contains("does not know what SoC"), "{}", outcome.err);
    Ok(())
}

/// The same wait, ending the other way: the bootrom comes back and names itself, so the
/// bootstrap runs with the variant the *settled* answer carried.
///
/// A live bootrom answers those reads, so this is the case where the first `DISCOVER` was
/// early. The `0xFF` that was waited out must not be what goes on the wire.
#[test]
fn a_bootrom_that_names_itself_late_is_bootstrapped_with_that_name() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))],
            vec![Step::Ok(discovered(0, WireVariant(50)))], // t32lq, on the second ask
            vec![Step::Ok(ok())],                           // BOOTSTRAP
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-b"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(outcome.slept, vec![crate::wait::POLL_INTERVAL], "one re-ask was enough");
    assert!(
        outcome.err.contains("Auto-detected remote device: t32lq"),
        "{}",
        outcome.err
    );
    let (command, payload) = transcript.requests.get(2).ok_or("no bootstrap")?;
    assert_eq!(*command, Command::Bootstrap.wire_byte());
    assert_eq!(payload, &b"\x00\x05t32lq".to_vec(), "the settled name, not the 0xFF");
    Ok(())
}

/// **The empty-list pin, and the bench run after the wait's.** The gap has a phase in which the
/// device is on no list at all, and that is still the gap.
///
/// With the wait alone, the same T32LQ answered the *first* `DISCOVER` as a mid-boot
/// bootrom, so the wait began, and the very next one as an empty bus: the bootrom had
/// disconnected and the gadget had not enumerated yet. Treating that as "no device" ended
/// the wait one poll in, with `no Ingenic devices on the daemon's bus` after one second.
/// The daemon waits out exactly the same absence from its side
/// (`dfu-remote/main.c:344-353`, whose comment at `:334-341` calls the alternative a
/// spurious `Device not found`).
#[test]
fn a_target_that_leaves_the_bus_mid_reenumeration_is_still_waited_for() -> TestResult {
    let scratch = Scratch::new("remote-settle-gap")?;
    let dump = scratch.path("dump.bin");
    let data = b"re-enumerated".to_vec();
    let mut payload = data.clone();
    payload.extend_from_slice(&tdfu_proto::crc32(&data).to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))], // phase 1: mid-boot
            vec![Step::Ok(Vec::new())],                          // phase 2: nothing listed
            vec![Step::Ok(Vec::new())],                          // phase 2, still
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))], // phase 3: the gadget
            vec![Step::Ok(payload)],                             // and the read runs
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(std::fs::read(&dump)?, data, "the read ran, once the gadget enumerated");
    assert_eq!(
        outcome.slept,
        vec![crate::wait::POLL_INTERVAL; 3],
        "one poll interval per re-ask, the empty answers included"
    );
    let commands: Vec<u8> = transcript.requests.iter().map(|(command, _)| *command).collect();
    assert_eq!(
        commands,
        vec![
            Command::Discover.wire_byte(),
            Command::Discover.wire_byte(),
            Command::Discover.wire_byte(),
            Command::Discover.wire_byte(),
            Command::Read.wire_byte(),
        ],
        "four asks, then the read; and no BOOTSTRAP, because the wait found a gadget"
    );
    assert!(
        !outcome.err.contains("no Ingenic devices on the daemon's bus"),
        "an empty list inside the window is not an empty bench: {}",
        outcome.err
    );
    Ok(())
}

/// **The index is a row of a listing, and a listing moves.** A device that took the
/// target's position over while the target was re-enumerating is not bootstrapped in its
/// place.
///
/// The wire carries a position, and the daemon resolves it against the listing it last
/// sent this connection, so a position only means the device the operator picked while
/// the bus behind it holds still. Neither end sorts the rows, and a bootstrap is itself
/// what takes a device off the bus and puts it back, so the row at position 0 during the
/// settle window may be another camera's bootrom: two bootroms is the ordinary bench
/// state. Bootstrapping that one uploads a stage 1 to a device someone else may be
/// flashing, which is what the daemon's own bootrom gate exists to prevent and what a
/// stale position defeats.
#[test]
fn a_device_that_took_the_targets_row_is_not_bootstrapped_in_its_place() -> TestResult {
    /// A row at an address of the caller's choosing, so a *different* device can hold the
    /// same position in a later listing.
    fn row_at(address: u8, stage: u8, variant: WireVariant) -> Vec<u8> {
        DeviceEntry {
            bus: 1,
            address,
            vendor: 0xA108,
            product: 0xC309,
            stage,
            variant,
        }
        .encode()
        .to_vec()
    }

    let polls = settle_polls()?;
    // Address 7 is what `discovered` puts at position 0, so the target is that row.
    let mut script = vec![vec![Step::Ok(row_at(7, 0, WireVariant::UNKNOWN))]];
    // And from the next poll on, position 0 is another camera's bootrom, which names
    // itself at once: nothing about *it* is unsettled, so only its identity says no.
    script.extend(vec![vec![Step::Ok(row_at(9, 0, WireVariant(6)))]; polls]);

    let daemon = FakeDaemon::start(false, script)?;
    let plan = plan_for(daemon.port(), &["-b"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.contains("was bus 1 address 7 when this run picked it") && message.contains("is now bus 1 address 9"),
        "the refusal names both devices: {message}"
    );
    assert_eq!(code, DEVICE, "a bootstrap that refuses is the device class");
    assert!(
        !transcript
            .requests
            .iter()
            .any(|(command, _)| *command == Command::Bootstrap.wire_byte()),
        "no stage 1 goes to a device the operator did not pick: {:?}",
        transcript.requests
    );
    Ok(())
}

/// A daemon that has no listing to resolve an index against says so, and the client
/// renders it as the failure it is rather than as a transfer that happened.
///
/// The daemon keeps this connection's most recent `CMD_DISCOVER` as the frame of
/// reference for every index that follows, so a command whose index it cannot resolve is
/// refused rather than guessed at. This client never sends one, because it discovers
/// before it targets anything, and this pins what the operator sees if the far side ever
/// answers that way: the daemon's own words, and the running operation's exit code.
#[test]
fn a_write_the_daemon_cannot_resolve_is_rendered_as_the_refusal_it_is() -> TestResult {
    let scratch = Scratch::new("remote-no-listing")?;
    let image = scratch.write("fw.bin", b"firmware")?;

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))], // a gadget: nothing to bootstrap
            vec![Step::Fail("no DISCOVER on this connection".to_owned())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("could not complete the write: no DISCOVER on this connection"),
        "the daemon's own words, quoted: {message}"
    );
    assert_eq!(code, TRANSFER, "a refused write is the transfer class");
    Ok(())
}

/// The same wait, ending the other way: nothing ever comes back, and the empty-bus refusal
/// is then the true one.
///
/// The exit code is the **device** one and not the transfer one, because the action that
/// refused is the auto-bootstrap in front of the read, which is what the
/// bench saw: `-r` after `-b`, exit 1.
#[test]
fn a_bus_that_stays_empty_for_the_window_refuses_with_the_empty_bus_sentence() -> TestResult {
    let scratch = Scratch::new("remote-settle-gone")?;
    let dump = scratch.path("dump.bin");
    let polls = settle_polls()?;
    let mut script = vec![vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))]];
    script.extend(vec![vec![Step::Ok(Vec::new())]; polls]);

    let daemon = FakeDaemon::start(false, script)?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(
        message,
        format!(
            "no Ingenic devices on the daemon's bus at 127.0.0.1:{}: {}",
            plan.remote.as_ref().map_or(0, |remote| remote.port),
            crate::target::EMPTY_BUS_ADVICE
        ),
        "the window closed on nothing, which is what makes this sentence true"
    );
    assert_eq!(
        code, DEVICE,
        "the auto-bootstrap is what refused, so it is a device error"
    );
    assert_eq!(
        transcript.requests.len(),
        polls + 1,
        "the first ask, then one per poll; the refusal reads the last answer rather than re-asking"
    );
    assert_eq!(
        outcome.slept,
        vec![crate::wait::POLL_INTERVAL; polls],
        "the refusal comes after the last poll, not before the first"
    );
    Ok(())
}

/// Phase 2 with company: the target's row disappears while another device stays listed.
///
/// A bus with two cameras on it does not go empty when one of them re-enumerates, so the
/// list is never empty and the index is simply absent from it. The refusal that names how
/// many devices there are must wait the window out for the same reason the empty-bus one
/// does.
#[test]
fn an_index_that_vanishes_beside_another_device_is_the_same_gap() -> TestResult {
    let scratch = Scratch::new("remote-settle-pair")?;
    let dump = scratch.path("dump.bin");
    let data = b"the second camera".to_vec();
    let mut payload = data.clone();
    payload.extend_from_slice(&tdfu_proto::crc32(&data).to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            // Device 0 is a bootrom the daemon can name and is nobody's target here;
            // device 1 is the one that was just bootstrapped.
            vec![Step::Ok(discovered_rows(&[
                (0, WireVariant(50)),
                (0, WireVariant::UNKNOWN),
            ]))],
            // Phase 2: device 1 has gone and device 0 has not.
            vec![Step::Ok(discovered_rows(&[(0, WireVariant(50))]))],
            vec![Step::Ok(discovered_rows(&[
                (0, WireVariant(50)),
                (2, WireVariant::UNKNOWN),
            ]))],
            vec![Step::Ok(payload)],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-i", "1", "-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(std::fs::read(&dump)?, data, "the read ran on the device that came back");
    assert_eq!(outcome.slept, vec![crate::wait::POLL_INTERVAL; 2]);
    assert!(
        !outcome.err.contains("is not on the daemon's bus"),
        "a one-row list is not proof that device 1 is gone for good: {}",
        outcome.err
    );
    let (command, sent) = transcript.requests.last().ok_or("no read")?;
    assert_eq!(*command, Command::Read.wire_byte());
    assert_eq!(
        sent.first(),
        Some(&1_u8),
        "the read is for device 1, not for its neighbour"
    );
    Ok(())
}

/// `-l` prints the daemon's table on stdout and nothing else.
#[test]
fn rpc_cli_remote_list() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discovered(0, WireVariant(6)))]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome.out.starts_with("Found 1 device on 127.0.0.1:"),
        "{}",
        outcome.out
    );
    assert!(outcome.out.contains("a108:c309  bootrom  t31x"), "{}", outcome.out);
    assert!(
        !outcome.out.contains("Talking to"),
        "narration must stay off stdout: {}",
        outcome.out
    );
    assert_eq!(
        transcript
            .requests
            .first()
            .map(|(command, payload)| (*command, payload.len())),
        Some((Command::Discover.wire_byte(), 0)),
        "DISCOVER carries no payload"
    );
    Ok(())
}

/// `--diag` puts the daemon's report on stdout, alone.
#[test]
fn rpc_diag_text_reaches_stdout() -> TestResult {
    let report = "=== thingino-dfu diagnostics ===\nSoC: T31X\n";
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(report.as_bytes().to_vec())]])?;
    let plan = plan_for(daemon.port(), &["--diag", "-i", "2"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(outcome.out, "=== thingino-dfu diagnostics ===\nSoC: T31X\n");
    assert!(!outcome.err.contains("diagnostics"), "the report must not double up");
    assert_eq!(
        transcript
            .requests
            .first()
            .map(|(command, payload)| (*command, payload.clone())),
        Some((Command::Diag.wire_byte(), vec![2])),
        "one index byte"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading, which is the one payload that may exceed the cap.
// ---------------------------------------------------------------------------

/// `-r` streams `[data][crc32]` into the file and checks the CRC.
#[test]
fn rpc_read_streams_to_the_file() -> TestResult {
    let scratch = Scratch::new("remote-read")?;
    let dump = scratch.path("dump.bin");
    // Two chunks' worth plus a bit, so the streaming loop really loops.
    let data: Vec<u8> = (0..200_000_u32).map(|byte| byte.to_le_bytes()[0]).collect();
    let mut payload = data.clone();
    payload.extend_from_slice(&tdfu_proto::crc32(&data).to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(payload)],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string(), "--alt", "1"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(std::fs::read(&dump)?, data, "every byte, in order");
    assert!(
        outcome.err.contains("Saved 200000 bytes to") && outcome.err.contains("(CRC-32 checked)"),
        "{}",
        outcome.err
    );
    let (_, sent) = transcript.requests.get(1).ok_or("no read")?;
    assert_eq!(sent, &vec![0_u8, 0, 1, b'1'], "index, empty variant, alt \"1\"");
    Ok(())
}

/// **The cap's client half.** A `CMD_READ` payload past the 64 MiB cap is streamed,
/// not refused: a NAND alt 0 is 256 MiB (`crates/tdfu-core/tests/fixtures/results/`).
///
/// The daemon here announces exactly that and then dies part way through, which proves
/// both halves at once: the cap did not stop the transfer, and the bytes that arrived
/// were already in the file rather than in a buffer waiting for a payload that never
/// finished.
#[test]
fn rpc_cli_remote_read_may_exceed_the_cap_and_never_buffers() -> TestResult {
    let scratch = Scratch::new("remote-read-huge")?;
    let dump = scratch.path("nand.bin");
    let announced = 256 * 1024 * 1024_u32 + 4;
    assert!(
        tdfu_proto::exceeds_payload_cap(announced),
        "the fixture has to be past the cap to be the case at all"
    );
    // Two whole 64 KiB reads' worth, so both reach the file before the socket dies. A
    // *partial* third would not: a chunk that never arrives in full is never written,
    // which is what makes the CRC over the rest meaningful.
    let first = vec![0xA5_u8; 128 * 1024];

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![
                Step::Header {
                    status: Status::Ok.wire_byte(),
                    len: announced,
                },
                Step::Raw(first.clone()),
                Step::Close,
            ],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.contains("closed the connection during the read"),
        "a dropped connection is reported as one: {message}"
    );
    // The file the preflight created now holds 128 KiB of a 256 MiB dump, and
    // the message says so: the local `-r` arm makes naming a short file the policy, and
    // this path said nothing at all.
    assert!(
        message.ends_with(&format!(
            "; {} holds the {} bytes that arrived and is short",
            dump.display(),
            first.len()
        )),
        "{message}"
    );
    assert_eq!(code, PROTOCOL, "the wire failed, so 4");
    assert_eq!(
        std::fs::read(&dump)?,
        first,
        "the bytes that arrived were written as they arrived — nothing was buffered"
    );
    Ok(())
}

/// A read whose data all arrived but whose CRC-32 did not leaves a file that is
/// **complete and unchecked**, and the message says that rather than "short".
///
/// Every data byte is on disk, so calling it short would be the tool asserting something
/// untrue about a file the operator can see; what it must not do is flash it, which is
/// the same warning the CRC-mismatch arm gives.
#[test]
fn a_read_that_loses_only_its_crc_says_the_file_is_unchecked() -> TestResult {
    let scratch = Scratch::new("remote-read-no-crc")?;
    let dump = scratch.path("dump.bin");
    let data = vec![0x5A_u8; 64];
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![
                Step::Header {
                    status: Status::Ok.wire_byte(),
                    // The four CRC bytes are announced and never sent.
                    len: u32::try_from(data.len())? + 4,
                },
                Step::Raw(data.clone()),
                Step::Close,
            ],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, _) = outcome.refusal()?;
    assert!(
        message.ends_with(&format!(
            "; {} holds the {} bytes that arrived, but the CRC-32 that would check them never did, \
             so it must not be written back to a device",
            dump.display(),
            data.len()
        )),
        "{message}"
    );
    assert!(!message.contains("is short"), "every data byte arrived: {message}");
    assert_eq!(std::fs::read(&dump)?, data, "and they are all on disk");
    Ok(())
}

/// A read that drops before a single byte reaches the file says nothing about a file,
/// because there is nothing in it to warn about.
///
/// Both ways of getting there: the payload dropping on its first chunk, and a payload
/// that is only its own CRC-32 (`data_len == 0`) dropping on the trailer. Each has its
/// own `written > 0` guard, and without the second leg the trailer's guard could be
/// deleted and nothing would notice.
#[test]
fn a_read_that_never_started_does_not_name_an_empty_file() -> TestResult {
    let scratch = Scratch::new("remote-read-nothing")?;
    // `len: 4096` drops in the payload loop; `len: 4` announces a zero-length read whose
    // four CRC bytes never arrive, so the *trailer* read is what fails.
    for (case, len) in [("payload", 4096_u32), ("trailer", 4)] {
        let dump = scratch.path(&format!("dump-{case}.bin"));
        let daemon = FakeDaemon::start(
            false,
            vec![
                vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
                vec![
                    Step::Header {
                        status: Status::Ok.wire_byte(),
                        len,
                    },
                    Step::Close,
                ],
            ],
        )?;
        let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
        let outcome = drive(&plan);
        daemon.transcript()?;

        let (message, _) = outcome.refusal()?;
        assert!(
            message.ends_with("closed the connection during the read"),
            "{case}: nothing arrived, so there is no file to say anything about: {message}"
        );
        assert!(std::fs::read(&dump)?.is_empty(), "{case}: and the file really is empty");
    }
    Ok(())
}

/// A read whose bytes do not match the CRC the daemon sent is refused, loudly, and the
/// file is kept and named as untrustworthy.
///
/// The C deletes it (`cli/remote.c:359`). A local `-r` keeps its partial dump, and a
/// tool that keeps the evidence in one mode and destroys it in the other is the bug-15
/// shape again — so this keeps it, and says in the same breath that it must not be
/// flashed back.
#[test]
fn a_corrupted_read_is_refused_and_the_file_is_named() -> TestResult {
    let scratch = Scratch::new("remote-read-crc")?;
    let dump = scratch.path("dump.bin");
    let mut payload = b"not-the-image".to_vec();
    payload.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(payload)],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(message.contains("0xDEADBEEF"), "{message}");
    assert!(message.contains("arrived corrupted"), "{message}");
    assert!(message.contains("must not be written back to a device"), "{message}");
    assert!(message.contains(&dump.display().to_string()), "{message}");
    assert_eq!(code, PROTOCOL);
    assert_eq!(std::fs::read(&dump)?, b"not-the-image", "the evidence is kept");
    Ok(())
}

/// A read response too short to hold its own CRC is refused by name.
#[test]
fn a_read_response_shorter_than_its_crc_is_refused() -> TestResult {
    let scratch = Scratch::new("remote-read-short")?;
    let dump = scratch.path("dump.bin");
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(vec![1, 2, 3])],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.contains("shorter than the 4-byte CRC-32 that ends it"),
        "{message}"
    );
    assert_eq!(code, PROTOCOL);
    Ok(())
}

/// `--size` caps the file, and says up front that the transfer itself cannot be capped:
/// the read command's payload has no length field.
#[test]
fn size_caps_the_file_and_says_why_it_cannot_cap_the_transfer() -> TestResult {
    let scratch = Scratch::new("remote-read-size")?;
    let dump = scratch.path("head.bin");
    let data: Vec<u8> = (0..70_000_u32).map(|byte| byte.to_le_bytes()[0]).collect();
    let mut payload = data.clone();
    payload.extend_from_slice(&tdfu_proto::crc32(&data).to_be_bytes());

    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Ok(payload)],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-r", &dump.display().to_string(), "--size", "4096"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(std::fs::read(&dump)?, data[..4096], "exactly --size bytes");
    assert!(
        outcome.err.contains("--size 4096 is a client-side cap here"),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("Saved 4096 bytes to"), "{}", outcome.err);
    Ok(())
}

// ---------------------------------------------------------------------------
// Progress and logs.
// ---------------------------------------------------------------------------

/// **Progress frames and log frames together.** Progress frames draw the counter, and a log line
/// blanks it first.
///
/// Byte counts stopped being log lines when the daemon started sending real progress
/// frames, so terminating a live counter before a log line is this
/// client's job — the C never had to, because it had no counter to terminate.
///
/// **The fixture is built the way the daemon builds it**: `percent_of` for the
/// percentage and `progress::bytes_line` for the message, which is what `report::send`
/// calls. Written by hand it said `4096 / 16384 bytes`, a string the daemon has never
/// sent, so the assertion that the counter "is the local counter's shape" was made
/// against a shape neither end produced.
#[test]
fn rpc_progress_draws_the_bar_and_a_log_line_terminates_it() -> TestResult {
    /// One `RESP_PROGRESS` frame, exactly as `tdfu-daemon`'s `report::send` builds it
    /// for a `Progress::Bytes`.
    fn counting(done: u64, total: u64) -> Step {
        Step::Progress {
            percent: tdfu_proto::ProgressBody::percent_of(done, Some(total)),
            stage: tdfu_core::progress::Phase::Download.wire_byte(),
            message: tdfu_core::progress::bytes_line(done, Some(total)),
        }
    }

    let scratch = Scratch::new("remote-progress")?;
    let image = scratch.write("fw.bin", b"x")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![
                counting(4096, 16_384),
                counting(4096, 16_384),
                counting(8192, 16_384),
                Step::Log("DFU download complete\n".to_owned()),
                Step::Ok(ok()),
            ],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    // The line a *local* write of the same bytes would have drawn.
    let mut local = Vec::new();
    crate::render::Bar::new().render(
        &tdfu_core::Progress::Bytes {
            phase: tdfu_core::progress::Phase::Download,
            done: 4096,
            total: Some(16_384),
        },
        &mut local,
    );
    let local = String::from_utf8(local)?;
    let local = local.trim_matches(['\r', ' ']);
    assert!(
        outcome.err.contains(local),
        "the counter is the local counter, not merely its shape: wanted {local:?} in {:?}",
        outcome.err
    );
    assert_eq!(
        outcome.err.matches("25%").count(),
        1,
        "an identical frame is not redrawn: {:?}",
        outcome.err
    );
    assert!(outcome.err.contains("50%"), "{:?}", outcome.err);
    let complete = outcome
        .err
        .find("DFU download complete")
        .ok_or("the log line was dropped")?;
    let cleared = outcome.err[..complete]
        .rfind('\r')
        .ok_or("the counter was never terminated before the log line")?;
    assert!(
        outcome.err[cleared..complete].trim_matches(['\r', ' ']).is_empty(),
        "the counter must be blanked, not written over: {:?}",
        &outcome.err[cleared..complete]
    );
    Ok(())
}

/// A progress frame this client cannot read is noted, not fatal.
///
/// The frame's announced length was honoured, so the stream is still in sync and the
/// daemon goes on to finish the write. Refusing here exited 2 on a transfer that
/// completed, over a counter, and the log arm beside it has always been lenient.
#[test]
fn a_bad_progress_frame_does_not_kill_a_completed_transfer() -> TestResult {
    let scratch = Scratch::new("remote-bad-progress")?;
    let image = scratch.write("fw.bin", b"x")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![
                Step::Header {
                    status: Status::Progress.wire_byte(),
                    // Four bytes announcing a nine-byte message: the body does not add up,
                    // but the *frame* does.
                    len: 4,
                },
                Step::Raw(vec![25, 3, 0, 9]),
                Step::Ok(ok()),
            ],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    assert!(
        outcome.result.is_ok(),
        "the transfer completed: {:?}",
        outcome.refusal()
    );
    assert!(
        outcome.err.contains("note: the daemon at 127.0.0.1:")
            && outcome.err.contains("sent a progress frame this client cannot read"),
        "the bad frame is named: {:?}",
        outcome.err
    );
    assert!(
        outcome.err.contains("download   25%"),
        "percent and stage are at fixed offsets and are still drawn: {:?}",
        outcome.err
    );
    Ok(())
}

/// A log frame is rendered verbatim, and a phase byte this build does not know is
/// printed rather than guessed at.
#[test]
fn a_log_frame_is_verbatim_and_an_unknown_phase_says_its_byte() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![vec![
            Step::Log("careful: bad block at 0x1000".to_owned()),
            Step::Progress {
                percent: 7,
                stage: 99,
                message: "doing something new".to_owned(),
            },
            Step::Ok(discovered(0, WireVariant(6))),
        ]],
    )?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(
        outcome.err.contains("careful: bad block at 0x1000\n"),
        "verbatim, with the newline it did not send: {:?}",
        outcome.err
    );
    assert!(
        outcome.err.contains("stage 99    7%  doing something new"),
        "{:?}",
        outcome.err
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The failure paths. Every one of these is a message, not a silent exit.
// ---------------------------------------------------------------------------

/// **The connect half of not discarding a cause.** Every resolved address, with the
/// reason that address gave.
#[test]
fn a_refused_connection_names_the_address_and_the_errno() -> TestResult {
    let port = closed_port()?;
    // `localhost` normally resolves to both `::1` and `127.0.0.1`, which is the case the
    // C's discarded errnos are worst for; whatever this host resolves it to, every
    // address must appear with its own reason.
    let expected: Vec<String> = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", port))?
        .map(|address| address.to_string())
        .collect();
    let plan =
        Cli::try_parse_from(["thingino-dfu", "--host", "localhost", "--port", &port.to_string(), "-l"])?.into_plan()?;
    let outcome = drive(&plan);

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL, "a failed connect is 4");
    assert!(
        message.starts_with(&format!("cannot connect to localhost:{port}")),
        "{message}"
    );
    // In the resolver's order, not merely present: a mutant that reversed
    // `resolve`'s vector would make IPv4 the default on a dual-stacked host, which is a
    // different daemon on a different address family, and containment could not see it.
    let mut cursor = 0;
    for address in &expected {
        let at = message[cursor..]
            .find(address.as_str())
            .ok_or_else(|| format!("{address} is missing, or out of order, in: {message}"))?;
        cursor += at + address.len();
    }
    assert!(
        message.to_lowercase().contains("refused"),
        "the errno itself has to survive: {message}"
    );
    Ok(())
}

/// A name that does not resolve is a different failure from a port that refuses, and
/// says so.
#[test]
fn an_unresolvable_host_is_not_a_refused_port() -> TestResult {
    let plan =
        Cli::try_parse_from(["thingino-dfu", "--host", "no-such-host.invalid", "--port", "5050", "-l"])?.into_plan()?;
    let outcome = drive(&plan);

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert!(
        message.starts_with("cannot resolve no-such-host.invalid:5050: "),
        "{message}"
    );
    assert!(message.contains("Check the name, or give an address"), "{message}");
    Ok(())
}

/// **The version check the C never makes** (`cli/remote.c:232` tests the magic alone).
/// One line, naming both versions, instead of payloads that decode into nonsense.
#[test]
fn a_daemon_of_another_version_says_so_in_one_line() -> TestResult {
    let mut header = tdfu_proto::MAGIC.to_be_bytes().to_vec();
    header.push(2); // version 2
    header.push(Status::Ok.wire_byte());
    header.extend_from_slice(&0_u32.to_be_bytes());
    let daemon = FakeDaemon::start(false, vec![vec![Step::Raw(header)]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} speaks protocol version 2; this client speaks 1. \
             The two are not interchangeable — update whichever is older",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    Ok(())
}

/// Something else on the port answers, and is told apart from a daemon.
#[test]
fn a_peer_that_is_not_a_daemon_says_which_port_it_is() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![vec![Step::Raw(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec())]],
    )?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert!(message.contains("does not begin with the TDFU magic"), "{message}");
    assert!(message.contains("not as a dfu-remote daemon"), "{message}");
    Ok(())
}

/// A daemon that stops talking mid-operation is reported as a dropped connection,
/// never as anything else.
#[test]
fn a_dropped_connection_is_reported_as_a_dropped_connection() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Close]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} closed the connection during the device list",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    Ok(())
}

/// **The cap, the other half.** A final response past the cap for a command that is
/// not a read is refused, with the number it announced.
#[test]
fn rpc_cli_remote_oversize_final_response_is_refused() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![vec![Step::Header {
            status: Status::Ok.wire_byte(),
            len: tdfu_proto::MAX_PAYLOAD + 1,
        }]],
    )?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert!(
        message.contains("67108865 bytes, past the 67108864-byte payload cap"),
        "{message}"
    );
    assert!(message.contains("only a read is streamed past it"), "{message}");
    Ok(())
}

/// A log frame that announces more than a line of text is refused rather than silently
/// drained (`cli/remote.c:209-217` drains and carries on).
#[test]
fn an_oversize_intermediate_frame_is_refused_not_drained() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![vec![Step::Header {
            status: Status::Log.wire_byte(),
            len: 200_000,
        }]],
    )?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert!(message.contains("announced a 200000-byte frame"), "{message}");
    assert!(message.contains("lost frame sync"), "{message}");
    Ok(())
}

/// A `RESP_ERROR` is the daemon's own words, and the exit code is the **running
/// operation's** class — 1 for a bootstrap, 2 for a transfer — exactly as locally.
///
/// The C's remote path normalises every transfer branch to `EXIT_TRANSFER_ERROR`
/// (`cli/main.c:384`), so a failed auto-bootstrap under `-w` exits 2 remotely and 1
/// locally. That contradiction is not reproduced.
#[test]
fn a_daemon_refusal_takes_the_operations_own_exit_code() -> TestResult {
    // A bootstrap that fails: device class, exit 1.
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant(6)))],
            vec![Step::Fail("bootstrap failed: Device not found".to_owned())],
        ],
    )?;
    let scratch = Scratch::new("remote-refusal")?;
    let image = scratch.write("fw.bin", b"x")?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, code) = outcome.refusal()?;
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} could not complete the bootstrap: bootstrap failed: Device not found",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    assert_eq!(code, DEVICE, "a bootstrap is a device error, remotely as locally");

    // A write that fails: transfer class, exit 2.
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Fail("write failed: Transfer failed".to_owned())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("could not complete the write: write failed: Transfer failed"),
        "{message}"
    );
    assert_eq!(code, TRANSFER);
    Ok(())
}

/// A verify mismatch is not reported as the write failing.
///
/// `--verify` is `CMD_WRITE`'s trailing byte, so the daemon runs both
/// halves under one command and answers `verify failed at offset 0x…` on it. Labelled
/// "the write", that says the flash never took, when in fact it took and read back wrong
/// (two different next actions for the operator). Locally the verify is its own action
/// and its own error, and the exit code already agreed; now the account does too.
#[test]
fn a_verify_mismatch_names_the_verify_and_not_the_write() -> TestResult {
    let scratch = Scratch::new("remote-verify-blame")?;
    let image = scratch.write("fw.bin", b"xyz")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            // The frozen wire string, byte for byte.
            vec![Step::Fail("verify failed at offset 0x00000009".to_owned())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string(), "--verify"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("could not complete the write and its verify: verify failed at offset 0x00000009"),
        "{message}"
    );
    assert!(
        !message.contains("could not complete the write:"),
        "the write succeeded; only the verify did not: {message}"
    );
    assert_eq!(code, TRANSFER, "a transfer, exactly as locally");

    // The local wording for the same fault, for the pair: both name the verify and the
    // offset, and both exit 2.
    let local = tdfu_core::Error::Verify {
        offset: 9,
        expected: 0x11,
        actual: Some(0x22),
    }
    .to_string();
    assert!(local.starts_with("verify failed at offset 0x9"), "{local}");
    for half in [message.as_str(), local.as_str()] {
        assert!(half.contains("verify failed at offset"), "{half}");
    }

    // And without `--verify` the write is still just the write.
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
            vec![Step::Fail("write failed: Transfer failed".to_owned())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, _) = outcome.refusal()?;
    assert!(
        message.contains("could not complete the write: write failed"),
        "{message}"
    );
    Ok(())
}

/// A refusal with no payload says which side went quiet, rather than the C's `unknown`
/// (`cli/remote.c:655`), which reads as a diagnosis.
#[test]
fn a_refusal_with_no_reason_says_so() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Fail(String::new())]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("could not complete the device list, and sent no reason with the refusal"),
        "{message}"
    );
    assert_eq!(code, DEVICE, "a listing is a device-class operation");
    Ok(())
}

/// A file error exits **3** with `--host`, exactly as without it.
///
/// The preflight runs before the socket is opened, so the same code produces the same
/// error on both paths, which is why the C's contradiction cannot come back here.
#[test]
fn fe_cli_a_missing_image_exits_three_remotely_too() -> TestResult {
    let scratch = Scratch::new("remote-missing")?;
    let absent = scratch.path("not-here.bin");
    let port = closed_port()?;

    let remote = Cli::try_parse_from([
        "thingino-dfu",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "-w",
        &absent.display().to_string(),
    ])?
    .into_plan()?;
    let local = Cli::try_parse_from(["thingino-dfu", "-w", &absent.display().to_string()])?.into_plan()?;

    let (remote_message, remote_code) = drive(&remote).refusal()?;
    let (local_message, local_code) = drive(&local).refusal()?;
    assert_eq!(remote_code, FILE, "a file error is 3");
    assert_eq!(local_code, FILE);
    assert_eq!(remote_message, local_message, "and the same sentence, either way");
    assert!(
        remote_message.contains("cannot read the image for -w"),
        "{remote_message}"
    );
    Ok(())
}

/// One failure class in the matched table below: the bus and the daemon that each
/// produce it, and the one code both halves must exit with.
struct Matched {
    /// What is being refused.
    what: &'static str,
    /// Everything after the program name, without `--host`.
    args: Vec<String>,
    /// The local bus that produces the refusal.
    bus: Vec<crate::fake::FakeDevice>,
    /// What the daemon's `CMD_DISCOVER` answers.
    discover: Vec<u8>,
    /// How many times it has to answer it.
    ///
    /// One, except for the row whose device is a bootrom reporting `0xFF`: that is the one
    /// answer [`Session::settle`](super::Session) re-asks about, for the whole
    /// window, before the refusal this row is here to match.
    discovers: usize,
    /// The code both halves must exit with.
    code: u8,
}

/// **The local-versus-remote contradiction, one column over.** Every refusal this
/// client makes *about the device* exits with the same code the identical refusal exits
/// with locally.
///
/// The table is deliberately a matched pair per row rather than a mapping: a mapping test
/// pins what `class_of` does with a class it was handed, and the defect was that the
/// remote path handed it the wrong one. Each row runs the same argv twice, once against
/// a scripted bus and once against a scripted daemon, and asserts the two codes together.
/// Before the fix all four remote halves were **4** and all four local halves **1**.
#[test]
fn fe_cli_remote_exit_codes_match_the_local_ones() -> TestResult {
    let scratch = Scratch::new("remote-matched-codes")?;
    let image = scratch.write("fw.bin", b"x")?;
    let image = image.display().to_string();

    let rows = vec![
        Matched {
            what: "an empty bus under -w",
            args: vec!["-w".to_owned(), image.clone()],
            bus: Vec::new(),
            discover: Vec::new(),
            discovers: 1,
            code: DEVICE,
        },
        Matched {
            what: "-i past the end of a one-device bus",
            args: vec!["-b".to_owned(), "-i".to_owned(), "3".to_owned()],
            bus: vec![FakeBackend::bootrom(crate::fake::t31_regs(0x2222_1111))],
            discover: discovered(0, WireVariant(6)),
            discovers: 1,
            code: DEVICE,
        },
        Matched {
            what: "a target that is not a bootrom",
            args: vec!["-b".to_owned()],
            bus: vec![FakeBackend::opaque()],
            // Stage 1 is the wire's "running firmware", the nearest thing the daemon can
            // report to a device the local classifier cannot place: neither is a bootrom
            // and neither may be USB-booted.
            discover: discovered(1, WireVariant(6)),
            discovers: 1,
            code: DEVICE,
        },
        Matched {
            what: "an SoC nothing can identify",
            args: vec!["-b".to_owned()],
            // `cpu_id` 0x9999 is in no family table, so detection refuses; the daemon's
            // equivalent is the `0xFF` ordinal it reports when its own detection did not
            // resolve.
            bus: vec![FakeBackend::bootrom([0x0999_9000, 0, 0])],
            discover: discovered(0, WireVariant::UNKNOWN),
            discovers: settle_polls()? + 1,
            code: DEVICE,
        },
    ];

    for Matched {
        what,
        args,
        bus,
        discover,
        discovers,
        code,
    } in rows
    {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();

        let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discover)]; discovers])?;
        let remote = drive(&plan_for(daemon.port(), &borrowed)?);
        daemon.transcript()?;

        let mut line = vec!["thingino-dfu"];
        line.extend_from_slice(&borrowed);
        let local = drive_on(&FakeBackend::new(bus), &Cli::try_parse_from(line)?.into_plan()?);

        let (remote_message, remote_code) = remote.refusal()?;
        let (local_message, local_code) = local.refusal()?;
        assert_eq!(local_code, code, "{what}, locally: {local_message}");
        assert_eq!(
            remote_code, local_code,
            "{what} exits {remote_code} with --host and {local_code} without: {remote_message}"
        );
    }
    Ok(())
}

/// An empty daemon bus says the same thing an empty local bus says, `--wait` and all.
///
/// The advice was dropped remotely even though `--wait` works there
/// (`fe_cli_wait_polls_the_daemon`), which left the one message that could have told the
/// operator what to do saying only how many devices there were not.
///
/// **The empty bus, third pin.** A bus that is empty on the *first* `DISCOVER` is refused at
/// once, with no wait at all: nothing has been seen mid-boot, so there is nothing to be
/// patient about, and `-w` against an empty bench must not sit there for 30 s before
/// saying so. Only a device already caught between the bootrom and the gadget earns the
/// window.
#[test]
fn an_empty_daemon_bus_carries_the_local_advice() -> TestResult {
    let scratch = Scratch::new("remote-empty-bus")?;
    let image = scratch.write("fw.bin", b"x")?;
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(Vec::new())]])?;
    let plan = plan_for(daemon.port(), &["-w", &image.display().to_string()])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert_eq!(transcript.requests.len(), 1, "one ask, and the answer was the answer");
    assert_eq!(outcome.slept, Vec::new(), "an empty bench is not waited out");
    let (message, code) = outcome.refusal()?;
    assert_eq!(
        message,
        format!(
            "no Ingenic devices on the daemon's bus at 127.0.0.1:{}: {}",
            plan.remote.as_ref().map_or(0, |remote| remote.port),
            crate::target::EMPTY_BUS_ADVICE
        )
    );
    assert!(message.ends_with("or pass --wait"), "{message}");
    assert_eq!(code, DEVICE);
    Ok(())
}

/// An index the daemon has no device for says how many it does have.
#[test]
fn an_index_past_the_end_says_how_many_there_are() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discovered(0, WireVariant(6)))]])?;
    let plan = plan_for(daemon.port(), &["-b", "-i", "3"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.contains("device 3 is not on the daemon's bus") && message.contains("reports 1 device(s)"),
        "{message}"
    );
    assert_eq!(code, DEVICE, "`-i` past the end is a device error locally too");
    Ok(())
}

/// A daemon that cannot say what the SoC is gets a refusal with the two ways out, not a
/// guess: the C's pre-seeded `t31x` ordinal is exactly how a wrong loader gets
/// picked.
///
/// **The second pin on the settle.** The refusal is now made after the window has closed
/// rather than at once, because until it closes "this SoC has no name" and "this SoC is
/// half way into U-Boot and has stopped answering" are the same eight bytes. Held open for
/// the whole window, the answer never changes and the refusal is true.
#[test]
fn an_unknown_soc_refuses_with_the_two_ways_out() -> TestResult {
    let polls = settle_polls()?;
    let daemon = FakeDaemon::start(false, discovered_repeatedly(polls + 1, 0, WireVariant::UNKNOWN))?;
    let plan = plan_for(daemon.port(), &["-b"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(message.contains("does not know what SoC device 0 is"), "{message}");
    assert!(message.contains("pass --cpu"), "{message}");
    assert!(message.contains("--spl and --uboot"), "{message}");
    assert_eq!(
        code, DEVICE,
        "`Error::UnknownSoc` is a device error locally, so this is too"
    );
    assert_eq!(
        transcript.requests.len(),
        polls + 1,
        "the first ask, then one per poll of the window; and no BOOTSTRAP after them"
    );
    assert!(
        transcript
            .requests
            .iter()
            .all(|(command, _)| *command == Command::Discover.wire_byte()),
        "nothing but DISCOVER may go out while the target is unresolved"
    );
    assert_eq!(
        outcome.slept,
        vec![crate::wait::POLL_INTERVAL; polls],
        "the refusal comes after the last poll, not before the first"
    );
    Ok(())
}

/// The settle window is the daemon's, counted in `--wait`'s poll interval.
///
/// `SETTLE_POLLS` is written out rather than divided, so this is what stops the two from
/// drifting: 60 polls of 500 ms is the daemon's 120 probes of 250 ms
/// (`dfu-remote/main.c:344-353`).
#[test]
fn the_settle_window_is_fe_d_1s() -> TestResult {
    let window = crate::wait::POLL_INTERVAL * super::SETTLE_POLLS;
    assert_eq!(
        window,
        crate::wait::REENUM_INTERVAL * u32::try_from(crate::wait::REENUM_ATTEMPTS)?,
        "the client's window and the daemon's are one window"
    );
    assert_eq!(window.as_secs(), 30, "30 s");
    Ok(())
}

/// `--cpu` skips detection, and its value goes on the wire unchanged.
#[test]
fn cpu_skips_the_auto_detect_line() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))],
            vec![Step::Ok(ok())],
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-b", "--cpu", "t41nq"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(!outcome.err.contains("Auto-detected"), "{}", outcome.err);
    let (_, payload) = transcript.requests.get(1).ok_or("no bootstrap")?;
    assert_eq!(payload, &b"\x00\x05t41nq".to_vec());
    Ok(())
}

/// Every `--cpu` value is a name the wire's frozen table carries, so `--cpu` can never
/// produce a variant string the daemon will not recognise.
#[test]
fn every_cpu_value_has_a_wire_name() {
    for variant in tdfu_core::model::Variant::ALL {
        assert!(
            WireVariant::from_name(variant.loader_dir()).is_some(),
            "{} is not in the frozen wire table",
            variant.loader_dir()
        );
    }
}

/// A streamed `--spl` + `--uboot` pair replaces the variant entirely
/// and is sent as the bootstrap command's `[len][blob]` pair.
#[test]
fn custom_loaders_go_on_the_wire_instead_of_a_variant() -> TestResult {
    let scratch = Scratch::new("remote-blobs")?;
    let spl = scratch.write("spl.bin", b"stage-one")?;
    let uboot = scratch.write("u-boot.bin", b"u-boot!")?;
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(discovered(0, WireVariant::UNKNOWN))],
            vec![Step::Ok(ok())],
        ],
    )?;
    let plan = plan_for(
        daemon.port(),
        &[
            "--spl",
            &spl.display().to_string(),
            "--uboot",
            &uboot.display().to_string(),
        ],
    )?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    let mut expected = vec![0_u8, 0];
    expected.extend_from_slice(&9_u32.to_be_bytes());
    expected.extend_from_slice(b"stage-one");
    expected.extend_from_slice(&7_u32.to_be_bytes());
    expected.extend_from_slice(b"u-boot!");
    let (_, payload) = transcript.requests.get(1).ok_or("no bootstrap")?;
    assert_eq!(payload, &expected, "an empty variant, then both blobs");
    assert!(outcome.err.contains("Streaming --spl"), "{}", outcome.err);
    Ok(())
}

// ---------------------------------------------------------------------------
// Authentication.
// ---------------------------------------------------------------------------

/// With `--token`, the handshake goes first and carries the token.
#[test]
fn rpc_auth_handshake_precedes_the_first_command() -> TestResult {
    let daemon = FakeDaemon::start(
        true,
        vec![vec![Step::Ok(ok())], vec![Step::Ok(discovered(0, WireVariant(6)))]],
    )?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "hunter2"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert_eq!(transcript.token.as_deref(), Some(&b"hunter2"[..]));
    assert_eq!(
        transcript.requests.first().map(|(command, _)| *command),
        Some(Command::Discover.wire_byte())
    );
    Ok(())
}

/// **The bug this module's docs open with.** A daemon that drops the connection during
/// the handshake is not an authentication failure, and does not say it is.
///
/// The assertion is the **exact sentence**. It used to be "the message does not
/// contain both `token` and `reject`", which the C's own defect would have passed: the C
/// prints `Auth failed`, containing neither word, so the guard admitted the very
/// behaviour the test is named after.
#[test]
fn an_auth_drop_is_not_an_auth_failure() -> TestResult {
    let daemon = FakeDaemon::start(true, vec![vec![Step::Close]])?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "hunter2"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(code, PROTOCOL);
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} closed the connection during the token handshake",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    Ok(())
}

/// A rejected token quotes the daemon, and a rejection with no payload says the daemon
/// gave no reason.
#[test]
fn a_rejected_token_quotes_the_daemon() -> TestResult {
    let daemon = FakeDaemon::start(true, vec![vec![Step::Fail("auth: invalid token".to_owned())]])?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "wrong"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("rejected the token: auth: invalid token"),
        "{message}"
    );
    assert_eq!(code, PROTOCOL);

    let daemon = FakeDaemon::start(true, vec![vec![Step::Fail(String::new())]])?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "wrong"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;
    let (message, _) = outcome.refusal()?;
    assert!(message.ends_with("rejected the token, and sent no reason"), "{message}");
    Ok(())
}

/// A daemon that *requires* a token, addressed without one, says so
/// and exits 4.
///
/// The daemon reads this client's first command header as the token handshake and
/// answers one of the two frozen auth strings. Read as the device list's own refusal that
/// is `could not complete the device list: auth: invalid token` at exit **1**: a wrapper
/// is told "device error, retry" for something that was never attempted, and the word
/// `--token` never appears.
#[test]
fn a_daemon_that_requires_a_token_says_to_pass_one() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Fail("auth: invalid token".to_owned())]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} requires a token and none was sent: it read the device list's \
             command header as the handshake and answered \"auth: invalid token\". Pass --token with the \
             secret the daemon was started with",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    assert_eq!(code, PROTOCOL, "a failed handshake is 4, not 1");
    Ok(())
}

/// `--token` against a daemon started without one is not a rejected
/// token, and does not say it is.
///
/// That daemon never enters the handshake path, so the handshake bytes are decoded as a
/// command header whose `payload_len` is the token's first four characters, past the cap
/// for any printable token, and the answer is `payload too large`. Reported as
/// `rejected the token: payload too large`, it sends the operator to check a secret that
/// was never read.
#[test]
fn a_token_sent_to_a_daemon_without_one_says_which_side_is_wrong() -> TestResult {
    let daemon = FakeDaemon::start(true, vec![vec![Step::Fail("payload too large".to_owned())]])?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "hunter2"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert_eq!(
        message,
        format!(
            "the daemon at 127.0.0.1:{} answered the token handshake with \"payload too large\", which is not \
             one of the two refusals its auth path can send: it read the handshake as a command header, so it \
             was started without --token. Drop --token, or restart the daemon with one",
            plan.remote.as_ref().map_or(0, |remote| remote.port)
        )
    );
    assert!(
        !message.contains("rejected the token"),
        "no token was rejected: {message}"
    );
    assert_eq!(code, PROTOCOL);
    Ok(())
}

/// An `auth: ` refusal when a token *was* sent is still the daemon's own refusal: the
/// handshake succeeded, so the only thing that can say `auth:` afterwards is the daemon
/// itself, and the "you were addressed without a token" advice would be wrong.
#[test]
fn an_auth_body_after_a_good_handshake_is_the_daemons_refusal() -> TestResult {
    let daemon = FakeDaemon::start(
        true,
        vec![vec![Step::Ok(ok())], vec![Step::Fail("auth: invalid token".to_owned())]],
    )?;
    let plan = plan_for(daemon.port(), &["-l", "--token", "hunter2"])?;
    let outcome = drive(&plan);
    daemon.transcript()?;

    let (message, code) = outcome.refusal()?;
    assert!(
        message.ends_with("could not complete the device list: auth: invalid token"),
        "{message}"
    );
    assert!(!message.contains("Pass --token"), "a token was passed: {message}");
    assert_eq!(code, DEVICE, "the daemon refused a listing, so the listing's class");
    Ok(())
}

/// Without `--token` no handshake is sent at all: a daemon started without one expects
/// none, and would read those six bytes as a command header.
#[test]
fn no_token_means_no_handshake() -> TestResult {
    let daemon = FakeDaemon::start(false, vec![vec![Step::Ok(discovered(0, WireVariant(6)))]])?;
    let plan = plan_for(daemon.port(), &["-l"])?;
    let outcome = drive(&plan);
    // The fake is started *expecting no handshake*, so six stray bytes would land in the
    // request header and it would record `request magic was …`. That note is the
    // assertion here, so it is read explicitly rather than through `transcript()`.
    let transcript = daemon.transcript_raw()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(transcript.trouble.is_empty(), "{:?}", transcript.trouble);
    assert_eq!(transcript.requests.len(), 1, "one command, and nothing before it");
    Ok(())
}

// ---------------------------------------------------------------------------
// `--wait`.
// ---------------------------------------------------------------------------

/// `--wait` polls `CMD_DISCOVER` until the daemon can see something, with the local
/// wait's own two lines. The C accepts the flag in remote mode and drops it.
#[test]
fn fe_cli_wait_polls_the_daemon() -> TestResult {
    let daemon = FakeDaemon::start(
        false,
        vec![
            vec![Step::Ok(Vec::new())],                    // nothing yet
            vec![Step::Ok(Vec::new())],                    // still nothing
            vec![Step::Ok(discovered(0, WireVariant(6)))], // the wait is over
        ],
    )?;
    let plan = plan_for(daemon.port(), &["-l", "--wait"])?;
    let outcome = drive(&plan);
    let transcript = daemon.transcript()?;

    assert!(outcome.result.is_ok(), "{:?}", outcome.refusal());
    assert!(outcome.err.contains(crate::wait::WAITING), "{}", outcome.err);
    assert!(outcome.err.contains(crate::wait::ARRIVED), "{}", outcome.err);
    assert!(outcome.out.contains("Found 1 device"), "{}", outcome.out);
    assert_eq!(
        transcript.requests.len(),
        3,
        "three polls, and `-l` renders the answer the last one already gave"
    );
    // It *waits* between polls. Without this, deleting the sleep leaves three
    // requests and two announcement lines and turns the wait into a hot loop hammering
    // the daemon; the local twin has always asserted the same thing.
    assert_eq!(
        outcome.slept,
        vec![crate::wait::POLL_INTERVAL, crate::wait::POLL_INTERVAL],
        "one poll interval between each pair of polls, and none after the last"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The sweep: nothing exits non-zero in silence.
// ---------------------------------------------------------------------------

/// One case for the sweep below: what it is, what the daemon does, and what was typed.
struct Case {
    /// The failure being provoked.
    what: &'static str,
    /// What the daemon does about it.
    script: Vec<Vec<Step>>,
    /// The arguments after `--host` and `--port`.
    args: Vec<String>,
}

/// Every failure this client can reach says something before it exits.
///
/// An earlier implementation had **two** remote paths that printed nothing at all and
/// exited non-zero. This walks the classes and asserts, for each, that the message `main`
/// prints is not empty and not a bare error kind.
#[test]
fn no_remote_failure_exits_in_silence() -> TestResult {
    let scratch = Scratch::new("remote-silence")?;
    let dump = scratch.path("dump.bin");
    let cases = vec![
        Case {
            what: "a dead socket",
            script: vec![vec![Step::Close]],
            args: vec!["-l".to_owned()],
        },
        Case {
            what: "a refusal",
            script: vec![vec![Step::Fail("Device not found".to_owned())]],
            args: vec!["-l".to_owned()],
        },
        Case {
            what: "an unreadable device list",
            script: vec![vec![Step::Ok(vec![1, 2, 3])]],
            args: vec!["-l".to_owned()],
        },
        Case {
            what: "a truncated read",
            script: vec![
                vec![Step::Ok(discovered(2, WireVariant::UNKNOWN))],
                vec![
                    Step::Header {
                        status: Status::Ok.wire_byte(),
                        len: 1024,
                    },
                    Step::Close,
                ],
            ],
            args: vec!["-r".to_owned(), dump.display().to_string()],
        },
        // A progress frame that does not add up used to be here. It is not a failure any
        // more: the frame is noted and the operation carries on, which
        // `a_bad_progress_frame_does_not_kill_a_completed_transfer` pins instead.
        Case {
            what: "a progress frame whose announced length is impossible",
            script: vec![vec![Step::Header {
                status: Status::Progress.wire_byte(),
                len: 200_000,
            }]],
            args: vec!["-l".to_owned()],
        },
    ];

    for Case { what, script, args } in cases {
        let daemon = FakeDaemon::start(false, script)?;
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let plan = plan_for(daemon.port(), &borrowed)?;
        let outcome = drive(&plan);
        daemon.transcript()?;
        let (message, code) = outcome.refusal()?;
        assert_ne!(code, 0, "{what} must not exit 0");
        assert!(message.len() > 20, "{what} said only {message:?}");
        assert!(
            message.contains("127.0.0.1"),
            "{what} must name the daemon it failed against: {message}"
        );
    }
    Ok(())
}
