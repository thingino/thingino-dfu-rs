//! `CMD_BOOTSTRAP 0x02` — bring a bootrom up as a DFU gadget.
//!
//! Request: `[idx][vlen u8][variant vlen B]`, optionally followed by
//! `[spl_len u32 BE][spl][uboot_len u32 BE][uboot]` — both halves or neither, and either
//! length of zero is an error. Read at `dfu-remote/main.c:359-406`, where
//! `read_be32` (`:293-296`) is the big-endian reader and `:385`/`:393` are the two
//! zero-length refusals. OK payload is the two bytes `"OK"` (`:442`).
//!
//! # This daemon does not wait for the gadget afterwards
//!
//! The bootstrap returns as soon as U-Boot has been started, and
//! the *next* command's 30 s window is what waits for the gadget to enumerate. The C
//! has the same shape — `handle_bootstrap` never calls `dfu_pick_alt` — and it is the
//! right one: the device is gone from the bus for seconds while U-Boot probes MMC and
//! NAND, and a client that wanted to give up in the meantime can.
//!
//! # A variant supplied by the client is never cached
//!
//! The port cache exists so a gadget can report *the SoC that was detected* on its
//! port. A `--cpu` the caller supplied is a claim, not a detection, and feeding it back
//! through `DISCOVER` would republish the caller's guess as this daemon's finding —
//! which is exactly the shape the device list removes from the C. Only a
//! [`Detection::Resolved`] is remembered.

use tdfu_core::clock::Sleeper;
use tdfu_core::model::{Detection, Variant};
use tdfu_core::{Error, loader, ops};
use tdfu_proto::{Blobs, Command};
use tdfu_usb::LocalUsbBackend;

use super::report::{Queue, pump};
use super::state::{Activity, DaemonState, Identity, Port};
use super::{Reply, Wire, device, variant_field};
use crate::errors::{DaemonError, wire_message};

/// Bring the device at `index` up as a gadget.
///
/// # Errors
/// [`DaemonError`] only if the connection failed.
pub async fn handle<W, B, C>(
    conn: &mut W,
    state: &mut DaemonState<B, C>,
    index: u8,
    variant: &[u8],
    blobs: Option<Blobs>,
) -> Result<Reply, DaemonError>
where
    W: Wire,
    B: LocalUsbBackend,
    C: Sleeper,
{
    state.arm();
    let busy = state.busy(Activity::Bootstrapping);
    debug_assert_eq!(busy.activity(), Activity::Bootstrapping);

    // The one command that keeps the refusal: `resolve_images` turns this name
    // into `firmware/dfu/<variant>/…`, so a name with no loader directory is refused here
    // rather than as a missing file.
    let requested = match variant_field(Command::Bootstrap, variant) {
        Ok(requested) => requested,
        Err(error) => return Ok(Reply::Error(wire_message(&error))),
    };

    let row = match state.row(index) {
        Ok(row) => row.clone(),
        Err(error) => return Ok(Reply::failed("bootstrap", &error)),
    };
    let selected = match device::select(&state.backend, index, &row).await {
        Ok(selected) => selected,
        Err(error) => return Ok(Reply::failed("bootstrap", &error)),
    };
    // An audit's finding, on the daemon side. The gadget and the bootrom
    // share `a108:c309`, so a device the descriptors cannot classify is
    // genuinely unknown, and uploading a stage-1 image to one may be uploading it to a
    // device that is mid-flash. The C checks nothing here.
    //
    // It takes the `"bootstrap failed: <class>: <detail>"` shape, which is the point:
    // it used to be a hand-built `format!` with no operation prefix, so one
    // command answered in two shapes for no stated reason. The rule, and it is the C's
    // own split: a refusal **of the payload** is bare, because the C's are
    // (`"payload too short"` `dfu-remote/main.c:360`, `"bad variant length"` `:368`,
    // `"bad SPL override"` `:386`); everything that goes wrong **after the payload
    // parsed**, on the way to or during the work, is `"bootstrap failed: %s"` (`:438`).
    // This check is the second kind. `parse_variant`'s refusal above is the first, and
    // stays bare.
    if !selected.is_bootrom() {
        return Ok(Reply::failed(
            "bootstrap",
            &Error::Invalid(format!(
                "device {index} is {}, and only a device in the bootrom can be bootstrapped",
                selected.describe()
            )),
        ));
    }
    let port = Port::of(&selected.descriptors);
    let identity = Identity::of(&selected.descriptors);

    let device = match state.backend.open(&selected.id).await {
        Ok(device) => device,
        Err(error) => return Ok(Reply::failed("bootstrap", &Error::from(error))),
    };

    // Detection runs only when it has to. Custom blobs skip it *and* the firmware-dir
    // lookup: the caller has said which images to send, so asking the
    // device what it is would spend three transfers to answer a question nobody asked.
    let chosen = match resolve_images(state, &device, requested, blobs).await {
        Ok(chosen) => chosen,
        Err(error) => return Ok(Reply::failed("bootstrap", &error)),
    };
    let Chosen {
        stage1,
        uboot,
        detected,
        caveat,
    } = chosen;

    // The detection's qualification, as a `RESP_LOG` line before the upload starts: an answer that came
    // from a conservative fallback or from a row nobody has run says so, and it says so
    // *here* because the operator watching a remote bootstrap is the person who needs it.
    // An earlier implementation computed this sentence and printed it nowhere (see
    // `Detection::caveat`'s own doc). Logs are attached for `BOOTSTRAP`, so this
    // line is subject to the same gate as everything `pump` sends.
    if let Some(note) = caveat {
        conn.log(&note).await?;
    }

    let queue = Queue::new();
    let outcome = {
        let mut sink = queue.sink();
        pump(
            conn,
            Command::Bootstrap,
            &queue,
            ops::bootstrap(&device, &state.clock, &stage1, &uboot, &mut sink),
        )
        .await?
    };

    match outcome {
        Ok(()) => {
            // The device is on its way back as a DFU gadget with a new device number,
            // and this is the one thing that licenses the identity at that port to
            // change: the daemon asked for it. `DISCOVER` and the transfer commands both
            // read this, so neither has to accept "a gadget turned up somewhere near".
            state.expect_gadget_at(index);
            if let Some(variant) = detected {
                state.variants.put(&port, identity, true, variant);
                tracing::debug!(?variant, port = %port.describe(), "remembered the detected SoC for this port");
            }
            Ok(Reply::ok())
        }
        Err(error) => Ok(Reply::failed("bootstrap", &error)),
    }
}

/// What [`resolve_images`] settled on.
struct Chosen {
    /// The stage-1 image to send.
    stage1: Vec<u8>,
    /// The U-Boot image to send.
    uboot: Vec<u8>,
    /// The variant **detection** settled on, and only a detection: the port cache
    /// holds what this daemon found, never what a caller claimed, so a `--cpu` and a
    /// custom blob pair both leave this `None`.
    detected: Option<Variant>,
    /// The detection's qualification, when it carried one
    /// ([`Detection::caveat`]).
    caveat: Option<String>,
}

/// Check a caller's variant against the silicon that is open, and answer the line to
/// say about it.
///
/// The three reads are [`ops::detect`]'s and upload nothing, so this cannot spend the
/// mask ROM's one shot. Three outcomes:
///
/// * the families disagree: [`Error::Invalid`], before any image is sent, naming both and
///   how to insist (the request's own SPL and U-Boot override, which is the caller
///   saying it owns the images);
/// * the family agrees but the chip does not: a line, because a grade correction is what
///   a caller's variant is for;
/// * nothing could be read, or the `cpu_id` is in no table: a line saying so, and the
///   bootstrap goes ahead, because an operator on a chip detection cannot name is exactly
///   the one who has to supply the name.
///
/// The detection made for the check is returned when it resolved, so the bootstrap can
/// remember the silicon's own answer for the port; the caller's name is never what is
/// remembered, because a claim is not a detection.
async fn family_agrees<C, T>(
    device: &T,
    clock: &C,
    requested: Variant,
) -> Result<(Option<Variant>, Option<String>), Error>
where
    C: Sleeper,
    T: tdfu_usb::LocalUsbTransport,
{
    let detection = match ops::detect(device, clock).await {
        Ok(detection) => detection,
        Err(error) => {
            return Ok((
                None,
                Some(format!(
                    "could not read the SoC registers to check {}: {error}; using the loader you asked for",
                    requested.loader_dir()
                )),
            ));
        }
    };
    let Some(family) = detection.regs().family() else {
        return Ok((
            None,
            Some(format!(
                "this chip's cpu_id is in no table, so {} could not be checked against it; \
                 using the loader you asked for",
                requested.loader_dir()
            )),
        ));
    };
    if family != requested.family() {
        return Err(Error::Invalid(format!(
            "device is a {family:?} and {} is a {:?} loader; its DDR init would run on the wrong \
             controller. Pass the SoC this device really is, or send the SPL and U-Boot images \
             with the request to use them as they are",
            requested.loader_dir(),
            requested.family()
        )));
    }
    match detection {
        Detection::Resolved(resolved) => {
            let caveat = (resolved.variant != requested).then(|| {
                format!(
                    "this chip reads as {} and you asked for {}; both are {family:?}, so the loader you \
                     asked for is being used",
                    resolved.variant.loader_dir(),
                    requested.loader_dir()
                )
            });
            Ok((Some(resolved.variant), caveat))
        }
        _ => Ok((None, None)),
    }
}

/// The images to send, the detection to remember, and the caveat to say out loud.
async fn resolve_images<B, C, T>(
    state: &DaemonState<B, C>,
    device: &T,
    requested: Option<Variant>,
    blobs: Option<Blobs>,
) -> Result<Chosen, Error>
where
    B: LocalUsbBackend,
    C: Sleeper,
    T: tdfu_usb::LocalUsbTransport,
{
    if let Some(Blobs { spl, uboot }) = blobs {
        // An empty half is an error and `tdfu_proto`'s decoder already
        // refuses one, so anything that reaches here has both.
        return Ok(Chosen {
            stage1: spl,
            uboot,
            detected: None,
            caveat: None,
        });
    }
    let (variant, detected, caveat) = if let Some(variant) = requested {
        // A caller's `--cpu` is a claim, and it is checked against the silicon before a
        // DDR init from another family reaches a live bootrom. The check costs three
        // register reads and uploads nothing, and the loader pair is chosen from the
        // caller's name either way: what is refused is a **family** that disagrees,
        // which is the case where the loader configures the wrong DRAM controller and
        // the part never comes up. A grade within the family is exactly what `--cpu` is
        // for, so that disagreement is a line and not a refusal.
        //
        // The detection made for that check is what gets remembered for the port when it
        // resolved, never the caller's name: the gadget this device becomes then reports
        // the silicon's answer, and a client that discovers after its own bootstrap sees
        // the SoC it just flashed rather than "unknown".
        let (detected, caveat) = family_agrees(device, &state.clock, variant).await?;
        (variant, detected, caveat)
    } else {
        {
            let detection = ops::detect(device, &state.clock).await?;
            // The warning goes to the client; a documented-but-unseen row's provenance
            // sentence is a debug line here, as in the CLI and the page (decided
            // 2026-09-03).
            let caveat = detection.warning();
            if caveat.is_none()
                && let Some(provenance) = detection.caveat()
            {
                tracing::debug!("{provenance}");
            }
            match detection {
                Detection::Resolved(resolved) => (resolved.variant, Some(resolved.variant), caveat),
                // `Ambiguous` and `Unknown` both carry the registers and say what to
                // pass, and that whole sentence reaches the wire: it is the named
                // instance of a cause that used to be thrown away.
                Detection::Ambiguous { regs, candidates, .. } => {
                    return Err(Error::Ambiguous { regs, candidates });
                }
                Detection::Unknown { regs } => return Err(Error::UnknownSoc { regs }),
                // `Detection` is `#[non_exhaustive]`: an outcome added later must not
                // silently become a loader choice.
                other => {
                    return Err(Error::Invalid(format!(
                        "detection answered {other:?}, which has no loader rule"
                    )));
                }
            }
        }
    };
    let loaders = loader::resolve(state.firmware_dir(), variant);
    let (stage1, uboot) = loaders.read()?;
    Ok(Chosen {
        stage1,
        uboot,
        detected,
        caveat,
    })
}

#[cfg(test)]
mod tests {

    use crate::commands::fake::{FakeBackend, LoopbackConn, Scratch, Sent, TestResult, t23_regs};
    use crate::commands::fake::{dispatch, seen};
    use crate::commands::state::Window;
    use crate::commands::state::{Activity, DaemonState, Identity, Port};
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::model::Variant;
    use tdfu_proto::{Blobs, Command, Request, Status};
    use tdfu_usb::mock::block_on;

    fn daemon(backend: FakeBackend, root: &std::path::Path) -> DaemonState<FakeBackend, RecordingClock> {
        DaemonState::new(backend, RecordingClock::new(), root).with_window(Window {
            probes: 3,
            interval: core::time::Duration::from_millis(250),
        })
    }

    /// Where every bootrom fixture in this file sits.
    fn bootrom_port() -> Port {
        Port {
            bus: 1,
            path: vec![4, 2],
        }
    }

    /// And what it is, before a bootstrap gives it a new device number.
    fn bootrom_identity() -> Identity {
        Identity {
            address: 7,
            vendor: tdfu_usb::vid::INGENIC,
            product: tdfu_usb::pid::BOOTROM,
        }
    }

    /// The request layout, byte for byte, and its `"OK"` reply.
    ///
    /// `[idx][vlen][variant]` — `dfu-remote/main.c:363-379`. The encoder is
    /// `tdfu_proto`'s, so this fixture is the wire and not a paraphrase of it.
    #[test]
    fn rpc_bootstrap_layout() -> TestResult {
        let scratch = Scratch::new("bootstrap-layout")?;
        scratch.loader_tree(Variant::T23n)?;
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23n".to_vec(),
            blobs: None,
        }
        .encode()?;
        assert_eq!(payload, vec![0x00, 0x04, b't', b'2', b'3', b'n']);

        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// Streamed overrides skip both detection and the firmware directory:
    /// there is no loader tree here at all and the bootstrap still runs.
    #[test]
    fn rpc_bootstrap_streams_custom_blobs() -> TestResult {
        let payload = Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: Some(Blobs {
                spl: b"stage-1".to_vec(),
                uboot: b"u-boot".to_vec(),
            }),
        }
        .encode()?;
        // `[idx][vlen=0][spl_len BE][spl][uboot_len BE][uboot]`.
        assert_eq!(&payload[..2], &[0x00, 0x00]);
        assert_eq!(&payload[2..6], &[0, 0, 0, 7], "spl_len is a big-endian u32");

        // No detect script: streamed images skip the detection entirely, and a scripted
        // double refuses a request that is not the next expectation, so a check that
        // crept onto this path would fail here rather than pass quietly.
        let backend = FakeBackend::new(vec![FakeBackend::bootstrappable_bootrom(
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, std::path::Path::new("/nonexistent-firmware-dir"));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        Ok(())
    }

    /// An auto-detected bootstrap remembers the SoC for the port, so the
    /// gadget it becomes reports it.
    #[test]
    fn an_auto_detected_bootstrap_fills_the_variant_cache() -> TestResult {
        let scratch = Scratch::new("bootstrap-cache")?;
        scratch.loader_tree(Variant::T23n)?;
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(
            state.variants.get(&bootrom_port(), bootrom_identity(), false),
            Some(Variant::T23n)
        );
        Ok(())
    }

    /// ... and a `--cpu` the caller supplied is **not** remembered when nothing could be
    /// detected: a claim is not a detection, and republishing it through `DISCOVER` would
    /// be the C's guess-as-fact with an extra step.
    #[test]
    fn a_client_supplied_variant_is_not_cached() -> TestResult {
        let scratch = Scratch::new("bootstrap-nocache")?;
        scratch.loader_tree(Variant::T23n)?;
        // A bootrom whose cpu_id is in no table: the family check yields a line, the
        // bootstrap goes ahead on the caller's name, and there is nothing to remember.
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            [0x1FFF_F000, 0, 0],
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23n".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(
            state.variants.get(&bootrom_port(), bootrom_identity(), false),
            None,
            "nothing was detected"
        );
        Ok(())
    }

    /// A caller's name is checked against the silicon, and that check *is* a detection:
    /// when it resolves, the port remembers what the chip read as, not what was asked
    /// for, so the gadget it becomes reports the real SoC after the re-enumeration. This
    /// is the path the CLI takes on every remote `-b`: it sends the name `DISCOVER` gave
    /// it, and before this the daemon then reported that same device as "unknown".
    #[test]
    fn a_named_bootstrap_remembers_the_silicon_not_the_claim() -> TestResult {
        let scratch = Scratch::new("bootstrap-named-cache")?;
        scratch.loader_tree(Variant::T23x)?;
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23x".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(
            state.variants.get(&bootrom_port(), bootrom_identity(), false),
            Some(Variant::T23n),
            "the silicon's answer, not the caller's t23x"
        );
        Ok(())
    }

    /// **A caller's variant from another family is refused, and nothing is uploaded.**
    ///
    /// A wrong `--cpu` sends another family's DDR init to a live bootrom: the part does
    /// not come up, and the next command spends its whole window before saying `Device
    /// not found`, which points the operator at the cable. The check is three register
    /// reads on the device that is already open.
    #[test]
    fn a_variant_from_another_family_is_refused() -> TestResult {
        let scratch = Scratch::new("bootstrap-wrong-family")?;
        scratch.loader_tree(Variant::T31x)?;
        // A T23 answering, told it is a T31X.
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t31x".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        let message = conn
            .error_text()
            .ok_or("a loader from another family must be refused")?;
        assert!(
            message.starts_with("bootstrap failed: Invalid parameter: "),
            "{message}"
        );
        assert!(message.contains("T23"), "it names the silicon: {message}");
        assert!(message.contains("t31x"), "and the loader asked for: {message}");
        assert!(message.contains("SPL and U-Boot images"), "and the override: {message}");
        // Nothing was uploaded: the scripted double would have taken the stage-1 write.
        assert_eq!(state.activity(), Activity::Idle);
        Ok(())
    }

    /// ... and a variant from the **same** family is used, with a line saying the chip
    /// reads as something else. A grade correction is what a caller's `--cpu` is for.
    #[test]
    fn a_variant_within_the_family_is_used_and_said_out_loud() -> TestResult {
        let scratch = Scratch::new("bootstrap-same-family")?;
        scratch.loader_tree(Variant::T23dl)?;
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23dl".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(
            conn.response(),
            Some((Status::Ok, b"OK".to_vec())),
            "{:?}",
            conn.error_text()
        );
        Ok(())
    }

    /// The named instance of a cause kept rather than dropped: a bootstrap of a chip
    /// detection cannot name says so, with the registers and what to pass.
    #[test]
    fn an_undetectable_soc_says_what_to_pass() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom([0x0000_0099, 0, 0])]);
        let mut state = daemon(backend, std::path::Path::new("firmware"));
        let payload = Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        let message = conn.error_text().ok_or("an undetectable SoC must be refused")?;
        assert!(
            message.starts_with("bootstrap failed: Invalid parameter: "),
            "{message}"
        );
        assert!(message.contains("0x00000099"), "the soc_id must survive: {message}");
        assert!(message.contains("--cpu"), "{message}");
        assert!(message.contains("--spl"), "{message}");
        Ok(())
    }

    /// A missing loader file names the path: the third of the four causes an earlier
    /// implementation discarded.
    #[test]
    fn a_missing_loader_names_the_file() -> TestResult {
        let scratch = Scratch::new("bootstrap-noloader")?;
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t23_regs())]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23n".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        let message = conn.error_text().ok_or("a missing loader must be refused")?;
        assert!(message.starts_with("bootstrap failed: File I/O error: "), "{message}");
        assert!(message.contains("t23n"), "{message}");
        Ok(())
    }

    /// A gadget, and a device that classifies as nothing, are both refused
    /// rather than uploaded to. The C checks neither.
    ///
    /// The shape is the one every other post-payload bootstrap failure uses,
    /// `"bootstrap failed: <class>: <detail>"`; the argument for the split
    /// between this and the bare payload refusals is at the check.
    #[test]
    fn only_a_bootrom_is_bootstrapped() -> TestResult {
        for (row, expected) in [
            (FakeBackend::gadget(), "a U-Boot DFU gadget"),
            (FakeBackend::opaque(), "of an unrecognised kind"),
        ] {
            let backend = FakeBackend::new(vec![row]);
            let mut state = daemon(backend, std::path::Path::new("firmware"));
            let payload = Request::Bootstrap {
                index: 0,
                variant: b"t23n".to_vec(),
                blobs: None,
            }
            .encode()?;
            block_on(seen(&mut state))?;
            let mut conn = LoopbackConn::raw();
            block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
            let message = conn.error_text().ok_or("must be refused")?;
            assert!(
                message.starts_with("bootstrap failed: Invalid parameter: "),
                "{message}"
            );
            assert!(message.contains(expected), "{message}");
            assert!(state.backend.opened().is_empty(), "and nothing was opened");
        }
        Ok(())
    }

    /// **The gate's other side: `BOOTSTRAP` keeps the refusal.**
    ///
    /// `web/src/app.js:1299` sends `detectedVariantName` here as it does on READ and
    /// WRITE, and this is the one command where an unrecognised name has somewhere to
    /// go: `resolve_images` would look for `firmware/dfu/unknown/`. It does not arise
    /// from the same bench state either. DISCOVER *detects* a bootrom
    /// (`discover.rs:97`) and only reads a gadget's answer out of the port cache
    /// (`:101`), so the `0xFF` that renders as `"unknown"` reaches BOOTSTRAP only when
    /// detection itself did not settle, and then there is no loader to pick. The refusal
    /// says so and says what to pass; the payload is built the browser's way
    /// (`remote.js:201-208`).
    #[test]
    fn rpc_24_bootstrap_still_refuses_an_unknown_variant() -> TestResult {
        let mut payload = vec![0x00_u8, 0x07];
        payload.extend_from_slice(b"unknown");
        assert_eq!(payload, b"\x00\x07unknown".to_vec());

        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, std::path::Path::new("firmware"));
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        let message = conn.error_text().ok_or("a nameless loader must be refused")?;
        assert!(message.contains("unknown variant"), "{message}");
        assert!(message.contains("auto-detect"), "and what to do instead: {message}");
        assert!(state.backend.opened().is_empty(), "and nothing was opened");
        Ok(())
    }

    /// The error wordings for a payload that does not add up, produced by
    /// `tdfu_proto`'s decoder and passed through unchanged.
    #[test]
    fn rpc_bootstrap_payload_refusals() -> TestResult {
        for (payload, expected) in [
            (vec![0x00], "payload too short"),
            (vec![0x00, 0x09, b'x'], "bad variant length"),
            // `[idx][vlen=0][spl_len=0]` — a zero-length half is refused.
            (vec![0x00, 0x00, 0, 0, 0, 0], "bad SPL override"),
            (vec![0x00, 0x00, 0, 0, 0, 1, b'a', 0, 0, 0, 0], "bad U-Boot override"),
        ] {
            let mut conn = LoopbackConn::raw();
            let mut state = daemon(FakeBackend::empty(), std::path::Path::new("firmware"));
            block_on(seen(&mut state))?;
            block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
            assert_eq!(
                conn.sent(),
                vec![Sent::Response(Status::Error, expected.as_bytes().to_vec())],
                "{payload:02X?}"
            );
        }
        Ok(())
    }

    /// `BOOTSTRAP` attaches a log client, so core's notes reach the client.
    #[test]
    fn bootstrap_forwards_the_progress_it_produces() -> TestResult {
        let scratch = Scratch::new("bootstrap-logs")?;
        scratch.loader_tree(Variant::T23n)?;
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23n".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;

        // The upload's two phases, as progress frames.
        let stages: Vec<u8> = conn.progress_frames().iter().map(|body| body.stage).collect();
        assert!(stages.contains(&1), "stage1: {stages:?}");
        assert!(stages.contains(&2), "u-boot: {stages:?}");
        // And core's own note, as a log line.
        assert!(
            conn.log_lines().iter().any(|line| line.contains("re-enumerate")),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }

    /// **The detection's caveat leaves the daemon.**
    ///
    /// Both branches, driven through a whole `CMD_BOOTSTRAP` rather than asserted on the
    /// producer, because the finding was that the daemon computed the sentence and sent
    /// it nowhere. `t23_regs()` is `sub1 = 0`, a grade in no row of the T23 table, so
    /// detection falls back to `T23`'s conservative loader with `Evidence::Convention`
    /// and **must say so**; the bench T23N grade `0x1111` (`detect/mod.rs:336`, the
    /// 2026-08-22 capture) is `Evidence::Bench` and must say nothing.
    #[test]
    fn det_11b_the_caveat_reaches_the_client() -> TestResult {
        let scratch = Scratch::new("bootstrap-caveat")?;
        scratch.loader_tree(Variant::T23n)?;
        let payload = Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: None,
        }
        .encode()?;

        // A grade the table does not have: the loader is the family's fallback.
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        let lines = conn.log_lines();
        let caveat = lines
            .iter()
            .find(|line| line.contains("is not in the table"))
            .ok_or("the fallback must say it is a fallback")?;
        assert!(caveat.contains("t23n"), "and which loader it used: {caveat}");
        // It leads: the operator sees the qualification before the upload it qualifies.
        assert_eq!(lines.first(), Some(caveat), "{lines:?}");

        // A grade that *is* a bench row says nothing extra.
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            [0x1002_3000, 0x1111_1111, 0],
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let mut bench = LoopbackConn::raw();
        block_on(seen(&mut state))?;
        block_on(dispatch(&mut bench, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(bench.response(), Some((Status::Ok, b"OK".to_vec())));
        assert_eq!(
            state.variants.get(&bootrom_port(), bootrom_identity(), false),
            Some(Variant::T23n),
            "it did detect"
        );
        assert!(
            !bench.log_lines().iter().any(|line| line.contains("not in the table")),
            "a bench row needs no caveat: {:?}",
            bench.log_lines()
        );
        Ok(())
    }

    /// ... and a `--cpu` the caller supplied carries no caveat either: a caveat
    /// qualifies a detection, and a claim is not one.
    #[test]
    fn det_11b_a_supplied_variant_has_nothing_to_qualify() -> TestResult {
        let scratch = Scratch::new("bootstrap-nocaveat")?;
        scratch.loader_tree(Variant::T23n)?;
        let backend = FakeBackend::new(vec![FakeBackend::detectable_bootstrappable_bootrom(
            t23_regs(),
            b"stage-1".to_vec(),
            b"u-boot".to_vec(),
        )]);
        let mut state = daemon(backend, scratch.root());
        let payload = Request::Bootstrap {
            index: 0,
            variant: b"t23n".to_vec(),
            blobs: None,
        }
        .encode()?;
        block_on(seen(&mut state))?;
        let mut conn = LoopbackConn::raw();
        block_on(dispatch(&mut conn, &mut state, Command::Bootstrap, &payload))?;
        assert_eq!(conn.response(), Some((Status::Ok, b"OK".to_vec())));
        assert!(
            !conn.log_lines().iter().any(|line| line.contains("not in the table")),
            "{:?}",
            conn.log_lines()
        );
        Ok(())
    }
}
