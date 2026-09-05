//! `-l`: what is on the bus, and what each device is.
//!
//! Generic over [`LocalUsbBackend`] and [`Sleeper`], with **no mention of the native
//! backend anywhere in this file**. An earlier implementation hard-wired `NativeBackend`
//! into `main`, which put the whole list path behind a real USB bus and left `main.rs` at
//! 6% coverage. Here the backend is a parameter, so every rule
//! below is pinned against a scripted double.
//!
//! # What it does to a device, and what it does not
//!
//! * A **bootrom** is opened and identified: [`ops::detect`] claims the interface, reads
//!   three registers at kseg1 addresses, decodes them and releases on every path.
//!   Nothing is uploaded and nothing is executed, so the mask ROM's one-shot
//!   `PROG_STAGE1` is still there afterwards and a real `-b` on the same unit works.
//! * A **DFU gadget** is reported as a gadget and nothing else. It is not opened, not
//!   probed and not reset. The reset is the reason: `ops::probe` recovers a
//!   wedged gadget by resetting it (`dfu.c:501-508`), which is not something a *listing*
//!   may do to a device somebody else is flashing.
//! * **No variant is invented for a gadget.** The C pre-seeds `TDFU_VARIANT_T31X` before
//!   detection (`cli/main.c:213`) and its daemon sends ordinal 6 for an unknown gadget —
//!   a guess rendered as a fact, which the CLI would then hand back as a `--cpu` value
//!   over the wire. The column reads `-`.
//! * **A device that will not open is still listed.** One `AccessDenied` must not empty
//!   the table: the row keeps its VID:PID and carries the hint. The C behaves the same
//!   way by accident — its detection loop simply skips a device it cannot open
//!   (`cli/main.c:210-219`) — and here it is the point.

use tdfu_core::clock::Sleeper;
use tdfu_core::model::{Detection, Stage};
use tdfu_core::{Error, Result, ops};
use tdfu_usb::{DeviceDescriptors, LocalUsbBackend, UsbError, UsbErrorKind};

/// Everything `-l` found, in bus order.
///
/// The index of a row is its position here, and it is the number `-i` will select
/// (a leftover gadget from another unit steals index 0, which is a fact
/// the operator has to respect rather than something the host can fix).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listing {
    /// One entry per Ingenic device on the bus.
    pub rows: Vec<Row>,
}

impl Listing {
    /// Nothing on the bus. Not an error (see [`list`]).
    #[must_use]
    pub const fn empty() -> Self {
        Self { rows: Vec::new() }
    }

    /// Were there no Ingenic devices at all?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// One device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Row {
    /// Position in the listing — the number `-i` takes.
    pub index: usize,
    /// What enumeration knows: VID, PID, bus, address, port path.
    pub descriptors: DeviceDescriptors,
    /// Bootrom, gadget or firmware, from the **descriptor**, never the PID (the two
    /// share one). `None` means an Ingenic VID this tool has no rule for, which is worth
    /// showing rather than hiding.
    pub stage: Option<Stage>,
    /// What the SoC is, where asking was appropriate and possible.
    pub soc: Soc,
}

/// The identity of the chip behind a row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Soc {
    /// Not a bootrom, so there is nothing to ask and nothing is guessed.
    NotProbed,
    /// Detection ran. `Ambiguous` and `Unknown` are answers, not failures.
    Detected(Detection),
    /// The device could not be opened, or the registers could not be read.
    Unavailable(Unavailable),
}

/// Why a bootrom could not be identified, and what to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unavailable {
    /// What went wrong, in the words of whatever produced it. Never flattened: a
    /// dropped device and a refused open send users to different places, and an earlier
    /// implementation collapsed both under one message.
    pub reason: String,
    /// The fix, where there is a known one. `None` when there is nothing to add.
    pub hint: Option<&'static str>,
}

/// Enumerate every Ingenic device and identify the ones in the bootrom.
///
/// Zero devices is an empty [`Listing`] and **not** an error: the C prints `No Ingenic
/// devices found`, returns `TDFU_SUCCESS` (`cli/main.c:205-208`) and its `main` turns
/// that into exit **0** (`cli/main.c:495`). Same semantics here; the wording is ours
/// ([`render`](crate::render)).
///
/// # Errors
/// Only a failure of enumeration itself — [`Error::Usb`]. Per-device failures never
/// propagate; they become [`Soc::Unavailable`] on their own row, because a table that
/// vanishes because one device is claimed by another process is useless exactly when it
/// is needed.
pub async fn list<B, C>(backend: &B, clock: &C) -> Result<Listing>
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    let discovered = backend.list().await?;
    tracing::debug!(devices = discovered.len(), "enumerated Ingenic devices");

    let mut rows = Vec::with_capacity(discovered.len());
    for (index, device) in discovered.into_iter().enumerate() {
        // Descriptor-first. The gadget shares the bootrom's PID `0xC309`
        // since 2026-07-24, so a PID check reports "bootrom" for every current gadget.
        let stage = ops::classify(&device.descriptors);
        tracing::debug!(
            index,
            vendor = format_args!("{:04x}", device.descriptors.vendor_id),
            product = format_args!("{:04x}", device.descriptors.product_id),
            ?stage,
            "classified"
        );

        let soc = match stage {
            Some(Stage::Bootrom) => identify(backend, clock, &device.id).await,
            // A gadget, a firmware-stage device, an Ingenic VID with no rule, or a
            // stage added to the model later: nothing to ask, and nothing invented.
            // The wildcard is required because `Stage` is `#[non_exhaustive]`, and it
            // is the right default — a new stage must opt *in* to being opened.
            _ => Soc::NotProbed,
        };

        rows.push(Row {
            index,
            descriptors: device.descriptors,
            stage,
            soc,
        });
    }
    Ok(Listing { rows })
}

/// Open one bootrom and read its registers, turning any failure into a row that still
/// prints.
async fn identify<B, C>(backend: &B, clock: &C, id: &B::DeviceId) -> Soc
where
    B: LocalUsbBackend,
    C: Sleeper,
{
    let device = match backend.open(id).await {
        Ok(device) => device,
        Err(error) => {
            tracing::debug!(%error, "could not open a bootrom");
            return Soc::Unavailable(Unavailable::from_usb(&error));
        }
    };

    // `ops::detect` owns the claim and releases on every path, so there
    // is deliberately no second claim here: an extra `claim_interface` around it would
    // re-issue exactly the redundant request the differential USB capture flagged.
    match ops::detect(&device, clock).await {
        Ok(detection) => {
            tracing::debug!(regs = ?detection.regs(), "identified");
            Soc::Detected(detection)
        }
        Err(error) => {
            tracing::debug!(%error, "could not identify a bootrom");
            Soc::Unavailable(Unavailable::from_core(&error))
        }
    }
}

impl Unavailable {
    /// A failure to open.
    fn from_usb(error: &UsbError) -> Self {
        Self {
            reason: error.to_string(),
            hint: access_denied_hint(error.kind()),
        }
    }

    /// A failure once open.
    fn from_core(error: &Error) -> Self {
        let hint = match error {
            Error::Usb(usb) => access_denied_hint(usb.kind()),
            _ => None,
        };
        Self {
            reason: error.to_string(),
            hint,
        }
    }
}

/// The one wording of the udev/driver fix, printed **once**, for the one error that has
/// a fix.
///
/// The hint is a native-backend constant rather than error text,
/// and an earlier implementation printed the same advice twice in two wordings, one of
/// them carrying a 14-space gap from a string join. Reading it from
/// `tdfu_usb::native` keeps one copy, per platform.
///
/// No `cfg` for a browser build: this crate is native by construction — `main.rs` names
/// [`NativeBackend`](tdfu_usb::native::NativeBackend), which does not exist on wasm — so
/// a wasm arm here would be unreachable code that no test could falsify. Mutation
/// testing found exactly that and it was deleted rather than kept "just in case".
fn access_denied_hint(kind: &UsbErrorKind) -> Option<&'static str> {
    matches!(kind, UsbErrorKind::AccessDenied).then_some(tdfu_usb::native::ACCESS_DENIED_HINT)
}

#[cfg(test)]
mod tests {
    use super::{Listing, Soc, list};
    use crate::fake::{FakeBackend, TestResult, bootrom_descriptors, gadget_descriptors, t31_regs};
    use tdfu_core::clock::RecordingClock;
    use tdfu_core::model::{Detection, Stage};
    use tdfu_usb::mock::block_on;
    use tdfu_usb::{UsbError, UsbErrorKind};

    /// An empty bus is an empty listing, not an error.
    #[test]
    fn an_empty_bus_is_not_a_failure() -> TestResult {
        let backend = FakeBackend::new(Vec::new());
        let listing = block_on(list(&backend, &RecordingClock::new()))?;
        assert_eq!(listing, Listing::empty());
        assert!(listing.is_empty());
        Ok(())
    }

    /// A bootrom is opened and identified; a gadget is not touched at all.
    ///
    /// This is the rule in the form this crate can assert: the listing never
    /// probes a gadget, so it can never issue `ops::probe`'s recovery reset on one.
    #[test]
    fn fe_cli_list_never_opens_a_gadget() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111)), FakeBackend::gadget()]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;

        assert_eq!(listing.rows.len(), 2);
        assert_eq!(listing.rows[0].stage, Some(Stage::Bootrom));
        assert_eq!(listing.rows[1].stage, Some(Stage::Gadget));
        assert_eq!(listing.rows[1].soc, Soc::NotProbed, "a gadget invents no variant");
        assert_eq!(backend.opened(), vec![0], "only the bootrom was opened");

        let Soc::Detected(Detection::Resolved(resolved)) = &listing.rows[0].soc else {
            assert_eq!(format!("{:?}", listing.rows[0].soc), "Detected(Resolved(..))");
            return Ok(());
        };
        assert_eq!(resolved.chip, "T31X");
        Ok(())
    }

    /// One device that will not open must not empty the table.
    #[test]
    fn a_refused_device_still_gets_a_row() -> TestResult {
        let denied = UsbError::new(UsbErrorKind::AccessDenied, tdfu_usb::Pipe::Device);
        let backend = FakeBackend::new(vec![
            FakeBackend::refusing(bootrom_descriptors(1, 7), denied),
            FakeBackend::bootrom(t31_regs(0x2222_1111)),
        ]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;

        assert_eq!(listing.rows.len(), 2, "the refusal must not hide the second device");
        let Soc::Unavailable(unavailable) = &listing.rows[0].soc else {
            assert_eq!(format!("{:?}", listing.rows[0].soc), "Unavailable(..)");
            return Ok(());
        };
        assert!(unavailable.hint.is_some(), "AccessDenied is the error that has a fix");
        assert!(unavailable.reason.contains("access"), "{}", unavailable.reason);

        // The row it did not stop still carries its identity.
        assert_eq!(listing.rows[1].descriptors.vendor_id, tdfu_usb::vid::INGENIC);
        Ok(())
    }

    /// A claim refused **after** a successful open still carries the hint.
    ///
    /// The two failure paths differ: `open` returning `AccessDenied` goes through
    /// `Unavailable::from_usb`, while a claim refused inside `ops::detect` arrives as
    /// `Error::Usb` and goes through `from_core`. Both must offer the fix; only the
    /// first was covered until mutation testing deleted the `Error::Usb` arm and
    /// nothing failed.
    #[test]
    fn a_claim_refused_after_opening_still_carries_the_hint() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::unclaimable_bootrom()]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;

        let Soc::Unavailable(unavailable) = &listing.rows[0].soc else {
            assert_eq!(format!("{:?}", listing.rows[0].soc), "Unavailable(..)");
            return Ok(());
        };
        assert_eq!(unavailable.hint, Some(tdfu_usb::native::ACCESS_DENIED_HINT));
        Ok(())
    }

    /// A register read that fails leaves a row that says so, with no hint to offer.
    #[test]
    fn a_bootrom_that_will_not_answer_still_gets_a_row() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::mute_bootrom()]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;

        let Soc::Unavailable(unavailable) = &listing.rows[0].soc else {
            assert_eq!(format!("{:?}", listing.rows[0].soc), "Unavailable(..)");
            return Ok(());
        };
        assert!(
            unavailable.reason.contains("soc_id"),
            "the failure must name the register: {}",
            unavailable.reason
        );
        assert_eq!(unavailable.hint, None);
        Ok(())
    }

    /// Enumeration itself failing is the one thing that *is* an error.
    #[test]
    fn a_failed_enumeration_propagates() {
        let backend = FakeBackend::failing(UsbError::new(
            UsbErrorKind::Backend("sysfs is unreadable".into()),
            tdfu_usb::Pipe::Device,
        ));
        let outcome = block_on(list(&backend, &RecordingClock::new()));
        assert!(outcome.is_err(), "a bus that cannot be listed is a failure");
    }

    /// An Ingenic VID with no classification rule is listed, not hidden.
    #[test]
    fn an_unclassifiable_ingenic_device_is_still_shown() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::opaque()]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;
        assert_eq!(listing.rows.len(), 1);
        assert_eq!(listing.rows[0].stage, None);
        assert_eq!(listing.rows[0].soc, Soc::NotProbed);
        assert_eq!(
            backend.opened(),
            Vec::<usize>::new(),
            "nothing to ask, so nothing opened"
        );
        Ok(())
    }

    /// **Both** Ingenic vendor IDs reach the table.
    ///
    /// The VID filter is the backend's — `NativeBackend::list` applies
    /// `vid::is_ingenic`, which is `0xA108` **or** `0x601A` — and this asserts that the
    /// CLI adds no narrower one of its own. It deliberately does not assert the row's
    /// stage: classification is core's answer, and this test is about the vendor ID.
    #[test]
    fn disc_both_ingenic_vids_reach_the_table() -> TestResult {
        let backend = FakeBackend::new(vec![
            FakeBackend::bootrom(t31_regs(0x2222_1111)),
            FakeBackend::x_series(),
        ]);
        let listing = block_on(list(&backend, &RecordingClock::new()))?;

        let vendors: Vec<u16> = listing.rows.iter().map(|row| row.descriptors.vendor_id).collect();
        assert_eq!(vendors, vec![tdfu_usb::vid::INGENIC, tdfu_usb::vid::INGENIC_X]);
        Ok(())
    }

    /// The gadget descriptors the fake serves really do classify as a gadget, so the
    /// test above is not passing because `classify` failed.
    #[test]
    fn the_fake_gadget_is_a_gadget() {
        assert_eq!(tdfu_core::ops::classify(&gadget_descriptors(1, 9)), Some(Stage::Gadget));
    }
}
