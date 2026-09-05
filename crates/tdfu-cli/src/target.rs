//! Which device `-i` names, and what stage it is in.
//!
//! Enumeration only: no open, no claim, no probe, so selecting a target
//! cannot disturb a device another agent is flashing.
//!
//! # An unclassifiable device is never bootstrap-eligible
//!
//! `ops::classify` answers `None` when the descriptors carry no evidence either way —
//! an empty configuration descriptor, which `NativeBackend::list` documents producing on
//! a failed read. The gadget and the bootrom **share** `a108:c309`, so
//! "unknown" there is genuinely unknown, and treating it as a bootrom would upload a
//! stage-1 image to a device that may be mid-flash. An audit found exactly that
//! misclassification in `classify` and fixed it, and carried the frontend half here:
//! *render an unclassifiable device as unknown, never bootstrap-eligible*.

use tdfu_core::model::Stage;
use tdfu_core::{Error, Result, ops};
use tdfu_usb::{DeviceDescriptors, LocalUsbBackend};

/// What to do about a bus with no Ingenic device on it.
///
/// Shared with [`remote`](crate::remote), whose `entry` says the same thing about a
/// daemon's bus: an empty bus is one fault, `--wait` works on both paths,
/// and an operator reading one message and then the other must not be told two different
/// things. A constant rather than two literals, so the advice cannot drift.
pub const EMPTY_BUS_ADVICE: &str = "power-cycle the camera into the bootrom, or pass --wait";

/// What is said when the device's USB port path came back empty.
///
/// The port path is what [`find_gadget`] matches a re-enumerated device on, and it is
/// read once, before the bootstrap. When it is empty the gadget that comes up cannot be
/// told from any other gadget already on the bus, so the operator is given the two ways
/// to get an identifiable target back rather than a device chosen by bus order.
pub const UNREADABLE_PORT: &str = "the device's USB port path could not be read, so the DFU gadget it \
     re-enumerates as cannot be told apart from any other gadget on the bus: replug the camera and run \
     this again, or, once it is a U-Boot DFU gadget, name it with -i from the -l listing";

/// The device an operation will run against.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Selected<Id> {
    /// The `-i` number, which is the row's position in the listing.
    pub index: u8,
    /// The backend's handle, for [`open`](LocalUsbBackend::open).
    pub id: Id,
    /// What enumeration knows about it.
    pub descriptors: DeviceDescriptors,
    /// Bootrom, gadget, firmware — or `None` for "this cannot be told from the
    /// descriptors", which is never treated as a bootrom.
    pub stage: Option<Stage>,
}

impl<Id> Selected<Id> {
    /// May a bootstrap run against this device?
    ///
    /// Only a bootrom. A gadget is already what a bootstrap would produce; anything else
    /// — vendor firmware, or a device that cannot be classified — is a device this tool
    /// must not upload to.
    #[must_use]
    pub fn is_bootrom(&self) -> bool {
        self.stage == Some(Stage::Bootrom)
    }

    /// Is this the U-Boot DFU gadget every transfer needs?
    #[must_use]
    pub fn is_gadget(&self) -> bool {
        self.stage == Some(Stage::Gadget)
    }

    /// How to describe it in a refusal.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self.stage {
            Some(Stage::Bootrom) => "in the bootrom",
            Some(Stage::Gadget) => "a U-Boot DFU gadget",
            Some(Stage::Firmware) => "running vendor firmware",
            // `Stage` is `#[non_exhaustive]`; a stage added later must opt in to a
            // description rather than inherit a wrong one.
            _ => "of an unrecognised kind",
        }
    }
}

/// Pick the device `-i` names.
///
/// # Errors
/// [`Error::Usb`] if the bus cannot be enumerated; [`Error::Invalid`] when the index is
/// past the end of the listing, naming how many devices there actually are — the number
/// the operator needs in order to fix it.
pub async fn select<B: LocalUsbBackend>(backend: &B, index: u8) -> Result<Selected<B::DeviceId>> {
    let listing = backend.list().await?;
    let Some(device) = listing.get(usize::from(index)) else {
        return Err(Error::Invalid(match listing.len() {
            0 => format!("no Ingenic devices on the bus: {EMPTY_BUS_ADVICE}"),
            1 => format!("-i {index}: there is 1 Ingenic device, index 0"),
            count => format!("-i {index}: there are {count} Ingenic devices, indexes 0-{}", count - 1),
        }));
    };
    let stage = ops::classify(&device.descriptors);
    tracing::debug!(index, ?stage, "selected the target device");
    Ok(Selected {
        index,
        id: device.id.clone(),
        descriptors: device.descriptors.clone(),
        stage,
    })
}

/// Find the device that re-enumerated on `port_path`, whatever index it landed on.
///
/// The physical port path is the one identifier that survives the
/// bootrom → gadget re-enumeration: the VID and PID are unchanged, the bus
/// address is not, and the *index* is not either — a device that re-enumerates can move
/// in the listing, so re-using `-i` after a bootstrap can target a different camera. The
/// daemon keys its variant cache the same way.
///
/// # An unreadable port is refused, not guessed at
///
/// An empty `port_path` is not "this platform has no idea of ports": on the backends
/// this binary runs on it means *the platform's location lookup failed for this
/// device*. Linux always has the sysfs `devpath`, macOS always has a `locationID`, and
/// Windows leaves the path empty when `DEVPKEY_Device_LocationPaths` is missing or does
/// not parse. Taking the first gadget in bus order then is the wrong-camera failure the
/// `Port` column exists to prevent: a camera another run left sitting in the gadget
/// would take the transfer. So the empty case refuses and says how to get an
/// identifiable target back.
///
/// # Errors
/// [`Error::Usb`] if the bus cannot be enumerated; [`Error::Invalid`] when `port_path`
/// is empty, because no gadget on the bus can be told from any other.
pub async fn find_gadget<B: LocalUsbBackend>(backend: &B, port_path: &[u8]) -> Result<Option<Selected<B::DeviceId>>> {
    if port_path.is_empty() {
        return Err(Error::Invalid(UNREADABLE_PORT.to_owned()));
    }
    let listing = backend.list().await?;
    for (position, device) in listing.iter().enumerate() {
        if ops::classify(&device.descriptors) != Some(Stage::Gadget) {
            continue;
        }
        if device.descriptors.port_path != port_path {
            continue;
        }
        // The listing is at most 256 entries in practice and `-i` is a byte, so a
        // position past 255 has no `-i` that can name it; report it as the last
        // addressable index rather than wrapping onto device 0 the way the C's cast
        // does. An audit kept that difference from the C on purpose.
        let index = u8::try_from(position).unwrap_or(u8::MAX);
        return Ok(Some(Selected {
            index,
            id: device.id.clone(),
            descriptors: device.descriptors.clone(),
            stage: Some(Stage::Gadget),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{find_gadget, select};
    use crate::fake::{FakeBackend, TestResult, t31_regs};
    use tdfu_core::Error;
    use tdfu_core::model::Stage;
    use tdfu_usb::mock::block_on;

    #[test]
    fn the_index_picks_its_row() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::gadget(), FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        let first = block_on(select(&backend, 0))?;
        assert_eq!(first.index, 0);
        assert!(first.is_gadget());
        assert!(!first.is_bootrom());

        let second = block_on(select(&backend, 1))?;
        assert_eq!(second.id, 1);
        assert!(second.is_bootrom());
        assert_eq!(second.describe(), "in the bootrom");

        assert_eq!(backend.opened(), Vec::<usize>::new(), "selection opens nothing");
        Ok(())
    }

    /// An index past the end says how many there are.
    #[test]
    fn an_index_past_the_end_says_what_is_there() -> TestResult {
        let two = FakeBackend::new(vec![FakeBackend::gadget(), FakeBackend::gadget()]);
        let Err(Error::Invalid(message)) = block_on(select(&two, 5)) else {
            return Err("-i 5 against two devices must be refused".into());
        };
        assert!(
            message.contains("there are 2 Ingenic devices, indexes 0-1"),
            "{message}"
        );

        let one = FakeBackend::new(vec![FakeBackend::gadget()]);
        let Err(Error::Invalid(single)) = block_on(select(&one, 1)) else {
            return Err("-i 1 against one device must be refused".into());
        };
        assert!(single.contains("there is 1 Ingenic device, index 0"), "{single}");

        let none = FakeBackend::new(Vec::new());
        let Err(Error::Invalid(empty)) = block_on(select(&none, 0)) else {
            return Err("an empty bus has no device 0".into());
        };
        assert!(empty.contains("no Ingenic devices on the bus"), "{empty}");
        Ok(())
    }

    /// Every stage has its own phrase, including the firmware one.
    ///
    /// The refusals in [`run`](crate::run) and in [`remote`](crate::remote) both read
    /// this, and "running vendor firmware" is the case that decides whether an operator
    /// power-cycles the camera or goes looking for a cable: folding it into "of an
    /// unrecognised kind" was a mutation the suite did not notice, because the only
    /// device the fake bus offers for it is one nothing else needs.
    #[test]
    fn every_stage_describes_itself() {
        let named = [
            (Some(Stage::Bootrom), "in the bootrom"),
            (Some(Stage::Gadget), "a U-Boot DFU gadget"),
            (Some(Stage::Firmware), "running vendor firmware"),
            (None, "of an unrecognised kind"),
        ];
        for (stage, phrase) in named {
            let selected = super::Selected {
                index: 0,
                id: 0_usize,
                descriptors: crate::fake::gadget_descriptors(1, 7),
                stage,
            };
            assert_eq!(selected.describe(), phrase, "{stage:?}");
        }
    }

    /// **The audit's carried item**: a device the descriptors cannot classify is not a
    /// bootrom, so nothing will bootstrap it.
    #[test]
    fn fe_cli_an_unclassifiable_device_is_never_bootstrap_eligible() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::opaque()]);
        let selected = block_on(select(&backend, 0))?;
        assert_eq!(selected.stage, None);
        assert!(!selected.is_bootrom(), "unknown must never read as a bootrom");
        assert!(!selected.is_gadget());
        assert_eq!(selected.describe(), "of an unrecognised kind");
        Ok(())
    }

    /// A gadget is found by its port path, not by the index it happens to hold.
    #[test]
    fn disc_the_gadget_is_found_by_its_port_path() -> TestResult {
        // `FakeBackend::gadget()` sits on port path [4, 3]; the bootrom on [4, 2].
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111)), FakeBackend::gadget()]);
        let found = block_on(find_gadget(&backend, &[4, 3]))?.ok_or("the gadget is on [4, 3]")?;
        assert_eq!(found.index, 1);
        assert_eq!(found.stage, Some(Stage::Gadget));

        // A port path with no gadget on it finds nothing, even though a gadget exists.
        assert!(block_on(find_gadget(&backend, &[9, 9]))?.is_none());
        Ok(())
    }

    /// **A port path that could not be read never picks a gadget.**
    ///
    /// An empty path is a failed platform lookup, not "ports are unknown here", and the
    /// first gadget in bus order is exactly the wrong camera: one left in the gadget by
    /// an earlier run holds a low index and would take the transfer. Two gadgets on the
    /// bus, and neither is selected.
    #[test]
    fn fe_cli_an_unreadable_port_path_selects_no_gadget() -> TestResult {
        let backend = FakeBackend::new(vec![
            FakeBackend::gadget(),
            FakeBackend::probeable_gadget_at(vec![7, 1]),
        ]);
        let Err(Error::Invalid(message)) = block_on(find_gadget(&backend, &[])) else {
            return Err("an unreadable port path must be refused, not guessed at".into());
        };
        assert!(message.contains("port path could not be read"), "{message}");
        assert!(message.contains("-i"), "it must say how to name the device: {message}");
        assert_eq!(backend.opened(), Vec::<usize>::new(), "and nothing was opened");
        Ok(())
    }

    /// A bus with no gadget on it is `None`, not an error.
    #[test]
    fn a_bus_with_no_gadget_answers_none() -> TestResult {
        let backend = FakeBackend::new(vec![FakeBackend::bootrom(t31_regs(0x2222_1111))]);
        assert!(block_on(find_gadget(&backend, &[4, 2]))?.is_none());
        Ok(())
    }
}
