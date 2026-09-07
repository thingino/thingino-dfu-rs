//! [`NativeBackend`] — enumeration on the three desktop platforms.
//!
//! Not compiled for Android: `nusb::list_devices` does not exist there, and its
//! `Device::from_device_info` is `unimplemented!()`. An Android build reaches a device
//! through `NativeTransport::from_fd` instead, which is the only way Java can hand
//! one over anyway. Keeping the whole module behind that `cfg` is the CI
//! lesson `.github/workflows/ci.yml` records as failure 4 — the android leg exists to
//! catch a backend that compiles everywhere else.

use nusb::{DeviceInfo, MaybeFuture as _};

use core::fmt;

use super::error::device_error;
use super::transport::{NativeTransport, config_descriptor};
use crate::{DeviceDescriptors, Discovered, LocalUsbBackend, UsbError, vid};

/// Enumeration and opening for a real USB bus.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeBackend;

/// A device this backend listed, in a form it can re-open without another bus scan.
///
/// Opaque on purpose. An earlier `open(&DeviceDescriptors)` forced the backend to
/// re-enumerate and match a device by its fields — which is literally what the C does
/// (`manager.c:166` frees the device list, then `manager.c:259` calls
/// `usb_device_init(bus, address)`, which re-scans at `device.c:137-159`) and is the
/// residue worth deleting. Carrying `nusb`'s own handle removes
/// the rescan and the "it moved between listing and opening" failure with it.
#[derive(Clone)]
pub struct DeviceId {
    info: DeviceInfo,
}

impl fmt::Debug for DeviceId {
    /// Enough to identify the device in a log, and nothing a caller could match on.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceId")
            .field("bus", &bus_number(&self.info))
            .field("address", &self.info.device_address())
            .field("vendor_id", &format_args!("{:#06x}", self.info.vendor_id()))
            .field("product_id", &format_args!("{:#06x}", self.info.product_id()))
            .finish()
    }
}

impl LocalUsbBackend for NativeBackend {
    type Transport = NativeTransport;
    type DeviceId = DeviceId;

    /// Every Ingenic device on the bus.
    ///
    /// No claim, no probe, no reset, no transfer, on any platform: nothing this puts on
    /// the bus can disturb a bootrom that is sitting there waiting, which is what makes
    /// it safe to poll every 500 ms for `--wait`.
    ///
    /// **On Linux nothing is opened either.** The configuration descriptor comes from
    /// the world-readable sysfs `descriptors` attribute, so a poll touches no device
    /// node at all. **On macOS and Windows a handle is the only way to that descriptor**,
    /// so every Ingenic device on the bus is opened and closed once per call; see
    /// `config_descriptor_of` for why that is still no bus traffic, and for what it
    /// costs when the open fails.
    ///
    /// The VID filter is applied here rather than left to the caller because the
    /// config-descriptor read costs something: a bus full of hubs, keyboards and
    /// webcams is not worth reading descriptors for, and this tool
    /// opens nothing else.
    ///
    /// # Errors
    /// Whatever the platform's enumeration raises. A device whose descriptors cannot be
    /// read is still listed, with an empty `config_descriptor` — one unreadable device
    /// must not hide the rest of the bus.
    async fn list(&self) -> Result<Vec<Discovered<DeviceId>>, UsbError> {
        let devices = nusb::list_devices().wait().map_err(|error| device_error(&error))?;
        Ok(devices
            .filter(|info| vid::is_ingenic(info.vendor_id()))
            .map(|info| Discovered {
                descriptors: descriptors_of(&info, config_descriptor_of(&info)),
                id: DeviceId { info },
            })
            .collect())
    }

    /// Open a device this backend listed, with no second bus scan.
    ///
    /// The descriptors are rebuilt from the opened handle, so `config_descriptor` is
    /// populated here even when the listing could not read it.
    ///
    /// # Errors
    /// [`UsbErrorKind::NoDevice`](crate::UsbErrorKind::NoDevice) if it has gone;
    /// [`UsbErrorKind::AccessDenied`](crate::UsbErrorKind::AccessDenied) if the OS
    /// refuses — [`ACCESS_DENIED_HINT`](super::ACCESS_DENIED_HINT) is the
    /// one wording of the fix, and it belongs to whoever reports the error, printed
    /// once.
    async fn open(&self, id: &DeviceId) -> Result<NativeTransport, UsbError> {
        let device = id.info.open().wait().map_err(|error| device_error(&error))?;
        let descriptors = descriptors_of(&id.info, config_descriptor(&device));
        // The identity goes with the handle: a `reset()` destroys the handle and needs
        // something to re-open from, and this is the one moment we have it
        // without a second bus scan.
        Ok(NativeTransport::new(device, id.info.clone(), descriptors))
    }
}

/// A compile-time assertion that enumeration exists on this target. See the twin in
/// `transport.rs` for why these are written out.
const _: () = {
    const fn is_backend<B: LocalUsbBackend>() {}
    is_backend::<NativeBackend>();
};

/// Everything enumeration knows about a device, in the shape `tdfu-core` parses.
fn descriptors_of(info: &DeviceInfo, config: Vec<u8>) -> DeviceDescriptors {
    let mut descriptors = DeviceDescriptors::new(info.vendor_id(), info.product_id())
        .with_bus_address(bus_number(info), info.device_address())
        // Stable across the bootrom to gadget re-enumeration, and the key
        // the daemon remembers a device's SoC by.
        .with_port_path(info.port_chain().to_vec())
        .with_config_descriptor(config);
    if let Some(product) = info.product_string() {
        // Never compared for equality anywhere: the bootrom's iProduct is `U+00C3`,
        // TAB, SPACE, "USB Boot Device" on every unit seen, and `nusb` renders that
        // junk prefix faithfully where libusb showed a `?`.
        descriptors = descriptors.with_product_string(product);
    }
    descriptors
}

/// The bus number for the `-l` table and the wire `DeviceEntry.bus`.
///
/// Linux has a real `busnum`. The other two have only a bus *identifier* string, and it
/// is a different string on each of them, so [`bus_number_of`] carries the parse and the
/// reasons for it.
fn bus_number(info: &DeviceInfo) -> u8 {
    #[cfg(target_os = "linux")]
    {
        info.busnum()
    }
    #[cfg(not(target_os = "linux"))]
    {
        bus_number_of(info.bus_id())
    }
}

/// A bus number out of a `nusb` `bus_id`, on the platforms that have no `busnum`.
///
/// **Hexadecimal, because macOS writes it that way.** `nusb` builds the macOS `bus_id`
/// as `format!("{:02x}", (location_id >> 24) as u8)`
/// (`nusb-0.2.7/src/platform/macos_iokit/enumeration.rs:127`), so a controller whose
/// `locationID` high byte is `0x14` reports `"14"`. A decimal parse accepts that and
/// answers 14 for bus 20, silently and only for the high bytes whose hex digits happen
/// to be decimal ones; the rest fall back to 0 and look like "unknown". One wrong number
/// in the `-l` Bus column and in the daemon's `DeviceEntry.bus` is worse than none,
/// because an operator telling two cameras apart by bus and address believes it.
///
/// **Windows has no number to find and answers 0.** Its `bus_id` is the controller's
/// device location path, `"PCIROOT(0)#PCI(0201)#PCI(0000)#USBROOT(0)"`
/// (`windows_winusb/enumeration.rs:339-356`, `parse_location_path`), which no radix
/// parses; the `unwrap_or` is what makes that "unknown", which is what
/// [`DeviceDescriptors::bus`] documents 0 to mean. Nothing selects a device by this
/// field on any platform: selection is by [`DeviceId`] and by port path.
///
/// Compiled on Linux too when the tests are, and only then: the parse is dead there, but
/// a parse that only a macOS host can run is a parse nobody checks, and the bug it
/// replaces was a silently plausible number rather than a visible failure.
#[cfg(any(not(target_os = "linux"), test))]
fn bus_number_of(bus_id: &str) -> u8 {
    u8::from_str_radix(bus_id, 16).unwrap_or(0)
}

/// The configuration descriptor at index 0, read **without opening the device**
/// wherever the platform allows it.
///
/// This is the one place `nusb` is meaningfully thinner than libusb: libusb hands out
/// `libusb_get_config_descriptor(dev, 0)` from its own cache, while `nusb` exposes
/// configuration descriptors only on an opened `Device`. A listing wants a scan with
/// no open at all, so:
///
/// * **Linux** reads the sysfs `descriptors` attribute — world-readable, no `open()` of
///   the usbfs node, no permissions, no bus traffic. It holds the device descriptor
///   followed by every configuration descriptor, which is where `nusb` itself gets them
///   after opening.
/// * **macOS and Windows** fall back to opening the device and closing it again. That
///   still issues nothing on the wire (both are handle operations against the OS's
///   cached descriptors), but it is not free the way the Linux read is: a `--wait` poll
///   takes and drops a handle on every Ingenic device on the bus every 500 ms, and the
///   open can fail where the Linux path cannot: another program holding the device, a
///   handle this process is itself holding on macOS, or a missing WinUSB driver. A
///   failure here is not fatal and is not reported either: the device is listed with an
///   empty `config_descriptor`, which `tdfu-core` classifies descriptor-first, so it is
///   unclassifiable for that poll rather than an error. `open()` fills it in.
fn config_descriptor_of(info: &DeviceInfo) -> Vec<u8> {
    #[cfg(target_os = "linux")]
    {
        sysfs_config_descriptor(info).unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        info.open()
            .wait()
            .map(|device| config_descriptor(&device))
            .unwrap_or_default()
    }
}

/// The first configuration descriptor out of Linux's sysfs `descriptors` blob.
///
/// The blob is the device descriptor followed by every configuration descriptor, in bus
/// byte order. `bLength` of the device descriptor says where the first configuration
/// starts, and `nusb`'s own parser validates the rest and trims it to `wTotalLength` —
/// so a truncated or malformed blob yields `None` rather than a half-descriptor that
/// `tdfu-core` would go on to parse.
#[cfg(target_os = "linux")]
fn sysfs_config_descriptor(info: &DeviceInfo) -> Option<Vec<u8>> {
    let blob = std::fs::read(info.sysfs_path().join("descriptors")).ok()?;
    let device_descriptor_len = usize::from(*blob.first()?);
    let configuration = nusb::descriptors::ConfigurationDescriptor::new(blob.get(device_descriptor_len..)?)?;
    Some(configuration.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use nusb::descriptors::ConfigurationDescriptor;

    /// The T32LQ's DFU gadget, as captured in
    /// `crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`: one configuration, one
    /// interface, class `0xFE` subclass `0x01`, and the DFU functional descriptor.
    /// Trimmed to what a config-descriptor parse needs.
    const CONFIG: &[u8] = &[
        // configuration descriptor: bLength 9, type 2, wTotalLength 27, 1 interface
        0x09, 0x02, 0x1B, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01, //
        // interface descriptor: number 0, alt 0, 0 endpoints, class 0xFE/0x01/0x02
        0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00, //
        // DFU functional descriptor: bLength 9, type 0x21
        0x09, 0x21, 0x0B, 0xFF, 0x00, 0x00, 0x10, 0x00, 0x01,
    ];

    #[test]
    fn a_config_blob_is_trimmed_to_its_total_length() {
        // The sysfs blob carries every configuration back to back, so a parse that
        // ignored `wTotalLength` would hand `tdfu-core` the next one's bytes as
        // trailing descriptors of this one.
        let mut blob = CONFIG.to_vec();
        blob.extend_from_slice(CONFIG);

        let parsed = ConfigurationDescriptor::new(&blob).map(|c| c.as_bytes().to_vec());

        assert_eq!(parsed.as_deref(), Some(CONFIG));
    }

    #[test]
    fn a_truncated_config_blob_is_rejected_rather_than_half_parsed() {
        assert!(ConfigurationDescriptor::new(&CONFIG[..8]).is_none());
        assert!(ConfigurationDescriptor::new(&CONFIG[..20]).is_none());
        assert!(ConfigurationDescriptor::new(&[]).is_none());
    }

    #[test]
    fn a_bus_id_is_read_as_the_hexadecimal_macos_writes() {
        // `nusb` formats the macOS `bus_id` as `{:02x}` of the `locationID` high byte,
        // so `"14"` is bus 20 and `"20"` is bus 32. A decimal parse answers 14 and 20:
        // wrong, plausible, and only for the high bytes whose hex digits are also
        // decimal ones, which is what makes it hard to notice on a bench.
        assert_eq!(super::bus_number_of("14"), 20);
        assert_eq!(super::bus_number_of("20"), 32);
        assert_eq!(super::bus_number_of("0a"), 10);
        assert_eq!(super::bus_number_of("ff"), 255);
        assert_eq!(super::bus_number_of("00"), 0);
    }

    #[test]
    fn a_bus_id_that_names_no_number_is_unknown_rather_than_a_guess() {
        // Windows reports the controller's device location path here, which no radix
        // parses, and 0 is what `DeviceDescriptors::bus` documents "unknown" as.
        assert_eq!(super::bus_number_of("PCIROOT(0)#PCI(0201)#PCI(0000)#USBROOT(0)"), 0);
        assert_eq!(super::bus_number_of(""), 0);
        assert_eq!(super::bus_number_of("100"), 0, "wider than a bus number, not truncated");
    }

    #[test]
    fn a_device_descriptor_is_not_mistaken_for_a_configuration() {
        // What a wrong `bLength` offset into the sysfs blob would produce.
        let device_descriptor = [
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x08, 0xA1, 0x09, 0xC3, 0x00, 0x00, 0x01, 0x02, 0x03, 0x01,
        ];
        assert!(ConfigurationDescriptor::new(&device_descriptor).is_none());
    }
}
