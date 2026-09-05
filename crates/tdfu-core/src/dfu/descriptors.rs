//! Reading and parsing what a device says about itself.
//!
//! All descriptor reads go over **control transfers**, never a backend's
//! descriptor API, so the same code serves nusb and WebUSB.

use tdfu_usb::{ControlIn, ControlType, DeviceDescriptors, LocalUsbTransport, Recipient, pid, vid};

use super::host::CONTROL_TIMEOUT;
use crate::error::{Error, Result};
use crate::model::{DEFAULT_TRANSFER_SIZE, DfuAlt, DfuInfo, MAX_ALTS, Stage};

/// `bInterfaceClass` of a DFU interface.
pub const DFU_INTERFACE_CLASS: u8 = 0xFE;

/// `bInterfaceSubClass` of a DFU interface.
pub const DFU_INTERFACE_SUBCLASS: u8 = 0x01;

/// `bDescriptorType` of the DFU functional descriptor.
pub const DFU_FUNCTIONAL_DESCRIPTOR: u8 = 0x21;

/// `GET_DESCRIPTOR` (USB 2.0 §9.4.3), the only standard request this module issues.
const GET_DESCRIPTOR: u8 = 0x06;

/// `bDescriptorType` values this module walks or asks for.
const DESCRIPTOR_CONFIGURATION: u8 = 0x02;
const DESCRIPTOR_STRING: u8 = 0x03;
const DESCRIPTOR_INTERFACE: u8 = 0x04;

/// The configuration descriptor's own header: enough to learn
/// `wTotalLength`.
const CONFIG_HEADER_LEN: u16 = 9;

/// The shortest descriptor read that tells us anything: `bLength`,
/// `bDescriptorType`, `wTotalLength`. The C rejects below this in all three of its own
/// checks (`dfu.c:226` on the header read, `:229-230` on `wTotalLength`, `:232` on the
/// full read).
const CONFIG_MIN_LEN: usize = 4;

/// Offset of `bConfigurationValue` in a configuration descriptor (USB 2.0 §9.6.3),
/// which is what a claim must set (`dfu.c:426`).
const CONFIG_VALUE_OFFSET: usize = 5;

/// What to set when the configuration descriptor cannot be read. Every shipped loader
/// uses 1, and so does the C's fallback (`dfu.c:424`).
const DEFAULT_CONFIGURATION: u8 = 1;

/// `wIndex` for a string descriptor read: US English, as the C asks for
/// (`dfu.c:210`).
const LANGID_EN_US: u16 = 0x0409;

/// `wLength` for a string descriptor read. The C's buffer, and the most a
/// single-byte `bLength` can describe (`dfu.c:209-210`).
const STRING_DESCRIPTOR_LEN: u16 = 256;

/// What a bootrom's `iProduct` **contains**.
///
/// Never an equality test: the real string is `U+00C3`, TAB, SPACE,
/// `"USB Boot Device"` on every unit seen, and the
/// junk prefix renders differently per backend — libusb turns it into `?`, nusb keeps
/// it. The gadget's string is `"USB download gadget"`, which contains
/// none of this.
const BOOTROM_PRODUCT_MARKER: &str = "USB Boot Device";

/// What the U-Boot DFU gadget calls itself, matched by **containment** as above.
///
/// Hardcoded in U-Boot's `drivers/usb/gadget/g_dnl.c` (`static const char product[] =
/// "USB download gadget"`) in all three trees this project builds loaders from, with no
/// Ingenic call to `g_dnl_set_product` anywhere to override it; the literal is present
/// in all 34 shipped `firmware/dfu/*/uboot.bin` loaders and `"USB Boot Device"` is
/// present in none of them. Bench-confirmed on two devices in the 2026-08-22 sweep
/// (a descriptor sweep read `iProduct 2 USB download
/// gadget`), and the byte-exact capture in `t32lq-gadget-descriptors.txt` carries the
/// matching `iProduct` index.
///
/// Corroborating evidence only: the DFU-class interface is checked first and is the
/// stronger signal, because it survives a loader that changes its product string.
const GADGET_PRODUCT_MARKER: &str = "USB download gadget";

/// What stage a device is in, from its configuration descriptor.
///
/// **Descriptor first, product ID second — and in practice never the product ID at
/// all.** Any interface with class [`DFU_INTERFACE_CLASS`] and subclass
/// [`DFU_INTERFACE_SUBCLASS`] means [`Stage::Gadget`], whatever the PID says. The
/// gadget was re-PID'd to the bootrom's `0xC309` in July 2026, so the C's PID check
/// (`manager.c:53-68`) now reports stage 0 for every current gadget and its own gadget
/// branch is dead code.
///
/// The order, strongest evidence first:
///
/// 1. Not an Ingenic vendor → `None`.
/// 2. A DFU-class interface in the configuration descriptor → gadget. This is what the
///    C classifies on and it is the one signal a loader cannot change by accident.
/// 3. A product string *containing* [`BOOTROM_PRODUCT_MARKER`] → bootrom.
/// 4. A product string containing [`GADGET_PRODUCT_MARKER`] → gadget.
/// 5. The legacy DFU product ID → gadget.
/// 6. **Only if the configuration descriptor was actually read**, the product IDs.
///
/// Both string tests are **contains**, never equals: every real bootrom's string starts
/// with junk bytes (`U+00C3`, TAB, space on the twelve devices captured 2026-08-22), and
/// which of them a USB stack renders how differs between libusb and
/// `nusb`.
///
/// # Why step 6 is conditional
///
/// **The bootrom and the gadget share `a108:c309`** — the gadget was re-PID'd to the
/// bootrom's PID in July 2026. So the PID alone cannot tell them
/// apart, and answering `Bootrom` from it is a guess that happens to be right most of
/// the time. It was wrong in exactly the case that matters: an empty
/// `config_descriptor`, which is a state
/// [`NativeBackend::list`](tdfu_usb::native::NativeBackend) documents producing — a
/// failed descriptor read, common on macOS and Windows, or malformed sysfs on Linux. A
/// running gadget in that state was reported as a bootrom, which is to say as
/// **bootstrap-eligible**, and bootstrapping a device that is already in DFU mode is the
/// thing the stage is asked in order to avoid.
///
/// With no descriptor evidence, the honest answer is `None`, and a frontend renders that
/// as unknown rather than as anything actionable. A non-empty configuration descriptor
/// *without* a DFU interface is real evidence — it says this device is not a gadget —
/// and the PID is trusted from there.
///
/// # Deliberate differences from the C
///
/// * The C reaches its descriptor test only for a device whose PID was already one of
///   the known ones (`manager.c:100-110`), so an Ingenic device with an unknown PID and
///   a DFU interface is skipped entirely. Descriptor-first means the descriptor wins on
///   its own.
/// * The C classifies by no string at all — `grep -i iProduct` over the whole tree has
///   no hits, and its only string-descriptor reader serves `iInterface`
///   (`dfu.c:204-205`, called once at `:269`). Both strings are checked after the
///   descriptor, so neither can override it.
/// * The C has no "unknown" answer here and does not need one: it never consults the
///   descriptor for a device it has not already PID-matched.
///
/// Returns `None` for a device this tool cannot place.
#[must_use]
pub fn classify(descriptors: &DeviceDescriptors) -> Option<Stage> {
    if !vid::is_ingenic(descriptors.vendor_id) {
        return None;
    }
    if config_has_dfu_interface(&descriptors.config_descriptor) {
        return Some(Stage::Gadget);
    }
    if product_contains(descriptors, BOOTROM_PRODUCT_MARKER) {
        return Some(Stage::Bootrom);
    }
    if product_contains(descriptors, GADGET_PRODUCT_MARKER) {
        return Some(Stage::Gadget);
    }
    if descriptors.product_id == pid::DFU_LEGACY {
        return Some(Stage::Gadget);
    }
    // No descriptor, no string, no legacy PID: nothing here distinguishes a bootrom from
    // a gadget, because they share `a108:c309`. Say so.
    if descriptors.config_descriptor.is_empty() {
        return None;
    }
    match descriptors.product_id {
        pid::BOOTROM | pid::BOOTROM_X | pid::BOOTROM_ALT => Some(Stage::Bootrom),
        pid::FIRMWARE | pid::FIRMWARE_X => Some(Stage::Firmware),
        _ => None,
    }
}

/// Does the product string contain `marker`? Never an equality test.
fn product_contains(descriptors: &DeviceDescriptors, marker: &str) -> bool {
    descriptors
        .product_string
        .as_deref()
        .is_some_and(|product| product.contains(marker))
}

/// Does this raw configuration descriptor expose a DFU interface?
///
/// The C's `dfu_config_is_dfu` (`dfu.c:236-247`) and `usb_dev_has_dfu_interface`
/// (`manager.c:26-49`) ask the same question of the same bytes.
fn config_has_dfu_interface(config: &[u8]) -> bool {
    descriptors(config).any(is_dfu_interface)
}

/// Is this descriptor a DFU alternate setting?
///
/// The length check comes **first**. `desc[1]` was safe only through a non-local
/// invariant — [`Descriptors::next`] never yields fewer than two bytes — which is a
/// promise made in another function about a slice this one is handed by anyone.
/// A caller with a one-byte slice would have panicked, and a flashing tool
/// does not abort to answer a predicate.
fn is_dfu_interface(desc: &[u8]) -> bool {
    desc.len() >= 9
        && desc[1] == DESCRIPTOR_INTERFACE
        && desc[5] == DFU_INTERFACE_CLASS
        && desc[6] == DFU_INTERFACE_SUBCLASS
}

/// The `bConfigurationValue` a claim should set.
///
/// From the configuration descriptor enumeration already read, rather
/// than from a second `GET_DESCRIPTOR` on the wire: the C re-reads the 9-byte header
/// inside every claim (`dfu.c:424-426`) because it kept no copy, and a differential
/// USB capture is the reminder that redundant setup requests show up on
/// the wire. Falls back to [`DEFAULT_CONFIGURATION`] exactly where the C does — a
/// header it could not read.
pub(crate) fn configuration_value(descriptors: &DeviceDescriptors) -> u8 {
    let config = &descriptors.config_descriptor;
    if config.len() > CONFIG_VALUE_OFFSET && config[1] == DESCRIPTOR_CONFIGURATION {
        config[CONFIG_VALUE_OFFSET]
    } else {
        DEFAULT_CONFIGURATION
    }
}

/// Walk a raw descriptor chain, yielding one complete descriptor at a time.
///
/// Stops at the first malformed length, as the C's **two** copies of this loop do
/// (`dfu.c:237-245` and `dfu.c:260-276`): a `bLength` below 2 or past the end
/// of the buffer ends the walk rather than failing the parse, because a truncated tail
/// on a descriptor that already yielded its DFU interface is still usable.
fn descriptors(config: &[u8]) -> Descriptors<'_> {
    Descriptors { rest: config }
}

#[derive(Debug)]
struct Descriptors<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Descriptors<'a> {
    type Item = &'a [u8];

    /// The walk shrinks the slice rather than advancing an index: there is then no
    /// cursor arithmetic to get wrong, and no way to write a step that fails to
    /// advance. The C's `pos += blen` is one edit away from a loop that never ends.
    fn next(&mut self) -> Option<Self::Item> {
        // Two bytes is the shortest descriptor there is (`bLength`,
        // `bDescriptorType`), and the C's bound too: `pos + 2 <= total`.
        if self.rest.len() < 2 {
            return None;
        }
        let len = usize::from(self.rest[0]);
        if len < 2 || len > self.rest.len() {
            return None;
        }
        let (descriptor, rest) = self.rest.split_at(len);
        self.rest = rest;
        Some(descriptor)
    }
}

/// Read the configuration descriptor at **index 0** over control transfers.
///
/// Index 0, not the active configuration: the driverless gadget often has no
/// configuration set, and `libusb_get_active_config_descriptor` fails where
/// `libusb_get_config_descriptor(dev, 0)` succeeds. Read in two steps —
/// the 9-byte header for `wTotalLength`, then the whole thing.
///
/// The C caps the second read at a fixed 1024-byte buffer (`dfu.c:253`); this one is
/// bounded only by `wTotalLength`, which is a `u16`. That is a capability the C does
/// not have rather than a behaviour change: no shipped loader comes close (the T32LQ's
/// whole configuration is 45 bytes).
///
/// # Errors
/// Anything the transport raises, and
/// [`Error::Protocol`](crate::Error::Protocol) if the device answers with fewer than
/// four bytes or claims a total length shorter than its own header.
pub async fn read_config<T: LocalUsbTransport>(dev: &T) -> Result<Vec<u8>> {
    let header = get_descriptor(dev, DESCRIPTOR_CONFIGURATION, 0, 0, CONFIG_HEADER_LEN).await?;
    if header.len() < CONFIG_MIN_LEN {
        return Err(Error::Protocol(format!(
            "configuration descriptor header is {} bytes, need {CONFIG_MIN_LEN}",
            header.len()
        )));
    }
    let total = u16::from_le_bytes([header[2], header[3]]);
    if usize::from(total) < CONFIG_MIN_LEN {
        return Err(Error::Protocol(format!(
            "configuration descriptor claims wTotalLength {total}, need {CONFIG_MIN_LEN}"
        )));
    }
    let config = get_descriptor(dev, DESCRIPTOR_CONFIGURATION, 0, 0, total).await?;
    if config.len() < CONFIG_MIN_LEN {
        return Err(Error::Protocol(format!(
            "configuration descriptor is {} bytes of the {total} it advertised",
            config.len()
        )));
    }
    Ok(config)
}

/// One `GET_DESCRIPTOR`, standard, recipient device.
async fn get_descriptor<T: LocalUsbTransport>(
    dev: &T,
    descriptor_type: u8,
    index: u8,
    langid: u16,
    len: u16,
) -> Result<Vec<u8>> {
    let value = (u16::from(descriptor_type) << 8) | u16::from(index);
    let request = ControlIn {
        control_type: ControlType::Standard,
        recipient: Recipient::Device,
        request: GET_DESCRIPTOR,
        value,
        index: langid,
        len,
    };
    Ok(dev.control_in(request, CONTROL_TIMEOUT).await?)
}

/// Parse a configuration descriptor into [`DfuInfo`].
///
/// Every interface descriptor with class `0xFE`/subclass `0x01` is an alt, up to
/// [`MAX_ALTS`](crate::model::MAX_ALTS); the functional descriptor (`0x21`, length ≥ 9)
/// gives `bmAttributes`, `wTransferSize` and `bcdDFUVersion`, and `wTransferSize`
/// defaults to [`DEFAULT_TRANSFER_SIZE`](crate::model::DEFAULT_TRANSFER_SIZE) when the
/// descriptor is absent or says 0.
///
/// **Alt names are left empty here** — they are `iInterface` *indices* in these bytes,
/// and resolving one costs a string-descriptor read on the wire. [`read_info`] does
/// that; a caller who only has the bytes gets everything except the names, and a
/// nameless alt is still usable by index.
///
/// # Errors
/// [`Error::NotDfu`](crate::Error::NotDfu) when no alt is found — the C's
/// `DEVICE_NOT_FOUND` with "is the device in U-Boot DFU mode?" (`dfu.c:278-281`).
pub fn parse_config(config: &[u8]) -> Result<DfuInfo> {
    parse_config_parts(config).map(|(info, _)| info)
}

/// [`parse_config`], plus the `iInterface` index of each alt in the same order.
///
/// Private because the indices are a wire detail: the only caller that can use one is
/// [`read_info`], which is holding the transport they have to be resolved against.
fn parse_config_parts(config: &[u8]) -> Result<(DfuInfo, Vec<u8>)> {
    let mut interface: Option<u8> = None;
    let mut transfer_size = DEFAULT_TRANSFER_SIZE;
    let mut bcd_dfu = 0;
    let mut attributes = 0;
    let mut alts = Vec::new();
    let mut string_indices = Vec::new();

    for desc in descriptors(config) {
        if is_dfu_interface(desc) {
            // **Alts belong to one interface.** The C walks the whole configuration flat
            // and keeps overwriting `iface` (`dfu.c:259-270`), so on a composite device
            // with two DFU functions every alt lands under the *last* interface number
            // seen — and a claim of interface B then selects an alt that belongs to A.
            // Every shipped loader has exactly one DFU interface with three alts
            // (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`), so the C has never
            // met the case; the rule costs nothing and removes it.
            //
            // First interface, not lowest-numbered: the descriptor order is the device's
            // own statement of which function is primary, and DFU 1.1 gives no other
            // ranking.
            let number = desc[2];
            match interface {
                Some(claimed) if claimed != number => continue,
                Some(_) => {}
                None => interface = Some(number),
            }
            // At most 32. The C makes the cap the trailing conjunct of
            // the match itself (`dfu.c:264-265`, `info->alt_count < TDFU_DFU_MAX_ALTS`),
            // so a 33rd alt is ignored rather than an error.
            //
            // Known limitation: that 33rd alt is dropped **in silence**, and the
            // resulting `MissingAlt` reads "the loader has no alt named …" with no hint
            // that one existed and was discarded. There is nowhere to say so today — the
            // parse layer takes no `ProgressSink` — so it is documented here and
            // scheduled for whenever one exists. No shipped loader
            // declares more than three alts.
            if alts.len() >= MAX_ALTS {
                continue;
            }
            alts.push(DfuAlt::new(desc[3], String::new()));
            string_indices.push(desc[8]);
        } else if desc.len() >= 9 && desc[1] == DFU_FUNCTIONAL_DESCRIPTOR {
            attributes = desc[2];
            transfer_size = u16::from_le_bytes([desc[5], desc[6]]);
            bcd_dfu = u16::from_le_bytes([desc[7], desc[8]]);
        }
    }
    let interface = interface.unwrap_or(0);

    if alts.is_empty() {
        return Err(Error::NotDfu);
    }
    if transfer_size == 0 {
        transfer_size = DEFAULT_TRANSFER_SIZE;
    }

    Ok((
        DfuInfo {
            interface,
            transfer_size,
            bcd_dfu,
            attributes,
            alts,
        },
        string_indices,
    ))
}

/// Read and parse in one step, resolving every alt name.
///
/// **A name that cannot be read is empty, never an error.** The index may be 0 (no
/// string), the descriptor may not come back at all, or the backend may not do string
/// reads; the old browser shim did not, and the
/// WebUSB backend now answers them from the browser's own `interfaceName`. The C's
/// `dfu_get_string` returns `void` for the same reason (`dfu.c:205-221`):
/// a nameless alt is still a usable alt.
///
/// # Errors
/// As [`read_config`] and [`parse_config`].
pub async fn read_info<T: LocalUsbTransport>(dev: &T) -> Result<DfuInfo> {
    let config = read_config(dev).await?;
    let (mut info, string_indices) = parse_config_parts(&config)?;
    for (alt, index) in info.alts.iter_mut().zip(string_indices) {
        alt.name = read_string(dev, index).await;
    }
    Ok(info)
}

/// Read one string descriptor as ASCII; empty on anything that does not work.
///
/// Three known limitations, all deferred to whenever the parse layer gains somewhere to
/// report them:
///
/// * **An unreadable name is indistinguishable from a nameless one.** Index 0 means "no
///   string" and a stalled read means "the device would not say", and both come back as
///   `""`. The C has the same shape (`dfu_get_string` returns `void`, `dfu.c:205-221`)
///   for the same reason, and a nameless alt is still usable by index.
/// * **`LANGID_EN_US` is hardcoded.** The right sequence reads string descriptor 0 for
///   the device's supported LANGIDs and picks one; every loader in the tree answers
///   0x0409 and the C hardcodes it too.
/// * **A stalled string read surfaces later as `MissingAlt`**, because a name that never
///   arrived cannot match the name an operation asks for. The alt is there; only its
///   label is missing.
async fn read_string<T: LocalUsbTransport>(dev: &T, index: u8) -> String {
    if index == 0 {
        return String::new();
    }
    match get_descriptor(dev, DESCRIPTOR_STRING, index, LANGID_EN_US, STRING_DESCRIPTOR_LEN).await {
        Ok(bytes) => decode_string(&bytes),
        Err(_) => String::new(),
    }
}

/// UTF-16LE to ASCII, non-ASCII rendered `?`.
///
/// `bLength` decides how many characters were sent and `chunks_exact` decides how many
/// actually arrived, so a truncated reply yields the part that did — the C spells the
/// same two bounds as one loop condition (`dfu.c:215`), which is the clearest
/// surviving C loop shape in the tree.
fn decode_string(descriptor: &[u8]) -> String {
    if descriptor.len() < 2 || descriptor[1] != DESCRIPTOR_STRING {
        return String::new();
    }
    let chars = usize::from(descriptor[0]).saturating_sub(2) / 2;
    descriptor[2..]
        .chunks_exact(2)
        .take(chars)
        .map(|pair| {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            match u8::try_from(unit) {
                Ok(byte) if byte != 0 && byte < 0x80 => char::from(byte),
                _ => '?',
            }
        })
        .collect()
}

/// The configuration descriptors every DFU test parses.
///
/// One copy, shared by both files in this module: a test double that drifts from the
/// device it models silently removes coverage everywhere downstream, and two copies of
/// the same 45 bytes is how that starts.
#[cfg(test)]
pub(crate) mod fixtures {
    /// The T32LQ U-Boot DFU gadget's whole configuration descriptor, byte-exact from
    /// `crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt` (captured 2026-08-22):
    /// `wTotalLength` 45, `bConfigurationValue` 1, three alts on interface 0 named
    /// `flash`/`erase`/`reboot` (`iInterface` 5/6/7), functional descriptor
    /// `09 21 0F 00 00 00 10 10 01`. Machine-checked against that file by
    /// `the_t32lq_fixture_is_the_captured_descriptor`.
    pub const T32LQ_CONFIG: &[u8] = &[
        0x09, 0x02, 0x2D, 0x00, 0x01, 0x01, 0x02, 0xC0, 0x01, // configuration
        0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x05, // alt 0, iInterface 5
        0x09, 0x04, 0x00, 0x01, 0x00, 0xFE, 0x01, 0x02, 0x06, // alt 1, iInterface 6
        0x09, 0x04, 0x00, 0x02, 0x00, 0xFE, 0x01, 0x02, 0x07, // alt 2, iInterface 7
        0x09, 0x21, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01, // functional
    ];

    /// A single-alt gadget: one unnamed alt, functional descriptor present with
    /// `wTransferSize` 4096. The single-alt branch of a claim, and the second of the
    /// three required parse fixtures.
    pub const SINGLE_ALT_CONFIG: &[u8] = &[
        0x09, 0x02, 0x1B, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01, // configuration
        0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00, // alt 0, iInterface 0
        0x09, 0x21, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01, // functional
    ];

    /// A bootrom's configuration: one vendor-class interface with the two bulk
    /// endpoints the bootrom protocol uses, and **no DFU interface**.
    ///
    /// Its point is that it is *present*: a configuration descriptor that was read and
    /// carries no DFU interface is positive evidence of "not a gadget", which is what
    /// lets [`classify`](super::classify) trust the shared `a108:c309` product ID. An
    /// empty one is not evidence of anything.
    pub const BOOTROM_CONFIG: &[u8] = &[
        0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01, // configuration
        0x09, 0x04, 0x00, 0x00, 0x02, 0xFF, 0x00, 0x00, 0x00, // interface 0, vendor class
        0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00, // bulk IN 0x81
        0x07, 0x05, 0x01, 0x02, 0x00, 0x02, 0x00, // bulk OUT 0x01
    ];

    /// The gadget a browser sees: the functional descriptor is stripped
    /// and no alt name is resolvable. The third required fixture.
    pub const NO_FUNCTIONAL_CONFIG: &[u8] = &[
        0x09, 0x02, 0x1B, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01, // configuration
        0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00, // alt 0
        0x09, 0x04, 0x00, 0x01, 0x00, 0xFE, 0x01, 0x02, 0x00, // alt 1
    ];
}

#[cfg(test)]
mod tests {
    use super::fixtures::{BOOTROM_CONFIG, NO_FUNCTIONAL_CONFIG, SINGLE_ALT_CONFIG, T32LQ_CONFIG};
    use super::{
        CONFIG_VALUE_OFFSET, DESCRIPTOR_STRING, DFU_FUNCTIONAL_DESCRIPTOR, DFU_INTERFACE_CLASS, DFU_INTERFACE_SUBCLASS,
        classify, configuration_value, decode_string, descriptors, parse_config, read_config, read_info,
    };
    use crate::error::Error;
    use crate::model::{DEFAULT_TRANSFER_SIZE, Stage};
    use core::time::Duration;
    use tdfu_usb::mock::{Call, MockTransport, Reply, block_on};
    use tdfu_usb::{ControlType, DeviceDescriptors, Recipient, pid, vid};

    fn bootrom() -> DeviceDescriptors {
        // The junk prefix is real. Never compared for equality.
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("\u{c3}\t USB Boot Device")
            .with_config_descriptor(BOOTROM_CONFIG)
    }

    fn gadget() -> DeviceDescriptors {
        DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("USB download gadget")
            .with_config_descriptor(T32LQ_CONFIG)
    }

    fn get_config(len: u16) -> Call {
        Call::ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x06,
            value: 0x0200,
            index: 0,
            len,
        }
    }

    fn get_string(index: u8) -> Call {
        Call::ControlIn {
            control_type: ControlType::Standard,
            recipient: Recipient::Device,
            request: 0x06,
            value: 0x0300 | u16::from(index),
            index: 0x0409,
            len: 256,
        }
    }

    /// [`Iterator::count`] over the descriptor walk, bounded so it cannot spin.
    ///
    /// Every descriptor consumes at least its two header bytes, so a walk over `n` bytes
    /// yields at most `n / 2`. A walk that stopped advancing would yield the same
    /// descriptor forever, and three mutants of [`Descriptors::next`] did exactly that —
    /// **hanging** the suite rather than failing it, and there is no per-test timeout
    /// anywhere in this workspace to turn a hang into a red line. Taking one
    /// past the ceiling makes the count wrong instead of endless.
    fn bounded_count(config: &[u8]) -> usize {
        descriptors(config).take(config.len() / 2 + 1).count()
    }

    /// A USB string descriptor carrying `text`.
    fn string_descriptor(text: &str) -> Vec<u8> {
        let mut out = vec![0, 0x03];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out[0] = u8::try_from(out.len()).unwrap_or(0xFF);
        out
    }

    #[test]
    fn disc_gadget_by_class_not_pid() {
        // The gadget shares the bootrom's PID since 2026-07-24, so only the
        // descriptor can tell them apart.
        assert_eq!(classify(&gadget()), Some(Stage::Gadget));
        assert_eq!(classify(&bootrom()), Some(Stage::Bootrom));
        assert_eq!(gadget().product_id, bootrom().product_id);

        // The legacy PID is a gadget even with no descriptor to read.
        let legacy = DeviceDescriptors::new(vid::INGENIC, pid::DFU_LEGACY);
        assert_eq!(classify(&legacy), Some(Stage::Gadget));

        // A DFU-class interface wins even under a product ID nothing knows.
        let unknown_pid = DeviceDescriptors::new(vid::INGENIC, 0x1234).with_config_descriptor(T32LQ_CONFIG);
        assert_eq!(classify(&unknown_pid), Some(Stage::Gadget));
    }

    #[test]
    fn disc_product_string_contains() {
        // Never equality: every real bootrom string starts with junk bytes.
        let raw = bootrom();
        assert_ne!(raw.product_string.as_deref(), Some("USB Boot Device"));
        assert_eq!(classify(&raw), Some(Stage::Bootrom));

        // libusb renders the same lead byte as '?'; nusb keeps it. Both classify.
        let via_libusb = DeviceDescriptors::new(vid::INGENIC, 0x9999).with_product_string("?\t USB Boot Device");
        assert_eq!(classify(&via_libusb), Some(Stage::Bootrom));

        // And a gadget's string never contains the marker.
        assert_eq!(classify(&gadget()), Some(Stage::Gadget));
    }

    #[test]
    fn classify_ignores_foreign_vendors_and_unknown_product_ids() {
        // Only the Ingenic vendors are ever opened, whatever they claim.
        let foreign = DeviceDescriptors::new(0x1D6B, pid::BOOTROM).with_product_string("USB Boot Device");
        assert_eq!(classify(&foreign), None);

        let unknown = DeviceDescriptors::new(vid::INGENIC, 0x1234).with_config_descriptor(BOOTROM_CONFIG);
        assert_eq!(classify(&unknown), None);

        // A product ID is evidence only once a configuration descriptor has been read
        // and shown to carry no DFU interface.
        for product_id in [pid::FIRMWARE, pid::FIRMWARE_X] {
            assert_eq!(
                classify(&DeviceDescriptors::new(vid::INGENIC, product_id).with_config_descriptor(BOOTROM_CONFIG)),
                Some(Stage::Firmware)
            );
        }
        for product_id in [pid::BOOTROM, 0x4770, 0x601A] {
            assert_eq!(
                classify(&DeviceDescriptors::new(vid::INGENIC, product_id).with_config_descriptor(BOOTROM_CONFIG)),
                Some(Stage::Bootrom)
            );
        }
    }

    /// With no configuration descriptor there is nothing to tell a
    /// bootrom from a gadget, and the honest answer is "unknown".
    ///
    /// This pin was the wrong way round: it asserted `Some(Stage::Bootrom)` for a bare
    /// `a108:c309`, which the U-Boot DFU gadget also enumerates as since July 2026
    /// An empty `config_descriptor` is a state
    /// `NativeBackend::list` documents producing — a failed descriptor read, common on
    /// macOS and Windows, or malformed sysfs on Linux — so a running gadget whose
    /// descriptor would not come back was reported as bootstrap-eligible, and
    /// bootstrapping a device already in DFU mode is what asking the stage is meant to
    /// prevent.
    #[test]
    fn classify_answers_unknown_when_nothing_distinguishes_bootrom_from_gadget() {
        // The shared PID, no descriptor, no string: unknowable.
        let blind = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM);
        assert_eq!(classify(&blind), None, "a108:c309 alone cannot be placed");

        // A real gadget whose descriptor read failed: still not a bootrom.
        let blind_gadget =
            DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("USB download gadget");
        assert_eq!(
            classify(&blind_gadget),
            Some(Stage::Gadget),
            "the product string still places it"
        );

        // And with the string gone too, it is unknown rather than bootstrap-eligible.
        let nameless_gadget = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM);
        assert_ne!(
            classify(&nameless_gadget),
            Some(Stage::Bootrom),
            "a gadget with nothing readable must never be reported as a bootrom"
        );

        // The same device once its descriptor arrives resolves both ways.
        assert_eq!(classify(&gadget()), Some(Stage::Gadget));
        assert_eq!(classify(&bootrom()), Some(Stage::Bootrom));
    }

    /// The gadget's own product string, verified against the loaders that ship it.
    ///
    /// U-Boot hardcodes `"USB download gadget"` in `drivers/usb/gadget/g_dnl.c` in all
    /// three trees the loaders are built from, nothing on the Ingenic side calls
    /// `g_dnl_set_product` to change it, the literal is in all 34 shipped
    /// `firmware/dfu/*/uboot.bin` images, and the 2026-08-22 bench sweep read it back on
    /// two devices. It is corroborating evidence, never the primary signal.
    #[test]
    fn disc_gadget_product_string_is_corroborating_not_primary() {
        let by_string = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_product_string("USB download gadget");
        assert_eq!(classify(&by_string), Some(Stage::Gadget));

        // And the class descriptor outranks both strings. A device presenting a DFU
        // interface *and* the bootrom's product string is a gadget, because the
        // descriptor is what it is currently doing and the string is only what it calls
        // itself. Every string test runs after the descriptor test for that reason.
        let contradictory = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_product_string("\u{c3}\t USB Boot Device")
            .with_config_descriptor(T32LQ_CONFIG);
        assert_eq!(
            classify(&contradictory),
            Some(Stage::Gadget),
            "a DFU-class interface outranks every string"
        );
    }

    /// The descriptor walk always advances, so it terminates on any input at all.
    ///
    /// Three mutants of [`Descriptors::next`] **hung** rather than failing — a walk that
    /// stops advancing spins forever, and with no per-test timeout anywhere in this
    /// workspace a hang is a build that never finishes rather than a red line. Bounding
    /// the yield count turns that class of defect into an assertion: every descriptor
    /// consumes at least its two header bytes, so a buffer of `n` bytes can yield at most
    /// `n / 2` of them.
    ///
    /// `[0xFF; 64]` is the hostile shape: every `bLength` claims 255, which is past the
    /// end of the buffer at every offset, so a correct walk yields nothing at all.
    #[test]
    fn the_descriptor_walk_cannot_yield_more_than_it_consumes() {
        for bytes in [
            vec![0xFF_u8; 64],
            vec![0x00; 64],
            vec![0x01; 64],
            vec![0x02; 64],
            vec![0x09; 64],
            (0..64_u8).collect(),
            vec![],
            vec![0x02],
        ] {
            let ceiling = bytes.len() / 2;
            let mut seen = 0_usize;
            for desc in descriptors(&bytes) {
                assert!(desc.len() >= 2, "a descriptor shorter than its own header");
                seen += 1;
                assert!(
                    seen <= ceiling,
                    "{seen} descriptors out of {} bytes: the walk stopped advancing",
                    bytes.len()
                );
            }
        }

        // The specific hostile shape, spelled out: nothing is yielded, because every
        // claimed length runs past the end.
        assert_eq!(bounded_count(&[0xFF; 64]), 0);
        // And a buffer of minimum-length descriptors yields exactly the maximum.
        assert_eq!(bounded_count(&[0x02; 64]), 32);
    }

    /// A composite device's alts do not pool under one interface.
    ///
    /// The C walks the configuration flat and overwrites `iface` on every DFU interface
    /// it meets (`dfu.c:259-270`), so two DFU functions leave every alt filed under the
    /// **last** interface number — and a claim of interface 1 then issues
    /// `SET_INTERFACE` for an alt that belongs to interface 0.
    #[test]
    fn dfu_alts_belong_to_the_first_dfu_interface_only() -> Result<(), Error> {
        // Two DFU functions: interface 0 with two alts, interface 1 with one.
        const COMPOSITE: &[u8] = &[
            0x09, 0x02, 0x2D, 0x00, 0x02, 0x01, 0x00, 0xC0, 0x01, // configuration
            0x09, 0x04, 0x00, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00, // iface 0 alt 0
            0x09, 0x04, 0x00, 0x01, 0x00, 0xFE, 0x01, 0x02, 0x00, // iface 0 alt 1
            0x09, 0x04, 0x01, 0x00, 0x00, 0xFE, 0x01, 0x02, 0x00, // iface 1 alt 0
            0x09, 0x21, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01, // functional
        ];

        let info = parse_config(COMPOSITE)?;
        assert_eq!(info.interface, 0, "the first DFU interface is the one claimed");
        assert_eq!(
            info.alts.iter().map(|alt| alt.alt).collect::<Vec<_>>(),
            vec![0, 1],
            "interface 1's alt must not be filed under interface 0"
        );
        Ok(())
    }

    #[test]
    fn dfu_parse_config_fixture() -> Result<(), Error> {
        // The real T32LQ capture.
        let info = parse_config(T32LQ_CONFIG)?;
        assert_eq!(info.interface, 0);
        assert_eq!(info.transfer_size, 4096);
        assert_eq!(info.bcd_dfu, 0x0110);
        assert_eq!(info.attributes, 0x0F);
        assert_eq!(info.alts.iter().map(|alt| alt.alt).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert!(info.is_multi_alt());

        // Single alt.
        let single = parse_config(SINGLE_ALT_CONFIG)?;
        assert_eq!(single.alts.len(), 1);
        assert!(!single.is_multi_alt());
        assert_eq!(single.transfer_size, 4096);

        // No functional descriptor.
        let stripped = parse_config(NO_FUNCTIONAL_CONFIG)?;
        assert_eq!(stripped.alts.len(), 2);
        assert_eq!(stripped.bcd_dfu, 0);
        assert_eq!(stripped.attributes, 0);

        // No DFU interface at all is the one parse failure.
        let not_dfu = &[
            0x09, 0x02, 0x12, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01, 0x09, 0x04, 0x00, 0x00, 0x02, 0x08, 0x06, 0x50, 0x00,
        ];
        assert!(matches!(parse_config(not_dfu), Err(Error::NotDfu)));
        Ok(())
    }

    #[test]
    fn dfu_transfer_size_defaults() -> Result<(), Error> {
        // Absent functional descriptor.
        assert_eq!(parse_config(NO_FUNCTIONAL_CONFIG)?.transfer_size, DEFAULT_TRANSFER_SIZE);

        // Present but zero — the other half of the same rule (`dfu.c:282-283`).
        let mut zeroed = SINGLE_ALT_CONFIG.to_vec();
        zeroed[9 + 9 + 5] = 0;
        zeroed[9 + 9 + 6] = 0;
        assert_eq!(parse_config(&zeroed)?.transfer_size, DEFAULT_TRANSFER_SIZE);

        // And the real gadget's own value survives.
        assert_eq!(parse_config(T32LQ_CONFIG)?.transfer_size, 4096);
        Ok(())
    }

    #[test]
    fn parse_config_stops_at_a_malformed_length_and_caps_the_alts() -> Result<(), Error> {
        // A zero bLength would loop forever; the walk ends instead, keeping what it
        // already collected (`dfu.c:260-263` — the loop head, then `blen < 2` breaking
        // rather than failing the parse).
        let mut truncated = T32LQ_CONFIG.to_vec();
        truncated[18] = 0;
        let info = parse_config(&truncated)?;
        assert_eq!(info.alts.len(), 1, "the walk stops at the bad descriptor");
        assert_eq!(
            info.transfer_size, DEFAULT_TRANSFER_SIZE,
            "and never reached the functional descriptor"
        );

        // A descriptor claiming more bytes than remain ends the walk too — and with
        // no alt collected at all, that is `NotDfu` rather than a silent success.
        let mut overlong = T32LQ_CONFIG.to_vec();
        overlong[9] = 200;
        assert!(matches!(parse_config(&overlong), Err(Error::NotDfu)));

        // At most 32 alts, however many the device lists.
        let mut many = T32LQ_CONFIG[..9].to_vec();
        for alt in 0..40_u8 {
            many.extend_from_slice(&[0x09, 0x04, 0x00, alt, 0x00, 0xFE, 0x01, 0x02, 0x00]);
        }
        assert_eq!(parse_config(&many)?.alts.len(), 32);
        Ok(())
    }

    #[test]
    fn dfu_descriptors_via_control() -> Result<(), Box<dyn std::error::Error>> {
        // A 9-byte header for wTotalLength, then the whole thing, and
        // wValue 0x0200 is descriptor type 2, index **0**.
        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(T32LQ_CONFIG[..9].to_vec()))
            .expecting(get_config(45), Reply::Data(T32LQ_CONFIG.to_vec()));

        let config = block_on(read_config(&dev))?;
        assert_eq!(config, T32LQ_CONFIG);
        dev.verify()?;

        let calls = dev.calls();
        assert_eq!(calls.len(), 2, "two control transfers, no descriptor API");
        assert!(calls.iter().all(|call| call.timeout == Some(Duration::from_secs(5))));
        Ok(())
    }

    #[test]
    fn disc_reads_config_index_0() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(T32LQ_CONFIG[..9].to_vec()))
            .expecting(get_config(45), Reply::Data(T32LQ_CONFIG.to_vec()));
        block_on(read_config(&dev))?;

        // The driverless gadget often has no active configuration, so the request
        // names index 0 rather than asking for whatever is in force.
        let Some(Call::ControlIn { value, index, .. }) = dev.calls().first().map(|call| call.call.clone()) else {
            return Err("the first call must be the descriptor read".into());
        };
        assert_eq!(value, 0x0200, "descriptor type 2, index 0");
        assert_eq!(index, 0, "no langid on a configuration descriptor");
        Ok(())
    }

    #[test]
    fn read_info_resolves_every_alt_name() -> Result<(), Box<dyn std::error::Error>> {
        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(T32LQ_CONFIG[..9].to_vec()))
            .expecting(get_config(45), Reply::Data(T32LQ_CONFIG.to_vec()))
            .expecting(get_string(5), Reply::Data(string_descriptor("flash")))
            .expecting(get_string(6), Reply::Data(string_descriptor("erase")))
            .expecting(get_string(7), Reply::Data(string_descriptor("reboot")));

        let info = block_on(read_info(&dev))?;
        dev.verify()?;
        assert_eq!(
            info.alts.iter().map(|alt| alt.name.as_str()).collect::<Vec<_>>(),
            vec!["flash", "erase", "reboot"]
        );
        Ok(())
    }

    #[test]
    fn dfu_webusb_alt_by_index() -> Result<(), Box<dyn std::error::Error>> {
        // No string reads happen at all when iInterface is 0, and the
        // alts still carry their bAlternateSetting numbers, which is what selection
        // uses on that backend.
        let descriptors =
            DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_config_descriptor(NO_FUNCTIONAL_CONFIG);
        let dev = MockTransport::new(descriptors)
            .expecting(get_config(9), Reply::Data(NO_FUNCTIONAL_CONFIG[..9].to_vec()))
            .expecting(get_config(27), Reply::Data(NO_FUNCTIONAL_CONFIG.to_vec()));

        let info = block_on(read_info(&dev))?;
        dev.verify()?;
        assert_eq!(dev.calls().len(), 2, "iInterface 0 means no string descriptor read");
        assert!(info.alts.iter().all(|alt| alt.name.is_empty()));
        assert_eq!(info.alts.iter().map(|alt| alt.alt).collect::<Vec<_>>(), vec![0, 1]);
        assert!(info.is_multi_alt(), "two alts still need SET_INTERFACE for alt 0");
        Ok(())
    }

    #[test]
    fn an_unreadable_alt_name_is_empty_not_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let stall = tdfu_usb::UsbError::new(
            tdfu_usb::UsbErrorKind::Stall,
            tdfu_usb::Pipe::Control {
                direction: tdfu_usb::Direction::In,
                request: 0x06,
            },
        );
        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(T32LQ_CONFIG[..9].to_vec()))
            .expecting(get_config(45), Reply::Data(T32LQ_CONFIG.to_vec()))
            .expecting(get_string(5), Reply::Fail(stall))
            // A reply that is not a string descriptor is discarded too.
            .expecting(get_string(6), Reply::Data(vec![0x04, 0x02, b'x', 0x00]))
            .expecting(get_string(7), Reply::Data(string_descriptor("reboot")));

        let info = block_on(read_info(&dev))?;
        assert_eq!(
            info.alts.iter().map(|alt| alt.name.as_str()).collect::<Vec<_>>(),
            vec!["", "", "reboot"]
        );
        Ok(())
    }

    #[test]
    fn a_name_with_non_ascii_renders_question_marks() -> Result<(), Box<dyn std::error::Error>> {
        // Give the single alt an iInterface index so a name gets read at all.
        let mut config = SINGLE_ALT_CONFIG.to_vec();
        config[9 + 8] = 4;

        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(config[..9].to_vec()))
            .expecting(get_config(27), Reply::Data(config.clone()))
            .expecting(get_string(4), Reply::Data(string_descriptor("fl\u{e4}sh")));
        let info = block_on(read_info(&dev))?;
        dev.verify()?;
        assert_eq!(info.alts[0].name, "fl?sh", "non-ASCII becomes '?'");
        Ok(())
    }

    #[test]
    fn read_config_refuses_a_header_that_does_not_describe_a_configuration() {
        let short = MockTransport::new(gadget()).expecting(get_config(9), Reply::Data(vec![0x09, 0x02, 0x2D]));
        assert!(matches!(block_on(read_config(&short)), Err(Error::Protocol(_))));

        let tiny = MockTransport::new(gadget()).expecting(
            get_config(9),
            Reply::Data(vec![0x09, 0x02, 0x02, 0x00, 0x01, 0x01, 0x00, 0xC0, 0x01]),
        );
        assert!(matches!(block_on(read_config(&tiny)), Err(Error::Protocol(_))));

        let truncated = MockTransport::new(gadget())
            .expecting(
                get_config(9),
                Reply::Data(vec![0x09, 0x02, 0x2D, 0x00, 0x01, 0x01, 0x02, 0xC0, 0x01]),
            )
            .expecting(get_config(45), Reply::Data(vec![0x09, 0x02]));
        assert!(matches!(block_on(read_config(&truncated)), Err(Error::Protocol(_))));
    }

    #[test]
    fn the_configuration_value_comes_from_the_descriptor_we_already_read() {
        // The value the claim sets is bConfigurationValue, byte 5.
        assert_eq!(configuration_value(&gadget()), 1);

        let unusual = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_config_descriptor({
            let mut config = T32LQ_CONFIG.to_vec();
            config[5] = 3;
            config
        });
        assert_eq!(configuration_value(&unusual), 3);

        // Nothing to read falls back to 1, as the C does when its header read fails —
        // and so does a header too short to hold the field, which must never be read
        // past the end of (`dfu.c:425` wants six bytes for the same reason).
        for len in 0..=CONFIG_VALUE_OFFSET {
            let short =
                DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM).with_config_descriptor(T32LQ_CONFIG[..len].to_vec());
            assert_eq!(configuration_value(&short), 1, "{len} bytes cannot hold it");
        }
    }

    #[test]
    fn decode_string_bounds_by_both_the_length_byte_and_the_bytes_that_arrived() {
        // `bLength` says how many characters were sent; the reply says how many
        // arrived. The C bounds by both in one loop condition (`dfu.c:215`).
        let mut padded = string_descriptor("flash");
        padded.extend_from_slice(&[b'X', 0, b'Y', 0]);
        assert_eq!(decode_string(&padded), "flash", "bLength wins over a padded reply");

        let mut truncated = string_descriptor("reboot");
        truncated.truncate(6);
        assert_eq!(
            decode_string(&truncated),
            "re",
            "and the reply wins over an optimistic bLength"
        );

        // Nothing that can arrive may panic: a flashing tool must not abort on a
        // short descriptor.
        for len in 0..2 {
            assert_eq!(decode_string(&vec![0x03; len]), "");
        }
        assert_eq!(decode_string(&[0x02, DESCRIPTOR_STRING]), "", "an empty name is empty");
        assert_eq!(decode_string(&[0x04, 0x02, b'x', 0x00]), "", "not a string descriptor");
    }

    #[test]
    fn decode_string_renders_exactly_the_printable_ascii_range() {
        // The substitution, at both edges: 0x7F is ASCII, 0x80 is not, and a
        // NUL is not a character either.
        let name: String = ['a', '\u{7F}'].iter().collect();
        assert_eq!(decode_string(&string_descriptor(&name)), "a\u{7F}");
        assert_eq!(decode_string(&string_descriptor("a\u{80}")), "a?");
        assert_eq!(decode_string(&[0x06, 0x03, b'a', 0x00, 0x00, 0x00]), "a?");
    }

    #[test]
    fn the_descriptor_walk_yields_every_well_formed_descriptor() {
        // Two bytes is the shortest descriptor there is, including as the last one in
        // the chain, and the walk stops at the first length it cannot trust.
        // `bounded_count`, never a bare `.count()`: a walk that stops advancing yields
        // forever, and this test hung rather than failed for three mutants of
        // `Descriptors::next`.
        assert_eq!(bounded_count(&[0x02, 0x0B]), 1);
        assert_eq!(bounded_count(&[0x02, 0x0B, 0x02, 0x0C]), 2);
        assert_eq!(bounded_count(&[0x02, 0x0B, 0x09]), 1, "a one-byte tail is not one");
        assert_eq!(bounded_count(&[]), 0);
        assert_eq!(bounded_count(&[0x09]), 0);
        assert_eq!(bounded_count(&[0x00, 0x0B]), 0, "bLength 0 would never advance");
        assert_eq!(bounded_count(&[0x09, 0x02, 0x00]), 0, "and a length past the end stops");
        assert_eq!(bounded_count(T32LQ_CONFIG), 5);
    }

    #[test]
    fn parse_config_walks_past_a_minimal_descriptor() -> Result<(), Error> {
        // A two-byte descriptor is the shortest legal one, and an unknown one in the
        // chain must not end the walk — the C's bound is `pos + 2 <= total` with
        // `blen < 2` as the failure (`dfu.c:260-263`).
        let mut config = SINGLE_ALT_CONFIG[..18].to_vec();
        config.extend_from_slice(&[0x02, 0x0B]);
        config.extend_from_slice(&SINGLE_ALT_CONFIG[18..]);

        let info = parse_config(&config)?;
        assert_eq!(info.alts.len(), 1, "a minimal descriptor must not end the walk");
        assert_eq!(
            info.transfer_size, 4096,
            "the functional descriptor after it was still read"
        );
        Ok(())
    }

    #[test]
    fn read_config_accepts_the_shortest_header_the_c_accepts() -> Result<(), Box<dyn std::error::Error>> {
        // `dfu.c:226` takes anything from four bytes up, and `:229` any
        // `wTotalLength` from four up. Four bytes is all it takes to learn the total.
        let dev = MockTransport::new(gadget())
            .expecting(get_config(9), Reply::Data(vec![0x09, 0x02, 0x04, 0x00]))
            .expecting(get_config(4), Reply::Data(vec![0x09, 0x02, 0x04, 0x00]));

        assert_eq!(block_on(read_config(&dev))?, vec![0x09, 0x02, 0x04, 0x00]);
        dev.verify()?;
        Ok(())
    }

    #[test]
    fn the_t32lq_fixture_is_the_captured_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        // Machine-checked against the bench capture, so the fixture cannot drift from
        // the device it claims to be. The file holds the 18-byte device descriptor and
        // the whole configuration descriptor as one hex string.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt");
        let text = std::fs::read_to_string(&path)?;
        let blob = text
            .lines()
            .map(str::trim)
            .find(|line| line.len() > 100 && line.chars().all(|ch| ch.is_ascii_hexdigit()))
            .ok_or("no hex capture line in the descriptor file")?;
        let mut bytes = Vec::new();
        for pair in blob.as_bytes().chunks_exact(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
        }

        // The device descriptor is 18 bytes; the configuration descriptor follows it.
        let (device, config) = bytes.split_at(18);
        assert_eq!(device[0], 18, "bLength of the device descriptor");
        assert_eq!(u16::from_le_bytes([device[8], device[9]]), vid::INGENIC);
        assert_eq!(
            u16::from_le_bytes([device[10], device[11]]),
            pid::BOOTROM,
            "the gadget shares the bootrom's product ID"
        );
        assert_eq!(config, T32LQ_CONFIG, "the fixture must be the captured bytes");
        Ok(())
    }

    #[test]
    fn the_dfu_descriptor_constants_are_the_numbers_the_class_defines() {
        assert_eq!(DFU_INTERFACE_CLASS, 0xFE);
        assert_eq!(DFU_INTERFACE_SUBCLASS, 0x01);
        assert_eq!(DFU_FUNCTIONAL_DESCRIPTOR, 0x21);
    }
}
