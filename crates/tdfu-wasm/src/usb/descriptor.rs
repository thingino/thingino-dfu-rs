//! The configuration descriptor the browser will not give us, rebuilt from the tree it
//! will.
//!
//! WebUSB exposes no raw descriptors and refuses standard control requests, so a
//! `GET_DESCRIPTOR(CONFIGURATION)` cannot be made. What it *does* expose is
//! the parsed tree, `USBDevice.configurations[].interfaces[].alternates[]` with each
//! alternate's class, subclass, protocol and setting number, which is every field
//! `tdfu_core::dfu::descriptors::parse_config` and `classify` read. So the bytes are
//! rebuilt here, once, at open time, and served from
//! [`DeviceDescriptors::config_descriptor`] thereafter.
//!
//! # Three things the browser drops, and what is done about each
//!
//! * **The DFU functional descriptor** (`bDescriptorType 0x21`) is not in the tree at
//!   all, so `wTransferSize` and `bcdDFUVersion` cannot be read. One is appended when a
//!   DFU interface is present, advertising **4096 / DFU 1.10**, the value every shipped
//!   loader really carries (captured byte-exact from a live
//!   T32LQ gadget: `09 21 0F 00 00 00 10 10 01`,
//!   `crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`). It is logged at debug as
//!   **assumed rather than read**, so the log says 4096 was taken and not measured.
//!   That distinction is the whole reason the line exists.
//! * **Raw string descriptors**, but *not* the strings. `UsbAlternateInterface` carries
//!   `interfaceName`, which Chromium fills in from the device's own `iInterface` during
//!   enumeration, so the names are in hand; what is missing is only the wire format
//!   `dfu::descriptors::read_info` reads them in. So [`build`] hands each **named**
//!   alternate an `iInterface` of its own, numbered from 1 in tree order, and returns the
//!   [`Synthesised::strings`] those indices point into for the transport to answer
//!   `GET_DESCRIPTOR(STRING, index)` from. An alternate the browser has no name for keeps
//!   `iInterface = 0`, which `read_info` skips without a transfer, and its name is empty
//!   exactly as before. An audit settled this: the old rule ("`iInterface` is 0 on every
//!   alternate") was the 2019 shim's limitation, not WebUSB's, and it made the default
//!   alt (`flash` **by name**) unresolvable on every real three-alt loader.
//! * **Endpoint descriptors.** `bNumEndpoints` is 0 and none is emitted. Nothing in this
//!   tool reads one: the two bulk addresses are constants
//!   (`tdfu_usb::endpoint::BOOTROM_IN`/`BOOTROM_OUT`), and the C reads no endpoint
//!   descriptor anywhere either. Emitting a count without the
//!   descriptors to match would be worse than emitting neither.
//!
//! # The indices are ours, and that is the point
//!
//! The numbering here is **not** the device's. A live T32LQ carries `iInterface` 5, 6 and
//! 7 for `flash`, `erase` and `reboot`
//! (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`); this descriptor says 1, 2 and
//! 3. Nothing on the wire ever sees either number: WebUSB refuses standard control
//! transfers outright, so a `GET_DESCRIPTOR(STRING, 1)` could not be forwarded to the
//! device even if we wanted it to be, and forwarding index 1 to a device whose `flash`
//! string is at 5 would fetch the wrong string. The index is a private handle between
//! [`build`] and the transport that answers for it, and the answer is the string the
//! browser already read.
//!
//! The shim did the same rebuild at `web/src/libusb-webusb.js:299-341`. Three deliberate
//! differences: it wrote `wDetachTimeOut` as `0x00FF` where the real loaders carry `0`,
//! and this uses the captured value (the field is read by nothing here, so the only
//! reason to prefer one is that a synthesised descriptor should look like the device it
//! stands in for); it wrote `iInterface = 0` into every interface descriptor
//! (`:312-314`) and answered every `STRING` request with the two-byte stub `[2, 3]`
//! (`:327-328`), so no alt could ever be addressed by name; and it never read
//! `interfaceName` at all, which is what made the C's browser build carry an alt resolver
//! of its own (`libtdfu/src/core.c:170-178`).

use tdfu_core::dfu::descriptors::{DFU_INTERFACE_CLASS, DFU_INTERFACE_SUBCLASS};

/// `bDescriptorType` for a configuration descriptor (USB 2.0 §9.4.3).
pub const DESCRIPTOR_CONFIGURATION: u8 = 0x02;

/// `bDescriptorType` for an interface descriptor.
pub const DESCRIPTOR_INTERFACE: u8 = 0x04;

/// `bDescriptorType` for the DFU functional descriptor (DFU 1.1 §4.1.3).
pub const DESCRIPTOR_DFU_FUNCTIONAL: u8 = 0x21;

/// `bDescriptorType` for a string descriptor (USB 2.0 §9.6.7).
pub const DESCRIPTOR_STRING: u8 = 0x03;

/// An empty string descriptor: `bLength 2`, `bDescriptorType 3`, no characters.
///
/// The answer for a string index this descriptor never handed out, and for index 0,
/// which is the supported-LANGID list rather than a name: the browser says nothing about
/// which languages the device declares, and `decode_string` reads an empty descriptor as
/// an empty string, which is the truthful answer rather than an invented one.
pub const EMPTY_STRING_DESCRIPTOR: [u8; 2] = [2, DESCRIPTOR_STRING];

/// The most UTF-16 code units a string descriptor can carry: `bLength` is a `u8` and
/// the two header bytes come out of it, so 126 characters, 254 bytes.
const MAX_STRING_UNITS: usize = (u8::MAX as usize - 2) / 2;

/// `wTransferSize` for a gadget whose functional descriptor the browser stripped.
///
/// Two values were weighed: 1024 (the DFU specification's conservative floor, what a
/// native backend substitutes when a descriptor is absent) against 4096 (what every
/// shipped loader advertises). 4096 wins, with a debug log saying it was assumed. This
/// is the browser, the loaders are the shipped ones, and 4096 is four times fewer round
/// trips on a 16 MiB image.
pub const ASSUMED_TRANSFER_SIZE: u16 = 4096;

/// `bcdDFUVersion` 1.10, as the shipped loaders carry it.
pub const ASSUMED_BCD_DFU: u16 = 0x0110;

/// `bmAttributes`: download, upload, manifestation tolerant, will detach. `0x0F`, the
/// captured value.
const ASSUMED_ATTRIBUTES: u8 = 0x0F;

/// `wDetachTimeOut`, as the real T32LQ gadget carries it.
const DETACH_TIMEOUT: u16 = 0;

/// Lengths, so the header's `wTotalLength` cannot drift from what follows it.
const CONFIG_HEADER_LEN: u8 = 9;
const INTERFACE_LEN: u8 = 9;
const FUNCTIONAL_LEN: u8 = 9;

/// One alternate setting, as the browser describes it.
///
/// A plain struct rather than a borrowed `web_sys::UsbAlternateInterface` so that
/// [`build`] is a pure function of ordinary values: the whole synthesis is then
/// host-tested, byte for byte, against the descriptor a real T32LQ answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alternate {
    /// `bInterfaceNumber`.
    pub interface: u8,
    /// `bAlternateSetting`.
    pub alternate: u8,
    /// `bInterfaceClass`.
    pub class: u8,
    /// `bInterfaceSubClass`.
    pub subclass: u8,
    /// `bInterfaceProtocol`.
    pub protocol: u8,
    /// `UsbAlternateInterface.interfaceName`, empty when the browser has none.
    pub name: String,
}

/// A rebuilt configuration descriptor and the strings its `iInterface` indices name.
///
/// The two halves are returned together because they are one artefact: the indices in
/// `config` are meaningless without `strings`, and a caller that kept one without the
/// other would be back to nameless alts with no way to tell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Synthesised {
    /// The bytes, as `GET_DESCRIPTOR(CONFIGURATION, 0)` should answer them.
    pub config: Vec<u8>,
    /// The name at `iInterface = n` is `strings[n - 1]`. Index 0 is "no string".
    pub strings: Vec<String>,
    /// Did a DFU functional descriptor get appended?
    ///
    /// [`build`] already decided this, so the caller that logs "the transfer size was
    /// assumed" asks rather than scanning the bytes back for the pair
    /// `[9, 0x21]`: an alternate with `bInterfaceClass` 9 and `bInterfaceSubClass` 0x21,
    /// or `bInterfaceNumber` 9 with `bAlternateSetting` 0x21, matches that scan too.
    pub has_functional: bool,
}

/// Rebuild a configuration descriptor from the browser's tree.
///
/// `interfaces` is the number of *interfaces* (not alternates) the configuration has,
/// which is `bNumInterfaces`; `alternates` is every alternate of every one of them, in
/// tree order.
#[must_use]
pub fn build(configuration_value: u8, interfaces: usize, alternates: &[Alternate]) -> Synthesised {
    let has_dfu = alternates.iter().any(is_dfu);
    let body_len = alternates.len() * usize::from(INTERFACE_LEN) + usize::from(FUNCTIONAL_LEN) * usize::from(has_dfu);
    let total = usize::from(CONFIG_HEADER_LEN) + body_len;

    let mut out = Vec::with_capacity(total);
    let mut strings: Vec<String> = Vec::new();
    out.push(CONFIG_HEADER_LEN);
    out.push(DESCRIPTOR_CONFIGURATION);
    // `wTotalLength` is a u16 by definition; a configuration that overflowed it would be
    // malformed on the wire too. Saturating keeps the header self-consistent with a
    // truncated body rather than wrapping to a small number that describes nothing.
    out.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_le_bytes());
    out.push(u8::try_from(interfaces).unwrap_or(u8::MAX));
    out.push(configuration_value);
    // iConfiguration: the browser exposes no configuration name, only interface ones.
    out.push(0);
    out.push(0x80); // bmAttributes: bus powered, the reserved bit 7 set as USB 2.0 requires
    out.push(0); // bMaxPower, in 2 mA units; unknown and unread

    for alternate in alternates {
        out.push(INTERFACE_LEN);
        out.push(DESCRIPTOR_INTERFACE);
        out.push(alternate.interface);
        out.push(alternate.alternate);
        out.push(0); // bNumEndpoints: see the module doc
        out.push(alternate.class);
        out.push(alternate.subclass);
        out.push(alternate.protocol);
        out.push(string_index(&mut strings, &alternate.name));
    }

    if has_dfu {
        out.push(FUNCTIONAL_LEN);
        out.push(DESCRIPTOR_DFU_FUNCTIONAL);
        out.push(ASSUMED_ATTRIBUTES);
        out.extend_from_slice(&DETACH_TIMEOUT.to_le_bytes());
        out.extend_from_slice(&ASSUMED_TRANSFER_SIZE.to_le_bytes());
        out.extend_from_slice(&ASSUMED_BCD_DFU.to_le_bytes());
    }

    Synthesised {
        config: out,
        strings,
        has_functional: has_dfu,
    }
}

/// The `iInterface` for `name`, appending it to the table.
///
/// An empty name keeps index 0, which `read_info` skips without a transfer, so a device
/// that names none of its alternates behaves exactly as this backend did before the
/// names were carried. A table longer than a `u8` can index also answers 0: 255 named
/// alternates cannot happen behind the parser's cap of 32 alts, and a wrapped index would
/// hand out somebody else's name.
fn string_index(strings: &mut Vec<String>, name: &str) -> u8 {
    if name.is_empty() {
        return 0;
    }
    let Ok(index) = u8::try_from(strings.len() + 1) else {
        return 0;
    };
    strings.push(name.to_owned());
    index
}

/// The `GET_DESCRIPTOR(STRING, index)` answer for a table [`build`] returned.
///
/// Out-of-range indices and index 0 both get [`EMPTY_STRING_DESCRIPTOR`]: a caller asking
/// for a string this descriptor never handed out is asking about a device we know nothing
/// about, and an empty descriptor decodes to an empty name rather than stalling EP0.
#[must_use]
pub fn string_descriptor(strings: &[String], index: u8) -> Vec<u8> {
    let Some(name) = index.checked_sub(1).and_then(|slot| strings.get(usize::from(slot))) else {
        return EMPTY_STRING_DESCRIPTOR.to_vec();
    };
    encode_string(name)
}

/// One USB string descriptor: `bLength`, `bDescriptorType`, then UTF-16LE.
///
/// The inverse of `dfu::descriptors::decode_string`, which is what reads it back: it
/// takes `(bLength - 2) / 2` code units, so `bLength` has to count the two header bytes
/// and a truncated name has to be truncated in *units*, never in bytes, or the reader
/// would decode half a code unit as a character.
fn encode_string(name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().take(MAX_STRING_UNITS).collect();
    let len = 2 + units.len() * 2;
    let mut out = Vec::with_capacity(len);
    out.push(u8::try_from(len).unwrap_or(u8::MAX));
    out.push(DESCRIPTOR_STRING);
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Is this a DFU alternate setting (class `0xFE`, subclass `0x01`)?
fn is_dfu(alternate: &Alternate) -> bool {
    alternate.class == DFU_INTERFACE_CLASS && alternate.subclass == DFU_INTERFACE_SUBCLASS
}

/// The debug line that says the transfer size was assumed, not read.
///
/// A function rather than a literal at the call site so the wording is pinned by a test:
/// "logged at debug as assumed rather than read" is a requirement, and a log line nobody
/// checks is a log line that quietly loses the word "assumed".
#[must_use]
pub fn assumed_transfer_size_note() -> String {
    format!(
        "WebUSB strips the DFU functional descriptor: assuming wTransferSize {ASSUMED_TRANSFER_SIZE} \
         and bcdDFU {ASSUMED_BCD_DFU:#06x} rather than reading them"
    )
}

#[cfg(test)]
mod tests {
    use super::{ASSUMED_TRANSFER_SIZE, Alternate, assumed_transfer_size_note, build, string_descriptor};
    use tdfu_core::dfu::descriptors::parse_config;
    use tdfu_core::model::Stage;
    use tdfu_usb::{DeviceDescriptors, pid, vid};

    /// The names a shipped loader gives its three alts, in tree order: alt 0 is the boot flash.
    const GADGET_NAMES: [&str; 3] = ["flash", "erase", "reboot"];

    /// The three alternates a shipped U-Boot DFU loader exposes: `flash`, `erase`,
    /// `reboot`. All DFU class, one interface, three settings.
    fn gadget_alternates() -> Vec<Alternate> {
        named_alternates(&GADGET_NAMES)
    }

    /// The same three alternates as a browser that had no `interfaceName` for any of them
    /// would describe them: the shape before the names were carried through, and what a
    /// loader too old to name its alts still produces.
    fn nameless_alternates() -> Vec<Alternate> {
        named_alternates(&["", "", ""])
    }

    fn named_alternates(names: &[&str]) -> Vec<Alternate> {
        names
            .iter()
            .enumerate()
            .map(|(setting, name)| Alternate {
                interface: 0,
                alternate: u8::try_from(setting).unwrap_or(u8::MAX),
                class: 0xFE,
                subclass: 0x01,
                protocol: 0x02,
                name: (*name).to_owned(),
            })
            .collect()
    }

    /// The bootrom's single vendor-class interface.
    fn bootrom_alternates() -> Vec<Alternate> {
        vec![Alternate {
            interface: 0,
            alternate: 0,
            class: 0xFF,
            subclass: 0x00,
            protocol: 0x00,
            name: String::new(),
        }]
    }

    #[test]
    fn a_gadget_descriptor_parses_back_into_the_dfu_info_core_expects() -> Result<(), tdfu_core::Error> {
        let config = build(1, 1, &gadget_alternates()).config;
        let info = parse_config(&config)?;
        assert_eq!(info.interface, 0);
        assert_eq!(info.alts.len(), 3);
        // 4096, from the synthesised functional descriptor, not
        // `DEFAULT_TRANSFER_SIZE`'s 1024 - which is what a *missing* descriptor yields.
        assert_eq!(info.transfer_size, ASSUMED_TRANSFER_SIZE);
        assert_eq!(info.bcd_dfu, 0x0110);
        assert!(info.is_multi_alt(), "three alts is multi-alt");
        Ok(())
    }

    /// **The named-alternate pin, in the layer that decides the indices.**
    #[test]
    fn every_named_alternate_gets_a_string_index_that_answers_its_name() -> Result<(), tdfu_core::Error> {
        // The browser has the names, so the synthesised descriptor hands
        // each one an `iInterface` and the transport answers for it. When every index was
        // 0, `read_info` skipped every read, every name came back empty, and
        // `AltSel::Default` (the alt named `flash`) could not resolve on any three-alt
        // loader.
        let built = build(1, 1, &gadget_alternates());
        assert_eq!(built.strings, GADGET_NAMES.map(ToOwned::to_owned).to_vec());
        let info = parse_config(&built.config)?;
        assert_eq!(info.alts.iter().map(|alt| alt.alt).collect::<Vec<_>>(), vec![0, 1, 2]);

        // `iInterface` is the ninth byte of each interface descriptor, and the indices
        // run 1, 2, 3 in tree order rather than the device's own 5, 6, 7.
        let indices: Vec<u8> = (0..3).map(|nth| built.config[9 + nth * 9 + 8]).collect();
        assert_eq!(indices, vec![1, 2, 3]);
        for (index, want) in indices.iter().zip(GADGET_NAMES) {
            let descriptor = string_descriptor(&built.strings, *index);
            assert_eq!(descriptor[1], super::DESCRIPTOR_STRING, "{descriptor:?}");
            assert_eq!(usize::from(descriptor[0]), descriptor.len(), "bLength counts itself");
            let decoded: String = descriptor[2..]
                .chunks_exact(2)
                .map(|pair| char::from(pair[0]))
                .collect();
            assert_eq!(decoded, want);
        }
        Ok(())
    }

    #[test]
    fn an_alternate_the_browser_could_not_name_keeps_an_empty_name() -> Result<(), tdfu_core::Error> {
        // `interfaceName` is `null` for a device that carries no `iInterface`, and that is
        // still the nameless shape: index 0, no transfer, an empty name, and the
        // nameless-configuration default in `dfu::alt` is what makes it usable.
        let built = build(1, 1, &nameless_alternates());
        assert!(built.strings.is_empty(), "{:?}", built.strings);
        let info = parse_config(&built.config)?;
        for alt in &info.alts {
            assert!(alt.name.is_empty(), "alt {} has a name: {:?}", alt.alt, alt.name);
        }
        for nth in 0..3 {
            assert_eq!(built.config[9 + nth * 9 + 8], 0, "alt {nth} was given a string index");
        }
        // A mixed device is possible and gets the numbering it earns: only the named
        // alternate takes an index, and it takes the first one.
        let mixed = build(1, 1, &named_alternates(&["", "erase", ""]));
        assert_eq!(mixed.strings, vec!["erase".to_owned()]);
        assert_eq!(
            (0..3).map(|nth| mixed.config[9 + nth * 9 + 8]).collect::<Vec<_>>(),
            vec![0, 1, 0]
        );
        Ok(())
    }

    #[test]
    fn a_string_index_nobody_handed_out_answers_an_empty_descriptor() {
        // Index 0 is the supported-LANGID list, not a name, and an index past the table is
        // a question about a device this descriptor never described. Both answer `[2, 3]`,
        // which `decode_string` reads as "", rather than stalling EP0 and starting the
        // reset-and-retry-once recovery for nothing.
        let strings = vec!["flash".to_owned()];
        assert_eq!(string_descriptor(&strings, 0), super::EMPTY_STRING_DESCRIPTOR);
        assert_eq!(string_descriptor(&strings, 2), super::EMPTY_STRING_DESCRIPTOR);
        assert_eq!(string_descriptor(&[], 1), super::EMPTY_STRING_DESCRIPTOR);
        assert_eq!(
            string_descriptor(&strings, 1),
            vec![12, 3, b'f', 0, b'l', 0, b'a', 0, b's', 0, b'h', 0]
        );
    }

    #[test]
    fn a_name_too_long_for_a_descriptor_is_cut_in_code_units() {
        // `bLength` is a `u8`, so 126 UTF-16 units is the ceiling. Cutting in bytes would
        // leave half a code unit for `decode_string` to read as a character, and a
        // `bLength` that wrapped would describe a descriptor shorter than itself.
        let long = "f".repeat(200);
        let descriptor = string_descriptor(&[long], 1);
        assert_eq!(descriptor.len(), 254);
        assert_eq!(usize::from(descriptor[0]), descriptor.len());
    }

    #[test]
    fn the_header_length_matches_the_body_that_follows_it() {
        // A `wTotalLength` that disagreed with the bytes would make `read_config`'s
        // two-step read (header, then the whole thing) come back short - a
        // `Error::Protocol`, several layers away from the cause.
        for alternates in [gadget_alternates(), bootrom_alternates(), Vec::new()] {
            let config = build(1, 1, &alternates).config;
            let total = u16::from_le_bytes([config[2], config[3]]);
            assert_eq!(usize::from(total), config.len(), "{alternates:?}");
        }
    }

    #[test]
    fn a_dfu_class_with_another_subclass_is_not_a_dfu_interface() {
        // `is_dfu` is `class == 0xFE && subclass == 0x01`, and the gadget/bootrom pair
        // above cannot tell that `&&` from an `||`: one matches both halves and the other
        // matches neither. The rule that avoids this trap: before calling a mutant
        // equivalent, check that the fixture can express the input that separates the
        // operators. These two rows do.
        let wrong_subclass = Alternate {
            interface: 0,
            alternate: 0,
            class: 0xFE,
            subclass: 0x02,
            protocol: 0x02,
            name: String::new(),
        };
        let wrong_class = Alternate {
            interface: 0,
            alternate: 0,
            class: 0xFF,
            subclass: 0x01,
            protocol: 0x00,
            name: String::new(),
        };
        for alternate in [wrong_subclass, wrong_class] {
            let config = build(1, 1, core::slice::from_ref(&alternate)).config;
            assert!(
                !config.windows(2).any(|pair| pair == [9, 0x21]),
                "{alternate:?} was taken for a DFU interface"
            );
        }
    }

    #[test]
    fn the_functional_descriptor_appears_only_for_a_dfu_interface() {
        // A bootrom has no DFU interface, and appending a DFU functional descriptor to
        // its configuration would be inventing a capability.
        let gadget = build(1, 1, &gadget_alternates());
        let bootrom = build(1, 1, &bootrom_alternates());
        assert!(gadget.config.windows(2).any(|pair| pair == [9, 0x21]));
        assert!(!bootrom.config.windows(2).any(|pair| pair == [9, 0x21]));
        // And `has_functional` says the same thing without the scan, which is what the
        // assumed-transfer-size log reads. A byte-pair scan is not the same question:
        // an alternate with `bInterfaceClass` 9 and `bInterfaceSubClass` 0x21 carries
        // that pair with no functional descriptor anywhere.
        assert!(gadget.has_functional);
        assert!(!bootrom.has_functional);
        let confusing = Alternate {
            interface: 9,
            alternate: 0x21,
            class: 0xFF,
            subclass: 0x00,
            protocol: 0x00,
            name: String::new(),
        };
        let scanned = build(1, 1, core::slice::from_ref(&confusing));
        assert!(
            scanned.config.windows(2).any(|pair| pair == [9, 0x21]),
            "the fixture does not separate the scan from the answer: {:?}",
            scanned.config
        );
        assert!(!scanned.has_functional, "a scan would have logged an assumed 4096");
    }

    #[test]
    fn classify_reads_the_synthesised_bytes_the_way_it_reads_real_ones() {
        // The bootrom and the gadget share `a108:c309`, so the
        // descriptor is the only thing that tells them apart - which is exactly why it
        // has to be synthesised rather than left empty. An empty one answers `None`.
        let gadget = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_config_descriptor(build(1, 1, &gadget_alternates()).config);
        let bootrom = DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)
            .with_config_descriptor(build(1, 1, &bootrom_alternates()).config);
        assert_eq!(tdfu_core::ops::classify(&gadget), Some(Stage::Gadget));
        assert_eq!(tdfu_core::ops::classify(&bootrom), Some(Stage::Bootrom));
        assert_eq!(
            tdfu_core::ops::classify(&DeviceDescriptors::new(vid::INGENIC, pid::BOOTROM)),
            None,
            "no descriptor is no evidence"
        );
    }

    #[test]
    fn the_bytes_match_a_real_gadget_where_the_browser_can_know_them() {
        // The functional descriptor captured from a live T32LQ on 2026-08-22
        // (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`):
        //   09 21 0F 00 00 00 10 10 01
        // Not the shim's `09 21 0F FF 00 00 10 10 01`, whose wDetachTimeOut of 255 was
        // invented. Nothing here reads the field; a synthesised descriptor should still
        // look like the device it stands in for.
        let config = build(1, 1, &gadget_alternates()).config;
        let functional = &config[config.len() - 9..];
        assert_eq!(functional, [0x09, 0x21, 0x0F, 0x00, 0x00, 0x00, 0x10, 0x10, 0x01]);
    }

    #[test]
    fn the_assumed_note_says_it_was_assumed() {
        // The rule is 4096, with a debug-level log saying it was assumed rather than
        // read.
        let note = assumed_transfer_size_note();
        assert!(note.contains("assuming"), "{note}");
        assert!(note.contains("4096"), "{note}");
        assert!(note.contains("rather than reading"), "{note}");
    }
}
