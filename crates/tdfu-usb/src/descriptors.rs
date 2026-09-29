//! Reading a raw configuration descriptor and writing a setup packet's `bmRequestType`,
//! for a backend whose platform hands over bytes rather than a parsed tree.
//!
//! Compiled for the ESP-IDF backend and for this crate's tests, so the parsing is checked
//! on the host even though its only caller builds for the ESP32 alone.

use crate::{ControlType, Direction, Recipient};

const INTERFACE: u8 = 0x04;
const ENDPOINT: u8 = 0x05;

/// Every descriptor in `config` that sits in alternate setting 0 of `interface`, in order.
fn in_interface(config: &[u8], interface: u8) -> impl Iterator<Item = &[u8]> {
    let mut current = None;
    let mut rest = config;
    core::iter::from_fn(move || {
        loop {
            let len = usize::from(*rest.first()?);
            // A zero or overlong length is a malformed tail; nothing after it is trusted.
            let (desc, tail) = rest.split_at_checked(len).filter(|_| len >= 2)?;
            rest = tail;
            match desc[1] {
                INTERFACE if len >= 4 => current = Some((desc[2], desc[3])),
                _ if current == Some((interface, 0)) => return Some(desc),
                _ => {}
            }
        }
    })
}

/// `wMaxPacketSize` of the endpoint at `address` in alternate setting 0 of `interface`.
pub(crate) fn endpoint_mps(config: &[u8], interface: u8, address: u8) -> Option<usize> {
    in_interface(config, interface)
        .find(|desc| desc[1] == ENDPOINT && desc.len() >= 7 && desc[2] == address)
        .map(|desc| usize::from(u16::from_le_bytes([desc[4], desc[5]]) & 0x7ff))
}

/// Every endpoint address in alternate setting 0 of `interface`.
pub(crate) fn interface_endpoints(config: &[u8], interface: u8) -> Vec<u8> {
    in_interface(config, interface)
        .filter(|desc| desc[1] == ENDPOINT && desc.len() >= 3)
        .map(|desc| desc[2])
        .collect()
}

/// A setup packet's `bmRequestType`.
pub(crate) const fn request_type(direction: Direction, control_type: ControlType, recipient: Recipient) -> u8 {
    let direction = match direction {
        Direction::In => 0x80,
        Direction::Out => 0x00,
    };
    let control_type = match control_type {
        ControlType::Standard => 0x00,
        ControlType::Class => 0x20,
        ControlType::Vendor => 0x40,
    };
    let recipient = match recipient {
        Recipient::Device => 0,
        Recipient::Interface => 1,
        Recipient::Endpoint => 2,
        Recipient::Other => 3,
    };
    direction | control_type | recipient
}

#[cfg(test)]
mod tests {
    use super::{endpoint_mps, interface_endpoints, request_type};
    use crate::{ControlType, Direction, Recipient};

    /// The Ingenic bootrom's configuration: one interface, bulk IN 0x81 and OUT 0x01 at 64
    /// bytes (full speed), with a second interface and an alternate setting of the first
    /// added so that neither is mistaken for it.
    const CONFIG: &[u8] = &[
        9, 0x02, 55, 0, 2, 1, 0, 0x80, 50, // configuration, wTotalLength 55
        9, 0x04, 0, 0, 2, 0xff, 0, 0, 0, // interface 0, alt 0
        7, 0x05, 0x81, 0x02, 64, 0, 0, // bulk IN 0x81, 64
        7, 0x05, 0x01, 0x02, 64, 0, 0, // bulk OUT 0x01, 64
        9, 0x04, 0, 1, 1, 0xff, 0, 0, 0, // interface 0, alt 1
        7, 0x05, 0x82, 0x02, 0, 2, 0, // bulk IN 0x82, 512: not alt 0
        9, 0x04, 1, 0, 0, 0xfe, 1, 2, 0, // interface 1, alt 0: DFU, no endpoints
    ];

    #[test]
    fn endpoints_are_read_from_alternate_setting_zero_of_the_interface() {
        assert_eq!(endpoint_mps(CONFIG, 0, 0x81), Some(64));
        assert_eq!(endpoint_mps(CONFIG, 0, 0x01), Some(64));
        assert_eq!(endpoint_mps(CONFIG, 0, 0x82), None, "alt 1's endpoint is not alt 0's");
        assert_eq!(
            endpoint_mps(CONFIG, 1, 0x81),
            None,
            "nor is interface 0's interface 1's"
        );
        assert_eq!(interface_endpoints(CONFIG, 0), vec![0x81, 0x01]);
        assert_eq!(interface_endpoints(CONFIG, 1), Vec::<u8>::new());
    }

    /// A malformed descriptor ends the walk instead of being read past.
    #[test]
    fn a_malformed_length_ends_the_walk() {
        let mut truncated = CONFIG[..20].to_vec();
        truncated.extend_from_slice(&[40, 0x05, 0x01]); // claims 40 bytes, has 3
        assert_eq!(interface_endpoints(&truncated, 0), Vec::<u8>::new());
        let zero = [9, 0x04, 0, 0, 1, 0xff, 0, 0, 0, 0, 0x05, 0x81];
        assert_eq!(interface_endpoints(&zero, 0), Vec::<u8>::new());
        assert_eq!(endpoint_mps(&[], 0, 0x81), None);
    }

    /// The high bits of `wMaxPacketSize` count extra transactions per microframe, not bytes.
    #[test]
    fn the_transaction_bits_are_not_part_of_the_packet_size() {
        let config = [9, 0x04, 0, 0, 1, 0xff, 0, 0, 0, 7, 0x05, 0x81, 0x03, 0x00, 0x14, 1];
        assert_eq!(endpoint_mps(&config, 0, 0x81), Some(0x400));
    }

    #[test]
    fn request_type_packs_direction_type_and_recipient() {
        assert_eq!(
            request_type(Direction::In, ControlType::Vendor, Recipient::Device),
            0xc0
        );
        assert_eq!(
            request_type(Direction::Out, ControlType::Vendor, Recipient::Device),
            0x40
        );
        assert_eq!(
            request_type(Direction::Out, ControlType::Standard, Recipient::Endpoint),
            0x02
        );
        assert_eq!(
            request_type(Direction::Out, ControlType::Standard, Recipient::Interface),
            0x01
        );
        assert_eq!(
            request_type(Direction::In, ControlType::Class, Recipient::Interface),
            0xa1
        );
        assert_eq!(request_type(Direction::Out, ControlType::Class, Recipient::Other), 0x23);
    }
}
