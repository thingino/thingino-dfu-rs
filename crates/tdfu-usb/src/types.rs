//! The value types that cross the transport seam.
//!
//! Two shapes here are deliberate departures from an earlier implementation:
//!
//! * **No packed `bmRequestType`.** [`ControlType`] and [`Recipient`] are separate typed
//!   fields, and the direction is carried by the struct itself ([`ControlIn`] versus
//!   [`ControlOut`]). Only libusb wants the byte packed, libusb is banned here,
//!   and packing made the split *fallible* — an error class this deletes.
//! * **No per-call endpoint addresses.** A claim declares its bulk endpoints once
//!   ([`InterfaceSpec`]) and the transfer calls carry none. The earlier one passed a raw
//!   `ep: u8` on every `bulk_in`/`bulk_out`, which forced a per-address endpoint cache
//!   in the native backend with two branches unreachable by construction.

use core::fmt;

/// Transfer direction, from the host's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Device to host.
    In,
    /// Host to device.
    Out,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::In => "IN",
            Self::Out => "OUT",
        })
    }
}

/// The `bmRequestType` type field (USB 2.0 §9.3.1, bits 6:5), as a type.
///
/// This tool uses exactly two: [`Vendor`](ControlType::Vendor) for the bootrom's six
/// requests and [`Class`](ControlType::Class) for the DFU class
/// requests. [`Standard`](ControlType::Standard) is here because descriptor
/// reads go over control transfers rather than a backend's descriptor API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlType {
    /// USB standard request (`GET_DESCRIPTOR`, `SET_INTERFACE`, …).
    Standard,
    /// Class request. DFU 1.1 rides these on EP0.
    Class,
    /// Vendor request. The Ingenic bootrom's `0x00..=0x05`.
    Vendor,
}

/// The `bmRequestType` recipient field (USB 2.0 §9.3.1, bits 4:0), as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recipient {
    /// The device. The bootrom's vendor requests (`0x40` / `0xC0`).
    Device,
    /// An interface. DFU class requests (`0x21` / `0xA1`).
    Interface,
    /// An endpoint.
    Endpoint,
    /// Anything else.
    Other,
}

/// A control transfer that reads from the device.
///
/// `index` is `wIndex` and `value` is `wValue`; for the bootrom's address/length
/// requests they are the high and low halves of a 32-bit value, and for
/// DFU class requests `wIndex` is the interface number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlIn {
    /// `bmRequestType` bits 6:5.
    pub control_type: ControlType,
    /// `bmRequestType` bits 4:0.
    pub recipient: Recipient,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// `wLength`: the most the device may return.
    pub len: u16,
}

/// A control transfer that writes to the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlOut<'a> {
    /// `bmRequestType` bits 6:5.
    pub control_type: ControlType,
    /// `bmRequestType` bits 4:0.
    pub recipient: Recipient,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// The data stage. May be empty — a DFU `DNLOAD` with no data is the manifest
    /// trigger.
    pub data: &'a [u8],
}

/// One bulk endpoint of a claimed interface.
///
/// Constructed only through [`BulkEndpoint::new`], which refuses endpoint number 0 (the
/// control endpoint is not a bulk endpoint) and anything above 15 (USB 2.0 §9.6.6 gives
/// `bEndpointAddress` four bits for the number). That makes the whole "is this a valid
/// endpoint address" question unrepresentable past construction, which is the point:
/// an earlier implementation carried raw `u8` addresses through every transfer call
/// and validated them nowhere.
///
/// The bootrom uses `0x81` IN and `0x01` OUT. The DFU gadget uses neither —
/// DFU rides EP0 entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BulkEndpoint {
    address: u8,
}

impl BulkEndpoint {
    /// A bulk endpoint from its direction and its endpoint number.
    ///
    /// Returns `None` for number 0 or any number above 15.
    #[must_use]
    pub const fn new(direction: Direction, number: u8) -> Option<Self> {
        if number == 0 || number > 15 {
            return None;
        }
        let address = match direction {
            Direction::In => number | 0x80,
            Direction::Out => number,
        };
        Some(Self { address })
    }

    /// A bulk endpoint from a raw `bEndpointAddress`, as it appears in a descriptor.
    ///
    /// Returns `None` if the endpoint number is 0.
    #[must_use]
    pub const fn from_address(address: u8) -> Option<Self> {
        // Bits 6:4 of `bEndpointAddress` are reserved and zero (USB 2.0 §9.6.6), and
        // this accepts them set: `0x71` round-trips as endpoint 1, direction OUT. That
        // is deliberate for now — every address here comes from a descriptor the OS
        // parsed or from a `const` in this crate, so a reserved bit means the descriptor
        // is malformed, and a backend that cannot open the endpoint will say so with the
        // OS's reason. Tightening it would turn a device quirk into a refusal from a
        // layer that cannot explain it. Noted here rather than fixed.
        let number = address & 0x0F;
        if number == 0 {
            return None;
        }
        Some(Self { address })
    }

    /// The raw `bEndpointAddress` — what a backend passes to the OS.
    #[must_use]
    pub const fn address(self) -> u8 {
        self.address
    }

    /// The endpoint number, 1..=15.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.address & 0x0F
    }

    /// Which way the data flows.
    #[must_use]
    pub const fn direction(self) -> Direction {
        if self.address & 0x80 == 0 {
            Direction::Out
        } else {
            Direction::In
        }
    }
}

impl fmt::Display for BulkEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x}", self.address)
    }
}

/// What a claim asks for: one interface, and the bulk endpoints the caller intends to
/// use on it.
///
/// The endpoints are opened **once, here**, where a genuine "this interface has no such
/// endpoint" failure is reachable and correct — instead of on every transfer, where it
/// was unreachable by construction and the native backend needed a per-address cache to
/// answer it.
///
/// The bootrom claims interface 0 with both endpoints. The DFU host
/// claims its interface with [`InterfaceSpec::control_only`], because DFU 1.1 is EP0
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceSpec {
    /// `bInterfaceNumber`.
    pub interface: u8,
    /// The bulk IN endpoint to open, if the caller will read bulk data.
    pub bulk_in: Option<BulkEndpoint>,
    /// The bulk OUT endpoint to open, if the caller will write bulk data.
    pub bulk_out: Option<BulkEndpoint>,
}

impl InterfaceSpec {
    /// Claim `interface` for control transfers only — the DFU case.
    #[must_use]
    pub const fn control_only(interface: u8) -> Self {
        Self {
            interface,
            bulk_in: None,
            bulk_out: None,
        }
    }

    /// Claim `interface` with both bulk endpoints — the bootrom case, which
    /// uses both.
    #[must_use]
    pub const fn with_bulk(interface: u8, bulk_in: BulkEndpoint, bulk_out: BulkEndpoint) -> Self {
        Self {
            interface,
            bulk_in: Some(bulk_in),
            bulk_out: Some(bulk_out),
        }
    }
}

/// Everything `tdfu-core` knows about a device it was handed. Raw bytes; core parses.
///
/// Build with [`DeviceDescriptors::new`] and the `with_*` setters. `bus` and `address`
/// are fields rather than a backend-specific side channel: the CLI's `-l` table
/// and the wire
/// `DeviceEntry` both need them, and a second "detailed" listing
/// call to get them was pure redundancy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceDescriptors {
    /// `idVendor`. Only `0xA108` and `0x601A` are ever opened.
    pub vendor_id: u16,
    /// `idProduct`. Never the sole basis for stage classification.
    pub product_id: u16,
    /// `iProduct`, if the backend read it.
    ///
    /// **Never compare it for equality.** The bootrom's string is `U+00C3`, TAB, SPACE,
    /// `"USB Boot Device"` on every unit seen; test with `contains`.
    pub product_string: Option<String>,
    /// The C `-l` Bus column and the wire `DeviceEntry.bus`; 0 when the backend cannot
    /// tell (WebUSB, Android).
    pub bus: u8,
    /// The C `-l` Addr column and the wire `DeviceEntry.addr`; 0 when unknown.
    pub address: u8,
    /// Physical USB port numbers, root downwards. Empty when unknown — Android and
    /// wasm always. It is the key the daemon uses to remember a
    /// device's SoC across the bootrom to gadget re-enumeration.
    pub port_path: Vec<u8>,
    /// Configuration descriptor **index 0**, full `wTotalLength` bytes — not the active
    /// configuration, which the driverless gadget often does not have, and which
    /// a probe must not set.
    pub config_descriptor: Vec<u8>,
}

impl DeviceDescriptors {
    /// A device with only its VID and PID known.
    #[must_use]
    pub const fn new(vendor_id: u16, product_id: u16) -> Self {
        Self {
            vendor_id,
            product_id,
            product_string: None,
            bus: 0,
            address: 0,
            port_path: Vec::new(),
            config_descriptor: Vec::new(),
        }
    }

    /// Attach `iProduct`.
    #[must_use]
    pub fn with_product_string(mut self, product: impl Into<String>) -> Self {
        self.product_string = Some(product.into());
        self
    }

    /// Attach the bus number and device address.
    #[must_use]
    pub const fn with_bus_address(mut self, bus: u8, address: u8) -> Self {
        self.bus = bus;
        self.address = address;
        self
    }

    /// Attach the physical port path.
    #[must_use]
    pub fn with_port_path(mut self, port_path: impl Into<Vec<u8>>) -> Self {
        self.port_path = port_path.into();
        self
    }

    /// Attach the configuration descriptor at index 0.
    #[must_use]
    pub fn with_config_descriptor(mut self, config: impl Into<Vec<u8>>) -> Self {
        self.config_descriptor = config.into();
        self
    }
}

/// One device from [`LocalUsbBackend::list`](crate::LocalUsbBackend::list): its
/// descriptors, and the backend's own handle for opening it.
///
/// The handle is what removes the rescan: an earlier `open(&DeviceDescriptors)` made
/// every backend re-enumerate the whole bus and match a device by its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered<Id> {
    /// The backend's opaque handle. Meaningful only to the backend that produced it.
    pub id: Id,
    /// What the enumeration read.
    pub descriptors: DeviceDescriptors,
}
