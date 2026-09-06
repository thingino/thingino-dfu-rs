//! What a DFU gadget tells us about itself, and how a caller names an alt.

/// The most alternate settings this host will parse from a configuration
/// descriptor.
pub const MAX_ALTS: usize = 32;

/// The `wTransferSize` used when the functional descriptor is missing or
/// says 0.
///
/// The shipped loaders do carry the descriptor — captured byte-exact from a live T32LQ
/// gadget, `09 21 0F 00 00 00 10 10 01`, `wTransferSize` 4096
/// (`crates/tdfu-core/tests/fixtures/results/t32lq-gadget-descriptors.txt`). WebUSB strips it, and the
/// browser shim synthesises 4096 / DFU 1.10 instead.
pub const DEFAULT_TRANSFER_SIZE: u16 = 1024;

/// How a caller names the alt to operate on.
///
/// [`Index`](AltSel::Index) is `u8` and bounded by [`MAX_ALTS`] at the point of parsing.
/// The C's remote path copies an alt name into a fixed buffer without bounding it
/// (`remote_read_firmware`) and casts a device index to `uint8_t`, so
/// `-i 256` silently flashes device 0. Neither is reproduced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AltSel {
    /// The default alt. The CLI prefers the one named `flash`; the daemon takes
    /// the first alt. Same result on every shipped loader.
    Default,
    /// By `iInterface` string — `"flash"`, `"erase"`, `"reboot"`.
    Name(String),
    /// By `bAlternateSetting`: the way to address an alt whose name the backend could not
    /// read.
    Index(u8),
}

/// One alternate setting of the DFU interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DfuAlt {
    /// `bAlternateSetting`.
    pub alt: u8,
    /// The `iInterface` string, UTF-16LE decoded. Empty when the backend could
    /// not read it.
    pub name: String,
}

impl DfuAlt {
    /// An alt with its name.
    #[must_use]
    pub fn new(alt: u8, name: impl Into<String>) -> Self {
        Self { alt, name: name.into() }
    }
}

/// The DFU interface as the device describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DfuInfo {
    /// `bInterfaceNumber` of the DFU interface.
    pub interface: u8,
    /// `wTransferSize` from the functional descriptor, or [`DEFAULT_TRANSFER_SIZE`].
    pub transfer_size: u16,
    /// `bcdDFUVersion`.
    pub bcd_dfu: u16,
    /// `bmAttributes` from the functional descriptor.
    pub attributes: u8,
    /// Every alt, in descriptor order. At most [`MAX_ALTS`].
    pub alts: Vec<DfuAlt>,
}

impl DfuInfo {
    /// Is this a multi-alt gadget?
    ///
    /// The claim turns on this: `SET_INTERFACE` is issued for alt 0 **only** when it
    /// is, because a single-alt interface may STALL it (USB 9.4.10) and over WebUSB
    /// that stall wedges EP0 for every later request — while skipping it on a multi-alt
    /// gadget after an erase leaves the `erase` alt live and the next image's first
    /// block lands there ("dfu erase: bad token", seen on a T40XP).
    #[must_use]
    pub fn is_multi_alt(&self) -> bool {
        self.alts.len() > 1
    }
}
