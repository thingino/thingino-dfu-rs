//! Which stage of its life a device is in.

/// What a device on the bus currently is.
///
/// **Classified from the configuration descriptor, never from the product ID.**
/// The DFU gadget was re-PID'd to share the bootrom's `0xC309` on
/// 2026-07-24, so the C's PID check (`manager.c:53-68`) reports *bootrom* for every
/// current gadget — which makes its own gadget branch dead code and would run the
/// CPU-info probe against a gadget. The descriptor-first rule is one an earlier
/// implementation got right, and it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// The mask ROM, waiting for a stage-1 image. Vendor requests only.
    Bootrom,
    /// A U-Boot DFU gadget: some interface has class `0xFE` subclass `0x01`.
    Gadget,
    /// Running firmware that answers the Ingenic VID but is neither of the above.
    Firmware,
}

impl core::fmt::Display for Stage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Bootrom => "bootrom",
            Self::Gadget => "gadget",
            Self::Firmware => "firmware",
        })
    }
}
