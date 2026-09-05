//! Everything `thingino-dfu` knows how to do, with no frontend and no backend in it.
//!
//! Generic over [`LocalUsbTransport`](tdfu_usb::LocalUsbTransport) and
//! [`Sleeper`](clock::Sleeper), so the bootrom sequence, the DFU state machine and
//! every operation are written once and exercised against a scripted mock in tests.
//! The CLI, the daemon, the browser and Android are thin adapters over
//! [`ops`].
//!
//! # The two rules this crate exists to keep
//!
//! **Detection executes nothing on the device.** Three memory reads at kseg1 addresses
//! replace the C's 606-byte hand-assembled MIPS stub, which it uploads and runs through
//! the mask ROM's one-shot `PROG_STAGE1`. Proven on twelve devices and confirmed on the
//! wire by a differential USB capture. See [`addr`] for why the
//! address form is a type and not a convention.
//!
//! **The C is the specification of correct *device* behaviour, and nothing else.** It
//! encodes months of hardware debugging — the grace tiers, the blank check, reboot's
//! load-bearing post-ZLP poll — and it is the authority on what the device does.
//! It is not a model for error handling, message text, exit codes or
//! API shape, and its bugs are not reproduced.

#![forbid(unsafe_code)]

pub mod addr;
pub mod bootrom;
pub mod build;
pub mod clock;
pub mod detect;
pub mod dfu;
pub mod error;
#[cfg(not(target_family = "wasm"))]
pub mod loader;
pub mod model;
pub mod ops;
pub mod progress;

pub use error::{Error, Result};
pub use model::{
    AltSel, Candidate, Detection, DfuAlt, DfuInfo, Diag, Dram, DramKind, Evidence, Family, Resolved, SocRegs, Stage,
    Variant,
};
pub use progress::{Phase, Progress, ProgressSink};
