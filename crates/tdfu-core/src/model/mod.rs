//! The values the whole tool talks in: families, loaders, what a detection means, what
//! a DFU gadget looks like.
//!
//! Split one concept per file, so that work on one of them does not collide with work
//! on another.

pub mod detection;
pub mod dfu;
pub mod diag;
pub mod stage;
pub mod variant;

pub use detection::{Candidate, Detection, Dram, DramKind, Evidence, Grade, Resolved, SocRegs};
pub use dfu::{AltSel, DEFAULT_TRANSFER_SIZE, DfuAlt, DfuInfo, MAX_ALTS};
pub use diag::{Diag, EfuseLayout, SecureBoot};
pub use stage::Stage;
pub use variant::{Family, GradeSource, Variant};
