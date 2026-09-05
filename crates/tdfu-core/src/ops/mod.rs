//! The public API: one `async fn` per user-visible operation.
//!
//! Every frontend — CLI, daemon, wasm, JNI — is a thin adapter over these. **No
//! frontend re-implements a sequence**, which is how the C tree ended up with
//! `usb_manager_find_devices` and `..._fast` at 95% duplication.
//!
//! Every operation takes the device *and a clock* ([`Sleeper`](crate::clock::Sleeper)),
//! because every one of them waits: the settle after a vendor request, the device's own
//! `bwPollTimeout`, the re-enumeration window after a reset. See
//! [`clock`](crate::clock) for why the clock is mandatory rather than a second set of
//! `_with_clock` entry points.
//!
//! **One file per operation, decided before any of them are written.** A shared
//! `ops/mod.rs` is a bottleneck every operation has to edit; splitting it afterwards is
//! a commit of its own. This file holds only the re-exports and [`classify`].
//!
//! # A completion note precedes the release's verdict, everywhere, on purpose
//!
//! `write`, `verify` and `erase` all emit their `Progress::Note` — `DFU download
//! complete`, `Verify OK: N bytes match`, `Erase complete (verified blank)` — from
//! inside the claimed section, and only afterwards release the interface and let a
//! release failure decide the operation's `Result`. So a run whose release fails prints
//! "complete" and then returns an error.
//!
//! That ordering is the honest one and it is uniform, which is why it is stated once
//! here rather than apologised for three times. The note describes **what the device
//! did**: the bytes are on the flash, the read-back matched, the chip is blank. The
//! release describes what the *host* managed on the way out, and its failure does not
//! un-write the flash. Suppressing the note until the release succeeded would be the
//! misleading order — the operator would see nothing at all for work that completed —
//! and buffering it to re-order the two would put the frontends back in the business of
//! deciding when a completion line is earned, which is what core took over to stop.
//! The exit code still says the run failed.

mod bootstrap;
mod detect;
mod diag;
mod erase;
mod probe;
mod read;
mod reboot;
mod verify;
mod write;

pub use bootstrap::{POST_STAGE1_SETTLE, bootstrap};
pub use detect::detect;
pub use diag::diag;
pub use erase::erase;
pub use probe::{probe, probe_with_progress};
pub use read::read;
pub use reboot::reboot;
pub use verify::verify;
pub use write::write;

pub use crate::dfu::descriptors::classify;
pub use crate::model::Stage;
