//! `thingino-dfu`, the command-line tool.
//!
//! A thin adapter over [`tdfu_core::ops`]: it parses arguments into an ordered plan,
//! runs it, and renders [`Progress`](tdfu_core::Progress). It re-implements no
//! sequence.
//!
//! Two behaviours the flag surface must have, because their absence has already cost
//! real time:
//!
//! * **`-l` alongside an action does not swallow the action.** `thingino-dfu -l -w
//!   fw.bin` printed the device list and exited 0 without writing. Success reported for
//!   a flash that did not happen is the worst failure this tool has.
//! * **`--wait` waits for the right thing.** With `-w`/`-r`/`--erase`/`--reboot` it
//!   waited for a *gadget*, so it hung for ever on the one bus the auto-bootstrap exists
//!   to serve, and the hang skipped a bench harness's cleanup and left a device
//!   powered. The wait target is **any** Ingenic device
//!   (`main.c:248-251`), and that is kept on merit: the two forms differ only with a
//!   leftover gadget on the bus, where the narrow form waits for ever and the broad
//!   form fails in seconds naming the problem.
//!
//! # Layout
//!
//! One concept per file, and the I/O pushed to the edges so the middle is testable:
//! [`cli`], [`plan`], [`alt`] and [`loaders`] are pure (values in, values out);
//! [`list`], [`wait`] and [`target`] are generic over
//! [`LocalUsbBackend`](tdfu_usb::LocalUsbBackend) and
//! [`Sleeper`](tdfu_core::clock::Sleeper); [`images`] is the only module that opens a
//! local file, and it runs before any of them; [`render`] turns a listing into text
//! against a `Write`. `main.rs` is the only place that names
//! [`NativeBackend`](tdfu_usb::native::NativeBackend). An earlier implementation
//! hard-wired it, and an audit found its `main.rs` at 6% coverage as a result.

pub mod alt;
pub mod banner;
pub mod cli;
pub mod exit;
pub mod images;
pub mod list;
pub mod loaders;
pub mod logging;
pub mod plan;
pub mod remote;
pub mod render;
pub mod run;
pub mod runtime;
pub mod target;
pub mod wait;

#[cfg(test)]
mod fake;
