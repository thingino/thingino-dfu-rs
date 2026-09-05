//! The Android frontend: JNI bindings over `tdfu-core`.
//!
//! `thingino-app` pins a `libtdfu-android-<ver>.tar.gz` with a fixed JNI signature, so
//! the surface is the ten `Java_com_thingino_dfu_TdfuBridge_*` functions over the `jni`
//! crate rather than `UniFFI`, which would mean regenerating the app side for no gain.
//! The app must load this `.so` unchanged, so the symbol names, the `0`/`-1`
//! returns, the callback signatures and the bundled-asset paths are the contract; the
//! message text and everything behind the boundary are ours.
//!
//! Android's own constraints, all of them already learned on hardware:
//!
//! * **The device arrives as a file descriptor owned by Java.** The transport is built
//!   from it ([`fd::open_transport`] dups it into an `OwnedFd` and hands that to
//!   [`nusb::Device::from_fd`](tdfu_usb::native::NativeTransport::from_fd), proven on
//!   hardware by the T1 spike, no `unsafe` needed), so nusb owns and closes the dup while
//!   Java's descriptor is untouched.
//! * **No reset and no reopen.** A close-and-reopen before a DFU operation
//!   churns the gadget's controller and wedges EP0 for minutes with nothing on the UART,
//!   so `NativeTransport::reset` is [`UsbErrorKind::Unsupported`](tdfu_usb::UsbErrorKind)
//!   on Android and nothing here calls it.
//! * **No port path, no bus enumeration**: there is one device, the one Java handed over,
//!   so the operations run on the transport directly rather than through a backend that
//!   would enumerate, and [`DeviceDescriptors::port_path`](tdfu_usb::DeviceDescriptors)
//!   is empty.
//! * **Panics must not cross the JNI boundary** - unwinding across it is undefined
//!   behaviour. `catch_unwind` at the edge of every export, a caught panic
//!   becomes `-1` or an empty string.
//!
//! `unsafe` is permitted in this crate and nowhere else but the FFI edge of a `tdfu-usb`
//! backend, and every block carries a `// SAFETY:` comment. Here it is the `JavaVM` and
//! `AAssetManager` FFI edges: [`exports::JNI_OnLoad`] and [`asset`].
//!
//! # Module map
//!
//! * [`exports`] - the ten `Java_*` functions and `JNI_OnLoad`; each is a thin, panic-
//!   guarded wrapper.
//! * [`callback`] - the cached `JavaVM` and the registered log/progress callback.
//! * [`run`] - driving one operation to completion and collapsing it to `0`/`-1` or a name.
//! * [`progress`] - mapping `ops::Progress` to the callback's `(percent, stage, message)`.
//! * [`variant`] - the wire-ordinal name and the app's bundled-asset directory map.
//! * [`fd`] - dup-to-`OwnedFd`, so Java's descriptor is never closed.
//! * [`asset`] - reading a bundled loader through the NDK `AAssetManager`.
//! * [`exec`] - the parking executor that blocks the app's worker thread.
//!
//! # A duplicate `thiserror`
//!
//! `jni` 0.21 (chosen for its stable, classic API - the app must load this `.so`
//! unchanged) still depends on `thiserror` 1, while the workspace is on `thiserror` 2, so
//! this crate's tree carries both. It is a permissively licensed, Android-only wart:
//! `clippy.toml`'s `allowed-duplicate-crates` names `thiserror`/`thiserror-impl` (the
//! central home for lint config) and `deny.toml` records the matching `bans.skip`. Moving to
//! `jni` 0.22 would remove it (it is on `thiserror` 2) at the cost of the 0.22 API redesign.

mod asset;
mod callback;
mod exec;
mod exports;
mod fd;
mod progress;
mod run;
mod variant;

#[cfg(test)]
mod jvm_test;
