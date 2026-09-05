//! The ten `Java_com_thingino_dfu_TdfuBridge_*` exports and `JNI_OnLoad`.
//!
//! This is the drop-in surface: the symbol names, the `0`/`-1` returns, the empty string
//! on a failed `String` return, and the two callback signatures are the contract with
//! `thingino-app`'s `TdfuBridge.kt`, which must load this `.so` unchanged. The message
//! text and everything behind the boundary are ours.
//!
//! Every body is wrapped so a panic becomes `-1` (or an empty string) and never unwinds
//! into the JVM, which is undefined behaviour. Each export is thin: it
//! parses its arguments, opens the device from Java's fd, and hands a ready future to
//! [`run::finish`] or the name to [`run::drive_detect`].
#![allow(
    non_snake_case,
    reason = "the JNI symbol names are fixed by the Java package/class/method and are the contract"
)]

use core::ffi::c_void;
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use jni::objects::{JClass, JObject, JString};
use jni::sys::{JNI_VERSION_1_6, jboolean, jint, jstring};
use jni::{JNIEnv, JavaVM};

use tdfu_core::clock::BlockingClock;
use tdfu_core::model::AltSel;
use tdfu_core::ops;
use tdfu_usb::native::NativeTransport;

use crate::callback::{self, JniSink, Sink};
use crate::progress::route;
use crate::{asset, fd, run, variant};

/// The `jint` a native operation returns on any failure; the detail goes to the log
/// callback, never to the return. Success is `0`, returned by [`run::finish`].
const FAILURE: jint = -1;

// ============================ JNI lifecycle ============================

/// Cache the `JavaVM` and declare JNI 1.6, as the C's `JNI_OnLoad` does
/// (`tdfu_jni.c:46-49`). The callback plumbing reaches the VM through this.
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: *mut jni::sys::JavaVM, _reserved: *mut c_void) -> jint {
    // SAFETY: `vm` is the JavaVM pointer the JVM passes to JNI_OnLoad; it is valid for the
    // life of the VM, and `from_raw` only wraps it.
    if let Ok(vm) = unsafe { JavaVM::from_raw(vm) } {
        callback::store_vm(vm);
    }
    JNI_VERSION_1_6
}

// ============================ panic guards ============================

/// Run `body`, mapping any caught panic to [`FAILURE`] so nothing unwinds across JNI.
fn guard_int(body: impl FnOnce() -> jint) -> jint {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(FAILURE)
}

/// Run `body`, swallowing any panic (for the two `void` exports).
fn guard_void(body: impl FnOnce()) {
    let _ = catch_unwind(AssertUnwindSafe(body));
}

/// Run `body`, turning its `String` (or an empty string on a caught panic) into a Java
/// string; a `null` return only if the JVM itself cannot allocate the string.
fn guard_string(env: &mut JNIEnv<'_>, body: impl FnOnce() -> String) -> jstring {
    let text = catch_unwind(AssertUnwindSafe(body)).unwrap_or_default();
    env.new_string(text).map_or(core::ptr::null_mut(), JString::into_raw)
}

// ============================ argument helpers ============================

/// Read a Java string argument into an owned `String`, or `None` if it is null or
/// unreadable (the C returns `-1` for a null string argument, `tdfu_jni.c:395`).
fn arg_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> Option<String> {
    if value.as_raw().is_null() {
        return None;
    }
    let text = env.get_string(value).ok().map(String::from);
    // A failed read leaves the JVM's exception pending; the export turns the `None` into
    // its own `-1`, and a throwable travelling back alongside it would replace that.
    callback::clear_pending_exception(env);
    text
}

/// Open the device Java handed over, logging and returning `None` on failure.
fn open_device(sink: JniSink, fd: jint) -> Option<NativeTransport> {
    match fd::open_transport(fd) {
        Ok(transport) => Some(transport),
        Err(error) => {
            sink.log(&format!("failed to open USB device: {error}"));
            None
        }
    }
}

/// On success, send the C bridge's completion line at 100% (`tdfu_jni.c:508,559,602,638`).
///
/// It is what fills the app's bar, and for a read it is what ends the indeterminate bar:
/// the bridge cannot know a whole-chip read's total, so its counter reports
/// [`progress::UNKNOWN`](crate::progress::UNKNOWN) until the end. A failure has already
/// been logged by [`run::finish`] and leaves the bar where it was, as the C did (the app
/// resets it when the call returns).
fn complete(sink: JniSink, code: jint, stage: &str, done: &str) -> jint {
    if code == 0 {
        sink.progress(100, stage, done);
    }
    code
}

/// Open a device and USB-boot `stage1` + U-Boot onto it. Shared by both bootstrap exports.
fn bootstrap_blobs(fd: jint, stage1: &[u8], uboot: &[u8]) -> jint {
    let sink = JniSink;
    let Some(transport) = open_device(sink, fd) else {
        return FAILURE;
    };
    let clock = BlockingClock;
    let mut relay = |progress| route(&sink, progress);
    let operation = ops::bootstrap(&transport, &clock, stage1, uboot, &mut relay);
    let code = run::finish(&sink, "DFU bootstrap failed", operation);
    complete(sink, code, "bootstrap", "DFU U-Boot running")
}

// ============================ the ten exports ============================

/// `nativeSetCallback` - register (or, for null, clear) the log/progress callback.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeSetCallback<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    callback: JObject<'local>,
) {
    guard_void(|| callback::set_callback(&mut env, &callback));
}

/// `nativeSetDebug` - turn verbose logging on or off.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeSetDebug<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    enabled: jboolean,
) {
    guard_void(|| callback::set_debug(enabled != 0));
}

/// `nativeDetectSoc` - identify the SoC on the bootrom; the variant name, or empty on
/// failure.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeDetectSoc<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
) -> jstring {
    guard_string(&mut env, || {
        let sink = JniSink;
        sink.log("Detecting SoC...");
        callback::debug_log(|| format!("nativeDetectSoc: fd={fd}"));
        match open_device(sink, fd) {
            Some(transport) => run::drive_detect(&sink, &transport),
            None => String::new(),
        }
    })
}

/// `nativeVariantToString` - render a `tdfu_variant_t` wire ordinal as its app-facing
/// name.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeVariantToString<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    variant: jint,
) -> jstring {
    guard_string(&mut env, || variant::variant_to_string(variant).to_owned())
}

/// `nativeBootstrap` - USB-boot the bundled DFU U-Boot for `variant` onto the bootrom.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeBootstrap<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    variant: JString<'local>,
    _firmware_dir: JString<'local>,
    asset_manager: JObject<'local>,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        // `firmwareDir` is the C's scratch directory for staged asset files; here the
        // assets are read straight into memory, so there is nothing to stage.
        let Some(variant) = arg_string(&mut env, &variant) else {
            sink.log("DFU bootstrap: no variant supplied");
            return FAILURE;
        };
        // The loader lives in the app's assets under its own directory name; a name that
        // is not a loader directory has no assets, so there is nothing to bootstrap.
        let Some(dir) = variant::asset_dir(&variant) else {
            sink.log(&format!("DFU bootstrap: {variant:?} is not a loader this app bundles"));
            return FAILURE;
        };
        sink.log("DFU bootstrap (bootrom -> U-Boot DFU gadget)...");

        // Stage 1 is `tpl.bin` on the capped XBurst1 SoCs and `spl.bin` on the big-SPL
        // ones - try tpl first, exactly as the C does (`tdfu_jni.c:421-426`).
        let stage1 = asset::read_asset(&env, &asset_manager, &format!("firmware/dfu/{dir}/tpl.bin"))
            .or_else(|| asset::read_asset(&env, &asset_manager, &format!("firmware/dfu/{dir}/spl.bin")));
        let uboot = asset::read_asset(&env, &asset_manager, &format!("firmware/dfu/{dir}/uboot.bin"));
        let (Some(stage1), Some(uboot)) = (stage1, uboot) else {
            sink.log(&format!("missing DFU firmware asset for {dir}"));
            return FAILURE;
        };
        callback::debug_log(|| {
            format!(
                "nativeBootstrap: fd={fd} variant={variant} assets=firmware/dfu/{dir} stage1={} bytes u-boot={} bytes",
                stage1.len(),
                uboot.len()
            )
        });
        bootstrap_blobs(fd, &stage1, &uboot)
    })
}

/// `nativeBootstrapFiles` - USB-boot a caller-supplied SPL + U-Boot from two file paths.
/// A bootstrap takes both blobs or neither; one alone is an error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeBootstrapFiles<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    spl_path: JString<'local>,
    uboot_path: JString<'local>,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        let (Some(spl_path), Some(uboot_path)) = (arg_string(&mut env, &spl_path), arg_string(&mut env, &uboot_path))
        else {
            sink.log("DFU bootstrap: missing SPL or U-Boot path");
            return FAILURE;
        };
        sink.log("DFU bootstrap with custom SPL/U-Boot (bootrom -> U-Boot DFU gadget)...");
        let (Ok(stage1), Ok(uboot)) = (std::fs::read(&spl_path), std::fs::read(&uboot_path)) else {
            sink.log("cannot read the custom SPL/U-Boot files");
            return FAILURE;
        };
        callback::debug_log(|| {
            format!(
                "nativeBootstrapFiles: fd={fd} spl={spl_path} ({} bytes) uboot={uboot_path} ({} bytes)",
                stage1.len(),
                uboot.len()
            )
        });
        bootstrap_blobs(fd, &stage1, &uboot)
    })
}

/// `nativeReadFirmware` - DFU-upload the boot flash of the running gadget to `outputFile`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeReadFirmware<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    _variant: JString<'local>,
    output_file: JString<'local>,
    _firmware_dir: JString<'local>,
    _asset_manager: JObject<'local>,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        // The gadget is already running; the read is a DFU upload of the default alt
        // (the one named `flash`, else the only one), so `variant`/`firmwareDir`/
        // `assetManager` are unused, as the C `(void)`s them (`tdfu_jni.c:528-530`).
        let Some(output) = arg_string(&mut env, &output_file) else {
            sink.log("DFU read: no output file supplied");
            return FAILURE;
        };
        sink.log("DFU read (U-Boot gadget)...");
        let Some(transport) = open_device(sink, fd) else {
            return FAILURE;
        };
        let mut file = match std::fs::File::create(&output) {
            Ok(file) => file,
            Err(error) => {
                sink.log(&format!("cannot create {output}: {error}"));
                return FAILURE;
            }
        };
        let clock = BlockingClock;
        let alt = AltSel::Default;
        let mut relay = |progress| route(&sink, progress);
        callback::debug_log(|| format!("nativeReadFirmware: fd={fd} output={output}"));
        let operation = ops::read(&transport, &clock, &alt, None, &mut file, &mut relay);
        let code = run::finish(&sink, "DFU read failed", operation);
        complete(sink, code, "read", "Read complete!")
    })
}

/// `nativeWriteFirmware` - DFU-download `inputFile` to the boot flash of the running
/// gadget.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeWriteFirmware<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    _variant: JString<'local>,
    input_file: JString<'local>,
    _firmware_dir: JString<'local>,
    _asset_manager: JObject<'local>,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        let Some(input) = arg_string(&mut env, &input_file) else {
            sink.log("DFU write: no input file supplied");
            return FAILURE;
        };
        sink.log("DFU write (U-Boot gadget)...");
        let image = match std::fs::read(&input) {
            Ok(image) => image,
            Err(error) => {
                sink.log(&format!("cannot read {input}: {error}"));
                return FAILURE;
            }
        };
        let Some(transport) = open_device(sink, fd) else {
            return FAILURE;
        };
        let clock = BlockingClock;
        let alt = AltSel::Default;
        let mut relay = |progress| route(&sink, progress);
        callback::debug_log(|| format!("nativeWriteFirmware: fd={fd} input={input} ({} bytes)", image.len()));
        let operation = ops::write(&transport, &clock, &alt, &image, &mut relay);
        let code = run::finish(&sink, "DFU write failed", operation);
        complete(sink, code, "write", "Write complete!")
    })
}

/// `nativeVerifyFirmware` - read the boot flash back and compare it against `inputFile`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeVerifyFirmware<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    input_file: JString<'local>,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        let Some(input) = arg_string(&mut env, &input_file) else {
            sink.log("DFU verify: no input file supplied");
            return FAILURE;
        };
        sink.log("DFU verify (reading back)...");
        let image = match std::fs::read(&input) {
            Ok(image) => image,
            Err(error) => {
                sink.log(&format!("cannot read {input}: {error}"));
                return FAILURE;
            }
        };
        let Some(transport) = open_device(sink, fd) else {
            return FAILURE;
        };
        let clock = BlockingClock;
        let alt = AltSel::Default;
        let mut relay = |progress| route(&sink, progress);
        // `ops::verify`'s `Error::Verify` Display already carries the mismatch offset, so
        // the C's special-cased offset line needs nothing extra here.
        callback::debug_log(|| format!("nativeVerifyFirmware: fd={fd} input={input} ({} bytes)", image.len()));
        let operation = ops::verify(&transport, &clock, &alt, &image, &mut relay);
        let code = run::finish(&sink, "DFU verify failed", operation);
        complete(sink, code, "verify", "Verify OK!")
    })
}

/// `nativeReboot` - trigger the loader's reboot so the device leaves DFU.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_thingino_dfu_TdfuBridge_nativeReboot<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
) -> jint {
    guard_int(|| {
        let sink = JniSink;
        sink.log("DFU reboot: resetting the device...");
        let Some(transport) = open_device(sink, fd) else {
            return FAILURE;
        };
        let clock = BlockingClock;
        let mut relay = |progress| route(&sink, progress);
        callback::debug_log(|| format!("nativeReboot: fd={fd}"));
        let operation = ops::reboot(&transport, &clock, &mut relay);
        run::finish(&sink, "DFU reboot failed", operation)
    })
}

#[cfg(test)]
mod tests {
    use super::{guard_int, guard_void};

    /// The panic edge: a caught panic in a `jint` body becomes `-1`, and a normal return
    /// is untouched. This pins the panic edge without adding an eleventh
    /// symbol - the "export whose inner logic panics" is the closure the guard wraps.
    #[test]
    #[expect(
        clippy::panic,
        reason = "the panic is the fixture: a body that unwinds must be caught and mapped to -1"
    )]
    fn a_panicking_body_is_caught_and_returns_failure() {
        // The literal the boundary promises, not the `FAILURE` symbol, so flipping the
        // constant's sign is caught rather than compared against itself.
        assert_eq!(guard_int(|| panic!("boom")), -1);
        assert_eq!(guard_int(|| 0), 0);

        // `guard_void` runs its body, and swallows a panic rather than unwinding into the
        // JVM.
        let mut ran = false;
        guard_void(|| ran = true);
        assert!(ran, "guard_void did not run its body");
        guard_void(|| panic!("boom"));
    }
}
