//! The JNI surface, exercised through a real in-process `JavaVM` (JDK 21).
//!
//! This is the test the host cannot fake: it caches the `JavaVM` through the real
//! `JNI_OnLoad`, registers a scripted callback through the real `nativeSetCallback`,
//! drives every export through JNI, and asserts the Java callback received exactly the
//! arguments the bridge produced. A tiny `RecordingCallback` class is compiled with
//! `javac` at test time (the app's real `NativeCallback` is an interface; the bridge
//! resolves `onLog` / `onProgress` by name and signature, so a concrete recorder with
//! those two methods is all the surface needs).
//!
//! Each export is called with a fresh `Env` wrapper and a null class (the exports ignore
//! their class), exactly as the JVM would dispatch them. The device-touching exports are
//! called with an invalid fd, so on the host they take their "cannot open the device"
//! path and return the failure value the contract promises - which is enough to pin that
//! each export returns `-1` (or an empty string) rather than a default, without a device.
//!
//! If no in-process JVM is available (`javac` or `libjvm` missing), the test soft-skips,
//! the way the workspace's loader-tree test does - unless `TDFU_REQUIRE_JVM` is set, which
//! turns the skip into a failure so CI cannot pass by silently not running it.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use jni::objects::{JClass, JObject, JString};
use jni::sys::jint;
use jni::{InitArgsBuilder, JNIEnv, JNIVersion, JavaVM};

use crate::callback::{JniSink, Sink, debug_enabled};
use crate::exports;

/// A callback that records the last log and progress into static fields the test reads.
const RECORDING_CALLBACK: &str = r"
public class RecordingCallback {
    public static String lastLog = new String();
    public static int logCount = 0;
    public static int lastPercent = -999;
    public static String lastStage = new String();
    public static String lastMessage = new String();
    public void onLog(String message) { lastLog = message; logCount = logCount + 1; }
    public void onProgress(int percent, String stage, String message) {
        lastPercent = percent; lastStage = stage; lastMessage = message;
    }
}
";

/// A callback whose two methods both throw, for the pending-exception path.
const THROWING_CALLBACK: &str = r#"
public class ThrowingCallback {
    public void onLog(String message) { throw new RuntimeException("onLog threw"); }
    public void onProgress(int percent, String stage, String message) {
        throw new RuntimeException("onProgress threw");
    }
}
"#;

/// An fd no device is behind, so every device-touching export takes its open-failure path.
const BAD_FD: jint = -1;

/// Whether a missing JVM should fail the test rather than skip it.
fn require_jvm() -> bool {
    std::env::var_os("TDFU_REQUIRE_JVM").is_some_and(|value| value != "0")
}

/// Render any error as a string, so the test's `Result<(), String>` stays `unwrap`-free.
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The test's scratch directory, unique per process so parallel `cargo mutants` jobs (or
/// two test binaries) never race on the same `javac` output or staged blobs.
fn scratch_dir() -> PathBuf {
    std::env::temp_dir().join(format!("tdfu_jni_jvm_test_{}", std::process::id()))
}

/// Compile the two callback classes into the scratch directory and return it, or `None` if
/// `javac` is unavailable or fails. One public class per file, so one file each.
fn compile_callback() -> Option<PathBuf> {
    let dir = scratch_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let mut sources = Vec::new();
    for (name, body) in [
        ("RecordingCallback.java", RECORDING_CALLBACK),
        ("ThrowingCallback.java", THROWING_CALLBACK),
    ] {
        let source = dir.join(name);
        std::fs::write(&source, body).ok()?;
        sources.push(source);
    }
    let status = Command::new("javac").arg("-d").arg(&dir).args(&sources).status().ok()?;
    status.success().then_some(dir)
}

/// The process-wide JVM, created once. `JavaVM::new` may be called only once per process,
/// so it is cached; `JNI_OnLoad` caches the same VM in the bridge's own global.
fn jvm() -> Option<&'static JavaVM> {
    static VM: OnceLock<Option<JavaVM>> = OnceLock::new();
    VM.get_or_init(|| {
        let classpath = compile_callback()?;
        let args = InitArgsBuilder::new()
            .version(JNIVersion::V8)
            .option(format!("-Djava.class.path={}", classpath.display()))
            .build()
            .ok()?;
        let vm = JavaVM::new(args).ok()?;
        // Cache the VM in the bridge exactly as the JVM would on load.
        exports::JNI_OnLoad(vm.get_java_vm_pointer(), std::ptr::null_mut());
        Some(vm)
    })
    .as_ref()
}

/// A second `Env` wrapper over this thread's JNI environment, the way an export is handed
/// one. Its `'static` lifetime coerces down to whatever the export's arguments carry.
fn fresh_env(env: &JNIEnv<'_>) -> Result<JNIEnv<'static>, String> {
    // SAFETY: `env` is this attached thread's environment; a second wrapper over the same
    // raw pointer is valid and is what the JVM would pass a native method.
    unsafe { JNIEnv::from_raw(env.get_raw()) }.map_err(err)
}

/// The class argument the exports ignore.
fn null_class() -> JClass<'static> {
    // SAFETY: every export ignores its `class` parameter (`_class`), so a null class is
    // never dereferenced.
    unsafe { JClass::from_raw(std::ptr::null_mut()) }
}

/// Read a `String` static field of the recording callback.
fn static_string(env: &mut JNIEnv<'_>, class: &JClass<'_>, name: &str) -> Result<String, String> {
    let value = env.get_static_field(class, name, "Ljava/lang/String;").map_err(err)?;
    let object = JString::from(value.l().map_err(err)?);
    let text = env.get_string(&object).map_err(err)?;
    Ok(text.into())
}

/// Read an `int` static field of the recording callback.
fn static_int(env: &mut JNIEnv<'_>, class: &JClass<'_>, name: &str) -> Result<i32, String> {
    env.get_static_field(class, name, "I").map_err(err)?.i().map_err(err)
}

/// Call `nativeVariantToString` through JNI and return the string it produced.
fn variant_to_string(env: &mut JNIEnv<'_>, ordinal: i32) -> Result<String, String> {
    let raw = exports::Java_com_thingino_dfu_TdfuBridge_nativeVariantToString(fresh_env(env)?, null_class(), ordinal);
    read_jstring(env, raw)
}

/// `nativeSetDebug`, through the real export: it flips the switch the operations read, and
/// with a callback registered turning it on announces itself with the banner (what the web
/// engine's `setDebug(true)` prints, here with the library's name); turning it off says
/// nothing, so the app's start-up call with a stored "off" adds no line.
fn check_debug_announces_itself(env: &mut JNIEnv<'_>, class: &JClass<'_>) -> Result<(), String> {
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetDebug(fresh_env(env)?, null_class(), 1);
    assert!(debug_enabled(), "nativeSetDebug(true) did not take");
    let on = static_string(env, class, "lastLog")?;
    assert!(
        on.starts_with("Debug logging enabled; libtdfu_jni "),
        "nativeSetDebug(true) did not announce itself: {on:?}"
    );
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetDebug(fresh_env(env)?, null_class(), 0);
    assert!(!debug_enabled(), "nativeSetDebug(false) did not take");
    let off = static_string(env, class, "lastLog")?;
    assert_eq!(off, on, "nativeSetDebug(false) logged something");
    Ok(())
}

/// A callback that throws leaves nothing pending on the thread.
///
/// Both sinks are driven with a callback whose methods throw, and after each one the
/// thread must carry no throwable: the JNI spec makes any later call with one pending
/// undefined (`CheckJNI` aborts the process at the next `NewStringUTF`, mid-flash), and a
/// throwable still installed when the export returns is delivered to Java, turning an
/// operation that succeeded into the callback's exception. The recorder is put back at the
/// end so the rest of the test sees the callback it registered.
fn check_a_throwing_callback_leaves_nothing_pending(env: &mut JNIEnv<'_>, recorder: &JClass<'_>) -> Result<(), String> {
    let class = env.find_class("ThrowingCallback").map_err(err)?;
    let throwing = env.new_object(&class, "()V", &[]).map_err(err)?;
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetCallback(fresh_env(env)?, null_class(), throwing);

    JniSink.log("the callback throws on this line");
    let after_log = env.exception_check().map_err(err)?;
    // Clear it here as well, or a failure would leave the rest of the test making JNI
    // calls with a throwable installed and report something else entirely.
    if after_log {
        let _ = env.exception_clear();
    }
    JniSink.progress(50, "write", "the callback throws on this one too");
    let after_progress = env.exception_check().map_err(err)?;
    if after_progress {
        let _ = env.exception_clear();
    }

    // A fresh recorder: everything the test reads back is a static field of the class.
    let restored = env.new_object(recorder, "()V", &[]).map_err(err)?;
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetCallback(fresh_env(env)?, null_class(), restored);
    assert!(!after_log, "a throwing onLog left its exception pending");
    assert!(!after_progress, "a throwing onProgress left its exception pending");
    Ok(())
}

/// Call `nativeDetectSoc` through JNI and return the string it produced.
fn detect_soc(env: &mut JNIEnv<'_>, fd: jint) -> Result<String, String> {
    let raw = exports::Java_com_thingino_dfu_TdfuBridge_nativeDetectSoc(fresh_env(env)?, null_class(), fd);
    read_jstring(env, raw)
}

/// Turn a raw `jstring` an export returned into an owned `String`.
fn read_jstring(env: &mut JNIEnv<'_>, raw: jni::sys::jstring) -> Result<String, String> {
    if raw.is_null() {
        return Err("export returned a null string".to_owned());
    }
    // SAFETY: `raw` is the local string reference the export just created.
    let jstring = unsafe { JString::from_raw(raw) };
    Ok(env.get_string(&jstring).map_err(err)?.into())
}

#[test]
fn the_jni_surface_delivers_to_a_java_callback() -> Result<(), String> {
    // The debug switch is process-wide and this test flips it; hold the same lock the
    // other switch-moving tests hold, so they cannot observe each other's state.
    let _debug_switch = crate::callback::debug_switch_lock();
    let Some(vm) = jvm() else {
        if require_jvm() {
            return Err("TDFU_REQUIRE_JVM is set but no in-process JVM is available".to_owned());
        }
        eprintln!("skipped: no in-process JVM (javac or libjvm unavailable)");
        return Ok(());
    };

    let mut guard = vm.attach_current_thread().map_err(err)?;
    let env = &mut *guard;

    let class = env.find_class("RecordingCallback").map_err(err)?;

    // A real export returning a String through JNI: the wire-ordinal map, wrapped.
    assert_eq!(variant_to_string(env, 24)?, "t41nq");
    assert_eq!(variant_to_string(env, 999)?, "unknown");

    // Register the recorder through the real `nativeSetCallback`.
    let callback = env.new_object(&class, "()V", &[]).map_err(err)?;
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetCallback(fresh_env(env)?, null_class(), callback);

    check_debug_announces_itself(env, &class)?;

    // `nativeDetectSoc` on a bad fd returns empty and logs its start line then the failure,
    // so the callback is exercised through a real export as well as directly below.
    assert_eq!(detect_soc(env, BAD_FD)?, "");
    assert!(
        static_string(env, &class, "lastLog")?.starts_with("failed to open USB device"),
        "nativeDetectSoc did not log the open failure through the callback"
    );

    // Deliver a log and a progress line the way an operation would, and confirm the Java
    // callback received exactly those arguments on the two methods.
    JniSink.log("Detecting SoC...");
    JniSink.progress(45, "write", "Writing flash: 5/10 bytes");
    // Newline-terminated, as every `jni_log` line the C sent was: the app appends what it
    // is given, so a line without one runs onto the line before it.
    assert_eq!(static_string(env, &class, "lastLog")?, "Detecting SoC...\n");
    assert_eq!(static_int(env, &class, "lastPercent")?, 45);
    assert_eq!(static_string(env, &class, "lastStage")?, "write");
    assert_eq!(static_string(env, &class, "lastMessage")?, "Writing flash: 5/10 bytes");

    check_a_throwing_callback_leaves_nothing_pending(env, &class)?;

    // Every device-touching export returns -1 on a failed open, through real JNI dispatch,
    // rather than a default. A file some of them read is staged so the read path runs
    // before the open fails.
    let scratch = scratch_dir();
    let blob = scratch.join("blob.bin").to_string_lossy().into_owned();
    let out = scratch.join("out.bin").to_string_lossy().into_owned();
    std::fs::write(&blob, b"not a real image").map_err(err)?;

    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeReboot(fresh_env(env)?, null_class(), BAD_FD),
        -1
    );
    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeVerifyFirmware(
            fresh_env(env)?,
            null_class(),
            BAD_FD,
            env.new_string(blob.as_str()).map_err(err)?,
        ),
        -1
    );
    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeBootstrapFiles(
            fresh_env(env)?,
            null_class(),
            BAD_FD,
            env.new_string(blob.as_str()).map_err(err)?,
            env.new_string(blob.as_str()).map_err(err)?,
        ),
        -1
    );
    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeReadFirmware(
            fresh_env(env)?,
            null_class(),
            BAD_FD,
            env.new_string("t31x").map_err(err)?,
            env.new_string(out.as_str()).map_err(err)?,
            env.new_string("").map_err(err)?,
            JObject::null(),
        ),
        -1
    );
    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeWriteFirmware(
            fresh_env(env)?,
            null_class(),
            BAD_FD,
            env.new_string("t31x").map_err(err)?,
            env.new_string(blob.as_str()).map_err(err)?,
            env.new_string("").map_err(err)?,
            JObject::null(),
        ),
        -1
    );
    // `nativeBootstrap` reads its loaders from Android assets, absent on the host, so it
    // fails at "missing asset" - still -1, with a null AssetManager it never dereferences.
    assert_eq!(
        exports::Java_com_thingino_dfu_TdfuBridge_nativeBootstrap(
            fresh_env(env)?,
            null_class(),
            BAD_FD,
            env.new_string("t31x").map_err(err)?,
            env.new_string("").map_err(err)?,
            JObject::null(),
        ),
        -1
    );

    // Clearing the callback stops delivery: a further log must not reach the recorder.
    let before = static_int(env, &class, "logCount")?;
    exports::Java_com_thingino_dfu_TdfuBridge_nativeSetCallback(fresh_env(env)?, null_class(), JObject::null());
    JniSink.log("this must not be delivered");
    assert_eq!(
        static_int(env, &class, "logCount")?,
        before,
        "a log arrived after the callback was cleared"
    );
    Ok(())
}
