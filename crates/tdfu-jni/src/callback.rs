//! The registered Java callback, and the cached `JavaVM` that reaches it.
//!
//! `JNI_OnLoad` caches the `JavaVM`; `nativeSetCallback` holds a global reference to the
//! callback object so it survives past the call that set it (a plain local reference would
//! be freed when that native method returns). Every log and progress line an operation
//! emits arrives here and is delivered on whatever thread the operation is running on -
//! the app's worker thread, already attached because the native call came from Java.
//!
//! # The lock is never held across a Java call
//!
//! The C holds a `pthread_mutex` only long enough to read the callback pointer and method
//! ids, then unlocks before calling into the JVM (`tdfu_jni.c:64-74`). This does the same:
//! the global reference is cloned out from under the lock (a `GlobalRef` is cheap to
//! clone - it is a reference count, not a new JNI global ref) and the lock is dropped
//! before `call_method`. Calling into Java under the lock could deadlock against a thread
//! that re-enters `nativeSetCallback`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};

/// The `JavaVM`, cached by `JNI_OnLoad`. This is the JNI lifecycle, nothing to do with a
/// device boot. `OnceLock` because `JNI_OnLoad` runs exactly once, before any
/// native method, and nothing ever needs to replace it.
static VM: OnceLock<JavaVM> = OnceLock::new();

/// The registered callback, or `None`. Replaced (never mutated in place) by
/// `nativeSetCallback`; the old reference is dropped, which deletes its JNI global ref.
static CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// The app's verbose-logging switch (`nativeSetDebug`). The C exposes this as
/// `g_debug_enabled` to gate libtdfu's `LOG_DEBUG` stream into the app's log; here it
/// gates what reaches the callback through [`debug_log`] and [`debug_log_to`]:
///
/// * a banner with the version when it is turned on (what the web engine's `setDebug`
///   prints), and the identification detail behind a detection;
/// * an entry line per native call with its arguments (the lines the C sent to logcat with
///   `LOGI`, `tdfu_jni.c:401,479,540,590,626,657`);
/// * **the core's own protocol narration** ([`Progress::Debug`](tdfu_core::Progress)),
///   routed here by [`progress::route`](crate::progress::route): the `make_idle` polls, a
///   forgiven busy poll, the DFU descriptors and each alt, which alt was claimed and why,
///   the upload's start and its short block, a download's alt and block size, a failed
///   block, and both bootstrap stages with their addresses. That is the C's `LOG_DEBUG`
///   coverage, which this bridge had none of until core grew a channel for it: with debug
///   on, a 32 MiB flash used to produce one extra line (2026-09-03).
static DEBUG: AtomicBool = AtomicBool::new(false);

/// Cache the `JavaVM`. Called once, from `JNI_OnLoad`.
pub(crate) fn store_vm(vm: JavaVM) {
    // First writer wins. `JNI_OnLoad` is the only caller and runs once, so the result is
    // ignored rather than treated as an error.
    let _ = VM.set(vm);
}

/// Register (or, for a null object, clear) the callback.
///
/// A null object clears it, matching `nativeSetCallback(null)` on the Kotlin side and the
/// C's `if (callback)` guard (`tdfu_jni.c:293`). A global reference that cannot be created
/// leaves no callback rather than a dangling one.
pub(crate) fn set_callback(env: &mut JNIEnv<'_>, callback: &JObject<'_>) {
    let replacement = if callback.as_raw().is_null() {
        None
    } else {
        let global = env.new_global_ref(callback).ok();
        // A global reference the JVM could not allocate leaves an `OutOfMemoryError`
        // pending; the export must not carry it back into Java on top of leaving no
        // callback registered.
        clear_pending_exception(env);
        global
    };
    *lock() = replacement;
}

/// Report and clear a pending Java exception, so nothing after this call runs with one.
///
/// A JNI call that returns after the Java it invoked threw leaves the throwable installed
/// on the thread, and the spec makes every later JNI call with one pending undefined: on a
/// debuggable Android build `CheckJNI` aborts the process at the next `NewStringUTF`, in the
/// middle of a flash, and with `CheckJNI` off the throwable is delivered to Java the moment
/// the export returns, so an operation that actually succeeded surfaces to Kotlin as the
/// callback's exception rather than as `0`.
///
/// `exception_describe` prints the throwable and its stack to the JVM's own stream
/// (logcat on Android) and clears it; the `exception_clear` after it covers a describe that
/// failed. It deliberately does not go through the log callback: the callback is what
/// threw, so reporting there would re-enter it and throw again.
pub(crate) fn clear_pending_exception(env: &mut JNIEnv<'_>) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
}

/// Set the verbose-logging switch (`nativeSetDebug`).
///
/// Turning it on says so at once, with the build's version line, the way the web engine's
/// `setDebug(true)` does: the operator sees the switch take effect without having to run
/// something, and the version is the first thing a bug report needs. Turning it off is
/// silent, so the app's start-up call with a stored "off" adds nothing to the log.
pub(crate) fn set_debug(enabled: bool) {
    DEBUG.store(enabled, Ordering::Relaxed);
    if enabled {
        JniSink.log(&format!(
            "Debug logging enabled; {}",
            tdfu_core::build::banner("libtdfu_jni")
        ));
    }
}

/// Log a line only when the debug switch is on. The closure keeps the formatting off the
/// non-debug path, which matters for lines in the per-call entry points.
pub(crate) fn debug_log(line: impl FnOnce() -> String) {
    debug_log_to(&JniSink, line);
}

/// [`debug_log`], to a sink the caller names.
///
/// The pair exists for [`progress::route`](crate::progress::route), which is handed the
/// sink it must deliver to and is driven by the host tests through a recording one. Both
/// halves have to be pinned together: that a narration line goes through the *switch*, and
/// that it goes to the *callback*, which a `JniSink` hard-wired inside this function would
/// make untestable without a JVM.
pub(crate) fn debug_log_to(sink: &dyn Sink, line: impl FnOnce() -> String) {
    if debug_enabled() {
        sink.log(&line());
    }
}

/// Whether verbose logging is on. Read by the operations' JNI glue to decide whether to
/// log a detection's full caveat and not just its user-facing warning.
pub(crate) fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// Serialises the tests that move [`DEBUG`], which is process-wide.
///
/// `cargo test` runs a crate's tests on parallel threads, so two that flip the switch read
/// each other's value: one asserting "nothing is logged with debug off" fails while the
/// other has it on. Every test in this crate that *writes* the switch takes this first.
///
/// A poisoned lock is treated as merely locked, for the reason [`lock`] gives.
#[cfg(test)]
pub(crate) fn debug_switch_lock() -> std::sync::MutexGuard<'static, ()> {
    static SWITCH: Mutex<()> = Mutex::new(());
    SWITCH.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Lock the callback, treating a poisoned lock as merely locked.
///
/// The lock is only ever held to swap or clone an `Option<GlobalRef>` - never across code
/// that can panic - so poisoning cannot actually happen here; recovering the guard rather
/// than unwrapping keeps a lazy `unwrap` out of a flashing tool all the same: a tool that
/// writes flash must not abort mid-write on an internal invariant.
fn lock() -> std::sync::MutexGuard<'static, Option<GlobalRef>> {
    CALLBACK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where log and progress lines go. A trait so the host tests can record what the bridge
/// produced without a JVM, while [`JniSink`] delivers it for real.
pub(crate) trait Sink {
    /// A free-form line for the user - the `onLog(String)` half of the callback.
    fn log(&self, message: &str);
    /// A running operation's state - the `onProgress(int, String, String)` half.
    fn progress(&self, percent: i32, stage: &str, message: &str);
}

/// The real sink: it delivers to the registered Java callback.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JniSink;

impl Sink for JniSink {
    fn log(&self, message: &str) {
        // One line per call, newline-terminated: the app appends what it is given
        // (`DfuActivity.appendLog` is `logText.append`), and every `jni_log` line the C
        // sent ended in `\n`, so a line without one runs onto the line before it.
        let line = if message.ends_with('\n') {
            message.to_owned()
        } else {
            format!("{message}\n")
        };
        dispatch(|env, callback| {
            if let Ok(text) = env.new_string(&line) {
                let _ = env.call_method(
                    callback,
                    "onLog",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(text.as_ref())],
                );
            }
        });
    }

    fn progress(&self, percent: i32, stage: &str, message: &str) {
        dispatch(|env, callback| {
            let (Ok(stage), Ok(message)) = (env.new_string(stage), env.new_string(message)) else {
                return;
            };
            let _ = env.call_method(
                callback,
                "onProgress",
                "(ILjava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Int(percent),
                    JValue::Object(stage.as_ref()),
                    JValue::Object(message.as_ref()),
                ],
            );
        });
    }
}

/// Run `call` with an attached `JNIEnv` and the current callback, or do nothing.
///
/// Nothing happens if the VM was never cached (no `JNI_OnLoad`) or no callback is set -
/// both are the "before `nativeSetCallback`" state, and dropping the line is the right
/// answer, exactly as the C's `if (env && cb && m)` guard drops it (`tdfu_jni.c:68`).
///
/// Both sinks pass through here, so the one [`clear_pending_exception`] after `call`
/// covers `onLog` and `onProgress`: a callback that throws loses that one line and the
/// operation carries on, instead of leaving a throwable installed for the rest of the
/// flash. The C has the same hole and does not close it (`tdfu_jni.c:68-74` calls
/// `CallVoidMethod` with no `ExceptionCheck`).
fn dispatch(call: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>)) {
    let Some(vm) = VM.get() else { return };
    // Clone the reference out from under the lock and release it before touching the JVM.
    let Some(callback) = lock().clone() else { return };

    // The operation runs on the thread the native call arrived on, so it is already
    // attached and `get_env` answers without a round trip; the attach is the safety net
    // for a thread that somehow reaches here without one.
    if let Ok(mut env) = vm.get_env() {
        call(&mut env, callback.as_obj());
        clear_pending_exception(&mut env);
    } else if let Ok(mut guard) = vm.attach_current_thread() {
        call(&mut guard, callback.as_obj());
        clear_pending_exception(&mut guard);
    }
}

#[cfg(test)]
mod tests {
    use super::{debug_enabled, debug_switch_lock, set_debug};

    /// The debug switch round-trips: `nativeSetDebug` stores it and the operations read it
    /// back. Left at `false`, its default, so no other test sees a stray `true`.
    #[test]
    fn the_debug_switch_stores_and_reads_back() {
        let _guard = debug_switch_lock();
        set_debug(true);
        assert!(debug_enabled(), "set_debug(true) did not take");
        set_debug(false);
        assert!(!debug_enabled(), "set_debug(false) did not take");
    }
}
