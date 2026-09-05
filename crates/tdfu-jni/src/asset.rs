//! Reading a bundled loader out of the app's Android assets.
//!
//! `nativeBootstrap` loads its stage-1 and U-Boot images from the APK's `assets/`, not
//! from the fetched loader tree the CLI and daemon use. This is the app's asset layout
//! (see [`crate::variant::asset_dir`]): `firmware/dfu/<name>/{tpl.bin | spl.bin}` and
//! `firmware/dfu/<dir>/uboot.bin`.
//!
//! The C reaches the assets through the NDK's `AAssetManager` (`tdfu_jni.c:240-276`). This
//! is the same three-function path - `AAssetManager_fromJava`, `AAssetManager_open`,
//! `AAsset_read`/`AAsset_close` - declared as a minimal FFI against `libandroid` rather
//! than pulling the `ndk` crate and its transitive dependencies (either would do; the
//! smaller graph keeps `cargo deny`'s `multiple-versions` bar clear).
//! Every `unsafe` block carries a `// SAFETY:` note.
//!
//! Unlike the C, the bytes are read straight into memory (`ops::bootstrap` takes
//! `&[u8]`), so there is no staging file in `firmwareDir` to write, read back and unlink.
//! `firmwareDir` is accepted and unused, exactly as `read`/`write` `(void)` it.

#[cfg(target_os = "android")]
pub(crate) use android::read_asset;
#[cfg(not(target_os = "android"))]
pub(crate) use host::read_asset;

#[cfg(target_os = "android")]
mod android {
    use core::ffi::{c_char, c_int, c_void};
    use std::ffi::CString;

    use jni::JNIEnv;
    use jni::objects::JObject;

    /// `AASSET_MODE_STREAMING` from `<android/asset_manager.h>` - the mode the C uses.
    const AASSET_MODE_STREAMING: c_int = 2;

    /// Opaque `AAssetManager`, per `<android/asset_manager.h>`.
    #[repr(C)]
    struct AAssetManager {
        _private: [u8; 0],
    }

    /// Opaque `AAsset`.
    #[repr(C)]
    struct AAsset {
        _private: [u8; 0],
    }

    #[link(name = "android")]
    unsafe extern "C" {
        fn AAssetManager_fromJava(env: *mut jni::sys::JNIEnv, asset_manager: jni::sys::jobject) -> *mut AAssetManager;
        fn AAssetManager_open(manager: *mut AAssetManager, filename: *const c_char, mode: c_int) -> *mut AAsset;
        fn AAsset_read(asset: *mut AAsset, buffer: *mut c_void, count: usize) -> c_int;
        fn AAsset_close(asset: *mut AAsset);
    }

    /// Read the whole asset at `path` into memory, or `None` if it is absent or unreadable.
    pub(crate) fn read_asset(env: &JNIEnv<'_>, manager: &JObject<'_>, path: &str) -> Option<Vec<u8>> {
        // An asset path never contains a NUL; if it somehow did, it is not a real path.
        let c_path = CString::new(path).ok()?;

        // SAFETY: `env.get_raw()` is the live `JNIEnv` the JVM passed this native call, and
        // `manager.as_raw()` is the `AssetManager` jobject the app handed over. Both are
        // valid for the duration of this call; the returned pointer is owned by the JVM.
        let mgr = unsafe { AAssetManager_fromJava(env.get_raw(), manager.as_raw()) };
        if mgr.is_null() {
            return None;
        }

        // SAFETY: `mgr` is the non-null manager returned above; `c_path` is a valid
        // NUL-terminated string that outlives the call.
        let asset = unsafe { AAssetManager_open(mgr, c_path.as_ptr(), AASSET_MODE_STREAMING) };
        if asset.is_null() {
            return None;
        }

        let mut out = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut failed = false;
        loop {
            // SAFETY: `asset` is the non-null asset opened above; `buffer` is a writable
            // buffer of exactly `buffer.len()` bytes, and `AAsset_read` writes at most that.
            let read = unsafe { AAsset_read(asset, buffer.as_mut_ptr().cast::<c_void>(), buffer.len()) };
            if read < 0 {
                // A genuine read error, not EOF: surface it rather than silently
                // truncating the loader as the C's `while (... > 0)` loop does.
                failed = true;
                break;
            }
            if read == 0 {
                break;
            }
            let count = usize::try_from(read).unwrap_or(0).min(buffer.len());
            out.extend_from_slice(&buffer[..count]);
        }

        // SAFETY: `asset` is valid and is not used again after being closed.
        unsafe { AAsset_close(asset) };

        if failed { None } else { Some(out) }
    }
}

#[cfg(not(target_os = "android"))]
mod host {
    use jni::JNIEnv;
    use jni::objects::JObject;

    /// Off Android there is no `AAssetManager`, so the bundled-asset bootstrap finds
    /// nothing and returns `-1`. The host JVM tests drive exactly this path.
    pub(crate) fn read_asset(_env: &JNIEnv<'_>, _manager: &JObject<'_>, _path: &str) -> Option<Vec<u8>> {
        None
    }
}
