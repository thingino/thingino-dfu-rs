//! Variant names as the app uses them, in two directions.
//!
//! Two different spaces meet here, and keeping them apart is the whole point:
//!
//! * **The wire ordinal** the dfu-remote daemon sends in a discovery entry is a
//!   `tdfu_variant_t`, i.e. [`tdfu_proto::WireVariant`] (the frozen 59-entry table), *not*
//!   [`tdfu_core::model::Variant`] (the 34 loader directories). `nativeVariantToString`
//!   renders that ordinal, so it goes through [`variant_to_string`].
//! * **The bundled-asset directory** a bootstrap reads its loader from. The app ships the
//!   *whole* loader tree as assets under `firmware/dfu/<loader_dir>/` (its Gradle build
//!   copies `libtdfu-android-<ver>.tar.gz`'s `firmware/` in verbatim, and that tarball is
//!   `cp -r firmware`, the same 34 directories the CLI and daemon fetch). So the asset
//!   directory for a variant is exactly [`Variant::loader_dir`](tdfu_core::model::Variant::loader_dir).

use tdfu_core::model::Variant;

/// Render a `tdfu_variant_t` wire ordinal as the app-facing name.
///
/// This is `nativeVariantToString`'s whole job, and the drop-in contract is that it
/// spells names exactly as the shipped C's `tdfu_variant_to_string` did, because the app
/// displays them (`RemoteClient.variantName`) and feeds them back into
/// `nativeBootstrap`/read/write as the `variant` string. [`tdfu_proto::WireVariant`] is
/// that table, so this is a thin, total wrapper over it.
///
/// Anything outside the table - an out-of-range `jint`, or the `0xFF` an unknown gadget
/// carries - is `"unknown"`, matching both the C and the Kotlin doc on
/// `nativeVariantToString`. The C's silent `t31x` pre-seed for an unknown ordinal is a
/// bug - a guess rendered as a fact - and is deliberately not reproduced.
#[must_use]
pub(crate) fn variant_to_string(ordinal: i32) -> &'static str {
    u8::try_from(ordinal)
        .ok()
        .and_then(|byte| tdfu_proto::WireVariant(byte).name())
        .unwrap_or("unknown")
}

/// The bundled-asset directory a bootstrap reads a variant's loader from.
///
/// The app hands us a variant name (from `nativeDetectSoc`'s `Variant::loader_dir` or
/// `nativeVariantToString`'s wire name); we resolve it to a [`Variant`] and use that
/// variant's [`loader_dir`](Variant::loader_dir), which is exactly the directory the app
/// ships the loader under (`firmware/dfu/<loader_dir>/`). Resolving rather than trusting
/// the string means a `--cpu` alias such as `t31` reaches its real directory
/// (`t31` -> `T31n` -> `t31n`), not a directory of that literal name. `None` for a name no
/// variant answers to, so the caller fails the bootstrap instead of reading a directory
/// that is not there, and never flashes a guessed loader.
///
/// **The C's `dfu_asset_dir` (`tdfu_jni.c:217`) is not reproduced, because it is a bug.**
/// It remaps `t31x`/`t31zx`/`t31al` to `t31`, `t31a` to `t31_ddr3`, `t23`/`t23dl` to `t23`,
/// and `t40xp` to `t40_ddr3` - directories that do **not** exist in the shipped asset tree
/// (verified against `libtdfu-android-1.5.43.tar.gz` and the app's staged
/// `assets/firmware/dfu/`, which carry `t31x`, `t31a`, `t23dl`, `t40xp`, and no `t31`,
/// `t31_ddr3`, `t23` or `t40_ddr3`). So the C's Android bootstrap cannot find a loader for
/// any of those families; it looks in the wrong directory and returns "missing DFU
/// firmware asset". Reading each loader from its own directory is what makes the bootstrap
/// actually work, which is the parity that matters.
#[must_use]
pub(crate) fn asset_dir(variant_name: &str) -> Option<&'static str> {
    Variant::from_cpu_arg(variant_name).map(Variant::loader_dir)
}

#[cfg(test)]
mod tests {
    use super::{asset_dir, variant_to_string};
    use tdfu_core::model::Variant;

    /// The wire ordinals the app actually shows, spelled the way the C spelled them.
    #[test]
    fn variant_to_string_matches_the_wire_table() {
        // A representative spread of the frozen 59-entry table.
        assert_eq!(variant_to_string(6), "t31x");
        assert_eq!(variant_to_string(24), "t41nq");
        assert_eq!(variant_to_string(38), "t23n");
        assert_eq!(variant_to_string(20), "t40xp");
        assert_eq!(variant_to_string(8), "t31a");
        assert_eq!(variant_to_string(58), "a1n");
    }

    /// Out-of-range and the `0xFF` unknown marker both render `unknown`, never a silent
    /// `t31x`, which is what the Kotlin doc on `nativeVariantToString` promises.
    #[test]
    fn variant_to_string_is_total_and_never_defaults_to_t31x() {
        for ordinal in [-1, 59, 60, 255, 256, 1000, i32::MAX, i32::MIN] {
            assert_eq!(variant_to_string(ordinal), "unknown", "{ordinal}");
        }
        assert_eq!(variant_to_string(0xFF), "unknown");
    }

    /// A loader directory name resolves to itself, so the loader the app ships under
    /// `firmware/dfu/<name>/` is the one read - the families the C special-cased included
    /// (`t31x`, `t31a`, `t40xp`, `t23dl`), which the C sent to directories the shipped tree
    /// does not have.
    #[test]
    fn a_loader_directory_name_resolves_to_itself() {
        for name in ["t31x", "t31a", "t23dl", "t23n", "t40xp", "t41nq", "t33", "a1n"] {
            assert_eq!(asset_dir(name), Some(name), "{name}");
        }
    }

    /// A chip that shares another grade's loader resolves to that grade's shipped
    /// directory: a T31ZX or T31AL uses the `t31x` loader, which is what is bundled, not a
    /// `t31zx`/`t31al` directory that is not.
    #[test]
    fn a_shared_loader_name_resolves_to_the_shipped_directory() {
        assert_eq!(asset_dir("t31zx"), Some("t31x"));
        assert_eq!(asset_dir("t31al"), Some("t31x"));
    }

    /// Every loader directory the tool knows resolves to itself, so no variant the app can
    /// detect is left without an asset directory (the gap the C's remapping created).
    #[test]
    fn every_variant_resolves_to_its_own_asset_directory() {
        for variant in Variant::ALL {
            let name = variant.loader_dir();
            assert_eq!(asset_dir(name), Some(name), "{name}");
        }
    }

    /// A `--cpu` alias resolves to a real shipped directory, never the phantom the C's
    /// remapping produced: `t31` -> the `t31n` grade's directory, not a literal `t31`.
    #[test]
    fn an_alias_resolves_to_a_real_directory_not_the_phantom() {
        assert_eq!(asset_dir("t31"), Some("t31n"));
        assert_eq!(asset_dir("t40"), Some("t40n"));
        // The C's phantoms are returned for nothing.
        for name in ["t31x", "t31a", "t40xp", "t23dl", "t23n"] {
            assert_ne!(asset_dir(name), Some("t31"));
            assert_ne!(asset_dir(name), Some("t31_ddr3"));
            assert_ne!(asset_dir(name), Some("t40_ddr3"));
            assert_ne!(asset_dir(name), Some("t23"));
        }
    }

    /// A name no variant answers to has no asset directory, so the bootstrap fails rather
    /// than reading a directory that is not there, and never flashes a guess.
    #[test]
    fn an_unknown_name_has_no_asset_directory() {
        assert_eq!(asset_dir("nonsense"), None);
        assert_eq!(asset_dir("t40_ddr3"), None, "the C's phantom is not even a --cpu alias");
    }
}
