//! Which firmware root this frontend looks in, and one delegation to the rules.
//!
//! # Where the rules live
//!
//! The `tpl.bin`-else-`spl.bin` pick and the `<root>/dfu/<variant>/`
//! layout are **`tdfu_core::loader`'s**, not this module's, and [`resolve`] is a
//! one-line delegation to them, the same shape [`alt`](crate::alt) uses for the
//! alt rules. The pins stay here, guarding the CLI-visible behaviour across the seam.
//!
//! It was not always so, and the fork was not harmless. This module carried its own copy
//! that asked [`Path::is_file`] where core (and the C, whose check is an `fopen`/`fclose`
//! pair at `utils.c:451-461`) asks whether the file **opens**. A `tpl.bin` that is
//! present but unreadable — the wrong owner after a `sudo` unpack, a mode that lost its
//! read bit — therefore fell back to `spl.bin` in the C and in core, and was *picked and
//! then failed on* here, past the point where the fallback was still available. One rule
//! with two implementations had drifted into two behaviours, which is what the alt
//! resolver was consolidated to prevent: one rule in three places is three rules.
//!
//! # What is genuinely this frontend's
//!
//! [`firmware_root`] stays, because "where is the tree" is a *frontend* question and each
//! one answers it differently: this binary looks beside itself, the browser fetches over
//! the network and has no filesystem at all, and the daemon is configured. Core takes the
//! root as an argument for exactly that reason.

use std::path::{Path, PathBuf};

use tdfu_core::loader::{self, Loaders};
use tdfu_core::model::Variant;

/// The default firmware root, when `--firmware-dir` was not given.
pub const DEFAULT_ROOT: &str = "firmware";

/// Resolve `--firmware-dir`, or the binary-relative default.
///
/// `firmware_dir` defaults to `firmware/` **beside the binary**, which the
/// C resolves through `/proc/self/exe` (`cli/main.c:305-317`) so that an installed tool
/// finds its loaders whatever the working directory is. `./firmware` is the fallback for
/// the platforms and sandboxes where the executable path is not readable — the same
/// fallback, and the same order, as the C's.
#[must_use]
pub fn firmware_root(explicit: Option<&Path>) -> PathBuf {
    if let Some(root) = explicit {
        return root.to_path_buf();
    }
    if let Some(beside) = std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(Path::parent)
        .map(|dir| dir.join(DEFAULT_ROOT))
    {
        return beside;
    }
    PathBuf::from(DEFAULT_ROOT)
}

/// The two paths a bootstrap of `variant` will read.
///
/// One home for those rules: `tdfu_core::loader::resolve`, shared with the ops and with
/// the daemon.
#[must_use]
pub fn resolve(root: &Path, variant: Variant) -> Loaders {
    loader::resolve(root, variant)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_ROOT, firmware_root, resolve};
    use std::path::{Path, PathBuf};
    use tdfu_core::loader::Stage1Kind;
    use tdfu_core::model::Variant;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// **The `<root>/dfu/<variant>/` layout**, asserted through the delegation.
    #[test]
    fn boot_loader_paths_are_firmware_dfu_variant() {
        let root = Path::new("/opt/thingino/firmware");
        let paths = resolve(root, Variant::T31x);
        // No tree on disk, so the `spl.bin` fallback answers, and it is the path the
        // "missing loader" error will name.
        assert_eq!(paths.stage1, PathBuf::from("/opt/thingino/firmware/dfu/t31x/spl.bin"));
        assert_eq!(paths.uboot, PathBuf::from("/opt/thingino/firmware/dfu/t31x/uboot.bin"));
        assert_eq!(paths.stage1_kind, Stage1Kind::Spl);
    }

    /// **`tpl.bin` wins whenever the tree has one.**
    ///
    /// Against a real directory, because the rule core implements is "does it open" —
    /// the check this crate used to make its own, and got wrong (see the module docs).
    #[test]
    fn boot_prefers_tpl() -> TestResult {
        let scratch = crate::fake::Scratch::new("loaders-prefers-tpl")?;
        let dir = scratch.root().join("dfu").join("t20n");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("spl.bin"), b"spl")?;
        std::fs::write(dir.join("uboot.bin"), b"uboot")?;

        let fallback = resolve(scratch.root(), Variant::T20n);
        assert_eq!(fallback.stage1_kind, Stage1Kind::Spl);
        assert!(fallback.stage1.ends_with("spl.bin"), "{:?}", fallback.stage1);

        // Add `tpl.bin` beside it — with `spl.bin` still there, so this cannot pass on a
        // "whatever is present" rule.
        std::fs::write(dir.join("tpl.bin"), b"tpl")?;
        let capped = resolve(scratch.root(), Variant::T20n);
        assert_eq!(capped.stage1_kind, Stage1Kind::Tpl);
        assert!(capped.stage1.ends_with("tpl.bin"), "{:?}", capped.stage1);
        // The U-Boot half never changes name.
        assert!(capped.uboot.ends_with("uboot.bin"), "{:?}", capped.uboot);
        Ok(())
    }

    /// `--firmware-dir` wins over the binary-relative default.
    #[test]
    fn an_explicit_root_is_used_verbatim() {
        let explicit = PathBuf::from("/mnt/images/fw");
        assert_eq!(firmware_root(Some(&explicit)), explicit);
    }

    /// The default is `firmware/` beside the binary, not `./firmware` — a tool run from
    /// another directory must still find its loaders.
    #[test]
    fn the_default_root_sits_beside_the_binary() {
        let default = firmware_root(None);
        assert!(default.ends_with(DEFAULT_ROOT), "{}", default.display());

        // Under `cargo test` the "binary" is the test harness, which is in `target/`;
        // asserting the parent directory rather than a literal keeps this true wherever
        // the tree is checked out.
        if let Ok(exe) = std::env::current_exe() {
            assert_eq!(default.parent(), exe.parent(), "the default is beside the binary");
        }
    }
}
