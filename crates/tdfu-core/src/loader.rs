//! Finding the stage-1 and U-Boot images a bootstrap stages.
//!
//! The loader tree is **fetched, not vendored**: `cargo xtask
//! fetch-loaders` unpacks the current `usbboot` release under `target/firmware/dfu`,
//! which is a rolling pre-release and carries no version pin, and a
//! shipped binary carries its own `firmware/` beside it. Either way the shape is the
//! same and it is the C's: `<root>/dfu/<variant_dir>/{tpl|spl,uboot}.bin`.
//!
//! **Not compiled for wasm.** This is `std::fs` and nothing else, and the browser
//! frontend has no filesystem to look in — it hands
//! [`ops::bootstrap`](crate::ops::bootstrap) two byte slices it fetched over the
//! network. The C's equivalent is `#ifdef __EMSCRIPTEN__`-shaped for the same reason
//! (`libtdfu/src/dfu/dfu.c:1157-1160`).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::Variant;

/// The subdirectory of the firmware root that holds the DFU loaders.
pub const LOADER_SUBDIR: &str = "dfu";

/// The preferred stage-1 file name.
pub const TPL_FILE: &str = "tpl.bin";

/// The stage-1 file name used when [`TPL_FILE`] is not there.
pub const SPL_FILE: &str = "spl.bin";

/// The second-stage file name.
pub const UBOOT_FILE: &str = "uboot.bin";

/// Where a bootstrap's two images live, and which stage-1 file was picked.
///
/// Paths only. Reading them is [`read`](Loaders::read)'s job, and it is separate so a
/// frontend can show an operator *which* files it is about to stage before it stages
/// them — the C logs the pick at `LOG_INFO` for exactly that reason
/// (`libtdfu/src/dfu/dfu.c:1208`, `LOG_BOOTSTRAP_PICK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaders {
    /// The stage-1 image: `tpl.bin` if it was readable, else `spl.bin`.
    pub stage1: PathBuf,
    /// The second-stage image, always `uboot.bin`.
    pub uboot: PathBuf,
    /// Which of the two stage-1 names [`stage1`](Loaders::stage1) is.
    pub stage1_kind: Stage1Kind,
}

/// Which stage-1 file a variant's directory offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage1Kind {
    /// `tpl.bin` — a cache-as-RAM first stage that brings up DDR and returns to the
    /// bootrom.
    Tpl,
    /// `spl.bin` — the first stage of a big-SPL SoC.
    Spl,
}

impl Stage1Kind {
    /// The file name this kind is.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Tpl => TPL_FILE,
            Self::Spl => SPL_FILE,
        }
    }
}

impl Loaders {
    /// Read both images off disk.
    ///
    /// # Errors
    /// [`Error::LoaderMissing`] naming the exact path, for either file. The C
    /// distinguishes the two the same way — `"Missing DFU SPL: %s"` at
    /// `libtdfu/src/dfu/dfu.c:1221` and `"Missing DFU U-Boot: %s"` at `:1226` — and the
    /// path is the whole message, because "loader missing" without one sends an
    /// operator to guess at `--firmware-dir`, `--cpu` and a forgotten
    /// `xtask fetch-loaders` in turn.
    pub fn read(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((read_image(&self.stage1)?, read_image(&self.uboot)?))
    }
}

/// The directory a variant's loaders live in: `<root>/dfu/<variant_dir>`.
///
/// [`Variant::loader_dir`](crate::model::Variant::loader_dir) is the name, and all 34
/// of them are checked against the fetched tree by
/// `variant_all_matches_the_pinned_loader_tree`.
#[must_use]
pub fn directory(root: impl AsRef<Path>, variant: Variant) -> PathBuf {
    root.as_ref().join(LOADER_SUBDIR).join(variant.loader_dir())
}

/// Pick the stage-1 and U-Boot files for `variant` under the firmware root
/// `root`.
///
/// **`tpl.bin` if it is readable, else `spl.bin`.** The capped XBurst1 parts
/// (T10/T20/T21/T30) USB-boot a TPL as stage 1: it brings up DDR in cache-as-RAM and
/// returns to the bootrom, exactly as a big-SPL SoC's SPL does, and their DRAM-resident
/// SPL is NOR-only and unused over USB (`dfu.c:1209-1215`).
///
/// The choice is made **by what is on disk, never by family** — which is what the C
/// does (`firmware_file_check_readable` at `dfu.c:1214`, no variant test anywhere near
/// it) and what the shipped tree requires: 28 of its 34 directories ship `tpl.bin`,
/// including every T23, T31 and T32, and only `a1n`, `t33`, `t40n`, `t40xp`, `t41lq`
/// and `t41nq` ship `spl.bin`. Naming only the four capped families describes *why*
/// TPLs exist rather than *which* directories have one;
/// gating on the family list would refuse the TPL that every T23, T31 and T32 directory
/// actually ships.
///
/// "Readable", not "exists": the C opens the candidate
/// (`libtdfu/src/utils.c:451-461` is an `fopen`/`fclose` pair), so a `tpl.bin` that is
/// present but unreadable falls back to `spl.bin` there and here alike. [`std::fs::File::open`]
/// is the same test.
///
/// This resolves paths and does not read them — [`Loaders::read`] does, and reports a
/// missing file. A variant whose directory holds neither stage-1 name resolves to the
/// [`SPL_FILE`] path, which is the C's fallback and therefore the path its error names.
#[must_use]
pub fn resolve(root: impl AsRef<Path>, variant: Variant) -> Loaders {
    let dir = directory(root, variant);
    let tpl = dir.join(TPL_FILE);
    let stage1_kind = if is_readable(&tpl) {
        Stage1Kind::Tpl
    } else {
        Stage1Kind::Spl
    };
    Loaders {
        stage1: match stage1_kind {
            Stage1Kind::Tpl => tpl,
            Stage1Kind::Spl => dir.join(SPL_FILE),
        },
        uboot: dir.join(UBOOT_FILE),
        stage1_kind,
    }
}

/// Can this file be opened for reading?
///
/// `File::open` and not [`Path::exists`]: the C's check is an `fopen`/`fclose`
/// (`utils.c:451-461`), and the two agree case for case. A `tpl.bin` with no read
/// permission is *not* a usable stage 1 and falls through to `spl.bin` in both, where
/// `exists()` would answer yes and then fail the read a second later, past the point
/// where the fallback was available.
///
/// They agree on the odd case too, which is why this is `File::open` and not a
/// hand-rolled "is a readable regular file": on Linux, opening a *directory* read-only
/// succeeds — for `fopen` as much as for `File::open` — so a directory named `tpl.bin`
/// is picked as the stage 1 by both and fails at the read. Matching the C there is
/// worth more than being cleverer than it about a case no loader tree has.
fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

/// Read one loader image, or say which path was not there.
fn read_image(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| missing(path, &source))
}

/// The error a loader that will not load produces.
///
/// [`Error::LoaderMissing`] rather than [`Error::Io`] even when the OS reason is not
/// "not found": both exit 3 (`crates/tdfu-cli/src/exit.rs`), and the one thing an
/// operator can act on is *which file the tool wanted*. The OS's own words are kept
/// after the path rather than replacing it: discarding the cause leaves an operator
/// with a symptom, and "permission denied" versus "no such file" is the difference
/// between `sudo` and `cargo xtask fetch-loaders`.
fn missing(path: &Path, source: &std::io::Error) -> Error {
    Error::LoaderMissing(format!("{} ({source})", path.display()))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{LOADER_SUBDIR, SPL_FILE, Stage1Kind, TPL_FILE, UBOOT_FILE, directory, is_readable, missing, resolve};
    use crate::error::Error;
    use crate::model::Variant;

    /// Anything a loader test can fail with.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A scratch directory that cleans up after itself, so a test never leaves one
    /// behind and two running at once never collide.
    ///
    /// `std::env::temp_dir` plus the test's own name: no `tempfile` dependency for
    /// something this small, and a name a human can recognise if a panic ever does
    /// leave one behind.
    #[derive(Debug)]
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Result<Self, std::io::Error> {
            let path = std::env::temp_dir().join(format!("tdfu-loader-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Create `<root>/dfu/<dir>/<name>` with `bytes` in it.
        fn put(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<PathBuf, std::io::Error> {
            let parent = self.0.join(LOADER_SUBDIR).join(dir);
            std::fs::create_dir_all(&parent)?;
            let path = parent.join(name);
            std::fs::write(&path, bytes)?;
            Ok(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// **The stage-1 pick's pin.** `tpl.bin` wins when it is there; `spl.bin` is the
    /// fallback.
    ///
    /// The capped XBurst1 parts USB-boot a cache-as-RAM TPL and their DRAM-resident SPL
    /// is NOR-only, so picking `spl.bin` where a `tpl.bin` exists stages an image that
    /// cannot run over USB. Both directions are asserted in one directory, because the
    /// interesting failure is a rule that *always* answers one of the two.
    #[test]
    fn boot_prefers_tpl() -> TestResult {
        let scratch = Scratch::new("prefers-tpl")?;
        let variant = Variant::T20x;
        let dir = variant.loader_dir();

        // Only spl.bin: the fallback.
        scratch.put(dir, SPL_FILE, b"spl")?;
        scratch.put(dir, UBOOT_FILE, b"uboot")?;
        let only_spl = resolve(scratch.path(), variant);
        assert_eq!(only_spl.stage1_kind, Stage1Kind::Spl);
        assert!(only_spl.stage1.ends_with(SPL_FILE), "{:?}", only_spl.stage1);

        // Add tpl.bin beside it and the pick changes — with spl.bin still present, so
        // this cannot pass by accident on a "whatever is there" rule.
        let tpl = scratch.put(dir, TPL_FILE, b"tpl")?;
        let both = resolve(scratch.path(), variant);
        assert_eq!(both.stage1_kind, Stage1Kind::Tpl);
        assert_eq!(both.stage1, tpl);
        assert_eq!(
            both.uboot, only_spl.uboot,
            "the U-Boot path does not depend on the pick"
        );

        // And the bytes that come back are the ones the pick names.
        let (stage1, uboot) = both.read()?;
        assert_eq!(stage1, b"tpl");
        assert_eq!(uboot, b"uboot");
        Ok(())
    }

    /// The pick is by file, never by family.
    ///
    /// The C has no variant test near `firmware_file_check_readable` (`dfu.c:1213-1216`),
    /// and the shipped tree needs none: 28 of its 34 directories carry `tpl.bin`,
    /// including every T23, T31 and T32, while only
    /// T10/T20/T21/T30 are capped. A family gate would refuse the TPL that every T23, T31 and T32
    /// directory actually ships.
    #[test]
    fn boot_stage1_pick_does_not_consult_the_family() -> TestResult {
        let scratch = Scratch::new("no-family-gate")?;
        // A T41 — an SPL family — with a tpl.bin in its directory.
        let big_spl = Variant::T41nq;
        scratch.put(big_spl.loader_dir(), TPL_FILE, b"tpl")?;
        assert_eq!(resolve(scratch.path(), big_spl).stage1_kind, Stage1Kind::Tpl);

        // And a T20 — a capped XBurst1 — with only spl.bin.
        let capped = Variant::T20n;
        scratch.put(capped.loader_dir(), SPL_FILE, b"spl")?;
        assert_eq!(resolve(scratch.path(), capped).stage1_kind, Stage1Kind::Spl);
        Ok(())
    }

    /// **The path pin.** `<root>/dfu/<variant_dir>/{tpl|spl,uboot}.bin`, for every
    /// variant.
    ///
    /// The directory name is `Variant::loader_dir`, and the path is built from it rather
    /// than formatted at each call site, so `--firmware-dir` can be anything a
    /// [`Path`] can be — including a relative `./firmware` (`cli/main.c:330-332`) and a
    /// path with a space in it, which a `snprintf` of `"%s/dfu/%s/tpl.bin"` handles only
    /// because it never quotes.
    #[test]
    fn boot_loader_paths() {
        let root = Path::new("/opt/thingino/firmware");
        for variant in Variant::ALL {
            let picked = resolve(root, variant);
            let expected = root.join(LOADER_SUBDIR).join(variant.loader_dir());
            assert_eq!(directory(root, variant), expected);
            // Nothing exists under this root, so every variant falls back to spl.bin —
            // which is the C's fallback and therefore the path its error names.
            assert_eq!(picked.stage1_kind, Stage1Kind::Spl);
            assert_eq!(picked.stage1, expected.join(SPL_FILE));
            assert_eq!(picked.uboot, expected.join(UBOOT_FILE));
        }

        // A relative root stays relative: the C's default is a binary-relative
        // `./firmware` (`dfu.c:1172`, `cli/main.c:330-332`).
        let relative = resolve(Path::new("firmware"), Variant::T31n);
        assert_eq!(relative.uboot, Path::new("firmware/dfu/t31n/uboot.bin"));
    }

    /// A missing loader names the exact path it wanted, and the OS's reason with it.
    ///
    /// The C names the path in both messages (`dfu.c:1221`, `:1226`) and this keeps the
    /// cause as well, because "permission denied" and "no such file" send an operator
    /// to two different fixes, and dropping the cause loses that.
    /// The two files are distinguishable: a tree with U-Boot and no stage 1 must not
    /// report the U-Boot path.
    #[test]
    fn boot_missing_loader_names_the_path() -> TestResult {
        let scratch = Scratch::new("missing")?;
        let variant = Variant::T31n;

        // Nothing at all: the stage-1 path is reported, as spl.bin (the C's fallback).
        let error = resolve(scratch.path(), variant)
            .read()
            .err()
            .ok_or("an empty tree read two loaders")?;
        let text = error.to_string();
        assert!(text.starts_with("loader file missing: "), "{text}");
        assert!(text.contains("dfu/t31n/spl.bin"), "{text}");
        assert!(
            !text.contains(UBOOT_FILE),
            "the stage-1 failure named the U-Boot path: {text}"
        );
        // It is not recoverable and it exits 3, not 1 — a file error, not a device one.
        assert!(!error.is_recoverable());
        assert!(matches!(error, Error::LoaderMissing(_)));

        // Stage 1 present, U-Boot absent: now it is the U-Boot path.
        scratch.put(variant.loader_dir(), TPL_FILE, b"tpl")?;
        let error = resolve(scratch.path(), variant)
            .read()
            .err()
            .ok_or("a tree with no uboot.bin read two loaders")?;
        let text = error.to_string();
        assert!(text.contains("dfu/t31n/uboot.bin"), "{text}");
        assert!(
            !text.contains(TPL_FILE),
            "the U-Boot failure named the stage-1 path: {text}"
        );

        // The wording, pinned once.
        let source = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        assert_eq!(
            missing(Path::new("/firmware/dfu/t31n/tpl.bin"), &source).to_string(),
            "loader file missing: /firmware/dfu/t31n/tpl.bin (permission denied)"
        );
        Ok(())
    }

    /// "Readable", not "exists" — the C opens the candidate (`utils.c:451-461`).
    ///
    /// A `tpl.bin` that is there but cannot be opened answers yes to
    /// [`Path::exists`] and no to an open, and the difference decides whether the
    /// `spl.bin` fallback is still available or the bootstrap fails a second later with
    /// the fallback already passed.
    ///
    /// Unix only, and it **checks its own fixture**: a process that can read the file
    /// anyway (root, or a filesystem that ignores the mode) says so and stops, rather
    /// than reporting `ok` for an assertion it never made: the rule against silent
    /// self-skips, applied to a fixture instead of a tree.
    #[cfg(unix)]
    #[test]
    fn boot_stage1_pick_tests_readability_not_existence() -> TestResult {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("readability")?;
        let variant = Variant::T30x;
        let tpl = scratch.put(variant.loader_dir(), TPL_FILE, b"tpl")?;
        scratch.put(variant.loader_dir(), SPL_FILE, b"spl")?;
        assert_eq!(resolve(scratch.path(), variant).stage1_kind, Stage1Kind::Tpl);

        std::fs::set_permissions(&tpl, std::fs::Permissions::from_mode(0o000))?;
        assert!(tpl.exists(), "an unreadable file still exists");
        if is_readable(&tpl) {
            eprintln!("skipped: this process can read a mode-000 file (root?), so there is nothing to test");
            return Ok(());
        }
        assert_eq!(resolve(scratch.path(), variant).stage1_kind, Stage1Kind::Spl);

        // `Drop` needs to be able to remove it again.
        std::fs::set_permissions(&tpl, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// The real tree, when it is there: every variant resolves to two files that exist.
    ///
    /// Gated exactly as `variant_all_matches_the_pinned_loader_tree` is:
    /// the tree is fetched and not vendored, so this skips when it is absent — and
    /// `TDFU_REQUIRE_LOADERS=1` turns that skip into a failure, because a self-skip
    /// reporting `ok` is indistinguishable from a pass at the terminal. CI sets it and
    /// fetches first.
    ///
    /// This is the check a synthetic fixture cannot make: it asserts that the tree this
    /// run *fetched* resolves as written, for every variant, and that its TPL/SPL split
    /// still has the shape the family-blind rule rests on.
    #[test]
    fn boot_resolves_every_variant_in_the_pinned_loader_tree() -> TestResult {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/firmware");
        if !root.join(LOADER_SUBDIR).is_dir() {
            let required = std::env::var_os("TDFU_REQUIRE_LOADERS").is_some_and(|value| value != "0");
            assert!(
                !required,
                "TDFU_REQUIRE_LOADERS is set and {} is absent; run `cargo xtask fetch-loaders`",
                root.display()
            );
            eprintln!("skipped: {} is absent; run `cargo xtask fetch-loaders`", root.display());
            return Ok(());
        }

        let mut tpl = 0_usize;
        let mut spl = 0_usize;
        for variant in Variant::ALL {
            let picked = resolve(&root, variant);
            let (stage1, uboot) = picked.read().map_err(|error| format!("{variant:?}: {error}"))?;
            assert!(!stage1.is_empty(), "{variant:?} has an empty stage 1");
            assert!(!uboot.is_empty(), "{variant:?} has an empty U-Boot");
            assert!(picked.stage1.ends_with(picked.stage1_kind.file_name()));
            match picked.stage1_kind {
                Stage1Kind::Tpl => tpl += 1,
                Stage1Kind::Spl => spl += 1,
            }
        }
        assert_eq!(tpl + spl, Variant::ALL.len());
        // The split is what makes the family-blind rule necessary: far more directories
        // ship a TPL than there are capped parts. The release is rolling and nothing
        // pins it, so the exact pair moves whenever it gains or loses a variant; the
        // fact this rests on is the ratio, and only its inversion is a failure to act
        // on. Today the tree holds 28 TPL and 6 SPL.
        assert!(
            tpl > spl,
            "the fetched tree's TPL/SPL split inverted: {tpl} TPL, {spl} SPL"
        );
        Ok(())
    }
}
