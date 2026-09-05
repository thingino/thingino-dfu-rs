//! Every local file the run needs, opened **before** the bus is touched.
//!
//! # The rule, and why it is a rule
//!
//! The C opens the device and **claims its interface** first, and only then looks at the
//! paths it was given: `tdfu_dfu_bootstrap` claims at `dfu.c:1186` and calls `load_file`
//! at `dfu.c:1219`, so a typo in `--spl` costs an open, a `SET_CONFIGURATION`, a claim
//! and an alt selection before it is reported. On a bootrom that is worse than it
//! sounds: the operator has already put the camera into USB-boot, which on most of these
//! boards means holding a boot pin through a power cycle, and a refusal that could have
//! come instantly instead comes after the bus work.
//!
//! So: **read first, touch the device second.** An audit made this the rule for every
//! operation, and here it is the whole purpose of the module.
//! [`preflight`] runs before `--wait`, before
//! enumeration and before any open, and it is pinned that way in
//! [`run`](crate::run)'s tests.
//!
//! The loaders the *tree* supplies are the one thing that cannot always be read this
//! early — their path depends on the variant, and without `--cpu` the variant comes from
//! reading the device's registers. That read executes nothing and spends nothing,
//! so the invariant that actually matters still holds: **nothing is uploaded and
//! nothing is executed until every file the run needs is in memory.** [`loaders`] is
//! called at the point the variant is known and before the first upload.

use std::fs::{File, OpenOptions};
use std::io;
use std::io::Seek as _;
use std::path::Path;

use tdfu_core::model::Variant;
use tdfu_core::{Error, Result};

use crate::loaders;
use crate::plan::Images;

/// The stage-1 and U-Boot images one bootstrap will upload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Blobs {
    /// `tpl.bin`, `spl.bin` or `--spl`.
    pub stage1: Vec<u8>,
    /// `uboot.bin` or `--uboot`.
    pub uboot: Vec<u8>,
    /// What was read, for the line that says which loaders are being used.
    pub source: String,
}

/// Everything [`preflight`] managed to get hold of.
#[derive(Debug)]
#[non_exhaustive]
pub struct Loaded {
    /// The `-w` image, whole. `ops::write` takes `&[u8]`, and a flash image is at most
    /// the chip — 256 MiB on the largest NAND part in the tree, which is the same
    /// buffer the C allocates (`dfu.c:591`).
    pub write: Option<Vec<u8>>,
    /// The `-r` target, created if it was missing and held open so the transfer cannot
    /// fail on a path that was writable a moment ago and is not now. An existing file
    /// still holds its bytes: [`Output`] empties it when the first byte of the upload
    /// arrives.
    pub read: Option<Output>,
    /// The `--spl` + `--uboot` pair, when one was given.
    pub loaders: Option<Blobs>,
}

/// Read every path the plan named, and create the one it will write.
///
/// # Errors
/// [`Error::Io`] naming the path, for `-w` and `-r`; [`Error::LoaderMissing`] naming the
/// path, for `--spl` and `--uboot`. Both exit **3**.
pub fn preflight(images: &Images) -> Result<Loaded> {
    let write = images
        .write
        .as_deref()
        .map(|path| read_image(path, "the image for -w"))
        .transpose()?;

    let loaders = images
        .custom_loaders()
        .map(|(spl, uboot)| {
            Ok::<Blobs, Error>(Blobs {
                stage1: read_loader(spl)?,
                uboot: read_loader(uboot)?,
                source: format!("--spl {} + --uboot {}", spl.display(), uboot.display()),
            })
        })
        .transpose()?;

    // Last, because it is the only step that *changes* anything on disk: a run refused
    // for an unreadable `-w` leaves the `-r` target untouched.
    let read = images.read.as_deref().map(create_output).transpose()?;

    Ok(Loaded { write, read, loaders })
}

/// Read the tree's loaders for a variant.
///
/// Called once the variant is known — from `--cpu` before anything is opened, or from
/// detection, which reads three registers and executes nothing. Either way
/// this returns before the first byte is uploaded.
///
/// Both the pick and the reads are `tdfu_core::loader`'s: this used to resolve the pair
/// itself and asked `Path::is_file` where core and the C ask whether the file *opens*,
/// so an unreadable `tpl.bin` was chosen here and fell back to `spl.bin` there
/// ([`loaders`](crate::loaders) has the full note).
///
/// # Errors
/// [`Error::LoaderMissing`] naming the path and the reason. AGENTS.md D2: the loader
/// tree is fetched rather than vendored, so the usual cause is that
/// `cargo xtask fetch-loaders` has not run.
pub fn loaders(root: &Path, variant: Variant) -> Result<Blobs> {
    let paths = loaders::resolve(root, variant);
    let source = format!("{} ({})", paths.stage1.display(), variant.loader_dir());
    let (stage1, uboot) = paths.read()?;
    Ok(Blobs { stage1, uboot, source })
}

/// Read a user-named image, naming the path if it cannot be read.
///
/// `std::io::Error` carries no path. Printing it bare gives `No such file or
/// directory` and nothing else, which is information thrown away in one line. The
/// path is in hand here, so it goes in the message, and the `ErrorKind` is preserved so
/// a caller can still tell "missing" from "permission denied".
///
/// **A file with nothing in it is refused here**, where it costs nothing. `ops::write`
/// refuses one as well, and has to: it is the library's invariant. But that refusal
/// arrives at the download, which against a bootrom is after the camera has been
/// USB-booted for a transfer that could never have moved a byte, and it arrives in the
/// transfer class, where an exit **2** tells a wrapper a flash was attempted. An empty
/// image is a file problem: exit **3**, before the bus, with the camera untouched. An
/// interrupted download is the ordinary way to end up with one.
fn read_image(path: &Path, what: &str) -> Result<Vec<u8>> {
    let image = std::fs::read(path).map_err(|source| {
        Error::Io(io::Error::new(
            source.kind(),
            format!("cannot read {what}, {}: {source}", path.display()),
        ))
    })?;
    if image.is_empty() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{what} is empty, {}: there is nothing to write, and a zero-length download would \
                 report success",
                path.display()
            ),
        )));
    }
    Ok(image)
}

/// Read a `--spl` or `--uboot` blob the user named.
///
/// Only the *custom* pair comes through here — the tree's pair is
/// [`Loaders::read`](tdfu_core::loader::Loaders::read)'s, delegated above. A custom pair
/// has no `Loaders` to belong to: it is two paths the user typed, with no root, no
/// variant and no `tpl.bin`-else-`spl.bin` pick between them.
///
/// A missing one is a file error with the path named, and the wording is
/// core's `"<path> (<reason>)"` so that the two halves of the same refusal do not read
/// as two different tools.
fn read_loader(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|source| Error::LoaderMissing(format!("{} ({source})", path.display())))
}

/// Open the `-r` target now, so a disk problem is reported before the device is
/// disturbed, and **without truncating it**.
///
/// The two halves of this are separable and were run together by mistake. Proving the
/// path writable early is worth having: a read-only directory or a typo is then refused
/// instantly, before the operator's camera is bootstrapped. Emptying the file early is
/// not: a run that finds no device on the bus, or that an operator aborts during
/// `--wait`, would have destroyed an earlier dump for a transfer that never started.
/// So the file is created if it is missing, opened for writing either way, and
/// [`Output`] empties it when the first byte of the upload arrives.
fn create_output(path: &Path) -> Result<Output> {
    OpenOptions::new()
        .write(true)
        .create(true)
        // Explicitly not truncating: the file is emptied by the first byte written, so a
        // run that never transfers leaves what was there.
        .truncate(false)
        .open(path)
        .map(Output::new)
        .map_err(|source| {
            Error::Io(io::Error::new(
                source.kind(),
                format!("cannot create the output file for -r, {}: {source}", path.display()),
            ))
        })
}

/// The `-r` destination, emptied at the last possible moment.
///
/// A dump the operator already has is destroyed by nothing but the upload that replaces
/// it: the truncation happens on the first byte written, so every refusal in front of
/// the transfer (no device on the bus, a device that is not a gadget, an alt that does
/// not resolve) leaves the file exactly as it was found.
///
/// Once the bytes start arriving the old content is gone, which is what `-r` was asked
/// to do. A transfer that then fails part way leaves a short file rather than an empty
/// one, and [`run`](crate::run)'s read arm says so: a partial dump is what an operator
/// inspects to find out why it stopped.
#[derive(Debug)]
pub struct Output {
    file: File,
    emptied: bool,
}

impl Output {
    /// Wrap a handle that has not been truncated.
    const fn new(file: File) -> Self {
        Self { file, emptied: false }
    }

    /// Empty the file, once, immediately before the first byte lands in it.
    ///
    /// `set_len` alone would leave the cursor where it was, which is byte 0 for a handle
    /// nothing has written to yet; the seek makes that independent of how the handle was
    /// opened rather than true by accident.
    fn empty_once(&mut self) -> io::Result<()> {
        if self.emptied {
            return Ok(());
        }
        self.file.set_len(0)?;
        self.file.seek(io::SeekFrom::Start(0))?;
        self.emptied = true;
        Ok(())
    }
}

impl io::Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.empty_once()?;
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{loaders, preflight};
    use crate::fake::{Scratch, TestResult};
    use crate::plan::Images;

    use std::io::Write as _;
    use tdfu_core::Error;
    use tdfu_core::model::Variant;

    #[test]
    fn a_write_image_is_read_whole() -> TestResult {
        let scratch = Scratch::new("write-image")?;
        let image = scratch.write("fw.bin", b"\x01\x02\x03\x04")?;
        let loaded = preflight(&Images {
            write: Some(image),
            ..Images::default()
        })?;
        assert_eq!(loaded.write.as_deref(), Some(&b"\x01\x02\x03\x04"[..]));
        assert!(loaded.read.is_none());
        assert!(loaded.loaders.is_none());
        Ok(())
    }

    /// **The pin for the path typo.** A missing `-w` image is a file error that names
    /// the path — not `No such file or directory` on its own.
    #[test]
    fn a_missing_write_image_names_the_path() -> TestResult {
        let scratch = Scratch::new("missing-write")?;
        let absent = scratch.path("not-here.bin");
        let outcome = preflight(&Images {
            write: Some(absent.clone()),
            ..Images::default()
        });
        let Err(Error::Io(error)) = outcome else {
            assert_eq!(format!("{outcome:?}"), "Err(Io(..))");
            return Ok(());
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let rendered = error.to_string();
        assert!(rendered.contains(&absent.display().to_string()), "{rendered}");
        assert!(rendered.contains("-w"), "{rendered}");
        Ok(())
    }

    /// A `-w` image with nothing in it is a file error naming the path.
    #[test]
    fn an_empty_write_image_is_a_file_error() -> TestResult {
        let scratch = Scratch::new("empty-write")?;
        let empty = scratch.write("fw.bin", b"")?;
        let outcome = preflight(&Images {
            write: Some(empty.clone()),
            ..Images::default()
        });
        let Err(Error::Io(error)) = outcome else {
            assert_eq!(format!("{outcome:?}"), "Err(Io(..))");
            return Ok(());
        };
        let rendered = error.to_string();
        assert!(rendered.contains(&empty.display().to_string()), "{rendered}");
        assert!(rendered.contains("is empty"), "{rendered}");
        Ok(())
    }

    /// **The preflight opens the `-r` target and does not empty it.**
    ///
    /// The disk is proved writable before the device is touched, which is what the early
    /// open is for; an earlier dump is left where it is, because nothing has been
    /// transferred yet and a run that never finds a device must cost the operator
    /// nothing. [`Output`](super::Output) empties it when the first byte arrives.
    #[test]
    fn fe_cli_the_read_target_is_opened_but_not_emptied() -> TestResult {
        let scratch = Scratch::new("read-target")?;
        let target = scratch.write("out.bin", b"an earlier dump")?;
        let loaded = preflight(&Images {
            read: Some(target.clone()),
            ..Images::default()
        })?;
        assert!(loaded.read.is_some());
        assert_eq!(
            std::fs::read(&target)?,
            b"an earlier dump",
            "the preflight must not destroy a dump for a transfer that has not started"
        );

        // And a path that did not exist is created, so a missing directory is still a
        // refusal rather than a surprise at the end of a long upload.
        let fresh = scratch.path("fresh.bin");
        let _loaded = preflight(&Images {
            read: Some(fresh.clone()),
            ..Images::default()
        })?;
        assert!(fresh.is_file());
        Ok(())
    }

    /// The first byte written is what empties the file, and it empties it completely.
    #[test]
    fn the_output_is_emptied_by_the_first_byte_written() -> TestResult {
        let scratch = Scratch::new("output-truncate")?;
        let target = scratch.write("out.bin", &[0x5A; 4096])?;
        let mut out = super::create_output(&target)?;
        assert_eq!(std::fs::metadata(&target)?.len(), 4096, "still there, unopened bytes");

        out.write_all(b"new dump")?;
        out.flush()?;
        assert_eq!(std::fs::read(&target)?, b"new dump", "no stale tail survives the write");
        Ok(())
    }

    /// A `-r` target that cannot be created is a file error naming the path.
    #[test]
    fn an_uncreatable_read_target_names_the_path() -> TestResult {
        let scratch = Scratch::new("bad-read-target")?;
        // A directory component that is not a directory: portable, and it needs no
        // permission games that a root-in-a-container test would not see.
        let blocker = scratch.write("blocker", b"x")?;
        let impossible = blocker.join("out.bin");
        let outcome = preflight(&Images {
            read: Some(impossible.clone()),
            ..Images::default()
        });
        let Err(Error::Io(error)) = outcome else {
            assert_eq!(format!("{outcome:?}"), "Err(Io(..))");
            return Ok(());
        };
        let rendered = error.to_string();
        assert!(rendered.contains(&impossible.display().to_string()), "{rendered}");
        assert!(rendered.contains("-r"), "{rendered}");
        Ok(())
    }

    /// A refused `-w` leaves the `-r` target alone: the run never started.
    #[test]
    fn a_refused_write_image_does_not_truncate_the_read_target() -> TestResult {
        let scratch = Scratch::new("order")?;
        let target = scratch.write("out.bin", b"precious")?;
        let outcome = preflight(&Images {
            write: Some(scratch.path("absent.bin")),
            read: Some(target.clone()),
            ..Images::default()
        });
        assert!(outcome.is_err());
        assert_eq!(std::fs::read(&target)?, b"precious", "the target must be untouched");
        Ok(())
    }

    /// `--spl` + `--uboot` are read at preflight and reported as the source.
    #[test]
    fn a_custom_loader_pair_is_read_before_anything_else_happens() -> TestResult {
        let scratch = Scratch::new("custom-loaders")?;
        let spl = scratch.write("spl.bin", b"stage1")?;
        let uboot = scratch.write("uboot.bin", b"u-boot")?;
        let loaded = preflight(&Images {
            spl: Some(spl.clone()),
            uboot: Some(uboot),
            ..Images::default()
        })?;
        let blobs = loaded.loaders.ok_or("the pair must have been read")?;
        assert_eq!(blobs.stage1, b"stage1");
        assert_eq!(blobs.uboot, b"u-boot");
        assert!(blobs.source.contains(&spl.display().to_string()), "{}", blobs.source);
        Ok(())
    }

    /// A missing `--spl` is a loader error naming the path.
    #[test]
    fn a_missing_custom_loader_names_the_path() -> TestResult {
        let scratch = Scratch::new("missing-loader")?;
        let uboot = scratch.write("uboot.bin", b"u-boot")?;
        let absent = scratch.path("no-spl.bin");
        let outcome = preflight(&Images {
            spl: Some(absent.clone()),
            uboot: Some(uboot),
            ..Images::default()
        });
        let Err(Error::LoaderMissing(message)) = outcome else {
            assert_eq!(format!("{outcome:?}"), "Err(LoaderMissing(..))");
            return Ok(());
        };
        assert!(message.contains(&absent.display().to_string()), "{message}");
        Ok(())
    }

    /// The tree's loaders come from `<root>/dfu/<variant>/`, `tpl.bin` first.
    #[test]
    fn boot_loader_paths_read_the_tree() -> TestResult {
        let scratch = Scratch::new("tree")?;
        let dir = scratch.path("dfu").join("t20n");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("tpl.bin"), b"tpl")?;
        std::fs::write(dir.join("spl.bin"), b"spl")?;
        std::fs::write(dir.join("uboot.bin"), b"uboot")?;

        let blobs = loaders(scratch.root(), Variant::T20n)?;
        assert_eq!(blobs.stage1, b"tpl", "prefers tpl.bin");
        assert_eq!(blobs.uboot, b"uboot");

        // With no `tpl.bin`, `spl.bin` is used.
        std::fs::remove_file(dir.join("tpl.bin"))?;
        assert_eq!(loaders(scratch.root(), Variant::T20n)?.stage1, b"spl");
        Ok(())
    }

    /// A tree with no loaders for the variant says which file it wanted.
    #[test]
    fn a_missing_tree_loader_names_the_path() -> TestResult {
        let scratch = Scratch::new("empty-tree")?;
        let outcome = loaders(scratch.root(), Variant::T31x);
        let Err(Error::LoaderMissing(message)) = outcome else {
            assert_eq!(format!("{outcome:?}"), "Err(LoaderMissing(..))");
            return Ok(());
        };
        assert!(message.contains("t31x"), "{message}");
        assert!(message.contains("spl.bin"), "{message}");
        Ok(())
    }
}
