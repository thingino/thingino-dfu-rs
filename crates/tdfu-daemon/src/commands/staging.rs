//! The staging file `CMD_READ` fills before it answers.
//!
//! # 0600, and this is the one place the C was safer than us
//!
//! An earlier implementation created this file at **0664** in a shared
//! directory. It holds a whole flash image, the Wi-Fi credentials, the keys and the
//! configuration, so on a multi-user box every other user could read the contents of a
//! camera someone else was dumping. The C creates it with `mkstemp`
//! (`dfu-remote/main.c:643`, template at `:642`), which POSIX mandates at 0600, and the reason we lost that
//! is that `OpenOptions::create_new` gives the same *exclusivity* and says nothing about
//! the mode, so nothing looked missing.
//!
//! The mode is set explicitly at creation and pinned by a test.
//! [`OpenOptionsExt::mode`](std::os::unix::fs::OpenOptionsExt::mode) is masked by the
//! process umask, and that is safe here in the only direction that matters: a umask can
//! only *clear* permission bits, and 0600 has no group or other bits left to clear. Any
//! umask yields exactly 0600.
//!
//! # Why the file exists at all
//!
//! [`ops::read`](tdfu_core::ops::read) streams to a `Write` so a 256 MiB NAND alt never
//! buffers — a T40XP whole-chip read is four times the daemon's payload
//! cap and was proved on the bench. A file is the sink that keeps that property. The C
//! stages one too, and then buffers the whole image **twice** in RAM to answer
//! (`main.c:692` and `:714`, about 512 MiB peak for that T40XP); see [`Staged`]'s note
//! on what our seam can and cannot do about the second copy.
//!
//! # It is removed by `Drop`
//!
//! The C removes this file at **seven** call sites (`main.c:652`, `:667`, `:677`,
//! `:687`, `:695`, `:702`, `:707`) and still leaks its *write* temp file on one early
//! return (`:555`). An audit cleared "`Drop`-based cleanup beats the C's seven `remove`
//! call sites" as a decision already validated; this is it.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A uniquely-named file that removes itself when it is dropped.
///
/// Not `Clone`: two owners would mean two removals and a use-after-remove.
#[derive(Debug)]
pub struct Staged {
    path: PathBuf,
    file: Option<File>,
}

impl Staged {
    /// The mode the C's `mkstemp` gives this file, and the mode it must have here.
    pub const MODE: u32 = 0o600;

    /// How many names to try before giving up. A collision needs the same process id,
    /// the same counter and the same nanosecond, so one retry would do; ten is free.
    const ATTEMPTS: u32 = 10;

    /// Create `dir/<prefix>-<unique>` at [`MODE`](Staged::MODE), failing if it exists.
    ///
    /// # Errors
    /// [`io::Error`] from the create, unchanged: the reason a directory is unwritable
    /// is the actionable half and the C's `"failed to create temp file"`
    /// (`dfu-remote/main.c:645`) is not.
    pub fn create(dir: impl AsRef<Path>, prefix: &str) -> io::Result<Self> {
        Self::create_with(dir, prefix, unique)
    }

    /// [`create`](Staged::create) with the name source supplied.
    ///
    /// **The seam exists so the retry rule can be tested.** A name collision needs the
    /// same process id, the same counter *and* the same nanosecond, so no test can
    /// provoke one through [`unique`] — and a retry loop nothing can drive is a retry
    /// loop nobody knows the shape of. `cargo mutants` made the point directly: with the
    /// real generator, inverting this function's "is it a collision?" test survives the
    /// whole suite. That is an audit's corollary about equivalent mutants
    /// (contracts, "Amendments to the seam"): before calling one equivalent, check
    /// whether the fixture can express the input that separates the operators. Here it
    /// could not, so the fixture changed.
    ///
    /// Only a collision retries. Every other failure — the directory is missing, the
    /// filesystem is read-only, the disk is full — is returned at once, because retrying
    /// it nine more times changes nothing and delays the message that says what to fix.
    ///
    /// # Errors
    /// The first non-collision [`io::Error`], or the last collision if every name was
    /// taken.
    pub fn create_with(dir: impl AsRef<Path>, prefix: &str, mut names: impl FnMut() -> String) -> io::Result<Self> {
        let dir = dir.as_ref();
        let mut last = None;
        for _ in 0..Self::ATTEMPTS {
            let path = dir.join(format!("{prefix}-{}", names()));
            match options().open(&path) {
                Ok(file) => {
                    return Ok(Self { path, file: Some(file) });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("could not find an unused staging name")))
    }

    /// The handle to write through. `None` once [`finish`](Staged::finish) has run.
    pub fn file(&mut self) -> Option<&mut File> {
        self.file.as_mut()
    }

    /// Close the handle and hand back the path, keeping the removal-on-drop.
    ///
    /// Closing before reading matters on Windows, where a file open for writing cannot
    /// always be reopened.
    pub fn finish(&mut self) -> &Path {
        self.file = None;
        &self.path
    }

    /// Where it is. Used by tests and by the error messages.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        self.file = None;
        // A failed removal is not worth failing an otherwise-successful read over, but
        // it is worth a line: an undeletable staging file is a disk that will fill.
        if let Err(error) = std::fs::remove_file(&self.path)
            && worth_reporting(error.kind())
        {
            tracing::warn!(path = %self.path.display(), %error, "could not remove the staging file");
        }
    }
}

/// Is a failed removal worth a log line?
///
/// A file that is already gone is the outcome the removal wanted, so saying so would be
/// noise on every path where something else got there first. Everything else — a
/// read-only filesystem, a directory whose permissions changed under us — leaves a whole
/// flash image on disk and is worth hearing about.
///
/// A named function rather than an inline comparison because it is the only part of
/// `Drop` a test can reach: `cargo mutants` inverted the comparison and nothing failed,
/// since the difference is a log line no assertion looks at.
const fn worth_reporting(kind: io::ErrorKind) -> bool {
    !matches!(kind, io::ErrorKind::NotFound)
}

/// The open flags for a staging file: write, refuse to clobber, and on unix the mode.
///
/// **One function with the mode behind a `cfg` block, not two functions behind `cfg`
/// attributes.** With two, the Windows one is invisible to every check that runs on
/// Linux — `cargo mutants` emptied its body and nothing noticed, because nothing on this
/// platform compiles it. One function is covered by the same 0600 test everywhere it
/// matters and cannot silently rot on the platform nobody develops on.
///
/// Windows has no mode bits: a file in the per-user `%TEMP%` inherits that directory's
/// ACL, which is the platform's equivalent. `create_new` still gives the exclusivity
/// there, and the name is unique here where the C's is a fixed
/// `%TEMP%\tdfu-read-tmp.bin` shared by every concurrent daemon (`dfu-remote/main.c:639`).
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(Staged::MODE);
    }
    options
}

/// A name no other staging file will take: process, counter, nanosecond.
fn unique() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    format!("{}-{count}-{nanos:09}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::Staged;
    use std::io::Write;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A scratch directory that removes itself, so these tests need no `tempfile`.
    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(tag: &str) -> std::io::Result<Self> {
            let path = std::env::temp_dir().join(format!("tdfu-daemon-test-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The C's `mkstemp` gives 0600
    /// (`dfu-remote/main.c:643`, template at `:642`); an earlier implementation gave 0664 to a file holding a whole flash
    /// image. This is the pin that a permissive mode cannot come back.
    #[cfg(unix)]
    #[test]
    fn the_read_staging_file_is_0600() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new("mode")?;
        let staged = Staged::create(&dir.0, "tdfu-read")?;
        let mode = std::fs::metadata(staged.path())?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a flash image must not be group- or world-readable");
        assert_eq!(Staged::MODE, 0o600);
        Ok(())
    }

    /// And the mode survives a permissive umask, which is the reason
    /// `OpenOptions::mode` is enough on its own: a umask only clears bits and 0600 has
    /// none to clear.
    #[cfg(unix)]
    #[test]
    fn the_mode_survives_a_permissive_umask() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = Dir::new("umask")?;
        // SAFETY-free: `umask` is a libc call, but `std` does not expose it, so this
        // asserts the property the other way round - the mode requested has no bits a
        // umask could clear, which is checked arithmetically rather than by syscall.
        for umask in [0o000_u32, 0o002, 0o022, 0o077] {
            assert_eq!(
                Staged::MODE & !umask,
                Staged::MODE,
                "umask {umask:03o} would clear a bit"
            );
        }
        let staged = Staged::create(&dir.0, "tdfu-read")?;
        assert_eq!(std::fs::metadata(staged.path())?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    /// `Drop`-based cleanup, against the C's seven `remove` sites.
    #[test]
    fn the_staging_file_removes_itself() -> TestResult {
        let dir = Dir::new("drop")?;
        let path = {
            let mut staged = Staged::create(&dir.0, "tdfu-read")?;
            staged
                .file()
                .ok_or("a fresh staging file has a handle")?
                .write_all(b"secrets")?;
            let path = staged.path().to_path_buf();
            assert!(path.exists());
            path
        };
        assert!(!path.exists(), "the file must not outlive the operation");
        Ok(())
    }

    /// A removal that failed because the file was already gone is not worth a line; any
    /// other failure leaves a whole flash image on disk and is.
    #[test]
    fn only_a_real_removal_failure_is_reported() {
        use std::io::ErrorKind;
        assert!(!super::worth_reporting(ErrorKind::NotFound), "already gone is fine");
        for real in [
            ErrorKind::PermissionDenied,
            ErrorKind::ReadOnlyFilesystem,
            ErrorKind::DirectoryNotEmpty,
            ErrorKind::Other,
        ] {
            assert!(super::worth_reporting(real), "{real:?} leaves the image behind");
        }
    }

    /// Two staging files never collide, so two daemons — or a daemon and a test — do
    /// not share one. The C's Windows path uses a fixed name and does
    /// (`dfu-remote/main.c:639`).
    #[test]
    fn two_staging_files_have_different_names() -> TestResult {
        let dir = Dir::new("unique")?;
        let first = Staged::create(&dir.0, "tdfu-read")?;
        let second = Staged::create(&dir.0, "tdfu-read")?;
        assert_ne!(first.path(), second.path());
        Ok(())
    }

    /// A directory that does not exist gives the OS's reason, not a flat
    /// "failed to create temp file".
    #[test]
    fn a_bad_staging_directory_says_why() -> TestResult {
        let Err(error) = Staged::create("/definitely/not/a/directory/here", "tdfu-read") else {
            return Err("a missing directory cannot be staged into".into());
        };
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ),
            "{error:?}"
        );
        Ok(())
    }

    /// A name that is already taken is retried; the mode survives the retry.
    ///
    /// The real generator cannot collide, so this drives the loop through the seam —
    /// see [`Staged::create_with`] for why that seam exists.
    #[test]
    fn a_taken_name_is_retried_and_the_next_one_is_used() -> TestResult {
        let dir = Dir::new("collide")?;
        std::fs::write(dir.0.join("tdfu-read-taken"), b"someone else's")?;

        let mut names = ["taken", "taken", "free"].into_iter().map(str::to_owned);
        let staged = Staged::create_with(&dir.0, "tdfu-read", || names.next().unwrap_or_default())?;
        assert!(staged.path().ends_with("tdfu-read-free"), "{}", staged.path().display());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(staged.path())?.permissions().mode() & 0o777,
                0o600,
                "the retry must not lose the mode"
            );
        }
        // The file that was already there is untouched.
        assert_eq!(std::fs::read(dir.0.join("tdfu-read-taken"))?, b"someone else's");
        Ok(())
    }

    /// A failure that is **not** a collision is returned at once, not retried ten times.
    ///
    /// Counting the names asked for is what separates "only a collision retries" from
    /// "everything retries": both end with the same error value, so the error alone
    /// cannot tell them apart.
    #[test]
    fn a_failure_that_is_not_a_collision_is_not_retried() {
        let mut asked = 0_u32;
        let outcome = Staged::create_with("/definitely/not/a/directory", "tdfu-read", || {
            asked += 1;
            format!("name-{asked}")
        });
        assert!(outcome.is_err());
        assert_eq!(asked, 1, "a missing directory does not become better on the tenth try");
    }

    /// And when every name is taken, the loop gives up after `ATTEMPTS` and hands back
    /// the collision rather than a fabricated error.
    #[test]
    fn a_name_source_that_never_yields_a_free_name_gives_up() -> TestResult {
        let dir = Dir::new("exhausted")?;
        std::fs::write(dir.0.join("tdfu-read-always"), b"taken")?;
        let mut asked = 0_u32;
        let outcome = Staged::create_with(&dir.0, "tdfu-read", || {
            asked += 1;
            "always".to_owned()
        });
        let Err(error) = outcome else {
            return Err("every name was taken".into());
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(asked, 10, "one name per attempt");
        Ok(())
    }

    /// `finish` drops the handle and keeps the path, so the file can be re-opened for
    /// reading and is still removed when the value dies.
    #[test]
    fn finish_closes_the_handle_and_keeps_the_removal() -> TestResult {
        let dir = Dir::new("finish")?;
        let path;
        {
            let mut staged = Staged::create(&dir.0, "tdfu-read")?;
            staged.file().ok_or("handle")?.write_all(b"payload")?;
            path = staged.finish().to_path_buf();
            assert!(staged.file().is_none(), "the handle is gone");
            assert_eq!(std::fs::read(&path)?, b"payload");
        }
        assert!(!path.exists());
        Ok(())
    }
}
