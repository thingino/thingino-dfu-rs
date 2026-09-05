//! `cargo xtask package`: build one release archive from this tree.
//!
//! The six artifacts and their names are fixed, and they are the C
//! tool's names on purpose: a user's download link, the lab's unpack path
//! (`thingino-dfu-linux-aarch64/`), and the Android app's Gradle unpack must all survive
//! the cutover unchanged.
//!
//! ```text
//! thingino-dfu-linux-x86_64.tar.gz    thingino-dfu-linux-x86_64/{thingino-dfu,dfu-remote,README.md,firmware/dfu/...}
//! thingino-dfu-linux-aarch64.tar.gz   same
//! thingino-dfu-windows-x64.zip        same, with .exe
//! thingino-dfu-macos-universal.tar.gz same, lipo'd
//! thingino-dfu-web.tar.gz             thingino-dfu-web/ = web/dist, which carries its own firmware/dfu/
//! libtdfu-android-<version>.tar.gz    ./{README, jniLibs/<abi>/libtdfu_jni.so, firmware/dfu/...}, unpacked by thingino-app
//! ```
//!
//! **What is deliberately not copied from the C's `Package` step.** It writes
//! `[ -f build/dfu-remote/dfu-remote ] && cp ... || true`, so an archive that lost a
//! binary ships anyway and the failure surfaces on a user's machine. Every copy here is
//! checked, and a missing file ends the run. The C also publishes no checksums; every run
//! here writes a `sha256sum`-format line into `SHA256SUMS` beside the archive.
//!
//! **The archives are deterministic.** Every entry gets mode 0644 (0755 for the two
//! binaries and directories), owner 0:0 and one fixed timestamp, so re-cutting the same
//! commit produces the same bytes. That matters because `docs/release.md` forbids reusing
//! a tag with different bytes: with a deterministic archive, "same tag, same bytes" is
//! checkable rather than assumed.
//!
//! The build hash the banner prints comes from the tree being packaged (`TDFU_GIT_HASH`,
//! `crates/tdfu-cli/src/banner.rs`), so a locally built archive says which commit it is
//! as truthfully as a CI one, and says `-dirty` when it is not any commit at all.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

use crate::{Fallible, hex, workspace_root};

pub(crate) const USAGE: &str = "usage: cargo xtask package --target <triple|name> [--out <dir>] [--no-build]\n\
                                       cargo xtask package --check-tag <vX.Y.Z[-pre.N]>\n\
                                       cargo xtask package --print-version\n\
                                       cargo xtask package --print-jni-symbols";

/// Where the archives and `SHA256SUMS` land when `--out` is not given.
const DEFAULT_OUT: &str = "dist";

/// The two binaries every non-web archive carries, in the order they are listed.
const BINARIES: [&str; 2] = ["thingino-dfu", "dfu-remote"];

/// 2020-01-01T00:00:00Z. One fixed timestamp for every entry in every archive; see the
/// module doc on determinism.
const FIXED_MTIME: u64 = 1_577_836_800;

// ---------------------------------------------------------------------------
// The target table
// ---------------------------------------------------------------------------

/// How an archive is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    /// `.tar.gz`, for everything but Windows.
    TarGz,
    /// `.zip`, because that is what a Windows user can open without installing anything.
    Zip,
}

/// Which install instructions the archive's `README.md` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    Windows,
    MacOs,
    /// Served, not installed.
    Web,
    /// A build input for `thingino-app`, not an installable tool: a `.so` per ABI plus the
    /// loader assets. Its README is `README` (no `.md`) and its archive has no top
    /// directory, both to match what the app's Gradle already unpacks.
    Android,
}

/// What gets built before the archive is assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Build {
    /// One rustc target triple; binaries land in `target/<triple>/release/`.
    Triple(&'static str),
    /// Two apple triples joined with `lipo` into `target/macos-universal/release/`.
    Universal,
    /// `web/dist`, built by `cargo xtask web --release`; this command never builds it.
    Web,
    /// The `tdfu-jni` `cdylib` (`libtdfu_jni.so`) cross-compiled for the two Android ABIs
    /// in [`ANDROID_ABIS`], each with the NDK's clang as linker and the 16 KiB page-size
    /// link option, then laid out under `jniLibs/<abi>/`. Not a `Triple`: it is two
    /// triples producing one archive, and it stages a `.so` per ABI rather than binaries.
    Android,
}

/// One release target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Target {
    /// The suffix in `thingino-dfu-<name>`. These five strings are the published
    /// download names and are not ours to change.
    pub(crate) name: &'static str,
    pub(crate) build: Build,
    pub(crate) format: Format,
    pub(crate) os: Platform,
}

/// The six artifacts of a release, and nothing else.
pub(crate) const TARGETS: [Target; 6] = [
    Target {
        name: "linux-x86_64",
        build: Build::Triple("x86_64-unknown-linux-gnu"),
        format: Format::TarGz,
        os: Platform::Linux,
    },
    Target {
        name: "linux-aarch64",
        build: Build::Triple("aarch64-unknown-linux-gnu"),
        format: Format::TarGz,
        os: Platform::Linux,
    },
    Target {
        name: "windows-x64",
        build: Build::Triple("x86_64-pc-windows-gnu"),
        format: Format::Zip,
        os: Platform::Windows,
    },
    Target {
        name: "macos-universal",
        build: Build::Universal,
        format: Format::TarGz,
        os: Platform::MacOs,
    },
    Target {
        name: "web",
        build: Build::Web,
        format: Format::TarGz,
        os: Platform::Web,
    },
    Target {
        // `android` is a name, not a triple: it maps to two triples (`ANDROID_ABIS`), so
        // `--target android` is the only spelling `find_target` resolves for it. The
        // archive name is `libtdfu-android-<version>.tar.gz`, not `thingino-dfu-android`.
        name: "android",
        build: Build::Android,
        format: Format::TarGz,
        os: Platform::Android,
    },
];

/// The two halves of the macOS universal binary.
const APPLE_TRIPLES: [&str; 2] = ["x86_64-apple-darwin", "aarch64-apple-darwin"];

/// The two Android ABIs, as `(rustc target triple, jniLibs directory, NDK linker binary)`.
///
/// The linker name is not the triple: `armv7-linux-androideabi` links with
/// `armv7a-linux-androideabi21-clang` (note the `a` and the API level), and
/// `aarch64-linux-android` with `aarch64-linux-android21-clang`. API 21 matches the C's
/// `android-26` platform floor at the level where these two toolchains exist; the app's own
/// `minSdk` is 26. Both are the `<ndk>/toolchains/llvm/prebuilt/<host>/bin` clang wrappers.
const ANDROID_ABIS: [(&str, &str, &str); 2] = [
    ("aarch64-linux-android", "arm64-v8a", "aarch64-linux-android21-clang"),
    (
        "armv7-linux-androideabi",
        "armeabi-v7a",
        "armv7a-linux-androideabi21-clang",
    ),
];

/// The exact ten JNI exports every `libtdfu_jni.so` must carry and no others under the
/// `Java_com_thingino_dfu_TdfuBridge_` prefix. Renaming the Kotlin package silently breaks
/// statically registered JNI, so the drop-in asserts the full set rather than trusting the
/// build (the C does the weaker `readelf --dyn-syms | grep -c`, `build-libtdfu-android.sh:79`).
const JNI_PREFIX: &str = "Java_com_thingino_dfu_TdfuBridge_";
const JNI_EXPORTS: [&str; 10] = [
    "Java_com_thingino_dfu_TdfuBridge_nativeSetCallback",
    "Java_com_thingino_dfu_TdfuBridge_nativeSetDebug",
    "Java_com_thingino_dfu_TdfuBridge_nativeDetectSoc",
    "Java_com_thingino_dfu_TdfuBridge_nativeVariantToString",
    "Java_com_thingino_dfu_TdfuBridge_nativeBootstrap",
    "Java_com_thingino_dfu_TdfuBridge_nativeBootstrapFiles",
    "Java_com_thingino_dfu_TdfuBridge_nativeReadFirmware",
    "Java_com_thingino_dfu_TdfuBridge_nativeWriteFirmware",
    "Java_com_thingino_dfu_TdfuBridge_nativeVerifyFirmware",
    "Java_com_thingino_dfu_TdfuBridge_nativeReboot",
];
/// The JNI entry point. It is not under [`JNI_PREFIX`] and it is not optional: it is the
/// only caller of the bridge's `store_vm`, so a `.so` missing it delivers no log line and
/// no progress at all while every export still returns `0` or `-1`.
const JNI_ON_LOAD: &str = "JNI_OnLoad";

/// The Android system libraries a `libtdfu_jni.so` may name as `NEEDED`. Anything else means
/// something failed to link statically and would surface as a `dlopen` error on device, so
/// the package refuses it at build time (the C does the same, `build-libtdfu-android.sh:69`).
/// `ld-android.so` is on the list because a Rust `cdylib` names it where the C did not.
const ANDROID_SYSTEM_LIBS: [&str; 6] = [
    "libc.so",
    "libm.so",
    "libdl.so",
    "liblog.so",
    "libandroid.so",
    "ld-android.so",
];

impl Target {
    /// The on-disk staging directory under `--out`, and for every target but Android the
    /// top directory inside the archive too. Android stages under `libtdfu-android/` but its
    /// archive has no top directory (see [`Target::archive_prefix`]).
    fn dir_name(self) -> String {
        match self.os {
            Platform::Android => "libtdfu-android".to_owned(),
            _ => format!("thingino-dfu-{}", self.name),
        }
    }

    /// The prefix every archive entry carries. For the five `thingino-dfu-*` archives this
    /// is the top directory the archive unpacks to; for Android it is `.`, so entries are
    /// `./README`, `./jniLibs/<abi>/...` and `./firmware/dfu/...` at the archive root - the
    /// layout `thingino-dfu`'s `build-libtdfu-android.sh` produced with `tar -C stage .`
    /// and the app's Gradle unpacks verbatim.
    fn archive_prefix(self) -> String {
        match self.os {
            Platform::Android => ".".to_owned(),
            _ => self.dir_name(),
        }
    }

    /// The published file name. Android carries the version in the name
    /// (`libtdfu-android-<version>.tar.gz`, what the app pins); the others do not, because
    /// their name is a stable download link that must not move at the cutover.
    fn archive_name(self, version: &str) -> String {
        if self.os == Platform::Android {
            return format!("libtdfu-android-{version}.tar.gz");
        }
        match self.format {
            Format::TarGz => format!("{}.tar.gz", self.dir_name()),
            Format::Zip => format!("{}.zip", self.dir_name()),
        }
    }

    /// `.exe` on Windows, nothing anywhere else.
    fn exe_suffix(self) -> &'static str {
        if self.os == Platform::Windows { ".exe" } else { "" }
    }
}

/// The target named by `--target`, by artifact name **or** by rustc triple.
///
/// Both spellings are accepted because the workflow's matrix already carries the triples
/// (they are what `rustup target add` takes) and a person at a terminal thinks in the
/// download name. An unknown value is refused with the full list rather than defaulted:
/// the C's `--cpu` silently fell back to `t31x` and that is exactly the class of bug this
/// rewrite exists to stop reproducing.
pub(crate) fn find_target(arg: &str) -> Result<Target, String> {
    for target in TARGETS {
        if target.name == arg {
            return Ok(target);
        }
        if let Build::Triple(triple) = target.build
            && triple == arg
        {
            return Ok(target);
        }
    }
    let known: Vec<String> = TARGETS
        .iter()
        .map(|t| match t.build {
            Build::Triple(triple) => format!("{} ({triple})", t.name),
            _ => t.name.to_owned(),
        })
        .collect();
    Err(format!(
        "unknown target {arg:?}; this release has exactly six:\n  {}",
        known.join("\n  ")
    ))
}

// ---------------------------------------------------------------------------
// The version and the tag check
// ---------------------------------------------------------------------------

/// The workspace manifest, as much of it as this command reads.
#[derive(Debug, serde::Deserialize)]
struct Manifest {
    workspace: ManifestWorkspace,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestWorkspace {
    package: WorkspacePackage,
}

#[derive(Debug, serde::Deserialize)]
struct WorkspacePackage {
    version: String,
}

/// `workspace.package.version` from a manifest.
///
/// One reader, so the README, the archive and the tag check cannot disagree about which
/// version this is.
fn manifest_facts(text: &str) -> Result<String, String> {
    let manifest: Manifest = toml::from_str(text).map_err(|e| format!("Cargo.toml: {e}"))?;
    let version = manifest.workspace.package.version;
    if version.trim().is_empty() {
        return Err("Cargo.toml: workspace.package.version is empty".to_owned());
    }
    Ok(version)
}

/// Does the tag being released name the version this tree actually is?
///
/// A tag is `v` plus the version, exactly. A mismatch prints **both** values, because the
/// question the reader has at that moment is which of the two is wrong.
///
/// `refs/tags/v…` is accepted as well as `v…` so this works with `GITHUB_REF` as well as
/// `GITHUB_REF_NAME`.
pub(crate) fn check_tag(tag: &str, version: &str) -> Result<(), String> {
    let tag = tag.trim();
    let bare = tag.strip_prefix("refs/tags/").unwrap_or(tag);
    let Some(tagged) = bare.strip_prefix('v') else {
        return Err(format!(
            "tag {tag:?} does not start with `v`; a release tag is `v` plus the workspace version ({version})"
        ));
    };
    if tagged == version {
        return Ok(());
    }
    Err(format!(
        "the tag and the workspace version are not the same release\n  \
         tag                        {tag}\n  \
         workspace.package.version  {version}\n  \
         Bump Cargo.toml or retag; do not publish a v{tagged} archive that calls itself {version}."
    ))
}

/// A tag with a pre-release suffix publishes with `--prerelease`.
///
/// Semver's rule, not a spelling of `alpha`: everything after the first `-` in
/// `vX.Y.Z-…` is a pre-release identifier, so `-rc.1`, `-alpha.1` and anything else the
/// owner invents are all prereleases without this needing an edit.
pub(crate) fn is_prerelease(tag: &str) -> bool {
    let bare = tag.trim();
    let bare = bare.strip_prefix("refs/tags/").unwrap_or(bare);
    bare.strip_prefix('v').unwrap_or(bare).contains('-')
}

/// The line `release.yml` greps to gate `--prerelease`: `prerelease=true` or
/// `prerelease=false`, straight from [`is_prerelease`].
///
/// The publish step used to re-decide this in a bash `case *-*` that no test observed;
/// it reads this line now, so the gate that flips `--prerelease` and the logic
/// the tests pin are one function.
fn prerelease_line(tag: &str) -> String {
    format!("prerelease={}", is_prerelease(tag))
}

// ---------------------------------------------------------------------------
// The build hash
// ---------------------------------------------------------------------------

/// `TDFU_GIT_HASH` for the build about to happen.
///
/// `crates/tdfu-cli/src/banner.rs` reads this at compile time and prints `unknown` when
/// it is unset, which is the honest answer for a plain `cargo build`. A release archive
/// can do better: it knows which tree it is packaging.
///
/// An environment variable already in scope wins, so CI's `git rev-parse --short=7
/// "$GITHUB_SHA"` reaches the binaries unchanged.
fn build_hash(root: &Path) -> Option<String> {
    if let Ok(preset) = std::env::var("TDFU_GIT_HASH")
        && !preset.trim().is_empty()
    {
        return Some(preset.trim().to_owned());
    }
    let head = git(root, &["rev-parse", "--short=7", "HEAD"])?;
    let dirty = git(root, &["status", "--porcelain"]).is_some_and(|out| !out.trim().is_empty());
    Some(hash_label(&head, dirty))
}

/// The hash as the banner will print it.
///
/// `-dirty` is not decoration: an archive built from edits that are in no commit must not
/// claim to be that commit, because the first thing a pasted banner is used for is
/// finding the source it came from.
fn hash_label(head: &str, dirty: bool) -> String {
    let head = head.trim();
    if dirty {
        format!("{head}-dirty")
    } else {
        head.to_owned()
    }
}

/// Run git and return its trimmed stdout, or `None` if it could not answer.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git").current_dir(root).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim().to_owned();
    (!text.is_empty()).then_some(text)
}

// ---------------------------------------------------------------------------
// The `--help` first lines
// ---------------------------------------------------------------------------

/// The two lines the archive's README quotes, and where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HelpLines {
    cli: String,
    daemon: String,
}

/// The first line of the Rust string literal that follows `anchor` in `source`.
///
/// This is the fallback for a cross-compiled archive: the binaries in
/// `target/x86_64-pc-windows-gnu/release/` cannot be run on the machine assembling them,
/// but the text they would print is in this tree either way. Pure over the text, so both
/// anchors are pinned against the real files below.
///
/// Rust's escapes are decoded far enough to stop at the first `\n`, and a backslash at
/// end of line is a line continuation (the literal continues after the next line's
/// leading whitespace), which is how both of these are written.
fn first_help_line(source: &str, anchor: &str) -> Option<String> {
    let after = source.split_once(anchor)?.1;
    let body = after.split_once('"')?.1;
    let mut line = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\n' => break,
            '\\' => match chars.next()? {
                'n' => break,
                't' => line.push('\t'),
                '\\' => line.push('\\'),
                '"' => line.push('"'),
                '\'' => line.push('\''),
                // `\x20` is how this repo writes a leading space in a continued literal.
                'x' => {
                    let hex: String = chars.by_ref().take(2).collect();
                    let value = u8::from_str_radix(&hex, 16).ok()?;
                    line.push(char::from(value));
                }
                // End of line inside a literal: skip the newline and the next line's indent.
                '\n' | '\r' => {
                    let rest = chars.as_str().trim_start();
                    chars = rest.chars();
                }
                other => line.push(other),
            },
            other => line.push(other),
        }
    }
    let line = line.trim().to_owned();
    (!line.is_empty()).then_some(line)
}

/// `crates/tdfu-cli/src/cli.rs`: clap prints `long_about` for `--help`.
const CLI_HELP_ANCHOR: &str = "long_about =";
/// `crates/tdfu-daemon/src/transport/options.rs`: the `-h` text is one format string.
const DAEMON_HELP_ANCHOR: &str = "fn usage() -> String {";

/// The first `--help` line of each binary: from the built binary where this host can run
/// it, and from the source it was built from where it cannot.
///
/// Running the real binary is preferred because it is the answer to the question rather
/// than a reconstruction of it; the source is the honest fallback for a cross build, and
/// it is the same tree the binary was compiled from a minute earlier.
fn help_lines(root: &Path, stage: &Path, target: Target) -> HelpLines {
    let from_binary = |name: &str| -> Option<String> {
        let path = stage.join(format!("{name}{}", target.exe_suffix()));
        let output = Command::new(&path).arg("--help").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        text.lines().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_owned())
    };
    let from_source = |relative: &[&str], anchor: &str| -> Option<String> {
        let mut path = root.to_path_buf();
        for part in relative {
            path.push(part);
        }
        first_help_line(&fs::read_to_string(path).ok()?, anchor)
    };

    HelpLines {
        cli: from_binary("thingino-dfu")
            .or_else(|| from_source(&["crates", "tdfu-cli", "src", "cli.rs"], CLI_HELP_ANCHOR))
            .unwrap_or_else(|| "Flash Ingenic XBurst cameras over USB.".to_owned()),
        daemon: from_binary("dfu-remote")
            .or_else(|| {
                from_source(
                    &["crates", "tdfu-daemon", "src", "transport", "options.rs"],
                    DAEMON_HELP_ANCHOR,
                )
            })
            .unwrap_or_else(|| "dfu-remote - thingino-dfu remote daemon".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// The archive README
// ---------------------------------------------------------------------------

/// The tool's own repository, named in every archive.
///
/// A constant rather than a value read from the manifest, so the archive text is pinned
/// by a test and cannot drift with a manifest edit nobody meant for the READMEs.
const TOOL_REPOSITORY: &str = "https://github.com/thingino/thingino-dfu-rs";

/// The release the loaders are fetched from, named in every archive as their source.
fn loader_release_url() -> String {
    format!(
        "https://github.com/{}/releases/tag/{}",
        crate::LOADER_REPO,
        crate::LOADER_RELEASE
    )
}

/// Everything the archive's `README.md` says, gathered before any of it is rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Readme {
    version: String,
    hash: String,
    target: Target,
    /// The U-Boot commit the fetched loader tree was built from, from the stamp
    /// `fetch-loaders` writes beside it.
    loader_commit: String,
    help: Option<HelpLines>,
}

/// The archive's `README.md`.
///
/// Pure, so the whole document is pinned by a test rather than eyeballed once per
/// release. What has to be in it is fixed: the version, the install step
/// for this OS, the loader pin, and the two `--help` first lines.
fn render_readme(facts: &Readme) -> String {
    use core::fmt::Write as _;

    // Writing to a `String` cannot fail, and there is nothing useful to do with the
    // `Result` if the impl ever changed its mind; `hex` in `main.rs` does the same.
    let mut out = String::new();
    let name = facts.target.name;
    let version = &facts.version;
    let hash = &facts.hash;

    let _ = writeln!(out, "# thingino-dfu {version} - {name}\n");
    let _ = writeln!(
        out,
        "Flash Ingenic XBurst cameras (T10 to T41, A1) over USB. Built from {hash}.\n"
    );

    out.push_str("## What is in here\n\n");
    if facts.target.os == Platform::Web {
        out.push_str(
            "This archive is the browser flasher: an `index.html` and the assets it loads,\n\
             including the `firmware/dfu/` loader tree it bootstraps from. There is no\n\
             binary to install.\n\n",
        );
    } else {
        let exe = facts.target.exe_suffix();
        let _ = writeln!(
            out,
            "- `thingino-dfu{exe}` - the command line tool.\n\
             - `dfu-remote{exe}` - the daemon that serves the same operations over the network\n\
             \x20 to `thingino-dfu --host <addr>` and to the browser flasher.\n\
             - `firmware/dfu/<variant>/` - the loaders `-b` bootstraps with. Both binaries look\n\
             \x20 for this tree beside themselves, so keep it next to them when you move them.\n"
        );
    }

    if let Some(help) = &facts.help {
        out.push_str("```\n");
        let _ = writeln!(out, "$ thingino-dfu --help\n{}\n", help.cli);
        let _ = writeln!(out, "$ dfu-remote --help\n{}", help.daemon);
        out.push_str("```\n\n");
    }

    out.push_str("## Install\n\n");
    out.push_str(install_text(facts.target.os));
    out.push('\n');

    out.push_str("## The loaders\n\n");
    let _ = writeln!(
        out,
        "`firmware/dfu/` is not built here. It is the USB-boot loader set of the `{}` release\n\
         of `{}` (`isvp_<soc>_usbboot`), fetched when this archive was built. Those loaders\n\
         were built from U-Boot commit:\n",
        crate::LOADER_RELEASE,
        crate::LOADER_REPO
    );
    let _ = writeln!(out, "```\n{}\n```\n", facts.loader_commit);
    let _ = writeln!(
        out,
        "The release is {}. Bootstrapping with a loader that is not the one this archive\n\
         shipped looks exactly like a tool regression and is not, which is why the commit is\n\
         written down here.\n",
        loader_release_url()
    );

    out.push_str("## Where this came from\n\n");
    let _ = writeln!(
        out,
        "thingino-dfu {version}, the Rust rewrite of thingino-dfu.\n{TOOL_REPOSITORY}\nGPL-2.0-or-later."
    );
    out
}

/// The Android tarball's `README` (no `.md`).
///
/// Adapted from `thingino-dfu`'s `build-libtdfu-android.sh` README: what each part is, the
/// `com.thingino.dfu.TdfuBridge` package note, and min API 26. Pure, so the whole document
/// is pinned by a test rather than eyeballed. The tool named here is THIS repo, the Rust
/// rewrite; the loader pin's repo is named only as the loader source, the same split
/// [`render_readme`] makes.
fn render_android_readme(facts: &Readme) -> String {
    use core::fmt::Write as _;

    let mut out = String::new();
    let version = &facts.version;
    let hash = &facts.hash;

    let _ = writeln!(out, "libtdfu for Android {version}\n");
    let _ = writeln!(
        out,
        "Everything an Android app needs from thingino-dfu, built from {hash}. This is a\n\
         build input, not an app: thingino-app unpacks this tarball into its jniLibs/ and\n\
         assets/, and needs no NDK or C toolchain to consume it.\n"
    );

    out.push_str(
        "jniLibs/<abi>/libtdfu_jni.so\n\
         \x20   The JNI bridge over the Rust core, for arm64-v8a and armeabi-v7a. Only\n\
         \x20   Android system libraries are external. Copy into an APK at src/main/jniLibs/<abi>/.\n\
         \n\
         \x20   Declare the bindings from a Kotlin class named com.thingino.dfu.TdfuBridge.\n\
         \x20   That Java package is baked into the exported symbol names and is unrelated to\n\
         \x20   your applicationId, so keep it whatever your app is called. Renaming it\n\
         \x20   compiles and installs cleanly, then throws UnsatisfiedLinkError on the first flash.\n\
         \n\
         firmware/dfu/<variant>/\n\
         \x20   Bootstrap loaders (tpl.bin or spl.bin, and uboot.bin) per SoC variant, shipped\n\
         \x20   as the app's assets. Copy into an APK at src/main/assets/firmware/. Flashing\n\
         \x20   cannot work without them. This is the full loader tree, one directory per\n\
         \x20   variant, not a remapped subset.\n\
         \n\
         Minimum supported API level: 26.\n\n",
    );

    out.push_str("The loaders\n\n");
    let _ = writeln!(
        out,
        "firmware/dfu/ is not built here. It is the USB-boot loader set of the {} release of\n\
         {} (isvp_<soc>_usbboot), fetched when this tarball was built, from U-Boot commit:\n\
         \n\
         \x20   {}\n\
         \n\
         The release is {}.\n",
        crate::LOADER_RELEASE,
        crate::LOADER_REPO,
        facts.loader_commit,
        loader_release_url()
    );

    out.push_str("Where this came from\n\n");
    let _ = writeln!(
        out,
        "thingino-dfu {version}, the Rust rewrite of thingino-dfu.\n{TOOL_REPOSITORY}\nGPL-2.0-or-later."
    );
    out
}

/// The install step for one OS, one arm per platform an archive is built for.
fn install_text(os: Platform) -> &'static str {
    match os {
        Platform::Linux => {
            "Nothing to build. Unpack the archive and run `./thingino-dfu -l`, or move the whole\n\
             directory somewhere permanent - the binaries find `firmware/dfu/` beside themselves,\n\
             so move it whole rather than copying the binaries out on their own.\n\
             \n\
             Raw USB access needs a udev rule. A camera is two different USB devices over one\n\
             flash cycle - the bootrom before bootstrap and the U-Boot DFU gadget after - and\n\
             both are Ingenic vendor `a108`:\n\
             \n\
             ```\n\
             sudo tee /etc/udev/rules.d/99-thingino-dfu.rules >/dev/null <<'EOF'\n\
             # bootrom a108:c309, U-Boot DFU gadget a108:4d44\n\
             SUBSYSTEM==\"usb\", ATTR{idVendor}==\"a108\", MODE=\"0666\", TAG+=\"uaccess\"\n\
             # X series bootrom, for the day it speaks DFU\n\
             SUBSYSTEM==\"usb\", ATTR{idVendor}==\"601a\", MODE=\"0666\", TAG+=\"uaccess\"\n\
             EOF\n\
             sudo udevadm control --reload-rules && sudo udevadm trigger\n\
             ```\n\
             \n\
             Then unplug and replug the camera. Without the rule the tool reports access denied,\n\
             and so does the browser flasher on the same machine.\n"
        }
        Platform::Windows => {
            "Windows has no built-in driver this tool can claim, so install **WinUSB** with\n\
             [Zadig](https://zadig.akeo.ie/) - twice, because a camera is two different USB\n\
             devices over one flash cycle and WinUSB is bound per device:\n\
             \n\
             1. If the Ingenic vendor driver (`libusb0.sys`) is installed, remove it first in\n\
             \x20  Device Manager. It is not compatible with this tool.\n\
             2. Put the camera in USB boot mode. Open Zadig (Options -> List All Devices),\n\
             \x20  select **Ingenic USB Boot Device** (`A108:C309`) and install WinUSB.\n\
             3. Bootstrap: `thingino-dfu.exe -b`. The camera re-enumerates as a new device.\n\
             4. Run Zadig again, select **USB download gadget** (`A108:4D44`) and install WinUSB.\n\
             \n\
             Skip step 4 and the bootstrap succeeds while the write that follows cannot open the\n\
             device. It is a one-time setup per machine; after it, `thingino-dfu.exe -w fw.bin`\n\
             does bootstrap-and-write in one go.\n"
        }
        Platform::MacOs => {
            "Nothing to install. The binaries are universal (arm64 and x86_64) and macOS grants\n\
             USB access to the user, so there is no driver to add and no rule to write:\n\
             \n\
             ```\n\
             ./thingino-dfu -l\n\
             ```\n\
             \n\
             The archive is downloaded and unsigned, so Gatekeeper quarantines it. If macOS\n\
             refuses to run the binaries, clear the flag on the directory you unpacked:\n\
             \n\
             ```\n\
             xattr -dr com.apple.quarantine thingino-dfu-macos-universal\n\
             ```\n"
        }
        Platform::Web => {
            "Nothing to install: this is the flasher, served rather than installed. Unpack it\n\
             under any document root and open it in Chrome or Edge. WebUSB needs a\n\
             secure context, so that means HTTPS - `http://localhost` counts as one, and that\n\
             is what makes a local check possible:\n\
             \n\
             ```\n\
             python3 -m http.server --directory thingino-dfu-web 8000\n\
             ```\n\
             \n\
             On Linux the browser opens the same USB device the command line tool does, so it\n\
             needs the same udev rule for vendor `a108`; without it `USBDevice.open()` fails\n\
             with a SecurityError. Remote mode talks to a `dfu-remote` daemon from one of the\n\
             other archives.\n"
        }
        // Android has its own renderer (`render_android_readme`) and never routes through
        // `render_readme`, so this arm is not reached in a normal run; it keeps the match
        // exhaustive and gives an honest answer if a caller ever does ask.
        Platform::Android => {
            "This tarball is a build input for thingino-app, not an installable tool. thingino-app's\n\
             Gradle unpacks jniLibs/<abi>/libtdfu_jni.so and firmware/ into the APK for you; there\n\
             is nothing to install by hand. See the README for the package note and minimum API level.\n"
        }
    }
}

// ---------------------------------------------------------------------------
// SHA256SUMS
// ---------------------------------------------------------------------------

/// `SHA256SUMS` with `name` set to `digest`.
///
/// `sha256sum -c SHA256SUMS` format: the digest, two spaces, the file name. Merging
/// rather than appending means a local run that packages three targets one after another
/// accumulates three lines instead of three copies of the last one, and re-running one
/// target replaces its line instead of adding a second, stale one.
fn merge_sums(existing: &str, name: &str, digest: &str) -> String {
    use core::fmt::Write as _;

    let mut lines: BTreeMap<String, String> = BTreeMap::new();
    for line in existing.lines() {
        if let Some((sum, file)) = line.split_once("  ")
            && !file.trim().is_empty()
        {
            lines.insert(file.trim().to_owned(), sum.trim().to_owned());
        }
    }
    lines.insert(name.to_owned(), digest.to_owned());
    let mut out = String::new();
    for (file, sum) in lines {
        let _ = writeln!(out, "{sum}  {file}");
    }
    out
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

/// One file to put in the archive: where it is now, where it goes, and whether it is
/// executable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    source: PathBuf,
    /// Slash-separated, archive-relative, including the top directory.
    name: String,
    executable: bool,
}

/// Walk `dir` and list every file under it, following symlinks.
///
/// Symlinks are followed rather than stored: `web/dist/firmware` is a link into
/// `target/firmware` (`cargo xtask web` puts it there), and an archive that carries the
/// link instead of the tree unpacks to a dangling path on the user's machine.
///
/// `.gitkeep` files are skipped: they are repository scaffolding, and this is the one
/// place every archive's content passes through, so none of the six can carry one.
fn collect(dir: &Path, prefix: &str, into: &mut Vec<Entry>) -> Fallible {
    let mut names: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by_key(std::fs::DirEntry::file_name);
    for entry in names {
        let path = entry.path();
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(format!("{}: name is not UTF-8", path.display()).into());
        };
        if file_name == ".gitkeep" {
            // Repository scaffolding, never release content. The pinned loader tree carries
            // one (the C's web archive shipped it; its Android script deleted it before
            // tarring), and it would otherwise ride into all six archives.
            continue;
        }
        let name = format!("{prefix}/{file_name}");
        // `metadata`, not `file_type`: this follows the link.
        let meta = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.is_dir() {
            collect(&path, &name, into)?;
        } else {
            let executable = BINARIES
                .iter()
                .any(|bin| file_name == *bin || file_name == format!("{bin}.exe"));
            into.push(Entry {
                source: path,
                name,
                executable,
            });
        }
    }
    Ok(())
}

/// Copy one file, failing loudly when it is not there.
///
/// The C's `Package` step writes `[ -f … ] && cp … || true` for `dfu-remote`, so an
/// archive that lost a binary is published and the user finds out. This is that step
/// without the `|| true`.
fn require_copy(from: &Path, to: &Path, what: &str) -> Fallible {
    if !from.is_file() {
        return Err(format!(
            "{what} is missing: {}\n  \
             Nothing is packaged without it - an archive with a missing binary is a bug \
             delivered to a user, not a smaller archive.",
            from.display()
        )
        .into());
    }
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(from, to).map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))?;
    Ok(())
}

/// Recursive copy that follows symlinks, for the loader tree and `web/dist`.
fn copy_tree(from: &Path, to: &Path) -> Fallible {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let entry = entry?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let meta = fs::metadata(&source).map_err(|e| format!("{}: {e}", source.display()))?;
        if meta.is_dir() {
            copy_tree(&source, &target)?;
        } else {
            fs::copy(&source, &target).map_err(|e| format!("{}: {e}", source.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Writing the archives
// ---------------------------------------------------------------------------

/// Every directory prefix an entry list implies, deepest last.
fn directories(entries: &[Entry]) -> Vec<String> {
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let mut parts: Vec<&str> = entry.name.split('/').collect();
        parts.pop();
        let mut prefix = String::new();
        for part in parts {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            dirs.insert(prefix.clone());
        }
    }
    dirs.into_iter().collect()
}

/// Write a `.tar.gz` of `entries`.
fn write_tar_gz(path: &Path, entries: &[Entry]) -> Fallible {
    let file = fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut builder = tar::Builder::new(GzEncoder::new(file, Compression::default()));
    for dir in directories(entries) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(FIXED_MTIME);
        builder.append_data(&mut header, format!("{dir}/"), std::io::empty())?;
    }
    for entry in entries {
        let bytes = fs::read(&entry.source).map_err(|e| format!("{}: {e}", entry.source.display()))?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(if entry.executable { 0o755 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(FIXED_MTIME);
        builder.append_data(&mut header, &entry.name, bytes.as_slice())?;
    }
    builder.into_inner()?.finish()?;
    Ok(())
}

/// The fixed MS-DOS date stamp every zip entry carries: 2020-01-01, midnight.
///
/// The zip format has no other timestamp, so this is where [`FIXED_MTIME`] lands for the
/// Windows archive. `(year - 1980) << 9 | month << 5 | day`, and a time of zero.
const DOS_DATE: u16 = (40 << 9) | (1 << 5) | 1;
const DOS_TIME: u16 = 0;

/// A minimal deflate zip writer.
///
/// Written here rather than taken as a dependency: `cargo deny` runs
/// `multiple-versions = "deny"` over this workspace and a zip crate brings a subtree with
/// it, for a format that is a handful of little-endian records. Everything it needs -
/// deflate and CRC-32 - is already in `flate2`, which this crate uses for the tarballs.
///
/// Deliberately not implemented: zip64 (the archives are tens of megabytes; sizes are
/// range-checked rather than assumed), encryption, and data descriptors (the whole file
/// is in memory, so sizes and CRC are known before the header is written).
struct Zip {
    out: Vec<u8>,
    central: Vec<u8>,
    count: u16,
}

impl Zip {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            central: Vec::new(),
            count: 0,
        }
    }

    /// One member: `name` (with a trailing `/` for a directory), its bytes, its mode.
    fn add(&mut self, name: &str, data: &[u8], mode: u32) -> Fallible {
        let uncompressed =
            u32::try_from(data.len()).map_err(|_| format!("{name}: over 4 GiB, which this zip writer does not do"))?;
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc32 = crc.sum();

        let compressed: Vec<u8> = if data.is_empty() {
            Vec::new()
        } else {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data)?;
            encoder.finish()?
        };
        // `store` for an empty member (a directory), `deflate` otherwise.
        let method: u16 = if data.is_empty() { 0 } else { 8 };
        let compressed_len = u32::try_from(compressed.len()).map_err(|_| format!("{name}: compressed over 4 GiB"))?;
        let name_len = u16::try_from(name.len()).map_err(|_| format!("{name}: name longer than 65535 bytes"))?;
        let offset = u32::try_from(self.out.len())
            .map_err(|_| format!("{name}: the archive passed 4 GiB, which needs zip64"))?;

        // Local file header.
        self.out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        self.out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
        self.out.extend_from_slice(&0_u16.to_le_bytes()); // flags
        self.out.extend_from_slice(&method.to_le_bytes());
        self.out.extend_from_slice(&DOS_TIME.to_le_bytes());
        self.out.extend_from_slice(&DOS_DATE.to_le_bytes());
        self.out.extend_from_slice(&crc32.to_le_bytes());
        self.out.extend_from_slice(&compressed_len.to_le_bytes());
        self.out.extend_from_slice(&uncompressed.to_le_bytes());
        self.out.extend_from_slice(&name_len.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes()); // extra field length
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(&compressed);

        // Central directory record for the same member.
        let external = (mode << 16) | (u32::from(name.ends_with('/')) * 0x10);
        self.central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        self.central.extend_from_slice(&0x031e_u16.to_le_bytes()); // made by: unix, 3.0
        self.central.extend_from_slice(&20_u16.to_le_bytes());
        self.central.extend_from_slice(&0_u16.to_le_bytes());
        self.central.extend_from_slice(&method.to_le_bytes());
        self.central.extend_from_slice(&DOS_TIME.to_le_bytes());
        self.central.extend_from_slice(&DOS_DATE.to_le_bytes());
        self.central.extend_from_slice(&crc32.to_le_bytes());
        self.central.extend_from_slice(&compressed_len.to_le_bytes());
        self.central.extend_from_slice(&uncompressed.to_le_bytes());
        self.central.extend_from_slice(&name_len.to_le_bytes());
        self.central.extend_from_slice(&0_u16.to_le_bytes()); // extra
        self.central.extend_from_slice(&0_u16.to_le_bytes()); // comment
        self.central.extend_from_slice(&0_u16.to_le_bytes()); // disk number
        self.central.extend_from_slice(&0_u16.to_le_bytes()); // internal attrs
        self.central.extend_from_slice(&external.to_le_bytes());
        self.central.extend_from_slice(&offset.to_le_bytes());
        self.central.extend_from_slice(name.as_bytes());

        self.count = self
            .count
            .checked_add(1)
            .ok_or("more than 65535 files, which needs zip64")?;
        Ok(())
    }

    /// The central directory and the end record.
    fn finish(mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let offset = u32::try_from(self.out.len()).map_err(|_| "the archive passed 4 GiB")?;
        let size = u32::try_from(self.central.len()).map_err(|_| "the central directory passed 4 GiB")?;
        self.out.extend_from_slice(&self.central);
        self.out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes()); // this disk
        self.out.extend_from_slice(&0_u16.to_le_bytes()); // disk with central dir
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&size.to_le_bytes());
        self.out.extend_from_slice(&offset.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes()); // comment length
        Ok(self.out)
    }
}

/// Write a `.zip` of `entries`.
fn write_zip(path: &Path, entries: &[Entry]) -> Fallible {
    let mut zip = Zip::new();
    for dir in directories(entries) {
        zip.add(&format!("{dir}/"), &[], 0o755)?;
    }
    for entry in entries {
        let bytes = fs::read(&entry.source).map_err(|e| format!("{}: {e}", entry.source.display()))?;
        zip.add(&entry.name, &bytes, if entry.executable { 0o755 } else { 0o644 })?;
    }
    fs::write(path, zip.finish()?).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

/// `cargo xtask package`.
pub(crate) fn main(args: &[String]) -> Fallible {
    let mut target_arg: Option<String> = None;
    let mut out_arg: Option<String> = None;
    let mut check: Option<String> = None;
    let mut print_version = false;
    let mut print_jni_symbols = false;
    let mut build = true;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = |flag: &str| -> Result<String, String> {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match arg.as_str() {
            "--target" => target_arg = Some(value("--target")?),
            "--out" => out_arg = Some(value("--out")?),
            "--check-tag" => check = Some(value("--check-tag")?),
            "--print-version" => print_version = true,
            "--print-jni-symbols" => print_jni_symbols = true,
            "--no-build" => build = false,
            other => return Err(format!("unknown flag {other:?}\n{USAGE}").into()),
        }
    }

    let root = workspace_root()?;
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let version = manifest_facts(&manifest)?;

    // The version alone, nothing else on stdout, so a shell can read it. One reader for
    // `docs/release.md`'s "check the version line" step and for the release job's dry
    // run, rather than a `sed` over the manifest that answers differently when the file
    // moves a key.
    if print_version {
        println!("{version}");
        return Ok(());
    }

    // The symbol list a shell can compare an actual `.so` against, one per line and sorted.
    // CI reads this rather than counting matches: a count of ten is still ten after an
    // export is renamed and another added, and a renamed export is an `UnsatisfiedLinkError`
    // on the app's first flash. One list, here, for CI and for the packaging step alike.
    if print_jni_symbols {
        let mut names: Vec<&str> = required_jni_symbols().collect();
        names.sort_unstable();
        for name in names {
            println!("{name}");
        }
        return Ok(());
    }

    if let Some(tag) = check {
        check_tag(&tag, &version)?;
        println!("tag     {tag} matches workspace.package.version {version}");
        // The line release.yml greps to decide `--prerelease`: the gate is this tested
        // logic now, not a shell glob nothing observes.
        println!("{}", prerelease_line(&tag));
        return Ok(());
    }

    let Some(target_arg) = target_arg else {
        return Err(format!("--target is required\n{USAGE}").into());
    };
    let target = find_target(&target_arg)?;
    let out = root.join(out_arg.as_deref().unwrap_or(DEFAULT_OUT));

    package(&root, &out, target, &version, build)
}

/// Build what is needed, assemble the directory, write the archive and the checksum.
fn package(root: &Path, out: &Path, target: Target, version: &str, build: bool) -> Fallible {
    let hash = build_hash(root);
    println!(
        "package {} {version} ({})",
        target.name,
        hash.as_deref().unwrap_or("unknown")
    );

    // The web target is never built here: `cargo xtask web --release` owns that, it needs
    // npm and a matching `wasm-bindgen` CLI, and `stage_web` says exactly that when
    // `web/dist` is not there. So `--target web` archives, and only archives.
    if build && target.build != Build::Web {
        build_for(root, target, hash.as_deref())?;
    }

    let stage = out.join(target.dir_name());
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir_all(&stage)?;

    match target.build {
        Build::Web => stage_web(root, &stage)?,
        Build::Android => stage_android(root, &stage)?,
        _ => stage_native(root, &stage, target)?,
    }

    // Neither the web flasher nor the Android drop-in ships a runnable binary to quote a
    // `--help` line from.
    let help = match target.os {
        Platform::Web | Platform::Android => None,
        _ => Some(help_lines(root, &stage, target)),
    };
    // The staging above fetched the tree (or found one), so the stamp beside it says which
    // U-Boot commit these loaders are; an archive must not claim loaders it cannot name.
    let loader_commit = crate::loader_source(root).ok_or_else(|| {
        format!(
            "the loader tree carries no {} stamp; run `cargo xtask fetch-loaders`",
            crate::SOURCE_FILE
        )
    })?;
    let facts = Readme {
        version: version.to_owned(),
        hash: hash.unwrap_or_else(|| "unknown".to_owned()),
        target,
        loader_commit,
        help,
    };
    // The Android tarball's readme is `README` (no `.md`) and has its own shape; the five
    // `thingino-dfu-*` archives share `README.md` and `render_readme`.
    let (readme_name, readme) = if target.os == Platform::Android {
        ("README", render_android_readme(&facts))
    } else {
        ("README.md", render_readme(&facts))
    };
    fs::write(stage.join(readme_name), readme)?;

    let mut entries = Vec::new();
    collect(&stage, &target.archive_prefix(), &mut entries)?;
    if entries.is_empty() {
        return Err(format!("{} is empty; nothing to archive", stage.display()).into());
    }

    let archive = out.join(target.archive_name(version));
    match target.format {
        Format::TarGz => write_tar_gz(&archive, &entries)?,
        Format::Zip => write_zip(&archive, &entries)?,
    }
    let bytes = fs::read(&archive)?;
    let digest = hex(&Sha256::digest(&bytes));
    println!(
        "archive {} ({} files, {} bytes)",
        archive.display(),
        entries.len(),
        bytes.len()
    );

    let sums = out.join("SHA256SUMS");
    let existing = fs::read_to_string(&sums).unwrap_or_default();
    fs::write(&sums, merge_sums(&existing, &target.archive_name(version), &digest))?;
    println!("sha256  {digest}  {}", target.archive_name(version));
    Ok(())
}

/// `cargo build --release` for this target, with the banner's hash in scope.
fn build_for(root: &Path, target: Target, hash: Option<&str>) -> Fallible {
    let triples: &[&str] = match target.build {
        Build::Triple(triple) => &[triple][..],
        Build::Universal => &APPLE_TRIPLES[..],
        // `tdfu-jni` builds two triples, each with the NDK's clang as linker and its own
        // package set, so it has a path of its own rather than a triple list here.
        Build::Android => return build_android(root, hash),
        // Unreachable: `package` does not call this for the web target. Kept as a
        // refusal rather than a silent no-op so a future caller that does gets told why.
        Build::Web => {
            return Err("`--target web` archives web/dist; build it with \
                 `cargo xtask fetch-loaders && cargo xtask web --release` first"
                .into());
        }
    };
    let triples: Vec<&str> = triples.to_vec();
    for triple in &triples {
        println!("build   {triple} (release)");
        let mut cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
        cargo.current_dir(root).args([
            "build",
            "--locked",
            "--release",
            "--target",
            triple,
            "-p",
            "tdfu-cli",
            "-p",
            "tdfu-daemon",
        ]);
        if let Some(hash) = hash {
            cargo.env("TDFU_GIT_HASH", hash);
        }
        let status = cargo.status().map_err(|e| format!("cargo build: {e}"))?;
        if !status.success() {
            return Err(format!("cargo build --target {triple} failed: {status}").into());
        }
    }
    if target.build == Build::Universal {
        lipo(root)?;
    }
    Ok(())
}

/// Join the two apple builds into `target/macos-universal/release/`.
///
/// The same two commands CI's `build-macos` job runs, in the place the rest of the
/// packaging looks for binaries, so `cargo xtask package --target macos-universal` is the
/// whole job body rather than a step that has to agree with three others.
fn lipo(root: &Path) -> Fallible {
    let dest = root.join("target").join("macos-universal").join("release");
    fs::create_dir_all(&dest)?;
    for bin in BINARIES {
        let output = dest.join(bin);
        let mut command = Command::new("lipo");
        command.arg("-create").arg("-output").arg(&output);
        for triple in APPLE_TRIPLES {
            command.arg(root.join("target").join(triple).join("release").join(bin));
        }
        let status = command.status().map_err(|e| {
            format!("lipo: {e} - `--target macos-universal` needs a macOS host, or --no-build with the binaries already in {}", dest.display())
        })?;
        if !status.success() {
            return Err(format!("lipo {bin} failed: {status}").into());
        }
    }
    Ok(())
}

/// The two binaries plus the loader tree.
fn stage_native(root: &Path, stage: &Path, target: Target) -> Fallible {
    let release = match target.build {
        Build::Triple(triple) => root.join("target").join(triple).join("release"),
        _ => root.join("target").join("macos-universal").join("release"),
    };
    for bin in BINARIES {
        let name = format!("{bin}{}", target.exe_suffix());
        require_copy(&release.join(&name), &stage.join(&name), &name)?;
    }
    let loaders = ensure_loaders(root)?;
    copy_tree(&loaders, &stage.join("firmware").join("dfu"))?;
    println!("loaders {}", loaders.display());
    Ok(())
}

/// `web/dist`, which already carries its own loader tree.
fn stage_web(root: &Path, stage: &Path) -> Fallible {
    let dist = root.join("web").join("dist");
    if !dist.join("index.html").is_file() {
        return Err(format!(
            "{} is not a built flasher\n  \
             Build it first:  cargo xtask fetch-loaders && cargo xtask web --release",
            dist.display()
        )
        .into());
    }
    copy_tree(&dist, stage)?;
    // The web archive is also where `cargo xtask fetch-loaders` reads a pinned release's
    // loaders from, and the page 404s on every bootstrap without them. A silently
    // loader-less web tarball is the one failure this archive must not ship.
    let loaders = stage.join("firmware").join("dfu");
    if !loaders.is_dir() {
        return Err(format!(
            "{} has no firmware/dfu/ - `cargo xtask web` links it only when a tree has been \
             fetched, so run `cargo xtask fetch-loaders` and build the page again",
            dist.display()
        )
        .into());
    }
    Ok(())
}

/// The fetched loader tree, fetching it first if this checkout has none (decision D2).
fn ensure_loaders(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let loaders = root.join("target").join("firmware").join("dfu");
    if !loaders.is_dir() {
        println!("loaders none under target/firmware; fetching the current tree");
        crate::fetch_loaders(&[])?;
    }
    if !loaders.is_dir() {
        return Err(format!("{} is still missing after a fetch", loaders.display()).into());
    }
    Ok(loaders)
}

// ---------------------------------------------------------------------------
// Android
// ---------------------------------------------------------------------------

/// Build `tdfu-jni` as a `cdylib` for both Android ABIs.
///
/// Each ABI gets the NDK's clang as its linker (`CARGO_TARGET_<triple>_LINKER`, the path
/// derived from the NDK the same way ci.yml's android leg derives it) and the 16 KiB
/// page-size link option (`-Clink-arg=-Wl,-z,max-page-size=16384`, what the C's `CMake` sets
/// as `LINKER:-z,max-page-size=16384`; Android 15+ / API 35 devices need it). The link arg
/// rides `--config target.<triple>.rustflags`, which combines with the workspace's
/// `.cargo/config.toml` rather than replacing it the way a `RUSTFLAGS` env would.
fn build_android(root: &Path, hash: Option<&str>) -> Fallible {
    let ndk_bin = ndk_bin_dir()?;
    for (triple, _abi, linker_name) in ANDROID_ABIS {
        let linker = ndk_bin.join(linker_name);
        if !linker.is_file() {
            return Err(format!(
                "NDK linker not found: {}\n  \
                 Set ANDROID_NDK_HOME (or ANDROID_NDK_LATEST_HOME) to an NDK r25+ install.",
                linker.display()
            )
            .into());
        }
        println!("build   {triple} (release, -p tdfu-jni, ndk linker {linker_name})");
        let mut cargo = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
        cargo.current_dir(root).args([
            "build",
            "--locked",
            "--release",
            "--target",
            triple,
            "-p",
            "tdfu-jni",
            "--config",
            &android_rustflags_config(triple),
        ]);
        cargo.env(cargo_linker_env(triple), &linker);
        if let Some(hash) = hash {
            cargo.env("TDFU_GIT_HASH", hash);
        }
        let status = cargo.status().map_err(|e| format!("cargo build: {e}"))?;
        if !status.success() {
            return Err(format!("cargo build --target {triple} -p tdfu-jni failed: {status}").into());
        }
    }
    Ok(())
}

/// `CARGO_TARGET_<TRIPLE>_LINKER`, the cargo env var naming a target's linker: the triple
/// upcased with `-` turned to `_`. Pinned, because a wrong spelling is silently ignored
/// (cargo falls back to the default linker) and the link then fails deep in the build.
fn cargo_linker_env(triple: &str) -> String {
    format!("CARGO_TARGET_{}_LINKER", triple.to_uppercase().replace('-', "_"))
}

/// The `--config` value that adds the 16 KiB page-size link option for one triple. Config
/// `target.<triple>.rustflags` combines with the workspace's `target.'cfg(all())'.rustflags`
/// (a `RUSTFLAGS` env would replace it), so this adds the link arg without losing the rest.
fn android_rustflags_config(triple: &str) -> String {
    format!("target.{triple}.rustflags=[\"-Clink-arg=-Wl,-z,max-page-size=16384\"]")
}

/// The NDK's `toolchains/llvm/prebuilt/<host>/bin`, holding both clang linkers and the
/// `llvm-strip`/`llvm-nm`/`llvm-readelf` the staging step uses.
///
/// The NDK root comes from `ANDROID_NDK_LATEST_HOME`, then `ANDROID_NDK_HOME`, then
/// `ANDROID_NDK`: the first is set on GitHub's runners, the second is the local `--target
/// android` proof, the third is the C script's own convention. The host directory under
/// `prebuilt/` (`linux-x86_64`, `darwin-x86_64`, ...) is globbed rather than assumed,
/// because it differs between a laptop and a runner.
fn ndk_bin_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = ["ANDROID_NDK_LATEST_HOME", "ANDROID_NDK_HOME", "ANDROID_NDK"]
        .iter()
        .copied()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.trim().is_empty()))
        .ok_or(
            "set ANDROID_NDK_HOME (or ANDROID_NDK_LATEST_HOME) to an NDK r25+ install to build the Android target",
        )?;
    let prebuilt = Path::new(&root).join("toolchains").join("llvm").join("prebuilt");
    let mut hosts: Vec<PathBuf> = fs::read_dir(&prebuilt)
        .map_err(|e| format!("{}: {e} - is this an NDK?", prebuilt.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("bin").is_dir())
        .collect();
    hosts.sort();
    let host = hosts
        .into_iter()
        .next()
        .ok_or_else(|| format!("no toolchains/llvm/prebuilt/*/bin under {}", prebuilt.display()))?;
    Ok(host.join("bin"))
}

/// Stage a stripped, checked `libtdfu_jni.so` per ABI under `jniLibs/<abi>/`, plus the
/// loader tree under `firmware/dfu/`.
///
/// Each `.so` is stripped with the NDK's `llvm-strip --strip-unneeded` (as the C does), then
/// two assertions run against the stripped file: exactly the ten JNI exports under the
/// `Java_com_thingino_dfu_TdfuBridge_` prefix and no others (a renamed Kotlin package or a
/// dropped export is caught here, not on a user's phone), and no `NEEDED` shared library
/// outside the Android system set (a stray one means libusb or the core failed to link
/// statically). The loaders are the same fetched `firmware/dfu/` every other target stages:
/// the full tree, one directory per variant, not a remapped subset.
fn stage_android(root: &Path, stage: &Path) -> Fallible {
    let ndk_bin = ndk_bin_dir()?;
    let strip = ndk_bin.join("llvm-strip");
    let nm = ndk_bin.join("llvm-nm");
    let readelf = ndk_bin.join("llvm-readelf");

    for (triple, abi, _linker) in ANDROID_ABIS {
        let built = root.join("target").join(triple).join("release").join("libtdfu_jni.so");
        let dest = stage.join("jniLibs").join(abi).join("libtdfu_jni.so");
        require_copy(&built, &dest, &format!("libtdfu_jni.so ({abi})"))?;

        let stripped = Command::new(&strip)
            .arg("--strip-unneeded")
            .arg(&dest)
            .status()
            .map_err(|e| format!("{}: {e}", strip.display()))?;
        if !stripped.success() {
            return Err(format!("llvm-strip {} failed: {stripped}", dest.display()).into());
        }

        let symbols = dynamic_symbols(&nm, &dest)?;
        check_jni_exports(&symbols).map_err(|e| format!("{}: {e}", dest.display()))?;

        let needed = shared_needed(&readelf, &dest)?;
        let stray = stray_needed(&needed);
        if !stray.is_empty() {
            return Err(format!(
                "{}: NEEDED shared library outside the Android system set: {stray:?}\n  \
                 A stray dependency means something did not link statically and would fail as a \
                 dlopen error on device, not here.",
                dest.display()
            )
            .into());
        }
        println!("jni     {abi}: {} exports, needed {needed:?}", JNI_EXPORTS.len());
    }

    let loaders = ensure_loaders(root)?;
    copy_tree(&loaders, &stage.join("firmware").join("dfu"))?;
    println!("loaders {}", loaders.display());
    Ok(())
}

/// The defined dynamic symbol names of `so`, via the NDK's `llvm-nm -D --defined-only`.
fn dynamic_symbols(nm: &Path, so: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new(nm)
        .arg("-D")
        .arg("--defined-only")
        .arg(so)
        .output()
        .map_err(|e| format!("{}: {e}", nm.display()))?;
    if !output.status.success() {
        return Err(format!(
            "llvm-nm -D {} failed: {}",
            so.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(|line| line.split_whitespace().last().map(str::to_owned))
        .collect())
}

/// The `NEEDED` shared libraries of `so`, via the NDK's `llvm-readelf -d`.
fn shared_needed(readelf: &Path, so: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new(readelf)
        .arg("-d")
        .arg(so)
        .output()
        .map_err(|e| format!("{}: {e}", readelf.display()))?;
    if !output.status.success() {
        return Err(format!(
            "llvm-readelf -d {} failed: {}",
            so.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().filter_map(parse_needed).collect())
}

/// `... Shared library: [libc.so]` -> `libc.so`. The exact line `llvm-readelf -d` prints for
/// a `NEEDED` entry, the same field the C's `sed` pulls out.
fn parse_needed(line: &str) -> Option<String> {
    let marker = "Shared library: [";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find(']')?;
    Some(rest[..end].to_owned())
}

/// Exactly the ten [`JNI_EXPORTS`] under the `Java_com_thingino_dfu_TdfuBridge_` prefix, no
/// more and none missing, plus [`JNI_ON_LOAD`]. `symbols` is the whole defined dynamic
/// symbol list; anything that is neither of those (the odd runtime symbol) is ignored, the
/// way the C's `grep 'Java_...TdfuBridge_'` is. Pure, so the fixture cases are pinned on the
/// host, where no `.so` can be built.
///
/// `JNI_OnLoad` is required rather than ignored because it is what caches the `JavaVM`, and
/// the callback plumbing reaches the VM only through that cache: a `.so` without it links,
/// packages and ships, every export still answers `0` or `-1`, and the app's log pane and
/// progress bar stay empty for a whole flash with nothing to say why.
fn check_jni_exports(symbols: &[String]) -> Result<(), String> {
    let found: BTreeSet<&str> = symbols
        .iter()
        .map(String::as_str)
        .filter(|name| name.starts_with(JNI_PREFIX) || *name == JNI_ON_LOAD)
        .collect();
    let expected: BTreeSet<&str> = required_jni_symbols().collect();
    if found == expected {
        return Ok(());
    }
    let missing: Vec<&str> = expected.difference(&found).copied().collect();
    let unexpected: Vec<&str> = found.difference(&expected).copied().collect();
    Err(format!(
        "JNI exports are not the expected {}: missing {missing:?}, unexpected {unexpected:?}. \
         Renaming the Kotlin package or dropping an export breaks statically registered JNI.",
        expected.len()
    ))
}

/// Every symbol a `libtdfu_jni.so` must export: the ten the app resolves by name and the
/// entry point that caches the `JavaVM` for them.
fn required_jni_symbols() -> impl Iterator<Item = &'static str> {
    JNI_EXPORTS.iter().copied().chain(std::iter::once(JNI_ON_LOAD))
}

/// The `NEEDED` libraries that are not Android system libraries. Empty is the pass.
fn stray_needed(needed: &[String]) -> Vec<String> {
    needed
        .iter()
        .filter(|lib| !ANDROID_SYSTEM_LIBS.contains(&lib.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Build, Entry, Format, HelpLines, Platform, Readme, Target, Zip, android_rustflags_config, cargo_linker_env,
        check_jni_exports, check_tag, collect, directories, find_target, first_help_line, hash_label, install_text,
        is_prerelease, manifest_facts, merge_sums, parse_needed, prerelease_line, render_android_readme, render_readme,
        stray_needed, write_tar_gz, write_zip,
    };
    use std::path::{Path, PathBuf};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    /// The six published names. A user's download link, the lab's unpack path and the
    /// Android app's pin are these strings; changing one is a cutover break, not a rename.
    /// The Android name carries the version (what the app pins); the others do not.
    #[test]
    fn the_six_archive_names_are_the_c_tool_s() {
        let names: Vec<String> = super::TARGETS.iter().map(|t| t.archive_name("2.0.0-alpha.1")).collect();
        assert_eq!(
            names,
            [
                "thingino-dfu-linux-x86_64.tar.gz",
                "thingino-dfu-linux-aarch64.tar.gz",
                "thingino-dfu-windows-x64.zip",
                "thingino-dfu-macos-universal.tar.gz",
                "thingino-dfu-web.tar.gz",
                "libtdfu-android-2.0.0-alpha.1.tar.gz",
            ]
        );
    }

    /// Windows is the one zip, and it is the one archive whose binaries carry `.exe`.
    /// Reverting either half breaks a Windows user and nothing else, so both are pinned.
    #[test]
    fn only_windows_is_a_zip_and_only_windows_has_exe() -> TestResult {
        for target in super::TARGETS {
            let windows = target.os == Platform::Windows;
            assert_eq!(target.format == Format::Zip, windows, "{}", target.name);
            assert_eq!(target.exe_suffix() == ".exe", windows, "{}", target.name);
        }
        let windows = find_target("windows-x64")?;
        assert_eq!(windows.archive_name("2.0.0"), "thingino-dfu-windows-x64.zip");
        assert_eq!(windows.dir_name(), "thingino-dfu-windows-x64");
        Ok(())
    }

    /// Both spellings reach the same target, so the workflow matrix can carry triples
    /// and a person can type the download name.
    #[test]
    fn a_target_is_found_by_name_or_by_triple() -> TestResult {
        assert_eq!(find_target("linux-aarch64")?, find_target("aarch64-unknown-linux-gnu")?);
        assert_eq!(find_target("x86_64-pc-windows-gnu")?.name, "windows-x64");
        assert_eq!(find_target("web")?.build, Build::Web);
        assert_eq!(find_target("macos-universal")?.build, Build::Universal);
        // Android resolves by name only: it maps to two triples, so no single triple names it.
        assert_eq!(find_target("android")?.build, Build::Android);
        Ok(())
    }

    /// An unknown target is refused, not defaulted. This is the revert check for the
    /// habit the rewrite exists to break: the C's `--cpu` fell back to `t31x` silently.
    #[test]
    fn an_unknown_target_is_refused_with_the_list() -> TestResult {
        let Err(message) = find_target("linux-arm64") else {
            return Err("a target that does not exist must not resolve".into());
        };
        assert!(message.contains("linux-arm64"), "{message}");
        assert!(message.contains("linux-aarch64"), "{message}");
        assert!(message.contains("aarch64-unknown-linux-gnu"), "{message}");
        Ok(())
    }

    /// The tag check, and the two ways it must fail.
    #[test]
    fn a_tag_must_be_v_plus_the_workspace_version() -> TestResult {
        check_tag("v2.0.0-alpha.1", "2.0.0-alpha.1")?;
        check_tag("refs/tags/v2.0.0-alpha.1", "2.0.0-alpha.1")?;
        check_tag("  v2.0.0-alpha.1  ", "2.0.0-alpha.1")?;

        let Err(no_v) = check_tag("2.0.0-alpha.1", "2.0.0-alpha.1") else {
            return Err("a tag without the `v` must not pass".into());
        };
        assert!(no_v.contains("does not start with `v`"), "{no_v}");
        Ok(())
    }

    /// A mismatch prints both values, because which one is wrong is the open question.
    /// Revert check: a `starts_with` comparison would let `v2.0.0` release a
    /// `2.0.0-alpha.1` tree, which is the mistake worth catching.
    #[test]
    fn a_mismatched_tag_names_both_values() -> TestResult {
        let Err(message) = check_tag("v2.0.0", "2.0.0-alpha.1") else {
            return Err("v2.0.0 must not release a 2.0.0-alpha.1 tree".into());
        };
        assert!(message.contains("v2.0.0"), "{message}");
        assert!(message.contains("2.0.0-alpha.1"), "{message}");

        let Err(other_way) = check_tag("v2.0.0-alpha.11", "2.0.0-alpha.1") else {
            return Err("a longer version must not match a shorter one".into());
        };
        assert!(other_way.contains("alpha.11"), "{other_way}");
        Ok(())
    }

    /// Semver's rule, so `-rc.1` needs no edit here.
    #[test]
    fn a_hyphen_makes_it_a_prerelease() {
        assert!(is_prerelease("v2.0.0-alpha.1"));
        assert!(is_prerelease("v2.0.0-rc.1"));
        assert!(is_prerelease("refs/tags/v2.0.0-beta"));
        assert!(!is_prerelease("v2.0.0"));
        assert!(!is_prerelease("v2.1.3"));
    }

    /// The exact stdout line release.yml greps to gate `--prerelease`. That grep is the
    /// gate now, so the three cases the workflow relies on are pinned here
    /// rather than in a shell glob nothing exercises. Revert check: drop the `-` test in
    /// `is_prerelease` and the alpha and rc lines flip to `prerelease=false`.
    #[test]
    fn the_prerelease_line_is_the_release_gate() {
        assert_eq!(prerelease_line("v2.0.0-alpha.1"), "prerelease=true");
        assert_eq!(prerelease_line("v2.0.0-rc.1"), "prerelease=true");
        assert_eq!(prerelease_line("v2.0.0"), "prerelease=false");
        assert_eq!(prerelease_line("refs/tags/v2.0.0"), "prerelease=false");
    }

    /// The version the archives claim comes from one place.
    #[test]
    fn the_version_comes_from_the_workspace_manifest() -> TestResult {
        let version = manifest_facts(
            "[workspace.package]\nversion = \"2.0.0-alpha.1\"\nrepository = \"https://example.invalid/x\"\n",
        )?;
        assert_eq!(version, "2.0.0-alpha.1");
        Ok(())
    }

    /// And it is read out of the real manifest, so a moved key fails here rather than
    /// in a release job.
    #[test]
    fn the_real_manifest_still_parses() -> TestResult {
        let text = std::fs::read_to_string(root().join("Cargo.toml"))?;
        let version = manifest_facts(&text)?;
        assert!(version.starts_with("2."), "{version}");
        Ok(())
    }

    /// A manifest with no workspace version says so instead of packaging something
    /// unnamed.
    #[test]
    fn a_manifest_without_a_version_is_refused() -> TestResult {
        let Err(message) = manifest_facts("[workspace]\nmembers = []\n") else {
            return Err("a manifest with no workspace.package must not resolve a version".into());
        };
        assert!(message.contains("Cargo.toml"), "{message}");
        Ok(())
    }

    /// The hash the banner prints must not claim to be a commit it is not.
    #[test]
    fn a_dirty_tree_says_so() {
        assert_eq!(hash_label("a1b2c3d\n", false), "a1b2c3d");
        assert_eq!(hash_label("a1b2c3d", true), "a1b2c3d-dirty");
    }

    #[test]
    fn the_cli_help_line_is_read_out_of_the_source() {
        let source = r#"
#[command(
    name = "thingino-dfu",
    about = "short",
    long_about = "Flash Ingenic XBurst cameras over USB.\n\n\
                  Operations run in a fixed order."
)]
"#;
        assert_eq!(
            first_help_line(source, super::CLI_HELP_ANCHOR).as_deref(),
            Some("Flash Ingenic XBurst cameras over USB.")
        );
    }

    #[test]
    fn the_daemon_help_line_is_read_out_of_the_source() {
        let source = "\
fn usage() -> String {
    format!(
        \"dfu-remote - thingino-dfu remote daemon\\n\\
         Usage: dfu-remote [options]\\n\",
    )
}
";
        assert_eq!(
            first_help_line(source, super::DAEMON_HELP_ANCHOR).as_deref(),
            Some("dfu-remote - thingino-dfu remote daemon")
        );
    }

    /// The revert check for both anchors: they are read out of the files that are
    /// actually in this tree, so moving either string breaks this test rather than
    /// quietly putting the wrong line in a published README.
    #[test]
    fn both_anchors_still_find_a_line_in_the_real_source() -> TestResult {
        let cli = std::fs::read_to_string(root().join("crates/tdfu-cli/src/cli.rs"))?;
        let found = first_help_line(&cli, super::CLI_HELP_ANCHOR);
        assert_eq!(found.as_deref(), Some("Flash Ingenic XBurst cameras over USB."));

        let daemon = std::fs::read_to_string(root().join("crates/tdfu-daemon/src/transport/options.rs"))?;
        let found = first_help_line(&daemon, super::DAEMON_HELP_ANCHOR);
        assert_eq!(found.as_deref(), Some("dfu-remote - thingino-dfu remote daemon"));
        Ok(())
    }

    /// An anchor that is not there yields nothing rather than the next literal in the
    /// file, which would be a plausible-looking wrong answer.
    #[test]
    fn a_missing_anchor_finds_nothing() {
        assert_eq!(first_help_line("let x = \"hello\";", "long_about ="), None);
    }

    /// The commit the README quotes in the test facts below.
    const LOADER_COMMIT: &str = "e9edb408b048882191ad542221cecd3bb4811e20";

    fn facts(target: Target) -> Readme {
        Readme {
            version: "2.0.0-alpha.1".to_owned(),
            hash: "a1b2c3d".to_owned(),
            target,
            loader_commit: LOADER_COMMIT.to_owned(),
            help: Some(HelpLines {
                cli: "Flash Ingenic XBurst cameras over USB.".to_owned(),
                daemon: "dfu-remote - thingino-dfu remote daemon".to_owned(),
            }),
        }
    }

    /// Everything the archive README has to carry, in one place.
    #[test]
    fn the_readme_carries_the_version_the_pin_and_both_help_lines() -> TestResult {
        let linux = find_target("linux-x86_64")?;
        let text = render_readme(&facts(linux));
        assert!(
            text.starts_with("# thingino-dfu 2.0.0-alpha.1 - linux-x86_64"),
            "{text}"
        );
        assert!(text.contains("a1b2c3d"), "the build hash");
        assert!(text.contains(LOADER_COMMIT), "the loader commit");
        assert!(text.contains(&super::loader_release_url()), "the loader release");
        assert!(text.contains("Flash Ingenic XBurst cameras over USB."), "the cli help");
        assert!(
            text.contains("dfu-remote - thingino-dfu remote daemon"),
            "the daemon help"
        );
        assert!(text.contains("99-thingino-dfu.rules"), "the udev rule");
        assert!(text.contains("a108"), "the vendor id the rule matches");
        assert!(text.contains(super::TOOL_REPOSITORY), "the tool's own repo");
        Ok(())
    }

    /// The archive's "Where this came from" names the tool's own repo; the loader source
    /// (the U-Boot release the loaders are fetched from) belongs only in the loaders
    /// section, so a downloader is never sent to the U-Boot repo for the tool. Revert
    /// check: render the loader release in the came-from line and the second assert fails.
    #[test]
    fn the_readme_separates_the_tool_repo_from_the_loader_source() -> TestResult {
        let text = render_readme(&facts(find_target("linux-x86_64")?));

        let (loaders, came_from) = text
            .split_once("## Where this came from")
            .ok_or("the README has a `Where this came from` section")?;

        // Where it came from is the tool's own repo, and not the loader source.
        assert!(
            came_from.contains(super::TOOL_REPOSITORY),
            "the tool's own repo: {came_from}"
        );
        assert!(
            !came_from.contains(crate::LOADER_REPO),
            "the came-from line must not point at the loader source: {came_from}"
        );
        // The loader source is named where the loaders are described.
        assert!(
            loaders.contains(&super::loader_release_url()),
            "the loader source is named in the loaders section: {loaders}"
        );
        assert!(loaders.contains(LOADER_COMMIT), "the loader commit: {loaders}");
        Ok(())
    }

    /// Each OS gets its own install step and nobody else's: a Linux archive telling a
    /// user to run Zadig is worse than no README at all.
    #[test]
    fn each_os_gets_its_own_install_step() -> TestResult {
        let windows = render_readme(&facts(find_target("windows-x64")?));
        assert!(windows.contains("Zadig"), "{windows}");
        assert!(windows.contains("A108:4D44"), "both drivers");
        assert!(!windows.contains("udevadm"), "no udev on Windows");
        assert!(windows.contains("thingino-dfu.exe"), "the exe suffix");

        let macos = render_readme(&facts(find_target("macos-universal")?));
        assert!(macos.contains("Nothing to install"), "{macos}");
        assert!(!macos.contains("Zadig"), "no Zadig on macOS");
        assert!(!macos.contains("udevadm"), "no udev on macOS");

        let linux = render_readme(&facts(find_target("linux-x86_64")?));
        assert!(linux.contains("udevadm control --reload-rules"), "{linux}");
        assert!(!linux.contains("Zadig"), "no Zadig on Linux");
        Ok(())
    }

    /// The web archive has no binaries, so it quotes no `--help` lines and says what it
    /// is instead.
    #[test]
    fn the_web_readme_is_about_serving_not_installing() -> TestResult {
        let mut web = facts(find_target("web")?);
        web.help = None;
        let text = render_readme(&web);
        assert!(text.contains("served rather than installed"), "{text}");
        assert!(text.contains("secure context"), "{text}");
        assert!(!text.contains("$ thingino-dfu --help"), "no binaries in this archive");
        // It still needs the Linux udev rule, because the browser opens the same device.
        assert!(text.contains("udev rule"), "{text}");
        Ok(())
    }

    /// All four install texts are distinct and none is empty.
    #[test]
    fn every_os_has_install_text_of_its_own() {
        let all = [
            install_text(Platform::Linux),
            install_text(Platform::Windows),
            install_text(Platform::MacOs),
            install_text(Platform::Web),
        ];
        for text in all {
            assert!(text.len() > 100, "{text}");
        }
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    /// Merging, not appending: three targets packaged in a row leave three lines, and
    /// re-running one replaces its line rather than adding a stale second one.
    #[test]
    fn sha256sums_merges_by_file_name() {
        let first = merge_sums("", "thingino-dfu-linux-x86_64.tar.gz", "aa");
        assert_eq!(first, "aa  thingino-dfu-linux-x86_64.tar.gz\n");

        let second = merge_sums(&first, "thingino-dfu-web.tar.gz", "bb");
        assert_eq!(
            second,
            "aa  thingino-dfu-linux-x86_64.tar.gz\nbb  thingino-dfu-web.tar.gz\n"
        );

        let rebuilt = merge_sums(&second, "thingino-dfu-linux-x86_64.tar.gz", "cc");
        assert_eq!(
            rebuilt,
            "cc  thingino-dfu-linux-x86_64.tar.gz\nbb  thingino-dfu-web.tar.gz\n"
        );
    }

    /// The `sha256sum -c` format is two spaces, and a line that is not that is dropped
    /// rather than corrupting the file.
    #[test]
    fn sha256sums_ignores_lines_that_are_not_checksums() {
        let merged = merge_sums("not a checksum line\n\n", "a.tar.gz", "aa");
        assert_eq!(merged, "aa  a.tar.gz\n");
    }

    #[test]
    fn directories_are_every_prefix_once_shallowest_first() {
        let entries = [
            Entry {
                source: PathBuf::from("/x"),
                name: "thingino-dfu-linux-x86_64/firmware/dfu/t31x/uboot.bin".to_owned(),
                executable: false,
            },
            Entry {
                source: PathBuf::from("/y"),
                name: "thingino-dfu-linux-x86_64/thingino-dfu".to_owned(),
                executable: true,
            },
        ];
        assert_eq!(
            directories(&entries),
            [
                "thingino-dfu-linux-x86_64",
                "thingino-dfu-linux-x86_64/firmware",
                "thingino-dfu-linux-x86_64/firmware/dfu",
                "thingino-dfu-linux-x86_64/firmware/dfu/t31x",
            ]
        );
    }

    /// The zip writer, checked against the format rather than against itself: the
    /// signatures, the counts and the offsets are what an unzip reads first.
    #[test]
    fn the_zip_writer_produces_a_readable_central_directory() -> TestResult {
        let mut zip = Zip::new();
        zip.add("d/", &[], 0o755)?;
        zip.add("d/f.txt", b"hello hello hello hello", 0o644)?;
        let bytes = zip.finish()?;

        assert_eq!(&bytes[0..4], &0x0403_4b50_u32.to_le_bytes(), "local file header");
        let end = bytes.len() - 22;
        assert_eq!(
            &bytes[end..end + 4],
            &0x0605_4b50_u32.to_le_bytes(),
            "end of central dir"
        );
        let count = u16::from_le_bytes([bytes[end + 10], bytes[end + 11]]);
        assert_eq!(count, 2, "two members");
        let size = u32::from_le_bytes([bytes[end + 12], bytes[end + 13], bytes[end + 14], bytes[end + 15]]);
        let offset = u32::from_le_bytes([bytes[end + 16], bytes[end + 17], bytes[end + 18], bytes[end + 19]]);
        assert_eq!(
            offset as usize + size as usize,
            end,
            "the central directory ends at the end record"
        );
        assert_eq!(
            &bytes[offset as usize..offset as usize + 4],
            &0x0201_4b50_u32.to_le_bytes(),
            "central directory header"
        );
        Ok(())
    }

    /// A directory member is stored, a file member is deflated, and the deflate is
    /// actually smaller - the revert check for a writer that silently stores everything.
    #[test]
    fn files_are_deflated_and_directories_are_stored() -> TestResult {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut zip = Zip::new();
        zip.add("f", data, 0o644)?;
        let bytes = zip.finish()?;
        let method = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(method, 8, "deflate");
        let compressed = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]);
        assert!(
            (compressed as usize) < data.len(),
            "{compressed} is not smaller than {}",
            data.len()
        );

        let mut dir = Zip::new();
        dir.add("d/", &[], 0o755)?;
        let bytes = dir.finish()?;
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 0, "stored");
        Ok(())
    }

    /// The zip validated by a code path independent of the one that wrote it:
    /// `flate2::read::DeflateDecoder` inflates the member (the write path uses
    /// `flate2::write::DeflateEncoder`), and a CRC computed here over the inflated bytes
    /// is compared to the field the writer stored. A wrong CRC final-xor, a CRC taken
    /// over the compressed bytes, or a zlib-wrapped stream in place of the raw deflate all
    /// pass the structural tests above and fail here - which is the difference between a
    /// well-formed zip and one a Windows user can open.
    #[test]
    fn a_zip_member_inflates_to_its_input_and_the_stored_crc_matches() -> TestResult {
        use std::io::Read as _;

        use flate2::read::DeflateDecoder;

        // Compressible and non-trivial, so the member is really deflated (method 8) and
        // the read path has a stream to inflate rather than a stored copy.
        let input: Vec<u8> = b"thingino ".iter().cycle().take(4096).copied().collect();
        let mut zip = Zip::new();
        zip.add("thingino-dfu-linux-x86_64/firmware/dfu/t31x/uboot.bin", &input, 0o644)?;
        let bytes = zip.finish()?;

        // The one local file header is at offset 0: no directory member is added first.
        assert_eq!(&bytes[0..4], &0x0403_4b50_u32.to_le_bytes(), "local file header");
        let method = u16::from_le_bytes([bytes[8], bytes[9]]);
        assert_eq!(method, 8, "the member must be deflated for this test to mean anything");
        let stored_crc = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
        let comp_len = u32::from_le_bytes([bytes[18], bytes[19], bytes[20], bytes[21]]) as usize;
        let uncomp_len = u32::from_le_bytes([bytes[22], bytes[23], bytes[24], bytes[25]]) as usize;
        let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
        let data_start = 30 + name_len + extra_len;
        let compressed = &bytes[data_start..data_start + comp_len];

        // Independent of the write path's `DeflateEncoder`: the raw inflate rejects a
        // zlib-wrapped stream, so a `ZlibEncoder` swap fails right here.
        let mut inflated = Vec::new();
        DeflateDecoder::new(compressed).read_to_end(&mut inflated)?;
        assert_eq!(inflated, input, "the deflate stream must round-trip to the input");
        assert_eq!(
            inflated.len(),
            uncomp_len,
            "the stored uncompressed size must be honest"
        );

        // A CRC computed here, over the inflated bytes, must equal the field the zip
        // stored: this is what a real unzip checks and rejects the file over.
        let mut crc = flate2::Crc::new();
        crc.update(&inflated);
        assert_eq!(
            crc.sum(),
            stored_crc,
            "the stored CRC must be crc32 of the data, not of the compressed bytes"
        );
        Ok(())
    }

    /// Write one file and stamp it with a real on-disk mtime the archive writers must
    /// ignore. Two staged trees get different mtimes, so a writer that honoured them
    /// would produce two different archives - which is what the G1 revert check flips on.
    fn write_fixture(path: &Path, bytes: &[u8], mtime: std::time::SystemTime) -> TestResult {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_modified(mtime)?;
        Ok(())
    }

    /// A small fixed tree: the two binaries (executable by name), a README, and two loader
    /// directories, enough to exercise directory synthesis, the sort in `collect` and the
    /// executable-bit rule.
    fn stage_a_fixed_tree(dir: &Path, mtime: std::time::SystemTime) -> TestResult {
        write_fixture(&dir.join("thingino-dfu"), b"#!/bin/false\nnot a real binary\n", mtime)?;
        write_fixture(&dir.join("dfu-remote"), b"#!/bin/false\nnor this one\n", mtime)?;
        write_fixture(&dir.join("README.md"), b"# fixed tree\n", mtime)?;
        write_fixture(&dir.join("firmware/dfu/t31x/uboot.bin"), &[0u8; 512], mtime)?;
        write_fixture(&dir.join("firmware/dfu/a1n/spl.bin"), &[0xab_u8; 256], mtime)?;
        Ok(())
    }

    /// Determinism, the property `docs/release.md`'s "never reuse a tag with different
    /// bytes" rests on and that nothing exercised. The same tree staged in two
    /// temp dirs, with deliberately different on-disk mtimes, must produce byte-identical
    /// archives for both the tar and the zip: the bytes are a pure function of the names,
    /// the contents and the modes, so a wall clock, a source path or a readdir order must
    /// not leak in. Revert check: honour the files' real mtime in `write_tar_gz` (or a
    /// live DOS time in the zip) and the two archives stop matching.
    #[test]
    fn packaging_the_same_tree_twice_is_byte_identical() -> TestResult {
        use std::time::{Duration, UNIX_EPOCH};

        let base = std::env::temp_dir().join(format!("tdfu-g1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a = base.join("a");
        let b = base.join("b");
        stage_a_fixed_tree(&a, UNIX_EPOCH + Duration::from_secs(1_000_000_000))?;
        stage_a_fixed_tree(&b, UNIX_EPOCH + Duration::from_secs(2_000_000_000))?;

        // The same archive-relative top directory for both, so only the source path on
        // disk differs between the two packagings.
        let prefix = "thingino-dfu-linux-x86_64";
        let mut entries_a = Vec::new();
        collect(&a, prefix, &mut entries_a)?;
        let mut entries_b = Vec::new();
        collect(&b, prefix, &mut entries_b)?;

        let tar_a = base.join("a.tar.gz");
        let tar_b = base.join("b.tar.gz");
        write_tar_gz(&tar_a, &entries_a)?;
        write_tar_gz(&tar_b, &entries_b)?;
        assert_eq!(
            std::fs::read(&tar_a)?,
            std::fs::read(&tar_b)?,
            "the tar.gz is not deterministic"
        );

        let zip_a = base.join("a.zip");
        let zip_b = base.join("b.zip");
        write_zip(&zip_a, &entries_a)?;
        write_zip(&zip_b, &entries_b)?;
        assert_eq!(
            std::fs::read(&zip_a)?,
            std::fs::read(&zip_b)?,
            "the zip is not deterministic"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    /// A `.gitkeep` under the staged tree never reaches an archive. The pinned loader tree
    /// carries `firmware/dfu/.gitkeep` (the C's web archive shipped it; its Android script
    /// deleted it before tarring), and `collect` is the one walk every archive's content
    /// goes through, so this holds for all six shapes. Revert check: drop the `.gitkeep`
    /// skip in `collect` and the placeholder is listed.
    #[test]
    fn a_gitkeep_placeholder_is_never_archived() -> TestResult {
        use std::time::{Duration, UNIX_EPOCH};

        let base = std::env::temp_dir().join(format!("tdfu-gitkeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mtime = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        stage_a_fixed_tree(&base, mtime)?;
        write_fixture(&base.join("firmware/dfu/.gitkeep"), b"", mtime)?;

        let mut entries = Vec::new();
        collect(&base, ".", &mut entries)?;
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert!(
            !names.iter().any(|name| name.ends_with("/.gitkeep")),
            "a .gitkeep was archived: {names:?}"
        );
        // The content around it is untouched: the five fixture files, nothing more.
        assert!(names.contains(&"./firmware/dfu/t31x/uboot.bin"), "{names:?}");
        assert_eq!(entries.len(), 5, "{names:?}");

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    // -- Android --------------------------------------------------------------

    /// The ABI/triple/linker mapping, host-runnable. The linker name is deliberately not the
    /// triple, and getting it wrong is a silent fallback to the default linker.
    #[test]
    fn the_android_abi_triple_linker_mapping_is_pinned() {
        assert_eq!(
            super::ANDROID_ABIS,
            [
                ("aarch64-linux-android", "arm64-v8a", "aarch64-linux-android21-clang"),
                (
                    "armv7-linux-androideabi",
                    "armeabi-v7a",
                    "armv7a-linux-androideabi21-clang"
                ),
            ]
        );
    }

    /// The cargo env var that names a triple's linker. A wrong spelling is ignored by cargo,
    /// so the link fails deep in the build with no hint that this string was the cause.
    #[test]
    fn the_cargo_linker_env_name_is_the_triple_upcased() {
        assert_eq!(
            cargo_linker_env("aarch64-linux-android"),
            "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
        );
        assert_eq!(
            cargo_linker_env("armv7-linux-androideabi"),
            "CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER"
        );
    }

    /// The 16 KiB page-size link option, scoped to the triple so it combines with the
    /// workspace `.cargo/config.toml` rustflags rather than replacing them.
    #[test]
    fn the_android_rustflags_config_carries_the_16k_page_size() {
        let config = android_rustflags_config("aarch64-linux-android");
        assert!(config.contains("target.aarch64-linux-android.rustflags"), "{config}");
        assert!(config.contains("-Clink-arg=-Wl,-z,max-page-size=16384"), "{config}");
    }

    /// The archive name the app pins carries the version; the on-disk stage and the archive
    /// prefix do not (the tarball has no top directory, so entries start `./`).
    #[test]
    fn the_android_archive_is_named_and_laid_out_for_the_app() -> TestResult {
        let android = find_target("android")?;
        assert_eq!(android.archive_name("1.5.43"), "libtdfu-android-1.5.43.tar.gz");
        assert_eq!(android.dir_name(), "libtdfu-android");
        assert_eq!(android.archive_prefix(), ".");
        Ok(())
    }

    /// The symbol check over a fixture list: the ten pass amid noise a real `.so` carries,
    /// a dropped export fails naming it, an extra `Java_...TdfuBridge_` export fails naming
    /// it. This is the logic; the real check runs at package time against the built `.so`,
    /// which the host cannot build.
    #[test]
    fn exactly_the_ten_jni_exports_pass_and_extras_or_missing_fail() -> TestResult {
        let ten: Vec<String> = super::JNI_EXPORTS.iter().map(|s| (*s).to_owned()).collect();
        let required: Vec<String> = super::required_jni_symbols().map(str::to_owned).collect();

        // The required set plus a symbol a stripped cdylib really carries.
        let mut with_noise = required.clone();
        with_noise.push("__cxa_finalize".to_owned());
        check_jni_exports(&with_noise)?;

        let missing: Vec<String> = required.iter().skip(1).cloned().collect();
        let Err(message) = check_jni_exports(&missing) else {
            return Err("a missing export must fail".into());
        };
        assert!(message.contains("nativeSetCallback"), "{message}");

        // Without `JNI_OnLoad` nothing caches the `JavaVM`, so every log and progress line
        // is dropped while the exports still answer 0 or -1. It is named, not counted.
        let Err(message) = check_jni_exports(&ten) else {
            return Err("a .so without JNI_OnLoad must fail".into());
        };
        assert!(message.contains("JNI_OnLoad"), "{message}");

        let mut extra = required.clone();
        extra.push("Java_com_thingino_dfu_TdfuBridge_nativeBogus".to_owned());
        let Err(message) = check_jni_exports(&extra) else {
            return Err("an unexpected export must fail".into());
        };
        assert!(message.contains("nativeBogus"), "{message}");
        Ok(())
    }

    /// What `--print-jni-symbols` hands CI is exactly what the packaging step asserts, so
    /// the shell comparison in the workflow cannot drift away from the check in this file.
    #[test]
    fn the_printed_symbol_list_is_the_set_the_package_check_requires() -> TestResult {
        let printed: Vec<String> = super::required_jni_symbols().map(str::to_owned).collect();
        assert_eq!(printed.len(), super::JNI_EXPORTS.len() + 1);
        assert!(printed.contains(&"JNI_OnLoad".to_owned()));
        check_jni_exports(&printed)?;
        Ok(())
    }

    /// The `NEEDED` line parser and the system-library allowlist. A stray dependency means
    /// something failed to link statically, which the C also refuses to ship.
    #[test]
    fn the_needed_check_allows_only_android_system_libraries() {
        assert_eq!(
            parse_needed("  0x0000000000000001 (NEEDED)       Shared library: [libc.so]"),
            Some("libc.so".to_owned())
        );
        assert_eq!(parse_needed("  0x...  (SONAME)  Library soname: [x]"), None);

        let system = ["liblog.so", "libandroid.so", "libm.so", "libdl.so", "libc.so"].map(str::to_owned);
        assert!(stray_needed(&system).is_empty());

        let with_stray = ["libc.so".to_owned(), "libusb-1.0.so.0".to_owned()];
        assert_eq!(stray_needed(&with_stray), ["libusb-1.0.so.0"]);
    }

    /// The Android README: the package parts, the `com.thingino.dfu.TdfuBridge` note, min
    /// API 26, the loader commit, and the tool/loader-source split `render_readme` also
    /// makes. The tool is THIS repo; the loader source is named only by the loaders.
    #[test]
    fn the_android_readme_names_the_package_the_loaders_and_this_repo() -> TestResult {
        let text = render_android_readme(&facts(find_target("android")?));

        assert!(text.contains("libtdfu for Android 2.0.0-alpha.1"), "{text}");
        assert!(text.contains("jniLibs/<abi>/libtdfu_jni.so"), "{text}");
        assert!(text.contains("arm64-v8a") && text.contains("armeabi-v7a"), "{text}");
        assert!(text.contains("firmware/dfu/"), "{text}");
        assert!(text.contains("com.thingino.dfu.TdfuBridge"), "{text}");
        assert!(text.contains("API level: 26"), "{text}");
        assert!(text.contains(LOADER_COMMIT), "the loader commit: {text}");

        let (loaders, came_from) = text
            .split_once("Where this came from")
            .ok_or("the README has a `Where this came from` section")?;
        assert!(
            came_from.contains(super::TOOL_REPOSITORY),
            "the tool's own repo: {came_from}"
        );
        assert!(
            !came_from.contains(crate::LOADER_REPO),
            "the came-from line must not point at the loader source: {came_from}"
        );
        assert!(
            loaders.contains(&super::loader_release_url()),
            "the loader source is named in the loaders section: {loaders}"
        );
        Ok(())
    }

    /// The Android layout, staged with fake `.so` bytes (no NDK), and the same determinism
    /// property as G1: the `.`-prefixed tarball is byte-identical across two on-disk mtimes.
    /// This is the part of the android package that can be pinned without building a real
    /// `.so`; the symbol and NEEDED checks need the NDK and run at package time.
    #[test]
    fn packaging_the_android_tree_twice_is_byte_identical() -> TestResult {
        use std::time::{Duration, UNIX_EPOCH};

        let stage_android_tree = |dir: &Path, mtime: std::time::SystemTime| -> TestResult {
            write_fixture(&dir.join("README"), b"libtdfu for Android x\n", mtime)?;
            write_fixture(
                &dir.join("jniLibs/arm64-v8a/libtdfu_jni.so"),
                &[0x7f, b'E', b'L', b'F'],
                mtime,
            )?;
            write_fixture(
                &dir.join("jniLibs/armeabi-v7a/libtdfu_jni.so"),
                &[0x7f, b'E', b'L', b'F'],
                mtime,
            )?;
            write_fixture(&dir.join("firmware/dfu/t31x/uboot.bin"), &[0u8; 512], mtime)?;
            write_fixture(&dir.join("firmware/dfu/.usbboot-source"), b"isvp_t31_usbboot\n", mtime)?;
            Ok(())
        };

        let base = std::env::temp_dir().join(format!("tdfu-g1-android-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let a = base.join("a");
        let b = base.join("b");
        stage_android_tree(&a, UNIX_EPOCH + Duration::from_secs(1_000_000_000))?;
        stage_android_tree(&b, UNIX_EPOCH + Duration::from_secs(2_000_000_000))?;

        // The Android archive prefix is `.`, so entries are `./README`, `./jniLibs/...`.
        let mut entries_a = Vec::new();
        collect(&a, ".", &mut entries_a)?;
        let mut entries_b = Vec::new();
        collect(&b, ".", &mut entries_b)?;
        assert!(
            entries_a.iter().any(|e| e.name == "./jniLibs/arm64-v8a/libtdfu_jni.so"),
            "the `.` prefix must land entries at the archive root: {entries_a:?}"
        );

        let tar_a = base.join("a.tar.gz");
        let tar_b = base.join("b.tar.gz");
        write_tar_gz(&tar_a, &entries_a)?;
        write_tar_gz(&tar_b, &entries_b)?;
        assert_eq!(
            std::fs::read(&tar_a)?,
            std::fs::read(&tar_b)?,
            "the android tar.gz is not deterministic"
        );

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}
