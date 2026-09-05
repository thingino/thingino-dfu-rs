//! Workspace automation. Run as `cargo xtask <command>`.
//!
//! `fetch-loaders` is decision D2: the loader blobs under `firmware/dfu/` are **not
//! vendored** and not pinned. They are the current assets of the `usbboot` release of
//! `gtxaspec/u-boot`, downloaded into `target/firmware/dfu/` with the U-Boot commit they
//! were built from written beside them, so that every archive built from this tree can say
//! which loaders it carries. Bootstrapping with a loader that is not the one a release
//! shipped looks exactly like a tool regression and is not, which is why that commit is
//! recorded rather than assumed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

mod package;
mod web;

/// The repository whose release publishes the USB-boot loaders.
pub(crate) const LOADER_REPO: &str = "gtxaspec/u-boot";
/// The release: a rolling pre-release, replaced on every run of the workflow that builds
/// it, so "the latest loaders" is whatever it holds when a build runs.
pub(crate) const LOADER_RELEASE: &str = "usbboot";
/// The file written beside the tree, naming the U-Boot commit the loaders came from.
pub(crate) const SOURCE_FILE: &str = ".usbboot-source";
/// Nothing this xtask downloads is anywhere near this size; the cap stops a redirect to
/// something else from filling the disk.
const DOWNLOAD_LIMIT: u64 = 128 * 1024 * 1024;

type Fallible = Result<(), Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Fallible = match args.first().map(String::as_str) {
        Some("fetch-loaders") => fetch_loaders(&args[1..]),
        Some("web") => web::main(&args[1..]),
        Some("package") => package::main(&args[1..]),
        Some(other) => Err(format!("unknown command {other:?}\n{USAGE}").into()),
        None => Err(format!("no command given\n{USAGE}").into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("xtask: {err}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage: cargo xtask fetch-loaders [--force]\n\
                            cargo xtask web [--release]\n\
                            cargo xtask package --target <triple|name> [--out <dir>] [--no-build]\n\
                            cargo xtask package --check-tag <vX.Y.Z[-pre.N]>\n\
                            cargo xtask package --print-version\n\
                            cargo xtask package --print-jni-symbols";

/// The page of the releases API this reads: the assets and the commit they were built from.
fn release_url() -> String {
    format!("https://api.github.com/repos/{LOADER_REPO}/releases/tags/{LOADER_RELEASE}")
}

/// One asset of the release, as the GitHub API lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// The release, as the GitHub API describes it: the commit it was built from and its assets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Release {
    target_commitish: String,
    assets: Vec<Asset>,
}

/// One loader the release ships: the asset, and where it lands in the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Loader {
    asset: Asset,
    variant: String,
    file: &'static str,
}

/// Fetch the current loader tree (decision D2).
///
/// The release is read through the API (the asset list is not guessable: which chips boot
/// from a TPL and which from an SPL is the release's to say), every `isvp_<variant>_usbboot`
/// asset is downloaded into a staging directory, and the tree is swapped into place only
/// when all of it arrived, so a failed download never leaves half a tree for a build to
/// package. A tree already fetched from the same U-Boot commit is reused; `--force` fetches
/// it again.
fn fetch_loaders(args: &[String]) -> Fallible {
    let mut force = false;
    for arg in args {
        match arg.as_str() {
            "--force" => force = true,
            other => return Err(format!("unknown flag {other:?}\n{USAGE}").into()),
        }
    }

    let root = workspace_root()?;
    let dest = root.join("target").join("firmware");
    let dfu = dest.join("dfu");

    println!("release https://github.com/{LOADER_REPO}/releases/tag/{LOADER_RELEASE}");
    let release = release_manifest()?;
    let loaders = loaders_of(&release)?;
    let source = release.target_commitish.trim().to_owned();
    println!("source  {source} ({} loader assets)", loaders.len());

    if !force && tree_is_from(&dfu, &source, &loaders) {
        println!(
            "cached  {} is already from that commit; --force fetches again",
            dfu.display()
        );
        return Ok(());
    }

    let staging = dest.join("dfu.fetching");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    for loader in &loaders {
        let bytes = download(&loader.asset.browser_download_url)?;
        let arrived = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if arrived != loader.asset.size {
            return Err(format!(
                "{}: the release lists {} bytes but {} arrived",
                loader.asset.name,
                loader.asset.size,
                bytes.len()
            )
            .into());
        }
        let target = staging.join(&loader.variant).join(loader.file);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)?;
        println!(
            "fetched {:<40} -> {}/{}",
            loader.asset.name, loader.variant, loader.file
        );
    }
    fs::write(staging.join(SOURCE_FILE), format!("{source}\n"))?;

    if dfu.exists() {
        // A moved release must not leave last time's variants behind.
        fs::remove_dir_all(&dfu)?;
    }
    fs::rename(&staging, &dfu)?;
    println!("tree    {} files under {}", loaders.len(), dfu.display());
    println!("loader  {source}");
    Ok(())
}

/// The `GITHUB_TOKEN`, trimmed, when one is set and not empty.
///
/// Every request this file makes sends it, because an unauthenticated request is rate
/// limited per address and CI runners share addresses. It is the assets, not the one API
/// call, that exhaust the quota: a release of 68 of them is 68 requests, and the failure
/// arrives as `GET ... -> HTTP 403`, which reads as a missing asset rather than as a rate
/// limit. ureq drops an `Authorization` header across a redirect by default
/// (`RedirectAuthHeaders::Never`), so the token does not follow an asset to the CDN.
fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

/// GET the release description from the API.
fn release_manifest() -> Result<Release, Box<dyn std::error::Error>> {
    let url = release_url();
    let mut request = ureq::get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "thingino-dfu xtask");
    if let Some(token) = github_token() {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = request.call().map_err(|e| {
        format!("GET {url}: {e} - the loaders are downloaded, never vendored (D2), so there is no offline fallback")
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} -> HTTP {status}").into());
    }
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(DOWNLOAD_LIMIT)
        .read_to_end(&mut body)?;
    parse_release(&body)
}

/// The release description, parsed and sanity-checked.
fn parse_release(body: &[u8]) -> Result<Release, Box<dyn std::error::Error>> {
    let url = release_url();
    let release: Release = serde_json::from_slice(body).map_err(|e| format!("{url}: cannot parse the release: {e}"))?;
    let commit = release.target_commitish.trim();
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{url}: target_commitish {commit:?} is not a commit; the release must be built from a commit, not a branch"
        )
        .into());
    }
    Ok(release)
}

/// The loaders in a release: every `isvp_<variant>_usbboot-u-boot*.bin` asset, mapped to
/// its place in the tree. A release with none is refused, because a tree with no loaders
/// is a bootstrap that fails on hardware for no visible reason.
fn loaders_of(release: &Release) -> Result<Vec<Loader>, Box<dyn std::error::Error>> {
    let mut loaders: Vec<Loader> = release
        .assets
        .iter()
        .filter_map(|asset| {
            loader_path(&asset.name).map(|(variant, file)| Loader {
                asset: asset.clone(),
                variant,
                file,
            })
        })
        .collect();
    if loaders.is_empty() {
        return Err(
            format!("{LOADER_REPO} release {LOADER_RELEASE} lists no isvp_<variant>_usbboot loader assets").into(),
        );
    }
    loaders.sort_by(|a, b| (&a.variant, a.file).cmp(&(&b.variant, b.file)));
    check_every_variant_is_whole(&loaders)?;
    Ok(loaders)
}

/// Refuse a release in which a variant is missing a loader, naming the variant and what it
/// lacks.
///
/// Bootstrapping a variant takes its `uboot.bin` and a stage 1 (`tpl.bin` on most parts,
/// `spl.bin` on the capped ones), so a variant with only one of the two is not a variant
/// this tool can bootstrap. The release is rolling, re-cut on every run of the workflow
/// that builds it, so a single failed build leg is enough to publish a half variant: laid
/// out, that tree satisfies [`tree_is_from`] (every asset the release listed is on disk),
/// is copied wholesale into all six archives, and fails for the first time on a user's
/// bench, where `loader::resolve` falls through to `spl.bin` and the read reports a missing
/// loader. Refusing at fetch time turns a hardware-only failure into a build-time one.
fn check_every_variant_is_whole(loaders: &[Loader]) -> Fallible {
    let mut by_variant: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
        std::collections::BTreeMap::new();
    for loader in loaders {
        by_variant.entry(&loader.variant).or_default().insert(loader.file);
    }
    let mut missing: Vec<String> = Vec::new();
    for (variant, files) in by_variant {
        if !files.contains("uboot.bin") {
            missing.push(format!("{variant} has no uboot.bin"));
        }
        if !files.contains("tpl.bin") && !files.contains("spl.bin") {
            missing.push(format!("{variant} has neither tpl.bin nor spl.bin"));
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{LOADER_REPO} release {LOADER_RELEASE} is incomplete: {}",
        missing.join("; ")
    )
    .into())
}

/// Where an asset lands: `isvp_t31x_usbboot-u-boot-spl.bin` -> `t31x/spl.bin`,
/// `isvp_t10l_usbboot-u-boot-tpl.bin` -> `t10l/tpl.bin`, `isvp_t31x_usbboot-u-boot.bin` ->
/// `t31x/uboot.bin`, the names the C tool's sync gave them and the ones
/// `loader::resolve` looks for. Anything else in the release is not a loader.
///
/// The variant is used as a directory name, so it is held to the characters a loader
/// directory can have; a name that could climb out of the tree is refused here.
fn loader_path(name: &str) -> Option<(String, &'static str)> {
    let rest = name.strip_prefix("isvp_")?;
    let (variant, tail) = rest.split_once("_usbboot-u-boot")?;
    let file = match tail {
        "-tpl.bin" => "tpl.bin",
        "-spl.bin" => "spl.bin",
        ".bin" => "uboot.bin",
        _ => return None,
    };
    if variant.is_empty() || !variant.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return None;
    }
    Some((variant.to_owned(), file))
}

/// Is `dfu` a complete tree fetched from `source`?
fn tree_is_from(dfu: &Path, source: &str, loaders: &[Loader]) -> bool {
    let stamped = fs::read_to_string(dfu.join(SOURCE_FILE)).is_ok_and(|text| text.trim() == source);
    stamped
        && loaders
            .iter()
            .all(|loader| dfu.join(&loader.variant).join(loader.file).is_file())
}

/// The U-Boot commit the fetched tree came from, from the stamp `fetch-loaders` writes.
pub(crate) fn loader_source(root: &Path) -> Option<String> {
    let text = fs::read_to_string(root.join("target").join("firmware").join("dfu").join(SOURCE_FILE)).ok()?;
    let commit = text.trim();
    (!commit.is_empty()).then(|| commit.to_owned())
}

/// GET `url`, following redirects. Fails loudly: there is no offline fallback, because a
/// silently absent loader tree is a bootstrap that fails on hardware for no visible reason.
fn download(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut request = ureq::get(url).header("User-Agent", "thingino-dfu xtask");
    if let Some(token) = github_token() {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = request.call().map_err(|e| {
        format!("GET {url}: {e} - the loaders are downloaded, never vendored (D2), so there is no offline fallback")
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GET {url} -> HTTP {status}").into());
    }
    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(DOWNLOAD_LIMIT)
        .read_to_end(&mut body)?;
    if body.is_empty() {
        return Err(format!("GET {url} returned an empty body").into());
    }
    Ok(body)
}

/// Lowercase hex, for the checksums the packager writes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// The workspace root, from this crate's manifest directory.
pub(crate) fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{} has no parent", manifest.display()).into())
}

#[cfg(test)]
mod tests {
    use super::{
        Asset, Loader, Release, SOURCE_FILE, hex, loader_path, loaders_of, parse_release, release_url, tree_is_from,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    /// The three asset shapes the release uses, and where each lands.
    #[test]
    fn a_loader_asset_lands_in_its_variant_directory() {
        assert_eq!(
            loader_path("isvp_t31x_usbboot-u-boot-spl.bin"),
            Some(("t31x".to_owned(), "spl.bin"))
        );
        assert_eq!(
            loader_path("isvp_t10l_usbboot-u-boot-tpl.bin"),
            Some(("t10l".to_owned(), "tpl.bin"))
        );
        assert_eq!(
            loader_path("isvp_t31x_usbboot-u-boot.bin"),
            Some(("t31x".to_owned(), "uboot.bin"))
        );
        assert_eq!(
            loader_path("isvp_a1n_usbboot-u-boot.bin"),
            Some(("a1n".to_owned(), "uboot.bin"))
        );
    }

    /// Anything that is not a loader is skipped, and a name that could climb out of the
    /// tree is refused: the asset list is downloaded, so it is not trusted with a path.
    #[test]
    fn anything_else_is_not_a_loader() {
        for name in [
            "isvp_t31x_usbboot-u-boot-foo.bin",
            "isvp_t31x_usbboot-u-boot.txt",
            "t31x_usbboot-u-boot.bin",
            "isvp__usbboot-u-boot.bin",
            "isvp_../x_usbboot-u-boot.bin",
            "isvp_T31X_usbboot-u-boot.bin",
            "SHA256SUMS",
        ] {
            assert_eq!(loader_path(name), None, "{name}");
        }
    }

    fn asset(name: &str, size: u64) -> Asset {
        Asset {
            name: name.to_owned(),
            browser_download_url: format!("https://example.invalid/{name}"),
            size,
        }
    }

    /// The release description as the API returns it: the commit and the loader assets,
    /// with anything else in the asset list ignored, sorted so a tree is laid out the same
    /// way from any listing order.
    #[test]
    fn a_release_lists_its_loaders_sorted_and_its_commit() -> TestResult {
        let body = br#"{
            "tag_name": "usbboot",
            "target_commitish": "e9edb408b048882191ad542221cecd3bb4811e20",
            "assets": [
                {"name": "isvp_t31x_usbboot-u-boot.bin", "browser_download_url": "https://example.invalid/u", "size": 3},
                {"name": "notes.txt", "browser_download_url": "https://example.invalid/n", "size": 1},
                {"name": "isvp_t31x_usbboot-u-boot-spl.bin", "browser_download_url": "https://example.invalid/s", "size": 2},
                {"name": "isvp_a1n_usbboot-u-boot-spl.bin", "browser_download_url": "https://example.invalid/a", "size": 4},
                {"name": "isvp_a1n_usbboot-u-boot.bin", "browser_download_url": "https://example.invalid/b", "size": 5}
            ]
        }"#;
        let release = parse_release(body)?;
        assert_eq!(release.target_commitish, "e9edb408b048882191ad542221cecd3bb4811e20");
        let loaders = loaders_of(&release)?;
        let laid_out: Vec<(&str, &str)> = loaders
            .iter()
            .map(|loader| (loader.variant.as_str(), loader.file))
            .collect();
        assert_eq!(
            laid_out,
            [
                ("a1n", "spl.bin"),
                ("a1n", "uboot.bin"),
                ("t31x", "spl.bin"),
                ("t31x", "uboot.bin")
            ]
        );
        Ok(())
    }

    /// A variant that cannot be bootstrapped is refused with its name and what it lacks,
    /// rather than laid out, cached as complete and packaged into all six archives. The
    /// release is rolling, so one failed build leg upstream is the whole trigger.
    #[test]
    fn a_variant_missing_a_loader_is_refused() -> TestResult {
        for (assets, wanted) in [
            (
                vec!["isvp_t23n_usbboot-u-boot-tpl.bin", "isvp_t31x_usbboot-u-boot.bin"],
                "t23n has no uboot.bin",
            ),
            (
                vec!["isvp_t31x_usbboot-u-boot.bin"],
                "t31x has neither tpl.bin nor spl.bin",
            ),
        ] {
            let release = Release {
                target_commitish: "e9edb408b048882191ad542221cecd3bb4811e20".to_owned(),
                assets: assets.iter().map(|name| asset(name, 1)).collect(),
            };
            let Err(err) = loaders_of(&release) else {
                return Err(format!("an incomplete release must be refused: {assets:?}").into());
            };
            let err = err.to_string();
            assert!(err.contains(wanted), "{err}");
            assert!(err.contains("is incomplete"), "{err}");
        }

        // Both stage 1 files beside a uboot.bin is whole: `loader::resolve` prefers the
        // TPL and falls back to the SPL, so a release that ships both is not an error.
        let release = Release {
            target_commitish: "e9edb408b048882191ad542221cecd3bb4811e20".to_owned(),
            assets: ["-tpl.bin", "-spl.bin", ".bin"]
                .iter()
                .map(|tail| asset(&format!("isvp_t31x_usbboot-u-boot{tail}"), 1))
                .collect(),
        };
        assert_eq!(loaders_of(&release)?.len(), 3);
        Ok(())
    }

    /// A release built from a branch rather than a commit cannot be recorded as a source,
    /// and a release with no loaders in it is refused rather than laid out empty.
    #[test]
    fn a_release_without_a_commit_or_without_loaders_is_refused() -> TestResult {
        let branch = br#"{"target_commitish": "master", "assets": []}"#;
        let Err(err) = parse_release(branch) else {
            return Err("a branch is not a commit".into());
        };
        let err = err.to_string();
        assert!(err.contains("not a commit"), "{err}");
        assert!(err.contains(&release_url()), "{err}");

        let release = Release {
            target_commitish: "e9edb408b048882191ad542221cecd3bb4811e20".to_owned(),
            assets: vec![asset("notes.txt", 1)],
        };
        let Err(err) = loaders_of(&release) else {
            return Err("a release without loaders must be refused".into());
        };
        let err = err.to_string();
        assert!(err.contains("no isvp_<variant>_usbboot loader assets"), "{err}");
        Ok(())
    }

    /// A tree is reused only when its stamp names the same commit and every loader the
    /// release lists is present; a stamp alone, or the files alone, is not enough.
    #[test]
    fn a_tree_is_reused_only_when_complete_and_from_the_same_commit() -> TestResult {
        let base = std::env::temp_dir().join(format!("tdfu-loaders-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dfu = base.join("dfu");
        let loaders = vec![Loader {
            asset: asset("isvp_t31x_usbboot-u-boot.bin", 3),
            variant: "t31x".to_owned(),
            file: "uboot.bin",
        }];
        let source = "e9edb408b048882191ad542221cecd3bb4811e20";

        assert!(!tree_is_from(&dfu, source, &loaders), "nothing there yet");
        std::fs::create_dir_all(dfu.join("t31x"))?;
        std::fs::write(dfu.join("t31x").join("uboot.bin"), b"abc")?;
        assert!(!tree_is_from(&dfu, source, &loaders), "files but no stamp");
        std::fs::write(dfu.join(SOURCE_FILE), format!("{source}\n"))?;
        assert!(tree_is_from(&dfu, source, &loaders), "complete and stamped");
        assert!(
            !tree_is_from(&dfu, "0000000000000000000000000000000000000000", &loaders),
            "another commit"
        );
        std::fs::remove_file(dfu.join("t31x").join("uboot.bin"))?;
        assert!(!tree_is_from(&dfu, source, &loaders), "stamp but a file missing");

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }
}
