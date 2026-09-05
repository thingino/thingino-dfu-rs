//! `cargo xtask web`: build the browser flasher end to end.
//!
//! Four steps, in order, each failing loudly:
//!
//! 1. `cargo build --target wasm32-unknown-unknown -p tdfu-wasm`
//! 2. `wasm-bindgen --target web --out-dir web/src/wasm` over what that produced
//! 3. `npm ci` in `web/`
//! 4. `npm run build` in `web/`
//!
//! **The `wasm-bindgen` CLI must be the same version as the crate.** They are one tool
//! split in two halves: the macro writes a description of the bindings into a custom
//! section of the wasm, and the CLI reads it back. A mismatched pair does not degrade, it
//! refuses, and the message it prints ("schema version mismatch") is the sort of thing
//! that costs an afternoon the first time. So the version is resolved from the dependency
//! graph, compared against `wasm-bindgen --version` before anything is built, and a
//! mismatch prints the exact `cargo install` line that fixes it.
//!
//! `cargo xtask web --print-wasm-bindgen-version` prints that same version and builds
//! nothing, so CI installs the CLI from one reader rather than keeping its own copy of
//! the rule in a `sed` script.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Fallible, workspace_root};

/// The crate whose `cdylib` becomes the engine.
const WASM_CRATE: &str = "tdfu-wasm";
/// Its output, before `wasm-bindgen` rewrites it.
const WASM_FILE: &str = "tdfu_wasm.wasm";
/// The target the engine is built for. Never Emscripten: the core is Rust compiled to
/// wasm, not C.
const WASM_TARGET: &str = "wasm32-unknown-unknown";
/// The package whose resolved version the CLI must match.
const BINDGEN_CRATE: &str = "wasm-bindgen";

/// `npm` is `npm.cmd` on Windows, and Rust's `Command` does not consult `PATHEXT`, so
/// spawning "npm" there fails with "program not found".
#[cfg(windows)]
const NPM: &str = "npm.cmd";
#[cfg(not(windows))]
const NPM: &str = "npm";

/// Build the flasher: wasm, bindings, then the page.
pub(crate) fn main(args: &[String]) -> Fallible {
    let mut release = false;
    let mut print_version = false;
    for arg in args {
        match arg.as_str() {
            "--release" => release = true,
            "--print-wasm-bindgen-version" => print_version = true,
            other => return Err(format!("unknown flag {other:?}\n{USAGE}").into()),
        }
    }

    let root = workspace_root()?;

    if print_version {
        println!("{}", resolved_wasm_bindgen_version(&root)?);
        return Ok(());
    }

    let web = root.join("web");
    if !web.join("package.json").is_file() {
        return Err(format!("{} is not the web tree", web.display()).into());
    }

    let wanted = resolved_wasm_bindgen_version(&root)?;
    check_wasm_bindgen(&wanted)?;

    let profile = if release { "release" } else { "debug" };
    println!("build   {WASM_CRATE} for {WASM_TARGET} ({profile})");
    let mut build = Command::new("cargo");
    build.current_dir(&root);
    build.args(["build", "--locked", "--target", WASM_TARGET, "-p", WASM_CRATE]);
    if release {
        build.arg("--release");
    }
    run(&mut build, "cargo build")?;

    let wasm = root.join("target").join(WASM_TARGET).join(profile).join(WASM_FILE);
    if !wasm.is_file() {
        return Err(format!("{} was not produced by the build", wasm.display()).into());
    }

    // Generated, never committed: `.gitignore` covers web/src/wasm/. Wiping it first
    // means a rename in the crate cannot leave a stale export behind for the page to
    // import successfully and then fail on at run time.
    let out = web.join("src").join("wasm");
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    fs::create_dir_all(&out)?;
    println!("bindgen {} -> {}", wasm.display(), out.display());
    run(
        Command::new("wasm-bindgen")
            .arg("--target")
            .arg("web")
            .arg("--out-dir")
            .arg(&out)
            .arg(&wasm),
        "wasm-bindgen",
    )?;

    let glue = out.join("tdfu_wasm.js");
    let text = fs::read_to_string(&glue).map_err(|e| format!("{}: {e}", glue.display()))?;
    check_seam(&text).map_err(|missing| seam_error(&glue, &missing))?;
    println!("seam    {}", glue.display());
    link_loader_tree(&root, &web)?;

    println!("npm ci  {}", web.display());
    run(Command::new(NPM).current_dir(&web).arg("ci"), "npm ci")?;

    println!("npm     run build");
    run(
        Command::new(NPM).current_dir(&web).args(["run", "build"]),
        "npm run build",
    )?;

    println!("built   {}", web.join("dist").display());
    Ok(())
}

pub(crate) const USAGE: &str = "usage: cargo xtask web [--release] [--print-wasm-bindgen-version]";

/// The module-level names `web/src/tdfu.js` imports. `default` is
/// `init()`, which the glue exports as `export { initSync, __wbg_init as default }`.
const SEAM_EXPORTS: [&str; 4] = ["default", "Engine", "variantNames", "version"];

/// The `Engine` members `web/src/tdfu.js` calls.
///
/// A missing *method* is not a rollup error at all: rollup only resolves module-level
/// bindings, so `engine.write is not a function` first appears in the browser, mid-flash,
/// with a device half written. It costs one string per name to find it here
/// instead.
const SEAM_METHODS: [&str; 12] = [
    "constructor",
    "setDebug",
    "requestDevice",
    "discover",
    "detect",
    "bootstrap",
    "write",
    "read",
    "verify",
    "erase",
    "reboot",
    "diag",
];

/// Every name the glue exports at module level.
///
/// The three forms `wasm-bindgen --target web` emits, and nothing else: a declaration
/// (`export function version()`, `export class Engine {`) and a list
/// (`export { initSync, __wbg_init as default };`). Anchored at the start of a line,
/// because the words also appear in the doc comments above them, which is exactly how a
/// substring scan came to pass on glue that exported nothing at all.
fn exported_names(glue: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::new();
    for line in glue.lines() {
        let Some(rest) = line.strip_prefix("export ") else {
            continue;
        };
        if let Some(decl) = rest
            .strip_prefix("function ")
            .or_else(|| rest.strip_prefix("async function "))
            .or_else(|| rest.strip_prefix("class "))
            .or_else(|| rest.strip_prefix("const "))
            .or_else(|| rest.strip_prefix("let "))
        {
            let name = decl.trim_start().split(['(', ' ', '{', '=', ';']).next().unwrap_or("");
            if !name.is_empty() {
                names.insert(name);
            }
        } else if let Some(list) = rest.strip_prefix('{').and_then(|r| r.split('}').next()) {
            for item in list.split(',') {
                // `__wbg_init as default` exports `default`; a bare `initSync` exports itself.
                let name = item.rsplit(" as ").next().unwrap_or("").trim();
                if !name.is_empty() {
                    names.insert(name);
                }
            }
        } else if rest.starts_with("default ") {
            names.insert("default");
        }
    }
    names
}

/// Every member declared in the body of `export class Engine`.
///
/// The body is bounded by the closing brace in column 0, which is where a top-level
/// class ends in generated output; a member is a line whose whole content is an
/// identifier, a parameter list and an opening brace. Statements inside a member body do
/// not match either half of that, so nothing needs a JS parser here.
fn engine_methods(glue: &str) -> BTreeSet<&str> {
    let mut methods = BTreeSet::new();
    let mut inside = false;
    for line in glue.lines() {
        if line.starts_with("export class Engine") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line == "}" {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.ends_with('{') {
            continue;
        }
        let Some(open) = trimmed.find('(') else {
            continue;
        };
        let name = trimmed[..open].trim();
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$') {
            methods.insert(name);
        }
    }
    methods
}

/// Fail before the page build when the glue does not carry the seam.
///
/// Rollup's message for a missing export is a stack trace pointing at the import site,
/// which reads like a bug in the page. It is not: it is an engine that does not export
/// what the page was written against. Say that instead.
///
/// Returns the missing names, exports first, so the caller can build the message with the
/// path it read. Pure over the text so the negative case can be pinned.
fn check_seam(glue: &str) -> Result<(), Vec<String>> {
    let exports = exported_names(glue);
    let methods = engine_methods(glue);
    let mut missing: Vec<String> = SEAM_EXPORTS
        .into_iter()
        .filter(|name| !exports.contains(name))
        .map(str::to_owned)
        .collect();
    // A glue with no `Engine` at all has already said so; do not repeat it once per method.
    if exports.contains("Engine") {
        missing.extend(
            SEAM_METHODS
                .into_iter()
                .filter(|name| !methods.contains(name))
                .map(|name| format!("Engine.{name}")),
        );
    }
    if missing.is_empty() { Ok(()) } else { Err(missing) }
}

/// The message for a glue that is missing part of the seam, and the way out.
///
/// The remedy has to work from the state it is printed in: this is raised *after*
/// `wasm-bindgen` wrote the glue and a `tdfu_wasm_bg.wasm` beside it, and the stub
/// refuses to replace a real glue, so the plain `npm run stub` the old message named
/// exited 0 and changed nothing. `--force` replaces the glue and deletes
/// that wasm, and the page build then wants `TDFU_ALLOW_STUB=1` in front of it to say
/// out loud that this build has no engine in it.
fn seam_error(glue: &Path, missing: &[String]) -> String {
    format!(
        "{} does not export {}.\n  \
         For a page build without the engine:\n    \
         node web/test/make-seam-stub.mjs --force\n    \
         TDFU_ALLOW_STUB=1 npm --prefix web run build",
        glue.display(),
        missing.join(", ")
    )
}

/// Point `web/public/firmware/dfu` at the fetched loader tree, if there is one.
///
/// The page fetches `firmware/dfu/<variant>/{tpl,spl}.bin` and `uboot.bin` for a local
/// bootstrap, and `cargo xtask fetch-loaders` unpacks exactly that tree under
/// `target/firmware/`. The link is a build product (gitignored), not something committed:
/// the blobs are not vendored (decision D2), so a checkout with no fetched tree gets no
/// link and the page's fetch 404s, which is the honest failure and the one the C tree
/// has too. Nothing else in the build needs it, so a missing tree is a note, not an error.
fn link_loader_tree(root: &Path, web: &Path) -> Fallible {
    let loaders = root.join("target").join("firmware").join("dfu");
    let link_dir = web.join("public").join("firmware");
    let link = link_dir.join("dfu");
    if !loaders.is_dir() {
        println!(
            "loaders no tree under {} - run `cargo xtask fetch-loaders`",
            loaders.display()
        );
        return Ok(());
    }
    fs::create_dir_all(&link_dir)?;
    // Replace rather than reuse: the target may have moved, and a symlink pointing at
    // last week's path silently serves nothing.
    remove_existing(&link)?;
    match symlink_dir(&loaders, &link) {
        Ok(()) => println!("loaders {} -> {}", link.display(), loaders.display()),
        Err(e) => {
            // Windows needs SeCreateSymbolicLinkPrivilege for this (admin, or Developer
            // Mode), and a repo that builds a Windows CLI should build its page there
            // too, so an unprivileged shell copies the tree instead. The
            // copy is 34 loader directories of a few hundred KiB, once per build.
            println!("loaders symlink refused ({e}); copying instead");
            copy_dir(&loaders, &link)?;
            println!("loaders {} copied from {}", link.display(), loaders.display());
        }
    }
    Ok(())
}

/// Remove whatever is at `path`, symlink or directory, and answer Ok if nothing was.
///
/// `remove_file` is right for a Unix symlink-to-directory and wrong for a Windows
/// directory symlink, where `remove_dir` is the one that unlinks without touching the
/// target (`remove_dir_all` over a directory symlink is the behaviour worth
/// not guessing about, and this never reaches it for a link).
fn remove_existing(path: &Path) -> Fallible {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    let result = if meta.file_type().is_symlink() {
        #[cfg(windows)]
        {
            fs::remove_dir(path).or_else(|_| fs::remove_file(path))
        }
        #[cfg(not(windows))]
        {
            fs::remove_file(path)
        }
    } else if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|e| format!("{}: {e}", path.display()).into())
}

/// Recursive directory copy, for the platforms that will not make a link.
fn copy_dir(from: &Path, to: &Path) -> Fallible {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

/// The `wasm-bindgen` version the dependency graph resolved to.
///
/// One reader, `cargo metadata`, for the xtask and for CI (`--print-wasm-bindgen-version`).
/// There used to be three - a `sed` over `Cargo.lock`, a `toml` parse of the same file and
/// a `cargo metadata` call in a third step - and all three took the first match, so two
/// majors in one graph would have had them agreeing on a version that is not the one
/// `tdfu-wasm` builds against. This one refuses instead.
fn resolved_wasm_bindgen_version(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--locked", "--format-version", "1"])
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let text = String::from_utf8(output.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
    Ok(pick_version(&text, BINDGEN_CRATE)?)
}

/// The one version of `name` in a `cargo metadata` document, or why there is not one.
fn pick_version(metadata: &str, name: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        #[serde(default)]
        packages: Vec<Package>,
    }
    #[derive(serde::Deserialize)]
    struct Package {
        name: String,
        version: String,
    }

    let parsed: Metadata = serde_json::from_str(metadata).map_err(|e| format!("cargo metadata: {e}"))?;
    let mut found: Vec<String> = parsed
        .packages
        .into_iter()
        .filter(|p| p.name == name)
        .map(|p| p.version)
        .collect();
    found.sort();
    found.dedup();
    match found.len() {
        0 => Err(format!(
            "no {name} in the dependency graph - does {WASM_CRATE} depend on it yet?"
        )),
        1 => Ok(found.remove(0)),
        _ => Err(format!(
            "the graph resolves {n} versions of {name}: {list}\n  \
             The CLI can only match one of them, and picking the first silently builds \
             against the other. Unify them (cargo tree -i {name}) before building the page.",
            n = found.len(),
            list = found.join(", ")
        )),
    }
}

/// Refuse to run against a `wasm-bindgen` CLI that is not the crate's own version.
fn check_wasm_bindgen(wanted: &str) -> Fallible {
    let output = Command::new("wasm-bindgen").arg("--version").output();
    let output = match output {
        Ok(output) => output,
        Err(e) => return Err(format!("wasm-bindgen is not on PATH ({e})\n  {}", install_line(wanted)).into()),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    if let Some(complaint) = version_complaint(&text, wanted) {
        return Err(complaint.into());
    }
    println!("bindgen wasm-bindgen {wanted} (matches the dependency graph)");
    Ok(())
}

/// The `cargo install` line that fixes a mismatch, exactly as it must be typed.
fn install_line(wanted: &str) -> String {
    format!("cargo install -f wasm-bindgen-cli --version {wanted}")
}

/// What is wrong with `wasm-bindgen --version`'s output, if anything.
///
/// Pure over the reported text, so the mismatch message is pinned rather than reasoned
/// about. The output is one line, `"wasm-bindgen 0.2.127"`.
fn version_complaint(reported: &str, wanted: &str) -> Option<String> {
    let found = reported.split_whitespace().nth(1).unwrap_or("").trim();
    if found == wanted {
        return None;
    }
    Some(format!(
        "wasm-bindgen CLI is {found:?}, the workspace builds against {wanted:?}\n  \
         The macro and the CLI are one tool; a mismatch is refused, not degraded.\n  {}",
        install_line(wanted)
    ))
}

/// Run a command, inheriting stdio, and fail with its exit status.
fn run(cmd: &mut Command, what: &str) -> Fallible {
    let status = cmd.status().map_err(|e| format!("{what}: {e}"))?;
    if !status.success() {
        return Err(format!("{what} failed: {status}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Path, check_seam, engine_methods, exported_names, fs, link_loader_tree, pick_version, seam_error,
        version_complaint,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A temporary directory, removed when the guard drops.
    #[derive(Debug)]
    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let mut path = std::env::temp_dir();
            path.push(format!("xtask-web-{}-{name}", std::process::id()));
            drop(fs::remove_dir_all(&path));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    /// Glue shaped like what `wasm-bindgen --target web` writes for this crate.
    const GLUE: &str = "\
/**
 * What the page holds: one engine per page, driving every authorized device.
 */
export class Engine {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
    }
    /**
     * `bootstrap(id, { variant, spl, uboot })`
     */
    bootstrap(id, options) {
        const ret = wasm.engine_bootstrap(this.__wbg_ptr, id, options);
        return ret;
    }
    detect(id) {
        const ret = wasm.engine_detect(this.__wbg_ptr, id);
        return ret;
    }
    diag(id) {
        return wasm.engine_diag(this.__wbg_ptr, id);
    }
    discover() {
        return wasm.engine_discover(this.__wbg_ptr);
    }
    erase(id) {
        return wasm.engine_erase(this.__wbg_ptr, id);
    }
    constructor(callbacks) {
        const ret = wasm.engine_new(callbacks);
    }
    read(id, options) {
        return wasm.engine_read(this.__wbg_ptr, id, options);
    }
    reboot(id) {
        return wasm.engine_reboot(this.__wbg_ptr, id);
    }
    requestDevice() {
        return wasm.engine_requestDevice(this.__wbg_ptr);
    }
    setDebug(on) {
        wasm.engine_setDebug(this.__wbg_ptr, on);
    }
    verify(id, options) {
        return wasm.engine_verify(this.__wbg_ptr, id, options);
    }
    write(id, options) {
        return wasm.engine_write(this.__wbg_ptr, id, options);
    }
}
if (Symbol.dispose) Engine.prototype[Symbol.dispose] = Engine.prototype.free;

export function start() {
    wasm.start();
}

export function variantNames() {
    return wasm.variantNames();
}

export function version() {
    return wasm.version();
}

export { initSync, __wbg_init as default };
";

    #[test]
    fn the_generated_glue_carries_the_seam() {
        assert_eq!(check_seam(GLUE), Ok(()));
        assert!(exported_names(GLUE).contains("default"), "init() is the default export");
        assert!(engine_methods(GLUE).contains("write"));
    }

    /// What counts as a member declaration, and what is a statement or a computed key.
    ///
    /// The filter is an identifier check, so `_` and `$` belong in a name and a bracketed
    /// key does not: `Engine.prototype[Symbol.dispose]` is not a name the seam can ask
    /// for, and admitting it would make a missing method look present.
    #[test]
    fn only_identifier_members_are_taken() {
        let glue = "\
export class Engine {
    __destroy_into_raw() {
        return this.__wbg_ptr;
    }
    $legacy(id) {
        return id;
    }
    [Symbol.dispose]() {
        this.free();
    }
    write(id, options) {
        const ret = wasm.engine_write(this.__wbg_ptr, id, options);
    }
}
";
        let methods = engine_methods(glue);
        assert!(methods.contains("__destroy_into_raw"), "{methods:?}");
        assert!(methods.contains("$legacy"), "{methods:?}");
        assert!(methods.contains("write"), "{methods:?}");
        assert!(!methods.contains("[Symbol.dispose]"), "{methods:?}");
        assert!(!methods.iter().any(|m| m.is_empty()), "{methods:?}");
    }

    /// The negative case the old substring scan could not see.
    #[test]
    fn glue_that_only_mentions_the_names_is_refused() -> TestResult {
        let doc_only = "\
/**
 * The Engine class, version() and variantNames() live here.
 */
const Engine = 1;
";
        let Err(missing) = check_seam(doc_only) else {
            return Err("glue that exports nothing must not pass".into());
        };
        assert_eq!(missing, ["default", "Engine", "variantNames", "version"]);
        // And nothing is said about the methods of a class that is not exported.
        assert!(!missing.iter().any(|m| m.starts_with("Engine.")));
        Ok(())
    }

    /// A missing *method* is a browser error mid-flash, not a rollup error.
    #[test]
    fn a_missing_engine_method_is_named() -> TestResult {
        let glue = GLUE.replace(
            "    write(id, options) {\n        return wasm.engine_write(this.__wbg_ptr, id, options);\n    }\n",
            "",
        );
        let Err(missing) = check_seam(&glue) else {
            return Err("an Engine with no write() must not pass".into());
        };
        assert_eq!(missing, ["Engine.write"]);
        Ok(())
    }

    /// The remedy has to work from the state it is printed in.
    #[test]
    fn the_remedy_forces_the_stub_and_names_the_build_that_accepts_one() {
        let text = seam_error(Path::new("web/src/wasm/tdfu_wasm.js"), &["Engine".to_owned()]);
        assert!(text.contains("make-seam-stub.mjs --force"), "{text}");
        assert!(text.contains("TDFU_ALLOW_STUB=1 npm --prefix web run build"), "{text}");
    }

    #[test]
    fn the_version_comes_from_the_dependency_graph() -> TestResult {
        let metadata = r#"{"packages":[
            {"name":"cfg-if","version":"1.0.0"},
            {"name":"wasm-bindgen","version":"0.2.127"}
        ]}"#;
        assert_eq!(pick_version(metadata, "wasm-bindgen")?, "0.2.127");
        Ok(())
    }

    #[test]
    fn a_graph_without_it_says_so() -> TestResult {
        let Err(err) = pick_version(r#"{"packages":[{"name":"cfg-if","version":"1.0.0"}]}"#, "wasm-bindgen") else {
            return Err("a graph with no wasm-bindgen must not resolve one".into());
        };
        assert!(err.contains("no wasm-bindgen"), "{err}");
        Ok(())
    }

    /// Two majors in one graph is the case all three old readers answered wrongly.
    #[test]
    fn two_versions_are_refused_by_name() -> TestResult {
        let metadata = r#"{"packages":[
            {"name":"wasm-bindgen","version":"0.2.100"},
            {"name":"serde","version":"1.0.0"},
            {"name":"wasm-bindgen","version":"0.2.127"}
        ]}"#;
        let Err(err) = pick_version(metadata, "wasm-bindgen") else {
            return Err("two versions must not resolve to one".into());
        };
        assert!(err.contains("0.2.100"), "{err}");
        assert!(err.contains("0.2.127"), "{err}");
        Ok(())
    }

    /// The same version twice in the document is one version, not a conflict.
    #[test]
    fn the_same_version_listed_twice_is_not_a_conflict() -> TestResult {
        let metadata = r#"{"packages":[
            {"name":"wasm-bindgen","version":"0.2.127"},
            {"name":"wasm-bindgen","version":"0.2.127"}
        ]}"#;
        assert_eq!(pick_version(metadata, "wasm-bindgen")?, "0.2.127");
        Ok(())
    }

    #[test]
    fn a_matching_cli_has_no_complaint() {
        assert_eq!(version_complaint("wasm-bindgen 0.2.127\n", "0.2.127"), None);
    }

    #[test]
    fn a_mismatched_cli_names_both_versions_and_the_fix() -> TestResult {
        let Some(complaint) = version_complaint("wasm-bindgen 0.2.100\n", "0.2.127") else {
            return Err("a CLI that is not the wanted version must complain".into());
        };
        assert!(complaint.contains("\"0.2.100\""), "{complaint}");
        assert!(complaint.contains("\"0.2.127\""), "{complaint}");
        assert!(
            complaint.contains("cargo install -f wasm-bindgen-cli --version 0.2.127"),
            "{complaint}"
        );
        Ok(())
    }

    #[test]
    fn a_cli_that_prints_nothing_is_a_mismatch() {
        assert!(version_complaint("", "0.2.127").is_some());
    }

    /// The link is replaced, not reused: a stale one silently serves nothing.
    #[cfg(unix)]
    #[test]
    fn a_stale_loader_link_is_replaced() -> TestResult {
        let dir = Dir::new("loaders")?;
        let root = dir.path().join("root");
        let web = dir.path().join("web");
        let loaders = root.join("target").join("firmware").join("dfu");
        fs::create_dir_all(loaders.join("t31x"))?;
        fs::write(loaders.join("t31x").join("uboot.bin"), b"new")?;
        fs::create_dir_all(web.join("public").join("firmware"))?;

        // A link left by an earlier build, pointing somewhere that is not the tree.
        let stale = dir.path().join("elsewhere");
        fs::create_dir_all(&stale)?;
        let link = web.join("public").join("firmware").join("dfu");
        std::os::unix::fs::symlink(&stale, &link)?;

        link_loader_tree(&root, &web)?;
        assert_eq!(fs::read_link(&link)?, loaders);
        assert_eq!(fs::read(link.join("t31x").join("uboot.bin"))?, b"new");
        Ok(())
    }

    /// No fetched tree is a note, not an error, and it leaves no link behind.
    #[test]
    fn no_loader_tree_is_not_an_error() -> TestResult {
        let dir = Dir::new("noloaders")?;
        let root = dir.path().join("root");
        let web = dir.path().join("web");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&web)?;
        link_loader_tree(&root, &web)?;
        assert!(!web.join("public").join("firmware").join("dfu").exists());
        Ok(())
    }

    /// A real directory where the link goes is replaced too: that is what a Windows
    /// copy leaves behind, and it must not accumulate last build's loaders.
    #[test]
    fn a_copied_tree_is_replaced_by_the_next_build() -> TestResult {
        let dir = Dir::new("copied")?;
        let root = dir.path().join("root");
        let web = dir.path().join("web");
        let loaders = root.join("target").join("firmware").join("dfu");
        fs::create_dir_all(loaders.join("t23n"))?;
        fs::write(loaders.join("t23n").join("uboot.bin"), b"new")?;
        let link = web.join("public").join("firmware").join("dfu");
        fs::create_dir_all(link.join("t10"))?;
        fs::write(link.join("t10").join("uboot.bin"), b"old")?;

        link_loader_tree(&root, &web)?;
        assert!(link.join("t23n").join("uboot.bin").exists());
        assert!(!link.join("t10").exists(), "last build's variants are gone");
        Ok(())
    }
}
