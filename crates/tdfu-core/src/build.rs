//! The build identity every binary and the page print: the crate version and the
//! revision this build came from.
//!
//! The `option_env!("TDFU_GIT_HASH")` rule lived three times over - `tdfu-cli`'s banner,
//! `tdfu-daemon`'s `main.rs` and `tdfu-wasm`'s `version_line` each read it and each fell
//! back to `unknown`. It lives here once now, and the three consume it, so
//! where the hash comes from cannot drift between them.
//!
//! # Where the hash comes from, and why there is no build script
//!
//! [`HASH`] reads `TDFU_GIT_HASH` at compile time and is the literal `unknown` when it is
//! unset - the honest answer for a plain `cargo build`. `cargo xtask package` and the
//! release workflow set it for the whole workspace in one build, so the two binaries and
//! the page cannot disagree. A `build.rs` that shelled out to `git` would make `cargo
//! build` non-hermetic, and `.git` is a *file* rather than a directory in a secondary
//! working tree, so its `rerun-if-changed` would not fire. An honest `unknown` beats a
//! stale hash.

/// The workspace version, from `CARGO_PKG_VERSION`.
///
/// `docs/release.md` bumps it and the release job refuses a tag that does not match it
/// (`cargo xtask package --check-tag`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The revision this build came from, or `unknown` when `TDFU_GIT_HASH` was unset.
pub const HASH: &str = match option_env!("TDFU_GIT_HASH") {
    Some(hash) => hash,
    None => "unknown",
};

/// The banner line for `tool`, without its newline: `<tool> <VERSION> (<HASH>)`.
///
/// The CLI and the daemon print this on stderr before anything else; the browser drops
/// the tool name and shows [`version_line`] instead.
#[must_use]
pub fn banner(tool: &str) -> String {
    format!("{tool} {VERSION} ({HASH})")
}

/// The banner without a tool name: `<VERSION> (<HASH>)`, what the page shows because it
/// already knows what it is running.
#[must_use]
pub fn version_line() -> String {
    format!("{VERSION} ({HASH})")
}

#[cfg(test)]
mod tests {
    use super::{HASH, VERSION, banner, version_line};

    /// The identity's shape is pinned; the hash value deliberately is not, so this passes
    /// with or without `TDFU_GIT_HASH` set for the build. The one `tdfu-core` test that
    /// the three consumers' twin tests now sit on top of.
    #[test]
    fn the_identity_names_the_build_without_depending_on_the_hash() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!HASH.is_empty(), "an empty hash would render as ()");
        assert_eq!(banner("thingino-dfu"), format!("thingino-dfu {VERSION} ({HASH})"));
        // version_line is the banner with the tool name dropped.
        assert_eq!(banner("x"), format!("x {}", version_line()));
        assert!(!banner("dfu-remote").contains('\n'), "the banner is one line");
    }

    /// The fallback pinned as a rule rather than a value: `HASH` is `unknown` exactly when
    /// the variable was unset. Revert check: change the `None` arm to `""` and this fails
    /// on a plain `cargo build`.
    #[test]
    fn the_hash_is_unknown_only_when_the_variable_is_unset() {
        match option_env!("TDFU_GIT_HASH") {
            Some(hash) => assert_eq!(HASH, hash),
            None => assert_eq!(HASH, "unknown"),
        }
    }
}
