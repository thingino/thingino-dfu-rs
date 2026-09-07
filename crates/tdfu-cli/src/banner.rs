//! The startup line: which build wrote everything that follows.
//!
//! `thingino-dfu 2.0.0-alpha.1 (a1b2c3d)` on **stderr**, before anything else, exactly
//! as the C does it (`cli/main.c:296`). It is kept **ON MERIT** rather
//! than for parity: a pasted terminal that does not say which build produced it costs a
//! round trip, and stderr means no pipeline sees it.
//!
//! # Where the identity comes from
//!
//! [`NAME`] is this binary's; the version and the build hash are [`tdfu_core::build`]'s,
//! shared with the daemon and the page, so the `option_env!("TDFU_GIT_HASH")` rule and its
//! `unknown` fallback live in exactly one place (audit N3). That module's doc explains why
//! there is no `build.rs` and why an honest `unknown` beats a stale hash.

use std::io::{self, Write};

/// The name the binary is invoked by.
pub const NAME: &str = "thingino-dfu";

/// The crate version, from [`tdfu_core::build::VERSION`]. `docs/release.md` bumps it; the
/// release job refuses a tag that does not match it (`cargo xtask package --check-tag`).
pub const VERSION: &str = tdfu_core::build::VERSION;

/// The revision this binary was built from, or `unknown`. From [`tdfu_core::build::HASH`],
/// the one reader of `TDFU_GIT_HASH` (audit N3).
pub const BUILD: &str = tdfu_core::build::HASH;

/// The banner line, without its newline.
#[must_use]
pub fn banner() -> String {
    tdfu_core::build::banner(NAME)
}

/// Write the banner.
///
/// # Errors
/// Whatever `out` raises.
pub fn print(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{}", banner())
}

#[cfg(test)]
mod tests {
    use super::{BUILD, NAME, VERSION, banner, print};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The shape is pinned; the hash value deliberately is not, so the test passes
    /// whether or not `TDFU_GIT_HASH` was set for this build.
    #[test]
    fn the_banner_names_the_build_without_depending_on_it() {
        let line = banner();
        assert!(line.starts_with(&format!("{NAME} {VERSION} (")), "{line}");
        assert!(line.ends_with(')'), "{line}");
        assert!(!BUILD.is_empty(), "an empty build id would render as `()`");
        assert!(!line.contains('\n'), "the banner is one line: {line}");
    }

    #[test]
    fn the_version_is_the_crate_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn it_writes_one_line_terminated() -> TestResult {
        let mut out = Vec::new();
        print(&mut out)?;
        let written = String::from_utf8(out)?;
        assert_eq!(written, format!("{}\n", banner()));
        Ok(())
    }
}
