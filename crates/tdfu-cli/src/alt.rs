//! Which DFU alt-setting an operation targets.
//!
//! A pure function over the [`DfuInfo`] a probe returned and the [`AltSel`] the user
//! typed. No bus, no I/O — the whole rule is testable against fixture descriptors.
//!
//! # Why the CLI resolves it rather than leaving it to the operation
//!
//! `ops::write`/`read`/`verify` all take `&AltSel`, so each of them
//! would otherwise carry its own copy of the resolution rules: three copies of a rule
//! that has already drifted three ways once (the CLI prefers the alt named
//! `flash`, the daemon takes the first alt, the web takes the first alt). Resolving here
//! and handing the operation an [`AltSel::Index`] leaves exactly one implementation of
//! the rule, and the operations' own resolution becomes a lookup that cannot disagree
//! with it.
//!
//! It also puts the failure in the right exit class. "No alt" counts as a
//! **device** error (exit 1), not a transfer error (exit 2) — nothing has been written
//! when the alt cannot be found — and resolving alongside the probe rather than inside
//! the write is what makes that fall out instead of needing a special case.

use tdfu_core::Result;
use tdfu_core::model::{AltSel, DfuInfo};

/// The name every shipped loader gives its boot flash.
///
/// A second declaration of the same byte string as
/// [`tdfu_core::dfu::FLASH_ALT`](tdfu_core::dfu::FLASH_ALT), and deliberately not a
/// re-export: this one is the CLI's *test vocabulary* — it appears in the fixtures that
/// pin the alt rules across the seam, which is the point of keeping the CLI's own pins after
/// [`resolve`] began delegating to the core. The rule itself has exactly one
/// home, `tdfu_core::dfu::alt::resolve`, and this constant never reaches it. If the two
/// ever disagree the CLI's own tests fail, because they drive the core resolver with
/// alts named from here.
pub const FLASH: &str = "flash";

/// Turn a selection into the `bAlternateSetting` an operation will use.
///
/// The rules, from `dfu.c:510-538`:
///
/// * a **name** matches an alt's `iInterface` string; failing that, a string of digits
///   is retried as an alt number, which is the C's own fallback (`dfu.c:517-524`) and
///   the way to address an alt whose name the backend could not read;
/// * a **number** matches an alt's `bAlternateSetting` — not its position, because a
///   loader may declare 0, 1 and 2 in any order;
/// * the **default** is the alt named `flash`, else the only alt, else a refusal that
///   says to pass `--alt`. Loaders grew a second alt (`erase`) in `a73e4da`, so "exactly
///   one alt, take it" stopped covering the common case on its own.
///
/// # Errors
/// [`Error::MissingAlt`] when the default rule finds neither a `flash` alt nor a single
/// alt; [`Error::Invalid`] when a name or number the user typed is not on the device —
/// the message names it and the alts that are, which [`Error::MissingAlt`] cannot do
/// (it carries a `&'static str`).
pub fn resolve(info: &DfuInfo, selection: &AltSel) -> Result<u8> {
    // One home for the rules: they live in `tdfu_core::dfu::alt`, shared
    // with the ops and with the daemon. The pins below stay here, guarding the
    // CLI-visible behaviour across that seam.
    tdfu_core::dfu::resolve_alt(info, selection)
}

#[cfg(test)]
mod tests {
    use super::{FLASH, resolve};
    use crate::fake::{TestResult, dfu_info};
    use tdfu_core::Error;
    use tdfu_core::model::{AltSel, DfuInfo};

    /// A gadget with the alts named. Built through the real descriptor parser, so a
    /// fixture here is a `DfuInfo` a device could actually have produced.
    fn gadget(alts: &[(u8, &str)]) -> tdfu_core::Result<DfuInfo> {
        dfu_info(alts)
    }

    /// The three-alt shape every shipped loader has.
    fn shipped() -> tdfu_core::Result<DfuInfo> {
        gadget(&[(0, FLASH), (1, "erase"), (2, "reboot")])
    }

    /// The message of an [`Error::Invalid`], without a `panic!` — the workspace denies
    /// `clippy::panic` in tests too.
    fn invalid_message(outcome: Result<u8, Error>) -> String {
        match outcome {
            Err(Error::Invalid(message)) => message,
            other => format!("expected Error::Invalid, got {other:?}"),
        }
    }

    /// **The default-alt pin.**
    #[test]
    fn fe_default_alt_rules() -> TestResult {
        // `flash` wins, even though it is not the only alt.
        assert_eq!(resolve(&shipped()?, &AltSel::Default)?, 0);

        // `flash` wins even when it is not first, so this is not "alt 0 by another
        // name": the daemon and the web take the first alt and would answer 2 here.
        let reordered = gadget(&[(2, "reboot"), (1, "erase"), (0, FLASH)])?;
        assert_eq!(resolve(&reordered, &AltSel::Default)?, 0);
        // And it is the *named* alt that wins, not the number 0.
        let renumbered = gadget(&[(0, "erase"), (7, FLASH)])?;
        assert_eq!(resolve(&renumbered, &AltSel::Default)?, 7);

        // No `flash`, but only one alt: take it. This is the pre-`a73e4da` loader.
        assert_eq!(resolve(&gadget(&[(3, "nor")])?, &AltSel::Default)?, 3);
        // Even nameless, an alt whose string the backend could not read.
        assert_eq!(resolve(&gadget(&[(0, "")])?, &AltSel::Default)?, 0);

        // No `flash` and more than one: refuse, and say what to pass.
        // `tdfu_core::Error` is not `PartialEq`, so the variant is matched rather than
        // compared.
        let ambiguous = resolve(&gadget(&[(0, "nor"), (1, "nand")])?, &AltSel::Default);
        assert!(matches!(ambiguous, Err(Error::MissingAlt(FLASH))), "{ambiguous:?}");
        // No alts at all is the same refusal.
        let none = resolve(&gadget(&[])?, &AltSel::Default);
        assert!(matches!(none, Err(Error::MissingAlt(FLASH))), "{none:?}");
        Ok(())
    }

    #[test]
    fn a_name_selects_its_alt() -> TestResult {
        assert_eq!(resolve(&shipped()?, &AltSel::Name("erase".into()))?, 1);
        assert_eq!(resolve(&shipped()?, &AltSel::Name("reboot".into()))?, 2);
        Ok(())
    }

    #[test]
    fn a_number_selects_by_alternate_setting_not_by_position() -> TestResult {
        let renumbered = gadget(&[(4, "a"), (9, "b")])?;
        assert_eq!(resolve(&renumbered, &AltSel::Index(9))?, 9);
        // Position 0 holds alt 4, so "index 0" must not answer 4.
        assert!(resolve(&renumbered, &AltSel::Index(0)).is_err());
        Ok(())
    }

    /// The C's decimal fallback: a name that is not a name is retried as a number
    /// (`dfu.c:517-524`). Reachable through `AltSel::Name` even though this crate's
    /// parser routes digits to `AltSel::Index`, because the daemon and the browser
    /// build an `AltSel` from a wire string.
    #[test]
    fn a_numeric_name_falls_back_to_the_number() -> TestResult {
        assert_eq!(resolve(&shipped()?, &AltSel::Name("2".into()))?, 2);
        // And a name that exists still wins over the number it looks like.
        let trap = gadget(&[(0, "1"), (1, "flash")])?;
        assert_eq!(resolve(&trap, &AltSel::Name("1".into()))?, 0, "the name matches first");
        Ok(())
    }

    /// A selection the device does not have names what it does have.
    #[test]
    fn an_unknown_selection_lists_what_is_there() -> TestResult {
        let message = invalid_message(resolve(&shipped()?, &AltSel::Name("rootfs".into())));
        assert!(message.contains("rootfs"), "{message}");
        assert!(message.contains("0 (flash)"), "{message}");
        assert!(message.contains("2 (reboot)"), "{message}");

        let numeric = invalid_message(resolve(&shipped()?, &AltSel::Index(9)));
        // Wording is the shared resolver's: "alt 9", no flag prefix.
        assert!(numeric.contains("alt 9"), "{numeric}");
        Ok(())
    }

    /// A device with no alts at all says that, rather than listing nothing.
    #[test]
    fn a_device_with_no_alts_says_so() -> TestResult {
        let message = invalid_message(resolve(&gadget(&[])?, &AltSel::Index(0)));
        assert!(message.contains("no alt-settings at all"), "{message}");
        Ok(())
    }

    /// A nameless alt is offered by number, not as `0 ()`.
    #[test]
    fn a_nameless_alt_is_offered_by_number() -> TestResult {
        let webusb = gadget(&[(0, ""), (1, "")])?;
        let message = invalid_message(resolve(&webusb, &AltSel::Index(5)));
        assert!(message.contains("offers 0, 1"), "{message}");
        Ok(())
    }
}
