//! Which alt-setting a selection names.
//!
//! A pure function over the [`DfuInfo`] a probe returned and the [`AltSel`] the caller
//! chose. No bus, no I/O, so the whole rule is testable against fixture descriptors.
//!
//! # Why the rule lives here and not in each frontend
//!
//! The C has one implementation (`tdfu_dfu_find_alt` at `dfu.c:510-526` and
//! `tdfu_dfu_default_alt` at `:531-538`) and **three callers that disagree about the
//! default**: the CLI prefers the alt named `flash`
//! (`cli/main.c:546-553`), the daemon takes the first alt, and the
//! Emscripten path takes `alts[0].alt` outright because its shim read no `iInterface`
//! strings so `"flash"` could never match (`core.c:170-177`). Three frontends, three
//! answers, one rule they were all supposed to share. The third case is the fallback
//! [`default_alt`] carries below: not a frontend's private answer, but what any backend
//! should do when *no* alt on the device carries a name.
//!
//! Every operation here takes an [`AltSel`], so
//! without a shared home each of `write`, `read` and `verify` would carry its own copy
//! of a rule that has already drifted three ways once. This module is that home: the
//! operations resolve through it, and the daemon resolves through it too.
//!
//! A frontend may still refuse *early* — the CLI does, so that "no such alt" lands in
//! the CLI's device class (exit 1) before anything is written rather than in its
//! transfer class (exit 2). That refusal is the same function, called sooner: resolving
//! twice is a lookup over a `Vec` of at most [`MAX_ALTS`](crate::model::MAX_ALTS)
//! entries, and the second answer cannot disagree with the first.

use super::FLASH_ALT;
use crate::error::{Error, Result};
use crate::model::{AltSel, DfuInfo};

/// Turn a selection into the `bAlternateSetting` an operation will use.
///
/// Verified against `dfu.c:510-538`:
///
/// * [`Default`](AltSel::Default) is the alt named [`FLASH_ALT`], else the only alt if
///   there is exactly one, else the **first** alt if the device named none of them at all
///   else a refusal that says to pass `--alt` (`dfu.c:531-538`,
///   `core.c:170-178`). It is **not** "alt 0": `tdfu_dfu_default_alt` matches the *name*
///   first, and only falls back to `alts[0].alt` when nothing about the names can decide.
///   Loaders grew a second alt (`erase`) in `a73e4da`, which is what stopped "exactly
///   one alt, take it" from covering the common case on its own.
/// * [`Name`](AltSel::Name) is an exact `iInterface` match (`dfu.c:512-515`), and
///   failing that a string of decimal digits is retried as an alt number
///   (`dfu.c:517-524`) — the C's own fallback, and the only way to address an alt over
///   WebUSB, where no name is readable.
/// * [`Index`](AltSel::Index) matches a `bAlternateSetting` **by value, not by
///   position** (`dfu.c:521-523` compares `info->alts[i].alt`), because a loader may
///   declare its alts in any order. It is a `u8`, so the C's `(uint8_t)` wrap — where
///   `-i 256` silently addresses 0 — cannot be expressed.
///
/// # Errors
/// [`Error::MissingAlt`] when the default rule finds no `flash` alt on a device that has
/// several and named at least one of them. [`Error::Invalid`] when a name or a number is
/// not on this device: the message
/// names **what was offered**: the alt list is in hand, and the C's `-1` return threw
/// it away.
pub fn resolve(info: &DfuInfo, selection: &AltSel) -> Result<u8> {
    // Deliberately exhaustive with no catch-all. `AltSel` is `#[non_exhaustive]`, so a
    // downstream crate must write one — but this module is *inside* `tdfu-core`, where
    // adding a variant should fail the build here rather than fall through to a
    // runtime refusal. A selector nobody gave a rule to must not silently resolve to
    // the boot flash.
    match selection {
        AltSel::Default => default_alt(info),
        AltSel::Name(name) => by_name(info, name),
        AltSel::Index(index) => by_index(info, *index),
    }
}

/// The default: `flash`, else the only alt, else the first alt of a
/// configuration that named none, else refuse (`dfu.c:531-538`, `core.c:170-178`).
fn default_alt(info: &DfuInfo) -> Result<u8> {
    if let Some(flash) = info.alts.iter().find(|alt| alt.name == FLASH_ALT) {
        return Ok(flash.alt);
    }
    match info.alts.as_slice() {
        [only] => Ok(only.alt),
        // **No name anywhere is not the same as the wrong names.**
        // A device whose `iInterface` strings could not be read hands back a `DfuInfo`
        // whose alts are all `""`, and refusing it would mean refusing the default on a
        // backend that never had one to match. The C's browser build carried a resolver of
        // its own for exactly this and returned `info.alts[0].alt` (`core.c:170-178`), on
        // the ground that every shipped loader builds `dfu_alt_info` as
        // `"<flash>=flash raw ...&mmc 0=sdcard raw ..."`, so the first alt is the boot
        // flash and any later one is secondary. That reasoning is about the loaders, not
        // about the browser, so the rule lives here and applies to every backend.
        //
        // The refusal stays for a configuration that *did* name its alts and named none of
        // them `flash`: there the names were readable, none is the boot flash, and picking
        // the first would be a guess about a device that told us otherwise.
        [first, ..] if info.alts.iter().all(|alt| alt.name.is_empty()) => Ok(first.alt),
        _ => Err(Error::MissingAlt(FLASH_ALT)),
    }
}

/// A name, with the C's decimal fallback behind it (`dfu.c:512-524`).
fn by_name(info: &DfuInfo, name: &str) -> Result<u8> {
    if let Some(found) = info.alts.iter().find(|alt| alt.name == name) {
        return Ok(found.alt);
    }
    if let Ok(index) = name.parse::<u8>()
        && let Ok(alt) = by_index(info, index)
    {
        return Ok(alt);
    }
    Err(unknown(info, &format!("alt {name:?}")))
}

/// A `bAlternateSetting`, matched by value rather than by position.
fn by_index(info: &DfuInfo, index: u8) -> Result<u8> {
    info.alts
        .iter()
        .find(|alt| alt.alt == index)
        .map(|alt| alt.alt)
        .ok_or_else(|| unknown(info, &format!("alt {index}")))
}

/// "That alt is not on this device, and these are."
fn unknown(info: &DfuInfo, asked_for: &str) -> Error {
    if info.alts.is_empty() {
        return Error::Invalid(format!(
            "{asked_for}: this DFU device declares no alt-settings at all — its loader is too old or its \
             descriptors are unreadable"
        ));
    }
    let offered = info
        .alts
        .iter()
        .map(|alt| {
            if alt.name.is_empty() {
                format!("{}", alt.alt)
            } else {
                format!("{} ({})", alt.alt, alt.name)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    Error::Invalid(format!("{asked_for}: this device offers {offered}"))
}

#[cfg(test)]
mod tests {
    use super::{FLASH_ALT, resolve};
    use crate::error::Error;
    use crate::model::{AltSel, DfuAlt, DfuInfo};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A gadget offering these `(bAlternateSetting, iInterface)` pairs.
    fn gadget(alts: &[(u8, &str)]) -> DfuInfo {
        DfuInfo {
            interface: 0,
            transfer_size: 4096,
            bcd_dfu: 0x0110,
            attributes: 0x0F,
            alts: alts
                .iter()
                .map(|(alt, name)| DfuAlt {
                    alt: *alt,
                    name: (*name).to_owned(),
                })
                .collect(),
        }
    }

    /// The three-alt shape every shipped loader has.
    fn shipped() -> DfuInfo {
        gadget(&[(0, FLASH_ALT), (1, "erase"), (2, "reboot")])
    }

    /// The message of an [`Error::Invalid`], without a `panic!` — the workspace denies
    /// `clippy::panic` in tests too.
    fn invalid_message(outcome: Result<u8, Error>) -> String {
        match outcome {
            Err(Error::Invalid(message)) => message,
            other => format!("expected Error::Invalid, got {other:?}"),
        }
    }

    /// **The default pin, in the layer that owns the rule.**
    #[test]
    fn alt_default_rules() -> TestResult {
        // `flash` wins even though it is not the only alt.
        assert_eq!(resolve(&shipped(), &AltSel::Default)?, 0);

        // …and even when it is not first, so this is not "alt 0 by another name": the
        // daemon and the web path take the first alt and would answer 2 here.
        assert_eq!(
            resolve(
                &gadget(&[(2, "reboot"), (1, "erase"), (0, FLASH_ALT)]),
                &AltSel::Default
            )?,
            0
        );
        // It is the *named* alt that wins, not the number 0.
        assert_eq!(resolve(&gadget(&[(0, "erase"), (7, FLASH_ALT)]), &AltSel::Default)?, 7);

        // No `flash`, but exactly one alt: take it — the pre-`a73e4da` loader.
        assert_eq!(resolve(&gadget(&[(3, "nor")]), &AltSel::Default)?, 3);
        // Even nameless, which is a device whose names could not be read.
        assert_eq!(resolve(&gadget(&[(0, "")]), &AltSel::Default)?, 0);

        // No `flash` and more than one: refuse. `Error` is not `PartialEq`, so the
        // variant is matched rather than compared.
        let ambiguous = resolve(&gadget(&[(0, "nor"), (1, "nand")]), &AltSel::Default);
        assert!(matches!(ambiguous, Err(Error::MissingAlt(FLASH_ALT))), "{ambiguous:?}");
        // No alts at all is the same refusal.
        let none = resolve(&gadget(&[]), &AltSel::Default);
        assert!(matches!(none, Err(Error::MissingAlt(FLASH_ALT))), "{none:?}");
        Ok(())
    }

    /// **The nameless-alt fallback pin.**
    #[test]
    fn a_configuration_that_named_no_alt_defaults_to_the_first() -> TestResult {
        // The three-alt shape a loader has when nothing could read its `iInterface`
        // strings. Before this rule it was the `MissingAlt` refusal above, so a WebUSB
        // write of the boot flash could not resolve its own default and the C's browser
        // build carried a resolver of its own (`core.c:170-178`).
        let unreadable = gadget(&[(0, ""), (1, ""), (2, "")]);
        assert_eq!(resolve(&unreadable, &AltSel::Default)?, 0);

        // The *first* alt in descriptor order, which is `alts[0].alt` in the C, and on
        // every shipped loader that is alt 0. A loader that declared them in another order
        // gets the one it put first rather than the number 0.
        let renumbered = gadget(&[(2, ""), (1, ""), (0, "")]);
        assert_eq!(resolve(&renumbered, &AltSel::Default)?, 2);

        // Names that were readable and are simply not `flash` are still a refusal: there
        // the device said what its alts are, and none of them is the boot flash.
        let named = resolve(&gadget(&[(0, "nor"), (1, "nand")]), &AltSel::Default);
        assert!(matches!(named, Err(Error::MissingAlt(FLASH_ALT))), "{named:?}");
        // And so is a device that named only some of them: one readable name is evidence
        // the reads worked, so an unnamed alt is an alt the device left unnamed.
        let partly = resolve(&gadget(&[(0, ""), (1, "erase")]), &AltSel::Default);
        assert!(matches!(partly, Err(Error::MissingAlt(FLASH_ALT))), "{partly:?}");
        Ok(())
    }

    #[test]
    fn a_name_selects_its_alt() -> TestResult {
        assert_eq!(resolve(&shipped(), &AltSel::Name("erase".into()))?, 1);
        assert_eq!(resolve(&shipped(), &AltSel::Name("reboot".into()))?, 2);
        assert_eq!(resolve(&shipped(), &AltSel::Name(FLASH_ALT.into()))?, 0);
        Ok(())
    }

    #[test]
    fn a_number_selects_by_alternate_setting_not_by_position() -> TestResult {
        let renumbered = gadget(&[(4, "a"), (9, "b")]);
        assert_eq!(resolve(&renumbered, &AltSel::Index(9))?, 9);
        assert_eq!(resolve(&renumbered, &AltSel::Index(4))?, 4);
        // Position 0 holds alt 4, so "index 0" must not answer 4.
        assert!(resolve(&renumbered, &AltSel::Index(0)).is_err());
        Ok(())
    }

    /// The C's decimal fallback (`dfu.c:517-524`), reachable through
    /// [`AltSel::Name`] because the daemon and the browser build a selection out of a
    /// wire string that was never parsed.
    #[test]
    fn a_numeric_name_falls_back_to_the_number() -> TestResult {
        assert_eq!(resolve(&shipped(), &AltSel::Name("2".into()))?, 2);
        // A name that exists still wins over the number it looks like, which is the
        // order the C scans in.
        let trap = gadget(&[(0, "1"), (1, FLASH_ALT)]);
        assert_eq!(resolve(&trap, &AltSel::Name("1".into()))?, 0, "the name matches first");
        // Out of a `u8`'s range: the C's `strtol` would take 256 and its `(uint8_t)`
        // cast address alt 0. Here it is simply not a number this device has.
        let wrapped = resolve(&shipped(), &AltSel::Name("256".into()));
        assert!(matches!(wrapped, Err(Error::Invalid(_))), "{wrapped:?}");
        Ok(())
    }

    /// The `strtol` guard: a *partly* numeric name is not a number.
    #[test]
    fn a_partly_numeric_name_is_not_a_number() {
        // `strtol("2x")` stops at `x` and the C rejects it because `*end != '\0'`
        // (`dfu.c:519`). `parse::<u8>` refuses the whole string, same answer.
        let message = invalid_message(resolve(&shipped(), &AltSel::Name("2x".into())));
        assert!(message.contains("2x"), "{message}");
    }

    /// A selection the device does not have names what it does have — the Type-3 rule.
    #[test]
    fn an_unknown_selection_lists_what_is_there() {
        let message = invalid_message(resolve(&shipped(), &AltSel::Name("rootfs".into())));
        assert!(message.contains("rootfs"), "{message}");
        assert!(message.contains("0 (flash)"), "{message}");
        assert!(message.contains("1 (erase)"), "{message}");
        assert!(message.contains("2 (reboot)"), "{message}");

        let numeric = invalid_message(resolve(&shipped(), &AltSel::Index(9)));
        assert!(numeric.contains("alt 9"), "{numeric}");
        assert!(numeric.contains("0 (flash)"), "{numeric}");
    }

    /// A device with no alts at all says that, rather than listing nothing.
    #[test]
    fn a_device_with_no_alts_says_so() {
        let message = invalid_message(resolve(&gadget(&[]), &AltSel::Index(0)));
        assert!(message.contains("no alt-settings at all"), "{message}");
        let named = invalid_message(resolve(&gadget(&[]), &AltSel::Name("flash".into())));
        assert!(named.contains("no alt-settings at all"), "{named}");
    }

    /// A nameless alt is offered by number, not as `0 ()`.
    #[test]
    fn a_nameless_alt_is_offered_by_number() {
        let webusb = gadget(&[(0, ""), (1, "")]);
        let message = invalid_message(resolve(&webusb, &AltSel::Index(5)));
        assert!(message.contains("offers 0, 1"), "{message}");
    }
}
