//! The options objects the page passes, and the rules they are read under.
//!
//! # `js_sys::Reflect`, not `serde-wasm-bindgen`
//!
//! Either would work; the smaller dependency surface wins. It is this
//! one, on three counts:
//!
//! * `serde-wasm-bindgen` brings `serde` and `serde_derive`, which is a proc-macro and
//!   its parser, for four objects with eleven fields between them. `js-sys` is a
//!   dependency this crate already has and cannot avoid.
//! * **The payloads are typed arrays.** `spl`, `uboot` and `image` are `Uint8Array`s of
//!   up to a whole flash image. `serde` sees a sequence and deserialises it element by
//!   element into a `Vec<u8>`; `js_sys::Uint8Array::to_vec` is one `copy_to` of the
//!   backing buffer. For a 16 MiB image that is not a micro-optimisation.
//! * The refusals are better. A hand-written reader says *which field* was wrong and
//!   what was expected, in this project's wording; `serde`'s would say
//!   `invalid type: floating point '1.5', expected u8`.
//!
//! # What is pure and what is not
//!
//! Every *rule* (both-or-neither, the alt bound, a size that must be a whole
//! non-negative number) is a function over ordinary Rust values, so it is host-tested
//! and mutation-visible. Only the reading of a `JsValue` needs a JS heap, and that half
//! is covered by the `wasm-bindgen-test` suite. Splitting it that way is why a rule can
//! be checked at all without a browser.

use js_sys::{Reflect, Uint8Array};
use tdfu_core::model::{AltSel, Variant};
use tdfu_core::{Error, Result};
use wasm_bindgen::{JsCast, JsValue};

/// What the page put in an `alt` field: a name, an index, or nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum AltArg {
    /// `alt: "flash"`: an alt name.
    Name(String),
    /// `alt: 0`: an alt index, the selection that works whether or not the browser could
    /// name the alternate.
    Index(f64),
}

/// `alt` → [`AltSel`], with the index bound checked.
///
/// An absent `alt` is [`AltSel::Default`], which `dfu::alt::resolve` turns into the alt
/// named `flash`, else the only alt, else the first alt of a nameless configuration: one home for that rule, in
/// `tdfu-core`, rather than a second copy here.
///
/// The index is bounded at 255 because `AltSel::Index` is a `u8` and because the C's
/// `remote_read_firmware` smashed its stack on an unbounded one.
/// A fractional or negative index is a caller bug and is named as one rather than
/// silently truncated: `alt: 1.5` meaning alt 1 is a guess.
///
/// # Errors
/// [`Error::Invalid`] naming the value, for an index that is not a whole number in
/// `0..=255`.
pub fn alt_selection(alt: Option<AltArg>) -> Result<AltSel> {
    match alt {
        None => Ok(AltSel::Default),
        Some(AltArg::Name(name)) => Ok(AltSel::Name(name)),
        Some(AltArg::Index(index)) => {
            if index.fract() != 0.0 || !(0.0..=255.0).contains(&index) {
                return Err(Error::Invalid(format!(
                    "alt index {index} is not a whole number between 0 and 255"
                )));
            }
            // Checked immediately above: whole, and within `u8`'s range.
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "the range and the fractional part are both checked on the line above; \
                          `f64 as u8` is exact for every value that reaches here"
            )]
            Ok(AltSel::Index(index as u8))
        }
    }
}

/// `spl` and `uboot` → the pair `ops::bootstrap` stages, or a refusal.
///
/// **Both or neither.** One half alone cannot be right: a custom SPL
/// with the bundled U-Boot pairs a DDR setup with a second stage built against a
/// different one, and the whole point of the custom path is that the operator is
/// replacing the pair.
///
/// `None` back means the page sent neither, and the caller has to say so: this crate
/// cannot fetch the bundled loader for it. That is not an omission:
/// `tdfu_core::loader` is not compiled for wasm, and its own doc says why ("the browser
/// frontend has no filesystem to look in, it hands `ops::bootstrap` two byte slices it
/// fetched over the network", `crates/tdfu-core/src/loader.rs:8-12`). It is also what
/// the shipped page already does: `web/src/app.js` fetches
/// `firmware/dfu/<dir>/{tpl,spl}.bin` and `uboot.bin` and only then calls in.
///
/// # Errors
/// [`Error::Invalid`] naming the half that is missing.
pub fn blob_pair(spl: Option<Vec<u8>>, uboot: Option<Vec<u8>>) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    match (spl, uboot) {
        (Some(spl), Some(uboot)) => Ok(Some((spl, uboot))),
        (None, None) => Ok(None),
        (Some(_), None) => Err(Error::Invalid(
            "bootstrap was given spl but not uboot: pass both or neither".to_owned(),
        )),
        (None, Some(_)) => Err(Error::Invalid(
            "bootstrap was given uboot but not spl: pass both or neither".to_owned(),
        )),
    }
}

/// What to tell a page that asked to bootstrap and sent no loader bytes.
///
/// Actionable rather than a wall: it names the directory to fetch from, and both stage-1
/// spellings, because a variant's stage 1 is `tpl.bin` if its directory has one and `spl.bin` if not,
/// by file presence and never by family, which the page cannot know in advance either (`web/src/app.js`'s
/// `fetchDfuLoaders` tries `tpl.bin` and falls back on a 404).
#[must_use]
pub fn missing_loader_message(variant: Option<Variant>) -> String {
    match variant {
        Some(variant) => format!(
            "bootstrap needs the loader bytes: fetch firmware/dfu/{dir}/tpl.bin (or spl.bin) and \
             firmware/dfu/{dir}/uboot.bin and pass them as spl and uboot",
            dir = variant.loader_dir()
        ),
        None => "bootstrap needs the loader bytes: detect the device first, then fetch \
                 firmware/dfu/<variant>/tpl.bin (or spl.bin) and firmware/dfu/<variant>/uboot.bin \
                 and pass them as spl and uboot"
            .to_owned(),
    }
}

/// `size` → `ops::read`'s `limit`.
///
/// `size: 0` is kept as `Some(0)` and reads exactly zero bytes, which is the behaviour
/// `ops::read` documents. Collapsing it to `None` would turn
/// "read nothing" into "read the whole 16 MiB alt", which is the opposite request.
///
/// # Errors
/// [`Error::Invalid`] for a negative or fractional size.
pub fn size_limit(size: Option<f64>) -> Result<Option<u64>> {
    let Some(size) = size else { return Ok(None) };
    if size.fract() != 0.0 || size < 0.0 || size > 2f64.powi(53) {
        return Err(Error::Invalid(format!(
            "size {size} is not a whole number of bytes between 0 and 2^53"
        )));
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "checked on the line above: whole, non-negative, and below 2^53 where f64 is exact"
    )]
    Ok(Some(size as u64))
}

/// `variant` → a loader.
///
/// [`Variant::from_cpu_arg`] is the one parser, so the browser accepts exactly what
/// `--cpu` accepts, C-era aliases included. An unknown name is refused rather than
/// defaulted: the C silently fell back to `t31x` for a name it did not know, and that is a
/// wrong loader on nine families out of ten.
///
/// # Errors
/// [`Error::Invalid`] naming the value that is not a variant.
pub fn variant_of(name: Option<&str>) -> Result<Option<Variant>> {
    match name {
        None => Ok(None),
        Some(name) => Variant::from_cpu_arg(name).map(Some).ok_or_else(|| {
            Error::Invalid(format!(
                "{name:?} is not a known SoC variant; pass one of the names variantNames() lists"
            ))
        }),
    }
}

/// Read one property of an options object.
///
/// A missing property, and an `options` that is not an object at all (`undefined`, which
/// is what `engine.erase(id)` style calls pass), both read as `undefined`, so every
/// field is optional by construction and no call site needs a null check before it can
/// ask a question.
#[must_use]
pub fn field(options: &JsValue, key: &str) -> JsValue {
    Reflect::get(options, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

/// A string field, or `None` when it is absent or null.
#[must_use]
pub fn string_field(options: &JsValue, key: &str) -> Option<String> {
    field(options, key).as_string()
}

/// A number field, or `None` when it is absent or null.
#[must_use]
pub fn number_field(options: &JsValue, key: &str) -> Option<f64> {
    field(options, key).as_f64()
}

/// A boolean field, defaulting to `false`.
///
/// `verify: undefined` is "do not verify", which is the CLI's default too: `--verify`
/// is a flag the operator adds. JS truthiness is deliberately not used: `verify: "no"`
/// would be `true` under it, and a silent verify-when-you-meant-not is a slow surprise
/// rather than a wrong result, while `verify: 0` meaning "yes" would be a wrong result.
#[must_use]
pub fn bool_field(options: &JsValue, key: &str) -> bool {
    field(options, key).as_bool().unwrap_or(false)
}

/// An `alt` field: `string | number | undefined`.
///
/// # Errors
/// [`Error::Invalid`] for anything that is neither.
pub fn alt_field(options: &JsValue, key: &str) -> Result<Option<AltArg>> {
    let value = field(options, key);
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if let Some(name) = value.as_string() {
        return Ok(Some(AltArg::Name(name)));
    }
    if let Some(index) = value.as_f64() {
        return Ok(Some(AltArg::Index(index)));
    }
    Err(Error::Invalid(format!(
        "{key} must be an alt name or an alt index, not {}",
        js_type_name(&value)
    )))
}

/// A byte field: a `Uint8Array`, an `ArrayBuffer`, or absent.
///
/// `ArrayBuffer` is accepted as well as the `Uint8Array` the seam names, because
/// `await (await fetch(url)).arrayBuffer()` is the shortest path to a loader image in a
/// browser and refusing it would buy nothing but a puzzled caller. Any other typed-array
/// view is refused rather than reinterpreted: a `Uint32Array` of 4096 entries is 16 KiB
/// of bytes, and quietly deciding which reading was meant is how a wrong image gets
/// flashed.
///
/// # Errors
/// [`Error::Invalid`] naming the field and what arrived.
pub fn bytes_field(options: &JsValue, key: &str) -> Result<Option<Vec<u8>>> {
    let value = field(options, key);
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    if let Some(array) = value.dyn_ref::<Uint8Array>() {
        return Ok(Some(array.to_vec()));
    }
    if let Some(buffer) = value.dyn_ref::<js_sys::ArrayBuffer>() {
        return Ok(Some(Uint8Array::new(buffer).to_vec()));
    }
    Err(Error::Invalid(format!(
        "{key} must be a Uint8Array or an ArrayBuffer, not {}",
        js_type_name(&value)
    )))
}

/// A short name for what a `JsValue` is, for a refusal message.
///
/// `typeof` plus the constructor name, because `typeof someTypedArray` is `"object"` and
/// that alone tells a caller nothing about what they passed.
fn js_type_name(value: &JsValue) -> String {
    if value.is_null() {
        return "null".to_owned();
    }
    let constructor = value
        .dyn_ref::<js_sys::Object>()
        .map(|object| object.constructor().name())
        .map(String::from)
        .filter(|name| !name.is_empty());
    match constructor {
        Some(name) => format!("a {name}"),
        None => format!("a {}", value.js_typeof().as_string().unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::{AltArg, alt_selection, blob_pair, missing_loader_message, size_limit, variant_of};
    use tdfu_core::model::{AltSel, Variant};

    type TestResult = Result<(), tdfu_core::Error>;

    #[test]
    fn an_absent_alt_is_the_default_that_core_resolves() -> TestResult {
        // Not `Name("flash")`: the default-alt rule lives in `dfu::alt::resolve`, and a
        // second copy of it here is exactly the duplication that shared resolver removed.
        assert_eq!(alt_selection(None)?, AltSel::Default);
        Ok(())
    }

    #[test]
    fn an_alt_name_and_an_alt_index_both_arrive_intact() -> TestResult {
        assert_eq!(
            alt_selection(Some(AltArg::Name("erase".to_owned())))?,
            AltSel::Name("erase".to_owned())
        );
        assert_eq!(alt_selection(Some(AltArg::Index(0.0)))?, AltSel::Index(0));
        assert_eq!(alt_selection(Some(AltArg::Index(255.0)))?, AltSel::Index(255));
        Ok(())
    }

    #[test]
    fn an_out_of_range_or_fractional_alt_index_is_refused_not_truncated() {
        // A bounded `--alt` and a refused `-i 256` are deliberate: the C wraps
        // `(uint8_t)256` to 0, which silently addresses another entity. A fractional
        // index is the same class of guess.
        for index in [-1.0, 256.0, 1.5, f64::NAN, f64::INFINITY] {
            assert!(
                alt_selection(Some(AltArg::Index(index))).is_err(),
                "alt {index} was accepted"
            );
        }
    }

    #[test]
    fn the_loader_pair_is_both_or_neither() -> TestResult {
        assert_eq!(blob_pair(None, None)?, None);
        assert_eq!(blob_pair(Some(vec![1]), Some(vec![2]))?, Some((vec![1], vec![2])));
        assert!(blob_pair(Some(vec![1]), None).is_err());
        assert!(blob_pair(None, Some(vec![2])).is_err());
        Ok(())
    }

    /// The refusal text, or a sentinel that fails the assertion it lands in: a
    /// `panic!`-free way to say "this should have been an error" (`unwrap`, `expect` and
    /// `panic` are denied in tests too).
    fn refusal<T>(result: Result<T, tdfu_core::Error>) -> String {
        match result {
            Err(error) => error.to_string(),
            Ok(_) => "this was accepted".to_owned(),
        }
    }

    #[test]
    fn each_missing_half_names_itself() {
        // "pass both or neither" alone would leave the caller guessing which one it
        // forgot: the information was in hand and thrown away.
        let spl_only = refusal(blob_pair(Some(vec![1]), None));
        let uboot_only = refusal(blob_pair(None, Some(vec![1])));
        assert!(spl_only.contains("not uboot"), "{spl_only}");
        assert!(uboot_only.contains("not spl"), "{uboot_only}");
    }

    #[test]
    fn the_missing_loader_message_names_the_directory_when_it_can() {
        let known = missing_loader_message(Some(Variant::T41nq));
        assert!(known.contains("firmware/dfu/t41nq/tpl.bin"), "{known}");
        assert!(known.contains("firmware/dfu/t41nq/uboot.bin"), "{known}");
        let unknown = missing_loader_message(None);
        assert!(unknown.contains("detect the device first"), "{unknown}");
    }

    #[test]
    fn a_zero_size_reads_nothing_rather_than_everything() -> TestResult {
        // `limit: Some(0)` reads exactly zero bytes. Collapsing
        // it to `None` would read the whole alt - the opposite of what was asked.
        assert_eq!(size_limit(Some(0.0))?, Some(0));
        assert_eq!(size_limit(None)?, None);
        assert_eq!(size_limit(Some(16.0 * 1024.0 * 1024.0))?, Some(16 * 1024 * 1024));
        Ok(())
    }

    #[test]
    fn a_size_that_is_not_a_whole_count_of_bytes_is_refused() {
        for size in [-1.0, 0.5, f64::NAN, 2f64.powi(54)] {
            assert!(size_limit(Some(size)).is_err(), "size {size} was accepted");
        }
    }

    #[test]
    fn the_ceiling_is_the_largest_exact_integer_and_it_is_inclusive() {
        // `2^53` is where an `f64` stops being able to name every integer, so it is the
        // last size a JS `Number` can express exactly - and it is legal. Off by one here
        // (`>` becoming `>=`) would refuse the only value at the boundary, which no test
        // that only uses 16 MiB and 2^54 can tell apart.
        assert_eq!(size_limit(Some(2f64.powi(53))).ok().flatten(), Some(1 << 53));
        assert!(size_limit(Some(2f64.powi(53) + 2048.0)).is_err());
    }

    #[test]
    fn a_variant_goes_through_the_one_cpu_parser() -> TestResult {
        assert_eq!(variant_of(Some("t41nq"))?, Some(Variant::T41nq));
        assert_eq!(variant_of(None)?, None);
        Ok(())
    }

    #[test]
    fn an_unknown_variant_is_refused_rather_than_defaulted_to_t31x() {
        // The C fell back to `t31x` for anything it did not know,
        // which is a wrong DDR init on every family but one.
        let error = refusal(variant_of(Some("t99z")));
        assert!(error.contains("t99z"), "{error}");
        assert!(!error.contains("t31x"), "{error}");
    }
}
