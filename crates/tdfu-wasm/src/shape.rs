//! The JS-facing value shapes, frozen.
//!
//! `DeviceInfo`, `Detection` and the rejection `Error` are the seam `web/src/tdfu.js`
//! consumes; they were agreed in writing before either side was written, so the engine
//! and the page could be built at the same time. Nothing here invents a field.
//!
//! Everything that decides *what string* goes in a field is a pure function over a
//! `tdfu-core` value, so the tables are host-tested; only the `Object`/`Reflect`
//! construction needs a JS heap. Two of those tables, [`family_name`] and
//! [`stage_name`], read enums that are `#[non_exhaustive]` in `tdfu-core`, so they
//! cannot be matched exhaustively from here and each carries a fallback. The fallback is
//! not the safety net: [`tests::every_family_has_a_name`] walks `Family::ALL` and fails
//! if any entry reaches it, which is what turns "a new family was added upstream" from a
//! silent `"unknown"` into a red test.

use js_sys::{Object, Reflect};
use tdfu_core::model::{Evidence, Family, Stage};
use tdfu_core::{Detection, Error};
use tdfu_usb::DeviceDescriptors;
use wasm_bindgen::JsValue;

/// Set one property of a freshly built object.
///
/// `Reflect::set` answers `Ok(false)` for a refused write and `Err` for a proxy that
/// threw. Neither is reachable on an extensible `Object` this function just created and
/// nobody else holds, so the answer is discarded here rather than propagated into every
/// builder's signature, which would put a `?` on forty lines to describe a branch that
/// cannot be taken.
fn set(object: &Object, key: &str, value: &JsValue) {
    let _ignored = Reflect::set(object, &JsValue::from_str(key), value);
}

/// An `Error` for the page: `message`, `kind`, `recoverable`.
///
/// A real `js_sys::Error`, not a plain object: `instanceof Error` holds, the stack is
/// captured, and a `console.error` of it renders as an error rather than as `[object
/// Object]`. `kind` and `recoverable` ride as own properties, which is how the seam
/// spells them.
#[must_use]
pub fn error_object(message: &str, kind: &str, recoverable: bool) -> JsValue {
    let error = js_sys::Error::new(message);
    let object = Object::from(JsValue::from(error));
    set(&object, "kind", &JsValue::from_str(kind));
    set(&object, "recoverable", &JsValue::from_bool(recoverable));
    object.into()
}

/// The `kind` of a [`tdfu_core::Error`]: the variant's own name.
///
/// `tdfu_core::Error` is `#[non_exhaustive]`, so this match cannot be exhaustive from
/// outside that crate. The wildcard answers `"Error"` rather than guessing, and
/// [`tests::every_error_variant_has_its_own_kind`] names every variant that exists today
/// so a rename is caught; a variant *added* upstream would fall through to the wildcard,
/// which is the cost of the attribute and is recorded here rather than papered over.
#[must_use]
pub fn kind_name(error: &Error) -> &'static str {
    match error {
        Error::Usb(_) => "Usb",
        Error::UsbWhile { .. } => "UsbWhile",
        Error::Protocol(_) => "Protocol",
        Error::State(_) => "State",
        Error::NotDfu => "NotDfu",
        Error::Verify { .. } => "Verify",
        Error::MissingAlt(_) => "MissingAlt",
        Error::Ambiguous { .. } => "Ambiguous",
        Error::UnknownSoc { .. } => "UnknownSoc",
        Error::LoaderMissing(_) => "LoaderMissing",
        Error::Invalid(_) => "Invalid",
        Error::Io(_) => "Io",
        _ => "Error",
    }
}

/// A [`tdfu_core::Error`] as the page's rejection value.
///
/// `message` is the error's `Display` and nothing else: not a wrapped, prefixed or
/// re-worded version of it. The completion notes, the retry announcements and the
/// actionable hints all reach the page through the `log` callback, so the one place a
/// caller reads a failure has exactly one wording, which is `tdfu-core`'s.
#[must_use]
pub fn error_for(error: &Error) -> JsValue {
    error_object(&error.to_string(), kind_name(error), error.is_recoverable())
}

/// `DeviceInfo = { id, vid, pid, stage, variant }`.
///
/// `variant` is the *loader* name (`t41nq`), which is what the page shows and what a
/// `--cpu` argument spells, and it is `null` until detection has run: a device that has
/// only been enumerated has no evidence for one, and inventing a default is exactly the
/// `t31x` guess rendered as a fact, the thing `WireVariant::UNKNOWN` (`0xFF`, outside the
/// frozen table) exists to replace.
#[must_use]
pub fn device_info(id: u32, descriptors: &DeviceDescriptors, variant: Option<&str>) -> JsValue {
    let object = Object::new();
    set(&object, "id", &JsValue::from_f64(f64::from(id)));
    set(&object, "vid", &JsValue::from_f64(f64::from(descriptors.vendor_id)));
    set(&object, "pid", &JsValue::from_f64(f64::from(descriptors.product_id)));
    set(
        &object,
        "stage",
        &JsValue::from_str(stage_name(tdfu_core::ops::classify(descriptors))),
    );
    set(&object, "variant", &variant.map_or(JsValue::NULL, JsValue::from_str));
    object.into()
}

/// `Detection = { variant, chip, family, dram, evidence, caveat }`.
///
/// # `caveat` is filled in on every arm, not only on `Resolved`
///
/// [`Detection::caveat`] answers `None` for `Ambiguous` and `Unknown`, because on those
/// arms the qualification is not a footnote, it is the whole answer, and `tdfu-core`
/// carries it as [`Error::Ambiguous`] / [`Error::UnknownSoc`], whose `Display` names the
/// register words and every candidate's DRAM. A page that showed `variant: null` and
/// nothing else would leave an operator with an ambiguous T41 no way to learn what to
/// pass to `--cpu`. That is the failure this crate is written against: the information
/// was in hand and thrown away. So the two errors are *constructed* here to
/// borrow their wording rather than restated: one sentence, one home, in `tdfu-core`.
#[must_use]
pub fn detection(detection: &Detection) -> JsValue {
    let object = Object::new();
    let (family, dram, evidence) = match detection {
        Detection::Resolved(resolved) => (
            Some(resolved.variant.family()),
            resolved.dram.map(|dram| dram.to_string()),
            Some(resolved.evidence),
        ),
        Detection::Ambiguous { family, .. } => (Some(*family), None, None),
        _ => (None, None, None),
    };
    set(
        &object,
        "variant",
        &detection
            .variant()
            .map_or(JsValue::NULL, |variant| JsValue::from_str(variant.loader_dir())),
    );
    set(
        &object,
        "chip",
        &match detection {
            Detection::Resolved(resolved) => JsValue::from_str(resolved.chip),
            _ => JsValue::NULL,
        },
    );
    set(
        &object,
        "family",
        &family.map_or(JsValue::NULL, |family| JsValue::from_str(family_name(family))),
    );
    set(
        &object,
        "dram",
        &dram.map_or(JsValue::NULL, |dram| JsValue::from_str(&dram)),
    );
    set(
        &object,
        "evidence",
        &evidence.map_or(JsValue::NULL, |evidence| JsValue::from_str(evidence_name(evidence))),
    );
    set(
        &object,
        "caveat",
        &caveat_text(detection).map_or(JsValue::NULL, |text| JsValue::from_str(&text)),
    );
    object.into()
}

/// The sentence the page must show with this detection, on every arm.
///
/// Pure, so the "every arm says something" property is host-tested rather than asserted
/// in prose.
#[must_use]
pub fn caveat_text(detection: &Detection) -> Option<String> {
    match detection {
        // `warning`, not `caveat`: the documented-but-unseen sentence is a debug line
        // (the engine logs it, `Engine::detect`), decided 2026-09-03.
        Detection::Resolved(_) => detection.warning(),
        Detection::Ambiguous { regs, candidates, .. } => Some(
            Error::Ambiguous {
                regs: *regs,
                candidates: candidates.clone(),
            }
            .to_string(),
        ),
        Detection::Unknown { regs } => Some(Error::UnknownSoc { regs: *regs }.to_string()),
        // `Detection` is `#[non_exhaustive]`; a new arm with no sentence is better than a
        // wrong one, and `tests::every_detection_arm_says_something` covers the three.
        _ => None,
    }
}

/// `"bootrom"` | `"dfu"` | `"firmware"` | `"unknown"`.
///
/// `Stage::Gadget` is spelled `"dfu"` for the page because that is the word the UI and
/// the operator use ("the device came up as a DFU gadget"), and the seam froze it.
#[must_use]
pub fn stage_name(stage: Option<Stage>) -> &'static str {
    match stage {
        Some(Stage::Bootrom) => "bootrom",
        Some(Stage::Gadget) => "dfu",
        Some(Stage::Firmware) => "firmware",
        _ => "unknown",
    }
}

/// The SoC family, as the page spells it.
#[must_use]
pub fn family_name(family: Family) -> &'static str {
    match family {
        Family::T10 => "T10",
        Family::T20 => "T20",
        Family::T21 => "T21",
        Family::T23 => "T23",
        Family::T30 => "T30",
        Family::T31 => "T31",
        Family::T32 => "T32",
        Family::T33 => "T33",
        // The T40 and T41 share one `cpu_id` and one grade space, which is why the
        // family is spelled with a wildcard: no register tells the two product lines apart.
        Family::T4x => "T4x",
        Family::A1 => "A1",
        _ => "unknown",
    }
}

/// How well a resolved row is known: bench-seen, vendor-documented, or by convention.
#[must_use]
pub fn evidence_name(evidence: Evidence) -> &'static str {
    match evidence {
        Evidence::Bench => "bench",
        Evidence::Vendor => "vendor",
        Evidence::Convention => "convention",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{caveat_text, evidence_name, family_name, kind_name, stage_name};
    use tdfu_core::detect::decode;
    use tdfu_core::model::{Evidence, Family, GradeSource, SocRegs, Stage};
    use tdfu_core::{Detection, Error};
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// Registers of a real T41NQ, read on the bench, so the messages under test
    /// are the ones an operator would actually see.
    const T41NQ: SocRegs = SocRegs::new(0x1004_0003, 0, 0xAAAA_2222);

    /// A detection that **resolved** and still needs a sentence: a known family with a
    /// grade no row claims falls back to the family's conservative loader with
    /// `Evidence::Convention`. `tdfu-core` covers the whole table; this
    /// is one instance, so the `Resolved` arm of [`caveat_text`] has a live case.
    fn resolved_by_convention() -> Detection {
        let family = Family::T31;
        let soc_id = u32::from(family.cpu_id()) << 12;
        let no_row_claims_it = 0x1234_0000;
        let regs = match family.grade_source() {
            GradeSource::SubSocType1 => SocRegs::new(soc_id, no_row_claims_it, 0),
            _ => SocRegs::new(soc_id, 0, no_row_claims_it),
        };
        decode(regs)
    }

    #[test]
    fn every_family_has_a_name() {
        // `Family` is `#[non_exhaustive]`, so `family_name`'s match needs a wildcard and
        // a family added upstream would silently render as "unknown". This walks
        // `Family::ALL` instead, so that addition fails here rather than in a browser.
        for family in Family::ALL {
            assert_ne!(family_name(family), "unknown", "{family:?} has no name");
        }
        assert_eq!(family_name(Family::T4x), "T4x");
    }

    #[test]
    fn the_three_stages_are_the_frozen_spellings() {
        // The seam says stage is "bootrom"|"dfu"|"firmware"|"unknown", and `tdfu.js`
        // switches on the string.
        assert_eq!(stage_name(Some(Stage::Bootrom)), "bootrom");
        assert_eq!(stage_name(Some(Stage::Gadget)), "dfu");
        assert_eq!(stage_name(Some(Stage::Firmware)), "firmware");
        assert_eq!(stage_name(None), "unknown");
    }

    #[test]
    fn the_three_evidence_grades_are_named() {
        assert_eq!(evidence_name(Evidence::Bench), "bench");
        assert_eq!(evidence_name(Evidence::Vendor), "vendor");
        assert_eq!(evidence_name(Evidence::Convention), "convention");
    }

    #[test]
    fn every_error_variant_has_its_own_kind() {
        // No two share a name, and none is the wildcard's "Error": `tdfu.js` branches on
        // `.kind`, so a collision would make two different failures indistinguishable.
        let errors = [
            Error::Usb(UsbError::new(UsbErrorKind::Timeout, Pipe::Device)),
            Error::UsbWhile {
                doing: "claiming".to_owned(),
                source: UsbError::new(UsbErrorKind::Stall, Pipe::Device),
            },
            Error::Protocol("p".to_owned()),
            Error::State("s".to_owned()),
            Error::NotDfu,
            Error::Verify {
                offset: 0,
                expected: 0,
                actual: None,
            },
            Error::MissingAlt("flash"),
            Error::Ambiguous {
                regs: T41NQ,
                candidates: Vec::new(),
            },
            Error::UnknownSoc { regs: T41NQ },
            Error::LoaderMissing("l".to_owned()),
            Error::Invalid("i".to_owned()),
            Error::Io(std::io::Error::other("io")),
        ];
        let mut seen = Vec::new();
        for error in &errors {
            let kind = kind_name(error);
            assert_ne!(kind, "Error", "{error} fell through to the wildcard");
            assert!(!seen.contains(&kind), "{kind} is used twice");
            seen.push(kind);
        }
        assert_eq!(seen.len(), errors.len());
    }

    #[test]
    fn a_resolved_detection_that_needs_a_caveat_gets_one() {
        // The `Resolved` arm is the one that delegates to `Detection::caveat()`, and it
        // is the arm most at risk of losing information: an earlier implementation
        // carried the evidence and printed none of it. A resolved-by-convention row that
        // said nothing would be that bug back, with the page as the place it does not
        // show.
        let detection = resolved_by_convention();
        assert!(
            matches!(detection, Detection::Resolved(_)),
            "the fixture stopped resolving: {detection:?}"
        );
        let caveat = caveat_text(&detection);
        assert!(caveat.is_some(), "a conventional row said nothing: {detection:?}");
        assert_eq!(caveat, detection.caveat(), "the sentence is core's, not a second copy");
    }

    #[test]
    fn every_detection_arm_says_something() {
        // The point of the field: an operator who gets `variant: null` must still be
        // told what to do. `Detection::caveat()` answers `None` on two of these three.
        let ambiguous = Detection::Ambiguous {
            regs: T41NQ,
            family: Family::T4x,
            candidates: Vec::new(),
        };
        let unknown = Detection::Unknown { regs: T41NQ };
        for detection in [&ambiguous, &unknown] {
            let text = caveat_text(detection);
            assert!(text.is_some(), "{detection:?} says nothing");
            assert!(
                text.is_some_and(|text| !text.is_empty()),
                "an empty caveat is the same as none"
            );
        }
    }

    #[test]
    fn an_ambiguous_caveat_borrows_the_core_wording_rather_than_restating_it() {
        // One sentence, one home. If `tdfu-core` re-words `Error::Ambiguous`, the page
        // follows without an edit here - and this fails if someone writes a second copy.
        let candidates = Vec::new();
        let detection = Detection::Ambiguous {
            regs: T41NQ,
            family: Family::T4x,
            candidates: candidates.clone(),
        };
        let expected = Error::Ambiguous {
            regs: T41NQ,
            candidates,
        }
        .to_string();
        assert_eq!(caveat_text(&detection), Some(expected));
    }
}
