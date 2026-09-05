//! Crate-level pins: the clock seam, the public entry points, and the ordinal table.
//!
//! The clock-seam half lives in the `wasm-bindgen-test` suite, because a pin
//! that "a browser clock drives the core" is worth nothing if the clock is a stand-in:
//! it has to be a real `setTimeout`, which needs a JS runtime. See
//! `tests/browser_clock.rs`.

use crate::variant_name_table;

#[test]
fn variant_names_cover_the_whole_table() {
    // The wire ordinal table is frozen at 59 entries and `remote.js` indexes it by ordinal,
    // so a hole would render a device's variant as the empty string and a length change
    // would shift every name after it.
    let names = variant_name_table();
    assert_eq!(
        u8::try_from(names.len()),
        Ok(tdfu_proto::WireVariant::COUNT),
        "the table is 59 entries and the page indexes it by ordinal"
    );
    for (ordinal, name) in names.iter().enumerate() {
        assert!(!name.is_empty(), "ordinal {ordinal} has no name");
    }
}

#[test]
fn the_unknown_ordinal_is_not_in_the_table() {
    // `WireVariant::UNKNOWN` is `0xFF`, outside the frozen table: it replaces the C's
    // pre-seed of ordinal 6 (`t31x`) for an unknown gadget: a guess rendered as a fact,
    // which the CLI would then send back as a --cpu value.
    let names = variant_name_table();
    assert!(
        usize::from(tdfu_proto::WireVariant::UNKNOWN.0) >= names.len(),
        "0xFF must be past the end of the table, not an index into it"
    );
    assert_eq!(tdfu_proto::WireVariant::UNKNOWN.name(), None);
}

#[test]
fn the_version_line_is_the_banner_without_the_program_name() {
    // The seam says `version()` is "2.0.0-alpha.0 (<sha>)", the CLI's banner text.
    // The page already knows what it is running, so the name is dropped; the shape is
    // pinned and the hash deliberately is not, so this passes with or without
    // `TDFU_GIT_HASH` set.
    let line = crate::version_line();
    assert!(line.starts_with(crate::VERSION), "{line}");
    assert!(line.ends_with(')'), "{line}");
    assert!(!line.contains('\n'), "{line}");
    assert!(!crate::BUILD.is_empty(), "an empty build id would render as ()");
}

#[test]
fn the_access_denied_hint_is_one_clean_sentence() {
    // The same three checks the native backend's hint carries: one literal, one line, no
    // run of spaces from a `rustfmt` join, which is how an earlier implementation's copy
    // of this advice acquired a 14-space hole in the middle of a sentence.
    assert!(
        !crate::ACCESS_DENIED_HINT.contains("  "),
        "{:?}",
        crate::ACCESS_DENIED_HINT
    );
    assert!(!crate::ACCESS_DENIED_HINT.contains('\n'));
    assert!(!crate::ACCESS_DENIED_HINT.ends_with('.'));
    assert!(crate::ACCESS_DENIED_HINT.contains("udev"));
    // Both vendor ids this tool opens, so an X-series operator is not sent a rule that
    // does not cover the device that was refused.
    assert!(crate::ACCESS_DENIED_HINT.contains("a108"));
    assert!(crate::ACCESS_DENIED_HINT.contains("601a"));
}

/// **`every_entry_point_is_public`**: nothing a browser frontend needs is private.
///
/// The failure it guards against: an earlier implementation had eighteen `_with_clock`
/// twins and several were not `pub`, so the browser (the one frontend that *must* pass its
/// own clock) could not reach them. The twins are gone, the clock is a mandatory parameter
/// of the single form, which is why this list has no `_with_clock`
/// name in it: there is no second form left to forget to export.
///
/// Every item below is **named as a value**, not called. A coercion to a function pointer
/// or a `const` binding is a use, so demoting any of them to `pub(crate)` fails this
/// module's compilation rather than being noticed in a browser six weeks later. The list
/// is what a frontend needs: the nine operations, the classifier, the ten bootrom
/// primitives, the DFU host layer, and the clock seam itself.
#[test]
fn every_entry_point_is_public() {
    use tdfu_core::{bootrom, clock, dfu, ops};

    // The clock seam. `Sleeper` has to be nameable and implementable from outside
    // `tdfu-core`, or a browser cannot supply a clock at all.
    const fn implements_sleeper<S: clock::Sleeper>() {}
    implements_sleeper::<crate::clock::JsSleeper>();
    implements_sleeper::<clock::RecordingClock>();

    // The nine operations, each taking a clock as its second argument.
    let _ = ops::detect::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::bootstrap::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::probe::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::probe_with_progress::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::write::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::read::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::verify::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::erase::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::reboot::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::diag::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = ops::classify;
    let _ = ops::POST_STAGE1_SETTLE;

    // The bootrom primitives. Five of them take a clock; `claim`, `release` and
    // `get_cpu_info` do not, because they do not sleep - a parameter nothing reads is the
    // kind of vestigial residue this crate exists to avoid carrying.
    let _ = bootrom::claim::<crate::WebUsbTransport>;
    let _ = bootrom::release::<crate::WebUsbTransport>;
    let _ = bootrom::get_cpu_info::<crate::WebUsbTransport>;
    let _ = bootrom::set_data_addr::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::set_data_len::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::flush_cache::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::prog_stage1::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::prog_stage2::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::read_memory::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::load_to_memory::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = bootrom::bulk_timeout;
    let _ = bootrom::pad_stage1;

    // The DFU host layer. `poll_until_ready` is the one that sleeps for
    // `bwPollTimeout`, which is the whole reason the browser needs its own clock.
    let _ = dfu::host::claim::<crate::WebUsbTransport>;
    let _ = dfu::host::release::<crate::WebUsbTransport>;
    let _ = dfu::host::get_status::<crate::WebUsbTransport>;
    let _ = dfu::host::make_idle::<crate::WebUsbTransport>;
    let _ = dfu::host::dnload::<crate::WebUsbTransport>;
    let _ = dfu::host::upload::<crate::WebUsbTransport>;
    let _ = dfu::host::abort::<crate::WebUsbTransport>;
    let _ = dfu::host::clr_status::<crate::WebUsbTransport>;
    let _ = dfu::host::poll_until_ready::<crate::WebUsbTransport, crate::clock::JsSleeper>;
    let _ = dfu::alt::resolve;
    let _ = dfu::descriptors::read_config::<crate::WebUsbTransport>;
    let _ = dfu::descriptors::read_info::<crate::WebUsbTransport>;
    let _ = dfu::descriptors::parse_config;

    // `reset_and_retry_once` and `retry_stale_block0` are generic over a closure, so they
    // cannot be named as values; instantiating them inside a function that is named but
    // never called is the same proof, and it also pins their argument order.
    let _ = the_two_retry_helpers_are_callable_from_here;
}

/// Never called: naming it above is what forces it to compile, which is what proves
/// the reset-and-retry-once and stale-block-0 helpers are reachable from a browser
/// frontend with a browser clock.
async fn the_two_retry_helpers_are_callable_from_here(device: &crate::WebUsbTransport) -> tdfu_core::Result<()> {
    use tdfu_core::dfu;

    let clock = crate::clock::JsSleeper::new();
    let mut ignore = tdfu_core::progress::sink_ignore();
    dfu::host::reset_and_retry_once(device, &clock, &mut ignore, async |_attempt, _sink| Ok(())).await?;
    dfu::host::retry_stale_block0(device, 0, &mut ignore, async |_transaction, _sink| Ok(())).await
}
