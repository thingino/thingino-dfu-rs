//! Properties over arbitrary bytes.
//!
//! A codec's contract with the world is not "these fixtures round-trip" but "no input
//! makes it misbehave". Everything a network hands this crate is attacker-shaped: the
//! daemon parses it before any authentication on the HTTP transport, so a
//! panic here is a remote denial of service, and a *silent* mis-parse is worse.
//!
//! The invariant worth naming: **whatever decodes, re-encodes.** That is what a silent
//! truncation would break, and it holds for every input in the state space rather than
//! the handful a fixture can list.

use proptest::prelude::*;
use tdfu_proto::{
    Command, Crc32, DeviceEntry, ERASE_ALT, ERASE_TOKEN, MAX_PAYLOAD, ProgressBody, Request, RequestHeader,
    ResponseHeader, Status, WireVariant, crc32,
};

/// Every command byte, for a decoder that must survive being handed the wrong one.
fn any_command() -> impl Strategy<Value = Command> {
    prop::sample::select(Command::ALL.to_vec())
}

fn any_status() -> impl Strategy<Value = Status> {
    prop::sample::select(Status::ALL.to_vec())
}

/// Strings to hand [`WireVariant::from_name`], weighted towards the ones that decide
/// anything.
///
/// A bare `".{0,16}"` is 16 random code points: it will not produce `"t31x"` this side of
/// the heat death of the universe, so every assertion about a *near miss* of a real name
/// would go unexercised. The literals are the interesting neighbourhood — real names,
/// case variants, the three input-only aliases, and strings one character away from a
/// name, which is exactly where a `from_name` that compared a prefix or lowercased one
/// side would answer wrongly.
fn a_variant_name() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::sample::select(vec![
            // Real table names, first / middle / last, plus the aliases.
            "t10", "t31x", "t41_ddr3", "a1n", "c100", "t41zn", "t40nn",
            // Case, which `from_name` accepts.
            "T31X", "T41_DDR3", "C100",
        ])
        .prop_map(str::to_owned),
        3 => prop::sample::select(vec![
            // One character away from a real name, in every direction that matters.
            "t1", "t10x", "t10 ", " t10", "t31", "t31xx", "a1nn", "c10", "t41_ddr", "",
            // Whole-string matching means an embedded NUL never resolves either.
            "t31x\0", "\0t31x",
        ])
        .prop_map(str::to_owned),
        1 => ".{0,16}".prop_map(|name: String| name),
    ]
}

proptest! {
    /// No payload, for any command, makes the decoder panic — and anything it accepts,
    /// it can put back on the wire unchanged.
    #[test]
    fn decoding_arbitrary_payloads_never_panics(
        command in any_command(),
        payload in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Ok(request) = Request::decode(command, &payload) {
            prop_assert_eq!(request.command(), command);
            let re_encoded = request.encode().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let again = Request::decode(command, &re_encoded);
            prop_assert_eq!(again.as_ref(), Ok(&request), "re-encoding changed the meaning");
        }
    }

    /// A `WRITE` payload is the one an attacker gets to make big, and the one whose
    /// misparse writes to a device. Bias the generator towards its shape so the
    /// interesting branches are actually reached.
    #[test]
    fn write_payloads_survive_arbitrary_lengths(
        index in any::<u8>(),
        variant in prop::collection::vec(any::<u8>(), 0..8),
        alt in prop::collection::vec(any::<u8>(), 0..8),
        image in prop::collection::vec(any::<u8>(), 0..64),
        declared_len in prop_oneof![0..80_u32, any::<u32>()],
        tail in prop::collection::vec(any::<u8>(), 0..3),
    ) {
        let mut payload = vec![index];
        payload.push(u8::try_from(variant.len()).unwrap_or(0));
        payload.extend_from_slice(&variant);
        payload.push(u8::try_from(alt.len()).unwrap_or(0));
        payload.extend_from_slice(&alt);
        payload.extend_from_slice(&declared_len.to_be_bytes());
        payload.extend_from_slice(&image);
        payload.extend_from_slice(&tail);

        if let Ok(request) = Request::decode(Command::Write, &payload) {
            // A declared length that lied cannot have produced a `Write`.
            let Request::Write { image: decoded, .. } = &request else {
                return Err(TestCaseError::fail("a WRITE payload decoded as something else"));
            };
            prop_assert_eq!(Ok(decoded.len()), usize::try_from(declared_len));
            let re_encoded = request.encode().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let again = Request::decode(Command::Write, &re_encoded);
            prop_assert_eq!(again.as_ref(), Ok(&request));
        }
    }

    /// Headers: never a panic, and a legal one round-trips.
    #[test]
    fn decoding_arbitrary_headers_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..24)) {
        let _ = RequestHeader::decode(&bytes);
        let _ = ResponseHeader::decode(&bytes);
    }

    #[test]
    fn header_round_trip(
        command in any_command(),
        status in any_status(),
        payload_len in 0..=MAX_PAYLOAD,
    ) {
        let request = RequestHeader { command, payload_len };
        let decoded = RequestHeader::decode(&request.encode());
        prop_assert_eq!(decoded, Ok(request));
        let response = ResponseHeader { status, payload_len };
        let decoded = ResponseHeader::decode(&response.encode());
        prop_assert_eq!(decoded, Ok(response));
    }

    /// The `DISCOVER` reply and the `PROGRESS` body are parsed by clients, which are no
    /// less exposed than the daemon: a hostile daemon is a plausible thing to be pointed
    /// at by a URL.
    #[test]
    fn decoding_arbitrary_replies_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(entries) = DeviceEntry::decode_list(&bytes) {
            prop_assert_eq!(entries.len() * DeviceEntry::LEN, bytes.len());
            let re_encoded: Vec<u8> =
                entries.iter().flat_map(DeviceEntry::encode).collect();
            prop_assert_eq!(re_encoded, bytes.clone());
        }
        if let Ok(progress) = ProgressBody::decode(&bytes) {
            let re_encoded = progress.encode().map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(re_encoded, bytes.clone());
        }
    }

    /// A request built from values in range always encodes, and always comes back.
    #[test]
    fn well_formed_requests_round_trip(
        index in any::<u8>(),
        variant in prop::collection::vec(any::<u8>(), 0..=255),
        alt in prop::collection::vec(any::<u8>(), 0..=255),
        image in prop::collection::vec(any::<u8>(), 0..128),
        verify in any::<Option<bool>>(),
        alt_present in any::<bool>(),
        blobs in any::<bool>(),
    ) {
        let crc = crc32(&image);
        let requests = [
            Request::Discover,
            Request::Status,
            Request::Cancel,
            Request::Diag { index },
            Request::Reboot { index },
            Request::Bootstrap {
                index,
                variant: variant.clone(),
                blobs: blobs.then(|| tdfu_proto::Blobs {
                    spl: vec![0xAA; 3],
                    uboot: vec![0xBB; 5],
                }),
            },
            Request::Read {
                index,
                variant: variant.clone(),
                alt: alt_present.then(|| alt.clone()),
            },
            Request::Write {
                index,
                variant,
                alt,
                image,
                crc32: crc,
                verify,
            },
        ];
        for request in requests {
            let bytes = request.encode().map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded = Request::decode(request.command(), &bytes);
            prop_assert_eq!(decoded.as_ref(), Ok(&request));
        }
    }

    /// The erase routing is exact-length in both halves, whatever is thrown at it. The C
    /// `strcmp`s a NUL-terminated copy of the alt, so `"erase\0…"` wipes a chip there
    /// (`dfu-remote/main.c:505`); that is not copied here.
    #[test]
    fn only_the_exact_erase_pair_erases(
        alt in prop::collection::vec(any::<u8>(), 0..24),
        image in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        let request = Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: alt.clone(),
            image: image.clone(),
            crc32: 0,
            verify: None,
        };
        prop_assert_eq!(
            request.is_erase(),
            alt.as_slice() == ERASE_ALT && image.as_slice() == ERASE_TOKEN
        );
    }

    /// A name is matched whole, and a lookup of an arbitrary string never panics.
    ///
    /// Both arms cross-check `from_name` against `name()` and the table bound, in
    /// opposite directions. The `None` arm used to re-call `from_name` and assert it was
    /// still `None`, which is what reaching that arm already proved: `from_name` is pure
    /// — it lowercases its argument and searches two immutable tables — so the second
    /// call could not answer differently, and the assertion held for *any*
    /// implementation.
    #[test]
    fn variant_lookup_is_total(name in a_variant_name()) {
        match WireVariant::from_name(&name) {
            Some(variant) => {
                let resolved = variant.name();
                prop_assert!(resolved.is_some(), "an ordinal from a name must have one");
                prop_assert!(variant.0 < WireVariant::COUNT);
                // Whole-string matching, the other half of the same rule: whatever came
                // back is spelled exactly like the input (case aside), or the input is
                // one of the three documented input-only aliases. A `from_name` that
                // matched a prefix or a suffix, or that stopped at an embedded NUL,
                // lands here with neither.
                let same = resolved.is_some_and(|canonical| canonical.eq_ignore_ascii_case(&name));
                let alias = ["c100", "t41zn", "t40nn"]
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&name));
                prop_assert!(
                    same || alias,
                    "from_name({:?}) gave ordinal {} which is called {:?}",
                    name,
                    variant.0,
                    resolved
                );
            }
            None => {
                // A refusal has to survive the table read the other way round: if
                // `from_name` will not place this string, then no ordinal answers to it
                // either. A `from_name` that skipped an entry, compared a prefix, or
                // lowercased only one side would land here with a name that `name()`
                // still spells.
                for ordinal in 0..WireVariant::COUNT {
                    if let Some(canonical) = WireVariant(ordinal).name() {
                        prop_assert!(
                            !canonical.eq_ignore_ascii_case(&name),
                            "from_name refused {:?}, but ordinal {} is called {:?}",
                            name,
                            ordinal,
                            canonical
                        );
                    }
                }
            }
        }
    }

    /// Chunking never changes a checksum, whatever the pieces are.
    #[test]
    fn crc32_is_chunk_independent(pieces in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..64),
        0..8,
    )) {
        let whole: Vec<u8> = pieces.concat();
        let mut hasher = Crc32::new();
        for piece in &pieces {
            hasher.update(piece);
        }
        prop_assert_eq!(hasher.finalize(), crc32(&whole));
    }
}
