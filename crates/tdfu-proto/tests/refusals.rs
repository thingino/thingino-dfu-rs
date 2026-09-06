//! What the codec refuses, and with which words.
//!
//! Two rules learned from an earlier implementation are pinned here and nowhere else:
//!
//! * **Nothing is ever truncated to fit.** `Request::encode` returns an error naming the
//!   field and its length. The earlier one returned a `Vec<u8>` and quietly shortened a
//!   300-byte `--alt` into a different, valid 255-byte one — a write to the wrong
//!   partition, reported as a success.
//! * **A refusal that the peer must not hear says so.** `ProtoError::wire_message` is
//!   `None` for every error that is this side's business.

use tdfu_proto::{Blobs, Command, ProtoError, Request};

fn variant_only(command: Command, payload: &[u8]) -> Result<Request, ProtoError> {
    Request::decode(command, payload)
}

/// The three commands that begin `[idx][vlen][variant]` refuse the same three ways, with
/// the C's wording (`dfu-remote/main.c:359`/`:367`, `:453`/`:461`, `:606`/`:614`).
#[test]
fn a_short_or_overrunning_head_is_refused() {
    for command in [Command::Bootstrap, Command::Write, Command::Read] {
        assert_eq!(
            variant_only(command, &[]),
            Err(ProtoError::Malformed("payload too short")),
            "{command:?}"
        );
        assert_eq!(
            variant_only(command, &[0x00]),
            Err(ProtoError::Malformed("payload too short")),
            "{command:?}"
        );
        assert_eq!(
            variant_only(command, &[0x00, 0x08, b't', b'3', b'1']),
            Err(ProtoError::Malformed("bad variant length")),
            "{command:?}"
        );
    }
}

/// `WRITE`'s own layout, field by field (`dfu-remote/main.c:471-486`).
#[test]
fn a_write_payload_is_refused_field_by_field() {
    let cases: [(&[u8], &str); 5] = [
        (&[0x00, 0x00], "missing alt field"),
        (&[0x00, 0x00, 0x04, b'a'], "bad alt length"),
        (&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01], "missing firmware length"),
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01],
            "firmware data truncated",
        ),
        // The image arrives whole and the CRC does not: the C tests them together.
        (
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00],
            "firmware data truncated",
        ),
    ];
    for (payload, message) in cases {
        assert_eq!(
            Request::decode(Command::Write, payload),
            Err(ProtoError::Malformed(message)),
            "{payload:?}"
        );
    }
}

/// A payload that parses *and* has a tail is a length mistake. The C stops reading and
/// ignores the rest; this codec says so. Nothing sends a tail today.
#[test]
fn bytes_left_over_are_refused() {
    let trailing = Err(ProtoError::Malformed("trailing bytes"));
    // The commands that take no payload at all.
    for command in [Command::Discover, Command::Status, Command::Cancel] {
        assert_eq!(Request::decode(command, &[0x00]), trailing, "{command:?}");
    }
    // One index byte and no more.
    for command in [Command::Diag, Command::Reboot] {
        assert_eq!(Request::decode(command, &[0x00, 0x00]), trailing, "{command:?}");
    }
    // READ: an alt field, then junk.
    assert_eq!(
        Request::decode(Command::Read, &[0x00, 0x00, 0x01, b'a', 0xFF]),
        trailing
    );
    // WRITE: the verify byte is the last byte there is.
    assert_eq!(
        Request::decode(
            Command::Write,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
            ]
        ),
        trailing
    );
    // BOOTSTRAP: both override halves, then junk.
    assert_eq!(
        Request::decode(
            Command::Bootstrap,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x01, 0xBB, 0xCC
            ]
        ),
        trailing
    );
}

/// The scenario that motivated the refusal: a 300-byte `--alt`. An earlier
/// implementation put 255 of those bytes on the wire and called it success.
#[test]
fn an_over_long_field_is_an_error_not_a_shorter_field() {
    let long_alt = vec![b'x'; 300];
    let request = Request::Write {
        index: 0,
        variant: Vec::new(),
        alt: long_alt.clone(),
        image: Vec::new(),
        crc32: 0,
        verify: None,
    };
    assert_eq!(
        request.encode(),
        Err(ProtoError::FieldTooLong {
            field: "alt",
            len: 300,
            max: 255
        })
    );

    // 255 is still legal; 256 is not. The boundary is where a truncation would start.
    for (len, expected_ok) in [(0_usize, true), (255, true), (256, false)] {
        let request = Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: vec![b'x'; len],
            image: Vec::new(),
            crc32: 0,
            verify: None,
        };
        assert_eq!(request.encode().is_ok(), expected_ok, "alt of {len} bytes");
    }

    // The same rule on every `u8`-prefixed field, on every command that has one.
    let long = vec![b'x'; 256];
    let too_long = |field| {
        Err(ProtoError::FieldTooLong {
            field,
            len: 256,
            max: 255,
        })
    };
    assert_eq!(
        Request::Bootstrap {
            index: 0,
            variant: long.clone(),
            blobs: None
        }
        .encode(),
        too_long("variant")
    );
    assert_eq!(
        Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: Some(long.clone())
        }
        .encode(),
        too_long("alt")
    );
    assert_eq!(
        Request::Write {
            index: 0,
            variant: long,
            alt: Vec::new(),
            image: Vec::new(),
            crc32: 0,
            verify: None
        }
        .encode(),
        too_long("variant")
    );
}

/// An encode refusal is never a reply: there is no frame to reply to.
#[test]
fn an_encode_refusal_has_no_wire_wording() {
    let refusals = [
        Request::Write {
            index: 0,
            variant: vec![b'x'; 256],
            alt: Vec::new(),
            image: Vec::new(),
            crc32: 0,
            verify: None,
        },
        Request::Bootstrap {
            index: 0,
            variant: Vec::new(),
            blobs: Some(Blobs {
                spl: vec![1],
                uboot: Vec::new(),
            }),
        },
    ];
    for request in refusals {
        let error = request.encode().err();
        assert!(error.is_some(), "{request:?}");
        assert_eq!(error.and_then(|e| e.wire_message()), None, "{request:?}");
    }

    // Every decode refusal, by contrast, has something to send back.
    for payload in [&[][..], &[0x00], &[0x00, 0x00, 0x04, b'a']] {
        if let Err(error) = Request::decode(Command::Write, payload) {
            assert!(error.wire_message().is_some(), "{payload:?} -> {error}");
        }
    }
}

/// **The parse-desync, the one named C bug this codec removes, in its grave.**
///
/// `handle_write` and `handle_read` copy the variant into a 64-byte buffer and then
/// advance the payload cursor by the **clamped** length (`dfu-remote/main.c:465-468`,
/// `:617-621`), while `handle_bootstrap` advances by the true one (`:370-373`). So on two
/// of the three commands a variant of 64 bytes or more shifts every field after it: the
/// variant's 64th byte becomes the `alen` prefix, the alt becomes whatever follows, and
/// the length that used to be the image's is read from the middle of something else. The
/// catastrophic form is silent, because a shifted `alt` can be another alt the loader
/// really has, and the firmware then lands on a different partition and is reported as a
/// success.
///
/// `Reader` has one cursor and no clamp anywhere in `Request::decode`. The proptest
/// `well_formed_requests_round_trip` draws its variant from `0..=255` and would fail on a
/// clamping decoder too, but probabilistically and under a name that says nothing about
/// this. These are the two boundary lengths, deterministic, on both affected commands.
#[test]
fn rpc_a_long_variant_does_not_desync_the_fields() -> Result<(), ProtoError> {
    let image = b"abcd".to_vec();
    for length in [64_usize, 255] {
        // The last byte of the variant is what a clamped cursor reads as `alen`, and it
        // is deliberately not the `alen` this payload carries.
        let mut variant = vec![b'v'; length - 1];
        variant.push(0x7F);

        let write = Request::Write {
            index: 3,
            variant: variant.clone(),
            alt: b"flash".to_vec(),
            image: image.clone(),
            crc32: 0xDEAD_BEEF,
            verify: Some(true),
        };
        let payload = write.encode()?;
        // The layout, so the clamp's landing site is visible rather than argued:
        // `[idx][vlen][variant …][alen][alt]`.
        assert_eq!(payload[0], 3, "{length}");
        assert_eq!(usize::from(payload[1]), length, "{length}");
        assert_eq!(payload[1 + length], 0x7F, "the byte a clamped cursor reads as alen");
        assert_eq!(payload[2 + length], 5, "the alen this payload really carries");
        assert_eq!(
            Request::decode(Command::Write, &payload)?,
            write,
            "WRITE, {length}-byte variant"
        );

        let read = Request::Read {
            index: 3,
            variant,
            alt: Some(b"flash".to_vec()),
        };
        assert_eq!(
            Request::decode(Command::Read, &read.encode()?)?,
            read,
            "READ, {length}-byte variant"
        );
    }
    Ok(())
}

/// Whatever a decoder accepted, the encoder can put back. There is no shape on this wire
/// that parses and then cannot be re-sent — which is the invariant a silent truncation
/// would break.
#[test]
fn anything_decoded_can_be_encoded_again() -> Result<(), ProtoError> {
    let payloads: [(Command, &[u8]); 8] = [
        (Command::Discover, &[]),
        (Command::Status, &[]),
        (Command::Cancel, &[]),
        (Command::Diag, &[0x02]),
        (Command::Reboot, &[]),
        (Command::Bootstrap, &[0x00, 0xFF, 0x41]),
        (Command::Read, &[0x01, 0x00, 0x00]),
        (
            Command::Write,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00],
        ),
    ];
    for (command, payload) in payloads {
        // A variant field of 0xFF bytes cannot fit `payload` above, so build the legal
        // ones only; the point is that `decode` -> `encode` never fails.
        let Ok(request) = Request::decode(command, payload) else {
            continue;
        };
        let re_encoded = request.encode()?;
        assert_eq!(Request::decode(command, &re_encoded)?, request, "{command:?}");
    }
    Ok(())
}
