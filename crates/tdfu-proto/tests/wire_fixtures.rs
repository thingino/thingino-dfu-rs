//! Byte-exact fixtures for every command's request payload and its OK/ERROR
//! reply.
//!
//! Each array below was written by hand from the C's own encoder or decoder and carries
//! the `file:line` it came from. That is the point of a fixture: a round-trip test only
//! proves this codec agrees with itself, and the protocol is a contract with something
//! else. The bytes are ours to change now, but only on purpose, which
//! is what a fixture makes visible in a diff.

use tdfu_proto::{
    Blobs, Command, DeviceEntry, ERASE_ALT, ERASE_TOKEN, ERROR_STRINGS, ProtoError, Request, RequestHeader,
    ResponseHeader, Status, WireVariant, crc32, verify_failed_message,
};

/// Encode a request and check it against the bytes the C would have put on the wire,
/// then decode those bytes back to the same value.
fn round_trip(request: &Request, expected: &[u8]) -> Result<(), ProtoError> {
    assert_eq!(request.encode()?, expected, "{request:?}");
    assert_eq!(&Request::decode(request.command(), expected)?, request);
    Ok(())
}

/// `DISCOVER`. Request: no payload. The OK payload is N × 8 bytes
/// (`protocol.h:69-76`, `dfu-remote/main.c:243-281`).
#[test]
fn rpc_discover_layout() -> Result<(), ProtoError> {
    round_trip(&Request::Discover, &[])?;

    let bootrom = DeviceEntry {
        bus: 1,
        address: 9,
        vendor: 0xA108,
        product: 0xC309,
        stage: 0,
        variant: WireVariant(50), // t32lq
    };
    let gadget = DeviceEntry {
        bus: 2,
        address: 17,
        vendor: 0xA108,
        product: 0xC309,
        stage: 2,
        variant: WireVariant::UNKNOWN,
    };
    assert_eq!(bootrom.encode(), [0x01, 0x09, 0xA1, 0x08, 0xC3, 0x09, 0x00, 0x32]);
    assert_eq!(gadget.encode(), [0x02, 0x11, 0xA1, 0x08, 0xC3, 0x09, 0x02, 0xFF]);

    let mut payload = bootrom.encode().to_vec();
    payload.extend_from_slice(&gadget.encode());
    assert_eq!(DeviceEntry::decode_list(&payload)?, vec![bootrom, gadget]);
    assert_eq!(DeviceEntry::decode_list(&[])?, vec![]);

    // A gadget of unknown SoC renders `unknown`, not the C's `t31x`
    // guess.
    assert_eq!(gadget.variant.name(), None);
    assert_eq!(gadget.variant.to_string(), "unknown");

    // A payload that does not divide into entries is a length mistake, not a shorter
    // list: the shipped web client drops the tail silently (`web/src/remote.js:166`).
    payload.push(0x00);
    assert_eq!(
        DeviceEntry::decode_list(&payload),
        Err(ProtoError::Malformed("partial device entry"))
    );

    // The ERROR payload here is the daemon's bare message, no length and no NUL
    // (`dfu-remote/main.c:235`). It is `tdfu-daemon`'s string, not this codec's, so it
    // is pinned where it is built; an assertion here could only compare this file to
    // itself.
    Ok(())
}

/// One entry is exactly eight bytes — not "at least eight".
///
/// Both guards below were **missed mutants** on the first mutation run: every test went
/// through `decode_list`, which only ever hands `decode` a whole chunk, so inverting
/// either comparison changed nothing that was measured. Under the inversion a seven-byte
/// buffer indexes past its end, which is the kind of hole a coverage number cannot see.
#[test]
fn a_device_entry_is_exactly_its_own_length() -> Result<(), ProtoError> {
    let entry = DeviceEntry {
        bus: 1,
        address: 2,
        vendor: 0xA108,
        product: 0xC309,
        stage: 1,
        variant: WireVariant(0),
    };
    let bytes = entry.encode();
    assert_eq!(DeviceEntry::decode(&bytes)?, entry);

    for len in 0..DeviceEntry::LEN {
        assert_eq!(DeviceEntry::decode(&bytes[..len]), Err(ProtoError::Truncated), "{len}");
    }
    let mut too_long = bytes.to_vec();
    too_long.push(0x00);
    assert_eq!(
        DeviceEntry::decode(&too_long),
        Err(ProtoError::Malformed("trailing bytes"))
    );
    Ok(())
}

/// `BOOTSTRAP`. `[idx][vlen][variant]`, optionally `[spl_len u32][spl][uboot_len][uboot]`
/// (`cli/remote.c:539-560`, `dfu-remote/main.c:357-400`).
#[test]
fn rpc_bootstrap_layout() -> Result<(), ProtoError> {
    round_trip(
        &Request::Bootstrap {
            index: 0,
            variant: b"t31n".to_vec(),
            blobs: None,
        },
        &[0x00, 0x04, b't', b'3', b'1', b'n'],
    )?;

    // An empty variant means "auto-detect" (`main.c:424`), and is not the same thing as
    // an unknown one.
    round_trip(
        &Request::Bootstrap {
            index: 3,
            variant: Vec::new(),
            blobs: None,
        },
        &[0x03, 0x00],
    )?;

    round_trip(
        &Request::Bootstrap {
            index: 1,
            variant: Vec::new(),
            blobs: Some(Blobs {
                spl: vec![0xAA, 0xBB],
                uboot: vec![0xCC],
            }),
        },
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x01, 0xCC,
        ],
    )?;

    // OK is the two bytes "OK" (`main.c:449`), built by `tdfu-daemon` and pinned there.
    // ERROR interpolates the error string (`main.c:446`).
    assert_eq!(
        format!("bootstrap failed: {}", ERROR_STRINGS[2]),
        "bootstrap failed: Device not found"
    );
    Ok(())
}

/// Both halves or neither, and either length 0 is an error
/// (`dfu-remote/main.c:385`, `:393`).
#[test]
fn rpc_bootstrap_blob_edges() {
    let empty_half = Request::Bootstrap {
        index: 0,
        variant: Vec::new(),
        blobs: Some(Blobs {
            spl: Vec::new(),
            uboot: vec![1],
        }),
    };
    assert_eq!(empty_half.encode(), Err(ProtoError::EmptyBlob { field: "spl" }));

    let zero_length_on_the_wire = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        Request::decode(Command::Bootstrap, &zero_length_on_the_wire),
        Err(ProtoError::Malformed("bad SPL override"))
    );
    // A length that promises more than arrived.
    assert_eq!(
        Request::decode(Command::Bootstrap, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01]),
        Err(ProtoError::Malformed("bad SPL override"))
    );
    // The SPL arrives whole and the U-Boot half is missing.
    assert_eq!(
        Request::decode(Command::Bootstrap, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA]),
        Err(ProtoError::Malformed("bad U-Boot override length"))
    );
    assert_eq!(
        Request::decode(
            Command::Bootstrap,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00]
        ),
        Err(ProtoError::Malformed("bad U-Boot override"))
    );
}

/// `WRITE`. `[idx][vlen][variant][alen][alt][fw_len u32][fw][crc32 u32][verify?]`
/// (`cli/remote.c:617-637`, `dfu-remote/main.c:451-495`).
#[test]
fn rpc_write_layout() -> Result<(), ProtoError> {
    let image = b"hello".to_vec();
    let crc = crc32(&image);
    assert_eq!(crc, 0x3610_A686);

    round_trip(
        &Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: b"kernel".to_vec(),
            image: image.clone(),
            crc32: crc,
            verify: Some(true),
        },
        &[
            0x00, 0x00, // index, no variant
            0x06, b'k', b'e', b'r', b'n', b'e', b'l', // alt
            0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o', // image
            0x36, 0x10, 0xA6, 0x86, // crc32, big-endian
            0x01, // verify
        ],
    )?;

    // The web client always sends alen = 0 and no verify byte
    // (`web/src/remote.js:236`, `:249`).
    round_trip(
        &Request::Write {
            index: 0,
            variant: Vec::new(),
            alt: Vec::new(),
            image: Vec::new(),
            crc32: 0,
            verify: None,
        },
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    )?;

    // `verify` present-and-zero is not the same value as absent. The C collapses them
    // (`main.c:492` reads `*p != 0`); keeping them apart is what the contract kept.
    let present_zero = Request::decode(
        Command::Write,
        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    )?;
    assert!(matches!(
        present_zero,
        Request::Write {
            verify: Some(false),
            ..
        }
    ));

    // ERROR strings (`main.c:590`, `:592`).
    assert_eq!(verify_failed_message(0x1234), "verify failed at offset 0x00001234");
    assert_eq!(
        format!("write failed: {}", ERROR_STRINGS[4]),
        "write failed: Transfer failed"
    );
    Ok(())
}

/// The erase routing, and the exact-length comparison it turns on.
#[test]
fn rpc_write_erase_token() -> Result<(), ProtoError> {
    assert_eq!(ERASE_ALT, b"erase");
    assert_eq!(ERASE_TOKEN, b"XBURST-FLASH-WIPE");
    assert_eq!(ERASE_TOKEN.len(), 17, "`dfu.h:74`");

    let erase = |alt: &[u8], image: &[u8]| Request::Write {
        index: 0,
        variant: Vec::new(),
        alt: alt.to_vec(),
        image: image.to_vec(),
        crc32: crc32(image),
        verify: None,
    };

    assert!(erase(ERASE_ALT, ERASE_TOKEN).is_erase());

    // The C copies the alt into a NUL-terminated buffer and `strcmp`s it
    // (`dfu-remote/main.c:477`, `:505`), so every one of these wipes the chip there.
    // Reproducing that would *widen* the set of payloads that erase a flash.
    for alt in [
        b"erase\0junk".as_slice(),
        b"erase\0",
        b"erase ",
        b"eras",
        b"erased",
        b"ERASE",
        b"",
    ] {
        assert!(!erase(alt, ERASE_TOKEN).is_erase(), "alt {alt:?} must not erase");
    }
    // The token is compared whole too - the C already does (`:506` guards `memcmp`
    // with a `strlen` equality), so there is no bug to avoid, only one to keep out.
    for image in [
        b"XBURST-FLASH-WIPE\0".as_slice(),
        b"XBURST-FLASH-WIP",
        b"XBURST-FLASH-WIPED",
        b"xburst-flash-wipe",
        b"",
    ] {
        assert!(!erase(ERASE_ALT, image).is_erase(), "image {image:?} must not erase");
    }

    // And the whole erase frame, byte for byte (`cli/remote.c:688`).
    let mut expected = vec![0x00, 0x00, 0x05];
    expected.extend_from_slice(ERASE_ALT);
    expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x11]);
    expected.extend_from_slice(ERASE_TOKEN);
    expected.extend_from_slice(&crc32(ERASE_TOKEN).to_be_bytes());
    round_trip(&erase(ERASE_ALT, ERASE_TOKEN), &expected)?;
    Ok(())
}

/// `READ`. `[idx][vlen][variant]` and an **optional** `[alen][alt]`
/// (`dfu-remote/main.c:604-631`; the web client omits it, `web/src/remote.js:219`).
#[test]
fn rpc_read_layout() -> Result<(), ProtoError> {
    round_trip(
        &Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: None,
        },
        &[0x00, 0x00],
    )?;
    round_trip(
        &Request::Read {
            index: 2,
            variant: b"t41nq".to_vec(),
            alt: Some(b"all".to_vec()),
        },
        &[0x02, 0x05, b't', b'4', b'1', b'n', b'q', 0x03, b'a', b'l', b'l'],
    )?;
    // An alt field that is present and empty is not the same as no alt field, and both
    // mean "the default alt" to the daemon (`main.c:660`). The wire keeps them apart, so
    // this codec does.
    round_trip(
        &Request::Read {
            index: 0,
            variant: Vec::new(),
            alt: Some(Vec::new()),
        },
        &[0x00, 0x00, 0x00],
    )?;

    // The OK payload is `[data][crc32 u32 BE]` (`main.c:700-716`, `remote.js:222`).
    let data = b"\x01\x02\x03\x04".to_vec();
    let mut ok = data.clone();
    ok.extend_from_slice(&crc32(&data).to_be_bytes());
    assert_eq!(ok, [0x01, 0x02, 0x03, 0x04, 0xB6, 0x3C, 0xFB, 0xCD]);
    assert_eq!(crc32(&data), 0xB63C_FBCD);
    Ok(())
}

/// `STATUS`: no payload, and the OK payload is one of six state strings
/// (`dfu-remote/main.c:63`, `:733`).
#[test]
fn rpc_status_strings() -> Result<(), ProtoError> {
    round_trip(&Request::Status, &[])?;
    // The six state strings are `tdfu-daemon`'s and are pinned there. Repeating them
    // here would assert this file against itself: a rename or a NUL added over there
    // would leave every assertion in this test passing.
    Ok(())
}

/// `CANCEL`: no payload, OK is `"OK"` (`dfu-remote/main.c:737`).
#[test]
fn rpc_cancel_reply() -> Result<(), ProtoError> {
    round_trip(&Request::Cancel, &[])?;
    Ok(())
}

/// `DIAG`: `[idx]`, or an empty payload meaning device 0
/// (`dfu-remote/main.c:744`).
#[test]
fn rpc_diag_layout() -> Result<(), ProtoError> {
    round_trip(&Request::Diag { index: 0 }, &[0x00])?;
    round_trip(&Request::Diag { index: 7 }, &[0x07])?;
    assert_eq!(
        Request::decode(Command::Diag, &[])?,
        Request::Diag { index: 0 },
        "an empty DIAG payload is device 0"
    );

    // The OK payload is the formatted text and nothing else - no length, no header, no
    // NUL. The web shows it verbatim (`web/src/app.js` via `remote.js:181`). The text is
    // `tdfu-daemon`'s and is pinned there; a literal written out here would only be
    // compared with itself.

    // ERROR is the bare error string - no "diag failed:" prefix (`main.c:757`).
    assert_eq!(ERROR_STRINGS[6], "Invalid parameter");
    Ok(())
}

/// `REBOOT`: `[idx]`, and the OK carries **no** payload — the only command whose OK
/// is not `"OK"` (`dfu-remote/main.c:775`).
#[test]
fn rpc_reboot_empty_ok() -> Result<(), ProtoError> {
    round_trip(&Request::Reboot { index: 0 }, &[0x00])?;
    round_trip(&Request::Reboot { index: 1 }, &[0x01])?;
    assert_eq!(Request::decode(Command::Reboot, &[])?, Request::Reboot { index: 0 });

    let ok = ResponseHeader {
        status: Status::Ok,
        payload_len: 0,
    };
    assert_eq!(
        ok.encode(),
        [b'T', b'D', b'F', b'U', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(ResponseHeader::decode(&ok.encode())?.payload_len, 0);
    Ok(())
}

/// Thirteen error strings, in the order `tdfu_error_to_string` returns them
/// (`libtdfu/src/utils.c:258-303`).
#[test]
fn rpc_error_strings() {
    assert_eq!(
        ERROR_STRINGS,
        [
            "Success",
            "Initialization failed",
            "Device not found",
            "Failed to open device",
            "Transfer failed",
            "Timeout",
            "Invalid parameter",
            "Memory allocation failed",
            "File I/O error",
            "Protocol error",
            "Transfer timeout",
            "Verify failed (read-back mismatch)",
            "Unknown error",
        ]
    );
}

/// A whole frame: header then payload, as a reader sees it.
#[test]
fn a_command_frame_end_to_end() -> Result<(), ProtoError> {
    let request = Request::Diag { index: 2 };
    let payload = request.encode()?;
    let header = RequestHeader {
        command: request.command(),
        payload_len: u32::try_from(payload.len()).unwrap_or(u32::MAX),
    };
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&payload);
    assert_eq!(
        frame,
        [b'T', b'D', b'F', b'U', 0x01, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02]
    );

    let decoded_header = RequestHeader::decode(&frame)?;
    let body = &frame[tdfu_proto::HEADER_LEN..];
    assert_eq!(body.len(), decoded_header.payload_len as usize);
    assert_eq!(Request::decode(decoded_header.command, body)?, request);
    Ok(())
}

/// The wire wording for a failed verify is not the local one,
/// and it is uppercase and zero-padded (`dfu-remote/main.c:590`).
#[test]
fn the_wire_verify_string_is_not_a_local_one() {
    assert_eq!(verify_failed_message(0), "verify failed at offset 0x00000000");
    assert_eq!(verify_failed_message(0xDEAD_BEEF), "verify failed at offset 0xDEADBEEF");
    assert_eq!(
        verify_failed_message(0x1_0000_0000),
        "verify failed at offset 0x100000000",
        "wider than eight digits when the offset needs it"
    );
    let wire = verify_failed_message(0xAB);
    assert!(!wire.contains("0xab"), "lowercase hex is the local wording");
    assert_ne!(wire, ERROR_STRINGS[11], "the string is a third wording again");
}
