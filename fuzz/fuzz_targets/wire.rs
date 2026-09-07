//! Everything a socket can hand the codec, in one target.
//!
//! The daemon parses a frame *before* any authentication on the HTTP transport,
//! and the browser flasher points a client at whatever host the user typed, so
//! both directions of this protocol read bytes from somewhere untrusted. A panic in here
//! is a remote denial of service; a mis-parse that still round-trips is worse, because it
//! reaches a device.
//!
//! The invariants asserted are the ones a fixture cannot cover exhaustively:
//!
//! 1. Nothing panics, whatever the input.
//! 2. Whatever decodes, **re-encodes** — the property a silent truncation breaks.
//! 3. Re-encoding is a fixed point: decoding it again yields the same value.
//!
//! The payload decoders are driven directly with the raw input as well as through a
//! whole frame, so the eight command layouts are reached without libFuzzer first having
//! to guess the four magic bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tdfu_proto::{
    Command, Crc32, DeviceEntry, HEADER_LEN, ProgressBody, Request, RequestHeader,
    ResponseHeader, WireVariant, crc32,
};

fuzz_target!(|data: &[u8]| {
    // A whole request frame, exactly as a reader would take it off the socket.
    if let Ok(header) = RequestHeader::decode(data) {
        let body = &data[HEADER_LEN..];
        check_request(header.command, body);
    }
    let _ = ResponseHeader::decode(data);

    // Each payload decoder on its own, so no command layout is gated behind the magic.
    for command in Command::ALL {
        check_request(command, data);
    }

    // The reply side: a client parses these from a daemon it does not control.
    if let Ok(entries) = DeviceEntry::decode_list(data) {
        assert_eq!(entries.len() * DeviceEntry::LEN, data.len());
        let re_encoded: Vec<u8> = entries.iter().flat_map(DeviceEntry::encode).collect();
        assert_eq!(re_encoded, data, "a device list did not survive re-encoding");
    }
    if let Ok(progress) = ProgressBody::decode(data) {
        let re_encoded = progress.encode().expect("a decoded progress body must re-encode");
        assert_eq!(re_encoded, data, "a progress body did not survive re-encoding");
    }

    // A name that resolves must resolve to an ordinal that has one.
    if let Ok(text) = core::str::from_utf8(data) {
        if let Some(variant) = WireVariant::from_name(text) {
            assert!(variant.name().is_some(), "{text:?} named an empty ordinal");
            assert!(variant.0 < WireVariant::COUNT);
        }
    }

    // Splitting the input never changes its checksum (`cli/remote.c:40`).
    if let Some(split) = data.first().map(|&at| usize::from(at) % (data.len() + 1)) {
        let (head, tail) = data.split_at(split);
        let mut hasher = Crc32::new();
        hasher.update(head);
        hasher.update(tail);
        assert_eq!(hasher.finalize(), crc32(data), "chunking changed a checksum");
    }
});

fn check_request(command: Command, payload: &[u8]) {
    let Ok(request) = Request::decode(command, payload) else {
        return;
    };
    assert_eq!(request.command(), command);

    // Nothing that came off the wire can be too long to put back on it.
    let re_encoded = request
        .encode()
        .expect("a decoded request must always encode");

    // ...and the second decode is the same value: the codec has one canonical form per
    // meaning, so a daemon that forwards what it parsed cannot change it.
    let again = Request::decode(command, &re_encoded).expect("a re-encoded request must decode");
    assert_eq!(again, request, "re-encoding changed the meaning");

    // The erase routing is the one decision here that destroys data. It is exact-length
    // in both halves; the C's `strcmp` on a NUL-terminated copy is not (`main.c:505`).
    if request.is_erase() {
        let Request::Write { alt, image, .. } = &request else {
            unreachable!("only a WRITE can be an erase");
        };
        assert_eq!(alt.as_slice(), tdfu_proto::ERASE_ALT);
        assert_eq!(image.as_slice(), tdfu_proto::ERASE_TOKEN);
    }
}
