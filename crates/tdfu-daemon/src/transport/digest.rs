//! SHA-1 and base64, for the `Sec-WebSocket-Accept` header and nothing else.
//!
//! **Why this is not two dependencies.** `deny.toml` sets `multiple-versions = "deny"`,
//! which makes every added crate a standing liability the whole workspace pays for, and
//! this is ~90 lines of pure function with published test vectors. It is also not a
//! security primitive: RFC 6455 §1.3's accept key proves to the client that the server
//! understood the upgrade — it authenticates nothing and protects no secret. (The thing
//! that *is* a security primitive here, the token comparison, lives in
//! [`crate::auth`] and is written for constant time.) The C reaches the same conclusion
//! and ships the same two functions inline (`dfu-remote/ws.c:56-167`, "Self-contained: a
//! tiny SHA-1 + base64 for the handshake accept key").
//!
//! Both are pinned against their standards' own vectors: FIPS 180-1 for SHA-1, RFC 4648
//! §10 for base64, and RFC 6455 §1.3's worked handshake for the pair of them.

/// The RFC 6455 §1.3 GUID appended to the client's key before hashing.
pub(crate) const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `base64(sha1(key + GUID))` — the value of `Sec-WebSocket-Accept`.
pub(crate) fn accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64(&hasher.finish())
}

/// SHA-1 (FIPS 180-1), streaming.
#[derive(Debug)]
struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    used: usize,
    length: u64,
}

impl Sha1 {
    const fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            block: [0; 64],
            used: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        while !input.is_empty() {
            let take = (64 - self.used).min(input.len());
            let (head, tail) = input.split_at(take);
            if let Some(slot) = self.block.get_mut(self.used..self.used + take) {
                slot.copy_from_slice(head);
            }
            self.used += take;
            input = tail;
            if self.used == 64 {
                let block = self.block;
                compress(&mut self.state, &block);
                self.used = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 20] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.used != 56 {
            self.update(&[0x00]);
        }
        self.update(&bits.to_be_bytes());

        let mut out = [0_u8; 20];
        for (slot, word) in out.chunks_exact_mut(4).zip(self.state) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// One 64-byte block into the state.
///
/// FIPS 180-1 §7 names the five working variables a, b, c, d, e, and this loop is checked
/// against that text. Renaming them would make it harder to verify, not easier to read.
#[allow(clippy::many_single_char_names, reason = "FIPS 180-1 §7's own names")]
fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut schedule = [0_u32; 80];
    for (word, bytes) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap_or([0; 4]));
    }
    for index in 16..80 {
        let mixed = word_at(&schedule, index - 3)
            ^ word_at(&schedule, index - 8)
            ^ word_at(&schedule, index - 14)
            ^ word_at(&schedule, index - 16);
        if let Some(slot) = schedule.get_mut(index) {
            *slot = mixed.rotate_left(1);
        }
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (index, &word) in schedule.iter().enumerate() {
        // **The `|`s here are equivalent to `^`, and that is recorded rather than
        // re-derived.** `cargo mutants` replaces each of them and every
        // replacement survives, because:
        //
        // * `Ch = (b & c) | (!b & d)` has **disjoint** operands, so at every bit at most
        //   one side is set and `|` and `^` agree by construction.
        // * `Maj = (b & c) | (b & d) | (c & d)` agrees with `^` on all eight input
        //   combinations for **either** of its two operators. `^` binds tighter than `|`,
        //   so the mutants are `((b&c) ^ (b&d)) | (c&d)` and `(b&c) | ((b&d) ^ (c&d))`;
        //   both match the full truth table, since the exclusive-or of the three pairwise
        //   ANDs is the majority function.
        //
        // FIPS 180-1 writes them with `|`; they stay that way because that is the
        // standard's text, not because a test can tell.
        let (mixed, constant) = match index {
            0..20 => ((b & c) | (!b & d), 0x5A82_7999),
            20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(mixed)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }

    let [s0, s1, s2, s3, s4] = *state;
    *state = [
        s0.wrapping_add(a),
        s1.wrapping_add(b),
        s2.wrapping_add(c),
        s3.wrapping_add(d),
        s4.wrapping_add(e),
    ];
}

/// A schedule word, or zero — the index is always in range by construction, and this is
/// how that is expressed without a panicking form.
fn word_at(schedule: &[u32; 80], index: usize) -> u32 {
    schedule.get(index).copied().unwrap_or(0)
}

/// Standard base64 with padding (RFC 4648 §4).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for group in input.chunks(3) {
        let (first, second, third) = (
            u32::from(group.first().copied().unwrap_or(0)),
            u32::from(group.get(1).copied().unwrap_or(0)),
            u32::from(group.get(2).copied().unwrap_or(0)),
        );
        // Three disjoint byte lanes, so both `|`s are equivalent to `^` and both mutants
        // survive by construction (the same note as the SHA-1 rounds).
        let packed = (first << 16) | (second << 8) | third;
        let symbol = |shift: u32| char::from(ALPHABET[((packed >> shift) & 63) as usize]);
        out.push(symbol(18));
        out.push(symbol(12));
        out.push(if group.len() > 1 { symbol(6) } else { '=' });
        out.push(if group.len() > 2 { symbol(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Sha1, accept_key, base64};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut text, byte| {
            use core::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn sha1(input: &[u8]) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(input);
        hasher.finish()
    }

    /// FIPS 180-1's own vectors, plus the empty string.
    #[test]
    fn sha1_matches_the_published_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // A million 'a': the vector that catches a wrong length counter or a bad
        // multi-block carry.
        assert_eq!(
            hex(&sha1(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    /// The padding boundaries: 55 bytes fits the length in the same block, 56 forces a
    /// second one, 64 is exactly one block.
    #[test]
    fn sha1_pads_across_a_block_boundary() {
        assert_eq!(hex(&sha1(&[b'a'; 55])), "c1c8bbdc22796e28c0e15163d20899b65621d65a");
        assert_eq!(hex(&sha1(&[b'a'; 56])), "c2db330f6083854c99d4b5bfb6e8f29f201be699");
        assert_eq!(hex(&sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
    }

    /// Streaming in awkward pieces must equal hashing in one go.
    #[test]
    fn sha1_is_the_same_however_it_is_fed() {
        let message: Vec<u8> = (0..=255_u8).cycle().take(1000).collect();
        let whole = sha1(&message);
        for piece in [1_usize, 3, 7, 63, 64, 65, 127] {
            let mut hasher = Sha1::new();
            for chunk in message.chunks(piece) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finish(), whole, "in {piece}-byte pieces");
        }
    }

    /// RFC 4648 §10, whose vectors are the prefixes of one word — so the table is written
    /// as prefixes, which also makes the three padding cases line up by length.
    #[test]
    fn base64_matches_rfc_4648() {
        let vectors = b"foobar";
        for (length, expected) in [
            (0, ""),
            (1, "Zg=="),
            (2, "Zm8="),
            (3, "Zm9v"),
            (4, "Zm9vYg=="),
            (5, "Zm9vYmE="),
            (6, "Zm9vYmFy"),
        ] {
            assert_eq!(base64(&vectors[..length]), expected, "{length} bytes");
        }
        // The two symbols the URL-safe alphabet would spell differently, so a swapped
        // table is caught.
        assert_eq!(base64(&[0xFB, 0xFF]), "+/8=");
    }

    /// RFC 6455 §1.3's worked example, which is the only vector that proves the two
    /// halves are wired together in the right order.
    #[test]
    fn rpc_ws_accept_key_matches_rfc_6455() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
