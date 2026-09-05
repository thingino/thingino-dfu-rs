//! CRC-32 over a `WRITE` payload's image.
//!
//! One implementation, two shapes: [`crc32`] for a buffer you already hold, and
//! [`Crc32`] for a stream you do not. The C keeps exactly this pair
//! (`cli/remote.c:39-51`: `remote_crc32_update` seeded with `0xFFFF_FFFF`, fed chunk by
//! chunk, finalised with `~crc`) and it *needs* it — a NAND alt 0 is 256 MiB and cannot
//! be buffered to be checksummed. An earlier implementation shipped only the one-shot
//! form, so its CLI re-derived the polynomial for the streamed read and the wire's
//! checksum existed twice in one workspace. It exists once here.

/// The reflected IEEE 802.3 polynomial, as the C spells it (`cli/remote.c:44`).
const POLY: u32 = 0xEDB8_8320;

/// Seed and final XOR: init `0xFFFFFFFF`, then XOR out.
const INIT: u32 = 0xFFFF_FFFF;

/// One byte's worth of the polynomial, precomputed at compile time.
///
/// The table is the only difference from the C's bit-at-a-time loop, and it is an
/// implementation detail: `table_agrees_with_the_bitwise_reference` re-derives every
/// entry the C's way and compares.
static TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0_usize;
    while index < 256 {
        // `index` is bounded by the loop, so the truncation cannot happen; a `const fn`
        // has no `try_from` to say that with.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "index < 256, and const fn cannot call TryFrom"
        )]
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 { crc >> 1 } else { (crc >> 1) ^ POLY };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

/// IEEE 802.3 reflected CRC-32, zlib-compatible.
///
/// Computed over the **image only**, never over the whole payload.
///
/// Hand-written rather than pulled from a crate: it is twenty lines, it is on the hot
/// path of a 16 MiB write, and the dependency graph is meant to stay small enough to
/// read in one sitting.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(data);
    hasher.finalize()
}

/// A resumable CRC-32, for data that arrives in pieces.
///
/// This is the form a streamed `READ` needs: its OK payload ends in the
/// checksum of everything before it, and a 256 MiB NAND image is written to a file as it
/// arrives rather than held in RAM (`cli/remote.c:284` `recv_read_to_file`). Feeding the
/// chunks here gives the same value as [`crc32`] over the whole image — pinned by
/// `chunking_never_changes_the_checksum`.
///
/// ```
/// # use tdfu_proto::crc::{Crc32, crc32};
/// let mut hasher = Crc32::new();
/// hasher.update(b"1234");
/// hasher.update(b"56789");
/// assert_eq!(hasher.finalize(), crc32(b"123456789"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// A hasher over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: INIT }
    }

    /// Fold `data` in. Call it as many times as the data has pieces.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        for &byte in data {
            let slot = (crc ^ u32::from(byte)) & 0xFF;
            crc = (crc >> 8) ^ TABLE[slot as usize];
        }
        self.state = crc;
    }

    /// The checksum of everything fed so far.
    #[must_use]
    pub const fn finalize(self) -> u32 {
        !self.state
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Crc32, POLY, crc32};

    /// The vectors every CRC-32 implementation is checked against.
    #[test]
    fn rpc_crc32_standard_vectors() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
        assert_eq!(crc32(&[0xFF; 32]), 0xFF6C_AB0B);
    }

    /// The C's own loop, transcribed from `cli/remote.c:39-47`, as an independent
    /// oracle: the table is ours, the polynomial is the protocol's.
    fn c_reference(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF_u32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (POLY & 0_u32.wrapping_sub(crc & 1));
            }
        }
        !crc
    }

    #[test]
    fn table_agrees_with_the_bitwise_reference() {
        for len in 0..64_usize {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
            assert_eq!(crc32(&data), c_reference(&data), "len {len}");
        }
    }

    #[test]
    fn chunking_never_changes_the_checksum() {
        let data: Vec<u8> = (0..1024_u32).map(|i| u8::try_from(i % 256).unwrap_or(0)).collect();
        for chunk in [1_usize, 3, 7, 64, 512, 1024, 4096] {
            let mut hasher = Crc32::new();
            for piece in data.chunks(chunk) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finalize(), crc32(&data), "chunk size {chunk}");
        }
    }

    #[test]
    fn an_empty_update_changes_nothing() {
        let mut hasher = Crc32::new();
        hasher.update(b"123456789");
        hasher.update(b"");
        assert_eq!(hasher.finalize(), crc32(b"123456789"));
        assert_eq!(Crc32::default().finalize(), crc32(b""));
    }
}
