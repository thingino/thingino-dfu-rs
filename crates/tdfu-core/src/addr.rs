//! Bootrom register addresses, in the one form that works.
//!
//! **Every address this crate issues to a bootrom is a kseg1 alias, and a physical one
//! cannot be constructed here.** The physical form (`0x13xxxxxx`) is a kuseg address;
//! the mask ROM sets up no TLB, so the access raises an exception the ROM never returns
//! from — the device stays enumerated but its USB handler is dead until the power relay
//! cycles. That hang is the reason the C tree uploads and executes a
//! 606-byte MIPS stub to read three registers; the belief recorded at `protocol.c:177`
//! — "USB DMA cannot access peripheral registers (0x1300xxxx) — hangs" — is an
//! addressing error, not a hardware limit.
//!
//! Proven on T41NQ 2026-08-22 with the standalone probe's physical-address mode: kseg1
//! reads succeed, then
//! `read_mem(0x1300002C)` times out and every subsequent request times out with it,
//! including the kseg1 reads that had just worked.
//!
//! [`Kseg1`] is why this is a *type* and not a convention. An earlier implementation
//! had a second, live register-read path with no kseg1 guard at all: a rule that has to
//! be remembered at every call site eventually is not. [`bootrom::read_memory`](crate::bootrom::read_memory) takes a
//! `Kseg1`, so there is no call site left to forget it at. Do not weaken this
//! rule.

use core::fmt;

/// An address in kseg1: uncached, unmapped, and safe to hand the mask ROM.
///
/// The only ways to make one are [`Kseg1::from_phys`], which sets the kseg1 bits, and
/// [`Kseg1::new`], which refuses anything that is not already kseg1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kseg1(u32);

impl Kseg1 {
    /// The kseg1 alias of a peripheral physical address.
    ///
    /// The low 29 bits are **masked before the kseg1 bits go on**, and that is not
    /// tidiness. A bare `phys | 0xA000_0000` leaves bit 30 wherever it was, so
    /// `0x4000_0000` comes back as `0xE000_0000` — bits 31:29 `0b111`, which is kseg3:
    /// TLB-mapped, and the mask ROM sets up no TLB. Handing the bootrom one wedges it
    /// until the power relay cycles, exactly as the physical form does,
    /// and it would do so through the *type* that exists to make that impossible.
    ///
    /// Masking means every `u32` maps into kseg1's 512 MB window and the type's promise
    /// holds for every input rather than for the ones we happened to try.
    ///
    /// Intended for the constants below, whose values are checked at compile time by
    /// the assertions at the end of this file. For an address that comes from anywhere
    /// but a literal, use [`Kseg1::new`].
    #[must_use]
    pub const fn from_phys(phys: u32) -> Self {
        Self((phys & 0x1FFF_FFFF) | 0xA000_0000)
    }

    /// Wrap an address that is already in kseg1, or refuse it.
    #[must_use]
    pub const fn new(addr: u32) -> Option<Self> {
        if is_kseg1(addr) { Some(Self(addr)) } else { None }
    }

    /// The address itself, for a backend to put on the wire.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Kseg1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010X}", self.0)
    }
}

/// Is `addr` in kseg1 — bits 31:29 equal to `0b101`?
#[must_use]
pub const fn is_kseg1(addr: u32) -> bool {
    addr >> 29 == 0b101
}

/// `soc_id`. `cpu_id = (soc_id >> 12) & 0xFFFF`.
///
/// Physical `0x1300002C`; the same register U-Boot's `soc -m` reads
/// (`ingenic-u-boot-xburst1/common/cmd_socinfo.c:46-50`).
pub const SOC_ID: Kseg1 = Kseg1::from_phys(0x1300_002C);

/// `subsoctype1`. `sub1 = (subsoctype1 >> 16) & 0xFFFF`; the XBurst1 grade
/// discriminator.
pub const SUBSOCTYPE1: Kseg1 = Kseg1::from_phys(0x1354_0238);

/// `subsoctype2`. `sub2 = (subsoctype2 >> 16) & 0xFFFF`; for T40/T41 the **only**
/// reliable discriminator — `soc_id`, `sub1` and `subremark` are identical across the
/// family and `cppsr` is a live clock register that varies per read.
pub const SUBSOCTYPE2: Kseg1 = Kseg1::from_phys(0x1354_0250);

/// The T33 variant selector. T33 alone is graded by **byte 3 of this word**, not by
/// `subsoctype1`/`subsoctype2`
/// (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:31-36, 102-113`).
///
/// Reading it is what stops a T33 in the bootrom being un-bootstrappable: without it
/// the family decodes to an ambiguous set and the operator has to supply `--cpu`.
/// The C cannot decode a T33 at all — `protocol.c` has no
/// `case 0x0033` and falls through to "Unknown SoC CPU ID" at `protocol.c:766-768`.
pub const T33_SELECTOR: Kseg1 = Kseg1::from_phys(0x1354_021C);

/// The eFuse shadow window that `--diag` reads (`diag.c:28-30`).
///
/// It *contains* `subsoctype1` at [`EFUSE_OFFSET_SUBSOCTYPE1`] and `subsoctype2` at
/// [`EFUSE_OFFSET_SUBSOCTYPE2`], cross-checked byte-exact against the individual reads
/// on four devices, so diag is one window read plus one `soc_id` read and **no code
/// execution at all**.
pub const EFUSE_WINDOW: Kseg1 = Kseg1::from_phys(0x1354_0200);

/// How much of the eFuse window `--diag` reads.
///
/// 256 bytes covers every layout: the serial at `+0x00`, the XBurst1
/// secure word at `+0x10` and key hash at `+0x40`, and the XBurst2 security word at
/// `+0x24` with its key hash at `+0x80` OR-redundant with `+0xC0`.
pub const EFUSE_WINDOW_LEN: usize = 256;

/// `subsoctype1`'s offset inside [`EFUSE_WINDOW`].
pub const EFUSE_OFFSET_SUBSOCTYPE1: usize = 0x38;

/// `subsoctype2`'s offset inside [`EFUSE_WINDOW`].
pub const EFUSE_OFFSET_SUBSOCTYPE2: usize = 0x50;

/// The T33 grade selector's offset inside [`EFUSE_WINDOW`].
///
/// [`T33_SELECTOR`] (`0xB354_021C`) has always been inside the window, so `--diag`
/// resolves a T33's grade from the window it already read, with no fourth transfer
/// at all. `ops::detect` still reads the register directly - it never reads the window.
pub const EFUSE_OFFSET_T33_SELECTOR: usize = 0x1C;

const _: () = assert!((T33_SELECTOR.get() - EFUSE_WINDOW.get()) as usize == EFUSE_OFFSET_T33_SELECTOR);

// The whole register set, asserted at compile time. The
// values are asserted too, not just the bit pattern, so a typo that still happens to
// land in kseg1 does not pass.
const _: () = assert!(is_kseg1(SOC_ID.get()) && SOC_ID.get() == 0xB300_002C);
const _: () = assert!(is_kseg1(SUBSOCTYPE1.get()) && SUBSOCTYPE1.get() == 0xB354_0238);
const _: () = assert!(is_kseg1(SUBSOCTYPE2.get()) && SUBSOCTYPE2.get() == 0xB354_0250);
const _: () = assert!(is_kseg1(T33_SELECTOR.get()) && T33_SELECTOR.get() == 0xB354_021C);
const _: () = assert!(is_kseg1(EFUSE_WINDOW.get()) && EFUSE_WINDOW.get() == 0xB354_0200);
// A physical address must never pass the guard.
const _: () = assert!(!is_kseg1(0x1300_002C));
const _: () = assert!(Kseg1::new(0x1300_002C).is_none());
// And `from_phys` must land in kseg1 for *every* input, including the ones that used to
// escape into kseg3 through the bare OR.
const _: () = assert!(is_kseg1(Kseg1::from_phys(0x4000_0000).get()));
const _: () = assert!(is_kseg1(Kseg1::from_phys(u32::MAX).get()));
const _: () = assert!(is_kseg1(Kseg1::from_phys(0).get()));

#[cfg(test)]
mod tests {
    use super::{EFUSE_WINDOW, Kseg1, SOC_ID, SUBSOCTYPE1, SUBSOCTYPE2, T33_SELECTOR, is_kseg1};

    #[test]
    fn det_addresses_are_kseg1() {
        for addr in [SOC_ID, SUBSOCTYPE1, SUBSOCTYPE2, T33_SELECTOR, EFUSE_WINDOW] {
            assert!(is_kseg1(addr.get()), "{addr} is not a kseg1 address");
        }
    }

    #[test]
    fn a_physical_address_cannot_become_a_kseg1() {
        assert!(Kseg1::new(0x1300_002C).is_none(), "the physical form must never pass");
        assert!(
            Kseg1::new(0x8000_1000).is_none(),
            "kseg0 (the SPL load address) is not kseg1"
        );
        assert_eq!(Kseg1::new(0xB300_002C).map(Kseg1::get), Some(0xB300_002C));
    }

    #[test]
    fn from_phys_is_idempotent_on_an_alias() {
        assert_eq!(Kseg1::from_phys(0xB300_002C), SOC_ID);
    }

    /// `from_phys` lands in kseg1 for every input, not just the ones the constants use.
    ///
    /// The bare `phys | 0xA000_0000` it replaces left bit 30 alone, so `0x4000_0000`
    /// became `0xE000_0000` — kseg3, TLB-mapped, and a wedged mask ROM via
    /// the one type that exists to make that unreachable.
    #[test]
    fn from_phys_never_escapes_kseg1() {
        for phys in [
            0x0000_0000,
            0x1300_002C,
            0x1354_0238,
            // The bit that used to escape, alone and with company.
            0x4000_0000,
            0x6000_0000,
            0x8000_1000,
            0xE000_0000,
            u32::MAX,
        ] {
            let alias = Kseg1::from_phys(phys);
            assert!(is_kseg1(alias.get()), "from_phys({phys:#010X}) = {alias} is not kseg1");
        }
        // The specific regressions, spelled out.
        assert_eq!(Kseg1::from_phys(0x4000_0000).get(), 0xA000_0000, "kseg3, not kseg1");
        assert_eq!(Kseg1::from_phys(u32::MAX).get(), 0xBFFF_FFFF);
    }
}
