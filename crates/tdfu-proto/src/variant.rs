//! The frozen 59-entry variant ordinal table.

/// A variant as a wire ordinal.
///
/// The table is **frozen and append-only**: new variants take 59, 60, … Protocol
/// version stays 1. It is kept not because any shipped C binary must still be served —
/// that requirement was withdrawn — but because two independent
/// implementations already agree on it and changing it is churn.
///
/// The ordinal-to-string design is acknowledged as poor and is **not** urgent: it means
/// a client can only render a name it was compiled with. Redesigning it is a protocol
/// version 2 conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WireVariant(pub u8);

impl WireVariant {
    /// How many ordinals the frozen table has.
    pub const COUNT: u8 = 59;

    /// The ordinal for "this device's variant is not known".
    ///
    /// Deliberately outside the table, so every client renders `unknown`. The C
    /// pre-seeds ordinal **6** (`t31x`) for an unknown gadget, which makes a guess
    /// indistinguishable from a detection and gets sent back as a `--cpu` value
    /// there. That defect is not reproduced.
    pub const UNKNOWN: Self = Self(0xFF);

    /// The name for this ordinal, or `None` if it is outside the table.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        NAMES.get(usize::from(self.0)).copied()
    }

    /// The ordinal for a name.
    ///
    /// Accepts the 59 table names **plus** the three input-only aliases the C accepted
    /// (`c100` → 8, `t41zn` → 22, `t40nn` → 57); [`name`](WireVariant::name) never emits
    /// them. An unknown name is `None`: the C's silent `t31x` default is
    /// **not** reproduced, because a wrong loader is a dead DDR init, and
    /// callers decide what to do with `None`.
    ///
    /// Matching is ASCII-case-insensitive, as `utils.c:136-139` makes it by lowercasing
    /// its argument first: `--cpu T31X` has always worked and dropping that would be a
    /// functional-parity regression for the sake of nothing. Case is the *only*
    /// latitude — a name is compared whole, so no prefix, no suffix and no embedded NUL
    /// resolves to a variant.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let lowered = name.to_ascii_lowercase();
        if let Some(index) = NAMES.iter().position(|known| *known == lowered) {
            return u8::try_from(index).ok().map(Self);
        }
        ALIASES
            .iter()
            .find(|(alias, _)| *alias == lowered)
            .map(|&(_, ordinal)| Self(ordinal))
    }
}

/// The frozen table, ordinal by ordinal (`tdfu.h:80-128` for the enum,
/// `utils.c:34-129` `tdfu_variant_to_string` for the spellings).
///
/// `rpc_variant_ordinals_frozen` compares this against an independent literal copy, so
/// an edit here has to be made twice on purpose.
static NAMES: [&str; WireVariant::COUNT as usize] = [
    "t10", "t20", "t21", "t23", "t30", "t31", "t31x", "t31zx", "t31a", "a1", "t40", "t41", "t32", "x1000", "x1600",
    "x1700", "x2000", "x2100", "x2600", "t31al", "t40xp", "t23dl", "t41_ddr3", "t41n", "t41nq", "t41l", "t41lq",
    "t41a", "t41zl", "t41zx", "t32_ddr3", "t10n", "t10l", "t20n", "t20x", "t20l", "t21n", "t21hp", "t23n", "t23dn",
    "t23nhp", "t23nlp", "t23x", "t23zn", "t30n", "t30x", "t30l", "t30a", "t31n", "t31l", "t32lq", "t32nq", "t32vn",
    "t32vnp", "t32vx", "t32xq", "t33", "t40n", "a1n",
];

/// The three spellings the C accepts as input and never prints
/// (`utils.c:166`, `:191`, `:193`): `c100` is the module name for a T31A,
/// `t41zn` is indistinguishable from the generic T41 DDR3 part, and `t40nn` is an older
/// spelling of `t40n`.
const ALIASES: [(&str, u8); 3] = [("c100", 8), ("t41zn", 22), ("t40nn", 57)];

impl core::fmt::Display for WireVariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ALIASES, WireVariant};

    /// An independent transcription of the table, kept apart from `NAMES` on
    /// purpose: two copies that must agree is the whole point of the pin.
    const FROZEN: [(u8, &str); 59] = [
        (0, "t10"),
        (1, "t20"),
        (2, "t21"),
        (3, "t23"),
        (4, "t30"),
        (5, "t31"),
        (6, "t31x"),
        (7, "t31zx"),
        (8, "t31a"),
        (9, "a1"),
        (10, "t40"),
        (11, "t41"),
        (12, "t32"),
        (13, "x1000"),
        (14, "x1600"),
        (15, "x1700"),
        (16, "x2000"),
        (17, "x2100"),
        (18, "x2600"),
        (19, "t31al"),
        (20, "t40xp"),
        (21, "t23dl"),
        (22, "t41_ddr3"),
        (23, "t41n"),
        (24, "t41nq"),
        (25, "t41l"),
        (26, "t41lq"),
        (27, "t41a"),
        (28, "t41zl"),
        (29, "t41zx"),
        (30, "t32_ddr3"),
        (31, "t10n"),
        (32, "t10l"),
        (33, "t20n"),
        (34, "t20x"),
        (35, "t20l"),
        (36, "t21n"),
        (37, "t21hp"),
        (38, "t23n"),
        (39, "t23dn"),
        (40, "t23nhp"),
        (41, "t23nlp"),
        (42, "t23x"),
        (43, "t23zn"),
        (44, "t30n"),
        (45, "t30x"),
        (46, "t30l"),
        (47, "t30a"),
        (48, "t31n"),
        (49, "t31l"),
        (50, "t32lq"),
        (51, "t32nq"),
        (52, "t32vn"),
        (53, "t32vnp"),
        (54, "t32vx"),
        (55, "t32xq"),
        (56, "t33"),
        (57, "t40n"),
        (58, "a1n"),
    ];

    /// Both directions, every ordinal, against the literal above.
    #[test]
    fn rpc_variant_ordinals_frozen() {
        assert_eq!(FROZEN.len(), usize::from(WireVariant::COUNT));
        for (ordinal, name) in FROZEN {
            assert_eq!(WireVariant(ordinal).name(), Some(name), "ordinal {ordinal}");
            assert_eq!(WireVariant::from_name(name), Some(WireVariant(ordinal)), "{name}");
            assert_eq!(WireVariant(ordinal).to_string(), name);
        }
    }

    /// Nothing outside the table has a name — including the `0xFF` an unknown gadget is
    /// reported with, which is the point of putting it there.
    #[test]
    fn rpc_variant_outside_the_table_has_no_name() {
        for ordinal in WireVariant::COUNT..=u8::MAX {
            assert_eq!(WireVariant(ordinal).name(), None, "ordinal {ordinal}");
            assert_eq!(WireVariant(ordinal).to_string(), "unknown");
        }
        assert_eq!(WireVariant::UNKNOWN.name(), None);
    }

    /// The three input-only spellings, and the rule that they are input-only.
    #[test]
    fn rpc_variant_aliases_are_accepted_and_never_emitted() {
        assert_eq!(WireVariant::from_name("c100"), Some(WireVariant(8)));
        assert_eq!(WireVariant::from_name("t41zn"), Some(WireVariant(22)));
        assert_eq!(WireVariant::from_name("t40nn"), Some(WireVariant(57)));
        for ordinal in 0..=u8::MAX {
            if let Some(name) = WireVariant(ordinal).name() {
                assert!(
                    !ALIASES.iter().any(|(alias, _)| *alias == name),
                    "ordinal {ordinal} emits the alias {name}"
                );
            }
        }
        // Exactly three, so a fourth has to be added deliberately.
        assert_eq!(ALIASES.len(), 3);
    }

    /// An unknown name is `None`. The C answers `t31x` for anything it does not know
    /// (`utils.c:134`, `:242`), which is how a wrong loader gets picked; the
    /// caller decides here.
    #[test]
    fn rpc_variant_unknown_name_is_none() {
        for name in [
            "", " ", "t99", "t31xx", "t31 ", " t31", "t31\0", "unknown", "c101", "t40nnn",
        ] {
            assert_eq!(WireVariant::from_name(name), None, "{name:?}");
        }
    }

    /// `--cpu T31X` has always worked (`utils.c:136-139` lowercases first). Case is the
    /// only latitude: a name still has to match whole.
    #[test]
    fn variant_names_are_case_insensitive_but_still_whole() {
        assert_eq!(WireVariant::from_name("T31X"), Some(WireVariant(6)));
        assert_eq!(WireVariant::from_name("T31x"), Some(WireVariant(6)));
        assert_eq!(WireVariant::from_name("C100"), Some(WireVariant(8)));
        assert_eq!(WireVariant::from_name("T41_DDR3"), Some(WireVariant(22)));
        assert_eq!(WireVariant::from_name("T31X "), None);
    }

    /// Every accepted spelling: 59 names + exactly 3 aliases = 62, and no two names
    /// share an ordinal by accident.
    #[test]
    fn the_accepted_spellings_are_exactly_sixty_two() {
        let mut spellings: Vec<&str> = FROZEN.iter().map(|(_, name)| *name).collect();
        spellings.extend(ALIASES.iter().map(|(alias, _)| *alias));
        spellings.sort_unstable();
        let count = spellings.len();
        spellings.dedup();
        assert_eq!(spellings.len(), count, "a spelling is listed twice");
        assert_eq!(count, 62);
        for spelling in spellings {
            assert!(WireVariant::from_name(spelling).is_some(), "{spelling}");
        }
    }

    #[test]
    fn the_table_is_the_frozen_size_and_unknown_sits_outside_it() {
        assert_eq!(WireVariant::COUNT, 59, "frozen, append-only");
        assert_ne!(
            WireVariant::UNKNOWN,
            WireVariant(6),
            "the C's t31x pre-seed is not reproduced"
        );
        assert!(u16::from(WireVariant::UNKNOWN.0) >= u16::from(WireVariant::COUNT));
    }
}
