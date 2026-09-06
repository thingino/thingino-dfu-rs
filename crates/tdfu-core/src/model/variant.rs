//! SoC families and the loader directories that serve them.

/// A SoC family, from `cpu_id = (soc_id >> 12) & 0xFFFF`.
///
/// [`T4x`](Family::T4x) is one family because T40 and T41 **share** the SoC ID
/// `0x10040003` *and* the grade-code space, and no register distinguishes the product
/// lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Family {
    /// `cpu_id 0x0005`.
    T10,
    /// `cpu_id 0x2000`.
    T20,
    /// `cpu_id 0x0021`.
    T21,
    /// `cpu_id 0x0023`.
    T23,
    /// `cpu_id 0x0030`.
    T30,
    /// `cpu_id 0x0031`.
    T31,
    /// `cpu_id 0x0032`.
    T32,
    /// `cpu_id 0x0033`. Graded by [`addr::T33_SELECTOR`](crate::addr::T33_SELECTOR),
    /// not by `subsoctype1`/`subsoctype2`.
    T33,
    /// `cpu_id 0x0040`: T40 **and** T41, indistinguishable by register.
    T4x,
    /// `cpu_id 0x0001`.
    A1,
}

impl Family {
    /// Every family, for exhaustive tests.
    pub const ALL: [Self; 10] = [
        Self::T10,
        Self::T20,
        Self::T21,
        Self::T23,
        Self::T30,
        Self::T31,
        Self::T32,
        Self::T33,
        Self::T4x,
        Self::A1,
    ];

    /// The family for a decoded `cpu_id`, or `None` for an id not in the table
    /// (the C's "Unknown SoC CPU ID" row).
    #[must_use]
    pub const fn from_cpu_id(cpu_id: u16) -> Option<Self> {
        Some(match cpu_id {
            0x0005 => Self::T10,
            0x2000 => Self::T20,
            0x0021 => Self::T21,
            0x0023 => Self::T23,
            0x0030 => Self::T30,
            0x0031 => Self::T31,
            0x0032 => Self::T32,
            0x0033 => Self::T33,
            0x0040 => Self::T4x,
            0x0001 => Self::A1,
            _ => return None,
        })
    }

    /// The `cpu_id` this family decodes from.
    #[must_use]
    pub const fn cpu_id(self) -> u16 {
        match self {
            Self::T10 => 0x0005,
            Self::T20 => 0x2000,
            Self::T21 => 0x0021,
            Self::T23 => 0x0023,
            Self::T30 => 0x0030,
            Self::T31 => 0x0031,
            Self::T32 => 0x0032,
            Self::T33 => 0x0033,
            Self::T4x => 0x0040,
            Self::A1 => 0x0001,
        }
    }

    /// Which register carries this family's grade.
    ///
    /// XBurst1 grades live in `subsoctype1`; T40/T41 grades live in `subsoctype2` and
    /// **only** there; T33 has its own selector word.
    #[must_use]
    pub const fn grade_source(self) -> GradeSource {
        match self {
            Self::T10 | Self::T20 | Self::T21 | Self::T23 | Self::T30 | Self::T31 | Self::T32 => {
                GradeSource::SubSocType1
            }
            Self::T33 => GradeSource::T33Selector,
            Self::T4x | Self::A1 => GradeSource::SubSocType2,
        }
    }
}

/// Where a family's grade code comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GradeSource {
    /// `(subsoctype1 >> 16) & 0xFFFF` — every XBurst1 family.
    SubSocType1,
    /// `(subsoctype2 >> 16) & 0xFFFF` — T40/T41 and A1.
    SubSocType2,
    /// `(t33_selector >> 24) & 0xFF` — T33 only
    /// (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:31-36`).
    T33Selector,
}

/// One loader directory under `firmware/dfu/`.
///
/// Exactly the 34 that exist in the pinned loader release and nothing
/// else. A chip whose grade has no loader of its own resolves to its family's
/// conservative loader and the caller is told so — see
/// [`Detection::caveat`](crate::model::Detection::caveat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Variant {
    /// `a1n`.
    A1n,
    /// `t10l`.
    T10l,
    /// `t10n`.
    T10n,
    /// `t20l`.
    T20l,
    /// `t20n` — the 64 MB base part.
    T20n,
    /// `t20x` — 128 MB.
    T20x,
    /// `t21hp`. Never auto-selected: no grade code maps to it.
    T21hp,
    /// `t21n` — every T21 grade resolves here.
    T21n,
    /// `t23dl` — DDR2 32 MB.
    T23dl,
    /// `t23dn`.
    T23dn,
    /// `t23n`.
    T23n,
    /// `t23nhp`.
    T23nhp,
    /// `t23nlp`.
    T23nlp,
    /// `t23x`.
    T23x,
    /// `t23zn`.
    T23zn,
    /// `t30a` — 128 MB.
    T30a,
    /// `t30l`.
    T30l,
    /// `t30n`.
    T30n,
    /// `t30x` — 128 MB.
    T30x,
    /// `t31a` — DDR3. The C100 is this chip.
    T31a,
    /// `t31l`.
    T31l,
    /// `t31n`.
    T31n,
    /// `t31x` — the T31 family's conservative loader.
    T31x,
    /// `t32lq` — DDR2.
    T32lq,
    /// `t32nq` — DDR3.
    T32nq,
    /// `t32vn` — the T32 family's conservative `@350` profile.
    T32vn,
    /// `t32vnp`.
    T32vnp,
    /// `t32vx`.
    T32vx,
    /// `t32xq`.
    T32xq,
    /// `t33` — the whole T33 family shares one loader.
    T33,
    /// `t40n` — DDR2 32-bit.
    T40n,
    /// `t40xp` — DDR3 32-bit.
    T40xp,
    /// `t41lq` — DDR2 16-bit.
    T41lq,
    /// `t41nq` — DDR3 16-bit.
    T41nq,
}

impl Variant {
    /// Every loader directory that exists, in the order they are declared.
    pub const ALL: [Self; 34] = [
        Self::A1n,
        Self::T10l,
        Self::T10n,
        Self::T20l,
        Self::T20n,
        Self::T20x,
        Self::T21hp,
        Self::T21n,
        Self::T23dl,
        Self::T23dn,
        Self::T23n,
        Self::T23nhp,
        Self::T23nlp,
        Self::T23x,
        Self::T23zn,
        Self::T30a,
        Self::T30l,
        Self::T30n,
        Self::T30x,
        Self::T31a,
        Self::T31l,
        Self::T31n,
        Self::T31x,
        Self::T32lq,
        Self::T32nq,
        Self::T32vn,
        Self::T32vnp,
        Self::T32vx,
        Self::T32xq,
        Self::T33,
        Self::T40n,
        Self::T40xp,
        Self::T41lq,
        Self::T41nq,
    ];

    /// The directory name under `firmware/dfu/`.
    #[must_use]
    pub const fn loader_dir(self) -> &'static str {
        match self {
            Self::A1n => "a1n",
            Self::T10l => "t10l",
            Self::T10n => "t10n",
            Self::T20l => "t20l",
            Self::T20n => "t20n",
            Self::T20x => "t20x",
            Self::T21hp => "t21hp",
            Self::T21n => "t21n",
            Self::T23dl => "t23dl",
            Self::T23dn => "t23dn",
            Self::T23n => "t23n",
            Self::T23nhp => "t23nhp",
            Self::T23nlp => "t23nlp",
            Self::T23x => "t23x",
            Self::T23zn => "t23zn",
            Self::T30a => "t30a",
            Self::T30l => "t30l",
            Self::T30n => "t30n",
            Self::T30x => "t30x",
            Self::T31a => "t31a",
            Self::T31l => "t31l",
            Self::T31n => "t31n",
            Self::T31x => "t31x",
            Self::T32lq => "t32lq",
            Self::T32nq => "t32nq",
            Self::T32vn => "t32vn",
            Self::T32vnp => "t32vnp",
            Self::T32vx => "t32vx",
            Self::T32xq => "t32xq",
            Self::T33 => "t33",
            Self::T40n => "t40n",
            Self::T40xp => "t40xp",
            Self::T41lq => "t41lq",
            Self::T41nq => "t41nq",
        }
    }

    /// The family this loader serves.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Self::A1n => Family::A1,
            Self::T10l | Self::T10n => Family::T10,
            Self::T20l | Self::T20n | Self::T20x => Family::T20,
            Self::T21hp | Self::T21n => Family::T21,
            Self::T23dl | Self::T23dn | Self::T23n | Self::T23nhp | Self::T23nlp | Self::T23x | Self::T23zn => {
                Family::T23
            }
            Self::T30a | Self::T30l | Self::T30n | Self::T30x => Family::T30,
            Self::T31a | Self::T31l | Self::T31n | Self::T31x => Family::T31,
            Self::T32lq | Self::T32nq | Self::T32vn | Self::T32vnp | Self::T32vx | Self::T32xq => Family::T32,
            Self::T33 => Family::T33,
            Self::T40n | Self::T40xp | Self::T41lq | Self::T41nq => Family::T4x,
        }
    }

    /// Parse a `--cpu` argument.
    ///
    /// Accepts the loader directory names and the C-era spellings the shipped tool took
    /// — including `t41_ddr3`, `t41zn` and `t40nn` (`utils.c:168-194`) — because a user
    /// with a working command line must keep it: functional parity.
    /// Matching is ASCII-case-insensitive: the C lowercases the argument before every
    /// comparison (`utils.c:136-140`), so `--cpu T31X` works there.
    ///
    /// **`t41zl` must not map to a DDR3 loader.** The C groups it with the DDR3 parts
    /// (`dfu.c:1115-1117`) and Ingenic's own header is explicit that it is DDR2
    /// (`ingenic-u-boot-xburst2/include/configs/isvp_t41.h:444-446`, alongside
    /// `CONFIG_T41L` and `CONFIG_T41LQ`). An earlier implementation copied the C *and
    /// pinned the mistake with a test* — the single worst bug it carried.
    ///
    /// **An unrecognised string is [`None`].** The C returns `TDFU_VARIANT_T31X` for
    /// anything it does not know *and for a null pointer* (`utils.c:133-134`,
    /// `utils.c:241-242`), so a typo flashes a T31X loader onto whatever is attached.
    /// That renders a guess as a fact and it is not reproduced: the caller decides.
    ///
    /// **The six X-series names are not accepted** (`x1000`, `x1600`, `x1700`, `x2000`,
    /// `x2100`, `x2600`, `utils.c:199-210`). The C takes the string and then resolves
    /// `firmware/dfu/x1000/spl.bin`, which does not exist in the loader tree; both tools
    /// refuse, ours at the argument rather than at the open. No capability is lost.
    #[must_use]
    pub fn from_cpu_arg(arg: &str) -> Option<Self> {
        let arg = arg.to_ascii_lowercase();

        // Every loader directory is spelled exactly as its `--cpu` name, and the C
        // accepts all 34 of them too (`utils.c:152, 158, 162, 170, 179, 183, 212-239`).
        // Deriving this from `ALL` rather than transcribing it is what keeps a future
        // 35th loader accepted without a second edit.
        if let Some(variant) = Self::ALL.into_iter().find(|v| v.loader_dir() == arg) {
            return Some(variant);
        }

        CPU_ARG_ALIASES
            .iter()
            .find(|(alias, _)| *alias == arg)
            .map(|&(_, variant)| variant)
    }
}

/// The `--cpu` spellings the C accepts that are **not** loader directory names.
///
/// A table rather than a `match` so that every alias keeps its own citation line: the
/// left column says where the C accepts the string (`utils.c`), the comment says where
/// the C turns it into a directory (`dfu.c:1084-1123`) and — for anything whose answer
/// depends on the memory type — which Ingenic config says what the DRAM is. Those
/// citations are the whole point of the table, and merging arms by shared value would
/// delete them.
const CPU_ARG_ALIASES: &[(&str, Variant)] = &[
    // ---- bare family names (`utils.c:142-157, 168-173, 195-196`) ----
    ("a1", Variant::A1n),    // `dfu.c:1118-1119`
    ("t10", Variant::T10l),  // `dfu.c:1086-1089` — only T10L silicon has ever been seen
    ("t20", Variant::T20n),  // `dfu.c:1090-1091` — the 64 MB base part
    ("t21", Variant::T21n),  // `dfu.c:1092-1093`
    ("t23", Variant::T23n),  // `dfu.c:1094-1095`
    ("t30", Variant::T30n),  // `dfu.c:1096-1097`
    ("t31", Variant::T31n),  // `dfu.c:1098-1099`
    ("t32", Variant::T32lq), // `dfu.c:1103-1104` — the base T32 is DDR2
    ("t40", Variant::T40n),  // `dfu.c:1107-1108` — T40N is DDR2 32-bit
    ("t41", Variant::T41lq), // `dfu.c:1109-1111` — the C's bare T41 is the DDR2 loader
    // ---- T31 grades served by the family's DDR2 128 MB profile ----
    ("t31zx", Variant::T31x), // `utils.c:160-161`, `dfu.c:1100-1102`
    ("t31al", Variant::T31x), // `utils.c:164-165`, `dfu.c:1101-1102`
    // The C100 is a die-shrink of the T31A and has no chip id of its own
    // (`crates/tdfu-core/tests/fixtures/thingino-soc.sh:117-118`). `utils.c:166-167` maps it to
    // `TDFU_VARIANT_T31A`, which falls through `dfu.c:1120-1121` to `"t31a"`.
    ("c100", Variant::T31a),
    // The conservative @350 DDR3 profile covers T32 nq/vn/vx/xq.
    ("t32_ddr3", Variant::T32vn), // `utils.c:197-198`, `dfu.c:1105-1106`
    // ---- T4x. Every row here is checked against Ingenic's `isvp_t40.h`/`isvp_t41.h`
    // rather than against the C, because the C's grouping is wrong once and picking a
    // DDR3 loader for a DDR2 part runs DDR3 init on DDR2 silicon. ----
    ("t40nn", Variant::T40n),     // `utils.c:193-194`; DDR2 32-bit, `isvp_t40.h:414-416`
    ("t41_ddr3", Variant::T41nq), // `utils.c:174-175`, `dfu.c:1112,1117`
    ("t41l", Variant::T41lq),     // `utils.c:177-178`; DDR2, `isvp_t41.h:444-446` — C agrees
    ("t41n", Variant::T41nq),     // `utils.c:181-182`; DDR3 16-bit, `isvp_t41.h:439-441` — C agrees
    ("t41a", Variant::T41nq),     // `utils.c:185-186`; DDR3 16-bit, `isvp_t41.h:449-451` — C agrees
    ("t41zx", Variant::T41nq),    // `utils.c:189-190`; DDR3, `isvp_t41.h:464-466` — C agrees
    ("t41zn", Variant::T41nq),    // `utils.c:191-192`; DDR3 16-bit, `isvp_t41.h:439-441` — C agrees
    // THE CORRECTION. `utils.c:187-188` accepts the string and `dfu.c:1115-1117` returns
    // the DDR3 `t41nq`; `isvp_t41.h:444-446` puts `CONFIG_T41ZL` with `CONFIG_T41L` and
    // `CONFIG_T41LQ` under `CONFIG_DDR_TYPE_DDR2`, and thingino's `soc/ingenic/t41.mk:13-15`
    // builds `t41zl` from `isvp_t41lq_sfcnor` at 64 MB. Two sources that actually build
    // the loader beat one that only names it.
    ("t41zl", Variant::T41lq),
];

impl core::fmt::Display for Variant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.loader_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::{Family, Variant};

    /// Every `--cpu` spelling the C accepts that is not already a loader directory
    /// name, with the directory the C resolves it to. Transcribed from
    /// `utils.c:142-239` (which string is accepted) and `dfu.c:1084-1123` (which
    /// directory it becomes), with the one correction this table exists to carry.
    const C_ERA_ALIASES: &[(&str, &str)] = &[
        ("a1", "a1n"),
        ("t10", "t10l"),
        ("t20", "t20n"),
        ("t21", "t21n"),
        ("t23", "t23n"),
        ("t30", "t30n"),
        ("t31", "t31n"),
        ("t31zx", "t31x"),
        ("t31al", "t31x"),
        ("c100", "t31a"),
        ("t32", "t32lq"),
        ("t32_ddr3", "t32vn"),
        ("t40", "t40n"),
        ("t40nn", "t40n"),
        ("t41", "t41lq"),
        ("t41_ddr3", "t41nq"),
        ("t41l", "t41lq"),
        ("t41n", "t41nq"),
        ("t41a", "t41nq"),
        // The C says `t41nq` here (`dfu.c:1115-1117`). See the DRAM cross-check below.
        ("t41zl", "t41lq"),
        ("t41zx", "t41nq"),
        ("t41zn", "t41nq"),
    ];

    #[test]
    fn every_loader_dir_is_distinct() {
        let mut dirs: Vec<&str> = Variant::ALL.iter().map(|v| v.loader_dir()).collect();
        dirs.sort_unstable();
        let count = dirs.len();
        dirs.dedup();
        assert_eq!(dirs.len(), count, "two variants share a loader directory");
    }

    #[test]
    fn family_round_trips_through_its_cpu_id() {
        for family in Family::ALL {
            assert_eq!(Family::from_cpu_id(family.cpu_id()), Some(family));
        }
    }

    #[test]
    fn every_variant_names_a_family() {
        for variant in Variant::ALL {
            assert!(Family::ALL.contains(&variant.family()));
        }
    }

    /// The 34 are the 34 that exist — checked against the fetched loader tree rather
    /// than transcribed and hoped for.
    ///
    /// Skipped when the tree is absent, because it is fetched and not vendored.
    /// CI runs `cargo xtask fetch-loaders` before `cargo test` so that
    /// this actually runs there.
    ///
    /// **`TDFU_REQUIRE_LOADERS=1` turns the skip into a failure**, and CI sets it. A
    /// self-skip that reports `ok` is indistinguishable from a pass at the terminal
    /// if the fetch step were ever removed, reordered or silently failed,
    /// the one test that checks `Variant::ALL` against reality would go on saying `ok`
    /// forever. The environment variable is what makes "the loaders were there" an
    /// assertion rather than an assumption.
    #[test]
    fn variant_all_matches_the_pinned_loader_tree() -> Result<(), std::io::Error> {
        let tree = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/firmware/dfu");
        if !tree.is_dir() {
            let required = std::env::var_os("TDFU_REQUIRE_LOADERS").is_some_and(|value| value != "0");
            assert!(
                !required,
                "TDFU_REQUIRE_LOADERS is set and {} is absent; run `cargo xtask fetch-loaders`",
                tree.display()
            );
            eprintln!("skipped: {} is absent; run `cargo xtask fetch-loaders`", tree.display());
            return Ok(());
        }
        let mut on_disk: Vec<String> = std::fs::read_dir(&tree)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                entry
                    .file_type()
                    .ok()?
                    .is_dir()
                    .then(|| entry.file_name().to_string_lossy().into_owned())
            })
            .collect();
        on_disk.sort();

        let mut declared: Vec<String> = Variant::ALL.iter().map(|v| v.loader_dir().to_owned()).collect();
        declared.sort();

        assert_eq!(declared, on_disk, "Variant::ALL and the pinned loader tree disagree");
        Ok(())
    }

    /// `--cpu t41zl` selects the **DDR2** loader.
    ///
    /// The worst bug an earlier implementation carried: the C groups
    /// `t41zl` with the DDR3 parts (`dfu.c:1115-1117`) and that implementation copied it
    /// *and pinned it with a test*, so a DDR3 init ran on DDR2 silicon behind two
    /// layers of defence. Two sources that actually build the loader say DDR2 —
    /// `isvp_t41.h:444-446` and `soc/ingenic/t41.mk:13-15`.
    #[test]
    fn det_t41zl_maps_to_the_ddr2_loader() {
        assert_eq!(Variant::from_cpu_arg("t41zl"), Some(Variant::T41lq));
        assert_ne!(
            Variant::from_cpu_arg("t41zl"),
            Some(Variant::T41nq),
            "t41zl is DDR2; t41nq is the DDR3 loader"
        );
    }

    /// The DRAM class of every T4x `--cpu` spelling, checked against the loader it
    /// picks.
    ///
    /// This is the shape of test that would have caught bug 1 on its own: it does not
    /// assert *which* loader an alias picks, it asserts that the alias and the loader
    /// agree about the memory on the board. The four T4x loaders' own DRAM comes from
    /// `isvp_t40.h:414-416` / `:427-429` and `isvp_t41.h:444-446` /
    /// `:439-441`.
    #[test]
    fn every_t4x_cpu_arg_picks_a_loader_of_its_own_dram_type() {
        /// The DRAM each of the four T4x loaders initialises.
        ///
        /// `t40n` is T40N/T40NN, DDR2 32-bit (`isvp_t40.h:414-416`); `t40xp` is DDR3
        /// 32-bit (`isvp_t40.h:427-429`); `t41lq` is DDR2 16-bit
        /// (`isvp_t41.h:444-446`); `t41nq` is DDR3 16-bit (`isvp_t41.h:439-441`).
        fn loader_dram(variant: Variant) -> Option<&'static str> {
            let table = [
                (Variant::T40n, "DDR2"),
                (Variant::T40xp, "DDR3"),
                (Variant::T41lq, "DDR2"),
                (Variant::T41nq, "DDR3"),
            ];
            table.into_iter().find(|&(v, _)| v == variant).map(|(_, dram)| dram)
        }

        // Every T4x `--cpu` spelling with the DRAM Ingenic's header gives that part.
        let documented: &[(&str, &str)] = &[
            ("t40", "DDR2"),      // T40N, `isvp_t40.h:414-416`
            ("t40n", "DDR2"),     // same part
            ("t40nn", "DDR2"),    // = CONFIG_T40N, `isvp_t40.h:414-416`
            ("t40xp", "DDR3"),    // `isvp_t40.h:427-429`
            ("t41", "DDR2"),      // the C's bare T41 is the DDR2 loader, `dfu.c:1109-1111`
            ("t41_ddr3", "DDR3"), // the name is the claim
            ("t41l", "DDR2"),     // `isvp_t41.h:444-446`
            ("t41lq", "DDR2"),    // `isvp_t41.h:444-446`
            ("t41n", "DDR3"),     // `isvp_t41.h:439-441`
            ("t41nq", "DDR3"),    // `isvp_t41.h:439-441`
            ("t41a", "DDR3"),     // `isvp_t41.h:449-451`
            ("t41zl", "DDR2"),    // `isvp_t41.h:444-446` — the C says DDR3 and is wrong
            ("t41zx", "DDR3"),    // `isvp_t41.h:464-466`
            ("t41zn", "DDR3"),    // `isvp_t41.h:439-441`
        ];

        for &(arg, dram) in documented {
            assert_eq!(
                Variant::from_cpu_arg(arg).and_then(loader_dram),
                Some(dram),
                "--cpu {arg} is a {dram} part; it picked {:?}",
                Variant::from_cpu_arg(arg)
            );
        }
    }

    /// Every loader directory is its own `--cpu` name, all 34 of them.
    #[test]
    fn every_loader_dir_is_accepted_as_a_cpu_arg() {
        for variant in Variant::ALL {
            assert_eq!(
                Variant::from_cpu_arg(variant.loader_dir()),
                Some(variant),
                "{variant} is not accepted as a --cpu value"
            );
        }
    }

    /// The C-era spellings still work, because a user with a working command line
    /// keeps it.
    #[test]
    fn every_c_era_alias_still_resolves() {
        for &(alias, dir) in C_ERA_ALIASES {
            assert_eq!(
                Variant::from_cpu_arg(alias).map(Variant::loader_dir),
                Some(dir),
                "--cpu {alias}"
            );
        }
    }

    /// The C lowercases the argument first (`utils.c:136-140`), so `--cpu T31X` works
    /// there and must work here.
    #[test]
    fn cpu_arg_is_ascii_case_insensitive() {
        assert_eq!(Variant::from_cpu_arg("T31X"), Some(Variant::T31x));
        assert_eq!(Variant::from_cpu_arg("T41ZL"), Some(Variant::T41lq));
        assert_eq!(Variant::from_cpu_arg("C100"), Some(Variant::T31a));
        assert_eq!(Variant::from_cpu_arg("T32_DDR3"), Some(Variant::T32vn));
    }

    /// An unknown string is `None`, **not** a silent T31X.
    ///
    /// The C returns `TDFU_VARIANT_T31X` for anything it does not recognise
    /// (`utils.c:241-242`) and for a null pointer (`utils.c:133-134`), so `--cpu t41zq`
    /// flashes a T31X loader onto a T41. The caller decides here.
    #[test]
    fn cpu_arg_refuses_the_unknown_rather_than_defaulting_to_t31x() {
        for arg in ["", "t41zq", "nonsense", "t31 ", " t31x", "t99", "t41zm", "t41xq"] {
            assert_eq!(Variant::from_cpu_arg(arg), None, "--cpu {arg:?} must not resolve");
        }
    }

    /// No alias is dead.
    ///
    /// `from_cpu_arg` matches the loader directories first, so an alias that repeated a
    /// directory name would never be reached — and a repeated *alias* would hide
    /// whichever row came second. Both are silent, so both are asserted.
    #[test]
    fn the_alias_table_has_no_dead_rows() {
        let mut names: Vec<&str> = super::CPU_ARG_ALIASES.iter().map(|&(alias, _)| alias).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "two alias rows share a name");

        for &(alias, _) in super::CPU_ARG_ALIASES {
            assert!(
                !Variant::ALL.iter().any(|v| v.loader_dir() == alias),
                "alias {alias:?} repeats a loader directory and can never be reached"
            );
            assert_eq!(alias.to_ascii_lowercase(), alias, "alias {alias:?} must be lower case");
        }
    }

    /// The X-series names the C accepts have no loader directory, so they are refused
    /// at the argument instead of at the file open (`utils.c:199-210`).
    #[test]
    fn cpu_arg_refuses_the_x_series() {
        for arg in ["x1000", "x1600", "x1700", "x2000", "x2100", "x2600"] {
            assert_eq!(Variant::from_cpu_arg(arg), None, "--cpu {arg} has no loader");
        }
    }
}
