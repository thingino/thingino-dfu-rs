//! The one error type the operations return.
//!
//! Every message here is written to be actionable on its own, because the alternative
//! has a track record. An earlier implementation formatted `"unrecognised SoC (soc_id
//! 0x…); send a variant, or stream --spl and --uboot"` and then **discarded it**, sending
//! `Invalid parameter` to the user; a dropped connection was reported as `Auth failed`,
//! sending people to debug a token that was fine. The C's messages are terse because C
//! makes propagating a cause awkward — that is a constraint we do not have, and copying
//! the terseness without the necessity throws away the one thing a user could act on.

use tdfu_usb::{UsbError, UsbErrorKind};

use crate::model::{Candidate, SocRegs};

/// Anything an operation can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The transport failed. The [`UsbError`] carries the pipe, the length, the
    /// deadline and how far it got.
    #[error(transparent)]
    Usb(#[from] UsbError),

    /// The transport failed, plus what the operation was attempting at the time.
    ///
    /// Use this wherever the caller knows something the transport cannot: *which*
    /// register was being read, *which* image was being uploaded. The alternative — the
    /// one this replaces — was wrapping the failure in
    /// [`Protocol`](Error::Protocol), which reads the same but **flips its
    /// recoverability**: `Protocol` is unconditionally recoverable, so an
    /// [`AccessDenied`](tdfu_usb::UsbErrorKind::AccessDenied) laundered through it came
    /// back out retryable, inverting the reasoning three lines of
    /// [`is_recoverable`](Error::is_recoverable) exist to state.
    ///
    /// [`is_recoverable`](Error::is_recoverable) delegates to `source`, so the class is
    /// the transport's whatever the wording is.
    #[error("{doing}: {source}")]
    UsbWhile {
        /// What was being attempted, in the present participle: `"reading soc_id at
        /// 0xB300002C"`.
        doing: String,
        /// The transport's own account, with the pipe, length, deadline and progress.
        source: UsbError,
    },

    /// The device answered, but not with anything this protocol allows.
    #[error("protocol: {0}")]
    Protocol(String),

    /// The device is in a DFU state the operation cannot proceed from.
    ///
    /// The C flattens this into its `PROTOCOL` code (`dfu.c`'s `make_idle` failures).
    /// Same recoverability, clearer wording — and the daemon's error mapper must send
    /// `"Protocol error"` on the wire for it, or the wire string diverges
    /// for a make-idle failure.
    #[error("device is in state {0}, which this operation cannot proceed from")]
    State(String),

    /// No DFU interface on the device.
    #[error("no DFU interface: is the device in U-Boot DFU mode?")]
    NotDfu,

    /// A read-back did not match what was written.
    ///
    /// **Never recoverable.** A data mismatch is final; the reset-and-retry class
    /// excludes it explicitly, and the pin is
    /// `dfu_verify_never_reset_retried`. The wire form is a fixed string —
    /// `tdfu_proto::verify_failed_message` — not this wording.
    #[error(
        "verify failed at offset {offset:#x}: wrote {expected:#04x}, read back {}",
        .actual.map_or_else(
            || "nothing - the device ended the upload there".to_owned(),
            |byte| format!("{byte:#04x}")
        )
    )]
    Verify {
        /// Where the first difference is.
        offset: u64,
        /// The byte that was written.
        expected: u8,
        /// The byte that came back, or `None` when the device ended the upload at
        /// `offset` and there was no byte at all: fabricating a value would print a
        /// read that never happened.
        actual: Option<u8>,
    },

    /// The loader has no alt by that name.
    ///
    /// The daemon's mapper sends the C's `"Invalid parameter"` for this
    /// (`dfu.c:708`, `dfu.c:756` both return `TDFU_ERROR_INVALID_PARAMETER`), not a new
    /// string.
    #[error("the loader has no alt named {0:?}: update the DFU loader firmware")]
    MissingAlt(&'static str),

    /// Detection narrowed the chip to several candidates and cannot choose.
    ///
    /// The message names every candidate with its DRAM, because that is what an
    /// operator needs to pick the right `--cpu` — and picking the wrong one runs a DDR3
    /// init on a DDR2 part.
    ///
    /// It also names the registers, and that half is not decoration: a
    /// **grade code** is what promotes a row from convention to documented, so the code
    /// that produced an ambiguity is the single datum a bug report needs in order to
    /// extend the table. Carrying only the candidate list threw it away — and when the
    /// list is empty (an undocumented T4x grade) it left a message that named nothing at
    /// all.
    #[error("the SoC grade is shared (soc_id {:#010X}, subsoctype1 {:#010X}, subsoctype2 {:#010X}); {}",
            .regs.soc_id, .regs.subsoctype1, .regs.subsoctype2, format_candidates(.candidates))]
    Ambiguous {
        /// What was read. The grade code lives in `subsoctype1` or `subsoctype2`
        /// depending on the family, so all three are named rather than guessed between.
        regs: SocRegs,
        /// Every chip the grade could be, each with its DRAM and its `--cpu` value.
        /// Empty when no documented grade matches at all.
        candidates: Vec<Candidate>,
    },

    /// The `cpu_id` is not in the decode table.
    ///
    /// Carries the registers so a bug report can extend the table without another bench
    /// session — and says what to do instead, which is the part an earlier
    /// implementation computed and threw away.
    #[error(
        "unrecognised SoC (soc_id {:#010X}, subsoctype1 {:#010X}, subsoctype2 {:#010X}); \
         pass --cpu, or stream your own loader with --spl and --uboot",
        .regs.soc_id, .regs.subsoctype1, .regs.subsoctype2
    )]
    UnknownSoc {
        /// What was read.
        regs: SocRegs,
    },

    /// The loader tree has no file for the chosen variant. The tree is
    /// fetched, not vendored, so a missing file usually means `xtask fetch-loaders` has
    /// not run.
    #[error("loader file missing: {0}")]
    LoaderMissing(String),

    /// The caller asked for something that cannot be done.
    #[error("invalid input: {0}")]
    Invalid(String),

    /// A file could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The set that a USB bus reset and one retry may clear.
    ///
    /// The C's recoverable set is `TRANSFER_FAILED`, `TRANSFER_TIMEOUT`, `TIMEOUT`,
    /// `PROTOCOL`, `DEVICE_NOT_FOUND` and `OPEN_FAILED` (`dfu.c:408-412`), and never
    /// `FILE_IO`, `MEMORY`, `INVALID_PARAMETER` or `VERIFY`.
    ///
    /// Three deliberate differences, two narrowing the C's class and one widening it:
    ///
    /// * **An unknown [`UsbErrorKind`] is not recoverable.** A pointless retry of a
    ///   write is worse than a missed recovery. `UsbErrorKind` is `#[non_exhaustive]`,
    ///   so a kind added later lands here until someone decides otherwise.
    /// * **[`UsbErrorKind::AccessDenied`] is not recoverable**, where the C's
    ///   `OPEN_FAILED` is. A bus reset does not install a udev rule, and retrying
    ///   silently buries the one message that tells the user what to fix, which is
    ///   precisely why that case is kept distinct.
    /// * **[`UsbErrorKind::Short`] *is* recoverable**, and the C agrees without having a
    ///   name for it: a short transfer is its `TDFU_ERROR_TRANSFER_FAILED`
    ///   (`libtdfu/src/usb/device.c:451`), which sits in the reset-retry class at
    ///   `libtdfu/src/dfu/dfu.c:408-411`. A block that came back short mid-read is
    ///   exactly the wedged-EP0 case the bus reset clears. Leaving it out was the one
    ///   place this function was narrower than the C by accident rather than on purpose.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Usb(err) => usb_is_recoverable(err.kind()),
            // The context is ours, the class is the transport's.
            Self::UsbWhile { source, .. } => usb_is_recoverable(source.kind()),
            Self::Protocol(_) | Self::State(_) | Self::NotDfu => true,
            Self::Verify { .. }
            | Self::MissingAlt(_)
            | Self::Ambiguous { .. }
            | Self::UnknownSoc { .. }
            | Self::LoaderMissing(_)
            | Self::Invalid(_)
            | Self::Io(_) => false,
        }
    }
}

/// The recoverable class, as a property of the transport failure alone.
///
/// Shared by [`Error::Usb`] and [`Error::UsbWhile`] so that adding context to a failure
/// cannot change what happens to it.
fn usb_is_recoverable(kind: &UsbErrorKind) -> bool {
    matches!(
        kind,
        UsbErrorKind::Timeout
            | UsbErrorKind::Stall
            | UsbErrorKind::NoDevice
            | UsbErrorKind::Fault
            | UsbErrorKind::Short { .. }
    )
}

fn format_candidates(candidates: &[Candidate]) -> String {
    // An undocumented T4x grade is `Ambiguous` with NO candidates, deliberately:
    // fabricating one would invent a grade no table documents. The message still has to
    // tell the operator what to do, and the registers the variant carries are what makes
    // it reportable.
    if candidates.is_empty() {
        return "no documented grade matches; pass --cpu".to_owned();
    }
    format!(
        "pass --cpu with one of: {}",
        candidates
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The result every operation returns.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::{Error, SocRegs};
    use crate::model::{Candidate, Dram, DramKind, Evidence, Variant};
    use tdfu_usb::{Pipe, UsbError, UsbErrorKind};

    /// A T41 in the bootrom whose grade code is not in any table.
    const UNDOCUMENTED: SocRegs = SocRegs::new(0x1004_0003, 0x0000_0000, 0xBBBB_2222);

    /// An undocumented grade carries no candidates, the message must
    /// still say what to do rather than trail off after a colon, **and** it must name the
    /// registers — the grade code is the evidence that would promote a row, so a bug
    /// report without it cannot extend the table.
    #[test]
    fn err_ambiguous_with_no_candidates_reads_clean() {
        let message = Error::Ambiguous {
            regs: UNDOCUMENTED,
            candidates: Vec::new(),
        }
        .to_string();
        assert_eq!(
            message,
            concat!(
                "the SoC grade is shared (soc_id 0x10040003, subsoctype1 0x00000000, subsoctype2 0xBBBB2222); ",
                "no documented grade matches; pass --cpu"
            )
        );
    }

    /// And with candidates: every chip, its DRAM, and the `--cpu` that picks it — plus
    /// the registers, still.
    #[test]
    fn err_ambiguous_names_the_registers_and_every_candidate() {
        let message = Error::Ambiguous {
            regs: SocRegs::new(0x1004_0003, 0, 0x7777_0000),
            candidates: vec![
                Candidate::new(
                    "T40XP",
                    Some(Variant::T40xp),
                    Some(Dram::new(DramKind::Ddr3)),
                    Evidence::Bench,
                ),
                Candidate::new(
                    "T41ZN",
                    Some(Variant::T41nq),
                    Some(Dram::new(DramKind::Ddr3)),
                    Evidence::Vendor,
                ),
            ],
        }
        .to_string();
        assert!(
            message.starts_with(
                "the SoC grade is shared (soc_id 0x10040003, subsoctype1 0x00000000, subsoctype2 0x77770000); "
            ),
            "the registers must lead: {message}"
        );
        assert!(message.contains("T40XP"), "{message}");
        assert!(message.contains("T41ZN"), "{message}");
        assert!(message.contains("pass --cpu with one of"), "{message}");
    }

    /// A3: adding context to a transport failure must not change what happens to it.
    /// Wrapping a read failure in `Protocol` did — `Protocol` is unconditionally
    /// recoverable, so an `AccessDenied` came back out retryable.
    #[test]
    fn context_does_not_change_a_usb_failure_s_class() {
        for kind in every_kind() {
            let bare = Error::Usb(UsbError::new(kind.clone(), Pipe::Device));
            let with_context = Error::UsbWhile {
                doing: "reading soc_id at 0xB300002C".to_owned(),
                source: UsbError::new(kind.clone(), Pipe::Device),
            };
            assert_eq!(
                bare.is_recoverable(),
                with_context.is_recoverable(),
                "{kind:?} changed class when it gained a context"
            );
            assert!(
                with_context.to_string().starts_with("reading soc_id at 0xB300002C: "),
                "the context must lead the message"
            );
        }

        // And the wrapping this replaces would have flipped it.
        let laundered = Error::Protocol("could not read soc_id: access denied by the OS".to_owned());
        assert!(laundered.is_recoverable(), "Protocol is unconditionally recoverable");
        assert!(
            !Error::UsbWhile {
                doing: "reading soc_id".to_owned(),
                source: UsbError::new(UsbErrorKind::AccessDenied, Pipe::Device),
            }
            .is_recoverable(),
            "which is exactly the inversion"
        );
    }

    /// The recoverable class, pinned kind by kind in both directions.
    ///
    /// `UsbErrorKind` is `#[non_exhaustive]`, so this list cannot be checked for
    /// completeness from here. `tdfu_usb`'s own `every_kind_is_accounted_for`
    /// is the compile-time guard that a new variant cannot be added without an author
    /// coming back to this table.
    #[test]
    fn dfu12_recoverable_class_is_pinned_for_every_kind() {
        for (kind, recoverable) in [
            (UsbErrorKind::Timeout, true),
            (UsbErrorKind::Stall, true),
            (UsbErrorKind::NoDevice, true),
            (UsbErrorKind::Fault, true),
            (UsbErrorKind::Short { got: 3, want: 4 }, true),
            // The C's `OPEN_FAILED` is recoverable and this is not: a bus reset does not
            // install a udev rule.
            (UsbErrorKind::AccessDenied, false),
            // A resource another process holds is not freed by a bus reset.
            (UsbErrorKind::Busy, false),
            (UsbErrorKind::Overflow, false),
            (UsbErrorKind::Unsupported, false),
            (UsbErrorKind::NotClaimed, false),
            (UsbErrorKind::Backend("scripted mismatch".to_owned()), false),
        ] {
            assert_eq!(
                Error::Usb(UsbError::new(kind.clone(), Pipe::Device)).is_recoverable(),
                recoverable,
                "{kind:?}"
            );
        }
    }

    /// Every kind the pin above covers, so the A3 parity check runs over the same set.
    fn every_kind() -> Vec<UsbErrorKind> {
        vec![
            UsbErrorKind::Timeout,
            UsbErrorKind::Stall,
            UsbErrorKind::NoDevice,
            UsbErrorKind::Fault,
            UsbErrorKind::Short { got: 3, want: 4 },
            UsbErrorKind::AccessDenied,
            UsbErrorKind::Busy,
            UsbErrorKind::Overflow,
            UsbErrorKind::Unsupported,
            UsbErrorKind::NotClaimed,
            UsbErrorKind::Backend("scripted mismatch".to_owned()),
        ]
    }
}
