//! DFU 1.1: reading what the gadget says about itself, and driving its state machine.

pub mod alt;
pub mod descriptors;
pub mod host;

pub use alt::resolve as resolve_alt;
pub use descriptors::{classify, parse_config, read_config, read_info};
pub use host::{Attempt, Grace, RetryReason, State, Status, Transaction};

/// The token that arms an erase, written to the alt named `erase`.
pub const ERASE_TOKEN: &[u8] = b"XBURST-FLASH-WIPE";

/// The token that arms a reboot, written to the alt named `reboot`.
pub const REBOOT_TOKEN: &[u8] = b"XBURST-REBOOT";

/// The alt a whole-chip erase is armed on.
pub const ERASE_ALT: &str = "erase";

/// The alt a reboot is armed on.
pub const REBOOT_ALT: &str = "reboot";

/// The alt an image is written to on every shipped loader.
///
/// The one the *rule* uses: [`alt::resolve`] matches on it, and every op that takes an
/// `--alt` goes through that function. `tdfu-cli`'s `alt::FLASH` is the same string
/// declared a second time for the CLI's own fixtures, which drive this resolver — so the
/// two cannot silently diverge, and neither is a re-export of the other on purpose.
pub const FLASH_ALT: &str = "flash";

#[cfg(test)]
mod tests {
    use super::{ERASE_TOKEN, REBOOT_TOKEN};

    #[test]
    fn tokens_are_the_lengths_the_loader_expects() {
        // Spec §0: 17 bytes and 13 bytes. The loader compares a `strlen`-guarded
        // `memcmp`, so a length change is a silent refusal.
        assert_eq!(ERASE_TOKEN.len(), 17);
        assert_eq!(REBOOT_TOKEN.len(), 13);
    }
}
