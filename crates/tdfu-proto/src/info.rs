//! `CMD_INFO`'s answer: what a daemon says about itself.
//!
//! UTF-8 text, one `key=value` per line, so a daemon can say more later without every
//! client having to understand it: a key a client does not know is skipped, and so is a
//! line that is not `key=value`.

/// Where a daemon's stage-1 and U-Boot images come from when a `BOOTSTRAP` carries none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Loaders {
    /// A loader tree of its own: a client names the variant and sends nothing else.
    Tree,
    /// None: a `BOOTSTRAP` has to carry the pair. A daemon on a microcontroller, which
    /// has no filesystem to keep a tree in.
    Absent,
}

impl Loaders {
    /// The value's spelling on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Absent => "none",
        }
    }
}

/// A daemon's answer to `CMD_INFO`. Every field is optional: a daemon says what it knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DaemonInfo {
    /// The daemon's version, as its banner prints it.
    pub version: Option<String>,
    /// Where its loaders come from.
    pub loaders: Option<Loaders>,
}

impl DaemonInfo {
    /// An answer naming `version` and `loaders`.
    #[must_use]
    pub fn new(version: impl Into<String>, loaders: Loaders) -> Self {
        Self {
            version: Some(version.into()),
            loaders: Some(loaders),
        }
    }

    /// The payload: `version=…` and `loaders=…`, one per line. A value never carries a
    /// line break, which would start a line of its own.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        if let Some(version) = &self.version {
            out.push_str("version=");
            out.push_str(&version.replace(['\r', '\n'], " "));
            out.push('\n');
        }
        if let Some(loaders) = self.loaders {
            out.push_str("loaders=");
            out.push_str(loaders.as_str());
            out.push('\n');
        }
        out.into_bytes()
    }

    /// Read an answer, skipping whatever is not understood.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Self {
        let mut info = Self::default();
        for line in String::from_utf8_lossy(payload).lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "version" => info.version = Some(value.to_owned()),
                "loaders" => {
                    info.loaders = match value {
                        "tree" => Some(Loaders::Tree),
                        "none" => Some(Loaders::Absent),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        info
    }
}

#[cfg(test)]
mod tests {
    use super::{DaemonInfo, Loaders};

    /// The layout, byte for byte, and back.
    #[test]
    fn the_answer_is_key_value_lines() {
        let info = DaemonInfo::new("2.0.1 (abc123)", Loaders::Absent);
        assert_eq!(info.encode(), b"version=2.0.1 (abc123)\nloaders=none\n");
        assert_eq!(DaemonInfo::decode(&info.encode()), info);
        let tree = DaemonInfo::new("2.0.1", Loaders::Tree);
        assert_eq!(DaemonInfo::decode(&tree.encode()).loaders, Some(Loaders::Tree));
    }

    /// A daemon may say more than a client knows: unknown keys, lines that are not
    /// `key=value`, an unknown value and Windows line ends are all taken in stride.
    #[test]
    fn what_is_not_understood_is_skipped() {
        let info = DaemonInfo::decode(b"motd=hello\r\nnot a pair\r\n loaders = none \r\nversion=9\r\n");
        assert_eq!(info.loaders, Some(Loaders::Absent));
        assert_eq!(info.version.as_deref(), Some("9"));
        assert_eq!(DaemonInfo::decode(b"loaders=cloud\n").loaders, None);
        assert_eq!(DaemonInfo::decode(&[0xFF, 0xFE]), DaemonInfo::default());
    }

    /// A value cannot break out into a line of its own.
    #[test]
    fn a_value_never_carries_a_line_break() {
        let info = DaemonInfo::new("1.0\nloaders=none", Loaders::Tree);
        assert_eq!(DaemonInfo::decode(&info.encode()).loaders, Some(Loaders::Tree));
    }
}
