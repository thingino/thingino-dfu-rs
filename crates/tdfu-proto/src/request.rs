//! The eight commands' payloads.

use crate::error::ProtoError;
use crate::frame::Command;
use crate::variant::WireVariant;

/// A custom loader pair streamed with a `BOOTSTRAP`, instead of naming a variant.
///
/// A named struct rather than a bare `(Vec<u8>, Vec<u8>)`: which half is which
/// matters, and sending U-Boot where the SPL belongs bricks nothing but wastes a bench
/// slot working out why. The wire layout is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blobs {
    /// The stage-1 image.
    pub spl: Vec<u8>,
    /// The U-Boot image.
    pub uboot: Vec<u8>,
}

/// One request's payload, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// No payload.
    Discover,
    /// Bring the device at `index` up as a gadget.
    Bootstrap {
        /// Device index from the last `DISCOVER`.
        index: u8,
        /// The variant name, or empty to auto-detect.
        variant: Vec<u8>,
        /// Custom loaders, which skip detection *and* the firmware-dir lookup
        /// entirely.
        blobs: Option<Blobs>,
    },
    /// Write `image` to `alt`.
    Write {
        /// Device index.
        index: u8,
        /// The variant name, or empty to auto-detect.
        variant: Vec<u8>,
        /// The alt name.
        alt: Vec<u8>,
        /// The image.
        image: Vec<u8>,
        /// CRC-32 over `image` only.
        crc32: u32,
        /// Verify after writing. `None` is *absent*, which the C collapses with
        /// *present and zero*. Keeping them apart is strictly better, so it is kept.
        verify: Option<bool>,
    },
    /// Read from `alt`. The response may exceed the payload cap and is streamed
    /// instead.
    Read {
        /// Device index.
        index: u8,
        /// The variant name, or empty to auto-detect.
        variant: Vec<u8>,
        /// The alt name, or `None` for the default.
        alt: Option<Vec<u8>>,
    },
    /// No payload.
    Status,
    /// No payload.
    Cancel,
    /// Read the eFuse window of the device at `index`.
    Diag {
        /// Device index. An empty payload means 0.
        index: u8,
    },
    /// Reboot the device at `index`.
    Reboot {
        /// Device index. An empty payload means 0.
        index: u8,
    },
}

impl Request {
    /// Which command this is.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::Discover => Command::Discover,
            Self::Bootstrap { .. } => Command::Bootstrap,
            Self::Write { .. } => Command::Write,
            Self::Read { .. } => Command::Read,
            Self::Status => Command::Status,
            Self::Cancel => Command::Cancel,
            Self::Diag { .. } => Command::Diag,
            Self::Reboot { .. } => Command::Reboot,
        }
    }

    /// The payload only — the header is [`RequestHeader`](crate::RequestHeader)'s job.
    ///
    /// **Fallible, and that is the point.** An earlier `encode` returned a `Vec<u8>`
    /// and could not fail, so a field longer than its length prefix was silently
    /// truncated: a 300-byte `--alt` went out as a *different, valid* 255-byte alt and
    /// the write that followed was reported as success: a flash to the wrong
    /// partition. Every prefix here is checked before it is written,
    /// and the caller is told which field and by how much
    /// ([`ProtoError::FieldTooLong`]). Nothing is ever shortened to fit.
    ///
    /// # Errors
    /// [`ProtoError::FieldTooLong`] if `variant`, `alt`, `image`, `spl` or `uboot` is
    /// longer than the prefix that must describe it (255 bytes for the `u8`-prefixed
    /// fields, `u32::MAX` for the rest); [`ProtoError::EmptyBlob`] if a `BOOTSTRAP`
    /// override carries an empty half, which is an error.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = Vec::new();
        match self {
            Self::Discover | Self::Status | Self::Cancel => {}
            Self::Bootstrap { index, variant, blobs } => {
                out.push(*index);
                push_u8_prefixed(&mut out, "variant", variant)?;
                if let Some(Blobs { spl, uboot }) = blobs {
                    push_blob(&mut out, "spl", spl)?;
                    push_blob(&mut out, "uboot", uboot)?;
                }
            }
            Self::Write {
                index,
                variant,
                alt,
                image,
                crc32,
                verify,
            } => {
                out.push(*index);
                push_u8_prefixed(&mut out, "variant", variant)?;
                push_u8_prefixed(&mut out, "alt", alt)?;
                push_u32_prefixed(&mut out, "image", image)?;
                out.extend_from_slice(&crc32.to_be_bytes());
                if let Some(verify) = verify {
                    out.push(u8::from(*verify));
                }
            }
            Self::Read { index, variant, alt } => {
                out.push(*index);
                push_u8_prefixed(&mut out, "variant", variant)?;
                if let Some(alt) = alt {
                    push_u8_prefixed(&mut out, "alt", alt)?;
                }
            }
            Self::Diag { index } | Self::Reboot { index } => out.push(*index),
        }
        Ok(out)
    }

    /// Decode a payload for `command`.
    ///
    /// Accepts every shape the wire allows: an optional alt on `READ` (the web client
    /// omits it, `web/src/remote.js:219`), an optional verify byte on `WRITE`
    /// (`dfu-remote/main.c:492`), an empty `DIAG`/`REBOOT` payload meaning index 0
    /// (`:744`, `:765`).
    ///
    /// It is stricter than the C in one way: bytes left over after a command's layout
    /// are an error, where the C stops reading and ignores them. Nothing sends them
    /// today, and a frame nobody meant to send is worth hearing about — a payload that
    /// parses *and* has a tail is the shape a length mistake takes.
    ///
    /// # Errors
    /// [`ProtoError::Malformed`], carrying the same wording the C daemon answers with
    /// for that mistake (`dfu-remote/main.c:359` … `:627`).
    pub fn decode(command: Command, payload: &[u8]) -> Result<Self, ProtoError> {
        let mut reader = Reader::new(payload);
        let request = match command {
            Command::Discover => Self::Discover,
            Command::Status => Self::Status,
            Command::Cancel => Self::Cancel,
            Command::Bootstrap => {
                let (index, variant) = reader.index_and_variant()?;
                let blobs = if reader.is_empty() {
                    None
                } else {
                    Some(Blobs {
                        spl: reader.blob("bad SPL override length", "bad SPL override")?,
                        uboot: reader.blob("bad U-Boot override length", "bad U-Boot override")?,
                    })
                };
                Self::Bootstrap { index, variant, blobs }
            }
            Command::Write => {
                let (index, variant) = reader.index_and_variant()?;
                if reader.is_empty() {
                    return Err(ProtoError::Malformed("missing alt field"));
                }
                let alt = reader.length_prefixed("bad alt length")?;
                let image_len = reader.be32("missing firmware length")?;
                let image = reader.take_u32(image_len, "firmware data truncated")?;
                // The C tests the image and the CRC together (`dfu-remote/main.c:485`), so a
                // payload that stops between them is "firmware data truncated" too.
                let crc32 = reader.be32("firmware data truncated")?;
                let verify = if reader.is_empty() {
                    None
                } else {
                    Some(reader.byte()? != 0)
                };
                Self::Write {
                    index,
                    variant,
                    alt,
                    image,
                    crc32,
                    verify,
                }
            }
            Command::Read => {
                let (index, variant) = reader.index_and_variant()?;
                let alt = if reader.is_empty() {
                    None
                } else {
                    Some(reader.length_prefixed("bad alt length")?)
                };
                Self::Read { index, variant, alt }
            }
            Command::Diag => Self::Diag {
                index: reader.optional_index(),
            },
            Command::Reboot => Self::Reboot {
                index: reader.optional_index(),
            },
        };
        reader.finish()?;
        Ok(request)
    }

    /// Is this `WRITE` the whole-chip erase?
    ///
    /// The remote protocol has no erase command: the wipe token written to the loader's
    /// `erase` alt *is* the erase, and the daemon routes it to the grace-and-blank-check
    /// path instead of a generic download (`dfu-remote/main.c:505`).
    ///
    /// **Both halves are compared whole.** The C copies the alt into a 32-byte buffer
    /// and `strcmp`s it, so `alt = "erase\0junk"` wipes the chip too; reproducing that
    /// *widens* the set of payloads that erase a flash, so it is not reproduced.
    /// Here `"erase\0junk"`, `"erase "` and `"eras"` are all
    /// ordinary writes — pinned by `rpc_write_erase_token`.
    #[must_use]
    pub fn is_erase(&self) -> bool {
        matches!(self, Self::Write { alt, image, .. }
            if alt.as_slice() == ERASE_ALT && image.as_slice() == ERASE_TOKEN)
    }
}

/// The alt name the whole-chip erase is addressed to (`dfu.h:73`).
pub const ERASE_ALT: &[u8] = b"erase";

/// The 17-byte payload that means "wipe it" (`dfu.h:74`).
pub const ERASE_TOKEN: &[u8] = b"XBURST-FLASH-WIPE";

/// The most a one-byte length prefix can describe.
const U8_PREFIX_MAX: usize = u8::MAX as usize;

/// The most a four-byte length prefix can describe.
const U32_PREFIX_MAX: usize = u32::MAX as usize;

fn push_u8_prefixed(out: &mut Vec<u8>, field: &'static str, data: &[u8]) -> Result<(), ProtoError> {
    let len = u8::try_from(data.len()).map_err(|_| ProtoError::FieldTooLong {
        field,
        len: data.len(),
        max: U8_PREFIX_MAX,
    })?;
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

fn push_u32_prefixed(out: &mut Vec<u8>, field: &'static str, data: &[u8]) -> Result<(), ProtoError> {
    let len = u32::try_from(data.len()).map_err(|_| ProtoError::FieldTooLong {
        field,
        len: data.len(),
        max: U32_PREFIX_MAX,
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// A `BOOTSTRAP` override half: `u32`-prefixed, and never empty.
fn push_blob(out: &mut Vec<u8>, field: &'static str, data: &[u8]) -> Result<(), ProtoError> {
    if data.is_empty() {
        return Err(ProtoError::EmptyBlob { field });
    }
    push_u32_prefixed(out, field, data)
}

/// A payload cursor that cannot run off the end.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn byte(&mut self) -> Result<u8, ProtoError> {
        let (&first, rest) = self.bytes.split_first().ok_or(ProtoError::Truncated)?;
        self.bytes = rest;
        Ok(first)
    }

    fn take(&mut self, len: usize, message: &'static str) -> Result<Vec<u8>, ProtoError> {
        if self.bytes.len() < len {
            return Err(ProtoError::Malformed(message));
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(head.to_vec())
    }

    /// `take`, for a length that came off the wire as a `u32`. The conversion can only
    /// fail on a 16-bit target, which this workspace does not build for; saying so with
    /// `try_from` is cheaper than a comment claiming it.
    fn take_u32(&mut self, len: u32, message: &'static str) -> Result<Vec<u8>, ProtoError> {
        let len = usize::try_from(len).map_err(|_| ProtoError::Malformed(message))?;
        self.take(len, message)
    }

    fn be32(&mut self, message: &'static str) -> Result<u32, ProtoError> {
        if self.bytes.len() < 4 {
            return Err(ProtoError::Malformed(message));
        }
        let (head, rest) = self.bytes.split_at(4);
        self.bytes = rest;
        let mut word = [0_u8; 4];
        word.copy_from_slice(head);
        Ok(u32::from_be_bytes(word))
    }

    /// `[len u8][bytes]`, the shape every string field on this wire has.
    fn length_prefixed(&mut self, message: &'static str) -> Result<Vec<u8>, ProtoError> {
        let len = self.byte().map_err(|_| ProtoError::Malformed(message))?;
        self.take(usize::from(len), message)
    }

    /// `[idx][vlen][variant]`, the first two fields of BOOTSTRAP, WRITE and READ. All
    /// three refuse a payload shorter than two bytes with the same wording
    /// (`dfu-remote/main.c:359`, `:453`, `:606`).
    fn index_and_variant(&mut self) -> Result<(u8, Vec<u8>), ProtoError> {
        if self.bytes.len() < 2 {
            return Err(ProtoError::Malformed("payload too short"));
        }
        let index = self.byte()?;
        let variant = self.length_prefixed("bad variant length")?;
        Ok((index, variant))
    }

    /// `[len u32][bytes]` with a length of zero refused: both halves or neither.
    fn blob(&mut self, length_message: &'static str, data_message: &'static str) -> Result<Vec<u8>, ProtoError> {
        let len = self.be32(length_message)?;
        if len == 0 {
            return Err(ProtoError::Malformed(data_message));
        }
        self.take_u32(len, data_message)
    }

    /// `DIAG`/`REBOOT`: one index byte, or nothing, which means device 0
    /// (`dfu-remote/main.c:744`, `:765`).
    fn optional_index(&mut self) -> u8 {
        self.byte().unwrap_or(0)
    }

    /// Nothing may be left over.
    fn finish(self) -> Result<(), ProtoError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Malformed("trailing bytes"))
        }
    }
}

/// One entry of a `DISCOVER` reply: 8 bytes — bus, addr, vendor BE, product BE, stage,
/// variant ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Bus number.
    pub bus: u8,
    /// Device address.
    pub address: u8,
    /// `idVendor`.
    pub vendor: u16,
    /// `idProduct`.
    pub product: u16,
    /// 0 bootrom, 1 firmware, 2 gadget.
    pub stage: u8,
    /// The variant ordinal, or [`WireVariant::UNKNOWN`] when it is not known.
    ///
    /// **Not ordinal 6.** The C pre-seeds an unknown gadget's variant with `t31x`, so
    /// every client renders a guess as a fact and the CLI will send that name back as a
    /// `--cpu` value. `0xFF` is outside the frozen table, so every client renders
    /// `unknown` instead.
    pub variant: WireVariant,
}

impl DeviceEntry {
    /// Bytes per entry, fixed (`protocol.h:69-76`).
    pub const LEN: usize = 8;

    /// The eight bytes, big-endian where the field is wider than one.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0_u8; Self::LEN];
        out[0] = self.bus;
        out[1] = self.address;
        out[2..4].copy_from_slice(&self.vendor.to_be_bytes());
        out[4..6].copy_from_slice(&self.product.to_be_bytes());
        out[6] = self.stage;
        out[7] = self.variant.0;
        out
    }

    /// One entry, from exactly [`LEN`](DeviceEntry::LEN) bytes.
    ///
    /// # Errors
    /// [`ProtoError::Truncated`] for anything shorter, [`ProtoError::Malformed`] for
    /// anything longer — a caller holding a whole `DISCOVER` payload wants
    /// [`decode_list`](DeviceEntry::decode_list).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() < Self::LEN {
            return Err(ProtoError::Truncated);
        }
        if bytes.len() > Self::LEN {
            return Err(ProtoError::Malformed("trailing bytes"));
        }
        let mut vendor = [0_u8; 2];
        vendor.copy_from_slice(&bytes[2..4]);
        let mut product = [0_u8; 2];
        product.copy_from_slice(&bytes[4..6]);
        Ok(Self {
            bus: bytes[0],
            address: bytes[1],
            vendor: u16::from_be_bytes(vendor),
            product: u16::from_be_bytes(product),
            stage: bytes[6],
            variant: WireVariant(bytes[7]),
        })
    }

    /// A whole `DISCOVER` OK payload: N entries, and **nothing else**.
    ///
    /// The obvious `chunks_exact(8)` drops a short tail without a word, which is the
    /// same silent-truncation shape that made an earlier `encode` dangerous. A
    /// payload whose length is not a multiple of the entry size is a length mistake, and
    /// a client that has just been told which devices exist should hear about it. (The
    /// shipped web client loops `off + 8 <= length` and ignores the remainder,
    /// `web/src/remote.js:166`.)
    ///
    /// # Errors
    /// [`ProtoError::Malformed`] if the payload does not divide into whole entries.
    pub fn decode_list(payload: &[u8]) -> Result<Vec<Self>, ProtoError> {
        if !payload.len().is_multiple_of(Self::LEN) {
            return Err(ProtoError::Malformed("partial device entry"));
        }
        payload.chunks(Self::LEN).map(Self::decode).collect()
    }
}
