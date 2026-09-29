//! A streamed request's leading fields, read off the connection one at a time.
//!
//! [`Request::decode`](tdfu_proto::Request::decode) reads a payload it holds whole. A
//! streamed payload ([`dispatch_streamed`](super::dispatch_streamed)) is still on the
//! socket, so its fields are read here instead, **with the decoder's checks, in the
//! decoder's order and in its words**: a request is refused the same way however it
//! arrived. Every read is checked against what the payload has left, so a length that
//! overruns the payload is refused before anything past it is read.

use super::Wire;
use crate::errors::DaemonError;

/// Why a streamed request's fields stopped being read.
#[derive(Debug)]
pub enum Refusal {
    /// The layout is wrong. The words are `tdfu_proto`'s for the same mistake, and the
    /// peer is answered with them.
    Payload(&'static str),
    /// The connection failed.
    Conn(DaemonError),
}

impl From<DaemonError> for Refusal {
    fn from(error: DaemonError) -> Self {
        Self::Conn(error)
    }
}

/// A streamed payload, read a field at a time.
#[derive(Debug)]
pub struct Fields {
    /// Payload bytes not yet read.
    left: u64,
    /// Whether to keep what was read.
    keep: bool,
    /// What was read, in order, when kept.
    read: Vec<u8>,
}

impl Fields {
    /// A payload of `len` bytes, keeping nothing.
    #[must_use]
    pub const fn new(len: u64) -> Self {
        Self {
            left: len,
            keep: false,
            read: Vec::new(),
        }
    }

    /// A payload of `len` bytes, keeping what is read, for a request that may turn out
    /// small enough to decode whole ([`into_read`](Self::into_read)).
    #[must_use]
    pub const fn keeping(len: u64) -> Self {
        Self {
            left: len,
            keep: true,
            read: Vec::new(),
        }
    }

    /// Payload bytes not yet read.
    #[must_use]
    pub const fn left(&self) -> u64 {
        self.left
    }

    /// What was read, when kept.
    #[must_use]
    pub fn into_read(self) -> Vec<u8> {
        self.read
    }

    /// The next `len` bytes, or `short` if the payload has fewer left.
    ///
    /// # Errors
    /// [`Refusal::Payload`] carrying `short`, or [`Refusal::Conn`].
    pub async fn bytes<W: Wire>(&mut self, conn: &mut W, len: usize, short: &'static str) -> Result<Vec<u8>, Refusal> {
        if u64::try_from(len).map_or(true, |len| len > self.left) {
            return Err(Refusal::Payload(short));
        }
        let mut field = vec![0_u8; len];
        conn.payload(&mut field).await?;
        self.left -= len as u64;
        if self.keep {
            self.read.extend_from_slice(&field);
        }
        Ok(field)
    }

    /// The next `N` bytes, or `short` if the payload has fewer left.
    ///
    /// # Errors
    /// As [`bytes`](Self::bytes).
    pub async fn array<W: Wire, const N: usize>(
        &mut self,
        conn: &mut W,
        short: &'static str,
    ) -> Result<[u8; N], Refusal> {
        let field = self.bytes(conn, N, short).await?;
        let mut array = [0_u8; N];
        array.copy_from_slice(&field);
        Ok(array)
    }

    /// A big-endian `u32`, or `short` if fewer than four bytes are left.
    ///
    /// # Errors
    /// As [`bytes`](Self::bytes).
    pub async fn be32<W: Wire>(&mut self, conn: &mut W, short: &'static str) -> Result<u32, Refusal> {
        Ok(u32::from_be_bytes(self.array::<W, 4>(conn, short).await?))
    }

    /// `[len u8][bytes]`, the shape of every string field on the wire, with `short` for
    /// a missing length byte or a string the payload cannot hold.
    ///
    /// # Errors
    /// As [`bytes`](Self::bytes).
    pub async fn length_prefixed<W: Wire>(&mut self, conn: &mut W, short: &'static str) -> Result<Vec<u8>, Refusal> {
        let [len] = self.array::<W, 1>(conn, short).await?;
        self.bytes(conn, usize::from(len), short).await
    }

    /// `[idx][vlen][variant]`, the first fields of `BOOTSTRAP`, `WRITE` and `READ`.
    ///
    /// # Errors
    /// As [`bytes`](Self::bytes).
    pub async fn index_and_variant<W: Wire>(&mut self, conn: &mut W) -> Result<(u8, Vec<u8>), Refusal> {
        if self.left < 2 {
            return Err(Refusal::Payload("payload too short"));
        }
        let [index] = self.array::<W, 1>(conn, "payload too short").await?;
        let variant = self.length_prefixed(conn, "bad variant length").await?;
        Ok((index, variant))
    }
}
