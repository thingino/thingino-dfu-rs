//! The two ends an image can stream through, so that no frontend has to hold one.
//!
//! [`ops::read_to`](crate::ops::read_to) and [`ops::verify_with`](crate::ops::verify_with)
//! hand an upload to an [`AsyncSink`]; [`ops::write_from`](crate::ops::write_from) and
//! [`ops::bootstrap_from`](crate::ops::bootstrap_from) take a download from an
//! [`AsyncSource`]. They are async so a frontend can put a socket behind them: the daemon
//! on an ESP32 has a few hundred kilobytes of RAM, and a 256 MiB NAND alt passes through
//! it a block at a time. The slice- and `Write`-based operations are these with
//! [`SliceSource`] and [`SyncSink`] plugged in, so there is one sequence of each.

use std::io;

/// Where an upload's bytes go.
#[allow(
    async_fn_in_trait,
    reason = "AGENTS.md D1: ?Send is the point, and no async_trait crate"
)]
pub trait AsyncSink {
    /// Take all of `data`, or fail.
    ///
    /// # Errors
    /// Whatever the destination reports; the operation stops there.
    async fn write_all(&mut self, data: &[u8]) -> io::Result<()>;
}

/// Where a download's bytes come from.
#[allow(
    async_fn_in_trait,
    reason = "AGENTS.md D1: ?Send is the point, and no async_trait crate"
)]
pub trait AsyncSource {
    /// Fill `buf` completely, or fail. Running out first is
    /// [`io::ErrorKind::UnexpectedEof`].
    ///
    /// # Errors
    /// Whatever the origin reports, or the early end.
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()>;
}

/// A synchronous writer as a sink: what [`ops::read`](crate::ops::read) has always taken.
pub struct SyncSink<'a>(pub &'a mut dyn io::Write);

impl core::fmt::Debug for SyncSink<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SyncSink")
    }
}

impl AsyncSink for SyncSink<'_> {
    async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.write_all(data)
    }
}

/// A slice as a source: what [`ops::write`](crate::ops::write) and
/// [`ops::bootstrap`](crate::ops::bootstrap) have always taken.
#[derive(Debug, Clone)]
pub struct SliceSource<'a> {
    rest: &'a [u8],
}

impl<'a> SliceSource<'a> {
    /// A source that yields `data` and then ends.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    /// How many bytes are left.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.rest.len()
    }
}

impl AsyncSource for SliceSource<'_> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let Some((head, tail)) = self.rest.split_at_checked(buf.len()) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} bytes wanted, {} left", buf.len(), self.rest.len()),
            ));
        };
        buf.copy_from_slice(head);
        self.rest = tail;
        Ok(())
    }
}

/// A source that yields `inner`'s first `len` bytes and then zeros up to `padded`: the
/// bootrom takes images padded to [`STAGE1_ALIGN`](crate::bootrom::STAGE1_ALIGN), and a
/// streamed image is padded on the way through rather than copied to be padded.
#[derive(Debug)]
pub struct Padded<'s, S> {
    inner: &'s mut S,
    real_left: usize,
}

impl<'s, S: AsyncSource> Padded<'s, S> {
    /// `inner` has `len` real bytes; the rest of what is read is zero.
    #[must_use]
    pub const fn new(inner: &'s mut S, len: usize) -> Self {
        Self { inner, real_left: len }
    }
}

impl<S: AsyncSource> AsyncSource for Padded<'_, S> {
    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let real = self.real_left.min(buf.len());
        let (head, tail) = buf.split_at_mut(real);
        self.inner.read_exact(head).await?;
        self.real_left -= real;
        tail.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tdfu_usb::mock::block_on;

    use super::{AsyncSink, AsyncSource, Padded, SliceSource, SyncSink};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_slice_source_yields_its_bytes_in_order_and_then_ends() -> TestResult {
        let mut source = SliceSource::new(b"abcdef");
        let mut first = [0_u8; 4];
        block_on(source.read_exact(&mut first))?;
        assert_eq!(&first, b"abcd");
        assert_eq!(source.remaining(), 2);

        let mut too_much = [0_u8; 3];
        let ended = block_on(source.read_exact(&mut too_much));
        assert_eq!(ended.map_err(|err| err.kind()), Err(io::ErrorKind::UnexpectedEof));
        assert_eq!(source.remaining(), 2, "a failed read takes nothing");
        Ok(())
    }

    #[test]
    fn a_sync_sink_passes_everything_to_its_writer() -> TestResult {
        let mut out = Vec::new();
        let mut sink = SyncSink(&mut out);
        block_on(sink.write_all(b"one "))?;
        block_on(sink.write_all(b"two"))?;
        assert_eq!(out, b"one two");
        Ok(())
    }

    #[test]
    fn padding_is_zeros_after_the_real_bytes_across_any_split() -> TestResult {
        let mut inner = SliceSource::new(b"abcde");
        let mut padded = Padded::new(&mut inner, 5);
        let mut first = [0xAA_u8; 3];
        block_on(padded.read_exact(&mut first))?;
        let mut second = [0xAA_u8; 5];
        block_on(padded.read_exact(&mut second))?;
        assert_eq!(&first, b"abc");
        assert_eq!(&second, b"de\0\0\0");
        assert_eq!(inner.remaining(), 0);
        Ok(())
    }
}
