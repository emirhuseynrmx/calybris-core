use std::io::{self, Write};

/// A writer that never forwards more than `limit` bytes to its inner writer.
pub(crate) struct LimitedWriter<W> {
    inner: W,
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl<W> LimitedWriter<W> {
    pub(crate) fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            exceeded: false,
        }
    }

    pub(crate) fn limit_exceeded(&self) -> bool {
        self.exceeded
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.written);
        if buffer.len() > remaining {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized artifact exceeds configured byte limit",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.written += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_forwards_bytes_past_limit() {
        let mut writer = LimitedWriter::new(Vec::new(), 3);
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert!(writer.limit_exceeded());
        assert_eq!(writer.into_inner(), b"abc");
    }
}
