//! Bounded TLS-presentation-style encoding for administrative records.

use crate::AdminError;

/// Appends fixed-width and length-prefixed fields under a total ceiling.
pub(crate) struct Writer {
    bytes: Vec<u8>,
    ceiling: usize,
}

impl Writer {
    pub(crate) const fn with_ceiling(ceiling: usize) -> Self {
        Self {
            bytes: Vec::new(),
            ceiling,
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), AdminError> {
        let total = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(AdminError::Overflow)?;
        if total > self.ceiling {
            return Err(AdminError::Limit);
        }
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| AdminError::Limit)
    }

    pub(crate) fn put_u8(&mut self, value: u8) -> Result<(), AdminError> {
        self.put_fixed(&[value])
    }

    pub(crate) fn put_u16(&mut self, value: u16) -> Result<(), AdminError> {
        self.put_fixed(&value.to_be_bytes())
    }

    pub(crate) fn put_u64(&mut self, value: u64) -> Result<(), AdminError> {
        self.put_fixed(&value.to_be_bytes())
    }

    pub(crate) fn put_fixed(&mut self, bytes: &[u8]) -> Result<(), AdminError> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes a `<0..255>` vector behind a one-byte length.
    pub(crate) fn put_vector_u8(&mut self, bytes: &[u8]) -> Result<(), AdminError> {
        let length = u8::try_from(bytes.len()).map_err(|_| AdminError::Limit)?;
        self.put_u8(length)?;
        self.put_fixed(bytes)
    }

    /// Writes a `<0..65535>` vector behind a two-byte length.
    pub(crate) fn put_vector_u16(&mut self, bytes: &[u8]) -> Result<(), AdminError> {
        let length = u16::try_from(bytes.len()).map_err(|_| AdminError::Limit)?;
        self.put_u16(length)?;
        self.put_fixed(bytes)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Consumes fixed-width and length-prefixed fields without over-reading.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], AdminError> {
        let (head, tail) = self
            .bytes
            .split_at_checked(count)
            .ok_or(AdminError::Audit)?;
        self.bytes = tail;
        Ok(head)
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], AdminError> {
        let head = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(head);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, AdminError> {
        self.fixed::<1>().map(|[value]| value)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, AdminError> {
        self.fixed::<2>().map(u16::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, AdminError> {
        self.fixed::<8>().map(u64::from_be_bytes)
    }

    /// Reads a `<0..255>` vector bounded to `maximum` bytes.
    pub(crate) fn vector_u8(&mut self, maximum: usize) -> Result<&'a [u8], AdminError> {
        let length = usize::from(self.u8()?);
        if length > maximum {
            return Err(AdminError::Audit);
        }
        self.take(length)
    }

    /// Reads a `<0..65535>` vector bounded to `maximum` bytes.
    pub(crate) fn vector_u16(&mut self, maximum: usize) -> Result<&'a [u8], AdminError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(AdminError::Audit);
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), AdminError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(AdminError::Audit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Reader, Writer};
    use crate::AdminError;

    #[test]
    fn writer_and_reader_round_trip_within_the_ceiling() -> Result<(), AdminError> {
        let mut writer = Writer::with_ceiling(32);
        writer.put_u8(1)?;
        writer.put_u16(2)?;
        writer.put_u64(3)?;
        writer.put_vector_u8(b"ab")?;
        writer.put_vector_u16(b"cde")?;
        let bytes = writer.finish();
        assert_eq!(bytes.len(), 1 + 2 + 8 + 3 + 5);
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8()?, 1);
        assert_eq!(reader.u16()?, 2);
        assert_eq!(reader.u64()?, 3);
        assert_eq!(reader.vector_u8(2)?, b"ab");
        assert_eq!(reader.vector_u16(3)?, b"cde");
        reader.finish()?;

        let mut over = Writer::with_ceiling(2);
        assert_eq!(over.put_u64(1), Err(AdminError::Limit));
        let mut short = Reader::new(&bytes);
        assert_eq!(short.take(64), Err(AdminError::Audit));
        let mut trailing = Reader::new(&bytes);
        trailing.u8()?;
        assert_eq!(trailing.finish(), Err(AdminError::Audit));
        let mut bounded = Reader::new(&[2, 0, 0]);
        assert_eq!(bounded.vector_u8(1), Err(AdminError::Audit));
        let mut bounded16 = Reader::new(&[0, 2, 0, 0]);
        assert_eq!(bounded16.vector_u16(1), Err(AdminError::Audit));
        let big = vec![0_u8; 300];
        let mut oversized = Writer::with_ceiling(1_024);
        assert_eq!(oversized.put_vector_u8(&big), Err(AdminError::Limit));
        Ok(())
    }
}
