//! Small canonical network-order codec used by every persistent object.

use crate::StorageError;

pub(crate) struct Encoder {
    bytes: Vec<u8>,
    limit: usize,
}

impl Encoder {
    pub(crate) fn with_capacity(capacity: usize, limit: usize) -> Result<Self, StorageError> {
        if capacity > limit {
            return Err(StorageError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| StorageError::AllocationFailed)?;
        Ok(Self { bytes, limit })
    }

    pub(crate) fn put_u16(&mut self, value: u16) -> Result<(), StorageError> {
        self.put_fixed(&value.to_be_bytes())
    }

    pub(crate) fn put_u32(&mut self, value: u32) -> Result<(), StorageError> {
        self.put_fixed(&value.to_be_bytes())
    }

    pub(crate) fn put_u64(&mut self, value: u64) -> Result<(), StorageError> {
        self.put_fixed(&value.to_be_bytes())
    }

    pub(crate) fn put_fixed(&mut self, value: &[u8]) -> Result<(), StorageError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(StorageError::Overflow)?;
        if next > self.limit {
            return Err(StorageError::LimitExceeded);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn put_vector_u32(&mut self, value: &[u8]) -> Result<(), StorageError> {
        let length = u32::try_from(value.len()).map_err(|_| StorageError::LimitExceeded)?;
        self.put_u32(length)?;
        self.put_fixed(value)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], StorageError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(StorageError::Overflow)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(StorageError::InvalidEncoding)?;
        self.cursor = end;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], StorageError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, StorageError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, StorageError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(crate) fn vector_u32(&mut self, maximum: usize) -> Result<&'a [u8], StorageError> {
        let length = usize::try_from(self.u32()?).map_err(|_| StorageError::Overflow)?;
        if length > maximum {
            return Err(StorageError::LimitExceeded);
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), StorageError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }
}
