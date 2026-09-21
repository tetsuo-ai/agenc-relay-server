//! Cloned delivery rows share immutable bytes and the reservation that owns them.
#![forbid(unsafe_code)]

use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryPermit};
use std::sync::Arc;

struct Allocation {
    bytes: Vec<u8>,
    _memory: MemoryPermit,
}

/// Immutable delivery bytes; cloning does not duplicate the allocation or its charge.
#[derive(Clone)]
pub struct SharedBytes(Arc<Allocation>);

impl SharedBytes {
    pub(crate) fn from_owned(
        bytes: Vec<u8>,
        backing: &BackingReservationPort,
    ) -> Result<Self, RuntimeError> {
        let capacity = allocation_capacity(bytes.capacity())?;
        let memory = backing.reserve(capacity)?;
        Ok(Self(Arc::new(Allocation {
            bytes,
            _memory: memory,
        })))
    }

    pub(crate) fn copy_from(
        bytes: &[u8],
        backing: &BackingReservationPort,
    ) -> Result<Self, RuntimeError> {
        let memory = backing.reserve(allocation_capacity(bytes.len())?)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| RuntimeError::InvalidValue)?;
        if owned.capacity() > bytes.len() {
            return Err(RuntimeError::InvalidValue);
        }
        owned.extend_from_slice(bytes);
        Ok(Self(Arc::new(Allocation {
            bytes: owned,
            _memory: memory,
        })))
    }

    #[cfg(test)]
    pub(crate) fn for_fixture(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        use crate::budget::{MemoryBudget, MemoryCharge};
        let charge = MemoryCharge::allocation(
            u64::try_from(allocation_capacity(bytes.capacity())?)
                .map_err(|_| RuntimeError::Overflow)?,
        )?;
        Self::from_owned(
            bytes,
            &BackingReservationPort::new(Arc::new(MemoryBudget::new(charge.bytes()))),
        )
    }
}

fn allocation_capacity(bytes: usize) -> Result<usize, RuntimeError> {
    bytes
        .checked_add(std::mem::size_of::<Allocation>())
        .and_then(|value| value.checked_add(2 * std::mem::size_of::<usize>()))
        .ok_or(RuntimeError::Overflow)
}

impl std::ops::Deref for SharedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.bytes
    }
}

impl PartialEq for SharedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.bytes == other.0.bytes
    }
}
impl Eq for SharedBytes {}

impl std::fmt::Debug for SharedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedBytes")
            .field("len", &self.0.bytes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
