//! Persistent replay copies retain their own backing until their last owner expires.
#![forbid(unsafe_code)]
use super::{CompanionFault, StoredResult};
use crate::budget::{BackingReservationPort, MemoryPermit};
use std::collections::BTreeMap;

const MAX_RESULT_BYTES: usize = 8192;
const MAX_RESPONSES: usize = 32;

#[cfg(test)]
#[path = "tests/result_memory.rs"]
mod tests;

pub(crate) struct Prepared {
    value: StoredResult,
    _memory: MemoryPermit,
}

impl Prepared {
    pub(crate) fn capture(
        result: &[u8],
        responses: impl ExactSizeIterator<Item = [u8; 32]>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        if result.len() > MAX_RESULT_BYTES || responses.len() > MAX_RESPONSES {
            return Err(CompanionFault::Ceiling);
        }
        // Covers both vectors and a full new BTree node before allocation, including
        // overlap when replacing an existing result or merging a prepared map.
        let bytes = responses
            .len()
            .checked_mul(32)
            .and_then(|size| size.checked_add(result.len()))
            .and_then(|size| size.checked_add(4096))
            .ok_or(CompanionFault::Ceiling)?;
        let memory = backing
            .reserve(bytes)
            .map_err(|_| CompanionFault::Ceiling)?;
        Ok(Self {
            value: StoredResult {
                result: result.to_vec(),
                responses: responses.collect(),
            },
            _memory: memory,
        })
    }

    pub(crate) fn apply(self, store: &mut Store, request: [u8; 32]) {
        store.rows.insert(request, self);
    }
}

/// Retained request results whose persistent allocations each own a budget permit.
#[derive(Default)]
pub struct Store {
    rows: BTreeMap<[u8; 32], Prepared>,
}

impl Store {
    /// The committed result for one request object.
    #[must_use]
    pub fn get(&self, request: &[u8; 32]) -> Option<&StoredResult> {
        self.rows.get(request).map(|owned| &owned.value)
    }

    /// Whether a committed request result is retained.
    #[must_use]
    pub fn contains_key(&self, request: &[u8; 32]) -> bool {
        self.rows.contains_key(request)
    }

    /// The number of retained request results.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no request result is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Committed values in request-object order.
    pub fn values(&self) -> impl Iterator<Item = &StoredResult> {
        self.rows.values().map(|owned| &owned.value)
    }

    pub(crate) fn remove(&mut self, request: &[u8; 32]) {
        self.rows.remove(request);
    }

    pub(crate) fn append(&mut self, prepared: &mut Self) {
        self.rows.append(&mut prepared.rows);
    }

    // Corruption fixtures mutate a committed result to exercise receipt validation.
    #[cfg(test)]
    pub(crate) fn get_mut(&mut self, request: &[u8; 32]) -> Option<&mut StoredResult> {
        self.rows.get_mut(request).map(|owned| &mut owned.value)
    }
}
