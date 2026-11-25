//! Resident admission for the bounded, objectless claim/v1 rows (companion 11.6).
#![forbid(unsafe_code)]

use super::CompanionFault;
use crate::budget::{BackingReservationPort, MemoryPermit};
use std::collections::BTreeMap;

pub(super) type Key = ([u8; 32], [u8; 16]);
/// An account may keep this many outstanding no-stock operations.
pub(super) const PER_ACCOUNT: usize = 64;
/// All accounts share this many outstanding no-stock operations.
pub(super) const GLOBAL: usize = 4096;
// Covers both sparse BTree nodes (directory record and permit), the fixed-size
// claim/v1 metadata, and its bounded staging copy during admission or restore.
const ENTRY_BACKING: usize = 8192;

#[derive(Default)]
pub(super) struct Slots {
    retained: BTreeMap<Key, MemoryPermit>,
}

impl Slots {
    pub(super) fn reserve(
        &self,
        key: Key,
        backing: &BackingReservationPort,
    ) -> Result<MemoryPermit, CompanionFault> {
        if self.retained.contains_key(&key) {
            return Err(CompanionFault::Storage);
        }
        let claimant = key.0;
        if self.retained.len() >= GLOBAL
            || self
                .retained
                .range((claimant, [0; 16])..=(claimant, [u8::MAX; 16]))
                .take(PER_ACCOUNT)
                .count()
                >= PER_ACCOUNT
        {
            return Err(CompanionFault::Ceiling);
        }
        backing
            .reserve(ENTRY_BACKING)
            .map_err(|_| CompanionFault::Ceiling)
    }

    pub(super) fn insert(&mut self, key: Key, permit: MemoryPermit) {
        self.retained.insert(key, permit);
    }

    pub(super) fn contains(&self, key: &Key) -> bool {
        self.retained.contains_key(key)
    }

    pub(super) fn retire(&mut self, key: &Key) {
        let permit = self.retained.remove(key);
        if self.retained.is_empty() {
            self.retained.clear();
        }
        drop(permit);
    }
}
