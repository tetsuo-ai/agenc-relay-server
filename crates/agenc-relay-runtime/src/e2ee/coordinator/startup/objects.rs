//! Complete object collection refuses capacity loss before dependency rebuild.
#![forbid(unsafe_code)]

mod selection;

use crate::budget::{BackingReservationPort, MemoryPermit};
use std::collections::BTreeMap;

use agenc_relay_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey};

use super::super::{CompanionFault, CompanionState, MAX_RETAINED_OBJECT_BYTES};

#[derive(Default)]
pub(super) struct Restore {
    values: BTreeMap<[u8; 32], Vec<u8>>,
    bytes: usize,
    failed: bool,
    selection: Option<selection::Selection>,
    memory: BTreeMap<[u8; 32], MemoryPermit>,
}

impl Restore {
    pub(super) fn admit(&mut self, key: &StoredKey, value: &PersistentRecordValue) {
        if self.failed {
            return;
        }
        if self.collect(key, value).is_err() {
            self.failed = true;
            self.values.clear();
            self.bytes = 0;
            self.memory.clear();
        }
    }

    fn collect(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), CompanionFault> {
        if value.record_kind() != OBJECT_RECORD_KIND {
            return Err(CompanionFault::Storage);
        }
        let row = ObjectRow::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
        if row.key().map_err(|_| CompanionFault::Storage)? != *key {
            return Err(CompanionFault::Storage);
        }
        let id = key
            .as_bytes()
            .try_into()
            .map_err(|_| CompanionFault::Storage)?;
        if let Some(selection) = &self.selection
            && !selection.retain(&id, row.kind().map_err(|_| CompanionFault::Storage)?)?
        {
            return Ok(());
        }
        if let Some(previous) = self.values.get(&id) {
            return if previous == &row.bytes {
                Ok(())
            } else {
                Err(CompanionFault::Storage)
            };
        }
        let total = self
            .bytes
            .checked_add(row.bytes.len())
            .ok_or(CompanionFault::Ceiling)?;
        if total > MAX_RETAINED_OBJECT_BYTES {
            return Err(CompanionFault::Ceiling);
        }
        if let Some(selection) = &self.selection {
            let memory = selection.reserve(row.bytes.capacity())?;
            self.memory.insert(id, memory);
        }
        self.values.insert(id, row.bytes);
        self.bytes = total;
        Ok(())
    }

    pub(super) fn apply(mut self, state: &mut CompanionState) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        if let Some(selection) = &self.selection {
            selection.complete(&state.objects, &self.values)?;
        }
        let mut total = state.object_bytes;
        for (id, bytes) in &self.values {
            if let Some(previous) = state.objects.get(id) {
                if previous != bytes {
                    return Err(CompanionFault::Storage);
                }
            } else {
                total = total
                    .checked_add(bytes.len())
                    .ok_or(CompanionFault::Ceiling)?;
            }
        }
        if total > MAX_RETAINED_OBJECT_BYTES {
            return Err(CompanionFault::Ceiling);
        }
        state.objects.append(&mut self.values);
        state.object_memory.append(&mut self.memory);
        state.object_bytes = total;
        Ok(())
    }
}

impl Restore {
    pub(super) fn select(
        &mut self,
        rows: &[(StoredKey, agenc_relay_storage::e2ee_records::MailboxRow)],
        replays: &[(StoredKey, agenc_relay_storage::e2ee_records::ReplayRow)],
        backing: BackingReservationPort,
    ) -> Result<(), CompanionFault> {
        if self.failed || self.selection.is_some() || !self.values.is_empty() {
            return Err(CompanionFault::Storage);
        }
        self.selection = Some(selection::Selection::new(rows, replays, backing)?);
        Ok(())
    }
    pub(super) fn selected(&self) -> bool {
        self.selection.is_some()
    }
    pub(super) fn poison(&mut self) {
        self.failed = true;
    }
}

#[cfg(test)]
#[path = "../tests/selective_objects.rs"]
mod tests;
