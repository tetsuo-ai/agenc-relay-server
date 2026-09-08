//! Complete object collection refuses capacity loss before dependency rebuild.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use agenc_ircd_storage::{PersistentRecordValue, StoredKey};

use super::super::{CompanionFault, CompanionState, MAX_RETAINED_OBJECT_BYTES};

#[derive(Default)]
pub(super) struct Restore {
    values: BTreeMap<[u8; 32], Vec<u8>>,
    bytes: usize,
    failed: bool,
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
        self.values.insert(id, row.bytes);
        self.bytes = total;
        Ok(())
    }

    pub(super) fn apply(mut self, state: &mut CompanionState) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
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
        state.object_bytes = total;
        Ok(())
    }
}
