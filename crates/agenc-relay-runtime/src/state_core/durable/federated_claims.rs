//! Compact admission and exact-result ownership for the opt-in federation account operations.
#![forbid(unsafe_code)]

use super::{DurableIndex, IndexUpdate, Projection};
use crate::RuntimeError;
use crate::budget::MemoryPermit;
use agenc_relay_federation_wire::{
    DecodeBudget, FederationProfile, InitialRootResult, federation_object_id,
};
use agenc_relay_storage::federation_records::{COORDINATOR_RESULT_KIND, CoordinatorResultRecord};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) type Key = [u8; 64];
pub(crate) const WEEK: u64 = 7 * 86_400;
const PER_ORIGIN: usize = 128;
const PER_PEER: usize = 1_024;
const TOTAL: usize = 4_096;
// Covers the retained receive/operation keys, request-ID index and bounded owner bookkeeping.
const SLOT_BYTES: usize = 2_048;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Mapping {
    key: Key,
    digest: [u8; 32],
    pub(crate) deadline: u64,
    pub(crate) closing: bool,
    pub(crate) observed: bool,
}
impl Mapping {
    fn accepts_transition(self, next: Self) -> bool {
        self.digest == next.digest
            && !self.closing
            && next.deadline >= self.deadline
            && next.observed
            && (!self.observed || next.closing)
    }

    pub(crate) fn may_replay(self, now: u64) -> bool {
        !self.closing || now < self.deadline
    }
}

pub struct BackedMapping {
    row: Mapping,
    _backing: Arc<MemoryPermit>,
}
impl PartialEq for BackedMapping {
    fn eq(&self, other: &Self) -> bool {
        self.row == other.row
    }
}
impl Eq for BackedMapping {}

#[derive(Default)]
pub(super) struct Mappings(BTreeMap<Key, Arc<BackedMapping>>);

pub(crate) fn read(
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<Option<Mapping>, RuntimeError> {
    let Ok(key) = <Key>::try_from(key.as_bytes()) else {
        return Ok(None);
    };
    if value.record_kind() != COORDINATOR_RESULT_KIND {
        return Ok(None);
    }
    let bytes = CoordinatorResultRecord::result_bytes(value.body())?;
    if !bytes.starts_with(&2u16.to_be_bytes()) {
        return Ok(None);
    }
    let record = CoordinatorResultRecord::decode(value.body())?;
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let result = InitialRootResult::decode(
        FederationProfile::InitialRoot,
        &record.result_object,
        &mut budget,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    if result.layout.replay_key.to_bytes() != key
        || *result.layout.request_id.as_bytes() != record.request_id
        || *result.layout.request_object_id.as_bytes() != record.request_object_id
        || record.completion_event_id.is_some()
        || value.generation() > 2
        || *federation_object_id(&record.result_object).as_bytes() != record.result_object_id
    {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(Some(Mapping {
        key,
        digest: record.result_object_id,
        deadline: value.expires_at().ok_or(RuntimeError::InvalidValue)?,
        closing: value.generation() == 1,
        observed: value.generation() != 0,
    }))
}

#[derive(Default)]
struct Counts {
    origin: usize,
    peer: usize,
    total: usize,
}
impl Counts {
    fn add(&mut self, key: &Key, other: &Key) {
        self.total += 1;
        self.peer += usize::from(key.get(..16) == other.get(..16));
        self.origin += usize::from(key.get(..48) == other.get(..48));
    }
    fn room(&self) -> Result<(), RuntimeError> {
        if self.total >= TOTAL || self.peer >= PER_PEER || self.origin >= PER_ORIGIN {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(())
    }
}

impl DurableIndex {
    pub(crate) fn require_federated_claim_room<'a>(
        &self,
        key: &Key,
        held: impl IntoIterator<Item = &'a Key>,
    ) -> Result<(), RuntimeError> {
        let map = &self.federated_claims.0;
        if map.contains_key(key) {
            return Err(RuntimeError::InvalidValue);
        }
        let scope = |prefix| {
            let mut first = *key;
            let mut last = *key;
            if let (Some(first), Some(last)) = (first.get_mut(prefix..), last.get_mut(prefix..)) {
                first.fill(0);
                last.fill(255);
            }
            map.range(first..=last).count()
        };
        let mut counts = Counts {
            origin: scope(48),
            peer: scope(16),
            total: map.len(),
        };
        for other in held {
            if other == key {
                return Err(RuntimeError::InvalidValue);
            }
            counts.add(key, other);
        }
        counts.room()
    }
    pub(crate) fn federated_claim(&self, key: &Key) -> Option<Mapping> {
        self.federated_claims.0.get(key).map(|slot| slot.row)
    }
    pub(crate) fn holds_federated_claim(&self, key: &Key, result: &[u8]) -> bool {
        self.federated_claim(key)
            .is_some_and(|r| r.digest == *federation_object_id(result).as_bytes())
    }
    fn back_federated_claim(&self, row: Mapping) -> Result<Arc<BackedMapping>, RuntimeError> {
        let held = self
            .initial_root_backing
            .as_ref()
            .ok_or(RuntimeError::MemoryExhausted)?
            .reserve(SLOT_BYTES)?;
        Ok(Arc::new(BackedMapping {
            row,
            _backing: Arc::new(held),
        }))
    }
    pub(in crate::state_core) fn restore_federated_claim(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        if let Some(row) = read(key, value)? {
            self.require_federated_claim_room(&row.key, [])?;
            let slot = self.back_federated_claim(row)?;
            self.federated_claims.0.insert(row.key, slot);
        }
        Ok(())
    }
    pub(super) fn apply_federated(&mut self, held: &Arc<BackedMapping>) {
        self.federated_claims.0.insert(held.row.key, held.clone());
    }
    pub(super) fn remove_federated(&mut self, key: &Key) {
        self.federated_claims.0.remove(key);
    }
}
impl Projection<'_> {
    pub(super) fn project_federated_claim(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let Ok(raw) = <Key>::try_from(key.as_bytes()) else {
            return Ok(());
        };
        let prior = self.index.federated_claims.0.get(&raw);
        let Some(row) = read(key, value)? else {
            return if prior.is_some() {
                Err(RuntimeError::InvalidValue)
            } else {
                Ok(())
            };
        };
        if self.updates.iter().any(|update| {
            matches!(update, IndexUpdate::RetainFederatedClaim(other) if other.row.key == raw)
                || matches!(update, IndexUpdate::RemoveFederatedClaim(other) if *other == raw)
        }) {
            return Err(RuntimeError::InvalidValue);
        }
        let slot = match prior {
            Some(previous) if previous.row.accepts_transition(row) => Arc::new(BackedMapping {
                row,
                _backing: previous._backing.clone(),
            }),
            Some(_) => return Err(RuntimeError::InvalidValue),
            None => self.admit_new_federated_claim(key, row)?,
        };
        self.updates.push(IndexUpdate::RetainFederatedClaim(slot));
        Ok(())
    }

    fn admit_new_federated_claim(
        &self,
        key: &StoredKey,
        row: Mapping,
    ) -> Result<Arc<BackedMapping>, RuntimeError> {
        if self.index.holds(TableId::RequestResult, key) || row.observed {
            return Err(RuntimeError::InvalidValue);
        }
        let staged = self.updates.iter().filter_map(|update| match update {
            IndexUpdate::RetainFederatedClaim(held)
                if self.index.federated_claim(&held.row.key).is_none() =>
            {
                Some(&held.row.key)
            }
            _ => None,
        });
        self.index.require_federated_claim_room(&row.key, staged)?;
        self.index.back_federated_claim(row)
    }
    pub(super) fn forget_federated_claim(&mut self, key: &StoredKey) -> Result<(), RuntimeError> {
        let Ok(raw) = <Key>::try_from(key.as_bytes()) else {
            return Ok(());
        };
        if let Some(row) = self.index.federated_claim(&raw) {
            if !row.closing {
                return Err(RuntimeError::InvalidValue);
            }
            self.updates.push(IndexUpdate::RemoveFederatedClaim(raw));
        }
        Ok(())
    }
}

impl crate::state_core::StateCoreContext {
    pub(crate) fn trusted_federation_utc(&self) -> Result<u64, RuntimeError> {
        let wall = self.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        self.drift()
            .accepts_wall(self.now(), wall)
            .then_some(wall.get())
            .ok_or(RuntimeError::InvalidValue)
    }

    /// Recheck the durable expiration and clock at storage admission, after an asynchronous sweep.
    pub(in crate::state_core) fn revalidate_federated_write(
        &self,
        write: super::AccountServiceDurableWrite,
    ) -> Result<super::AccountServiceDurableWrite, RuntimeError> {
        use super::AccountServiceDurableWrite;
        match &write {
            AccountServiceDurableWrite::Delete {
                table: TableId::RequestResult,
                key,
            } if let Ok(raw) = <Key>::try_from(key.as_bytes())
                && let Some(held) = self.index().federated_claim(&raw) =>
            {
                if held.may_replay(self.trusted_federation_utc()?) {
                    return Err(RuntimeError::InvalidValue);
                }
            }
            AccountServiceDurableWrite::Put {
                table: TableId::RequestResult,
                key,
                plaintext,
            } if key.as_bytes().len() == 64 => {
                if let Some(restamped) = self.restamp_new_federated_result(key, plaintext)? {
                    return Ok(restamped);
                }
            }
            _ => {}
        }
        write.revalidate()
    }

    fn restamp_new_federated_result(
        &self,
        key: &StoredKey,
        plaintext: &[u8],
    ) -> Result<Option<super::AccountServiceDurableWrite>, RuntimeError> {
        if PersistentRecordValue::generation_expiry(plaintext, COORDINATOR_RESULT_KIND, 0)?
            .is_none()
        {
            return Ok(None);
        }
        let value = PersistentRecordValue::decode(TableId::RequestResult, plaintext)?;
        let Some(mapping) = read(key, &value)? else {
            return Ok(None);
        };
        let floor = self
            .trusted_federation_utc()?
            .checked_add(WEEK)
            .ok_or(RuntimeError::Overflow)?;
        if mapping.deadline >= floor {
            return Ok(None);
        }
        let updated = PersistentRecordValue::new(
            TableId::RequestResult,
            value.record_kind(),
            value.revision(),
            0,
            Some(floor),
            value.references().to_vec(),
            value.body().to_vec(),
        )?
        .encode()?;
        Ok(Some(super::AccountServiceDurableWrite::put(
            TableId::RequestResult,
            key.clone(),
            updated,
        )?))
    }
}

#[cfg(test)]
mod tests;
