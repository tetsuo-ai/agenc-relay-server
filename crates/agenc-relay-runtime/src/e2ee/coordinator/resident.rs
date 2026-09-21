//! One request admits every resident body before staging; only its receipt publishes them.
#![forbid(unsafe_code)]

mod retirement;
mod rows;
#[cfg(test)]
mod tests;

use super::{CompanionState, MAX_RETAINED_OBJECT_BYTES};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_e2ee::object::ArcWireObjectKind as Kind;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode as Code;
use agenc_relay_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use std::collections::BTreeMap;

pub(super) struct Prepared {
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    total: usize,
    retired: Option<[u8; 32]>,
    memory: BTreeMap<[u8; 32], MemoryPermit>,
}

impl Prepared {
    /// The owner allows one pending request and publishes these bodies before its effects.
    pub(super) fn apply(mut self, state: &mut CompanionState) {
        if let Some(id) = self.retired {
            drop(state.objects.remove(&id));
            state.object_memory.remove(&id);
        }
        state.objects.append(&mut self.objects);
        state.object_memory.append(&mut self.memory);
        state.object_bytes = self.total;
    }

    fn admit(
        &mut self,
        state: &CompanionState,
        key: &StoredKey,
        value: &PersistentRecordValue,
        required: &BTreeMap<[u8; 32], Kind>,
        excluded: Option<[u8; 32]>,
        backing: &BackingReservationPort,
    ) -> Result<(), Code> {
        if value.record_kind() != OBJECT_RECORD_KIND {
            return Err(Code::InvalidFragment);
        }
        let row = ObjectRow::decode(value.body()).map_err(|_| Code::InvalidFragment)?;
        if row.key().map_err(|_| Code::InvalidFragment)? != *key {
            return Err(Code::InvalidFragment);
        }
        let id = *agenc_relay_e2ee::ObjectId::compute(&row.bytes).as_bytes();
        let kind = row.kind().map_err(|_| Code::InvalidFragment)?;
        if required.get(&id).is_some_and(|expected| *expected != kind) {
            return Err(Code::InvalidFragment);
        }
        if excluded == Some(id) || (is_payload(kind) && !required.contains_key(&id)) {
            return Ok(());
        }
        if let Some(previous) = self.objects.get(&id).or_else(|| state.objects.get(&id)) {
            return if *previous == row.bytes {
                Ok(())
            } else {
                Err(Code::InvalidFragment)
            };
        }
        let total = self
            .total
            .checked_add(row.bytes.len())
            .ok_or(Code::RateLimited)?;
        if total > MAX_RETAINED_OBJECT_BYTES {
            return Err(Code::RateLimited);
        }
        let capacity = row
            .bytes
            .capacity()
            .checked_add(128)
            .ok_or(Code::RateLimited)?;
        let memory = backing.reserve(capacity).map_err(|_| Code::RateLimited)?;
        self.objects.insert(id, row.bytes);
        self.memory.insert(id, memory);
        self.total = total;
        Ok(())
    }
}

pub(super) fn prepare(
    state: &CompanionState,
    writes: &[Write],
    backing: &BackingReservationPort,
    excluded: Option<[u8; 32]>,
) -> Result<Prepared, Code> {
    let metadata_bytes = writes
        .len()
        .checked_mul(128)
        .and_then(|n| n.checked_add(8192))
        .ok_or(Code::RateLimited)?;
    let _metadata = backing
        .reserve(metadata_bytes)
        .map_err(|_| Code::RateLimited)?;
    let required = rows::required(writes, backing)?;
    let retirement = retirement::credit(state, writes, &required);
    let mut prepared = Prepared {
        objects: BTreeMap::new(),
        total: retirement.map_or(state.object_bytes, |(_, remaining)| remaining),
        retired: retirement.map(|(id, _)| id),
        memory: BTreeMap::new(),
    };
    for write in writes {
        let Some((TableId::E2eeObject, key, encoded)) = write.encoded_record() else {
            continue;
        };
        let decoded = rows::decode(TableId::E2eeObject, encoded, backing)?;
        prepared.admit(state, key, &decoded.value, &required, excluded, backing)?;
    }
    rows::complete(&required, state, &prepared.objects)?;
    Ok(prepared)
}

fn is_payload(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::ApplicationMls | Kind::WelcomeMls | Kind::StagedReinit | Kind::FederationEvent
    )
}

/// Mailbox retirement releases only the memory copy; stored bodies have independent owners.
pub(super) fn retire_payload(state: &mut CompanionState, id: &[u8; 32]) {
    if state.mailboxes.references_object(id) {
        return;
    }
    let Some(bytes) = state.objects.get(id) else {
        return;
    };
    let Ok((Kind::ApplicationMls | Kind::WelcomeMls | Kind::StagedReinit, _)) =
        agenc_relay_e2ee::object::ArcWireObject::peek(bytes)
    else {
        return;
    };
    let Some(total) = state.object_bytes.checked_sub(bytes.len()) else {
        return;
    };
    drop(state.objects.remove(id));
    state.object_memory.remove(id);
    state.object_bytes = total;
}
