//! Completed replay rows retire only behind an independent durable origin sequence floor.
#![forbid(unsafe_code)]

use super::{
    CompanionCoordinator, CompanionFault, CompanionOriginKey, CompanionState, response_read,
};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::origin::OriginSequenceRow;
use agenc_ircd_storage::e2ee_records::{ReplayKey, ReplayRow};
use std::ops::Bound::{Excluded, Unbounded};

pub(crate) const MAX_EXPIRY_ENTRIES: usize = 128;
const MAX_RESULT_BYTES: usize = 8192;
const MAX_RESPONSES: usize = 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Cursor(Option<ReplayKey>);

struct Change {
    key: ReplayKey,
    row: ReplayRow,
    owner: OriginSequenceRow,
}

pub(crate) struct Prepared {
    changes: Vec<Change>,
    next: Cursor,
    _backing: MemoryPermit,
}

impl Prepared {
    pub(crate) fn capture(
        executor: &CompanionCoordinator,
        cursor: Cursor,
        now: u64,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let metadata = backing
            .reserve(MAX_EXPIRY_ENTRIES * 2048 + 8192)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut prepared = Self {
            changes: Vec::with_capacity(MAX_EXPIRY_ENTRIES),
            next: cursor,
            _backing: metadata,
        };
        let start = cursor.0.map_or(Unbounded, Excluded);
        let mut scanned = 0;
        for (key, row) in executor
            .state
            .replays
            .range((start, Unbounded))
            .take(MAX_EXPIRY_ENTRIES)
        {
            scanned += 1;
            prepared.next = Cursor(Some(*key));
            if row.result_object_id.is_none() || row.retain_until == 0 || row.retain_until > now {
                continue;
            }
            let Some(owner) = covering_owner(&executor.state, key) else {
                continue;
            };
            let stored = executor
                .state
                .results
                .get(&row.request_object_id)
                .ok_or(CompanionFault::Storage)?;
            let _decode = backing
                .reserve(MAX_RESULT_BYTES * 4 + 8192)
                .map_err(|_| CompanionFault::Ceiling)?;
            response_read::validate_retained(executor, *key, row, stored)?;
            prepared.changes.push(Change {
                key: *key,
                row: row.clone(),
                owner,
            });
        }
        if scanned < MAX_EXPIRY_ENTRIES {
            prepared.next = Cursor::default();
        }
        Ok(prepared)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
    pub(crate) fn next_cursor(&self) -> Cursor {
        self.next
    }
    pub(crate) fn completes_cycle(&self) -> bool {
        self.next == Cursor::default()
    }

    pub(crate) fn writes(&self, _revision: u64) -> Result<Vec<Write>, crate::RuntimeError> {
        self.changes
            .iter()
            .map(|change| Write::delete(TableId::E2eeState, ReplayRow::key(&change.key)?))
            .collect()
    }

    pub(crate) fn apply(&self, executor: &mut CompanionCoordinator) -> Result<(), CompanionFault> {
        if !self
            .changes
            .iter()
            .all(|change| change.matches(&executor.state))
        {
            return Err(CompanionFault::Storage);
        }
        for change in &self.changes {
            executor.state.replays.remove(&change.key);
        }
        for change in &self.changes {
            if !executor
                .state
                .replays
                .values()
                .any(|row| row.request_object_id == change.row.request_object_id)
            {
                executor.state.results.remove(&change.row.request_object_id);
            }
            if let Some(id) = change.row.result_object_id {
                retire_result(&mut executor.state, &id);
            }
        }
        Ok(())
    }
}

impl Change {
    fn matches(&self, state: &CompanionState) -> bool {
        if state.replays.get(&self.key) != Some(&self.row)
            || covering_owner(state, &self.key) != Some(self.owner)
        {
            return false;
        }
        let Some(stored) = state.results.get(&self.row.request_object_id) else {
            return false;
        };
        // The captured body was fully decoded. Its content ID proves the same identity here
        // without another allocation after storage has committed.
        stored.result.len() <= MAX_RESULT_BYTES
            && stored.responses.len() <= MAX_RESPONSES
            && self.row.result_object_id == Some(*ObjectId::compute(&stored.result).as_bytes())
            && self.row.response_object_ids == stored.responses
    }
}

fn covering_owner(state: &CompanionState, key: &ReplayKey) -> Option<OriginSequenceRow> {
    let owner = *state.origin_sequences.get(&CompanionOriginKey {
        home_server_id: key.home_server_id,
        server_incarnation: key.server_incarnation,
        origin_id: key.origin_id,
    })?;
    (owner.next_sequence != 0
        && (owner.origin_generation > key.origin_generation
            || owner.origin_generation == key.origin_generation
                && owner.next_sequence > key.operation_sequence))
        .then_some(owner)
}

fn retire_result(state: &mut CompanionState, id: &[u8; 32]) {
    if state
        .replays
        .values()
        .any(|row| row.result_object_id == Some(*id))
    {
        return;
    }
    let Some(bytes) = state.objects.get(id) else {
        return;
    };
    if !matches!(
        IrcWireObject::peek(bytes),
        Ok((IrcWireObjectKind::FederationResult, _))
    ) {
        return;
    }
    let Some(total) = state.object_bytes.checked_sub(bytes.len()) else {
        return;
    };
    // Stored object bodies and charged output/read owners have independent lifetimes.
    drop(state.objects.remove(id));
    state.object_memory.remove(id);
    state.object_bytes = total;
}
