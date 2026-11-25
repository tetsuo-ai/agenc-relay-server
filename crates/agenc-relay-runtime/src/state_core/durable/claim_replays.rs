//! Bounded ownership of exact private account-service results. The permanent root
//! choice lives in its independent immutable account record.
#![forbid(unsafe_code)]

use super::{DurableIndex, IndexUpdate, Projection};
use crate::RuntimeError;
use crate::budget::MemoryPermit;
use agenc_relay_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_relay_types::{AccountId, RequestId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(crate) const CLAIM_REPLAY_SECONDS: u64 = 7 * 24 * 60 * 60;
const PER_ACCOUNT: usize = 128;
const TOTAL: usize = 16_384;
// Includes all three ordered entries and their share of the B-tree nodes.
const SLOT_BYTES: usize = 1_024;

/// Audited metadata of one immutable protected exact result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ClaimReplay {
    pub(crate) account: AccountId,
    pub(crate) id: RequestId,
    pub(crate) expires: u64,
}

/// Process backing is held from before staging until this exact receipt is retired.
pub struct BackedClaimReplay {
    row: ClaimReplay,
    _backing: MemoryPermit,
}

impl PartialEq for BackedClaimReplay {
    fn eq(&self, other: &Self) -> bool {
        self.row == other.row
    }
}

impl Eq for BackedClaimReplay {}

#[derive(Default)]
pub(super) struct Receipts {
    by_id: BTreeMap<RequestId, Arc<BackedClaimReplay>>,
    by_expiry: BTreeSet<(u64, RequestId)>,
    by_account: BTreeSet<(AccountId, u64, RequestId)>,
}

impl Receipts {
    fn for_account(
        &self,
        account: AccountId,
    ) -> impl Iterator<Item = &(AccountId, u64, RequestId)> {
        self.by_account.range(
            (account, 0, RequestId::from_bytes([0; 16]))
                ..=(account, u64::MAX, RequestId::from_bytes([u8::MAX; 16])),
        )
    }

    pub(super) fn put(&mut self, held: &Arc<BackedClaimReplay>) {
        let row = held.row;
        self.by_account.insert((row.account, row.expires, row.id));
        self.by_expiry.insert((row.expires, row.id));
        self.by_id.insert(row.id, Arc::clone(held));
    }

    pub(super) fn remove(&mut self, id: RequestId) {
        if let Some(held) = self.by_id.remove(&id) {
            let row = held.row;
            self.by_expiry.remove(&(row.expires, row.id));
            self.by_account.remove(&(row.account, row.expires, row.id));
        }
    }

    fn require_capacity(
        &self,
        row: ClaimReplay,
        staged: &[IndexUpdate],
    ) -> Result<(), RuntimeError> {
        if self.by_id.contains_key(&row.id) {
            return Err(RuntimeError::InvalidValue);
        }
        let mut total = self.by_id.len();
        let mut owned = self.for_account(row.account).count();
        for update in staged {
            match update {
                IndexUpdate::RetainClaimReplay(held) if held.row.id == row.id => {
                    return Err(RuntimeError::InvalidValue);
                }
                IndexUpdate::RetainClaimReplay(held) => {
                    total += 1;
                    owned += usize::from(held.row.account == row.account);
                }
                IndexUpdate::RemoveClaimReplay(id) => {
                    let old = self.by_id.get(id).ok_or(RuntimeError::InvalidValue)?;
                    total = total.checked_sub(1).ok_or(RuntimeError::InvalidValue)?;
                    owned = owned
                        .checked_sub(usize::from(old.row.account == row.account))
                        .ok_or(RuntimeError::InvalidValue)?;
                }
                _ => {}
            }
        }
        if total >= TOTAL || owned >= PER_ACCOUNT {
            Err(RuntimeError::LimitExceeded)
        } else {
            Ok(())
        }
    }
}

impl DurableIndex {
    fn back_claim_replay(
        &self,
        row: ClaimReplay,
        staged: &[IndexUpdate],
    ) -> Result<Arc<BackedClaimReplay>, RuntimeError> {
        self.claim_replays.require_capacity(row, staged)?;
        let backing = self
            .initial_root_backing
            .as_ref()
            .ok_or(RuntimeError::MemoryExhausted)?
            .reserve(SLOT_BYTES)?;
        Ok(Arc::new(BackedClaimReplay {
            row,
            _backing: backing,
        }))
    }

    pub(in crate::state_core) fn restore_claim_replay(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        if let Some(row) = crate::account_service::claim_replay_metadata(key, value)? {
            let held = self.back_claim_replay(row, &[])?;
            self.claim_replays.put(&held);
        }
        Ok(())
    }

    /// Atomically retire one mature receipt if needed for this claimant. An
    /// unexpired victim is never displaced to admit another protected response.
    pub(crate) fn claim_replay_room(
        &self,
        account: AccountId,
        now: u64,
    ) -> Result<Option<RequestId>, RuntimeError> {
        let replays = &self.claim_replays;
        let mut owned = replays.for_account(account);
        let first = owned.next();
        if first.is_some() && owned.count() + 1 >= PER_ACCOUNT {
            return first
                .filter(|(_, expires, _)| *expires <= now)
                .map(|(_, _, id)| Some(*id))
                .ok_or(RuntimeError::LimitExceeded);
        }
        let first_expired = replays
            .by_expiry
            .first()
            .filter(|(expires, _)| *expires <= now);
        if replays.by_id.len() >= TOTAL && first_expired.is_none() {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(first_expired.map(|(_, id)| *id))
    }

    pub(crate) fn expired_claim_replays(
        &self,
        now: u64,
        maximum: usize,
    ) -> impl Iterator<Item = RequestId> + '_ {
        self.claim_replays
            .by_expiry
            .iter()
            .take(maximum)
            .take_while(move |(expires, _)| *expires <= now)
            .map(|(_, id)| *id)
    }
}

impl Projection<'_> {
    pub(super) fn project_claim_replay(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        if let Some(row) = crate::account_service::claim_replay_metadata(key, value)? {
            if self.index.holds(TableId::RequestResult, key) {
                return Err(RuntimeError::InvalidValue);
            }
            let held = self.index.back_claim_replay(row, &self.updates)?;
            self.updates.push(IndexUpdate::RetainClaimReplay(held));
        } else if let Some(id) = request_for(key)
            && self.index.claim_replays.by_id.contains_key(&id)
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }

    pub(super) fn forget_claim_replay(&mut self, key: &StoredKey) -> Result<(), RuntimeError> {
        if let Some(id) = request_for(key)
            && self.index.claim_replays.by_id.contains_key(&id)
        {
            if self.updates.iter().any(
                |update| matches!(update, IndexUpdate::RemoveClaimReplay(staged) if staged == &id),
            ) {
                return Err(RuntimeError::InvalidValue);
            }
            self.updates.push(IndexUpdate::RemoveClaimReplay(id));
        }
        Ok(())
    }
}

fn request_for(key: &StoredKey) -> Option<RequestId> {
    key.as_bytes().try_into().ok().map(RequestId::from_bytes)
}

#[cfg(test)]
mod tests;
