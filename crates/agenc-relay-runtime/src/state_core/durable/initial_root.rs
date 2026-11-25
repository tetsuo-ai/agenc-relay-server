//! Account-private ownership retained against the process-wide memory budget.
#![forbid(unsafe_code)]

use std::sync::Arc;

use agenc_relay_storage::e2ee_records::initial_root::RootClaimOwner;

use super::DurableIndex;
use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryBudget, MemoryPermit};

/// Covers the private index entry, its immutable row, and the one replacement
/// held by the serialized writer until its commit publishes or is discarded.
/// The process budget adds allocator bookkeeping and rounds up to its quantum.
pub(super) const ROOT_SLOT_CAPACITY: usize = 2_048;
const _: () = assert!(2 * size_of::<BackedRootClaim>() < ROOT_SLOT_CAPACITY);

/// An immutable private result and the lifetime reservation for this account.
pub struct BackedRootClaim {
    row: RootClaimOwner,
    backing: Arc<MemoryPermit>,
}

impl BackedRootClaim {
    pub(in crate::state_core) const fn row(&self) -> &RootClaimOwner {
        &self.row
    }
}

impl PartialEq for BackedRootClaim {
    fn eq(&self, other: &Self) -> bool {
        self.row == other.row
    }
}

impl Eq for BackedRootClaim {}

impl DurableIndex {
    pub(crate) fn with_initial_root_budget(
        mut self,
        budget: &crate::sync::Arc<MemoryBudget>,
    ) -> Self {
        self.initial_root_backing
            .get_or_insert_with(|| BackingReservationPort::new(crate::sync::Arc::clone(budget)));
        self
    }

    pub(in crate::state_core) fn back_root_owner(
        &self,
        row: RootClaimOwner,
    ) -> Result<Arc<BackedRootClaim>, RuntimeError> {
        let backing = match self.initial_root_owners.get(&row.account) {
            Some(previous) => Arc::clone(&previous.backing),
            None if let Some(slot) =
                self.guarded_directory
                    .restored_slot(&super::guarded_directory::account(
                        row.network,
                        row.account,
                    )?) =>
            {
                Arc::clone(slot)
            }
            None => Arc::new(
                self.initial_root_backing
                    .as_ref()
                    .ok_or(RuntimeError::MemoryExhausted)?
                    .reserve(ROOT_SLOT_CAPACITY)?,
            ),
        };
        Ok(Arc::new(BackedRootClaim { row, backing }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::MemoryCharge;
    use crate::state_core::durable::IndexUpdate;
    use crate::test_support::TestResult;
    use agenc_relay_crypto::InitialRootClaimOwner;
    use agenc_relay_storage::e2ee_records::initial_root::RootClaimState;
    use agenc_relay_types::{AccountRandomId, NetworkId, RecoveryEpoch, RequestId};

    fn reserved(seed: u8) -> RootClaimOwner {
        RootClaimOwner {
            network: NetworkId::from_bytes([1; 32]),
            account: AccountRandomId::from_bytes([seed; 16]).to_account_id(),
            epoch: RecoveryEpoch::from_bytes([2; 16]),
            start: RequestId::from_bytes([3; 16]),
            owner: InitialRootClaimOwner::from_protected_bytes([4; 32]),
            state: RootClaimState::Reserved,
        }
    }

    #[test]
    fn initial_root_live_and_recovered_rows_share_one_charged_slot_through_publication()
    -> TestResult {
        let rounded = MemoryCharge::allocation(u64::try_from(ROOT_SLOT_CAPACITY)?)?.bytes();
        let short = crate::sync::Arc::new(MemoryBudget::new(rounded - 1));
        let unbacked = DurableIndex::new();
        assert!(matches!(
            unbacked.back_root_owner(reserved(1)),
            Err(RuntimeError::MemoryExhausted)
        ));
        let refusing = DurableIndex::new().with_initial_root_budget(&short);
        assert!(matches!(
            refusing.back_root_owner(reserved(1)),
            Err(RuntimeError::MemoryExhausted)
        ));
        assert_eq!(short.charged(), 0);
        let budget = crate::sync::Arc::new(MemoryBudget::new(rounded));
        let mut index = DurableIndex::new().with_initial_root_budget(&budget);
        let first = reserved(1);
        let key = first.account;
        let chosen = first.transition(RootClaimState::Chosen([5; 32]))?;
        let published = chosen.transition(RootClaimState::Published {
            fingerprint: [5; 32],
            object_id: [6; 32],
        })?;
        let prepared = index.back_root_owner(first)?;
        assert_eq!(budget.charged(), rounded);
        assert!(index.initial_root_owners.is_empty());
        index.apply(&[IndexUpdate::InitialRootOwner(prepared)]);
        let aborted = index.back_root_owner(chosen)?;
        drop(aborted);
        let original = index
            .initial_root_owners
            .get(&key)
            .ok_or("original retained")?;
        assert!(matches!(original.row().state, RootClaimState::Reserved));
        let chosen = original.row().transition(RootClaimState::Chosen([5; 32]))?;
        for row in [chosen, published] {
            let replacement = index.back_root_owner(row)?;
            index.apply(&[IndexUpdate::InitialRootOwner(replacement)]);
            assert!(matches!(
                index.back_root_owner(reserved(2)),
                Err(RuntimeError::MemoryExhausted)
            ));
            assert_eq!(budget.charged(), rounded);
        }
        index.apply(&[IndexUpdate::RemoveInitialRootOwner(key)]);
        assert_eq!(budget.available(), rounded);
        let abandoned = index.back_root_owner(reserved(2))?;
        drop(abandoned);
        assert_eq!(budget.available(), rounded);
        Ok(())
    }
}
