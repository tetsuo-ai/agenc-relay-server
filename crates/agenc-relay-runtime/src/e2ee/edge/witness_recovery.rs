//! Bounded retained metadata for unresolved historical chain witnesses.

#![forbid(unsafe_code)]

use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_relay_storage::e2ee_records::WitnessRow;

// The existing authenticated edge reconstruction row ceiling.
const MAX_RETAINED_WITNESSES: usize = 1_000_000;

type RecoveryWitness = ([u8; 32], WitnessRow);

#[derive(Default)]
pub(super) struct WitnessRecovery {
    backing: Option<BackingReservationPort>,
    entries: Vec<RecoveryWitness>,
    // Release the backing before returning its charge.
    permit: Option<MemoryPermit>,
}

impl WitnessRecovery {
    /// Whether a retained row still blocks every conversation: a row an
    /// authenticated resolution marked `conflict` blocks only its own.
    pub(super) fn pending(&self) -> bool {
        self.entries.iter().any(|(_, row)| !row.conflict)
    }

    /// The admission port every retained row is charged against.
    pub(super) fn backing(&self) -> Option<BackingReservationPort> {
        self.backing.clone()
    }

    /// The retained rows in conversation order.
    pub(super) fn entries(&self) -> &[RecoveryWitness] {
        &self.entries
    }

    fn find(&self, conversation: &[u8; 32]) -> Result<usize, usize> {
        self.entries
            .binary_search_by_key(conversation, |entry| entry.0)
    }

    /// The retained row of `conversation`.
    pub(super) fn row(&self, conversation: &[u8; 32]) -> Option<&WitnessRow> {
        let index = self.find(conversation).ok()?;
        self.entries.get(index).map(|entry| &entry.1)
    }

    /// Drops the row of `conversation` after its durable deletion.
    pub(super) fn forget(&mut self, conversation: &[u8; 32]) -> bool {
        let Ok(index) = self.find(conversation) else {
            return false;
        };
        self.entries.remove(index);
        true
    }

    /// Marks the row of `conversation` a durable conflict.
    pub(super) fn mark_conflict(&mut self, conversation: &[u8; 32]) -> bool {
        let Ok(index) = self.find(conversation) else {
            return false;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return false;
        };
        entry.1.conflict = true;
        true
    }

    pub(super) fn install_backing(
        &mut self,
        port: BackingReservationPort,
    ) -> Result<(), RuntimeError> {
        if self.backing.is_some() || !self.entries.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        self.backing = Some(port);
        Ok(())
    }

    pub(super) fn restore(
        &mut self,
        conversation: [u8; 32],
        row: WitnessRow,
    ) -> Result<(), RuntimeError> {
        let port = self
            .backing
            .as_ref()
            .ok_or(RuntimeError::InvalidValue)?
            .clone();
        self.reserve_one(&port)?;
        self.insert_reserved(conversation, row)
    }

    fn reserve_one(&mut self, port: &BackingReservationPort) -> Result<(), RuntimeError> {
        if self.entries.len() < self.entries.capacity() {
            return Ok(());
        }
        let needed = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        if needed > MAX_RETAINED_WITNESSES {
            return Err(RuntimeError::LimitExceeded);
        }
        let capacity = self
            .entries
            .capacity()
            .max(1)
            .checked_mul(2)
            .ok_or(RuntimeError::Overflow)?
            .min(MAX_RETAINED_WITNESSES);
        self.grow(port, capacity.max(needed))
    }

    fn grow(&mut self, port: &BackingReservationPort, capacity: usize) -> Result<(), RuntimeError> {
        let bytes = capacity
            .checked_mul(std::mem::size_of::<RecoveryWitness>())
            .ok_or(RuntimeError::Overflow)?;
        let permit = port.reserve(bytes)?;
        let mut next = Vec::new();
        if next.try_reserve_exact(capacity).is_err() || next.capacity() != capacity {
            drop(next);
            return Err(RuntimeError::MemoryExhausted);
        }
        next.append(&mut self.entries);
        let previous = std::mem::replace(&mut self.entries, next);
        drop(previous);
        self.permit = Some(permit);
        Ok(())
    }

    fn insert_reserved(
        &mut self,
        conversation: [u8; 32],
        row: WitnessRow,
    ) -> Result<(), RuntimeError> {
        match self
            .entries
            .binary_search_by_key(&conversation, |entry| entry.0)
        {
            Ok(index) => {
                *self
                    .entries
                    .get_mut(index)
                    .ok_or(RuntimeError::InvalidValue)? = (conversation, row);
            }
            Err(index) => {
                if self.entries.len() == self.entries.capacity() {
                    return Err(RuntimeError::MemoryExhausted);
                }
                self.entries.insert(index, (conversation, row));
            }
        }
        Ok(())
    }
}

impl super::E2eeEdge {
    pub(crate) fn restore_witness_backing(
        &mut self,
        backing: BackingReservationPort,
    ) -> Result<(), RuntimeError> {
        self.witness_recovery.install_backing(backing)
    }

    pub(crate) fn restore_chain_witness(
        &mut self,
        key: &agenc_relay_storage::StoredKey,
        row: WitnessRow,
    ) -> Result<(), RuntimeError> {
        let conversation = WitnessRow::parse_key(key)?;
        self.witness_recovery.restore(conversation, row)
    }

    /// A persisted witness is not cleared by an ordinary resume or an
    /// unproven larger head. Its verified recovery carrier is still required.
    /// A row an authenticated resolution marked `conflict` no longer blocks
    /// the link; it blocks only its own conversation, permanently (12.5.1).
    pub(crate) fn witness_recovery_pending(&self) -> bool {
        self.witness_failure.durable() || self.witness_recovery.pending()
    }

    /// Whether `conversation` holds a durable `witness/v1` row of any kind,
    /// so its route still reads `E2EE_SYNCING`.
    pub(crate) fn witness_conversation_blocked(&self, conversation: &[u8; 32]) -> bool {
        self.durable_witness_row(conversation).is_some()
    }

    /// The durable rows awaiting an `EWITNESS` resolution, in conversation
    /// order: the just-recorded violation and every restored row.
    pub(super) fn unresolved_witnesses(&self) -> Vec<([u8; 32], WitnessRow)> {
        let mut rows: Vec<([u8; 32], WitnessRow)> = self
            .witness_recovery
            .entries()
            .iter()
            .filter(|(_, row)| !row.conflict)
            .cloned()
            .collect();
        if let Some((conversation, row)) = self.witness_failure.durable_row()
            && rows.iter().all(|(known, _)| *known != conversation)
        {
            rows.push((conversation, row));
        }
        rows.sort_unstable_by_key(|(conversation, _)| *conversation);
        rows
    }

    /// The durable row of `conversation`, whichever owner holds it.
    pub(super) fn durable_witness_row(&self, conversation: &[u8; 32]) -> Option<WitnessRow> {
        self.witness_recovery
            .row(conversation)
            .cloned()
            .or_else(|| {
                self.witness_failure
                    .durable_row()
                    .filter(|(known, _)| known == conversation)
                    .map(|(_, row)| row)
            })
    }

    /// Forgets the durable row of `conversation` after its deletion committed.
    pub(super) fn forget_durable_witness(&mut self, conversation: &[u8; 32]) {
        let dropped = self.witness_recovery.forget(conversation);
        let released = self.witness_failure.forget_durable(conversation);
        let _both = dropped | released;
    }

    /// Marks the durable row of `conversation` a conflict after its receipt.
    pub(super) fn mark_durable_conflict(&mut self, conversation: &[u8; 32]) {
        let marked = self.witness_recovery.mark_conflict(conversation);
        let failed = self.witness_failure.mark_conflict(conversation);
        let _both = marked | failed;
    }

    /// The admission port retained resolution metadata is charged against.
    pub(super) fn witness_backing(&self) -> Option<BackingReservationPort> {
        self.witness_recovery.backing()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{MemoryBudget, MemoryCharge};
    use crate::sync::Arc;

    fn row(sequence: u64) -> WitnessRow {
        WitnessRow {
            event_kind: 17,
            expected_sequence: sequence,
            expected_head_id: [1; 32],
            observed_sequence: sequence.saturating_add(1),
            observed_id: [2; 32],
            observed_predecessor_id: None,
            conflict: false,
        }
    }

    #[test]
    fn historical_witness_growth_retains_its_backing_charge_until_owner_drop()
    -> Result<(), RuntimeError> {
        let budget = Arc::new(MemoryBudget::new(1 << 20));
        let mut owner = WitnessRecovery::default();
        owner.install_backing(BackingReservationPort::new(Arc::clone(&budget)))?;
        for index in [3, 1, 2] {
            owner.restore([index; 32], row(u64::from(index)))?;
        }
        assert_eq!(owner.entries.len(), 3);
        assert_eq!(owner.entries.capacity(), 4);
        assert_eq!(
            owner
                .entries
                .iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32], [3; 32]]
        );
        let bytes = 4_usize
            .checked_mul(std::mem::size_of::<RecoveryWitness>())
            .ok_or(RuntimeError::Overflow)?;
        let charge =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)?;
        assert_eq!(budget.charged(), charge.bytes());
        drop(owner);
        assert_eq!(budget.charged(), 0);
        Ok(())
    }

    #[test]
    fn refused_growth_preserves_prior_witnesses_and_their_allocation_charge()
    -> Result<(), RuntimeError> {
        let bytes = 2_usize
            .checked_mul(std::mem::size_of::<RecoveryWitness>())
            .ok_or(RuntimeError::Overflow)?;
        let charge =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)?;
        let budget = Arc::new(MemoryBudget::new(charge.bytes()));
        let mut owner = WitnessRecovery::default();
        owner.install_backing(BackingReservationPort::new(Arc::clone(&budget)))?;
        owner.restore([1; 32], row(1))?;
        owner.restore([2; 32], row(2))?;
        assert!(matches!(
            owner.restore([3; 32], row(3)),
            Err(RuntimeError::MemoryExhausted)
        ));
        assert_eq!(owner.entries.len(), 2);
        assert_eq!(owner.entries.capacity(), 2);
        assert_eq!(owner.entries.first(), Some(&([1; 32], row(1))));
        assert_eq!(owner.entries.last(), Some(&([2; 32], row(2))));
        assert_eq!(budget.charged(), charge.bytes());
        drop(owner);
        assert_eq!(budget.charged(), 0);
        Ok(())
    }

    #[test]
    fn restoration_without_a_backing_port_refuses_before_allocation() {
        let mut owner = WitnessRecovery::default();
        assert!(matches!(
            owner.restore([1; 32], row(1)),
            Err(RuntimeError::InvalidValue)
        ));
        assert_eq!(owner.entries.len(), 0);
        assert_eq!(owner.entries.capacity(), 0);
    }
}
