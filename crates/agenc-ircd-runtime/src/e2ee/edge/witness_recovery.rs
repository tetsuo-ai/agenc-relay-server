//! Bounded retained metadata for unresolved historical chain witnesses.

#![forbid(unsafe_code)]

use crate::RuntimeError;
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_ircd_storage::e2ee_records::WitnessRow;

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
    pub(super) fn pending(&self) -> bool {
        !self.entries.is_empty()
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
        key: &agenc_ircd_storage::StoredKey,
        row: WitnessRow,
    ) -> Result<(), RuntimeError> {
        let conversation = WitnessRow::parse_key(key)?;
        self.witness_recovery.restore(conversation, row)
    }

    /// A persisted witness is not cleared by an ordinary resume or an
    /// unproven larger head. Its verified recovery carrier is still required.
    pub(crate) fn witness_recovery_pending(&self) -> bool {
        self.witness_failure.durable() || self.witness_recovery.pending()
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
