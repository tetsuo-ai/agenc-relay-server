//! A reservation-only handle to the existing process memory budget.

#![forbid(unsafe_code)]

use super::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, MemoryPermit};
use crate::RuntimeError;
use crate::sync::Arc;

/// Cloning the handle grants no access to the budget's counters or limits.
#[derive(Clone)]
pub(crate) struct BackingReservationPort {
    budget: Arc<MemoryBudget>,
}

impl BackingReservationPort {
    pub(crate) fn new(budget: Arc<MemoryBudget>) -> Self {
        Self { budget }
    }

    pub(crate) fn reserve(&self, capacity: usize) -> Result<MemoryPermit, RuntimeError> {
        let charge =
            MemoryCharge::allocation(u64::try_from(capacity).map_err(|_| RuntimeError::Overflow)?)?;
        self.budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloned_ports_share_one_budget_and_release_only_their_own_reservations()
    -> Result<(), RuntimeError> {
        let charge = MemoryCharge::allocation(1)?;
        let budget = Arc::new(MemoryBudget::new(charge.bytes()));
        let first = BackingReservationPort::new(budget);
        let second = first.clone();
        let held = first.reserve(1)?;
        assert!(second.reserve(1).is_err());
        drop(first);
        assert!(second.reserve(1).is_err());
        drop(held);
        let replacement = second.reserve(1)?;
        assert!(second.reserve(1).is_err());
        drop(replacement);
        assert!(second.reserve(1).is_ok());
        Ok(())
    }
}
