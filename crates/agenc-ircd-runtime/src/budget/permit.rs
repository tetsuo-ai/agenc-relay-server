//! RAII permits minted only by the budget (spec 24.2, lines 6513-6518).

use super::Ledger;
use crate::sync::Arc;

/// Exact bytes held against the live pool until dropped.
///
/// The type has private fields, no `Clone`, and returns its bytes exactly
/// once through `Drop`, so a permit cannot be minted, inflated, duplicated,
/// or forgotten by any caller.
#[must_use = "dropping a permit returns its bytes to the budget"]
pub struct MemoryPermit {
    bytes: u64,
    ledger: Arc<Ledger>,
}

impl MemoryPermit {
    /// Returns the bytes this permit holds.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        self.ledger.release(self.bytes);
    }
}

/// One acquired batch that can be split into exact permits.
///
/// Splitting preserves the exact total: every split byte moves into the
/// returned permit and the remainder returns to the budget on drop.
#[must_use = "dropping a batch returns its unsplit bytes to the budget"]
pub struct MemoryPermitBatch {
    remaining: u64,
    ledger: Arc<Ledger>,
}

impl MemoryPermitBatch {
    pub(crate) fn new(total: u64, ledger: Arc<Ledger>) -> Self {
        Self {
            remaining: total,
            ledger,
        }
    }

    /// Returns the bytes not yet split out of this batch.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.remaining
    }

    /// Carves exactly `bytes` into a permit, or returns `None` when the
    /// batch holds fewer bytes and leaves it unchanged.
    pub fn split_exact(&mut self, bytes: u64) -> Option<MemoryPermit> {
        let remaining = self.remaining.checked_sub(bytes)?;
        self.remaining = remaining;
        Some(MemoryPermit {
            bytes,
            ledger: Arc::clone(&self.ledger),
        })
    }
}

impl Drop for MemoryPermitBatch {
    fn drop(&mut self) {
        self.ledger.release(self.remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
    use crate::RuntimeError;

    #[test]
    fn splits_are_exact_and_every_byte_returns_exactly_once() -> Result<(), RuntimeError> {
        let budget = MemoryBudget::new(10_000);
        let mut batch = budget.try_acquire_batch(BoundedMemoryCharges::new(vec![
            MemoryCharge::fixed(4_096),
            MemoryCharge::fixed(4_096),
        ])?)?;
        assert_eq!(batch.total(), 8_192);
        assert!(batch.split_exact(8_193).is_none());
        assert_eq!(batch.total(), 8_192);
        let first = batch.split_exact(4_096).ok_or(RuntimeError::InvalidValue)?;
        let zero = batch.split_exact(0).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(first.bytes(), 4_096);
        assert_eq!(zero.bytes(), 0);
        assert_eq!(batch.total(), 4_096);
        assert_eq!(budget.available(), 1_808);
        drop(first);
        assert_eq!(budget.available(), 5_904);
        drop(zero);
        assert_eq!(budget.available(), 5_904);
        drop(batch);
        assert_eq!(budget.available(), 10_000);
        Ok(())
    }
}
