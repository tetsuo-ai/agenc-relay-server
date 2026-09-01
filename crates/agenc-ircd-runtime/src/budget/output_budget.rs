//! The renderer's reservation authority backed by an acquired permit batch.

use agenc_ircd_client_wire::{OutputBudget, RenderError};

use super::{MemoryCharge, MemoryPermit, MemoryPermitBatch};

/// Splits frame permits out of one batch that StateCore acquired for a
/// complete fanout (spec 15.3, lines 2229-2232).
///
/// Each measured frame is charged as one backing allocation of exactly its
/// byte length, so the permit the encoded frame owns is
/// `allocation_charge(bytes)` (spec lines 2720-2723). Encoding therefore
/// allocates only capacity that the batch already holds.
pub struct PermitCursor<'a> {
    batch: &'a mut MemoryPermitBatch,
}

impl<'a> PermitCursor<'a> {
    /// Wraps a batch for one rendering pass.
    #[must_use]
    pub fn new(batch: &'a mut MemoryPermitBatch) -> Self {
        Self { batch }
    }
}

impl OutputBudget for PermitCursor<'_> {
    type Permit = MemoryPermit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        let capacity = u64::try_from(bytes).map_err(|_| RenderError::Overflow)?;
        let charge = MemoryCharge::allocation(capacity).map_err(|_| RenderError::Overflow)?;
        self.batch
            .split_exact(charge.bytes())
            .ok_or(RenderError::ReservationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeError;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort};

    #[test]
    fn the_cursor_reserves_the_allocation_charge_and_fails_closed() -> Result<(), RuntimeError> {
        let budget = MemoryBudget::new(20_000);
        let mut batch =
            budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::allocation(
                8_703,
            )?])?)?;
        let mut cursor = PermitCursor::new(&mut batch);
        let permit = cursor
            .try_reserve_exact(8_703)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(permit.bytes(), 12_288);
        assert_eq!(
            cursor.try_reserve_exact(1).err(),
            Some(RenderError::ReservationFailed)
        );
        assert_eq!(
            cursor.try_reserve_exact(usize::MAX).err(),
            Some(RenderError::Overflow)
        );
        drop(permit);
        drop(batch);
        assert_eq!(budget.available(), 20_000);
        Ok(())
    }
}
