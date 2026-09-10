//! Stream preparation reserves its independent row container before cloning handles.
#![forbid(unsafe_code)]

use super::{CompanionFault, DeliveryStream, MAX_ACKED_REPLAY_ROWS, StreamRow};
use crate::budget::{BackingReservationPort, MemoryPermit};

pub(crate) struct Backing {
    _memory: MemoryPermit,
}

impl std::fmt::Debug for Backing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RowBacking")
            .field("bytes", &self._memory.bytes())
            .finish()
    }
}

impl DeliveryStream {
    pub(crate) fn with_row_capacity(
        capacity: usize,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let unacked = usize::try_from(agenc_ircd_e2ee::limits::MAX_UNACKED_E2EE_EVENTS_PER_EDGE)
            .map_err(|_| CompanionFault::Ceiling)?;
        let maximum = unacked
            .checked_add(MAX_ACKED_REPLAY_ROWS)
            .ok_or(CompanionFault::Ceiling)?;
        if capacity > maximum {
            return Err(CompanionFault::Ceiling);
        }
        let mut result = Self::default();
        if capacity == 0 {
            return Ok(result);
        }
        let bytes = capacity
            .checked_mul(std::mem::size_of::<StreamRow>())
            .ok_or(CompanionFault::Ceiling)?;
        // This local precedes the allocated queue. Any refusal drops the queue first.
        let memory = backing
            .reserve(bytes)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut rows = std::collections::VecDeque::new();
        rows.try_reserve_exact(capacity)
            .map_err(|_| CompanionFault::Ceiling)?;
        if rows.capacity() > capacity {
            return Err(CompanionFault::Ceiling);
        }
        result.rows = rows;
        result.row_backing = Some(Backing { _memory: memory });
        Ok(result)
    }

    /// Body allocations remain shared; this new metadata container has its own charge.
    pub(crate) fn try_clone(
        &self,
        additional: usize,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let capacity = self
            .rows
            .len()
            .checked_add(additional)
            .ok_or(CompanionFault::Ceiling)?;
        let mut result = Self::with_row_capacity(capacity, backing)?;
        result.owner = self.owner.clone();
        result.generation = self.generation;
        result.next_sequence = self.next_sequence;
        result.acked = self.acked;
        result.blocked = self.blocked;
        result.barrier = self.barrier;
        result.hold_after = self.hold_after;
        result.replay = self.replay;
        result.rows.extend(self.rows.iter().cloned());
        Ok(result)
    }
}

// Resource handles do not change the semantic delivery state compared by tests.
impl PartialEq for DeliveryStream {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.generation == other.generation
            && self.next_sequence == other.next_sequence
            && self.acked == other.acked
            && self.rows == other.rows
            && self.blocked == other.blocked
            && self.barrier == other.barrier
            && self.hold_after == other.hold_after
            && self.replay == other.replay
    }
}
impl Eq for DeliveryStream {}

#[cfg(test)]
mod tests;
