//! Per-generation retention limits enforced inside the projecting transaction.

#[cfg(test)]
mod tests;

use agenc_relay_storage::TableId;
use agenc_relay_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PeerPhase, peer_key,
};
use agenc_relay_types::ServerId;

use super::{
    CrossProfileAssignment, EdgeDelivery, FederationProjector, OutboundEvent, ProjectedOutput,
    row_write,
};
use crate::RuntimeError;

/// Current peer checkpoint and committed usage supplied by the link owner.
pub(crate) struct OutboxBudget {
    pub(crate) peer: FederationPeerRecord,
    pub(crate) objects: u64,
    pub(crate) bytes: u64,
    pub(crate) max_objects: u64,
    pub(crate) max_bytes: u64,
    pub(crate) barrier_open: bool,
}

impl FederationProjector {
    pub(crate) fn set_outbox_budget(&mut self, peer: ServerId, budget: OutboxBudget) {
        self.outbox_budgets.insert(peer, budget);
    }

    /// Takes only fences whose containing domain mutation has committed.
    pub(crate) fn take_outbox_fences(&mut self) -> Vec<ServerId> {
        std::mem::take(&mut self.committed_fences)
            .into_iter()
            .collect()
    }

    pub(super) fn fit_outbox(
        &self,
        peer: ServerId,
        delivery: EdgeDelivery,
        events: &[OutboundEvent],
        assignment: Option<CrossProfileAssignment>,
        output: &mut ProjectedOutput,
    ) -> Result<bool, RuntimeError> {
        if events.is_empty() {
            return Ok(true);
        }
        let Some(budget) = self.outbox_budgets.get(&peer) else {
            return Ok(true);
        };
        let objects = u64::try_from(events.len()).map_err(|_| RuntimeError::Overflow)?;
        let bytes = events.iter().try_fold(0_u64, |sum, event| {
            let bytes = u64::try_from(event.encoded.len()).map_err(|_| RuntimeError::Overflow)?;
            sum.checked_add(bytes).ok_or(RuntimeError::Overflow)
        })?;
        if budget
            .objects
            .checked_add(objects)
            .is_some_and(|count| count <= budget.max_objects)
            && budget
                .bytes
                .checked_add(bytes)
                .is_some_and(|count| count <= budget.max_bytes)
        {
            return Ok(true);
        }
        // A snapshot cannot replace a partial cross-profile barrier.
        if assignment.is_some() || budget.barrier_open {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut record = budget.peer.clone();
        record.projection_generation = delivery.projection_generation;
        record.next_delivery_sequence = delivery.next_delivery_sequence;
        record.snapshot_required = true;
        if record.phase == PeerPhase::Ready {
            record.phase = PeerPhase::Suspended;
        }
        output.writes.push(row_write(
            TableId::FederationPeer,
            PEER_RECORD_KIND,
            peer_key(peer)?,
            output.revision,
            0,
            record.encode()?,
        )?);
        output.fences.push(peer);
        Ok(false)
    }
}
