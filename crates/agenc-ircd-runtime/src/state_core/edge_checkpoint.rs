//! Exclusive ordinary-edge checkpoints with exact prepublication admission.

use super::StateCoreContext;
use super::durable::{AccountServiceDurableWrite, preflight_checkpoint};
use super::fanout::{FanoutRefused, FanoutRequest};
use super::pending::{PendingMutationBatch, StagedPlan};
use crate::RuntimeError;
use agenc_ircd_storage::{StorageError, TableId};

/// Only resource failures from this exact preparation may shrink a prefix.
#[derive(Debug)]
pub(crate) enum CheckpointRefused {
    Resource,
    Busy,
    Invalid,
}

impl StateCoreContext {
    /// Both the prior receipt and its authenticated index refresh must finish.
    pub(crate) fn edge_checkpoint_ready(&self) -> bool {
        self.pending.is_none() && !self.index.has_pending()
    }

    /// Owns the final rows behind one exclusive checkpoint. The plan has no
    /// domain events or entity writes, so history adds nothing; a coordinator
    /// projector is explicitly refused. Submission reprojects this exact row
    /// set and cannot accept a second plan before the receipt.
    pub(crate) fn stage_edge_checkpoint(
        &mut self,
        revision: u64,
        request: FanoutRequest,
        writes: Vec<AccountServiceDurableWrite>,
    ) -> Result<(), CheckpointRefused> {
        if !self.edge_checkpoint_ready() || self.quiescing {
            return Err(CheckpointRefused::Busy);
        }
        if self.federation.is_some() || !edge_rows(&writes) {
            return Err(CheckpointRefused::Invalid);
        }
        let plan = self
            .domain
            .plan_account_service_checkpoint()
            .map_err(|_| CheckpointRefused::Invalid)?;
        if plan.resulting_revision().get() != revision {
            return Err(CheckpointRefused::Invalid);
        }
        preflight_checkpoint(
            &writes,
            revision,
            &self.index,
            &self.keys,
            self.head,
            self.ceilings,
        )
        .map_err(preflight_refusal)?;
        let reservation = self.reserve_fanout(&request).map_err(fanout_refusal)?;
        if reservation.slow_consumer_count() != 0 {
            return Err(CheckpointRefused::Resource);
        }
        let staged = StagedPlan::with_account_service_writes(plan, reservation, None, 0, writes);
        let batch = PendingMutationBatch::start_exclusive(staged, self.now())
            .map_err(|_| CheckpointRefused::Invalid)?;
        self.pending = Some(batch);
        Ok(())
    }
}

fn edge_rows(writes: &[AccountServiceDurableWrite]) -> bool {
    !writes.is_empty()
        && writes.iter().all(|write| {
            let table = match write {
                AccountServiceDurableWrite::Put { table, .. }
                | AccountServiceDurableWrite::Delete { table, .. } => *table,
            };
            matches!(
                table,
                TableId::EdgeProjection | TableId::FederationPeer | TableId::RequestResult
            )
        })
}

fn preflight_refusal(error: RuntimeError) -> CheckpointRefused {
    match error {
        RuntimeError::Storage(StorageError::LimitExceeded) | RuntimeError::MemoryExhausted => {
            CheckpointRefused::Resource
        }
        _ => CheckpointRefused::Invalid,
    }
}

fn fanout_refusal(error: FanoutRefused) -> CheckpointRefused {
    match error {
        FanoutRefused::MemoryExhausted
        | FanoutRefused::Prepare(crate::connection::sink::QueueAllocationError::AllocationFailed)
        | FanoutRefused::Invalid(RuntimeError::MemoryExhausted | RuntimeError::LimitExceeded) => {
            CheckpointRefused::Resource
        }
        _ => CheckpointRefused::Invalid,
    }
}
