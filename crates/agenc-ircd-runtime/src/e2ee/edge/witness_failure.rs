//! Retained metadata and exact receipt ownership for a refused record chain.

#![forbid(unsafe_code)]

use agenc_ircd_storage::e2ee_records::{WITNESS_ROW_KIND, WitnessRow};
use agenc_ircd_types::MonotonicTick;

use super::{E2eeEdge, PendingCommit};
use crate::RuntimeError;
use crate::federation::LinkId;
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;
use crate::state_core::timers::{TimedId, TimerEntry, TimerGeneration, TimerKind};

const RETRY_MILLIS: u64 = 100;

/// One node-wide timer is admitted before companion processing. Its next
/// reservation precedes each retry, so refused storage never loses its wake.
#[derive(Default)]
pub(super) struct WitnessFailure {
    timer: Option<TimerEntry>,
    record: Option<Record>,
}

struct Record {
    conversation: [u8; 32],
    row: WitnessRow,
    link: Option<LinkId>,
    staged: Option<WitnessRejection>,
    durable: bool,
}

impl WitnessFailure {
    /// Whether the recorded row is durable and still blocks the link; a row
    /// marked `conflict` blocks only its own conversation (12.5.1).
    pub(super) fn durable(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(|record| record.durable && !record.row.conflict)
    }

    /// The durable row this owner holds, with its conversation.
    pub(super) fn durable_row(&self) -> Option<([u8; 32], WitnessRow)> {
        let record = self.record.as_ref().filter(|record| record.durable)?;
        Some((record.conversation, record.row.clone()))
    }

    /// Releases the durable row of `conversation` after its deletion
    /// committed, so a later violation may take the owner again.
    pub(super) fn forget_durable(&mut self, conversation: &[u8; 32]) -> bool {
        let owns = self
            .record
            .as_ref()
            .is_some_and(|record| record.durable && record.conversation == *conversation);
        if owns {
            self.record = None;
        }
        owns
    }

    /// Marks the durable row of `conversation` a conflict.
    pub(super) fn mark_conflict(&mut self, conversation: &[u8; 32]) -> bool {
        let Some(record) = self
            .record
            .as_mut()
            .filter(|record| record.durable && record.conversation == *conversation)
        else {
            return false;
        };
        record.row.conflict = true;
        true
    }
}

/// One attempt captured before another rejection callback may stage work.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct WitnessRejection {
    staged_after: u64,
    generation: TimerGeneration,
}

impl E2eeEdge {
    pub(super) fn witness_pending(&self) -> bool {
        self.witness_failure
            .record
            .as_ref()
            .is_some_and(|record| !record.durable)
            || self.witnessed.is_some()
    }

    pub(super) fn prepare_witness_retry(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> bool {
        if self.witness_failure.timer.is_some() {
            return true;
        }
        if self.arm_witness_retry(context).is_ok() {
            return true;
        }
        // This admission check precedes witness decoding and consumption.
        edge.fail_companion_link(context);
        self.link_down();
        false
    }

    fn arm_witness_retry(&mut self, context: &mut StateCoreContext) -> Result<(), RuntimeError> {
        let deadline = MonotonicTick::from_ticks(
            context
                .now()
                .get()
                .checked_add(RETRY_MILLIS)
                .ok_or(RuntimeError::Overflow)?,
        );
        let kind = TimerKind::CompanionWitnessRetry;
        let id = TimedId::Peer(self.config.coordinator_server_id);
        let generation = context.timers_mut().schedule(deadline, kind, id)?;
        self.witness_failure.timer = Some(TimerEntry {
            deadline,
            kind,
            id,
            generation,
        });
        Ok(())
    }

    pub(super) fn record_witness(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
    ) -> bool {
        if let Some(record) = self.witness_failure.record.as_ref() {
            // The retained record owns the close until its receipt stands,
            // and a second observation is dropped with it. Once the receipt
            // stands the owner is settled, so a failure that observed no new
            // violation is an ordinary profile violation: a refused witness
            // resolution closes the link and retains the row (12.5.1).
            return !record.durable || self.witnessed.take().is_some();
        }
        let Some((conversation, row)) = self.witnessed.take() else {
            return false;
        };
        self.witness_failure.record = Some(Record {
            conversation,
            row,
            link: edge.current_companion_link_id(),
            staged: None,
            durable: false,
        });
        self.try_witness_stage(context);
        true
    }

    fn try_witness_stage(&mut self, context: &mut StateCoreContext) {
        if self.commit.is_some()
            || context.pending_len() != 0
            || context.in_flight()
            || context.is_quiescing()
            || self.witness_failure.timer.is_none()
        {
            return;
        }
        let Some(record) = self.witness_failure.record.as_ref() else {
            return;
        };
        if record.staged.is_some() || record.durable {
            return;
        }
        let Some(timer) = self.witness_failure.timer else {
            return;
        };
        let write = WitnessRow::key(&record.conversation)
            .and_then(|key| Ok((key, record.row.encode()?)))
            .ok()
            .and_then(|(key, body)| super::events::state_row(key, WITNESS_ROW_KIND, body).ok());
        let Some(write) = write else {
            return;
        };
        let before = context.head().storage_commit_sequence;
        if self
            .stage(context, vec![write], PendingCommit::Witness)
            .is_ok()
            && let Some(record) = self.witness_failure.record.as_mut()
        {
            record.staged = Some(WitnessRejection {
                staged_after: before,
                generation: timer.generation,
            });
        }
    }

    pub(crate) fn witness_timer_fired(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        entry: TimerEntry,
    ) -> bool {
        if entry.kind == TimerKind::CompanionWitnessResolution {
            self.witness_request_wake_fired(context, edge, entry);
            return true;
        }
        if entry.kind != TimerKind::CompanionWitnessRetry {
            return false;
        }
        let owned = self.witness_failure.timer.is_some_and(|timer| {
            timer.id == entry.id
                && timer.generation == entry.generation
                && timer.deadline == entry.deadline
        });
        if !owned {
            return true;
        }
        self.witness_failure.timer = None;
        // The due entry has freed its slot. Re-arm before any stage can
        // allocate unrelated timers or receive a determinate rejection.
        if !self.prepare_witness_retry(context, edge) {
            return true;
        }
        self.try_witness_stage(context);
        true
    }

    pub(super) fn witness_batch_applied(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> bool {
        let Some(record) = self.witness_failure.record.as_ref() else {
            return false;
        };
        if record.durable {
            // The receipt already stood; this batch belongs to another
            // owner, such as the resolution that deletes the row (12.5.1).
            return false;
        }
        let committed = record
            .staged
            .and_then(|attempt| attempt.staged_after.checked_add(1))
            == Some(context.head().storage_commit_sequence)
            && matches!(self.commit, Some(PendingCommit::Witness));
        if !committed {
            return true;
        }
        let original = record.link;
        if let Some(record) = self.witness_failure.record.as_mut() {
            record.durable = true;
            record.staged = None;
        }
        if let Some(timer) = self.witness_failure.timer.take() {
            context.timers_mut().cancel(timer.kind, timer.id);
        }
        self.commit = None;
        self.counters.chain_violations = self.counters.chain_violations.saturating_add(1);
        if original.is_some() && original == edge.current_companion_link_id() {
            self.counters.violations = self.counters.violations.saturating_add(1);
            edge.fail_companion_witness(context);
        }
        self.link_down();
        true
    }

    /// StateCore has removed the rejected batch before entering registration.
    /// Capture here, before any other role can stage a successor batch.
    pub(crate) fn witness_rejection(&self, context: &StateCoreContext) -> Option<WitnessRejection> {
        let attempt = self.witness_failure.record.as_ref()?.staged?;
        (context.pending_len() == 0
            && !context.in_flight()
            && attempt.staged_after == context.head().storage_commit_sequence
            && matches!(self.commit, Some(PendingCommit::Witness)))
        .then_some(attempt)
    }

    pub(crate) fn witness_batch_rejected(&mut self, rejected: Option<WitnessRejection>) -> bool {
        let Some(record) = self.witness_failure.record.as_mut() else {
            return false;
        };
        if rejected.is_some()
            && record.staged == rejected
            && matches!(self.commit, Some(PendingCommit::Witness))
        {
            record.staged = None;
            self.commit = None;
        }
        // The already-reserved timer retries after all old callbacks drain.
        true
    }
}

#[cfg(test)]
#[path = "tests/witness_failure_owner.rs"]
mod owner_tests;
