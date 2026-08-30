//! The one durable batch StateCore may have staged or in flight (spec 21.5,
//! lines 4152-4171 and 4203-4210).
//!
//! A `PendingMutationBatch` never leaves the state owner: it carries the
//! domain plans together with their fanout reservations, sink generations,
//! and origin markers, none of which may cross the storage boundary.

use std::collections::BTreeSet;

use agenc_ircd_domain::MutationPlan;
use agenc_ircd_types::{MonotonicTick, TransactionId};

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::durable::{EntityId, RetainedProjection, touched_entities};
use crate::state_core::fanout::FanoutReservation;

/// Plans one batch may gather (spec line 4152).
pub const MAX_BATCH_PLANS: usize = 256;
/// The gather window after the first staged plan (spec line 4153).
pub const GATHER_WINDOW_MILLIS: u64 = 1;

/// The connection whose command produced a staged plan, kept so a rejected
/// batch can render its bounded failure to the right sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedOrigin {
    /// The originating connection's queue generation.
    pub generation: ConnectionGeneration,
}

/// One plan waiting on the durable outcome.
pub(super) struct StagedPlan {
    plan: MutationPlan,
    fanout: FanoutReservation,
    origin: Option<StagedOrigin>,
    response_count_increment: u64,
}

impl StagedPlan {
    /// Binds a plan to the fanout it reserved and the connection it came from.
    #[must_use]
    pub(super) fn new(
        plan: MutationPlan,
        fanout: FanoutReservation,
        origin: Option<StagedOrigin>,
        response_count_increment: u64,
    ) -> Self {
        Self {
            plan,
            fanout,
            origin,
            response_count_increment,
        }
    }

    /// Borrows the domain plan.
    #[must_use]
    pub(super) const fn plan(&self) -> &MutationPlan {
        &self.plan
    }

    /// Returns the originating connection.
    #[must_use]
    pub(super) const fn origin(&self) -> Option<StagedOrigin> {
        self.origin
    }

    /// Returns the response-count permits this plan consumes.
    #[must_use]
    pub(super) const fn response_count_increment(&self) -> u64 {
        self.response_count_increment
    }

    /// Splits the staged plan into its domain plan and fanout reservation.
    pub(super) fn into_parts(self) -> (MutationPlan, FanoutReservation, Option<StagedOrigin>) {
        (self.plan, self.fanout, self.origin)
    }
}

/// Where the batch is in its life.
pub(super) enum BatchPhase {
    /// Plans may still join until the deadline or the count ceiling.
    Gathering {
        /// The monotonic tick the window closes at.
        deadline: MonotonicTick,
    },
    /// The batch was handed to storage; nothing may join.
    InFlight {
        /// The transaction identity the receipt must carry.
        transaction_id: TransactionId,
        /// What the index applies after `Committed`.
        retained: RetainedProjection,
    },
}

/// The batch and everything reserved for it.
pub(super) struct PendingMutationBatch {
    plans: Vec<StagedPlan>,
    reserved: BTreeSet<EntityId>,
    phase: BatchPhase,
}

/// Why a plan could not join the batch; the plan is handed back untouched.
pub(super) enum StageRefusal {
    /// The batch is already with storage.
    InFlight,
    /// The batch holds the maximum number of plans.
    Full,
    /// The plan expects a revision the staged chain does not produce, or it
    /// touches an entity the batch already reserved.
    Incompatible,
}

impl PendingMutationBatch {
    /// Opens a batch with its first plan and starts the gather window.
    pub(super) fn start(plan: StagedPlan, now: MonotonicTick) -> Result<Self, RuntimeError> {
        let deadline = MonotonicTick::from_ticks(
            now.get()
                .checked_add(GATHER_WINDOW_MILLIS)
                .ok_or(RuntimeError::Overflow)?,
        );
        let reserved = touched_entities(&plan.plan);
        Ok(Self {
            plans: vec![plan],
            reserved,
            phase: BatchPhase::Gathering { deadline },
        })
    }

    /// Adds a plan to a gathering batch when it chains on the previous plan's
    /// resulting revision and touches no reserved entity.
    pub(super) fn try_stage(&mut self, plan: StagedPlan) -> Result<(), StageRefusal> {
        if matches!(self.phase, BatchPhase::InFlight { .. }) {
            return Err(StageRefusal::InFlight);
        }
        if self.plans.len() >= MAX_BATCH_PLANS {
            return Err(StageRefusal::Full);
        }
        let chained = self
            .plans
            .last()
            .is_some_and(|last| last.plan.resulting_revision() == plan.plan.expected_revision());
        let touched = touched_entities(&plan.plan);
        if !chained || !self.reserved.is_disjoint(&touched) {
            return Err(StageRefusal::Incompatible);
        }
        self.reserved.extend(touched);
        self.plans.push(plan);
        Ok(())
    }

    /// Returns whether the gather window has closed or the batch is full.
    #[must_use]
    pub(super) fn gather_due(&self, now: MonotonicTick) -> bool {
        match self.phase {
            BatchPhase::Gathering { deadline } => {
                now >= deadline || self.plans.len() >= MAX_BATCH_PLANS
            }
            BatchPhase::InFlight { .. } => false,
        }
    }

    /// Returns the gather deadline while the batch still gathers.
    #[must_use]
    pub(super) fn gather_deadline(&self) -> Option<MonotonicTick> {
        match self.phase {
            BatchPhase::Gathering { deadline } => Some(deadline),
            BatchPhase::InFlight { .. } => None,
        }
    }

    /// Returns whether the batch is with storage.
    #[must_use]
    pub(super) const fn in_flight(&self) -> bool {
        matches!(self.phase, BatchPhase::InFlight { .. })
    }

    /// Returns the transaction identity once submitted.
    #[must_use]
    pub(super) const fn transaction_id(&self) -> Option<TransactionId> {
        match &self.phase {
            BatchPhase::InFlight { transaction_id, .. } => Some(*transaction_id),
            BatchPhase::Gathering { .. } => None,
        }
    }

    /// Marks the batch submitted; the completion receiver now belongs to
    /// StateCore alone (spec lines 4203-4206).
    pub(super) fn mark_in_flight(
        &mut self,
        transaction_id: TransactionId,
        retained: RetainedProjection,
    ) {
        self.phase = BatchPhase::InFlight {
            transaction_id,
            retained,
        };
    }

    /// Returns the number of staged plans.
    #[must_use]
    pub(super) fn len(&self) -> usize {
        self.plans.len()
    }

    /// Returns whether a plan touches an entity this batch reserved.
    #[must_use]
    pub(super) fn conflicts_with(&self, plan: &MutationPlan) -> bool {
        !self.reserved.is_disjoint(&touched_entities(plan))
    }

    /// Borrows the staged plans in canonical order.
    #[must_use]
    pub(super) fn plans(&self) -> &[StagedPlan] {
        &self.plans
    }

    /// Consumes the batch into its plans and the retained projection.
    #[must_use]
    pub(super) fn finish(self) -> (Vec<StagedPlan>, Option<RetainedProjection>) {
        let retained = match self.phase {
            BatchPhase::InFlight { retained, .. } => Some(retained),
            BatchPhase::Gathering { .. } => None,
        };
        (self.plans, retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_domain::{AccountState, DomainState};
    use agenc_ircd_testkit::account_id;
    use agenc_ircd_types::{Generation, Revision};

    fn staged(expected_revision: u64, seed: u8) -> Result<StagedPlan, RuntimeError> {
        let revision = Revision::new(expected_revision).map_err(|_| RuntimeError::InvalidValue)?;
        let state = DomainState::restore(revision, Vec::new(), Vec::new(), Vec::new())
            .map_err(|_| RuntimeError::InvalidValue)?;
        let generation = Generation::new(1).map_err(|_| RuntimeError::InvalidValue)?;
        let account = AccountState::new(account_id(seed), generation, state.revision());
        let plan = state
            .plan_account_created(account)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(StagedPlan::new(plan, FanoutReservation::empty(), None, 0))
    }

    #[test]
    fn gathering_closes_at_one_millisecond_and_rejects_entity_conflicts() -> Result<(), RuntimeError>
    {
        let mut batch = PendingMutationBatch::start(staged(0, 1)?, MonotonicTick::from_ticks(10))?;
        assert_eq!(batch.gather_deadline(), Some(MonotonicTick::from_ticks(11)));
        assert!(!batch.gather_due(MonotonicTick::from_ticks(10)));
        batch
            .try_stage(staged(1, 2)?)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.try_stage(staged(2, 1)?),
            Err(StageRefusal::Incompatible)
        ));
        assert!(batch.gather_due(MonotonicTick::from_ticks(11)));
        Ok(())
    }

    #[test]
    fn gathering_accepts_exactly_the_256_plan_boundary() -> Result<(), RuntimeError> {
        let mut batch = PendingMutationBatch::start(staged(0, 0)?, MonotonicTick::from_ticks(0))?;
        for index in 1..MAX_BATCH_PLANS {
            let seed = u8::try_from(index).map_err(|_| RuntimeError::Overflow)?;
            batch
                .try_stage(staged(
                    u64::try_from(index).map_err(|_| RuntimeError::Overflow)?,
                    seed,
                )?)
                .map_err(|_| RuntimeError::InvalidValue)?;
        }
        assert_eq!(batch.len(), MAX_BATCH_PLANS);
        assert!(batch.gather_due(MonotonicTick::from_ticks(0)));
        assert!(matches!(
            batch.try_stage(staged(
                u64::try_from(MAX_BATCH_PLANS).map_err(|_| RuntimeError::Overflow)?,
                0,
            )?),
            Err(StageRefusal::Full)
        ));
        Ok(())
    }

    #[test]
    fn gathering_deadline_overflow_is_rejected() -> Result<(), RuntimeError> {
        assert_eq!(
            PendingMutationBatch::start(staged(0, 1)?, MonotonicTick::from_ticks(u64::MAX)).err(),
            Some(RuntimeError::Overflow)
        );
        Ok(())
    }
}
