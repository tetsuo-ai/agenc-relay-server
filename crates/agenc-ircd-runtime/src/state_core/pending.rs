//! The one durable batch StateCore may have staged or in flight (spec 21.5,
//! lines 4152-4171 and 4203-4210).
//!
//! A `PendingMutationBatch` never leaves the state owner: it carries the
//! domain plans together with their fanout reservations, sink generations,
//! and origin markers, none of which may cross the storage boundary.

use std::collections::BTreeSet;

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_domain::MutationPlan;
use agenc_ircd_types::{MonotonicTick, TransactionId};

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;
use crate::state_core::CommandObservation;
use crate::state_core::durable::{
    AccountServiceDurableWrite, EntityId, RetainedProjection, touched_entities,
};
use crate::state_core::fanout::FanoutReservation;
use crate::state_core::projector::PendingProjection;

/// Plans one batch may gather (spec line 4152).
pub const MAX_BATCH_PLANS: usize = 256;
/// The gather window after the first staged plan (spec line 4153).
pub const GATHER_WINDOW_MILLIS: u64 = 1;

/// The connection whose command produced a staged plan, kept so a rejected
/// batch can render its bounded failure to the right sink.
pub struct StagedOrigin {
    /// The originating connection's queue generation.
    generation: ConnectionGeneration,
    rejection_frames: Vec<WireMessage>,
    observation: Option<CommandObservation>,
}

impl StagedOrigin {
    /// Marks an internal durable operation whose coordinator owns rejection.
    #[must_use]
    pub(crate) const fn silent(generation: ConnectionGeneration) -> Self {
        Self {
            generation,
            rejection_frames: Vec::new(),
            observation: None,
        }
    }

    /// Retains an already rendered public failure until the durable outcome.
    #[must_use]
    pub(crate) const fn with_rejection_frames(
        generation: ConnectionGeneration,
        rejection_frames: Vec<WireMessage>,
    ) -> Self {
        Self {
            generation,
            rejection_frames,
            observation: None,
        }
    }

    /// Attaches the input-free observation token for this client command.
    #[must_use]
    pub(crate) fn with_observation(mut self, observation: Option<CommandObservation>) -> Self {
        self.observation = observation;
        self
    }

    /// Moves the observation token to the durable completion boundary.
    pub(crate) fn take_observation(&mut self) -> Option<CommandObservation> {
        self.observation.take()
    }

    /// Returns the generation fenced to this origin.
    #[must_use]
    pub(crate) const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    /// Moves the retained failure frames to the rejection router.
    pub(crate) fn into_rejection(self) -> (ConnectionGeneration, Vec<WireMessage>) {
        (self.generation, self.rejection_frames)
    }
}

/// One plan waiting on the durable outcome.
pub(super) struct StagedPlan {
    plan: MutationPlan,
    fanout: FanoutReservation,
    origin: Option<StagedOrigin>,
    response_count_increment: u64,
    account_service_writes: Vec<AccountServiceDurableWrite>,
    projection: Option<PendingProjection>,
    history: Option<super::history::HistoryMutation>,
}

impl StagedPlan {
    pub(super) fn with_history(mut self, history: Option<super::history::HistoryMutation>) -> Self {
        self.history = history;
        self
    }

    pub(super) fn take_history(&mut self) -> Option<super::history::HistoryMutation> {
        self.history.take()
    }

    /// Binds one account-service record set to the plan that authorizes it.
    #[must_use]
    pub(super) fn with_account_service_writes(
        plan: MutationPlan,
        fanout: FanoutReservation,
        origin: Option<StagedOrigin>,
        response_count_increment: u64,
        account_service_writes: Vec<AccountServiceDurableWrite>,
    ) -> Self {
        Self {
            plan,
            fanout,
            origin,
            response_count_increment,
            account_service_writes,
            projection: None,
            history: None,
        }
    }

    /// Attaches the federation projection reserved with this plan.
    #[must_use]
    pub(super) fn with_projection(mut self, projection: Option<PendingProjection>) -> Self {
        self.projection = projection;
        self
    }

    /// Moves the reserved projection out at the durable boundary.
    pub(super) fn take_projection(&mut self) -> Option<PendingProjection> {
        self.projection.take()
    }

    /// Borrows the domain plan.
    #[must_use]
    pub(super) const fn plan(&self) -> &MutationPlan {
        &self.plan
    }

    /// Returns the response-count permits this plan consumes.
    #[must_use]
    pub(super) const fn response_count_increment(&self) -> u64 {
        self.response_count_increment
    }

    /// Borrows the inseparable account-service rows.
    #[must_use]
    pub(super) fn account_service_writes(&self) -> &[AccountServiceDurableWrite] {
        &self.account_service_writes
    }

    /// Moves the client command observation to its final durable boundary.
    pub(super) fn take_observation(&mut self) -> Option<CommandObservation> {
        self.origin
            .as_mut()
            .and_then(StagedOrigin::take_observation)
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
    pub(super) fn start(
        plan: StagedPlan,
        now: MonotonicTick,
    ) -> Result<Self, (RuntimeError, Box<StagedPlan>)> {
        let Some(deadline) = now.get().checked_add(GATHER_WINDOW_MILLIS) else {
            return Err((RuntimeError::Overflow, Box::new(plan)));
        };
        let deadline = MonotonicTick::from_ticks(deadline);
        let reserved = touched_entities(&plan.plan);
        Ok(Self {
            plans: vec![plan],
            reserved,
            phase: BatchPhase::Gathering { deadline },
        })
    }

    /// Adds a plan to a gathering batch when it chains on the previous plan's
    /// resulting revision and touches no reserved entity.
    pub(super) fn try_stage(
        &mut self,
        plan: StagedPlan,
    ) -> Result<(), (StageRefusal, Box<StagedPlan>)> {
        if matches!(self.phase, BatchPhase::InFlight { .. }) {
            return Err((StageRefusal::InFlight, Box::new(plan)));
        }
        if self.plans.len() >= MAX_BATCH_PLANS {
            return Err((StageRefusal::Full, Box::new(plan)));
        }
        let chained = self
            .plans
            .last()
            .is_some_and(|last| last.plan.resulting_revision() == plan.plan.expected_revision());
        let touched = touched_entities(&plan.plan);
        if !chained || !self.reserved.is_disjoint(&touched) {
            return Err((StageRefusal::Incompatible, Box::new(plan)));
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
    use crate::observe::metrics::CommandClass;
    use agenc_ircd_client_wire::numeric_reply;
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
        Ok(StagedPlan::with_account_service_writes(
            plan,
            FanoutReservation::empty(),
            None,
            0,
            Vec::new(),
        ))
    }

    #[test]
    fn staged_origin_moves_retained_rejection_frames() -> Result<(), RuntimeError> {
        let generation = ConnectionGeneration::new(41);
        let frame = numeric_reply("server", 481, "requester", &[], Some("Server is busy"))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let origin = StagedOrigin::with_rejection_frames(generation, vec![frame]);
        assert_eq!(origin.generation(), generation);
        let (retained_generation, frames) = origin.into_rejection();
        assert_eq!(retained_generation, generation);
        assert_eq!(frames.len(), 1);
        Ok(())
    }

    #[test]
    fn silent_staged_origin_retains_no_public_failure() {
        let generation = ConnectionGeneration::new(42);
        let (retained_generation, frames) = StagedOrigin::silent(generation).into_rejection();
        assert_eq!(retained_generation, generation);
        assert!(frames.is_empty());
    }

    #[test]
    fn staged_observation_can_move_to_only_one_completion_boundary() {
        let mut origin = StagedOrigin::silent(ConnectionGeneration::new(43))
            .with_observation(Some(CommandObservation::new(CommandClass::Message)));
        assert!(origin.take_observation().is_some());
        assert!(origin.take_observation().is_none());
    }

    #[test]
    fn gathering_closes_at_one_millisecond_and_rejects_entity_conflicts() -> Result<(), RuntimeError>
    {
        let mut batch = PendingMutationBatch::start(staged(0, 1)?, MonotonicTick::from_ticks(10))
            .map_err(|(error, _plan)| error)?;
        assert_eq!(batch.gather_deadline(), Some(MonotonicTick::from_ticks(11)));
        assert!(!batch.gather_due(MonotonicTick::from_ticks(10)));
        batch
            .try_stage(staged(1, 2)?)
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.try_stage(staged(2, 1)?),
            Err((StageRefusal::Incompatible, _))
        ));
        assert!(batch.gather_due(MonotonicTick::from_ticks(11)));
        Ok(())
    }

    #[test]
    fn gathering_accepts_exactly_the_256_plan_boundary() -> Result<(), RuntimeError> {
        let mut batch = PendingMutationBatch::start(staged(0, 0)?, MonotonicTick::from_ticks(0))
            .map_err(|(error, _plan)| error)?;
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
            Err((StageRefusal::Full, _))
        ));
        Ok(())
    }

    #[test]
    fn gathering_deadline_overflow_is_rejected() -> Result<(), RuntimeError> {
        let error = PendingMutationBatch::start(staged(0, 1)?, MonotonicTick::from_ticks(u64::MAX))
            .err()
            .map(|(error, _plan)| error);
        assert_eq!(error, Some(RuntimeError::Overflow));
        Ok(())
    }
}
