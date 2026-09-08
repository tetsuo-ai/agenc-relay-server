//! Offline replay maintenance retains its exact owner and publishes only on a receipt.
#![forbid(unsafe_code)]

use super::super::restore::replay::State;
use super::{CompanionFault, DeliveryOwner, Draft, prefix, recovery, update};
use crate::budget::BackingReservationPort;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_ircd_storage::e2ee_records::delivery_recovery::CutPhase;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::ReplayLedgerRow;
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey};
use agenc_ircd_types::ServerId;

#[derive(Clone)]
pub(crate) struct Candidate {
    peer: ServerId,
    owner: DeliveryOwner,
    replay: State,
    barrier: Option<(u64, u64)>,
    hold_after: Option<u64>,
    now: u64,
}

pub(crate) struct Job {
    candidate: Candidate,
    query: Option<recovery::Query>,
    ready: bool,
    // All buffered metadata drops before the reader's reservation.
    prefix: prefix::Prefix,
}

pub(crate) struct Prepared {
    candidate: Candidate,
    owner: super::ReplayOwner,
    update: update::Update,
}

impl Candidate {
    pub(crate) fn due(
        coordinator: &CompanionCoordinator,
        peer: ServerId,
        now: u64,
    ) -> Result<Option<Self>, CompanionFault> {
        let Some(stream) = coordinator.state.streams.get(&peer) else {
            return Ok(None);
        };
        let Some(replay) = stream.replay else {
            return Ok(None);
        };
        let Some(head) = replay.head else {
            return Ok(None);
        };
        if !head.expired(Some(now)) {
            return Ok(None);
        }
        let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
        if owner.phase() != CutPhase::Ready {
            return Ok(None);
        }
        let candidate = Self {
            peer,
            owner: owner.clone(),
            replay,
            barrier: stream.barrier,
            hold_after: stream.hold_after,
            now,
        };
        candidate.validate(coordinator)?;
        Ok(Some(candidate))
    }

    pub(crate) fn peer(&self) -> ServerId {
        self.peer
    }

    pub(crate) fn scope(
        &self,
    ) -> &agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryScope {
        self.owner.scope()
    }

    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        coordinator.validate_delivery_scope(self.owner.scope())?;
        let stream = coordinator
            .state
            .streams
            .get(&self.peer)
            .ok_or(CompanionFault::Protocol)?;
        if coordinator.has_pending()
            || self.owner.phase() != CutPhase::Ready
            || stream.owner.as_ref() != Some(&self.owner)
            || stream.replay != Some(self.replay)
            || super::super::cursor(stream)? != *self.owner.cursor()
            || stream.barrier != self.barrier
            || stream.hold_after != self.hold_after
        {
            return Err(CompanionFault::Protocol);
        }
        super::validate_previous(&self.owner, Some(self.replay.owner))
    }

    pub(crate) fn begin(
        self,
        coordinator: &CompanionCoordinator,
        protected_first: Option<u64>,
        commit: u64,
        backing: &BackingReservationPort,
    ) -> Result<Job, CompanionFault> {
        self.validate(coordinator)?;
        if self.hold_after.is_some() && protected_first.is_none() {
            return Err(CompanionFault::Storage);
        }
        let draft = Draft::maintenance(&self.owner, self.replay.owner, Some(self.now))?;
        let prefix = prefix::Prefix::new(
            self.owner.clone(),
            self.replay,
            draft,
            protected_first,
            Some(commit),
            backing,
        )?;
        Ok(Job {
            candidate: self,
            query: None,
            ready: false,
            prefix,
        })
    }
}

impl Job {
    pub(crate) fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub(crate) fn next(&mut self) -> Result<Option<ReadPlan>, CompanionFault> {
        if self.query.is_some() {
            return Err(CompanionFault::Storage);
        }
        match self.prefix.next()? {
            prefix::Next::Read(query) => {
                let plan = query.plan()?;
                self.query = Some(query);
                Ok(Some(plan))
            }
            prefix::Next::Done => {
                self.ready = true;
                Ok(None)
            }
        }
    }

    pub(crate) fn admit(
        &mut self,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        let query = self.query.take().ok_or(CompanionFault::Storage)?;
        self.prefix.admit(&query, commit, truncated, records)
    }

    pub(crate) fn finish(
        self,
        coordinator: &CompanionCoordinator,
    ) -> Result<Prepared, CompanionFault> {
        if !self.ready || self.query.is_some() {
            return Err(CompanionFault::Storage);
        }
        self.candidate.validate(coordinator)?;
        let proposal = self.prefix.finish()?;
        if proposal.range.is_some()
            || proposal.owner.fields().first_retained
                <= self.candidate.replay.owner.fields().first_retained
        {
            return Err(CompanionFault::Storage);
        }
        let stream = coordinator
            .state
            .streams
            .get(&self.candidate.peer)
            .ok_or(CompanionFault::Storage)?;
        Ok(Prepared {
            candidate: self.candidate,
            owner: proposal.owner,
            update: update::Update::new(stream, &proposal),
        })
    }
}

impl Prepared {
    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        self.candidate.validate(coordinator)
    }

    pub(crate) fn write(&self) -> Result<AccountServiceDurableWrite, CompanionFault> {
        let row = ReplayLedgerRow::Owner(self.owner);
        crate::e2ee::coordinator::request::state_row(
            agenc_ircd_storage::TableId::E2eeState,
            agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
            row.key().map_err(|_| CompanionFault::Storage)?,
            row.encode().map_err(|_| CompanionFault::Storage)?,
        )
        .map_err(|_| CompanionFault::Storage)
    }

    pub(crate) fn apply(
        self,
        coordinator: &mut CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        self.validate(coordinator)?;
        let stream = coordinator
            .state
            .streams
            .get_mut(&self.candidate.peer)
            .ok_or(CompanionFault::Storage)?;
        self.update.apply(stream);
        Ok(())
    }
}
