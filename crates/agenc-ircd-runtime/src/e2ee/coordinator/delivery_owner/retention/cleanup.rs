//! Only a persisted, fully reconstructed floor authorizes obsolete reference deletion.
#![forbid(unsafe_code)]

mod page;

use super::super::restore::replay::State;
use super::{CompanionFault, DeliveryOwner};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{CutPhase, DeliveryScope, outbox};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};
use agenc_ircd_types::ServerId;

const PAGE_ROWS: u16 = 128;
const METADATA_BYTES: usize = PAGE_ROWS as usize
    * (agenc_ircd_storage::MAX_STORED_KEY_BYTES + std::mem::size_of::<StoredKey>())
    + 8_192;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Stamp {
    peer: ServerId,
    scope: DeliveryScope,
    generation: u64,
    floor: u64,
}

impl Stamp {
    pub(crate) fn peer(self) -> ServerId {
        self.peer
    }
}

pub(crate) struct Candidate {
    owner: DeliveryOwner,
    replay: State,
    stamp: Stamp,
}

impl Candidate {
    pub(crate) fn current(
        coordinator: &CompanionCoordinator,
        peer: ServerId,
    ) -> Result<Option<Self>, CompanionFault> {
        let Some(stream) = coordinator.state.streams.get(&peer) else {
            return Ok(None);
        };
        let Some(replay) = stream.replay else {
            return Ok(None);
        };
        let Some(owner) = stream.owner.as_ref() else {
            return Err(CompanionFault::Storage);
        };
        if replay.owner.fields().first_retained == 0
            || owner.phase() != CutPhase::Ready
            || stream.barrier.is_some()
            || stream.hold_after.is_some()
        {
            return Ok(None);
        }
        let candidate = Self {
            owner: owner.clone(),
            replay,
            stamp: Stamp {
                peer,
                scope: *owner.scope(),
                generation: owner.cursor().generation(),
                floor: replay.owner.fields().first_retained,
            },
        };
        candidate.validate(coordinator)?;
        Ok(Some(candidate))
    }

    pub(crate) fn stamp(&self) -> Stamp {
        self.stamp
    }

    pub(crate) fn scope(&self) -> &DeliveryScope {
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
            .get(&self.stamp.peer)
            .ok_or(CompanionFault::Protocol)?;
        if coordinator.has_pending()
            || stream.owner.as_ref() != Some(&self.owner)
            || stream.replay != Some(self.replay)
            || super::super::cursor(stream)? != *self.owner.cursor()
            || stream.barrier.is_some()
            || stream.hold_after.is_some()
        {
            return Err(CompanionFault::Protocol);
        }
        super::validate_previous(&self.owner, Some(self.replay.owner))
    }

    pub(crate) fn begin(
        self,
        coordinator: &CompanionCoordinator,
        commit: u64,
        backing: &BackingReservationPort,
    ) -> Result<Job, CompanionFault> {
        self.validate(coordinator)?;
        let lease = backing
            .reserve(METADATA_BYTES)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut deletes = Vec::new();
        deletes
            .try_reserve_exact(usize::from(PAGE_ROWS))
            .map_err(|_| CompanionFault::Ceiling)?;
        Ok(Job {
            candidate: self,
            commit,
            phase: Phase::Owner,
            waiting: false,
            failed: false,
            deletes,
            _backing: lease,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Owner,
    Rows,
    Ranges,
    Done,
}

pub(crate) struct Job {
    candidate: Candidate,
    commit: u64,
    phase: Phase,
    waiting: bool,
    failed: bool,
    deletes: Vec<StoredKey>,
    _backing: MemoryPermit,
}

impl Job {
    pub(crate) fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub(crate) fn next(&mut self) -> Result<Option<ReadPlan>, CompanionFault> {
        if self.waiting || self.failed {
            return Err(CompanionFault::Storage);
        }
        let stamp = self.candidate.stamp;
        let plan = match self.phase {
            Phase::Owner => outbox::replay::replay_owner_key(&stamp.scope, stamp.generation)
                .map(|key| ReadPlan::exact(TableId::E2eeState, key)),
            Phase::Rows => outbox::outbox_from(&stamp.scope, stamp.generation, 0, PAGE_ROWS),
            Phase::Ranges => {
                outbox::replay::ack_ranges_from(&stamp.scope, stamp.generation, 0, PAGE_ROWS)
            }
            Phase::Done => return Ok(None),
        }
        .map_err(|_| CompanionFault::Storage)?;
        self.waiting = true;
        Ok(Some(plan))
    }

    pub(crate) fn admit(
        &mut self,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.failed
            || !self.waiting
            || self.commit != commit
            || records.len() > usize::from(PAGE_ROWS)
            || truncated && records.is_empty()
        {
            self.failed = true;
            return Err(CompanionFault::Storage);
        }
        self.waiting = false;
        let result = page::admit(self, truncated, records);
        self.failed = result.is_err();
        result
    }

    pub(crate) fn finish(
        self,
        coordinator: &CompanionCoordinator,
    ) -> Result<Prepared, CompanionFault> {
        if self.failed || self.waiting || self.phase != Phase::Done {
            return Err(CompanionFault::Storage);
        }
        self.candidate.validate(coordinator)?;
        Ok(Prepared {
            candidate: self.candidate,
            deletes: self.deletes,
            _backing: self._backing,
        })
    }
}

pub(crate) struct Prepared {
    candidate: Candidate,
    deletes: Vec<StoredKey>,
    _backing: MemoryPermit,
}

impl Prepared {
    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        self.candidate.validate(coordinator)
    }

    pub(crate) fn clean_stamp(&self) -> Option<Stamp> {
        self.deletes.is_empty().then_some(self.candidate.stamp)
    }

    pub(crate) fn writes(&self) -> Result<Vec<AccountServiceDurableWrite>, CompanionFault> {
        self.deletes
            .iter()
            .map(|key| {
                AccountServiceDurableWrite::delete(TableId::E2eeState, key.clone())
                    .map_err(|_| CompanionFault::Storage)
            })
            .collect()
    }
}
