//! One read owner drives either expiry or deletion below an existing durable floor.
#![forbid(unsafe_code)]

use super::*;
use crate::budget::BackingReservationPort;
use crate::e2ee::coordinator::{CompanionCoordinator, PreparedReplayMaintenance, replay_cleanup};
use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, StoredKey};

pub(super) enum Candidate {
    Expire(Box<ReplayMaintenanceCandidate>),
    Cleanup(Box<replay_cleanup::Candidate>),
}

impl Candidate {
    pub(super) fn scope(
        &self,
    ) -> &agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryScope {
        match self {
            Self::Expire(candidate) => candidate.scope(),
            Self::Cleanup(candidate) => candidate.scope(),
        }
    }
    pub(super) fn peer(&self) -> ServerId {
        match self {
            Self::Expire(candidate) => candidate.peer(),
            Self::Cleanup(candidate) => candidate.stamp().peer(),
        }
    }

    pub(super) fn begin(
        self,
        executor: &CompanionCoordinator,
        commit: u64,
        backing: &BackingReservationPort,
    ) -> Result<Job, CompanionFault> {
        match self {
            Self::Expire(candidate) => candidate
                .begin(executor, None, commit, backing)
                .map(|job| Job::Expire(Box::new(job))),
            Self::Cleanup(candidate) => candidate
                .begin(executor, commit, backing)
                .map(|job| Job::Cleanup(Box::new(job))),
        }
    }
}

pub(super) enum Job {
    Expire(Box<ReplayMaintenanceJob>),
    Cleanup(Box<replay_cleanup::Job>),
}

impl Job {
    pub(super) fn scope(
        &self,
    ) -> &agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryScope {
        match self {
            Self::Expire(job) => job.candidate().scope(),
            Self::Cleanup(job) => job.candidate().scope(),
        }
    }
    pub(super) fn peer(&self) -> ServerId {
        match self {
            Self::Expire(job) => job.candidate().peer(),
            Self::Cleanup(job) => job.candidate().stamp().peer(),
        }
    }

    pub(super) fn requires_clock(&self) -> bool {
        matches!(self, Self::Expire(_))
    }

    pub(super) fn validate(&self, executor: &CompanionCoordinator) -> Result<(), CompanionFault> {
        match self {
            Self::Expire(job) => job.candidate().validate(executor),
            Self::Cleanup(job) => job.candidate().validate(executor),
        }
    }

    pub(super) fn next(&mut self) -> Result<Option<ReadPlan>, CompanionFault> {
        match self {
            Self::Expire(job) => job.next(),
            Self::Cleanup(job) => job.next(),
        }
    }

    pub(super) fn admit(
        &mut self,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        match self {
            Self::Expire(job) => job.admit(commit, truncated, records),
            Self::Cleanup(job) => job.admit(commit, truncated, records),
        }
    }

    pub(super) fn finish(
        self,
        executor: &CompanionCoordinator,
    ) -> Result<Prepared, CompanionFault> {
        match self {
            Self::Expire(job) => job
                .finish(executor)
                .map(|prepared| Prepared::Expire(Box::new(prepared))),
            Self::Cleanup(job) => job
                .finish(executor)
                .map(|prepared| Prepared::Cleanup(Box::new(prepared))),
        }
    }
}

pub(super) enum Prepared {
    Expire(Box<PreparedReplayMaintenance>),
    Cleanup(Box<replay_cleanup::Prepared>),
}

impl Prepared {
    pub(super) fn validate(&self, executor: &CompanionCoordinator) -> Result<(), CompanionFault> {
        match self {
            Self::Expire(prepared) => prepared.validate(executor),
            Self::Cleanup(prepared) => prepared.validate(executor),
        }
    }

    pub(super) fn clean_stamp(&self) -> Option<replay_cleanup::Stamp> {
        match self {
            Self::Expire(_) => None,
            Self::Cleanup(prepared) => prepared.clean_stamp(),
        }
    }

    pub(super) fn writes(&self) -> Result<Vec<AccountServiceDurableWrite>, CompanionFault> {
        match self {
            Self::Expire(prepared) => prepared.write().map(|write| vec![write]),
            Self::Cleanup(prepared) => prepared.writes(),
        }
    }

    pub(super) fn apply(self, executor: &mut CompanionCoordinator) -> Result<(), CompanionFault> {
        match self {
            Self::Expire(prepared) => prepared.apply(executor),
            Self::Cleanup(prepared) => prepared.validate(executor),
        }
    }
}
