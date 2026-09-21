//! The complete owner and cut-page passes precede each private body recovery job.
#![forbid(unsafe_code)]

use super::{CompanionCoordinator, CompanionFault, Restore, barriers, replay};
use crate::budget::BackingReservationPort;
use agenc_relay_storage::{PersistentRecordValue, StoredKey};

impl Restore {
    fn next_replay(
        &mut self,
        backing: &BackingReservationPort,
        pinned_commit: u64,
    ) -> Result<Option<replay::Request>, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        self.replay_started = true;
        barriers::validate_owners(&self.barriers, &self.owners)?;
        loop {
            if let Some((_, job)) = &mut self.active {
                if let Some(request) = job.next()? {
                    return Ok(Some(request));
                }
                let (peer, job) = self.active.take().ok_or(CompanionFault::Storage)?;
                if self
                    .streams
                    .insert(peer, job.finish()?.into_stream())
                    .is_some()
                {
                    return Err(CompanionFault::Storage);
                }
            }
            let Some((peer, owner)) = self
                .owners
                .iter()
                .find(|(peer, _)| !self.streams.contains_key(peer))
            else {
                return Ok(None);
            };
            self.active = Some((
                *peer,
                Box::new(replay::Job::new(
                    owner.clone(),
                    self.barriers.get(peer).cloned(),
                    Some(pinned_commit),
                    backing.clone(),
                )?),
            ));
        }
    }
}

impl CompanionCoordinator {
    /// A pinned read result must complete before the request can advance.
    pub(crate) fn next_restored_replay(
        &mut self,
        backing: &BackingReservationPort,
        pinned_commit: u64,
    ) -> Result<Option<replay::Request>, CompanionFault> {
        self.restore
            .delivery
            .validate_scopes(|scope| self.validate_delivery_scope(scope))?;
        self.restore.delivery.next_replay(backing, pinned_commit)
    }

    /// The storage adapter holds raw and decoding reservations through this call.
    pub(crate) fn admit_restored_replay(
        &mut self,
        request: &replay::Request,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        let restore = &mut self.restore.delivery;
        if restore.failed {
            return Err(CompanionFault::Storage);
        }
        let (_, job) = restore.active.as_mut().ok_or(CompanionFault::Storage)?;
        let result = job.admit(request, commit, truncated, records);
        restore.failed |= result.is_err();
        result
    }
}
