//! A fixed startup retirement retains the original owner until its receipt.
#![forbid(unsafe_code)]

use super::super::{CompanionCoordinator, CompanionFault};
use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{CutPhase, DeliveryOwner};
use agenc_ircd_types::ServerId;

/// No live link can substitute for this authenticated startup owner.
pub(crate) struct Retirement {
    peer: ServerId,
    expected: DeliveryOwner,
    version: (u64, u64),
    retired: DeliveryOwner,
}

impl Retirement {
    pub(crate) fn write(&self) -> Result<AccountServiceDurableWrite, CompanionFault> {
        super::write(&self.retired)
    }

    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        coordinator.validate_delivery_scope(self.expected.scope())?;
        let snapshot = coordinator
            .peers
            .get(&self.peer)
            .and_then(|sync| sync.snapshot.as_ref())
            .ok_or(CompanionFault::Storage)?;
        let owner = coordinator
            .state
            .streams
            .get(&self.peer)
            .and_then(|stream| stream.owner.as_ref())
            .ok_or(CompanionFault::Storage)?;
        if owner != &self.expected
            || snapshot.stored_version != Some(self.version)
            || snapshot.scope != *self.expected.scope()
            || snapshot.cut != super::cut(&self.expected)
            || snapshot.retirement.map(CutPhase::Retired) != Some(self.retired.phase())
        {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }

    pub(crate) fn apply(
        self,
        coordinator: &mut CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        self.validate(coordinator)?;
        let stream = coordinator
            .state
            .streams
            .get_mut(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        stream.owner = Some(self.retired);
        let sync = coordinator
            .peers
            .get_mut(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        // Retiring this cut releases page metadata only. The stream survives.
        sync.snapshot = None;
        sync.active = false;
        sync.transfer_incomplete = true;
        Ok(())
    }
}

impl CompanionCoordinator {
    pub(crate) fn next_restored_retirement(&self) -> Result<Option<Retirement>, CompanionFault> {
        for (peer, sync) in &self.peers {
            let Some(snapshot) = sync.snapshot.as_ref() else {
                continue;
            };
            let Some(reason) = snapshot.retirement else {
                continue;
            };
            let version = snapshot.stored_version.ok_or(CompanionFault::Storage)?;
            let expected = self
                .state
                .streams
                .get(peer)
                .and_then(|stream| stream.owner.as_ref())
                .ok_or(CompanionFault::Storage)?;
            if !matches!(expected.phase(), CutPhase::Pending { .. }) {
                return Err(CompanionFault::Storage);
            }
            let retired = DeliveryOwner::new(
                *expected.scope(),
                *expected.cursor(),
                *expected.cut(),
                CutPhase::Retired(reason),
            )
            .map_err(|_| CompanionFault::Storage)?;
            return Ok(Some(Retirement {
                peer: *peer,
                expected: expected.clone(),
                version,
                retired,
            }));
        }
        Ok(None)
    }
}
