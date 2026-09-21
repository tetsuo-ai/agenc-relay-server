//! Durable companion delivery scope and receipt-owned cursor transitions.
#![forbid(unsafe_code)]

pub(super) mod acknowledgement;
pub(super) mod capture;
pub(super) mod clock;
pub(super) mod fetch;
pub(super) mod pages;
pub(super) mod publication;
pub(super) mod restore;
pub(super) mod retention;
pub(crate) mod retirement;
pub(super) mod snapshot;

use agenc_relay_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryCursor, DeliveryOwner, DeliveryRecoveryRow, DeliveryScope,
    DeliveryScopeFields, LastAcknowledged, SnapshotCut, SnapshotCutFields,
};
use agenc_relay_types::{RecoveryEpoch, ServerId, ServerIncarnation};

use super::events::DeliveryStream;
use super::sync::Cut;
use super::{CompanionCoordinator, CompanionFault};
use crate::state_core::durable::AccountServiceDurableWrite;

/// Local authenticated database identity, installed before delivery is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LocalIdentity {
    incarnation: ServerIncarnation,
    recovery_epoch: RecoveryEpoch,
}

impl LocalIdentity {
    pub(super) const fn recovery_epoch(self) -> RecoveryEpoch {
        self.recovery_epoch
    }
}

impl CompanionCoordinator {
    /// Binds durable delivery to the authenticated local database identity.
    pub fn configure_delivery_identity(
        &mut self,
        incarnation: ServerIncarnation,
        recovery_epoch: RecoveryEpoch,
    ) -> Result<(), CompanionFault> {
        let identity = LocalIdentity {
            incarnation,
            recovery_epoch,
        };
        if self
            .delivery_identity
            .is_some_and(|current| current != identity)
            || self.pending.is_some()
            || !self.state.streams.is_empty()
        {
            return Err(CompanionFault::Protocol);
        }
        self.delivery_identity = Some(identity);
        Ok(())
    }

    pub(super) fn delivery_scope(
        &self,
        peer: ServerId,
        incarnation: [u8; 16],
        base_epoch: u64,
    ) -> Result<DeliveryScope, CompanionFault> {
        let local = self.delivery_identity.ok_or(CompanionFault::Storage)?;
        DeliveryScope::new(DeliveryScopeFields {
            network_id: self.network_id,
            coordinator_server_id: *self.server_id.as_bytes(),
            coordinator_incarnation: *local.incarnation.as_bytes(),
            coordinator_recovery_epoch: *local.recovery_epoch.as_bytes(),
            target_server_id: *peer.as_bytes(),
            target_incarnation: incarnation,
            covered_base_client_resync_epoch: base_epoch,
        })
        .map_err(|_| CompanionFault::Storage)
    }

    pub(super) fn validate_delivery_scope(
        &self,
        scope: &DeliveryScope,
    ) -> Result<(), CompanionFault> {
        let expected = self.delivery_scope(
            ServerId::from_bytes(scope.target_server_id()),
            scope.target_incarnation(),
            scope.covered_base_client_resync_epoch(),
        )?;
        if expected != *scope {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }
}

pub(super) fn cursor(stream: &DeliveryStream) -> Result<DeliveryCursor, CompanionFault> {
    let acknowledged = stream
        .acked
        .map_or(LastAcknowledged::BeforeFirst, |(sequence, event_id)| {
            LastAcknowledged::At { sequence, event_id }
        });
    DeliveryCursor::new(stream.generation, stream.next_sequence, acknowledged)
        .map_err(|_| CompanionFault::Storage)
}

pub(super) fn refreshed(stream: &DeliveryStream) -> Result<DeliveryOwner, CompanionFault> {
    let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
    DeliveryOwner::new(*owner.scope(), cursor(stream)?, *owner.cut(), owner.phase())
        .map_err(|_| CompanionFault::Storage)
}

pub(super) fn ready(
    scope: DeliveryScope,
    cut: Cut,
    total_object_bytes: u64,
    stream: &DeliveryStream,
) -> Result<DeliveryOwner, CompanionFault> {
    let cut = SnapshotCut::new(SnapshotCutFields {
        token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        entry_count: cut.entry_count,
        digest: cut.digest,
        page_count: cut.entry_count.div_ceil(32).max(1),
        total_object_bytes,
    })
    .map_err(|_| CompanionFault::Storage)?;
    DeliveryOwner::new(scope, cursor(stream)?, cut, CutPhase::Ready)
        .map_err(|_| CompanionFault::Storage)
}

pub(super) fn write(owner: &DeliveryOwner) -> Result<AccountServiceDurableWrite, CompanionFault> {
    let row = DeliveryRecoveryRow::Owner(owner.clone());
    let key = row.key().map_err(|_| CompanionFault::Storage)?;
    let body = row.encode().map_err(|_| CompanionFault::Storage)?;
    super::request::state_row(
        agenc_relay_storage::TableId::E2eeState,
        agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND,
        key,
        body,
    )
    .map_err(|_| CompanionFault::Storage)
}

pub(super) fn cut(owner: &DeliveryOwner) -> Cut {
    Cut {
        token: owner.cut().token(),
        state_generation: owner.cut().state_generation(),
        delivery_generation: owner.cut().delivery_generation(),
        digest: owner.cut().digest(),
        entry_count: owner.cut().entry_count(),
    }
}

pub(super) fn append_object(
    writes: &mut Vec<AccountServiceDurableWrite>,
    bytes: &[u8],
) -> Result<(), agenc_relay_e2ee::wire::reply::E2eeReplyCode> {
    let write = CompanionCoordinator::object_write(bytes)?;
    if !writes.iter().any(|existing| existing.same_put(&write)) {
        writes.push(write);
    }
    Ok(())
}
