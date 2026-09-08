//! Exact reconstruction of accepted scopes and retained delivery bytes.
#![forbid(unsafe_code)]

mod barriers;
mod pending;
pub(in crate::e2ee::coordinator) mod replay;
mod replay_collection;

use std::collections::BTreeMap;

use agenc_ircd_e2ee::limits::MAX_FEDERATION_CONTROL_OBJECT;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationEvent;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_storage::StoredKey;
use agenc_ircd_storage::e2ee_records::CrossProfileTuple;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    ACK_RANGE_PREFIX, REPLAY_OWNER_PREFIX, ReplayLedgerRow,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    CutPhase, DeliveryBarrier, DeliveryOwner, DeliveryRecoveryRow, LastAcknowledged, ScopedOutbox,
};
use agenc_ircd_types::ServerId;

use super::super::events::{DeliveryStream, MAX_ACKED_REPLAY_ROWS, StreamRow};
use super::super::{CompanionCoordinator, CompanionFault};

/// Row collection never substitutes a current peer epoch for absent history.
#[derive(Default)]
pub(crate) struct Restore {
    owners: BTreeMap<ServerId, DeliveryOwner>,
    versions: BTreeMap<ServerId, (u64, u64)>,
    streams: BTreeMap<ServerId, DeliveryStream>,
    active: Option<(ServerId, Box<replay::Job>)>,
    replay_started: bool,
    barriers: BTreeMap<ServerId, DeliveryBarrier>,
    failed: bool,
    pending: pending::Pending,
    backing: Option<crate::budget::BackingReservationPort>,
}

impl Restore {
    pub(crate) fn set_backing(&mut self, backing: crate::budget::BackingReservationPort) {
        self.backing = Some(backing);
    }

    pub(crate) fn admit_owner(
        &mut self,
        key: &StoredKey,
        value: &agenc_ircd_storage::PersistentRecordValue,
    ) {
        let bytes = value.body();
        if self.pending.started() || self.replay_started {
            self.failed = true;
            return;
        }
        if key.as_bytes().starts_with(REPLAY_OWNER_PREFIX)
            || key.as_bytes().starts_with(ACK_RANGE_PREFIX)
        {
            self.failed |= ReplayLedgerRow::decode_at(key, bytes).is_err();
            return;
        }
        match DeliveryRecoveryRow::decode_at(key, bytes) {
            Ok(DeliveryRecoveryRow::Owner(owner)) => {
                if self.owners.len() >= crate::federation::MAX_FEDERATION_PEERS {
                    self.failed = true;
                    return;
                }
                let peer = ServerId::from_bytes(owner.scope().target_server_id());
                self.failed |= self.owners.insert(peer, owner).is_some();
                self.failed |= self
                    .versions
                    .insert(peer, (value.revision(), value.generation()))
                    .is_some();
            }
            Ok(DeliveryRecoveryRow::Barrier(gate)) => {
                let peer = ServerId::from_bytes(gate.scope().target_server_id());
                if self.barriers.len() >= crate::federation::MAX_FEDERATION_PEERS {
                    self.failed = true;
                    return;
                }
                self.failed |= self.barriers.insert(peer, gate).is_some();
            }
            Ok(DeliveryRecoveryRow::CutPage(_)) => {}
            Ok(DeliveryRecoveryRow::Outbox(_)) => {}
            _ => self.failed = true,
        }
    }

    pub(crate) fn admit_outbox(&mut self, _key: &StoredKey, _bytes: &[u8]) {
        // Legacy transport records carry no full historical scope.
        self.failed = true;
    }

    pub(crate) fn apply(
        mut self,
        coordinator: &mut CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        if self.failed || self.active.is_some() || self.streams.len() != self.owners.len() {
            return Err(CompanionFault::Storage);
        }
        barriers::validate_owners(&self.barriers, &self.owners)?;
        for (peer, owner) in self.owners {
            coordinator.validate_delivery_scope(owner.scope())?;
            if matches!(owner.phase(), CutPhase::Pending { .. }) {
                let pages = self.pending.take(peer)?;
                let version = self.versions.remove(&peer).ok_or(CompanionFault::Storage)?;
                coordinator.peers.entry(peer).or_default().snapshot = Some(
                    super::super::sync::Snapshot::restored(&owner, pages, version)?,
                );
            }
            let stream = self.streams.remove(&peer).ok_or(CompanionFault::Storage)?;
            if stream.owner.as_ref() != Some(&owner) {
                return Err(CompanionFault::Storage);
            }
            coordinator.state.streams.insert(peer, stream);
        }
        barriers::install(&mut coordinator.state.streams, &self.barriers)?;
        coordinator.state.restored_barriers = self.barriers;
        for (peer, stream) in &coordinator.state.streams {
            validate_complete(stream)?;
            let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
            let sync = coordinator.peers.entry(*peer).or_default();
            sync.incarnation = Some(owner.scope().target_incarnation());
            sync.resync_epoch = owner.scope().covered_base_client_resync_epoch();
            sync.ready_cut = (owner.phase() == CutPhase::Ready).then(|| super::cut(owner));
            sync.transfer_incomplete = owner.phase() != CutPhase::Ready;
        }
        Ok(())
    }
}

impl Restore {
    pub(crate) fn validate_scopes(
        &self,
        mut validate: impl FnMut(
            &agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryScope,
        ) -> Result<(), CompanionFault>,
    ) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        for owner in self.owners.values() {
            validate(owner.scope())?;
        }
        Ok(())
    }

    pub(crate) fn next_page(
        &mut self,
        backing: &crate::budget::BackingReservationPort,
    ) -> Result<Option<StoredKey>, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        self.pending.next(&self.owners, backing)
    }

    pub(crate) fn admit_page(
        &mut self,
        key: &StoredKey,
        body: &[u8],
    ) -> Result<(), CompanionFault> {
        self.pending.admit(key, body)
    }

    pub(crate) fn inventory_page(
        &self,
        key: &StoredKey,
        body: &[u8],
    ) -> Result<(), CompanionFault> {
        self.pending.inventory(&self.owners, key, body)
    }
}

fn decode_row(
    objects: &BTreeMap<[u8; 32], Vec<u8>>,
    owner: &DeliveryOwner,
    sequence: u64,
    row: ScopedOutbox,
    gate: Option<&DeliveryBarrier>,
    backing: &crate::budget::BackingReservationPort,
) -> Result<StreamRow, CompanionFault> {
    let event_id = row.event_id();
    let event_object_id = row.event_object_id();
    let stored_cross = row.cross_profile();
    let bytes = objects
        .get(&event_object_id)
        .ok_or(CompanionFault::Storage)?;
    if *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != event_object_id
        || usize::try_from(row.event_bytes()).ok() != Some(bytes.len())
    {
        return Err(CompanionFault::Storage);
    }
    let event = decode_event(bytes)?;
    validate_event(owner, sequence, event_id, &event)?;
    if cross_profile(&event)? != stored_cross {
        return Err(CompanionFault::Storage);
    }
    barriers::validate_event(gate, &event, row.acknowledgement().is_acknowledged())?;
    let payload = payload(
        objects,
        row.payload_object_id(),
        row.payload_bytes(),
        &event,
        backing,
    )?;
    Ok(StreamRow {
        sequence,
        event_id,
        event: super::super::events::SharedBytes::copy_from(bytes, backing)
            .map_err(|_| CompanionFault::Ceiling)?,
        payload,
        acknowledgement: row.acknowledgement(),
    })
}

fn validate_event(
    owner: &DeliveryOwner,
    sequence: u64,
    event_id: [u8; 16],
    event: &IrcFederationEvent,
) -> Result<(), CompanionFault> {
    if event.profile_version != 1
        || event.network_id != owner.scope().network_id()
        || event.target_server_id != owner.scope().target_server_id()
        || event.delivery_generation != owner.cursor().generation()
        || event.delivery_sequence != sequence
        || event.event_id != event_id
        || event.coordinator_state_generation < owner.cut().state_generation()
    {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

type RestoredPayload = ([u8; 32], super::super::events::SharedBytes);

fn payload(
    objects: &BTreeMap<[u8; 32], Vec<u8>>,
    object_id: Option<[u8; 32]>,
    length: u32,
    event: &IrcFederationEvent,
    backing: &crate::budget::BackingReservationPort,
) -> Result<Option<RestoredPayload>, CompanionFault> {
    let header_id = optional::<32>(event.payload_object_id.as_slice())?;
    if header_id != object_id {
        return Err(CompanionFault::Storage);
    }
    let Some(id) = object_id else {
        return if length == 0 {
            Ok(None)
        } else {
            Err(CompanionFault::Storage)
        };
    };
    let bytes = objects.get(&id).ok_or(CompanionFault::Storage)?;
    if usize::try_from(length).ok() != Some(bytes.len())
        || *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id
    {
        return Err(CompanionFault::Storage);
    }
    Ok(Some((
        id,
        super::super::events::SharedBytes::copy_from(bytes, backing)
            .map_err(|_| CompanionFault::Ceiling)?,
    )))
}

fn validate_complete(stream: &DeliveryStream) -> Result<(), CompanionFault> {
    let mut expected = stream
        .acked
        .map_or(Some(0), |(sequence, _)| sequence.checked_add(1))
        .ok_or(CompanionFault::Storage)?;
    for row in stream.rows.iter().filter(|row| !row.acked()) {
        if row.sequence != expected {
            return Err(CompanionFault::Storage);
        }
        expected = expected.checked_add(1).ok_or(CompanionFault::Storage)?;
    }
    let retained = stream.rows.iter().filter(|row| row.acked()).count();
    if expected != stream.next_sequence
        || retained > MAX_ACKED_REPLAY_ROWS
        || stream.would_block(0, 0)
    {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

pub(crate) fn decode_event(bytes: &[u8]) -> Result<IrcFederationEvent, CompanionFault> {
    let mut budget = DecodeBudget::new(MAX_FEDERATION_CONTROL_OBJECT, 256);
    let object =
        IrcWireObject::decode_exact(bytes, &mut budget).map_err(|_| CompanionFault::Storage)?;
    if object.kind() != IrcWireObjectKind::FederationEvent {
        return Err(CompanionFault::Storage);
    }
    let mut budget = DecodeBudget::new(MAX_FEDERATION_CONTROL_OBJECT, 256);
    IrcFederationEvent::decode_exact(object.body(), &mut budget)
        .map_err(|_| CompanionFault::Storage)
}

pub(crate) fn cross_profile(
    event: &IrcFederationEvent,
) -> Result<Option<CrossProfileTuple>, CompanionFault> {
    let Some(mutation_id) = optional::<16>(event.cross_profile_mutation_id.as_slice())? else {
        return if event.cross_profile_part_index == 0 && event.cross_profile_part_count == 0 {
            Ok(None)
        } else {
            Err(CompanionFault::Storage)
        };
    };
    if event.cross_profile_part_count < 2
        || event.cross_profile_part_count > 2_048
        || event.cross_profile_part_index >= event.cross_profile_part_count
    {
        return Err(CompanionFault::Storage);
    }
    Ok(Some(CrossProfileTuple {
        mutation_id,
        part_index: event.cross_profile_part_index,
        part_count: event.cross_profile_part_count,
    }))
}

fn optional<const N: usize>(bytes: &[u8]) -> Result<Option<[u8; N]>, CompanionFault> {
    if bytes.is_empty() {
        return Ok(None);
    }
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| CompanionFault::Storage)
}

impl CompanionCoordinator {
    /// Borrows metadata during the pinned base-outbox scan; it grants no delivery authority.
    pub(crate) fn restored_delivery_barrier(&self, peer: ServerId) -> Option<&DeliveryBarrier> {
        self.restore.delivery.barriers.get(&peer)
    }

    /// Called only after the complete state-table owner collection pass.
    pub(crate) fn next_restored_delivery_page(
        &mut self,
        backing: &crate::budget::BackingReservationPort,
    ) -> Result<Option<StoredKey>, CompanionFault> {
        self.restore
            .delivery
            .validate_scopes(|scope| self.validate_delivery_scope(scope))?;
        self.restore.delivery.next_page(backing)
    }

    pub(crate) fn admit_restored_delivery_page(
        &mut self,
        key: &StoredKey,
        value: &agenc_ircd_storage::PersistentRecordValue,
    ) -> Result<(), CompanionFault> {
        if value.record_kind() != agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND {
            return Err(CompanionFault::Storage);
        }
        self.restore.delivery.admit_page(key, value.body())
    }

    pub(crate) fn inventory_restored_delivery_page(
        &self,
        key: &StoredKey,
        value: &agenc_ircd_storage::PersistentRecordValue,
    ) -> Result<(), CompanionFault> {
        if value.record_kind() != agenc_ircd_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND {
            return Err(CompanionFault::Storage);
        }
        self.restore.delivery.inventory_page(key, value.body())
    }
}
