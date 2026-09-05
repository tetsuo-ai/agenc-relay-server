//! Authenticated edge projection and barrier reconstruction before link admission.

use std::collections::BTreeMap;

use agenc_ircd_domain::federation::{ProjectedEvent, ProjectionRecord};
use agenc_ircd_federation_wire::{
    DecodeBudget, EventHeader, ProjectionEntryHeader, SchemaObject, decode_event_arm,
    decode_projection_arm, federation_object_id,
};
use agenc_ircd_storage::e2ee_records::barrier::{
    BarrierHead, BarrierPart, CrossProfileStream, parse_key,
};
use agenc_ircd_storage::e2ee_records::{
    BARRIER_ROW_KIND, DELIVERY_ROW_KIND, DeliveryRow, OBJECT_RECORD_KIND, ObjectRow,
    ROUTE_ROW_KIND, RouteRow,
};
use agenc_ircd_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND, ProjectionEntryRecord, peer_key,
    projection_entry_key,
};
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StorageError, StoragePort, StoredKey, TableId,
};
use agenc_ircd_types::{EventId, RecoveryEpoch, ServerIncarnation};

use super::{EdgeFederation, barrier::OpenBarrier};
use crate::RuntimeError;
use crate::bridge::storage::read_blocking;
use crate::e2ee::barrier::{BarrierAssembly, replay_matches};
use crate::e2ee::edge::E2eeEdge;
use crate::state_core::durable::{HeadCounters, KeyDeriver};
use crate::state_core::reconstruct::scan_table;

/// The standing projection ceiling also bounds retained startup material.
const MAX_RESTORE_BYTES: usize = 536_870_912;
const MAX_RESTORE_ROWS: usize = 1_000_000;
type Mutation = [u8; 16];

#[derive(Default)]
struct Restore {
    peer: Option<FederationPeerRecord>,
    projection: Vec<ProjectionRecord>,
    heads: BTreeMap<Mutation, BarrierHead>,
    parts: BTreeMap<Mutation, Vec<BarrierPart>>,
    bytes: usize,
    rows: usize,
}

pub(super) fn invalid() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

impl EdgeFederation {
    /// The collecting mutation, including an admitted part awaiting storage.
    pub(crate) fn collecting_barrier(&self) -> Option<[u8; 16]> {
        if let Some(super::PendingCommit::BarrierPart(open)) = self.commit.as_ref() {
            return Some(open.assembly.identity().mutation_id);
        }
        self.barrier
            .open
            .as_ref()
            .map(|open| open.assembly.identity().mutation_id)
    }

    /// Reloads authenticated committed rows on the blocking startup thread.
    pub(crate) fn restore(
        &mut self,
        port: &StoragePort,
        keys: &KeyDeriver,
        mut companion: Option<&mut E2eeEdge>,
        head: HeadCounters,
    ) -> Result<(), RuntimeError> {
        let mut restored = Restore::default();
        scan_values(port, keys, TableId::FederationPeer, |key, value| {
            if key == peer_key(self.config.coordinator.server_id())? {
                if value.record_kind() != PEER_RECORD_KIND {
                    return Err(invalid());
                }
                restored.peer = Some(FederationPeerRecord::decode(value.body())?);
            }
            Ok(())
        })?;
        scan_values(port, keys, TableId::EdgeProjection, |key, value| {
            restored.projection(self, key, value)
        })?;
        restored.install_projection(self)?;
        scan_values(port, keys, TableId::RequestResult, |key, value| {
            super::history::validate_restored(self, &key, &value)
        })?;
        scan_values(port, keys, TableId::E2eeState, |key, value| {
            restored.admit_state(self, companion.as_deref_mut(), key, value)
        })?;
        if let Some(companion) = companion.as_deref_mut() {
            companion.restore_base_cursor(self);
            if companion.needs_witness_snapshot() {
                self.installed_epoch = None;
            }
        }
        restored.install_barriers(self, companion, port, keys, head)
    }
}

fn scan_values(
    port: &StoragePort,
    keys: &KeyDeriver,
    table: TableId,
    mut visit: impl FnMut(StoredKey, PersistentRecordValue) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    scan_table(port, table, |key, sealed| {
        let envelope = SealedRecord::decode(&sealed)?;
        let opened = keys.open(table, &key, &envelope)?;
        let value = PersistentRecordValue::decode(table, opened.expose_for_storage_codec())?;
        visit(key, value)
    })
}

impl Restore {
    fn charge(&mut self, bytes: usize) -> Result<(), RuntimeError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        self.rows = self.rows.checked_add(1).ok_or_else(invalid)?;
        if self.bytes > MAX_RESTORE_BYTES || self.rows > MAX_RESTORE_ROWS {
            return Err(RuntimeError::MemoryExhausted);
        }
        Ok(())
    }

    fn projection(
        &mut self,
        edge: &EdgeFederation,
        key: StoredKey,
        value: PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        if value.record_kind() != PROJECTION_ENTRY_KIND {
            return Err(invalid());
        }
        let row = ProjectionEntryRecord::decode(value.body())?;
        let mut budget = DecodeBudget::new(1 << 20, 4096);
        let object =
            SchemaObject::decode_exact("FederationProjectionEntry", &row.entry_object, &mut budget)
                .map_err(|_| invalid())?;
        let header = ProjectionEntryHeader::from_object(&object).map_err(|_| invalid())?;
        if header.network_id != edge.config.network_id
            || header.target_server_id != edge.config.server_id
            || *federation_object_id(&row.entry_object).as_bytes() != row.entry_object_id
        {
            return Err(invalid());
        }
        let (arm, _) = decode_projection_arm(&object, &mut budget).map_err(|_| invalid())?;
        let record = crate::federation::codec::projection::projection_record_of(
            header.projection_kind,
            &arm,
        )
        .map_err(|_| invalid())?;
        let semantic = record.key();
        if key
            != projection_entry_key(
                edge.config.server_id,
                header.projection_generation,
                semantic.kind(),
                semantic.primary(),
            )?
        {
            return Err(invalid());
        }
        if self.peer.as_ref().is_some_and(|peer| {
            !peer.snapshot_required && peer.projection_generation == header.projection_generation
        }) {
            self.charge(row.entry_object.len())?;
            self.projection.push(record);
        }
        Ok(())
    }

    fn install_projection(&mut self, edge: &mut EdgeFederation) -> Result<(), RuntimeError> {
        let Some(peer) = self.peer.as_ref() else {
            return Ok(());
        };
        if peer.next_delivery_sequence
            != peer
                .cursor
                .as_ref()
                .map_or(Some(0), |cursor| cursor.delivery_sequence.checked_add(1))
                .ok_or_else(invalid)?
            || (!peer.snapshot_required
                && usize::try_from(peer.active_entry_count).ok() != Some(self.projection.len()))
        {
            return Err(invalid());
        }
        edge.replica
            .install(
                peer.projection_generation,
                std::mem::take(&mut self.projection),
            )
            .map_err(|_| invalid())?;
        edge.cursor = peer.cursor.as_ref().map(|cursor| {
            (
                cursor.delivery_sequence,
                EventId::from_bytes(cursor.event_id),
            )
        });
        edge.accepted_epoch = Some(RecoveryEpoch::from_bytes(peer.recovery_epoch));
        edge.installed_epoch =
            (!peer.snapshot_required).then_some(RecoveryEpoch::from_bytes(peer.recovery_epoch));
        edge.installed_incarnation = Some(ServerIncarnation::from_bytes(peer.server_incarnation));
        edge.client_resync_epoch = peer.client_resync_epoch;
        Ok(())
    }

    fn admit_state(
        &mut self,
        edge: &EdgeFederation,
        companion: Option<&mut E2eeEdge>,
        key: StoredKey,
        value: PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        match value.record_kind() {
            BARRIER_ROW_KIND => {
                self.admit_barrier(edge, key, &value)?;
            }
            ROUTE_ROW_KIND => {
                self.charge(value.body().len())?;
                companion
                    .ok_or_else(invalid)?
                    .restore_route(&key, &RouteRow::decode(value.body())?)?;
            }
            DELIVERY_ROW_KIND
                if key
                    == DeliveryRow::cursor_key(edge.config.coordinator.server_id().as_bytes())? =>
            {
                companion
                    .ok_or_else(invalid)?
                    .restore_delivery(&DeliveryRow::decode(value.body())?)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn admit_barrier(
        &mut self,
        edge: &EdgeFederation,
        key: StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        self.charge(value.body().len())?;
        let parsed = parse_key(&key)?;
        if parsed.part_index.is_some() {
            let part = BarrierPart::decode(value.body())?;
            if key != part.identity.part_key(part.part_index)? {
                return Err(invalid());
            }
            self.parts
                .entry(part.identity.mutation_id)
                .or_default()
                .push(part);
            return Ok(());
        }
        let head = BarrierHead::decode(value.body())?;
        check_identity(edge, head.identity())?;
        if key != head.identity().head_key()?
            || self
                .heads
                .insert(head.identity().mutation_id, head)
                .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn install_barriers(
        mut self,
        edge: &mut EdgeFederation,
        mut companion: Option<&mut E2eeEdge>,
        port: &StoragePort,
        keys: &KeyDeriver,
        head: HeadCounters,
    ) -> Result<(), RuntimeError> {
        for (mutation, barrier_head) in self.heads {
            let parts = self.parts.remove(&mutation).unwrap_or_default();
            match barrier_head {
                BarrierHead::Stage(stage) => {
                    install_stage(
                        edge,
                        &mut companion,
                        stage,
                        parts,
                        self.peer.as_ref().ok_or_else(invalid)?,
                        (port, keys),
                    )?;
                }
                BarrierHead::Receipt(receipt) => {
                    validate_receipt(edge, &receipt, &parts, head, (port, keys))?;
                    edge.barrier.applied.insert(mutation, receipt);
                }
            }
        }
        if !self.parts.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }
}

fn install_stage(
    edge: &mut EdgeFederation,
    companion: &mut Option<&mut E2eeEdge>,
    stage: agenc_ircd_storage::e2ee_records::barrier::BarrierStage,
    parts: Vec<BarrierPart>,
    peer: &FederationPeerRecord,
    storage: (&StoragePort, &KeyDeriver),
) -> Result<(), RuntimeError> {
    if peer.server_incarnation != stage.identity.coordinator_server_incarnation
        || peer.recovery_epoch != stage.identity.coordinator_recovery_epoch
    {
        if parts
            .iter()
            .any(|part| part.identity != stage.identity || !stage.is_received(part.part_index))
        {
            return Err(invalid());
        }
        edge.barrier.fenced.insert(
            stage.identity.mutation_id,
            super::fence::FencedBarrier { stage, parts },
        );
        return Ok(());
    }
    if edge.barrier.open.is_some() {
        return Err(invalid());
    }
    // Legacy edge cursors did not checkpoint the witnessed record head. An
    // active collecting barrier cannot be discarded without its durable fence.
    if companion
        .as_deref()
        .is_some_and(E2eeEdge::needs_witness_snapshot)
    {
        return Err(invalid());
    }
    let base_events = restore_stage_events(companion, &parts, storage)?;
    let assembly = BarrierAssembly::restore(stage, parts).map_err(|_| invalid())?;
    edge.barrier.ready = assembly.is_complete();
    edge.barrier.open = Some(OpenBarrier {
        assembly,
        base_events,
    });
    Ok(())
}

fn restore_stage_events(
    companion: &mut Option<&mut E2eeEdge>,
    parts: &[BarrierPart],
    storage: (&StoragePort, &KeyDeriver),
) -> Result<BTreeMap<u16, (EventHeader, ProjectedEvent)>, RuntimeError> {
    let mut base_events = BTreeMap::new();
    for part in parts {
        match part.stream {
            CrossProfileStream::Base => {
                base_events.insert(part.part_index, base_event(part)?);
            }
            CrossProfileStream::Companion => {
                let payload = read_payload(storage.0, storage.1, part)?;
                companion
                    .as_deref_mut()
                    .ok_or_else(invalid)?
                    .restore_part(part, payload)?;
            }
        }
    }
    Ok(base_events)
}

fn check_identity(
    edge: &EdgeFederation,
    identity: &agenc_ircd_storage::e2ee_records::barrier::BarrierIdentity,
) -> Result<(), RuntimeError> {
    if identity.network_id != *edge.config.network_id.as_bytes()
        || identity.coordinator_server_id != *edge.config.coordinator.server_id().as_bytes()
        || identity.target_server_id != *edge.config.server_id.as_bytes()
        || identity.target_server_incarnation != *edge.config.incarnation.as_bytes()
    {
        return Err(invalid());
    }
    Ok(())
}

fn base_event(part: &BarrierPart) -> Result<(EventHeader, ProjectedEvent), RuntimeError> {
    let mut budget = DecodeBudget::new(1 << 20, 4096);
    let object =
        SchemaObject::decode_exact("FederationEvent", &part.encoded_event_object, &mut budget)
            .map_err(|_| invalid())?;
    let header = EventHeader::from_object(&object).map_err(|_| invalid())?;
    let expected = agenc_ircd_federation_wire::CrossProfilePart {
        mutation_id: part.identity.mutation_id,
        part_index: part.part_index,
        part_count: part.identity.part_count,
    };
    if header.network_id.as_bytes() != &part.identity.network_id
        || header.target_server_id.as_bytes() != &part.identity.target_server_id
        || header.cross_profile != Some(expected)
        || header.coordinator_state_generation != part.identity.coordinator_state_generation
        || header.projection_generation != part.delivery_generation
        || header.delivery_sequence != part.delivery_sequence
        || header.event_id.as_bytes() != &part.event_id
        || federation_object_id(&part.encoded_event_object).as_bytes() != &part.event_object_id
    {
        return Err(invalid());
    }
    let arm = decode_event_arm(&object, &mut budget).map_err(|_| invalid())?;
    let projected =
        crate::federation::codec::events::projected_event_of(header.event_kind, &arm, &mut budget)
            .map_err(|_| invalid())?;
    Ok((header, projected))
}

fn read_payload(
    port: &StoragePort,
    keys: &KeyDeriver,
    part: &BarrierPart,
) -> Result<Option<Vec<u8>>, RuntimeError> {
    let Some(id) = part.payload_object_id else {
        return Ok(None);
    };
    let key = StoredKey::new(id.to_vec())?;
    let mut result = read_blocking(port, ReadPlan::exact(TableId::E2eeObject, key.clone()))?;
    let record = result.records.pop().ok_or_else(invalid)?;
    if record.table != TableId::E2eeObject || record.key != key {
        return Err(invalid());
    }
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    let plaintext = keys.open(TableId::E2eeObject, &key, &sealed)?;
    let value =
        PersistentRecordValue::decode(TableId::E2eeObject, plaintext.expose_for_storage_codec())?;
    if value.record_kind() != OBJECT_RECORD_KIND {
        return Err(invalid());
    }
    let row = ObjectRow::decode(value.body())?;
    if row.key()? != key || usize::try_from(part.payload_object_bytes).ok() != Some(row.bytes.len())
    {
        return Err(invalid());
    }
    Ok(Some(row.bytes))
}

fn validate_receipt(
    edge: &EdgeFederation,
    receipt: &agenc_ircd_storage::e2ee_records::barrier::BarrierReceipt,
    parts: &[BarrierPart],
    head: HeadCounters,
    storage: (&StoragePort, &KeyDeriver),
) -> Result<(), RuntimeError> {
    receipt_counters(edge, receipt, parts, head)?;
    // The head is deleted last. Missing parts are durable cleanup progress;
    // unexpired receipts must always retain their entire immutable set.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    if now < receipt.retain_until && parts.len() != usize::from(receipt.identity.part_count) {
        return Err(invalid());
    }
    validate_retained_parts(receipt, parts, storage, now < receipt.retain_until)
}

fn validate_retained_parts(
    receipt: &agenc_ircd_storage::e2ee_records::barrier::BarrierReceipt,
    parts: &[BarrierPart],
    storage: (&StoragePort, &KeyDeriver),
    require_payload: bool,
) -> Result<(), RuntimeError> {
    let mut bytes = 0_u64;
    for part in parts {
        let id = match part.stream {
            CrossProfileStream::Base => {
                *federation_object_id(&part.encoded_event_object).as_bytes()
            }
            CrossProfileStream::Companion => {
                *agenc_ircd_e2ee::ObjectId::compute(&part.encoded_event_object).as_bytes()
            }
        };
        if id != part.event_object_id {
            return Err(invalid());
        }
        bytes = bytes
            .checked_add(part.contributed_bytes()?)
            .ok_or_else(invalid)?;
        if require_payload {
            read_payload(storage.0, storage.1, part)?;
        }
    }
    if parts.len() == usize::from(receipt.identity.part_count)
        && bytes != receipt.aggregate_event_payload_bytes
    {
        return Err(invalid());
    }
    Ok(())
}

fn receipt_counters(
    edge: &EdgeFederation,
    receipt: &agenc_ircd_storage::e2ee_records::barrier::BarrierReceipt,
    parts: &[BarrierPart],
    head: HeadCounters,
) -> Result<(), RuntimeError> {
    if receipt.applied_storage_commit_sequence == 0
        || receipt.applied_local_state_generation == 0
        || receipt.applied_storage_commit_sequence > head.storage_commit_sequence
        || receipt.applied_local_state_generation > head.state_generation
        || parts.iter().any(|part| !replay_matches(receipt, part))
        || !super::retention::cursors_cover(edge, receipt)
    {
        return Err(invalid());
    }
    Ok(())
}
