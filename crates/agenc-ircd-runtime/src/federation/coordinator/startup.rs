//! Bounded reload of the coordinator's durable federation rows at startup.
//!
//! The rows were indexed by reconstruction; their contents are read back
//! here one page at a time so the origin table, retained request index,
//! projection standing, and peer positions match storage before the first
//! link is accepted.

use agenc_ircd_domain::federation::{
    EdgeLink, EdgePhase, OperationKey, OriginBinding, OriginEntry, OriginKey, OriginPrincipal,
    OriginStatus, RetainedRequest,
};
use agenc_ircd_federation_wire::{DecodeBudget, OriginRecord, SchemaObject, decode_projection_arm};
use agenc_ircd_storage::federation_records::{
    COORDINATOR_RESULT_KIND, CoordinatorResultRecord, FederationOriginRecord, FederationPeerRecord,
    ORIGIN_RECORD_KIND, OriginRowStatus, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND,
    PROJECTION_MARKER_KIND, PeerPhase, ProjectionEntryRecord, ProjectionGenerationState,
    ProjectionMarkerRecord, parse_origin_key, parse_projection_key,
};
use agenc_ircd_storage::{
    MAX_STORED_KEY_BYTES, PersistentRecordValue, ReadPlan, StoredKey, TableId,
};
use agenc_ircd_types::{Generation, OriginId, RecoveryEpoch, ServerId, ServerIncarnation};

use super::{FederationCoordinator, grace};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::federation::codec::projection::projection_record_of;
use crate::state_core::StateCoreContext;
use crate::state_core::projector::EdgeDelivery;

const PAGE_ROWS: u16 = 256;
const ENTRY_DECODE_BYTES: usize = 16_384;
const ENTRY_DECODE_VALUES: usize = 256;

/// The tables reloaded, in order. The E2EE object table precedes the
/// state table so every retained object is present when a state row that
/// names it is admitted.
const TABLES: [TableId; 6] = [
    TableId::FederationPeer,
    TableId::FederationOrigin,
    TableId::RequestResult,
    TableId::EdgeProjection,
    TableId::E2eeObject,
    TableId::E2eeState,
];

/// The reload state machine.
#[derive(Default)]
pub(super) struct Loader {
    position: usize,
    pending: Option<StorageReadId>,
    complete: bool,
}

impl Loader {
    /// Reports whether every table was reloaded.
    pub(super) const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Reports whether the read belongs to the loader.
    pub(super) fn owns(&self, read_id: StorageReadId) -> bool {
        self.pending == Some(read_id)
    }
}

/// Starts the reload at the first table.
pub(super) fn begin(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    coordinator.loader = Loader::default();
    request_page(coordinator, context, first_key());
}

fn first_key() -> Option<StoredKey> {
    StoredKey::new(vec![0]).ok()
}

fn request_page(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    start: Option<StoredKey>,
) {
    let Some(table) = TABLES.get(coordinator.loader.position).copied() else {
        finish(coordinator, context);
        return;
    };
    let plan = start
        .zip(StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES]).ok())
        .and_then(|(start, end)| ReadPlan::range(table, start, end, PAGE_ROWS).ok());
    match plan.and_then(|plan| context.submit_storage_read(plan).ok()) {
        Some(read_id) => coordinator.loader.pending = Some(read_id),
        None => finish(coordinator, context),
    }
}

/// Ends the reload. Every restored peer is treated as freshly lost: a link
/// that has not returned gets one grace interval measured from this boot,
/// and an expiry interrupted by the restart resumes hiding its sessions.
fn finish(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    coordinator.loader.complete = true;
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        executor.finish_restore();
    }
    grace::restored(coordinator, context);
}

/// Consumes one page; returns whether the message belonged to the loader.
pub(super) fn read_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: &StorageReadCompletionMessage,
) -> bool {
    if coordinator.loader.pending != Some(message.read_id) {
        return false;
    }
    coordinator.loader.pending = None;
    let Some(table) = TABLES.get(coordinator.loader.position).copied() else {
        return true;
    };
    let Ok(result) = &message.result else {
        finish(coordinator, context);
        return true;
    };
    let mut last = None;
    for record in &result.records {
        let opened = context.open_storage_plaintext(table, &record.key, &record.sealed_record);
        if let Ok(opened) = opened
            && let Ok(value) =
                PersistentRecordValue::decode(table, opened.expose_for_storage_codec())
        {
            admit(coordinator, context, table, &record.key, &value);
        }
        last = Some(record.key.clone());
    }
    match (result.truncated, last.and_then(|key| successor(&key))) {
        (true, Some(next)) => request_page(coordinator, context, Some(next)),
        _ => {
            coordinator.loader.position = coordinator.loader.position.saturating_add(1);
            request_page(coordinator, context, first_key());
        }
    }
    true
}

fn successor(key: &StoredKey) -> Option<StoredKey> {
    let mut bytes = key.as_bytes().to_vec();
    if bytes.len() >= MAX_STORED_KEY_BYTES {
        return None;
    }
    bytes.push(0);
    StoredKey::new(bytes).ok()
}

fn admit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    table: TableId,
    key: &StoredKey,
    value: &PersistentRecordValue,
) {
    match (table, value.record_kind()) {
        (TableId::FederationPeer, PEER_RECORD_KIND) => admit_peer(coordinator, context, key, value),
        (TableId::FederationOrigin, ORIGIN_RECORD_KIND) => admit_origin(coordinator, key, value),
        (TableId::RequestResult, COORDINATOR_RESULT_KIND) => admit_result(coordinator, key, value),
        (TableId::EdgeProjection, PROJECTION_ENTRY_KIND) => admit_entry(context, key, value),
        (TableId::EdgeProjection, PROJECTION_MARKER_KIND) => admit_marker(coordinator, key, value),
        (TableId::E2eeObject | TableId::E2eeState, _) => {
            if let Some(executor) = coordinator.companion_exec.as_mut() {
                executor.admit_restored(table, key, value);
            }
        }
        _ => {}
    }
}

fn admit_peer(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    key: &StoredKey,
    value: &PersistentRecordValue,
) {
    let Ok(bytes) = <[u8; 16]>::try_from(key.as_bytes()) else {
        return;
    };
    let peer = ServerId::from_bytes(bytes);
    let Ok(record) = FederationPeerRecord::decode(value.body()) else {
        return;
    };
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return;
    };
    if record.server_incarnation != [0; 16] {
        state.incarnation = Some(ServerIncarnation::from_bytes(record.server_incarnation));
    }
    if record.recovery_epoch != [0; 16] {
        state.recovery_epoch = Some(RecoveryEpoch::from_bytes(record.recovery_epoch));
    }
    state.accepted_epochs = record
        .accepted_epochs
        .iter()
        .map(|epoch| RecoveryEpoch::from_bytes(*epoch))
        .collect();
    state.phase = record.phase;
    state.projection_generation = record.projection_generation;
    state.outbox.cursor = record.cursor.map(|cursor| {
        (
            cursor.delivery_sequence,
            agenc_ircd_types::EventId::from_bytes(cursor.event_id),
        )
    });
    state.outbox.snapshot_required = record.snapshot_required;
    state.quarantined = record.quarantined;
    state.client_resync_epoch = record.client_resync_epoch;
    if let Some(incarnation) = state.incarnation {
        // The origin table must know the incarnation before grace, expiry,
        // or a RESET under a new incarnation can fence it.
        let phase = match record.phase {
            PeerPhase::Ready | PeerPhase::Suspended => EdgePhase::Ready,
            PeerPhase::Expired | PeerPhase::Clean => EdgePhase::Expired,
        };
        coordinator.origins.restore_edge(
            peer,
            EdgeLink {
                server_incarnation: incarnation,
                phase,
            },
        );
    }
    if let Some(projector) = context.federation_mut() {
        projector.set_edge(
            peer,
            EdgeDelivery {
                projection_generation: record.projection_generation,
                next_delivery_sequence: record.next_delivery_sequence,
            },
        );
    }
}

fn admit_origin(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) {
    let (Ok(parts), Ok(record)) = (
        parse_origin_key(key),
        FederationOriginRecord::decode(value.body()),
    ) else {
        return;
    };
    let mut budget = DecodeBudget::new(4_096, 64);
    let Ok(object) =
        SchemaObject::decode_exact("FederationOrigin", &record.origin_object, &mut budget)
            .and_then(|object| OriginRecord::from_object(&object))
    else {
        return;
    };
    let origin = OriginKey {
        home_server_id: parts.peer,
        server_incarnation: parts.incarnation,
        origin_id: OriginId::from_bytes(parts.origin_id),
    };
    let account = object.account.and_then(|account| {
        Generation::new(account.account_session_generation)
            .ok()
            .map(|generation| (account.account_id, generation))
    });
    let entry = OriginEntry {
        generation: parts.generation,
        next_sequence: record.next_sequence,
        object_id: record.origin_object_id,
        binding: OriginBinding {
            connection_id: object.connection_id,
            connection_nonce: object.connection_nonce,
        },
        principal: OriginPrincipal {
            session: object
                .session
                .map(|session| (session.session_id, session.user_id)),
            account,
        },
        status: match record.status {
            OriginRowStatus::Live | OriginRowStatus::Suspended => OriginStatus::Suspended,
            OriginRowStatus::Blocked => OriginStatus::Blocked,
            OriginRowStatus::Deleted => OriginStatus::Deleted,
            OriginRowStatus::Fenced => OriginStatus::Fenced,
        },
    };
    coordinator.origins.restore_origin(origin, entry);
    coordinator
        .origin_objects
        .insert(origin, record.origin_object);
}

fn admit_result(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) {
    let Ok(record) = CoordinatorResultRecord::decode(value.body()) else {
        return;
    };
    let bytes = key.as_bytes();
    let (Some(home), Some(incarnation), Some(origin)) = (
        bytes
            .get(..16)
            .and_then(|part| <[u8; 16]>::try_from(part).ok()),
        bytes
            .get(16..32)
            .and_then(|part| <[u8; 16]>::try_from(part).ok()),
        bytes
            .get(32..48)
            .and_then(|part| <[u8; 16]>::try_from(part).ok()),
    ) else {
        return;
    };
    let (Some(generation), Some(sequence)) = (
        bytes
            .get(48..56)
            .and_then(|part| <[u8; 8]>::try_from(part).ok()),
        bytes
            .get(56..64)
            .and_then(|part| <[u8; 8]>::try_from(part).ok()),
    ) else {
        return;
    };
    let key = OperationKey {
        origin: OriginKey {
            home_server_id: ServerId::from_bytes(home),
            server_incarnation: ServerIncarnation::from_bytes(incarnation),
            origin_id: OriginId::from_bytes(origin),
        },
        generation: u64::from_be_bytes(generation),
        sequence: u64::from_be_bytes(sequence),
    };
    coordinator.retained.insert(
        key,
        RetainedRequest {
            request_id: agenc_ircd_types::RequestId::from_bytes(record.request_id),
            request_object_id: record.request_object_id,
        },
    );
    coordinator.origins.restore_request_id(
        agenc_ircd_types::RequestId::from_bytes(record.request_id),
        key,
    );
}

/// Restores the durable READY identity of the peer's current generation so
/// a re-sent READY after restart still gets the byte-identical ACTIVE.
fn admit_marker(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) {
    let (Ok(parts), Ok(record)) = (
        parse_projection_key(key),
        ProjectionMarkerRecord::decode(value.body()),
    ) else {
        return;
    };
    let Some(state) = coordinator.peers.get_mut(&parts.target) else {
        return;
    };
    if parts.projection_generation != state.projection_generation
        || record.state != ProjectionGenerationState::Active
    {
        return;
    }
    let Some(token) = record.snapshot_token else {
        return;
    };
    state.ready_identity = Some(agenc_ircd_federation_wire::SnapshotIdentity {
        snapshot_token: agenc_ircd_federation_wire::FederationHash32::from_bytes(token),
        recovery_epoch: RecoveryEpoch::from_bytes(record.recovery_epoch),
        projection_generation: parts.projection_generation,
        state_generation: record.state_generation,
        snapshot_digest: agenc_ircd_federation_wire::FederationHash32::from_bytes(record.digest),
    });
}

fn admit_entry(context: &mut StateCoreContext, key: &StoredKey, value: &PersistentRecordValue) {
    let (Ok(parts), Ok(record)) = (
        parse_projection_key(key),
        ProjectionEntryRecord::decode(value.body()),
    ) else {
        return;
    };
    let mut budget = DecodeBudget::new(ENTRY_DECODE_BYTES, ENTRY_DECODE_VALUES);
    let Ok(entry) = SchemaObject::decode_exact(
        "FederationProjectionEntry",
        &record.entry_object,
        &mut budget,
    ) else {
        return;
    };
    let Ok((arm, primary)) = decode_projection_arm(&entry, &mut budget) else {
        return;
    };
    let Ok(kind) = agenc_ircd_types::FederationProjectionKind::from_wire(primary.kind()) else {
        return;
    };
    let Ok(projection) = projection_record_of(kind, &arm) else {
        return;
    };
    if let Some(projector) = context.federation_mut() {
        projector.restore_key(parts.target, &projection);
    }
}
