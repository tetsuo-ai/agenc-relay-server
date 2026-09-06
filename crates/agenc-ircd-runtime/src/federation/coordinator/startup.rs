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

use super::{FederationCoordinator, Violation, grace};
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
const TABLES: [TableId; 7] = [
    TableId::FederationPeer,
    TableId::FederationOrigin,
    TableId::RequestResult,
    TableId::EdgeProjection,
    TableId::EdgeOutbox,
    TableId::E2eeObject,
    TableId::E2eeState,
];

/// The reload state machine.
#[derive(Default)]
pub(super) struct Loader {
    position: usize,
    pending: Option<StorageReadId>,
    complete: bool,
    started: bool,
    failed: bool,
    retry: Option<StoredKey>,
}

impl Loader {
    pub(super) fn blocks_admission(&self) -> bool {
        self.started && !self.complete
    }
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
    coordinator.loader = Loader {
        started: true,
        ..Loader::default()
    };
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
    coordinator.loader.retry = start.clone();
    let plan = start
        .zip(StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES]).ok())
        .and_then(|(start, end)| ReadPlan::range(table, start, end, PAGE_ROWS).ok());
    let Some(plan) = plan else {
        fail_restore(coordinator);
        return;
    };
    if let Ok(read_id) = context.submit_storage_read(plan) {
        coordinator.loader.pending = Some(read_id);
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
    for peer in coordinator.peers.keys().copied() {
        coordinator.sync_outbox_budget(context, peer);
    }
    grace::restored(coordinator, context);
    coordinator.drain_backlog(context);
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
        request_page(coordinator, context, coordinator.loader.retry.clone());
        return true;
    };
    let mut last = None;
    for record in &result.records {
        if last
            .as_ref()
            .is_some_and(|previous| previous >= &record.key)
        {
            fail_restore(coordinator);
            return true;
        }
        let value = context
            .open_storage_plaintext(table, &record.key, &record.sealed_record)
            .and_then(|opened| {
                PersistentRecordValue::decode(table, opened.expose_for_storage_codec())
                    .map_err(crate::RuntimeError::from)
            });
        let accepted = value
            .map_err(|_| Violation::Codec)
            .and_then(|value| admit(coordinator, context, table, &record.key, &value));
        if accepted.is_err() {
            fail_restore(coordinator);
            return true;
        }
        last = Some(record.key.clone());
    }
    if result.truncated {
        if let Some(next) = last.and_then(|key| successor(&key)) {
            request_page(coordinator, context, Some(next));
        } else {
            fail_restore(coordinator);
        }
    } else {
        coordinator.loader.position = coordinator.loader.position.saturating_add(1);
        request_page(coordinator, context, first_key());
    }
    true
}

fn successor(key: &StoredKey) -> Option<StoredKey> {
    let mut bytes = key.as_bytes().to_vec();
    if bytes.len() < MAX_STORED_KEY_BYTES {
        bytes.push(0);
        return StoredKey::new(bytes).ok();
    }
    while let Some(last) = bytes.pop() {
        if let Some(next) = last.checked_add(1) {
            bytes.push(next);
            return StoredKey::new(bytes).ok();
        }
    }
    None
}

fn admit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    table: TableId,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    match (table, value.record_kind()) {
        (TableId::FederationPeer, PEER_RECORD_KIND) => admit_peer(coordinator, context, key, value),
        (TableId::FederationOrigin, ORIGIN_RECORD_KIND) => admit_origin(coordinator, key, value),
        (TableId::RequestResult, COORDINATOR_RESULT_KIND) => {
            admit_result(coordinator, context, key, value)
        }
        (
            TableId::RequestResult,
            agenc_ircd_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND,
        ) => admit_result(coordinator, context, key, value),
        (TableId::EdgeProjection, PROJECTION_ENTRY_KIND) => {
            admit_entry(coordinator, context, key, value)
        }
        (TableId::EdgeProjection, PROJECTION_MARKER_KIND) => admit_marker(coordinator, key, value),
        (TableId::EdgeOutbox, agenc_ircd_storage::federation_records::OUTBOX_EVENT_KIND) => {
            admit_outbox(coordinator, context, key, value)
        }
        (TableId::E2eeObject | TableId::E2eeState, _) => {
            if let Some(executor) = coordinator.companion_exec.as_mut() {
                executor.admit_restored(table, key, value);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Peer checkpoints can precede an event committed while the edge was away.
/// Recover its reserved sequence from the authenticated immutable outbox.
fn admit_outbox(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let (parts, event) = super::snapshot::decode_outbox_record(key, value)?;
    let Some(state) = coordinator.peers.get_mut(&parts.target) else {
        return Ok(());
    };
    if parts.projection_generation != state.projection_generation {
        return Ok(());
    }
    let next = parts
        .delivery_sequence
        .checked_add(1)
        .ok_or(Violation::Codec)?;
    state.outbox.reserved_next = state.outbox.reserved_next.max(next);
    if state
        .outbox
        .cursor
        .is_none_or(|(sequence, _)| parts.delivery_sequence > sequence)
        && !state.outbox.snapshot_required
    {
        let bytes = u64::try_from(event.event_object.len()).map_err(|_| Violation::Ceiling)?;
        state.outbox.unacked.push_back((
            parts.delivery_sequence,
            agenc_ircd_types::EventId::from_bytes(event.event_id),
            bytes,
        ));
        state.outbox.unacked_bytes = state.outbox.unacked_bytes.saturating_add(bytes);
        if u64::try_from(state.outbox.unacked.len()).map_err(|_| Violation::Ceiling)?
            > coordinator.config.outbox_objects_per_edge
            || state.outbox.unacked_bytes > coordinator.config.outbox_bytes_per_edge
        {
            state.outbox.snapshot_required = true;
            state.outbox.dirty = true;
        }
    }
    if let Some(projector) = context.federation_mut() {
        projector.set_edge(
            parts.target,
            EdgeDelivery {
                projection_generation: state.projection_generation,
                next_delivery_sequence: state.outbox.reserved_next,
            },
        );
        if state.outbox.snapshot_required {
            projector.require_snapshot(parts.target);
        }
    }
    Ok(())
}

fn admit_peer(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let bytes = <[u8; 16]>::try_from(key.as_bytes()).map_err(|_| Violation::Codec)?;
    let peer = ServerId::from_bytes(bytes);
    let record = FederationPeerRecord::decode(value.body()).map_err(|_| Violation::Codec)?;
    let Some(state) = coordinator.peers.get_mut(&peer) else {
        return Ok(());
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
    for incarnation in &record.fenced_incarnations {
        coordinator
            .origins
            .restore_fenced_incarnation(peer, ServerIncarnation::from_bytes(*incarnation));
    }
    state.phase = record.phase;
    state.cleanup_cursor = record.cleanup_cursor;
    if matches!(record.phase, PeerPhase::Expired | PeerPhase::Clean) {
        context.fence_federation_peer(peer);
    }
    state.projection_generation = record.projection_generation;
    state.outbox.cursor = record.cursor.map(|cursor| {
        (
            cursor.delivery_sequence,
            agenc_ircd_types::EventId::from_bytes(cursor.event_id),
        )
    });
    state.outbox.snapshot_required = record.snapshot_required;
    state.outbox.reserved_next = record.next_delivery_sequence;
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
        if record.snapshot_required {
            projector.require_snapshot(peer);
        }
    }
    Ok(())
}

fn admit_origin(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let (Ok(parts), Ok(record)) = (
        parse_origin_key(key),
        FederationOriginRecord::decode(value.body()),
    ) else {
        return Err(Violation::Codec);
    };
    let mut budget = DecodeBudget::new(4_096, 64);
    let Ok(object) =
        SchemaObject::decode_exact("FederationOrigin", &record.origin_object, &mut budget)
            .and_then(|object| OriginRecord::from_object(&object))
    else {
        return Err(Violation::Codec);
    };
    let origin = OriginKey {
        home_server_id: parts.peer,
        server_incarnation: parts.incarnation,
        origin_id: OriginId::from_bytes(parts.origin_id),
    };
    if object.network_id != coordinator.config.network_id
        || object.home_server_id != parts.peer
        || object.server_incarnation != parts.incarnation
        || object.origin_id.as_bytes() != &parts.origin_id
        || object.generation != parts.generation
        || agenc_ircd_federation_wire::federation_object_id(&record.origin_object).as_bytes()
            != &record.origin_object_id
    {
        return Err(Violation::Codec);
    }
    let account = restored_account(&object)?;
    let deleted_after =
        matches!(record.status, OriginRowStatus::Deleted).then_some(record.next_sequence);
    let entry = OriginEntry {
        generation: parts.generation,
        next_sequence: record.next_sequence,
        deleted_after,
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
    Ok(())
}

fn restored_account(
    object: &OriginRecord,
) -> Result<Option<(agenc_ircd_types::AccountId, Generation)>, Violation> {
    object
        .account
        .map(|account| {
            Generation::new(account.account_session_generation)
                .map(|generation| (account.account_id, generation))
        })
        .transpose()
        .map_err(|_| Violation::Codec)
}

fn admit_result(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let Some((request_id, request_object_id)) = result_identity(key, value) else {
        return Err(Violation::Codec);
    };
    if !retain_history_result(context, value) {
        return Err(Violation::Codec);
    }
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
        return Err(Violation::Codec);
    };
    let (Some(generation), Some(sequence)) = (
        bytes
            .get(48..56)
            .and_then(|part| <[u8; 8]>::try_from(part).ok()),
        bytes
            .get(56..64)
            .and_then(|part| <[u8; 8]>::try_from(part).ok()),
    ) else {
        return Err(Violation::Codec);
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
            request_id: agenc_ircd_types::RequestId::from_bytes(request_id),
            request_object_id,
        },
    );
    coordinator
        .origins
        .restore_request_id(agenc_ircd_types::RequestId::from_bytes(request_id), key);
    if value.record_kind() == COORDINATOR_RESULT_KIND {
        let record = CoordinatorResultRecord::decode(value.body()).map_err(|_| Violation::Codec)?;
        super::request::remember_registration(
            coordinator,
            context,
            key.origin,
            &record.result_object,
        )?;
    }
    Ok(())
}

fn admit_marker(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let (Ok(parts), Ok(record)) = (
        parse_projection_key(key),
        ProjectionMarkerRecord::decode(value.body()),
    ) else {
        return Err(Violation::Codec);
    };
    let Some(state) = coordinator.peers.get_mut(&parts.target) else {
        return Ok(());
    };
    if parts.projection_generation != state.projection_generation
        || record.state != ProjectionGenerationState::Active
    {
        return Ok(());
    }
    let Some(token) = record.snapshot_token else {
        return Ok(());
    };
    state.ready_identity = Some(agenc_ircd_federation_wire::SnapshotIdentity {
        snapshot_token: agenc_ircd_federation_wire::FederationHash32::from_bytes(token),
        recovery_epoch: RecoveryEpoch::from_bytes(record.recovery_epoch),
        projection_generation: parts.projection_generation,
        state_generation: record.state_generation,
        snapshot_digest: agenc_ircd_federation_wire::FederationHash32::from_bytes(record.digest),
    });
    Ok(())
}

fn admit_entry(
    coordinator: &FederationCoordinator,
    context: &mut StateCoreContext,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    let (Ok(parts), Ok(record)) = (
        parse_projection_key(key),
        ProjectionEntryRecord::decode(value.body()),
    ) else {
        return Err(Violation::Codec);
    };
    let mut budget = DecodeBudget::new(ENTRY_DECODE_BYTES, ENTRY_DECODE_VALUES);
    let Ok(entry) = SchemaObject::decode_exact(
        "FederationProjectionEntry",
        &record.entry_object,
        &mut budget,
    ) else {
        return Err(Violation::Codec);
    };
    let Ok((arm, primary)) = decode_projection_arm(&entry, &mut budget) else {
        return Err(Violation::Codec);
    };
    let Ok(kind) = agenc_ircd_types::FederationProjectionKind::from_wire(primary.kind()) else {
        return Err(Violation::Codec);
    };
    let Ok(projection) = projection_record_of(kind, &arm) else {
        return Err(Violation::Codec);
    };
    if coordinator
        .peers
        .get(&parts.target)
        .is_none_or(|state| state.projection_generation != parts.projection_generation)
    {
        return Ok(());
    }
    if let Some(projector) = context.federation_mut() {
        projector.restore_key(parts.target, &projection);
    }
    Ok(())
}

fn result_identity(key: &StoredKey, value: &PersistentRecordValue) -> Option<([u8; 16], [u8; 32])> {
    Some(match value.record_kind() {
        agenc_ircd_storage::history_records::HISTORY_COORDINATOR_RESULT_KIND => {
            let Ok(record) =
                agenc_ircd_storage::history_records::HistoryCoordinatorResultRecord::decode(
                    value.body(),
                )
            else {
                return None;
            };
            if key.as_bytes() != record.request.replay_key {
                return None;
            }
            (record.request.request_id, record.request.request_object_id)
        }
        _ => {
            let Ok(record) = CoordinatorResultRecord::decode(value.body()) else {
                return None;
            };
            (record.request_id, record.request_object_id)
        }
    })
}

fn retain_history_result(context: &mut StateCoreContext, value: &PersistentRecordValue) -> bool {
    use agenc_ircd_storage::history_records::{
        HISTORY_COORDINATOR_RESULT_KIND, HistoryCoordinatorResultRecord, HistoryResultStatus,
    };
    if value.record_kind() != HISTORY_COORDINATOR_RESULT_KIND {
        return true;
    }
    let Ok(record) = HistoryCoordinatorResultRecord::decode(value.body()) else {
        return false;
    };
    record.status != HistoryResultStatus::Available
        || context
            .history_result_retained(
                agenc_ircd_types::ChannelInstanceId::from_bytes(record.page.channel_id),
                true,
            )
            .is_ok()
}

fn fail_restore(coordinator: &mut FederationCoordinator) {
    coordinator.loader.failed = true;
    coordinator.loader.pending = None;
    coordinator.counters.violations = coordinator.counters.violations.saturating_add(1);
    for state in coordinator.peers.values_mut() {
        state.quarantined = true;
        if let Some(live) = state.live.take() {
            live.handle.close();
        }
    }
    for message in coordinator.backlog.drain(..) {
        if let crate::federation::LinkEvent::Established { handle, .. } = message.event {
            handle.close();
        }
    }
}

impl FederationCoordinator {
    pub(crate) fn continue_restore(&mut self, context: &mut StateCoreContext) {
        if self.loader.blocks_admission() && !self.loader.failed && self.loader.pending.is_none() {
            request_page(self, context, self.loader.retry.clone());
        }
        if !self.loader.blocks_admission() {
            self.continue_background(context);
        }
    }
}

pub(super) fn hold_before_loaded(
    coordinator: &mut FederationCoordinator,
    message: crate::federation::FederationInbound,
) {
    if coordinator.loader.failed || coordinator.backlog.len() >= super::MAX_BACKLOG {
        let link = message.link;
        coordinator.backlog.retain(|queued| {
            if queued.link != link {
                return true;
            }
            if let crate::federation::LinkEvent::Established { handle, .. } = &queued.event {
                handle.close();
            }
            false
        });
        if let crate::federation::LinkEvent::Established { handle, .. } = message.event {
            handle.close();
        }
        return;
    }
    coordinator.backlog.push_back(message);
}
