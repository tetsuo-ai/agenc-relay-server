//! Link synchronization on the edge: origin replay, FRESUME, and snapshot
//! installation (spec 20.5, 20.9).

use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_relay_domain::federation::ProjectionRecord;
use agenc_relay_federation_wire::{
    AssembledObject, DecodeBudget, DeliveryCursor, FederationFrame, FederationHash32,
    ProjectionEntryHeader, SchemaObject, SnapshotIdentity, decode_projection_arm, snapshot_digest,
};
use agenc_relay_storage::TableId;
use agenc_relay_storage::federation_records::{PROJECTION_ENTRY_KIND, projection_entry_key};

use super::{EdgeCompletion, EdgeFederation, PendingCommit, Phase, Violation, request};
use crate::federation::codec::projection::projection_record_of;
use crate::state_core::StateCoreContext;

/// The fixed standing-projection ceilings (spec 20.8).
const MAX_SNAPSHOT_ENTRIES: u64 = 1_000_000;
const MAX_SNAPSHOT_BYTES: u64 = 536_870_912;
#[cfg(test)]
#[path = "tests/pending_generation.rs"]
pub(crate) mod pending_generation;

/// Cut rows written per checkpoint batch while installing.
const INSTALL_BATCH_ROWS: usize = 256;

/// A snapshot being received or installed.
pub(super) struct SnapshotInstall {
    identity: SnapshotIdentity,
    coordinator_incarnation: agenc_relay_types::ServerIncarnation,
    expected: u64,
    entries: Vec<ProjectionRecord>,
    ids: Vec<FederationHash32>,
    bytes: u64,
    verified: bool,
    written: usize,
    ready_sent: bool,
    cursor: Option<(u64, agenc_relay_types::EventId)>,
    staged_end: Option<usize>,
    resync: Vec<crate::connection::ConnectionGeneration>,
}

impl SnapshotInstall {
    /// Whether the generation being installed already holds the entry
    /// `key`; entries are admitted in strict key order.
    pub(super) fn holds(&self, key: &agenc_relay_domain::federation::ProjectionKey) -> bool {
        self.entries
            .binary_search_by_key(key, ProjectionRecord::key)
            .is_ok()
    }

    /// The accounts of the sessions the generation being installed holds;
    /// sessions sort first, so they are a prefix of the entries.
    pub(super) fn session_accounts(
        &self,
    ) -> impl Iterator<Item = agenc_relay_types::AccountId> + '_ {
        self.entries
            .iter()
            .map_while(|entry| match entry {
                ProjectionRecord::Session(session) => Some(session.account),
                _ => None,
            })
            .flatten()
            .map(|(account, _)| account)
    }
}

/// Whether the snapshot install keeps the state owner off its safe point.
///
/// Before shutdown every install stage does, so a reload never activates
/// across a generation change. After shutdown has begun only a staged
/// install batch does: it is a local durable commit that must settle. The
/// receiving stage and the ready-sent stage wait on the coordinator alone.
pub(super) fn holds_safe_point(edge: &EdgeFederation) -> bool {
    edge.snapshot
        .as_ref()
        .is_some_and(|snapshot| !edge.stopping || snapshot.staged_end.is_some())
}

/// Abandons the install stages a stopping edge must not wait for.
///
/// | Stage | Durable state | At shutdown |
/// | --- | --- | --- |
/// | receiving (unverified) | none | abandoned |
/// | installing, batch staged | the batch | the batch settles (held by `staged_end`), the rest is abandoned in `installed` |
/// | installing, between batches | rows of an unmarked generation | abandoned |
/// | ready-sent | pending marker, peer `pending_generation`, every row | the wait is abandoned |
/// | switching (`SnapshotActivated` staged) | the swap | finishes; held by `commit` |
///
/// Each abandonment leaves exactly what a crash at the same point leaves.
/// Startup ignores the rows of a generation the peer record does not name,
/// and restores a marked pending generation through `restore_pending`, after
/// which `begin` sends READY again or drops it for a changed coordinator.
pub(super) fn abandon_for_shutdown(edge: &mut EdgeFederation) {
    if edge
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.staged_end.is_none())
    {
        edge.snapshot = None;
    }
}

/// Starts the origin exchange on a fresh link.
pub(super) fn begin(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    if let Some(snapshot) = edge
        .snapshot
        .as_ref()
        .filter(|snapshot| snapshot.ready_sent)
    {
        if edge.live.as_ref().is_some_and(|live| {
            live.coordinator_epoch == snapshot.identity.recovery_epoch
                && edge.installed_incarnation == Some(live.coordinator_incarnation)
        }) {
            edge.phase = Phase::Snapshot;
            send_ready(edge, context);
            return;
        }
        edge.snapshot = None;
    }
    resume(edge, context);
}

fn begin_origins(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    edge.phase = Phase::Origins;
    edge.origin_ready = false;
    edge.note_phase();
    if !edge.send_frame(
        context,
        &FederationFrame::OriginReset {
            coordinator_server_id: edge.config.coordinator.server_id(),
            server_incarnation: edge.config.incarnation,
        },
    ) {
        return;
    }
    for origin in edge.origins.values_mut() {
        origin.acked_generation = None;
    }
    let connections: Vec<_> = edge.origins.keys().copied().collect();
    for connection in connections {
        request::replay_origin(edge, context, connection);
    }
}

pub(super) fn origin_ready(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    incarnation: agenc_relay_types::ServerIncarnation,
) -> Result<(), Violation> {
    if incarnation != edge.config.incarnation
        || !matches!(edge.phase, Phase::Origins | Phase::Active)
    {
        return Err(Violation::Consistency);
    }
    edge.origin_ready = true;
    activate_origins(edge, context);
    Ok(())
}

pub(super) fn activate_origins(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    if edge.phase == Phase::Origins
        && edge.origin_ready
        && edge.origins.iter().all(|(connection, origin)| {
            if origin.deleted {
                origin.del_acked
                    && super::journal::is_durable(
                        edge,
                        super::journal::Identity::Origin(*connection),
                    )
            } else {
                origin.pending_updates.is_empty()
                    && origin.acked_generation == Some(origin.generation)
            }
        })
    {
        edge.phase = Phase::Active;
        edge.note_phase();
        request::resend_pending(edge, context);
    }
}

/// Sends FRESUME from the durable cursor, or asks for a snapshot outright
/// when the installed epoch is not the coordinator's.
fn resume(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    if matches!(edge.commit, Some(PendingCommit::OrdinaryBatch(_))) {
        return;
    }
    let epoch_matches = edge
        .live
        .as_ref()
        .is_some_and(|live| edge.installed_epoch == Some(live.coordinator_epoch));
    let cursor = match (epoch_matches, edge.cursor) {
        (true, Some((delivery_sequence, event_id))) => DeliveryCursor::At {
            delivery_sequence,
            event_id,
        },
        (true, None) if edge.replica.entry_count() == 0 => DeliveryCursor::Empty,
        _ => DeliveryCursor::At {
            delivery_sequence: u64::MAX,
            event_id: agenc_relay_types::EventId::from_bytes([0; 16]),
        },
    };
    edge.phase = Phase::Resuming;
    edge.note_phase();
    edge.send_frame(
        context,
        &FederationFrame::Resume {
            coordinator_server_id: edge.config.coordinator.server_id(),
            projection_generation: edge.replica.projection_generation(),
            cursor,
        },
    );
}

/// FRESUME OK: the replica continues and unanswered requests are resent.
pub(super) fn resume_ok(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    projection_generation: u64,
    next_delivery_sequence: u64,
) -> Result<(), Violation> {
    if edge.phase != Phase::Resuming {
        return Err(Violation::Phase);
    }
    let expected = edge
        .cursor
        .map_or(0, |(sequence, _)| sequence.saturating_add(1));
    if projection_generation != edge.replica.projection_generation()
        || next_delivery_sequence != expected
    {
        return Err(Violation::Consistency);
    }
    if let Some(live) = edge.live.as_ref() {
        edge.installed_epoch = Some(live.coordinator_epoch);
        edge.accepted_epoch = Some(live.coordinator_epoch);
        edge.installed_incarnation = Some(live.coordinator_incarnation);
    }
    begin_origins(edge, context);
    Ok(())
}

/// FRESUME SNAPSHOT: BEGIN follows.
pub(super) fn resume_snapshot(edge: &mut EdgeFederation) -> Result<(), Violation> {
    if edge.phase != Phase::Resuming {
        return Err(Violation::Phase);
    }
    edge.phase = Phase::Snapshot;
    edge.note_phase();
    Ok(())
}

/// FSNAPSHOT BEGIN: the identity is checked before anything is allocated.
pub(super) fn snapshot_begin(
    edge: &mut EdgeFederation,
    identity: SnapshotIdentity,
    entry_count: u64,
) -> Result<(), Violation> {
    if edge.phase != Phase::Snapshot || edge.snapshot.is_some() {
        return Err(Violation::Phase);
    }
    // A snapshot cannot supersede an open barrier (spec 20.8).
    if edge.barrier.is_open() {
        return Err(Violation::Consistency);
    }
    let epoch = edge
        .live
        .as_ref()
        .map(|live| live.coordinator_epoch)
        .ok_or(Violation::Phase)?;
    if identity.recovery_epoch != epoch || entry_count > MAX_SNAPSHOT_ENTRIES {
        return Err(Violation::Consistency);
    }
    if identity.projection_generation <= edge.replica.projection_generation() {
        return Err(Violation::Consistency);
    }
    edge.snapshot = Some(SnapshotInstall {
        identity,
        coordinator_incarnation: edge
            .live
            .as_ref()
            .ok_or(Violation::Phase)?
            .coordinator_incarnation,
        expected: entry_count,
        entries: Vec::new(),
        ids: Vec::new(),
        bytes: 0,
        verified: false,
        written: 0,
        ready_sent: false,
        cursor: None,
        staged_end: None,
        resync: Vec::new(),
    });
    Ok(())
}

/// FSNAPSHOT ENTRY: entries arrive in index order and are decoded at once.
pub(super) fn snapshot_entry(
    edge: &mut EdgeFederation,
    snapshot_token: FederationHash32,
    entry_index: u32,
    object_id: FederationHash32,
    object: &AssembledObject,
) -> Result<(), Violation> {
    let network_id = edge.config.network_id;
    let server_id = edge.config.server_id;
    let snapshot = edge.snapshot.as_mut().ok_or(Violation::Phase)?;
    if snapshot.identity.snapshot_token != snapshot_token
        || u64::from(entry_index) != u64::try_from(snapshot.entries.len()).unwrap_or(u64::MAX)
        || object_id != object.object_id()
        || u64::from(entry_index) >= snapshot.expected
    {
        return Err(Violation::Consistency);
    }
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let entry =
        SchemaObject::decode_exact("FederationProjectionEntry", object.as_slice(), &mut budget)
            .map_err(|_| Violation::Codec)?;
    let header = ProjectionEntryHeader::from_object(&entry).map_err(|_| Violation::Codec)?;
    if header.network_id != network_id
        || header.target_server_id != server_id
        || header.projection_generation != snapshot.identity.projection_generation
    {
        return Err(Violation::Consistency);
    }
    let (arm, key) = decode_projection_arm(&entry, &mut budget).map_err(|_| Violation::Codec)?;
    let record =
        projection_record_of(header.projection_kind, &arm).map_err(|_| Violation::Codec)?;
    if snapshot
        .entries
        .last()
        .is_some_and(|previous| previous.key() >= record.key())
    {
        return Err(Violation::Consistency);
    }
    let _ = key;
    snapshot.bytes = snapshot
        .bytes
        .saturating_add(u64::try_from(object.len()).unwrap_or(u64::MAX));
    if snapshot.bytes > MAX_SNAPSHOT_BYTES {
        return Err(Violation::Ceiling);
    }
    snapshot.ids.push(object.object_id());
    snapshot.entries.push(record);
    Ok(())
}

/// FSNAPSHOT END: count, digest, and cross-references are verified, the
/// generation is installed, and its rows go durable before READY.
pub(super) fn snapshot_end(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    snapshot_token: FederationHash32,
    cursor: DeliveryCursor,
) -> Result<Vec<EdgeCompletion>, Violation> {
    let snapshot = edge.snapshot.as_mut().ok_or(Violation::Phase)?;
    let count = u64::try_from(snapshot.entries.len()).unwrap_or(u64::MAX);
    if snapshot.identity.snapshot_token != snapshot_token || count != snapshot.expected {
        return Err(Violation::Consistency);
    }
    let digest = snapshot_digest(
        &snapshot.identity.recovery_epoch,
        snapshot.identity.projection_generation,
        snapshot.identity.state_generation,
        &snapshot.ids,
    )
    .map_err(|_| Violation::Codec)?;
    if digest != snapshot.identity.snapshot_digest {
        return Err(Violation::Consistency);
    }
    let mut verified = agenc_relay_domain::federation::EdgeReplica::new(edge.config.server_id);
    verified
        .install(
            snapshot.identity.projection_generation,
            snapshot.entries.clone(),
        )
        .map_err(|_| Violation::Consistency)?;
    snapshot.verified = true;
    snapshot.cursor = match cursor {
        DeliveryCursor::Empty => None,
        DeliveryCursor::At {
            delivery_sequence,
            event_id,
        } => Some((delivery_sequence, event_id)),
    };
    edge.client_resync_epoch = edge
        .client_resync_epoch
        .checked_add(1)
        .ok_or(Violation::Ceiling)?;
    mark_resync(edge);
    write_install_rows(edge, context)?;
    Ok(Vec::new())
}

/// Writes the next batch of installed rows; READY follows the last one.
fn write_install_rows(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Result<(), Violation> {
    if super::journal::has_dirty(edge) {
        super::journal::continue_write(edge, context);
        return Ok(());
    }
    let (start, end) = match edge.snapshot.as_ref() {
        Some(snapshot) => (
            snapshot.written,
            snapshot
                .written
                .saturating_add(INSTALL_BATCH_ROWS)
                .min(snapshot.entries.len()),
        ),
        None => return Ok(()),
    };
    if let Some(snapshot) = edge.snapshot.as_mut() {
        snapshot.staged_end = Some(end);
    }
    let cursor = edge.cursor;
    let result = super::events::stage_rows(
        edge,
        context,
        cursor,
        PendingCommit::SnapshotInstalled,
        super::render::EventFanout::default().finish()?,
        |edge, _, revision| install_rows(edge, start, end, revision),
    );
    if result.is_err()
        && let Some(snapshot) = edge.snapshot.as_mut()
    {
        snapshot.staged_end = None;
    }
    result
}

/// The rows of one install batch under the installed generation.
fn install_rows(
    edge: &EdgeFederation,
    start: usize,
    end: usize,
    revision: u64,
) -> Result<Vec<AccountServiceDurableWrite>, Violation> {
    let snapshot = edge.snapshot.as_ref().ok_or(Violation::Phase)?;
    let generation = snapshot.identity.projection_generation;
    let mut writes = Vec::new();
    for record in snapshot
        .entries
        .get(start..end)
        .ok_or(Violation::Consistency)?
    {
        writes.push(install_row(edge, record, generation, revision)?);
    }
    if end == snapshot.entries.len() {
        writes.push(marker_row(edge, revision, false)?);
    }
    Ok(writes)
}

fn install_row(
    edge: &EdgeFederation,
    record: &ProjectionRecord,
    generation: u64,
    revision: u64,
) -> Result<AccountServiceDurableWrite, Violation> {
    let key = record.key();
    let arm = crate::federation::codec::projection::projection_arm_object(record)
        .map_err(|_| Violation::Codec)?;
    let entry = ProjectionEntryHeader {
        network_id: edge.config.network_id,
        target_server_id: edge.config.server_id,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)
    .map_err(|_| Violation::Codec)?;
    let encoded = agenc_relay_federation_wire::CanonicalEncode::encode_canonical(&entry)
        .map_err(|_| Violation::Codec)?;
    let body = agenc_relay_storage::federation_records::ProjectionEntryRecord {
        entry_object_id: *agenc_relay_federation_wire::federation_object_id(encoded.as_slice())
            .as_bytes(),
        entry_object: encoded.as_slice().to_vec(),
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let stored = projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary())
        .map_err(|_| Violation::Codec)?;
    edge.row_write(
        TableId::EdgeProjection,
        PROJECTION_ENTRY_KIND,
        stored,
        revision,
        generation,
        body,
    )
    .map_err(|_| Violation::Codec)
}

/// One install batch is durable: continue, or send READY after the last.
pub(super) fn installed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Vec<EdgeCompletion> {
    let Some(snapshot) = edge.snapshot.as_mut() else {
        return Vec::new();
    };
    if let Some(end) = snapshot.staged_end.take() {
        snapshot.written = end;
    }
    if snapshot.written < snapshot.entries.len() {
        if edge.stopping || context.is_quiescing() {
            // Shutdown was requested: the settled batch was the last local
            // obligation. An install is up to a million rows in batches of
            // 256, so chaining the rest would spend the drain budget on
            // work the next start repeats anyway. The rows of the unmarked
            // generation are ignored by that start.
            edge.snapshot = None;
            return Vec::new();
        }
        if let Err(violation) = write_install_rows(edge, context) {
            edge.fail_link(context, violation);
        }
        return Vec::new();
    }
    snapshot.ready_sent = true;
    edge.installed_incarnation = Some(snapshot.coordinator_incarnation);
    let resync = std::mem::take(&mut snapshot.resync)
        .into_iter()
        .map(|generation| EdgeCompletion::Resync { generation })
        .collect();
    edge.counters.snapshots_installed = edge.counters.snapshots_installed.saturating_add(1);
    send_ready(edge, context);
    resync
}

fn send_ready(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    let Some(identity) = edge.snapshot.as_ref().map(|snapshot| snapshot.identity) else {
        return;
    };
    edge.send_frame(
        context,
        &FederationFrame::SnapshotReady {
            coordinator_server_id: edge.config.coordinator.server_id(),
            identity,
        },
    );
}

pub(super) fn has_durable_ready(edge: &EdgeFederation) -> bool {
    edge.snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.ready_sent)
}

pub(super) fn pending_generation(edge: &EdgeFederation) -> Option<u64> {
    edge.snapshot
        .as_ref()
        .filter(|snapshot| {
            snapshot.ready_sent || snapshot.staged_end == Some(snapshot.entries.len())
        })
        .map(|snapshot| snapshot.identity.projection_generation)
}

fn marker_row(
    edge: &EdgeFederation,
    revision: u64,
    active: bool,
) -> Result<AccountServiceDurableWrite, Violation> {
    use agenc_relay_storage::federation_records::{
        DeliveryCursorRecord, PROJECTION_MARKER_KIND, ProjectionGenerationState,
        ProjectionMarkerRecord, projection_marker_key,
    };
    let snapshot = edge.snapshot.as_ref().ok_or(Violation::Phase)?;
    let identity = snapshot.identity;
    let body = ProjectionMarkerRecord {
        state: if active {
            ProjectionGenerationState::Active
        } else {
            ProjectionGenerationState::Pending
        },
        state_generation: identity.state_generation,
        entry_count: snapshot.expected,
        entry_bytes: snapshot.bytes,
        digest: *identity.snapshot_digest.as_bytes(),
        snapshot_token: Some(*identity.snapshot_token.as_bytes()),
        cut_cursor: snapshot
            .cursor
            .map(|(delivery_sequence, event_id)| DeliveryCursorRecord {
                delivery_sequence,
                event_id: *event_id.as_bytes(),
            }),
        recovery_epoch: *identity.recovery_epoch.as_bytes(),
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    edge.row_write(
        TableId::EdgeProjection,
        PROJECTION_MARKER_KIND,
        projection_marker_key(edge.config.server_id, identity.projection_generation)
            .map_err(|_| Violation::Codec)?,
        revision,
        identity.projection_generation,
        body,
    )
    .map_err(|_| Violation::Codec)
}

/// ACTIVE authorizes a durable swap before any new-generation traffic.
pub(super) fn snapshot_active(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    identity: SnapshotIdentity,
) -> Result<(), Violation> {
    let snapshot = edge.snapshot.as_ref().ok_or(Violation::Phase)?;
    if !snapshot.ready_sent || snapshot.identity != identity {
        return Err(Violation::Consistency);
    }
    if edge.commit.is_some() || context.in_flight() {
        return Err(Violation::Ceiling);
    }
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let mut peer = edge.peer_record(snapshot.cursor);
    peer.projection_generation = identity.projection_generation;
    peer.active_entry_count = snapshot.expected;
    peer.active_entry_bytes = snapshot.bytes;
    peer.pending_generation = None;
    peer.snapshot_required = false;
    let peer_write = edge
        .row_write(
            TableId::FederationPeer,
            agenc_relay_storage::federation_records::PEER_RECORD_KIND,
            agenc_relay_storage::federation_records::peer_key(edge.config.coordinator.server_id())
                .map_err(|_| Violation::Codec)?,
            revision,
            0,
            peer.encode().map_err(|_| Violation::Codec)?,
        )
        .map_err(|_| Violation::Codec)?;
    let (coverage, mut writes) =
        super::journal::snapshot_writes(edge, identity.state_generation, revision)?;
    writes.extend([marker_row(edge, revision, true)?, peer_write]);
    context
        .stage_durable_with_account_service(
            plan,
            super::render::EventFanout::default().finish()?,
            None,
            0,
            writes,
        )
        .map_err(|_| Violation::Ceiling)?;
    edge.commit = Some(PendingCommit::SnapshotActivated { coverage });
    Ok(())
}

pub(super) fn activated(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    coverage: Vec<super::journal::Version>,
) -> Vec<EdgeCompletion> {
    let Some(snapshot) = edge.snapshot.take() else {
        return Vec::new();
    };
    let identity = snapshot.identity;
    if edge
        .replica
        .install(identity.projection_generation, snapshot.entries)
        .is_err()
    {
        edge.fail_link(context, Violation::Consistency);
        return Vec::new();
    }
    edge.cursor = snapshot.cursor;
    edge.snapshot_cut = Some((identity.projection_generation, identity.state_generation));
    let outputs = super::journal::snapshot_committed(edge, context, coverage);
    edge.installed_epoch = Some(identity.recovery_epoch);
    edge.accepted_epoch = Some(identity.recovery_epoch);
    edge.phase = Phase::Origins;
    edge.note_phase();
    if edge.live.is_some() {
        begin_origins(edge, context);
    }
    outputs
}

pub(super) fn restore_pending(
    edge: &mut EdgeFederation,
    generation: u64,
    marker: agenc_relay_storage::federation_records::ProjectionMarkerRecord,
    entries: Vec<ProjectionRecord>,
    cause: &mut super::startup::EdgeRestoreCause,
) -> Result<(), crate::RuntimeError> {
    let invalid = super::startup::invalid;
    let token = marker.snapshot_token.ok_or_else(invalid)?;
    if marker.state != agenc_relay_storage::federation_records::ProjectionGenerationState::Pending
        || usize::try_from(marker.entry_count).ok() != Some(entries.len())
    {
        return Err(invalid());
    }
    verify_restored_cut(edge, generation, (&marker, &entries), cause)?;
    let mut verified = agenc_relay_domain::federation::EdgeReplica::new(edge.config.server_id);
    verified
        .install(generation, entries.clone())
        .map_err(|error| {
            *cause = super::startup::EdgeRestoreCause::PendingProjection(error);
            invalid()
        })?;
    edge.snapshot = Some(SnapshotInstall {
        identity: SnapshotIdentity {
            snapshot_token: FederationHash32::from_bytes(token),
            recovery_epoch: agenc_relay_types::RecoveryEpoch::from_bytes(marker.recovery_epoch),
            projection_generation: generation,
            state_generation: marker.state_generation,
            snapshot_digest: FederationHash32::from_bytes(marker.digest),
        },
        coordinator_incarnation: edge.installed_incarnation.ok_or_else(invalid)?,
        expected: marker.entry_count,
        written: entries.len(),
        entries,
        ids: Vec::new(),
        bytes: marker.entry_bytes,
        verified: true,
        ready_sent: true,
        cursor: marker.cut_cursor.map(|cursor| {
            (
                cursor.delivery_sequence,
                agenc_relay_types::EventId::from_bytes(cursor.event_id),
            )
        }),
        staged_end: None,
        resync: Vec::new(),
    });
    Ok(())
}

fn mark_resync(edge: &mut EdgeFederation) {
    let mut connections: std::collections::BTreeSet<_> = edge
        .origins
        .iter()
        .filter(|(_, origin)| origin.session.is_some() && !origin.deleted)
        .map(|(connection, _)| *connection)
        .collect();
    connections.extend(
        edge.pending
            .values()
            .filter(|pending| {
                !pending.sink_gone
                    && matches!(
                        pending.result,
                        Some(crate::federation::codec::results::ResultArm::SessionRegistered(_))
                    )
            })
            .map(|pending| pending.generation),
    );
    for connection in &connections {
        if let Some(origin) = edge.origins.get_mut(connection) {
            origin.deleted = true;
        }
        super::journal::mark_dirty(edge, super::journal::Identity::Origin(*connection));
    }
    let mut dirty = Vec::new();
    for (id, pending) in &mut edge.pending {
        if connections.contains(&pending.generation) {
            pending.sink_gone = true;
            dirty.push(*id);
        }
    }
    for id in dirty {
        super::journal::mark_dirty(edge, super::journal::Identity::Request(id));
    }
    if let Some(snapshot) = edge.snapshot.as_mut() {
        snapshot.resync.extend(connections);
    }
}

pub(super) fn continue_install(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    if edge.phase == Phase::Snapshot
        && edge.commit.is_none()
        && !context.in_flight()
        && !super::journal::has_dirty(edge)
        && edge
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.verified && !snapshot.ready_sent)
        && let Err(violation) = write_install_rows(edge, context)
    {
        edge.fail_link(context, violation);
    }
}

fn verify_restored_cut(
    edge: &EdgeFederation,
    generation: u64,
    restored: (
        &agenc_relay_storage::federation_records::ProjectionMarkerRecord,
        &[ProjectionRecord],
    ),
    cause: &mut super::startup::EdgeRestoreCause,
) -> Result<(), crate::RuntimeError> {
    use agenc_relay_federation_wire::CanonicalEncode;
    let invalid = super::startup::invalid;
    let (marker, entries) = restored;
    // A generation over a standing-projection ceiling is the same admission
    // fact the live install reports as `Violation::Ceiling`; reporting it as
    // stale durable state would send an operator to the storage layer.
    let ceiling = super::startup::EdgeRestoreCause::PendingProjectionCeiling;
    if marker.entry_count > MAX_SNAPSHOT_ENTRIES {
        *cause = ceiling;
        return Err(crate::RuntimeError::LimitExceeded);
    }
    if generation <= edge.replica.projection_generation()
        || entries
            .windows(2)
            .any(|pair| matches!(pair, [first, second] if first.key() >= second.key()))
    {
        return Err(invalid());
    }
    let mut ids = Vec::new();
    let mut bytes = 0_u64;
    for record in entries {
        let arm = crate::federation::codec::projection::projection_arm_object(record)
            .map_err(|_| invalid())?;
        let encoded = ProjectionEntryHeader {
            network_id: edge.config.network_id,
            target_server_id: edge.config.server_id,
            projection_generation: generation,
            projection_kind: crate::federation::codec::projection::projection_kind(record),
        }
        .build(&arm)
        .and_then(|entry| entry.encode_canonical())
        .map_err(|_| invalid())?;
        bytes = bytes
            .checked_add(u64::try_from(encoded.as_slice().len()).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if bytes > MAX_SNAPSHOT_BYTES {
            *cause = ceiling;
            return Err(crate::RuntimeError::LimitExceeded);
        }
        ids.push(agenc_relay_federation_wire::federation_object_id(
            encoded.as_slice(),
        ));
    }
    let digest = snapshot_digest(
        &agenc_relay_types::RecoveryEpoch::from_bytes(marker.recovery_epoch),
        generation,
        marker.state_generation,
        &ids,
    )
    .map_err(|_| invalid())?;
    if digest.as_bytes() != &marker.digest || bytes != marker.entry_bytes {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn rejected_install(edge: &mut EdgeFederation) {
    if let Some(snapshot) = edge.snapshot.as_mut() {
        snapshot.staged_end = None;
    }
    if !has_durable_ready(edge) {
        edge.snapshot = None;
    }
}

#[cfg(test)]
#[path = "tests/sync_stages.rs"]
mod sync_stages;
