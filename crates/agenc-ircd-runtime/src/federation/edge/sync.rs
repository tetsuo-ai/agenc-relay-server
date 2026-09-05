//! Link synchronization on the edge: origin replay, FRESUME, and snapshot
//! installation (spec 20.5, 20.9).

use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_ircd_domain::federation::ProjectionRecord;
use agenc_ircd_federation_wire::{
    AssembledObject, DecodeBudget, DeliveryCursor, FederationFrame, FederationHash32,
    ProjectionEntryHeader, SchemaObject, SnapshotIdentity, decode_projection_arm, snapshot_digest,
};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::federation_records::{PROJECTION_ENTRY_KIND, projection_entry_key};

use super::{EdgeCompletion, EdgeFederation, PendingCommit, Phase, Violation, request};
use crate::federation::codec::projection::projection_record_of;
use crate::state_core::StateCoreContext;

/// The fixed standing-projection ceilings (spec 20.8).
const MAX_SNAPSHOT_ENTRIES: u64 = 1_000_000;
const MAX_SNAPSHOT_BYTES: u64 = 536_870_912;
/// Cut rows written per checkpoint batch while installing.
const INSTALL_BATCH_ROWS: usize = 256;

/// A snapshot being received or installed.
pub(super) struct SnapshotInstall {
    identity: SnapshotIdentity,
    expected: u64,
    entries: Vec<ProjectionRecord>,
    ids: Vec<FederationHash32>,
    bytes: u64,
    verified: bool,
    written: usize,
    ready_sent: bool,
}

/// Starts the origin exchange on a fresh link.
pub(super) fn begin(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    let reset_sent = edge.send_frame(
        context,
        &FederationFrame::OriginReset {
            coordinator_server_id: edge.config.coordinator.server_id(),
            server_incarnation: edge.config.incarnation,
        },
    );
    if !reset_sent {
        return;
    }
    // Acknowledgements belong to the link that gave them: the companion
    // mirror waits for this link's FORIGIN ACK before it declares.
    for origin in edge.origins.values_mut() {
        origin.acked_generation = None;
    }
    let generations: Vec<_> = edge.origins.keys().copied().collect();
    for generation in generations {
        let update = edge
            .origins
            .get(&generation)
            .is_some_and(|origin| origin.generation > 0);
        request::declare_origin(edge, context, generation, update);
    }
    let ready_sent = edge.send_frame(
        context,
        &FederationFrame::OriginReady {
            edge_server_id: edge.config.server_id,
            server_incarnation: edge.config.incarnation,
        },
    );
    if ready_sent {
        resume(edge, context);
    }
}

/// Sends FRESUME from the durable cursor, or asks for a snapshot outright
/// when the installed epoch is not the coordinator's.
fn resume(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
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
            event_id: agenc_ircd_types::EventId::from_bytes([0; 16]),
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
    edge.phase = Phase::Active;
    edge.note_phase();
    request::resend_pending(edge, context);
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
        expected: entry_count,
        entries: Vec::new(),
        ids: Vec::new(),
        bytes: 0,
        verified: false,
        written: 0,
        ready_sent: false,
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
    let entries = snapshot.entries.clone();
    let generation = snapshot.identity.projection_generation;
    snapshot.verified = true;
    edge.replica
        .install(generation, entries)
        .map_err(|_| Violation::Consistency)?;
    edge.cursor = match cursor {
        DeliveryCursor::Empty => None,
        DeliveryCursor::At {
            delivery_sequence,
            event_id,
        } => Some((delivery_sequence, event_id)),
    };
    edge.applied_completions.clear();
    // Every registered global client reconnects: the state image replaces
    // events they never saw (spec 20.9).
    edge.client_resync_epoch = edge.client_resync_epoch.saturating_add(1);
    let resync: Vec<EdgeCompletion> = edge
        .origins
        .iter()
        .filter(|(_, origin)| origin.session.is_some())
        .map(|(generation, _)| EdgeCompletion::Resync {
            generation: *generation,
        })
        .collect();
    write_install_rows(edge, context)?;
    Ok(resync)
}

/// Writes the next batch of installed rows; READY follows the last one.
fn write_install_rows(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Result<(), Violation> {
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
        snapshot.written = end;
    }
    let cursor = edge.cursor;
    super::events::stage_rows(
        edge,
        context,
        cursor,
        PendingCommit::SnapshotInstalled,
        super::render::EventFanout::default().finish()?,
        |edge, _, revision| install_rows(edge, start, end, revision),
    )
}

/// The rows of one install batch under the installed generation.
fn install_rows(
    edge: &EdgeFederation,
    start: usize,
    end: usize,
    revision: u64,
) -> Vec<AccountServiceDurableWrite> {
    let generation = edge.replica.projection_generation();
    let Some(snapshot) = edge.snapshot.as_ref() else {
        return Vec::new();
    };
    let mut writes = Vec::new();
    for record in snapshot.entries.get(start..end).unwrap_or(&[]) {
        if let Some(write) = install_row(edge, record, generation, revision) {
            writes.push(write);
        }
    }
    writes
}

fn install_row(
    edge: &EdgeFederation,
    record: &ProjectionRecord,
    generation: u64,
    revision: u64,
) -> Option<AccountServiceDurableWrite> {
    let key = record.key();
    let arm = crate::federation::codec::projection::projection_arm_object(record).ok()?;
    let entry = ProjectionEntryHeader {
        network_id: edge.config.network_id,
        target_server_id: edge.config.server_id,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)
    .ok()?;
    let encoded = agenc_ircd_federation_wire::CanonicalEncode::encode_canonical(&entry).ok()?;
    let body = agenc_ircd_storage::federation_records::ProjectionEntryRecord {
        entry_object_id: *agenc_ircd_federation_wire::federation_object_id(encoded.as_slice())
            .as_bytes(),
        entry_object: encoded.as_slice().to_vec(),
    }
    .encode()
    .ok()?;
    let stored =
        projection_entry_key(edge.config.server_id, generation, key.kind(), key.primary()).ok()?;
    edge.row_write(
        TableId::EdgeProjection,
        PROJECTION_ENTRY_KIND,
        stored,
        revision,
        generation,
        body,
    )
    .ok()
}

/// One install batch is durable: continue, or send READY after the last.
pub(super) fn installed(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    let (done, identity) = match edge.snapshot.as_ref() {
        Some(snapshot) => (
            snapshot.written >= snapshot.entries.len(),
            snapshot.identity,
        ),
        None => return,
    };
    if !done {
        if let Err(violation) = write_install_rows(edge, context) {
            edge.fail_link(context, violation);
        }
        return;
    }
    if let Some(snapshot) = edge.snapshot.as_mut() {
        if snapshot.ready_sent {
            return;
        }
        snapshot.ready_sent = true;
    }
    edge.counters.snapshots_installed = edge.counters.snapshots_installed.saturating_add(1);
    edge.send_frame(
        context,
        &FederationFrame::SnapshotReady {
            coordinator_server_id: edge.config.coordinator.server_id(),
            identity,
        },
    );
}

/// FSNAPSHOT ACTIVE: the installed generation becomes the live one.
pub(super) fn snapshot_active(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    identity: SnapshotIdentity,
) -> Result<(), Violation> {
    let snapshot = edge.snapshot.as_ref().ok_or(Violation::Phase)?;
    if !snapshot.ready_sent || snapshot.identity != identity {
        return Err(Violation::Consistency);
    }
    edge.snapshot = None;
    edge.installed_epoch = Some(identity.recovery_epoch);
    edge.accepted_epoch = Some(identity.recovery_epoch);
    edge.installed_incarnation = edge.live.as_ref().map(|live| live.coordinator_incarnation);
    edge.phase = Phase::Active;
    edge.note_phase();
    request::resend_pending(edge, context);
    Ok(())
}
