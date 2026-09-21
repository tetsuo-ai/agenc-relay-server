//! Authenticated edge projection and barrier reconstruction before link admission.

use std::collections::BTreeMap;

use agenc_relay_domain::federation::{ProjectedEvent, ProjectionRecord};
use agenc_relay_federation_wire::{
    DecodeBudget, EventHeader, ProjectionEntryHeader, SchemaObject, decode_event_arm,
    decode_projection_arm, federation_object_id,
};
use agenc_relay_storage::e2ee_records::barrier::{
    BarrierHead, BarrierPart, CrossProfileStream, parse_key,
};
use agenc_relay_storage::e2ee_records::{
    BARRIER_ROW_KIND, DELIVERY_ROW_KIND, DeliveryRow, OBJECT_RECORD_KIND, ObjectRow,
    ROUTE_ROW_KIND, RouteRow, WITNESS_ROW_KIND, WitnessRow,
};
use agenc_relay_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND, ProjectionEntryRecord, peer_key,
    projection_entry_key,
};
use agenc_relay_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StorageError, StoragePort, StoredKey, TableId,
};
use agenc_relay_types::{EventId, RecoveryEpoch, ServerIncarnation};

use super::{EdgeFederation, barrier::OpenBarrier};

#[cfg(test)]
#[path = "tests/reconstruction_pools.rs"]
mod reconstruction_pools;

use crate::RuntimeError;
use crate::bridge::storage::read_blocking;
use crate::e2ee::barrier::{BarrierAssembly, replay_matches};
use crate::e2ee::edge::E2eeEdge;
use crate::state_core::durable::{HeadCounters, KeyDeriver};
use crate::state_core::reconstruct::scan_table;

/// The fixed standing-projection ceilings (spec 20.8). These are exactly what
/// the live path admits for **one** projection generation: `snapshot_start`
/// refuses an entry count above `MAX_SNAPSHOT_ENTRIES` and `snapshot_entry`
/// refuses aggregate bytes above `MAX_SNAPSHOT_BYTES`
/// (`crates/agenc-relay-runtime/src/federation/edge/sync.rs`).
///
/// An edge holds the active generation and, from the moment a snapshot
/// install begins until retention has swept the superseded rows, a pending
/// one, so both generations' entry rows are durable at once. Each generation
/// is therefore charged against its own pool: the restore must be able to
/// rebuild every state the admission side can admit, and a single shared pool
/// the size of one generation could not.
const MAX_GENERATION_BYTES: usize = 536_870_912;
const MAX_GENERATION_ROWS: usize = 1_000_000;
/// The companion, barrier and delivery material retained beside the two
/// projection generations, charged against its own pool for the same reason.
const MAX_COMPANION_BYTES: usize = 536_870_912;
const MAX_COMPANION_ROWS: usize = 1_000_000;
type Mutation = [u8; 16];

/// One charged reconstruction pool: the bytes and rows admitted so far.
#[derive(Default)]
struct Pool {
    bytes: usize,
    rows: usize,
}

impl Pool {
    /// Charges one row against this pool, refusing at `ceiling` with `over` as
    /// the recorded cause so the refusal does not read as stale durable state.
    fn charge(
        &mut self,
        bytes: usize,
        ceiling: (usize, usize),
        over: EdgeRestoreCause,
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(RuntimeError::Overflow)?;
        self.rows = self.rows.checked_add(1).ok_or(RuntimeError::Overflow)?;
        if self.bytes > ceiling.0 || self.rows > ceiling.1 {
            *cause = over;
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Restore {
    peer: Option<FederationPeerRecord>,
    projection: Vec<ProjectionRecord>,
    pending_projection: Vec<ProjectionRecord>,
    pending_marker: Option<agenc_relay_storage::federation_records::ProjectionMarkerRecord>,
    active_cut: Option<(u64, u64)>,
    heads: BTreeMap<Mutation, BarrierHead>,
    parts: BTreeMap<Mutation, Vec<BarrierPart>>,
    active: Pool,
    pending: Pool,
    companion: Pool,
}

pub(super) fn invalid() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

/// Names the reconstruction step an edge restore was performing when it
/// refused, so one operator-visible refusal line identifies the record family
/// that could not be proved instead of naming storage in general.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeRestoreStep {
    /// Reserving the memory backing the companion's witness recovery needs.
    WitnessBacking,
    /// The `FederationPeer` row naming this edge's coordinator.
    PeerRecord,
    /// The `EdgeProjection` entry and generation-marker rows.
    ProjectionEntries,
    /// Installing the restored projection against the peer row that counts it.
    ProjectionInstall,
    /// The `FederationOrigin` rows carrying durable connection ownership.
    OriginJournal,
    /// The `RequestResult` rows carrying the durable request journal.
    RequestJournal,
    /// The `E2eeState` companion cursor, route, witness and barrier rows.
    CompanionState,
    /// Completing the companion's restored snapshot generation.
    CompanionSnapshot,
    /// Installing the restored barrier heads, parts and receipts.
    BarrierInstall,
}

impl EdgeRestoreStep {
    /// Returns the fixed lowercase label this step prints in a refusal line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WitnessBacking => "companion-witness-backing",
            Self::PeerRecord => "federation-peer-record",
            Self::ProjectionEntries => "edge-projection-rows",
            Self::ProjectionInstall => "edge-projection-install",
            Self::OriginJournal => "federation-origin-journal",
            Self::RequestJournal => "request-result-journal",
            Self::CompanionState => "e2ee-state-rows",
            Self::CompanionSnapshot => "companion-snapshot-restore",
            Self::BarrierInstall => "barrier-install",
        }
    }
}

/// Names the refusal an edge restore step would otherwise have discarded.
///
/// A step that calls into the replica, the barrier assembly or the companion
/// snapshot gets back that owner's own classification, and mapping it to a
/// bare `StorageError::StaleState` destroys the only fact an operator can act
/// on. This carries that classification out beside the step so the daemon can
/// print it, and it distinguishes a ceiling refusal from stale durable state:
/// a ceiling refusal is an admission fact about how much this edge holds, not
/// a claim that the storage layer is inconsistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeRestoreCause {
    /// The step's own fence refused; the error carries the whole meaning.
    Unclassified,
    /// The edge replica refused the restored active standing projection.
    ActiveProjection(agenc_relay_domain::federation::ReplicaError),
    /// The edge replica refused the restored pending projection generation.
    PendingProjection(agenc_relay_domain::federation::ReplicaError),
    /// The restored active generation crosses the standing-projection ceiling.
    ActiveProjectionCeiling,
    /// The restored pending generation crosses the standing-projection ceiling.
    PendingProjectionCeiling,
    /// The restored companion and barrier rows cross their own ceiling.
    CompanionCeiling,
    /// The companion's READY snapshot generation is missing restored rows.
    CompanionSnapshotIncomplete,
    /// The barrier assembly refused the restored head and parts.
    BarrierAssembly(crate::e2ee::barrier::BarrierFault),
    /// The restore was handed no memory-admission port to reserve against.
    MissingAdmissionPort,
}

impl core::fmt::Display for EdgeRestoreCause {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unclassified => formatter.write_str("unclassified"),
            Self::ActiveProjection(error) => write!(formatter, "active projection: {error}"),
            Self::PendingProjection(error) => write!(formatter, "pending projection: {error}"),
            Self::ActiveProjectionCeiling => {
                formatter.write_str("active projection over the standing-projection ceiling")
            }
            Self::PendingProjectionCeiling => {
                formatter.write_str("pending projection over the standing-projection ceiling")
            }
            Self::CompanionCeiling => {
                formatter.write_str("companion and barrier rows over the reconstruction ceiling")
            }
            Self::CompanionSnapshotIncomplete => {
                formatter.write_str("companion snapshot generation is incomplete")
            }
            Self::BarrierAssembly(fault) => write!(formatter, "barrier assembly: {fault}"),
            Self::MissingAdmissionPort => {
                formatter.write_str("no memory-admission port for the restore")
            }
        }
    }
}

/// One refused edge restore: the step that refused, the cause it carried and
/// the error it raised.
///
/// The error keeps its own meaning; the step and the cause are the
/// identification the daemon adds when it reports the refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeRestoreRefusal {
    /// The reconstruction step that refused.
    pub step: EdgeRestoreStep,
    /// The classified cause the step would otherwise have discarded.
    pub cause: EdgeRestoreCause,
    /// The refusal the step raised, unchanged.
    pub error: RuntimeError,
}

impl core::fmt::Display for EdgeRestoreRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.cause {
            EdgeRestoreCause::Unclassified => {
                write!(formatter, "{}: {}", self.step.label(), self.error)
            }
            cause => write!(formatter, "{} ({cause}): {}", self.step.label(), self.error),
        }
    }
}

impl core::error::Error for EdgeRestoreRefusal {}

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
    ///
    /// A refusal names the step that raised it and the cause the step would
    /// otherwise have discarded, so the daemon can report which reconstruction
    /// refused, on which record family, and whether the refusal was an
    /// admission fact or a claim about stale durable state.
    pub(crate) fn restore(
        &mut self,
        port: &StoragePort,
        keys: &KeyDeriver,
        companion: Option<&mut E2eeEdge>,
        head: HeadCounters,
        backing: Option<crate::budget::BackingReservationPort>,
    ) -> Result<(), EdgeRestoreRefusal> {
        let mut step = EdgeRestoreStep::WitnessBacking;
        let mut cause = EdgeRestoreCause::Unclassified;
        self.restore_steps(
            port,
            keys,
            companion,
            head,
            backing,
            (&mut step, &mut cause),
        )
        .map_err(|error| EdgeRestoreRefusal { step, cause, error })
    }

    /// Runs the restore steps, recording each one in `step` before it begins
    /// and each classified refusal in `cause` before it propagates.
    fn restore_steps(
        &mut self,
        port: &StoragePort,
        keys: &KeyDeriver,
        mut companion: Option<&mut E2eeEdge>,
        head: HeadCounters,
        backing: Option<crate::budget::BackingReservationPort>,
        report: (&mut EdgeRestoreStep, &mut EdgeRestoreCause),
    ) -> Result<(), RuntimeError> {
        let (step, cause) = report;
        if let Some(companion) = companion.as_deref_mut() {
            let backing = backing.ok_or_else(|| {
                *cause = EdgeRestoreCause::MissingAdmissionPort;
                RuntimeError::InvalidValue
            })?;
            companion.install_snapshot_backing(backing.clone());
            companion.restore_witness_backing(backing)?;
        }
        let mut restored = Restore::default();
        *step = EdgeRestoreStep::PeerRecord;
        scan_values(port, keys, TableId::FederationPeer, |key, value| {
            if key == peer_key(self.config.coordinator.server_id())? {
                if value.record_kind() != PEER_RECORD_KIND {
                    return Err(invalid());
                }
                restored.peer = Some(FederationPeerRecord::decode(value.body())?);
            }
            Ok(())
        })?;
        *step = EdgeRestoreStep::ProjectionEntries;
        scan_values(port, keys, TableId::EdgeProjection, |key, value| {
            restored.projection(self, key, value, cause)
        })?;
        *step = EdgeRestoreStep::ProjectionInstall;
        restored.install_projection(self, cause)?;
        *step = EdgeRestoreStep::OriginJournal;
        scan_values(port, keys, TableId::FederationOrigin, |key, value| {
            if value.record_kind() == agenc_relay_storage::federation_records::ORIGIN_RECORD_KIND {
                super::journal::restore_origin(self, &key, &value)?;
            }
            Ok(())
        })?;
        *step = EdgeRestoreStep::RequestJournal;
        scan_values(port, keys, TableId::RequestResult, |key, value| {
            if value.record_kind() == agenc_relay_storage::federation_records::EDGE_REQUEST_KIND {
                super::journal::restore_request(self, &key, &value)
            } else {
                super::history::validate_restored(self, &key, &value)
            }
        })?;
        super::journal::finish_restore(self);
        *step = EdgeRestoreStep::CompanionState;
        scan_values(port, keys, TableId::E2eeState, |key, value| {
            restored.admit_state(self, companion.as_deref_mut(), (key, value), cause)
        })?;
        if let Some(companion) = companion.as_deref_mut() {
            *step = EdgeRestoreStep::CompanionSnapshot;
            companion.finish_snapshot_restore(cause)?;
            companion.restore_base_cursor(self);
            if companion.needs_witness_snapshot() {
                self.installed_epoch = None;
            }
        }
        *step = EdgeRestoreStep::BarrierInstall;
        restored.install_barriers(self, companion, (port, keys, head), cause)
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
    /// Charges one entry row of the active or the pending generation against
    /// that generation's own pool.
    fn charge_generation(
        &mut self,
        pending: bool,
        bytes: usize,
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        let ceiling = (MAX_GENERATION_BYTES, MAX_GENERATION_ROWS);
        if pending {
            self.pending.charge(
                bytes,
                ceiling,
                EdgeRestoreCause::PendingProjectionCeiling,
                cause,
            )
        } else {
            self.active.charge(
                bytes,
                ceiling,
                EdgeRestoreCause::ActiveProjectionCeiling,
                cause,
            )
        }
    }

    /// Charges one companion, barrier or delivery row against their pool.
    fn charge_companion(
        &mut self,
        bytes: usize,
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        self.companion.charge(
            bytes,
            (MAX_COMPANION_BYTES, MAX_COMPANION_ROWS),
            EdgeRestoreCause::CompanionCeiling,
            cause,
        )
    }

    fn marker(
        &mut self,
        edge: &EdgeFederation,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let parts = agenc_relay_storage::federation_records::parse_projection_key(key)?;
        let marker =
            agenc_relay_storage::federation_records::ProjectionMarkerRecord::decode(value.body())?;
        if parts.target != edge.config.server_id
            || *key
                != agenc_relay_storage::federation_records::projection_marker_key(
                    parts.target,
                    parts.projection_generation,
                )?
        {
            return Err(invalid());
        }
        if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.pending_generation == Some(parts.projection_generation))
        {
            self.pending_marker = Some(marker);
        } else if marker.state
            == agenc_relay_storage::federation_records::ProjectionGenerationState::Active
            && self
                .peer
                .as_ref()
                .is_some_and(|peer| peer.projection_generation == parts.projection_generation)
        {
            self.active_cut = Some((parts.projection_generation, marker.state_generation));
        }
        Ok(())
    }

    fn active_projection(&self, generation: u64) -> bool {
        self.peer.as_ref().is_some_and(|peer| {
            (!peer.snapshot_required || peer.pending_generation.is_some())
                && peer.projection_generation == generation
        })
    }

    fn projection(
        &mut self,
        edge: &EdgeFederation,
        key: StoredKey,
        value: PersistentRecordValue,
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        if value.record_kind() == agenc_relay_storage::federation_records::PROJECTION_MARKER_KIND {
            return self.marker(edge, &key, &value);
        }
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
        if self.active_projection(header.projection_generation) {
            self.charge_generation(false, row.entry_object.len(), cause)?;
            self.projection.push(record);
        } else if self
            .peer
            .as_ref()
            .is_some_and(|peer| peer.pending_generation == Some(header.projection_generation))
        {
            self.charge_generation(true, row.entry_object.len(), cause)?;
            self.pending_projection.push(record);
        }
        Ok(())
    }

    fn install_projection(
        &mut self,
        edge: &mut EdgeFederation,
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
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
        let entries = std::mem::take(&mut self.projection);
        // The active generation is this edge's own rows, not a coordinator
        // snapshot: `apply` reaches states the snapshot closure refuses, and a
        // restore that cannot rebuild one of them bricks a node that crossed
        // no rule (RUN-08, issue #134). Everything else still refuses.
        edge.replica
            .install_recovered(peer.projection_generation, entries)
            .map_err(|error| {
                *cause = EdgeRestoreCause::ActiveProjection(error);
                invalid()
            })?;
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
        edge.snapshot_cut = self.active_cut;
        if let Some(generation) = peer.pending_generation {
            super::sync::restore_pending(
                edge,
                generation,
                self.pending_marker.take().ok_or_else(invalid)?,
                std::mem::take(&mut self.pending_projection),
                cause,
            )?;
        }
        Ok(())
    }

    fn admit_state(
        &mut self,
        edge: &EdgeFederation,
        companion: Option<&mut E2eeEdge>,
        row: (StoredKey, PersistentRecordValue),
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        let (key, value) = row;
        match value.record_kind() {
            WITNESS_ROW_KIND => {
                self.charge_companion(value.body().len(), cause)?;
                companion
                    .ok_or_else(invalid)?
                    .restore_chain_witness(&key, WitnessRow::decode(value.body())?)?;
            }
            BARRIER_ROW_KIND => {
                self.admit_barrier(edge, key, &value, cause)?;
            }
            ROUTE_ROW_KIND => {
                self.charge_companion(value.body().len(), cause)?;
                companion
                    .ok_or_else(invalid)?
                    .restore_route(&key, &RouteRow::decode(value.body())?)?;
            }
            agenc_relay_storage::e2ee_records::SNAPSHOT_MARKER_ROW_KIND => {
                use agenc_relay_storage::e2ee_records::SnapshotMarkerRow;
                companion
                    .ok_or_else(invalid)?
                    .restore_snapshot_marker(&key, &SnapshotMarkerRow::decode(value.body())?)?;
            }
            agenc_relay_storage::e2ee_records::PENDING_ROUTE_ROW_KIND => {
                use agenc_relay_storage::e2ee_records::PendingRouteRow;
                self.charge_companion(value.body().len(), cause)?;
                companion
                    .ok_or_else(invalid)?
                    .restore_pending_route(&key, &PendingRouteRow::decode(value.body())?)?;
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
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        self.charge_companion(value.body().len(), cause)?;
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
        storage: (&StoragePort, &KeyDeriver, HeadCounters),
        cause: &mut EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        let (port, keys, head) = storage;
        for (mutation, barrier_head) in std::mem::take(&mut self.heads) {
            let parts = self.parts.remove(&mutation).unwrap_or_default();
            match barrier_head {
                BarrierHead::Stage(stage) => {
                    install_stage(
                        edge,
                        &mut companion,
                        (stage, parts, self.peer.as_ref().ok_or_else(invalid)?),
                        (port, keys),
                        cause,
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
    restored: (
        agenc_relay_storage::e2ee_records::barrier::BarrierStage,
        Vec<BarrierPart>,
        &FederationPeerRecord,
    ),
    storage: (&StoragePort, &KeyDeriver),
    cause: &mut EdgeRestoreCause,
) -> Result<(), RuntimeError> {
    let (stage, parts, peer) = restored;
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
    // A collecting barrier requires the edge checkpoint that witnessed it.
    if companion
        .as_deref()
        .is_some_and(E2eeEdge::needs_witness_snapshot)
    {
        return Err(invalid());
    }
    let base_events = restore_stage_events(companion, &parts, storage)?;
    let assembly = BarrierAssembly::restore(stage, parts).map_err(|fault| {
        *cause = EdgeRestoreCause::BarrierAssembly(fault);
        // An aggregate over the ceiling is an admission fact about how much
        // this barrier carries, not a claim that the rows disagree.
        if fault == crate::e2ee::barrier::BarrierFault::Aggregate {
            RuntimeError::LimitExceeded
        } else {
            invalid()
        }
    })?;
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
    identity: &agenc_relay_storage::e2ee_records::barrier::BarrierIdentity,
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
    let expected = agenc_relay_federation_wire::CrossProfilePart {
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
    receipt: &agenc_relay_storage::e2ee_records::barrier::BarrierReceipt,
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
    receipt: &agenc_relay_storage::e2ee_records::barrier::BarrierReceipt,
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
                *agenc_relay_e2ee::ObjectId::compute(&part.encoded_event_object).as_bytes()
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
    receipt: &agenc_relay_storage::e2ee_records::barrier::BarrierReceipt,
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
