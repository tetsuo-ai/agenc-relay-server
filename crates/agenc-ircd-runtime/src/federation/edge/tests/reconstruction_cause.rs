#![forbid(unsafe_code)]

//! RUN-08: a refused edge restore must carry out the cause it was given.
//!
//! Two arms of the restore mapped an owner's own refusal to
//! `StorageError::StaleState` and threw the cause away, which is what sent
//! #124 to the storage layer. These cases pin the operator-visible line for a
//! refusal the edge replica raised, for an incomplete companion snapshot
//! generation, and for the restore's own admission ceilings, which must not
//! read as stale durable state.

use super::*;

use agenc_ircd_domain::Role;
use agenc_ircd_domain::federation::{MembershipRecord, ProjectionRecord, ReplicaError};
use agenc_ircd_federation_wire::CanonicalEncode;
use agenc_ircd_storage::federation_records::{
    FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND, PeerPhase,
    ProjectionEntryRecord, peer_key, projection_entry_key,
};
use agenc_ircd_storage::{InitialStorageRecord, PersistentRecordValue, StorageError, TableId};

use crate::federation::edge::{EdgeRestoreCause, EdgeRestoreStep};

/// The coordinator row of an edge holding one standing entry at `generation`.
fn peer_row(generation: u64, entries: u64) -> TestResult<InitialStorageRecord> {
    let record = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *HUB_INCARNATION.as_bytes(),
        recovery_epoch: *COORDINATOR_EPOCH.as_bytes(),
        accepted_epochs: Vec::new(),
        phase: PeerPhase::Suspended,
        projection_generation: generation,
        next_delivery_sequence: 0,
        cursor: None,
        active_entry_count: entries,
        active_entry_bytes: 0,
        pending_generation: None,
        snapshot_required: false,
        cleanup_cursor: None,
        quarantined: false,
        client_resync_epoch: 0,
    };
    durable_row(
        TableId::FederationPeer,
        peer_key(COORDINATOR)?,
        (PEER_RECORD_KIND, 0),
        record.encode()?,
    )
}

/// One durable `EdgeProjection` entry row under its own semantic key.
fn projection_row(generation: u64, record: &ProjectionRecord) -> TestResult<InitialStorageRecord> {
    let arm = crate::federation::codec::projection::projection_arm_object(record)
        .map_err(|error| format!("arm: {error:?}"))?;
    let entry = agenc_ircd_federation_wire::ProjectionEntryHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)
    .map_err(|error| format!("entry: {error:?}"))?
    .encode_canonical()
    .map_err(|error| format!("encode: {error:?}"))?;
    let bytes = entry.as_slice().to_vec();
    let row = ProjectionEntryRecord {
        entry_object_id: *agenc_ircd_federation_wire::federation_object_id(&bytes).as_bytes(),
        entry_object: bytes,
    };
    let semantic = record.key();
    durable_row(
        TableId::EdgeProjection,
        projection_entry_key(EDGE, generation, semantic.kind(), semantic.primary())?,
        (PROJECTION_ENTRY_KIND, generation),
        row.encode()?,
    )
}

/// Wraps one encoded record body as a seeded initial storage row.
fn durable_row(
    table: TableId,
    key: agenc_ircd_storage::StoredKey,
    record: (u16, u64),
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let (kind, generation) = record;
    let value =
        PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body)?.encode()?;
    Ok(InitialStorageRecord::new(table, key, 1, value)?)
}

/// A membership whose channel and member were never projected. The replica
/// refuses it as a dangling reference, which the restore used to report as
/// stale storage state.
fn dangling_membership() -> TestResult<ProjectionRecord> {
    Ok(ProjectionRecord::Membership(MembershipRecord {
        channel_id: ChannelInstanceId::from_bytes([91; 16]),
        user_id: UserId::from_bytes([92; 16]),
        role: Role::Member,
        membership_revision: Revision::new(4)?,
        joined_at: agenc_ircd_types::UtcSecond::new(1_700_000_000)?,
    }))
}

#[tokio::test]
async fn a_projection_the_replica_refuses_names_the_replica_and_not_the_storage_layer() -> TestResult
{
    let mut records = peer_row(1, 1).map(|row| vec![row])?;
    records.push(projection_row(1, &dangling_membership()?)?);
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore installed a projection the replica cannot hold")?;
    assert_eq!(refusal.step, EdgeRestoreStep::ProjectionInstall);
    assert_eq!(
        refusal.cause,
        EdgeRestoreCause::ActiveProjection(ReplicaError::DanglingReference),
        "the replica's own refusal must survive the restore's error mapping"
    );
    assert_eq!(
        refusal.error,
        RuntimeError::Storage(StorageError::StaleState)
    );
    assert_eq!(
        crate::daemon::DaemonError::from(refusal).to_string(),
        "runtime startup failed: edge federation restore at edge-projection-install (active \
         projection: federation replica reference does not resolve) refused the recovered state: \
         storage owner failed: storage state is stale or inconsistent",
    );
    Ok(())
}

#[tokio::test]
async fn an_unnamed_refusal_still_prints_the_line_the_step_label_alone_produced() -> TestResult {
    let fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        vec![peer_row(1, 7)?],
    )?;
    let mut edge = resync_edge();
    let refusal = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .ok_or("the restore accepted a count no durable row supports")?;
    assert_eq!(refusal.cause, EdgeRestoreCause::Unclassified);
    assert_eq!(
        crate::daemon::DaemonError::from(refusal).to_string(),
        "runtime startup failed: edge federation restore at edge-projection-install refused the \
         recovered state: storage owner failed: storage state is stale or inconsistent",
    );
    Ok(())
}
