#![forbid(unsafe_code)]

//! Peer, marker and projection-entry rows that disagree with this edge refuse the reload at the
//! step that owns them, and a pending generation with its marker restores as a snapshot in
//! progress.

use agenc_relay_domain::federation::ProjectionRecord;
use agenc_relay_federation_wire::{
    CanonicalEncode, ProjectionEntryHeader, federation_object_id, snapshot_digest,
};
use agenc_relay_storage::federation_records::{
    DeliveryCursorRecord, FederationPeerRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND,
    PROJECTION_MARKER_KIND, PeerPhase, ProjectionEntryRecord, ProjectionGenerationState,
    ProjectionMarkerRecord, peer_key, projection_entry_key, projection_marker_key,
};
use agenc_relay_storage::{
    InitialStorageRecord, PersistentRecordValue, ProtocolRecordBody, StoredKey, TableId,
};

use super::*;
use crate::federation::edge::EdgeRestoreStep;

fn peer(generation: u64, entries: u64) -> FederationPeerRecord {
    FederationPeerRecord {
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
    }
}

fn row(
    table: TableId,
    key: StoredKey,
    kind: u16,
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let generation = u64::from(table == TableId::EdgeProjection);
    let value =
        PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body)?.encode()?;
    Ok(InitialStorageRecord::new(table, key, 1, value)?)
}

fn peer_row(record: &FederationPeerRecord, kind: u16) -> TestResult<InitialStorageRecord> {
    let body = if kind == PEER_RECORD_KIND {
        record.encode()?
    } else {
        foreign_body(TableId::FederationPeer, kind)?
    };
    row(TableId::FederationPeer, peer_key(COORDINATOR)?, kind, body)
}

/// A well-formed protocol body of a kind the restore does not read.
fn foreign_body(table: TableId, kind: u16) -> TestResult<Vec<u8>> {
    Ok(ProtocolRecordBody::new(table, kind, 1, vec![1, 2, 3])?.encode()?)
}

fn session(seed: u8) -> TestResult<ProjectionRecord> {
    Ok(ProjectionRecord::Session(session_record(
        SessionId::from_bytes([seed; 16]),
        UserId::from_bytes([seed; 16]),
        &format!("restored{seed}"),
        1,
        seed,
    )?))
}

fn entry_bytes(
    network: NetworkId,
    target: ServerId,
    generation: u64,
    record: &ProjectionRecord,
) -> TestResult<Vec<u8>> {
    let arm = crate::federation::codec::projection::projection_arm_object(record)?;
    let entry = ProjectionEntryHeader {
        network_id: network,
        target_server_id: target,
        projection_generation: generation,
        projection_kind: crate::federation::codec::projection::projection_kind(record),
    }
    .build(&arm)?;
    Ok(entry.encode_canonical()?.as_slice().to_vec())
}

fn entry_key(generation: u64, record: &ProjectionRecord) -> TestResult<StoredKey> {
    let semantic = record.key();
    Ok(projection_entry_key(
        EDGE,
        generation,
        semantic.kind(),
        semantic.primary(),
    )?)
}

fn entry_row(
    key: StoredKey,
    kind: u16,
    object_id: Option<[u8; 32]>,
    bytes: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let record = ProjectionEntryRecord {
        entry_object_id: object_id.unwrap_or(*federation_object_id(&bytes).as_bytes()),
        entry_object: bytes,
    };
    row(TableId::EdgeProjection, key, kind, record.encode()?)
}

fn honest_entry(generation: u64, record: &ProjectionRecord) -> TestResult<InitialStorageRecord> {
    entry_row(
        entry_key(generation, record)?,
        PROJECTION_ENTRY_KIND,
        None,
        entry_bytes(NETWORK, EDGE, generation, record)?,
    )
}

fn marker_row(key: StoredKey, marker: &ProjectionMarkerRecord) -> TestResult<InitialStorageRecord> {
    row(
        TableId::EdgeProjection,
        key,
        PROJECTION_MARKER_KIND,
        marker.encode()?,
    )
}

fn pending_marker(
    generation: u64,
    entries: &[ProjectionRecord],
) -> TestResult<ProjectionMarkerRecord> {
    let mut ids = Vec::new();
    let mut bytes = 0_u64;
    for record in entries {
        let encoded = entry_bytes(NETWORK, EDGE, generation, record)?;
        bytes = bytes.saturating_add(u64::try_from(encoded.len())?);
        ids.push(federation_object_id(&encoded));
    }
    Ok(ProjectionMarkerRecord {
        state: ProjectionGenerationState::Pending,
        state_generation: 7,
        entry_count: u64::try_from(entries.len())?,
        entry_bytes: bytes,
        digest: *snapshot_digest(&COORDINATOR_EPOCH, generation, 7, &ids)?.as_bytes(),
        snapshot_token: Some([9; 32]),
        cut_cursor: None,
        recovery_epoch: *COORDINATOR_EPOCH.as_bytes(),
    })
}

fn restored(
    records: Vec<InitialStorageRecord>,
) -> TestResult<(Option<EdgeRestoreStep>, EdgeFederation)> {
    let fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    let mut edge = resync_edge();
    let step = fixture
        .restore_edge_refusal(&mut edge, None)?
        .err()
        .map(|refusal| refusal.step);
    Ok((step, edge))
}

fn assert_refused(records: Vec<InitialStorageRecord>, step: EdgeRestoreStep) -> TestResult {
    let (refused, edge) = restored(records)?;
    assert_eq!(refused, Some(step));
    assert_eq!(edge.replica.entry_count(), 0, "nothing is installed");
    Ok(())
}

#[tokio::test]
async fn a_peer_row_of_another_kind_refuses_at_the_peer_record() -> TestResult {
    assert_refused(
        vec![peer_row(&peer(1, 0), PEER_RECORD_KIND + 1)?],
        EdgeRestoreStep::PeerRecord,
    )
}

#[tokio::test]
async fn a_projection_row_of_an_unknown_kind_refuses_at_the_projection_entries() -> TestResult {
    let record = session(20)?;
    assert_refused(
        vec![
            peer_row(&peer(1, 1), PEER_RECORD_KIND)?,
            row(
                TableId::EdgeProjection,
                entry_key(1, &record)?,
                PROJECTION_MARKER_KIND + 1,
                foreign_body(TableId::EdgeProjection, PROJECTION_MARKER_KIND + 1)?,
            )?,
        ],
        EdgeRestoreStep::ProjectionEntries,
    )
}

#[tokio::test]
async fn a_projection_entry_that_disagrees_with_this_edge_refuses_at_the_projection_entries()
-> TestResult {
    let record = session(20)?;
    let other = session(21)?;
    let honest = entry_bytes(NETWORK, EDGE, 1, &record)?;
    let tampered: Vec<InitialStorageRecord> = vec![
        entry_row(
            entry_key(1, &record)?,
            PROJECTION_ENTRY_KIND,
            None,
            entry_bytes(NetworkId::from_bytes([99; 32]), EDGE, 1, &record)?,
        )?,
        entry_row(
            entry_key(1, &record)?,
            PROJECTION_ENTRY_KIND,
            None,
            entry_bytes(NETWORK, HUB, 1, &record)?,
        )?,
        entry_row(
            entry_key(1, &record)?,
            PROJECTION_ENTRY_KIND,
            Some([99; 32]),
            honest.clone(),
        )?,
        entry_row(
            entry_key(2, &record)?,
            PROJECTION_ENTRY_KIND,
            None,
            honest.clone(),
        )?,
        entry_row(entry_key(1, &other)?, PROJECTION_ENTRY_KIND, None, honest)?,
    ];
    for entry in tampered {
        assert_refused(
            vec![peer_row(&peer(1, 1), PEER_RECORD_KIND)?, entry],
            EdgeRestoreStep::ProjectionEntries,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn a_marker_under_another_target_or_an_entry_key_refuses_at_the_projection_entries()
-> TestResult {
    let marker = pending_marker(1, &[])?;
    let record = session(20)?;
    for key in [projection_marker_key(HUB, 1)?, entry_key(1, &record)?] {
        assert_refused(
            vec![
                peer_row(&peer(1, 0), PEER_RECORD_KIND)?,
                marker_row(key, &marker)?,
            ],
            EdgeRestoreStep::ProjectionEntries,
        )?;
    }
    Ok(())
}

#[tokio::test]
async fn a_peer_row_whose_delivery_sequence_disagrees_with_its_cursor_refuses_at_install()
-> TestResult {
    let mut record = peer(1, 0);
    record.cursor = Some(DeliveryCursorRecord {
        delivery_sequence: 3,
        event_id: [5; 16],
    });
    record.next_delivery_sequence = 3;
    assert_refused(
        vec![peer_row(&record, PEER_RECORD_KIND)?],
        EdgeRestoreStep::ProjectionInstall,
    )?;
    record.next_delivery_sequence = 4;
    let (refused, edge) = restored(vec![peer_row(&record, PEER_RECORD_KIND)?])?;
    assert_eq!(refused, None);
    assert_eq!(edge.cursor.map(|(sequence, _)| sequence), Some(3));
    Ok(())
}

#[tokio::test]
async fn a_pending_generation_with_its_marker_restores_as_a_snapshot_in_progress() -> TestResult {
    let mut record = peer(1, 0);
    record.pending_generation = Some(2);
    record.snapshot_required = true;
    let pending = session(20)?;
    let marker = pending_marker(2, std::slice::from_ref(&pending))?;
    let stray = session(21)?;
    let (refused, edge) = restored(vec![
        peer_row(&record, PEER_RECORD_KIND)?,
        marker_row(projection_marker_key(EDGE, 2)?, &marker)?,
        honest_entry(2, &pending)?,
        // A generation that is neither active nor pending is left alone.
        honest_entry(3, &stray)?,
    ])?;
    assert_eq!(refused, None);
    let snapshot = edge.snapshot.as_ref().ok_or("no pending snapshot")?;
    assert!(snapshot.holds(&pending.key()));
    assert!(!snapshot.holds(&stray.key()));
    assert_eq!(
        edge.replica.entry_count(),
        0,
        "the active generation is empty"
    );
    assert!(
        edge.installed_epoch.is_none(),
        "a fenced generation has no installed epoch"
    );
    Ok(())
}

#[tokio::test]
async fn an_active_marker_records_the_cut_of_the_active_generation() -> TestResult {
    let mut marker = pending_marker(1, &[])?;
    marker.state = ProjectionGenerationState::Active;
    marker.snapshot_token = None;
    let (refused, edge) = restored(vec![
        peer_row(&peer(1, 0), PEER_RECORD_KIND)?,
        marker_row(projection_marker_key(EDGE, 1)?, &marker)?,
    ])?;
    assert_eq!(refused, None);
    assert_eq!(edge.snapshot_cut, Some((1, 7)));
    Ok(())
}
