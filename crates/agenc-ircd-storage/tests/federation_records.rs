//! Stage 07 federation record codecs: round trips, boundary rejections, table
//! and arm binding, key layouts, and acceptance by the persistent envelope.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_storage::{
    COMPLETION_COVERAGE_KIND, COORDINATOR_RESULT_KIND, CompletionCoverageRecord,
    CoordinatorResultRecord, DeliveryCursorRecord, EDGE_REQUEST_KIND, EdgeRequestPhase,
    EdgeRequestRecord, FederationOriginRecord, FederationPeerRecord, MAX_ACCEPTED_EPOCHS,
    ORIGIN_FLAG_PENDING_DEL, ORIGIN_FLAG_SINK_GONE, ORIGIN_RECORD_KIND, OUTBOX_EVENT_KIND,
    OriginRowStatus, OutboxEventRecord, PEER_RECORD_KIND, PROJECTION_ENTRY_KIND,
    PROJECTION_MARKER_KIND, PeerPhase, PersistentRecordValue, ProjectionEntryRecord,
    ProjectionGenerationState, ProjectionMarkerRecord, StorageError, TableId, origin_key,
    outbox_key, outbox_range, parse_origin_key, parse_outbox_key, parse_projection_key, peer_key,
    projection_entry_key, projection_marker_key, projection_range, request_result_key,
};
use agenc_ircd_types::{ServerId, ServerIncarnation};

type TestResult = Result<(), Box<dyn Error>>;

const TARGET: ServerId = ServerId::from_bytes([7; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([8; 16]);

fn peer() -> FederationPeerRecord {
    FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: [1; 16],
        recovery_epoch: [2; 16],
        accepted_epochs: vec![[2; 16], [3; 16]],
        phase: PeerPhase::Ready,
        projection_generation: 4,
        next_delivery_sequence: 10,
        cursor: Some(DeliveryCursorRecord {
            delivery_sequence: 9,
            event_id: [5; 16],
        }),
        active_entry_count: 3,
        active_entry_bytes: 700,
        pending_generation: Some(5),
        snapshot_required: true,
        cleanup_cursor: Some([6; 16]),
        quarantined: false,
        client_resync_epoch: 2,
    }
}

fn origin() -> FederationOriginRecord {
    FederationOriginRecord {
        origin_object: vec![1, 2, 3, 4],
        origin_object_id: [9; 32],
        next_sequence: 3,
        status: OriginRowStatus::Live,
        flags: ORIGIN_FLAG_SINK_GONE,
    }
}

fn coordinator_result() -> CoordinatorResultRecord {
    CoordinatorResultRecord {
        request_id: [1; 16],
        request_object_id: [2; 32],
        result_object_id: [3; 32],
        result_object: vec![4; 40],
        completion_event_id: Some([5; 16]),
        resulting_state_generation: 77,
    }
}

fn edge_request() -> EdgeRequestRecord {
    EdgeRequestRecord {
        completion_coverage: None,
        request_id: [1; 16],
        request_object_id: [2; 32],
        request_object: vec![3; 30],
        phase: EdgeRequestPhase::ResultPending,
        sink_gone: false,
        result_object_id: Some([4; 32]),
        result_object: vec![5; 20],
        completion_event_id: Some([6; 16]),
        resulting_state_generation: 8,
    }
}

fn coverage() -> CompletionCoverageRecord {
    CompletionCoverageRecord {
        request_object_id: [1; 32],
        completion_event_id: [2; 16],
        completion_object_id: [3; 32],
        projection_generation: 4,
        delivery_sequence: 5,
        coordinator_state_generation: 6,
    }
}

fn outbox() -> OutboxEventRecord {
    OutboxEventRecord {
        event_id: [1; 16],
        event_object_id: [2; 32],
        event_object: vec![3; 50],
        coordinator_state_generation: 9,
        acknowledged: false,
        completion_replay_key: Some([4; 64]),
    }
}

fn entry() -> ProjectionEntryRecord {
    ProjectionEntryRecord {
        entry_object_id: [1; 32],
        entry_object: vec![2; 60],
    }
}

fn marker() -> ProjectionMarkerRecord {
    ProjectionMarkerRecord {
        state: ProjectionGenerationState::Active,
        state_generation: 12,
        entry_count: 3,
        entry_bytes: 180,
        digest: [7; 32],
        snapshot_token: None,
        cut_cursor: Some(DeliveryCursorRecord {
            delivery_sequence: 11,
            event_id: [8; 16],
        }),
        recovery_epoch: [9; 16],
    }
}

#[test]
fn every_arm_round_trips_and_binds_its_table_and_kind() -> TestResult {
    let peer_bytes = peer().encode()?;
    assert_eq!(FederationPeerRecord::decode(&peer_bytes)?, peer());
    assert!(FederationOriginRecord::decode(&peer_bytes).is_err());

    let origin_bytes = origin().encode()?;
    assert_eq!(FederationOriginRecord::decode(&origin_bytes)?, origin());
    assert!(FederationPeerRecord::decode(&origin_bytes).is_err());

    let result_bytes = coordinator_result().encode()?;
    assert_eq!(
        CoordinatorResultRecord::decode(&result_bytes)?,
        coordinator_result()
    );
    assert!(EdgeRequestRecord::decode(&result_bytes).is_err());

    let request_bytes = edge_request().encode()?;
    assert_eq!(EdgeRequestRecord::decode(&request_bytes)?, edge_request());
    assert!(CompletionCoverageRecord::decode(&request_bytes).is_err());

    let coverage_bytes = coverage().encode()?;
    assert_eq!(
        CompletionCoverageRecord::decode(&coverage_bytes)?,
        coverage()
    );

    let outbox_bytes = outbox().encode()?;
    assert_eq!(OutboxEventRecord::decode(&outbox_bytes)?, outbox());

    let entry_bytes = entry().encode()?;
    assert_eq!(ProjectionEntryRecord::decode(&entry_bytes)?, entry());
    assert!(ProjectionMarkerRecord::decode(&entry_bytes).is_err());

    let marker_bytes = marker().encode()?;
    assert_eq!(ProjectionMarkerRecord::decode(&marker_bytes)?, marker());
    Ok(())
}

#[test]
fn optional_fields_and_phases_cover_every_shape() -> TestResult {
    let mut bare = peer();
    bare.accepted_epochs.clear();
    bare.cursor = None;
    bare.pending_generation = None;
    bare.snapshot_required = false;
    bare.cleanup_cursor = None;
    bare.quarantined = true;
    for phase in [
        PeerPhase::Ready,
        PeerPhase::Suspended,
        PeerPhase::Expired,
        PeerPhase::Clean,
    ] {
        bare.phase = phase;
        assert_eq!(FederationPeerRecord::decode(&bare.encode()?)?, bare);
    }
    let mut record = origin();
    for status in [
        OriginRowStatus::Live,
        OriginRowStatus::Suspended,
        OriginRowStatus::Blocked,
        OriginRowStatus::Deleted,
        OriginRowStatus::Fenced,
    ] {
        record.status = status;
        record.flags = ORIGIN_FLAG_PENDING_DEL;
        assert_eq!(FederationOriginRecord::decode(&record.encode()?)?, record);
    }
    let mut request = edge_request();
    request.result_object_id = None;
    request.result_object.clear();
    request.completion_event_id = None;
    request.sink_gone = true;
    for phase in [
        EdgeRequestPhase::Sent,
        EdgeRequestPhase::ResultPending,
        EdgeRequestPhase::EventCovered,
        EdgeRequestPhase::SnapshotCovered,
        EdgeRequestPhase::Rendered,
    ] {
        request.phase = phase;
        assert_eq!(EdgeRequestRecord::decode(&request.encode()?)?, request);
    }
    let mut result = coordinator_result();
    result.completion_event_id = None;
    assert_eq!(CoordinatorResultRecord::decode(&result.encode()?)?, result);
    let mut event = outbox();
    event.completion_replay_key = None;
    event.acknowledged = true;
    assert_eq!(OutboxEventRecord::decode(&event.encode()?)?, event);
    let mut marker = marker();
    marker.snapshot_token = Some([1; 32]);
    marker.cut_cursor = None;
    for state in [
        ProjectionGenerationState::Pending,
        ProjectionGenerationState::Active,
        ProjectionGenerationState::Quarantined,
    ] {
        marker.state = state;
        assert_eq!(ProjectionMarkerRecord::decode(&marker.encode()?)?, marker);
    }
    Ok(())
}

#[test]
fn encoders_reject_out_of_bound_values() -> TestResult {
    let mut peer_record = peer();
    peer_record.accepted_epochs = vec![[0; 16]; MAX_ACCEPTED_EPOCHS + 1];
    assert_eq!(
        peer_record.encode().err(),
        Some(StorageError::LimitExceeded)
    );

    let mut origin_record = origin();
    origin_record.origin_object.clear();
    assert_eq!(
        origin_record.encode().err(),
        Some(StorageError::LimitExceeded)
    );
    origin_record.origin_object = vec![0; 513];
    assert_eq!(
        origin_record.encode().err(),
        Some(StorageError::LimitExceeded)
    );
    origin_record.origin_object = vec![0; 8];
    origin_record.flags = 4;
    assert_eq!(
        origin_record.encode().err(),
        Some(StorageError::InvalidEncoding)
    );

    let mut result = coordinator_result();
    result.result_object.clear();
    assert_eq!(result.encode().err(), Some(StorageError::LimitExceeded));
    result.result_object = vec![0; 262_145];
    assert_eq!(result.encode().err(), Some(StorageError::LimitExceeded));

    let mut request = edge_request();
    request.result_object.clear();
    assert_eq!(request.encode().err(), Some(StorageError::InvalidEncoding));
    request.result_object_id = None;
    request.request_object.clear();
    assert_eq!(request.encode().err(), Some(StorageError::InvalidEncoding));

    let mut event = outbox();
    event.event_object = vec![0; 262_345];
    assert_eq!(event.encode().err(), Some(StorageError::LimitExceeded));
    event.event_object.clear();
    assert_eq!(event.encode().err(), Some(StorageError::LimitExceeded));

    let mut projection = entry();
    projection.entry_object = vec![0; 8_321];
    assert_eq!(projection.encode().err(), Some(StorageError::LimitExceeded));
    projection.entry_object.clear();
    assert_eq!(projection.encode().err(), Some(StorageError::LimitExceeded));
    Ok(())
}

/// Byte offsets inside the wrapped bodies used by the corruption cases:
/// the protocol envelope is 12 bytes, then each arm's own version prefix.
const ENVELOPE_BYTES: usize = 12;
const PEER_PHASE_OFFSET: usize = ENVELOPE_BYTES + 2 + 16 + 16 + 2 + 32;
const ORIGIN_STATUS_OFFSET: usize = ENVELOPE_BYTES + 2 + 4 + 4 + 32 + 8;
const ORIGIN_FLAGS_OFFSET: usize = ORIGIN_STATUS_OFFSET + 2;
const MARKER_STATE_OFFSET: usize = ENVELOPE_BYTES + 2;

fn patch(bytes: &mut [u8], offset: usize, value: u8) -> TestResult {
    *bytes.get_mut(offset).ok_or("offset outside body")? = value;
    Ok(())
}

#[test]
fn decoders_reject_corrupt_flags_options_and_trailing_bytes() -> TestResult {
    let mut trailing = peer().encode()?;
    trailing.push(0);
    assert!(FederationPeerRecord::decode(&trailing).is_err());

    let mut corrupt_phase = peer().encode()?;
    patch(&mut corrupt_phase, PEER_PHASE_OFFSET, 0)?;
    patch(&mut corrupt_phase, PEER_PHASE_OFFSET + 1, 9)?;
    assert!(FederationPeerRecord::decode(&corrupt_phase).is_err());

    let mut flags_bytes = origin().encode()?;
    patch(&mut flags_bytes, ORIGIN_FLAGS_OFFSET + 1, 0xff)?;
    assert!(FederationOriginRecord::decode(&flags_bytes).is_err());

    let mut status_bytes = origin().encode()?;
    patch(&mut status_bytes, ORIGIN_STATUS_OFFSET + 1, 9)?;
    assert!(FederationOriginRecord::decode(&status_bytes).is_err());

    let mut marker_bytes = marker().encode()?;
    patch(&mut marker_bytes, MARKER_STATE_OFFSET + 1, 9)?;
    assert!(ProjectionMarkerRecord::decode(&marker_bytes).is_err());

    let mut absent_cursor_with_value = peer();
    absent_cursor_with_value.cursor = None;
    let mut bytes = absent_cursor_with_value.encode()?;
    let cursor_present_offset = PEER_PHASE_OFFSET + 2 + 8 + 8;
    patch(&mut bytes, cursor_present_offset + 2 + 7, 1)?;
    assert!(FederationPeerRecord::decode(&bytes).is_err());
    patch(&mut bytes, cursor_present_offset + 2 + 7, 0)?;
    patch(&mut bytes, cursor_present_offset + 1, 2)?;
    assert!(FederationPeerRecord::decode(&bytes).is_err());
    Ok(())
}

#[test]
fn keys_have_fixed_layouts_and_round_trip() -> TestResult {
    assert_eq!(peer_key(TARGET)?.as_bytes().len(), 16);
    let origin = origin_key(TARGET, INCARNATION, [3; 16], 4)?;
    assert_eq!(origin.as_bytes().len(), 56);
    let parts = parse_origin_key(&origin)?;
    assert_eq!(parts.peer, TARGET);
    assert_eq!(parts.incarnation, INCARNATION);
    assert_eq!(parts.origin_id, [3; 16]);
    assert_eq!(parts.generation, 4);
    assert!(parse_origin_key(&peer_key(TARGET)?).is_err());

    assert_eq!(request_result_key([1; 64])?.as_bytes().len(), 64);

    let outbox = outbox_key(TARGET, 2, 3)?;
    assert_eq!(outbox.as_bytes().len(), 32);
    let parts = parse_outbox_key(&outbox)?;
    assert_eq!(parts.target, TARGET);
    assert_eq!(parts.projection_generation, 2);
    assert_eq!(parts.delivery_sequence, 3);
    assert!(parse_outbox_key(&origin).is_err());
    let (start, end) = outbox_range(TARGET, 2, 3, 5)?;
    assert!(start == outbox);
    assert!(end == outbox_key(TARGET, 2, 6)?);
    assert!(outbox_key(TARGET, 2, 5)? < end);
    assert!(outbox_range(TARGET, 2, 5, 3).is_err());
    let (_, end) = outbox_range(TARGET, 2, u64::MAX, u64::MAX)?;
    assert!(outbox_key(TARGET, 2, u64::MAX)? < end);
    assert!(end < outbox_key(TARGET, 3, 0)?);

    let entry = projection_entry_key(TARGET, 5, 4, &[1; 32])?;
    assert_eq!(entry.as_bytes().len(), 58);
    let parts = parse_projection_key(&entry)?;
    assert_eq!(parts.kind, 4);
    assert_eq!(parts.primary, vec![1; 32]);
    assert_eq!(parts.projection_generation, 5);
    assert_eq!(parts.target, TARGET);
    assert!(projection_entry_key(TARGET, 5, 0, &[1]).is_err());
    assert!(projection_entry_key(TARGET, 5, 1, &[]).is_err());
    let marker = projection_marker_key(TARGET, 5)?;
    assert_eq!(marker.as_bytes().len(), 26);
    let parts = parse_projection_key(&marker)?;
    assert_eq!(parts.kind, 0);
    assert!(parts.primary.is_empty());
    assert!(parse_projection_key(&outbox).is_err());
    let mut fake_marker = marker.as_bytes().to_vec();
    fake_marker.push(1);
    assert!(parse_projection_key(&agenc_ircd_storage::StoredKey::new(fake_marker)?).is_err());
    let (start, end) = projection_range(TARGET, 5)?;
    assert!(start == marker);
    assert!(marker < entry && entry < end);
    assert!(end == projection_marker_key(TARGET, 6)?);
    let (start, end) = projection_range(TARGET, u64::MAX)?;
    assert!(start < end);
    Ok(())
}

#[test]
fn persistent_envelope_accepts_every_federation_arm() -> TestResult {
    let cases: Vec<(TableId, u16, u64, Vec<u8>)> = vec![
        (
            TableId::FederationPeer,
            PEER_RECORD_KIND,
            0,
            peer().encode()?,
        ),
        (
            TableId::FederationOrigin,
            ORIGIN_RECORD_KIND,
            0,
            origin().encode()?,
        ),
        (
            TableId::RequestResult,
            COORDINATOR_RESULT_KIND,
            0,
            coordinator_result().encode()?,
        ),
        (
            TableId::RequestResult,
            EDGE_REQUEST_KIND,
            0,
            edge_request().encode()?,
        ),
        (
            TableId::RequestResult,
            COMPLETION_COVERAGE_KIND,
            0,
            coverage().encode()?,
        ),
        (
            TableId::EdgeOutbox,
            OUTBOX_EVENT_KIND,
            0,
            outbox().encode()?,
        ),
        (
            TableId::EdgeProjection,
            PROJECTION_ENTRY_KIND,
            5,
            entry().encode()?,
        ),
        (
            TableId::EdgeProjection,
            PROJECTION_MARKER_KIND,
            5,
            marker().encode()?,
        ),
    ];
    for (table, kind, generation, body) in cases {
        let value =
            PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body.clone())?;
        assert_eq!(value.body(), body.as_slice());
        let wrong_kind = kind % 3 + 1;
        if wrong_kind != kind {
            assert!(
                PersistentRecordValue::new(
                    table,
                    wrong_kind,
                    1,
                    generation,
                    None,
                    Vec::new(),
                    body
                )
                .is_err()
            );
        }
    }
    Ok(())
}
