//! Each reloaded row is judged against its own key and the owner's tables before it is admitted.
#![forbid(unsafe_code)]

use agenc_ircd_domain::federation::ProjectedEvent;
use agenc_ircd_federation_wire::{CanonicalEncode, EventHeader, federation_object_id};
use agenc_ircd_storage::federation_records::{
    DeliveryCursorRecord, OUTBOX_EVENT_KIND, OutboxEventRecord, origin_key, outbox_key, peer_key,
    projection_marker_key, request_result_key,
};
use agenc_ircd_types::{ConnectionId, EventId, NetworkId};

use super::*;
use crate::bridge::crypto::ChannelKeyVerifierRecord;
use crate::federation::coordinator::CoordinatorConfig;
use crate::test_support::{StateCoreFixture, TestResult};

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const COORDINATOR: ServerId = ServerId::from_bytes([32; 16]);
const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([99; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn owner() -> FederationCoordinator {
    FederationCoordinator::new(
        CoordinatorConfig {
            network_id: NETWORK,
            server_id: COORDINATOR,
            server_name: "server.example".into(),
            recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 1,
        },
        vec![crate::federation::PeerIdentity::new(
            PEER,
            "edge.example",
            agenc_ircd_types::FederationRole::Edge,
            RecoveryEpoch::from_bytes([34; 16]),
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([9; 32]).public_key(),
            [8; 32],
        )],
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    )
}

fn value(table: TableId, kind: u16, body: Vec<u8>) -> TestResult<PersistentRecordValue> {
    // Projection rows carry their generation; every other table leaves it zero.
    let generation = u64::from(table == TableId::EdgeProjection);
    Ok(PersistentRecordValue::new(
        table,
        kind,
        1,
        generation,
        None,
        Vec::new(),
        body,
    )?)
}

fn peer_state(
    coordinator: &FederationCoordinator,
) -> TestResult<&crate::federation::coordinator::PeerState> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?)
}

#[test]
fn a_page_continues_at_the_smallest_key_after_the_last_row() -> TestResult {
    let short = StoredKey::new(vec![7, 0xff])?;
    assert_eq!(
        successor(&short).ok_or("successor")?.as_bytes(),
        [7, 0xff, 0]
    );
    let mut full = vec![7; MAX_STORED_KEY_BYTES];
    let next = successor(&StoredKey::new(full.clone())?).ok_or("successor")?;
    assert_eq!(next.as_bytes().len(), MAX_STORED_KEY_BYTES);
    assert_eq!(next.as_bytes().last(), Some(&8));
    full.pop();
    full.push(0xff);
    let carried = successor(&StoredKey::new(full)?).ok_or("successor")?;
    assert_eq!(carried.as_bytes().len(), MAX_STORED_KEY_BYTES - 1);
    assert_eq!(carried.as_bytes().last(), Some(&8));
    let last = StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES])?;
    assert!(
        successor(&last).is_none(),
        "nothing sorts after the last key"
    );
    Ok(())
}

#[test]
fn every_reload_pass_must_observe_the_pinned_commit() {
    let mut coordinator = owner();
    assert_eq!(pin_result(&mut coordinator, 4), Ok(()));
    assert_eq!(pin_result(&mut coordinator, 4), Ok(()));
    assert_eq!(pin_result(&mut coordinator, 5), Err(Violation::Codec));
    assert_eq!(coordinator.loader.pinned_commit, Some(4));
}

fn peer_record(phase: PeerPhase) -> FederationPeerRecord {
    FederationPeerRecord {
        fenced_incarnations: vec![[52; 16]],
        server_incarnation: *INCARNATION.as_bytes(),
        recovery_epoch: [35; 16],
        accepted_epochs: vec![[35; 16]],
        phase,
        projection_generation: 3,
        next_delivery_sequence: 9,
        cursor: Some(DeliveryCursorRecord {
            delivery_sequence: 8,
            event_id: [61; 16],
        }),
        active_entry_count: 0,
        active_entry_bytes: 0,
        pending_generation: None,
        snapshot_required: true,
        cleanup_cursor: Some([7; 16]),
        quarantined: true,
        client_resync_epoch: 5,
    }
}

#[tokio::test]
async fn a_peer_row_restores_its_position_fences_and_origin_phase() -> TestResult {
    for (phase, expected) in [
        (PeerPhase::Suspended, EdgePhase::Ready),
        (PeerPhase::Expired, EdgePhase::Expired),
    ] {
        let mut core = StateCoreFixture::new(vec![1; 256])?;
        let mut coordinator = owner();
        let row = value(
            TableId::FederationPeer,
            PEER_RECORD_KIND,
            peer_record(phase).encode()?,
        )?;
        let admitted = admit(
            &mut coordinator,
            core.context_mut()?,
            TableId::FederationPeer,
            &peer_key(PEER)?,
            &row,
        );
        assert_eq!(admitted, Ok(()));
        let state = peer_state(&coordinator)?;
        assert_eq!(state.incarnation, Some(INCARNATION));
        assert_eq!(
            state.recovery_epoch,
            Some(RecoveryEpoch::from_bytes([35; 16]))
        );
        assert_eq!(state.accepted_epochs, [RecoveryEpoch::from_bytes([35; 16])]);
        assert_eq!(state.phase, phase);
        assert_eq!(state.projection_generation, 3);
        assert_eq!(
            state.outbox.cursor,
            Some((8, EventId::from_bytes([61; 16])))
        );
        assert_eq!(state.outbox.reserved_next, 9);
        assert!(state.outbox.snapshot_required && state.quarantined);
        assert_eq!(state.cleanup_cursor, Some([7; 16]));
        assert_eq!(state.client_resync_epoch, 5);
        assert_eq!(
            coordinator.origins.edge(PEER).map(|link| link.phase),
            Some(expected)
        );
        let fenced: Vec<_> = coordinator.origins.fenced_incarnations_of(PEER).collect();
        assert!(fenced.contains(&ServerIncarnation::from_bytes([52; 16])));
        assert_eq!(fenced.contains(&INCARNATION), phase == PeerPhase::Expired);
    }
    Ok(())
}

#[tokio::test]
async fn a_peer_row_that_never_linked_restores_no_incarnation() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    let mut record = peer_record(PeerPhase::Clean);
    record.server_incarnation = [0; 16];
    record.recovery_epoch = [0; 16];
    let row = value(TableId::FederationPeer, PEER_RECORD_KIND, record.encode()?)?;
    let table = TableId::FederationPeer;
    assert_eq!(
        admit(&mut coordinator, context, table, &peer_key(PEER)?, &row),
        Ok(())
    );
    let state = peer_state(&coordinator)?;
    assert_eq!(state.incarnation, None);
    assert_eq!(state.recovery_epoch, None);
    assert!(coordinator.origins.edge(PEER).is_none());
    // A row for a peer that is no longer configured is not this reload's to judge.
    let mut unconfigured = owner();
    assert_eq!(
        admit(
            &mut unconfigured,
            context,
            table,
            &peer_key(STRANGER)?,
            &row
        ),
        Ok(())
    );
    assert_eq!(
        state_of_default(&unconfigured)?,
        (None, PeerPhase::Clean, 1)
    );
    Ok(())
}

fn state_of_default(
    coordinator: &FederationCoordinator,
) -> TestResult<(Option<ServerIncarnation>, PeerPhase, u64)> {
    let state = peer_state(coordinator)?;
    Ok((state.incarnation, state.phase, state.projection_generation))
}

#[tokio::test]
async fn a_peer_row_under_a_malformed_key_fails_the_reload() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    let table = TableId::FederationPeer;
    let honest = value(
        table,
        PEER_RECORD_KIND,
        peer_record(PeerPhase::Ready).encode()?,
    )?;
    let short_key = StoredKey::new(vec![50; 15])?;
    assert_eq!(
        admit(&mut coordinator, context, table, &short_key, &honest),
        Err(Violation::Codec)
    );
    assert_eq!(state_of_default(&coordinator)?, (None, PeerPhase::Clean, 1));
    Ok(())
}

fn origin_object(generation: u64) -> OriginRecord {
    OriginRecord {
        network_id: NETWORK,
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([70; 16]),
        generation,
        previous_origin_object_id: [0; 32],
        connection_id: ConnectionId::from_bytes([71; 16]),
        session: None,
        account: None,
        connection_nonce: [72; 32],
    }
}

fn origin_row(
    object: &OriginRecord,
    status: OriginRowStatus,
) -> TestResult<(FederationOriginRecord, Vec<u8>)> {
    let bytes = object.to_object()?.encode_canonical()?.as_slice().to_vec();
    Ok((
        FederationOriginRecord {
            origin_object_id: *federation_object_id(&bytes).as_bytes(),
            origin_object: bytes.clone(),
            next_sequence: 6,
            status,
            flags: 0,
        },
        bytes,
    ))
}

#[tokio::test]
async fn an_origin_row_restores_suspended_until_its_edge_resets() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let table = TableId::FederationOrigin;
    let key = origin_key(PEER, INCARNATION, [70; 16], 0)?;
    let origin = OriginKey {
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([70; 16]),
    };
    for (stored, restored, deleted_after) in [
        (OriginRowStatus::Live, OriginStatus::Suspended, None),
        (OriginRowStatus::Suspended, OriginStatus::Suspended, None),
        (OriginRowStatus::Blocked, OriginStatus::Blocked, None),
        (OriginRowStatus::Deleted, OriginStatus::Deleted, Some(6)),
        (OriginRowStatus::Fenced, OriginStatus::Fenced, None),
    ] {
        let mut coordinator = owner();
        let (record, bytes) = origin_row(&origin_object(0), stored)?;
        let row = value(table, ORIGIN_RECORD_KIND, record.encode()?)?;
        assert_eq!(admit(&mut coordinator, context, table, &key, &row), Ok(()));
        let entry = coordinator.origins.origin(&origin).ok_or("origin")?;
        assert_eq!(entry.status, restored);
        assert_eq!(entry.deleted_after, deleted_after);
        assert_eq!(entry.next_sequence, 6);
        assert_eq!(entry.binding.connection_nonce, [72; 32]);
        assert_eq!(coordinator.origin_objects.get(&origin), Some(&bytes));
    }
    Ok(())
}

type OriginDefect = fn(&mut OriginRecord);

#[tokio::test]
async fn an_origin_row_whose_object_disagrees_with_its_key_fails_the_reload() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let table = TableId::FederationOrigin;
    let key = origin_key(PEER, INCARNATION, [70; 16], 0)?;
    let defects: [OriginDefect; 4] = [
        |object| object.network_id = NetworkId::from_bytes([99; 32]),
        |object| object.home_server_id = STRANGER,
        |object| object.server_incarnation = ServerIncarnation::from_bytes([99; 16]),
        |object| object.origin_id = OriginId::from_bytes([99; 16]),
    ];
    for defect in defects {
        let mut coordinator = owner();
        let mut object = origin_object(0);
        defect(&mut object);
        let (record, _) = origin_row(&object, OriginRowStatus::Live)?;
        let row = value(table, ORIGIN_RECORD_KIND, record.encode()?)?;
        assert_eq!(
            admit(&mut coordinator, context, table, &key, &row),
            Err(Violation::Codec)
        );
        assert!(coordinator.origin_objects.is_empty());
    }
    let mut coordinator = owner();
    let (mut record, _) = origin_row(&origin_object(0), OriginRowStatus::Live)?;
    let wrong_generation = origin_key(PEER, INCARNATION, [70; 16], 1)?;
    let row = value(table, ORIGIN_RECORD_KIND, record.encode()?)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &wrong_generation, &row),
        Err(Violation::Codec)
    );
    record.origin_object_id = [0; 32];
    let row = value(table, ORIGIN_RECORD_KIND, record.encode()?)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &key, &row),
        Err(Violation::Codec)
    );
    record.origin_object = vec![0xff; 8];
    let row = value(table, ORIGIN_RECORD_KIND, record.encode()?)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &key, &row),
        Err(Violation::Codec)
    );
    let short_key = StoredKey::new(vec![50; 8])?;
    assert_eq!(
        admit(&mut coordinator, context, table, &short_key, &row),
        Err(Violation::Codec)
    );
    Ok(())
}

#[tokio::test]
async fn a_result_row_is_retained_only_under_a_replay_key() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    let table = TableId::RequestResult;
    let body = CoordinatorResultRecord {
        request_id: [61; 16],
        request_object_id: [62; 32],
        result_object_id: [63; 32],
        result_object: vec![0xff; 8],
        completion_event_id: None,
        resulting_state_generation: 1,
    }
    .encode()?;
    let row = value(table, COORDINATOR_RESULT_KIND, body)?;
    let account_service_key = StoredKey::new(vec![3; 16])?;
    assert_eq!(
        admit(&mut coordinator, context, table, &account_service_key, &row),
        Ok(())
    );
    assert!(coordinator.retained.is_empty(), "another owner's row");
    let replay_key = request_result_key([4; REPLAY_KEY_BYTES])?;
    assert_eq!(
        admit(&mut coordinator, context, table, &replay_key, &row),
        Err(Violation::Codec),
        "the retained result object must decode"
    );
    let retained = coordinator.retained.values().next().ok_or("retained")?;
    assert_eq!(retained.request_object_id, [62; 32]);
    Ok(())
}

fn marker(state: ProjectionGenerationState, token: Option<[u8; 32]>) -> ProjectionMarkerRecord {
    ProjectionMarkerRecord {
        state,
        state_generation: 7,
        entry_count: 0,
        entry_bytes: 0,
        digest: [8; 32],
        snapshot_token: token,
        cut_cursor: None,
        recovery_epoch: [34; 16],
    }
}

#[tokio::test]
async fn only_the_active_marker_of_the_current_generation_restores_a_ready_identity() -> TestResult
{
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let table = TableId::EdgeProjection;
    let active = ProjectionGenerationState::Active;
    let pending = ProjectionGenerationState::Pending;
    for (target, generation, record, restored) in [
        (STRANGER, 1, marker(active, Some([9; 32])), false),
        (PEER, 2, marker(active, Some([9; 32])), false),
        (PEER, 1, marker(pending, Some([9; 32])), false),
        (PEER, 1, marker(active, None), false),
        (PEER, 1, marker(active, Some([9; 32])), true),
    ] {
        let mut coordinator = owner();
        let key = projection_marker_key(target, generation)?;
        let row = value(table, PROJECTION_MARKER_KIND, record.encode()?)?;
        assert_eq!(admit(&mut coordinator, context, table, &key, &row), Ok(()));
        let identity = peer_state(&coordinator)?.ready_identity;
        assert_eq!(identity.is_some(), restored);
        if let Some(identity) = identity {
            assert_eq!(identity.snapshot_token.as_bytes(), &[9; 32]);
            assert_eq!(identity.projection_generation, 1);
            assert_eq!(identity.state_generation, 7);
            assert_eq!(identity.snapshot_digest.as_bytes(), &[8; 32]);
        }
    }
    Ok(())
}

fn outbox_row_for(
    target: ServerId,
    generation: u64,
    sequence: u64,
    cross_profile: bool,
) -> TestResult<PersistentRecordValue> {
    let event = ProjectedEvent::NetworkNotice {
        code: "RELOAD".to_owned(),
        text: "retained".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: target,
        projection_generation: generation,
        coordinator_state_generation: 1,
        delivery_sequence: sequence,
        event_id: EventId::from_bytes([61; 16]),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: cross_profile.then_some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: [81; 16],
            part_index: 0,
            part_count: 2,
        }),
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    value(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        OutboxEventRecord {
            event_id: [61; 16],
            event_object_id: *federation_object_id(&bytes).as_bytes(),
            event_object: bytes,
            coordinator_state_generation: 1,
            acknowledged: false,
            completion_replay_key: None,
        }
        .encode()?,
    )
}

fn outbox_row(sequence: u64, cross_profile: bool) -> TestResult<PersistentRecordValue> {
    outbox_row_for(PEER, 1, sequence, cross_profile)
}

#[tokio::test]
async fn reloaded_outbox_rows_rebuild_the_window_and_fence_it_at_the_ceiling() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    let table = TableId::EdgeOutbox;
    for sequence in [0, 1] {
        let row = outbox_row(sequence, false)?;
        let key = outbox_key(PEER, 1, sequence)?;
        assert_eq!(admit(&mut coordinator, context, table, &key, &row), Ok(()));
    }
    let state = peer_state(&coordinator)?;
    assert_eq!(state.outbox.unacked.len(), 2);
    assert_eq!(state.outbox.reserved_next, 2);
    assert!(state.outbox.snapshot_required, "one object is the ceiling");
    assert!(state.outbox.dirty);
    let row = outbox_row(2, false)?;
    let key = outbox_key(PEER, 1, 2)?;
    assert_eq!(admit(&mut coordinator, context, table, &key, &row), Ok(()));
    let state = peer_state(&coordinator)?;
    assert_eq!(
        state.outbox.unacked.len(),
        2,
        "a fenced window stops growing"
    );
    assert_eq!(state.outbox.reserved_next, 3);
    Ok(())
}

#[tokio::test]
async fn reloaded_outbox_rows_outside_the_window_are_skipped_or_only_reserve() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    let table = TableId::EdgeOutbox;
    let row = outbox_row_for(STRANGER, 1, 4, false)?;
    let foreign = outbox_key(STRANGER, 1, 4)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &foreign, &row),
        Ok(())
    );
    let row = outbox_row_for(PEER, 2, 4, false)?;
    let stale = outbox_key(PEER, 2, 4)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &stale, &row),
        Ok(())
    );
    let misfiled = outbox_key(PEER, 1, 4)?;
    assert_eq!(
        admit(&mut coordinator, context, table, &misfiled, &row),
        Err(Violation::Codec),
        "a row must agree with the key it is stored under"
    );
    assert_eq!(peer_state(&coordinator)?.outbox.reserved_next, 0);
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .outbox
        .cursor = Some((4, EventId::from_bytes([61; 16])));
    let covered_barrier_part = outbox_row(4, true)?;
    let key = outbox_key(PEER, 1, 4)?;
    assert_eq!(
        admit(
            &mut coordinator,
            context,
            table,
            &key,
            &covered_barrier_part
        ),
        Ok(())
    );
    let state = peer_state(&coordinator)?;
    assert!(
        state.outbox.unacked.is_empty(),
        "a covered row is not resent"
    );
    assert_eq!(state.outbox.reserved_next, 5);
    let uncovered = outbox_key(PEER, 1, 5)?;
    assert_eq!(
        admit(
            &mut coordinator,
            context,
            table,
            &uncovered,
            &outbox_row(5, true)?
        ),
        Err(Violation::Codec),
        "an uncovered barrier part cannot reload as ordinary"
    );
    Ok(())
}

#[tokio::test]
async fn object_selection_and_the_final_rebuild_each_run_once() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    assert_eq!(select_objects(&mut coordinator, context), Ok(()));
    assert_eq!(select_objects(&mut coordinator, context), Ok(()));
    assert_eq!(rebuild_once(&mut coordinator, context), Ok(()));
    assert_eq!(rebuild_once(&mut coordinator, context), Ok(()));
    assert!(coordinator.loader.objects_selected && coordinator.loader.rebuilt);
    Ok(())
}

#[tokio::test]
async fn a_second_startup_and_traffic_after_a_failed_reload_are_refused() -> TestResult {
    let mut core = StateCoreFixture::new(vec![1; 256])?;
    let context = core.context_mut()?;
    let mut coordinator = owner();
    begin(&mut coordinator, context);
    assert!(coordinator.loader.blocks_admission());
    let (held, mut held_queue) = crate::federation::link::link_queue(1 << 20);
    let established = |link: u64, handle| crate::federation::FederationInbound {
        link: crate::federation::LinkId::new(link),
        peer: PEER,
        event: crate::federation::LinkEvent::Established {
            session: crate::federation::LinkSession {
                link: crate::federation::LinkId::new(link),
                peer: PEER,
                peer_incarnation: INCARNATION,
                peer_recovery_epoch: RecoveryEpoch::from_bytes([0; 16]),
                transition: agenc_ircd_federation_wire::EpochTransition::Initial,
            },
            handle,
        },
        charge: None,
    };
    coordinator.inbound(context, established(1, held));
    assert_eq!(
        coordinator.backlog.len(),
        1,
        "held until the reload finishes"
    );
    begin(&mut coordinator, context);
    assert!(coordinator.loader.failed);
    assert!(coordinator.backlog.is_empty());
    assert!(peer_state(&coordinator)?.quarantined);
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), held_queue.recv()).await?;
    assert!(closed.is_none(), "the held link was closed");
    let (late, mut late_queue) = crate::federation::link::link_queue(1 << 20);
    coordinator.inbound(context, established(2, late));
    assert!(coordinator.backlog.is_empty());
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), late_queue.recv()).await?;
    assert!(closed.is_none(), "a failed reload admits no link");
    coordinator.continue_restore(context);
    assert!(!coordinator.loaded());
    Ok(())
}
