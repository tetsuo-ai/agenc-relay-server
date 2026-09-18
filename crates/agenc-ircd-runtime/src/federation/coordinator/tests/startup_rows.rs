#![forbid(unsafe_code)]

//! Startup admits an origin or marker row only when it agrees with its own key and this network.

use agenc_ircd_domain::federation::OriginKey;
use agenc_ircd_federation_wire::{CanonicalEncode, OriginRecord, federation_object_id};
use agenc_ircd_storage::federation_records::{
    FederationOriginRecord, ORIGIN_RECORD_KIND, OriginRowStatus, PROJECTION_MARKER_KIND,
    ProjectionGenerationState, ProjectionMarkerRecord, origin_key, projection_marker_key,
};
use agenc_ircd_types::{ConnectionId, OriginId};

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);
const ORIGIN: OriginId = OriginId::from_bytes([71; 16]);

type OriginEdit = fn(&mut OriginRecord, &mut FederationOriginRecord);

fn sealed(
    table: TableId,
    kind: u16,
    key: agenc_ircd_storage::StoredKey,
    generation: u64,
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let value =
        PersistentRecordValue::new(table, kind, 1, generation, None, Vec::new(), body)?.encode()?;
    Ok(InitialStorageRecord::new(table, key, 1, value)?)
}

/// An origin row stored under the honest key, its object edited before sealing.
fn origin_row(edit: OriginEdit) -> TestResult<InitialStorageRecord> {
    let mut object = OriginRecord {
        network_id: NETWORK,
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        generation: 0,
        previous_origin_object_id: [0; 32],
        connection_id: ConnectionId::from_bytes([72; 16]),
        session: None,
        account: None,
        connection_nonce: [74; 32],
    };
    let mut row = FederationOriginRecord {
        origin_object_id: [0; 32],
        origin_object: Vec::new(),
        next_sequence: 1,
        status: OriginRowStatus::Live,
        flags: 0,
    };
    edit(&mut object, &mut row);
    let honest_hash = row.origin_object_id == [0; 32];
    row.origin_object = object.to_object()?.encode_canonical()?.as_slice().to_vec();
    if honest_hash {
        row.origin_object_id = *federation_object_id(&row.origin_object).as_bytes();
    }
    sealed(
        TableId::FederationOrigin,
        ORIGIN_RECORD_KIND,
        origin_key(PEER, INCARNATION, *ORIGIN.as_bytes(), 0)?,
        0,
        row.encode()?,
    )
}

/// Runs the startup reload to its end: loaded, or fenced with the peer quarantined.
async fn boot(
    rows: Vec<InitialStorageRecord>,
) -> TestResult<(StateCoreFixture, FederationCoordinator)> {
    let mut fixture =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), rows)?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..32 {
        let fenced = coordinator
            .peers
            .get(&PEER)
            .is_some_and(|state| state.quarantined);
        if coordinator.loaded() || fenced {
            break;
        }
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    Ok((fixture, coordinator))
}

fn restored_origin(coordinator: &FederationCoordinator) -> bool {
    coordinator
        .origins
        .origin(&OriginKey {
            home_server_id: PEER,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
        })
        .is_some()
}

#[tokio::test]
async fn an_origin_row_that_disagrees_with_its_key_fences_startup() -> TestResult {
    let edits: [OriginEdit; 6] = [
        |object, _| object.network_id = NetworkId::from_bytes([99; 32]),
        |object, _| object.home_server_id = ServerId::from_bytes([99; 16]),
        |object, _| object.server_incarnation = ServerIncarnation::from_bytes([99; 16]),
        |object, _| object.origin_id = OriginId::from_bytes([99; 16]),
        |object, _| {
            object.generation = 3;
            object.previous_origin_object_id = [1; 32];
        },
        |_, row| row.origin_object_id = [99; 32],
    ];
    for edit in edits {
        let (_fixture, coordinator) = boot(vec![origin_row(edit)?]).await?;
        assert!(!coordinator.loaded());
        assert!(!restored_origin(&coordinator));
        assert!(
            coordinator
                .peers
                .get(&PEER)
                .is_some_and(|state| state.quarantined && state.live.is_none())
        );
    }
    let (_fixture, coordinator) = boot(vec![origin_row(|_, _| {})?]).await?;
    assert!(coordinator.loaded());
    assert!(restored_origin(&coordinator));
    Ok(())
}

fn marker_row(
    generation: u64,
    state: ProjectionGenerationState,
    token: Option<[u8; 32]>,
) -> TestResult<InitialStorageRecord> {
    let body = ProjectionMarkerRecord {
        state,
        state_generation: 4,
        entry_count: 0,
        entry_bytes: 0,
        digest: [5; 32],
        snapshot_token: token,
        cut_cursor: None,
        recovery_epoch: [34; 16],
    }
    .encode()?;
    sealed(
        TableId::EdgeProjection,
        PROJECTION_MARKER_KIND,
        projection_marker_key(PEER, generation)?,
        generation,
        body,
    )
}

/// The peer checkpoint of an edge whose active projection is generation one.
fn peer_row() -> TestResult<InitialStorageRecord> {
    let body = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *INCARNATION.as_bytes(),
        recovery_epoch: [0; 16],
        accepted_epochs: Vec::new(),
        phase: PeerPhase::Suspended,
        projection_generation: 1,
        next_delivery_sequence: 0,
        cursor: None,
        active_entry_count: 0,
        active_entry_bytes: 0,
        pending_generation: None,
        snapshot_required: false,
        cleanup_cursor: None,
        quarantined: false,
        client_resync_epoch: 0,
    }
    .encode()?;
    sealed(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        peer_key(PEER)?,
        0,
        body,
    )
}

#[tokio::test]
async fn only_the_active_marker_of_the_current_generation_restores_a_ready_identity() -> TestResult
{
    let ignored = [
        marker_row(7, ProjectionGenerationState::Active, Some([6; 32]))?,
        marker_row(1, ProjectionGenerationState::Pending, Some([6; 32]))?,
        marker_row(1, ProjectionGenerationState::Active, None)?,
    ];
    for row in ignored {
        let (_fixture, coordinator) = boot(vec![peer_row()?, row]).await?;
        assert!(coordinator.loaded());
        let state = coordinator.peers.get(&PEER).ok_or("peer")?;
        assert_eq!(state.ready_identity, None);
        assert!(!state.quarantined);
    }
    let row = marker_row(1, ProjectionGenerationState::Active, Some([6; 32]))?;
    let (_fixture, coordinator) = boot(vec![peer_row()?, row]).await?;
    assert!(coordinator.loaded());
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    let identity = state.ready_identity.ok_or("ready identity")?;
    assert_eq!(identity.projection_generation, 1);
    assert_eq!(identity.state_generation, 4);
    Ok(())
}
