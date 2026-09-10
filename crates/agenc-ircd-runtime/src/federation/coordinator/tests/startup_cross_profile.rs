//! An uncovered base barrier cannot be reopened as ordinary replay at startup.

#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};
use agenc_ircd_storage::{StoredKey, federation_records::DeliveryCursorRecord};

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const EVENT: [u8; 16] = [61; 16];

fn record(
    table: TableId,
    key: StoredKey,
    kind: u16,
    body: Vec<u8>,
) -> TestResult<InitialStorageRecord> {
    let value = PersistentRecordValue::new(table, kind, 1, 0, None, Vec::new(), body)?;
    Ok(InitialStorageRecord::new(table, key, 1, value.encode()?)?)
}

fn peer(covered: bool, snapshot_required: bool) -> TestResult<InitialStorageRecord> {
    record(
        TableId::FederationPeer,
        peer_key(PEER)?,
        PEER_RECORD_KIND,
        FederationPeerRecord {
            fenced_incarnations: Vec::new(),
            server_incarnation: [51; 16],
            recovery_epoch: [0; 16],
            accepted_epochs: Vec::new(),
            phase: PeerPhase::Ready,
            projection_generation: 0,
            next_delivery_sequence: 1,
            cursor: covered.then_some(DeliveryCursorRecord {
                delivery_sequence: 0,
                event_id: EVENT,
            }),
            active_entry_count: 0,
            active_entry_bytes: 0,
            pending_generation: None,
            snapshot_required,
            cleanup_cursor: None,
            quarantined: false,
            client_resync_epoch: 0,
        }
        .encode()?,
    )
}

fn event() -> TestResult<InitialStorageRecord> {
    let event = ProjectedEvent::NetworkNotice {
        code: "BARRIER".to_owned(),
        text: "retained base part".to_owned(),
    };
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: PEER,
        projection_generation: 0,
        coordinator_state_generation: 1,
        delivery_sequence: 0,
        event_id: agenc_ircd_types::EventId::from_bytes(EVENT),
        event_kind: event.kind(),
        correlation: None,
        cross_profile: Some(agenc_ircd_federation_wire::CrossProfilePart {
            mutation_id: [81; 16],
            part_index: 0,
            part_count: 2,
        }),
    };
    let arm = crate::federation::codec::events::event_arm_object(&event)?;
    let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
    record(
        TableId::EdgeOutbox,
        outbox_key(PEER, 0, 0)?,
        OUTBOX_EVENT_KIND,
        OutboxEventRecord {
            event_id: EVENT,
            event_object_id: *federation_object_id(&bytes).as_bytes(),
            event_object: bytes,
            coordinator_state_generation: 1,
            acknowledged: false,
            completion_replay_key: None,
        }
        .encode()?,
    )
}

async fn boot(covered: bool, snapshot_required: bool) -> TestResult<bool> {
    let mut fixture = StateCoreFixture::with_registration_router_and_records(
        entropy_script(),
        vec![peer(covered, snapshot_required)?, event()?],
    )?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.startup(fixture.context_mut()?);
    for _ in 0..16 {
        if coordinator.loaded()
            || coordinator
                .peers
                .get(&PEER)
                .is_some_and(|state| state.quarantined)
        {
            break;
        }
        let message = fixture.next_storage_read().await?;
        coordinator.storage_read_completed(fixture.context_mut()?, message);
    }
    Ok(coordinator.loaded())
}

#[tokio::test]
async fn an_unacknowledged_base_barrier_refuses_ordinary_restart() -> TestResult {
    assert!(!boot(false, false).await?);
    Ok(())
}

#[tokio::test]
async fn a_snapshot_flag_cannot_replace_an_unacknowledged_base_barrier() -> TestResult {
    assert!(!boot(false, true).await?);
    Ok(())
}

#[tokio::test]
async fn a_base_cursor_covering_the_retained_part_still_restarts() -> TestResult {
    assert!(boot(true, false).await?);
    Ok(())
}
