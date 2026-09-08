//! Actual edge-batch FACKs retain ordinary coordinator receipt ordering.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};
use agenc_ircd_types::EventId;

const PEER: ServerId = ServerId::from_bytes([36; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn event_record(bytes: Vec<u8>) -> TestResult<InitialStorageRecord> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let event = SchemaObject::decode_exact("FederationEvent", &bytes, &mut budget)?;
    let header = EventHeader::from_object(&event)?;
    assert_eq!(header.network_id, NETWORK);
    assert_eq!(header.target_server_id, PEER);
    assert_eq!(header.projection_generation, 1);
    assert!(header.cross_profile.is_none());
    let body = OutboxEventRecord {
        event_id: *header.event_id.as_bytes(),
        event_object_id: *federation_object_id(&bytes).as_bytes(),
        event_object: bytes,
        coordinator_state_generation: header.coordinator_state_generation,
        acknowledged: false,
        completion_replay_key: None,
    }
    .encode()?;
    let value = PersistentRecordValue::new(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::EdgeOutbox,
        outbox_key(PEER, 1, header.delivery_sequence)?,
        1,
        value,
    )?)
}

fn receiver_peer_record() -> TestResult<InitialStorageRecord> {
    let body = FederationPeerRecord {
        fenced_incarnations: Vec::new(),
        server_incarnation: *INCARNATION.as_bytes(),
        recovery_epoch: [0; 16],
        accepted_epochs: Vec::new(),
        phase: PeerPhase::Ready,
        projection_generation: 1,
        next_delivery_sequence: 3,
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
    let value = PersistentRecordValue::new(
        TableId::FederationPeer,
        PEER_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    )?
    .encode()?;
    Ok(InitialStorageRecord::new(
        TableId::FederationPeer,
        peer_key(PEER)?,
        1,
        value,
    )?)
}

async fn receiver(objects: Vec<Vec<u8>>) -> TestResult<(StateCoreFixture, FederationCoordinator)> {
    let mut records = vec![receiver_peer_record()?];
    for bytes in objects {
        records.push(event_record(bytes)?);
    }
    let mut core =
        StateCoreFixture::with_registration_router_and_records(entropy_script(), records)?;
    core.context_mut()?.install_federation_projector(
        crate::state_core::projector::FederationProjector::new(NETWORK, COORDINATOR),
    );
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.startup(core.context_mut()?);
    for _ in 0..64 {
        if coordinator.loaded() {
            return Ok((core, coordinator));
        }
        let completion =
            tokio::time::timeout(std::time::Duration::from_secs(5), core.next_storage_read())
                .await??;
        coordinator.storage_read_completed(core.context_mut()?, completion);
    }
    Err("bounded ACK receiver startup did not complete".into())
}

fn acknowledgement(frame: &FederationFrame) -> TestResult<(u64, EventId)> {
    let FederationFrame::Ack {
        coordinator_server_id,
        delivery_sequence,
        event_id,
    } = frame
    else {
        return Err("edge emitted a non-ACK frame".into());
    };
    assert_eq!(*coordinator_server_id, COORDINATOR);
    Ok((*delivery_sequence, *event_id))
}

fn assert_retained(core: &StateCoreFixture, first: u64) -> TestResult {
    for sequence in 0..3 {
        assert_eq!(
            core.stored_row_exists(TableId::EdgeOutbox, outbox_key(PEER, 1, sequence)?)?,
            sequence >= first,
            "only a committed ordinary ACK can retire its exact row",
        );
    }
    Ok(())
}

async fn commit_ordered_acknowledgements(
    core: &mut StateCoreFixture,
    coordinator: &mut FederationCoordinator,
    head: u64,
    expected: Vec<(u64, EventId)>,
) -> TestResult {
    for (index, identity) in expected.into_iter().enumerate() {
        assert!(
            matches!(coordinator.pending, Some(PendingCommit::DeliveryAcknowledged {
            peer: PEER, delivery_sequence, event_id, barrier: None, resume: None,
        }) if (delivery_sequence, event_id) == identity)
        );
        assert_eq!(core.context_mut()?.pending_len(), 1);
        core.commit_staged_batch().await?;
        let committed = u64::try_from(index)?.checked_add(1).ok_or("commit count")?;
        assert_eq!(
            core.context_mut()?.head().storage_commit_sequence,
            head.checked_add(committed).ok_or("commit sequence")?
        );
        assert_retained(core, committed)?;
        coordinator.batch_applied(core.context_mut()?);
        assert_eq!(
            coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
            Some(identity)
        );
        assert_eq!(coordinator.backlog.len(), 1_usize.saturating_sub(index));
    }
    Ok(())
}

#[tokio::test]
async fn actual_batched_edge_acks_wait_for_each_coordinator_receipt() -> TestResult {
    let (objects, frames) =
        Box::pin(crate::federation::edge::committed_ordinary_acknowledgements()).await?;
    assert_eq!(objects.len(), 3);
    assert_eq!(frames.len(), 3);
    let expected = frames
        .iter()
        .map(acknowledgement)
        .collect::<TestResult<Vec<_>>>()?;
    let (mut core, mut coordinator) = Box::pin(receiver(objects)).await?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(
        core.context_mut()?,
        established(1, PEER, INCARNATION, handle),
    );
    let head = core.context_mut()?.head().storage_commit_sequence;
    for (index, frame) in frames.into_iter().enumerate() {
        assert_eq!(
            expected.get(index).ok_or("ACK identity")?.0,
            u64::try_from(index)?
        );
        coordinator.inbound(
            core.context_mut()?,
            FederationInbound {
                link: LinkId::new(1),
                peer: PEER,
                event: LinkEvent::Frame(frame),
                charge: None,
            },
        );
    }
    assert_eq!(coordinator.backlog.len(), 2);
    assert_eq!(
        coordinator.peers.get(&PEER).ok_or("peer")?.outbox.cursor,
        None
    );
    assert_retained(&core, 0)?;
    commit_ordered_acknowledgements(&mut core, &mut coordinator, head, expected).await?;
    assert!(coordinator.pending.is_none());
    assert!(coordinator.backlog.is_empty());
    assert_eq!(coordinator.counters.violations, 0);
    assert!(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some());
    Ok(())
}
