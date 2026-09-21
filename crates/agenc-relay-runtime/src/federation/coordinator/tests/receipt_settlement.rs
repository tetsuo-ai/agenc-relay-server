#![forbid(unsafe_code)]

//! What a committed or refused batch publishes, and the operator quarantine that rides one.

use agenc_relay_domain::federation::{OriginBinding, OriginEntry, OriginPrincipal, OriginStatus};
use agenc_relay_types::OriginId;

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([99; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn live(coordinator: &FederationCoordinator) -> TestResult<bool> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some())
}

fn linked(
    context: &mut StateCoreContext,
) -> (FederationCoordinator, crate::federation::link::LinkQueue) {
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    (coordinator, queue)
}

/// Declares the origin `staged_request` names, expecting its sequence next.
fn declare_staged_origin(coordinator: &mut FederationCoordinator) -> OriginKey {
    let key = OriginKey {
        home_server_id: PEER,
        server_incarnation: INCARNATION,
        origin_id: OriginId::from_bytes([77; 16]),
    };
    coordinator.origins.restore_origin(
        key,
        OriginEntry {
            generation: 1,
            next_sequence: 3,
            object_id: [1; 32],
            binding: OriginBinding {
                connection_id: agenc_relay_types::ConnectionId::from_bytes([2; 16]),
                connection_nonce: [3; 32],
            },
            principal: OriginPrincipal::UNREGISTERED,
            status: OriginStatus::Live,
            deleted_after: None,
        },
    );
    key
}

#[tokio::test]
async fn a_committed_request_for_an_undeclared_origin_fails_its_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    let staged = staged_request(PEER, INCARNATION);
    assert!(!coordinator.apply_pending_receipt(context, Some(staged), &[]));
    assert_eq!(coordinator.counters().violations, 1);
    assert_eq!(coordinator.counters().requests_committed, 0);
    assert!(coordinator.retained.is_empty());
    assert!(!live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn a_committed_request_whose_result_does_not_decode_fails_its_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    let key = declare_staged_origin(&mut coordinator);
    let staged = staged_request(PEER, INCARNATION);
    assert!(!coordinator.apply_pending_receipt(context, Some(staged), &[]));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    // The sequence was durably consumed before the result was inspected.
    assert_eq!(
        coordinator
            .origins
            .origin(&key)
            .map(|entry| entry.next_sequence),
        Some(4)
    );
    assert_eq!(coordinator.retained.len(), 1);
    assert_eq!(coordinator.counters().requests_committed, 1);
    Ok(())
}

#[tokio::test]
async fn a_receipt_of_another_kind_settles_no_request_or_acknowledgement() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    assert!(!coordinator.settle_request(context, PendingCommit::Acknowledged));
    coordinator.delivery_ack_receipt(context, PendingCommit::Acknowledged);
    coordinator.reject_request_batch(context, PendingCommit::Acknowledged);
    coordinator.companion_receipt(context, PendingCommit::Acknowledged, &[]);
    assert_eq!(coordinator.counters(), CoordinatorCounters::default());
    assert!(live(&coordinator)?);
    assert!(coordinator.retained.is_empty());
    Ok(())
}

#[tokio::test]
async fn receipts_naming_an_unconfigured_peer_change_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
    state.phase = PeerPhase::Expired;
    state.outbox.dirty = true;
    for pending in [
        PendingCommit::CleanupFinished { peer: STRANGER },
        PendingCommit::OutboxRequired { peer: STRANGER },
    ] {
        assert!(coordinator.apply_pending_receipt(context, Some(pending), &[]));
    }
    coordinator.acknowledgement_committed(
        context,
        STRANGER,
        0,
        agenc_relay_types::EventId::from_bytes([61; 16]),
        None,
    );
    coordinator.sync_outbox_budget(context, STRANGER);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(state.phase, PeerPhase::Expired);
    assert!(state.outbox.dirty);
    assert_eq!(state.outbox.cursor, None);
    Ok(())
}

#[tokio::test]
async fn a_finished_cleanup_returns_the_peer_to_clean() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
    state.phase = PeerPhase::Expired;
    state.cleanup_cursor = Some([9; 16]);
    let receipt = PendingCommit::CleanupFinished { peer: PEER };
    assert!(coordinator.apply_pending_receipt(context, Some(receipt), &[]));
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(state.phase, PeerPhase::Clean);
    assert_eq!(state.cleanup_cursor, None);
    Ok(())
}

#[tokio::test]
async fn origin_ready_is_published_only_for_a_known_incarnation() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, mut queue) = linked(context);
    coordinator.publish_origin_ready(context, PEER, LinkId::new(1));
    let quiet = tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv()).await;
    assert!(quiet.is_err(), "no incarnation was ever accepted");
    coordinator.peers.get_mut(&PEER).ok_or("peer")?.incarnation = Some(INCARNATION);
    coordinator.publish_origin_ready(context, PEER, LinkId::new(1));
    let line = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await?
        .ok_or("ready line")?;
    let expected = FederationFrame::OriginReady {
        edge_server_id: PEER,
        server_incarnation: INCARNATION,
    }
    .render(COORDINATOR_NAME)?;
    assert_eq!(line.as_str(), expected.as_str());
    Ok(())
}

#[tokio::test]
async fn a_refused_origin_batch_for_a_superseded_link_spares_the_new_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    coordinator.pending = Some(PendingCommit::OriginReady {
        peer: PEER,
        link: LinkId::new(9),
    });
    coordinator.batch_rejected(context);
    assert!(coordinator.pending.is_none());
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn a_refused_companion_batch_without_an_executor_is_dropped() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    coordinator.pending = Some(PendingCommit::Companion {
        peer: PEER,
        link: LinkId::new(1),
        resume: false,
        barrier: None,
    });
    coordinator.batch_rejected(context);
    assert!(coordinator.pending.is_none());
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn a_refused_acknowledgement_batch_without_a_link_keeps_the_window() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let event_id = agenc_relay_types::EventId::from_bytes([61; 16]);
    let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
    state.outbox.unacked.push_back((0, event_id, 128));
    coordinator.pending = Some(PendingCommit::DeliveryAcknowledged {
        resume: None,
        peer: PEER,
        delivery_sequence: 0,
        event_id,
        barrier: None,
    });
    coordinator.batch_rejected(context);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(state.outbox.unacked.len(), 1);
    assert_eq!(state.outbox.cursor, None);
    assert_eq!(coordinator.counters().violations, 0);
    Ok(())
}

#[tokio::test]
async fn quarantine_names_its_refusal_exactly() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, _queue) = linked(context);
    assert!(matches!(
        coordinator.admin_quarantine_peer(context, STRANGER),
        Err(PeerQuarantineRefusal::UnknownPeer)
    ));
    coordinator.pending = Some(PendingCommit::Acknowledged);
    assert!(matches!(
        coordinator.admin_quarantine_peer(context, PEER),
        Err(PeerQuarantineRefusal::Busy)
    ));
    assert!(live(&coordinator)?, "a busy refusal fences nothing");
    assert_eq!(coordinator.federation_stats(), [1, 0, 0, 0, 0, 0, 0]);
    coordinator.pending = None;
    assert!(coordinator.admin_quarantine_peer(context, PEER).is_ok());
    assert!(matches!(
        coordinator.admin_quarantine_peer(context, PEER),
        Err(PeerQuarantineRefusal::AlreadyQuarantined)
    ));
    Ok(())
}

#[tokio::test]
async fn quarantining_an_unlinked_peer_records_the_fence_durably() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let mut coordinator = standalone_coordinator(PEER);
    assert!(
        coordinator
            .admin_quarantine_peer(fixture.context_mut()?, PEER)
            .is_ok()
    );
    assert_eq!(coordinator.counters().violations, 0);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Acknowledged)
    ));
    let record = coordinator.peer_record_at(PEER, None)?;
    assert!(record.quarantined);
    fixture.commit_staged_batch().await?;
    coordinator.batch_applied(fixture.context_mut()?);
    assert!(coordinator.pending.is_none());
    assert!(fixture.stored_row_exists(TableId::FederationPeer, peer_key(PEER)?)?);
    assert_eq!(coordinator.federation_stats(), [1, 0, 1, 0, 0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn quarantining_a_linked_peer_closes_its_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (mut coordinator, mut queue) = linked(context);
    assert!(coordinator.admin_quarantine_peer(context, PEER).is_ok());
    assert!(!live(&coordinator)?);
    assert_eq!(coordinator.counters().violations, 1);
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv()).await?;
    assert!(closed.is_none());
    Ok(())
}
