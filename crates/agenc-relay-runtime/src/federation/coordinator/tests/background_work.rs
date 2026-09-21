#![forbid(unsafe_code)]

//! Background work takes the free batch slot one obligation at a time, in a fixed order.

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn dirty(coordinator: &mut FederationCoordinator) -> TestResult {
    coordinator.peers.get_mut(&PEER).ok_or("peer")?.outbox.dirty = true;
    Ok(())
}

#[tokio::test]
async fn an_authority_fence_is_staged_before_any_other_background_row() -> TestResult {
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    dirty(&mut coordinator)?;
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .fence_pending = true;
    coordinator.continue_background(context);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::AuthorityFence {
            peer: PEER,
            generation: 2,
            ..
        })
    ));
    assert_eq!(context.pending_len(), 1);
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert!(state.outbox.dirty, "the outbox row waits for the next slot");
    Ok(())
}

#[tokio::test]
async fn a_settled_origin_reset_is_answered_before_delivery_work() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator.origins.reset(PEER, INCARNATION);
    coordinator.continue_background(context);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::OriginReady { peer: PEER, link }) if link == LinkId::new(1)
    ));
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[tokio::test]
async fn background_work_is_idle_when_no_peer_owes_a_row() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.continue_background(context);
    assert!(coordinator.pending.is_none());
    assert_eq!(context.pending_len(), 0);
    assert!(coordinator.reload_ready());
    coordinator.pending = Some(PendingCommit::Acknowledged);
    assert!(!coordinator.reload_ready());
    coordinator.continue_background(context);
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::Acknowledged)
    ));
    Ok(())
}

#[tokio::test]
async fn authority_fences_and_cleanup_wait_behind_a_staged_batch() -> TestResult {
    use crate::federation::coordinator::authority;
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .fence_pending = true;
    coordinator.continue_background(context);
    assert_eq!(context.pending_len(), 1);
    authority::continue_fence(&mut coordinator, context, PEER);
    authority::continue_clean(&mut coordinator, context, PEER);
    assert_eq!(
        context.pending_len(),
        1,
        "nothing is staged over the open batch"
    );
    assert!(matches!(
        coordinator.pending,
        Some(PendingCommit::AuthorityFence { peer: PEER, .. })
    ));
    Ok(())
}

#[tokio::test]
async fn cleanup_waits_for_an_expired_peer_with_no_fence_or_cleanup_pending() -> TestResult {
    use crate::federation::coordinator::authority;
    use agenc_relay_storage::federation_records::PeerPhase;
    let mut fixture = StateCoreFixture::with_federation_coordinator(
        entropy_script(),
        vec![peer_identity(PEER, "edge.example")],
    )?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    {
        let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        state.phase = PeerPhase::Expired;
        state.fence_pending = true;
    }
    authority::continue_clean(&mut coordinator, context, PEER);
    assert_eq!(context.pending_len(), 0, "a pending fence precedes cleanup");
    {
        let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        state.fence_pending = false;
        state.cleanup.push_back(UserId::from_bytes([7; 16]));
    }
    authority::continue_clean(&mut coordinator, context, PEER);
    assert_eq!(
        context.pending_len(),
        0,
        "queued session cleanup precedes the terminal row"
    );
    coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .cleanup
        .clear();
    authority::continue_clean(&mut coordinator, context, PEER);
    assert_eq!(
        context.pending_len(),
        1,
        "the empty cleanup reaches its durable terminal state"
    );
    Ok(())
}
