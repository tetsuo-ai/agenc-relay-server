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
