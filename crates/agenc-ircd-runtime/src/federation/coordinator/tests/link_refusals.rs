#![forbid(unsafe_code)]

//! Link admission, misaddressed frames and the writes a dead link refuses.

use agenc_ircd_federation_wire::{DeliveryCursor, SnapshotIdentity};
use agenc_ircd_types::{EventId, OriginId};

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const STRANGER: ServerId = ServerId::from_bytes([99; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn frame(link: u64, peer: ServerId, frame: FederationFrame) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer,
        event: LinkEvent::Frame(frame),
        charge: None,
    }
}

fn ack_to(coordinator: ServerId) -> FederationFrame {
    FederationFrame::Ack {
        coordinator_server_id: coordinator,
        delivery_sequence: 0,
        event_id: EventId::from_bytes([61; 16]),
    }
}

async fn expect_close(queue: &mut crate::federation::link::LinkQueue) -> TestResult {
    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await
        .map_err(|_| "the link writer received no close request")?;
    assert!(closed.is_none(), "the close request ends the queue");
    Ok(())
}

fn live(coordinator: &FederationCoordinator) -> TestResult<bool> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some())
}

fn misaddressed_frames() -> Vec<FederationFrame> {
    let identity = SnapshotIdentity {
        snapshot_token: FederationHash32::from_bytes([1; 32]),
        recovery_epoch: RecoveryEpoch::from_bytes([34; 16]),
        projection_generation: 1,
        state_generation: 1,
        snapshot_digest: FederationHash32::from_bytes([2; 32]),
    };
    vec![
        ack_to(STRANGER),
        FederationFrame::OriginReset {
            coordinator_server_id: STRANGER,
            server_incarnation: INCARNATION,
        },
        FederationFrame::OriginDel {
            coordinator_server_id: STRANGER,
            server_incarnation: INCARNATION,
            origin_id: OriginId::from_bytes([70; 16]),
            generation: 1,
            next_operation_sequence: 0,
        },
        FederationFrame::Resume {
            coordinator_server_id: STRANGER,
            projection_generation: 1,
            cursor: DeliveryCursor::Empty,
        },
        FederationFrame::SnapshotReady {
            coordinator_server_id: STRANGER,
            identity,
        },
    ]
}

#[tokio::test]
async fn a_frame_addressed_to_another_coordinator_closes_the_link_untouched() -> TestResult {
    for misaddressed in misaddressed_frames() {
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        let context = fixture.context_mut()?;
        let mut coordinator = standalone_coordinator(PEER);
        let (handle, mut queue) = link_queue(1 << 20);
        coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
        coordinator.inbound(context, frame(1, PEER, misaddressed));
        assert_eq!(coordinator.counters().violations, 1);
        assert!(!live(&coordinator)?);
        assert!(coordinator.pending.is_none());
        assert_eq!(context.pending_len(), 0);
        expect_close(&mut queue).await?;
    }
    Ok(())
}

#[tokio::test]
async fn an_edge_only_frame_sent_to_the_coordinator_is_a_phase_violation() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let outcome = coordinator.handle_frame(
        context,
        LinkId::new(1),
        PEER,
        FederationFrame::ResumeSnapshot {
            edge_server_id: PEER,
        },
    );
    assert_eq!(outcome, Err(Violation::Phase));
    coordinator.inbound(
        context,
        frame(
            1,
            PEER,
            FederationFrame::ResumeSnapshot {
                edge_server_id: PEER,
            },
        ),
    );
    assert_eq!(coordinator.counters().violations, 1);
    expect_close(&mut queue).await
}

#[tokio::test]
async fn traffic_from_an_unconfigured_peer_is_dropped_without_a_violation() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(7, STRANGER, INCARNATION, handle));
    coordinator.inbound(context, frame(7, STRANGER, ack_to(COORDINATOR)));
    assert_eq!(coordinator.counters().violations, 0);
    assert!(coordinator.links.is_empty());
    assert!(coordinator.backlog.is_empty());
    assert_eq!(coordinator.federation_stats(), [1, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

#[tokio::test]
async fn a_session_naming_an_unconfigured_peer_installs_no_link() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, _queue) = link_queue(1 << 20);
    // The envelope names a configured peer while the session names another.
    let mut message = established(7, STRANGER, INCARNATION, handle);
    message.peer = PEER;
    coordinator.inbound(context, message);
    assert!(coordinator.links.is_empty());
    assert!(!live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn traffic_on_a_link_that_is_not_the_live_one_is_ignored() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator.inbound(context, frame(2, PEER, ack_to(STRANGER)));
    coordinator.inbound(context, closed(2, PEER));
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    assert_eq!(coordinator.links.get(&LinkId::new(1)), Some(&PEER));
    Ok(())
}

#[tokio::test]
async fn a_second_link_replaces_the_first_in_the_link_table() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (first, _first_queue) = link_queue(1 << 20);
    let (second, _second_queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, first));
    coordinator.inbound(context, established(2, PEER, INCARNATION, second));
    assert_eq!(coordinator.links.len(), 1);
    assert_eq!(coordinator.links.get(&LinkId::new(2)), Some(&PEER));
    let state = coordinator.peers.get(&PEER).ok_or("peer")?;
    assert_eq!(
        state.live.as_ref().map(|live| live.link),
        Some(LinkId::new(2))
    );
    assert_eq!(state.accepted_epochs.len(), 1, "the epoch is recorded once");
    Ok(())
}

type Fence = fn(&mut FederationCoordinator) -> TestResult;

fn fences() -> [Fence; 4] {
    [
        |coordinator| {
            coordinator.peers.get_mut(&PEER).ok_or("peer")?.quarantined = true;
            Ok(())
        },
        |coordinator| {
            coordinator
                .peers
                .get_mut(&PEER)
                .ok_or("peer")?
                .fence_pending = true;
            Ok(())
        },
        |coordinator| {
            coordinator.peers.get_mut(&PEER).ok_or("peer")?.phase = PeerPhase::Expired;
            Ok(())
        },
        |coordinator| {
            coordinator
                .origins
                .restore_fenced_incarnation(PEER, INCARNATION);
            Ok(())
        },
    ]
}

#[tokio::test]
async fn a_fenced_peer_is_refused_a_new_link() -> TestResult {
    for fence in fences() {
        let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
        let context = fixture.context_mut()?;
        let mut coordinator = standalone_coordinator(PEER);
        fence(&mut coordinator)?;
        let (handle, mut queue) = link_queue(1 << 20);
        coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
        assert!(!live(&coordinator)?);
        assert!(coordinator.links.is_empty());
        assert_eq!(coordinator.counters().violations, 0);
        expect_close(&mut queue).await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_full_backlog_retires_the_link_as_a_slow_consumer() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator.pending = Some(PendingCommit::Acknowledged);
    for _ in 0..MAX_BACKLOG {
        coordinator.inbound(context, frame(1, PEER, ack_to(COORDINATOR)));
    }
    assert_eq!(coordinator.backlog.len(), MAX_BACKLOG);
    assert!(live(&coordinator)?);
    coordinator.inbound(context, frame(1, PEER, ack_to(COORDINATOR)));
    assert_eq!(coordinator.backlog.len(), MAX_BACKLOG);
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    expect_close(&mut queue).await
}

#[tokio::test]
async fn a_closed_link_takes_its_backlogged_frames_with_it() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator.pending = Some(PendingCommit::Acknowledged);
    coordinator.inbound(context, frame(1, PEER, ack_to(COORDINATOR)));
    coordinator.inbound(context, frame(2, PEER, ack_to(COORDINATOR)));
    assert_eq!(coordinator.backlog.len(), 2);
    coordinator.inbound(context, closed(1, PEER));
    assert_eq!(coordinator.backlog.len(), 1);
    assert_eq!(
        coordinator.backlog.front().map(|message| message.link),
        Some(LinkId::new(2))
    );
    assert!(!live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn failing_a_link_that_is_not_live_counts_the_violation_and_closes_nothing() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    coordinator.fail_link(context, LinkId::new(9), PEER, Violation::Phase);
    assert_eq!(coordinator.counters().violations, 1);
    assert!(live(&coordinator)?);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), queue.recv())
            .await
            .is_err(),
        "the live link saw no close request"
    );
    Ok(())
}

#[tokio::test]
async fn a_write_for_a_superseded_link_is_not_sent() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let ready = FederationFrame::OriginReady {
        edge_server_id: PEER,
        server_incarnation: INCARNATION,
    };
    assert!(!coordinator.send_frame(context, LinkId::new(1), PEER, &ready));
    let (handle, _queue) = link_queue(1 << 20);
    let observer = handle.clone();
    coordinator.inbound(context, established(2, PEER, INCARNATION, handle));
    assert!(!coordinator.send_frame(context, LinkId::new(1), PEER, &ready));
    let PendingCommit::Request { descriptor, .. } = staged_request(PEER, INCARNATION) else {
        return Err("staged request".into());
    };
    coordinator.send_result(context, LinkId::new(1), PEER, descriptor, &[1, 2, 3]);
    assert_eq!(observer.queued_bytes(), 0);
    assert!(live(&coordinator)?);
    assert!(coordinator.send_frame(context, LinkId::new(2), PEER, &ready));
    assert!(observer.queued_bytes() > 0);
    Ok(())
}

#[tokio::test]
async fn a_frame_that_overflows_the_writer_queue_is_a_slow_consumer() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, mut queue) = link_queue(0);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let ready = FederationFrame::OriginReady {
        edge_server_id: PEER,
        server_incarnation: INCARNATION,
    };
    assert!(!coordinator.send_frame(context, LinkId::new(1), PEER, &ready));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    expect_close(&mut queue).await
}

#[tokio::test]
async fn a_write_to_an_ended_link_task_retires_the_link_without_a_violation() -> TestResult {
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    drop(queue);
    let PendingCommit::Request { descriptor, .. } = staged_request(PEER, INCARNATION) else {
        return Err("staged request".into());
    };
    coordinator.send_result(context, LinkId::new(1), PEER, descriptor, &[1, 2, 3]);
    assert_eq!(coordinator.counters().violations, 0);
    assert!(!live(&coordinator)?);
    assert!(coordinator.links.is_empty());
    Ok(())
}
