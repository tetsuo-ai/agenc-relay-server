#![forbid(unsafe_code)]

//! Companion profile negotiation as the coordinator's link owner sees it.

use crate::e2ee::coordinator::CompanionFault;
use crate::e2ee::link::CompanionViolation;

use super::*;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

fn companion(link: u64, frame: CompanionFrame) -> FederationInbound {
    FederationInbound {
        link: LinkId::new(link),
        peer: PEER,
        event: LinkEvent::Companion(frame),
        charge: None,
    }
}

fn live(coordinator: &FederationCoordinator) -> TestResult<bool> {
    Ok(coordinator.peers.get(&PEER).ok_or("peer")?.live.is_some())
}

async fn next_line(queue: &mut crate::federation::link::LinkQueue) -> TestResult<Option<String>> {
    let line = tokio::time::timeout(std::time::Duration::from_secs(5), queue.recv())
        .await
        .map_err(|_| "the link writer received nothing")?;
    Ok(line.map(|line| line.as_str().to_owned()))
}

fn profiled() -> TestResult<(FederationCoordinator, CompanionProfile)> {
    let setup = companion_setup()?;
    let mut coordinator = standalone_coordinator(PEER);
    coordinator.set_companion_profile(Some(CompanionProfile {
        local: setup.profile.local.clone(),
    }));
    Ok((coordinator, setup.profile))
}

#[tokio::test]
async fn a_companion_frame_without_a_profile_is_answered_with_the_violation_line() -> TestResult {
    let setup = companion_setup()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let mut coordinator = standalone_coordinator(PEER);
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let expected = coordinator
        .companion
        .violation_line()
        .map_err(|violation| format!("{violation:?}"))?;
    coordinator.inbound(
        context,
        companion(1, CompanionFrame::EcapOffer(setup.profile.local)),
    );
    assert_eq!(
        next_line(&mut queue).await?.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(next_line(&mut queue).await?, None, "then the link closes");
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    assert!(!coordinator.companion_active(PEER));
    Ok(())
}

#[tokio::test]
async fn a_new_link_is_offered_the_profile_and_given_a_deadline() -> TestResult {
    let (mut coordinator, _profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let offer = next_line(&mut queue).await?.ok_or("offer")?;
    assert!(offer.contains("ECAP IRCMLS OFFER"), "{offer}");
    let deadline = coordinator
        .companion
        .deadline(LinkId::new(1))
        .map(MonotonicTick::from_ticks)
        .ok_or("deadline")?;
    assert!(deadline > context.now());
    assert!(!coordinator.companion_active(PEER));
    let entry = context.timers_mut().pop_due(deadline).ok_or("timer")?;
    assert_eq!(entry.kind, TimerKind::CompanionProfileDeadline);
    assert_eq!(entry.id, TimedId::Peer(PEER));
    assert_eq!(entry.deadline, deadline);
    Ok(())
}

#[tokio::test]
async fn an_unanswered_offer_fails_the_link_at_its_deadline() -> TestResult {
    let (mut coordinator, _profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let deadline = coordinator
        .companion
        .deadline(LinkId::new(1))
        .map(MonotonicTick::from_ticks)
        .ok_or("deadline")?;
    let entry = context.timers_mut().pop_due(deadline).ok_or("timer")?;
    assert!(coordinator.timer_fired(context, entry));
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    assert_eq!(coordinator.companion.deadline(LinkId::new(1)), None);
    // The same timer for a peer whose link is already gone is consumed quietly.
    assert!(coordinator.timer_fired(context, entry));
    assert_eq!(coordinator.counters().violations, 1);
    Ok(())
}

#[tokio::test]
async fn a_deadline_that_has_not_passed_leaves_the_link_negotiating() -> TestResult {
    let (mut coordinator, _profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let deadline = coordinator
        .companion
        .deadline(LinkId::new(1))
        .map(MonotonicTick::from_ticks)
        .ok_or("deadline")?;
    let mut entry = context.timers_mut().pop_due(deadline).ok_or("timer")?;
    entry.deadline = context.now();
    assert!(coordinator.timer_fired(context, entry));
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    Ok(())
}

#[tokio::test]
async fn a_matching_offer_is_acknowledged_on_the_same_link() -> TestResult {
    let (mut coordinator, profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, mut queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let _offer = next_line(&mut queue).await?.ok_or("offer")?;
    coordinator.inbound(
        context,
        companion(1, CompanionFrame::EcapOffer(profile.local)),
    );
    let ack = next_line(&mut queue).await?.ok_or("ack")?;
    assert!(ack.contains("ECAP IRCMLS ACK"), "{ack}");
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?);
    assert!(coordinator.drain_companion(PEER).is_empty());
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_the_writer_cannot_queue_is_a_slow_consumer() -> TestResult {
    let (mut coordinator, profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, mut queue) = link_queue(0);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    assert!(live(&coordinator)?, "a dropped offer alone is not fatal");
    coordinator.inbound(
        context,
        companion(1, CompanionFrame::EcapOffer(profile.local)),
    );
    assert_eq!(coordinator.counters().violations, 1);
    assert!(!live(&coordinator)?);
    assert_eq!(next_line(&mut queue).await?, None);
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_to_an_ended_link_task_is_not_a_violation() -> TestResult {
    let (mut coordinator, profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    drop(queue);
    coordinator.inbound(
        context,
        companion(1, CompanionFrame::EcapOffer(profile.local)),
    );
    assert_eq!(coordinator.counters().violations, 0);
    assert!(live(&coordinator)?, "the Closed event retires the link");
    Ok(())
}

#[tokio::test]
async fn companion_work_for_a_link_that_is_not_live_is_dropped() -> TestResult {
    let (mut coordinator, profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let outcome = coordinator.handle_companion(
        context,
        LinkId::new(4),
        PEER,
        CompanionFrame::EcapOffer(profile.local),
    );
    assert_eq!(outcome, Ok(()));
    coordinator.start_companion(context, LinkId::new(4), PEER);
    assert!(
        context.timers_mut().is_empty(),
        "no deadline is armed for a link that does not exist"
    );
    assert!(!coordinator.companion_active(PEER));
    assert!(coordinator.drain_companion(PEER).is_empty());
    Ok(())
}

#[tokio::test]
async fn an_executor_for_another_network_or_server_is_refused() -> TestResult {
    let incarnation = ServerIncarnation::from_bytes([33; 16]);
    let mut foreign_network = companion_setup()?.executor;
    foreign_network.network_id = [99; 32];
    let mut coordinator = standalone_coordinator(PEER);
    assert_eq!(
        coordinator.install_companion_executor(foreign_network, incarnation),
        Err(CompanionFault::Protocol)
    );
    let mut foreign_server = companion_setup()?.executor;
    foreign_server.server_id = ServerId::from_bytes([99; 16]);
    assert_eq!(
        coordinator.install_companion_executor(foreign_server, incarnation),
        Err(CompanionFault::Protocol)
    );
    assert!(coordinator.companion_executor().is_none());
    coordinator
        .install_companion_executor(companion_setup()?.executor, incarnation)
        .map_err(|fault| format!("{fault:?}"))?;
    assert!(coordinator.companion_executor().is_some());
    Ok(())
}

#[tokio::test]
async fn a_companion_request_before_the_profile_is_active_is_a_profile_violation() -> TestResult {
    let (mut coordinator, _profile) = profiled()?;
    let mut fixture = StateCoreFixture::with_registration_router(entropy_script())?;
    let context = fixture.context_mut()?;
    let (handle, _queue) = link_queue(1 << 20);
    coordinator.inbound(context, established(1, PEER, INCARNATION, handle));
    let outcome = coordinator.handle_companion(
        context,
        LinkId::new(1),
        PEER,
        CompanionFrame::OriginReset {
            coordinator_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
        },
    );
    assert!(matches!(
        outcome,
        Err(Violation::Companion(CompanionViolation::Profile(_)))
    ));
    Ok(())
}
