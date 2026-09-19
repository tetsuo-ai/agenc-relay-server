//! The router's action loop: bounded queues, nickname leases, the access
//! token, guest policy, and the durable registration commit.
#![forbid(unsafe_code)]

use agenc_ircd_client_wire::encode_account_payload;

use super::test_harness::{Harness, Options, Role, TestResult, saw};
use super::*;

fn token_options(token: [u8; 32]) -> Options {
    Options {
        role: Role::Plain,
        allow_guests: true,
        access_token: Some(token),
        entropy: None,
    }
}

#[tokio::test]
async fn configured_access_token_admits_the_matching_pass() -> TestResult {
    let mut harness = Harness::with(token_options([5; 32]))?;
    assert_eq!(
        harness.router.access_policy(),
        AccessTokenPolicy::RequireConfiguredToken
    );
    let sink = harness.open(1, true)?;
    harness.line(1, &format!("PASS {}", encode_account_payload(&[5; 32])))?;
    harness.line(1, "NICK keyed")?;
    harness.line(1, "USER keyed 0 * :Keyed")?;
    harness.settle().await?;
    assert!(saw(&sink, " 001 keyed "), "lines: {:?}", sink.lines());
    Ok(())
}

#[tokio::test]
async fn configured_access_token_closes_a_client_with_another_pass() -> TestResult {
    let mut harness = Harness::with(token_options([5; 32]))?;
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK keyed")?;
    let outcome = harness.line(1, &format!("PASS {}", encode_account_payload(&[6; 32])))?;
    assert!(
        matches!(outcome, RouteOutcome::Close(CloseReason::ClientQuit)),
        "lines: {:?}",
        sink.lines()
    );
    assert!(saw(&sink, "ERROR"), "lines: {:?}", sink.lines());
    assert!(harness.router.leases.is_empty());
    Ok(())
}

#[tokio::test]
async fn actions_for_a_session_the_table_does_not_hold_close_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let state = harness
        .router
        .connections
        .get_mut(&generation)
        .ok_or("connection")?;
    state.bound = Some(BoundSession {
        session_id: SessionId::from_bytes([1; 16]),
        user_id: UserId::from_bytes([2; 16]),
        capability_hash: [3; 32],
    });
    let outcome = harness.drive(1, Vec::new())?;
    assert!(matches!(
        outcome,
        RouteOutcome::Close(CloseReason::ProtocolError)
    ));
    Ok(())
}

fn pongs(count: usize) -> Vec<RegistrationAction> {
    (0..count)
        .map(|_| RegistrationAction::Pong("token".to_owned()))
        .collect()
}

#[tokio::test]
async fn action_queue_beyond_its_bound_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    let outcome = harness.drive(1, pongs(MAX_PENDING_ACTIONS + 1))?;
    assert!(matches!(
        outcome,
        RouteOutcome::Close(CloseReason::ProtocolError)
    ));
    assert!(sink.lines().is_empty());
    let outcome = harness.drive(1, pongs(MAX_PENDING_ACTIONS))?;
    assert!(matches!(outcome, RouteOutcome::Continue));
    assert_eq!(sink.lines().len(), MAX_PENDING_ACTIONS);
    Ok(())
}

#[tokio::test]
async fn follow_up_actions_beyond_the_queue_bound_close_the_client() -> TestResult {
    let mut harness = Harness::with(token_options([5; 32]))?;
    let _sink = harness.open(1, true)?;
    harness.line(1, "NICK keyed")?;
    let pass = format!("PASS {}", encode_account_payload(&[6; 32]));
    let mut actions = harness.actions(1, &pass)?;
    assert!(matches!(
        actions.first(),
        Some(RegistrationAction::CheckAccessToken { .. })
    ));
    actions.extend(pongs(MAX_PENDING_ACTIONS - 1));
    let outcome = harness.drive(1, actions)?;
    assert!(matches!(
        outcome,
        RouteOutcome::Close(CloseReason::ProtocolError)
    ));
    Ok(())
}

#[tokio::test]
async fn resumed_input_without_its_observation_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK early")?;
    harness.line(1, "USER early 0 * :Early")?;
    let deferred = harness.actions(1, "PING early")?;
    assert!(matches!(
        deferred.first(),
        Some(RegistrationAction::InputDeferred)
    ));
    harness.settle().await?;
    assert!(saw(&sink, " 001 early "), "lines: {:?}", sink.lines());
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn release_for_another_lease_generation_keeps_the_nickname() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    harness.line(1, "NICK keeper")?;
    let held = harness
        .state(1)?
        .lease
        .as_ref()
        .map(|lease| lease.generation)
        .ok_or("lease")?;
    harness.drive(
        1,
        vec![RegistrationAction::ReleaseNickname {
            generation: held.saturating_add(9),
        }],
    )?;
    assert_eq!(harness.router.leases.len(), 1);
    harness.drive(
        1,
        vec![RegistrationAction::ReleaseNickname { generation: held }],
    )?;
    assert!(harness.router.leases.is_empty());
    assert!(harness.state(1)?.lease.is_none());
    Ok(())
}

#[tokio::test]
async fn closing_a_client_never_releases_a_lease_another_connection_owns() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    harness.line(1, "NICK shared")?;
    let nickname = NicknameValue::parse("shared")?;
    let other = ConnectionGeneration::new(2);
    harness.router.leases.insert(nickname.clone(), other);
    let context = harness.fixture.context_mut()?;
    harness.router.connection_closed(
        context,
        ConnectionGeneration::new(1),
        CloseReason::TransportLoss,
    );
    assert_eq!(harness.router.leases.get(&nickname), Some(&other));
    Ok(())
}

#[tokio::test]
async fn nickname_leased_to_another_connection_is_not_reserved_twice() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _first = harness.open(1, true)?;
    let _second = harness.open(2, true)?;
    harness.line(1, "NICK wanted")?;
    harness.line(2, "NICK wanted")?;
    assert!(harness.state(1)?.lease.is_some());
    assert!(harness.state(2)?.lease.is_none());
    assert_eq!(
        harness.router.leases.get(&NicknameValue::parse("wanted")?),
        Some(&ConnectionGeneration::new(1))
    );
    Ok(())
}

#[tokio::test]
async fn nickname_of_a_registered_session_is_not_leased() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _first = harness.register(1, "owner").await?;
    let _second = harness.open(2, true)?;
    harness.line(2, "NICK owner")?;
    assert!(harness.state(2)?.lease.is_none());
    assert!(harness.router.leases.is_empty());
    Ok(())
}

#[tokio::test]
async fn guests_are_refused_when_policy_forbids_them() -> TestResult {
    let mut harness = Harness::with(Options {
        role: Role::Plain,
        allow_guests: false,
        access_token: None,
        entropy: None,
    })?;
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK guest")?;
    let outcome = harness.line(1, "USER guest 0 * :Guest")?;
    println!(
        "outcome close: {}",
        matches!(outcome, RouteOutcome::Close(_))
    );
    println!("lines: {:?}", sink.lines());
    assert!(harness.router.pending_registrations.is_empty());
    assert!(!saw(&sink, " 001 "));
    Ok(())
}

#[tokio::test]
async fn second_commit_for_a_connection_with_a_staged_registration_closes_it() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    harness.line(1, "NICK twice")?;
    let actions = harness.actions(1, "USER twice 0 * :Twice")?;
    harness.router.pending_registrations.insert(
        ConnectionGeneration::new(1),
        PendingRegistration {
            event_generation: 0,
            bound: BoundSession {
                session_id: SessionId::from_bytes([1; 16]),
                user_id: UserId::from_bytes([2; 16]),
                capability_hash: [3; 32],
            },
            nickname: "twice".to_owned(),
            authenticated: false,
        },
    );
    let outcome = harness.drive(1, actions)?;
    assert!(matches!(
        outcome,
        RouteOutcome::Close(CloseReason::ProtocolError)
    ));
    Ok(())
}

#[tokio::test]
async fn registration_committed_after_its_client_left_is_closed_again() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    harness.line(1, "NICK leaver")?;
    harness.line(1, "USER leaver 0 * :Leaver")?;
    let bound = harness
        .router
        .pending_registrations
        .get(&ConnectionGeneration::new(1))
        .map(|pending| pending.bound)
        .ok_or("pending registration")?;
    let context = harness.fixture.context_mut()?;
    harness.router.connection_closed(
        context,
        ConnectionGeneration::new(1),
        CloseReason::TransportLoss,
    );
    harness.settle().await?;
    let context = harness.fixture.context_mut()?;
    assert!(context.domain().session(bound.user_id).is_some());
    assert_eq!(context.pending_len(), 1, "the close is staged");
    assert!(!harness.router.reload_ready());
    harness.router.queue_session_close(context, bound, "again");
    assert_eq!(harness.router.pending_closures.len(), 1);
    harness.settle().await?;
    let context = harness.fixture.context_mut()?;
    assert!(context.domain().session(bound.user_id).is_none());
    assert!(harness.router.pending_closures.is_empty());
    assert!(harness.router.reload_ready());
    Ok(())
}

#[tokio::test]
async fn nickname_claimed_by_a_remote_session_before_the_commit_refuses_the_registration()
-> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK raced")?;
    let home = ServerId::from_bytes([99; 16]);
    let context = harness.fixture.context_mut()?;
    let seed = crate::test_support::remote_session_seed(context, home, "raced")?;
    let opened = context.domain().plan_session_opened(seed)?;
    context
        .stage_durable(opened, FanoutRequest::new(Vec::new(), Vec::new())?, None, 0)
        .map_err(|error| format!("remote session: {error:?}"))?;
    harness.fixture.commit_staged_batch().await?;
    let outcome = harness.line(1, "USER raced 0 * :Raced")?;
    assert!(matches!(
        outcome,
        RouteOutcome::Close(CloseReason::ClientQuit)
    ));
    assert!(
        saw(&sink, "ERROR :Registration rejected"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.router.pending_registrations.is_empty());
    assert!(harness.router.leases.is_empty());
    Ok(())
}
