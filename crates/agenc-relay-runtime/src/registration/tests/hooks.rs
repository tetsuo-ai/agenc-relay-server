//! The router's state-core hooks outside the client line path: connection
//! admission, timers nobody owns, rejected batches, and role-dependent calls.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Options, Role, TestResult, executor, saw};
use super::*;
use crate::state_core::inbox::MaintenanceEvent;

const ALL_ROLES: [Role; 5] = [
    Role::Plain,
    Role::Hosted,
    Role::Edge,
    Role::Coordinator,
    Role::E2eeEdge,
];

fn hosted_config(
    harness: &Harness,
    network_id: NetworkId,
    server_id: ServerId,
) -> TestResult<RegistrationRouterConfig> {
    let fixture = &harness.fixture;
    Ok(RegistrationRouterConfig {
        network_id,
        server_id,
        server_prefix: "server.example".to_owned(),
        display_name: "TestNetwork".to_owned(),
        allow_guests: true,
        access_token: None,
        account_service: AccountServiceRole::Hosted(Box::new(
            crate::test_support::account_service_config(
                &fixture.identity,
                &fixture.opaque,
                fixture.key_state,
            )?,
        )),
    })
}

#[tokio::test]
async fn hosted_account_service_of_another_network_or_server_is_refused() -> TestResult {
    let harness = Harness::new(Role::Plain)?;
    let network_id = harness.fixture.identity.network_id;
    let server_id = harness.fixture.identity.server_id;
    let other_network = hosted_config(&harness, NetworkId::from_bytes([1; 32]), server_id)?;
    assert_eq!(
        RegistrationRouter::new(other_network, executor()?).err(),
        Some(RuntimeError::InvalidValue)
    );
    let other_server = hosted_config(&harness, network_id, ServerId::from_bytes([1; 16]))?;
    assert_eq!(
        RegistrationRouter::new(other_server, executor()?).err(),
        Some(RuntimeError::InvalidValue)
    );
    let matching = hosted_config(&harness, network_id, server_id)?;
    assert!(RegistrationRouter::new(matching, executor()?).is_ok());
    Ok(())
}

#[tokio::test]
async fn opening_a_connection_the_session_table_does_not_hold_registers_nothing() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .connection_opened(context, ConnectionGeneration::new(5));
    assert!(harness.router.connections.is_empty());
    assert!(context.timers_mut().is_empty());
    Ok(())
}

#[tokio::test]
async fn connection_whose_registration_window_overflows_the_clock_is_closed() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    harness
        .fixture
        .context_mut()?
        .set_monotonic_for_test(u64::MAX - 5);
    let _sink = harness.open(1, true)?;
    assert!(harness.router.connections.is_empty());
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn connection_the_account_service_cannot_admit_is_closed_without_timers() -> TestResult {
    let mut harness = Harness::with(Options {
        role: Role::Hosted,
        allow_guests: true,
        access_token: None,
        entropy: Some(Vec::new()),
    })?;
    let _sink = harness.open(1, true)?;
    assert!(harness.router.connections.is_empty());
    assert!(harness.sink_gone(1)?);
    assert_eq!(harness.fixture.context_mut()?.timers_mut().live_len(), 0);
    Ok(())
}

#[tokio::test]
async fn closing_a_connection_the_router_never_saw_changes_nothing() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let _sink = harness.open(1, true)?;
    let context = harness.fixture.context_mut()?;
    harness.router.connection_closed(
        context,
        ConnectionGeneration::new(8),
        CloseReason::TransportLoss,
    );
    assert_eq!(harness.router.connections.len(), 1);
    assert!(harness.router.pending_closures.is_empty());
    Ok(())
}

#[tokio::test]
async fn router_without_a_federation_role_drops_link_input_and_reports_no_stats() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let context = harness.fixture.context_mut()?;
    harness.router.federation_inbound(
        context,
        crate::federation::FederationInbound {
            link: crate::federation::LinkId::new(1),
            peer: ServerId::from_bytes([90; 16]),
            event: crate::federation::LinkEvent::Closed(
                crate::federation::LinkCloseReason::PeerClosed,
            ),
            charge: None,
        },
    );
    assert!(harness.router.federation_stats().is_none());
    assert!(harness.router.e2ee_stats().is_none());
    assert!(matches!(
        harness
            .router
            .admin_peer_quarantine(context, ServerId::from_bytes([90; 16])),
        Err(PeerQuarantineRefusal::UnknownPeer)
    ));
    assert!(harness.router.begin_shutdown(context));
    Ok(())
}

#[tokio::test]
async fn reloaded_policy_applies_without_an_account_service() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let snapshot = crate::test_support::golden_snapshot("Renamed", None)?;
    let expected = snapshot.account_policy().allow_guests;
    let context = harness.fixture.context_mut()?;
    harness.router.config_reloaded(context, &snapshot);
    assert_eq!(&*harness.router.config.display_name, "Renamed");
    assert_eq!(harness.router.config.allow_guests, expected);
    Ok(())
}

#[tokio::test]
async fn reload_waits_for_a_staged_registration() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let _sink = harness.open(1, true)?;
    assert!(harness.router.reload_ready());
    harness.line(1, "NICK pending")?;
    harness.line(1, "USER pending 0 * :Pending")?;
    assert!(!harness.router.reload_ready());
    harness.settle().await?;
    assert!(harness.router.reload_ready());
    Ok(())
}

fn maintain(harness: &mut Harness) -> TestResult<usize> {
    let context = harness.fixture.context_mut()?;
    for event in [
        MaintenanceEvent::ClockDriftCheck,
        MaintenanceEvent::RetentionSweep,
    ] {
        harness.router.maintenance(context, event);
    }
    Ok(context.pending_len())
}

#[tokio::test]
async fn idle_maintenance_stages_nothing_in_any_role() -> TestResult {
    for role in ALL_ROLES {
        let mut harness = Harness::new(role)?;
        assert_eq!(maintain(&mut harness)?, 0);
        assert!(harness.router.reload_ready());
    }
    Ok(())
}

fn schedule(harness: &mut Harness, kind: TimerKind, id: TimedId) -> TestResult {
    let context = harness.fixture.context_mut()?;
    let now = context.now();
    context.timers_mut().schedule(now, kind, id)?;
    Ok(())
}

#[tokio::test]
async fn timers_no_owner_claims_are_dropped_in_every_role() -> TestResult {
    for role in ALL_ROLES {
        let mut harness = Harness::new(role)?;
        let sink = harness.open(1, true)?;
        schedule(&mut harness, TimerKind::Reservation, TimedId::Global)?;
        schedule(&mut harness, TimerKind::SecretChannelFloor, TimedId::Global)?;
        schedule(
            &mut harness,
            TimerKind::SecretChannelFloor,
            TimedId::Connection(ConnectionGeneration::new(1)),
        )?;
        let now = harness.fixture.context_mut()?.now().get();
        assert_eq!(harness.fire_timers_at(now)?, 3);
        assert!(sink.lines().is_empty());
        assert!(!harness.sink_gone(1)?);
    }
    Ok(())
}

#[tokio::test]
async fn timer_of_another_kind_than_the_armed_deadline_is_ignored() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    let connection = TimedId::Connection(ConnectionGeneration::new(1));
    schedule(&mut harness, TimerKind::Ping, connection)?;
    schedule(
        &mut harness,
        TimerKind::Pong,
        TimedId::Connection(ConnectionGeneration::new(7)),
    )?;
    let now = harness.fixture.context_mut()?.now().get();
    assert_eq!(harness.fire_timers_at(now)?, 2);
    assert!(sink.lines().is_empty());
    assert!(matches!(
        harness.state(1)?.deadline,
        DeadlineState::Registration
    ));
    Ok(())
}

#[tokio::test]
async fn answered_ping_rearms_the_idle_deadline() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.register(1, "ponger").await?;
    harness.fire_timers_at(KEEPALIVE_IDLE_MILLIS + 10)?;
    let ping = sink
        .lines()
        .into_iter()
        .find(|line| line.contains(" PING "))
        .ok_or("no keepalive ping")?;
    let token = ping.rsplit(':').next().ok_or("ping token")?.to_owned();
    harness.line(1, "CAP LIST")?;
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::Pong));
    harness.line(1, &format!("PONG {token}"))?;
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::Idle));
    assert!(!harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn keepalive_timer_that_would_overflow_the_clock_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let _sink = harness.open(1, true)?;
    let context = harness.fixture.context_mut()?;
    context.set_monotonic_for_test(u64::MAX - 5);
    schedule_connection_timer(
        context,
        ConnectionGeneration::new(1),
        TimerKind::Ping,
        KEEPALIVE_IDLE_MILLIS,
    );
    assert!(harness.sink_gone(1)?);
    Ok(())
}

#[tokio::test]
async fn unowned_crypto_and_storage_completions_are_dropped() -> TestResult {
    for role in ALL_ROLES {
        let mut harness = Harness::new(role)?;
        let sink = harness.open(1, true)?;
        let context = harness.fixture.context_mut()?;
        harness.router.crypto_completed(
            context,
            crate::bridge::CryptoCompletionMessage {
                job_id: crate::bridge::CryptoJobId::new(9_999),
                output: Err(agenc_relay_crypto::CryptoWorkerError::QueueFull),
            },
        );
        harness.router.storage_read_completed(
            context,
            crate::bridge::StorageReadCompletionMessage {
                read_id: crate::bridge::StorageReadId::new(9_999),
                result: Err(agenc_relay_storage::StorageError::Unavailable),
            },
        );
        assert!(sink.lines().is_empty());
        assert!(!harness.sink_gone(1)?);
    }
    Ok(())
}

#[tokio::test]
async fn carrier_completion_for_a_vanished_connection_is_dropped() -> TestResult {
    for role in [Role::Hosted, Role::Coordinator] {
        let mut harness = Harness::new(role)?;
        let context = harness.fixture.context_mut()?;
        harness.router.apply_account_completions(
            context,
            vec![CarrierCompletion {
                generation: ConnectionGeneration::new(4),
                carrier_generation: 0,
                close: false,
                result: ResultClass::Ok,
            }],
        );
        assert!(harness.router.connections.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn carrier_completion_the_registration_does_not_expect_keeps_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    let context = harness.fixture.context_mut()?;
    harness.router.apply_account_completions(
        context,
        vec![CarrierCompletion {
            generation: ConnectionGeneration::new(1),
            carrier_generation: 77,
            close: false,
            result: ResultClass::Ok,
        }],
    );
    assert!(sink.lines().is_empty());
    assert!(!harness.sink_gone(1)?);
    assert!(harness.state(1).is_ok());
    Ok(())
}

fn reject(harness: &mut Harness, origin: Option<StagedOrigin>) -> TestResult {
    let context = harness.fixture.context_mut()?;
    context.discard_pending_for_test();
    harness.router.batch_rejected(
        context,
        origin,
        agenc_relay_storage::StorageError::Unavailable,
    );
    Ok(())
}

#[tokio::test]
async fn rejected_batch_without_an_origin_reaches_no_client_in_any_role() -> TestResult {
    for role in ALL_ROLES {
        let mut harness = Harness::new(role)?;
        let sink = harness.open(1, true)?;
        reject(&mut harness, None)?;
        assert!(sink.lines().is_empty());
        assert!(!harness.sink_gone(1)?);
    }
    Ok(())
}

fn stage_registration(harness: &mut Harness, nick: &str) -> TestResult<BoundSession> {
    harness.line(1, &format!("NICK {nick}"))?;
    harness.line(1, &format!("USER {nick} 0 * :Real"))?;
    harness
        .router
        .pending_registrations
        .get(&ConnectionGeneration::new(1))
        .map(|pending| pending.bound)
        .ok_or_else(|| "the registration was not staged".into())
}

#[tokio::test]
async fn rejected_registration_batch_unbinds_the_session_and_closes_the_client() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let bound = stage_registration(&mut harness, "unlucky")?;
    reject(&mut harness, Some(StagedOrigin::silent(generation)))?;
    assert!(
        saw(&sink, "ERROR :Registration rejected"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    assert!(harness.router.pending_registrations.is_empty());
    assert!(harness.router.leases.is_empty());
    let context = harness.fixture.context_mut()?;
    assert!(context.domain().session(bound.user_id).is_none());
    assert_eq!(
        context
            .sessions()
            .connection(generation)
            .and_then(crate::state_core::session::ConnectionEntry::session),
        None
    );
    Ok(())
}

#[tokio::test]
async fn rejected_registration_batch_tolerates_a_session_that_is_already_unbound() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let bound = stage_registration(&mut harness, "unbound")?;
    harness
        .fixture
        .context_mut()?
        .sessions_mut()
        .unbind_session(generation, bound)?;
    reject(&mut harness, Some(StagedOrigin::silent(generation)))?;
    assert!(saw(&sink, "ERROR"), "lines: {:?}", sink.lines());
    assert!(harness.router.pending_registrations.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejected_registration_batch_of_a_departed_client_renders_nothing() -> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    stage_registration(&mut harness, "departed")?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .connection_closed(context, generation, CloseReason::TransportLoss);
    let before = sink.lines().len();
    reject(&mut harness, Some(StagedOrigin::silent(generation)))?;
    assert_eq!(sink.lines().len(), before);
    assert!(harness.router.pending_registrations.is_empty());
    assert!(harness.router.connections.is_empty());
    Ok(())
}

fn refusal_origin(generation: ConnectionGeneration) -> TestResult<StagedOrigin> {
    let frame = WireMessage::new(
        "server.example",
        "FAIL",
        &["JOIN", "TEMPORARILY_UNAVAILABLE"],
        Some("Try again"),
    )?;
    Ok(StagedOrigin::with_rejection_frames(generation, vec![frame]))
}

#[tokio::test]
async fn rejected_command_batch_delivers_the_retained_failure() -> TestResult {
    for role in [Role::Plain, Role::Hosted] {
        let mut harness = Harness::new(role)?;
        let sink = harness.open(1, true)?;
        let origin = refusal_origin(ConnectionGeneration::new(1))?;
        reject(&mut harness, Some(origin))?;
        assert!(
            saw(&sink, "FAIL JOIN TEMPORARILY_UNAVAILABLE"),
            "lines: {:?}",
            sink.lines()
        );
        assert!(!harness.sink_gone(1)?);
    }
    Ok(())
}

#[tokio::test]
async fn retained_failure_for_a_gone_transport_is_not_delivered() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    harness.drop_transport(1)?;
    let origin = refusal_origin(ConnectionGeneration::new(1))?;
    reject(&mut harness, Some(origin))?;
    assert!(sink.lines().is_empty());
    assert!(harness.sink_gone(1)?);
    Ok(())
}

/// Stages, by hand, an authenticated registration whose grant the account
/// service never issued.
fn pending_without_a_grant(harness: &mut Harness, nick: &str) -> TestResult<BoundSession> {
    let generation = ConnectionGeneration::new(1);
    harness.line(1, &format!("NICK {nick}"))?;
    let actions = harness.actions(1, &format!("USER {nick} 0 * :Real"))?;
    let Some(RegistrationAction::CommitRegistration {
        generation: event_generation,
        ..
    }) = actions.into_iter().next()
    else {
        return Err("expected the registration commit".into());
    };
    let bound = BoundSession {
        session_id: SessionId::from_bytes([71; 16]),
        user_id: UserId::from_bytes([72; 16]),
        capability_hash: [0; 32],
    };
    harness.fixture.context_mut()?.sessions_mut().bind_session(
        generation,
        bound,
        crate::test_support::negotiated_capabilities(&[])?,
    )?;
    harness.router.pending_registrations.insert(
        generation,
        PendingRegistration {
            event_generation,
            bound,
            nickname: nick.to_owned(),
            authenticated: true,
        },
    );
    Ok(bound)
}

#[tokio::test]
async fn authenticated_registration_without_its_grant_is_closed_at_commit() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    pending_without_a_grant(&mut harness, "grantless")?;
    let context = harness.fixture.context_mut()?;
    harness.router.batch_applied(context, 1);
    assert!(harness.sink_gone(1)?);
    assert!(!saw(&sink, " 001 "), "lines: {:?}", sink.lines());
    assert!(harness.router.pending_registrations.is_empty());
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::None));
    Ok(())
}

#[tokio::test]
async fn rejected_authenticated_registration_is_unbound_and_closed() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    pending_without_a_grant(&mut harness, "rejected")?;
    reject(&mut harness, Some(StagedOrigin::silent(generation)))?;
    assert!(
        saw(&sink, "ERROR :Registration rejected"),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.sink_gone(1)?);
    let context = harness.fixture.context_mut()?;
    assert_eq!(
        context
            .sessions()
            .connection(generation)
            .and_then(crate::state_core::session::ConnectionEntry::session),
        None
    );
    Ok(())
}

#[tokio::test]
async fn coordinator_consumes_a_grace_timer_of_a_peer_without_origins() -> TestResult {
    let mut harness = Harness::new(Role::Coordinator)?;
    let sink = harness.open(1, true)?;
    schedule(
        &mut harness,
        TimerKind::FederationGrace,
        TimedId::Peer(ServerId::from_bytes([90; 16])),
    )?;
    let now = harness.fixture.context_mut()?.now().get();
    assert_eq!(harness.fire_timers_at(now)?, 1);
    assert!(sink.lines().is_empty());
    assert_eq!(harness.fixture.context_mut()?.pending_len(), 0);
    Ok(())
}
