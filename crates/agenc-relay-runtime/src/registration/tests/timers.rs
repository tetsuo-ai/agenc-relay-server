//! Registration deadlines and keepalive timers reach the registration state
//! machine through the router's timer hook.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Role, TestResult, saw};
use super::*;

#[tokio::test]
async fn unregistered_client_is_closed_when_its_registration_deadline_fires() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "NICK slow")?;
    let fired = harness.fire_timers_at(REGISTRATION_TIMEOUT_MILLIS + 10)?;
    assert!(fired >= 1, "the registration deadline must be scheduled");
    assert!(saw(&sink, "ERROR"), "lines: {:?}", sink.lines());
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::None));
    assert!(harness.state(1)?.lease.is_none());
    assert!(harness.router.leases.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_node_without_an_account_service_still_enforces_the_registration_deadline() -> TestResult
{
    // An edge is built with the advertised policy only. Its timer hook used to return before
    // the registration and keepalive timers, so a client that never registered stayed open.
    for role in [Role::Plain, Role::Edge] {
        let mut harness = Harness::new(role)?;
        let sink = harness.open(1, true)?;
        harness.line(1, "NICK slow")?;
        let fired = harness.fire_timers_at(REGISTRATION_TIMEOUT_MILLIS + 10)?;
        assert!(fired >= 1, "the registration deadline must be scheduled");
        assert!(saw(&sink, "ERROR"), "lines: {:?}", sink.lines());
        assert!(matches!(harness.state(1)?.deadline, DeadlineState::None));
    }
    Ok(())
}

#[tokio::test]
async fn idle_registered_client_is_pinged_then_closed_without_a_pong() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let sink = harness.register(1, "idler").await?;
    assert!(saw(&sink, " 001 idler "), "lines: {:?}", sink.lines());
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::Idle));
    harness.fire_timers_at(KEEPALIVE_IDLE_MILLIS + 10)?;
    assert!(saw(&sink, " PING "), "lines: {:?}", sink.lines());
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::Pong));
    harness.fire_timers_at(KEEPALIVE_IDLE_MILLIS + KEEPALIVE_PONG_MILLIS + 20)?;
    assert!(saw(&sink, "ERROR"), "lines: {:?}", sink.lines());
    assert!(matches!(harness.state(1)?.deadline, DeadlineState::None));
    Ok(())
}

#[tokio::test]
async fn carrier_without_an_account_service_fails_unavailable_and_registration_continues()
-> TestResult {
    let mut harness = Harness::new(Role::Plain)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP REQ :sasl")?;
    let outcome = harness.line(1, "AUTHENTICATE AGENC-OPAQUE")?;
    assert!(matches!(outcome, RouteOutcome::Continue));
    assert!(
        saw(&sink, "FAIL AUTHENTICATE UNAVAILABLE"),
        "lines: {:?}",
        sink.lines()
    );
    Ok(())
}

#[test]
fn a_connection_timer_that_cannot_be_placed_on_the_clock_closes_the_transport() -> TestResult {
    let mut harness = Harness::new(Role::Hosted)?;
    let _sink = harness.open(1, true)?;
    let generation = ConnectionGeneration::new(1);
    let context = harness.fixture.context_mut()?;
    context.set_monotonic_for_test(u64::MAX);
    assert!(context.sessions().sink_for_generation(generation).is_some());
    schedule_connection_timer(context, generation, TimerKind::Ping, KEEPALIVE_IDLE_MILLIS);
    assert!(context.sessions().sink_for_generation(generation).is_none());
    Ok(())
}
