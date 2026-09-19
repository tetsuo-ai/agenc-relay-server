//! E2EE client lines on an edge are admitted before they reach the E2EE
//! router, and a router missing a role refuses them.
#![forbid(unsafe_code)]

use super::test_harness::{Harness, Role, TestResult, parsed, saw};
use super::*;
use crate::federation::edge::EdgeCompletion;

fn route(harness: &mut Harness, number: u64, line: &str) -> TestResult<ResultClass> {
    let generation = ConnectionGeneration::new(number);
    let message = parsed(line)?;
    let context = harness.fixture.context_mut()?;
    let state = harness
        .router
        .connections
        .remove(&generation)
        .ok_or("connection")?;
    let class = harness
        .router
        .route_e2ee_line(context, generation, &state, &message);
    harness.router.connections.insert(generation, state);
    Ok(class)
}

fn bind(harness: &mut Harness, number: u64, nick: &str) -> TestResult {
    harness.line(number, &format!("NICK {nick}"))?;
    let actions = harness.actions(number, &format!("USER {nick} 0 * :Real"))?;
    let Some(RegistrationAction::CommitRegistration {
        generation: event_generation,
        ..
    }) = actions.into_iter().next()
    else {
        return Err("expected the registration commit".into());
    };
    let context = harness.fixture.context_mut()?;
    harness.router.apply_edge_completion(
        context,
        EdgeCompletion::SessionRegistered {
            generation: ConnectionGeneration::new(number),
            session_id: SessionId::from_bytes([61; 16]),
            user_id: UserId::from_bytes([62; 16]),
            event_generation,
            nickname: nick.to_owned(),
        },
    );
    Ok(())
}

#[tokio::test]
async fn e2ee_capability_is_advertised_with_the_edge_e2ee_router() -> TestResult {
    let mut harness = Harness::new(Role::E2eeEdge)?;
    let sink = harness.open(1, true)?;
    harness.line(1, "CAP LS 302")?;
    assert!(
        saw(&sink, crate::e2ee::edge::E2EE_CAPABILITY),
        "lines: {:?}",
        sink.lines()
    );
    assert!(harness.router.e2ee().is_some());
    assert!(harness.router.e2ee_stats().is_some());
    Ok(())
}

#[tokio::test]
async fn e2ee_line_before_registration_is_rejected_without_an_answer() -> TestResult {
    let mut harness = Harness::new(Role::E2eeEdge)?;
    let sink = harness.open(1, true)?;
    assert_eq!(route(&mut harness, 1, "EKEY LIST")?, ResultClass::Rejected);
    assert!(sink.lines().is_empty());
    Ok(())
}

#[tokio::test]
async fn e2ee_lines_beyond_the_session_burst_are_refused_as_rate_limited() -> TestResult {
    let mut harness = Harness::new(Role::E2eeEdge)?;
    let sink = harness.open(1, true)?;
    bind(&mut harness, 1, "sender")?;
    let mut limited = false;
    for _ in 0..512 {
        route(&mut harness, 1, "EKEY LIST")?;
        if saw(&sink, "RATE_LIMITED") {
            limited = true;
            break;
        }
    }
    assert!(limited, "tail: {:?}", sink.lines().last());
    Ok(())
}
