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

/// An ordinary companion event at `sequence` for the harness's edge.
fn companion_event(
    harness: &Harness,
    sequence: u64,
) -> TestResult<Vec<agenc_relay_e2ee::federation::frames::CompanionFrame>> {
    use agenc_relay_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
    use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
    use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationEventKind};
    use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
    let identity = &harness.fixture.identity;
    let id = [u8::try_from(sequence)?; 16];
    let event = ArcFederationEvent {
        profile_version: 1,
        network_id: *identity.network_id.as_bytes(),
        target_server_id: *identity.server_id.as_bytes(),
        delivery_generation: 2,
        coordinator_state_generation: 5,
        delivery_sequence: sequence,
        event_id: id,
        event_kind: ArcFederationEventKind::RequestCompleted,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(Vec::new())?,
        route_sequence: 0,
        origin_id: Opaque::new(Vec::new())?,
        origin_generation: 0,
        source_view: Opaque::new(Vec::new())?,
        request_home_server_id: Opaque::new(Vec::new())?,
        request_server_incarnation: Opaque::new(Vec::new())?,
        request_origin_id: Opaque::new(Vec::new())?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(Vec::new())?,
        encoded_event_result: Opaque::new(Vec::new())?,
    };
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
    let object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let position = DeliveryPosition {
        server_id: *identity.server_id.as_bytes(),
        delivery_generation: 2,
        delivery_sequence: sequence,
        event_id: id,
    };
    Ok(agenc_relay_e2ee::wire::fragment::fragment_object(&bytes)?
        .into_iter()
        .map(|fragment| CompanionFrame::Event {
            position,
            object_id,
            fragment,
        })
        .collect())
}

#[tokio::test]
async fn companion_events_waiting_for_a_refused_batch_apply_at_the_refusal() -> TestResult {
    let mut harness = Harness::new(Role::E2eeEdge)?;
    let frames = companion_event(&harness, 7)?;
    let context = harness.fixture.context_mut()?;
    harness
        .router
        .e2ee
        .as_mut()
        .ok_or("e2ee router")?
        .resume_for_test(2, (6, [6; 16]));
    // Another batch gathers in the state core when the event arrives, so
    // the event waits for it.
    let plan = context
        .domain()
        .plan_account_created(agenc_relay_domain::AccountState::new(
            agenc_relay_testkit::account_id(9),
            agenc_relay_testkit::generation(1)?,
            context.domain().revision(),
        ))?;
    context
        .stage_durable(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
        )
        .map_err(|error| format!("other batch: {error:?}"))?;
    let (Some(e2ee), Some(edge)) = (harness.router.e2ee.as_mut(), harness.router.edge.as_mut())
    else {
        return Err("roles".into());
    };
    let _outputs = e2ee.handle_frames(context, edge, frames);
    assert_eq!(e2ee.event_state_for_test(), (1, false), "the event waits");
    // Storage refuses that batch: the router's refusal applies the event.
    context.discard_pending_for_test();
    harness
        .router
        .batch_rejected(context, None, agenc_relay_storage::StorageError::QueueFull);
    assert_eq!(
        harness
            .router
            .e2ee
            .as_ref()
            .ok_or("e2ee router")?
            .event_state_for_test(),
        (0, true),
        "the waiting event applied"
    );
    assert_eq!(context.pending_len(), 1);
    Ok(())
}
