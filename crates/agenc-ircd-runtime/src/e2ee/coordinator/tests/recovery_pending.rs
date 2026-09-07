//! Restored routes refuse fresh authority before sequencing or signing.
//! Positive controls use the same signed input as the recovery negatives.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use agenc_ircd_domain::e2ee::lifecycle::{Lifecycle, RecoveryGate};
use agenc_ircd_domain::e2ee::sequencer_log::SequencerLog;
use agenc_ircd_domain::e2ee::{ConversationId, RecoveryState, RouteTable};
use agenc_ircd_storage::e2ee_records::{ROUTE_ROW_KIND, RouteRow};
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use agenc_ircd_types::{ChannelInstanceId, ServerId};

use super::*;
use crate::e2ee::coordinator::events::DeliveryStream;
use crate::e2ee::coordinator::ops::{self, Exec, Fail};
use crate::e2ee::coordinator::request::{self, Classified, Outcome};
use crate::e2ee::coordinator::{CompanionOrigin, ConversationState};
use crate::state_core::durable::AccountServiceDurableWrite as Write;

#[path = "recovery_mailbox.rs"]
mod mailbox;

#[path = "recovery_reinit.rs"]
mod reinit_endpoints;

#[test]
fn a_pending_restored_route_cannot_sign_a_new_finalization() -> TestResult {
    assert_pending_finalization_refused(true)
}

#[test]
fn pending_finalization_is_refused_before_the_signer_is_required() -> TestResult {
    assert_pending_finalization_refused(false)
}

fn finalization_fixture() -> TestResult<(Harness, [u8; 32], Vec<u8>)> {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let (receipt, commit_id, candidate_id) = submit_candidate(&mut harness, conversation, 0, 20)?;
    let ack = acknowledge(&mut harness, conversation, candidate_id, commit_id)?;
    let request = finalization_request(
        &harness,
        conversation,
        &receipt,
        commit_id,
        candidate_id,
        &ack,
        &[DEVICE],
    )?;
    let mut normal = harness.reloaded()?;
    let valid = ok(evaluate_finalization(&mut normal, conversation, &request)?)?;
    assert!(matches!(valid.result, ResultBody::Finalized(..)));
    assert!(!valid.writes.is_empty());
    assert!(!valid.events.is_empty());
    Ok((harness, conversation, request))
}

/// Models CAP72's typed-row output without calling the production transformer,
/// so this admission regression cannot fail merely because CAP72 is absent.
fn restored_pending(harness: &mut Harness, conversation: [u8; 32]) -> TestResult<Harness> {
    let route_key = RouteRow::key(&conversation)?;
    let mut changed = 0_usize;
    for write in &mut harness.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if *table != TableId::E2eeState || *key != route_key {
            continue;
        }
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        assert_eq!(value.record_kind(), ROUTE_ROW_KIND);
        let mut route = RouteRow::decode(value.body())?;
        route.recovery_gate = true;
        let value = PersistentRecordValue::new(
            *table,
            value.record_kind(),
            value.revision(),
            value.generation(),
            value.expires_at(),
            value.references().to_vec(),
            route.encode()?,
        )?;
        *write = Write::put(*table, key.clone(), value.encode()?)?;
        changed = changed.checked_add(1).ok_or("route count overflow")?;
    }
    assert!(changed > 0);
    let restored = harness.reloaded()?;
    let route = restored
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("restored route")?;
    assert_eq!(route.recovery, RecoveryState::Pending);
    assert_eq!(
        restored
            .coordinator
            .state
            .lifecycles
            .get(&conversation)
            .ok_or("restored lifecycle")?
            .gate(),
        RecoveryGate::Pending
    );
    Ok(restored)
}

/// Calls the real opcode dispatcher without the Harness::run helper's deliberate
/// request-sequence update or simulated commit. A rejected new-epoch request may
/// get a durable failure result in the full executor; it must not advance the
/// restored conversation or issue new sequencer authority.
fn evaluate_finalization(
    harness: &mut Harness,
    conversation: [u8; 32],
    bytes: &[u8],
) -> TestResult<Result<Outcome, Fail>> {
    evaluate_request(harness, Op::SubmitFinalization, &conversation, Some(bytes))
}

fn evaluate_request(
    harness: &mut Harness,
    opcode: Op,
    parameters: &[u8],
    payload: Option<&[u8]>,
) -> TestResult<Result<Outcome, Fail>> {
    let mut entropy = super::super::Counter(harness.entropy.0);
    let result = evaluate_request_with_entropy(harness, opcode, parameters, payload, &mut entropy);
    harness.entropy = entropy;
    result
}

fn evaluate_request_with_entropy(
    harness: &Harness,
    opcode: Op,
    parameters: &[u8],
    payload: Option<&[u8]>,
    entropy: &mut dyn agenc_ircd_types::EntropySource,
) -> TestResult<Result<Outcome, Fail>> {
    let queries = harness.query_sessions.query_reservations(
        agenc_ircd_types::UserId::from_bytes(super::super::ORIGIN),
        harness.query_limits,
        harness.backing.clone(),
    );
    evaluate_request_with_queries(harness, opcode, parameters, payload, entropy, queries)
}

fn evaluate_request_with_queries(
    harness: &Harness,
    opcode: Op,
    parameters: &[u8],
    payload: Option<&[u8]>,
    entropy: &mut dyn agenc_ircd_types::EntropySource,
    queries: crate::state_core::query_usage::QueryReservationPort<'_>,
) -> TestResult<Result<Outcome, Fail>> {
    let complete = harness.request(opcode, parameters, payload)?;
    evaluate_complete_with_queries(harness, complete, entropy, queries)
}

fn evaluate_complete_with_queries(
    harness: &Harness,
    complete: crate::e2ee::coordinator::CompleteRequest,
    entropy: &mut dyn agenc_ircd_types::EntropySource,
    queries: crate::state_core::query_usage::QueryReservationPort<'_>,
) -> TestResult<Result<Outcome, Fail>> {
    let decoded = request::decode(&harness.coordinator, &complete)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    let key = crate::e2ee::coordinator::CompanionOriginKey {
        home_server_id: decoded.request.home_server_id,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
    };
    assert_eq!(
        request::classify(&harness.coordinator.state, key.home_server_id, &decoded),
        Classified::Fresh
    );
    let origin = harness
        .coordinator
        .state
        .origins
        .get(&key)
        .cloned()
        .ok_or("attached origin")?;
    let home = ServerId::from_bytes(key.home_server_id);
    let peers = [home, ServerId::from_bytes([12; 16])];
    let holds = |_: ServerId, _: ChannelInstanceId| true;
    let hosting = |_: ChannelInstanceId| vec![home];
    let attached = |_: &[u8; 32]| vec![home];
    let member = |_: ChannelInstanceId| true;
    let plan_binding = |_: ChannelInstanceId, _: &[[u8; 24]]| Ok(None);
    let mut exec = Exec {
        queries: Some(queries),
        backing: harness.backing.clone(),
        monotonic_millis: harness.monotonic_millis,
        coordinator: &harness.coordinator,
        home,
        origin: &origin,
        decoded: &decoded,
        now: super::super::NOW,
        entropy,
        peers: &peers,
        holds_channel: &holds,
        hosting: &hosting,
        attached_edges: &attached,
        channel_member: &member,
        plan_binding: &plan_binding,
        state_generation: super::super::STATE_GENERATION,
        source_view: Vec::new(),
    };
    Ok(ops::execute(&mut exec))
}

#[test]
fn either_recovery_representation_refuses_fresh_finalization() -> TestResult {
    let (source, conversation, bytes) = finalization_fixture()?;
    for (route_gate, lifecycle_gate) in [
        (RecoveryState::Pending, RecoveryGate::Normal),
        (RecoveryState::Normal, RecoveryGate::Pending),
        (RecoveryState::Conflict, RecoveryGate::Normal),
        (RecoveryState::Normal, RecoveryGate::Conflict),
        (RecoveryState::Closed, RecoveryGate::Normal),
        (RecoveryState::Normal, RecoveryGate::Closed),
    ] {
        let mut fixture = source.reloaded()?;
        set_recovery(&mut fixture, conversation, route_gate, lifecycle_gate)?;
        fixture.coordinator.signer = None;
        let before = retained_state(&fixture)?;
        let outcome = evaluate_finalization(&mut fixture, conversation, &bytes)?;
        assert_route_refused(outcome)?;
        assert_eq!(retained_state(&fixture)?, before);
    }
    Ok(())
}

#[test]
fn missing_recovery_state_cannot_authorize_a_known_conversation() -> TestResult {
    let (source, conversation, bytes) = finalization_fixture()?;
    for missing_route in [false, true] {
        let mut fixture = source.reloaded()?;
        if missing_route {
            fixture
                .coordinator
                .state
                .routes
                .remove_projection(&ConversationId(conversation));
        } else {
            fixture.coordinator.state.lifecycles.remove(&conversation);
        }
        fixture.coordinator.signer = None;
        let before = retained_state(&fixture)?;
        assert_route_refused(evaluate_finalization(&mut fixture, conversation, &bytes)?)?;
        assert_eq!(retained_state(&fixture)?, before);
    }
    Ok(())
}

fn set_recovery(
    fixture: &mut Harness,
    conversation: [u8; 32],
    route_gate: RecoveryState,
    lifecycle_gate: RecoveryGate,
) -> TestResult {
    let state = &mut fixture.coordinator.state;
    let mut route = *state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("existing route")?;
    route.recovery = route_gate;
    state.routes.restore_entry(route);
    state.lifecycles.insert(
        conversation,
        Lifecycle::restore(lifecycle_gate, false, false),
    );
    Ok(())
}

fn assert_route_refused(outcome: Result<Outcome, Fail>) -> TestResult {
    let Err(failure) = outcome else {
        return Err("recovery mutation reached the handler".into());
    };
    assert_eq!(failure.code, E2eeReplyCode::RouteInvalid);
    Ok(())
}

#[test]
fn a_pending_route_keeps_retained_public_receipts_readable() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let mut fixture = restored_pending(&mut source, conversation)?;
    fixture.coordinator.signer = None;
    let before = retained_state(&fixture)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&0_u64.to_be_bytes());
    parameters.push(0);
    let outcome = ok(evaluate_request(
        &mut fixture,
        Op::FetchReceipts,
        &parameters,
        None,
    )?)?;
    assert!(!outcome.responses.is_empty());
    for response in &outcome.responses {
        assert_eq!(
            fixture
                .coordinator
                .state
                .objects
                .get(&object_id(&response.bytes)),
            Some(&response.bytes)
        );
    }
    assert!(outcome.writes.is_empty());
    assert!(outcome.events.is_empty());
    assert!(outcome.effects.is_empty());
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn a_pending_route_refuses_reservation_before_the_signer_is_required() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let mut fixture = restored_pending(&mut source, conversation)?;
    fixture.coordinator.signer = None;
    let before = retained_state(&fixture)?;
    let mut parameters = INSTANCE.to_vec();
    parameters.push(5);
    parameters.extend_from_slice(b"#room");
    assert_route_refused(evaluate_request(
        &mut fixture,
        Op::ReserveChannel,
        &parameters,
        None,
    )?)?;
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn a_pending_route_does_not_block_an_independent_reservation() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let mut fixture = restored_pending(&mut source, conversation)?;
    let before = retained_state(&fixture)?;
    let mut parameters = [98; 16].to_vec();
    parameters.push(6);
    parameters.extend_from_slice(b"#other");
    let outcome = ok(evaluate_request(
        &mut fixture,
        Op::ReserveChannel,
        &parameters,
        None,
    )?)?;
    assert!(matches!(outcome.result, ResultBody::Reserved(..)));
    assert!(!outcome.responses.is_empty());
    assert!(!outcome.writes.is_empty());
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn bind_cannot_replace_an_existing_pending_conversation() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    let mut fixture = restored_pending(&mut source, conversation)?;
    let before = retained_state(&fixture)?;
    let mut parameters = [98; 16].to_vec();
    parameters.extend_from_slice(&conversation);
    parameters.extend_from_slice(&[44; 32]);
    assert_route_refused(evaluate_request(
        &mut fixture,
        Op::BindGroup,
        &parameters,
        Some(&binding),
    )?)?;
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct RetainedRecoveryState {
    routes: RouteTable,
    logs: BTreeMap<[u8; 32], SequencerLog>,
    lifecycles: BTreeMap<[u8; 32], Lifecycle>,
    conversations: BTreeMap<[u8; 32], ConversationState>,
    objects: BTreeMap<[u8; 32], Vec<u8>>,
    streams: BTreeMap<ServerId, DeliveryStream>,
    object_bytes: usize,
    origin: CompanionOrigin,
    harness_sequence: u64,
    write_count: usize,
}

fn retained_state(harness: &Harness) -> TestResult<RetainedRecoveryState> {
    let state = &harness.coordinator.state;
    Ok(RetainedRecoveryState {
        routes: state.routes.clone(),
        logs: state.logs.clone(),
        lifecycles: state.lifecycles.clone(),
        conversations: state.conversations.clone(),
        objects: state.objects.clone(),
        streams: state.streams.clone(),
        object_bytes: state.object_bytes,
        origin: state
            .origins
            .get(&super::super::origin_key())
            .cloned()
            .ok_or("attached origin")?,
        harness_sequence: harness.sequence,
        write_count: harness.writes.len(),
    })
}

fn assert_pending_finalization_refused(with_signer: bool) -> TestResult {
    let (mut source, conversation, bytes) = finalization_fixture()?;
    let mut restored = restored_pending(&mut source, conversation)?;
    if !with_signer {
        restored.coordinator.signer = None;
    }
    let before = retained_state(&restored)?;
    let outcome = evaluate_finalization(&mut restored, conversation, &bytes)?;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(Fail { code, context }) => Outcome::failed(code, context),
    };
    assert!(
        outcome.writes.is_empty(),
        "pending recovery staged new durable rows"
    );
    assert!(
        outcome.responses.is_empty(),
        "pending recovery returned a signed artifact"
    );
    assert!(
        outcome.events.is_empty(),
        "pending recovery emitted an authority event"
    );
    assert!(outcome.effects.is_empty());
    assert!(outcome.snapshot_token.is_none());
    assert!(outcome.next_cursor.is_none());
    assert!(outcome.base_plan.is_none());
    assert!(!outcome.security_mutation);
    assert!(matches!(
        outcome.result,
        ResultBody::Failed {
            code: E2eeReplyCode::RouteInvalid,
            ..
        }
    ));
    assert_eq!(retained_state(&restored)?, before);
    Ok(())
}
