#![forbid(unsafe_code)]

//! The copies of an ACK or terminal event (companion 11.7 and 12.5): an ACK,
//! close, ReInit stage, finalization, abort, ReInit activation or ReInit
//! abort that completes a local request answers the requesting connection
//! with exactly one labeled scalar, and sends its untagged copy to every
//! other eligible local sink but never to the requesting connection, in
//! either arrival order of the result and its completion, on the ordinary
//! event path and through a cross-profile barrier. An event that completes
//! no request of a connection, such as the later terminal of a request
//! answered `PENDING`, reaches that connection as the untagged copy.

use std::collections::BTreeMap;

use agenc_relay_client_wire::WireMessage;
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation, DeliveryPosition};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{
    ArcFederationEvent, ArcFederationEventKind as E, ArcFederationResult,
    ArcFederationResultKind as K, ArcFederationRouteState, ArcRouteStateKind,
};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::command::{EgroupCommand, SubmitKind};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_e2ee::wire::response::{
    SuccessLine, render_ack_notice, render_broadcast, render_labeled,
};
use agenc_relay_types::UserId;

use super::super::ClientOutput;
use super::super::events::OpenEvent;
use super::projection::base_edge;
use super::*;
use crate::test_support::StateCoreFixture;

const SERVER: &str = "edge.example";
const CONVERSATION: [u8; 32] = [77; 32];
/// The request the event completes, and a request the edge never held.
const REQUEST: [u8; 16] = [5; 16];
const UNKNOWN_REQUEST: [u8; 16] = [6; 16];
const EVENT: [u8; 16] = [11; 16];
const LABEL: &str = "own";
const IDS: [[u8; 32]; 3] = [[21; 32], [22; 32], [23; 32]];
const EPOCH: u64 = 9;
const MUTATION: [u8; 16] = [70; 16];

/// The requesting connection, a connection of the direct peer, and a second
/// connection of the requester's own account: all three are attached to the
/// direct route and so are eligible local sinks.
const REQUESTER: u64 = 1;
const PEER: u64 = 2;
const SIBLING: u64 = 3;

/// One request, the event that completes it and the result that answers
/// it. `submit` names an `EGROUP SUBMIT` kind; `None` is `EGROUP CLOSE`.
struct Case {
    submit: Option<SubmitKind>,
    event: E,
    result: K,
}

const CASES: [Case; 8] = [
    Case {
        submit: Some(SubmitKind::Ack),
        event: E::CommitAckEvent,
        result: K::CommitAcked,
    },
    Case {
        submit: Some(SubmitKind::ReinitAck),
        event: E::ReinitAckEvent,
        result: K::ReinitAcked,
    },
    Case {
        submit: Some(SubmitKind::Finalization),
        event: E::FinalizedEvent,
        result: K::Finalized,
    },
    Case {
        submit: Some(SubmitKind::Abort),
        event: E::AbortedEvent,
        result: K::Aborted,
    },
    Case {
        submit: None,
        event: E::ClosedEvent,
        result: K::Closed,
    },
    Case {
        submit: Some(SubmitKind::ReinitAttempt),
        event: E::ReinitStagedEvent,
        result: K::ReinitStaged,
    },
    Case {
        submit: Some(SubmitKind::ReinitActivate),
        event: E::ReinitActivatedEvent,
        result: K::ReinitActivated,
    },
    Case {
        submit: Some(SubmitKind::ReinitAbort),
        event: E::ReinitAbortedEvent,
        result: K::ReinitAborted,
    },
];

/// The wire form of one Account ID.
fn account(seed: u8) -> TestResult<[u8; 24]> {
    let id = agenc_relay_types::AccountId::from_random(
        agenc_relay_types::AccountRandomId::from_bytes([seed; 16]),
    );
    Ok(id.to_text().as_bytes().try_into()?)
}

/// A companion origin authenticated as `account` with an attached device.
fn attached(account: [u8; 24], seed: u8) -> LocalOrigin {
    LocalOrigin {
        origin_id: [seed; 16],
        declared: Some(1),
        acked: Some(1),
        predates_device: None,
        next_sequence: 0,
        sequenced: Some(1),
        state_id: [0; 32],
        declaration: None,
        user_id: Some(UserId::from_bytes([seed; 16])),
        account: Some(account),
        device: Some(([seed; 16], 1)),
        device_principal: Some((Some(UserId::from_bytes([seed; 16])), Some(account))),
    }
}

/// The edge projecting one active direct route between two accounts, with
/// the three attached connections, at delivery position six.
fn hosting_edge() -> TestResult<E2eeEdge> {
    let mut edge = edge();
    let (own, peer) = (account(40)?, account(41)?);
    let (first, second) = if own <= peer {
        (own, peer)
    } else {
        (peer, own)
    };
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: 4,
        conversation_id: CONVERSATION,
        conversation_kind: ArcConversationKind::Direct,
        route_binding: [26; 32],
        semantic_route_lock_id: [23; 32],
        channel_instance_id: Opaque::new(Vec::new())?,
        canonical_channel_name_hash: [0; 32],
        direct_account_a: Opaque::new(first.to_vec())?,
        direct_account_b: Opaque::new(second.to_vec())?,
        binding_id: [34; 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 4,
        sequencer_record_head_id: [59; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationState, state.encode()?)?.encode()?;
    edge.route_changed(&bytes)
        .map_err(|refusal| refusal.code.to_string())?;
    for (generation, holder, seed) in [(REQUESTER, own, 31), (PEER, peer, 32), (SIBLING, own, 33)] {
        edge.origins.insert(
            ConnectionGeneration::new(generation),
            attached(holder, seed),
        );
    }
    edge.delivery.generation = 2;
    edge.delivery.cursor = Some((6, [12; 16]));
    Ok(edge)
}

/// The labeled request of `case` that `generation` sent.
fn submission(case: &Case, generation: u64) -> PendingRequest {
    let mut request = pending(generation, 0, false);
    request.label = Some(LABEL.to_owned());
    let command = match case.submit {
        Some(kind) => EgroupCommand::Submit {
            kind,
            conversation_id: CONVERSATION,
        },
        None => EgroupCommand::Close {
            conversation_id: CONVERSATION,
            reason_code: 1,
        },
    };
    request.command = Resolved::Command(ClientCommand::Egroup(command));
    request
}

/// The ACK object an ACK event carries as its payload.
fn ack_object(case: &Case) -> TestResult<Option<Vec<u8>>> {
    let kind = match case.event {
        E::CommitAckEvent => ArcWireObjectKind::CommitAck,
        E::ReinitAckEvent => ArcWireObjectKind::ReinitAck,
        _ => return Ok(None),
    };
    Ok(Some(ArcWireObject::new(kind, vec![6; 64])?.encode()?))
}

/// The event's encoded result: the ACK selector, or the identifiers of the
/// terminal record (12.5).
fn event_result(case: &Case) -> Vec<u8> {
    let [first, second, third] = IDS;
    match case.event {
        E::CommitAckEvent | E::ReinitAckEvent => first.to_vec(),
        E::FinalizedEvent => [EPOCH.to_be_bytes().as_slice(), &first, &second].concat(),
        E::ClosedEvent => first.to_vec(),
        E::ReinitStagedEvent => [first, second].concat(),
        _ => [first, second, third].concat(),
    }
}

/// The result tuple that answers the request (12.5).
fn result_tuple(case: &Case) -> Vec<u8> {
    let [first, second, third] = IDS;
    match case.result {
        K::Finalized => [
            CONVERSATION.as_slice(),
            &EPOCH.to_be_bytes(),
            &first,
            &second,
        ]
        .concat(),
        K::Closed => [CONVERSATION, first].concat(),
        K::CommitAcked | K::ReinitStaged | K::ReinitAcked => [CONVERSATION, first, second].concat(),
        _ => [CONVERSATION, first, second, third].concat(),
    }
}

/// The untagged copy an eligible sink receives (11.7).
fn untagged_copy(case: &Case, ack: Option<&[u8]>) -> TestResult<String> {
    let [first, second, third] = IDS;
    let ack_id = ack.map(|bytes| *ObjectId::compute(bytes).as_bytes());
    let line = match case.event {
        E::CommitAckEvent | E::ReinitAckEvent => {
            let reinit = case.event == E::ReinitAckEvent;
            let object = ack_id.ok_or("an ACK event names its ACK object")?;
            return Ok(render_ack_notice(
                SERVER,
                reinit,
                &CONVERSATION,
                &first,
                &object,
            )?);
        }
        E::FinalizedEvent => SuccessLine::Finalized(CONVERSATION, EPOCH, first, second),
        E::AbortedEvent => SuccessLine::Aborted(CONVERSATION, first, second, third),
        E::ClosedEvent => SuccessLine::Closed(CONVERSATION, first),
        E::ReinitStagedEvent => SuccessLine::ReinitStaged(CONVERSATION, first, second),
        E::ReinitActivatedEvent => SuccessLine::ReinitActivated(CONVERSATION, first, second, third),
        _ => SuccessLine::ReinitAborted(CONVERSATION, first, second, third),
    };
    Ok(render_broadcast(SERVER, &line)?)
}

/// The one labeled scalar the requesting connection receives (11.7).
fn labeled_scalar(case: &Case) -> TestResult<String> {
    let [first, second, third] = IDS;
    let line = match case.result {
        K::CommitAcked => SuccessLine::Acked(CONVERSATION, first, second),
        K::ReinitAcked => SuccessLine::ReinitAcked(CONVERSATION, first, second),
        K::ReinitStaged => SuccessLine::ReinitStaged(CONVERSATION, first, second),
        K::Finalized => SuccessLine::Finalized(CONVERSATION, EPOCH, first, second),
        K::Closed => SuccessLine::Closed(CONVERSATION, first),
        K::Aborted => SuccessLine::Aborted(CONVERSATION, first, second, third),
        K::ReinitActivated => SuccessLine::ReinitActivated(CONVERSATION, first, second, third),
        _ => SuccessLine::ReinitAborted(CONVERSATION, first, second, third),
    };
    Ok(render_labeled(LABEL, SERVER, &line)?)
}

/// The event of `case`, whose request correlation names `request` of this
/// edge's incarnation, or nothing.
fn event(case: &Case, request: Option<[u8; 16]>, ack: Option<&[u8]>) -> TestResult<OpenEvent> {
    let position = DeliveryPosition {
        server_id: [2; 16],
        delivery_generation: 2,
        delivery_sequence: 7,
        event_id: EVENT,
    };
    let correlated =
        |bytes: Vec<u8>| Opaque::new(if request.is_some() { bytes } else { Vec::new() });
    let event = ArcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: [2; 16],
        delivery_generation: position.delivery_generation,
        coordinator_state_generation: 5,
        delivery_sequence: position.delivery_sequence,
        event_id: position.event_id,
        event_kind: case.event,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(CONVERSATION.to_vec())?,
        route_sequence: 5,
        origin_id: Opaque::new(Vec::new())?,
        origin_generation: 0,
        source_view: Opaque::new(Vec::new())?,
        request_home_server_id: correlated(vec![2; 16])?,
        request_server_incarnation: correlated(vec![4; 16])?,
        request_origin_id: correlated(vec![8; 16])?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(request.map_or_else(Vec::new, |request| request.to_vec()))?,
        payload_object_id: Opaque::new(ack.map_or_else(Vec::new, |bytes| {
            ObjectId::compute(bytes).as_bytes().to_vec()
        }))?,
        encoded_event_result: Opaque::new(event_result(case))?,
    };
    let payload_object_id = ack.map(|bytes| *ObjectId::compute(bytes).as_bytes());
    Ok(OpenEvent {
        position,
        event,
        payload_object_id,
    })
}

/// The `federation_result` object the coordinator sends for the request,
/// naming the event as its completion.
fn result_object(case: &Case) -> TestResult<Vec<u8>> {
    let result = ArcFederationResult {
        profile_version: 1,
        network_id: [1; 32],
        home_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
        request_object_id: [7; 32],
        coordinator_state_generation: 1,
        completion_event_id: Opaque::new(EVENT.to_vec())?,
        result_kind: case.result,
        encoded_result: Opaque::new(result_tuple(case))?,
        snapshot_token: Opaque::new(Vec::new())?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(Vec::new())?,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationResult, result.encode()?)?.encode()?)
}

/// Delivers the result as `ERESULT` fragments and returns what renders.
fn deliver_result(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    case: &Case,
) -> TestResult<Vec<ClientOutput>> {
    let bytes = result_object(case)?;
    let correlation = Correlation {
        peer_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
    };
    let object_id = *ObjectId::compute(&bytes).as_bytes();
    let mut outputs = Vec::new();
    for fragment in fragment_object(&bytes)? {
        let frame = CompanionFrame::Result {
            correlation,
            object_id,
            fragment,
        };
        outputs.extend(
            edge.on_result_frame(fixture.context_mut()?, frame)
                .map_err(|refusal| refusal.code.to_string())?,
        );
    }
    Ok(outputs)
}

/// Delivers the event as `EEVENT` fragments, and its ACK object as `EDATA`,
/// commits its batch and returns the lines it released.
fn deliver_event(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    open: &OpenEvent,
    ack: Option<&[u8]>,
) -> TestResult<Vec<ClientOutput>> {
    let mut base = base_edge();
    let bytes =
        ArcWireObject::new(ArcWireObjectKind::FederationEvent, open.event.encode()?)?.encode()?;
    let objects = [Some((bytes.as_slice(), false)), ack.map(|ack| (ack, true))];
    for (object, data) in objects.into_iter().flatten() {
        let object_id = *ObjectId::compute(object).as_bytes();
        for fragment in fragment_object(object)? {
            let released = edge
                .on_event_frame(
                    fixture.context_mut()?,
                    &mut base,
                    open.position,
                    object_id,
                    fragment,
                    data,
                )
                .map_err(|refusal| refusal.code.to_string())?;
            assert!(released.is_empty(), "nothing is released before the commit");
        }
    }
    fixture.context_mut()?.discard_pending_for_test();
    Ok(edge.batch_applied(fixture.context_mut()?, &mut base))
}

/// What a connection received when it was not exactly `line`, as one frame,
/// for the failure report of a whole case table.
fn mismatch(
    outputs: &[ClientOutput],
    generation: u64,
    line: &str,
    context: &str,
) -> TestResult<Option<String>> {
    let received: Vec<&WireMessage> = outputs
        .iter()
        .filter(|output| output.generation == ConnectionGeneration::new(generation))
        .flat_map(|output| output.frames.iter())
        .collect();
    let expected = WireMessage::extension_line(line)?;
    if received == [&expected] {
        return Ok(None);
    }
    let shown: Vec<(&str, &[String])> = received
        .iter()
        .map(|frame| (frame.command(), frame.middle()))
        .collect();
    Ok(Some(format!(
        "{context}: connection {generation} received {shown:?}"
    )))
}

/// The order in which the request's result and its completion arrive.
#[derive(Clone, Copy, Debug)]
enum Order {
    ResultFirst,
    CompletionFirst,
}

#[tokio::test]
async fn a_completed_request_reaches_its_requesting_connection_only_as_its_labeled_result()
-> TestResult {
    let mut failures = Vec::new();
    for order in [Order::ResultFirst, Order::CompletionFirst] {
        for case in &CASES {
            let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
            let mut edge = hosting_edge()?;
            edge.pending.insert(REQUEST, submission(case, REQUESTER));
            let ack = ack_object(case)?;
            let open = event(case, Some(REQUEST), ack.as_deref())?;
            let mut outputs = Vec::new();
            if matches!(order, Order::ResultFirst) {
                let early = deliver_result(&mut edge, &mut fixture, case)?;
                assert!(early.is_empty(), "{:?}: no completion yet", case.event);
            }
            outputs.extend(deliver_event(
                &mut edge,
                &mut fixture,
                &open,
                ack.as_deref(),
            )?);
            if matches!(order, Order::CompletionFirst) {
                outputs.extend(deliver_result(&mut edge, &mut fixture, case)?);
            }
            let context = format!("{:?} with {order:?}", case.event);
            failures.extend(mismatch(
                &outputs,
                REQUESTER,
                &labeled_scalar(case)?,
                &context,
            )?);
            let copy = untagged_copy(case, ack.as_deref())?;
            for sink in [PEER, SIBLING] {
                failures.extend(mismatch(&outputs, sink, &copy, &context)?);
            }
            if edge.pending.contains_key(&REQUEST) {
                failures.push(format!("{context}: the request is still held"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

#[tokio::test]
async fn the_untagged_copy_is_withheld_only_from_the_connection_whose_request_completes()
-> TestResult {
    let mut failures = Vec::new();
    for order in [Order::ResultFirst, Order::CompletionFirst] {
        for case in &CASES {
            let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
            let mut edge = hosting_edge()?;
            // The peer's request completes; the requester's own earlier
            // request of the same operation was answered `PENDING` and is
            // no longer held.
            edge.pending.insert(REQUEST, submission(case, PEER));
            let ack = ack_object(case)?;
            let open = event(case, Some(REQUEST), ack.as_deref())?;
            let mut outputs = Vec::new();
            if matches!(order, Order::ResultFirst) {
                let early = deliver_result(&mut edge, &mut fixture, case)?;
                assert!(early.is_empty(), "{:?}: no completion yet", case.event);
            }
            outputs.extend(deliver_event(
                &mut edge,
                &mut fixture,
                &open,
                ack.as_deref(),
            )?);
            if matches!(order, Order::CompletionFirst) {
                outputs.extend(deliver_result(&mut edge, &mut fixture, case)?);
            }
            let context = format!("{:?} with {order:?}", case.event);
            failures.extend(mismatch(&outputs, PEER, &labeled_scalar(case)?, &context)?);
            let copy = untagged_copy(case, ack.as_deref())?;
            for sink in [REQUESTER, SIBLING] {
                failures.extend(mismatch(&outputs, sink, &copy, &context)?);
            }
            if edge.pending.contains_key(&REQUEST) {
                failures.push(format!("{context}: the request is still held"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

#[tokio::test]
async fn an_event_that_completes_no_local_request_reaches_every_sink() -> TestResult {
    let mut failures = Vec::new();
    for case in &CASES {
        for request in [None, Some(UNKNOWN_REQUEST)] {
            let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
            let mut edge = hosting_edge()?;
            edge.pending.insert(REQUEST, submission(case, REQUESTER));
            let ack = ack_object(case)?;
            let open = event(case, request, ack.as_deref())?;
            let outputs = deliver_event(&mut edge, &mut fixture, &open, ack.as_deref())?;
            let context = format!("{:?} naming {request:?}", case.event);
            let copy = untagged_copy(case, ack.as_deref())?;
            for sink in [REQUESTER, PEER, SIBLING] {
                failures.extend(mismatch(&outputs, sink, &copy, &context)?);
            }
            // The held request is not this event's: it is still open.
            if !edge.pending.contains_key(&REQUEST) {
                failures.push(format!("{context}: the held request was retired"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}

#[tokio::test]
async fn a_barrier_completion_reaches_its_requesting_connection_only_as_its_labeled_result()
-> TestResult {
    let mut failures = Vec::new();
    for order in [Order::ResultFirst, Order::CompletionFirst] {
        for case in &CASES {
            let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
            let mut edge = hosting_edge()?;
            edge.pending.insert(REQUEST, submission(case, REQUESTER));
            let ack = ack_object(case)?;
            let mut open = event(case, Some(REQUEST), ack.as_deref())?;
            open.event.cross_profile_mutation_id = Opaque::new(MUTATION.to_vec())?;
            open.event.cross_profile_part_index = 1;
            open.event.cross_profile_part_count = 2;
            if matches!(order, Order::ResultFirst) {
                let early = deliver_result(&mut edge, &mut fixture, case)?;
                assert!(early.is_empty(), "{:?}: no completion yet", case.event);
            }
            edge.barrier_parts
                .insert(MUTATION, BTreeMap::from([(1, (open, ack.clone()))]));
            let (_, mut outputs) = edge
                .prepare_barrier(fixture.context_mut()?, &base_edge(), MUTATION)
                .map_err(|code| code.to_string())?;
            // Once the base edge's receipt stands, `barrier_outputs` commits
            // the completions the barrier prepared.
            for completion in std::mem::take(&mut edge.barrier_completions) {
                outputs.extend(edge.commit_completion(fixture.context_mut()?, completion));
            }
            if matches!(order, Order::CompletionFirst) {
                outputs.extend(deliver_result(&mut edge, &mut fixture, case)?);
            }
            let context = format!("{:?} in a barrier with {order:?}", case.event);
            failures.extend(mismatch(
                &outputs,
                REQUESTER,
                &labeled_scalar(case)?,
                &context,
            )?);
            let copy = untagged_copy(case, ack.as_deref())?;
            for sink in [PEER, SIBLING] {
                failures.extend(mismatch(&outputs, sink, &copy, &context)?);
            }
            if edge.pending.contains_key(&REQUEST) {
                failures.push(format!("{context}: the request is still held"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
    Ok(())
}
