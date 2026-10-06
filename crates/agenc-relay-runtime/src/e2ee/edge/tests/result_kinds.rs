#![forbid(unsafe_code)]

//! Every result kind keeps its own 11.7 line (companion 12.5 maps each
//! selector one-to-one): the three- and four-identifier tuples that `ACKED`,
//! `ABORTED` and the four ReInit results share render by their kind when the
//! completion was already applied, when it arrives after the result, on a
//! retry of the same submission, and in a batch, never as another kind.

use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_relay_e2ee::limits::WIRE_OBJECT_ENVELOPE_BYTES;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{
    ArcFederationEvent, ArcFederationEventKind, ArcFederationResponseDescriptor,
    ArcFederationResult, ArcFederationResultKind as K,
};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};
use agenc_relay_e2ee::wire::command::{EgroupCommand, SubmitKind};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_e2ee::wire::tokens::base64url_encode;

use super::super::ClientOutput;
use super::super::result::{DecodedResult, ResultValue};
use super::*;
use crate::test_support::StateCoreFixture;

const REQUEST: [u8; 16] = [5; 16];
const LABEL: &str = "kind";
const COMPLETION: [u8; 16] = [11; 16];
const IDS: [[u8; 32]; 4] = [[21; 32], [22; 32], [23; 32], [24; 32]];

/// One submission, the result kind that answers it, its tuple width, and
/// the token the 11.7 grammar gives the requester's labeled line.
struct Case {
    submit: SubmitKind,
    kind: K,
    width: usize,
    token: &'static str,
}

const CASES: [Case; 6] = [
    Case {
        submit: SubmitKind::Ack,
        kind: K::CommitAcked,
        width: 3,
        token: "ACKED",
    },
    Case {
        submit: SubmitKind::Abort,
        kind: K::Aborted,
        width: 4,
        token: "ABORTED",
    },
    Case {
        submit: SubmitKind::ReinitAttempt,
        kind: K::ReinitStaged,
        width: 3,
        token: "REINIT-STAGED",
    },
    Case {
        submit: SubmitKind::ReinitAck,
        kind: K::ReinitAcked,
        width: 3,
        token: "REINIT-ACKED",
    },
    Case {
        submit: SubmitKind::ReinitActivate,
        kind: K::ReinitActivated,
        width: 4,
        token: "REINIT-ACTIVATED",
    },
    Case {
        submit: SubmitKind::ReinitAbort,
        kind: K::ReinitAborted,
        width: 4,
        token: "REINIT-ABORTED",
    },
];

/// The exact labeled line companion 11.7 specifies for `case`.
fn expected(case: &Case, label: &str) -> String {
    let ids: Vec<String> = IDS
        .iter()
        .take(case.width)
        .map(|id| base64url_encode(id))
        .collect();
    format!(
        "@label={label} :edge.example EGROUP {} {}\r\n",
        case.token,
        ids.join(" ")
    )
}

/// The labeled submission `case` answers, cached for retries under `key`.
fn submission(case: &Case, key: Option<(u64, u64, [u8; 32], [u8; 32])>) -> PendingRequest {
    let mut request = pending(1, 0, false);
    request.label = Some(LABEL.to_owned());
    request.reply_key = key;
    request.command = Resolved::Command(ClientCommand::Egroup(EgroupCommand::Submit {
        kind: case.submit,
        conversation_id: IDS[0],
    }));
    request
}

/// The `federation_result` object the coordinator sends for `case`, naming
/// its completion event.
fn result_object(case: &Case) -> TestResult<Vec<u8>> {
    let tuple: Vec<u8> = IDS.iter().take(case.width).flatten().copied().collect();
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
        completion_event_id: Opaque::new(COMPLETION.to_vec())?,
        result_kind: case.kind,
        encoded_result: Opaque::new(tuple)?,
        snapshot_token: Opaque::new(Vec::new())?,
        next_cursor: Opaque::new(Vec::new())?,
        responses: TlsVec::new(Vec::new())?,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationResult, result.encode()?)?.encode()?)
}

/// Delivers `bytes` as the request's `ERESULT` fragments.
fn receive(
    edge: &mut E2eeEdge,
    fixture: &mut StateCoreFixture,
    bytes: &[u8],
) -> TestResult<Vec<ClientOutput>> {
    let correlation = Correlation {
        peer_server_id: [2; 16],
        server_incarnation: [4; 16],
        origin_id: [8; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: REQUEST,
    };
    let object_id = *ObjectId::compute(bytes).as_bytes();
    let mut outputs = Vec::new();
    for fragment in fragment_object(bytes)? {
        let frame = CompanionFrame::Result {
            correlation,
            object_id,
            fragment,
        };
        outputs.extend(
            edge.on_result_frame(fixture.context_mut()?, frame)
                .map_err(|error| error.code.to_string())?,
        );
    }
    Ok(outputs)
}

/// The completion event of the request, applied after its result.
fn completion_event() -> TestResult<ArcFederationEvent> {
    Ok(ArcFederationEvent {
        profile_version: 1,
        network_id: [1; 32],
        target_server_id: [2; 16],
        delivery_generation: 1,
        coordinator_state_generation: 1,
        delivery_sequence: 1,
        event_id: COMPLETION,
        event_kind: ArcFederationEventKind::RequestCompleted,
        cross_profile_mutation_id: Opaque::new(Vec::new())?,
        cross_profile_part_index: 0,
        cross_profile_part_count: 0,
        conversation_id: Opaque::new(IDS[0].to_vec())?,
        route_sequence: 0,
        origin_id: Opaque::new(Vec::new())?,
        origin_generation: 0,
        source_view: Opaque::new(Vec::new())?,
        request_home_server_id: Opaque::new(vec![2; 16])?,
        request_server_incarnation: Opaque::new(vec![4; 16])?,
        request_origin_id: Opaque::new(vec![8; 16])?,
        request_origin_generation: 0,
        request_operation_sequence: 0,
        request_id: Opaque::new(REQUEST.to_vec())?,
        payload_object_id: Opaque::new(Vec::new())?,
        encoded_event_result: Opaque::new(Vec::new())?,
    })
}

/// Requires `outputs` to be exactly the labeled line companion 11.7 gives
/// `case`: one output of one `EGROUP <token>` frame.
fn assert_only_line(outputs: &[ClientOutput], case: &Case, label: &str) -> TestResult {
    let [output] = outputs else {
        return Err(format!("{}: expected one output, got {}", case.token, outputs.len()).into());
    };
    let [frame] = output.frames.as_slice() else {
        return Err(format!(
            "{}: expected one line, got {}",
            case.token,
            output.frames.len()
        )
        .into());
    };
    assert_eq!(frame.command(), "EGROUP", "{}", case.token);
    assert_eq!(
        frame.middle().first().map(String::as_str),
        Some(case.token),
        "{}",
        case.token
    );
    assert_eq!(
        *frame,
        agenc_relay_client_wire::WireMessage::extension_line(&expected(case, label))?,
        "{}",
        case.token
    );
    Ok(())
}

#[test]
fn a_result_whose_completion_was_applied_renders_its_own_kind() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for case in &CASES {
        let mut edge = edge();
        edge.pending.insert(REQUEST, submission(case, None));
        edge.covered.insert(COMPLETION);
        let outputs = receive(&mut edge, &mut fixture, &result_object(case)?)?;
        assert_only_line(&outputs, case, LABEL)?;
    }
    Ok(())
}

#[test]
fn a_completion_after_the_result_renders_its_own_kind() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for case in &CASES {
        let mut edge = edge();
        edge.pending.insert(REQUEST, submission(case, None));
        assert!(
            receive(&mut edge, &mut fixture, &result_object(case)?)?.is_empty(),
            "{}: nothing renders before the completion",
            case.token
        );
        let (prepared, outputs) = edge
            .prepare_completion(fixture.context_mut()?, &completion_event()?)
            .map_err(|error| error.code.to_string())?;
        assert_only_line(&outputs, case, LABEL)?;
        assert!(
            edge.commit_completion(fixture.context_mut()?, prepared)
                .is_empty()
        );
        assert!(!edge.pending.contains_key(&REQUEST));
    }
    Ok(())
}

#[test]
fn a_retried_submission_replays_its_own_kind() -> TestResult {
    let key = (1, 0, IDS[0], [7; 32]);
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for case in &CASES {
        let mut edge = edge();
        let request = submission(case, Some(key));
        let command = request.command.clone();
        edge.pending.insert(REQUEST, request);
        edge.covered.insert(COMPLETION);
        receive(&mut edge, &mut fixture, &result_object(case)?)?;
        let replay = edge
            .replies
            .replay(key, &command, Some("retry"))
            .map_err(|error| error.code.to_string())?
            .ok_or("the completed reply is cached")?;
        assert_only_line(&[replay], case, "retry")?;
    }
    Ok(())
}

#[test]
fn a_tuple_under_a_kind_that_does_not_own_it_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut edge = edge();
    let request = submission(&CASES[0], None);
    for (kind, value) in [
        (K::Aborted, ResultValue::Triple(IDS[0], IDS[1], IDS[2])),
        (K::Bound, ResultValue::Triple(IDS[0], IDS[1], IDS[2])),
        (
            K::CommitAcked,
            ResultValue::Quad(IDS[0], IDS[1], IDS[2], IDS[3]),
        ),
        (
            K::Finalized,
            ResultValue::Quad(IDS[0], IDS[1], IDS[2], IDS[3]),
        ),
    ] {
        let result = DecodedResult {
            request_object_id: [7; 32],
            kind,
            value,
            completion_event_id: None,
            snapshot_token: None,
            next_cursor: None,
            descriptors: Vec::new(),
        };
        let refusal = edge
            .render_answer(fixture.context_mut()?, &request, &result)
            .err()
            .map(|refusal| refusal.code);
        assert_eq!(refusal, Some(E2eeReplyCode::InvalidFragment), "{kind:?}");
    }
    Ok(())
}

#[test]
fn only_an_aborted_tuple_names_an_aborted_batch_child() -> TestResult {
    let object = ArcWireObject::new(
        ArcWireObjectKind::RootIdentity,
        vec![3; 40 - WIRE_OBJECT_ENVELOPE_BYTES],
    )?
    .encode()?;
    let descriptor = ArcFederationResponseDescriptor {
        response_index: 0,
        wire_kind: ArcWireObjectKind::RootIdentity,
        object_id: *ObjectId::compute(&object).as_bytes(),
        total_size: u32::try_from(object.len())?,
        delivery_token: Opaque::new(Vec::new())?,
        target_device_id: Opaque::new(Vec::new())?,
    };
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    for (kind, child) in [
        (K::Aborted, true),
        (K::ReinitActivated, false),
        (K::ReinitAborted, false),
    ] {
        let mut edge = edge();
        let mut request = submission(&CASES[1], None);
        request.responses.insert(0, object.clone());
        let result = DecodedResult {
            request_object_id: [7; 32],
            kind,
            value: ResultValue::Quad(IDS[0], IDS[1], IDS[2], IDS[3]),
            completion_event_id: None,
            snapshot_token: Some([9; 32]),
            next_cursor: None,
            descriptors: vec![descriptor.clone()],
        };
        let lines = edge
            .render_answer(fixture.context_mut()?, &request, &result)
            .map_err(|error| error.code.to_string())?;
        let aborted = lines
            .iter()
            .filter(|line| line.contains(" EGROUP ABORTED "))
            .count();
        assert_eq!(aborted, usize::from(child), "{kind:?}: {lines:?}");
        assert!(
            lines.iter().any(|line| line.contains(" BATCH -")),
            "{lines:?}"
        );
    }
    Ok(())
}
