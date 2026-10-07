//! A complete request decodes only under this profile and network, with a
//! correlation that repeats its envelope and a payload that hashes to the
//! identifier it declares; a request outside its origin's live sequence is a
//! violation.

#![forbid(unsafe_code)]

use super::*;

type RequestEdit = fn(&mut ArcFederationRequest, &mut Correlation);

fn complete_with(harness: &Harness, edit: RequestEdit) -> TestResult<CompleteRequest> {
    let request_id = harness.request_id()?;
    let mut request = ArcFederationRequest {
        profile_version: 1,
        network_id: NETWORK,
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        operation_sequence: harness.sequence,
        request_id,
        opcode: Op::Whoami,
        encoded_parameters: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(Vec::new())?,
    };
    let mut correlation = Correlation {
        peer_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        operation_sequence: harness.sequence,
        request_id,
    };
    edit(&mut request, &mut correlation);
    Ok(CompleteRequest {
        correlation,
        request: wire(ArcWireObjectKind::FederationRequest, &request)?,
        payload: None,
        refusal: None,
    })
}

#[test]
fn a_request_envelope_must_carry_this_profile_network_and_its_own_correlation() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let edits: [(&str, RequestEdit); 4] = [
        ("another profile", |request, _| request.profile_version = 2),
        ("another network", |request, _| request.network_id = [9; 32]),
        ("a correlation at another sequence", |_, correlation| {
            correlation.operation_sequence += 1
        }),
        ("a correlation for another request", |_, correlation| {
            correlation.request_id = [99; 16]
        }),
    ];
    for (name, edit) in edits {
        let complete = complete_with(&harness, edit)?;
        assert_eq!(
            request::decode(&harness.coordinator, &complete).err(),
            Some(E2eeReplyCode::InvalidFragment),
            "{name}"
        );
    }
    let honest = complete_with(&harness, |_, _| {})?;
    let decoded = request::decode(&harness.coordinator, &honest)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    assert_eq!(
        request::classify(&harness.coordinator.state, HOME, &decoded),
        Classified::Fresh
    );
    Ok(())
}

#[test]
fn a_payload_must_hash_to_the_identifier_the_request_declares() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let policy = wire(ArcWireObjectKind::Policy, &harness.operational_policy)?;
    let mut complete = harness.request(Op::SubmitPolicy, &conversation, Some(&policy))?;
    complete.payload = Some(vec![1, 2, 3]);
    assert_eq!(
        request::decode(&harness.coordinator, &complete).err(),
        Some(E2eeReplyCode::HashMismatch)
    );
    Ok(())
}

#[test]
fn a_request_from_a_fenced_suspended_or_regenerated_origin_is_a_violation() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let regenerated = complete_with(&harness, |request, correlation| {
        request.origin_generation = 1;
        correlation.origin_generation = 1;
    })?;
    let decoded = request::decode(&harness.coordinator, &regenerated)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    assert_eq!(
        request::classify(&harness.coordinator.state, HOME, &decoded),
        Classified::Violation,
        "another origin generation"
    );
    let honest = complete_with(&harness, |_, _| {})?;
    let decoded = request::decode(&harness.coordinator, &honest)
        .map_err(|code| format!("decode failed with {code:?}"))?;
    for (name, fenced, suspended) in [("fenced", true, false), ("suspended", false, true)] {
        let origin = harness
            .coordinator
            .state
            .origins
            .get_mut(&origin_key())
            .ok_or("origin")?;
        origin.fenced = fenced;
        origin.suspended = suspended;
        assert_eq!(
            request::classify(&harness.coordinator.state, HOME, &decoded),
            Classified::Violation,
            "{name}"
        );
        let origin = harness
            .coordinator
            .state
            .origins
            .get_mut(&origin_key())
            .ok_or("origin")?;
        origin.fenced = false;
        origin.suspended = false;
    }
    assert_eq!(
        request::classify(&harness.coordinator.state, HOME, &decoded),
        Classified::Fresh
    );
    Ok(())
}
