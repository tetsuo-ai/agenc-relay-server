//! Retained result descriptors cannot outlive their required response bytes.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::request::{Classified, ResponseObject, ResultBody};
use crate::e2ee::coordinator::tests::support::{capabilities, principal};

fn retained_page() -> TestResult<(CompanionCoordinator, Decoded, Vec<Vec<u8>>)> {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let mut decoded = decoded(0, 0)?;
    let account = agenc_ircd_types::AccountId::from_random(
        agenc_ircd_types::AccountRandomId::from_bytes([30; 16]),
    )
    .to_text();
    let identity = principal(30, &account.as_bytes().try_into()?, &[31, 32, 33])?;
    let mut parameters = vec![24];
    parameters.extend_from_slice(account.as_bytes());
    parameters.push(0);
    decoded.request.opcode = IrcFederationOpcode::FetchCapabilities;
    decoded.request.encoded_parameters = Opaque::new(parameters)?;
    let request_bytes = IrcWireObject::new(
        IrcWireObjectKind::FederationRequest,
        decoded.request.encode()?,
    )?
    .encode()?;
    decoded.request_object_id = *agenc_ircd_e2ee::ObjectId::compute(&request_bytes).as_bytes();
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some([19; 32]);
    let mut responses = Vec::new();
    for seed in [31, 32, 33] {
        let capability = capabilities(seed, &identity.roster, 0, [0; 32], (100, 1000), vec![1])?;
        let bytes =
            IrcWireObject::new(IrcWireObjectKind::DeviceCapabilities, capability.encode()?)?
                .encode()?;
        responses.push(bytes.clone());
        outcome.responses.push(ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        });
    }
    let staged = assemble(
        &coordinator,
        HOME,
        ServerId::from_bytes(HOME),
        &decoded,
        outcome,
        1,
        500,
        BarrierInputs {
            backing: backing(),
            base_counts: None,
            base_capacity: &|_, _, _| true,
            entropy: &mut Entropy,
        },
    )
    .map_err(|code| format!("assemble: {code:?}"))?;
    for effect in staged.effects {
        effect(&mut coordinator.state);
    }
    Ok((coordinator, decoded, responses))
}

#[test]
fn replay_refuses_any_missing_response_without_renumbering_the_rest() -> TestResult {
    for missing in 0..3 {
        let (mut coordinator, decoded, responses) = retained_page()?;
        let bytes = responses.get(missing).ok_or("missing fixture response")?;
        let id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
        assert!(coordinator.state.objects.remove(&id).is_some());
        assert!(
            matches!(
                request::classify(&coordinator.state, HOME, &decoded),
                Classified::Violation
            ),
            "replay accepted a retained result with response {missing} absent"
        );
    }
    Ok(())
}

#[test]
fn complete_replay_preserves_original_response_order_and_bytes() -> TestResult {
    let (coordinator, decoded, responses) = retained_page()?;
    let Classified::Replay(result, replayed) =
        request::classify(&coordinator.state, HOME, &decoded)
    else {
        return Err("complete replay was refused".into());
    };
    assert_eq!(replayed, responses);
    assert_eq!(
        result,
        coordinator
            .state
            .results
            .get(&decoded.request_object_id)
            .ok_or("result")?
            .result
    );
    Ok(())
}

#[test]
fn empty_replay_has_no_required_response_objects() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    let staged = batch(&coordinator, &decoded)?;
    for effect in staged.effects {
        effect(&mut coordinator.state);
    }
    let Classified::Replay(_, responses) = request::classify(&coordinator.state, HOME, &decoded)
    else {
        return Err("empty result replay was refused".into());
    };
    assert!(responses.is_empty());
    Ok(())
}

fn recent_correlation(decoded: &Decoded) -> Correlation {
    Correlation {
        peer_server_id: COORDINATOR,
        server_incarnation: decoded.request.server_incarnation,
        origin_id: decoded.request.origin_id,
        origin_generation: decoded.request.origin_generation,
        operation_sequence: decoded.request.operation_sequence,
        request_id: decoded.request.request_id,
    }
}

#[test]
fn recent_fragment_replay_refuses_every_missing_response_before_emitting_lines() -> TestResult {
    for missing in 0..3 {
        let (mut coordinator, decoded, responses) = retained_page()?;
        let bytes = responses.get(missing).ok_or("response")?;
        let id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
        assert!(coordinator.state.objects.remove(&id).is_some());
        let result = coordinator.replay_recent(
            ServerId::from_bytes(HOME),
            &recent_correlation(&decoded),
            decoded.request_object_id,
        );
        assert!(
            result.is_err(),
            "recent-fragment replay emitted a partial result with response {missing} absent"
        );
    }
    Ok(())
}

#[test]
fn recent_fragment_replay_preserves_all_three_response_indices_and_object_ids() -> TestResult {
    use crate::federation::link::{ParsedLine, parse_line};
    let (coordinator, decoded, responses) = retained_page()?;
    let actions = coordinator.replay_recent(
        ServerId::from_bytes(HOME),
        &recent_correlation(&decoded),
        decoded.request_object_id,
    )?;
    let [super::super::super::sync::Action::Send(lines)] = actions.as_slice() else {
        return Err("recent replay did not return lines".into());
    };
    let mut returned = BTreeMap::new();
    for line in lines {
        if let ParsedLine::Companion(CompanionFrame::Response {
            response_index,
            object_id,
            ..
        }) = parse_line(
            line.as_str().strip_suffix("\r\n").ok_or("line ending")?,
            "coordinator.example",
        )
        .map_err(|e| format!("line: {e:?}"))?
        {
            assert!(
                returned
                    .insert(response_index, object_id)
                    .is_none_or(|previous| previous == object_id)
            );
        }
    }
    assert_eq!(returned.len(), 3);
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(
            returned.get(&u16::try_from(index)?),
            Some(agenc_ircd_e2ee::ObjectId::compute(response).as_bytes())
        );
    }
    Ok(())
}

#[test]
fn recent_fragment_replay_accepts_a_result_with_no_required_response_objects() -> TestResult {
    let mut coordinator = coordinator();
    declare(&mut coordinator, 0)?;
    let decoded = decoded(0, 0)?;
    for effect in batch(&coordinator, &decoded)?.effects {
        effect(&mut coordinator.state);
    }
    let actions = coordinator.replay_recent(
        ServerId::from_bytes(HOME),
        &recent_correlation(&decoded),
        decoded.request_object_id,
    )?;
    let [super::super::super::sync::Action::Send(lines)] = actions.as_slice() else {
        return Err("empty-result replay did not return lines".into());
    };
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|line| line.as_str().contains(" ERESULT ")));
    Ok(())
}
