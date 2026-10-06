#![forbid(unsafe_code)]

//! Requester response association and retained output memory boundaries.

use super::*;
use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
use crate::federation::codec::results::ResultArm;
use crate::test_support::TestResult;
use agenc_relay_federation_wire::{RequestCorrelation, RequestHeader};
use agenc_relay_types::{OriginId, ServerId, ServerIncarnation};

fn echo(
    budget: &MemoryBudget,
    name: &str,
    seed: u8,
) -> Result<JoinEcho, Box<dyn core::error::Error>> {
    let charge = MemoryCharge::allocation(u64::try_from(ECHO_BACKING_BYTES)?)?;
    let permit = budget
        .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
        .split_exact(charge.bytes())
        .ok_or("echo permit")?;
    let mut frame = WireMessage::new(
        "sam!public@cloak",
        "JOIN",
        &[name, "sam-account"],
        Some("Sam Real"),
    )?;
    frame.add_server_tag("account", Some("sam-account"))?;
    Ok(JoinEcho {
        request: RequestId::from_bytes([1; 16]),
        replay_key: ReplayKey {
            home_server_id: ServerId::from_bytes([2; 16]),
            server_incarnation: ServerIncarnation::from_bytes([3; 16]),
            origin_id: OriginId::from_bytes([4; 16]),
            origin_generation: 5,
            operation_sequence: 6,
        },
        state_generation: 7,
        channel: ChannelInstanceId::from_bytes([seed; 16]),
        frame,
        permit,
    })
}

fn topic(name: &str) -> Result<WireMessage, Box<dyn core::error::Error>> {
    Ok(agenc_relay_client_wire::numeric_reply(
        "edge.test",
        331,
        "sam",
        &[name],
        Some("No topic is set"),
    )?)
}

#[test]
fn exact_echoes_and_their_backing_survive_until_response_delivery() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let echoes = vec![echo(&budget, "#one", 1)?, echo(&budget, "#two", 2)?];
    let mut expected = Vec::new();
    for name in ["#one", "#two"] {
        let mut frame = WireMessage::new(
            "sam!public@cloak",
            "JOIN",
            &[name, "sam-account"],
            Some("Sam Real"),
        )?;
        frame.add_server_tag("account", Some("sam-account"))?;
        expected.push(frame);
    }
    let charge = budget.charged();
    assert!(charge >= 2 * u64::try_from(ECHO_BACKING_BYTES)?);
    let (frames, permits) = into_frames(7, echoes, vec![topic("#ONE")?, topic("#two")?])
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        frames.get(..2).ok_or("missing JOIN echoes")?,
        expected.as_slice()
    );
    assert_eq!(
        frames.iter().map(WireMessage::command).collect::<Vec<_>>(),
        ["JOIN", "JOIN", "331", "331"]
    );
    assert_eq!(permits.len(), 2);
    assert_eq!(budget.charged(), charge);
    drop(frames);
    drop(permits);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn inconsistent_echo_targets_and_generations_release_all_backing() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    for names in [["#one", "#wrong"], ["#one", "#one"]] {
        let echoes = vec![echo(&budget, "#one", 1)?, echo(&budget, "#two", 2)?];
        assert!(into_frames(7, echoes, vec![topic(names[0])?, topic(names[1])?]).is_err());
        assert_eq!(budget.charged(), 0);
    }
    assert!(into_frames(8, vec![echo(&budget, "#one", 1)?], vec![topic("#one")?]).is_err());
    assert_eq!(budget.charged(), 0);
    assert!(into_frames(7, Vec::new(), vec![topic("#one")?]).is_err());
    assert!(into_frames(7, vec![echo(&budget, "#one", 1)?], Vec::new()).is_err());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn an_echo_cannot_be_covered_by_a_failure_or_another_generation() -> TestResult {
    let budget = MemoryBudget::new(1 << 20);
    let echo = echo(&budget, "#one", 1)?;
    let request = echo.request;
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Committed {
                resulting_state_generation: 7
            }
        )
        .is_ok()
    );
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Committed {
                resulting_state_generation: 8
            }
        )
        .is_err()
    );
    assert!(
        check_result(
            &echo,
            request,
            &ResultArm::Failed {
                code: "UNAVAILABLE".to_owned(),
                context: String::new()
            }
        )
        .is_err()
    );
    assert!(check_result(&echo, request, &ResultArm::NoContent).is_err());
    assert!(
        check_result(
            &echo,
            RequestId::from_bytes([9; 16]),
            &ResultArm::Committed {
                resulting_state_generation: 8
            }
        )
        .is_ok()
    );
    Ok(())
}

/// An active edge whose one pending request is the JOIN `command`.
fn edge_with_pending(command: &str, header: RequestHeader) -> TestResult<EdgeFederation> {
    use agenc_relay_client_wire::{FramedLine, parse_message};
    let mut edge = EdgeFederation::new(crate::federation::edge::EdgeConfig {
        network_id: agenc_relay_types::NetworkId::from_bytes([31; 32]),
        server_id: ServerId::from_bytes([2; 16]),
        server_name: "edge.example".to_owned(),
        incarnation: ServerIncarnation::from_bytes([3; 16]),
        coordinator: crate::federation::PeerIdentity::new(
            ServerId::from_bytes([90; 16]),
            "hub.example",
            crate::federation::FederationRole::Coordinator,
            agenc_relay_types::RecoveryEpoch::from_bytes([91; 16]),
            agenc_relay_crypto::Ed25519SecretKey::from_bytes([12; 32]).public_key(),
            [13; 32],
        ),
    });
    let message = parse_message(FramedLine::new(command)?)?.ok_or("command")?;
    edge.pending.insert(
        header.request_id,
        PendingRequest {
            generation: ConnectionGeneration::new(1),
            sink_gone: false,
            kind: PendingKind::Command {
                message: Box::new(message),
            },
            header,
            bytes: Vec::new(),
            sent: true,
            result: None,
            result_bytes: Vec::new(),
            replies: Vec::new(),
            join_echoes: Vec::new(),
            message_echoes: Vec::new(),
            completion: None,
            completion_generation: None,
            completion_coverage: None,
        },
    );
    Ok(edge)
}

fn join_header(echo: &JoinEcho, opcode: agenc_relay_types::FederationOpcode) -> RequestHeader {
    RequestHeader {
        network_id: agenc_relay_types::NetworkId::from_bytes([31; 32]),
        replay_key: echo.replay_key,
        request_id: echo.request,
        opcode,
    }
}

#[test]
fn a_committed_echo_is_kept_only_by_its_own_live_join_request() -> TestResult {
    use agenc_relay_types::FederationOpcode;
    let budget = MemoryBudget::new(1 << 20);
    let probe = echo(&budget, "#one", 1)?;
    let header = join_header(&probe, FederationOpcode::Join);

    // No such request: the echo is dropped without a fault.
    let mut edge = edge_with_pending("JOIN #one", header)?;
    edge.pending.clear();
    assert!(committed(&mut edge, echo(&budget, "#one", 1)?).is_ok());

    // The client left: the echo is dropped without a fault.
    let mut edge = edge_with_pending("JOIN #one", header)?;
    edge.pending
        .get_mut(&probe.request)
        .ok_or("pending")?
        .sink_gone = true;
    assert!(committed(&mut edge, echo(&budget, "#one", 1)?).is_ok());

    // The request is not a JOIN.
    let mut edge = edge_with_pending("PART #one", join_header(&probe, FederationOpcode::Part))?;
    assert!(committed(&mut edge, echo(&budget, "#one", 1)?).is_err());

    // The request carries another replay key.
    let mut edge = edge_with_pending("JOIN #one", header)?;
    edge.pending
        .get_mut(&probe.request)
        .ok_or("pending")?
        .header
        .replay_key
        .operation_sequence = 99;
    assert!(committed(&mut edge, echo(&budget, "#one", 1)?).is_err());

    // The same channel twice, then the echo ceiling.
    let mut edge = edge_with_pending("JOIN #one", header)?;
    committed(&mut edge, echo(&budget, "#one", 1)?).map_err(|e| format!("{e:?}"))?;
    assert!(committed(&mut edge, echo(&budget, "#one", 1)?).is_err());
    for seed in 2..MAX_JOIN_ECHOES {
        let seed = u8::try_from(seed)?;
        committed(&mut edge, echo(&budget, "#one", seed)?).map_err(|e| format!("{e:?}"))?;
    }
    assert_eq!(
        edge.pending
            .get(&probe.request)
            .ok_or("pending")?
            .join_echoes
            .len(),
        MAX_JOIN_ECHOES - 1
    );
    committed(&mut edge, echo(&budget, "#one", 200)?).map_err(|e| format!("{e:?}"))?;
    assert!(
        committed(&mut edge, echo(&budget, "#one", 201)?).is_err(),
        "the echo over the ceiling is refused"
    );
    assert!(budget.charged() > 0);
    Ok(())
}

fn completion_header(correlation: Option<RequestCorrelation>, generation: u64) -> EventHeader {
    EventHeader {
        network_id: agenc_relay_types::NetworkId::from_bytes([31; 32]),
        target_server_id: ServerId::from_bytes([2; 16]),
        projection_generation: 1,
        coordinator_state_generation: generation,
        delivery_sequence: 3,
        event_id: agenc_relay_types::EventId::from_bytes([41; 16]),
        event_kind: agenc_relay_types::FederationEventKind::SessionVisible,
        correlation,
        cross_profile: None,
    }
}

#[test]
fn a_tentative_echo_must_extend_its_live_join_without_repeating_a_channel() -> TestResult {
    use agenc_relay_types::FederationOpcode;
    let budget = MemoryBudget::new(1 << 20);
    let probe = echo(&budget, "#one", 1)?;
    let header = join_header(&probe, FederationOpcode::Join);
    let none = std::collections::BTreeSet::new();
    let edge = edge_with_pending("JOIN #one", header)?;
    assert_eq!(validate_tentative(&edge, &[], &probe, &none), Ok(()));

    let mut unknown = edge_with_pending("JOIN #one", header)?;
    unknown.pending.clear();
    assert_eq!(
        validate_tentative(&unknown, &[], &probe, &none),
        Err(Violation::Consistency),
        "no such request"
    );
    let completed = std::collections::BTreeSet::from([probe.request]);
    assert_eq!(
        validate_tentative(&edge, &[], &probe, &completed),
        Err(Violation::Consistency),
        "the request already completed in this batch"
    );
    let mut covered = edge_with_pending("JOIN #one", header)?;
    covered
        .pending
        .get_mut(&probe.request)
        .ok_or("pending")?
        .completion_generation = Some(7);
    assert_eq!(
        validate_tentative(&covered, &[], &probe, &none),
        Err(Violation::Consistency),
        "the request already has its completion"
    );

    let same_channel = echo(&budget, "#one", 1)?;
    let mut other_generation = echo(&budget, "#two", 2)?;
    other_generation.state_generation = 8;
    let mut other_replay = echo(&budget, "#two", 2)?;
    other_replay.replay_key.operation_sequence = 99;
    for (name, prior) in [
        ("same channel", same_channel),
        ("another generation", other_generation),
        ("another replay key", other_replay),
    ] {
        assert_eq!(
            validate_tentative(&edge, &[prior], &probe, &none),
            Err(Violation::Consistency),
            "{name}"
        );
    }
    let foreign = {
        let mut foreign = echo(&budget, "#two", 2)?;
        foreign.request = RequestId::from_bytes([9; 16]);
        foreign
    };
    assert_eq!(
        validate_tentative(&edge, &[foreign], &probe, &none),
        Ok(()),
        "another request's tentative echo is not counted"
    );

    let mut full = edge_with_pending("JOIN #one", header)?;
    let pending = full.pending.get_mut(&probe.request).ok_or("pending")?;
    for seed in 0..MAX_JOIN_ECHOES {
        pending
            .join_echoes
            .push(echo(&budget, "#one", u8::try_from(seed + 10)?)?);
    }
    assert_eq!(
        validate_tentative(&full, &[], &probe, &none),
        Err(Violation::Ceiling),
        "the echo ceiling"
    );
    Ok(())
}

#[test]
fn a_completion_must_correlate_to_its_join_and_every_echo_of_it() -> TestResult {
    use agenc_relay_types::FederationOpcode;
    let budget = MemoryBudget::new(1 << 20);
    let probe = echo(&budget, "#one", 1)?;
    let header = join_header(&probe, FederationOpcode::Join);
    let correlation = RequestCorrelation {
        replay_key: probe.replay_key,
        request_id: probe.request,
    };
    let edge = edge_with_pending("JOIN #one", header)?;
    assert_eq!(
        validate_completion(&edge, &[], &completion_header(Some(correlation), 7)),
        Ok(())
    );
    assert_eq!(
        validate_completion(&edge, &[], &completion_header(None, 7)),
        Err(Violation::Consistency),
        "no correlation"
    );
    let mut unknown = correlation;
    unknown.request_id = RequestId::from_bytes([9; 16]);
    assert_eq!(
        validate_completion(&edge, &[], &completion_header(Some(unknown), 7)),
        Err(Violation::Consistency),
        "unknown request"
    );
    let mut other_replay = correlation;
    other_replay.replay_key.operation_sequence = 99;
    assert_eq!(
        validate_completion(&edge, &[], &completion_header(Some(other_replay), 7)),
        Err(Violation::Consistency),
        "another replay key"
    );
    let mut later = echo(&budget, "#two", 2)?;
    later.state_generation = 8;
    assert_eq!(
        validate_completion(&edge, &[later], &completion_header(Some(correlation), 7)),
        Err(Violation::Consistency),
        "a tentative echo from another generation"
    );
    let mut committed_edge = edge_with_pending("JOIN #one", header)?;
    let mut stale = echo(&budget, "#two", 2)?;
    stale.replay_key.origin_generation = 6;
    committed_edge
        .pending
        .get_mut(&probe.request)
        .ok_or("pending")?
        .join_echoes
        .push(stale);
    assert_eq!(
        validate_completion(
            &committed_edge,
            &[],
            &completion_header(Some(correlation), 7)
        ),
        Err(Violation::Consistency),
        "a committed echo under another replay key"
    );
    Ok(())
}
