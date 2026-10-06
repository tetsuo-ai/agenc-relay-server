#![forbid(unsafe_code)]

//! Which copy of a delivered message a labeled request holds for its one
//! response, when a held copy is refused, and how the held copies become
//! that response.

use super::*;
use crate::federation::edge::EdgeConfig;
use crate::test_support::{StateCoreFixture, TestResult, negotiated_capabilities};
use agenc_relay_client_wire::{FramedLine, parse_message};
use agenc_relay_domain::federation::{DeliveredMessageRecord, DeliveryTarget, SourceView};
use agenc_relay_domain::{MessageKind, NicknameValue};
use agenc_relay_federation_wire::{ReplayKey, RequestHeader};
use agenc_relay_types::{
    ChannelInstanceId, FederationEventKind, MessageId, NetworkId, OriginId, RequestId, Revision,
    ServerId, ServerIncarnation,
};

const NETWORK: NetworkId = NetworkId::from_bytes([31; 32]);
const SENDER: UserId = UserId::from_bytes([5; 16]);
const CONNECTION: ConnectionGeneration = ConnectionGeneration::new(1);
const REQUEST: RequestId = RequestId::from_bytes([1; 16]);
const GENERATION: u64 = 7;

/// An edge whose one pending request is `command`, sent by `CONNECTION`
/// under `opcode`.
fn edge_with(command: &str, opcode: FederationOpcode) -> TestResult<EdgeFederation> {
    let mut edge = EdgeFederation::new(EdgeConfig {
        network_id: NETWORK,
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
        REQUEST,
        PendingRequest {
            generation: CONNECTION,
            sink_gone: false,
            kind: PendingKind::Command {
                message: Box::new(message),
            },
            header: RequestHeader {
                network_id: NETWORK,
                replay_key: ReplayKey {
                    home_server_id: ServerId::from_bytes([2; 16]),
                    server_incarnation: ServerIncarnation::from_bytes([3; 16]),
                    origin_id: OriginId::from_bytes([4; 16]),
                    origin_generation: 5,
                    operation_sequence: 6,
                },
                request_id: REQUEST,
                opcode,
            },
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

/// The labeled channel message most cases send.
fn labeled_message() -> TestResult<EdgeFederation> {
    edge_with("@label=m1 PRIVMSG #edge :hi", FederationOpcode::Message)
}

/// A message `SENDER` sent to a channel.
fn delivered() -> TestResult<ProjectedEvent> {
    Ok(ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
        message_id: MessageId::from_bytes([3; 16]),
        kind: MessageKind::Privmsg,
        target: DeliveryTarget::Channel(ChannelInstanceId::from_bytes([4; 16])),
        sender: SourceView {
            user_id: SENDER,
            nickname: NicknameValue::parse("sam")?,
            public_cloak: agenc_relay_testkit::deterministic_cloak(1)?,
            account_label: None,
        },
        target_revision: Revision::new(2)?,
        channel_event_sequence: GENERATION,
        received_unix_milliseconds: 1,
        tags: Vec::new(),
        body: "hi".to_owned(),
    }))
}

/// The header of the event `event` at the coordinator state `generation`.
fn header(event: u8, generation: u64) -> EventHeader {
    EventHeader {
        network_id: NETWORK,
        target_server_id: ServerId::from_bytes([2; 16]),
        projection_generation: 1,
        coordinator_state_generation: generation,
        delivery_sequence: u64::from(event),
        event_id: EventId::from_bytes([event; 16]),
        event_kind: FederationEventKind::MessageDelivered,
        correlation: None,
        cross_profile: None,
    }
}

/// The one copy the renderer produced for the sender.
fn copy(text: &str) -> TestResult<Vec<WireMessage>> {
    Ok(vec![WireMessage::new(
        "sam!u-a@h-b.invalid",
        "PRIVMSG",
        &["#edge"],
        Some(text),
    )?])
}

fn labeled() -> TestResult<CapabilityState> {
    negotiated_capabilities(&["message-tags", "batch", "labeled-response", "echo-message"])
}

fn held(edge: &EdgeFederation) -> TestResult<usize> {
    Ok(edge
        .pending
        .get(&REQUEST)
        .ok_or("pending")?
        .message_echoes
        .len())
}

/// The bytes the fixture's memory budget has charged.
fn charged(context: &StateCoreContext) -> u64 {
    context.backing_budget_for_test().charged()
}

fn pending(edge: &mut EdgeFederation) -> TestResult<&mut PendingRequest> {
    Ok(edge.pending.get_mut(&REQUEST).ok_or("pending")?)
}

/// One case of a copy that is not held: its name, the edge, the event and
/// the recipient whose copy is rendered.
type Case<'a> = (
    &'static str,
    EdgeFederation,
    ProjectedEvent,
    (UserId, ConnectionGeneration, Option<&'a CapabilityState>),
);

#[test]
fn only_the_requesters_copy_of_a_labeled_message_is_held() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let unlabeled = negotiated_capabilities(&["message-tags", "batch", "echo-message"])?;
    let event = delivered()?;
    let mut sink_gone = labeled_message()?;
    pending(&mut sink_gone)?.sink_gone = true;
    let mut closing = labeled_message()?;
    pending(&mut closing)?.kind = PendingKind::Close;
    let cases: [Case<'_>; 11] = [
        (
            "not a message",
            labeled_message()?,
            ProjectedEvent::RequestCompleted {
                resulting_state_generation: GENERATION,
            },
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "another recipient's copy",
            labeled_message()?,
            delivered()?,
            (UserId::from_bytes([6; 16]), CONNECTION, Some(&capabilities)),
        ),
        (
            "an unlabeled request",
            edge_with("PRIVMSG #edge :hi", FederationOpcode::Message)?,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "another tag without a label",
            edge_with("@+typing=active TAGMSG #edge", FederationOpcode::Message)?,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "a label without a value",
            edge_with("@label PRIVMSG #edge :hi", FederationOpcode::Message)?,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "a label without labeled-response",
            labeled_message()?,
            delivered()?,
            (SENDER, CONNECTION, Some(&unlabeled)),
        ),
        (
            "no capabilities",
            labeled_message()?,
            delivered()?,
            (SENDER, CONNECTION, None),
        ),
        (
            "a request that is not a message",
            edge_with("@label=m1 JOIN #edge", FederationOpcode::Join)?,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "another connection",
            labeled_message()?,
            delivered()?,
            (SENDER, ConnectionGeneration::new(2), Some(&capabilities)),
        ),
        (
            "a connection that is gone",
            sink_gone,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
        (
            "a request that is not a command",
            closing,
            delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
        ),
    ];
    for (name, mut edge, event, recipient) in cases {
        let mut frames = copy("hi")?;
        let held_copy = capture(
            &mut edge,
            context,
            &header(1, GENERATION),
            &event,
            recipient,
            &mut frames,
        );
        assert_eq!(held_copy, Ok(()), "{name}");
        assert_eq!(frames.len(), 1, "{name}: the copy is sent with its event");
        assert_eq!(held(&edge)?, 0, "{name}");
    }
    // A labeled request without echo-message has no copy to hold.
    let mut edge = labeled_message()?;
    let mut frames = Vec::new();
    capture(
        &mut edge,
        context,
        &header(1, GENERATION),
        &event,
        (SENDER, CONNECTION, Some(&capabilities)),
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(held(&edge)?, 0);
    Ok(())
}

#[test]
fn a_held_copy_is_replaced_by_its_own_event_and_bounded_by_the_targets() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let event = delivered()?;
    let recipient = (SENDER, CONNECTION, Some(&capabilities));
    let before = charged(context);
    let mut edge = labeled_message()?;
    let mut frames = copy("first")?;
    capture(
        &mut edge,
        context,
        &header(1, GENERATION),
        &event,
        recipient,
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert!(frames.is_empty(), "the requester's copy is held");
    assert_eq!(held(&edge)?, 1);
    let holding = charged(context);
    assert!(holding >= before + u64::try_from(ECHO_BACKING_BYTES)?);
    // The same event rendered again replaces its copy and charges nothing.
    let mut frames = copy("again")?;
    capture(
        &mut edge,
        context,
        &header(1, GENERATION),
        &event,
        recipient,
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(held(&edge)?, 1);
    assert_eq!(charged(context), holding);
    let echo = pending(&mut edge)?
        .message_echoes
        .first()
        .ok_or("held copy")?;
    assert_eq!(echo.frame.trailing(), Some("again"));
    // A one-target message holds one copy.
    let mut frames = copy("third")?;
    assert_eq!(
        capture(
            &mut edge,
            context,
            &header(2, GENERATION),
            &event,
            recipient,
            &mut frames
        ),
        Err(Violation::Ceiling)
    );
    drop(edge);
    assert_eq!(
        charged(context),
        before,
        "a dropped request releases its copy"
    );
    // A two-target message holds two.
    let mut edge = edge_with(
        "@label=m2 PRIVMSG #edge,#two :hi",
        FederationOpcode::Message,
    )?;
    for event_number in [1, 2] {
        let mut frames = copy("hi")?;
        capture(
            &mut edge,
            context,
            &header(event_number, GENERATION),
            &event,
            recipient,
            &mut frames,
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    assert_eq!(held(&edge)?, 2);
    let mut frames = copy("hi")?;
    assert_eq!(
        capture(
            &mut edge,
            context,
            &header(3, GENERATION),
            &event,
            recipient,
            &mut frames
        ),
        Err(Violation::Ceiling)
    );
    drop(edge);
    assert_eq!(charged(context), before, "and both of its copies");
    Ok(())
}

#[test]
fn a_copy_that_contradicts_its_request_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let event = delivered()?;
    let recipient = (SENDER, CONNECTION, Some(&capabilities));
    let committed = |generation| ResultArm::Committed {
        resulting_state_generation: generation,
    };
    let mut completed = labeled_message()?;
    pending(&mut completed)?.completion_generation = Some(GENERATION);
    let mut covered = labeled_message()?;
    pending(&mut covered)?.completion_coverage = Some(
        agenc_relay_storage::federation_records::CompletionCoverageRecord {
            request_object_id: [8; 32],
            completion_event_id: [9; 16],
            completion_object_id: [10; 32],
            projection_generation: 1,
            delivery_sequence: 2,
            coordinator_state_generation: GENERATION,
        },
    );
    let mut later = labeled_message()?;
    pending(&mut later)?.result = Some(committed(GENERATION + 1));
    let mut failed = labeled_message()?;
    pending(&mut failed)?.result = Some(ResultArm::Failed {
        code: "SERVER_BUSY".to_owned(),
        context: String::new(),
    });
    let mut mixed = edge_with(
        "@label=m2 PRIVMSG #edge,#two :hi",
        FederationOpcode::Message,
    )?;
    let mut frames = copy("hi")?;
    capture(
        &mut mixed,
        context,
        &header(1, GENERATION + 1),
        &event,
        recipient,
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    for (name, mut edge) in [
        ("after its completion", completed),
        ("after its completion coverage", covered),
        ("under another generation than its result", later),
        ("for a failed request", failed),
        ("beside a copy of another generation", mixed),
    ] {
        let mut frames = copy("hi")?;
        assert_eq!(
            capture(
                &mut edge,
                context,
                &header(2, GENERATION),
                &event,
                recipient,
                &mut frames
            ),
            Err(Violation::Consistency),
            "{name}"
        );
    }
    // A copy at its result's generation is held.
    let mut edge = labeled_message()?;
    pending(&mut edge)?.result = Some(committed(GENERATION));
    let mut frames = copy("hi")?;
    capture(
        &mut edge,
        context,
        &header(1, GENERATION),
        &event,
        recipient,
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(held(&edge)?, 1);
    Ok(())
}

#[test]
fn a_copy_without_backing_is_refused() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let mut exhausted = Vec::new();
    for power in (12..=29).rev() {
        if let Ok(permit) = context.reserve_output_backing((1_usize << power) - 256) {
            exhausted.push(permit);
        }
    }
    let mut edge = labeled_message()?;
    let mut frames = copy("hi")?;
    assert_eq!(
        capture(
            &mut edge,
            context,
            &header(1, GENERATION),
            &delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
            &mut frames,
        ),
        Err(Violation::Ceiling)
    );
    assert_eq!(held(&edge)?, 0);
    drop(exhausted);
    Ok(())
}

#[test]
fn a_result_must_commit_at_every_held_copys_generation() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let mut edge = labeled_message()?;
    let committed = |generation| ResultArm::Committed {
        resulting_state_generation: generation,
    };
    let failed = || ResultArm::Failed {
        code: "SERVER_BUSY".to_owned(),
        context: String::new(),
    };
    // Nothing held: any result stands.
    for result in [committed(GENERATION + 1), failed(), ResultArm::NoContent] {
        assert_eq!(validate_result(pending(&mut edge)?, &result), Ok(()));
    }
    let mut frames = copy("hi")?;
    capture(
        &mut edge,
        context,
        &header(1, GENERATION),
        &delivered()?,
        (SENDER, CONNECTION, Some(&capabilities)),
        &mut frames,
    )
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        validate_result(pending(&mut edge)?, &committed(GENERATION)),
        Ok(())
    );
    for result in [committed(GENERATION + 1), failed(), ResultArm::NoContent] {
        assert_eq!(
            validate_result(pending(&mut edge)?, &result),
            Err(Violation::Consistency)
        );
    }
    Ok(())
}

#[test]
fn the_held_copies_become_the_response_and_keep_their_backing_until_sent() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let before = charged(context);
    let mut edge = edge_with(
        "@label=m2 PRIVMSG #edge,#two :hi",
        FederationOpcode::Message,
    )?;
    for (event_number, text) in [(1, "first"), (2, "second")] {
        let mut frames = copy(text)?;
        capture(
            &mut edge,
            context,
            &header(event_number, GENERATION),
            &delivered()?,
            (SENDER, CONNECTION, Some(&capabilities)),
            &mut frames,
        )
        .map_err(|error| format!("{error:?}"))?;
    }
    let request = edge.pending.remove(&REQUEST).ok_or("pending")?;
    let PendingKind::Command { message } = request.kind else {
        return Err("not a command".into());
    };
    let reply = agenc_relay_client_wire::numeric_reply(
        "edge.example",
        401,
        "sam",
        &["nobody"],
        Some("No such nick"),
    )?;
    let completions = complete(
        context,
        CONNECTION,
        message,
        request.message_echoes,
        vec![reply],
    );
    let [
        EdgeCompletion::MessageCommitted {
            generation,
            frames,
            echo_permits,
            message,
        },
    ] = completions.as_slice()
    else {
        return Err("expected one committed message".into());
    };
    assert_eq!(*generation, CONNECTION);
    assert_eq!(message.command(), "PRIVMSG");
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.trailing().unwrap_or_default())
            .collect::<Vec<_>>(),
        ["first", "second", "No such nick"]
    );
    assert_eq!(echo_permits.len(), 2);
    assert!(charged(context) > before);
    drop(completions);
    assert_eq!(charged(context), before);
    // A request with nothing held answers with nothing of its own.
    let message =
        parse_message(FramedLine::new("@label=m3 NOTICE #edge :hi")?)?.ok_or("command")?;
    let completions = complete(
        context,
        CONNECTION,
        Box::new(message),
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(
        completions.as_slice(),
        [EdgeCompletion::MessageCommitted { frames, echo_permits, .. }]
            if frames.is_empty() && echo_permits.is_empty()
    ));
    Ok(())
}
