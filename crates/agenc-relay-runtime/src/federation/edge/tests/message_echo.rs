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
                echo_channels: None,
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

#[test]
fn message_echoes_and_refusals_bind_the_same_original_targets_in_either_order() -> TestResult {
    let request = parse_message(FramedLine::new("PRIVMSG bob,#Room :hi")?)?.ok_or("request")?;
    let echo = |name, text| WireMessage::new("sam!u-a@h-b.invalid", "PRIVMSG", &[name], Some(text));
    let tagged = parse_message(FramedLine::new(
        "@label=x;+sample/typing=on;+empty TAGMSG #room",
    )?)?
    .ok_or("original tagged request")?;
    let frame = WireMessage::new("sam", "TAGMSG", &["#room"], None)?;
    let tags = [
        ("+empty".to_owned(), String::new()),
        ("+sample/typing".to_owned(), "on".to_owned()),
    ];
    assert!(original_message_echo(&tagged, &frame, &tags));
    assert!(!original_message_echo(&tagged, &frame, &tags[..1]));
    let changed = [tags[0].clone(), (tags[1].0.clone(), "off".to_owned())];
    assert!(!original_message_echo(&tagged, &frame, &changed));
    let room = echo("#room", "hi")?;
    let bob = echo("Bob", "hi")?;
    let other = echo("#other", "hi")?;
    let denied = agenc_relay_client_wire::numeric_reply(
        "edge.example",
        482,
        "Sam",
        &["#ROOM"],
        Some("Permission denied for channel"),
    )?;
    let missing = agenc_relay_client_wire::numeric_reply(
        "edge.example",
        401,
        "Sam",
        &["bob"],
        Some("No such nick"),
    )?;
    let private = agenc_relay_client_wire::numeric_reply(
        "edge.example",
        481,
        "Sam",
        &[],
        Some("Command is unavailable"),
    )?;
    assert!(original_message_echo(&request, &room, &[]));
    for unmatched in [
        &other,
        &echo("#room", "other")?,
        &WireMessage::new("sam", "NOTICE", &["#room"], Some("hi"))?,
    ] {
        assert!(!original_message_echo(&request, unmatched, &[]));
    }
    assert_eq!(
        check_message_replies(&request, [&room, &bob].into_iter(), &[]),
        Ok(())
    );
    assert_eq!(
        check_message_replies(
            &request,
            [&room].into_iter(),
            std::slice::from_ref(&private)
        ),
        Ok(())
    );
    for (frames, refusals) in [
        (vec![&room, &room], vec![]),
        (vec![&other], vec![]),
        (vec![&room], vec![denied]),
        (vec![&bob], vec![missing]),
        (vec![&bob], vec![private]),
    ] {
        assert_eq!(
            check_message_replies(&request, frames.into_iter(), &refusals),
            Err(Violation::Consistency)
        );
    }
    Ok(())
}

#[test]
fn a_malformed_echo_and_an_extra_recipient_cannot_account_for_a_decision() -> TestResult {
    let request = parse_message(FramedLine::new("PRIVMSG A,B,C,D,E :hi")?)?.ok_or("request")?;
    let malformed = WireMessage::new("sam", "PRIVMSG", &["A", "B"], Some("hi"))?;
    assert_eq!(
        check_message_replies(&request, [&malformed].into_iter(), &[]),
        Err(Violation::Consistency)
    );
    let fifth = WireMessage::new("sam", "PRIVMSG", &["E"], Some("hi"))?;
    assert_eq!(
        check_message_replies(&request, [&fifth].into_iter(), &[]),
        Err(Violation::Consistency)
    );
    let echoes = ["A", "B", "C", "D"]
        .map(|nick| WireMessage::new("sam", "PRIVMSG", &[nick], Some("hi")))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let refusal = agenc_relay_client_wire::numeric_reply(
        "edge.example",
        481,
        "Sam",
        &[],
        Some("Command is unavailable"),
    )?;
    assert_eq!(
        check_message_replies(&request, echoes.iter(), &[refusal]),
        Err(Violation::Consistency)
    );
    Ok(())
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

#[test]
fn only_the_original_topic_instance_actor_and_text_are_held() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
    let channel = ChannelInstanceId::from_bytes([7; 16]);
    let other = ChannelInstanceId::from_bytes([8; 16]);
    for (requested, observed, instance, sink, matched) in [
        ("value", "value", channel, SENDER, true),
        ("", "", channel, SENDER, true),
        ("value", "other", channel, SENDER, false),
        ("value", "value", other, SENDER, false),
        (
            "value",
            "value",
            channel,
            UserId::from_bytes([19; 16]),
            false,
        ),
    ] {
        let mut edge = edge_with(
            &format!("@label=t TOPIC #test :{requested}"),
            FederationOpcode::Topic,
        )?;
        let PendingKind::Command { echo_channels, .. } = &mut pending(&mut edge)?.kind else {
            return Err("missing original command".into());
        };
        *echo_channels = Some(EchoChannels::Topic(channel));
        let value = if observed.is_empty() {
            None
        } else {
            Some((
                observed.to_owned(),
                agenc_relay_types::UtcSecond::from_unix_seconds(5),
                MessageId::from_bytes([6; 16]),
            ))
        };
        let event = ProjectedEvent::TopicChanged {
            channel_id: instance,
            resulting_revision: Revision::new(3)?,
            actor: SourceView {
                user_id: SENDER,
                nickname: NicknameValue::parse("sam")?,
                public_cloak: agenc_relay_testkit::deterministic_cloak(1)?,
                account_label: None,
            },
            topic: value,
        };
        let mut header = header(1, GENERATION);
        header.event_kind = FederationEventKind::TopicChanged;
        let mut frames = vec![WireMessage::new(
            "sam!u-a@h-b.invalid",
            "TOPIC",
            &["#test"],
            Some(observed),
        )?];
        capture(
            &mut edge,
            context,
            &header,
            &event,
            (sink, CONNECTION, Some(&capabilities)),
            &mut frames,
        )
        .map_err(|e| format!("topic capture: {e:?}"))?;
        assert_eq!(frames.is_empty(), matched);
        assert_eq!(held(&edge)?, usize::from(matched));
    }
    Ok(())
}

#[test]
fn departure_backing_charges_both_allocations_before_the_request_can_be_sent() -> TestResult {
    use super::super::request::reserve_departure_backing;
    use crate::budget::MemoryCharge;
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let before = charged(context);
    let channel_charge =
        MemoryCharge::allocation(20 * size_of::<ChannelInstanceId>() as u64)?.bytes();
    let reason_charge = MemoryCharge::allocation(256)?.bytes();
    let permits = reserve_departure_backing(context, 20, 256)?;
    assert_eq!(charged(context), before + channel_charge + reason_charge);
    drop(permits);
    assert_eq!(charged(context), before);
    let empty_reason = reserve_departure_backing(context, 1, 0)?;
    assert_eq!(
        charged(context),
        before + MemoryCharge::allocation(size_of::<ChannelInstanceId>() as u64)?.bytes()
    );
    drop(empty_reason);
    assert!(matches!(
        reserve_departure_backing(context, usize::MAX, 0),
        Err(agenc_relay_domain::DomainError::ServerBusy)
    ));
    assert!(matches!(
        reserve_departure_backing(context, 1, usize::MAX),
        Err(agenc_relay_domain::DomainError::ServerBusy)
    ));
    #[cfg(target_pointer_width = "64")]
    {
        // The ID byte count fits independently; its allocator bookkeeping does not.
        let largest_id_array = usize::MAX / size_of::<ChannelInstanceId>();
        assert!(matches!(
            reserve_departure_backing(context, largest_id_array, 0),
            Err(agenc_relay_domain::DomainError::ServerBusy)
        ));
        // Both rounded allocations fit separately but their aggregate exceeds u64.
        let half = usize::MAX / 2;
        assert!(matches!(
            reserve_departure_backing(context, half / size_of::<ChannelInstanceId>(), half),
            Err(agenc_relay_domain::DomainError::ServerBusy)
        ));
        assert_eq!(charged(context), before);
    }
    let available = context.backing_budget_for_test().available();
    let all = context.reserve_kept_output(available)?;
    assert!(matches!(
        reserve_departure_backing(context, 20, 0),
        Err(agenc_relay_domain::DomainError::ServerBusy)
    ));
    drop(all);
    let guard = context.reserve_kept_output(available - channel_charge)?;
    let held = charged(context);
    assert!(matches!(
        reserve_departure_backing(context, 20, 256),
        Err(agenc_relay_domain::DomainError::ServerBusy)
    ));
    assert_eq!(charged(context), held);
    drop(guard);
    assert_eq!(charged(context), before);
    Ok(())
}

#[test]
fn a_departure_echo_belongs_to_one_original_instance_actor_and_reason() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = labeled()?;
    let first = ChannelInstanceId::from_bytes([7; 16]);
    let second = ChannelInstanceId::from_bytes([8; 16]);
    let foreign = ChannelInstanceId::from_bytes([9; 16]);
    for reason in ["", "requested"] {
        let mut edge = edge_with(
            &format!("@label=p PART #one,#two :{reason}"),
            FederationOpcode::Part,
        )?;
        let PendingKind::Command { echo_channels, .. } = &mut pending(&mut edge)?.kind else {
            return Err("missing original command".into());
        };
        *echo_channels = Some(EchoChannels::Part {
            channels: vec![first, second],
            reason: reason.to_owned(),
            requester: super::super::request::PartRequester::new("sender", &capabilities, 0)?,
            _backing: super::super::request::reserve_departure_backing(context, 2, reason.len())?,
        });
        for (id, channel, actor, observed, expected, held_count) in [
            (1, foreign, SENDER, reason, Ok(false), 0),
            (1, first, SENDER, "different", Ok(false), 0),
            (1, first, UserId::from_bytes([19; 16]), reason, Ok(false), 0),
            (1, first, SENDER, reason, Ok(true), 1),
            (1, first, SENDER, reason, Ok(true), 1),
            (1, second, SENDER, reason, Err(Violation::Consistency), 1),
            (2, first, SENDER, reason, Err(Violation::Consistency), 1),
            (2, second, SENDER, reason, Ok(true), 2),
        ] {
            let event = ProjectedEvent::MemberParted {
                channel_id: channel,
                source: SourceView {
                    user_id: actor,
                    nickname: NicknameValue::parse("sam")?,
                    public_cloak: agenc_relay_testkit::deterministic_cloak(1)?,
                    account_label: None,
                },
                resulting_revision: Revision::new(3)?,
                home_session_revision: Some(Revision::new(4)?),
                reason: observed.to_owned(),
            };
            let mut header = header(id, GENERATION);
            header.event_kind = FederationEventKind::MemberParted;
            let name = if channel == first { "#one" } else { "#two" };
            let mut frames = vec![WireMessage::new(
                "sam!u-a@h-b.invalid",
                "PART",
                &[name],
                Some(observed),
            )?];
            let result = capture(
                &mut edge,
                context,
                &header,
                &event,
                (SENDER, CONNECTION, Some(&capabilities)),
                &mut frames,
            );
            assert_eq!(result.map(|()| frames.is_empty()), expected);
            assert_eq!(held(&edge)?, held_count);
        }
        let denied = agenc_relay_client_wire::numeric_reply(
            "edge.example",
            482,
            "sam",
            &["#ONE"],
            Some("Permission denied for channel"),
        )?;
        let unrelated = agenc_relay_client_wire::numeric_reply(
            "edge.example",
            403,
            "sam",
            &["#elsewhere"],
            Some("No such channel"),
        )?;
        let original = pending(&mut edge)?;
        assert_eq!(validate_departure_replies(original, &[unrelated]), Ok(()));
        assert_eq!(
            validate_departure_replies(original, std::slice::from_ref(&denied)),
            Err(Violation::Consistency)
        );
        let missing_target = WireMessage::new("edge.example", "ACK", &[], None)?;
        assert_eq!(
            check_departure_reply(Some(first), &missing_target, &[]),
            Err(Violation::Consistency)
        );
        original.replies = vec![denied];
        let echo = WireMessage::new("sam!u-a@h-b.invalid", "PART", &["#one"], Some(reason))?;
        assert_eq!(
            hold_echo(
                original,
                context,
                &header(1, GENERATION),
                Some(first),
                2,
                echo
            ),
            Err(Violation::Consistency)
        );
    }
    Ok(())
}

#[test]
fn only_the_negotiated_original_prepared_display_name_is_held() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let negotiated =
        negotiated_capabilities(&["message-tags", "batch", "labeled-response", "setname"])?;
    let no_setname = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
    for (text, sink, capabilities, matched) in [
        ("New Display", SENDER, &negotiated, true),
        ("Other", SENDER, &negotiated, false),
        (
            "New Display",
            UserId::from_bytes([9; 16]),
            &negotiated,
            false,
        ),
        ("New Display", SENDER, &no_setname, false),
    ] {
        let mut edge = edge_with(
            "@label=name SETNAME :New  Display",
            FederationOpcode::Setname,
        )?;
        let notification = ProjectedEvent::DisplayNameChanged {
            view: agenc_relay_domain::federation::SessionEventView {
                source: SourceView {
                    user_id: SENDER,
                    nickname: NicknameValue::parse("sam")?,
                    public_cloak: agenc_relay_testkit::deterministic_cloak(1)?,
                    account_label: None,
                },
                home_projection: None,
            },
            display_name: agenc_relay_domain::DisplayNameValue::prepare(text)?,
        };
        let mut header = header(1, GENERATION);
        header.event_kind = FederationEventKind::DisplayNameChanged;
        let mut frames = vec![WireMessage::new(
            "sam!u-a@h-b.invalid",
            "SETNAME",
            &[],
            Some(text),
        )?];
        capture(
            &mut edge,
            context,
            &header,
            &notification,
            (sink, CONNECTION, Some(capabilities)),
            &mut frames,
        )
        .map_err(|e| format!("display name capture: {e:?}"))?;
        assert_eq!(held(&edge)?, usize::from(matched));
        assert_eq!(frames.is_empty(), matched);
    }
    Ok(())
}

#[test]
fn only_the_exact_original_nickname_change_is_held_without_echo_message() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let capabilities = negotiated_capabilities(&["message-tags", "batch", "labeled-response"])?;
    for (request, new_name, recipient, matched) in [
        ("@label=n NICK Wren", "Wren", SENDER, true),
        ("@label=n NICK :Wren", "Wren", SENDER, true),
        ("@label=n NICK Wren", "Other", SENDER, false),
        (
            "@label=n NICK Wren",
            "Wren",
            UserId::from_bytes([9; 16]),
            false,
        ),
        ("NICK Wren", "Wren", SENDER, false),
    ] {
        let mut edge = edge_with(request, FederationOpcode::NickChange)?;
        let notification = ProjectedEvent::NicknameChanged {
            old_nickname: NicknameValue::parse("sam")?,
            view: agenc_relay_domain::federation::SessionEventView {
                source: SourceView {
                    user_id: SENDER,
                    nickname: NicknameValue::parse(new_name)?,
                    public_cloak: agenc_relay_testkit::deterministic_cloak(1)?,
                    account_label: None,
                },
                home_projection: None,
            },
        };
        let mut header = header(1, GENERATION);
        header.event_kind = FederationEventKind::NicknameChanged;
        let mut frames = vec![WireMessage::new(
            "sam!u-a@h-b.invalid",
            "NICK",
            &[],
            Some(new_name),
        )?];
        capture(
            &mut edge,
            context,
            &header,
            &notification,
            (recipient, CONNECTION, Some(&capabilities)),
            &mut frames,
        )
        .map_err(|violation| format!("unexpected NICK capture rejection: {violation:?}"))?;
        assert_eq!(held(&edge)?, usize::from(matched));
        assert_eq!(frames.is_empty(), matched);
        if matched {
            assert!(
                validate_result(
                    pending(&mut edge)?,
                    &ResultArm::Committed {
                        resulting_state_generation: GENERATION + 1
                    }
                )
                .is_err()
            );
            validate_result(
                pending(&mut edge)?,
                &ResultArm::Committed {
                    resulting_state_generation: GENERATION,
                },
            )
            .map_err(|violation| format!("matching NICK completion rejected: {violation:?}"))?;
        }
    }
    Ok(())
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
    let PendingKind::Command { message, .. } = request.kind else {
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
