#![forbid(unsafe_code)]

//! Security and state-machine regressions found during the Stage 00–02 audit.

use std::error::Error;
use std::io;

use agenc_relay_client_wire::{
    AccessTokenPolicy, AccountCarrierKind, AccountTransfer, AuthTransportError, CapRequestReply,
    CapabilityProfile, CapabilitySpec, CapabilityState, ClientWebSocketFrame, FramedLine,
    FramingError, MAX_CLIENT_TAG_DATA_BYTES, MAX_COMMAND_BYTES, MessageTag, OutputBudget,
    PendingInputQueue, RegistrationAction, RegistrationAuthCarrier, RegistrationError,
    RegistrationEvent, RegistrationGrammarError, RegistrationPhase, RegistrationState, RenderError,
    ReplyKind, SafeReplyDescription, WebSocketEvent, WebSocketOpcode, WebSocketSubprotocol,
    WebSocketWire, WireMessage, labeled_response, parse_message, standard_reply,
};
use agenc_relay_types::PublicErrorCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

struct Permit;

struct ExactBudget(usize);

impl OutputBudget for ExactBudget {
    type Permit = Permit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        if bytes != self.0 {
            return Err(RenderError::ReservationFailed);
        }
        Ok(Permit)
    }
}

#[test]
fn capability_state_preserves_302_support_and_blind_req_blocks_registration()
-> Result<(), Box<dyn Error>> {
    let advertised = capabilities()?;
    let mut state = CapabilityState::default();
    let with_values = state.ls(Some("302"), &advertised)?;
    assert!(
        with_values
            .iter()
            .any(|token| token == "agenc.ag/recovery=v1.AAAAAAAAAAAAAAAAAAAAAA")
    );
    assert!(state.enabled("cap-notify"));

    let bare = state.ls(None, &advertised)?;
    assert!(bare.iter().all(|token| !token.contains('=')));
    assert!(state.enabled("cap-notify"));
    state.end()?;

    let mut blind = CapabilityState::default();
    assert!(matches!(
        blind.request("batch", &advertised)?,
        CapRequestReply::Ack(_)
    ));
    assert!(matches!(
        blind.request("message-tags batch", &advertised)?,
        CapRequestReply::Ack(_)
    ));
    assert!(blind.blocks_registration());
    blind.end()?;
    assert!(!blind.blocks_registration());
    Ok(())
}

#[test]
fn in_flight_commit_defers_owned_input_and_resumes_it_after_registration()
-> Result<(), Box<dyn Error>> {
    let advertised = capabilities()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let reserve = reserve_generation(&state.message(parsed("NICK Alice")?, 1, &advertised)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 2, &advertised)?;
    let commit = commit_generation(&state.event(
        RegistrationEvent::NicknameReserved {
            generation: reserve,
            accepted: true,
        },
        2,
    )?)?;

    assert!(matches!(
        state
            .message(parsed("CAP LS 302")?, 3, &advertised)?
            .as_slice(),
        [RegistrationAction::InputDeferred]
    ));
    assert!(matches!(
        state
            .message(parsed("CAP REQ :message-tags batch")?, 4, &advertised)?
            .as_slice(),
        [RegistrationAction::InputDeferred]
    ));

    let welcome = state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit,
            accepted: true,
            authenticated: false,
        },
        5,
    )?;
    assert_eq!(state.phase(), RegistrationPhase::Registered);
    let mut welcome = welcome.into_iter();
    assert!(matches!(
        welcome.next(),
        Some(RegistrationAction::WelcomeBurst(_))
    ));
    let Some(RegistrationAction::ResumeDeferredInput(deferred)) = welcome.next() else {
        return Err(test_error().into());
    };
    assert!(welcome.next().is_none());
    assert_eq!(deferred.message_count(), 2);
    let deferred_bytes = deferred.backing_bytes();
    assert!(deferred_bytes > 0);
    let mut deferred = deferred.into_messages();

    assert!(matches!(
        state
            .message(deferred.next().ok_or_else(test_error)?, 6, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityLs(_)]
    ));
    assert!(matches!(
        state
            .message(deferred.next().ok_or_else(test_error)?, 7, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityRequest(CapRequestReply::Ack(
            _
        ))]
    ));
    assert!(deferred.next().is_none());
    assert!(matches!(
        state
            .message(parsed("CAP LIST")?, 7, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityList { .. }]
    ));
    assert!(
        state
            .message(parsed("CAP END")?, 8, &advertised)?
            .is_empty()
    );
    assert_eq!(state.phase(), RegistrationPhase::Registered);
    Ok(())
}

#[test]
fn repeated_commit_defer_resume_cycles_retain_fifo_message_ownership() -> Result<(), Box<dyn Error>>
{
    let advertised = capabilities()?;
    for started_at in [0, 100] {
        let mut state =
            RegistrationState::new(started_at, AccessTokenPolicy::IgnoreCompatibilityPass)?;
        let reserve = reserve_generation(&state.message(
            parsed("NICK Alice")?,
            started_at + 1,
            &advertised,
        )?)?;
        state.message(
            parsed("USER user 0 * :Real Name")?,
            started_at + 2,
            &advertised,
        )?;
        let commit = commit_generation(&state.event(
            RegistrationEvent::NicknameReserved {
                generation: reserve,
                accepted: true,
            },
            started_at + 2,
        )?)?;
        assert!(matches!(
            state
                .message(parsed("PING token")?, started_at + 3, &advertised)?
                .as_slice(),
            [RegistrationAction::InputDeferred]
        ));

        let actions = state.event(
            RegistrationEvent::RegistrationCommitted {
                generation: commit,
                accepted: true,
                authenticated: false,
            },
            started_at + 4,
        )?;
        let mut actions = actions.into_iter();
        assert!(matches!(
            actions.next(),
            Some(RegistrationAction::WelcomeBurst(_))
        ));
        let Some(RegistrationAction::ResumeDeferredInput(deferred)) = actions.next() else {
            return Err(test_error().into());
        };
        assert!(actions.next().is_none());
        let mut deferred = deferred.into_messages();
        assert!(matches!(
            state
                .message(
                    deferred.next().ok_or_else(test_error)?,
                    started_at + 5,
                    &advertised,
                )?
                .as_slice(),
            [RegistrationAction::Pong(token)] if token == "token"
        ));
        assert!(deferred.next().is_none());
    }
    Ok(())
}

#[test]
fn blind_cap_req_delays_commit_until_end() -> Result<(), Box<dyn Error>> {
    let advertised = capabilities()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert!(matches!(
        state
            .message(parsed("CAP REQ :message-tags batch")?, 1, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityRequest(CapRequestReply::Ack(
            _
        ))]
    ));
    let reserve = reserve_generation(&state.message(parsed("NICK Alice")?, 2, &advertised)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 3, &advertised)?;
    assert!(
        state
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: reserve,
                    accepted: true,
                },
                3
            )?
            .is_empty()
    );
    assert!(matches!(
        state
            .message(parsed("CAP END")?, 4, &advertised)?
            .as_slice(),
        [RegistrationAction::CommitRegistration { .. }]
    ));
    Ok(())
}

#[test]
fn invalid_pass_does_not_consume_attempt_and_late_events_cannot_reopen_close()
-> Result<(), Box<dyn Error>> {
    let advertised = capabilities()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::RequireConfiguredToken)?;
    assert_eq!(
        state.message(parsed("PASS invalid")?, 1, &advertised).err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::InvalidArgument
        ))
    );

    let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let generation =
        token_generation(&state.message(parsed(&format!("PASS {token}"))?, 2, &advertised)?)?;
    assert!(matches!(
        state
            .message(parsed("QUIT :done")?, 3, &advertised)?
            .as_slice(),
        [RegistrationAction::Close(_)]
    ));
    assert_eq!(state.phase(), RegistrationPhase::Closing);
    assert!(
        state
            .event(
                RegistrationEvent::AccessTokenChecked {
                    generation,
                    accepted: true,
                },
                3
            )?
            .is_empty()
    );
    assert_eq!(state.phase(), RegistrationPhase::Closing);
    state.event(RegistrationEvent::TransportClosed, 3)?;
    assert_eq!(state.phase(), RegistrationPhase::Closed);
    assert!(
        state
            .event(
                RegistrationEvent::AccessTokenChecked {
                    generation,
                    accepted: true,
                },
                3
            )?
            .is_empty()
    );
    assert_eq!(state.phase(), RegistrationPhase::Closed);
    Ok(())
}

#[test]
fn framing_proof_and_websocket_share_exact_command_and_tag_budgets() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        FramedLine::new("bad\0line").err(),
        Some(FramingError::EmbeddedNul)
    );
    assert_eq!(
        FramedLine::new("bad\rline").err(),
        Some(FramingError::BareCarriageReturn)
    );
    assert_eq!(
        FramedLine::new("bad\nline").err(),
        Some(FramingError::BareLineFeed)
    );

    let exact_command = "A".repeat(MAX_COMMAND_BYTES);
    let _ = FramedLine::new(&exact_command)?;
    let over_command = "A".repeat(MAX_COMMAND_BYTES + 1);
    assert_eq!(
        FramedLine::new(&over_command).err(),
        Some(FramingError::LineTooLong)
    );

    let exact_tags = format!("@{} PING", "a".repeat(MAX_CLIENT_TAG_DATA_BYTES));
    let _ = FramedLine::new(&exact_tags)?;
    let over_tags = format!("@{} PING", "a".repeat(MAX_CLIENT_TAG_DATA_BYTES + 1));
    assert_eq!(
        FramedLine::new(&over_tags).err(),
        Some(FramingError::ClientTagsTooLong)
    );

    assert_websocket_message(&exact_command)?;
    assert_eq!(websocket_error(&over_command)?, 1009);
    assert_fragmented_websocket_message(&exact_tags)?;
    assert_eq!(websocket_error(&over_tags)?, 1009);
    Ok(())
}

#[test]
fn websocket_validates_utf8_after_reassembly_for_both_subprotocols() -> Result<(), Box<dyn Error>> {
    const LINE: &str = "NOTICE target :é";
    let first_mask = [1, 2, 3, 4];
    let second_mask = [4, 3, 2, 1];
    let split = LINE.len().checked_sub(1).ok_or_else(test_error)?;
    let first = mask(
        LINE.as_bytes().get(..split).ok_or_else(test_error)?,
        first_mask,
    );
    let second = mask(
        LINE.as_bytes().get(split..).ok_or_else(test_error)?,
        second_mask,
    );
    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert!(
        text.accept(ClientWebSocketFrame {
            fin: false,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some(first_mask),
            payload: &first,
        })?
        .is_none()
    );
    let Some(WebSocketEvent::Message(message)) = text.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Continuation,
        mask: Some(second_mask),
        payload: &second,
    })?
    else {
        return Err(test_error().into());
    };
    assert_eq!(message.as_str(), LINE);

    let invalid = mask(&[0xff], first_mask);
    let mut binary = WebSocketWire::new(WebSocketSubprotocol::BinaryIrcv3)?;
    assert_eq!(
        binary
            .accept(ClientWebSocketFrame {
                fin: true,
                reserved_bits: false,
                opcode: WebSocketOpcode::Binary,
                mask: Some(first_mask),
                payload: &invalid,
            })
            .err()
            .map(|close| close.code()),
        Some(1007)
    );
    Ok(())
}

#[test]
fn websocket_enforces_close_payload_and_status_boundaries() -> Result<(), Box<dyn Error>> {
    let key = [1, 2, 3, 4];
    for code in [
        1000_u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999,
        4000, 4999,
    ] {
        let mut close_payload = code.to_be_bytes().to_vec();
        close_payload.extend_from_slice(b"bye");
        let payload = mask(&close_payload, key);
        let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
        let Some(WebSocketEvent::Close {
            code: Some(actual),
            reason,
        }) = wire.accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Close,
            mask: Some(key),
            payload: &payload,
        })?
        else {
            return Err(test_error().into());
        };
        assert_eq!(actual, code);
        assert_eq!(reason, "bye");
    }

    for code in [999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, u16::MAX] {
        let payload = mask(&code.to_be_bytes(), key);
        let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
        assert_eq!(
            wire.accept(ClientWebSocketFrame {
                fin: true,
                reserved_bits: false,
                opcode: WebSocketOpcode::Close,
                mask: Some(key),
                payload: &payload,
            })
            .err()
            .map(|close| close.code()),
            Some(1002),
            "close status {code}"
        );
    }

    let maximum_reason = "r".repeat(123);
    let mut close_payload = 1000_u16.to_be_bytes().to_vec();
    close_payload.extend_from_slice(maximum_reason.as_bytes());
    let payload = mask(&close_payload, key);
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let Some(WebSocketEvent::Close { reason, .. }) = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Close,
        mask: Some(key),
        payload: &payload,
    })?
    else {
        return Err(test_error().into());
    };
    assert_eq!(reason, maximum_reason);

    let mut oversized = 1000_u16.to_be_bytes().to_vec();
    oversized.extend_from_slice(&[b'r'; 124]);
    let payload = mask(&oversized, key);
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert_eq!(
        wire.accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Close,
            mask: Some(key),
            payload: &payload,
        })
        .err()
        .map(|close| close.code()),
        Some(1002)
    );
    Ok(())
}

#[test]
fn renderer_measures_utf8_bytes_and_applies_capability_and_registry_rules()
-> Result<(), Box<dyn Error>> {
    let capabilities = renderer_capabilities()?;
    let mut message = WireMessage::new("server", "NOTICE", &["nick"], Some("hello"))?;
    message.add_server_tag("tag", Some("é"))?;
    let measured = message.measure()?;
    let byte_count = measured.bytes();
    let mut budget = ExactBudget(byte_count);
    let encoded = measured.encode(&mut budget)?;
    assert_eq!(encoded.as_bytes().len(), byte_count);

    assert_eq!(
        MessageTag::new("tag", Some("bad\0value")).err(),
        Some(agenc_relay_client_wire::TagError::InvalidValue)
    );
    let mut nul = WireMessage::new("server", "NOTICE", &[], None)?;
    assert_eq!(
        nul.add_server_tag("tag", Some("bad\0value")),
        Err(RenderError::InvalidSyntax)
    );
    let mut ping = WireMessage::new("server", "PING", &[], Some("token"))?;
    assert_eq!(
        ping.add_client_only_tag(&capabilities, "+draft/test", None),
        Err(RenderError::InvalidSyntax)
    );
    assert!(
        standard_reply(
            &capabilities,
            "server",
            ReplyKind::Fail,
            "*",
            PublicErrorCode::REGISTRATIONREQUIRED,
            &[],
            SafeReplyDescription::new("Registration required")?,
        )
        .is_ok()
    );

    let semantic = vec![WireMessage::new(
        "server",
        "NOTICE",
        &["nick"],
        Some("reply"),
    )?];
    let logical = labeled_response(
        &CapabilityState::default(),
        "server",
        Some("secret-label"),
        None,
        semantic,
    )?;
    let response = logical
        .into_messages()
        .into_iter()
        .next()
        .ok_or_else(test_error)?;
    let measured = response.measure()?;
    let bytes = measured.bytes();
    let mut budget = ExactBudget(bytes);
    let response = measured.encode(&mut budget)?;
    assert!(!std::str::from_utf8(response.as_bytes())?.contains("secret-label"));
    Ok(())
}

#[test]
fn renderer_encodes_a_client_only_tag_without_server_tags() -> Result<(), Box<dyn Error>> {
    let capabilities = renderer_capabilities()?;
    let mut message = WireMessage::new("server", "PRIVMSG", &["#room"], Some("hello"))?;
    message.add_client_only_tag(&capabilities, "+draft/test", Some("value"))?;

    let measured = message.measure()?;
    let mut budget = ExactBudget(measured.bytes());
    let encoded = measured.encode(&mut budget)?;
    assert_eq!(
        encoded.as_bytes(),
        b"@+draft/test=value :server PRIVMSG #room :hello\r\n"
    );
    Ok(())
}

#[test]
fn renderer_enforces_client_tag_budgets_before_mutation() -> Result<(), Box<dyn Error>> {
    let capabilities = renderer_capabilities()?;
    let mut count = WireMessage::new("server", "NOTICE", &["nick"], Some("body"))?;
    for index in 0..agenc_relay_client_wire::MAX_CLIENT_ONLY_TAGS {
        count.add_client_only_tag(&capabilities, &format!("+t{index}"), None)?;
    }
    assert_eq!(
        count.add_client_only_tag(&capabilities, "+overflow", None),
        Err(RenderError::LineBudget)
    );

    let mut value = WireMessage::new("server", "NOTICE", &["nick"], Some("body"))?;
    assert_eq!(
        value.add_client_only_tag(
            &capabilities,
            "+ordinary",
            Some(&"x".repeat(agenc_relay_client_wire::MAX_CLIENT_ONLY_VALUE_BYTES + 1)),
        ),
        Err(RenderError::LineBudget)
    );

    let mut aggregate = WireMessage::new("server", "NOTICE", &["nick"], Some("body"))?;
    for index in 0..3 {
        aggregate.add_client_only_tag(
            &capabilities,
            &format!("+ordinary{index}"),
            Some(&"x".repeat(agenc_relay_client_wire::MAX_CLIENT_ONLY_VALUE_BYTES)),
        )?;
    }
    let remaining = agenc_relay_client_wire::MAX_CLIENT_ONLY_TOTAL_BYTES
        - 3 * ("+ordinary0".len() + agenc_relay_client_wire::MAX_CLIENT_ONLY_VALUE_BYTES);
    aggregate.add_client_only_tag(
        &capabilities,
        "+last",
        Some(&"x".repeat(remaining - "+last".len())),
    )?;
    assert_eq!(
        aggregate.add_client_only_tag(&capabilities, "+one-more", Some("x")),
        Err(RenderError::LineBudget)
    );

    let mut e2ee = WireMessage::new("server", "TAGMSG", &["nick"], None)?;
    e2ee.add_client_only_tag(&capabilities, "+agenc.ag/e2ee", Some(&"x".repeat(1_000)))?;
    e2ee.add_client_only_tag(
        &capabilities,
        "+ordinary",
        Some(&"x".repeat(agenc_relay_client_wire::MAX_CLIENT_ONLY_VALUE_BYTES)),
    )?;
    assert!(e2ee.measure().is_ok());
    Ok(())
}

#[test]
fn peer_material_is_redacted_from_debug_surfaces() -> Result<(), Box<dyn Error>> {
    const SECRET: &str = "AUDIT_SECRET_CANARY";
    let parsed_message = parsed(&format!("PASS {SECRET}"))?;
    assert!(!format!("{parsed_message:?}").contains(SECRET));

    let tag = MessageTag::new("tag", Some(SECRET))?;
    assert!(!format!("{tag:?}").contains(SECRET));
    let registration = RegistrationAction::ForwardAuthCarrier {
        generation: 1,
        carrier: RegistrationAuthCarrier::Sasl,
        message: parsed(&format!("AUTHENTICATE {SECRET}"))?,
    };
    assert!(!format!("{registration:?}").contains(SECRET));
    let mut pending = PendingInputQueue::new()?;
    pending.admit(parsed(&format!("AUTHENTICATE {SECRET}"))?)?;
    assert!(!format!("{pending:?}").contains(SECRET));
    let deferred = RegistrationAction::ResumeDeferredInput(pending);
    assert!(!format!("{deferred:?}").contains(SECRET));
    let key = [1, 2, 3, 4];
    let payload = mask(SECRET.as_bytes(), key);
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let event = wire
        .accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some(key),
            payload: &payload,
        })?
        .ok_or_else(test_error)?;
    assert!(!format!("{event:?}").contains(SECRET));
    Ok(())
}

#[test]
fn pending_ownership_and_auth_failures_are_transactional_and_terminal() -> Result<(), Box<dyn Error>>
{
    let mut pending = PendingInputQueue::new()?;
    let message = parsed("PING token")?;
    let requested_backing_bytes = message.requested_backing_bytes();
    pending.admit(message)?;
    assert_eq!(pending.message_count(), 1);
    assert_eq!(pending.backing_bytes(), requested_backing_bytes);
    let owned = pending.into_messages().next().ok_or_else(test_error)?;
    assert_eq!(owned.command(), "PING");
    assert_eq!(owned.requested_backing_bytes(), requested_backing_bytes);

    let mut missing = AccountTransfer::new(AccountCarrierKind::Create)?;
    missing.client("START", Some("4726"), false, 0)?;
    assert_eq!(
        missing.client("DATA", None, false, 1).err(),
        Some(AuthTransportError::InvalidChunk)
    );
    assert_eq!(
        missing.client("START", Some("4726"), false, 2).err(),
        Some(AuthTransportError::BadState)
    );

    let mut overflow = AccountTransfer::new(AccountCarrierKind::Create)?;
    assert_eq!(
        overflow
            .client("START", Some("4726"), false, u64::MAX)
            .err(),
        Some(AuthTransportError::Overflow)
    );
    assert_eq!(
        overflow.client("START", Some("4726"), false, 0).err(),
        Some(AuthTransportError::BadState)
    );
    Ok(())
}

fn capabilities() -> Result<CapabilityProfile, Box<dyn Error>> {
    Ok(CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("standard-replies", None)?,
        CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?,
    ])?)
}

fn renderer_capabilities() -> Result<CapabilityState, Box<dyn Error>> {
    let advertised = capabilities()?;
    let mut capabilities = CapabilityState::default();
    capabilities.ls(Some("302"), &advertised)?;
    capabilities.request("message-tags standard-replies", &advertised)?;
    Ok(capabilities)
}

fn parsed(line: &str) -> Result<agenc_relay_client_wire::ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("missing parsed message").into())
}

fn reserve_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::ReserveNickname { generation, .. }) = actions.first() else {
        return Err(test_error());
    };
    Ok(*generation)
}

fn token_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CheckAccessToken { generation, .. }) = actions.first() else {
        return Err(test_error());
    };
    Ok(*generation)
}

fn commit_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CommitRegistration { generation, .. }) = actions.first() else {
        return Err(test_error());
    };
    Ok(*generation)
}

fn assert_websocket_message(message: &str) -> Result<(), Box<dyn Error>> {
    let key = [1, 2, 3, 4];
    let payload = mask(message.as_bytes(), key);
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let Some(WebSocketEvent::Message(actual)) = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Text,
        mask: Some(key),
        payload: &payload,
    })?
    else {
        return Err(test_error().into());
    };
    assert_eq!(actual.as_str(), message);
    Ok(())
}

fn assert_fragmented_websocket_message(message: &str) -> Result<(), Box<dyn Error>> {
    let key = [4, 3, 2, 1];
    let middle = message.len() / 2;
    let first = mask(
        message.as_bytes().get(..middle).ok_or_else(test_error)?,
        key,
    );
    let second = mask(
        message.as_bytes().get(middle..).ok_or_else(test_error)?,
        key,
    );
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert!(
        wire.accept(ClientWebSocketFrame {
            fin: false,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some(key),
            payload: &first,
        })?
        .is_none()
    );
    let Some(WebSocketEvent::Message(actual)) = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Continuation,
        mask: Some(key),
        payload: &second,
    })?
    else {
        return Err(test_error().into());
    };
    assert_eq!(actual.as_str(), message);
    Ok(())
}

fn websocket_error(message: &str) -> Result<u16, Box<dyn Error>> {
    let key = [1, 2, 3, 4];
    let payload = mask(message.as_bytes(), key);
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Text,
        mask: Some(key),
        payload: &payload,
    })
    .err()
    .map(|close| close.code())
    .ok_or_else(|| test_error().into())
}

fn mask(payload: &[u8], key: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| *byte ^ *key_byte)
        .collect()
}

fn test_error() -> io::Error {
    io::Error::other("test precondition failed")
}
