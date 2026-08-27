#![forbid(unsafe_code)]

//! Stage-02 bounded client-wire boundary and state-machine tests.

use std::error::Error;
use std::io;

use agenc_ircd_client_wire::{
    ACCOUNT_IDLE_TIMEOUT_MILLIS, ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES, AccessTokenPolicy,
    AccountCarrierAction, AccountCarrierKind, AccountCarrierPhase, AccountTransfer,
    CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState, ClientWebSocketFrame,
    FramedLine, FramingError, MAX_COMMAND_BYTES, MAX_PENDING_MESSAGES, OutputBudget,
    PendingInputQueue, RegistrationAction, RegistrationEvent, RegistrationPhase, RegistrationState,
    RenderError, SaslAction, SaslNumeric, SaslTransport, StreamFramer, WebSocketOpcode,
    WebSocketSubprotocol, WebSocketWire, WelcomeStep, WireMessage, isupport_messages,
    labeled_response, parse_client_tags, parse_message, render_tags, split_capability_lines,
};
use agenc_ircd_types::NetworkId;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

struct Permit;

struct TestOutputBudget {
    maximum: usize,
    requested: Option<usize>,
}

impl TestOutputBudget {
    const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            requested: None,
        }
    }
}

impl OutputBudget for TestOutputBudget {
    type Permit = Permit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        self.requested = Some(bytes);
        if bytes > self.maximum {
            return Err(RenderError::ReservationFailed);
        }
        Ok(Permit)
    }
}

#[test]
fn stream_framer_handles_every_split_and_coalesced_boundary() -> Result<(), Box<dyn Error>> {
    let input = b"PING :one\r\nNOTICE target :two\r\n";
    for split in 0..=input.len() {
        let mut framer = StreamFramer::new()?;
        let mut lines = Vec::new();
        framer.feed(input.get(..split).ok_or_else(test_error)?, |line| {
            lines.push(line.as_str().to_owned());
        })?;
        framer.feed(input.get(split..).ok_or_else(test_error)?, |line| {
            lines.push(line.as_str().to_owned());
        })?;
        framer.finish()?;
        assert_eq!(lines, ["PING :one", "NOTICE target :two"]);
    }
    Ok(())
}

#[test]
fn stream_framer_enforces_terminators_utf8_nul_eof_and_exact_limits() -> Result<(), Box<dyn Error>>
{
    let mut framer = StreamFramer::new()?;
    assert_eq!(
        framer.feed(b"PING\n", |_| {}).err(),
        Some(FramingError::BareLineFeed)
    );
    assert_eq!(
        framer.feed(b"PING\rX", |_| {}).err(),
        Some(FramingError::BareCarriageReturn)
    );
    assert_eq!(
        framer.feed(b"PI\0NG\r\n", |_| {}).err(),
        Some(FramingError::EmbeddedNul)
    );
    assert_eq!(
        framer.feed(&[0xff, b'\r', b'\n'], |_| {}).err(),
        Some(FramingError::InvalidUtf8)
    );
    framer.feed(b"partial", |_| {})?;
    assert_eq!(framer.finish(), Err(FramingError::UnexpectedEof));
    framer.feed(b"partial", |_| {})?;
    assert_eq!(framer.timeout(), Err(FramingError::TimedOut));

    let exact = format!("{}\r\n", "A".repeat(MAX_COMMAND_BYTES));
    let mut count = 0;
    framer.feed(exact.as_bytes(), |_| count += 1)?;
    assert_eq!(count, 1);
    let too_long = "A".repeat(MAX_COMMAND_BYTES + 1);
    assert_eq!(
        framer.feed(too_long.as_bytes(), |_| {}).err(),
        Some(FramingError::LineTooLong)
    );

    let tags = "a".repeat(4_094);
    let tagged = format!("@{tags} PING\r\n");
    framer.feed(tagged.as_bytes(), |_| count += 1)?;
    assert_eq!(count, 2);
    let tags = "a".repeat(4_095);
    let tagged = format!("@{tags} PING\r\n");
    assert_eq!(
        framer.feed(tagged.as_bytes(), |_| {}).err(),
        Some(FramingError::ClientTagsTooLong)
    );
    Ok(())
}

#[test]
fn websocket_reassembles_masked_utf8_and_rejects_protocol_classes() -> Result<(), Box<dyn Error>> {
    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let first = masked(b"PING ", [1, 2, 3, 4]);
    let second = masked(b":token", [4, 3, 2, 1]);
    assert!(
        wire.accept(ClientWebSocketFrame {
            fin: false,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some([1, 2, 3, 4]),
            payload: &first,
        })?
        .is_none()
    );
    let event = wire.accept(ClientWebSocketFrame {
        fin: true,
        reserved_bits: false,
        opcode: WebSocketOpcode::Continuation,
        mask: Some([4, 3, 2, 1]),
        payload: &second,
    })?;
    let Some(agenc_ircd_client_wire::WebSocketEvent::Message(message)) = event else {
        return Err(test_error().into());
    };
    assert_eq!(message.as_str(), "PING :token");

    let plain = b"PING";
    let close = wire
        .accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: None,
            payload: plain,
        })
        .err()
        .ok_or_else(test_error)?;
    assert_eq!(close.code(), 1002);

    let masked_ping = masked(b"PING", [0, 0, 0, 0]);
    assert_eq!(
        wire.accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some([0, 0, 0, 0]),
            payload: &masked_ping,
        })
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let invalid = masked(&[0xff], [0, 0, 0, 0]);
    let close = wire
        .accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some([0, 0, 0, 0]),
            payload: &invalid,
        })
        .err()
        .ok_or_else(test_error)?;
    assert_eq!(close.code(), 1007);

    let mut wire = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let oversized = vec![0_u8; 8_702];
    let close = wire
        .accept(ClientWebSocketFrame {
            fin: true,
            reserved_bits: false,
            opcode: WebSocketOpcode::Text,
            mask: Some([0, 0, 0, 0]),
            payload: &oversized,
        })
        .err()
        .ok_or_else(test_error)?;
    assert_eq!(close.code(), 1009);
    Ok(())
}

#[test]
fn tags_unescape_once_reject_duplicates_and_preserve_opaque_keys() -> Result<(), Box<dyn Error>> {
    let tags = parse_client_tags(r"vendor/key=a\:b\sc\\d\r\n\q;+draft/x=;odd.key=value")?;
    assert_eq!(tags.len(), 3);
    assert_eq!(tags.first().ok_or_else(test_error)?.key(), "vendor/key");
    assert_eq!(
        tags.first().ok_or_else(test_error)?.value(),
        Some("a;b c\\d\r\nq")
    );
    assert_eq!(tags.get(1).ok_or_else(test_error)?.value(), None);
    assert_eq!(
        render_tags(&tags)?,
        r"vendor/key=a\:b\sc\\d\r\nq;+draft/x;odd.key=value"
    );
    assert!(parse_client_tags("Case=one;case=two").is_ok());
    assert!(parse_client_tags("same=one;same=two").is_err());
    assert!(parse_client_tags(&format!("+x={}", "a".repeat(257))).is_err());
    Ok(())
}

#[test]
fn syntax_parser_canonicalizes_commands_and_preserves_trailing_presence()
-> Result<(), Box<dyn Error>> {
    let message =
        parse_message(FramedLine::new("@+x=one privmsg target :")?)?.ok_or_else(test_error)?;
    assert_eq!(message.command(), "PRIVMSG");
    assert_eq!(message.middle(), ["target"]);
    assert_eq!(message.trailing(), Some(""));
    assert_eq!(message.parameter_count(), 2);
    assert!(parse_message(FramedLine::new(":client PRIVMSG target :bad")?).is_err());
    assert!(parse_message(FramedLine::new("PR1VMSG target")?).is_err());
    let parameters = (0..16)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!("NOTICE {parameters}");
    assert!(parse_message(FramedLine::new(&line)?).is_err());
    assert_eq!(parse_message(FramedLine::new("   ")?)?, None);
    Ok(())
}

#[test]
fn capability_requests_are_case_sensitive_atomic_and_dependency_checked()
-> Result<(), Box<dyn Error>> {
    let advertised = capability_profile()?;
    let mut state = CapabilityState::default();
    let ls = state.ls(Some("302"), &advertised)?;
    assert!(ls.contains(&"agenc.ag/recovery=v1.AAAAAAAAAAAAAAAAAAAAAA".to_owned()));
    assert!(state.enabled("cap-notify"));
    assert!(matches!(
        state.request("batch", &advertised)?,
        CapRequestReply::Ack(_)
    ));
    assert_eq!(
        state.request("message-tags batch labeled-response", &advertised)?,
        CapRequestReply::Ack(vec![
            "message-tags".to_owned(),
            "batch".to_owned(),
            "labeled-response".to_owned()
        ])
    );
    let before = state.list()?;
    assert!(matches!(
        state.request("message-tags UNKNOWN", &advertised)?,
        CapRequestReply::Nak(_)
    ));
    assert_eq!(state.list()?, before);
    assert!(matches!(
        state.request("-batch", &advertised)?,
        CapRequestReply::Nak(_)
    ));
    assert!(matches!(
        state.request("-cap-notify", &advertised)?,
        CapRequestReply::Nak(_)
    ));
    state.end()?;
    assert!(!state.blocks_registration());

    let lines = split_capability_lines(&ls, 64)?;
    assert!(lines.len() > 1);
    assert!(lines.iter().all(|line| line.capabilities.len() <= 64));
    assert!(!lines.last().ok_or_else(test_error)?.continuation);
    Ok(())
}

#[test]
fn registration_waits_for_generation_bound_results_and_orders_welcome() -> Result<(), Box<dyn Error>>
{
    let advertised = capability_profile()?;
    let mut state = RegistrationState::new(1_000, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let nick = parsed("NICK Alice")?;
    let actions = state.message(nick, 1_001, &advertised)?;
    let generation = reserve_generation(&actions)?;
    assert!(
        state
            .message(
                parsed("USER ignored 0 * :Real\u{7} Name")?,
                1_002,
                &advertised,
            )?
            .is_empty()
    );
    let actions = state.event(
        RegistrationEvent::NicknameReserved {
            generation,
            accepted: true,
        },
        1_002,
    )?;
    let commit_generation = commit_generation(&actions)?;
    assert_eq!(state.phase(), RegistrationPhase::Negotiating);
    let welcome = state.event(
        RegistrationEvent::RegistrationCommitted {
            generation: commit_generation,
            accepted: true,
            authenticated: true,
        },
        1_003,
    )?;
    assert_eq!(state.phase(), RegistrationPhase::Registered);
    let RegistrationAction::WelcomeBurst(steps) = welcome.first().ok_or_else(test_error)? else {
        return Err(test_error().into());
    };
    assert_eq!(
        steps,
        &[
            WelcomeStep::WelcomeThroughMyInfo,
            WelcomeStep::Isupport,
            WelcomeStep::LuserCounters,
            WelcomeStep::Motd,
            WelcomeStep::AccountState,
            WelcomeStep::RegistrationBatches,
        ]
    );
    Ok(())
}

#[test]
fn registration_bounds_pending_input_keepalive_and_close_idempotence() -> Result<(), Box<dyn Error>>
{
    let mut pending = PendingInputQueue::new()?;
    for _ in 0..MAX_PENDING_MESSAGES {
        pending.admit(parsed("PING token")?)?;
    }
    assert_eq!(pending.message_count(), MAX_PENDING_MESSAGES);
    assert!(pending.admit(parsed("PING token")?).is_err());
    assert_eq!(pending.into_messages().count(), MAX_PENDING_MESSAGES);

    let advertised = capability_profile()?;
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    let actions = state.tick(30_000, None)?;
    assert!(matches!(actions.as_slice(), [RegistrationAction::Close(_)]));
    assert!(
        state
            .message(parsed("QUIT :again")?, 30_001, &advertised)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn sasl_transport_enforces_fixed_chunks_responses_attempts_and_timeout()
-> Result<(), Box<dyn Error>> {
    let mut sasl = SaslTransport::new()?;
    assert!(matches!(
        sasl.client("AGENC-OPAQUE", 10)?.as_slice(),
        [SaslAction::SendPlus]
    ));
    let request = vec![7_u8; ACCOUNT_REQUEST_BYTES];
    let encoded = STANDARD.encode(&request);
    let mut request_seen = false;
    for chunk in encoded.as_bytes().chunks(400) {
        let text = std::str::from_utf8(chunk)?;
        let actions = sasl.client(text, 11)?;
        if let [SaslAction::RequestEnvelope { finish, bytes }] = actions.as_slice() {
            assert!(!finish);
            assert_eq!(bytes.expose(), request);
            request_seen = true;
        }
    }
    assert!(request_seen);
    let response = vec![9_u8; ACCOUNT_RESPONSE_BYTES];
    let actions = sasl.server_response(&response, 12)?;
    assert_eq!(actions.len(), 15);
    assert!(
        actions
            .iter()
            .take(14)
            .all(|action| matches!(action, SaslAction::SendChunk(chunk) if chunk.len() == 400))
    );
    assert!(matches!(actions.last(), Some(SaslAction::SendChunk(chunk)) if chunk.len() == 192));

    let mut timeout = SaslTransport::new()?;
    timeout.client("AGENC-OPAQUE", 0)?;
    assert!(matches!(
        timeout.tick(30_000)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));
    Ok(())
}

#[test]
fn account_transfer_requires_exact_data_end_and_deadlines() -> Result<(), Box<dyn Error>> {
    let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
    assert!(matches!(
        transfer.client("START", Some("4726"), false, 0)?.as_slice(),
        [AccountCarrierAction::Ready(AccountCarrierPhase::Start)]
    ));
    let request = URL_SAFE_NO_PAD.encode(vec![3_u8; ACCOUNT_REQUEST_BYTES]);
    for chunk in request.as_bytes().chunks(400) {
        transfer.client("DATA", Some(std::str::from_utf8(chunk)?), false, 1)?;
    }
    let actions = transfer.client("END", None, false, 2)?;
    assert!(matches!(
        actions.as_slice(),
        [AccountCarrierAction::RequestEnvelope {
            phase: AccountCarrierPhase::Start,
            ..
        }]
    ));
    let response = vec![4_u8; ACCOUNT_RESPONSE_BYTES];
    let actions = transfer.server_response(AccountCarrierPhase::Start, &response, 3)?;
    assert_eq!(actions.len(), 17);
    assert!(matches!(
        actions.first(),
        Some(AccountCarrierAction::ResponseStart(
            AccountCarrierPhase::Start
        ))
    ));
    assert!(matches!(actions.last(), Some(AccountCarrierAction::End)));

    let mut expired = AccountTransfer::new(AccountCarrierKind::Create)?;
    expired.client("START", Some("4726"), false, 0)?;
    assert!(expired.tick(ACCOUNT_IDLE_TIMEOUT_MILLIS).is_err());
    let mut tagged = AccountTransfer::new(AccountCarrierKind::Create)?;
    assert!(tagged.client("START", Some("4726"), true, 0).is_err());
    Ok(())
}

#[test]
fn renderer_measures_before_permit_and_orders_tags_and_labeled_batches()
-> Result<(), Box<dyn Error>> {
    let capabilities = labeled_capabilities()?;
    let mut message =
        WireMessage::new("server.example", "NOTICE", &["Alice"], Some("hello world"))?;
    message.add_client_only_tag(&capabilities, "+z", Some("last"))?;
    message.add_server_tag("z", Some("two"))?;
    message.add_server_tag("a", Some("one"))?;
    message.add_client_only_tag(&capabilities, "+a", Some("first"))?;
    let measured = message.measure()?;
    let bytes = measured.bytes();
    let mut insufficient = TestOutputBudget::new(bytes - 1);
    assert_eq!(
        message.measure()?.encode(&mut insufficient).err(),
        Some(RenderError::ReservationFailed)
    );
    assert_eq!(insufficient.requested, Some(bytes));
    let mut exact = TestOutputBudget::new(bytes);
    let rendered = message.measure()?.encode(&mut exact)?;
    assert_eq!(rendered.as_bytes().len(), bytes);
    assert_eq!(
        std::str::from_utf8(rendered.as_bytes())?,
        "@a=one;z=two;+a=first;+z=last :server.example NOTICE Alice :hello world\r\n"
    );

    let first = WireMessage::new("server.example", "NOTICE", &["Alice"], Some("one"))?;
    let second = WireMessage::new("server.example", "NOTICE", &["Alice"], Some("two"))?;
    let logical = labeled_response(
        &capabilities,
        "server.example",
        Some("request-1"),
        Some("batch-1"),
        vec![first, second],
    )?;
    assert_eq!(logical.messages().len(), 4);
    let encoded = encode_all(logical.into_messages())?;
    assert_eq!(encoded.matches("label=request-1").count(), 1);
    assert_eq!(encoded.matches("batch=batch-1").count(), 2);

    let acknowledgement = labeled_response(
        &capabilities,
        "server.example",
        Some("request-empty"),
        None,
        Vec::new(),
    )?;
    assert_eq!(
        encode_all(acknowledgement.into_messages())?,
        "@label=request-empty :server.example ACK\r\n"
    );
    Ok(())
}

#[test]
fn isupport_surface_contains_mandatory_network_tokens() -> Result<(), Box<dyn Error>> {
    let network_id = NetworkId::from_bytes([0_u8; 32]);
    let network_text = network_id.to_base64url();
    let messages = isupport_messages("server.example", "Alice", "AgenC", &network_id)?;
    assert_eq!(messages.len(), 3);
    let encoded = encode_all(messages)?;
    assert!(encoded.contains("NETWORK=AgenC"));
    assert!(encoded.contains(&format!("AGENCNET={network_text}")));
    assert!(encoded.contains("CHANMODES=beI,,kl,imnpst"));
    Ok(())
}

fn parsed(line: &str) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| test_error().into())
}

fn labeled_capabilities() -> Result<CapabilityState, Box<dyn Error>> {
    let advertised = capability_profile()?;
    let mut state = CapabilityState::default();
    state.ls(Some("302"), &advertised)?;
    let CapRequestReply::Ack(_) =
        state.request("batch labeled-response message-tags", &advertised)?
    else {
        return Err(test_error().into());
    };
    Ok(state)
}

fn capability_profile() -> Result<CapabilityProfile, Box<dyn Error>> {
    Ok(CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?,
    ])?)
}

fn reserve_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::ReserveNickname { generation, .. }) = actions.first() else {
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

fn masked(payload: &[u8], key: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(position, byte)| {
            let mask = key.get(position % key.len()).copied().unwrap_or_default();
            *byte ^ mask
        })
        .collect()
}

fn encode_all(messages: Vec<WireMessage>) -> Result<String, Box<dyn Error>> {
    let mut output = String::new();
    for message in messages {
        let bytes = message.measure()?.bytes();
        let mut budget = TestOutputBudget::new(bytes);
        let rendered = message.measure()?.encode(&mut budget)?;
        output.push_str(std::str::from_utf8(rendered.as_bytes())?);
    }
    Ok(output)
}

fn test_error() -> io::Error {
    io::Error::other("test fixture shape mismatch")
}
