#![forbid(unsafe_code)]

//! Branch-complete negative and state-transition coverage for Stage 02.

use std::error::Error;
use std::io;

use agenc_ircd_client_wire::{
    ACCOUNT_IDLE_TIMEOUT_MILLIS, ACCOUNT_REQUEST_BYTES, ACCOUNT_RESPONSE_BYTES,
    ACCOUNT_TOTAL_TIMEOUT_MILLIS, AUTH_CHUNK_CHARACTERS, AccessTokenPolicy, AccountCarrierAction,
    AccountCarrierKind, AccountCarrierPhase, AccountTransfer, AuthTransportError, BatchStack,
    CapError, CapRequestReply, CapabilityChange, CapabilityProfile, CapabilitySpec,
    CapabilityState, ClientWebSocketFrame, FramedLine, FramingError, KEEPALIVE_IDLE_MILLIS,
    KEEPALIVE_PONG_MILLIS, MAX_BATCH_NESTING, MAX_CLIENT_ONLY_TAGS, MAX_CLIENT_TAG_DATA_BYTES,
    MAX_COMMAND_BYTES, MAX_CORRELATION_TAG_BYTES, MAX_SEMANTIC_REPLIES, MessageParseError,
    MessageTag, OutputBudget, PendingInputQueue, RegistrationAction, RegistrationAuthCarrier,
    RegistrationError, RegistrationEvent, RegistrationGrammarError, RegistrationPhase,
    RegistrationState, RenderError, ReplyKind, SASL_TIMEOUT_MILLIS, SafeReplyContext,
    SafeReplyDescription, SaslAction, SaslNumeric, SaslTransport, StreamFramer, TagError,
    WebSocketEvent, WebSocketOpcode, WebSocketSubprotocol, WebSocketWire, WireMessage,
    isupport_messages, labeled_response, numeric_reply, parse_client_tags, parse_message,
    render_tags, slow_consumer_warning, split_capability_lines, standard_reply,
};
use agenc_ircd_types::{
    AccountDeletionToken, ChannelName, NetworkId, PublicErrorCode, SafeContext,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

struct Permit(usize);

struct ExactBudget(usize);

impl OutputBudget for ExactBudget {
    type Permit = Permit;

    fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
        if bytes != self.0 {
            return Err(RenderError::ReservationFailed);
        }
        Ok(Permit(bytes))
    }
}

#[test]
fn batch_nesting_hard_max_is_sixteen() {
    assert_eq!(MAX_BATCH_NESTING, 16);
}

#[test]
fn capability_profiles_cover_errors_dependencies_changes_and_splitting()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        CapabilitySpec::new("not-registered", None).err(),
        Some(CapError::UnknownCapability)
    );
    assert_eq!(
        CapabilitySpec::new("batch", Some("")).err(),
        Some(CapError::InvalidValue)
    );
    assert_eq!(
        CapabilitySpec::new("batch", Some("two words")).err(),
        Some(CapError::InvalidValue)
    );
    assert_eq!(
        CapabilitySpec::new("batch", Some("value")).err(),
        Some(CapError::InvalidValue)
    );
    assert_eq!(
        CapabilitySpec::new("agenc.ag/recovery", Some("v1.invalid")).err(),
        Some(CapError::InvalidValue)
    );
    assert_eq!(
        CapabilitySpec::new("sasl", None).err(),
        Some(CapError::InvalidValue)
    );

    let batch = CapabilitySpec::new("batch", None)?;
    assert_eq!(batch.name(), "batch");
    assert_eq!(batch.value(), None);
    let message_tags = CapabilitySpec::new("message-tags", None)?;
    let labeled = CapabilitySpec::new("labeled-response", None)?;
    let notify = CapabilitySpec::new("cap-notify", None)?;
    let old_recovery = CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?;
    let new_recovery = CapabilitySpec::new("agenc.ag/recovery", Some("v1.AQEBAQEBAQEBAQEBAQEBAQ"))?;
    let sts = CapabilitySpec::new("sts", Some("duration=31536000"))?;
    assert_eq!(
        CapabilityProfile::new(vec![labeled.try_clone()?]).err(),
        Some(CapError::InvalidAdvertisement)
    );
    let batch_profile =
        CapabilityProfile::new(vec![message_tags.try_clone()?, batch.try_clone()?])?;

    let mut state = CapabilityState::default();
    state.end()?;
    assert_eq!(state.end(), Err(CapError::InvalidState));
    assert_eq!(
        state.ls(Some("301"), &batch_profile).err(),
        Some(CapError::UnsupportedVersion)
    );
    assert_eq!(state.ls(None, &batch_profile)?, ["message-tags", "batch"]);
    assert_eq!(
        CapabilityProfile::new(vec![
            message_tags.try_clone()?,
            batch.try_clone()?,
            batch.try_clone()?,
        ])
        .err(),
        Some(CapError::InvalidAdvertisement)
    );
    assert_eq!(
        CapabilityProfile::new(vec![labeled.try_clone()?]).err(),
        Some(CapError::InvalidAdvertisement)
    );
    assert!(state.blocks_registration());
    assert!(!state.enabled("cap-notify"));
    assert!(matches!(
        state.request("", &batch_profile)?,
        CapRequestReply::Nak(_)
    ));
    assert!(matches!(
        state.request("unknown", &batch_profile)?,
        CapRequestReply::Nak(_)
    ));
    assert!(matches!(
        state.request("batch=value", &batch_profile)?,
        CapRequestReply::Nak(_)
    ));
    assert!(matches!(
        state.request("-", &batch_profile)?,
        CapRequestReply::Nak(_)
    ));
    state.end()?;
    assert_eq!(state.end(), Err(CapError::InvalidState));

    let dependency_profile = CapabilityProfile::new(vec![
        message_tags.try_clone()?,
        batch.try_clone()?,
        labeled.try_clone()?,
    ])?;
    let mut dependency_state = CapabilityState::default();
    assert!(matches!(
        dependency_state.request("labeled-response", &dependency_profile)?,
        CapRequestReply::Nak(_)
    ));
    assert!(matches!(
        dependency_state.request("batch labeled-response", &dependency_profile)?,
        CapRequestReply::Ack(_)
    ));
    assert!(matches!(
        dependency_state.request("message-tags batch labeled-response", &dependency_profile)?,
        CapRequestReply::Ack(_)
    ));
    assert!(matches!(
        dependency_state.request(
            "-labeled-response -batch -message-tags",
            &dependency_profile
        )?,
        CapRequestReply::Ack(_)
    ));

    let mut state_302 = CapabilityState::default();
    let notify_profile = CapabilityProfile::new(vec![
        notify.try_clone()?,
        message_tags.try_clone()?,
        batch.try_clone()?,
    ])?;
    state_302.ls(Some("302"), &notify_profile)?;
    assert!(state_302.enabled("cap-notify"));
    assert!(matches!(
        state_302.request("-cap-notify", &notify_profile)?,
        CapRequestReply::Nak(_)
    ));

    let old_availability = CapabilityProfile::new(vec![
        old_recovery.try_clone()?,
        sts.try_clone()?,
        message_tags.try_clone()?,
        batch.try_clone()?,
    ])?;
    let current_availability = CapabilityProfile::new(vec![
        new_recovery.try_clone()?,
        sts.try_clone()?,
        message_tags.try_clone()?,
        batch.try_clone()?,
        labeled.try_clone()?,
    ])?;
    let mut changing = CapabilityState::default();
    changing.ls(Some("302"), &old_availability)?;
    assert_eq!(
        changing.apply_profile(&current_availability)?,
        [
            CapabilityChange::ReconnectRequired("agenc.ag/recovery".to_owned()),
            CapabilityChange::New("labeled-response".to_owned()),
        ]
    );
    assert!(changing.reconnect_required());
    assert!(changing.apply_profile(&current_availability)?.is_empty());
    assert!(matches!(
        changing.request("message-tags batch labeled-response", &current_availability)?,
        CapRequestReply::Ack(_)
    ));
    let reduced = CapabilityProfile::new(vec![new_recovery, sts, message_tags])?;
    assert_eq!(
        changing.apply_profile(&reduced)?,
        [
            CapabilityChange::Del("batch".to_owned()),
            CapabilityChange::Del("labeled-response".to_owned()),
        ]
    );
    assert!(!changing.enabled("batch"));
    assert!(!changing.enabled("labeled-response"));

    let old_profile = URL_SAFE_NO_PAD.encode([0_u8; 32]);
    let new_profile = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let old_e2ee_value =
        format!("v1,profile={old_profile},seg=2940,obj=262144,parts=90,welcome=4194304");
    let new_e2ee_value =
        format!("v1,profile={new_profile},seg=2940,obj=262144,parts=90,welcome=4194304");
    let old_e2ee = CapabilitySpec::new("agenc.ag/e2ee-mls", Some(&old_e2ee_value))?;
    let new_e2ee = CapabilitySpec::new("agenc.ag/e2ee-mls", Some(&new_e2ee_value))?;
    let e2ee_profile = |e2ee| {
        CapabilityProfile::new(vec![
            CapabilitySpec::new("message-tags", None)?,
            CapabilitySpec::new("echo-message", None)?,
            CapabilitySpec::new("batch", None)?,
            CapabilitySpec::new("labeled-response", None)?,
            CapabilitySpec::new("standard-replies", None)?,
            CapabilitySpec::new("account-tag", None)?,
            e2ee,
        ])
    };
    let old_e2ee_profile = e2ee_profile(old_e2ee)?;
    let new_e2ee_profile = e2ee_profile(new_e2ee)?;
    let mut e2ee_state = CapabilityState::default();
    e2ee_state.ls(Some("302"), &old_e2ee_profile)?;
    assert!(matches!(
        e2ee_state.request(
            "message-tags echo-message batch labeled-response standard-replies account-tag agenc.ag/e2ee-mls",
            &old_e2ee_profile,
        )?,
        CapRequestReply::Ack(_)
    ));
    assert_eq!(
        e2ee_state.apply_profile(&new_e2ee_profile)?,
        [CapabilityChange::ReconnectRequired(
            "agenc.ag/e2ee-mls".to_owned()
        )]
    );
    assert!(!e2ee_state.enabled("agenc.ag/e2ee-mls"));
    assert_eq!(
        CapabilitySpec::new(
            "agenc.ag/e2ee-mls",
            Some(&format!(
                "v1,profile={old_profile},obj=262144,seg=2940,parts=90,welcome=4194304"
            )),
        )
        .err(),
        Some(CapError::InvalidValue)
    );

    assert_eq!(
        split_capability_lines(&["long-token".to_owned()], 4).err(),
        Some(CapError::LineBudget)
    );
    let empty = split_capability_lines(&[], 0)?;
    assert_eq!(empty.len(), 1);
    let empty_line = empty.first().ok_or_else(test_error)?;
    assert!(empty_line.capabilities.is_empty());
    assert!(!empty_line.continuation);
    let split = split_capability_lines(&["aa".to_owned(), "bb".to_owned()], 2)?;
    assert_eq!(split.len(), 2);
    assert!(split.first().ok_or_else(test_error)?.continuation);
    assert!(!split.last().ok_or_else(test_error)?.continuation);
    Ok(())
}

#[test]
fn registration_profile_changes_notify_only_opted_in_clients_and_always_reconnect()
-> Result<(), Box<dyn Error>> {
    let old_epoch = URL_SAFE_NO_PAD.encode([0_u8; 16]);
    let new_epoch = URL_SAFE_NO_PAD.encode([1_u8; 16]);
    let old_profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("agenc.ag/recovery", Some(&format!("v1.{old_epoch}")))?,
    ])?;
    let current_profile = CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("agenc.ag/recovery", Some(&format!("v1.{new_epoch}")))?,
        CapabilitySpec::new("monitor", None)?,
    ])?;

    let mut notified = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    notified.message(parsed("CAP LS 302")?, 1, &old_profile)?;
    let actions = notified.apply_capability_profile(&current_profile)?;
    assert!(matches!(
        actions.as_slice(),
        [
            RegistrationAction::CapabilityDel(deleted),
            RegistrationAction::CapabilityReconnectRequired(reconnect),
            RegistrationAction::CapabilityNew(added),
        ] if deleted == "batch" && reconnect == "agenc.ag/recovery" && added == "monitor"
    ));
    assert!(matches!(
        notified
            .message(parsed("CAP LS 302")?, 2, &current_profile)?
            .as_slice(),
        [RegistrationAction::CapabilityLs(_)]
    ));

    let mut unnotified = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    unnotified.message(parsed("CAP LS")?, 1, &old_profile)?;
    assert!(matches!(
        unnotified
            .apply_capability_profile(&current_profile)?
            .as_slice(),
        [RegistrationAction::CapabilityReconnectRequired(name)]
            if name == "agenc.ag/recovery"
    ));
    Ok(())
}

#[test]
fn framing_parser_and_tags_cover_all_peer_controlled_error_classes() -> Result<(), Box<dyn Error>> {
    let mut framer = StreamFramer::new()?;
    framer.finish()?;
    framer.timeout()?;
    let progress = framer.feed(b"\r\n", |_| {})?;
    assert_eq!(progress.empty_lines, 1);
    framer.feed(b"\r", |_| {})?;
    assert_eq!(framer.finish(), Err(FramingError::UnexpectedEof));
    framer.feed(b"\r", |_| {})?;
    assert_eq!(framer.timeout(), Err(FramingError::TimedOut));

    let unterminated_tags = format!("@{}\r\n", "a".repeat(MAX_CLIENT_TAG_DATA_BYTES));
    let mut emitted = None;
    let progress = framer.feed(unterminated_tags.as_bytes(), |line| {
        emitted = Some(line.as_str().to_owned());
    })?;
    assert_eq!(progress.messages, 1);
    let emitted = emitted.ok_or_else(test_error)?;
    assert_eq!(
        parse_message(FramedLine::new(&emitted)?).err(),
        Some(MessageParseError::UnterminatedTags)
    );
    let tagged_command = format!("@a {}\r\n", "A".repeat(MAX_COMMAND_BYTES + 1));
    assert_eq!(
        framer.feed(tagged_command.as_bytes(), |_| {}).err(),
        Some(FramingError::LineTooLong)
    );

    assert_eq!(
        parse_message(FramedLine::new("@tag")?).err(),
        Some(MessageParseError::UnterminatedTags)
    );
    assert!(matches!(
        parse_message(FramedLine::new("@ PING")?),
        Err(MessageParseError::Tags(TagError::InvalidKey))
    ));
    assert_eq!(
        parse_message(FramedLine::new(":prefix PING")?).err(),
        Some(MessageParseError::ClientPrefix)
    );
    assert_eq!(
        parse_message(FramedLine::new("123 target")?).err(),
        Some(MessageParseError::InvalidCommand)
    );
    assert_eq!(
        parse_message(FramedLine::new("@tag=value    ")?).err(),
        Some(MessageParseError::InvalidCommand)
    );
    let fourteen = (0..14).map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
    let fourteen_line = format!("NOTICE {fourteen} :last");
    assert!(parse_message(FramedLine::new(&fourteen_line)?)?.is_some());
    let fifteen = (0..15).map(|n| n.to_string()).collect::<Vec<_>>().join(" ");
    assert_eq!(
        parse_message(FramedLine::new(&format!("NOTICE {fifteen} :last"))?).err(),
        Some(MessageParseError::TooManyParameters)
    );

    assert_eq!(
        parse_client_tags(&"a".repeat(MAX_CLIENT_TAG_DATA_BYTES + 1)).err(),
        Some(TagError::RawSectionTooLong)
    );
    for raw in ["", "bad key", "bad=key=value;bad=other", "bad;;key"] {
        assert!(parse_client_tags(raw).is_err(), "{raw}");
    }
    let too_many = (0..=MAX_CLIENT_ONLY_TAGS)
        .map(|n| format!("+x{n}"))
        .collect::<Vec<_>>()
        .join(";");
    assert_eq!(
        parse_client_tags(&too_many).err(),
        Some(TagError::TooManyClientOnlyTags)
    );
    let over_total = (0..5)
        .map(|n| format!("+x{n}={}", "v".repeat(205)))
        .collect::<Vec<_>>()
        .join(";");
    assert_eq!(
        parse_client_tags(&over_total).err(),
        Some(TagError::ClientOnlyTotalTooLong)
    );
    let e2ee = format!("+agenc.ag/e2ee={}", "v".repeat(1_500));
    assert_eq!(parse_client_tags(&e2ee)?.len(), 1);
    assert_eq!(
        parse_client_tags(&format!(
            "label={}",
            "x".repeat(MAX_CORRELATION_TAG_BYTES + 1)
        ))
        .err(),
        Some(TagError::CorrelationValueTooLong)
    );
    assert_eq!(
        MessageTag::new("bad key", None).err(),
        Some(TagError::InvalidKey)
    );
    let tag = MessageTag::new("+client", Some("a;b c\\d\r\n"))?;
    assert!(tag.is_client_only());
    assert_eq!(
        render_tags(std::slice::from_ref(&tag))?,
        r"+client=a\:b\sc\\d\r\n"
    );
    let trailing_escape = parse_client_tags(r"key=tail\")?;
    assert_eq!(
        trailing_escape.first().ok_or_else(test_error)?.value(),
        Some("tail")
    );
    Ok(())
}

#[test]
fn websocket_covers_fragment_control_close_and_subprotocol_branches() -> Result<(), Box<dyn Error>>
{
    let key = [1, 2, 3, 4];

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert_eq!(
        text.accept(frame(true, true, WebSocketOpcode::Text, Some(key), b"PING"))
            .err()
            .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Binary,
            Some(key),
            b"PING"
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Continuation,
            Some(key),
            b"x"
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Reserved(3),
            Some(key),
            b"x"
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let first = mask(b"part", key);
    assert!(
        text.accept(frame(
            false,
            false,
            WebSocketOpcode::Text,
            Some(key),
            &first
        ))?
        .is_none()
    );
    let second_data = mask(b"again", key);
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Text,
            Some(key),
            &second_data
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let first = mask(b"a", key);
    text.accept(frame(
        false,
        false,
        WebSocketOpcode::Text,
        Some(key),
        &first,
    ))?;
    let middle = mask(b"b", key);
    assert!(
        text.accept(frame(
            false,
            false,
            WebSocketOpcode::Continuation,
            Some(key),
            &middle
        ))?
        .is_none()
    );
    let last = mask(b"c", key);
    let Some(WebSocketEvent::Message(message)) = text.accept(frame(
        true,
        false,
        WebSocketOpcode::Continuation,
        Some(key),
        &last,
    ))?
    else {
        return Err(test_error().into());
    };
    assert_eq!(message.as_str(), "abc");

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let near_limit = vec![b'a'; 8_700];
    let first = mask(&near_limit, key);
    text.accept(frame(
        false,
        false,
        WebSocketOpcode::Text,
        Some(key),
        &first,
    ))?;
    let excess = mask(b"xx", key);
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Continuation,
            Some(key),
            &excess
        ))
        .err()
        .map(|close| close.code()),
        Some(1009)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    for (opcode, expected) in [
        (WebSocketOpcode::Ping, WebSocketEvent::Ping(b"hi".to_vec())),
        (WebSocketOpcode::Pong, WebSocketEvent::Pong(b"hi".to_vec())),
    ] {
        let payload = mask(b"hi", key);
        assert_eq!(
            text.accept(frame(true, false, opcode, Some(key), &payload))?,
            Some(expected)
        );
    }

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let payload = mask(b"hi", key);
    assert_eq!(
        text.accept(frame(
            false,
            false,
            WebSocketOpcode::Ping,
            Some(key),
            &payload
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let payload = mask(&[0_u8; 126], key);
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Ping,
            Some(key),
            &payload
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    for (close_payload, code) in [
        (Vec::new(), None),
        (
            [1000_u16.to_be_bytes().as_slice(), b"bye"].concat(),
            Some(1000),
        ),
    ] {
        let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
        let payload = mask(&close_payload, key);
        let Some(WebSocketEvent::Close { code: actual, .. }) = text.accept(frame(
            true,
            false,
            WebSocketOpcode::Close,
            Some(key),
            &payload,
        ))?
        else {
            return Err(test_error().into());
        };
        assert_eq!(actual, code);
        let ping = mask(b"PING", key);
        assert_eq!(
            text.accept(frame(true, false, WebSocketOpcode::Text, Some(key), &ping,))
                .err()
                .map(|close| close.code()),
            Some(1002)
        );
    }
    for close_payload in [
        vec![1],
        999_u16.to_be_bytes().to_vec(),
        [1000_u16.to_be_bytes().as_slice(), &[0xff]].concat(),
    ] {
        let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
        let payload = mask(&close_payload, key);
        assert!(
            text.accept(frame(
                true,
                false,
                WebSocketOpcode::Close,
                Some(key),
                &payload
            ))
            .is_err()
        );
    }

    let mut text = WebSocketWire::new(WebSocketSubprotocol::TextIrcv3)?;
    let newline = mask(b"bad\nline", key);
    assert_eq!(
        text.accept(frame(
            true,
            false,
            WebSocketOpcode::Text,
            Some(key),
            &newline
        ))
        .err()
        .map(|close| close.code()),
        Some(1002)
    );

    let mut binary = WebSocketWire::new(WebSocketSubprotocol::BinaryIrcv3)?;
    let payload = mask(b"PING", key);
    let Some(WebSocketEvent::Message(message)) = binary.accept(frame(
        true,
        false,
        WebSocketOpcode::Binary,
        Some(key),
        &payload,
    ))?
    else {
        return Err(test_error().into());
    };
    assert_eq!(message.as_str(), "PING");
    Ok(())
}

#[test]
fn sasl_covers_abort_retry_finish_completion_and_failure_branches() -> Result<(), Box<dyn Error>> {
    let mut sasl = SaslTransport::new()?;
    assert_eq!(
        sasl.client("*", 0).err(),
        Some(AuthTransportError::BadState)
    );
    assert!(matches!(
        sasl.client("PLAIN", 0)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Mechanisms)]
    ));
    assert_eq!(
        sasl.client("AGENC-OPAQUE", u64::MAX).err(),
        Some(AuthTransportError::Overflow)
    );

    for invalid in ["+", "", "short"] {
        let mut carrier = SaslTransport::new()?;
        carrier.client("AGENC-OPAQUE", 0)?;
        assert!(carrier.client(invalid, 1).is_err(), "{invalid}");
    }
    let mut long = SaslTransport::new()?;
    long.client("AGENC-OPAQUE", 0)?;
    assert!(matches!(
        long.client(&"A".repeat(AUTH_CHUNK_CHARACTERS + 1), 1)?
            .as_slice(),
        [SaslAction::Numeric(SaslNumeric::TooLong)]
    ));
    assert!(matches!(
        long.client("AGENC-OPAQUE", 2)?.as_slice(),
        [SaslAction::SendPlus]
    ));
    let mut invalid_base64 = SaslTransport::new()?;
    invalid_base64.client("AGENC-OPAQUE", 0)?;
    for _ in 0..15 {
        invalid_base64.client(&"A".repeat(400), 1)?;
    }
    assert_eq!(
        invalid_base64.client(&"!".repeat(304), 1).err(),
        Some(AuthTransportError::InvalidChunk)
    );

    let request = vec![7_u8; ACCOUNT_REQUEST_BYTES];
    let response = vec![9_u8; ACCOUNT_RESPONSE_BYTES];
    let mut complete = SaslTransport::new()?;
    complete.client("AGENC-OPAQUE", 10)?;
    feed_sasl_request(&mut complete, &request, 11)?;
    assert_eq!(
        complete.client("anything", 12).err(),
        Some(AuthTransportError::BadState)
    );
    complete.server_response(&response, 12)?;
    feed_sasl_request(&mut complete, &request, 13)?;
    complete.server_response(&response, 13)?;
    assert!(matches!(
        complete.complete(true, 13)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Success)]
    ));
    assert!(matches!(
        complete.client("ignored", 14)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::AlreadyAuthenticated)]
    ));
    assert!(matches!(
        complete.client("*", 15)?.as_slice(),
        [SaslAction::Logout]
    ));
    assert_eq!(
        complete.complete(true, 15).err(),
        Some(AuthTransportError::BadState)
    );

    let mut rejected = SaslTransport::new()?;
    rejected.client("AGENC-OPAQUE", 0)?;
    feed_sasl_request(&mut rejected, &request, 1)?;
    rejected.server_response(&response, 1)?;
    feed_sasl_request(&mut rejected, &request, 2)?;
    rejected.server_response(&response, 2)?;
    assert!(matches!(
        rejected.complete(false, 2)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));

    let mut attempts = SaslTransport::new()?;
    for _ in 0..2 {
        attempts.client("AGENC-OPAQUE", 0)?;
        assert!(matches!(
            attempts.client("*", 1)?.as_slice(),
            [SaslAction::Numeric(SaslNumeric::Aborted)]
        ));
    }
    assert_eq!(
        attempts.client("AGENC-OPAQUE", 2).err(),
        Some(AuthTransportError::LimitExceeded)
    );

    let mut timed = SaslTransport::new()?;
    assert!(timed.tick(0)?.is_empty());
    timed.client("AGENC-OPAQUE", 5)?;
    assert!(timed.tick(5 + SASL_TIMEOUT_MILLIS - 1)?.is_empty());
    assert!(matches!(
        timed.tick(5 + SASL_TIMEOUT_MILLIS)?.as_slice(),
        [SaslAction::Numeric(SaslNumeric::Failed)]
    ));

    let mut client_deadline = SaslTransport::new()?;
    client_deadline.client("AGENC-OPAQUE", 20)?;
    assert_eq!(
        client_deadline
            .client(&"A".repeat(AUTH_CHUNK_CHARACTERS), 20 + SASL_TIMEOUT_MILLIS)
            .err(),
        Some(AuthTransportError::TimedOut)
    );

    let mut response_deadline = SaslTransport::new()?;
    response_deadline.client("AGENC-OPAQUE", 30)?;
    feed_sasl_request(&mut response_deadline, &request, 31)?;
    assert_eq!(
        response_deadline
            .server_response(&response, 30 + SASL_TIMEOUT_MILLIS)
            .err(),
        Some(AuthTransportError::TimedOut)
    );

    let mut completion_deadline = SaslTransport::new()?;
    completion_deadline.client("AGENC-OPAQUE", 40)?;
    feed_sasl_request(&mut completion_deadline, &request, 41)?;
    completion_deadline.server_response(&response, 42)?;
    feed_sasl_request(&mut completion_deadline, &request, 43)?;
    completion_deadline.server_response(&response, 44)?;
    assert_eq!(
        completion_deadline
            .complete(true, 40 + SASL_TIMEOUT_MILLIS)
            .err(),
        Some(AuthTransportError::TimedOut)
    );

    assert_eq!(
        SaslTransport::new()?.server_response(&response, 0).err(),
        Some(AuthTransportError::BadState)
    );
    let mut wrong = SaslTransport::new()?;
    wrong.client("AGENC-OPAQUE", 0)?;
    feed_sasl_request(&mut wrong, &request, 1)?;
    let short_response = response
        .get(..ACCOUNT_RESPONSE_BYTES - 1)
        .ok_or_else(test_error)?;
    assert_eq!(
        wrong.server_response(short_response, 1).err(),
        Some(AuthTransportError::WrongLength)
    );
    Ok(())
}

#[test]
fn account_carriers_cover_sequence_shape_finish_and_deadlines() -> Result<(), Box<dyn Error>> {
    let mut create = AccountTransfer::new(AccountCarrierKind::Create)?;
    let credentials = AccountTransfer::new(AccountCarrierKind::Credentials)?;
    assert_eq!(create.command(), "ACCTCREATE");
    assert_eq!(credentials.command(), "ACCTCRED");
    assert_eq!(
        create.client("START", Some("4726"), true, 0).err(),
        Some(AuthTransportError::TagsForbidden)
    );

    for (subcommand, parameter) in [
        ("START", None),
        ("START", Some("0")),
        ("FINISH", Some("4726")),
        ("DATA", Some("a")),
        ("END", Some("bad")),
        ("UNKNOWN", None),
    ] {
        let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
        assert!(transfer.client(subcommand, parameter, false, 0).is_err());
    }

    let mut missing = AccountTransfer::new(AccountCarrierKind::Create)?;
    missing.client("START", Some("4726"), false, 0)?;
    assert_eq!(
        missing.client("DATA", None, false, 1).err(),
        Some(AuthTransportError::InvalidChunk)
    );
    for invalid in ["a".repeat(399), "!".repeat(400)] {
        let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
        transfer.client("START", Some("4726"), false, 0)?;
        assert_eq!(
            transfer.client("DATA", Some(&invalid), false, 1).err(),
            Some(AuthTransportError::InvalidChunk)
        );
    }
    let mut early = AccountTransfer::new(AccountCarrierKind::Create)?;
    early.client("START", Some("4726"), false, 0)?;
    assert_eq!(
        early.client("END", None, false, 1).err(),
        Some(AuthTransportError::WrongLength)
    );

    let request = vec![3_u8; ACCOUNT_REQUEST_BYTES];
    let response = vec![4_u8; ACCOUNT_RESPONSE_BYTES];
    let mut full = AccountTransfer::new(AccountCarrierKind::Credentials)?;
    feed_account_request(&mut full, AccountCarrierPhase::Start, &request, 0)?;
    assert_eq!(
        full.server_response(AccountCarrierPhase::Finish, &response, 2)
            .err(),
        Some(AuthTransportError::BadState)
    );

    let mut full = AccountTransfer::new(AccountCarrierKind::Credentials)?;
    feed_account_request(&mut full, AccountCarrierPhase::Start, &request, 0)?;
    let start_actions = full.server_response(AccountCarrierPhase::Start, &response, 2)?;
    assert!(matches!(
        start_actions.first(),
        Some(AccountCarrierAction::ResponseStart(
            AccountCarrierPhase::Start
        ))
    ));
    feed_account_request(&mut full, AccountCarrierPhase::Finish, &request, 3)?;
    let finish_actions = full.server_response(AccountCarrierPhase::Finish, &response, 5)?;
    assert!(matches!(
        finish_actions.last(),
        Some(AccountCarrierAction::End)
    ));
    full.tick(ACCOUNT_TOTAL_TIMEOUT_MILLIS + 10)?;
    assert!(full.client("START", Some("4726"), false, 6).is_err());

    let mut idle = AccountTransfer::new(AccountCarrierKind::Create)?;
    idle.tick(u64::MAX)?;
    idle.client("START", Some("4726"), false, 10)?;
    assert!(idle.tick(10 + ACCOUNT_IDLE_TIMEOUT_MILLIS - 1).is_ok());
    assert_eq!(
        idle.tick(10 + ACCOUNT_IDLE_TIMEOUT_MILLIS).err(),
        Some(AuthTransportError::TimedOut)
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

#[test]
fn renderer_covers_registry_syntax_budgets_labels_and_batch_stack() -> Result<(), Box<dyn Error>> {
    for prefix in ["", "bad prefix", "bad\n"] {
        assert_eq!(
            WireMessage::new(prefix, "NOTICE", &[], None).err(),
            Some(RenderError::InvalidSyntax)
        );
    }
    for command in ["notice", "999", "NOPE"] {
        assert_eq!(
            WireMessage::new("server", command, &[], None).err(),
            Some(RenderError::UnknownRegistryValue)
        );
    }
    assert_eq!(
        WireMessage::new("server", "001", &[], Some("welcome")).err(),
        Some(RenderError::InapplicableReply)
    );
    let sixteen = vec!["x"; 16];
    assert_eq!(
        WireMessage::new("server", "NOTICE", &sixteen, None).err(),
        Some(RenderError::InvalidSyntax)
    );
    for middle in ["", ":bad", "bad value", "bad\r"] {
        assert_eq!(
            WireMessage::new("server", "NOTICE", &[middle], None).err(),
            Some(RenderError::InvalidSyntax)
        );
    }
    assert_eq!(
        WireMessage::new("server", "NOTICE", &[], Some("bad\n")).err(),
        Some(RenderError::InvalidSyntax)
    );
    assert_eq!(
        WireMessage::new("server", "BATCH", &["+raw", "labeled-response"], None).err(),
        Some(RenderError::InvalidBatch)
    );

    let advertised = CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("labeled-response", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("standard-replies", None)?,
    ])?;
    let mut render_capabilities = CapabilityState::default();
    render_capabilities.ls(Some("302"), &advertised)?;
    assert!(matches!(
        render_capabilities.request(
            "batch labeled-response message-tags standard-replies",
            &advertised,
        )?,
        CapRequestReply::Ack(_)
    ));

    let mut message = WireMessage::new("server", "NOTICE", &[], None)?;
    assert_eq!(
        message.add_server_tag("+client", None),
        Err(RenderError::InvalidSyntax)
    );
    assert_eq!(
        message.add_client_only_tag(&CapabilityState::default(), "+client", None),
        Err(RenderError::CapabilityRequired)
    );
    assert_eq!(
        message.add_client_only_tag(&render_capabilities, "server", None),
        Err(RenderError::InvalidSyntax)
    );
    for key in ["", "bad key", "bad;key", "bad=key"] {
        assert_eq!(
            message.add_server_tag(key, None),
            Err(RenderError::InvalidSyntax)
        );
    }
    message.add_server_tag("tag", None)?;
    assert_eq!(
        message.add_server_tag("tag", None),
        Err(RenderError::InvalidSyntax)
    );
    assert_eq!(
        message.add_server_tag("label", Some(&"x".repeat(MAX_CORRELATION_TAG_BYTES + 1))),
        Err(RenderError::InvalidSyntax)
    );
    assert_eq!(
        message.add_server_tag("batch", Some("raw")),
        Err(RenderError::InvalidSyntax)
    );
    message.add_client_only_tag(&render_capabilities, "+empty", None)?;
    let measured = message.measure()?;
    let measured_bytes = measured.bytes();
    let mut budget = ExactBudget(measured_bytes);
    let rendered = measured.encode(&mut budget)?;
    assert_eq!(rendered.permit().0, rendered.as_bytes().len());
    assert!(std::str::from_utf8(rendered.as_bytes())?.starts_with("@tag;+empty "));

    assert_eq!(
        WireMessage::new(
            "server",
            "NOTICE",
            &[],
            Some(&"x".repeat(MAX_COMMAND_BYTES)),
        )
        .err(),
        Some(RenderError::LineBudget)
    );
    let mut server_tags = WireMessage::new("server", "NOTICE", &[], None)?;
    assert_eq!(
        server_tags.add_server_tag("tag", Some(&"x".repeat(4_095))),
        Err(RenderError::LineBudget)
    );
    let mut client_tags = WireMessage::new("server", "NOTICE", &[], None)?;
    assert_eq!(
        client_tags.add_client_only_tag(&render_capabilities, "+tag", Some(&"x".repeat(4_095)),),
        Err(RenderError::LineBudget)
    );

    let bad = SafeReplyDescription::new("bad")?;
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "notice",
            PublicErrorCode::BADSTATE,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::UnknownRegistryValue)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Warn,
            "NOTICE",
            PublicErrorCode::CHALLENGE,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    let challenge = AccountDeletionToken::from_bytes([7_u8; 16]);
    let deletion_reply = standard_reply(
        &render_capabilities,
        "server",
        ReplyKind::Note,
        "ACCT",
        PublicErrorCode::DELETECHALLENGE,
        &[SafeReplyContext::DeletionChallenge(&challenge)],
        SafeReplyDescription::new("Confirm account deletion")?,
    )?;
    let deletion_bytes = deletion_reply.measure()?.bytes();
    let mut deletion_budget = ExactBudget(deletion_bytes);
    let deletion_reply = deletion_reply.measure()?.encode(&mut deletion_budget)?;
    assert!(
        std::str::from_utf8(deletion_reply.as_bytes())?
            .contains(" DELETE_CHALLENGE BwcHBwcHBwcHBwcHBwcHBw :Confirm account deletion")
    );

    let updated_channel = ChannelName::parse("#known-secret")?;
    assert!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Note,
            "CHANCTL",
            PublicErrorCode::UPDATED,
            &[SafeReplyContext::Channel(&updated_channel)],
            SafeReplyDescription::new("Channel setting updated")?,
        )
        .is_ok()
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "PRIVMSG",
            PublicErrorCode::E2EEREQUIRED,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "*",
            PublicErrorCode::SERVERBUSY,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Warn,
            "NOTICE",
            PublicErrorCode::SLOWCONSUMER,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &CapabilityState::default(),
            "server",
            ReplyKind::Note,
            "NOTICE",
            PublicErrorCode::BADSTATE,
            &[],
            SafeReplyDescription::new("ok")?,
        )
        .err(),
        Some(RenderError::CapabilityRequired)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Note,
            "NOTICE",
            PublicErrorCode::BADSTATE,
            &[],
            SafeReplyDescription::new("ok")?,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "ACK",
            PublicErrorCode::BADSTATE,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Note,
            "CHANCTL",
            PublicErrorCode::UPDATED,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Note,
            "ACCT",
            PublicErrorCode::DELETECHALLENGE,
            &[],
            bad,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert!(slow_consumer_warning(&render_capabilities, "server")?.is_some());
    assert!(slow_consumer_warning(&CapabilityState::default(), "server")?.is_none());
    assert_eq!(
        SafeReplyDescription::new(""),
        Err(RenderError::InvalidSyntax)
    );
    assert_eq!(
        SafeReplyDescription::new("bad\ntext"),
        Err(RenderError::InvalidSyntax)
    );
    const MAX_DESCRIPTION: &str = concat!(
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    );
    const OVERSIZED_DESCRIPTION: &str = concat!(
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "x",
    );
    assert!(SafeReplyDescription::new(MAX_DESCRIPTION).is_ok());
    assert_eq!(
        SafeReplyDescription::new(OVERSIZED_DESCRIPTION),
        Err(RenderError::InvalidSyntax)
    );

    let unrelated_contexts = [SafeReplyContext::Bounded(SafeContext::Maximum(u64::MAX)); 12];
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "NOTICE",
            PublicErrorCode::BADSTATE,
            &unrelated_contexts,
            SafeReplyDescription::new("bounded")?,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        standard_reply(
            &render_capabilities,
            "server",
            ReplyKind::Fail,
            "NOTICE",
            PublicErrorCode::BADSTATE,
            &[SafeReplyContext::Bounded(SafeContext::None)],
            SafeReplyDescription::new("bounded")?,
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    let channel = ChannelName::parse("#public")?;
    let typed_context = [SafeReplyContext::Channel(&channel)];
    let typed = standard_reply(
        &render_capabilities,
        "server",
        ReplyKind::Fail,
        "JOIN",
        PublicErrorCode::NETWORKUNAVAILABLE,
        &typed_context,
        SafeReplyDescription::new("Network unavailable")?,
    )?;
    let typed_bytes = typed.measure()?.bytes();
    let mut typed_budget = ExactBudget(typed_bytes);
    let typed = typed.measure()?.encode(&mut typed_budget)?;
    assert!(std::str::from_utf8(typed.as_bytes())?.contains(" #public :Network unavailable"));
    assert_eq!(
        numeric_reply("server", 999, "nick", &[], None).err(),
        Some(RenderError::UnknownRegistryValue)
    );
    assert_eq!(
        numeric_reply(
            "server",
            401,
            "nick",
            &["missing", "extra"],
            Some("No such nick"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert_eq!(
        numeric_reply("server", 1, "nick", &[], None).err(),
        Some(RenderError::InapplicableReply)
    );
    assert!(numeric_reply("server", 1, "nick", &[], Some("welcome")).is_ok());
    assert!(numeric_reply("server", 417, "nick", &[], Some("Input line was too long")).is_ok());
    assert!(numeric_reply("server", 252, "nick", &["1"], Some("operator online")).is_ok());
    assert_eq!(
        numeric_reply(
            "server",
            252,
            "nick",
            &["1", "unrelated"],
            Some("operator online"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert!(
        numeric_reply(
            "server",
            4,
            "nick",
            &["server", "version", "io", "io"],
            None
        )
        .is_ok()
    );
    assert!(
        numeric_reply(
            "server",
            900,
            "nick",
            &["nick!u-aaaaaaaaaa@h-aaaaaaaaaaaaaaaa.invalid", "account"],
            Some("You are now logged in"),
        )
        .is_ok()
    );
    assert_eq!(
        numeric_reply(
            "server",
            900,
            "nick",
            &["nick!u-aaaaaaaaaa@h-aaaaaaaaaaaaaaaa.invalid"],
            Some("You are now logged in"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );
    assert!(
        numeric_reply(
            "server",
            903,
            "nick",
            &[],
            Some("SASL authentication successful")
        )
        .is_ok()
    );
    assert_eq!(
        numeric_reply(
            "server",
            908,
            "nick",
            &["PLAIN"],
            Some("are available SASL mechanisms"),
        )
        .err(),
        Some(RenderError::InapplicableReply)
    );

    let network = NetworkId::from_bytes([0_u8; 32]);
    for display in ["", "bad name"] {
        assert_eq!(
            isupport_messages("server", "nick", display, &network).err(),
            Some(RenderError::InvalidSyntax)
        );
    }

    let no_capabilities = CapabilityState::default();

    let base = || WireMessage::new("server", "NOTICE", &["nick"], Some("ok"));
    assert!(
        labeled_response(&no_capabilities, "server", None, None, vec![])?
            .messages()
            .is_empty()
    );
    assert_eq!(
        labeled_response(
            &render_capabilities,
            "server",
            Some("empty-label"),
            None,
            vec![],
        )?
        .messages()
        .len(),
        1
    );
    assert_eq!(
        labeled_response(&no_capabilities, "server", None, None, vec![base()?])?
            .messages()
            .len(),
        1
    );
    assert_eq!(
        labeled_response(
            &no_capabilities,
            "server",
            Some("label"),
            None,
            vec![base()?],
        )?
        .messages()
        .len(),
        1
    );
    assert_eq!(
        labeled_response(
            &render_capabilities,
            "server",
            Some(""),
            None,
            vec![base()?],
        )
        .err(),
        Some(RenderError::InvalidCorrelation)
    );
    assert_eq!(
        labeled_response(
            &render_capabilities,
            "server",
            Some("label"),
            None,
            vec![base()?, base()?],
        )
        .err(),
        Some(RenderError::InvalidCorrelation)
    );
    assert_eq!(
        labeled_response(
            &no_capabilities,
            "server",
            None,
            None,
            (0..=MAX_SEMANTIC_REPLIES)
                .map(|_| base())
                .collect::<Result<Vec<_>, _>>()?,
        )
        .err(),
        Some(RenderError::TooManyReplies)
    );

    let mut batches = BatchStack::default();
    assert_eq!(
        batches.close("server", "none").err(),
        Some(RenderError::InvalidBatch)
    );
    assert_eq!(
        batches
            .open(&CapabilityState::default(), "server", "one", "label-one",)
            .err(),
        Some(RenderError::CapabilityRequired)
    );
    assert_eq!(batches.depth(), 0);
    let _open_one = batches.open(&render_capabilities, "server", "one", "label-one")?;
    assert_eq!(
        batches
            .open(&render_capabilities, "server", "one", "label-one")
            .err(),
        Some(RenderError::InvalidBatch)
    );
    let _open_two = batches.open(&render_capabilities, "server", "two", "label-two")?;
    let mut batched = base()?;
    batches.attach("one", &mut batched)?;
    assert_eq!(
        batches.attach("missing", &mut batched),
        Err(RenderError::InvalidBatch)
    );
    assert_eq!(
        batches.close("server", "one").err(),
        Some(RenderError::InvalidBatch)
    );
    let _close_two = batches.close("server", "two")?;
    let _close_one = batches.close("server", "one")?;
    assert_eq!(batches.depth(), 0);
    assert_eq!(
        batches.close("server", "one").err(),
        Some(RenderError::InvalidBatch)
    );
    for depth in 0..MAX_BATCH_NESTING {
        let _open = batches.open(
            &render_capabilities,
            "server",
            &format!("id-{depth}"),
            "label-nested",
        )?;
    }
    assert_eq!(batches.depth(), MAX_BATCH_NESTING);
    assert_eq!(
        batches
            .open(&render_capabilities, "server", "overflow", "label-overflow",)
            .err(),
        Some(RenderError::InvalidBatch)
    );
    Ok(())
}

#[test]
fn registration_covers_cap_pass_generation_close_and_keepalive_paths() -> Result<(), Box<dyn Error>>
{
    assert_eq!(
        RegistrationState::new(u64::MAX, AccessTokenPolicy::IgnoreCompatibilityPass).err(),
        Some(RegistrationError::Overflow)
    );
    let advertised = registration_capabilities()?;

    let mut negotiation = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert!(matches!(
        negotiation.message(parsed("PING :hello")?, 1, &advertised)?.as_slice(),
        [RegistrationAction::Pong(value)] if value == "hello"
    ));
    assert!(matches!(
        negotiation
            .message(parsed("PRIVMSG x :bad")?, 2, &advertised)?
            .as_slice(),
        [RegistrationAction::NotRegistered]
    ));
    for line in [
        "CAP",
        "CAP LS 302 extra",
        "CAP LS :bad",
        "CAP REQ",
        "CAP REQ extra :batch",
        "CAP WHAT",
    ] {
        assert!(
            negotiation.message(parsed(line)?, 3, &advertised).is_err(),
            "{line}"
        );
    }
    assert!(matches!(
        negotiation
            .message(parsed("CAP LS 302")?, 4, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityLs(_)]
    ));
    assert!(matches!(
        negotiation
            .message(parsed("CAP REQ :sasl")?, 5, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityRequest(CapRequestReply::Ack(
            _
        ))]
    ));
    let forwarded = negotiation.message(parsed("AUTHENTICATE AGENC-OPAQUE")?, 6, &advertised)?;
    let [
        RegistrationAction::ForwardAuthCarrier {
            generation,
            carrier: RegistrationAuthCarrier::Sasl,
            message,
        },
    ] = forwarded.as_slice()
    else {
        return Err(test_error().into());
    };
    assert_eq!(message.middle(), ["AGENC-OPAQUE"]);
    assert_eq!(
        negotiation
            .message(parsed("CAP END")?, 6, &advertised)
            .err(),
        Some(RegistrationError::AuthenticationInProgress)
    );
    negotiation.event(
        RegistrationEvent::AuthCarrierFinished {
            generation: *generation,
        },
        6,
    )?;
    assert!(matches!(
        negotiation
            .message(parsed("CAP REQ :message-tags batch")?, 7, &advertised)?
            .as_slice(),
        [RegistrationAction::CapabilityRequest(CapRequestReply::Ack(
            _
        ))]
    ));
    assert!(matches!(
        negotiation.message(parsed("CAP LIST")?, 7, &advertised)?.as_slice(),
        [RegistrationAction::CapabilityList { tokens, multiline: true }]
            if tokens.contains(&"batch".to_owned())
    ));
    assert!(
        negotiation
            .message(parsed("CAP END")?, 8, &advertised)?
            .is_empty()
    );
    assert!(
        negotiation
            .message(parsed("CAP END")?, 9, &advertised)
            .is_err()
    );

    for pass in ["PASS :", &format!("PASS :{}", "x".repeat(257))] {
        let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
        assert!(state.message(parsed(pass)?, 1, &advertised).is_err());
    }
    let mut repeat = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert!(
        repeat
            .message(parsed("PASS secret")?, 1, &advertised)?
            .is_empty()
    );
    assert!(matches!(
        repeat
            .message(parsed("PASS again")?, 2, &advertised)?
            .as_slice(),
        [RegistrationAction::AlreadyRegistered]
    ));

    let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let mut invalid_required =
        RegistrationState::new(0, AccessTokenPolicy::RequireConfiguredToken)?;
    assert_eq!(
        invalid_required
            .message(parsed("PASS invalid")?, 1, &advertised)
            .err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::InvalidArgument
        ))
    );
    let mut required = RegistrationState::new(0, AccessTokenPolicy::RequireConfiguredToken)?;
    let actions = required.message(parsed(&format!("PASS {token}"))?, 2, &advertised)?;
    let token_generation = token_generation(&actions)?;
    assert!(
        required
            .event(
                RegistrationEvent::AccessTokenChecked {
                    generation: token_generation + 1,
                    accepted: true
                },
                2
            )?
            .is_empty()
    );
    let close = required.event(
        RegistrationEvent::AccessTokenChecked {
            generation: token_generation,
            accepted: false,
        },
        2,
    )?;
    assert!(matches!(close.as_slice(), [RegistrationAction::Close(_)]));

    let mut fields = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert_eq!(
        fields
            .message(parsed("NICK bad,nick")?, 1, &advertised)
            .err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::InvalidArgument
        ))
    );
    assert_eq!(
        fields
            .message(parsed("USER only two :real")?, 2, &advertised)
            .err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::NeedMoreParameters
        ))
    );
    assert_eq!(
        fields
            .message(
                parsed(&format!("USER user 0 * :{}", "x".repeat(65)))?,
                3,
                &advertised
            )
            .err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::InputTooLong
        ))
    );
    assert!(
        fields
            .message(parsed("USER user 0 * :Real\u{7} Name")?, 4, &advertised)?
            .is_empty()
    );
    assert!(matches!(
        fields
            .message(parsed("USER user 0 * :again")?, 5, &advertised)?
            .as_slice(),
        [RegistrationAction::AlreadyRegistered]
    ));
    assert!(matches!(
        fields
            .message(parsed("PASS too-late")?, 6, &advertised)?
            .as_slice(),
        [RegistrationAction::AlreadyRegistered]
    ));
    let first = reserve_generation(&fields.message(parsed("NICK First")?, 7, &advertised)?)?;
    let second = reserve_generation(&fields.message(parsed("NICK Second")?, 8, &advertised)?)?;
    assert!(matches!(
        fields
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: first,
                    accepted: true
                },
                8
            )?
            .as_slice(),
        [RegistrationAction::ReleaseNickname { generation }] if *generation == first
    ));
    assert!(
        fields
            .event(
                RegistrationEvent::NicknameReserved {
                    generation: second,
                    accepted: false
                },
                8
            )?
            .is_empty()
    );
    let third = reserve_generation(&fields.message(parsed("NICK Third")?, 9, &advertised)?)?;
    let commit = commit_generation(&fields.event(
        RegistrationEvent::NicknameReserved {
            generation: third,
            accepted: true,
        },
        9,
    )?)?;
    assert!(
        fields
            .event(
                RegistrationEvent::RegistrationCommitted {
                    generation: commit + 1,
                    accepted: true,
                    authenticated: false
                },
                9
            )?
            .is_empty()
    );
    assert!(matches!(
        fields
            .event(
                RegistrationEvent::RegistrationCommitted {
                    generation: commit,
                    accepted: false,
                    authenticated: false
                },
                9
            )?
            .as_slice(),
        [
            RegistrationAction::ReleaseNickname { generation },
            RegistrationAction::Close(_)
        ] if *generation == third
    ));

    let mut registered = complete_registration(&advertised, true)?;
    assert_eq!(registered.phase(), RegistrationPhase::Registered);
    assert!(matches!(
        registered
            .message(parsed("PASS late")?, 10, &advertised)?
            .as_slice(),
        [RegistrationAction::AlreadyRegistered]
    ));
    assert!(matches!(
        registered.message(parsed("PING :value")?, 11, &advertised)?.as_slice(),
        [RegistrationAction::Pong(value)] if value == "value"
    ));
    assert!(matches!(
        registered
            .message(parsed("NOTICE x :ok")?, 12, &advertised)?
            .as_slice(),
        [RegistrationAction::ForwardRegisteredCommand(command)]
            if command.kind()
                == agenc_ircd_client_wire::RegisteredCommandKind::Public(
                    agenc_ircd_client_wire::PostRegistrationCommandKind::Notice
                )
                && command.message().command() == "NOTICE"
    ));
    assert!(
        registered
            .tick(12 + KEEPALIVE_IDLE_MILLIS - 1, None)?
            .is_empty()
    );
    assert_eq!(
        registered
            .tick(12 + KEEPALIVE_IDLE_MILLIS, Some("short"))
            .err(),
        Some(RegistrationError::InvalidRegistrationField)
    );
    let ping_at = 12 + KEEPALIVE_IDLE_MILLIS;
    let ping_token = "ABCDEFGHIJKLMNOPQRSTUV";
    assert!(matches!(
        registered.tick(ping_at, Some(ping_token))?.as_slice(),
        [RegistrationAction::Ping(value)] if value == ping_token
    ));
    registered.message(parsed("PONG wrong")?, ping_at + 1, &advertised)?;
    assert!(
        registered
            .tick(ping_at + KEEPALIVE_PONG_MILLIS - 1, None)?
            .is_empty()
    );
    assert!(matches!(
        registered
            .tick(ping_at + KEEPALIVE_PONG_MILLIS, None)?
            .as_slice(),
        [RegistrationAction::Close(_)]
    ));
    assert!(
        registered
            .message(
                parsed("QUIT :again")?,
                ping_at + KEEPALIVE_PONG_MILLIS + 1,
                &advertised
            )?
            .is_empty()
    );
    registered.event(
        RegistrationEvent::TransportClosed,
        ping_at + KEEPALIVE_PONG_MILLIS + 1,
    )?;
    assert_eq!(registered.phase(), RegistrationPhase::Closed);

    let mut pong = complete_registration(&advertised, false)?;
    let now = 20 + KEEPALIVE_IDLE_MILLIS;
    pong.tick(now, Some(ping_token))?;
    pong.message(parsed(&format!("PONG {ping_token}"))?, now + 1, &advertised)?;
    assert!(pong.tick(now + KEEPALIVE_PONG_MILLIS, None)?.is_empty());
    assert_eq!(
        pong.message(
            parsed(&format!("QUIT :{}", "q".repeat(300)))?,
            now + 2,
            &advertised
        )
        .err(),
        Some(RegistrationError::Grammar(
            RegistrationGrammarError::InputTooLong
        ))
    );
    assert!(matches!(
        pong.message(
            parsed(&format!("QUIT :{}", "q".repeat(256)))?,
            now + 3,
            &advertised
        )?
        .as_slice(),
        [RegistrationAction::Close(reason)] if reason.len() == 256
    ));
    Ok(())
}

#[test]
fn pending_queue_owns_exact_messages_and_applies_atomic_limits() -> Result<(), Box<dyn Error>> {
    let mut messages = PendingInputQueue::new()?;
    for _ in 0..16 {
        messages.admit(parsed("PING token")?)?;
    }
    assert_eq!(
        messages.admit(parsed("PING token")?).err(),
        Some(RegistrationError::PendingInputExceeded)
    );
    assert_eq!(messages.message_count(), 16);
    let ordered = messages.into_messages().collect::<Vec<_>>();
    assert_eq!(ordered.len(), 16);
    assert!(ordered.iter().all(|message| message.command() == "PING"));

    let large_line = format!("@+agenc.ag/e2ee={} PING token", "x".repeat(3_900));
    let mut bytes = PendingInputQueue::new()?;
    let mut admitted = 0;
    loop {
        match bytes.admit(parsed(&large_line)?) {
            Ok(()) => admitted += 1,
            Err(RegistrationError::PendingInputExceeded) => break,
            Err(error) => return Err(error.into()),
        }
    }
    assert!(admitted < 16);
    let admitted_bytes = bytes.backing_bytes();
    assert_eq!(
        bytes.admit(parsed(&large_line)?).err(),
        Some(RegistrationError::PendingInputExceeded)
    );
    assert_eq!(bytes.backing_bytes(), admitted_bytes);
    assert_eq!(bytes.into_messages().count(), admitted);

    Ok(())
}

#[test]
fn remaining_short_circuit_alternatives_are_observable() -> Result<(), Box<dyn Error>> {
    let advertised = registration_capabilities()?;
    let mut negotiating = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    assert!(negotiating.tick(1, None)?.is_empty());

    let token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let mut required = RegistrationState::new(0, AccessTokenPolicy::RequireConfiguredToken)?;
    let actions = required.message(parsed(&format!("PASS {token}"))?, 1, &advertised)?;
    let generation = token_generation(&actions)?;
    assert!(
        required
            .event(
                RegistrationEvent::AccessTokenChecked {
                    generation,
                    accepted: true,
                },
                1
            )?
            .is_empty()
    );

    assert_eq!(
        standard_reply(
            &CapabilityState::default(),
            "server",
            ReplyKind::Fail,
            "",
            PublicErrorCode::BADSTATE,
            &[],
            SafeReplyDescription::new("bad")?,
        )
        .err(),
        Some(RenderError::UnknownRegistryValue)
    );

    let mut transfer = AccountTransfer::new(AccountCarrierKind::Create)?;
    transfer.client("START", Some("4726"), false, 0)?;
    let encoded = URL_SAFE_NO_PAD.encode(vec![3_u8; ACCOUNT_REQUEST_BYTES]);
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        transfer.client("DATA", Some(std::str::from_utf8(chunk)?), false, 1)?;
    }
    assert_eq!(
        transfer
            .client("DATA", Some(&"a".repeat(302)), false, 2)
            .err(),
        Some(AuthTransportError::InvalidChunk)
    );
    Ok(())
}

fn parsed(line: &str) -> Result<agenc_ircd_client_wire::ParsedMessage, Box<dyn Error>> {
    parse_message(FramedLine::new(line)?)?
        .ok_or_else(|| io::Error::other("missing parsed message").into())
}

fn frame<'a>(
    fin: bool,
    reserved_bits: bool,
    opcode: WebSocketOpcode,
    mask: Option<[u8; 4]>,
    payload: &'a [u8],
) -> ClientWebSocketFrame<'a> {
    ClientWebSocketFrame {
        fin,
        reserved_bits,
        opcode,
        mask,
        payload,
    }
}

fn mask(payload: &[u8], key: [u8; 4]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(position, byte)| {
            let mask_byte = key.get(position % key.len()).copied().unwrap_or_default();
            *byte ^ mask_byte
        })
        .collect()
}

fn feed_sasl_request(
    sasl: &mut SaslTransport,
    request: &[u8],
    now: u64,
) -> Result<(), Box<dyn Error>> {
    let encoded = STANDARD.encode(request);
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        sasl.client(std::str::from_utf8(chunk)?, now)?;
    }
    Ok(())
}

fn feed_account_request(
    transfer: &mut AccountTransfer,
    phase: AccountCarrierPhase,
    request: &[u8],
    now: u64,
) -> Result<(), Box<dyn Error>> {
    let subcommand = match phase {
        AccountCarrierPhase::Start => "START",
        AccountCarrierPhase::Finish => "FINISH",
    };
    transfer.client(subcommand, Some("4726"), false, now)?;
    let encoded = URL_SAFE_NO_PAD.encode(request);
    for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        transfer.client("DATA", Some(std::str::from_utf8(chunk)?), false, now + 1)?;
    }
    transfer.client("END", None, false, now + 1)?;
    Ok(())
}

fn registration_capabilities() -> Result<CapabilityProfile, Box<dyn Error>> {
    Ok(CapabilityProfile::new(vec![
        CapabilitySpec::new("cap-notify", None)?,
        CapabilitySpec::new("message-tags", None)?,
        CapabilitySpec::new("batch", None)?,
        CapabilitySpec::new("sasl", Some("AGENC-OPAQUE"))?,
        CapabilitySpec::new("agenc.ag/account-create", Some("v1"))?,
        CapabilitySpec::new("agenc.ag/account-credentials", Some("v1"))?,
        CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?,
    ])?)
}

fn complete_registration(
    advertised: &CapabilityProfile,
    recovery: bool,
) -> Result<RegistrationState, Box<dyn Error>> {
    let mut state = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)?;
    if recovery {
        state.message(parsed("CAP LS 302")?, 1, advertised)?;
        state.message(parsed("CAP REQ :agenc.ag/recovery")?, 2, advertised)?;
    }
    let reserve = reserve_generation(&state.message(parsed("NICK Alice")?, 3, advertised)?)?;
    state.message(parsed("USER user 0 * :Real Name")?, 4, advertised)?;
    let actions = state.event(
        RegistrationEvent::NicknameReserved {
            generation: reserve,
            accepted: true,
        },
        4,
    )?;
    if recovery {
        assert!(actions.is_empty());
        let actions = state.message(parsed("CAP END")?, 5, advertised)?;
        let commit = commit_generation(&actions)?;
        state.event(
            RegistrationEvent::RegistrationCommitted {
                generation: commit,
                accepted: true,
                authenticated: false,
            },
            5,
        )?;
    } else {
        let commit = commit_generation(&actions)?;
        state.event(
            RegistrationEvent::RegistrationCommitted {
                generation: commit,
                accepted: true,
                authenticated: false,
            },
            4,
        )?;
    }
    Ok(state)
}

fn reserve_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(generation) = actions.iter().find_map(|action| match action {
        RegistrationAction::ReserveNickname { generation, .. }
        | RegistrationAction::ReplaceNickname { generation, .. } => Some(*generation),
        _ => None,
    }) else {
        return Err(io::Error::other("missing nickname reservation"));
    };
    Ok(generation)
}

fn token_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CheckAccessToken { generation, token }) = actions.first() else {
        return Err(io::Error::other("missing access-token check"));
    };
    assert_eq!(token.expose().len(), 32);
    Ok(*generation)
}

fn commit_generation(actions: &[RegistrationAction]) -> Result<u64, io::Error> {
    let Some(RegistrationAction::CommitRegistration { generation, .. }) = actions.first() else {
        return Err(io::Error::other("missing registration commit"));
    };
    Ok(*generation)
}

fn test_error() -> io::Error {
    io::Error::other("test fixture shape mismatch")
}
