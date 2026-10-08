#![forbid(unsafe_code)]
#![no_main]

use agenc_relay_client_wire::{
    ACCOUNT_REQUEST_BYTES, ACCOUNT_REQUEST_CHARACTERS, ACCOUNT_RESPONSE_BYTES,
    AUTH_CHUNK_CHARACTERS, AccessTokenPolicy, AccountCarrierKind, AccountCarrierPhase,
    AccountTransfer, CanonicalBase64Url, CapRequestReply, CapabilityChange, CapabilityProfile,
    CapabilitySpec, CapabilityState, FramedLine, KEEPALIVE_IDLE_MILLIS, MAX_COMMAND_BYTES,
    RegistrationAction, RegistrationEvent, RegistrationPhase, RegistrationState,
    SASL_REQUEST_CHARACTERS, SaslTransport, parse_message, parse_u16_decimal, parse_u32_decimal,
    parse_u64_decimal, split_capability_lines, validate_post_registration_command,
};
use agenc_relay_types::{DisplayName, MAX_DISPLAY_NAME_BYTES, NormalizedLogin};
use libfuzzer_sys::fuzz_target;

const MAX_CAPABILITY_OPERATIONS: usize = 64;
const RECOVERY_V1: &str = "v1.AAAAAAAAAAAAAAAAAAAAAA";
const RECOVERY_V2: &str = "v1.AQEBAQEBAQEBAQEBAQEBAQ";
const E2EE_V1: &str = "v1,profile=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,seg=2940,obj=262144,parts=90,welcome=4194304";
const E2EE_V2: &str = "v1,profile=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE,seg=2940,obj=262144,parts=90,welcome=4194304";
const POST_REGISTRATION_VALID: &[&str] = &[
    "JOIN 0",
    "PART #one",
    "MODE #one",
    "TOPIC #one",
    "NAMES",
    "LIST",
    "INVITE Nick #one",
    "KICK #one Nick",
    "PRIVMSG Nick :body",
    "NOTICE Nick :",
    "@+example TAGMSG Nick",
    "MOTD",
    "LUSERS",
    "VERSION",
    "TIME",
    "ADMIN",
    "INFO",
    "LINKS",
    "WHO",
    "WHOIS Nick",
    "WHOWAS Nick",
    "AWAY",
    "ISON Nick",
    "USERHOST Nick",
    "MONITOR C",
    "SETNAME :",
    "ACCT LABEL *",
    "CHANCTL REGISTER #one",
    "CHATHISTORY LATEST #one * 1",
];
const POST_REGISTRATION_INVALID: &[&str] = &[
    "JOIN",
    "PART",
    "MODE",
    "TOPIC",
    "NAMES #one extra",
    "LIST #one extra",
    "INVITE Nick",
    "KICK #one",
    "PRIVMSG Nick",
    "NOTICE",
    "TAGMSG Nick",
    "MOTD extra",
    "LUSERS extra",
    "VERSION extra",
    "TIME extra",
    "ADMIN extra",
    "INFO extra",
    "LINKS extra",
    "WHO a b",
    "WHOIS",
    "WHOWAS",
    "AWAY text",
    "ISON",
    "USERHOST",
    "MONITOR",
    "SETNAME text",
    "ACCT LABEL",
    "CHANCTL REGISTER",
    "CHATHISTORY LATEST #one * 0",
];

fuzz_target!(|data: &[u8]| {
    if data.len() > 32_768 {
        return;
    }
    exercise_decimal_and_base64(data);
    exercise_capability_state(data);
    exercise_registration(data);
    exercise_post_registration_grammar(data);
    exercise_display_name(data);
    match data.first().copied().unwrap_or_default() % 3 {
        0 => exercise_sasl(data),
        1 => exercise_account_transfer(data),
        _ => exercise_invalid_carriers(data),
    }
});

fn exercise_post_registration_grammar(data: &[u8]) {
    let selector =
        usize::from(data.first().copied().unwrap_or_default()) % POST_REGISTRATION_VALID.len();
    let Some(valid) = POST_REGISTRATION_VALID.get(selector) else {
        return;
    };
    let Some(invalid) = POST_REGISTRATION_INVALID.get(selector) else {
        return;
    };
    exercise_post_registration_line(valid, Some(true));
    exercise_post_registration_line(invalid, Some(false));
    if let Ok(arbitrary) = std::str::from_utf8(data) {
        exercise_post_registration_line(arbitrary, None);
    }
}

/// Display-name preparation prepares or refuses every input; a prepared name
/// is bounded and prepares to itself, and a `SETNAME` line carrying the same
/// text gets a grammar result.
fn exercise_display_name(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Ok(prepared) = DisplayName::prepare(&text) {
        assert!(prepared.as_str().len() <= MAX_DISPLAY_NAME_BYTES);
        let again = DisplayName::prepare(prepared.as_str());
        assert!(again.is_ok_and(|again| again.as_str() == prepared.as_str()));
    }
    let _login = NormalizedLogin::prepare(&text);
    let display = text.replace(['\r', '\n', '\0'], "");
    exercise_post_registration_line(&format!("SETNAME :{display}"), None);
}

fn exercise_post_registration_line(line: &str, expected: Option<bool>) {
    let Ok(line) = FramedLine::new(line) else {
        assert_ne!(expected, Some(true));
        return;
    };
    let Ok(Some(message)) = parse_message(line) else {
        assert_ne!(expected, Some(true));
        return;
    };
    let result = validate_post_registration_command(&message);
    if let Some(expected) = expected {
        assert_eq!(result.is_ok(), expected);
    }
}

#[derive(Clone, Copy)]
struct CapabilityOperation {
    kind: u8,
    variant: u8,
    detail: u8,
    extra: u8,
}

struct CapabilityProfiles {
    base: CapabilityProfile,
    changed: CapabilityProfile,
    reduced: CapabilityProfile,
    duplicate: Vec<CapabilitySpec>,
}

#[derive(Debug, Eq, PartialEq)]
struct CapabilitySnapshot {
    enabled: Vec<String>,
    blocks_registration: bool,
    reconnect_required: bool,
}

fn exercise_capability_state(data: &[u8]) {
    let Some(profiles) = capability_profiles() else {
        return;
    };
    let mut state = CapabilityState::default();
    let operation_count = data.len().div_ceil(4).clamp(1, MAX_CAPABILITY_OPERATIONS);
    for index in 0..operation_count {
        let offset = index.saturating_mul(4);
        let operation = CapabilityOperation {
            kind: data.get(offset).copied().unwrap_or_default(),
            variant: data
                .get(offset.saturating_add(1))
                .copied()
                .unwrap_or_default(),
            detail: data
                .get(offset.saturating_add(2))
                .copied()
                .unwrap_or_default(),
            extra: data
                .get(offset.saturating_add(3))
                .copied()
                .unwrap_or_default(),
        };
        match operation.kind % 8 {
            0 => exercise_capability_ls(&mut state, &profiles, operation),
            1 => exercise_capability_request(&mut state, &profiles.base, operation),
            2 => exercise_capability_end(&mut state),
            3 => assert_capability_invariants(&state),
            4 => exercise_capability_changes(&mut state, &profiles, operation),
            5 => exercise_capability_line_splitting(&state, operation),
            6 => exercise_duplicate_advertisement(&mut state, &profiles.duplicate),
            _ => state = CapabilityState::default(),
        }
        assert_capability_invariants(&state);
    }
}

fn exercise_capability_ls(
    state: &mut CapabilityState,
    profiles: &CapabilityProfiles,
    operation: CapabilityOperation,
) {
    let version = match operation.variant % 4 {
        0 => None,
        1 => Some("302"),
        2 => Some("301"),
        _ => Some(""),
    };
    let advertised = match operation.detail % 3 {
        0 => &profiles.base,
        1 => &profiles.changed,
        _ => &profiles.reduced,
    };
    let Some(before) = capability_snapshot(state) else {
        return;
    };
    match state.ls(version, advertised) {
        Ok(tokens) => {
            assert_eq!(tokens.len(), advertised.capabilities().len());
            assert!(version.is_none() || version == Some("302"));
            let budget = usize::from(operation.extra).max(1);
            if let Ok(lines) = split_capability_lines(&tokens, budget) {
                assert_capability_lines(&tokens, &lines, budget);
            }
        }
        Err(_) => assert_eq!(capability_snapshot(state), Some(before)),
    }
}

fn exercise_capability_request(
    state: &mut CapabilityState,
    advertised: &CapabilityProfile,
    operation: CapabilityOperation,
) {
    let request = capability_request(operation);
    let Some(before) = capability_snapshot(state) else {
        return;
    };
    match state.request(&request, advertised) {
        Ok(CapRequestReply::Ack(tokens)) => {
            assert_reply_tokens(&request, &tokens);
        }
        Ok(CapRequestReply::Nak(tokens)) => {
            assert_reply_tokens(&request, &tokens);
            assert_eq!(state.list().ok(), Some(before.enabled));
        }
        Err(_) => assert_eq!(capability_snapshot(state), Some(before)),
    }
}

fn exercise_capability_end(state: &mut CapabilityState) {
    let Some(before) = capability_snapshot(state) else {
        return;
    };
    let result = state.end();
    assert_eq!(state.list().ok(), Some(before.enabled));
    if result.is_ok() {
        assert!(!state.blocks_registration());
    } else {
        assert_eq!(state.blocks_registration(), before.blocks_registration);
    }
}

fn exercise_capability_changes(
    state: &mut CapabilityState,
    profiles: &CapabilityProfiles,
    operation: CapabilityOperation,
) {
    let current = match operation.variant % 3 {
        0 => &profiles.base,
        1 => &profiles.changed,
        _ => &profiles.reduced,
    };
    let Ok(before) = state.try_clone() else {
        return;
    };
    let Ok(mut mirror) = before.try_clone() else {
        return;
    };
    let first = state.apply_profile(current);
    let second = mirror.apply_profile(current);
    assert_eq!(first, second);
    if let Ok(changes) = first {
        assert_capability_changes(current.capabilities(), &changes);
        assert_enabled_in_profile(state, current);
        if changes
            .iter()
            .any(|change| matches!(change, CapabilityChange::ReconnectRequired(_)))
        {
            assert!(state.reconnect_required());
        }
    } else {
        assert_eq!(state, &before);
    }
}

fn exercise_capability_line_splitting(state: &CapabilityState, operation: CapabilityOperation) {
    let Ok(tokens) = state.list() else {
        return;
    };
    let budgets = [0, 1, 2, 63, 64, MAX_COMMAND_BYTES];
    let budget = budgets[usize::from(operation.variant) % budgets.len()];
    if let Ok(lines) = split_capability_lines(&tokens, budget) {
        assert_capability_lines(&tokens, &lines, budget);
    }
}

fn exercise_duplicate_advertisement(state: &mut CapabilityState, duplicate: &[CapabilitySpec]) {
    let Some(before) = capability_snapshot(state) else {
        return;
    };
    let mut copied = Vec::new();
    if copied.try_reserve_exact(duplicate.len()).is_err() {
        return;
    }
    for capability in duplicate {
        let Ok(capability) = capability.try_clone() else {
            return;
        };
        copied.push(capability);
    }
    assert!(CapabilityProfile::new(copied).is_err());
    assert_eq!(capability_snapshot(state), Some(before));
}

fn capability_request(operation: CapabilityOperation) -> String {
    const REQUESTS: &[&str] = &[
        "",
        "batch",
        "labeled-response",
        "batch labeled-response",
        "-batch",
        "-labeled-response -batch",
        "UNKNOWN",
        "Batch",
        "batch=value",
        "-",
        "-cap-notify",
        "message-tags echo-message batch labeled-response standard-replies account-tag agenc.ag/e2ee-mls",
        "agenc.ag/e2ee-mls",
        "draft/chathistory",
        "batch server-time message-ids draft/chathistory",
        "batch\nmessage-tags",
    ];
    let selector = usize::from(operation.variant) % (REQUESTS.len().saturating_add(2));
    if let Some(request) = REQUESTS.get(selector) {
        return (*request).to_owned();
    }
    if selector == REQUESTS.len() {
        return "x".repeat(MAX_COMMAND_BYTES.saturating_add(1));
    }
    generated_capability_request(operation)
}

fn generated_capability_request(operation: CapabilityOperation) -> String {
    const TOKENS: &[&str] = &[
        "batch",
        "labeled-response",
        "message-tags",
        "echo-message",
        "standard-replies",
        "account-tag",
        "agenc.ag/e2ee-mls",
        "agenc.ag/recovery",
        "server-time",
        "message-ids",
        "draft/chathistory",
        "cap-notify",
    ];
    let count = usize::from(operation.detail % 8).saturating_add(1);
    let mut request = String::new();
    for index in 0..count {
        if !request.is_empty() {
            request.push(' ');
        }
        if operation.extra.rotate_right(index as u32) & 1 != 0 {
            request.push('-');
        }
        let selector = usize::from(
            operation
                .variant
                .wrapping_add(operation.detail.wrapping_mul(index as u8)),
        ) % TOKENS.len();
        if let Some(token) = TOKENS.get(selector) {
            request.push_str(token);
        }
    }
    request
}

fn capability_profiles() -> Option<CapabilityProfiles> {
    let cap_notify = CapabilitySpec::new("cap-notify", None).ok()?;
    let batch = CapabilitySpec::new("batch", None).ok()?;
    let labeled = CapabilitySpec::new("labeled-response", None).ok()?;
    let message_tags = CapabilitySpec::new("message-tags", None).ok()?;
    let echo_message = CapabilitySpec::new("echo-message", None).ok()?;
    let standard_replies = CapabilitySpec::new("standard-replies", None).ok()?;
    let account_tag = CapabilitySpec::new("account-tag", None).ok()?;
    let server_time = CapabilitySpec::new("server-time", None).ok()?;
    let message_ids = CapabilitySpec::new("message-ids", None).ok()?;
    let chathistory = CapabilitySpec::new("draft/chathistory", None).ok()?;
    let recovery_v1 = CapabilitySpec::new("agenc.ag/recovery", Some(RECOVERY_V1)).ok()?;
    let recovery_v2 = CapabilitySpec::new("agenc.ag/recovery", Some(RECOVERY_V2)).ok()?;
    let e2ee_v1 = CapabilitySpec::new("agenc.ag/e2ee-mls", Some(E2EE_V1)).ok()?;
    let e2ee_v2 = CapabilitySpec::new("agenc.ag/e2ee-mls", Some(E2EE_V2)).ok()?;

    let base = CapabilityProfile::new(vec![
        cap_notify.try_clone().ok()?,
        batch.try_clone().ok()?,
        labeled.try_clone().ok()?,
        message_tags.try_clone().ok()?,
        echo_message.try_clone().ok()?,
        standard_replies.try_clone().ok()?,
        account_tag.try_clone().ok()?,
        server_time.try_clone().ok()?,
        message_ids.try_clone().ok()?,
        chathistory.try_clone().ok()?,
        recovery_v1,
        e2ee_v1,
    ])
    .ok()?;
    let changed = CapabilityProfile::new(vec![
        cap_notify.try_clone().ok()?,
        batch.try_clone().ok()?,
        labeled,
        message_tags,
        echo_message,
        standard_replies,
        account_tag,
        server_time,
        message_ids,
        chathistory,
        recovery_v2,
        e2ee_v2,
    ])
    .ok()?;
    let reduced = CapabilityProfile::new(vec![cap_notify, batch.try_clone().ok()?]).ok()?;
    let duplicate = vec![batch.try_clone().ok()?, batch];
    Some(CapabilityProfiles {
        base,
        changed,
        reduced,
        duplicate,
    })
}

fn capability_snapshot(state: &CapabilityState) -> Option<CapabilitySnapshot> {
    Some(CapabilitySnapshot {
        enabled: state.list().ok()?,
        blocks_registration: state.blocks_registration(),
        reconnect_required: state.reconnect_required(),
    })
}

fn assert_capability_invariants(state: &CapabilityState) {
    let Ok(enabled) = state.list() else {
        return;
    };
    for (index, name) in enabled.iter().enumerate() {
        assert!(!enabled[..index].contains(name));
    }
    assert_dependency(&enabled, "labeled-response", &["batch"]);
    assert_dependency(
        &enabled,
        "draft/chathistory",
        &["batch", "server-time", "message-ids"],
    );
    assert_dependency(
        &enabled,
        "agenc.ag/e2ee-mls",
        &[
            "message-tags",
            "echo-message",
            "batch",
            "labeled-response",
            "standard-replies",
            "account-tag",
        ],
    );
}

fn assert_dependency(enabled: &[String], capability: &str, dependencies: &[&str]) {
    if enabled.iter().any(|name| name == capability) {
        assert!(
            dependencies
                .iter()
                .all(|dependency| enabled.iter().any(|name| name == dependency))
        );
    }
}

fn assert_reply_tokens(request: &str, tokens: &[String]) {
    assert!(
        tokens
            .iter()
            .map(String::as_str)
            .eq(request.split_ascii_whitespace())
    );
}

fn assert_capability_lines(
    tokens: &[String],
    lines: &[agenc_relay_client_wire::CapLine],
    budget: usize,
) {
    assert!(!lines.is_empty());
    for (index, line) in lines.iter().enumerate() {
        assert!(line.capabilities.len() <= budget);
        assert_eq!(line.continuation, index.saturating_add(1) < lines.len());
    }
    assert!(
        lines
            .iter()
            .flat_map(|line| line.capabilities.split_ascii_whitespace())
            .eq(tokens.iter().map(String::as_str))
    );
}

fn assert_capability_changes(current: &[CapabilitySpec], changes: &[CapabilityChange]) {
    let mut names = Vec::new();
    for change in changes {
        let name = match change {
            CapabilityChange::New(token) => {
                let name = token.split_once('=').map_or(token.as_str(), |pair| pair.0);
                assert!(current.iter().any(|capability| capability.name() == name));
                name
            }
            CapabilityChange::Del(name) => {
                assert!(!current.iter().any(|capability| capability.name() == name));
                name.as_str()
            }
            CapabilityChange::ReconnectRequired(name) => {
                let new = current.iter().find(|capability| capability.name() == name);
                assert!(new.is_some());
                assert!(matches!(
                    name.as_str(),
                    "agenc.ag/recovery" | "agenc.ag/e2ee-mls"
                ));
                name.as_str()
            }
        };
        assert!(!names.contains(&name));
        names.push(name);
    }
}

fn assert_enabled_in_profile(state: &CapabilityState, profile: &CapabilityProfile) {
    assert!(state.enabled_names().iter().all(|name| {
        profile
            .capabilities()
            .iter()
            .any(|capability| capability.name() == name)
    }));
}

fn exercise_decimal_and_base64(data: &[u8]) {
    for value in ["0", "65535", "65536", "4294967295", "18446744073709551615"] {
        let _u16 = parse_u16_decimal(value);
        let _u32 = parse_u32_decimal(value);
        let _u64 = parse_u64_decimal(value);
    }
    let decimal: String = data
        .iter()
        .take(24)
        .map(|byte| char::from(b'0'.saturating_add(*byte % 10)))
        .collect();
    let _u16 = parse_u16_decimal(&decimal);
    let _u32 = parse_u32_decimal(&decimal);
    let _u64 = parse_u64_decimal(&decimal);

    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let token: String = data
        .iter()
        .take(128)
        .map(|byte| char::from(alphabet[usize::from(*byte) % alphabet.len()]))
        .collect();
    let _arbitrary = CanonicalBase64Url::parse(&token, 1, 96);
    let canonical = CanonicalBase64Url::parse("AQ", 1, 1);
    assert_eq!(
        canonical.as_ref().map(CanonicalBase64Url::as_bytes),
        Ok([1].as_slice())
    );
}

fn exercise_registration(data: &[u8]) {
    let Some(advertised) = advertised_capabilities() else {
        return;
    };
    let Ok(mut state) = RegistrationState::new(0, AccessTokenPolicy::IgnoreCompatibilityPass)
    else {
        return;
    };
    let request = if data.get(1).copied().unwrap_or_default() & 1 == 0 {
        "CAP REQ :batch labeled-response"
    } else {
        "CAP REQ :labeled-response"
    };
    let registration_now = data.len() as u64;
    for command in [
        "CAP LS 302",
        request,
        "NICK Fuzzer",
        "USER ignored 0 * :Fuzz User",
        "CAP END",
    ] {
        feed_registration(&mut state, &advertised, command, registration_now);
    }
    assert_eq!(state.phase(), RegistrationPhase::Registered);
    let idle_now = registration_now.saturating_add(KEEPALIVE_IDLE_MILLIS);
    let actions = state
        .tick(idle_now, Some("AAAAAAAAAAAAAAAAAAAAAA"))
        .unwrap_or_default();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, RegistrationAction::Ping(_)))
    );

    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(line) = FramedLine::new(text)
        && let Ok(Some(message)) = parse_message(line)
    {
        let _actions = state.message(message, idle_now, &advertised);
    }
}

fn advertised_capabilities() -> Option<CapabilityProfile> {
    CapabilityProfile::new(vec![
        CapabilitySpec::new("batch", None).ok()?,
        CapabilitySpec::new("cap-notify", None).ok()?,
        CapabilitySpec::new("labeled-response", None).ok()?,
        CapabilitySpec::new("message-tags", None).ok()?,
        CapabilitySpec::new("standard-replies", None).ok()?,
    ])
    .ok()
}

fn feed_registration(
    state: &mut RegistrationState,
    advertised: &CapabilityProfile,
    text: &str,
    now: u64,
) {
    let Ok(line) = FramedLine::new(text) else {
        return;
    };
    let Ok(Some(message)) = parse_message(line) else {
        return;
    };
    let Ok(actions) = state.message(message, now, advertised) else {
        return;
    };
    apply_registration_actions(state, actions, now);
}

fn apply_registration_actions(
    state: &mut RegistrationState,
    actions: Vec<RegistrationAction>,
    now: u64,
) {
    let mut pending = actions;
    while let Some(action) = pending.pop() {
        let event = match action {
            RegistrationAction::ReserveNickname { generation, .. } => {
                Some(RegistrationEvent::NicknameReserved {
                    generation,
                    accepted: true,
                })
            }
            RegistrationAction::CheckAccessToken { generation, token } => {
                Some(RegistrationEvent::AccessTokenChecked {
                    generation,
                    accepted: !token.expose().is_empty(),
                })
            }
            RegistrationAction::CommitRegistration { generation, .. } => {
                Some(RegistrationEvent::RegistrationCommitted {
                    generation,
                    accepted: true,
                    authenticated: false,
                })
            }
            _ => None,
        };
        if let Some(event) = event
            && let Ok(follow_up) = state.event(event, now)
        {
            pending.extend(follow_up);
        }
    }
}

fn exercise_sasl(data: &[u8]) {
    let Ok(mut sasl) = SaslTransport::new() else {
        return;
    };
    if sasl.client("AGENC-OPAQUE", 0).is_err() {
        return;
    }
    let mut request = "A".repeat(SASL_REQUEST_CHARACTERS.saturating_sub(2));
    request.push_str("==");
    feed_sasl_request(&mut sasl, &request);
    let response_byte = data.get(1).copied().unwrap_or_default();
    let response = vec![response_byte; ACCOUNT_RESPONSE_BYTES];
    let _response_actions = sasl.server_response(&response, 2);
    let _deadline = sasl.tick(30_000);
}

fn feed_sasl_request(sasl: &mut SaslTransport, request: &str) {
    let mut offset = 0usize;
    while offset < request.len() {
        let end = offset
            .saturating_add(AUTH_CHUNK_CHARACTERS)
            .min(request.len());
        let Some(chunk) = request.get(offset..end) else {
            return;
        };
        if sasl.client(chunk, 1).is_err() {
            return;
        }
        offset = end;
    }
}

fn exercise_account_transfer(data: &[u8]) {
    let Ok(mut transfer) = AccountTransfer::new(AccountCarrierKind::Create) else {
        return;
    };
    if transfer.client("START", Some("4726"), false, 0).is_err() {
        return;
    }
    let request = "A".repeat(ACCOUNT_REQUEST_CHARACTERS);
    for chunk in request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        let Ok(chunk) = std::str::from_utf8(chunk) else {
            return;
        };
        if transfer.client("DATA", Some(chunk), false, 1).is_err() {
            return;
        }
    }
    let _request = transfer.client("END", None, false, 2);
    let response = vec![data.get(1).copied().unwrap_or_default(); ACCOUNT_RESPONSE_BYTES];
    let _response = transfer.server_response(AccountCarrierPhase::Start, &response, 3);
    let _deadline = transfer.tick(60_000);
    assert_eq!(
        request.len(),
        ACCOUNT_REQUEST_BYTES.saturating_mul(4).div_ceil(3)
    );
}

fn exercise_invalid_carriers(data: &[u8]) {
    let chunk = safe_carrier(data, AUTH_CHUNK_CHARACTERS.saturating_add(1));
    if let Ok(mut sasl) = SaslTransport::new() {
        let _mechanism = sasl.client("AGENC-OPAQUE", u64::MAX);
        let _chunk = sasl.client(&chunk, 0);
        let _abort = sasl.client("*", 1);
    }
    if let Ok(mut account) = AccountTransfer::new(AccountCarrierKind::Credentials) {
        let _start = account.client("FINISH", Some("4726"), false, 0);
        let _tags = account.client("DATA", Some(&chunk), true, 1);
        let _timeout = account.tick(u64::MAX);
    }
}

fn safe_carrier(data: &[u8], maximum: usize) -> String {
    data.iter()
        .take(maximum)
        .map(|byte| char::from(b'A'.saturating_add(*byte % 26)))
        .collect()
}
