//! Boundary coverage for renderable CAP ACK, NAK, and LIST payloads.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_client_wire::{
    CapError, CapRequestReply, CapabilityProfile, CapabilitySpec, CapabilityState,
    MAX_TRADITIONAL_LINE_BYTES, WireMessage,
};

const MAX_SERVER_NAME_WIRE_BYTES: usize = 253;
const MAX_CAP_TARGET_WIRE_BYTES: usize = 32;
const CAP_LIST_FIXED_BYTES: usize = 1
    + MAX_SERVER_NAME_WIRE_BYTES
    + 1
    + "CAP".len()
    + 1
    + MAX_CAP_TARGET_WIRE_BYTES
    + 1
    + "LIST".len()
    + 2;
const CAP_COMMAND_BYTES: usize = MAX_TRADITIONAL_LINE_BYTES - 2;
const CAP_TOKEN_LIST_BUDGET: usize = CAP_COMMAND_BYTES - CAP_LIST_FIXED_BYTES;
const MAX_SERVER_NAME: &str = concat!(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.",
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.",
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
);
const MAX_CAP_TARGET: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";

const EXACT_CAPABILITIES: &[&str] = &[
    "account-notify",
    "account-tag",
    "away-notify",
    "batch",
    "echo-message",
    "extended-join",
    "invite-notify",
    "labeled-response",
    "message-ids",
    "message-tags",
    "monitor",
    "multi-prefix",
    "sasl",
    "server-time",
    "setname",
    "standard-replies",
    "userhost-in-names",
    "sts",
];

const EXACT_REQUEST: &str = "account-notify account-tag away-notify batch echo-message \
extended-join invite-notify labeled-response message-ids message-tags monitor multi-prefix sasl \
server-time setname standard-replies userhost-in-names sts";
const EXACT_NAK_REQUEST: &str = "account-notify account-tag away-notify batch echo-message \
extended-join invite-notify labeled-response unknown-cap -message-ids monitor multi-prefix sasl \
server-time setname standard-replies userhost-in-names sts";
const PLUS_ONE_REQUEST: &str = "account-notify account-tag -away-notify batch echo-message \
extended-join invite-notify labeled-response message-ids message-tags monitor multi-prefix sasl \
server-time setname standard-replies userhost-in-names sts";

#[test]
fn capability_budget_remains_traditional_inside_the_extended_envelope() -> Result<(), Box<dyn Error>>
{
    assert_eq!(MAX_SERVER_NAME.len(), MAX_SERVER_NAME_WIRE_BYTES);
    assert_eq!(MAX_CAP_TARGET.len(), MAX_CAP_TARGET_WIRE_BYTES);

    let exact = WireMessage::new(
        MAX_SERVER_NAME,
        "CAP",
        &[MAX_CAP_TARGET, "LIST"],
        Some(EXACT_REQUEST),
    )?;
    assert_eq!(exact.measure()?.bytes(), MAX_TRADITIONAL_LINE_BYTES);
    let extended = WireMessage::new(
        MAX_SERVER_NAME,
        "CAP",
        &[MAX_CAP_TARGET, "LIST"],
        Some(PLUS_ONE_REQUEST),
    )?;
    assert_eq!(extended.measure()?.bytes(), MAX_TRADITIONAL_LINE_BYTES + 1);
    Ok(())
}

#[test]
fn req_accepts_exact_ack_and_rejects_plus_one_before_mutation() -> Result<(), Box<dyn Error>> {
    let profile = profile(&["cap-notify"])?;
    assert_eq!(EXACT_REQUEST.len(), CAP_TOKEN_LIST_BUDGET);
    assert_eq!(PLUS_ONE_REQUEST.len(), CAP_TOKEN_LIST_BUDGET + 1);

    let mut exact = CapabilityState::default();
    assert_eq!(
        exact.request(EXACT_REQUEST, &profile)?,
        CapRequestReply::Ack(request_tokens(EXACT_REQUEST)?)
    );
    assert_eq!(joined_length(&exact.list()?)?, CAP_TOKEN_LIST_BUDGET);

    let mut plus_one = CapabilityState::default();
    assert_eq!(
        plus_one.request(PLUS_ONE_REQUEST, &profile).err(),
        Some(CapError::LineBudget)
    );
    assert_eq!(plus_one, CapabilityState::default());
    Ok(())
}

#[test]
fn req_returns_an_exact_boundary_nak_without_enabling_any_token() -> Result<(), Box<dyn Error>> {
    let profile = profile(&[])?;
    assert_eq!(EXACT_NAK_REQUEST.len(), CAP_TOKEN_LIST_BUDGET);

    let mut state = CapabilityState::default();
    assert_eq!(
        state.request(EXACT_NAK_REQUEST, &profile)?,
        CapRequestReply::Nak(request_tokens(EXACT_NAK_REQUEST)?)
    );
    assert!(state.list()?.is_empty());
    Ok(())
}

#[test]
fn req_naks_a_projected_list_that_would_exceed_the_budget() -> Result<(), Box<dyn Error>> {
    let profile = profile(&["cap-notify"])?;
    let mut state = CapabilityState::default();
    assert!(matches!(
        state.request(EXACT_REQUEST, &profile)?,
        CapRequestReply::Ack(_)
    ));
    let before = state.try_clone()?;

    assert!(matches!(
        state.request("cap-notify", &profile)?,
        CapRequestReply::Nak(_)
    ));
    assert_eq!(state, before);
    assert_eq!(joined_length(&state.list()?)?, CAP_TOKEN_LIST_BUDGET);
    Ok(())
}

#[test]
fn cap_302_allows_a_multiline_enabled_list() -> Result<(), Box<dyn Error>> {
    let profile = profile(&["cap-notify"])?;
    let mut state = CapabilityState::default();
    assert!(matches!(
        state.request(EXACT_REQUEST, &profile)?,
        CapRequestReply::Ack(_)
    ));
    state.ls(Some("302"), &profile)?;
    let enabled = state.list()?;
    assert!(enabled.contains(&"cap-notify".to_owned()));
    assert!(joined_length(&enabled)? > CAP_TOKEN_LIST_BUDGET);
    assert!(state.supports_multiline());
    Ok(())
}

#[test]
fn cap_302_profile_change_can_grow_a_multiline_list() -> Result<(), Box<dyn Error>> {
    let old_profile = profile(&[])?;
    let new_profile = profile(&["cap-notify"])?;
    let mut state = CapabilityState::default();
    state.ls(Some("302"), &old_profile)?;
    assert!(matches!(
        state.request(EXACT_REQUEST, &old_profile)?,
        CapRequestReply::Ack(_)
    ));
    state.apply_profile(&new_profile)?;
    let enabled = state.list()?;
    assert!(enabled.contains(&"cap-notify".to_owned()));
    assert!(joined_length(&enabled)? > CAP_TOKEN_LIST_BUDGET);
    Ok(())
}

fn profile(extra: &[&str]) -> Result<CapabilityProfile, CapError> {
    let capacity = EXACT_CAPABILITIES
        .len()
        .checked_add(extra.len())
        .ok_or(CapError::Overflow)?;
    let mut capabilities = Vec::new();
    capabilities
        .try_reserve_exact(capacity)
        .map_err(|_| CapError::AllocationFailed)?;
    for name in EXACT_CAPABILITIES.iter().chain(extra) {
        let value = match *name {
            "sasl" => Some("AGENC-OPAQUE"),
            "sts" => Some("duration=31536000"),
            _ => None,
        };
        capabilities.push(CapabilitySpec::new(name, value)?);
    }
    CapabilityProfile::new(capabilities)
}

fn joined_length(tokens: &[String]) -> Result<usize, CapError> {
    let mut length = tokens.len().saturating_sub(1);
    for token in tokens {
        length = length.checked_add(token.len()).ok_or(CapError::Overflow)?;
    }
    Ok(length)
}

fn request_tokens(request: &str) -> Result<Vec<String>, CapError> {
    let token_count = request.split_ascii_whitespace().count();
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(token_count)
        .map_err(|_| CapError::AllocationFailed)?;
    for token in request.split_ascii_whitespace() {
        let mut owned = String::new();
        owned
            .try_reserve_exact(token.len())
            .map_err(|_| CapError::AllocationFailed)?;
        owned.push_str(token);
        tokens.push(owned);
    }
    Ok(tokens)
}
