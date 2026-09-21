//! Case-sensitive IRCv3 capability negotiation and change notification.

use std::error::Error;
use std::fmt;

use agenc_relay_types::CAPABILITIES;

use crate::{CanonicalBase64Url, MAX_TRADITIONAL_LINE_BYTES};

const MAX_CAP_COMMAND_BYTES: usize = MAX_TRADITIONAL_LINE_BYTES - 2;

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
// ACK, NAK, and legacy LIST cannot continue, so reserve the longest
// non-continuation CAP form at the frozen server-name and nickname maxima.
const MAX_CAP_TOKEN_LIST_BYTES: usize = MAX_CAP_COMMAND_BYTES - CAP_LIST_FIXED_BYTES;

/// One currently advertisable capability and optional LS/NEW value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySpec {
    name: String,
    value: Option<String>,
}

impl CapabilitySpec {
    /// Creates a known bare capability name and optional advertised value.
    pub fn new(name: &str, value: Option<&str>) -> Result<Self, CapError> {
        if !CAPABILITIES.contains(&name) || name.contains('=') || name.contains(' ') {
            return Err(CapError::UnknownCapability);
        }
        if value.is_some_and(|value| {
            value.is_empty()
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b' ')
        }) {
            return Err(CapError::InvalidValue);
        }
        validate_profile_value(name, value)?;
        let value_length = value
            .map(|value| value.len().checked_add(1).ok_or(CapError::Overflow))
            .transpose()?
            .unwrap_or(0);
        let encoded_length = name
            .len()
            .checked_add(value_length)
            .ok_or(CapError::Overflow)?;
        if encoded_length > MAX_CAP_TOKEN_LIST_BYTES {
            return Err(CapError::LineBudget);
        }
        Ok(Self {
            name: copy_string(name)?,
            value: value.map(copy_string).transpose()?,
        })
    }

    /// Returns the opaque, case-sensitive bare name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the value advertised only through LS or NEW.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Fallibly duplicates this bounded specification.
    pub fn try_clone(&self) -> Result<Self, CapError> {
        Ok(Self {
            name: copy_string(&self.name)?,
            value: self.value.as_deref().map(copy_string).transpose()?,
        })
    }

    fn ls_token(&self, include_value: bool) -> Result<String, CapError> {
        if !include_value {
            return copy_string(&self.name);
        }
        let Some(value) = &self.value else {
            return copy_string(&self.name);
        };
        let capacity = self
            .name
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(CapError::Overflow)?;
        let mut token = String::new();
        token
            .try_reserve_exact(capacity)
            .map_err(|_| CapError::AllocationFailed)?;
        token.push_str(&self.name);
        token.push('=');
        token.push_str(value);
        Ok(token)
    }
}

/// One dependency-complete, duplicate-free capability advertisement.
#[derive(Debug, Eq, PartialEq)]
pub struct CapabilityProfile {
    capabilities: Vec<CapabilitySpec>,
}

impl CapabilityProfile {
    /// Validates and consumes one complete advertised capability set.
    pub fn new(capabilities: Vec<CapabilitySpec>) -> Result<Self, CapError> {
        validate_advertisement(&capabilities)?;
        let mut normalized = Vec::new();
        normalized
            .try_reserve_exact(capabilities.len())
            .map_err(|_| CapError::AllocationFailed)?;
        for capability in capabilities {
            normalized.push(capability);
        }
        Ok(Self {
            capabilities: normalized,
        })
    }

    /// Borrows capability specifications in advertised order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilitySpec] {
        &self.capabilities
    }

    fn contains(&self, name: &str) -> bool {
        self.capabilities
            .iter()
            .any(|capability| capability.name == name)
    }
}

/// One capability availability/value transition.
#[derive(Debug, Eq, PartialEq)]
pub enum CapabilityChange {
    /// Advertise the complete new token through CAP NEW.
    New(String),
    /// Remove the bare capability name through CAP DEL.
    Del(String),
    /// A security-profile value changed and requires a reconnect.
    ReconnectRequired(String),
}

/// Atomic response to one CAP REQ.
#[derive(Debug, Eq, PartialEq)]
pub enum CapRequestReply {
    /// Every requested transition was applied; tokens preserve request order.
    Ack(Vec<String>),
    /// Nothing changed; tokens preserve the rejected request order.
    Nak(Vec<String>),
}

/// One bounded CAP LS continuation segment.
#[derive(Debug, Eq, PartialEq)]
pub struct CapLine {
    /// Whether another CAP line follows this one.
    pub continuation: bool,
    /// Space-separated capability tokens.
    pub capabilities: String,
}

/// Closed capability negotiation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapError {
    /// The LS version was neither absent nor exactly `302`.
    UnsupportedVersion,
    /// A capability was absent from the frozen registry or advertisement.
    UnknownCapability,
    /// A name/value token violated the local grammar.
    InvalidValue,
    /// An advertised set duplicated a name or exceeded the closed registry.
    InvalidAdvertisement,
    /// A request omitted a required companion or broke an enabled dependency.
    MissingDependency,
    /// CAP END occurred more than once or before negotiation started.
    InvalidState,
    /// A capability token or unsplittable token list exceeded the line budget.
    LineBudget,
    /// A checked line-size calculation overflowed.
    Overflow,
    /// One bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for CapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "CAP LS version must be absent or exactly 302",
            Self::UnknownCapability => "capability is not available",
            Self::InvalidValue => "capability token or value is invalid",
            Self::InvalidAdvertisement => "capability advertisement is invalid",
            Self::MissingDependency => "capability dependency is not enabled",
            Self::InvalidState => "capability negotiation state is invalid",
            Self::LineBudget => "capability response exceeds the line budget",
            Self::Overflow => "capability line calculation overflowed",
            Self::AllocationFailed => "capability allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for CapError {}

/// Pure per-connection capability negotiation state.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct CapabilityState {
    started: bool,
    ended: bool,
    version_302: bool,
    profile_initialized: bool,
    reconnect_required: bool,
    advertised: Vec<CapabilitySpec>,
    enabled: Vec<String>,
}

impl CapabilityState {
    /// Starts or refreshes CAP LS and returns tokens with advertised values.
    pub fn ls(
        &mut self,
        version: Option<&str>,
        profile: &CapabilityProfile,
    ) -> Result<Vec<String>, CapError> {
        if version.is_some_and(|version| version != "302") {
            return Err(CapError::UnsupportedVersion);
        }
        let advertised = profile.capabilities();
        let stored_profile = self.prepare_profile(profile)?;
        let reply_uses_values = version == Some("302");
        let version_302 = self.version_302 || reply_uses_values;
        let mut enabled = copy_strings(&self.enabled)?;
        if version_302
            && advertised
                .iter()
                .any(|capability| capability.name == "cap-notify")
        {
            insert_unique(&mut enabled, "cap-notify")?;
        }
        ensure_enabled_list_renderable(&enabled, version_302)?;
        let mut tokens = Vec::new();
        tokens
            .try_reserve_exact(advertised.len())
            .map_err(|_| CapError::AllocationFailed)?;
        for capability in advertised {
            tokens.push(capability.ls_token(reply_uses_values)?);
        }
        self.started = true;
        self.ended = false;
        self.version_302 = version_302;
        if let Some(stored_profile) = stored_profile {
            self.advertised = stored_profile;
            self.profile_initialized = true;
        }
        self.enabled = enabled;
        Ok(tokens)
    }

    /// Applies an all-or-nothing CAP REQ using bare names and `-name` disables.
    pub fn request(
        &mut self,
        request: &str,
        profile: &CapabilityProfile,
    ) -> Result<CapRequestReply, CapError> {
        if request.len() > MAX_CAP_COMMAND_BYTES
            || request.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(CapError::InvalidValue);
        }
        let token_count = request.split_ascii_whitespace().count();
        let mut tokens = Vec::new();
        tokens
            .try_reserve_exact(token_count)
            .map_err(|_| CapError::AllocationFailed)?;
        for token in request.split_ascii_whitespace() {
            tokens.push(copy_string(token)?);
        }
        ensure_token_list_renderable(&tokens)?;
        let advertised = profile.capabilities();
        let stored_profile = self.prepare_profile(profile)?;
        let mut projected = copy_strings(&self.enabled)?;
        let transition = if tokens.is_empty() {
            Err(CapError::InvalidValue)
        } else {
            apply_requested_tokens(&mut projected, &tokens, advertised, self.version_302)
                .and_then(|()| validate_dependencies(&projected))
                .and_then(|()| ensure_enabled_list_renderable(&projected, self.version_302))
        };
        let reply = match transition {
            Ok(()) => {
                self.enabled = projected;
                CapRequestReply::Ack(tokens)
            }
            Err(error @ (CapError::AllocationFailed | CapError::Overflow)) => return Err(error),
            Err(_) => CapRequestReply::Nak(tokens),
        };
        self.started = true;
        self.ended = false;
        if let Some(stored_profile) = stored_profile {
            self.advertised = stored_profile;
            self.profile_initialized = true;
        }
        Ok(reply)
    }

    /// Returns enabled bare names for CAP LIST.
    pub fn list(&self) -> Result<Vec<String>, CapError> {
        ensure_enabled_list_renderable(&self.enabled, self.version_302)?;
        copy_strings(&self.enabled)
    }

    /// Completes negotiation, including an initial standalone `CAP END`.
    pub fn end(&mut self) -> Result<(), CapError> {
        if self.ended {
            return Err(CapError::InvalidState);
        }
        self.started = true;
        self.ended = true;
        Ok(())
    }

    /// Returns whether registration must still wait for CAP END.
    #[must_use]
    pub const fn blocks_registration(&self) -> bool {
        self.started && !self.ended
    }

    /// Returns whether one exact capability name is enabled.
    #[must_use]
    pub fn enabled(&self, name: &str) -> bool {
        self.enabled.iter().any(|candidate| candidate == name)
    }

    /// Borrows the enabled bare names for a registered-session handoff.
    #[must_use]
    pub fn enabled_names(&self) -> &[String] {
        &self.enabled
    }

    /// Returns whether CAP 302 multiline LS and LIST rendering is active.
    #[must_use]
    pub const fn supports_multiline(&self) -> bool {
        self.version_302
    }

    /// Fallibly duplicates the complete bounded negotiation state.
    pub fn try_clone(&self) -> Result<Self, CapError> {
        Ok(Self {
            started: self.started,
            ended: self.ended,
            version_302: self.version_302,
            profile_initialized: self.profile_initialized,
            reconnect_required: self.reconnect_required,
            advertised: copy_specs(&self.advertised)?,
            enabled: copy_strings(&self.enabled)?,
        })
    }

    /// Applies one validated availability change and updates enabled state atomically.
    pub fn apply_profile(
        &mut self,
        current: &CapabilityProfile,
    ) -> Result<Vec<CapabilityChange>, CapError> {
        if !self.profile_initialized {
            return Err(CapError::InvalidState);
        }
        let changes = diff_advertisements(&self.advertised, current.capabilities())?;
        let mut enabled = Vec::new();
        enabled
            .try_reserve_exact(self.enabled.len())
            .map_err(|_| CapError::AllocationFailed)?;
        for name in &self.enabled {
            let Some(previous) = self
                .advertised
                .iter()
                .find(|capability| capability.name == *name)
            else {
                continue;
            };
            let Some(next) = current
                .capabilities()
                .iter()
                .find(|capability| capability.name == *name)
            else {
                continue;
            };
            if previous.value != next.value && reconnects_on_value_change(name) {
                continue;
            }
            enabled.push(copy_string(name)?);
        }
        if self.version_302 && current.contains("cap-notify") {
            insert_unique(&mut enabled, "cap-notify")?;
        }
        validate_dependencies(&enabled)?;
        ensure_enabled_list_renderable(&enabled, self.version_302)?;
        let advertised = copy_specs(current.capabilities())?;
        let reconnect_required = self.reconnect_required
            || changes
                .iter()
                .any(|change| matches!(change, CapabilityChange::ReconnectRequired(_)));
        self.enabled = enabled;
        self.advertised = advertised;
        self.reconnect_required = reconnect_required;
        Ok(changes)
    }

    /// Returns whether a security-profile transition requires reconnect.
    #[must_use]
    pub const fn reconnect_required(&self) -> bool {
        self.reconnect_required
    }

    fn prepare_profile(
        &self,
        profile: &CapabilityProfile,
    ) -> Result<Option<Vec<CapabilitySpec>>, CapError> {
        if !self.profile_initialized {
            return copy_specs(profile.capabilities()).map(Some);
        }
        if self.advertised == profile.capabilities() {
            Ok(None)
        } else {
            Err(CapError::InvalidAdvertisement)
        }
    }
}

fn diff_advertisements(
    previous: &[CapabilitySpec],
    current: &[CapabilitySpec],
) -> Result<Vec<CapabilityChange>, CapError> {
    let capacity = previous
        .len()
        .checked_add(current.len())
        .ok_or(CapError::Overflow)?;
    let mut changes = Vec::new();
    changes
        .try_reserve_exact(capacity)
        .map_err(|_| CapError::AllocationFailed)?;
    for old in previous {
        match current.iter().find(|new| new.name == old.name) {
            None => changes.push(CapabilityChange::Del(copy_string(&old.name)?)),
            Some(new) if new.value != old.value && reconnects_on_value_change(&old.name) => {
                changes.push(CapabilityChange::ReconnectRequired(copy_string(&old.name)?));
            }
            Some(new) if new.value != old.value => {
                changes.push(CapabilityChange::New(new.ls_token(true)?));
            }
            Some(_) => {}
        }
    }
    for new in current {
        if !previous.iter().any(|old| old.name == new.name) {
            changes.push(CapabilityChange::New(new.ls_token(true)?));
        }
    }
    Ok(changes)
}

/// Splits CAP 302 LS or LIST tokens without splitting a token or exceeding `budget`.
///
/// Callers must use the continuation marker only after CAP 302 negotiation.
pub fn split_capability_lines(tokens: &[String], budget: usize) -> Result<Vec<CapLine>, CapError> {
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(tokens.len().max(1))
        .map_err(|_| CapError::AllocationFailed)?;
    let mut current = String::new();
    for token in tokens {
        if token.len() > budget {
            return Err(CapError::LineBudget);
        }
        let separator = usize::from(!current.is_empty());
        let next = current
            .len()
            .checked_add(separator)
            .and_then(|length| length.checked_add(token.len()))
            .ok_or(CapError::Overflow)?;
        if next > budget {
            lines.push(CapLine {
                continuation: true,
                capabilities: current,
            });
            current = copy_string(token)?;
        } else {
            let additional = token
                .len()
                .checked_add(separator)
                .ok_or(CapError::Overflow)?;
            current
                .try_reserve_exact(additional)
                .map_err(|_| CapError::AllocationFailed)?;
            if separator != 0 {
                current.push(' ');
            }
            current.push_str(token);
        }
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(CapLine {
            continuation: false,
            capabilities: current,
        });
    } else if let Some(last) = lines.last_mut() {
        last.continuation = false;
    }
    Ok(lines)
}

fn apply_requested_tokens(
    projected: &mut Vec<String>,
    tokens: &[String],
    advertised: &[CapabilitySpec],
    version_302: bool,
) -> Result<(), CapError> {
    for token in tokens {
        let (disable, name) = token
            .strip_prefix('-')
            .map_or((false, token.as_str()), |name| (true, name));
        if name.is_empty() || name.contains('=') {
            return Err(CapError::InvalidValue);
        }
        if !advertised.iter().any(|capability| capability.name == name) {
            return Err(CapError::UnknownCapability);
        }
        if disable {
            if version_302 && name == "cap-notify" {
                return Err(CapError::InvalidState);
            }
            projected.retain(|enabled| enabled != name);
        } else {
            insert_unique(projected, name)?;
        }
    }
    Ok(())
}

fn validate_dependencies(enabled: &[String]) -> Result<(), CapError> {
    for capability in enabled {
        for dependency in dependencies(capability) {
            if !enabled.iter().any(|candidate| candidate == dependency) {
                return Err(CapError::MissingDependency);
            }
        }
    }
    Ok(())
}

fn ensure_token_list_renderable(tokens: &[String]) -> Result<(), CapError> {
    let mut length = tokens.len().saturating_sub(1);
    for token in tokens {
        length = length.checked_add(token.len()).ok_or(CapError::Overflow)?;
    }
    if length > MAX_CAP_TOKEN_LIST_BYTES {
        Err(CapError::LineBudget)
    } else {
        Ok(())
    }
}

fn ensure_enabled_list_renderable(tokens: &[String], multiline: bool) -> Result<(), CapError> {
    if multiline {
        Ok(())
    } else {
        ensure_token_list_renderable(tokens)
    }
}

fn dependencies(capability: &str) -> &'static [&'static str] {
    match capability {
        "labeled-response" => &["batch"],
        "extended-join" => &["account-notify"],
        "draft/chathistory" => &["batch", "server-time", "message-ids"],
        "agenc.ag/e2ee-mls" => &[
            "message-tags",
            "echo-message",
            "batch",
            "labeled-response",
            "standard-replies",
            "account-tag",
        ],
        _ => &[],
    }
}

fn insert_unique(values: &mut Vec<String>, value: &str) -> Result<(), CapError> {
    if !values.iter().any(|candidate| candidate == value) {
        values
            .try_reserve(1)
            .map_err(|_| CapError::AllocationFailed)?;
        values.push(copy_string(value)?);
    }
    Ok(())
}

fn validate_profile_value(name: &str, value: Option<&str>) -> Result<(), CapError> {
    let valid = match name {
        "agenc.ag/privacy"
        | "agenc.ag/account-controls"
        | "agenc.ag/account-credentials"
        | "agenc.ag/channel-controls"
        | "agenc.ag/account-create" => value == Some("v1"),
        "agenc.ag/recovery" => value
            .and_then(|value| value.strip_prefix("v1."))
            .is_some_and(|epoch| CanonicalBase64Url::parse(epoch, 16, 16).is_ok()),
        "agenc.ag/e2ee-mls" => value.is_some_and(validate_e2ee_value),
        "sasl" => value == Some("AGENC-OPAQUE"),
        "sts" => value == Some("duration=31536000"),
        _ => value.is_none(),
    };
    if valid {
        Ok(())
    } else {
        Err(CapError::InvalidValue)
    }
}

fn reconnects_on_value_change(name: &str) -> bool {
    matches!(name, "agenc.ag/recovery" | "agenc.ag/e2ee-mls")
}

fn validate_e2ee_value(value: &str) -> bool {
    const PREFIX: &str = "v1,profile=";
    const SUFFIX: &str = ",seg=2940,obj=262144,parts=90,welcome=4194304";

    value
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .is_some_and(|profile_hash| CanonicalBase64Url::parse(profile_hash, 32, 32).is_ok())
}

fn validate_advertisement(advertised: &[CapabilitySpec]) -> Result<(), CapError> {
    if advertised.len() > CAPABILITIES.len() {
        return Err(CapError::InvalidAdvertisement);
    }
    for (index, capability) in advertised.iter().enumerate() {
        let (previous, _) = advertised.split_at(index);
        if previous
            .iter()
            .any(|previous| previous.name == capability.name)
        {
            return Err(CapError::InvalidAdvertisement);
        }
        if dependencies(&capability.name).iter().any(|dependency| {
            !advertised
                .iter()
                .any(|candidate| candidate.name == *dependency)
        }) {
            return Err(CapError::InvalidAdvertisement);
        }
    }
    Ok(())
}

fn copy_string(value: &str) -> Result<String, CapError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| CapError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn copy_strings(values: &[String]) -> Result<Vec<String>, CapError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(values.len())
        .map_err(|_| CapError::AllocationFailed)?;
    for value in values {
        copied.push(copy_string(value)?);
    }
    Ok(copied)
}

fn copy_specs(values: &[CapabilitySpec]) -> Result<Vec<CapabilitySpec>, CapError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(values.len())
        .map_err(|_| CapError::AllocationFailed)?;
    for value in values {
        copied.push(CapabilitySpec {
            name: copy_string(&value.name)?,
            value: value.value.as_deref().map(copy_string).transpose()?,
        });
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::CAPABILITIES;

    use super::{
        CapError, CapRequestReply, CapabilityChange, CapabilityProfile, CapabilitySpec,
        CapabilityState, split_capability_lines, validate_advertisement,
    };

    #[test]
    fn profile_does_not_retain_caller_vector_headroom() -> Result<(), super::CapError> {
        let mut capabilities = Vec::with_capacity(4_096);
        capabilities.push(CapabilitySpec::new("monitor", None)?);
        let caller_capacity = capabilities.capacity();

        let profile = CapabilityProfile::new(capabilities)?;

        assert!(profile.capabilities.capacity() < caller_capacity);
        assert_eq!(profile.capabilities.len(), 1);
        Ok(())
    }

    #[test]
    fn capability_values_reject_each_malformed_shape() -> Result<(), CapError> {
        assert_eq!(
            CapabilitySpec::new("not-registered", None),
            Err(CapError::UnknownCapability)
        );
        for value in ["", "two words", "line\nfeed"] {
            assert_eq!(
                CapabilitySpec::new("batch", Some(value)),
                Err(CapError::InvalidValue),
                "{value:?}"
            );
        }
        for (name, value) in [
            ("agenc.ag/privacy", None),
            ("agenc.ag/privacy", Some("v2")),
            ("agenc.ag/recovery", Some("v1.invalid")),
            ("agenc.ag/e2ee-mls", Some("v1,profile=invalid")),
            ("sasl", Some("PLAIN")),
            ("sts", Some("duration=1")),
            ("monitor", Some("v1")),
        ] {
            assert_eq!(
                CapabilitySpec::new(name, value),
                Err(CapError::InvalidValue),
                "{name}"
            );
        }

        let valued = CapabilitySpec::new("agenc.ag/privacy", Some("v1"))?;
        let copied = valued.try_clone()?;
        assert_eq!(copied.name(), "agenc.ag/privacy");
        assert_eq!(copied.value(), Some("v1"));
        Ok(())
    }

    #[test]
    fn capability_state_covers_atomic_negotiation_and_profile_changes() -> Result<(), CapError> {
        let message_tags = CapabilitySpec::new("message-tags", None)?;
        let batch = CapabilitySpec::new("batch", None)?;
        let labeled = CapabilitySpec::new("labeled-response", None)?;
        let notify = CapabilitySpec::new("cap-notify", None)?;
        let profile = CapabilityProfile::new(vec![
            notify.try_clone()?,
            message_tags.try_clone()?,
            batch.try_clone()?,
            labeled.try_clone()?,
        ])?;

        let mut state = CapabilityState::default();
        assert_eq!(state.apply_profile(&profile), Err(CapError::InvalidState));
        assert_eq!(
            state.ls(Some("301"), &profile),
            Err(CapError::UnsupportedVersion)
        );
        assert_eq!(
            state.ls(None, &profile)?,
            ["cap-notify", "message-tags", "batch", "labeled-response"]
        );
        assert!(state.blocks_registration());
        assert!(!state.enabled("cap-notify"));
        assert!(matches!(
            state.request("", &profile)?,
            CapRequestReply::Nak(_)
        ));
        assert!(matches!(
            state.request("unknown", &profile)?,
            CapRequestReply::Nak(_)
        ));
        assert!(matches!(
            state.request("-", &profile)?,
            CapRequestReply::Nak(_)
        ));
        assert!(matches!(
            state.request("batch=value", &profile)?,
            CapRequestReply::Nak(_)
        ));
        assert!(matches!(
            state.request("message-tags batch labeled-response", &profile)?,
            CapRequestReply::Ack(_)
        ));
        assert_eq!(state.list()?, ["message-tags", "batch", "labeled-response"]);

        let clone = state.try_clone()?;
        assert_eq!(clone.enabled_names(), state.enabled_names());
        state.end()?;
        assert!(!state.blocks_registration());
        assert_eq!(state.end(), Err(CapError::InvalidState));

        let changed = CapabilityProfile::new(vec![
            notify.try_clone()?,
            message_tags.try_clone()?,
            batch.try_clone()?,
        ])?;
        assert_eq!(
            state.apply_profile(&changed)?,
            [CapabilityChange::Del("labeled-response".to_owned())]
        );
        assert!(!state.enabled("labeled-response"));
        assert_eq!(
            state.ls(None, &profile),
            Err(CapError::InvalidAdvertisement)
        );

        let mut state_302 = CapabilityState::default();
        assert_eq!(
            state_302.ls(Some("302"), &profile)?,
            ["cap-notify", "message-tags", "batch", "labeled-response"]
        );
        assert!(state_302.enabled("cap-notify"));
        assert!(matches!(
            state_302.request("-cap-notify", &profile)?,
            CapRequestReply::Nak(_)
        ));

        let profile_without_notify = CapabilityProfile::new(vec![
            message_tags.try_clone()?,
            batch.try_clone()?,
            labeled.try_clone()?,
        ])?;
        let mut no_notify_302 = CapabilityState::default();
        no_notify_302.ls(Some("302"), &profile_without_notify)?;
        no_notify_302.ls(None, &profile_without_notify)?;
        assert!(!no_notify_302.enabled("cap-notify"));
        assert_eq!(
            no_notify_302.request("\u{7f}", &profile_without_notify),
            Err(CapError::InvalidValue)
        );
        assert_eq!(
            no_notify_302.request(
                &"x".repeat(super::MAX_CAP_COMMAND_BYTES + 1),
                &profile_without_notify
            ),
            Err(CapError::InvalidValue)
        );

        let mut pre_302 = CapabilityState::default();
        pre_302.ls(None, &profile)?;
        assert!(matches!(
            pre_302.request("-cap-notify", &profile)?,
            CapRequestReply::Ack(_)
        ));

        let mut defensive = CapabilityState::default();
        defensive.ls(None, &profile_without_notify)?;
        defensive.enabled.push("not-advertised".to_owned());
        defensive.apply_profile(&profile_without_notify)?;
        assert!(!defensive.enabled("not-advertised"));

        let old_recovery =
            CapabilitySpec::new("agenc.ag/recovery", Some("v1.AAAAAAAAAAAAAAAAAAAAAA"))?;
        let new_recovery =
            CapabilitySpec::new("agenc.ag/recovery", Some("v1.AQEBAQEBAQEBAQEBAQEBAQ"))?;
        let old_security = CapabilityProfile::new(vec![old_recovery])?;
        let new_security = CapabilityProfile::new(vec![new_recovery])?;
        let mut security = CapabilityState::default();
        security.ls(Some("302"), &old_security)?;
        assert!(matches!(
            security.request("agenc.ag/recovery", &old_security)?,
            CapRequestReply::Ack(_)
        ));
        assert!(matches!(
            security.apply_profile(&new_security)?.as_slice(),
            [CapabilityChange::ReconnectRequired(_)]
        ));
        assert!(security.reconnect_required());
        assert!(!security.enabled("agenc.ag/recovery"));
        Ok(())
    }

    #[test]
    fn advertisement_and_split_boundaries_are_closed() -> Result<(), CapError> {
        let duplicate = CapabilitySpec::new("monitor", None)?;
        assert_eq!(
            CapabilityProfile::new(vec![duplicate.try_clone()?, duplicate]),
            Err(CapError::InvalidAdvertisement)
        );
        assert_eq!(
            CapabilityProfile::new(vec![CapabilitySpec::new("labeled-response", None)?]),
            Err(CapError::InvalidAdvertisement)
        );

        let mut oversized = Vec::new();
        for _ in 0..=CAPABILITIES.len() {
            oversized.push(CapabilitySpec::new("monitor", None)?);
        }
        assert_eq!(
            validate_advertisement(&oversized),
            Err(CapError::InvalidAdvertisement)
        );

        assert_eq!(
            split_capability_lines(&["oversized".to_owned()], 4),
            Err(CapError::LineBudget)
        );
        let empty = split_capability_lines(&[], 0)?;
        assert_eq!(empty.len(), 1);
        let empty_line = empty.first().ok_or(CapError::InvalidState)?;
        assert_eq!(empty_line.capabilities, "");
        assert!(!empty_line.continuation);

        let exact = split_capability_lines(&["aa".to_owned(), "bb".to_owned()], 5)?;
        assert_eq!(exact.len(), 1);
        let exact_line = exact.first().ok_or(CapError::InvalidState)?;
        assert_eq!(exact_line.capabilities, "aa bb");
        let split = split_capability_lines(&["aa".to_owned(), "bb".to_owned()], 2)?;
        assert_eq!(split.len(), 2);
        let first = split.first().ok_or(CapError::InvalidState)?;
        let last = split.last().ok_or(CapError::InvalidState)?;
        assert!(first.continuation);
        assert!(!last.continuation);
        Ok(())
    }
}

#[cfg(test)]
mod display_tests {
    use super::CapError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            CapError::UnsupportedVersion,
            CapError::UnknownCapability,
            CapError::InvalidValue,
            CapError::InvalidAdvertisement,
            CapError::MissingDependency,
            CapError::InvalidState,
            CapError::LineBudget,
            CapError::Overflow,
            CapError::AllocationFailed,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
