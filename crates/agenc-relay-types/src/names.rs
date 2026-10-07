//! Canonical names with presentation kept separate from comparison identity.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use precis_profiles::precis_core::profile::{PrecisFastInvocation as _, Rules as _};
use precis_profiles::{Nickname as PrecisNickname, UsernameCaseMapped};
use zeroize::Zeroize;

use crate::ValidationError;

/// Maximum hostile input admitted to one PRECIS adapter invocation.
pub const MAX_PRECIS_INPUT_BYTES: usize = 256;
/// Maximum UTF-8 bytes in a prepared display name.
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;
const MAX_DNS_LABEL_BYTES: usize = 63;
/// Applications of the RFC 8266 enforcement rules before a result that has not
/// stabilized is refused: the bound the pinned PRECIS dependency applies to its
/// own profile (RFC 8266 Section 2.1 and RFC 8264 Section 7).
const PRECIS_ENFORCEMENT_PASSES: usize = 3;

fn is_ascii_name_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn ascii_lowercase_copy(input: &str) -> Result<String, ValidationError> {
    let mut canonical = String::new();
    canonical
        .try_reserve_exact(input.len())
        .map_err(|_| ValidationError::AllocationFailed)?;
    for byte in input.bytes() {
        canonical.push(char::from(byte.to_ascii_lowercase()));
    }
    Ok(canonical)
}

fn fallible_string_copy(input: &str) -> Result<String, ValidationError> {
    let mut output = String::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| ValidationError::AllocationFailed)?;
    output.push_str(input);
    Ok(output)
}

fn into_owned_fallible(input: Cow<'_, str>) -> Result<String, ValidationError> {
    match input {
        Cow::Borrowed(value) => fallible_string_copy(value),
        Cow::Owned(value) => Ok(value),
    }
}

/// A mutable ASCII routing nickname with a separate comparison key.
pub struct Nickname {
    presentation: String,
    canonical: String,
}

impl Nickname {
    /// Parses the exact portable nickname grammar.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        let Some((&first, remaining)) = input.as_bytes().split_first() else {
            return Err(ValidationError::Empty);
        };
        if input.len() > 32 {
            return Err(ValidationError::TooLong);
        }
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !remaining.iter().copied().all(is_ascii_name_character)
        {
            return Err(ValidationError::InvalidCharacter);
        }
        let canonical = ascii_lowercase_copy(input)?;
        let mut presentation = String::new();
        presentation
            .try_reserve_exact(input.len())
            .map_err(|_| ValidationError::AllocationFailed)?;
        presentation.push_str(input);
        Ok(Self {
            presentation,
            canonical,
        })
    }

    /// Borrows the first accepted wire spelling.
    #[must_use]
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Borrows the lowercase ASCII routing key.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

impl PartialEq for Nickname {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for Nickname {}

impl PartialOrd for Nickname {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Nickname {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for Nickname {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

/// A portable channel name with preserved display spelling.
pub struct ChannelName {
    presentation: String,
    canonical: String,
}

impl ChannelName {
    /// Parses one global (`#`) or local (`&`) channel name.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        let Some((&prefix, remaining)) = input.as_bytes().split_first() else {
            return Err(ValidationError::Empty);
        };
        if input.len() < 2 {
            return Err(ValidationError::TooShort);
        }
        if input.len() > 64 {
            return Err(ValidationError::TooLong);
        }
        if !matches!(prefix, b'#' | b'&') {
            return Err(ValidationError::InvalidPrefix);
        }
        if !remaining
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        {
            return Err(ValidationError::InvalidCharacter);
        }
        let canonical = ascii_lowercase_copy(input)?;
        let mut presentation = String::new();
        presentation
            .try_reserve_exact(input.len())
            .map_err(|_| ValidationError::AllocationFailed)?;
        presentation.push_str(input);
        Ok(Self {
            presentation,
            canonical,
        })
    }

    /// Borrows the first accepted wire spelling.
    #[must_use]
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Borrows the lowercase ASCII comparison key.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Reports whether this is a coordinator-owned global channel.
    #[must_use]
    pub fn is_global(&self) -> bool {
        self.canonical.starts_with('#')
    }
}

impl PartialEq for ChannelName {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ChannelName {}

impl PartialOrd for ChannelName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChannelName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for ChannelName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

fn is_space_separator(character: char) -> bool {
    matches!(
        character,
        '\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

fn canonicalize_precis_spaces(input: &str) -> Result<String, ValidationError> {
    if input.len() > MAX_PRECIS_INPUT_BYTES {
        return Err(ValidationError::TooLong);
    }
    collapse_precis_spaces(input)
}

/// Applies the RFC 8266 additional mapping rule: every `Zs` space becomes one
/// ASCII space, interior runs collapse to one, and leading and trailing spaces
/// are removed.
fn collapse_precis_spaces(input: &str) -> Result<String, ValidationError> {
    let mut canonical = String::new();
    canonical
        .try_reserve_exact(input.len())
        .map_err(|_| ValidationError::AllocationFailed)?;
    let mut pending_space = false;
    for character in input.chars() {
        if is_space_separator(character) {
            pending_space = !canonical.is_empty();
            continue;
        }
        if pending_space {
            canonical.push(' ');
            pending_space = false;
        }
        canonical.push(character);
    }
    Ok(canonical)
}

/// A private RFC 8265 UsernameCaseMapped login identifier.
pub struct NormalizedLogin(String);

impl NormalizedLogin {
    /// Applies the pinned UsernameCaseMapped profile under a hostile-input cap.
    pub fn prepare(input: &str) -> Result<Self, ValidationError> {
        if input.len() > MAX_PRECIS_INPUT_BYTES {
            return Err(ValidationError::TooLong);
        }
        let normalized = UsernameCaseMapped::enforce(input)
            .map_err(|_| ValidationError::PrecisRejected)
            .and_then(into_owned_fallible)
            .map(Self)?;
        if !(3..=64).contains(&normalized.0.len()) {
            return Err(if normalized.0.len() < 3 {
                ValidationError::TooShort
            } else {
                ValidationError::TooLong
            });
        }
        Ok(normalized)
    }

    /// Borrows the exact normalized login bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for NormalizedLogin {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A public mutable account label with exact-case comparison.
pub struct AccountLabel(String);

impl AccountLabel {
    /// Parses the closed safe-ASCII account-label grammar.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        let Some((&first, remaining)) = input.as_bytes().split_first() else {
            return Err(ValidationError::Empty);
        };
        if input.len() > 32 {
            return Err(ValidationError::TooLong);
        }
        if !first.is_ascii_alphanumeric()
            || !remaining
                .iter()
                .copied()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ValidationError::InvalidCharacter);
        }
        fallible_string_copy(input).map(Self)
    }

    /// Borrows the exact public label spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A prepared Unicode display name that never carries routing authority.
pub struct DisplayName(String);

impl DisplayName {
    /// Applies RFC 8266 through the bounded private PRECIS adapter.
    ///
    /// The adapter applies the enforcement rules itself until the result is
    /// stable: each pass checks the FreeformClass, collapses spaces and then
    /// normalizes, so spaces are collapsed after normalization. Every input is
    /// either prepared or refused with a typed error.
    pub fn prepare(input: &str) -> Result<Self, ValidationError> {
        let mut current = canonicalize_precis_spaces(input)?;
        for _pass in 0..PRECIS_ENFORCEMENT_PASSES {
            let next = enforce_nickname_rules(&current)?;
            if next == current {
                if current.len() > MAX_DISPLAY_NAME_BYTES {
                    return Err(ValidationError::TooLong);
                }
                return Ok(Self(current));
            }
            current = next;
        }
        Err(ValidationError::PrecisRejected)
    }

    /// Borrows the prepared display text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One application of the RFC 8266 Section 2.3 enforcement rules: the
/// FreeformClass preparation check, the additional mapping rule, NFKC and the
/// non-empty check. The dependency supplies only the class check and NFKC.
fn enforce_nickname_rules(input: &str) -> Result<String, ValidationError> {
    PrecisNickname::prepare(input).map_err(|_| ValidationError::PrecisRejected)?;
    let spaced = collapse_precis_spaces(input)?;
    let normalized = PrecisNickname::new()
        .normalization_rule(spaced)
        .map_err(|_| ValidationError::PrecisRejected)?;
    if normalized.is_empty() {
        return Err(ValidationError::PrecisRejected);
    }
    into_owned_fallible(normalized)
}

/// A configured lowercase ASCII DNS server name.
pub struct ServerName(String);

fn is_valid_server_label(label: &str) -> bool {
    if label.is_empty()
        || label.len() > MAX_DNS_LABEL_BYTES
        || label.starts_with('-')
        || label.ends_with('-')
    {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl ServerName {
    /// Parses the exact configured server-name profile.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        if input.is_empty() {
            return Err(ValidationError::Empty);
        }
        if input.len() > 253 {
            return Err(ValidationError::TooLong);
        }
        if !input.contains('.') || !input.split('.').all(is_valid_server_label) {
            return Err(ValidationError::InvalidCharacter);
        }
        fallible_string_copy(input).map(Self)
    }

    /// Borrows the configured exact-match name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Independently random visible user and host cloak components.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicCloak {
    user_component: [u8; 10],
    host_component: [u8; 16],
}

impl PublicCloak {
    /// Validates lowercase unpadded base32 cloak components.
    pub fn parse(user: &str, host: &str) -> Result<Self, ValidationError> {
        if user.len() != 10 || host.len() != 16 {
            return Err(ValidationError::IdentifierLength);
        }
        if !user
            .bytes()
            .chain(host.bytes())
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
        {
            return Err(ValidationError::InvalidCharacter);
        }
        let mut user_component = [0_u8; 10];
        let mut host_component = [0_u8; 16];
        user_component.copy_from_slice(user.as_bytes());
        host_component.copy_from_slice(host.as_bytes());
        Ok(Self {
            user_component,
            host_component,
        })
    }

    /// Rebuilds a cloak from already validated wire components.
    pub fn from_components(
        user_component: [u8; 10],
        host_component: [u8; 16],
    ) -> Result<Self, ValidationError> {
        let user =
            std::str::from_utf8(&user_component).map_err(|_| ValidationError::InvalidUtf8)?;
        let host =
            std::str::from_utf8(&host_component).map_err(|_| ValidationError::InvalidUtf8)?;
        Self::parse(user, host)
    }

    /// Borrows the ten-character visible user component.
    #[must_use]
    pub const fn user_component(&self) -> &[u8; 10] {
        &self.user_component
    }

    /// Borrows the sixteen-character visible host component.
    #[must_use]
    pub const fn host_component(&self) -> &[u8; 16] {
        &self.host_component
    }
}
