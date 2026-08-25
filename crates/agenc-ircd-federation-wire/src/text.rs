//! Canonical base-federation text tokens and command-form validation.

use std::error::Error;
use std::fmt;

use agenc_ircd_types::{BASE_FRAGMENT_BYTES, BASE_FRAGMENT_COUNT, BASE_OBJECT_BYTES};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const FEDERATION_FRAGMENT_VERSION: &str = "v1";

/// Closed failures from base-federation text validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationTextError {
    /// A required text token was empty.
    Empty,
    /// A token exceeded its fixed encoded or decoded bound.
    TooLong,
    /// A token used bytes outside its closed alphabet.
    InvalidCharacter,
    /// A valid value used a noncanonical representation.
    NonCanonical,
    /// A decoded identifier or digest had the wrong fixed width.
    WrongLength,
    /// A canonical decimal exceeded its selected integer range.
    OutOfRange,
    /// A command or subcommand was not in the frozen registry.
    UnknownCommandForm,
    /// A registered command did not have its exact parameter count.
    WrongArity,
    /// A command used or omitted its fragment tag contrary to the registry.
    WrongTagPolicy,
    /// A fragment had the wrong field count or version.
    InvalidFragment,
    /// Fragment count, total, index, or segment length was inconsistent.
    FragmentRange,
    /// A checked text-carrier calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for FederationTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "federation text token is empty",
            Self::TooLong => "federation text token exceeds its bound",
            Self::InvalidCharacter => "federation text token contains an invalid character",
            Self::NonCanonical => "federation text token is not canonical",
            Self::WrongLength => "federation text token has the wrong decoded length",
            Self::OutOfRange => "federation decimal is outside its range",
            Self::UnknownCommandForm => "federation command form is not registered",
            Self::WrongArity => "federation command form has the wrong arity",
            Self::WrongTagPolicy => "federation fragment-tag policy is violated",
            Self::InvalidFragment => "federation fragment grammar is invalid",
            Self::FragmentRange => "federation fragment fields are inconsistent",
            Self::Overflow => "federation text calculation overflowed",
            Self::AllocationFailed => "federation text allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for FederationTextError {}

/// One exact 16-byte identifier represented as 22 Base64url characters.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FederationId16([u8; 16]);

impl FederationId16 {
    /// Parses the unique unpadded URL-safe encoding.
    pub fn parse(token: &str) -> Result<Self, FederationTextError> {
        Ok(Self(decode_fixed(token)?))
    }

    /// Constructs from exact identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrows exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Produces the unique unpadded URL-safe encoding.
    #[must_use]
    pub fn to_text(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// One exact 32-byte digest represented as 43 Base64url characters.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FederationHash32([u8; 32]);

impl FederationHash32 {
    /// Parses the unique unpadded URL-safe encoding.
    pub fn parse(token: &str) -> Result<Self, FederationTextError> {
        Ok(Self(decode_fixed(token)?))
    }

    /// Constructs from exact digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Produces the unique unpadded URL-safe encoding.
    #[must_use]
    pub fn to_text(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

fn decode_fixed<const LENGTH: usize>(token: &str) -> Result<[u8; LENGTH], FederationTextError> {
    let expected_encoded = encoded_base64_length(LENGTH)?;
    if token.len() != expected_encoded {
        return Err(FederationTextError::WrongLength);
    }
    validate_base64_alphabet(token)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| FederationTextError::NonCanonical)?;
    if decoded.len() != LENGTH || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return Err(FederationTextError::NonCanonical);
    }
    decoded
        .try_into()
        .map_err(|_| FederationTextError::WrongLength)
}

fn decode_variable(token: &str, maximum: usize) -> Result<Vec<u8>, FederationTextError> {
    if token.is_empty() {
        return Err(FederationTextError::Empty);
    }
    if token.len() > encoded_base64_length(maximum)? {
        return Err(FederationTextError::TooLong);
    }
    validate_base64_alphabet(token)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| FederationTextError::NonCanonical)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(FederationTextError::TooLong);
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != token {
        return Err(FederationTextError::NonCanonical);
    }
    Ok(decoded)
}

fn encoded_base64_length(decoded: usize) -> Result<usize, FederationTextError> {
    let complete = decoded
        .checked_div(3)
        .and_then(|value| value.checked_mul(4))
        .ok_or(FederationTextError::Overflow)?;
    let remainder = match decoded % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return Err(FederationTextError::Overflow),
    };
    complete
        .checked_add(remainder)
        .ok_or(FederationTextError::Overflow)
}

fn validate_base64_alphabet(token: &str) -> Result<(), FederationTextError> {
    if token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Ok(());
    }
    Err(FederationTextError::InvalidCharacter)
}

/// Parses a canonical unsigned 32-bit federation decimal.
pub fn parse_federation_u32(token: &str) -> Result<u32, FederationTextError> {
    let value = parse_decimal(token, 10, u64::from(u32::MAX))?;
    u32::try_from(value).map_err(|_| FederationTextError::OutOfRange)
}

/// Parses a canonical unsigned 64-bit federation decimal.
pub fn parse_federation_u64(token: &str) -> Result<u64, FederationTextError> {
    parse_decimal(token, 20, u64::MAX)
}

fn parse_decimal(
    token: &str,
    maximum_digits: usize,
    maximum: u64,
) -> Result<u64, FederationTextError> {
    if token.is_empty() {
        return Err(FederationTextError::Empty);
    }
    if token.len() > maximum_digits {
        return Err(FederationTextError::TooLong);
    }
    if token.len() > 1 && token.starts_with('0') {
        return Err(FederationTextError::NonCanonical);
    }
    if !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FederationTextError::InvalidCharacter);
    }
    let value = token
        .parse::<u64>()
        .map_err(|_| FederationTextError::OutOfRange)?;
    if value > maximum {
        return Err(FederationTextError::OutOfRange);
    }
    Ok(value)
}

/// Canonical `*` or unsigned 64-bit cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StarCursor {
    /// No retained cursor.
    Star,
    /// Exact retained delivery sequence.
    Value(u64),
}

impl StarCursor {
    /// Parses `*` or one canonical unsigned decimal.
    pub fn parse(token: &str) -> Result<Self, FederationTextError> {
        if token == "*" {
            return Ok(Self::Star);
        }
        Ok(Self::Value(parse_federation_u64(token)?))
    }
}

/// Canonical `*` or exact 16-byte identifier.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StarId {
    /// No retained identifier.
    Star,
    /// Exact retained identifier.
    Value(FederationId16),
}

impl StarId {
    /// Parses `*` or one canonical 16-byte identifier.
    pub fn parse(token: &str) -> Result<Self, FederationTextError> {
        if token == "*" {
            return Ok(Self::Star);
        }
        Ok(Self::Value(FederationId16::parse(token)?))
    }
}

/// Canonical `agenc.ag/fed=v1...` tag value without its tag name.
pub struct FederationFragment {
    object_id: FederationHash32,
    part: u32,
    count: u32,
    total: u32,
    segment: Vec<u8>,
}

impl FederationFragment {
    /// Parses the exact six-field value and all context-independent fragment
    /// relationships.
    pub fn parse(value: &str) -> Result<Self, FederationTextError> {
        let mut fields = value.split('.');
        let version = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        let object_id = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        let part = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        let count = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        let total = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        let segment = fields.next().ok_or(FederationTextError::InvalidFragment)?;
        if version != FEDERATION_FRAGMENT_VERSION || fields.next().is_some() {
            return Err(FederationTextError::InvalidFragment);
        }
        let object_id = FederationHash32::parse(object_id)?;
        let part = parse_federation_u32(part)?;
        let count = parse_federation_u32(count)?;
        let total = parse_federation_u32(total)?;
        let maximum = usize_constant(BASE_FRAGMENT_BYTES)?;
        let segment = decode_variable(segment, maximum)?;
        Self::from_parts(object_id, part, count, total, segment)
    }

    /// Constructs after validating all scalars, copying the segment last.
    pub fn new(
        object_id: FederationHash32,
        part: u32,
        count: u32,
        total: u32,
        segment: &[u8],
    ) -> Result<Self, FederationTextError> {
        validate_fragment_relationships(part, count, total, segment.len())?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(segment.len())
            .map_err(|_| FederationTextError::AllocationFailed)?;
        owned.extend_from_slice(segment);
        Self::from_parts(object_id, part, count, total, owned)
    }

    fn from_parts(
        object_id: FederationHash32,
        part: u32,
        count: u32,
        total: u32,
        segment: Vec<u8>,
    ) -> Result<Self, FederationTextError> {
        validate_fragment_relationships(part, count, total, segment.len())?;
        Ok(Self {
            object_id,
            part,
            count,
            total,
            segment,
        })
    }

    /// Returns the complete-object digest.
    #[must_use]
    pub const fn object_id(&self) -> FederationHash32 {
        self.object_id
    }

    /// Returns the zero-based fragment index.
    #[must_use]
    pub const fn part(&self) -> u32 {
        self.part
    }

    /// Returns the exact total fragment count.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Returns the exact complete-object byte length.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.total
    }

    /// Borrows this fragment's raw bytes.
    #[must_use]
    pub fn segment(&self) -> &[u8] {
        &self.segment
    }

    /// Produces the unique six-field fragment value.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{FEDERATION_FRAGMENT_VERSION}.{}.{}.{}.{}.{}",
            self.object_id.to_text(),
            self.part,
            self.count,
            self.total,
            URL_SAFE_NO_PAD.encode(&self.segment)
        )
    }
}

fn validate_fragment_relationships(
    part: u32,
    count: u32,
    total: u32,
    segment_length: usize,
) -> Result<(), FederationTextError> {
    let maximum_count = u32_constant(BASE_FRAGMENT_COUNT)?;
    let maximum_total = u32_constant(BASE_OBJECT_BYTES)?;
    if total == 0 || total > maximum_total || count == 0 || count > maximum_count || part >= count {
        return Err(FederationTextError::FragmentRange);
    }
    let fragment_bytes = u32_constant(BASE_FRAGMENT_BYTES)?;
    let expected_count = total
        .checked_add(fragment_bytes - 1)
        .ok_or(FederationTextError::Overflow)?
        / fragment_bytes;
    let expected_length = expected_fragment_length(part, total, fragment_bytes)?;
    if count != expected_count || segment_length != expected_length {
        return Err(FederationTextError::FragmentRange);
    }
    Ok(())
}

fn expected_fragment_length(
    part: u32,
    total: u32,
    fragment_bytes: u32,
) -> Result<usize, FederationTextError> {
    let start = part
        .checked_mul(fragment_bytes)
        .ok_or(FederationTextError::Overflow)?;
    let remaining = total
        .checked_sub(start)
        .ok_or(FederationTextError::FragmentRange)?;
    usize::try_from(remaining.min(fragment_bytes)).map_err(|_| FederationTextError::Overflow)
}

fn usize_constant(value: u64) -> Result<usize, FederationTextError> {
    usize::try_from(value).map_err(|_| FederationTextError::Overflow)
}

fn u32_constant(value: u64) -> Result<u32, FederationTextError> {
    u32::try_from(value).map_err(|_| FederationTextError::Overflow)
}

/// Whether one command form requires the sole federation fragment tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentTagPolicy {
    /// The command must have exactly one `agenc.ag/fed` tag.
    Required,
    /// The command must not have an `agenc.ag/fed` tag.
    Forbidden,
}

/// One exact frozen federation command or command/subcommand form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationCommandDescriptor {
    /// Registry form name, such as `FSNAPSHOT_ENTRY`.
    pub form: &'static str,
    /// Exact top-level command token.
    pub command: &'static str,
    /// Exact first-parameter subcommand when this is a split form.
    pub subcommand: Option<&'static str>,
    /// Exact parameter count excluding a split subcommand.
    pub parameter_count: usize,
    /// Required or forbidden object-fragment tag.
    pub fragment_tag: FragmentTagPolicy,
}

include!("generated_text_registry.rs");

/// Validates exact case, subcommand, arity, and fragment-tag presence.
pub fn validate_federation_command(
    command: &str,
    parameters: &[&str],
    has_fragment_tag: bool,
) -> Result<&'static FederationCommandDescriptor, FederationTextError> {
    validate_command_token(command)?;
    let descriptor = select_command_form(command, parameters)?;
    let subcommand_count = usize::from(descriptor.subcommand.is_some());
    let expected = descriptor
        .parameter_count
        .checked_add(subcommand_count)
        .ok_or(FederationTextError::Overflow)?;
    if parameters.len() != expected {
        return Err(FederationTextError::WrongArity);
    }
    validate_tag_policy(descriptor.fragment_tag, has_fragment_tag)?;
    Ok(descriptor)
}

fn validate_command_token(command: &str) -> Result<(), FederationTextError> {
    if command.is_empty() {
        return Err(FederationTextError::Empty);
    }
    if command
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Ok(());
    }
    Err(FederationTextError::InvalidCharacter)
}

fn select_command_form(
    command: &str,
    parameters: &[&str],
) -> Result<&'static FederationCommandDescriptor, FederationTextError> {
    let first = parameters.first().copied();
    FEDERATION_COMMAND_FORMS
        .iter()
        .find(|descriptor| {
            descriptor.command == command
                && descriptor
                    .subcommand
                    .is_none_or(|subcommand| first == Some(subcommand))
        })
        .ok_or(FederationTextError::UnknownCommandForm)
}

fn validate_tag_policy(
    policy: FragmentTagPolicy,
    has_fragment_tag: bool,
) -> Result<(), FederationTextError> {
    if matches!(
        (policy, has_fragment_tag),
        (FragmentTagPolicy::Required, true) | (FragmentTagPolicy::Forbidden, false)
    ) {
        return Ok(());
    }
    Err(FederationTextError::WrongTagPolicy)
}
