//! Canonical text-carrier primitives shared by bounded client commands.

use std::error::Error;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Maximum raw bytes in one E2EE fragment.
pub const MAX_E2EE_FRAGMENT_BYTES: usize = 2_940;
/// Maximum fragments in one mailbox or control object.
pub const MAX_E2EE_FRAGMENT_COUNT: u16 = 1_427;
/// Maximum complete bytes admitted by the E2EE carrier grammar.
pub const MAX_E2EE_OBJECT_BYTES: u32 = 4_194_304;

/// Closed failures from canonical text-carrier validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextCarrierError {
    /// A required token was empty.
    Empty,
    /// A token exceeded its closed encoded or decoded bound.
    TooLong,
    /// A token used bytes outside its closed alphabet.
    InvalidCharacter,
    /// A valid value used a noncanonical representation.
    NonCanonical,
    /// A decoded token had the wrong fixed width.
    WrongLength,
    /// A canonical decimal exceeded its selected integer range.
    OutOfRange,
    /// A command did not have its exact parameter count.
    WrongArity,
    /// A token was not in its closed registry.
    UnknownToken,
    /// A fragment had the wrong field count or profile version.
    InvalidFragment,
    /// Fragment index, count, total, or segment length was inconsistent.
    FragmentRange,
    /// A checked carrier calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for TextCarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "text carrier token is empty",
            Self::TooLong => "text carrier token exceeds its bound",
            Self::InvalidCharacter => "text carrier token contains an invalid character",
            Self::NonCanonical => "text carrier token is not canonical",
            Self::WrongLength => "text carrier token has the wrong decoded length",
            Self::OutOfRange => "text carrier decimal is outside its range",
            Self::WrongArity => "text carrier command has the wrong arity",
            Self::UnknownToken => "text carrier token is not registered",
            Self::InvalidFragment => "E2EE fragment grammar is invalid",
            Self::FragmentRange => "E2EE fragment fields are inconsistent",
            Self::Overflow => "text carrier calculation overflowed",
            Self::AllocationFailed => "text carrier allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for TextCarrierError {}

/// Canonical unpadded URL-safe Base64 with explicit decoded bounds.
///
/// The decoded bytes are deliberately not printable through `Debug` or
/// `Display`; callers opt in to wire rendering with [`Self::to_text`].
pub struct CanonicalBase64Url {
    bytes: Vec<u8>,
}

impl CanonicalBase64Url {
    /// Parses after validating encoded length and alphabet, then proves exact
    /// decode/re-encode equality.
    pub fn parse(
        token: &str,
        minimum_decoded: usize,
        maximum_decoded: usize,
    ) -> Result<Self, TextCarrierError> {
        validate_base64_shape(token, minimum_decoded, maximum_decoded)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| TextCarrierError::NonCanonical)?;
        validate_decoded_length(bytes.len(), minimum_decoded, maximum_decoded)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != token {
            return Err(TextCarrierError::NonCanonical);
        }
        Ok(Self { bytes })
    }

    /// Constructs from already bounded bytes, copying only after validation.
    pub fn from_bytes(
        bytes: &[u8],
        minimum_decoded: usize,
        maximum_decoded: usize,
    ) -> Result<Self, TextCarrierError> {
        validate_decoded_length(bytes.len(), minimum_decoded, maximum_decoded)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| TextCarrierError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// Borrows the exact decoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Produces the unique unpadded URL-safe representation.
    #[must_use]
    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.bytes)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn validate_base64_shape(
    token: &str,
    minimum_decoded: usize,
    maximum_decoded: usize,
) -> Result<(), TextCarrierError> {
    if minimum_decoded > maximum_decoded {
        return Err(TextCarrierError::OutOfRange);
    }
    if token.is_empty() && minimum_decoded != 0 {
        return Err(TextCarrierError::Empty);
    }
    let maximum_encoded = encoded_base64_length(maximum_decoded)?;
    if token.len() > maximum_encoded {
        return Err(TextCarrierError::TooLong);
    }
    if !token.bytes().all(is_base64url_character) {
        return Err(TextCarrierError::InvalidCharacter);
    }
    Ok(())
}

fn encoded_base64_length(decoded: usize) -> Result<usize, TextCarrierError> {
    let complete = decoded
        .checked_div(3)
        .and_then(|value| value.checked_mul(4))
        .ok_or(TextCarrierError::Overflow)?;
    let remainder = match decoded % 3 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => return Err(TextCarrierError::Overflow),
    };
    complete
        .checked_add(remainder)
        .ok_or(TextCarrierError::Overflow)
}

fn validate_decoded_length(
    length: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), TextCarrierError> {
    if length < minimum {
        return Err(TextCarrierError::WrongLength);
    }
    if length > maximum {
        return Err(TextCarrierError::TooLong);
    }
    Ok(())
}

const fn is_base64url_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

/// Parses a canonical unsigned 16-bit decimal.
pub fn parse_u16_decimal(token: &str) -> Result<u16, TextCarrierError> {
    let value = parse_decimal(token, 5, u64::from(u16::MAX))?;
    u16::try_from(value).map_err(|_| TextCarrierError::OutOfRange)
}

/// Parses a canonical unsigned 32-bit decimal.
pub fn parse_u32_decimal(token: &str) -> Result<u32, TextCarrierError> {
    let value = parse_decimal(token, 10, u64::from(u32::MAX))?;
    u32::try_from(value).map_err(|_| TextCarrierError::OutOfRange)
}

/// Parses a canonical unsigned 64-bit decimal.
pub fn parse_u64_decimal(token: &str) -> Result<u64, TextCarrierError> {
    parse_decimal(token, 20, u64::MAX)
}

fn parse_decimal(
    token: &str,
    maximum_digits: usize,
    maximum: u64,
) -> Result<u64, TextCarrierError> {
    if token.is_empty() {
        return Err(TextCarrierError::Empty);
    }
    if token.len() > maximum_digits {
        return Err(TextCarrierError::TooLong);
    }
    if token.len() > 1 && token.starts_with('0') {
        return Err(TextCarrierError::NonCanonical);
    }
    if !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TextCarrierError::InvalidCharacter);
    }
    let value = token
        .parse::<u64>()
        .map_err(|_| TextCarrierError::OutOfRange)?;
    if value > maximum {
        return Err(TextCarrierError::OutOfRange);
    }
    Ok(value)
}

/// Validates one exact uppercase command or subcommand literal.
pub fn validate_uppercase_token(token: &str) -> Result<(), TextCarrierError> {
    if token.is_empty() {
        return Err(TextCarrierError::Empty);
    }
    if token
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Ok(());
    }
    Err(TextCarrierError::InvalidCharacter)
}

/// Exact parameter-count contract for one already selected command form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactArity {
    parameters: usize,
}

impl ExactArity {
    /// Creates an exact parameter count.
    #[must_use]
    pub const fn new(parameters: usize) -> Self {
        Self { parameters }
    }

    /// Returns the required parameter count.
    #[must_use]
    pub const fn parameters(self) -> usize {
        self.parameters
    }

    /// Rejects missing and trailing parameters.
    pub fn validate(self, parameters: &[&str]) -> Result<(), TextCarrierError> {
        if parameters.len() == self.parameters {
            return Ok(());
        }
        Err(TextCarrierError::WrongArity)
    }
}

/// Canonical `v1` E2EE fragment-tag value.
pub struct E2eeFragment {
    object_id: [u8; 32],
    part: u16,
    count: u16,
    total: u32,
    segment: Vec<u8>,
}

impl E2eeFragment {
    /// Parses the exact six-field fragment grammar and validates all
    /// context-independent fragment arithmetic.
    pub fn parse(value: &str) -> Result<Self, TextCarrierError> {
        let mut fields = value.split('.');
        let version = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        let object_id = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        let part = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        let count = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        let total = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        let segment = fields.next().ok_or(TextCarrierError::InvalidFragment)?;
        if version != "v1" || fields.next().is_some() {
            return Err(TextCarrierError::InvalidFragment);
        }
        let object_id = parse_object_id(object_id)?;
        let part = parse_fragment_decimal(part)?;
        let count = parse_fragment_decimal(count)?;
        let total = parse_total_decimal(total)?;
        let segment = CanonicalBase64Url::parse(segment, 1, MAX_E2EE_FRAGMENT_BYTES)?;
        Self::from_parts(object_id, part, count, total, segment.into_bytes())
    }

    /// Constructs a validated fragment, copying the segment only after all
    /// scalar relationships pass.
    pub fn new(
        object_id: [u8; 32],
        part: u16,
        count: u16,
        total: u32,
        segment: &[u8],
    ) -> Result<Self, TextCarrierError> {
        validate_fragment_relationships(part, count, total, segment.len())?;
        let segment = CanonicalBase64Url::from_bytes(segment, 1, MAX_E2EE_FRAGMENT_BYTES)?;
        Self::from_parts(object_id, part, count, total, segment.into_bytes())
    }

    fn from_parts(
        object_id: [u8; 32],
        part: u16,
        count: u16,
        total: u32,
        segment: Vec<u8>,
    ) -> Result<Self, TextCarrierError> {
        validate_fragment_relationships(part, count, total, segment.len())?;
        Ok(Self {
            object_id,
            part,
            count,
            total,
            segment,
        })
    }

    /// Borrows the complete-object SHA-256 bytes.
    #[must_use]
    pub const fn object_id(&self) -> &[u8; 32] {
        &self.object_id
    }

    /// Returns the zero-based fragment index.
    #[must_use]
    pub const fn part(&self) -> u16 {
        self.part
    }

    /// Returns the exact total fragment count.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// Returns the exact complete-object byte length.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.total
    }

    /// Borrows the raw fragment bytes.
    #[must_use]
    pub fn segment(&self) -> &[u8] {
        &self.segment
    }

    /// Produces the unique `v1.<id>.<part>.<count>.<total>.<segment>` value.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "v1.{}.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(self.object_id),
            self.part,
            self.count,
            self.total,
            URL_SAFE_NO_PAD.encode(&self.segment)
        )
    }
}

fn parse_object_id(token: &str) -> Result<[u8; 32], TextCarrierError> {
    let bytes = CanonicalBase64Url::parse(token, 32, 32)?.into_bytes();
    bytes.try_into().map_err(|_| TextCarrierError::WrongLength)
}

fn parse_fragment_decimal(token: &str) -> Result<u16, TextCarrierError> {
    if token.len() > 4 {
        return Err(TextCarrierError::TooLong);
    }
    parse_u16_decimal(token)
}

fn parse_total_decimal(token: &str) -> Result<u32, TextCarrierError> {
    if token.len() > 7 {
        return Err(TextCarrierError::TooLong);
    }
    parse_u32_decimal(token)
}

fn validate_fragment_relationships(
    part: u16,
    count: u16,
    total: u32,
    segment_length: usize,
) -> Result<(), TextCarrierError> {
    let expected_count = expected_fragment_count(total)?;
    if count == 0 || count > MAX_E2EE_FRAGMENT_COUNT || count != expected_count || part >= count {
        return Err(TextCarrierError::FragmentRange);
    }
    let expected_length = expected_segment_length(part, total)?;
    if segment_length != expected_length {
        return Err(TextCarrierError::FragmentRange);
    }
    Ok(())
}

fn expected_fragment_count(total: u32) -> Result<u16, TextCarrierError> {
    if total == 0 || total > MAX_E2EE_OBJECT_BYTES {
        return Err(TextCarrierError::FragmentRange);
    }
    let fragment_bytes =
        u32::try_from(MAX_E2EE_FRAGMENT_BYTES).map_err(|_| TextCarrierError::Overflow)?;
    let rounded = total
        .checked_add(fragment_bytes - 1)
        .ok_or(TextCarrierError::Overflow)?;
    u16::try_from(rounded / fragment_bytes).map_err(|_| TextCarrierError::OutOfRange)
}

fn expected_segment_length(part: u16, total: u32) -> Result<usize, TextCarrierError> {
    let fragment_bytes =
        u32::try_from(MAX_E2EE_FRAGMENT_BYTES).map_err(|_| TextCarrierError::Overflow)?;
    let start = u32::from(part)
        .checked_mul(fragment_bytes)
        .ok_or(TextCarrierError::Overflow)?;
    let remaining = total
        .checked_sub(start)
        .ok_or(TextCarrierError::FragmentRange)?;
    usize::try_from(remaining.min(fragment_bytes)).map_err(|_| TextCarrierError::Overflow)
}

/// Canonical safe label restricted to unescaped Base64url characters.
pub struct SafeLabel(String);

impl SafeLabel {
    /// Parses the exact one-to-64-byte safe-label grammar.
    pub fn parse(token: &str) -> Result<Self, TextCarrierError> {
        if token.is_empty() {
            return Err(TextCarrierError::Empty);
        }
        if token.len() > 64 {
            return Err(TextCarrierError::TooLong);
        }
        if !token.bytes().all(is_base64url_character) {
            return Err(TextCarrierError::InvalidCharacter);
        }
        Ok(Self(token.to_owned()))
    }

    /// Borrows the exact validated label bytes as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed request-command token used by E2EE object batches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum E2eeRequestCommand {
    /// Encrypted-group command family.
    Egroup,
    /// Encrypted directory/mailbox command family.
    Ekey,
}

impl E2eeRequestCommand {
    /// Parses one exact uppercase request-command token.
    pub fn parse(token: &str) -> Result<Self, TextCarrierError> {
        match token {
            "EGROUP" => Ok(Self::Egroup),
            "EKEY" => Ok(Self::Ekey),
            _ => Err(TextCarrierError::UnknownToken),
        }
    }

    /// Returns the exact uppercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Egroup => "EGROUP",
            Self::Ekey => "EKEY",
        }
    }
}

/// Closed mailbox-kind token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxKind {
    /// MLS application ciphertext.
    Application,
    /// Conversation-binding package.
    Binding,
    /// Delivered MLS Welcome wrapper.
    Welcome,
    /// Staged ReInit wrapper.
    StagedReinit,
}

impl MailboxKind {
    /// Parses one exact uppercase mailbox-kind token.
    pub fn parse(token: &str) -> Result<Self, TextCarrierError> {
        match token {
            "APPLICATION" => Ok(Self::Application),
            "BINDING" => Ok(Self::Binding),
            "WELCOME" => Ok(Self::Welcome),
            "STAGED-REINIT" => Ok(Self::StagedReinit),
            _ => Err(TextCarrierError::UnknownToken),
        }
    }

    /// Returns the exact uppercase token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "APPLICATION",
            Self::Binding => "BINDING",
            Self::Welcome => "WELCOME",
            Self::StagedReinit => "STAGED-REINIT",
        }
    }
}

/// Exact Section-11.7 object-kind tokens in documented ordinal order.
pub const E2EE_OBJECT_KINDS: &[&str] = &[
    "APPLICATION",
    "COMMIT",
    "AUTHORIZATION",
    "ACK",
    "FINALIZATION-REQUEST",
    "FINALIZATION-CERTIFICATE",
    "ABORT-REQUEST",
    "ABORT-CERTIFICATE",
    "WELCOME",
    "IDENTITY",
    "ROOT-CHAIN",
    "ROSTER",
    "CAPABILITIES",
    "PACKAGE",
    "BINDING",
    "CLOSE",
    "RESERVATION",
    "REINIT-ATTEMPT",
    "STAGED-REINIT",
    "REINIT-ACK",
    "REINIT-ACTIVATION-REQUEST",
    "REINIT-ACTIVATION-CERTIFICATE",
    "REINIT-ABORT-REQUEST",
    "REINIT-ABORT-CERTIFICATE",
    "SEQUENCER-RECORD",
    "DEVICE-ATTACH-CHALLENGE",
    "DEVICE-ATTACH",
    "BINDING-LOCK",
    "FEDERATION-STATE",
    "FEDERATION-ORIGIN",
    "FEDERATION-REQUEST",
    "FEDERATION-RESULT",
    "FEDERATION-EVENT",
];

/// A validated closed E2EE object-kind token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eeObjectKind(&'static str);

impl E2eeObjectKind {
    /// Parses one exact Section-11.7 object-kind token.
    pub fn parse(token: &str) -> Result<Self, TextCarrierError> {
        let value = E2EE_OBJECT_KINDS
            .iter()
            .copied()
            .find(|candidate| *candidate == token)
            .ok_or(TextCarrierError::UnknownToken)?;
        Ok(Self(value))
    }

    /// Returns the exact registered token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}
