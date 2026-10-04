//! Canonical text-carrier primitives shared by bounded client commands.

use std::error::Error;
use std::fmt::{self, Write as _};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::{Zeroize as _, Zeroizing};

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
        let expected_decoded_length =
            validate_base64_shape(token, minimum_decoded, maximum_decoded)?;
        let mut bytes = zeroed_buffer(expected_decoded_length)?;
        let decoded_length = URL_SAFE_NO_PAD
            .decode_slice(token.as_bytes(), &mut bytes)
            .map_err(|_| TextCarrierError::NonCanonical)?;
        if decoded_length != expected_decoded_length {
            return Err(TextCarrierError::NonCanonical);
        }

        let encoded_length = encoded_base64_length(bytes.len())?;
        let mut canonical = zeroed_buffer(encoded_length)?;
        let canonical_length = URL_SAFE_NO_PAD
            .encode_slice(&bytes, &mut canonical)
            .map_err(|_| TextCarrierError::Overflow)?;
        if canonical_length != token.len() || canonical.as_slice() != token.as_bytes() {
            return Err(TextCarrierError::NonCanonical);
        }
        Ok(Self {
            bytes: std::mem::take(&mut *bytes),
        })
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
    pub fn to_text(&self) -> Result<String, TextCarrierError> {
        let encoded_length = encoded_base64_length(self.bytes.len())?;
        let mut encoded = String::new();
        encoded
            .try_reserve_exact(encoded_length)
            .map_err(|_| TextCarrierError::AllocationFailed)?;
        append_base64url(&mut encoded, &self.bytes)?;
        Ok(encoded)
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

fn zeroed_buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, TextCarrierError> {
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(length)
        .map_err(|_| TextCarrierError::AllocationFailed)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

impl Drop for CanonicalBase64Url {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn validate_base64_shape(
    token: &str,
    minimum_decoded: usize,
    maximum_decoded: usize,
) -> Result<usize, TextCarrierError> {
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
    let complete = token
        .len()
        .checked_div(4)
        .and_then(|length| length.checked_mul(3))
        .ok_or(TextCarrierError::Overflow)?;
    let remainder = match token.len() % 4 {
        0 => 0,
        2 => 1,
        3 => 2,
        1 => return Err(TextCarrierError::NonCanonical),
        _ => return Err(TextCarrierError::Overflow),
    };
    let decoded_length = complete
        .checked_add(remainder)
        .ok_or(TextCarrierError::Overflow)?;
    validate_decoded_length(decoded_length, minimum_decoded, maximum_decoded)?;
    Ok(decoded_length)
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
        let part = parse_fragment_decimal(part)?;
        let count = parse_fragment_decimal(count)?;
        let total = parse_total_decimal(total)?;
        let expected_segment_length = validate_fragment_scalars(part, count, total)?;
        let object_id = parse_object_id(object_id)?;
        let segment =
            CanonicalBase64Url::parse(segment, expected_segment_length, expected_segment_length)?;
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
    pub fn to_text(&self) -> Result<String, TextCarrierError> {
        let object_length = encoded_base64_length(self.object_id.len())?;
        let segment_length = encoded_base64_length(self.segment.len())?;
        let rendered_length = 7_usize
            .checked_add(object_length)
            .and_then(|length| length.checked_add(decimal_digits_u32(u32::from(self.part))))
            .and_then(|length| length.checked_add(decimal_digits_u32(u32::from(self.count))))
            .and_then(|length| length.checked_add(decimal_digits_u32(self.total)))
            .and_then(|length| length.checked_add(segment_length))
            .ok_or(TextCarrierError::Overflow)?;

        let mut rendered = String::new();
        rendered
            .try_reserve_exact(rendered_length)
            .map_err(|_| TextCarrierError::AllocationFailed)?;
        rendered.push_str("v1.");
        append_base64url(&mut rendered, &self.object_id)?;
        write!(rendered, ".{}.{}.{}.", self.part, self.count, self.total)
            .map_err(|_| TextCarrierError::Overflow)?;
        append_base64url(&mut rendered, &self.segment)?;
        if rendered.len() != rendered_length {
            return Err(TextCarrierError::Overflow);
        }
        Ok(rendered)
    }
}

fn append_base64url(output: &mut String, bytes: &[u8]) -> Result<(), TextCarrierError> {
    let encoded_length = encoded_base64_length(bytes.len())?;
    output
        .try_reserve_exact(encoded_length)
        .map_err(|_| TextCarrierError::AllocationFailed)?;
    let original_length = output.len();
    URL_SAFE_NO_PAD.encode_string(bytes, output);
    if output.len() != original_length + encoded_length {
        return Err(TextCarrierError::Overflow);
    }
    Ok(())
}

const fn decimal_digits_u32(mut value: u32) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
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
    let expected_length = validate_fragment_scalars(part, count, total)?;
    if segment_length != expected_length {
        return Err(TextCarrierError::FragmentRange);
    }
    Ok(())
}

fn validate_fragment_scalars(part: u16, count: u16, total: u32) -> Result<usize, TextCarrierError> {
    let expected_count = expected_fragment_count(total)?;
    if count == 0 || count > MAX_E2EE_FRAGMENT_COUNT || count != expected_count || part >= count {
        return Err(TextCarrierError::FragmentRange);
    }
    expected_segment_length(part, total)
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
        let mut owned = String::new();
        owned
            .try_reserve_exact(token.len())
            .map_err(|_| TextCarrierError::AllocationFailed)?;
        owned.push_str(token);
        Ok(Self(owned))
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
    "POLICY",
    "RECOVERY-SUBMISSION",
    "WITNESS-RESOLUTION",
    "LEAF-MEMBERSHIP-PROOF",
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
