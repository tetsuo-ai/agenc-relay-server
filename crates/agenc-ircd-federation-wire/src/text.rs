//! Canonical base-federation text tokens and command-form validation.

use std::error::Error;
use std::fmt::{self, Write as _};

use agenc_ircd_types::{BASE_FRAGMENT_BYTES, BASE_FRAGMENT_COUNT, BASE_OBJECT_BYTES};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::{Zeroize as _, Zeroizing};

const FEDERATION_FRAGMENT_VERSION: &str = "v1";
/// Exact sole tag name permitted on object-bearing federation commands.
pub const FEDERATION_FRAGMENT_TAG_NAME: &str = "agenc.ag/fed";
const MAX_FIXED_BASE64_TEXT_BYTES: usize = 43;

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
    /// A command's complete tag set violated its frozen form.
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

impl fmt::Debug for FederationId16 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FederationId16([redacted])")
    }
}

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

impl fmt::Debug for FederationHash32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FederationHash32([redacted])")
    }
}

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
    if token.len() != expected_encoded || expected_encoded > MAX_FIXED_BASE64_TEXT_BYTES {
        return Err(FederationTextError::WrongLength);
    }
    validate_base64_alphabet(token)?;
    let mut decoded = [0_u8; LENGTH];
    let written = URL_SAFE_NO_PAD
        .decode_slice(token.as_bytes(), &mut decoded)
        .map_err(|_| FederationTextError::NonCanonical)?;
    if written != LENGTH {
        return Err(FederationTextError::WrongLength);
    }
    let mut canonical = [0_u8; MAX_FIXED_BASE64_TEXT_BYTES];
    let canonical_length = URL_SAFE_NO_PAD
        .encode_slice(decoded, &mut canonical)
        .map_err(|_| FederationTextError::Overflow)?;
    let canonical = canonical
        .get(..canonical_length)
        .ok_or(FederationTextError::Overflow)?;
    if canonical != token.as_bytes() {
        return Err(FederationTextError::NonCanonical);
    }
    Ok(decoded)
}

fn decode_variable(
    token: &str,
    maximum: usize,
) -> Result<SecretFragmentBytes, FederationTextError> {
    let decoded_length = validate_variable_base64_shape(token, maximum)?;
    let mut decoded = zeroed_secret_buffer(decoded_length)?;
    let written = URL_SAFE_NO_PAD
        .decode_slice(token.as_bytes(), &mut decoded)
        .map_err(|_| FederationTextError::NonCanonical)?;
    if written != decoded_length {
        return Err(FederationTextError::NonCanonical);
    }
    if !base64_reencode_matches(&decoded, token)? {
        return Err(FederationTextError::NonCanonical);
    }
    Ok(SecretFragmentBytes(std::mem::take(&mut *decoded)))
}

fn zeroed_secret_buffer(length: usize) -> Result<Zeroizing<Vec<u8>>, FederationTextError> {
    let mut buffer = Zeroizing::new(Vec::new());
    buffer
        .try_reserve_exact(length)
        .map_err(|_| FederationTextError::AllocationFailed)?;
    buffer.resize(length, 0);
    Ok(buffer)
}

fn validate_variable_base64_shape(
    token: &str,
    maximum: usize,
) -> Result<usize, FederationTextError> {
    if token.is_empty() {
        return Err(FederationTextError::Empty);
    }
    if token.len() > encoded_base64_length(maximum)? {
        return Err(FederationTextError::TooLong);
    }
    validate_base64_alphabet(token)?;
    let decoded_length = decoded_base64_length(token.len())?;
    if decoded_length > maximum {
        return Err(FederationTextError::TooLong);
    }
    Ok(decoded_length)
}

fn decoded_base64_length(encoded: usize) -> Result<usize, FederationTextError> {
    let complete = encoded
        .checked_div(4)
        .and_then(|value| value.checked_mul(3))
        .ok_or(FederationTextError::Overflow)?;
    let remainder = match encoded % 4 {
        0 => 0,
        1 => return Err(FederationTextError::NonCanonical),
        2 => 1,
        3 => 2,
        _ => return Err(FederationTextError::Overflow),
    };
    complete
        .checked_add(remainder)
        .ok_or(FederationTextError::Overflow)
}

fn base64_reencode_matches(decoded: &[u8], expected: &str) -> Result<bool, FederationTextError> {
    let mut canonical = zeroed_secret_buffer(expected.len())?;
    let written = URL_SAFE_NO_PAD
        .encode_slice(decoded, &mut canonical)
        .map_err(|_| FederationTextError::Overflow)?;
    Ok(written == expected.len() && canonical.as_slice() == expected.as_bytes())
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
    segment: SecretFragmentBytes,
}

struct SecretFragmentBytes(Vec<u8>);

impl SecretFragmentBytes {
    fn try_copy_from_slice(bytes: &[u8]) -> Result<Self, FederationTextError> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| FederationTextError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn zeroize_storage(&mut self) {
        zeroize_vec_capacity(&mut self.0);
    }
}

impl Drop for SecretFragmentBytes {
    fn drop(&mut self) {
        self.zeroize_storage();
    }
}

/// Move-only rendered federation fragment text that erases its backing
/// allocation on drop.
///
/// Fragment text can carry complete federation request or result bytes. It is
/// deliberately not printable through `Debug` or `Display`; borrow it only at
/// the transport boundary with [`Self::as_str`].
///
/// ```compile_fail
/// use agenc_ircd_federation_wire::FederationFragmentText;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<FederationFragmentText>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_federation_wire::FederationFragmentText;
///
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<FederationFragmentText>();
/// ```
#[must_use = "rendered federation text must be sent or explicitly dropped"]
pub struct FederationFragmentText {
    text: String,
}

impl FederationFragmentText {
    /// Borrows the canonical wire text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the encoded byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Reports whether the encoded text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn zeroize_storage(&mut self) {
        zeroize_string_capacity(&mut self.text);
    }
}

impl AsRef<str> for FederationFragmentText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Drop for FederationFragmentText {
    fn drop(&mut self) {
        self.zeroize_storage();
    }
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
        let decoded_segment_length = validate_variable_base64_shape(segment, maximum)?;
        let expected_segment_length = validate_fragment_header(part, count, total)?;
        if decoded_segment_length != expected_segment_length {
            return Err(FederationTextError::FragmentRange);
        }
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
        let owned = SecretFragmentBytes::try_copy_from_slice(segment)?;
        Self::from_parts(object_id, part, count, total, owned)
    }

    fn from_parts(
        object_id: FederationHash32,
        part: u32,
        count: u32,
        total: u32,
        segment: SecretFragmentBytes,
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
        self.segment.as_slice()
    }

    /// Produces the unique six-field fragment value.
    pub fn to_text(&self) -> Result<FederationFragmentText, FederationTextError> {
        let object_length = encoded_base64_length(self.object_id.as_bytes().len())?;
        let segment_length = encoded_base64_length(self.segment.len())?;
        let rendered_length = 7_usize
            .checked_add(object_length)
            .and_then(|length| length.checked_add(decimal_digits_u32(self.part)))
            .and_then(|length| length.checked_add(decimal_digits_u32(self.count)))
            .and_then(|length| length.checked_add(decimal_digits_u32(self.total)))
            .and_then(|length| length.checked_add(segment_length))
            .ok_or(FederationTextError::Overflow)?;

        let mut rendered = Zeroizing::new(String::new());
        rendered
            .try_reserve_exact(rendered_length)
            .map_err(|_| FederationTextError::AllocationFailed)?;
        rendered.push_str(FEDERATION_FRAGMENT_VERSION);
        rendered.push('.');
        append_base64url(&mut rendered, self.object_id.as_bytes())?;
        write!(rendered, ".{}.{}.{}.", self.part, self.count, self.total)
            .map_err(|_| FederationTextError::Overflow)?;
        append_base64url(&mut rendered, self.segment.as_slice())?;
        if rendered.len() != rendered_length {
            return Err(FederationTextError::Overflow);
        }
        Ok(FederationFragmentText {
            text: std::mem::take(&mut *rendered),
        })
    }
}

fn zeroize_vec_capacity(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.capacity(), 0);
    bytes.as_mut_slice().zeroize();
}

fn zeroize_string_capacity(text: &mut String) {
    let remaining = text.capacity().saturating_sub(text.len());
    text.extend(std::iter::repeat_n('\0', remaining));
    text.as_mut_str().zeroize();
}

fn append_base64url(output: &mut String, bytes: &[u8]) -> Result<(), FederationTextError> {
    let encoded_length = encoded_base64_length(bytes.len())?;
    output
        .try_reserve_exact(encoded_length)
        .map_err(|_| FederationTextError::AllocationFailed)?;
    let original_length = output.len();
    URL_SAFE_NO_PAD.encode_string(bytes, output);
    if output.len() != original_length + encoded_length {
        return Err(FederationTextError::Overflow);
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

fn validate_fragment_relationships(
    part: u32,
    count: u32,
    total: u32,
    segment_length: usize,
) -> Result<(), FederationTextError> {
    let expected_length = validate_fragment_header(part, count, total)?;
    if segment_length != expected_length {
        return Err(FederationTextError::FragmentRange);
    }
    Ok(())
}

fn validate_fragment_header(
    part: u32,
    count: u32,
    total: u32,
) -> Result<usize, FederationTextError> {
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
    if count != expected_count {
        return Err(FederationTextError::FragmentRange);
    }
    Ok(expected_length)
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

/// One borrowed message tag supplied to the federation command boundary.
#[derive(Clone, Copy)]
pub struct FederationCommandTag<'a> {
    name: &'a str,
    value: Option<&'a str>,
}

impl<'a> FederationCommandTag<'a> {
    /// Borrows one decoded tag name and value without allocating.
    #[must_use]
    pub const fn new(name: &'a str, value: Option<&'a str>) -> Self {
        Self { name, value }
    }

    /// Returns the exact case-sensitive tag name.
    #[must_use]
    pub const fn name(self) -> &'a str {
        self.name
    }

    /// Returns the decoded tag value, when present.
    #[must_use]
    pub const fn value(self) -> Option<&'a str> {
        self.value
    }
}

impl fmt::Debug for FederationCommandTag<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederationCommandTag")
            .field("name_bytes", &self.name.len())
            .field(
                "is_fragment_tag",
                &(self.name == FEDERATION_FRAGMENT_TAG_NAME),
            )
            .field("value_bytes", &self.value.map(str::len))
            .finish()
    }
}

/// Exact bounded tag set admitted on one base-federation command.
///
/// The set contains either no tags or one parsed `agenc.ag/fed` fragment. Any
/// duplicate, unrelated, client-only, valueless, or malformed tag is rejected
/// during construction.
pub struct FederationCommandTags {
    fragment: Option<FederationFragment>,
}

impl FederationCommandTags {
    /// Validates a complete decoded tag set without accepting unbounded input.
    pub fn parse(tags: &[FederationCommandTag<'_>]) -> Result<Self, FederationTextError> {
        let [tag] = tags else {
            return if tags.is_empty() {
                Ok(Self { fragment: None })
            } else {
                Err(FederationTextError::WrongTagPolicy)
            };
        };
        if tag.name != FEDERATION_FRAGMENT_TAG_NAME {
            return Err(FederationTextError::WrongTagPolicy);
        }
        let value = tag
            .value
            .filter(|value| !value.is_empty())
            .ok_or(FederationTextError::WrongTagPolicy)?;
        if value.len() > maximum_fragment_tag_value_bytes()? {
            return Err(FederationTextError::TooLong);
        }
        Ok(Self {
            fragment: Some(FederationFragment::parse(value)?),
        })
    }

    /// Constructs the sole valid tag set for an untagged command.
    #[must_use]
    pub const fn empty() -> Self {
        Self { fragment: None }
    }

    /// Borrows the validated fragment when this is the sole tagged form.
    #[must_use]
    pub const fn fragment(&self) -> Option<&FederationFragment> {
        self.fragment.as_ref()
    }

    /// Moves the validated fragment out of the tag set.
    #[must_use]
    pub fn into_fragment(self) -> Option<FederationFragment> {
        self.fragment
    }
}

fn maximum_fragment_tag_value_bytes() -> Result<usize, FederationTextError> {
    let fragment_bytes = usize_constant(BASE_FRAGMENT_BYTES)?;
    let encoded_fragment_bytes = encoded_base64_length(fragment_bytes)?;
    let decimal_bytes = decimal_digits_u32(u32::MAX)
        .checked_mul(3)
        .ok_or(FederationTextError::Overflow)?;
    7_usize
        .checked_add(MAX_FIXED_BASE64_TEXT_BYTES)
        .and_then(|length| length.checked_add(decimal_bytes))
        .and_then(|length| length.checked_add(encoded_fragment_bytes))
        .ok_or(FederationTextError::Overflow)
}

/// Whether one command form requires the sole federation fragment tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentTagPolicy {
    /// The command must have exactly one `agenc.ag/fed` tag.
    Required,
    /// The command must have no tags.
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

/// Validates exact case, subcommand, arity, and the complete tag set.
pub fn validate_federation_command(
    command: &str,
    parameters: &[&str],
    tags: &FederationCommandTags,
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
    validate_tag_policy(descriptor.fragment_tag, tags)?;
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
    tags: &FederationCommandTags,
) -> Result<(), FederationTextError> {
    if matches!(
        (policy, tags.fragment.is_some()),
        (FragmentTagPolicy::Required, true) | (FragmentTagPolicy::Forbidden, false),
    ) {
        return Ok(());
    }
    Err(FederationTextError::WrongTagPolicy)
}

#[cfg(test)]
mod tests {
    use super::{FederationFragmentText, SecretFragmentBytes};

    #[test]
    fn secret_storage_wipers_cover_complete_backing_capacity() {
        let mut raw_bytes = Vec::with_capacity(32);
        raw_bytes.extend_from_slice(b"secret fragment");
        let byte_capacity = raw_bytes.capacity();
        let mut bytes = SecretFragmentBytes(raw_bytes);
        bytes.zeroize_storage();
        assert_eq!(bytes.as_slice().len(), byte_capacity);
        assert!(bytes.as_slice().iter().all(|byte| *byte == 0));

        let mut raw_text = String::with_capacity(32);
        raw_text.push_str("v1.secret-fragment");
        let text_capacity = raw_text.capacity();
        let mut text = FederationFragmentText { text: raw_text };
        text.zeroize_storage();
        assert_eq!(text.len(), text_capacity);
        assert!(text.as_str().as_bytes().iter().all(|byte| *byte == 0));
    }
}
