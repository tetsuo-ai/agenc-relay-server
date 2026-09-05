//! IRCv3 message-tag parsing and canonical escaping.

use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;
use std::ops::Range;

use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    MAX_CLIENT_ONLY_TAGS, MAX_CLIENT_ONLY_TOTAL_BYTES, MAX_CLIENT_ONLY_VALUE_BYTES,
    MAX_CLIENT_TAG_DATA_BYTES, MAX_CORRELATION_TAG_BYTES,
};

const E2EE_TAG: &str = "+agenc.ag/e2ee";

/// One owned, decoded message tag with an opaque, case-sensitive key.
#[derive(Eq, PartialEq)]
pub struct MessageTag {
    key: String,
    value: Option<String>,
}

impl MessageTag {
    /// Constructs an already decoded tag while enforcing local bounds.
    pub fn new(key: &str, value: Option<&str>) -> Result<Self, TagError> {
        let value = value.filter(|value| !value.is_empty());
        validate_key(key)?;
        validate_decoded_value(value)?;
        validate_correlation_value(key, value)?;
        let mut budget = ClientOnlyBudget::default();
        budget.admit(key, value)?;
        if encoded_tag_len(key, value)? > MAX_CLIENT_TAG_DATA_BYTES {
            return Err(TagError::RawSectionTooLong);
        }
        Ok(Self {
            key: copy_string(key)?,
            value: value.map(copy_string).transpose()?,
        })
    }

    /// Returns the exact opaque key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the decoded value; an empty wire value is represented as absent.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// Returns whether this is an untrusted client-only tag.
    #[must_use]
    pub fn is_client_only(&self) -> bool {
        self.key.starts_with('+')
    }

    fn as_ref(&self) -> MessageTagRef<'_> {
        MessageTagRef {
            key: &self.key,
            value: self.value.as_deref(),
        }
    }
}

impl fmt::Debug for MessageTag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageTag")
            .field("key", &self.key)
            .field("value", &self.value.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl Drop for MessageTag {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some(value) = &mut self.value {
            value.zeroize();
        }
    }
}

/// A borrowed view of one parsed or locally constructed message tag.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MessageTagRef<'a> {
    key: &'a str,
    value: Option<&'a str>,
}

impl<'a> MessageTagRef<'a> {
    /// Returns the exact opaque key.
    #[must_use]
    pub const fn key(self) -> &'a str {
        self.key
    }

    /// Returns the decoded value; an empty wire value is represented as absent.
    #[must_use]
    pub const fn value(self) -> Option<&'a str> {
        self.value
    }

    /// Returns whether this is an untrusted client-only tag.
    #[must_use]
    pub fn is_client_only(self) -> bool {
        self.key.starts_with('+')
    }
}

impl fmt::Debug for MessageTagRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageTagRef")
            .field("key", &self.key)
            .field("value", &self.value.map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PackedRange(u32);

const _: [(); 4] = [(); size_of::<PackedRange>()];

impl PackedRange {
    const ABSENT: Self = Self(u32::MAX);

    fn new(start: usize, len: usize) -> Result<Self, TagError> {
        let start = u16::try_from(start).map_err(|_| TagError::Overflow)?;
        let len = u16::try_from(len).map_err(|_| TagError::Overflow)?;
        Ok(Self((u32::from(start) << 16) | u32::from(len)))
    }

    fn range(self) -> Option<Range<usize>> {
        if self == Self::ABSENT {
            return None;
        }
        let start = usize::from((self.0 >> 16) as u16);
        let len = usize::from(self.0 as u16);
        start.checked_add(len).map(|end| start..end)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ParsedTag {
    key: PackedRange,
    value: PackedRange,
}

pub(crate) const PARSED_TAG_DESCRIPTOR_BYTES: usize = 8;
const _: [(); PARSED_TAG_DESCRIPTOR_BYTES] = [(); size_of::<ParsedTag>()];

/// Compact owner for parsed tags.
///
/// Every key and decoded value shares one fallibly allocated UTF-8 arena. The
/// range table uses eight bytes per tag, so a maximal client tag section does
/// not create one heap allocation per peer-controlled field.
pub struct ParsedTags {
    storage: Zeroizing<String>,
    tags: Vec<ParsedTag>,
}

impl ParsedTags {
    pub(crate) fn empty() -> Self {
        Self {
            storage: Zeroizing::new(String::new()),
            tags: Vec::new(),
        }
    }

    /// Returns the number of parsed tags.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Returns whether no tags were present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Returns the first tag, if present.
    #[must_use]
    pub fn first(&self) -> Option<MessageTagRef<'_>> {
        self.get(0)
    }

    /// Returns the tag at `index`, if present.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<MessageTagRef<'_>> {
        self.tags
            .get(index)
            .and_then(|tag| parsed_tag_ref(&self.storage, *tag))
    }

    /// Iterates over tags in their received order.
    pub fn iter(&self) -> ParsedTagIter<'_> {
        ParsedTagIter {
            tags: self,
            position: 0,
        }
    }

    pub(crate) fn requested_backing_capacities(&self) -> (usize, usize) {
        (
            self.storage.len(),
            self.tags.len().saturating_mul(size_of::<ParsedTag>()),
        )
    }

    #[cfg(test)]
    pub(crate) fn actual_backing_capacities(&self) -> (usize, usize) {
        (
            self.storage.capacity(),
            self.tags.capacity().saturating_mul(size_of::<ParsedTag>()),
        )
    }
}

impl fmt::Debug for ParsedTags {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedTags")
            .field("tag_count", &self.tags.len())
            .field("decoded_bytes", &self.storage.len())
            .finish()
    }
}

impl PartialEq for ParsedTags {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && (0..self.len()).all(|index| self.get(index) == other.get(index))
    }
}

impl Eq for ParsedTags {}

/// Ordered iterator over compact parsed tags.
pub struct ParsedTagIter<'a> {
    tags: &'a ParsedTags,
    position: usize,
}

impl<'a> Iterator for ParsedTagIter<'a> {
    type Item = MessageTagRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let tag = self.tags.get(self.position)?;
        self.position = self.position.saturating_add(1);
        Some(tag)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.tags.len().saturating_sub(self.position);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ParsedTagIter<'_> {}
impl FusedIterator for ParsedTagIter<'_> {}

impl<'a> IntoIterator for &'a ParsedTags {
    type Item = MessageTagRef<'a>;
    type IntoIter = ParsedTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Read-only tag access accepted by [`render_tags`].
///
/// This trait is sealed so measuring and encoding always observe the same
/// immutable tag collection.
pub trait MessageTagSource: sealed::Sealed {
    /// Returns the number of available tags.
    fn tag_count(&self) -> usize;

    /// Returns the tag at `index`, if present.
    fn tag_at(&self, index: usize) -> Option<MessageTagRef<'_>>;
}

impl sealed::Sealed for ParsedTags {}

impl MessageTagSource for ParsedTags {
    fn tag_count(&self) -> usize {
        self.len()
    }

    fn tag_at(&self, index: usize) -> Option<MessageTagRef<'_>> {
        self.get(index)
    }
}

impl sealed::Sealed for [MessageTag] {}

impl MessageTagSource for [MessageTag] {
    fn tag_count(&self) -> usize {
        self.len()
    }

    fn tag_at(&self, index: usize) -> Option<MessageTagRef<'_>> {
        self.get(index).map(MessageTag::as_ref)
    }
}

impl sealed::Sealed for Vec<MessageTag> {}

impl MessageTagSource for Vec<MessageTag> {
    fn tag_count(&self) -> usize {
        self.len()
    }

    fn tag_at(&self, index: usize) -> Option<MessageTagRef<'_>> {
        self.as_slice().tag_at(index)
    }
}

impl<const TAGS: usize> sealed::Sealed for [MessageTag; TAGS] {}

impl<const TAGS: usize> MessageTagSource for [MessageTag; TAGS] {
    fn tag_count(&self) -> usize {
        self.len()
    }

    fn tag_at(&self, index: usize) -> Option<MessageTagRef<'_>> {
        self.as_slice().tag_at(index)
    }
}

/// Closed message-tag failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagError {
    /// The raw client tag side exceeded 4,094 bytes.
    RawSectionTooLong,
    /// A key was empty or contained a message delimiter.
    InvalidKey,
    /// A raw or decoded value contained a forbidden wire byte.
    InvalidValue,
    /// One exact case-sensitive key occurred more than once.
    DuplicateKey,
    /// More than 16 client-only tags were supplied.
    TooManyClientOnlyTags,
    /// An ordinary client-only value exceeded 256 decoded bytes.
    ClientOnlyValueTooLong,
    /// Ordinary decoded client-only data exceeded 1,024 bytes.
    ClientOnlyTotalTooLong,
    /// A local correlation tag exceeded 64 bytes.
    CorrelationValueTooLong,
    /// A checked tag length or compact range calculation overflowed.
    Overflow,
    /// A bounded tag allocation failed.
    AllocationFailed,
}

impl fmt::Display for TagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RawSectionTooLong => "client tag section exceeds its raw byte budget",
            Self::InvalidKey => "message tag key is empty or contains a delimiter",
            Self::InvalidValue => "message tag value contains a forbidden wire byte",
            Self::DuplicateKey => "message tag key is duplicated",
            Self::TooManyClientOnlyTags => "too many client-only message tags",
            Self::ClientOnlyValueTooLong => "client-only tag value exceeds its decoded bound",
            Self::ClientOnlyTotalTooLong => "client-only tags exceed their decoded total bound",
            Self::CorrelationValueTooLong => "correlation tag exceeds its byte bound",
            Self::Overflow => "message tag length calculation overflowed",
            Self::AllocationFailed => "message tag allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for TagError {}

/// Parses client-provided tag data without the leading `@` or trailing space.
pub fn parse_client_tags(raw: &str) -> Result<ParsedTags, TagError> {
    if raw.len() > MAX_CLIENT_TAG_DATA_BYTES {
        return Err(TagError::RawSectionTooLong);
    }
    let shape = validate_tag_section(raw)?;
    reject_duplicate_keys(raw)?;

    let mut storage = Zeroizing::new(String::new());
    storage
        .try_reserve_exact(shape.decoded_bytes)
        .map_err(|_| TagError::AllocationFailed)?;
    let mut tags = Vec::new();
    tags.try_reserve_exact(shape.field_count)
        .map_err(|_| TagError::AllocationFailed)?;
    for field in raw.split(';') {
        let (key, encoded_value) = split_field(field);
        let key = append_text(&mut storage, key)?;
        let value = if let Some(encoded_value) = encoded_value {
            let start = storage.len();
            unescape_value_into(encoded_value, &mut storage);
            let len = storage.len().checked_sub(start).ok_or(TagError::Overflow)?;
            if len == 0 {
                PackedRange::ABSENT
            } else {
                PackedRange::new(start, len)?
            }
        } else {
            PackedRange::ABSENT
        };
        tags.push(ParsedTag { key, value });
    }
    Ok(ParsedTags { storage, tags })
}

#[derive(Clone, Copy)]
struct TagSectionShape {
    field_count: usize,
    decoded_bytes: usize,
}

fn validate_tag_section(raw: &str) -> Result<TagSectionShape, TagError> {
    let mut budget = ClientOnlyBudget::default();
    let mut field_count = 0_usize;
    let mut decoded_bytes = 0_usize;
    for field in raw.split(';') {
        let (key, encoded_value) = split_field(field);
        validate_key(key)?;
        let value_len = encoded_value
            .map(decoded_value_len)
            .transpose()?
            .filter(|len| *len != 0);
        validate_correlation_value_len(key, value_len)?;
        budget.admit_len(key, value_len)?;
        field_count = field_count.checked_add(1).ok_or(TagError::Overflow)?;
        decoded_bytes = decoded_bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value_len.unwrap_or_default()))
            .ok_or(TagError::Overflow)?;
    }
    Ok(TagSectionShape {
        field_count,
        decoded_bytes,
    })
}

fn reject_duplicate_keys(raw: &str) -> Result<(), TagError> {
    for (right_position, right) in raw.split(';').enumerate().skip(1) {
        let (right_key, _) = split_field(right);
        for left in raw.split(';').take(right_position) {
            let (left_key, _) = split_field(left);
            if left_key == right_key {
                return Err(TagError::DuplicateKey);
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct ClientOnlyBudget {
    count: usize,
    decoded_bytes: usize,
}

impl ClientOnlyBudget {
    fn admit(&mut self, key: &str, value: Option<&str>) -> Result<(), TagError> {
        self.admit_len(key, value.map(str::len))
    }

    fn admit_len(&mut self, key: &str, value_len: Option<usize>) -> Result<(), TagError> {
        if !key.starts_with('+') {
            return Ok(());
        }
        self.count = self.count.checked_add(1).ok_or(TagError::Overflow)?;
        if self.count > MAX_CLIENT_ONLY_TAGS {
            return Err(TagError::TooManyClientOnlyTags);
        }
        if key == E2EE_TAG {
            return Ok(());
        }
        let value_len = value_len.unwrap_or_default();
        if value_len > MAX_CLIENT_ONLY_VALUE_BYTES {
            return Err(TagError::ClientOnlyValueTooLong);
        }
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value_len))
            .ok_or(TagError::Overflow)?;
        if self.decoded_bytes > MAX_CLIENT_ONLY_TOTAL_BYTES {
            return Err(TagError::ClientOnlyTotalTooLong);
        }
        Ok(())
    }
}

fn split_field(field: &str) -> (&str, Option<&str>) {
    field.split_once('=').map_or((field, None), |(key, value)| {
        (key, if value.is_empty() { None } else { Some(value) })
    })
}

/// Renders decoded tags in their supplied canonical order.
pub fn render_tags<T: MessageTagSource + ?Sized>(tags: &T) -> Result<String, TagError> {
    let mut rendered = String::new();
    let bytes = validate_rendered_collection(tags)?;
    rendered
        .try_reserve_exact(bytes)
        .map_err(|_| TagError::AllocationFailed)?;
    for position in 0..tags.tag_count() {
        let Some(tag) = tags.tag_at(position) else {
            return Err(TagError::Overflow);
        };
        if position != 0 {
            rendered.push(';');
        }
        rendered.push_str(tag.key());
        if let Some(value) = tag.value() {
            rendered.push('=');
            escape_value(value, &mut rendered);
        }
    }
    Ok(rendered)
}

fn validate_rendered_collection<T: MessageTagSource + ?Sized>(tags: &T) -> Result<usize, TagError> {
    let tag_count = tags.tag_count();
    let minimum_bytes = if tag_count == 0 {
        0
    } else {
        tag_count
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_sub(1))
            .ok_or(TagError::Overflow)?
    };
    if minimum_bytes > MAX_CLIENT_TAG_DATA_BYTES {
        return Err(TagError::RawSectionTooLong);
    }

    let mut client_only_budget = ClientOnlyBudget::default();
    let mut bytes = tag_count.saturating_sub(1);
    for position in 0..tag_count {
        let Some(tag) = tags.tag_at(position) else {
            return Err(TagError::Overflow);
        };
        validate_key(tag.key())?;
        validate_decoded_value(tag.value())?;
        validate_correlation_value(tag.key(), tag.value())?;
        client_only_budget.admit(tag.key(), tag.value())?;
        bytes = bytes
            .checked_add(encoded_tag_len(tag.key(), tag.value())?)
            .ok_or(TagError::Overflow)?;
        if bytes > MAX_CLIENT_TAG_DATA_BYTES {
            return Err(TagError::RawSectionTooLong);
        }
    }
    reject_duplicate_source_keys(tags, tag_count)?;
    Ok(bytes)
}

fn reject_duplicate_source_keys<T: MessageTagSource + ?Sized>(
    tags: &T,
    tag_count: usize,
) -> Result<(), TagError> {
    for right_position in 1..tag_count {
        let Some(right) = tags.tag_at(right_position) else {
            return Err(TagError::Overflow);
        };
        for left_position in 0..right_position {
            let Some(left) = tags.tag_at(left_position) else {
                return Err(TagError::Overflow);
            };
            if left.key() == right.key() {
                return Err(TagError::DuplicateKey);
            }
        }
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), TagError> {
    if key.is_empty()
        || key
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';' | b'='))
    {
        return Err(TagError::InvalidKey);
    }
    Ok(())
}

fn validate_correlation_value(key: &str, value: Option<&str>) -> Result<(), TagError> {
    validate_correlation_value_len(key, value.map(str::len))
}

fn validate_correlation_value_len(key: &str, value_len: Option<usize>) -> Result<(), TagError> {
    if matches!(key, "label" | "batch")
        && value_len.is_some_and(|len| len > MAX_CORRELATION_TAG_BYTES)
    {
        return Err(TagError::CorrelationValueTooLong);
    }
    Ok(())
}

fn validate_encoded_value(value: &str) -> Result<(), TagError> {
    if value
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';'))
    {
        return Err(TagError::InvalidValue);
    }
    Ok(())
}

fn validate_decoded_value(value: Option<&str>) -> Result<(), TagError> {
    if value.is_some_and(|value| value.bytes().any(|byte| byte == 0)) {
        return Err(TagError::InvalidValue);
    }
    Ok(())
}

fn decoded_value_len(encoded: &str) -> Result<usize, TagError> {
    validate_encoded_value(encoded)?;
    let mut bytes = 0_usize;
    let mut escaped = false;
    for character in encoded.chars() {
        if escaped {
            let decoded = match character {
                ':' | 's' | '\\' | 'r' | 'n' => 1,
                other => other.len_utf8(),
            };
            bytes = bytes.checked_add(decoded).ok_or(TagError::Overflow)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            bytes = bytes
                .checked_add(character.len_utf8())
                .ok_or(TagError::Overflow)?;
        }
    }
    Ok(bytes)
}

fn unescape_value_into(encoded: &str, decoded: &mut String) {
    let mut escaped = false;
    for character in encoded.chars() {
        if escaped {
            match character {
                ':' => decoded.push(';'),
                's' => decoded.push(' '),
                '\\' => decoded.push('\\'),
                'r' => decoded.push('\r'),
                'n' => decoded.push('\n'),
                other => decoded.push(other),
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
}

fn append_text(storage: &mut String, value: &str) -> Result<PackedRange, TagError> {
    let start = storage.len();
    storage.push_str(value);
    PackedRange::new(start, value.len())
}

fn packed_text(storage: &str, range: PackedRange) -> Option<&str> {
    storage.get(range.range()?)
}

fn parsed_tag_ref(storage: &str, tag: ParsedTag) -> Option<MessageTagRef<'_>> {
    Some(MessageTagRef {
        key: packed_text(storage, tag.key)?,
        value: if tag.value == PackedRange::ABSENT {
            None
        } else {
            Some(packed_text(storage, tag.value)?)
        },
    })
}

fn escape_value(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            ';' => output.push_str("\\:"),
            ' ' => output.push_str("\\s"),
            '\\' => output.push_str("\\\\"),
            '\r' => output.push_str("\\r"),
            '\n' => output.push_str("\\n"),
            other => output.push(other),
        }
    }
}

fn encoded_tag_len(key: &str, value: Option<&str>) -> Result<usize, TagError> {
    let mut bytes = key.len();
    if let Some(value) = value {
        bytes = bytes.checked_add(1).ok_or(TagError::Overflow)?;
        for byte in value.bytes() {
            bytes = bytes
                .checked_add(if matches!(byte, b';' | b' ' | b'\\' | b'\r' | b'\n') {
                    2
                } else {
                    1
                })
                .ok_or(TagError::Overflow)?;
        }
    }
    Ok(bytes)
}

fn copy_string(value: &str) -> Result<String, TagError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| TagError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

#[cfg(test)]
mod tests {
    use super::{PARSED_TAG_DESCRIPTOR_BYTES, PackedRange, ParsedTag, TagError, parse_client_tags};
    use crate::MAX_CLIENT_TAG_DATA_BYTES;

    const KEY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    #[test]
    fn semicolon_flood_fails_syntax_validation() {
        let raw = ";".repeat(MAX_CLIENT_TAG_DATA_BYTES);
        assert_eq!(parse_client_tags(&raw).err(), Some(TagError::InvalidKey));
    }

    #[test]
    fn compact_ranges_bound_a_maximal_valid_section() -> Result<(), TagError> {
        let raw = maximal_two_byte_key_section()?;
        assert_eq!(raw.len(), MAX_CLIENT_TAG_DATA_BYTES);

        let tags = parse_client_tags(&raw)?;
        assert_eq!(tags.len(), 1_365);
        assert_eq!(size_of::<PackedRange>(), 4);
        assert_eq!(size_of::<ParsedTag>(), PARSED_TAG_DESCRIPTOR_BYTES);
        assert_eq!(tags.requested_backing_capacities(), (2_730, 10_920));
        Ok(())
    }

    #[test]
    fn duplicate_detection_finds_a_late_duplicate() -> Result<(), TagError> {
        let mut raw = two_byte_key_section(1_000)?;
        raw.push_str(";AA");
        assert_eq!(parse_client_tags(&raw).err(), Some(TagError::DuplicateKey));
        Ok(())
    }

    fn maximal_two_byte_key_section() -> Result<String, TagError> {
        two_byte_key_section(1_365)
    }

    fn two_byte_key_section(count: usize) -> Result<String, TagError> {
        let mut raw = String::new();
        let requested = count
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_sub(1))
            .ok_or(TagError::Overflow)?;
        raw.try_reserve_exact(requested)
            .map_err(|_| TagError::AllocationFailed)?;
        for index in 0..count {
            if index != 0 {
                raw.push(';');
            }
            let high = index / KEY_ALPHABET.len();
            let low = index % KEY_ALPHABET.len();
            let first = KEY_ALPHABET.get(high).copied().ok_or(TagError::Overflow)?;
            let second = KEY_ALPHABET.get(low).copied().ok_or(TagError::Overflow)?;
            raw.push(char::from(first));
            raw.push(char::from(second));
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod display_tests {
    use super::TagError;

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            TagError::RawSectionTooLong,
            TagError::InvalidKey,
            TagError::InvalidValue,
            TagError::DuplicateKey,
            TagError::TooManyClientOnlyTags,
            TagError::ClientOnlyValueTooLong,
            TagError::ClientOnlyTotalTooLong,
            TagError::CorrelationValueTooLong,
            TagError::Overflow,
            TagError::AllocationFailed,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }
}
