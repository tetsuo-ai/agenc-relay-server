//! Raw-preserving parsing of a server line's tag section (Architecture 9.2).
//!
//! A server line carries server-added tags and, on `PRIVMSG`, `NOTICE` and
//! `TAGMSG`, relayed client-only `+` tags. [`parse_server_tags`] checks the
//! whole section and keeps it verbatim: every [`ServerTag`] borrows its key
//! and its raw, still escaped value, so a consumer can apply a rule to the
//! raw bytes (the companion's fragment tags forbid any backslash) before it
//! asks for the strict unescape.

use std::borrow::Cow;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::iter::FusedIterator;

use crate::server_framing::SERVER_TAG_SECTION_DATA_BYTES;
use crate::{
    MAX_CLIENT_ONLY_TAGS, MAX_CLIENT_ONLY_TOTAL_BYTES, MAX_CLIENT_ONLY_VALUE_BYTES,
    MAX_CLIENT_TAG_DATA_BYTES, MAX_CORRELATION_TAG_BYTES, MAX_SERVER_TAG_DATA_BYTES,
};

/// The one client-only key exempt from the value and total budgets.
const E2EE_CLIENT_TAG: &str = "+agenc.ag/e2ee";
const LABEL_TAG: &str = "label";
const BATCH_TAG: &str = "batch";
/// The longest vendor host name of a key, and its longest label.
const MAX_VENDOR_BYTES: usize = 253;
const MAX_VENDOR_LABEL_BYTES: usize = 63;
/// Sections with at most this many fields find duplicates without a hash set.
const SMALL_SECTION_FIELDS: usize = 16;

/// Closed failures of a server line's tag section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerTagError {
    /// The section held no tag.
    EmptySection,
    /// The section exceeded 8,191 bytes with its `@` and space.
    SectionTooLong,
    /// A field between separators was empty.
    EmptyTag,
    /// A key violated the IRCv3 key grammar.
    InvalidKey,
    /// A raw value contained NUL, CR, LF or a space.
    InvalidValue,
    /// A value held an escape outside `\:` `\s` `\\` `\r` `\n`, or ended in a
    /// backslash.
    InvalidEscape,
    /// One exact key occurred more than once.
    DuplicateKey,
    /// Server-added tag data exceeded 4,094 bytes.
    ServerSideTooLong,
    /// Relayed client-only tag data exceeded 4,094 bytes.
    ClientSideTooLong,
    /// More than 16 client-only tags.
    TooManyClientOnlyTags,
    /// A client-only value exceeded 256 decoded bytes.
    ClientOnlyValueTooLong,
    /// Client-only keys and values exceeded 1,024 decoded bytes.
    ClientOnlyTotalTooLong,
    /// A `label` was empty, over 64 decoded bytes, or decoded to a byte a
    /// label never holds.
    InvalidLabel,
    /// A `batch` reference was not one to 64 ASCII letters, digits or hyphens.
    InvalidBatchReference,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for ServerTagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySection => "server tag section is empty",
            Self::SectionTooLong => "server tag section exceeds its combined budget",
            Self::EmptyTag => "server tag section contains an empty tag",
            Self::InvalidKey => "message tag key violates the key grammar",
            Self::InvalidValue => "message tag value contains a forbidden wire byte",
            Self::InvalidEscape => "message tag value contains an unknown or dangling escape",
            Self::DuplicateKey => "message tag key is duplicated",
            Self::ServerSideTooLong => "server-added tag data exceeds its side budget",
            Self::ClientSideTooLong => "client-only tag data exceeds its side budget",
            Self::TooManyClientOnlyTags => "too many client-only message tags",
            Self::ClientOnlyValueTooLong => "client-only tag value exceeds its decoded bound",
            Self::ClientOnlyTotalTooLong => "client-only tags exceed their decoded total bound",
            Self::InvalidLabel => "label tag violates its bounds",
            Self::InvalidBatchReference => "batch tag violates the batch reference grammar",
            Self::AllocationFailed => "message tag allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ServerTagError {}

/// One tag of a server line: its exact key and its raw value slice.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerTag<'a> {
    key: &'a str,
    raw_value: Option<&'a str>,
}

impl<'a> ServerTag<'a> {
    /// Splits one field at its first `=`; an empty value is absent.
    fn from_field(field: &'a str) -> Self {
        match field.split_once('=') {
            Some((key, value)) => Self {
                key,
                raw_value: (!value.is_empty()).then_some(value),
            },
            None => Self {
                key: field,
                raw_value: None,
            },
        }
    }

    /// The exact, case-sensitive key, with its leading `+` if it has one.
    #[must_use]
    pub const fn key(&self) -> &'a str {
        self.key
    }

    /// The value exactly as received, escapes intact; `None` for a tag
    /// without a value or with an empty one.
    #[must_use]
    pub const fn raw_value(&self) -> Option<&'a str> {
        self.raw_value
    }

    /// Whether this is an untrusted client-only tag.
    #[must_use]
    pub fn is_client_only(&self) -> bool {
        self.key.starts_with('+')
    }

    /// The value unescaped by [`unescape_server_tag_value`].
    pub fn unescaped_value(&self) -> Result<Option<Cow<'a, str>>, ServerTagError> {
        self.raw_value.map(unescape_server_tag_value).transpose()
    }
}

impl fmt::Debug for ServerTag<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTag")
            .field("key_bytes", &self.key.len())
            .field("value_bytes", &self.raw_value.map(str::len))
            .finish()
    }
}

/// A validated tag section of a server line, kept verbatim.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerTags<'a> {
    raw: &'a str,
    count: usize,
    server_data_bytes: usize,
    client_data_bytes: usize,
    client_only_count: usize,
    label: Option<&'a str>,
    batch: Option<&'a str>,
}

impl<'a> ServerTags<'a> {
    /// The empty section of an untagged line.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            raw: "",
            count: 0,
            server_data_bytes: 0,
            client_data_bytes: 0,
            client_only_count: 0,
            label: None,
            batch: None,
        }
    }

    /// The number of tags.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the line had no tag section.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The section verbatim, without its `@` and space.
    #[must_use]
    pub const fn raw_section(&self) -> &'a str {
        self.raw
    }

    /// Bytes of server-added tag data: its fields and the separators between
    /// them, counted as if they were adjacent.
    #[must_use]
    pub const fn server_data_bytes(&self) -> usize {
        self.server_data_bytes
    }

    /// Bytes of relayed client-only tag data, counted the same way.
    #[must_use]
    pub const fn client_data_bytes(&self) -> usize {
        self.client_data_bytes
    }

    /// The number of client-only tags.
    #[must_use]
    pub const fn client_only_count(&self) -> usize {
        self.client_only_count
    }

    /// The raw `label` value. It holds no escaped delimiter; a companion
    /// `safe-label` is its own raw form ([`validate_safe_label`]).
    #[must_use]
    pub const fn label(&self) -> Option<&'a str> {
        self.label
    }

    /// The `batch` reference, which [`validate_batch_reference`] accepted.
    #[must_use]
    pub const fn batch(&self) -> Option<&'a str> {
        self.batch
    }

    /// Iterates over the tags in received order.
    #[must_use]
    pub fn iter(&self) -> ServerTagIter<'a> {
        ServerTagIter {
            rest: (!self.raw.is_empty()).then_some(self.raw),
        }
    }

    /// Finds a tag by its exact key; keys are unique.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<ServerTag<'a>> {
        self.iter().find(|tag| tag.key == key)
    }

    fn note(&mut self, tag: ServerTag<'a>) {
        match tag.key {
            LABEL_TAG => self.label = tag.raw_value,
            BATCH_TAG => self.batch = tag.raw_value,
            _ => {}
        }
    }
}

impl fmt::Debug for ServerTags<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTags")
            .field("count", &self.count)
            .field("server_data_bytes", &self.server_data_bytes)
            .field("client_data_bytes", &self.client_data_bytes)
            .finish()
    }
}

impl<'a> IntoIterator for &ServerTags<'a> {
    type Item = ServerTag<'a>;
    type IntoIter = ServerTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over the tags of a validated section.
#[derive(Clone)]
pub struct ServerTagIter<'a> {
    rest: Option<&'a str>,
}

impl<'a> Iterator for ServerTagIter<'a> {
    type Item = ServerTag<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest?;
        let (field, tail) = match rest.split_once(';') {
            Some((field, tail)) => (field, Some(tail)),
            None => (rest, None),
        };
        self.rest = tail;
        Some(ServerTag::from_field(field))
    }
}

impl FusedIterator for ServerTagIter<'_> {}

impl fmt::Debug for ServerTagIter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerTagIter")
            .field("remaining_bytes", &self.rest.map_or(0, str::len))
            .finish()
    }
}

/// Parses one server tag section, given without its `@` and space.
///
/// The section is kept verbatim (see [`ServerTags`]). What is checked, in
/// this order: the section is not empty and is at most 8,191 bytes with its
/// `@` and space; then each field, left to right, is not empty, has a key in
/// the IRCv3 grammar (`[+][vendor/]name`, `name` one or more of
/// `[A-Za-z0-9-]`, `vendor` a DNS host name), has a value with no raw NUL,
/// CR, LF or space and only the escapes `\:` `\s` `\\` `\r` `\n`, keeps
/// `label` and `batch` to their bounds, fits its side's 4,094 bytes
/// (server-added and client-only tags counted apart, in either order), keeps
/// the client-only limits (16 tags, 256 decoded bytes per value and 1,024 in
/// all, `+agenc.ag/e2ee` exempt from the last two), and repeats no key.
/// Duplicates are found in linear time. A `label` is one to 64 decoded bytes
/// and holds no escaped delimiter, as the renderer emits it; a `batch` value
/// is a [`validate_batch_reference`] reference.
pub fn parse_server_tags(raw: &str) -> Result<ServerTags<'_>, ServerTagError> {
    if raw.is_empty() {
        return Err(ServerTagError::EmptySection);
    }
    if raw.len() > SERVER_TAG_SECTION_DATA_BYTES {
        return Err(ServerTagError::SectionTooLong);
    }
    let fields = raw.bytes().filter(|byte| *byte == b';').count() + 1;
    let mut seen = SeenKeys::with_fields(fields)?;
    let mut budget = SideBudget::default();
    let mut tags = ServerTags {
        raw,
        ..ServerTags::empty()
    };
    for field in raw.split(';') {
        if field.is_empty() {
            return Err(ServerTagError::EmptyTag);
        }
        let tag = ServerTag::from_field(field);
        let decoded_value = check_tag(tag)?;
        budget.admit(tag.key, field.len(), decoded_value)?;
        seen.insert(tag.key)?;
        tags.note(tag);
    }
    tags.count = fields;
    tags.server_data_bytes = budget.server_bytes;
    tags.client_data_bytes = budget.client_bytes;
    tags.client_only_count = budget.client_count;
    Ok(tags)
}

/// Checks one field's key, value and correlation bounds; returns the decoded
/// length of its value.
fn check_tag(tag: ServerTag<'_>) -> Result<usize, ServerTagError> {
    validate_key(tag.key)?;
    let shape = tag
        .raw_value
        .map_or(Ok(ValueShape::default()), scan_value)?;
    match tag.key {
        LABEL_TAG if tag.raw_value.is_none() || !shape.is_correlation_safe() => {
            Err(ServerTagError::InvalidLabel)
        }
        BATCH_TAG => validate_batch_reference(tag.raw_value.unwrap_or_default())
            .map(|()| shape.decoded_bytes),
        _ => Ok(shape.decoded_bytes),
    }
}

fn validate_key(key: &str) -> Result<(), ServerTagError> {
    let body = key.strip_prefix('+').unwrap_or(key);
    let (vendor, name) = match body.split_once('/') {
        Some((vendor, name)) => (Some(vendor), name),
        None => (None, body),
    };
    let name_ok = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if name_ok && vendor.is_none_or(is_vendor_host) {
        Ok(())
    } else {
        Err(ServerTagError::InvalidKey)
    }
}

fn is_vendor_host(vendor: &str) -> bool {
    !vendor.is_empty()
        && vendor.len() <= MAX_VENDOR_BYTES
        && vendor.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_VENDOR_LABEL_BYTES
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// What one raw value decodes to.
#[derive(Clone, Copy, Default)]
struct ValueShape {
    decoded_bytes: usize,
    escaped_delimiter: bool,
}

impl ValueShape {
    /// Whether this is a correlation value the renderer can emit: one to 64
    /// decoded bytes and no escaped `;`, space, CR or LF.
    const fn is_correlation_safe(self) -> bool {
        self.decoded_bytes <= MAX_CORRELATION_TAG_BYTES && !self.escaped_delimiter
    }
}

/// Validates one raw value and measures what it decodes to.
fn scan_value(raw: &str) -> Result<ValueShape, ServerTagError> {
    let bytes = raw.as_bytes();
    let mut shape = ValueShape::default();
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index) {
        index += match byte {
            0 | b'\r' | b'\n' | b' ' => return Err(ServerTagError::InvalidValue),
            b'\\' => escape_width(bytes.get(index + 1), &mut shape)?,
            _ => 1,
        };
        shape.decoded_bytes += 1;
    }
    Ok(shape)
}

/// The raw width of one escape, which decodes to one byte.
fn escape_width(next: Option<&u8>, shape: &mut ValueShape) -> Result<usize, ServerTagError> {
    match next {
        Some(b'\\') => Ok(2),
        Some(b':' | b's' | b'r' | b'n') => {
            shape.escaped_delimiter = true;
            Ok(2)
        }
        _ => Err(ServerTagError::InvalidEscape),
    }
}

/// Unescapes one raw tag value strictly.
///
/// The value must pass the checks of [`parse_server_tags`]: no raw NUL, CR,
/// LF or space, and only the escapes `\:` `\s` `\\` `\r` `\n`. A value
/// without an escape is borrowed; otherwise the decoded copy is allocated
/// once at its exact length.
pub fn unescape_server_tag_value(raw: &str) -> Result<Cow<'_, str>, ServerTagError> {
    let shape = scan_value(raw)?;
    if !raw.contains('\\') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut decoded = String::new();
    decoded
        .try_reserve_exact(shape.decoded_bytes)
        .map_err(|_| ServerTagError::AllocationFailed)?;
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            decoded.push(unescaped(characters.next()));
        } else {
            decoded.push(character);
        }
    }
    Ok(Cow::Owned(decoded))
}

/// The character one validated escape stands for.
fn unescaped(escaped: Option<char>) -> char {
    match escaped {
        Some(':') => ';',
        Some('s') => ' ',
        Some('r') => '\r',
        Some('n') => '\n',
        _ => '\\',
    }
}

/// Validates a raw `label` value as a companion `safe-label`: one to 64 of
/// `[A-Za-z0-9_-]`, the grammar of [`SafeLabel`](crate::SafeLabel), checked
/// on the raw bytes so no escape can expand it.
///
/// The base profile bounds a `label` only to 64 bytes (Architecture 9.2);
/// the companion's commands require a safe label.
pub fn validate_safe_label(raw: &str) -> Result<(), ServerTagError> {
    if correlation_token(raw, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
    }) {
        Ok(())
    } else {
        Err(ServerTagError::InvalidLabel)
    }
}

/// Validates a raw `batch` reference: one to 64 ASCII letters, digits or
/// hyphens, the grammar every batch the renderer opens uses (companion
/// Section 11.7 `batch-id`).
pub fn validate_batch_reference(raw: &str) -> Result<(), ServerTagError> {
    if is_batch_reference(raw) {
        Ok(())
    } else {
        Err(ServerTagError::InvalidBatchReference)
    }
}

/// The batch reference grammar, shared with the renderer.
pub(crate) fn is_batch_reference(value: &str) -> bool {
    correlation_token(value, |byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn correlation_token(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= MAX_CORRELATION_TAG_BYTES && value.bytes().all(allowed)
}

/// Per-side and client-only accounting of one section.
#[derive(Default)]
struct SideBudget {
    server_count: usize,
    server_bytes: usize,
    client_count: usize,
    client_bytes: usize,
    client_decoded_bytes: usize,
}

impl SideBudget {
    /// Admits one field of `field_bytes` raw bytes whose value decodes to
    /// `decoded_value` bytes. A side's data is its fields and the separators
    /// between them, as the renderer measures it.
    fn admit(
        &mut self,
        key: &str,
        field_bytes: usize,
        decoded_value: usize,
    ) -> Result<(), ServerTagError> {
        if key.starts_with('+') {
            return self.admit_client_only(key, field_bytes, decoded_value);
        }
        self.server_bytes += field_bytes + usize::from(self.server_count > 0);
        self.server_count += 1;
        if self.server_bytes > MAX_SERVER_TAG_DATA_BYTES {
            return Err(ServerTagError::ServerSideTooLong);
        }
        Ok(())
    }

    fn admit_client_only(
        &mut self,
        key: &str,
        field_bytes: usize,
        decoded_value: usize,
    ) -> Result<(), ServerTagError> {
        self.client_bytes += field_bytes + usize::from(self.client_count > 0);
        self.client_count += 1;
        if self.client_bytes > MAX_CLIENT_TAG_DATA_BYTES {
            return Err(ServerTagError::ClientSideTooLong);
        }
        if self.client_count > MAX_CLIENT_ONLY_TAGS {
            return Err(ServerTagError::TooManyClientOnlyTags);
        }
        if key == E2EE_CLIENT_TAG {
            return Ok(());
        }
        if decoded_value > MAX_CLIENT_ONLY_VALUE_BYTES {
            return Err(ServerTagError::ClientOnlyValueTooLong);
        }
        self.client_decoded_bytes += key.len() + decoded_value;
        if self.client_decoded_bytes > MAX_CLIENT_ONLY_TOTAL_BYTES {
            return Err(ServerTagError::ClientOnlyTotalTooLong);
        }
        Ok(())
    }
}

/// Keys seen so far, reserved once from the field count: a list scanned in
/// full for small sections and a hash set for larger ones, so each insert is
/// bounded work and the whole check is linear in the section.
enum SeenKeys<'a> {
    Small(Vec<&'a str>),
    Large(HashSet<&'a str>),
}

impl<'a> SeenKeys<'a> {
    fn with_fields(fields: usize) -> Result<Self, ServerTagError> {
        if fields > SMALL_SECTION_FIELDS {
            let mut set = HashSet::new();
            set.try_reserve(fields)
                .map_err(|_| ServerTagError::AllocationFailed)?;
            return Ok(Self::Large(set));
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(fields)
            .map_err(|_| ServerTagError::AllocationFailed)?;
        Ok(Self::Small(keys))
    }

    /// Records `key`, which fits the reservation because each field is
    /// recorded once.
    fn insert(&mut self, key: &'a str) -> Result<(), ServerTagError> {
        let fresh = match self {
            Self::Small(keys) => {
                let fresh = !keys.contains(&key);
                keys.push(key);
                fresh
            }
            Self::Large(set) => set.insert(key),
        };
        if fresh {
            Ok(())
        } else {
            Err(ServerTagError::DuplicateKey)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SMALL_SECTION_FIELDS, SeenKeys, ServerTagError};

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            ServerTagError::EmptySection,
            ServerTagError::SectionTooLong,
            ServerTagError::EmptyTag,
            ServerTagError::InvalidKey,
            ServerTagError::InvalidValue,
            ServerTagError::InvalidEscape,
            ServerTagError::DuplicateKey,
            ServerTagError::ServerSideTooLong,
            ServerTagError::ClientSideTooLong,
            ServerTagError::TooManyClientOnlyTags,
            ServerTagError::ClientOnlyValueTooLong,
            ServerTagError::ClientOnlyTotalTooLong,
            ServerTagError::InvalidLabel,
            ServerTagError::InvalidBatchReference,
            ServerTagError::AllocationFailed,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }

    /// The scanned list holds at most 16 keys, so each insert is a bounded
    /// number of comparisons; every larger section uses the hash set.
    #[test]
    fn duplicate_tracking_switches_representation_at_the_small_limit() -> Result<(), ServerTagError>
    {
        assert!(matches!(SeenKeys::with_fields(1)?, SeenKeys::Small(_)));
        assert!(matches!(
            SeenKeys::with_fields(SMALL_SECTION_FIELDS)?,
            SeenKeys::Small(_)
        ));
        assert!(matches!(
            SeenKeys::with_fields(SMALL_SECTION_FIELDS + 1)?,
            SeenKeys::Large(_)
        ));
        let keys: Vec<String> = (0..48).map(|index| format!("k{index}")).collect();
        for fields in 1..=keys.len() {
            let mut seen = SeenKeys::with_fields(fields)?;
            for key in keys.iter().take(fields) {
                assert_eq!(seen.insert(key), Ok(()), "{fields} fields: first {key}");
            }
            for key in keys.iter().take(fields) {
                assert_eq!(
                    seen.insert(key),
                    Err(ServerTagError::DuplicateKey),
                    "{fields} fields: repeated {key}"
                );
            }
        }
        Ok(())
    }
}
