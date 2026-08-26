//! Total syntax parsing for one already framed client message.

use std::error::Error;
use std::fmt;

use zeroize::Zeroize as _;

use crate::{FramedLine, MAX_PARAMETERS, ParsedTags, TagError, parse_client_tags};

/// A syntax-validated client message without authorization or domain effects.
#[derive(Eq, PartialEq)]
pub struct ParsedMessage {
    tags: ParsedTags,
    wire_bytes: usize,
    requested_backing_bytes: usize,
    command: String,
    middle: Vec<String>,
    trailing: Option<String>,
}

impl ParsedMessage {
    /// Returns parsed tags in their received order.
    #[must_use]
    pub fn tags(&self) -> &ParsedTags {
        &self.tags
    }

    /// Returns the original framed payload length, excluding any TCP CRLF.
    #[must_use]
    pub const fn wire_bytes(&self) -> usize {
        self.wire_bytes
    }

    /// Returns the exact capacities requested for retained parsed backing.
    ///
    /// This excludes the inline [`ParsedMessage`] value and allocator page
    /// charging. It is the logical byte quantity to reserve against a parsed
    /// command arena before transferring ownership of this message.
    #[must_use]
    pub const fn requested_backing_bytes(&self) -> usize {
        self.requested_backing_bytes
    }

    /// Returns the canonical uppercase command.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Returns middle parameters, excluding the optional trailing parameter.
    #[must_use]
    pub fn middle(&self) -> &[String] {
        &self.middle
    }

    /// Returns the explicitly present trailing parameter, which may be empty.
    #[must_use]
    pub fn trailing(&self) -> Option<&str> {
        self.trailing.as_deref()
    }

    /// Returns the total middle-plus-trailing parameter count.
    #[must_use]
    pub fn parameter_count(&self) -> usize {
        self.middle.len() + usize::from(self.trailing.is_some())
    }

    pub(crate) fn take_single_parameter(&mut self) -> Option<String> {
        match (self.middle.as_slice(), self.trailing.as_ref()) {
            ([_], None) => self.middle.pop(),
            ([], Some(_)) => self.trailing.take(),
            _ => None,
        }
    }
}

impl fmt::Debug for ParsedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedMessage")
            .field("tag_count", &self.tags.len())
            .field("command", &self.command)
            .field("parameter_count", &self.parameter_count())
            .field("trailing_present", &self.trailing.is_some())
            .finish()
    }
}

impl Drop for ParsedMessage {
    fn drop(&mut self) {
        self.command.zeroize();
        for parameter in &mut self.middle {
            parameter.zeroize();
        }
        if let Some(trailing) = &mut self.trailing {
            trailing.zeroize();
        }
    }
}

/// Closed syntax parser failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageParseError {
    /// Client prefixes are forbidden.
    ClientPrefix,
    /// A tag section lacked its required separating space.
    UnterminatedTags,
    /// Message-tag validation failed.
    Tags(TagError),
    /// The command was empty or contained non-ASCII-letter bytes.
    InvalidCommand,
    /// More than 15 parameters were supplied.
    TooManyParameters,
    /// A middle parameter violated IRC syntax.
    InvalidMiddleParameter,
    /// A parsed backing-capacity calculation overflowed.
    Overflow,
    /// A bounded parser allocation failed.
    AllocationFailed,
}

impl fmt::Display for MessageParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ClientPrefix => "client messages may not contain a prefix",
            Self::UnterminatedTags => "message tag section lacks a separating space",
            Self::Tags(_) => "message tags are invalid",
            Self::InvalidCommand => "client command must contain only ASCII letters",
            Self::TooManyParameters => "client message has more than 15 parameters",
            Self::InvalidMiddleParameter => "client middle parameter is invalid",
            Self::Overflow => "client message backing-capacity calculation overflowed",
            Self::AllocationFailed => "client message allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for MessageParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Tags(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TagError> for MessageParseError {
    fn from(error: TagError) -> Self {
        Self::Tags(error)
    }
}

/// Parses one non-empty UTF-8 protocol line; empty lines return `None`.
pub fn parse_message(line: FramedLine<'_>) -> Result<Option<ParsedMessage>, MessageParseError> {
    let wire_bytes = line.as_str().len();
    let mut rest = line.as_str().trim_start_matches(' ');
    if rest.is_empty() {
        return Ok(None);
    }
    let tags = if rest.starts_with('@') {
        let Some(space) = rest.find(' ') else {
            return Err(MessageParseError::UnterminatedTags);
        };
        let Some(raw_tags) = rest.get(1..space) else {
            return Err(MessageParseError::UnterminatedTags);
        };
        rest = rest
            .get(space.saturating_add(1)..)
            .unwrap_or_default()
            .trim_start_matches(' ');
        parse_client_tags(raw_tags)?
    } else {
        ParsedTags::empty()
    };
    if rest.starts_with(':') {
        return Err(MessageParseError::ClientPrefix);
    }
    let command_end = rest.find(' ').unwrap_or(rest.len());
    let Some(raw_command) = rest.get(..command_end) else {
        return Err(MessageParseError::InvalidCommand);
    };
    if raw_command.is_empty() || !raw_command.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(MessageParseError::InvalidCommand);
    }
    let mut command = String::new();
    command
        .try_reserve_exact(raw_command.len())
        .map_err(|_| MessageParseError::AllocationFailed)?;
    command.extend(
        raw_command
            .bytes()
            .map(|byte| char::from(byte.to_ascii_uppercase())),
    );
    rest = rest
        .get(command_end..)
        .unwrap_or_default()
        .trim_start_matches(' ');
    let (middle, trailing) = parse_parameters(rest)?;
    let requested_backing_bytes =
        calculate_requested_backing_bytes(&tags, &command, &middle, trailing.as_deref())?;
    Ok(Some(ParsedMessage {
        tags,
        wire_bytes,
        requested_backing_bytes,
        command,
        middle,
        trailing,
    }))
}

fn parse_parameters(mut rest: &str) -> Result<(Vec<String>, Option<String>), MessageParseError> {
    let middle_count = validate_parameters(rest)?;
    let mut middle = Vec::new();
    middle
        .try_reserve_exact(middle_count)
        .map_err(|_| MessageParseError::AllocationFailed)?;
    let mut trailing = None;
    while !rest.is_empty() {
        if let Some(value) = rest.strip_prefix(':') {
            trailing = Some(copy_string(value)?);
            break;
        }
        let end = rest.find(' ').unwrap_or(rest.len());
        let Some(parameter) = rest.get(..end) else {
            return Err(MessageParseError::InvalidMiddleParameter);
        };
        middle.push(copy_string(parameter)?);
        rest = rest.get(end..).unwrap_or_default().trim_start_matches(' ');
    }
    Ok((middle, trailing))
}

fn validate_parameters(mut rest: &str) -> Result<usize, MessageParseError> {
    let mut middle_count = 0_usize;
    while !rest.is_empty() {
        if middle_count >= MAX_PARAMETERS {
            return Err(MessageParseError::TooManyParameters);
        }
        if rest.starts_with(':') {
            return Ok(middle_count);
        }
        let end = rest.find(' ').unwrap_or(rest.len());
        let Some(parameter) = rest.get(..end) else {
            return Err(MessageParseError::InvalidMiddleParameter);
        };
        if parameter.is_empty()
            || parameter.starts_with(':')
            || parameter
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' '))
        {
            return Err(MessageParseError::InvalidMiddleParameter);
        }
        middle_count = middle_count
            .checked_add(1)
            .ok_or(MessageParseError::TooManyParameters)?;
        rest = rest.get(end..).unwrap_or_default().trim_start_matches(' ');
    }
    Ok(middle_count)
}

fn copy_string(value: &str) -> Result<String, MessageParseError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| MessageParseError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn calculate_requested_backing_bytes(
    tags: &ParsedTags,
    command: &str,
    middle: &[String],
    trailing: Option<&str>,
) -> Result<usize, MessageParseError> {
    let (tag_text, tag_ranges) = tags.requested_backing_capacities();
    let middle_table = middle
        .len()
        .checked_mul(size_of::<String>())
        .ok_or(MessageParseError::Overflow)?;
    let mut total = tag_text
        .checked_add(tag_ranges)
        .and_then(|bytes| bytes.checked_add(command.len()))
        .and_then(|bytes| bytes.checked_add(middle_table))
        .ok_or(MessageParseError::Overflow)?;
    for parameter in middle {
        total = total
            .checked_add(parameter.len())
            .ok_or(MessageParseError::Overflow)?;
    }
    total
        .checked_add(trailing.map_or(0, str::len))
        .ok_or(MessageParseError::Overflow)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{MessageParseError, ParsedMessage, parse_message};
    use crate::tags::PARSED_TAG_DESCRIPTOR_BYTES;
    use crate::{FramedLine, MAX_CLIENT_TAG_DATA_BYTES, MAX_COMMAND_BYTES, MAX_PARAMETERS};

    const KEY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const HARD_PARSED_ARENA_BYTES: usize = 128 * 1_024;
    const ALLOCATION_BOOKKEEPING_BYTES: usize = 256;
    const ALLOCATION_PAGE_BYTES: usize = 4_096;

    #[test]
    fn maximal_message_stays_below_the_hard_parsed_arena() -> Result<(), Box<dyn Error>> {
        let tags = maximal_two_byte_key_section()?;
        let command = maximal_parameter_section();
        let line = format!("@{tags} {command}");
        let Some(message) = parse_message(FramedLine::new(&line)?)? else {
            return Err(MessageParseError::InvalidCommand.into());
        };
        assert_eq!(message.wire_bytes(), line.len());
        assert_eq!(message.requested_backing_bytes(), 14_480);

        let actual_charge = requested_allocation_charge(&message);
        assert_eq!(actual_charge, 86_016);
        assert!(actual_charge < HARD_PARSED_ARENA_BYTES);

        let maximum_tag_count = MAX_CLIENT_TAG_DATA_BYTES.div_ceil(2);
        let conservative_charge = allocation_charge(MAX_CLIENT_TAG_DATA_BYTES)
            + allocation_charge(maximum_tag_count * PARSED_TAG_DESCRIPTOR_BYTES)
            + allocation_charge(MAX_PARAMETERS * size_of::<String>())
            + (MAX_PARAMETERS + 1) * allocation_charge(MAX_COMMAND_BYTES);
        assert_eq!(conservative_charge, 98_304);
        assert!(conservative_charge < HARD_PARSED_ARENA_BYTES);
        let conservative_requested_backing = MAX_CLIENT_TAG_DATA_BYTES
            + maximum_tag_count * PARSED_TAG_DESCRIPTOR_BYTES
            + MAX_PARAMETERS * size_of::<String>()
            + MAX_COMMAND_BYTES;
        assert_eq!(conservative_requested_backing, 21_340);
        assert!(conservative_requested_backing < 32 * 1_024);
        Ok(())
    }

    #[test]
    fn sixteenth_middle_parameter_is_rejected_before_growth() -> Result<(), Box<dyn Error>> {
        let line = "A x x x x x x x x x x x x x x x x";
        assert_eq!(
            parse_message(FramedLine::new(line)?).err(),
            Some(MessageParseError::TooManyParameters)
        );
        Ok(())
    }

    #[test]
    fn parser_covers_empty_prefix_command_and_parameter_shapes() -> Result<(), Box<dyn Error>> {
        assert_eq!(parse_message(FramedLine::new("   ")?)?, None);
        assert_eq!(
            parse_message(FramedLine::new("@label")?).err(),
            Some(MessageParseError::UnterminatedTags)
        );
        assert_eq!(
            parse_message(FramedLine::new(":server PING")?).err(),
            Some(MessageParseError::ClientPrefix)
        );
        for line in ["@label=one    ", "123", "P1NG"] {
            assert_eq!(
                parse_message(FramedLine::new(line)?).err(),
                Some(MessageParseError::InvalidCommand),
                "{line:?}"
            );
        }

        let mut middle = parse_message(FramedLine::new("PING token")?)?
            .ok_or(MessageParseError::InvalidCommand)?;
        assert_eq!(middle.take_single_parameter().as_deref(), Some("token"));
        assert_eq!(middle.take_single_parameter(), None);

        let mut trailing =
            parse_message(FramedLine::new("PING :")?)?.ok_or(MessageParseError::InvalidCommand)?;
        assert_eq!(trailing.take_single_parameter().as_deref(), Some(""));

        let mut multiple = parse_message(FramedLine::new("CMD one two")?)?
            .ok_or(MessageParseError::InvalidCommand)?;
        assert_eq!(multiple.take_single_parameter(), None);
        Ok(())
    }

    #[test]
    fn parameter_validation_rejects_each_forbidden_middle_byte() {
        for parameters in ["\0", "\r", "\n"] {
            assert_eq!(
                super::validate_parameters(parameters),
                Err(MessageParseError::InvalidMiddleParameter),
                "{parameters:?}"
            );
        }
        assert_eq!(super::validate_parameters(":"), Ok(0));
        assert_eq!(allocation_charge(0), 0);
    }

    fn requested_allocation_charge(message: &ParsedMessage) -> usize {
        let (tag_text, tag_ranges) = message.tags.actual_backing_capacities();
        let parameter_text = message
            .middle
            .iter()
            .map(|parameter| allocation_charge(parameter.capacity()))
            .sum::<usize>();
        allocation_charge(tag_text)
            + allocation_charge(tag_ranges)
            + allocation_charge(message.command.capacity())
            + allocation_charge(message.middle.capacity() * size_of::<String>())
            + parameter_text
            + message
                .trailing
                .as_ref()
                .map_or(0, |trailing| allocation_charge(trailing.capacity()))
    }

    fn allocation_charge(capacity: usize) -> usize {
        if capacity == 0 {
            return 0;
        }
        let charged_capacity = capacity + ALLOCATION_BOOKKEEPING_BYTES;
        let pages = charged_capacity.div_ceil(ALLOCATION_PAGE_BYTES);
        pages * ALLOCATION_PAGE_BYTES
    }

    fn maximal_parameter_section() -> String {
        let mut command = String::from("A");
        for _ in 0..MAX_PARAMETERS - 1 {
            command.push_str(" x");
        }
        command.push_str(" :");
        command.push_str(&"y".repeat(MAX_COMMAND_BYTES - command.len()));
        command
    }

    fn maximal_two_byte_key_section() -> Result<String, MessageParseError> {
        const TAG_COUNT: usize = 1_365;

        let mut raw = String::new();
        raw.try_reserve_exact(MAX_CLIENT_TAG_DATA_BYTES)
            .map_err(|_| MessageParseError::AllocationFailed)?;
        for index in 0..TAG_COUNT {
            if index != 0 {
                raw.push(';');
            }
            let high = index / KEY_ALPHABET.len();
            let low = index % KEY_ALPHABET.len();
            let first = KEY_ALPHABET
                .get(high)
                .copied()
                .ok_or(MessageParseError::AllocationFailed)?;
            let second = KEY_ALPHABET
                .get(low)
                .copied()
                .ok_or(MessageParseError::AllocationFailed)?;
            raw.push(char::from(first));
            raw.push(char::from(second));
        }
        Ok(raw)
    }
}
