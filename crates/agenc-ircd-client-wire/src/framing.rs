//! Incremental CRLF stream framing over one reusable bounded buffer.

use std::error::Error;
use std::fmt;

use crate::{MAX_CLIENT_TAG_DATA_BYTES, MAX_COMBINED_TAG_SECTION_BYTES, MAX_COMMAND_BYTES};

/// Result counters from one stream-framer feed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameProgress {
    /// Complete non-empty protocol lines emitted to the callback.
    pub messages: usize,
    /// Empty lines ignored while still consuming caller-owned flood budget.
    pub empty_lines: usize,
}

/// Closed failures at the raw client-stream boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramingError {
    /// A line contained LF without a preceding CR.
    BareLineFeed,
    /// A CR was not immediately followed by LF.
    BareCarriageReturn,
    /// A line contained an embedded NUL byte.
    EmbeddedNul,
    /// A complete message was not valid UTF-8.
    InvalidUtf8,
    /// A line exceeded its applicable physical or command limit.
    LineTooLong,
    /// Client-provided tag data exceeded its side budget.
    ClientTagsTooLong,
    /// The connection ended in the middle of a protocol line.
    UnexpectedEof,
    /// A caller-owned framing deadline expired with a partial line buffered.
    TimedOut,
    /// The bounded framing buffer could not reserve its fixed capacity.
    AllocationFailed,
}

impl fmt::Display for FramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BareLineFeed => "client stream contains a bare line feed",
            Self::BareCarriageReturn => "client stream contains a bare carriage return",
            Self::EmbeddedNul => "client stream contains an embedded NUL",
            Self::InvalidUtf8 => "client message is not valid UTF-8",
            Self::LineTooLong => "client message exceeds its physical or command limit",
            Self::ClientTagsTooLong => "client tag data exceeds its side budget",
            Self::UnexpectedEof => "client stream ended with a partial message",
            Self::TimedOut => "client stream framing deadline expired",
            Self::AllocationFailed => "client stream buffer allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for FramingError {}

/// Borrowed proof that one UTF-8 client line passed the physical wire bounds.
///
/// The value excludes the transport CRLF. Its private field prevents syntax
/// parsing from bypassing the framing checks.
#[must_use]
pub struct FramedLine<'a> {
    line: &'a str,
}

impl<'a> FramedLine<'a> {
    /// Validates one WebSocket or otherwise already delimited client message.
    pub fn new(line: &'a str) -> Result<Self, FramingError> {
        let bytes = line.as_bytes();
        if bytes.contains(&0) {
            return Err(FramingError::EmbeddedNul);
        }
        if bytes.contains(&b'\r') {
            return Err(FramingError::BareCarriageReturn);
        }
        if bytes.contains(&b'\n') {
            return Err(FramingError::BareLineFeed);
        }
        validate_line_budgets(bytes)?;
        Ok(Self { line })
    }

    /// Borrows the validated line without its transport delimiter.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.line
    }
}

/// Incremental TCP/onion IRC framer with a single reusable allocation.
pub struct StreamFramer {
    buffer: Vec<u8>,
    tagged_command_start: Option<usize>,
    pending_carriage_return: bool,
}

impl StreamFramer {
    /// Allocates the one fixed-capacity framing buffer.
    pub fn new() -> Result<Self, FramingError> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(MAX_CLIENT_STREAM_CONTENT_CAPACITY)
            .map_err(|_| FramingError::AllocationFailed)?;
        Ok(Self {
            buffer,
            tagged_command_start: None,
            pending_carriage_return: false,
        })
    }

    /// Feeds arbitrary stream fragments and emits complete borrowed messages.
    ///
    /// The callback must consume the line before returning. No peer-controlled
    /// output collection is accumulated by the framer.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        mut emit: impl FnMut(FramedLine<'_>),
    ) -> Result<FrameProgress, FramingError> {
        let mut progress = FrameProgress::default();
        for byte in bytes {
            self.accept_byte(*byte, &mut emit, &mut progress)?;
        }
        Ok(progress)
    }

    /// Validates stream closure and clears any partial sensitive input.
    pub fn finish(&mut self) -> Result<(), FramingError> {
        if self.buffer.is_empty() && !self.pending_carriage_return {
            return Ok(());
        }
        self.clear();
        Err(FramingError::UnexpectedEof)
    }

    /// Applies a caller-owned deadline to a partial message.
    pub fn timeout(&mut self) -> Result<(), FramingError> {
        if self.buffer.is_empty() && !self.pending_carriage_return {
            return Ok(());
        }
        self.clear();
        Err(FramingError::TimedOut)
    }

    fn accept_byte(
        &mut self,
        byte: u8,
        emit: &mut impl FnMut(FramedLine<'_>),
        progress: &mut FrameProgress,
    ) -> Result<(), FramingError> {
        if self.pending_carriage_return {
            if byte != b'\n' {
                self.clear();
                return Err(FramingError::BareCarriageReturn);
            }
            self.pending_carriage_return = false;
            return self.emit_line(emit, progress);
        }
        match byte {
            0 => self.fail(FramingError::EmbeddedNul),
            b'\n' => self.fail(FramingError::BareLineFeed),
            b'\r' => {
                self.pending_carriage_return = true;
                Ok(())
            }
            _ => self.push_content(byte),
        }
    }

    fn push_content(&mut self, byte: u8) -> Result<(), FramingError> {
        if self.buffer.is_empty() {
            self.buffer.push(byte);
            return Ok(());
        }

        if self.buffer.first().copied() != Some(b'@') {
            if self.buffer.len() >= MAX_COMMAND_BYTES {
                return self.fail(FramingError::LineTooLong);
            }
        } else if let Some(command_start) = self.tagged_command_start {
            if self.buffer.len().saturating_sub(command_start) >= MAX_COMMAND_BYTES {
                return self.fail(FramingError::LineTooLong);
            }
        } else if byte == b' ' {
            self.tagged_command_start = Some(self.buffer.len().saturating_add(1));
        } else if self.buffer.len().saturating_sub(1) >= MAX_CLIENT_TAG_DATA_BYTES {
            return self.fail(FramingError::ClientTagsTooLong);
        }

        if self.buffer.len() >= MAX_CLIENT_STREAM_CONTENT_CAPACITY {
            return self.fail(FramingError::LineTooLong);
        }
        self.buffer.push(byte);
        Ok(())
    }

    fn emit_line(
        &mut self,
        emit: &mut impl FnMut(FramedLine<'_>),
        progress: &mut FrameProgress,
    ) -> Result<(), FramingError> {
        if self.buffer.is_empty() {
            progress.empty_lines = progress.empty_lines.saturating_add(1);
            return Ok(());
        }
        if let Err(error) = validate_line_budgets(&self.buffer) {
            return self.fail(error);
        }
        let Ok(line) = std::str::from_utf8(&self.buffer) else {
            return self.fail(FramingError::InvalidUtf8);
        };
        emit(FramedLine { line });
        progress.messages = progress.messages.saturating_add(1);
        self.clear();
        Ok(())
    }

    fn fail(&mut self, error: FramingError) -> Result<(), FramingError> {
        self.clear();
        Err(error)
    }

    fn clear(&mut self) {
        self.buffer.fill(0);
        self.buffer.clear();
        self.tagged_command_start = None;
        self.pending_carriage_return = false;
    }
}

const MAX_CLIENT_STREAM_CONTENT_CAPACITY: usize =
    1 + MAX_CLIENT_TAG_DATA_BYTES + 1 + MAX_COMMAND_BYTES;

fn validate_line_budgets(line: &[u8]) -> Result<(), FramingError> {
    if line.first().copied() != Some(b'@') {
        return if line.len() <= MAX_COMMAND_BYTES {
            Ok(())
        } else {
            Err(FramingError::LineTooLong)
        };
    }
    let Some(space) = line.iter().position(|byte| *byte == b' ') else {
        let tag_data = line.len().saturating_sub(1);
        return if tag_data <= MAX_CLIENT_TAG_DATA_BYTES {
            Ok(())
        } else {
            Err(FramingError::ClientTagsTooLong)
        };
    };
    let tag_data = space.saturating_sub(1);
    if tag_data > MAX_CLIENT_TAG_DATA_BYTES {
        return Err(FramingError::ClientTagsTooLong);
    }
    if space.saturating_add(1) > MAX_COMBINED_TAG_SECTION_BYTES {
        return Err(FramingError::LineTooLong);
    }
    let command_bytes = line.len().saturating_sub(space.saturating_add(1));
    if command_bytes > MAX_COMMAND_BYTES {
        return Err(FramingError::LineTooLong);
    }
    Ok(())
}

impl Drop for StreamFramer {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{FramedLine, FramingError, StreamFramer, validate_line_budgets};
    use crate::{MAX_CLIENT_TAG_DATA_BYTES, MAX_COMMAND_BYTES};

    #[test]
    fn delimited_lines_reject_each_embedded_stream_control() -> Result<(), FramingError> {
        assert_eq!(
            FramedLine::new("A\0B").err(),
            Some(FramingError::EmbeddedNul)
        );
        assert_eq!(
            FramedLine::new("A\rB").err(),
            Some(FramingError::BareCarriageReturn)
        );
        assert_eq!(
            FramedLine::new("A\nB").err(),
            Some(FramingError::BareLineFeed)
        );
        let line = FramedLine::new("PING")?;
        assert_eq!(line.as_str(), "PING");
        Ok(())
    }

    #[test]
    fn raw_budget_helper_checks_exact_and_maximum_plus_one() {
        assert_eq!(
            validate_line_budgets(&vec![b'x'; MAX_COMMAND_BYTES]),
            Ok(())
        );
        assert_eq!(
            validate_line_budgets(&vec![b'x'; MAX_COMMAND_BYTES + 1]),
            Err(FramingError::LineTooLong)
        );

        let exact_tags = format!("@{}", "a".repeat(MAX_CLIENT_TAG_DATA_BYTES));
        assert_eq!(validate_line_budgets(exact_tags.as_bytes()), Ok(()));
        let oversized_tags = format!("@{}", "a".repeat(MAX_CLIENT_TAG_DATA_BYTES + 1));
        assert_eq!(
            validate_line_budgets(oversized_tags.as_bytes()),
            Err(FramingError::ClientTagsTooLong)
        );

        let tagged_command = format!("@a {}", "x".repeat(MAX_COMMAND_BYTES + 1));
        assert_eq!(
            validate_line_budgets(tagged_command.as_bytes()),
            Err(FramingError::LineTooLong)
        );
    }

    #[test]
    fn stream_finish_and_timeout_are_idempotent_after_clearing() -> Result<(), FramingError> {
        let mut framer = StreamFramer::new()?;
        assert_eq!(framer.finish(), Ok(()));
        assert_eq!(framer.timeout(), Ok(()));
        framer.feed(b"partial", |_| {})?;
        assert_eq!(framer.finish(), Err(FramingError::UnexpectedEof));
        assert_eq!(framer.finish(), Ok(()));
        framer.feed(b"\r", |_| {})?;
        assert_eq!(framer.timeout(), Err(FramingError::TimedOut));
        assert_eq!(framer.timeout(), Ok(()));
        Ok(())
    }
}
