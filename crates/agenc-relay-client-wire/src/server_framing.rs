//! Server-to-client CRLF framing: the line bounds a client applies to the
//! stream a server sends (Architecture 9.1).
//!
//! [`StreamFramer`](crate::StreamFramer) and [`FramedLine`](crate::FramedLine)
//! keep their meaning: they frame what a client sends. A server's line may
//! carry server-added tags beside relayed client-only tags, so a client
//! framing what it receives applies [`WireDirection::ServerToClient`]: the
//! same 8,703-byte physical line, a tag section of at most 8,191 bytes with
//! its `@` and space, and no empty line. Each side's 4,094-byte share of the
//! section depends on the keys, so [`parse_server_tags`](crate::parse_server_tags)
//! checks it.

use std::error::Error;
use std::fmt;

use crate::{MAX_CLIENT_TAG_DATA_BYTES, MAX_COMBINED_TAG_SECTION_BYTES, MAX_PHYSICAL_LINE_BYTES};

/// The CRLF that ends a stream line.
const CRLF_BYTES: usize = 2;
/// The `@` and the space around a tag section's data.
const TAG_SECTION_FRAME_BYTES: usize = 2;
/// Line content before the CRLF, in either direction.
const LINE_CONTENT_BYTES: usize = MAX_PHYSICAL_LINE_BYTES - CRLF_BYTES;
/// Tag data of a server line, between its `@` and its space.
pub(crate) const SERVER_TAG_SECTION_DATA_BYTES: usize =
    MAX_COMBINED_TAG_SECTION_BYTES - TAG_SECTION_FRAME_BYTES;

/// Which party sent a line; the tag allowance and the empty-line rule differ
/// by direction (Architecture 9.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireDirection {
    /// A client's line to a server, framed by
    /// [`StreamFramer`](crate::StreamFramer) and
    /// [`FramedLine`](crate::FramedLine): at most 4,094 bytes of client tag
    /// data, and an empty line is skipped.
    ClientToServer,
    /// A server's line to a client, framed by [`ServerStreamFramer`] and
    /// [`ServerFramedLine`]: a tag section of at most 8,191 bytes with its `@`
    /// and space, and an empty line is an error.
    ServerToClient,
}

impl WireDirection {
    /// Bytes of line content before the CRLF: 8,701 in either direction.
    #[must_use]
    pub const fn max_content_bytes(self) -> usize {
        match self {
            Self::ClientToServer | Self::ServerToClient => LINE_CONTENT_BYTES,
        }
    }

    /// Bytes of tag data between the `@` and the space that ends the section.
    #[must_use]
    pub const fn max_tag_data_bytes(self) -> usize {
        match self {
            Self::ClientToServer => MAX_CLIENT_TAG_DATA_BYTES,
            Self::ServerToClient => SERVER_TAG_SECTION_DATA_BYTES,
        }
    }

    /// Whether an empty line is a framing error rather than skipped.
    #[must_use]
    pub const fn rejects_empty_lines(self) -> bool {
        matches!(self, Self::ServerToClient)
    }
}

/// Closed failures at the server-to-client stream boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerFramingError {
    /// A line contained LF without a preceding CR.
    BareLineFeed,
    /// A CR was not immediately followed by LF.
    BareCarriageReturn,
    /// A line contained an embedded NUL byte.
    EmbeddedNul,
    /// A complete line was not valid UTF-8.
    InvalidUtf8,
    /// A line exceeded 8,701 content bytes before its CRLF.
    LineTooLong,
    /// A tag section exceeded 8,191 bytes with its `@` and space.
    TagSectionTooLong,
    /// A line was empty; a server never sends one.
    EmptyLine,
    /// The stream ended in the middle of a line.
    UnexpectedEof,
    /// A caller-owned framing deadline expired with a partial line buffered.
    TimedOut,
    /// The bounded framing buffer could not reserve its fixed capacity.
    AllocationFailed,
}

impl fmt::Display for ServerFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BareLineFeed => "server stream contains a bare line feed",
            Self::BareCarriageReturn => "server stream contains a bare carriage return",
            Self::EmbeddedNul => "server stream contains an embedded NUL",
            Self::InvalidUtf8 => "server line is not valid UTF-8",
            Self::LineTooLong => "server line exceeds its physical limit",
            Self::TagSectionTooLong => "server tag section exceeds its combined budget",
            Self::EmptyLine => "server stream contains an empty line",
            Self::UnexpectedEof => "server stream ended with a partial line",
            Self::TimedOut => "server stream framing deadline expired",
            Self::AllocationFailed => "server stream buffer allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ServerFramingError {}

/// Borrowed proof that one UTF-8 server line passed the server-to-client line
/// bounds.
///
/// The text excludes the CRLF. Its private field keeps
/// [`parse_server_message`](crate::parse_server_message) from reading a line
/// that skipped these checks.
#[derive(Clone, Copy)]
#[must_use]
pub struct ServerFramedLine<'a> {
    line: &'a str,
}

impl<'a> ServerFramedLine<'a> {
    /// Validates one already delimited server line, given without its CRLF.
    pub fn new(line: &'a str) -> Result<Self, ServerFramingError> {
        let bytes = line.as_bytes();
        if bytes.contains(&0) {
            return Err(ServerFramingError::EmbeddedNul);
        }
        if bytes.contains(&b'\r') {
            return Err(ServerFramingError::BareCarriageReturn);
        }
        if bytes.contains(&b'\n') {
            return Err(ServerFramingError::BareLineFeed);
        }
        check_server_line(bytes)?;
        Ok(Self { line })
    }

    /// Borrows the validated line without its CRLF.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.line
    }
}

impl fmt::Debug for ServerFramedLine<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerFramedLine")
            .field("bytes", &self.line.len())
            .finish()
    }
}

/// The bounds of one complete server line without its CRLF: not empty, a tag
/// section of at most 8,191 bytes with its `@` and space, and at most 8,701
/// bytes. The tag section is checked first because a stream reaches its
/// limit first.
fn check_server_line(line: &[u8]) -> Result<(), ServerFramingError> {
    if line.is_empty() {
        return Err(ServerFramingError::EmptyLine);
    }
    if line.first() == Some(&b'@') {
        let section_end = line
            .iter()
            .position(|byte| *byte == b' ')
            .unwrap_or(line.len());
        if section_end.saturating_sub(1) > SERVER_TAG_SECTION_DATA_BYTES {
            return Err(ServerFramingError::TagSectionTooLong);
        }
    }
    if line.len() > LINE_CONTENT_BYTES {
        return Err(ServerFramingError::LineTooLong);
    }
    Ok(())
}

/// Incremental server-to-client CRLF framer with one fixed allocation.
///
/// It follows [`StreamFramer`](crate::StreamFramer)'s design: one buffer
/// reserved at construction and never grown, CR, LF and NUL checked byte by
/// byte, each limit enforced as soon as it is exceeded rather than when the
/// line ends, and buffered bytes wiped whenever they are discarded. It frames
/// what a server sends: [`WireDirection::ServerToClient`] bounds, an empty
/// line is an error, and the first failure is final, because a client cannot
/// resynchronize a server stream it failed to frame.
pub struct ServerStreamFramer {
    buffer: Vec<u8>,
    tag_section_open: bool,
    pending_carriage_return: bool,
    failure: Option<ServerFramingError>,
}

impl ServerStreamFramer {
    /// Allocates the one fixed-capacity framing buffer.
    pub fn new() -> Result<Self, ServerFramingError> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(LINE_CONTENT_BYTES)
            .map_err(|_| ServerFramingError::AllocationFailed)?;
        Ok(Self {
            buffer,
            tag_section_open: false,
            pending_carriage_return: false,
            failure: None,
        })
    }

    /// Bytes retained for the unfinished line, including a trailing CR.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len() + usize::from(self.pending_carriage_return)
    }

    /// The failure that ended this stream, if any.
    #[must_use]
    pub const fn failure(&self) -> Option<ServerFramingError> {
        self.failure
    }

    /// Feeds arbitrary stream fragments and emits complete borrowed lines.
    ///
    /// The callback must consume each line before returning. Returns the
    /// number of lines emitted. After a failure every call returns that
    /// failure again.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        mut emit: impl FnMut(ServerFramedLine<'_>),
    ) -> Result<usize, ServerFramingError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        let mut lines = 0_usize;
        for byte in bytes {
            if self.accept_byte(*byte, &mut emit)? {
                lines = lines.saturating_add(1);
            }
        }
        Ok(lines)
    }

    /// Ends the stream: a partial line is [`ServerFramingError::UnexpectedEof`].
    pub fn finish(&mut self) -> Result<(), ServerFramingError> {
        self.end_with(ServerFramingError::UnexpectedEof)
    }

    /// Applies a caller-owned deadline: a partial line is
    /// [`ServerFramingError::TimedOut`].
    pub fn timeout(&mut self) -> Result<(), ServerFramingError> {
        self.end_with(ServerFramingError::TimedOut)
    }

    fn end_with(&mut self, error: ServerFramingError) -> Result<(), ServerFramingError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.buffer.is_empty() && !self.pending_carriage_return {
            return Ok(());
        }
        self.fail(error)
    }

    /// Takes one byte; returns whether it completed and emitted a line.
    fn accept_byte(
        &mut self,
        byte: u8,
        emit: &mut impl FnMut(ServerFramedLine<'_>),
    ) -> Result<bool, ServerFramingError> {
        if self.pending_carriage_return {
            if byte != b'\n' {
                return self.fail(ServerFramingError::BareCarriageReturn);
            }
            self.pending_carriage_return = false;
            return self.emit_line(emit).map(|()| true);
        }
        match byte {
            0 => self.fail(ServerFramingError::EmbeddedNul),
            b'\n' => self.fail(ServerFramingError::BareLineFeed),
            b'\r' => {
                self.pending_carriage_return = true;
                Ok(false)
            }
            _ => self.push_content(byte).map(|()| false),
        }
    }

    fn push_content(&mut self, byte: u8) -> Result<(), ServerFramingError> {
        if self.buffer.is_empty() {
            self.tag_section_open = byte == b'@';
        } else if self.tag_section_open {
            if byte == b' ' {
                self.tag_section_open = false;
            } else if self.buffer.len() > SERVER_TAG_SECTION_DATA_BYTES {
                return self.fail(ServerFramingError::TagSectionTooLong);
            }
        }
        if self.buffer.len() >= LINE_CONTENT_BYTES {
            return self.fail(ServerFramingError::LineTooLong);
        }
        self.buffer.push(byte);
        Ok(())
    }

    fn emit_line(
        &mut self,
        emit: &mut impl FnMut(ServerFramedLine<'_>),
    ) -> Result<(), ServerFramingError> {
        if let Err(error) = check_server_line(&self.buffer) {
            return self.fail(error);
        }
        let Ok(line) = std::str::from_utf8(&self.buffer) else {
            return self.fail(ServerFramingError::InvalidUtf8);
        };
        emit(ServerFramedLine { line });
        self.clear();
        Ok(())
    }

    fn fail<T>(&mut self, error: ServerFramingError) -> Result<T, ServerFramingError> {
        self.clear();
        self.failure = Some(error);
        Err(error)
    }

    fn clear(&mut self) {
        self.buffer.fill(0);
        self.buffer.clear();
        self.tag_section_open = false;
        self.pending_carriage_return = false;
    }
}

impl fmt::Debug for ServerStreamFramer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerStreamFramer")
            .field("buffered_bytes", &self.buffered_bytes())
            .field("failure", &self.failure)
            .finish()
    }
}

impl Drop for ServerStreamFramer {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerFramingError, ServerStreamFramer};

    #[test]
    fn every_discriminant_renders_a_distinct_message() {
        let variants = [
            ServerFramingError::BareLineFeed,
            ServerFramingError::BareCarriageReturn,
            ServerFramingError::EmbeddedNul,
            ServerFramingError::InvalidUtf8,
            ServerFramingError::LineTooLong,
            ServerFramingError::TagSectionTooLong,
            ServerFramingError::EmptyLine,
            ServerFramingError::UnexpectedEof,
            ServerFramingError::TimedOut,
            ServerFramingError::AllocationFailed,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }

    #[test]
    fn a_failure_wipes_the_buffer_and_is_final() -> Result<(), ServerFramingError> {
        let mut framer = ServerStreamFramer::new()?;
        assert_eq!(framer.feed(b"PING :partial", |_| {})?, 0);
        assert_eq!(framer.buffered_bytes(), 13);
        assert_eq!(
            framer.feed(b"\0", |_| {}),
            Err(ServerFramingError::EmbeddedNul)
        );
        assert_eq!(framer.buffered_bytes(), 0);
        assert_eq!(framer.failure(), Some(ServerFramingError::EmbeddedNul));
        assert_eq!(
            framer.feed(b"PING :x\r\n", |_| {}),
            Err(ServerFramingError::EmbeddedNul)
        );
        assert_eq!(framer.finish(), Err(ServerFramingError::EmbeddedNul));
        assert_eq!(framer.timeout(), Err(ServerFramingError::EmbeddedNul));
        Ok(())
    }
}
