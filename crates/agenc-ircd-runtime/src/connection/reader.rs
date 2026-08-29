//! The reader task of one admitted connection (spec 21.3, line 4079; spec
//! 9.1, lines 574-608).
//!
//! The reader frames the transport bytes with the client-wire
//! `StreamFramer`, parses each complete line, and forwards it to StateCore.
//! At most `requests_per_connection` parsed lines and `parsed_arena_bytes`
//! of their wire bytes wait between the transport and the inbox; when the
//! inbox cannot take them the reader stops reading the socket, and after 30
//! seconds of stall it closes the connection.

use std::collections::VecDeque;
use std::time::Duration;

use agenc_ircd_client_wire::{FramedLine, MAX_PHYSICAL_LINE_BYTES, StreamFramer, parse_message};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::mpsc;

use super::sink::ConnectionGeneration;
use crate::RuntimeError;
use crate::cancel::CancellationToken;
use crate::state_core::inbox::{
    CloseReason, MAX_PARSED_ARENA_BYTES, MAX_REQUESTS_PER_CONNECTION, StateCoreMessage,
};

/// Default outstanding requests per connection (spec line 2657).
pub const DEFAULT_REQUESTS_PER_CONNECTION: usize = 32;
/// Default parsed command arena per connection, 32 KiB (spec line 2672).
pub const DEFAULT_PARSED_ARENA_BYTES: usize = 32_768;
/// Time a paused reader waits for the inbox before closing (spec line 4079).
pub const READ_STALL_BUDGET: Duration = Duration::from_secs(30);
/// Bytes read from the transport per call: one complete physical line.
pub const READ_CHUNK_BYTES: usize = MAX_PHYSICAL_LINE_BYTES;
/// The shortest non-empty protocol line: one byte plus CRLF, so feeding
/// `n * 3` bytes can produce at most `n` messages.
const MIN_LINE_BYTES: usize = 3;

/// Validated per-connection reader ceilings (Appendix C.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderLimits {
    requests: usize,
    arena_bytes: usize,
}

impl ReaderLimits {
    /// The default reader shape.
    pub const DEFAULT: Self = Self {
        requests: DEFAULT_REQUESTS_PER_CONNECTION,
        arena_bytes: DEFAULT_PARSED_ARENA_BYTES,
    };

    /// Validates `1..=128` requests and an arena of at least one physical
    /// line and at most 128 KiB.
    pub const fn new(requests: usize, arena_bytes: usize) -> Result<Self, RuntimeError> {
        if requests == 0
            || requests > MAX_REQUESTS_PER_CONNECTION
            || arena_bytes < MAX_PHYSICAL_LINE_BYTES
            || arena_bytes > MAX_PARSED_ARENA_BYTES
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            requests,
            arena_bytes,
        })
    }

    /// Returns the outstanding-request ceiling.
    #[must_use]
    pub const fn requests(self) -> usize {
        self.requests
    }

    /// Returns the parsed arena ceiling in bytes.
    #[must_use]
    pub const fn arena_bytes(self) -> usize {
        self.arena_bytes
    }
}

struct Pending {
    messages: VecDeque<Box<agenc_ircd_client_wire::ParsedMessage>>,
    bytes: usize,
    rejected: bool,
}

impl Pending {
    fn accept(&mut self, line: FramedLine<'_>) {
        let wire_bytes = line.as_str().len();
        match parse_message(line) {
            Ok(Some(message)) => {
                self.messages.push_back(Box::new(message));
                self.bytes = self.bytes.saturating_add(wire_bytes);
            }
            Ok(None) => {}
            Err(_) => self.rejected = true,
        }
    }
}

/// Runs the reader until the transport, the inbox, or the token ends it.
pub async fn run_reader<R: AsyncRead + Unpin>(
    mut transport: R,
    generation: ConnectionGeneration,
    limits: ReaderLimits,
    inbox: mpsc::Sender<StateCoreMessage>,
    token: CancellationToken,
) -> CloseReason {
    let Ok(mut framer) = StreamFramer::new() else {
        return CloseReason::Overload;
    };
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut pending = Pending {
        messages: VecDeque::new(),
        bytes: 0,
        rejected: false,
    };
    loop {
        let read = tokio::select! {
            () = token.cancelled() => return CloseReason::Shutdown,
            read = transport.read(&mut buffer) => read,
        };
        let filled = match read {
            Ok(0) => {
                let _ = framer.finish();
                return CloseReason::TransportLoss;
            }
            Ok(filled) => filled,
            Err(_) => return CloseReason::TransportLoss,
        };
        let Some(bytes) = buffer.get(..filled) else {
            return CloseReason::TransportLoss;
        };
        if let Err(reason) = feed_and_forward(
            bytes,
            &mut framer,
            &mut pending,
            generation,
            limits,
            &inbox,
            &token,
        )
        .await
        {
            return reason;
        }
    }
}

/// Feeds one read buffer in slices sized so the pending set never exceeds
/// the request ceiling, forwarding after every slice.
async fn feed_and_forward(
    bytes: &[u8],
    framer: &mut StreamFramer,
    pending: &mut Pending,
    generation: ConnectionGeneration,
    limits: ReaderLimits,
    inbox: &mpsc::Sender<StateCoreMessage>,
    token: &CancellationToken,
) -> Result<(), CloseReason> {
    let mut offset = 0;
    while offset < bytes.len() {
        let slice_bytes = limits
            .requests
            .saturating_mul(MIN_LINE_BYTES)
            .min(limits.arena_bytes)
            .min(bytes.len() - offset);
        let end = offset.saturating_add(slice_bytes);
        let Some(slice) = bytes.get(offset..end) else {
            return Err(CloseReason::ProtocolError);
        };
        if framer.feed(slice, |line| pending.accept(line)).is_err() || pending.rejected {
            return Err(CloseReason::ProtocolError);
        }
        forward_pending(pending, generation, inbox, token).await?;
        offset = end;
    }
    Ok(())
}

/// Forwards every pending line; the socket is not read while this waits,
/// which is the pause of spec line 4079.
async fn forward_pending(
    pending: &mut Pending,
    generation: ConnectionGeneration,
    inbox: &mpsc::Sender<StateCoreMessage>,
    token: &CancellationToken,
) -> Result<(), CloseReason> {
    while let Some(message) = pending.messages.pop_front() {
        let line = StateCoreMessage::Line {
            generation,
            message,
        };
        let sent = tokio::select! {
            () = token.cancelled() => return Err(CloseReason::Shutdown),
            sent = tokio::time::timeout(READ_STALL_BUDGET, inbox.send(line)) => sent,
        };
        match sent {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(CloseReason::Shutdown),
            Err(_) => return Err(CloseReason::ReadStall),
        }
    }
    pending.bytes = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_limits_follow_the_hard_maxima() {
        assert_eq!(ReaderLimits::DEFAULT.requests(), 32);
        assert_eq!(ReaderLimits::DEFAULT.arena_bytes(), 32_768);
        assert_eq!(
            ReaderLimits::new(0, 32_768).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ReaderLimits::new(MAX_REQUESTS_PER_CONNECTION + 1, 32_768).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ReaderLimits::new(1, MAX_PHYSICAL_LINE_BYTES - 1).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ReaderLimits::new(1, MAX_PARSED_ARENA_BYTES + 1).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert!(ReaderLimits::new(MAX_REQUESTS_PER_CONNECTION, MAX_PARSED_ARENA_BYTES).is_ok());
        assert_eq!(READ_STALL_BUDGET, Duration::from_secs(30));
        assert_eq!(READ_CHUNK_BYTES, 8_703);
    }
}
