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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agenc_ircd_client_wire::{FramedLine, MAX_PHYSICAL_LINE_BYTES, StreamFramer, parse_message};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::mpsc;

use super::sink::ConnectionGeneration;
use crate::RuntimeError;
use crate::cancel::CancellationToken;
use crate::runtime_config::RuntimeConfigHandle;
use crate::state_core::inbox::{
    CloseReason, MAX_PARSED_ARENA_BYTES, MAX_REQUESTS_PER_CONNECTION, StateCoreMessage,
};
use crate::sync::Arc;

/// Default outstanding requests per connection (spec line 2657).
pub const DEFAULT_REQUESTS_PER_CONNECTION: usize = 32;
/// Default parsed command arena per connection, 32 KiB (spec line 2672).
pub const DEFAULT_PARSED_ARENA_BYTES: usize = 32_768;
/// Time a paused reader waits for the inbox before closing (spec line 4079).
pub const READ_STALL_BUDGET: Duration = Duration::from_secs(30);
/// Bytes read from the transport per call: one complete physical line.
pub const READ_CHUNK_BYTES: usize = MAX_PHYSICAL_LINE_BYTES;
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
    accepted_lines: Arc<AtomicU64>,
}

impl Pending {
    fn accept(&mut self, line: FramedLine<'_>, limits: ReaderLimits) {
        if self.rejected || line.as_str().trim_start_matches(' ').is_empty() {
            return;
        }
        let wire_bytes = line.as_str().len();
        let Some(next_bytes) = self.bytes.checked_add(wire_bytes) else {
            self.rejected = true;
            return;
        };
        if self.messages.len() >= limits.requests || next_bytes > limits.arena_bytes {
            self.rejected = true;
            return;
        }
        match parse_message(line) {
            Ok(Some(message)) => {
                self.messages.push_back(Box::new(message));
                self.bytes = next_bytes;
            }
            Ok(None) => {}
            Err(_) => self.rejected = true,
        }
    }
}

/// Runs the reader until the transport, the inbox, or the token ends it.
pub async fn run_reader<R: AsyncRead + Unpin>(
    transport: R,
    generation: ConnectionGeneration,
    limits: ReaderLimits,
    inbox: mpsc::Sender<StateCoreMessage>,
    token: CancellationToken,
) -> CloseReason {
    run_reader_sequenced(
        transport,
        generation,
        limits,
        None,
        inbox,
        token,
        Arc::new(AtomicU64::new(0)),
    )
    .await
}

pub(crate) async fn run_reader_sequenced<R: AsyncRead + Unpin>(
    mut transport: R,
    generation: ConnectionGeneration,
    limits: ReaderLimits,
    runtime_config: Option<RuntimeConfigHandle>,
    inbox: mpsc::Sender<StateCoreMessage>,
    token: CancellationToken,
    accepted_lines: Arc<AtomicU64>,
) -> CloseReason {
    let Ok(mut framer) = StreamFramer::new() else {
        return CloseReason::Overload;
    };
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut pending = Pending {
        messages: VecDeque::new(),
        bytes: 0,
        rejected: false,
        accepted_lines,
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
        let limits = runtime_config
            .as_ref()
            .map_or(limits, |handle| handle.load().connection_limits().reader);
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

/// Forwards each completed line before framing another. A line retained from
/// an earlier read can occupy the entire arena when its final bytes arrive.
async fn feed_and_forward(
    bytes: &[u8],
    framer: &mut StreamFramer,
    pending: &mut Pending,
    generation: ConnectionGeneration,
    limits: ReaderLimits,
    inbox: &mpsc::Sender<StateCoreMessage>,
    token: &CancellationToken,
) -> Result<(), CloseReason> {
    for slice in bytes.split_inclusive(|byte| *byte == b'\n') {
        if framer
            .feed(slice, |line| pending.accept(line, limits))
            .is_err()
            || pending.rejected
        {
            return Err(CloseReason::ProtocolError);
        }
        forward_pending(pending, generation, inbox, token).await?;
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
        let sequence = pending
            .accepted_lines
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or(CloseReason::Overload)?;
        let line = StateCoreMessage::Line {
            generation,
            sequence,
            message,
        };
        let sent = tokio::select! {
            () = token.cancelled() => return Err(CloseReason::Shutdown),
            sent = tokio::time::timeout(READ_STALL_BUDGET, inbox.send(line)) => sent,
        };
        match sent {
            Ok(Ok(())) => pending.accepted_lines.store(sequence, Ordering::Release),
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

    fn pending() -> Pending {
        Pending {
            messages: VecDeque::new(),
            bytes: 0,
            rejected: false,
            accepted_lines: Arc::new(AtomicU64::new(0)),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn full_inbox_stalls_the_reader_without_accepting_following_lines()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, mut receiver) = mpsc::channel(1);
        let accepted = Arc::new(AtomicU64::new(0));
        let observed = Arc::clone(&accepted);
        let start = tokio::time::Instant::now();
        let task = tokio::spawn(run_reader_sequenced(
            &b"PING :one\r\nPING :two\r\nPING :three\r\n"[..],
            ConnectionGeneration::new(7),
            ReaderLimits::new(1, MAX_PHYSICAL_LINE_BYTES)?,
            None,
            sender,
            CancellationToken::root(),
            accepted,
        ));
        assert_eq!(task.await?, CloseReason::ReadStall);
        assert_eq!(tokio::time::Instant::now() - start, READ_STALL_BUDGET);
        assert_eq!(observed.load(Ordering::Relaxed), 1);
        let StateCoreMessage::Line {
            sequence, message, ..
        } = receiver.try_recv()?
        else {
            return Err("unexpected inbox message".into());
        };
        assert_eq!(sequence, 1);
        assert_eq!(message.trailing(), Some("one"));
        assert!(receiver.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn fragmented_maximum_line_drains_before_following_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = ReaderLimits::new(128, MAX_PHYSICAL_LINE_BYTES)?;
        let mut framer = StreamFramer::new()?;
        let mut pending = pending();
        let (sender, mut receiver) = mpsc::channel(128);
        let token = CancellationToken::root();
        let generation = ConnectionGeneration::new(7);
        let payload_bytes = MAX_PHYSICAL_LINE_BYTES - 8;
        let line = format!("PING :{}\r\n", "c".repeat(payload_bytes));
        assert_eq!(line.len(), MAX_PHYSICAL_LINE_BYTES);
        let split = line.len() - 1;
        feed_and_forward(
            line.get(..split).ok_or("split")?.as_bytes(),
            &mut framer,
            &mut pending,
            generation,
            limits,
            &sender,
            &token,
        )
        .await
        .map_err(|reason| format!("reader closed: {reason:?}"))?;
        assert!(receiver.try_recv().is_err());
        let tail = format!("\n{}", "PING :next\r\n".repeat(31));
        feed_and_forward(
            tail.as_bytes(),
            &mut framer,
            &mut pending,
            generation,
            limits,
            &sender,
            &token,
        )
        .await
        .map_err(|reason| format!("reader closed: {reason:?}"))?;
        for expected in 1..=32 {
            let StateCoreMessage::Line {
                sequence, message, ..
            } = receiver.try_recv()?
            else {
                return Err("unexpected inbox message".into());
            };
            assert_eq!(sequence, expected);
            assert_eq!(message.command(), "PING");
            assert_eq!(
                message.trailing().map(str::len),
                Some(if expected == 1 { payload_bytes } else { 4 })
            );
        }
        assert!(!pending.rejected);
        assert_eq!(pending.bytes, 0);
        assert!(pending.messages.is_empty());
        Ok(())
    }

    #[test]
    fn parsed_arena_refuses_a_line_before_exceeding_its_byte_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = ReaderLimits::new(128, MAX_PHYSICAL_LINE_BYTES)?;
        let mut pending = pending();
        let line = format!("PING :{}", "a".repeat(494));
        for _ in 0..17 {
            pending.accept(FramedLine::new(&line)?, limits);
        }
        assert_eq!(pending.bytes, 8_500);
        assert!(!pending.rejected);
        pending.accept(FramedLine::new("PING :aa")?, limits);
        let remaining = limits.arena_bytes() - pending.bytes;
        let exact = format!("PING :{}", "b".repeat(remaining - 6));
        pending.accept(FramedLine::new(&exact)?, limits);
        assert_eq!(pending.bytes, limits.arena_bytes());
        assert!(!pending.rejected);
        pending.accept(FramedLine::new("PING")?, limits);
        assert!(pending.rejected);
        assert_eq!(pending.bytes, limits.arena_bytes());
        assert_eq!(pending.messages.len(), 19);
        pending.accept(FramedLine::new("PONG")?, limits);
        assert_eq!(pending.messages.len(), 19);
        Ok(())
    }

    #[test]
    fn parsed_arena_refuses_the_first_request_above_the_count_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let limits = ReaderLimits::new(1, MAX_PHYSICAL_LINE_BYTES)?;
        let mut pending = pending();
        pending.accept(FramedLine::new("")?, limits);
        assert_eq!(pending.messages.len(), 0);
        pending.accept(FramedLine::new("PING")?, limits);
        assert!(!pending.rejected);
        pending.accept(FramedLine::new("PONG")?, limits);
        assert!(pending.rejected);
        assert_eq!(pending.messages.len(), 1);
        assert_eq!(pending.bytes, 4);
        Ok(())
    }

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
