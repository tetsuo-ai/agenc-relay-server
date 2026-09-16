//! Reader delivery through its admitted queue or an explicit in-process fixture inbox.

#![forbid(unsafe_code)]

use std::time::Duration;

use crate::state_core::client_input::{ClientInputPort, InputRefusal};
use crate::state_core::inbox::StateCoreMessage;
use tokio::sync::mpsc;

/// First pause after the memory budget refused input overflow storage.
const INPUT_MEMORY_RETRY_FIRST: Duration = Duration::from_millis(5);
/// Longest pause between input overflow retries; the reader's stall budget
/// bounds the whole wait.
const INPUT_MEMORY_RETRY_MAX: Duration = Duration::from_millis(250);

pub(crate) enum ReaderInbox {
    Shared(mpsc::Sender<StateCoreMessage>),
    Connection(ClientInputPort),
}

impl From<mpsc::Sender<StateCoreMessage>> for ReaderInbox {
    fn from(sender: mpsc::Sender<StateCoreMessage>) -> Self {
        Self::Shared(sender)
    }
}

impl From<ClientInputPort> for ReaderInbox {
    fn from(port: ClientInputPort) -> Self {
        Self::Connection(port)
    }
}

impl ReaderInbox {
    /// Delivers one line. When input overflow storage cannot be charged the
    /// reader stays paused and retries, so the caller's stall budget decides
    /// when a starved connection closes (spec 21.3).
    pub(crate) async fn send(&self, message: StateCoreMessage) -> Result<(), ()> {
        match self {
            Self::Shared(sender) => sender.send(message).await.map_err(|_| ()),
            Self::Connection(port) => publish_with_retry(port, message).await,
        }
    }

    pub(crate) async fn closed(&self) {
        match self {
            Self::Shared(sender) => sender.closed().await,
            Self::Connection(port) => port.closed().await,
        }
    }
}

/// Publishes one line to its connection queue, pausing while the memory
/// budget refuses the queue's overflow storage and returning the line to the
/// next attempt untouched.
async fn publish_with_retry(port: &ClientInputPort, message: StateCoreMessage) -> Result<(), ()> {
    let mut message = message;
    let mut pause = INPUT_MEMORY_RETRY_FIRST;
    loop {
        message = match port.send(message) {
            Ok(()) => return Ok(()),
            Err(InputRefusal::Closed) => return Err(()),
            Err(InputRefusal::MemoryExhausted(returned)) => returned,
        };
        tokio::time::sleep(pause).await;
        pause = pause.saturating_mul(2).min(INPUT_MEMORY_RETRY_MAX);
    }
}
