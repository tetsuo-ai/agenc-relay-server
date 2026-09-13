//! Reader delivery through its admitted queue or an explicit in-process fixture inbox.

#![forbid(unsafe_code)]

use crate::state_core::{client_input::ClientInputPort, inbox::StateCoreMessage};
use tokio::sync::mpsc;

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
    pub(crate) async fn send(&self, message: StateCoreMessage) -> Result<(), ()> {
        match self {
            Self::Shared(sender) => sender.send(message).await.map_err(|_| ()),
            Self::Connection(port) => port.send(message).map_err(|_| ()),
        }
    }

    pub(crate) async fn closed(&self) {
        match self {
            Self::Shared(sender) => sender.closed().await,
            Self::Connection(port) => port.closed().await,
        }
    }
}
