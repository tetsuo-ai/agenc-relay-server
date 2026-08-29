//! The supervisor of one admitted connection (spec 21.2, lines 4064-4073).
//!
//! A connection supervisor exists only after the listener acquired both the
//! global and listener admission permits and the memory charges. It owns the
//! queue generation, spawns the reader and writer with child tokens, joins
//! both before releasing any permit, and reports the connection's open and
//! close to StateCore through the bounded inbox.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use super::queue::{ClosePolicy, QueueLimits, WriterQueue};
use super::reader::{ReaderLimits, run_reader};
use super::sink::{ClientSink, ConnectionGeneration};
use super::writer::run_writer;
use crate::budget::{MemoryPermit, MemoryPermitBatch};
use crate::cancel::CancellationToken;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::{CloseReason, SourceAddressKey, StateCoreMessage};
use crate::sync::Arc;

/// Time the supervisor waits for StateCore to take the open or close
/// notice before treating the inbox as gone; the reader's stall budget.
const INBOX_NOTICE_BUDGET: Duration = Duration::from_secs(30);

/// Validated reader and queue ceilings of one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    /// Reader ceilings.
    pub reader: ReaderLimits,
    /// Writer queue ceilings.
    pub queue: QueueLimits,
}

impl ConnectionLimits {
    /// The default connection shape.
    pub const DEFAULT: Self = Self {
        reader: ReaderLimits::DEFAULT,
        queue: QueueLimits::DEFAULT,
    };
}

/// What the transport established about the peer, beyond its address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIdentity {
    /// A client endpoint; TLS authenticated only the server.
    Anonymous,
    /// Operating-system credentials of a local Unix-socket peer (spec line
    /// 4367).
    LocalCredentials {
        /// The peer's effective user identifier.
        uid: u32,
        /// The peer's effective group identifier.
        gid: u32,
    },
    /// The SHA-256 of the peer's leaf certificate subject public key info
    /// under mutual TLS (spec line 4371).
    ClientCertificate {
        /// The SPKI digest compared against the exact allowlist.
        spki_sha256: [u8; 32],
    },
}

/// The facts one admitted connection carries into its supervisor.
#[derive(Clone, Copy)]
pub struct AdmittedConnection {
    /// The queue generation issued for this connection.
    pub generation: ConnectionGeneration,
    /// The listener that accepted it.
    pub purpose: ListenerPurpose,
    /// The admission key derived from the raw address.
    pub source: SourceAddressKey,
    /// What the transport established about the peer.
    pub peer: PeerIdentity,
}

/// The permits a connection holds for its whole lifetime.
pub struct ConnectionResources {
    /// The base charge and any remaining setup charge.
    pub permits: MemoryPermitBatch,
    /// The global client-count slot; absent for administrative listeners.
    pub global_slot: Option<OwnedSemaphorePermit>,
    /// The listener's own count slot.
    pub listener_slot: OwnedSemaphorePermit,
    /// The permit backing the writer queue's item slots.
    pub queue_backing: MemoryPermit,
}

/// How one connection ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionExit {
    /// The queue generation that ended.
    pub generation: ConnectionGeneration,
    /// The listener that accepted the connection.
    pub purpose: ListenerPurpose,
    /// Why it ended.
    pub reason: CloseReason,
}

/// Runs one connection to completion and releases every permit after both
/// the reader and the writer have joined.
pub async fn run_connection<T>(
    transport: T,
    admitted: AdmittedConnection,
    resources: ConnectionResources,
    limits: ConnectionLimits,
    inbox: mpsc::Sender<StateCoreMessage>,
    token: CancellationToken,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let exit = |reason| ConnectionExit {
        generation: admitted.generation,
        purpose: admitted.purpose,
        reason,
    };
    let ConnectionResources {
        permits,
        global_slot,
        listener_slot,
        queue_backing,
    } = resources;
    let Ok(queue) = WriterQueue::new(admitted.generation, limits.queue, queue_backing) else {
        drop((permits, global_slot, listener_slot));
        return exit(CloseReason::Overload);
    };
    let sink: Arc<dyn ClientSink> = queue.clone();
    let opened = StateCoreMessage::Opened {
        generation: admitted.generation,
        purpose: admitted.purpose,
        source: admitted.source,
        sink,
    };
    if notify_state_core(&inbox, opened, &token).await.is_err() {
        drop((permits, global_slot, listener_slot, queue));
        return exit(CloseReason::Shutdown);
    }
    let reason = supervise_tasks(
        transport,
        admitted.generation,
        &queue,
        limits,
        &inbox,
        &token,
    )
    .await;
    let closed = StateCoreMessage::Closed {
        generation: admitted.generation,
        reason,
    };
    let _ = notify_state_core(&inbox, closed, &token).await;
    drop((queue, permits, global_slot, listener_slot));
    exit(reason)
}

async fn supervise_tasks<T>(
    transport: T,
    generation: ConnectionGeneration,
    queue: &Arc<WriterQueue>,
    limits: ConnectionLimits,
    inbox: &mpsc::Sender<StateCoreMessage>,
    token: &CancellationToken,
) -> CloseReason
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (Ok(reader_token), Ok(writer_token)) = (token.child(), token.child()) else {
        return CloseReason::Overload;
    };
    let (read_half, write_half) = tokio::io::split(transport);
    let mut reader = tokio::spawn(run_reader(
        read_half,
        generation,
        limits.reader,
        inbox.clone(),
        reader_token.clone(),
    ));
    let mut writer = tokio::spawn(run_writer(
        write_half,
        Arc::clone(queue),
        writer_token.clone(),
    ));
    let reason = tokio::select! {
        reader_exit = &mut reader => {
            let reason = reader_exit.unwrap_or(CloseReason::TransportLoss);
            queue.close(reason, ClosePolicy::Immediate);
            writer_token.cancel();
            writer.await.unwrap_or(CloseReason::TransportLoss);
            reason
        }
        writer_exit = &mut writer => {
            let reason = writer_exit.unwrap_or(CloseReason::TransportLoss);
            reader_token.cancel();
            reader.await.unwrap_or(CloseReason::TransportLoss);
            reason
        }
    };
    reason
}

async fn notify_state_core(
    inbox: &mpsc::Sender<StateCoreMessage>,
    message: StateCoreMessage,
    token: &CancellationToken,
) -> Result<(), ()> {
    tokio::select! {
        () = token.cancelled() => Err(()),
        sent = tokio::time::timeout(INBOX_NOTICE_BUDGET, inbox.send(message)) => {
            match sent {
                Ok(Ok(())) => Ok(()),
                _ => Err(()),
            }
        }
    }
}
