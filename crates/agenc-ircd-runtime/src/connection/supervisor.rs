//! The supervisor of one admitted connection (spec 21.2, lines 4064-4073).
//!
//! A connection supervisor exists only after the listener acquired both the
//! global and listener admission permits and the memory charges. It owns the
//! queue generation, runs the reader and writer with child tokens, completes
//! both before releasing any permit, and reports the connection's open and
//! close to StateCore through bounded channels.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agenc_ircd_types::MonotonicTick;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use super::queue::{ClosePolicy, QueueLimits, WriterQueue};
use super::reader::{ReaderLimits, run_reader_sequenced};
use super::sink::{ClientSink, ConnectionGeneration};
use super::writer::run_writer;
use crate::budget::{CLIENT_CONNECTION_BASE_BYTES, MemoryPermit, MemoryPermitBatch};
use crate::cancel::CancellationToken;
use crate::purpose::ListenerPurpose;
use crate::state_core::inbox::{
    CloseReason, ConnectionClosePermit, ConnectionOpenOutcome, ConnectionStatePermit,
    PhysicalCloseNotice, SourceAddressKey, StateCoreMessage,
};
use crate::sync::Arc;

/// Time the supervisor waits for StateCore to take the open notice before
/// treating the inbox as gone; the reader's stall budget.
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

type ReleaseAdmission = Box<dyn FnOnce() -> Option<MonotonicTick> + Send>;

/// Single-consumption admission authority retained until the transport drops.
pub(crate) struct AdmissionLease {
    release: Option<ReleaseAdmission>,
    close_permit: Option<ConnectionClosePermit>,
    state_permit: Option<ConnectionStatePermit>,
    accepted_lines: Option<Arc<AtomicU64>>,
    generation: Option<ConnectionGeneration>,
    armed: bool,
}

impl AdmissionLease {
    pub(crate) fn new(release: ReleaseAdmission, close_permit: ConnectionClosePermit) -> Self {
        Self {
            release: Some(release),
            close_permit: Some(close_permit),
            state_permit: None,
            accepted_lines: None,
            generation: None,
            armed: false,
        }
    }

    pub(crate) fn assign_generation(&mut self, generation: ConnectionGeneration) {
        self.generation = Some(generation);
    }

    fn assign_state_permit(
        &mut self,
        permit: MemoryPermit,
        return_permit: oneshot::Sender<MemoryPermit>,
    ) {
        self.state_permit = Some(ConnectionStatePermit::new(permit, return_permit));
    }

    fn arm(&mut self) {
        self.armed = true;
    }

    fn assign_line_counter(&mut self, accepted_lines: Arc<AtomicU64>) {
        self.accepted_lines = Some(accepted_lines);
    }

    fn finish(&mut self, reason: CloseReason) -> Option<MonotonicTick> {
        let closed_at = self.release.take().and_then(|release| release());
        let permit = self.close_permit.take();
        let state_permit = self.state_permit.take();
        let final_line_sequence = self
            .accepted_lines
            .take()
            .map_or(0, |accepted| accepted.load(Ordering::Acquire));
        if self.armed
            && let (Some(permit), Some(generation), Some(state_permit)) =
                (permit, self.generation, state_permit)
        {
            permit.send(PhysicalCloseNotice {
                generation,
                reason,
                closed_at,
                final_line_sequence,
                state_permit,
            });
        }
        closed_at
    }

    pub(crate) fn release(mut self, reason: CloseReason) -> Option<MonotonicTick> {
        self.finish(reason)
    }
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        let _closed_at = self.finish(CloseReason::TransportLoss);
    }
}

/// Runs one connection to completion. Count and queue permits leave after
/// the reader and writer, while the base permit stays until StateCore has
/// removed the logical connection state.
// agenc-review: focus owner=runtime reviewed=2026-08-31 reason=the admission handshake keeps every transport resource and the physical-close sequence in one owner
pub(crate) async fn run_connection<T>(
    transport: T,
    admitted: AdmittedConnection,
    resources: ConnectionResources,
    limits: ConnectionLimits,
    inbox: mpsc::Sender<StateCoreMessage>,
    token: CancellationToken,
    lease: AdmissionLease,
) -> ConnectionExit
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut lease = lease;
    let transport = transport;
    let ConnectionResources {
        mut permits,
        global_slot,
        listener_slot,
        queue_backing,
    } = resources;
    let Some(state_permit) = permits.split_exact(CLIENT_CONNECTION_BASE_BYTES) else {
        drop(transport);
        drop((permits, global_slot, listener_slot, queue_backing));
        let _closed_at = lease.release(CloseReason::Overload);
        return connection_exit(&admitted, CloseReason::Overload);
    };
    let (return_permit, _returned_permit) = oneshot::channel();
    lease.assign_state_permit(state_permit, return_permit);
    let Ok(queue) = WriterQueue::new(admitted.generation, limits.queue, queue_backing) else {
        drop(transport);
        drop((permits, global_slot, listener_slot));
        let _closed_at = lease.release(CloseReason::Overload);
        return connection_exit(&admitted, CloseReason::Overload);
    };
    let sink: Arc<dyn ClientSink> = queue.clone();
    let (acknowledgement, open_outcome) = oneshot::channel();
    let opened = StateCoreMessage::Opened {
        generation: admitted.generation,
        purpose: admitted.purpose,
        source: admitted.source,
        sink,
        acknowledgement,
    };
    if notify_state_core(&inbox, opened, &token).await.is_err() {
        drop(transport);
        drop((permits, global_slot, listener_slot, queue));
        let _closed_at = lease.release(CloseReason::Shutdown);
        return connection_exit(&admitted, CloseReason::Shutdown);
    }
    let open_failure = match open_outcome.await {
        Ok(ConnectionOpenOutcome::Accepted) => None,
        Ok(ConnectionOpenOutcome::Refused) => Some(CloseReason::Overload),
        Err(_closed) => Some(CloseReason::Shutdown),
    };
    if let Some(reason) = open_failure {
        drop(transport);
        drop((permits, global_slot, listener_slot, queue));
        let _closed_at = lease.release(reason);
        return connection_exit(&admitted, reason);
    }
    let accepted_lines = Arc::new(AtomicU64::new(0));
    lease.assign_line_counter(Arc::clone(&accepted_lines));
    lease.arm();
    let reason = supervise_tasks(
        transport,
        admitted.generation,
        &queue,
        limits,
        &inbox,
        &token,
        accepted_lines,
    )
    .await;
    drop((queue, permits, global_slot, listener_slot));
    let _closed_at = lease.release(reason);
    connection_exit(&admitted, reason)
}

fn connection_exit(admitted: &AdmittedConnection, reason: CloseReason) -> ConnectionExit {
    ConnectionExit {
        generation: admitted.generation,
        purpose: admitted.purpose,
        reason,
    }
}

async fn supervise_tasks<T>(
    transport: T,
    generation: ConnectionGeneration,
    queue: &Arc<WriterQueue>,
    limits: ConnectionLimits,
    inbox: &mpsc::Sender<StateCoreMessage>,
    token: &CancellationToken,
    accepted_lines: Arc<AtomicU64>,
) -> CloseReason
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (Ok(reader_token), Ok(writer_token)) = (token.child(), token.child()) else {
        return CloseReason::Overload;
    };
    let (read_half, write_half) = tokio::io::split(transport);
    let reader = run_reader_sequenced(
        read_half,
        generation,
        limits.reader,
        inbox.clone(),
        reader_token.clone(),
        accepted_lines,
    );
    let writer = run_writer(write_half, Arc::clone(queue), writer_token.clone());
    tokio::pin!(reader);
    tokio::pin!(writer);
    let reason = tokio::select! {
        reader_exit = &mut reader => {
            let reason = reader_exit;
            queue.close(reason, ClosePolicy::Immediate);
            writer_token.cancel();
            let _writer_reason = writer.await;
            reason
        }
        writer_exit = &mut writer => {
            let reason = writer_exit;
            reader_token.cancel();
            let _reader_reason = reader.await;
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

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::RuntimeError;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
    use crate::state_core::inbox::connection_close_channel;

    use super::*;

    fn client_base_permit(budget: &MemoryBudget) -> Result<MemoryPermit, RuntimeError> {
        let charges =
            BoundedMemoryCharges::new(vec![MemoryCharge::fixed(CLIENT_CONNECTION_BASE_BYTES)])?;
        let mut batch = budget.try_acquire_batch(charges)?;
        batch
            .split_exact(CLIENT_CONNECTION_BASE_BYTES)
            .ok_or(RuntimeError::InvalidValue)
    }

    #[tokio::test]
    async fn admission_lease_drop_releases_once_and_delivers_its_reserved_close()
    -> Result<(), RuntimeError> {
        let (port, mut inbox) = connection_close_channel();
        let permit = port
            .try_reserve()
            .map_err(|()| RuntimeError::LimitExceeded)?;
        let releases = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&releases);
        let mut lease = AdmissionLease::new(
            Box::new(move || {
                counted.fetch_add(1, Ordering::Relaxed);
                Some(MonotonicTick::from_ticks(55))
            }),
            permit,
        );
        let generation = ConnectionGeneration::new(7);
        let budget = MemoryBudget::new(CLIENT_CONNECTION_BASE_BYTES);
        let (return_permit, returned_permit) = oneshot::channel();
        lease.assign_state_permit(client_base_permit(&budget)?, return_permit);
        lease.assign_generation(generation);
        lease.arm();
        drop(lease);

        let notice = inbox.recv().await.ok_or(RuntimeError::Cancelled)?;
        assert_eq!(releases.load(Ordering::Relaxed), 1);
        assert_eq!(notice.generation, generation);
        assert_eq!(notice.reason, CloseReason::TransportLoss);
        assert_eq!(notice.closed_at, Some(MonotonicTick::from_ticks(55)));
        assert_eq!(budget.available(), 0);
        drop(notice.state_permit);
        let returned = returned_permit.await.map_err(|_| RuntimeError::Cancelled)?;
        assert_eq!(budget.available(), 0);
        drop(returned);
        assert_eq!(budget.available(), CLIENT_CONNECTION_BASE_BYTES);
        Ok(())
    }

    #[tokio::test]
    async fn panicking_release_still_consumes_the_reserved_close_slot() -> Result<(), RuntimeError>
    {
        let (port, mut inbox) = connection_close_channel();
        let permit = port
            .try_reserve()
            .map_err(|()| RuntimeError::LimitExceeded)?;
        let releases = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&releases);
        let mut lease = AdmissionLease::new(
            Box::new(move || {
                let previous = counted.fetch_add(1, Ordering::Relaxed);
                assert_eq!(previous, u64::MAX, "injected release panic");
                None
            }),
            permit,
        );
        let generation = ConnectionGeneration::new(8);
        let budget = MemoryBudget::new(CLIENT_CONNECTION_BASE_BYTES);
        let (return_permit, returned_permit) = oneshot::channel();
        lease.assign_state_permit(client_base_permit(&budget)?, return_permit);
        lease.assign_generation(generation);
        lease.arm();

        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _closed_at = lease.release(CloseReason::Shutdown);
        }));
        assert!(panicked.is_err());
        let notice = inbox.recv().await.ok_or(RuntimeError::Cancelled)?;
        assert_eq!(releases.load(Ordering::Relaxed), 1);
        assert_eq!(notice.generation, generation);
        assert_eq!(notice.reason, CloseReason::TransportLoss);
        assert_eq!(notice.closed_at, None);
        assert_eq!(budget.available(), 0);
        drop(notice.state_permit);
        drop(returned_permit.await.map_err(|_| RuntimeError::Cancelled)?);
        assert_eq!(budget.available(), CLIENT_CONNECTION_BASE_BYTES);
        Ok(())
    }
}
