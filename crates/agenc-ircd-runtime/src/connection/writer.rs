//! The writer task of one admitted connection (spec 8.3, lines 522-523;
//! spec 19.3, lines 2816-2822).
//!
//! The writer drains the connection's queue in order. A write that stalls
//! for 30 seconds closes the connection; a closed queue ends the writer
//! after a close-notify with one second of grace. Nothing here allocates
//! per frame: each frame arrives as a shared rendered message that owns its
//! permit.

use tokio::io::{AsyncWrite, AsyncWriteExt as _};

use super::queue::{ClosePolicy, QueuePop, WriterQueue};
use crate::cancel::CancellationToken;
use crate::state_core::inbox::CloseReason;
use crate::sync::Arc;
use crate::tls::{CLOSE_NOTIFY_GRACE, WRITE_STALL_BUDGET};

/// Runs the writer until the queue closes, a write stalls, the transport
/// fails, or the token is cancelled.
pub async fn run_writer<W: AsyncWrite + Unpin>(
    mut transport: W,
    queue: Arc<WriterQueue>,
    token: CancellationToken,
) -> CloseReason {
    loop {
        let popped = next_or_cancel(&queue, &token).await;
        if let Some(reason) = handle_pop(&mut transport, &queue, popped).await {
            return reason;
        }
    }
}

/// Waits for the next frame; cancellation closes the queue immediately.
async fn next_or_cancel(queue: &WriterQueue, token: &CancellationToken) -> QueuePop {
    tokio::select! {
        () = token.cancelled() => {
            queue.close(CloseReason::Shutdown, ClosePolicy::Immediate);
            QueuePop::Closed(CloseReason::Shutdown)
        }
        popped = queue.next() => popped,
    }
}

/// Writes one frame or finishes the transport; `Some` ends the writer.
async fn handle_pop<W: AsyncWrite + Unpin>(
    transport: &mut W,
    queue: &WriterQueue,
    popped: QueuePop,
) -> Option<CloseReason> {
    match popped {
        QueuePop::Frame(frame) => match write_frame(transport, frame.as_bytes()).await {
            Ok(()) => None,
            Err(reason) => {
                queue.close(reason, ClosePolicy::Immediate);
                Some(reason)
            }
        },
        QueuePop::Closed(reason) => {
            finish(transport).await;
            queue.acknowledge_flush();
            Some(reason)
        }
        QueuePop::Empty => None,
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    transport: &mut W,
    bytes: &[u8],
) -> Result<(), CloseReason> {
    let write = async {
        transport.write_all(bytes).await?;
        transport.flush().await
    };
    match tokio::time::timeout(WRITE_STALL_BUDGET, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(CloseReason::TransportLoss),
        Err(_) => Err(CloseReason::WriteStall),
    }
}

/// Flushes and closes the transport within the close-notify grace.
async fn finish<W: AsyncWrite + Unpin>(transport: &mut W) {
    let close = async {
        let _ = transport.flush().await;
        let _ = transport.shutdown().await;
    };
    let _ = tokio::time::timeout(CLOSE_NOTIFY_GRACE, close).await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::RuntimeError;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort as _};
    use crate::connection::{ClientSink as _, ConnectionGeneration, QueueLimits};

    #[tokio::test]
    async fn orderly_shutdown_acknowledges_only_after_the_writer_finishes()
    -> Result<(), RuntimeError> {
        let budget = MemoryBudget::new(1_048_576);
        let charge = QueueLimits::DEFAULT.backing_charge()?;
        let mut permits = budget.try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        let backing = permits
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT, backing)?;
        let (_peer, transport) = tokio::io::duplex(1_024);
        let acknowledgement = queue.shutdown_after_flush();
        assert!(!acknowledgement.is_acknowledged());
        let writer = tokio::spawn(run_writer(
            transport,
            Arc::clone(&queue),
            CancellationToken::root(),
        ));
        tokio::time::timeout(Duration::from_secs(1), acknowledgement.wait())
            .await
            .map_err(|_| RuntimeError::Cancelled)?;
        assert!(acknowledgement.is_acknowledged());
        assert_eq!(
            writer.await.map_err(|_| RuntimeError::Cancelled)?,
            CloseReason::Shutdown
        );
        Ok(())
    }

    #[tokio::test]
    async fn orderly_shutdown_remembers_a_writer_that_already_finished() -> Result<(), RuntimeError>
    {
        let budget = MemoryBudget::new(1_048_576);
        let charge = QueueLimits::DEFAULT.backing_charge()?;
        let mut permits = budget.try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        let backing = permits
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT, backing)?;
        let (_peer, transport) = tokio::io::duplex(1_024);
        let writer = tokio::spawn(run_writer(
            transport,
            Arc::clone(&queue),
            CancellationToken::root(),
        ));
        queue.close(CloseReason::Shutdown, ClosePolicy::AfterFlush);
        assert_eq!(
            writer.await.map_err(|_| RuntimeError::Cancelled)?,
            CloseReason::Shutdown
        );

        let acknowledgement = queue.shutdown_after_flush();
        assert!(acknowledgement.is_acknowledged());
        acknowledgement.wait().await;
        Ok(())
    }
}
