//! The writer task of one admitted connection (spec 8.3, lines 522-523;
//! spec 19.3, lines 2816-2822).
//!
//! The writer drains the connection's queue in order. A write that stalls
//! for 30 seconds closes the connection. Closing the queue starts one
//! 30-second deadline for all accepted frames, followed by close-notify
//! with one second of grace. Nothing here allocates
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
        QueuePop::Frame(frame) => write_queued_frame(transport, queue, frame.as_bytes()).await,
        QueuePop::Closed(reason) => {
            finish(transport).await;
            queue.acknowledge_flush();
            Some(reason)
        }
        QueuePop::Empty => None,
    }
}

async fn write_queued_frame<W: AsyncWrite + Unpin>(
    transport: &mut W,
    queue: &WriterQueue,
    bytes: &[u8],
) -> Option<CloseReason> {
    let write_started = tokio::time::Instant::now();
    let started = queue
        .close_started()
        .unwrap_or(write_started)
        .min(write_started);
    match write_frame(transport, bytes, started).await {
        Ok(()) => None,
        Err(reason) => {
            queue.close(reason, ClosePolicy::Immediate);
            Some(reason)
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    transport: &mut W,
    bytes: &[u8],
    started: tokio::time::Instant,
) -> Result<(), CloseReason> {
    // A write already in progress when the queue closes has an earlier
    // deadline. Later writes share the first close's remaining budget.
    let deadline = started
        .checked_add(WRITE_STALL_BUDGET)
        .ok_or(CloseReason::WriteStall)?;
    if tokio::time::Instant::now() >= deadline {
        return Err(CloseReason::WriteStall);
    }
    let write = async {
        transport.write_all(bytes).await?;
        transport.flush().await
    };
    match tokio::time::timeout_at(deadline, write).await {
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

    fn three_control_frames() -> Result<(Arc<WriterQueue>, usize), RuntimeError> {
        use crate::budget::{MemoryCharge, PermitCursor};
        use agenc_ircd_client_wire::WireMessage;
        let budget = MemoryBudget::new(1_048_576);
        let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
        let message = WireMessage::new("server.test", "ERROR", &[], Some("Closing connection"))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let measured = message.measure().map_err(|_| RuntimeError::InvalidValue)?;
        let bytes = measured.bytes();
        let charge =
            MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)?;
        let mut permits = budget.try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?;
        let frame = Arc::new(
            measured
                .encode(&mut PermitCursor::new(&mut permits))
                .map_err(|_| RuntimeError::InvalidValue)?,
        );
        for _ in 0..3 {
            queue
                .push_control(Arc::clone(&frame))
                .map_err(|_| RuntimeError::LimitExceeded)?;
        }
        Ok((queue, bytes))
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_queue_has_one_deadline_across_all_accepted_frames() -> Result<(), RuntimeError>
    {
        use tokio::io::AsyncReadExt as _;
        let (queue, frame_bytes) = three_control_frames()?;
        let (mut peer, transport) = tokio::io::duplex(1);
        let started = tokio::time::Instant::now();
        let _acknowledgement = queue.close_after_flush(CloseReason::ClientQuit);
        let reader_queue = Arc::clone(&queue);
        let reader = tokio::spawn(async move {
            let mut frame = vec![0; frame_bytes];
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if peer.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let _repeated = reader_queue.close_after_flush(CloseReason::Shutdown);
            }
        });
        let reason = run_writer(transport, Arc::clone(&queue), CancellationToken::root()).await;
        reader.abort();
        assert_eq!(reason, CloseReason::WriteStall);
        assert_eq!(started.elapsed(), WRITE_STALL_BUDGET);
        assert_eq!(
            queue.control_bytes(),
            0,
            "deadline releases every queued permit"
        );
        assert_eq!(queue.closed_reason(), Some(CloseReason::ClientQuit));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn closing_during_a_write_bounds_every_following_frame() -> Result<(), RuntimeError> {
        use tokio::io::AsyncReadExt as _;
        let (queue, frame_bytes) = three_control_frames()?;
        let (mut peer, transport) = tokio::io::duplex(1);
        let started = tokio::time::Instant::now();
        let closing_queue = Arc::clone(&queue);
        let closer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _acknowledgement = closing_queue.close_after_flush(CloseReason::ClientQuit);
        });
        let reader = tokio::spawn(async move {
            let mut frame = vec![0; frame_bytes];
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if peer.read_exact(&mut frame).await.is_err() {
                    return;
                }
            }
        });
        let reason = run_writer(transport, Arc::clone(&queue), CancellationToken::root()).await;
        reader.abort();
        closer.await.map_err(|_| RuntimeError::Cancelled)?;
        assert_eq!(reason, CloseReason::WriteStall);
        assert_eq!(started.elapsed(), Duration::from_secs(40));
        assert_eq!(queue.control_bytes(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn orderly_shutdown_acknowledges_only_after_the_writer_finishes()
    -> Result<(), RuntimeError> {
        let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
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
        let queue = WriterQueue::new(ConnectionGeneration::new(1), QueueLimits::DEFAULT)?;
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
