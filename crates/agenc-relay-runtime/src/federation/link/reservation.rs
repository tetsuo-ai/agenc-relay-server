//! Pre-commit ownership of ordered federation acknowledgment output.

use super::{FederationLineText, LinkHandle, LinkOutbound, SendRefusal, release_queued};
use crate::budget::MemoryPermit;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

const ACK_MAX_BYTES: usize = 512;
const ACK_BACKING_PER_FRAME: usize = 2_048;

pub(super) struct QueuedReservation {
    ledger: Arc<AtomicU64>,
    bytes: u64,
    _backing: Arc<MemoryPermit>,
}

impl Drop for QueuedReservation {
    fn drop(&mut self) {
        release_queued(&self.ledger, self.bytes);
    }
}

struct ReservedFrame {
    line: FederationLineText,
    slot: mpsc::OwnedPermit<LinkOutbound>,
}

pub(crate) struct ReservedFrames {
    frames: Vec<ReservedFrame>,
    queued_bytes: Arc<AtomicU64>,
    bytes: u64,
    closed: Arc<std::sync::Mutex<bool>>,
    backing: Arc<MemoryPermit>,
}

impl ReservedFrames {
    /// Includes encoded strings, both preparation vectors, owned slots and Arc.
    pub(crate) fn backing_bytes(count: usize) -> Result<usize, SendRefusal> {
        if count == 0 || count > super::OUTBOUND_QUEUE_ITEMS {
            return Err(SendRefusal::QueueFull);
        }
        count
            .checked_mul(ACK_BACKING_PER_FRAME)
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or(SendRefusal::QueueFull)
    }

    /// Publishing cannot encounter item or byte contention. The actor must
    /// first verify the original authenticated LinkId is still current.
    pub(crate) fn publish(mut self) -> Result<(), SendRefusal> {
        let closed = self.closed.lock().map_err(|_| SendRefusal::Closed)?;
        if *closed {
            return Err(SendRefusal::Closed);
        }
        for frame in self.frames.drain(..) {
            let bytes = u64::try_from(frame.line.len()).unwrap_or(u64::MAX);
            let _sender = frame.slot.send(LinkOutbound {
                line: Some(frame.line),
                _reservation: Some(QueuedReservation {
                    ledger: Arc::clone(&self.queued_bytes),
                    bytes,
                    _backing: Arc::clone(&self.backing),
                }),
            });
            self.bytes = self.bytes.saturating_sub(bytes);
        }
        Ok(())
    }
}

impl Drop for ReservedFrames {
    fn drop(&mut self) {
        // Free slots and line backing before returning byte and memory charges.
        self.frames.clear();
        release_queued(&self.queued_bytes, self.bytes);
    }
}

impl LinkHandle {
    /// Owns complete short control frames until commit or rollback.
    pub(crate) fn reserve_frames(
        &self,
        lines: Vec<FederationLineText>,
        backing: MemoryPermit,
    ) -> Result<ReservedFrames, SendRefusal> {
        let required = ReservedFrames::backing_bytes(lines.len())?;
        if backing.bytes() < u64::try_from(required).map_err(|_| SendRefusal::QueueFull)?
            || lines.capacity() > lines.len()
            || lines.iter().any(|line| {
                line.len() > ACK_MAX_BYTES || line.backing_capacity() > ACK_MAX_BYTES * 2
            })
        {
            return Err(SendRefusal::QueueFull);
        }
        let bytes = lines
            .iter()
            .try_fold(0_u64, |bytes, line| {
                bytes.checked_add(u64::try_from(line.len()).ok()?)
            })
            .ok_or(SendRefusal::QueueFull)?;
        let mut reserved = ReservedFrames {
            frames: Vec::new(),
            queued_bytes: Arc::clone(&self.queued_bytes),
            bytes: 0,
            closed: Arc::clone(&self.closed),
            backing: Arc::new(backing),
        };
        reserved
            .frames
            .try_reserve_exact(lines.len())
            .map_err(|_| SendRefusal::QueueFull)?;
        for line in lines {
            let slot = self
                .sender
                .clone()
                .try_reserve_owned()
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => SendRefusal::QueueFull,
                    mpsc::error::TrySendError::Closed(_) => SendRefusal::Closed,
                })?;
            reserved.frames.push(ReservedFrame { line, slot });
        }
        self.queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued
                    .checked_add(bytes)
                    .filter(|total| *total <= self.capacity_bytes)
            })
            .map_err(|_| SendRefusal::QueueFull)?;
        reserved.bytes = bytes;
        Ok(reserved)
    }
}

struct BackedFrame {
    line: FederationLineText,
    backing: Arc<MemoryPermit>,
}

impl LinkHandle {
    /// Transfers one already-charged page line through the existing close latch.
    pub(crate) fn try_send_backed(
        &self,
        line: FederationLineText,
        backing: Arc<MemoryPermit>,
    ) -> Result<(), SendRefusal> {
        // Construct before every fallible branch: line storage drops first.
        let frame = BackedFrame { line, backing };
        let required = crate::budget::MemoryCharge::allocation(
            u64::try_from(frame.line.backing_capacity()).map_err(|_| SendRefusal::QueueFull)?,
        )
        .map_err(|_| SendRefusal::QueueFull)?;
        if frame.backing.bytes() < required.bytes() {
            return Err(SendRefusal::QueueFull);
        }
        let closed = self.closed.lock().map_err(|_| SendRefusal::Closed)?;
        if *closed {
            return Err(SendRefusal::Closed);
        }
        let slot = self
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendRefusal::QueueFull,
                mpsc::error::TrySendError::Closed(_) => SendRefusal::Closed,
            })?;
        let bytes = u64::try_from(frame.line.len()).map_err(|_| SendRefusal::QueueFull)?;
        self.queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued
                    .checked_add(bytes)
                    .filter(|total| *total <= self.capacity_bytes)
            })
            .map_err(|_| SendRefusal::QueueFull)?;
        let _sender = slot.send(LinkOutbound {
            line: Some(frame.line),
            _reservation: Some(QueuedReservation {
                ledger: Arc::clone(&self.queued_bytes),
                bytes,
                _backing: frame.backing,
            }),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};
    use crate::test_support::TestResult;

    fn backing(budget: &MemoryBudget, count: usize) -> TestResult<MemoryPermit> {
        let bytes = u64::try_from(ReservedFrames::backing_bytes(count)?)?;
        let charge = MemoryCharge::allocation(bytes)?;
        Ok(budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[charge])?)?
            .split_exact(charge.bytes())
            .ok_or("missing memory permit")?)
    }

    fn lines(count: usize) -> TestResult<Vec<FederationLineText>> {
        let mut lines = Vec::new();
        lines.try_reserve_exact(count)?;
        for index in 0..count {
            lines.push(FederationLineText::from_rendered(format!(
                ":edge FPONG :{index}\r\n"
            ))?);
        }
        Ok(lines)
    }

    #[tokio::test]
    async fn ack_reservations_hold_memory_and_bytes_until_the_last_queued_frame() -> TestResult {
        let budget = MemoryBudget::new(1 << 20);
        let (handle, mut queue) = super::super::link_queue(1 << 20);
        let reservation = handle.reserve_frames(lines(3)?, backing(&budget, 3)?)?;
        let bytes = handle.queued_bytes();
        assert!(bytes > 0);
        assert!(budget.available() < 1 << 20);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(2), queue.recv())
                .await
                .is_err()
        );
        reservation.publish()?;
        for index in 0..3 {
            let line = queue.recv().await.ok_or("missing reserved frame")?;
            assert_eq!(line.as_str(), format!(":edge FPONG :{index}\r\n"));
            if index < 2 {
                assert!(budget.available() < 1 << 20);
            }
        }
        assert_eq!(handle.queued_bytes(), 0);
        assert_eq!(budget.available(), 1 << 20);
        Ok(())
    }

    #[test]
    fn ack_reservation_partial_slot_and_byte_refusals_refund_every_owner() -> TestResult {
        let budget = MemoryBudget::new(1 << 20);
        let (handle, _queue) = super::super::link_queue(1 << 20);
        for _ in 0..super::super::OUTBOUND_QUEUE_ITEMS
            .checked_sub(1)
            .ok_or("slots")?
        {
            handle.try_send(FederationLineText::from_rendered(
                ":edge FPONG :x\r\n".to_owned(),
            )?)?;
        }
        let before = handle.queued_bytes();
        assert!(matches!(
            handle.reserve_frames(lines(2)?, backing(&budget, 2)?),
            Err(SendRefusal::QueueFull)
        ));
        assert_eq!(handle.queued_bytes(), before);
        assert_eq!(budget.available(), 1 << 20);
        handle.try_send(FederationLineText::from_rendered(
            ":edge FPONG :last\r\n".to_owned(),
        )?)?;
        let (handle, _queue) = super::super::link_queue(1);
        assert!(matches!(
            handle.reserve_frames(lines(2)?, backing(&budget, 2)?),
            Err(SendRefusal::QueueFull)
        ));
        assert_eq!(handle.queued_bytes(), 0);
        assert_eq!(budget.available(), 1 << 20);
        Ok(())
    }

    #[test]
    fn ack_reservations_refund_when_the_receiver_closes_before_or_after_publish() -> TestResult {
        let budget = MemoryBudget::new(1 << 20);
        for publish in [false, true] {
            let (handle, queue) = super::super::link_queue(1 << 20);
            let reservation = handle.reserve_frames(lines(2)?, backing(&budget, 2)?)?;
            if publish {
                reservation.publish()?;
                drop(queue);
            } else {
                drop(queue);
                let outcome = reservation.publish();
                assert_eq!(
                    handle.queued_bytes(),
                    0,
                    "a closed receiver retained reserved frame bytes"
                );
                assert_eq!(
                    budget.available(),
                    1 << 20,
                    "a closed receiver retained frame backing"
                );
                assert_eq!(outcome, Err(SendRefusal::Closed));
            }
            assert_eq!(handle.queued_bytes(), 0);
            assert_eq!(budget.available(), 1 << 20);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "reservation/tests/backed.rs"]
mod backed_tests;
