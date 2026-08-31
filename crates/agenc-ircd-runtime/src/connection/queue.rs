//! The owner-side writer queue behind one client sink (spec 15.3, lines
//! 2210-2260; spec 19.3, lines 2816-2822; spec 21.3, lines 4093-4106).
//!
//! The queue is a `VecDeque` whose slot capacity is fixed at admission and
//! charged once against the memory budget, so committing a reservation
//! never allocates and every reservation's additional backing charge is
//! zero. Normal output may use `client_output_bytes` minus the control
//! reserve; control frames may use the reserved subrange up to the total
//! ceiling. Crossing 75% of the normal ceiling raises one warning; a whole
//! demand that does not fit reports `Full` and the sink joins the
//! slow-consumer close list. No frame is ever evicted for a newer one.

use std::collections::VecDeque;
use std::mem::size_of;

use agenc_ircd_client_wire::RenderedMessage;
use tokio::sync::Notify;

use super::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, ConnectionGeneration, FlushAcknowledgement, QueueAllocationError,
    QueueReservationLedger, SinkReserveError, TentativeClientQueueReservation,
};
use crate::RuntimeError;
use crate::budget::{MemoryCharge, MemoryPermit};
use crate::state_core::inbox::CloseReason;
use crate::sync::{Arc, Mutex, lock};

/// Default normal outbound queue per client, 1 MiB (spec line 2660).
pub const DEFAULT_OUTPUT_BYTES: usize = 1_048_576;
/// Hard maximum normal outbound queue per client, 4 MiB (spec line 2660).
pub const MAX_OUTPUT_BYTES: usize = 4_194_304;
/// Default reserved control output within the queue, 64 KiB (spec line 2661).
pub const DEFAULT_CONTROL_OUTPUT_BYTES: usize = 65_536;
/// Hard maximum reserved control output, 256 KiB (spec line 2661).
pub const MAX_CONTROL_OUTPUT_BYTES: usize = 262_144;
/// Default queue item slots pre-allocated at admission: four maximal
/// fanout demands of 1,024 frames each plus the control slots.
pub const DEFAULT_QUEUE_ITEMS: usize = 4_104;
/// Hard maximum queue item slots: sixteen complete response demands plus
/// the eight control-only slots.
pub const MAX_QUEUE_ITEMS: usize = 16_392;
/// Item slots held back for control frames so a fatal or overload frame
/// always has a slot (spec lines 2748-2756).
pub const CONTROL_ITEM_SLOTS: usize = 8;
/// Queue occupancy that raises the one slow-consumer warning (spec line 2819).
pub const QUEUE_WARNING_PERCENT: usize = 75;

/// Validated byte and item ceilings of one client queue (Appendix C.6,
/// spec lines 9124-9126).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    total_bytes: usize,
    control_bytes: usize,
    items: usize,
}

impl QueueLimits {
    /// The default queue shape.
    pub const DEFAULT: Self = Self {
        total_bytes: DEFAULT_OUTPUT_BYTES,
        control_bytes: DEFAULT_CONTROL_OUTPUT_BYTES,
        items: DEFAULT_QUEUE_ITEMS,
    };

    /// Validates a total ceiling, a strictly smaller control reserve, and an
    /// item slot count above the control slots.
    pub const fn new(
        total_bytes: usize,
        control_bytes: usize,
        items: usize,
    ) -> Result<Self, RuntimeError> {
        if total_bytes == 0
            || total_bytes > MAX_OUTPUT_BYTES
            || control_bytes == 0
            || control_bytes > MAX_CONTROL_OUTPUT_BYTES
            || control_bytes >= total_bytes
            || items <= CONTROL_ITEM_SLOTS
            || items > MAX_QUEUE_ITEMS
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            total_bytes,
            control_bytes,
            items,
        })
    }

    /// Returns the total ceiling.
    #[must_use]
    pub const fn total_bytes(self) -> usize {
        self.total_bytes
    }

    /// Returns the control reserve.
    #[must_use]
    pub const fn control_bytes(self) -> usize {
        self.control_bytes
    }

    /// Returns the normal-output ceiling: total minus the control reserve.
    #[must_use]
    pub const fn normal_bytes(self) -> usize {
        self.total_bytes - self.control_bytes
    }

    /// Returns the pre-allocated item slots.
    #[must_use]
    pub const fn items(self) -> usize {
        self.items
    }

    /// Returns the normal-output item slots: total minus the control slots.
    #[must_use]
    pub const fn normal_items(self) -> usize {
        self.items - CONTROL_ITEM_SLOTS
    }

    /// Returns the byte count at which the warning fires.
    #[must_use]
    pub const fn warning_bytes(self) -> usize {
        self.normal_bytes() / 100 * QUEUE_WARNING_PERCENT
    }

    /// Returns the memory charge for the deque backing the item slots.
    pub fn backing_charge(self) -> Result<MemoryCharge, RuntimeError> {
        let bytes = self
            .items
            .checked_mul(size_of::<QueuedFrame>())
            .ok_or(RuntimeError::Overflow)?;
        MemoryCharge::allocation(u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?)
    }
}

/// Whether a close lets already queued frames drain first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosePolicy {
    /// Discard every queued frame and stop the writer at once.
    Immediate,
    /// Deliver queued frames, then stop the writer.
    AfterFlush,
}

/// What the writer found on the queue.
pub enum QueuePop {
    /// The next frame in output order.
    Frame(Arc<RenderedMessage<MemoryPermit>>),
    /// The queue is closed and holds nothing more to write.
    Closed(CloseReason),
    /// Nothing is queued yet.
    Empty,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FrameClass {
    Normal,
    Control,
}

struct QueuedFrame {
    class: FrameClass,
    frame: Arc<RenderedMessage<MemoryPermit>>,
}

struct QueueState {
    frames: VecDeque<QueuedFrame>,
    normal_bytes: usize,
    normal_items: usize,
    control_bytes: usize,
    control_items: usize,
    closed: Option<CloseReason>,
    warning_armed: bool,
    warning_pending: bool,
    flush_acknowledgement: Option<FlushAcknowledgement>,
}

impl QueueState {
    fn release(&mut self, class: FrameClass, bytes: usize) {
        match class {
            FrameClass::Normal => {
                self.normal_items = self.normal_items.saturating_sub(1);
                self.normal_bytes = self.normal_bytes.saturating_sub(bytes);
            }
            FrameClass::Control => {
                self.control_items = self.control_items.saturating_sub(1);
                self.control_bytes = self.control_bytes.saturating_sub(bytes);
            }
        }
    }
}

struct QueueShared {
    state: Mutex<QueueState>,
    notify: Notify,
}

impl QueueReservationLedger for QueueShared {
    fn rollback(&self, frames: usize, bytes: usize) {
        let mut state = lock(&self.state);
        state.normal_items = state.normal_items.saturating_sub(frames);
        state.normal_bytes = state.normal_bytes.saturating_sub(bytes);
    }
}

/// The writer queue of one admitted connection.
pub struct WriterQueue {
    generation: ConnectionGeneration,
    limits: QueueLimits,
    shared: Arc<QueueShared>,
    _backing: MemoryPermit,
}

impl WriterQueue {
    /// Creates a queue whose slots are backed by exactly `backing`, the
    /// permit for [`QueueLimits::backing_charge`].
    pub fn new(
        generation: ConnectionGeneration,
        limits: QueueLimits,
        backing: MemoryPermit,
    ) -> Result<Arc<Self>, RuntimeError> {
        if backing.bytes() != limits.backing_charge()?.bytes() {
            return Err(RuntimeError::InvalidValue);
        }
        let mut frames = VecDeque::new();
        frames
            .try_reserve_exact(limits.items())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        Ok(Arc::new(Self {
            generation,
            limits,
            shared: Arc::new(QueueShared {
                state: Mutex::new(QueueState {
                    frames,
                    normal_bytes: 0,
                    normal_items: 0,
                    control_bytes: 0,
                    control_items: 0,
                    closed: None,
                    warning_armed: true,
                    warning_pending: false,
                    flush_acknowledgement: None,
                }),
                notify: Notify::new(),
            }),
            _backing: backing,
        }))
    }

    /// Returns the queue limits.
    #[must_use]
    pub const fn limits(&self) -> QueueLimits {
        self.limits
    }

    /// Returns the normal bytes reserved or queued.
    #[must_use]
    pub fn normal_bytes(&self) -> usize {
        lock(&self.shared.state).normal_bytes
    }

    /// Returns the control bytes queued.
    #[must_use]
    pub fn control_bytes(&self) -> usize {
        lock(&self.shared.state).control_bytes
    }

    /// Returns the close reason once the queue is closed.
    #[must_use]
    pub fn closed_reason(&self) -> Option<CloseReason> {
        lock(&self.shared.state).closed
    }

    /// Takes the one pending slow-consumer warning, if it fired.
    #[must_use]
    pub fn take_warning(&self) -> bool {
        let mut state = lock(&self.shared.state);
        std::mem::take(&mut state.warning_pending)
    }

    /// Enqueues one control frame inside the control reserve, bypassing the
    /// normal ceiling (spec lines 2750-2756).
    pub fn push_control(
        &self,
        frame: Arc<RenderedMessage<MemoryPermit>>,
    ) -> Result<(), SinkReserveError> {
        let bytes = frame.as_bytes().len();
        let mut state = lock(&self.shared.state);
        if state.closed.is_some() {
            return Err(SinkReserveError::Closed);
        }
        let next_bytes = state
            .control_bytes
            .checked_add(bytes)
            .ok_or(SinkReserveError::Full)?;
        if next_bytes > self.limits.control_bytes() || state.control_items >= CONTROL_ITEM_SLOTS {
            return Err(SinkReserveError::Full);
        }
        state.control_bytes = next_bytes;
        state.control_items += 1;
        state.frames.push_back(QueuedFrame {
            class: FrameClass::Control,
            frame,
        });
        drop(state);
        self.shared.notify.notify_one();
        Ok(())
    }

    /// Closes the queue; `Immediate` discards queued frames and releases
    /// their permits as one operation.
    pub fn close(&self, reason: CloseReason, policy: ClosePolicy) {
        let mut state = lock(&self.shared.state);
        if state.closed.is_none() {
            state.closed = Some(reason);
        }
        if policy == ClosePolicy::Immediate {
            state.frames.clear();
            state.normal_bytes = 0;
            state.normal_items = 0;
            state.control_bytes = 0;
            state.control_items = 0;
        }
        drop(state);
        self.shared.notify.notify_one();
    }

    /// Completes the pending orderly-shutdown acknowledgement after the
    /// writer has attempted its final transport flush.
    pub fn acknowledge_flush(&self) {
        let acknowledgement = lock(&self.shared.state).flush_acknowledgement.clone();
        if let Some(acknowledgement) = acknowledgement {
            acknowledgement.acknowledge();
        }
    }

    /// Returns whether the queue is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        lock(&self.shared.state).closed.is_some()
    }

    /// Dequeues the next frame; dequeue releases its logical counts exactly
    /// once (spec line 4089).
    #[must_use]
    pub fn pop(&self) -> QueuePop {
        let mut state = lock(&self.shared.state);
        if let Some(queued) = state.frames.pop_front() {
            state.release(queued.class, queued.frame.as_bytes().len());
            return QueuePop::Frame(queued.frame);
        }
        match state.closed {
            Some(reason) => QueuePop::Closed(reason),
            None => QueuePop::Empty,
        }
    }

    /// Waits until the queue has a frame or is closed, then dequeues.
    pub async fn next(&self) -> QueuePop {
        loop {
            let notified = self.shared.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.pop() {
                QueuePop::Empty => notified.await,
                ready => return ready,
            }
        }
    }

    fn admit_normal(&self, state: &mut QueueState, demand: &ClientQueueDemand) -> bool {
        let Some(next_items) = state.normal_items.checked_add(demand.frame_count()) else {
            return false;
        };
        let Some(next_bytes) = state.normal_bytes.checked_add(demand.total_bytes()) else {
            return false;
        };
        if next_items > self.limits.normal_items() || next_bytes > self.limits.normal_bytes() {
            return false;
        }
        state.normal_items = next_items;
        state.normal_bytes = next_bytes;
        if state.warning_armed && next_bytes >= self.limits.warning_bytes() {
            state.warning_armed = false;
            state.warning_pending = true;
        }
        true
    }
}

impl ClientSink for WriterQueue {
    fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        let mut state = lock(&self.shared.state);
        if state.closed.is_some() {
            return Err(SinkReserveError::Closed);
        }
        if !self.admit_normal(&mut state, &demand) {
            return Err(SinkReserveError::Full);
        }
        drop(state);
        let ledger: Arc<dyn QueueReservationLedger> = self.shared.clone();
        Ok(TentativeClientQueueReservation::new(
            self.generation,
            demand,
            0,
            ledger,
        ))
    }

    fn prepare(
        &self,
        tentative: TentativeClientQueueReservation,
        backing: Option<MemoryPermit>,
    ) -> Result<ClientQueueReservation, QueueAllocationError> {
        if tentative.generation() != self.generation || self.is_closed() {
            return Err(QueueAllocationError::Closed);
        }
        ClientQueueReservation::prepare(tentative, backing)
    }

    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
        let mut transfer = reservation.into_transfer();
        let mut state = lock(&self.shared.state);
        if state.closed.is_some() || transfer.generation() != self.generation {
            drop(state);
            transfer.discard();
            return;
        }
        for frame in frames.into_frames() {
            state.frames.push_back(QueuedFrame {
                class: FrameClass::Normal,
                frame,
            });
        }
        drop(state);
        drop(transfer.take_backing());
        self.shared.notify.notify_one();
    }

    fn begin_slow_consumer_close(&self) {
        self.close(CloseReason::SlowConsumer, ClosePolicy::Immediate);
    }

    fn shutdown_after_flush(&self) -> FlushAcknowledgement {
        let mut state = lock(&self.shared.state);
        let acknowledgement = state
            .flush_acknowledgement
            .get_or_insert_with(FlushAcknowledgement::pending)
            .clone();
        if state.closed.is_none() {
            state.closed = Some(CloseReason::Shutdown);
        }
        drop(state);
        self.shared.notify.notify_one();
        acknowledgement
    }

    fn queue_snapshot(&self) -> ClientQueueSnapshot {
        let state = lock(&self.shared.state);
        ClientQueueSnapshot::new(
            u64::try_from(state.normal_bytes + state.control_bytes).unwrap_or(u64::MAX),
            u64::try_from(self.limits.total_bytes()).unwrap_or(u64::MAX),
        )
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_client_wire::WireMessage;

    use super::*;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, PermitCursor};

    fn budget() -> MemoryBudget {
        MemoryBudget::new(64 * 1_048_576)
    }

    fn queue(
        budget: &MemoryBudget,
        generation: u64,
        limits: QueueLimits,
    ) -> Result<Arc<WriterQueue>, RuntimeError> {
        let charge = limits.backing_charge()?;
        let mut batch = budget.try_acquire_batch(BoundedMemoryCharges::new(vec![charge])?)?;
        let backing = batch
            .split_exact(charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        WriterQueue::new(ConnectionGeneration::new(generation), limits, backing)
    }

    fn frame(
        budget: &MemoryBudget,
        text: &str,
    ) -> Result<Arc<RenderedMessage<MemoryPermit>>, RuntimeError> {
        let message = WireMessage::new("server.test", "NOTICE", &["*"], Some(text))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let measured = message.measure().map_err(|_| RuntimeError::InvalidValue)?;
        let bytes = u64::try_from(measured.bytes()).map_err(|_| RuntimeError::Overflow)?;
        let mut batch = budget.try_acquire_batch(BoundedMemoryCharges::new(vec![
            MemoryCharge::allocation(bytes)?,
        ])?)?;
        let rendered = measured
            .encode(&mut PermitCursor::new(&mut batch))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(Arc::new(rendered))
    }

    fn reserve_and_commit(
        queue: &WriterQueue,
        frames: Vec<Arc<RenderedMessage<MemoryPermit>>>,
    ) -> Result<(), RuntimeError> {
        let demand = ClientQueueDemand::new(frames.iter().map(|f| f.as_bytes().len()).collect())?;
        let tentative = queue
            .try_reserve(demand)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let prepared = queue
            .prepare(tentative, None)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
        queue.commit(prepared, bound);
        Ok(())
    }

    #[test]
    fn limits_enforce_the_appendix_c_orderings() -> Result<(), RuntimeError> {
        let limits = QueueLimits::DEFAULT;
        assert_eq!(limits.total_bytes(), 1_048_576);
        assert_eq!(limits.control_bytes(), 65_536);
        assert_eq!(limits.normal_bytes(), 983_040);
        assert_eq!(limits.items(), 4_104);
        assert_eq!(limits.normal_items(), 4_096);
        assert_eq!(limits.warning_bytes(), 737_250);
        assert!(limits.backing_charge()?.bytes() > 0);
        for (total, control, items) in [
            (0, 1, 64),
            (MAX_OUTPUT_BYTES + 1, 1, 64),
            (1_000, 0, 64),
            (1_000, MAX_CONTROL_OUTPUT_BYTES + 1, 64),
            (1_000, 1_000, 64),
            (1_000, 100, CONTROL_ITEM_SLOTS),
            (1_000, 100, MAX_QUEUE_ITEMS + 1),
        ] {
            assert_eq!(
                QueueLimits::new(total, control, items).err(),
                Some(RuntimeError::InvalidValue),
                "{total} {control} {items}"
            );
        }
        assert!(
            QueueLimits::new(MAX_OUTPUT_BYTES, MAX_CONTROL_OUTPUT_BYTES, MAX_QUEUE_ITEMS).is_ok()
        );
        Ok(())
    }

    #[test]
    fn construction_requires_the_exact_backing_permit() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::DEFAULT;
        let mut batch = budget
            .try_acquire_batch(BoundedMemoryCharges::new(vec![MemoryCharge::fixed(4_096)])?)?;
        let wrong = batch.split_exact(4_096).ok_or(RuntimeError::InvalidValue)?;
        assert!(WriterQueue::new(ConnectionGeneration::new(1), limits, wrong).is_err());
        let queue = queue(&budget, 1, limits)?;
        assert_eq!(queue.generation(), ConnectionGeneration::new(1));
        assert_eq!(queue.limits(), limits);
        assert_eq!(queue.normal_bytes(), 0);
        assert!(!queue.is_closed());
        Ok(())
    }

    #[test]
    fn whole_demand_reservation_rolls_back_or_commits_in_order() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(400, 100, 12)?;
        let queue = queue(&budget, 1, limits)?;
        let first = frame(&budget, "first")?;
        let second = frame(&budget, "second")?;
        let len = first.as_bytes().len() + second.as_bytes().len();

        let tentative = queue
            .try_reserve(ClientQueueDemand::new(vec![
                first.as_bytes().len(),
                second.as_bytes().len(),
            ])?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        assert_eq!(tentative.backing_charge(), 0);
        assert_eq!(queue.normal_bytes(), len);
        drop(tentative);
        assert_eq!(queue.normal_bytes(), 0, "drop rolled the counts back");

        assert!(matches!(queue.pop(), QueuePop::Empty));
        reserve_and_commit(&queue, vec![first.clone(), second.clone()])?;
        assert_eq!(queue.normal_bytes(), len);
        let QueuePop::Frame(popped) = queue.pop() else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(popped.as_bytes(), first.as_bytes());
        let QueuePop::Frame(popped) = queue.pop() else {
            return Err(RuntimeError::InvalidValue);
        };
        assert_eq!(popped.as_bytes(), second.as_bytes());
        assert_eq!(queue.normal_bytes(), 0);
        assert!(matches!(queue.pop(), QueuePop::Empty));
        Ok(())
    }

    #[test]
    fn queue_snapshot_contains_only_bounded_occupancy_and_capacity() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(400, 100, 12)?;
        let queue = queue(&budget, 1, limits)?;
        let output = frame(&budget, "snapshot")?;
        let output_bytes =
            u64::try_from(output.as_bytes().len()).map_err(|_| RuntimeError::Overflow)?;
        reserve_and_commit(&queue, vec![output])?;

        assert_eq!(
            queue.queue_snapshot(),
            ClientQueueSnapshot::new(output_bytes, 400)
        );
        let _popped = queue.pop();
        assert_eq!(queue.queue_snapshot(), ClientQueueSnapshot::new(0, 400));
        Ok(())
    }

    #[test]
    fn full_and_closed_sinks_refuse_whole_demands() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(200, 100, 10)?;
        let queue = queue(&budget, 1, limits)?;
        let over = ClientQueueDemand::new(vec![101])?;
        assert_eq!(queue.try_reserve(over).err(), Some(SinkReserveError::Full));
        let many = ClientQueueDemand::new(vec![1; 3])?;
        assert_eq!(queue.try_reserve(many).err(), Some(SinkReserveError::Full));
        assert_eq!(queue.normal_bytes(), 0, "a refused demand reserves nothing");
        let fits = ClientQueueDemand::new(vec![50, 50])?;
        let held = queue
            .try_reserve(fits)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        assert_eq!(
            queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
            Some(SinkReserveError::Full)
        );
        drop(held);

        queue.begin_slow_consumer_close();
        assert_eq!(queue.closed_reason(), Some(CloseReason::SlowConsumer));
        assert_eq!(
            queue.try_reserve(ClientQueueDemand::new(vec![1])?).err(),
            Some(SinkReserveError::Closed)
        );
        assert!(matches!(
            queue.pop(),
            QueuePop::Closed(CloseReason::SlowConsumer)
        ));
        queue.close(CloseReason::Shutdown, ClosePolicy::AfterFlush);
        assert_eq!(
            queue.closed_reason(),
            Some(CloseReason::SlowConsumer),
            "first reason wins"
        );
        Ok(())
    }

    #[test]
    fn prepare_and_commit_fence_the_generation_and_release_on_close() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(400, 100, 12)?;
        let earlier = queue(&budget, 1, limits)?;
        let later = queue(&budget, 2, limits)?;
        let text = frame(&budget, "hello")?;
        let demand = || ClientQueueDemand::new(vec![text.as_bytes().len()]);

        let foreign = earlier
            .try_reserve(demand()?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        assert_eq!(
            later.prepare(foreign, None).err(),
            Some(QueueAllocationError::Closed)
        );
        assert_eq!(
            earlier.normal_bytes(),
            0,
            "the refused reservation rolled back"
        );

        let tentative = earlier
            .try_reserve(demand()?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let prepared = earlier
            .prepare(tentative, None)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let frames = BoundedSharedClientFrames::for_reservation(&prepared, vec![text.clone()])?;
        earlier.close(CloseReason::TransportLoss, ClosePolicy::Immediate);
        let available_before = budget.available();
        earlier.commit(prepared, frames);
        assert_eq!(
            earlier.normal_bytes(),
            0,
            "commit after close discarded the frame"
        );
        assert!(matches!(
            earlier.pop(),
            QueuePop::Closed(CloseReason::TransportLoss)
        ));
        assert_eq!(budget.available(), available_before);

        let tentative = later
            .try_reserve(demand()?)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        later.close(CloseReason::ClientQuit, ClosePolicy::AfterFlush);
        assert_eq!(
            later.prepare(tentative, None).err(),
            Some(QueueAllocationError::Closed)
        );
        Ok(())
    }

    #[test]
    fn control_reserve_and_warning_follow_the_overload_rules() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(1_200, 400, 12)?;
        let queue = queue(&budget, 1, limits)?;
        let big = frame(&budget, &"x".repeat(150))?;
        let big_len = big.as_bytes().len();
        assert!(big_len > 150 && big_len < 200);

        assert!(!queue.take_warning());
        reserve_and_commit(
            &queue,
            vec![big.clone(), big.clone(), big.clone(), big.clone()],
        )?;
        assert!(queue.normal_bytes() >= limits.warning_bytes());
        assert!(queue.take_warning(), "crossing 75% raised the warning once");
        assert!(!queue.take_warning());

        queue
            .push_control(big.clone())
            .map_err(|_| RuntimeError::LimitExceeded)?;
        queue
            .push_control(big.clone())
            .map_err(|_| RuntimeError::LimitExceeded)?;
        assert_eq!(queue.control_bytes(), big_len * 2);
        assert_eq!(
            queue.push_control(big.clone()).err(),
            Some(SinkReserveError::Full),
            "the control reserve is byte bounded"
        );

        let mut popped = 0;
        while let QueuePop::Frame(_) = queue.pop() {
            popped += 1;
        }
        assert_eq!(popped, 6);
        assert_eq!(queue.control_bytes(), 0);
        assert_eq!(queue.normal_bytes(), 0);

        let slots = self::queue(&budget, 2, limits)?;
        let small = frame(&budget, "s")?;
        for _ in 0..CONTROL_ITEM_SLOTS {
            slots
                .push_control(small.clone())
                .map_err(|_| RuntimeError::LimitExceeded)?;
        }
        assert_eq!(
            slots.push_control(small.clone()).err(),
            Some(SinkReserveError::Full),
            "the control reserve is slot bounded"
        );
        slots.close(CloseReason::Shutdown, ClosePolicy::AfterFlush);
        assert_eq!(
            slots.push_control(small).err(),
            Some(SinkReserveError::Closed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn next_wakes_on_commit_and_on_close() -> Result<(), RuntimeError> {
        let budget = budget();
        let queue = queue(&budget, 1, QueueLimits::new(400, 100, 12)?)?;
        let text = frame(&budget, "wake")?;
        let waiter = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move {
                match queue.next().await {
                    QueuePop::Frame(frame) => frame.as_bytes().len(),
                    _ => 0,
                }
            }
        });
        tokio::task::yield_now().await;
        reserve_and_commit(&queue, vec![text.clone()])?;
        assert_eq!(
            waiter.await.map_err(|_| RuntimeError::Cancelled)?,
            text.as_bytes().len()
        );
        let closer = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { matches!(queue.next().await, QueuePop::Closed(CloseReason::Shutdown)) }
        });
        tokio::task::yield_now().await;
        queue.close(CloseReason::Shutdown, ClosePolicy::AfterFlush);
        assert!(closer.await.map_err(|_| RuntimeError::Cancelled)?);
        Ok(())
    }
}
