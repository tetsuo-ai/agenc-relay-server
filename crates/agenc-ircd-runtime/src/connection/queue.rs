//! The owner-side writer queue behind one client sink (spec 15.3, lines
//! 2210-2260; spec 19.2; spec 19.3, lines 2816-2822; spec 21.3, lines
//! 4093-4106).
//!
//! Queue ceilings are logical admission limits, never eager capacity. An idle
//! queue owns no backing allocation beyond the fixed entry ring inside its
//! connection state, which the client connection base charge covers. Each
//! committed demand occupies one ring entry until its final frame drains: a
//! single-frame demand lives in the entry itself, and a larger demand brings
//! one exact-capacity frame storage whose charge the fanout acquires with its
//! frame buffers and `prepare` allocates, so committing never allocates. The
//! storage and its permit leave together when the demand's final frame
//! drains or the queue closes. The ring holds every open response the hard
//! maximum admits plus the control slots. A demand reserved while more
//! demands are open than the open-response ceiling brings one more charged
//! cell instead (`queue/overflow.rs`), so a reservation the counts admit
//! always has a place and the sink is full only at its byte or item ceiling
//! (spec 15.3): a burst of one-line replies or deliveries is never a slow
//! consumer. Entries carry their commit sequence, and the writer drains the
//! ring and the cells in that one order.
//!
//! New reservations use the current runtime byte, item, and response
//! ceilings. A reload does not remove earlier reservations; an increase only
//! admits more charged demands. Normal output may use `client_output_bytes`
//! minus the control reserve; control frames may use the reserved subrange up
//! to the total ceiling. Crossing 75% of the normal ceiling raises one
//! warning; a whole demand that does not fit reports `Full` and the sink joins
//! the slow-consumer close list. No frame is ever evicted for a newer one.

use std::collections::VecDeque;

use tokio::sync::Notify;

mod overflow;

use overflow::OverflowQueue;
pub(crate) use overflow::{OVERFLOW_CELL_CHARGE, OverflowCell};

use super::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientQueueSnapshot,
    ClientSink, ConnectionGeneration, FlushAcknowledgement, MAX_DEMAND_FRAMES, QuerySnapshotPermit,
    QueueAllocationError, QueueReservationLedger, QueueTransfer, SharedClientFrame,
    SinkReserveError, TentativeClientQueueReservation, frame_storage_charge,
};
use crate::RuntimeError;
use crate::budget::MemoryPermit;
use crate::runtime_config::RuntimeConfigHandle;
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
/// Default logical queue items: four maximal fanout demands of 1,024 frames
/// each plus the control slots.
pub const DEFAULT_QUEUE_ITEMS: usize = 4_104;
/// Hard maximum logical queue items: sixteen complete response demands plus
/// the eight control-only slots.
pub const MAX_QUEUE_ITEMS: usize = 16_392;
/// Item slots held back for control frames so a fatal or overload frame
/// always has a slot (spec lines 2748-2756).
pub const CONTROL_ITEM_SLOTS: usize = 8;
/// Open response batches the hard item maximum admits (spec 19.2).
pub const MAX_RESPONSE_BATCHES: usize = (MAX_QUEUE_ITEMS - CONTROL_ITEM_SLOTS) / MAX_DEMAND_FRAMES;
/// Entries in the fixed ring: every admissible response batch plus every
/// control slot.
pub const QUEUE_ENTRY_SLOTS: usize = MAX_RESPONSE_BATCHES + CONTROL_ITEM_SLOTS;
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

    /// Returns the logical item ceiling.
    #[must_use]
    pub const fn items(self) -> usize {
        self.items
    }

    /// Returns the normal-output item slots: total minus the control slots.
    #[must_use]
    pub const fn normal_items(self) -> usize {
        self.items - CONTROL_ITEM_SLOTS
    }

    /// Returns the logical open-response ceiling the normal items represent.
    /// Production profiles allow one maximum-sized demand per configured
    /// response batch; smaller embedding queues still admit one.
    #[must_use]
    pub fn response_batches(self) -> usize {
        self.normal_items().div_ceil(MAX_DEMAND_FRAMES).max(1)
    }

    /// Returns the byte count at which the warning fires.
    #[must_use]
    pub const fn warning_bytes(self) -> usize {
        self.normal_bytes() / 100 * QUEUE_WARNING_PERCENT
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
    Frame(SharedClientFrame),
    /// The queue is closed and holds nothing more to write.
    Closed(CloseReason),
    /// Nothing is queued yet.
    Empty,
}

/// The frames of one committed demand.
enum DemandFrames {
    /// A single frame held in the ring entry; no backing allocation.
    Inline(Option<SharedClientFrame>),
    /// A larger demand in the exact-capacity storage `prepare` created.
    // Fields drop in declaration order: free the storage before its permit.
    Stored {
        frames: VecDeque<SharedClientFrame>,
        _backing: MemoryPermit,
    },
}

impl DemandFrames {
    fn pop_front(&mut self) -> Option<SharedClientFrame> {
        match self {
            Self::Inline(frame) => frame.take(),
            Self::Stored { frames, .. } => frames.pop_front(),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Inline(frame) => frame.is_none(),
            Self::Stored { frames, .. } => frames.is_empty(),
        }
    }
}

/// One committed response batch and the query snapshot it drains.
struct Response {
    sequence: u64,
    frames: DemandFrames,
    query_snapshot: Option<QuerySnapshotPermit>,
}

impl Response {
    /// Places a committed demand's frames: one inline, more in the storage
    /// its reservation prepared. `None` when a multi-frame transfer carries
    /// no fitting storage, which only a foreign reservation can produce.
    fn assemble(
        transfer: &mut QueueTransfer,
        frames: Vec<SharedClientFrame>,
        sequence: u64,
    ) -> Option<Self> {
        let frames = if frames.len() == 1 {
            DemandFrames::Inline(frames.into_iter().next())
        } else {
            let stored = transfer.take_storage()?.fill(frames)?;
            DemandFrames::Stored {
                frames: stored,
                _backing: transfer.take_backing()?,
            }
        };
        Some(Self {
            sequence,
            frames,
            query_snapshot: transfer.take_query_snapshot(),
        })
    }
}

enum Entry {
    Control(u64, SharedClientFrame),
    Response(Response),
}

impl Entry {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Control(sequence, _) => *sequence,
            Self::Response(response) => response.sequence,
        }
    }
}

/// A fixed ring of queue entries stored inside the connection state.
struct EntryRing {
    slots: [Option<Entry>; QUEUE_ENTRY_SLOTS],
    head: usize,
    len: usize,
}

impl EntryRing {
    fn new() -> Self {
        Self {
            slots: [const { None }; QUEUE_ENTRY_SLOTS],
            head: 0,
            len: 0,
        }
    }

    fn slot(&mut self, offset: usize) -> Option<&mut Option<Entry>> {
        self.slots.get_mut((self.head + offset) % QUEUE_ENTRY_SLOTS)
    }

    /// Appends in output order, or returns the entry when the ring is full.
    fn push_back(&mut self, entry: Entry) -> Result<(), Entry> {
        if self.len == QUEUE_ENTRY_SLOTS {
            return Err(entry);
        }
        let len = self.len;
        match self.slot(len) {
            Some(slot) => {
                *slot = Some(entry);
                self.len += 1;
                Ok(())
            }
            None => Err(entry),
        }
    }

    fn pop_front(&mut self) -> Option<Entry> {
        if self.len == 0 {
            return None;
        }
        let entry = self.slot(0)?.take();
        self.head = (self.head + 1) % QUEUE_ENTRY_SLOTS;
        self.len -= 1;
        entry
    }

    /// Puts a partly drained entry back into the slot `pop_front` just freed.
    fn restore_front(&mut self, entry: Entry) {
        self.head = (self.head + QUEUE_ENTRY_SLOTS - 1) % QUEUE_ENTRY_SLOTS;
        // The head slot always exists; the ring index is reduced modulo its length.
        let restored = self.slot(0).map(|slot| *slot = Some(entry)).is_some();
        self.len += usize::from(restored);
    }

    fn clear(&mut self) {
        while self.pop_front().is_some() {}
        self.head = 0;
    }

    fn front_sequence(&self) -> Option<u64> {
        let slot = self.slots.get(self.head % QUEUE_ENTRY_SLOTS)?;
        slot.as_ref().map(Entry::sequence)
    }

    fn largest_query_rows(&self) -> u64 {
        self.slots
            .iter()
            .flatten()
            .filter_map(|entry| match entry {
                Entry::Response(response) => response.query_snapshot.as_ref(),
                Entry::Control(..) => None,
            })
            .map(QuerySnapshotPermit::rows)
            .max()
            .unwrap_or(0)
    }
}

/// Where an admitted demand will be committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Placement {
    /// A fixed ring entry; no allocation.
    Ring,
    /// One charged overflow cell behind the ring.
    Beyond,
}

struct QueueState {
    entries: EntryRing,
    overflow: OverflowQueue,
    next_sequence: u64,
    close_notice: Option<SharedClientFrame>,
    normal_bytes: usize,
    normal_items: usize,
    control_bytes: usize,
    control_items: usize,
    normal_batches: usize,
    query_snapshots: u64,
    query_rows: u64,
    query_bytes: u64,
    largest_query_rows: u64,
    closed: Option<CloseReason>,
    close_started: Option<tokio::time::Instant>,
    warning_armed: bool,
    warning_pending: bool,
    flush_acknowledgement: Option<FlushAcknowledgement>,
}

impl QueueState {
    fn retain_query_snapshot(&mut self, rows: u64, bytes: u64) {
        // StateCore admits these values below the configured hard maxima, so
        // saturation is unreachable in valid state. Keeping the update total
        // preserves the queue commit contract even if that invariant is ever
        // violated: a prepared transfer is never silently discarded here.
        self.query_snapshots = self.query_snapshots.saturating_add(1);
        self.query_rows = self.query_rows.saturating_add(rows);
        self.query_bytes = self.query_bytes.saturating_add(bytes);
        self.largest_query_rows = self.largest_query_rows.max(rows);
    }

    fn release_query_snapshot(&mut self, snapshot: &QuerySnapshotPermit) {
        self.query_snapshots = self.query_snapshots.saturating_sub(1);
        self.query_rows = self.query_rows.saturating_sub(snapshot.rows());
        self.query_bytes = self.query_bytes.saturating_sub(snapshot.bytes());
        if snapshot.rows() == self.largest_query_rows {
            let beyond = self
                .overflow
                .responses()
                .filter_map(|response| response.query_snapshot.as_ref())
                .map(QuerySnapshotPermit::rows)
                .max()
                .unwrap_or(0);
            self.largest_query_rows = self.entries.largest_query_rows().max(beyond);
        }
    }

    fn take_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.wrapping_add(1);
        sequence
    }

    /// Discards every queued frame and releases its counts and permits.
    fn discard_all(&mut self) {
        self.entries.clear();
        self.overflow.clear();
        self.normal_bytes = 0;
        self.normal_items = 0;
        self.control_bytes = 0;
        self.control_items = 0;
        self.normal_batches = 0;
        self.query_snapshots = 0;
        self.query_rows = 0;
        self.query_bytes = 0;
        self.largest_query_rows = 0;
    }

    /// Enqueues one control frame when the control reserve has room.
    fn push_control(
        &mut self,
        frame: SharedClientFrame,
        limits: QueueLimits,
    ) -> Result<(), SinkReserveError> {
        let next_bytes = self
            .control_bytes
            .checked_add(frame.as_bytes().len())
            .ok_or(SinkReserveError::Full)?;
        if next_bytes > limits.control_bytes() || self.control_items >= CONTROL_ITEM_SLOTS {
            return Err(SinkReserveError::Full);
        }
        let sequence = self.next_sequence;
        if self
            .entries
            .push_back(Entry::Control(sequence, frame))
            .is_err()
        {
            return Err(SinkReserveError::Full);
        }
        self.next_sequence = sequence.wrapping_add(1);
        self.control_bytes = next_bytes;
        self.control_items += 1;
        Ok(())
    }

    /// Whether the oldest queued frame lives beyond the ring.
    fn oldest_is_beyond(&mut self) -> bool {
        match (
            self.entries.front_sequence(),
            self.overflow.front_sequence(),
        ) {
            (Some(ring), Some(beyond)) => beyond < ring,
            (None, Some(_)) => true,
            _ => false,
        }
    }

    /// Takes the next frame of the oldest overflow demand; its cell, frame
    /// storage, permit, batch count, and query snapshot leave with its final
    /// frame.
    fn pop_overflow_frame(&mut self) -> Option<SharedClientFrame> {
        let response = self.overflow.front_response()?;
        let frame = response.frames.pop_front()?;
        let drained = response.frames.is_empty();
        let snapshot = drained.then(|| response.query_snapshot.take()).flatten();
        self.normal_items = self.normal_items.saturating_sub(1);
        self.normal_bytes = self.normal_bytes.saturating_sub(frame.as_bytes().len());
        if drained {
            self.normal_batches = self.normal_batches.saturating_sub(1);
            self.overflow.remove_front();
        }
        if let Some(snapshot) = snapshot.as_ref() {
            self.release_query_snapshot(snapshot);
        }
        Some(frame)
    }

    /// Dequeues the next frame in output order and releases its logical
    /// counts exactly once.
    fn pop_frame(&mut self) -> Option<SharedClientFrame> {
        if self.oldest_is_beyond() {
            return self.pop_overflow_frame();
        }
        match self.entries.pop_front()? {
            Entry::Control(_, frame) => {
                self.control_items = self.control_items.saturating_sub(1);
                self.control_bytes = self.control_bytes.saturating_sub(frame.as_bytes().len());
                Some(frame)
            }
            Entry::Response(response) => self.pop_response_frame(response),
        }
    }

    /// Places a committed response in its prepared cell, or in the ring
    /// entry its ring placement guaranteed.
    fn place(&mut self, transfer: &mut QueueTransfer, response: Response) -> bool {
        match transfer.take_cell() {
            Some(cell) => self
                .overflow
                .push_back(cell, response, transfer.take_backing())
                .is_ok(),
            None => self.entries.push_back(Entry::Response(response)).is_ok(),
        }
    }

    /// Takes a response's next frame. The response returns to the front of
    /// the ring while frames remain; its storage, permit, batch slot, and
    /// query snapshot leave with its final frame.
    fn pop_response_frame(&mut self, mut response: Response) -> Option<SharedClientFrame> {
        // Every placed response holds at least one frame: `assemble` takes a
        // nonempty bound group and a drained response is never restored.
        let frame = response.frames.pop_front()?;
        self.normal_items = self.normal_items.saturating_sub(1);
        self.normal_bytes = self.normal_bytes.saturating_sub(frame.as_bytes().len());
        if response.frames.is_empty() {
            self.normal_batches = self.normal_batches.saturating_sub(1);
            if let Some(snapshot) = response.query_snapshot.as_ref() {
                self.release_query_snapshot(snapshot);
            }
        } else {
            self.entries.restore_front(Entry::Response(response));
        }
        Some(frame)
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
        state.normal_batches = state.normal_batches.saturating_sub(1);
    }
}

/// The writer queue of one admitted connection.
pub struct WriterQueue {
    #[cfg(feature = "wss")]
    registration_started: std::sync::OnceLock<std::time::Instant>,
    generation: ConnectionGeneration,
    limits: QueueLimits,
    runtime_config: Option<RuntimeConfigHandle>,
    shared: Arc<QueueShared>,
}

impl WriterQueue {
    #[cfg(feature = "wss")]
    pub(crate) fn set_registration_started(&self, started: std::time::Instant) {
        let _ = self.registration_started.set(started);
    }

    /// Creates an empty queue. It owns no backing allocation until a
    /// charged multi-frame demand commits.
    pub fn new(
        generation: ConnectionGeneration,
        limits: QueueLimits,
    ) -> Result<Arc<Self>, RuntimeError> {
        Self::new_with_runtime_config(generation, limits, None)
    }

    pub(crate) fn new_live(
        generation: ConnectionGeneration,
        limits: QueueLimits,
        runtime_config: RuntimeConfigHandle,
    ) -> Result<Arc<Self>, RuntimeError> {
        Self::new_with_runtime_config(generation, limits, Some(runtime_config))
    }

    fn new_with_runtime_config(
        generation: ConnectionGeneration,
        limits: QueueLimits,
        runtime_config: Option<RuntimeConfigHandle>,
    ) -> Result<Arc<Self>, RuntimeError> {
        Ok(Arc::new(Self {
            #[cfg(feature = "wss")]
            registration_started: std::sync::OnceLock::new(),
            generation,
            limits,
            runtime_config,
            shared: Arc::new(QueueShared {
                state: Mutex::new(QueueState {
                    entries: EntryRing::new(),
                    overflow: OverflowQueue::default(),
                    next_sequence: 0,
                    close_notice: None,
                    normal_bytes: 0,
                    normal_items: 0,
                    control_bytes: 0,
                    control_items: 0,
                    normal_batches: 0,
                    query_snapshots: 0,
                    query_rows: 0,
                    query_bytes: 0,
                    largest_query_rows: 0,
                    closed: None,
                    close_started: None,
                    warning_armed: true,
                    warning_pending: false,
                    flush_acknowledgement: None,
                }),
                notify: Notify::new(),
            }),
        }))
    }

    /// Returns the current byte, item, and response ceilings.
    #[must_use]
    pub fn limits(&self) -> QueueLimits {
        self.current_limits()
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

    /// Returns when the first close began, even when later callers close again.
    pub(super) fn close_started(&self) -> Option<tokio::time::Instant> {
        lock(&self.shared.state).close_started
    }

    /// Takes the one pending slow-consumer warning, if it fired.
    #[must_use]
    pub fn take_warning(&self) -> bool {
        let mut state = lock(&self.shared.state);
        std::mem::take(&mut state.warning_pending)
    }

    /// Enqueues one control frame inside the control reserve, bypassing the
    /// normal ceiling (spec lines 2750-2756).
    pub fn push_control(&self, frame: SharedClientFrame) -> Result<(), SinkReserveError> {
        let limits = self.current_limits();
        let mut state = lock(&self.shared.state);
        if state.closed.is_some() {
            return Err(SinkReserveError::Closed);
        }
        state.push_control(frame, limits)?;
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
            state.close_started = Some(tokio::time::Instant::now());
        }
        if policy == ClosePolicy::Immediate {
            state.discard_all();
        }
        drop(state);
        self.shared.notify.notify_one();
    }

    /// Completes the pending orderly-shutdown acknowledgement after the
    /// writer has attempted its final transport flush.
    pub fn acknowledge_flush(&self) {
        let acknowledgement = lock(&self.shared.state)
            .flush_acknowledgement
            .get_or_insert_with(FlushAcknowledgement::pending)
            .clone();
        acknowledgement.acknowledge();
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
        if let Some(frame) = state.pop_frame() {
            return QueuePop::Frame(frame);
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

    /// Admits a whole demand against the byte and item ceilings, the only
    /// ceilings that make a sink full (spec 15.3). The open-response ceiling
    /// decides where the demand lives, never whether it is admitted: within
    /// it the demand takes a fixed ring entry, beyond it one charged cell.
    /// A ring placement is granted only while every open demand fits the
    /// ring, so a ring demand always finds its entry at commit.
    fn admit_normal(
        state: &mut QueueState,
        demand: &ClientQueueDemand,
        limits: QueueLimits,
        response_batches: usize,
    ) -> Option<Placement> {
        let next_items = state.normal_items.checked_add(demand.frame_count())?;
        let next_bytes = state.normal_bytes.checked_add(demand.total_bytes())?;
        let next_batches = state.normal_batches.checked_add(1)?;
        if next_items > limits.normal_items() || next_bytes > limits.normal_bytes() {
            return None;
        }
        state.normal_items = next_items;
        state.normal_bytes = next_bytes;
        state.normal_batches = next_batches;
        if state.warning_armed && next_bytes >= limits.warning_bytes() {
            state.warning_armed = false;
            state.warning_pending = true;
        }
        if next_batches > response_batches.min(MAX_RESPONSE_BATCHES) {
            Some(Placement::Beyond)
        } else {
            Some(Placement::Ring)
        }
    }

    fn current_limits(&self) -> QueueLimits {
        self.current_admission_limits().0
    }

    fn current_admission_limits(&self) -> (QueueLimits, usize) {
        let Some(runtime_config) = &self.runtime_config else {
            return (self.limits, self.limits.response_batches());
        };
        let current = runtime_config.load().connection_limits().queue;
        (current, current.response_batches())
    }
}

impl ClientSink for WriterQueue {
    #[cfg(feature = "wss")]
    fn registration_elapsed_millis(&self) -> u64 {
        self.registration_started.get().map_or(0, |started| {
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
        })
    }

    fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
        let (limits, response_batches) = self.current_admission_limits();
        let mut state = lock(&self.shared.state);
        if state.closed.is_some() {
            return Err(SinkReserveError::Closed);
        }
        let placement = Self::admit_normal(&mut state, &demand, limits, response_batches)
            .ok_or(SinkReserveError::Full)?;
        drop(state);
        let backing_charge = frame_storage_charge(demand.frame_count());
        let ledger: Arc<dyn QueueReservationLedger> = self.shared.clone();
        let tentative =
            TentativeClientQueueReservation::new(self.generation, demand, backing_charge, ledger);
        Ok(match placement {
            Placement::Ring => tentative,
            Placement::Beyond => tentative.beyond_fixed_entries(),
        })
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
        let bound = frames.token() == reservation.token();
        let mut transfer = reservation.into_transfer();
        let mut state = lock(&self.shared.state);
        if !bound || state.closed.is_some() || transfer.generation() != self.generation {
            drop(state);
            transfer.discard();
            return;
        }
        let usage = transfer.query_snapshot_usage();
        let sequence = state.take_sequence();
        let placed = Response::assemble(&mut transfer, frames.into_frames(), sequence)
            .map(|response| state.place(&mut transfer, response));
        if !matches!(placed, Some(true)) {
            // Only a foreign reservation can arrive without fitting storage
            // or an entry. Exclude the whole sink rather than drop a frame.
            drop(state);
            transfer.discard();
            self.begin_slow_consumer_close();
            return;
        }
        if let Some((rows, bytes)) = usage {
            state.retain_query_snapshot(rows, bytes);
        }
        drop(state);
        drop(transfer);
        self.shared.notify.notify_one();
    }

    fn begin_forced_close(&self) {
        self.close(CloseReason::SlowConsumer, ClosePolicy::Immediate);
    }

    fn arm_slow_consumer_notice(&self, notice: SharedClientFrame) {
        lock(&self.shared.state).close_notice = Some(notice);
    }

    /// Destroys the whole queue and, on the first close, leaves only the
    /// armed `ERROR` line in the reserved control slot for the writer to
    /// deliver before it closes the transport (spec 1.2; spec 19.3).
    fn begin_slow_consumer_close(&self) {
        let limits = self.current_limits();
        let mut state = lock(&self.shared.state);
        let first_close = state.closed.is_none();
        if first_close {
            state.closed = Some(CloseReason::SlowConsumer);
            state.close_started = Some(tokio::time::Instant::now());
        }
        state.discard_all();
        if let Some(notice) = state.close_notice.take().filter(|_| first_close) {
            // The reserve was just emptied, so only a notice larger than the
            // whole control reserve is dropped; the close never waits on it.
            let _queued = state.push_control(notice, limits);
        }
        drop(state);
        self.shared.notify.notify_one();
    }

    fn close_after_flush(&self, reason: CloseReason) -> FlushAcknowledgement {
        let mut state = lock(&self.shared.state);
        let acknowledgement = state
            .flush_acknowledgement
            .get_or_insert_with(FlushAcknowledgement::pending)
            .clone();
        if state.closed.is_none() {
            state.closed = Some(reason);
            state.close_started = Some(tokio::time::Instant::now());
        }
        drop(state);
        self.shared.notify.notify_one();
        acknowledgement
    }

    fn queue_snapshot(&self) -> ClientQueueSnapshot {
        let limits = self.current_limits();
        let state = lock(&self.shared.state);
        ClientQueueSnapshot::with_query_usage(
            u64::try_from(state.normal_bytes + state.control_bytes).unwrap_or(u64::MAX),
            u64::try_from(limits.total_bytes()).unwrap_or(u64::MAX),
            state.query_snapshots,
            state.query_rows,
            state.query_bytes,
            state.largest_query_rows,
            state.query_snapshots,
        )
    }
}

#[cfg(test)]
#[path = "queue/tests/backing.rs"]
mod backing_tests;

#[cfg(test)]
mod tests {
    use agenc_ircd_client_wire::{RenderedMessage, WireMessage};

    use super::*;
    use crate::budget::{
        BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, PermitCursor,
    };

    fn budget() -> MemoryBudget {
        MemoryBudget::new(64 * 1_048_576)
    }

    fn queue(
        _budget: &MemoryBudget,
        generation: u64,
        limits: QueueLimits,
    ) -> Result<Arc<WriterQueue>, RuntimeError> {
        WriterQueue::new(ConnectionGeneration::new(generation), limits)
    }

    fn frame(
        budget: &MemoryBudget,
        text: &str,
    ) -> Result<Arc<RenderedMessage<MemoryPermit>>, RuntimeError> {
        let message = WireMessage::new("server.test", "NOTICE", &["*"], Some(text))
            .map_err(|_| RuntimeError::InvalidValue)?;
        let measured = message.measure().map_err(|_| RuntimeError::InvalidValue)?;
        let bytes = u64::try_from(measured.bytes()).map_err(|_| RuntimeError::Overflow)?;
        let mut batch =
            budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::allocation(
                bytes,
            )?])?)?;
        let rendered = measured
            .encode(&mut PermitCursor::new(&mut batch))
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(Arc::new(rendered))
    }

    /// The exact permit a tentative reservation's backing charge names.
    fn backing(budget: &MemoryBudget, charge: u64) -> Result<Option<MemoryPermit>, RuntimeError> {
        if charge == 0 {
            return Ok(None);
        }
        let mut batch =
            budget.try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(charge)])?)?;
        Ok(Some(
            batch
                .split_exact(charge)
                .ok_or(RuntimeError::InvalidValue)?,
        ))
    }

    fn prepared(
        budget: &MemoryBudget,
        queue: &WriterQueue,
        demand: ClientQueueDemand,
    ) -> Result<ClientQueueReservation, RuntimeError> {
        let tentative = queue
            .try_reserve(demand)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let permit = backing(budget, tentative.backing_charge())?;
        queue
            .prepare(tentative, permit)
            .map_err(|_| RuntimeError::InvalidValue)
    }

    fn reserve_and_commit(
        budget: &MemoryBudget,
        queue: &WriterQueue,
        frames: Vec<Arc<RenderedMessage<MemoryPermit>>>,
    ) -> Result<(), RuntimeError> {
        let demand = ClientQueueDemand::new(frames.iter().map(|f| f.as_bytes().len()).collect())?;
        let prepared = prepared(budget, queue, demand)?;
        let bound = BoundedSharedClientFrames::for_reservation(&prepared, frames)?;
        queue.commit(prepared, bound);
        Ok(())
    }

    #[test]
    #[cfg(feature = "wss")]
    fn tls_registration_start_is_immutable_and_tcp_elapsed_stays_zero() -> Result<(), RuntimeError>
    {
        let budget = budget();
        let queue = queue(&budget, 1, QueueLimits::DEFAULT)?;
        assert_eq!(queue.registration_elapsed_millis(), 0);
        let now = std::time::Instant::now();
        queue.set_registration_started(
            now.checked_sub(std::time::Duration::from_secs(31))
                .ok_or(RuntimeError::InvalidValue)?,
        );
        assert!(queue.registration_elapsed_millis() >= 31_000);
        queue.set_registration_started(now);
        assert!(queue.registration_elapsed_millis() >= 31_000);
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
        assert_eq!(limits.response_batches(), 4);
        assert_eq!(MAX_RESPONSE_BATCHES, 16);
        assert_eq!(QUEUE_ENTRY_SLOTS, 24);
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
    fn an_idle_queue_holds_no_backing_charge() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::DEFAULT;
        let queue = queue(&budget, 1, limits)?;
        assert_eq!(budget.available(), budget.capacity());
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
        assert_eq!(tentative.backing_charge(), 4_096);
        assert_eq!(queue.normal_bytes(), len);
        drop(tentative);
        assert_eq!(queue.normal_bytes(), 0, "drop rolled the counts back");

        assert!(matches!(queue.pop(), QueuePop::Empty));
        reserve_and_commit(&budget, &queue, vec![first.clone(), second.clone()])?;
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
    fn a_ring_entry_returns_only_after_its_final_frame() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(400, 100, 12)?;
        let queue = queue(&budget, 1, limits)?;
        let first = frame(&budget, "first")?;
        let last = frame(&budget, "last")?;
        reserve_and_commit(&budget, &queue, vec![first, last])?;

        let beyond = |queue: &WriterQueue| -> Result<u64, RuntimeError> {
            let reserved = queue
                .try_reserve(ClientQueueDemand::new(vec![1])?)
                .map_err(|_| RuntimeError::LimitExceeded)?;
            Ok(reserved.backing_charge())
        };
        assert_eq!(beyond(&queue)?, OVERFLOW_CELL_CHARGE);
        let _first = queue.pop();
        assert_eq!(beyond(&queue)?, OVERFLOW_CELL_CHARGE);
        let _last = queue.pop();
        assert_eq!(beyond(&queue)?, 0, "the drained demand returned its entry");
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
        reserve_and_commit(&budget, &queue, vec![output])?;

        assert_eq!(
            queue.queue_snapshot(),
            ClientQueueSnapshot::new(output_bytes, 400)
        );
        let _popped = queue.pop();
        assert_eq!(queue.queue_snapshot(), ClientQueueSnapshot::new(0, 400));
        Ok(())
    }

    #[test]
    fn query_snapshot_lease_drains_only_with_its_final_frame() -> Result<(), RuntimeError> {
        let budget = budget();
        let limits = QueueLimits::new(400, 100, 12)?;
        let queue = queue(&budget, 1, limits)?;
        let first = frame(&budget, "first query row")?;
        let last = frame(&budget, "last query row")?;
        let demand = ClientQueueDemand::new(vec![first.as_bytes().len(), last.as_bytes().len()])?;
        let tentative = queue
            .try_reserve(demand)
            .map_err(|_| RuntimeError::LimitExceeded)?;
        let snapshot_charge = MemoryCharge::allocation(8_000)?;
        let mut snapshot_batch =
            budget.try_acquire_batch(BoundedMemoryCharges::new(&[snapshot_charge])?)?;
        let snapshot_backing = snapshot_batch
            .split_exact(snapshot_charge.bytes())
            .ok_or(RuntimeError::InvalidValue)?;
        let permit = backing(&budget, tentative.backing_charge())?;
        let prepared = queue
            .prepare(tentative, permit)
            .map_err(|_| RuntimeError::InvalidValue)?
            .with_query_snapshot(QuerySnapshotPermit::new(17, snapshot_backing));
        let bound = BoundedSharedClientFrames::for_reservation(&prepared, vec![first, last])?;
        queue.commit(prepared, bound);

        let live = queue.queue_snapshot();
        assert_eq!(live.query_snapshots(), 1);
        assert_eq!(live.query_rows(), 17);
        assert_eq!(live.query_bytes(), snapshot_charge.bytes());
        assert_eq!(live.largest_query_rows(), 17);
        assert_eq!(live.max_query_snapshots_per_session(), 1);

        let _first = queue.pop();
        assert_eq!(queue.queue_snapshot().query_snapshots(), 1);
        let _last = queue.pop();
        let drained = queue.queue_snapshot();
        assert_eq!(drained.query_snapshots(), 0);
        assert_eq!(drained.query_rows(), 0);
        assert_eq!(drained.query_bytes(), 0);
        assert_eq!(drained.largest_query_rows(), 0);
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
    fn reasoned_after_flush_keeps_accepted_frames_and_first_reason() -> Result<(), RuntimeError> {
        let budget = budget();
        let queue = queue(&budget, 1, QueueLimits::new(400, 100, 12)?)?;
        let accepted = frame(&budget, "credential changed")?;
        reserve_and_commit(&budget, &queue, vec![accepted.clone()])?;

        let acknowledgement = queue.close_after_flush(CloseReason::ClientQuit);
        assert!(!acknowledgement.is_acknowledged());
        let repeated = queue.close_after_flush(CloseReason::Shutdown);
        repeated.acknowledge();
        assert!(acknowledgement.is_acknowledged());
        assert_eq!(queue.closed_reason(), Some(CloseReason::ClientQuit));
        let QueuePop::Frame(frame) = queue.pop() else {
            return Err(RuntimeError::InvalidValue);
        };
        assert!(Arc::ptr_eq(&frame, &accepted));
        assert!(matches!(
            queue.pop(),
            QueuePop::Closed(CloseReason::ClientQuit)
        ));
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
            &budget,
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
        reserve_and_commit(&budget, &queue, vec![text.clone()])?;
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
