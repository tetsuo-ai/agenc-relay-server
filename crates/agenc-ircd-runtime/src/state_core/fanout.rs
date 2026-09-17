//! The Section 15.3 fanout algorithm (spec lines 2210-2260; STA-08, line
//! 6889).
//!
//! StateCore measures every frame without allocating, groups the frames
//! destined for one sink into a single whole-demand reservation, acquires one
//! global permit batch for every distinct encoded buffer and every new queue
//! backing, encodes only into permitted capacity, and commits without
//! allocation. Any failure before commit drops every tentative reservation
//! and permit and changes no protocol or connection state.

use std::collections::BTreeSet;
use std::fmt;

use agenc_ircd_client_wire::{RenderError, RenderedMessage, WireMessage};

use crate::RuntimeError;
use crate::budget::{
    BoundedMemoryCharges, MemoryBudgetPort, MemoryCharge, MemoryChargeAccumulator, MemoryPermit,
    MemoryPermitBatch, PermitCursor,
};
use crate::connection::sink::{
    BoundedSharedClientFrames, ClientQueueDemand, ClientQueueReservation, ClientSink,
    ConnectionGeneration, MAX_DEMAND_BYTES, MAX_DEMAND_FRAMES, QuerySnapshotPermit,
    QueueAllocationError, SinkReserveError, TentativeClientQueueReservation,
};
use crate::sync::Arc;

/// Hard maximum recipients of one fanout: the members-per-channel ceiling
/// (spec 19.2, line 2646).
pub const MAX_FANOUT_TARGETS: usize = 65_535;
/// Hard maximum distinct frames of one fanout: one sink demand's frame bound.
pub const MAX_FANOUT_FRAMES: usize = MAX_DEMAND_FRAMES;

/// One local sink that may receive frames.
pub struct FanoutTarget {
    /// The queue generation the reservation binds to.
    pub generation: ConnectionGeneration,
    /// The output owner.
    pub sink: Arc<dyn ClientSink>,
}

/// One rendering and the targets that receive it.
///
/// Identical renderings share one immutable accounted buffer; every recipient
/// still owns its own queue-item reservation (spec lines 2249-2252).
pub struct FanoutFrame {
    message: WireMessage,
    recipients: Vec<usize>,
}

impl FanoutFrame {
    /// Binds a message plan to a nonempty, duplicate-free recipient index list.
    pub fn new(message: WireMessage, recipients: Vec<usize>) -> Result<Self, RuntimeError> {
        if recipients.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        let mut seen = BTreeSet::new();
        if !recipients.iter().all(|index| seen.insert(*index)) {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self {
            message,
            recipients,
        })
    }

    /// Borrows the message plan.
    #[must_use]
    pub const fn message(&self) -> &WireMessage {
        &self.message
    }

    /// Borrows the recipient indices into the target list.
    #[must_use]
    pub fn recipients(&self) -> &[usize] {
        &self.recipients
    }
}

/// A complete fanout demand: targets plus the frames in final output order.
pub struct FanoutRequest {
    targets: Vec<FanoutTarget>,
    frames: Vec<FanoutFrame>,
}

impl FanoutRequest {
    /// Validates the bounds and every recipient index.
    pub fn new(targets: Vec<FanoutTarget>, frames: Vec<FanoutFrame>) -> Result<Self, RuntimeError> {
        if targets.len() > MAX_FANOUT_TARGETS || frames.len() > MAX_FANOUT_FRAMES {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut generations = BTreeSet::new();
        let targets_are_distinct = targets.iter().all(|target| {
            target.generation == target.sink.generation() && generations.insert(target.generation)
        });
        if !targets_are_distinct {
            return Err(RuntimeError::InvalidValue);
        }
        let in_range = frames
            .iter()
            .flat_map(|frame| frame.recipients.iter())
            .all(|index| *index < targets.len());
        if !in_range {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(Self { targets, frames })
    }

    /// Returns the number of targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Returns the number of distinct frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

/// Why a fanout could not be represented; nothing changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutRefused {
    /// A frame plan could not be measured or encoded.
    Render(RenderError),
    /// The global memory budget refused the permit batch.
    MemoryExhausted,
    /// A sink refused to prepare a reservation it had admitted.
    Prepare(QueueAllocationError),
    /// A bound or invariant of the request was violated.
    Invalid(RuntimeError),
}

impl fmt::Display for FanoutRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Render(error) => write!(formatter, "fanout render failed: {error}"),
            Self::MemoryExhausted => formatter.write_str("fanout memory budget exhausted"),
            Self::Prepare(error) => write!(formatter, "fanout preparation failed: {error}"),
            Self::Invalid(error) => write!(formatter, "fanout request invalid: {error}"),
        }
    }
}

impl std::error::Error for FanoutRefused {}

impl From<RuntimeError> for FanoutRefused {
    fn from(error: RuntimeError) -> Self {
        Self::Invalid(error)
    }
}

impl From<RenderError> for FanoutRefused {
    fn from(error: RenderError) -> Self {
        Self::Render(error)
    }
}

struct FanoutEntry {
    sink: Arc<dyn ClientSink>,
    reservation: ClientQueueReservation,
    frames: BoundedSharedClientFrames,
}

struct SlowConsumer {
    generation: ConnectionGeneration,
    sink: Arc<dyn ClientSink>,
}

/// Every remaining sink reservation plus the sinks marked for slow-consumer
/// close, held until the owning batch commits or drops.
#[must_use = "dropping a fanout reservation rolls back every sink reservation and permit"]
pub struct FanoutReservation {
    entries: Vec<FanoutEntry>,
    slow_consumers: Vec<SlowConsumer>,
    excluded_closed: usize,
    remainder: Option<MemoryPermitBatch>,
}

/// What a committed fanout did.
pub struct FanoutCommitReport {
    /// Sinks that received their complete frame group.
    pub committed_sinks: usize,
    /// Sinks whose slow-consumer close became visible.
    pub slow_consumers_closed: usize,
    /// Sinks skipped because they were already closed.
    pub excluded_closed: usize,
    slow_consumers: Vec<SlowConsumer>,
}

impl FanoutCommitReport {
    /// The report of one group retained behind a response floor: nothing
    /// reached a sink yet, and nothing was closed or excluded.
    #[must_use]
    pub(crate) fn retained() -> Self {
        Self {
            committed_sinks: 0,
            slow_consumers_closed: 0,
            excluded_closed: 0,
            slow_consumers: Vec::new(),
        }
    }

    /// Iterates the generations whose policy close became visible during
    /// this commit.
    pub fn slow_consumer_generations(&self) -> impl Iterator<Item = ConnectionGeneration> + '_ {
        self.slow_consumers
            .iter()
            .map(|consumer| consumer.generation)
    }
}

impl FanoutReservation {
    /// A fanout with no local recipients, valid for objects nobody listens to.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            slow_consumers: Vec::new(),
            excluded_closed: 0,
            remainder: None,
        }
    }

    /// Returns the number of sinks holding a prepared reservation.
    #[must_use]
    pub fn reserved_sinks(&self) -> usize {
        self.entries.len()
    }

    /// Returns the number of sinks on the tentative slow-consumer close list.
    #[must_use]
    pub fn slow_consumer_count(&self) -> usize {
        self.slow_consumers.len()
    }

    /// Returns the number of sinks excluded because they were closed.
    #[must_use]
    pub const fn excluded_closed(&self) -> usize {
        self.excluded_closed
    }

    /// Makes the slow-consumer closes visible and transfers every frame
    /// group into its reserved slots without allocating (spec lines
    /// 2231-2235).
    pub fn commit(self) -> FanoutCommitReport {
        let slow_consumers_closed = self.slow_consumers.len();
        for consumer in &self.slow_consumers {
            consumer.sink.begin_slow_consumer_close();
        }
        let committed_sinks = self.entries.len();
        for entry in self.entries {
            entry.sink.commit(entry.reservation, entry.frames);
        }
        drop(self.remainder);
        FanoutCommitReport {
            committed_sinks,
            slow_consumers_closed,
            excluded_closed: self.excluded_closed,
            slow_consumers: self.slow_consumers,
        }
    }
}

struct Tentative {
    target: usize,
    reservation: TentativeClientQueueReservation,
    frame_indices: Vec<usize>,
}

struct QueuePass {
    tentatives: Vec<Tentative>,
    slow_consumers: Vec<SlowConsumer>,
    excluded_closed: usize,
}

/// Reserves the complete fanout or nothing (spec lines 2210-2235).
pub fn reserve(
    request: &FanoutRequest,
    budget: &dyn MemoryBudgetPort,
) -> Result<FanoutReservation, FanoutRefused> {
    reserve_bounded(request, budget, MAX_DEMAND_BYTES)
}

/// Reserves a fanout while enforcing the live per-response byte ceiling on
/// each sink's exact whole demand.
pub(crate) fn reserve_bounded(
    request: &FanoutRequest,
    budget: &dyn MemoryBudgetPort,
    max_response_batch_bytes: usize,
) -> Result<FanoutReservation, FanoutRefused> {
    reserve_inner(request, budget, max_response_batch_bytes, None)
}

/// Reserves one query response and transfers its immutable-snapshot lease to
/// the destination queue only when that whole response commits.
pub(crate) fn reserve_query(
    request: &FanoutRequest,
    budget: &dyn MemoryBudgetPort,
    max_response_batch_bytes: usize,
    query_snapshot: QuerySnapshotPermit,
) -> Result<FanoutReservation, FanoutRefused> {
    if request.target_count() != 1 {
        return Err(RuntimeError::InvalidValue.into());
    }
    reserve_inner(
        request,
        budget,
        max_response_batch_bytes,
        Some(query_snapshot),
    )
}

fn reserve_inner(
    request: &FanoutRequest,
    budget: &dyn MemoryBudgetPort,
    max_response_batch_bytes: usize,
    mut query_snapshot: Option<QuerySnapshotPermit>,
) -> Result<FanoutReservation, FanoutRefused> {
    if max_response_batch_bytes == 0 || max_response_batch_bytes > MAX_DEMAND_BYTES {
        return Err(RuntimeError::InvalidValue.into());
    }
    let sizes = measure_all(&request.frames)?;
    let pass = reserve_queues(request, &sizes, max_response_batch_bytes)?;
    if pass.tentatives.is_empty() {
        return Ok(FanoutReservation {
            entries: Vec::new(),
            slow_consumers: pass.slow_consumers,
            excluded_closed: pass.excluded_closed,
            remainder: None,
        });
    }
    let needed = needed_frames(&pass.tentatives);
    let charges = permit_charges(&sizes, &needed, &pass.tentatives)?;
    let mut batch = budget
        .try_acquire_batch(charges)
        .map_err(|_| FanoutRefused::MemoryExhausted)?;
    let encoded = encode_frames(&request.frames, &needed, &mut batch)?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(pass.tentatives.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for tentative in pass.tentatives {
        let snapshot = (tentative.target == 0)
            .then(|| query_snapshot.take())
            .flatten();
        entries.push(prepare_entry(
            request, tentative, &encoded, &mut batch, snapshot,
        )?);
    }
    Ok(FanoutReservation {
        entries,
        slow_consumers: pass.slow_consumers,
        excluded_closed: pass.excluded_closed,
        remainder: Some(batch),
    })
}

/// Measures every frame; no frame buffer exists yet (spec lines 2213-2215).
fn measure_all(frames: &[FanoutFrame]) -> Result<Vec<usize>, FanoutRefused> {
    let mut sizes = Vec::new();
    sizes
        .try_reserve_exact(frames.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for frame in frames {
        sizes.push(frame.message.measure()?.bytes());
    }
    Ok(sizes)
}

/// Groups the frames per sink in final order and reserves each sink whole.
fn reserve_queues(
    request: &FanoutRequest,
    sizes: &[usize],
    max_response_batch_bytes: usize,
) -> Result<QueuePass, FanoutRefused> {
    let mut per_target: Vec<Vec<usize>> = request.targets.iter().map(|_| Vec::new()).collect();
    for (index, frame) in request.frames.iter().enumerate() {
        for recipient in &frame.recipients {
            let list = per_target
                .get_mut(*recipient)
                .ok_or(RuntimeError::InvalidValue)?;
            list.push(index);
        }
    }
    let mut pass = QueuePass {
        tentatives: Vec::new(),
        slow_consumers: Vec::new(),
        excluded_closed: 0,
    };
    for (target, frame_indices) in per_target.into_iter().enumerate() {
        if frame_indices.is_empty() {
            continue;
        }
        let entry = request
            .targets
            .get(target)
            .ok_or(RuntimeError::InvalidValue)?;
        let response_bytes = frame_indices.iter().try_fold(0_usize, |total, index| {
            total
                .checked_add(*sizes.get(*index).ok_or(RuntimeError::InvalidValue)?)
                .ok_or(RuntimeError::Overflow)
        })?;
        if response_bytes > max_response_batch_bytes {
            return Err(RuntimeError::LimitExceeded.into());
        }
        let demand = demand_for(&frame_indices, sizes)?;
        match entry.sink.try_reserve(demand) {
            Ok(reservation) => pass.tentatives.push(Tentative {
                target,
                reservation,
                frame_indices,
            }),
            Err(SinkReserveError::Closed) => pass.excluded_closed += 1,
            Err(SinkReserveError::Full) => pass.slow_consumers.push(SlowConsumer {
                generation: entry.generation,
                sink: Arc::clone(&entry.sink),
            }),
        }
    }
    Ok(pass)
}

fn demand_for(
    frame_indices: &[usize],
    sizes: &[usize],
) -> Result<ClientQueueDemand, FanoutRefused> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(frame_indices.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for index in frame_indices {
        bytes.push(*sizes.get(*index).ok_or(RuntimeError::InvalidValue)?);
    }
    Ok(ClientQueueDemand::new(bytes)?)
}

/// The distinct frames at least one remaining sink still needs.
fn needed_frames(tentatives: &[Tentative]) -> BTreeSet<usize> {
    tentatives
        .iter()
        .flat_map(|tentative| tentative.frame_indices.iter().copied())
        .collect()
}

/// One checked batch: every distinct buffer plus every nonzero queue backing
/// (spec lines 2224-2227).
fn permit_charges(
    sizes: &[usize],
    needed: &BTreeSet<usize>,
    tentatives: &[Tentative],
) -> Result<BoundedMemoryCharges, FanoutRefused> {
    let mut charges = MemoryChargeAccumulator::new();
    for index in needed {
        let bytes = *sizes.get(*index).ok_or(RuntimeError::InvalidValue)?;
        let capacity = u64::try_from(bytes).map_err(|_| RuntimeError::Overflow)?;
        charges.try_push(MemoryCharge::allocation(capacity)?)?;
    }
    for tentative in tentatives {
        let backing = tentative.reservation.backing_charge();
        if backing != 0 {
            charges.try_push(MemoryCharge::fixed(backing))?;
        }
    }
    Ok(charges.finish()?)
}

/// Encodes each needed frame exactly once into its permitted capacity.
fn encode_frames(
    frames: &[FanoutFrame],
    needed: &BTreeSet<usize>,
    batch: &mut MemoryPermitBatch,
) -> Result<Vec<Option<Arc<RenderedMessage<MemoryPermit>>>>, FanoutRefused> {
    let mut encoded: Vec<Option<Arc<RenderedMessage<MemoryPermit>>>> = Vec::new();
    encoded
        .try_reserve_exact(frames.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for (index, frame) in frames.iter().enumerate() {
        if !needed.contains(&index) {
            encoded.push(None);
            continue;
        }
        let mut cursor = PermitCursor::new(batch);
        let rendered = frame.message.measure()?.encode(&mut cursor)?;
        encoded.push(Some(Arc::new(rendered)));
    }
    Ok(encoded)
}

/// Pairs one tentative reservation with its backing permit and frame group.
fn prepare_entry(
    request: &FanoutRequest,
    tentative: Tentative,
    encoded: &[Option<Arc<RenderedMessage<MemoryPermit>>>],
    batch: &mut MemoryPermitBatch,
    query_snapshot: Option<QuerySnapshotPermit>,
) -> Result<FanoutEntry, FanoutRefused> {
    let sink = Arc::clone(
        &request
            .targets
            .get(tentative.target)
            .ok_or(RuntimeError::InvalidValue)?
            .sink,
    );
    let backing = match tentative.reservation.backing_charge() {
        0 => None,
        charge => Some(
            batch
                .split_exact(charge)
                .ok_or(RuntimeError::InvalidValue)?,
        ),
    };
    let mut reservation = sink
        .prepare(tentative.reservation, backing)
        .map_err(FanoutRefused::Prepare)?;
    if let Some(snapshot) = query_snapshot {
        reservation = reservation.with_query_snapshot(snapshot);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(tentative.frame_indices.len())
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for index in &tentative.frame_indices {
        let frame = encoded
            .get(*index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::InvalidValue)?;
        frames.push(Arc::clone(frame));
    }
    let frames = BoundedSharedClientFrames::for_reservation(&reservation, frames)?;
    Ok(FanoutEntry {
        sink,
        reservation,
        frames,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::budget::MemoryBudget;
    use crate::connection::sink::{
        ClientQueueReservation, QueueReservationLedger, TentativeClientQueueReservation,
    };

    #[derive(Clone, Copy)]
    enum ReserveMode {
        Admit,
        Full,
        Closed,
    }

    #[derive(Default)]
    struct CountingLedger {
        frames: AtomicUsize,
        bytes: AtomicUsize,
    }

    impl QueueReservationLedger for CountingLedger {
        fn rollback(&self, frames: usize, bytes: usize) {
            self.frames.fetch_add(frames, Ordering::SeqCst);
            self.bytes.fetch_add(bytes, Ordering::SeqCst);
        }
    }

    struct RecordingSink {
        generation: ConnectionGeneration,
        mode: ReserveMode,
        backing_charge: u64,
        ledger: Arc<CountingLedger>,
        commits: AtomicUsize,
        closes: AtomicUsize,
        first_frame: AtomicUsize,
    }

    impl RecordingSink {
        fn new(generation: u64, mode: ReserveMode) -> Arc<Self> {
            Arc::new(Self {
                generation: ConnectionGeneration::new(generation),
                mode,
                backing_charge: 0,
                ledger: Arc::new(CountingLedger::default()),
                commits: AtomicUsize::new(0),
                closes: AtomicUsize::new(0),
                first_frame: AtomicUsize::new(0),
            })
        }

        fn target(self: &Arc<Self>) -> FanoutTarget {
            let sink: Arc<dyn ClientSink> = Arc::clone(self) as Arc<dyn ClientSink>;
            FanoutTarget {
                generation: self.generation,
                sink,
            }
        }
    }

    impl ClientSink for RecordingSink {
        fn generation(&self) -> ConnectionGeneration {
            self.generation
        }

        fn try_reserve(
            &self,
            demand: ClientQueueDemand,
        ) -> Result<TentativeClientQueueReservation, SinkReserveError> {
            match self.mode {
                ReserveMode::Admit => Ok(TentativeClientQueueReservation::new(
                    self.generation,
                    demand,
                    self.backing_charge,
                    Arc::clone(&self.ledger) as Arc<dyn QueueReservationLedger>,
                )),
                ReserveMode::Full => Err(SinkReserveError::Full),
                ReserveMode::Closed => Err(SinkReserveError::Closed),
            }
        }

        fn prepare(
            &self,
            tentative: TentativeClientQueueReservation,
            backing: Option<MemoryPermit>,
        ) -> Result<ClientQueueReservation, QueueAllocationError> {
            ClientQueueReservation::prepare(tentative, backing)
        }

        fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames) {
            self.commits.fetch_add(1, Ordering::SeqCst);
            if let Some(frame) = frames.into_frames().into_iter().next() {
                self.first_frame
                    .store(Arc::as_ptr(&frame) as usize, Ordering::SeqCst);
            }
            reservation.into_transfer().discard();
        }

        fn begin_slow_consumer_close(&self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }

        fn close_after_flush(
            &self,
            _reason: crate::state_core::inbox::CloseReason,
        ) -> crate::connection::FlushAcknowledgement {
            crate::connection::FlushAcknowledgement::complete()
        }

        fn queue_snapshot(&self) -> crate::connection::ClientQueueSnapshot {
            crate::connection::ClientQueueSnapshot::default()
        }
    }

    fn message(text: &str) -> Result<WireMessage, RenderError> {
        WireMessage::new("server.example", "NOTICE", &["nick"], Some(text))
    }

    #[test]
    fn a_successful_fanout_excludes_closed_and_closes_full_sinks() -> Result<(), FanoutRefused> {
        let live = RecordingSink::new(1, ReserveMode::Admit);
        let full = RecordingSink::new(2, ReserveMode::Full);
        let closed = RecordingSink::new(3, ReserveMode::Closed);
        let request = FanoutRequest::new(
            vec![live.target(), full.target(), closed.target()],
            vec![FanoutFrame::new(message("hello")?, vec![0, 1, 2])?],
        )?;
        let budget = MemoryBudget::new(4_096);
        let reservation = reserve(&request, &budget)?;
        assert_eq!(reservation.reserved_sinks(), 1);
        assert_eq!(reservation.slow_consumer_count(), 1);
        assert_eq!(reservation.excluded_closed(), 1);
        assert_eq!(budget.charged(), 4_096);
        let report = reservation.commit();
        assert_eq!(report.committed_sinks, 1);
        assert_eq!(report.slow_consumers_closed, 1);
        assert_eq!(report.excluded_closed, 1);
        assert_eq!(
            report.slow_consumer_generations().collect::<Vec<_>>(),
            vec![ConnectionGeneration::new(2)]
        );
        assert_eq!(live.commits.load(Ordering::SeqCst), 1);
        assert_eq!(full.closes.load(Ordering::SeqCst), 1);
        assert_eq!(closed.closes.load(Ordering::SeqCst), 0);
        assert_eq!(budget.available(), budget.capacity());
        Ok(())
    }

    #[test]
    fn identical_renderings_share_one_accounted_frame_buffer() -> Result<(), FanoutRefused> {
        let first = RecordingSink::new(1, ReserveMode::Admit);
        let second = RecordingSink::new(2, ReserveMode::Admit);
        let request = FanoutRequest::new(
            vec![first.target(), second.target()],
            vec![FanoutFrame::new(message("shared")?, vec![0, 1])?],
        )?;
        let budget = MemoryBudget::new(4_096);
        let reservation = reserve(&request, &budget)?;
        assert_eq!(budget.charged(), 4_096, "one distinct frame is charged");
        reservation.commit();
        let first_frame = first.first_frame.load(Ordering::SeqCst);
        assert_ne!(first_frame, 0);
        assert_eq!(first_frame, second.first_frame.load(Ordering::SeqCst));
        assert_eq!(budget.available(), budget.capacity());
        Ok(())
    }

    #[test]
    fn memory_refusal_rolls_back_every_tentative_and_no_close_becomes_visible()
    -> Result<(), FanoutRefused> {
        let live = RecordingSink::new(1, ReserveMode::Admit);
        let full = RecordingSink::new(2, ReserveMode::Full);
        let request = FanoutRequest::new(
            vec![live.target(), full.target()],
            vec![FanoutFrame::new(message("busy")?, vec![0, 1])?],
        )?;
        assert_eq!(
            reserve(&request, &MemoryBudget::new(0)).err(),
            Some(FanoutRefused::MemoryExhausted)
        );
        assert_eq!(live.ledger.frames.load(Ordering::SeqCst), 1);
        assert_ne!(live.ledger.bytes.load(Ordering::SeqCst), 0);
        assert_eq!(live.commits.load(Ordering::SeqCst), 0);
        assert_eq!(full.closes.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn live_response_byte_ceiling_refuses_before_sink_or_budget_reservation()
    -> Result<(), FanoutRefused> {
        let sink = RecordingSink::new(1, ReserveMode::Admit);
        let request = FanoutRequest::new(
            vec![sink.target()],
            vec![FanoutFrame::new(message("larger than one byte")?, vec![0])?],
        )?;
        let budget = MemoryBudget::new(4_096);
        assert_eq!(
            reserve_bounded(&request, &budget, 1).err(),
            Some(FanoutRefused::Invalid(RuntimeError::LimitExceeded))
        );
        assert_eq!(sink.ledger.frames.load(Ordering::SeqCst), 0);
        assert_eq!(sink.ledger.bytes.load(Ordering::SeqCst), 0);
        assert_eq!(budget.charged(), 0);
        Ok(())
    }

    #[test]
    fn target_generations_are_exact_and_unique() -> Result<(), RuntimeError> {
        let sink = RecordingSink::new(1, ReserveMode::Admit);
        let mismatched: Arc<dyn ClientSink> = Arc::clone(&sink) as Arc<dyn ClientSink>;
        assert_eq!(
            FanoutRequest::new(
                vec![FanoutTarget {
                    generation: ConnectionGeneration::new(2),
                    sink: mismatched,
                }],
                Vec::new(),
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            FanoutRequest::new(vec![sink.target(), sink.target()], Vec::new()).err(),
            Some(RuntimeError::InvalidValue)
        );
        Ok(())
    }
}
