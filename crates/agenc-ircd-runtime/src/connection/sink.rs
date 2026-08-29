//! The client sink contract and its reservation types (spec 24.2, lines
//! 6494-6527; spec 21.3, lines 4093-4106).
//!
//! StateCore reserves a whole ordered frame group on a sink before any
//! object is accepted, acquires one global permit batch for the encoded
//! frames and new queue backing, prepares each reservation with exactly its
//! backing permit, and commits without allocation. Every type here has
//! private fields so a mismatched or duplicated reservation cannot be built.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_client_wire::{MAX_PHYSICAL_LINE_BYTES, MAX_SEMANTIC_REPLIES, RenderedMessage};

use crate::RuntimeError;
use crate::budget::MemoryPermit;
use crate::sync::Arc;

/// Maximum frames in one sink demand: the 512 semantic replies of one
/// logical response plus one batch wrapper each (client-wire
/// `MAX_SEMANTIC_REPLIES`, spec 9.3).
pub const MAX_DEMAND_FRAMES: usize = MAX_SEMANTIC_REPLIES * 2;
/// Maximum bytes in one sink demand: the normal outbound queue hard maximum
/// of 4 MiB (spec 19.2, line 2660).
pub const MAX_DEMAND_BYTES: usize = 4_194_304;

/// Monotonic identity of one accepted connection's queue.
///
/// A reservation names the generation it was taken against, so a queue
/// closed and reused for a later connection can never receive a frame
/// reserved for the earlier one (spec 21.3, lines 4103-4106).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionGeneration(u64);

impl ConnectionGeneration {
    /// Wraps a generation issued by the connection supervisor.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the primitive generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Process-unique token binding prepared frames to their reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationToken(u64);

static NEXT_RESERVATION_TOKEN: AtomicU64 = AtomicU64::new(1);

impl ReservationToken {
    fn next() -> Self {
        // Wrapping after 2^64 reservations is unreachable in any process
        // lifetime; the counter only needs to be unique among live values.
        Self(NEXT_RESERVATION_TOKEN.fetch_add(1, Ordering::Relaxed))
    }
}

/// One complete ordered frame group destined for one sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientQueueDemand {
    frame_bytes: Vec<usize>,
    total_bytes: usize,
}

impl ClientQueueDemand {
    /// Validates a nonempty, count- and byte-bounded list of exact encoded
    /// frame lengths in final output order.
    pub fn new(frame_bytes: Vec<usize>) -> Result<Self, RuntimeError> {
        if frame_bytes.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        if frame_bytes.len() > MAX_DEMAND_FRAMES {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut total_bytes: usize = 0;
        for bytes in &frame_bytes {
            if *bytes == 0 || *bytes > MAX_PHYSICAL_LINE_BYTES {
                return Err(RuntimeError::InvalidValue);
            }
            total_bytes = total_bytes
                .checked_add(*bytes)
                .ok_or(RuntimeError::Overflow)?;
        }
        if total_bytes > MAX_DEMAND_BYTES {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok(Self {
            frame_bytes,
            total_bytes,
        })
    }

    /// Borrows the exact frame lengths in output order.
    #[must_use]
    pub fn frame_bytes(&self) -> &[usize] {
        &self.frame_bytes
    }

    /// Returns the number of frames.
    #[must_use]
    pub fn frame_count(&self) -> usize {
        self.frame_bytes.len()
    }

    /// Returns the checked sum of every frame length.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// Logical count rollback for a reservation that was never committed.
///
/// Sink implementations register their queue ledger here; dropping a
/// tentative or prepared reservation returns its item and byte counts
/// exactly once (spec 21.3, line 4097).
pub trait QueueReservationLedger: Send + Sync {
    /// Releases `frames` item slots and `bytes` logical queue bytes.
    fn rollback(&self, frames: usize, bytes: usize);
}

/// The sink refused a whole demand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkReserveError {
    /// The connection is closing; it is no longer a transport recipient.
    Closed,
    /// The logical byte or item ceiling would be exceeded; the sink joins the
    /// slow-consumer close list.
    Full,
}

impl fmt::Display for SinkReserveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("client sink is closed"),
            Self::Full => formatter.write_str("client sink is full"),
        }
    }
}

/// Preparing a reservation failed before any visible effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueAllocationError {
    /// The supplied permit did not match the exact backing charge.
    PermitMismatch,
    /// The backing allocation could not be created.
    AllocationFailed,
    /// The connection closed between reservation and preparation.
    Closed,
}

impl fmt::Display for QueueAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermitMismatch => formatter.write_str("queue backing permit mismatch"),
            Self::AllocationFailed => formatter.write_str("queue backing allocation failed"),
            Self::Closed => formatter.write_str("client sink closed before preparation"),
        }
    }
}

/// Whole-demand logical reservation on one sink, rolled back on drop.
#[must_use = "dropping a tentative reservation rolls back its logical counts"]
pub struct TentativeClientQueueReservation {
    generation: ConnectionGeneration,
    token: ReservationToken,
    demand: ClientQueueDemand,
    backing_charge: u64,
    ledger: Option<Arc<dyn QueueReservationLedger>>,
}

impl TentativeClientQueueReservation {
    /// Records a reservation the sink has already admitted against its
    /// ledger; `backing_charge` is the exact additional allocation charge,
    /// zero when existing backing suffices.
    pub fn new(
        generation: ConnectionGeneration,
        demand: ClientQueueDemand,
        backing_charge: u64,
        ledger: Arc<dyn QueueReservationLedger>,
    ) -> Self {
        Self {
            generation,
            token: ReservationToken::next(),
            demand,
            backing_charge,
            ledger: Some(ledger),
        }
    }

    /// Returns the queue generation this reservation is bound to.
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    /// Returns the exact additional backing charge, possibly zero.
    #[must_use]
    pub const fn backing_charge(&self) -> u64 {
        self.backing_charge
    }

    /// Borrows the reserved demand.
    #[must_use]
    pub const fn demand(&self) -> &ClientQueueDemand {
        &self.demand
    }

    fn disarm(&mut self) -> Option<Arc<dyn QueueReservationLedger>> {
        self.ledger.take()
    }
}

impl Drop for TentativeClientQueueReservation {
    fn drop(&mut self) {
        if let Some(ledger) = self.ledger.take() {
            ledger.rollback(self.demand.frame_count(), self.demand.total_bytes());
        }
    }
}

/// A tentative reservation paired with exactly its backing permit.
#[must_use = "dropping a prepared reservation rolls back its logical counts and permit"]
pub struct ClientQueueReservation {
    tentative: TentativeClientQueueReservation,
    backing: Option<MemoryPermit>,
}

impl ClientQueueReservation {
    /// Pairs a reservation with its permit: none when the backing charge is
    /// zero, exactly one matching permit otherwise. A mismatch drops the
    /// tentative reservation, rolling the whole demand back.
    pub fn prepare(
        tentative: TentativeClientQueueReservation,
        backing: Option<MemoryPermit>,
    ) -> Result<Self, QueueAllocationError> {
        let matches = match &backing {
            None => tentative.backing_charge() == 0,
            Some(permit) => {
                tentative.backing_charge() != 0 && permit.bytes() == tentative.backing_charge()
            }
        };
        if !matches {
            return Err(QueueAllocationError::PermitMismatch);
        }
        Ok(Self { tentative, backing })
    }

    /// Returns the queue generation this reservation is bound to.
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.tentative.generation()
    }

    /// Borrows the reserved demand.
    #[must_use]
    pub const fn demand(&self) -> &ClientQueueDemand {
        self.tentative.demand()
    }

    /// Returns the token that prepared frames must carry.
    #[must_use]
    pub const fn token(&self) -> ReservationToken {
        self.tentative.token
    }

    /// Transfers the counts and permit to the queue, disarming rollback.
    ///
    /// Only a sink implementation calls this from `commit`; the returned
    /// transfer owns the backing permit for the queue's lifetime.
    pub fn into_transfer(mut self) -> QueueTransfer {
        let ledger = self.tentative.disarm();
        QueueTransfer {
            generation: self.tentative.generation(),
            frame_count: self.tentative.demand().frame_count(),
            total_bytes: self.tentative.demand().total_bytes(),
            backing: self.backing.take(),
            ledger,
        }
    }
}

/// The counts and permit moved into a queue by a committed reservation.
#[must_use]
pub struct QueueTransfer {
    generation: ConnectionGeneration,
    frame_count: usize,
    total_bytes: usize,
    backing: Option<MemoryPermit>,
    ledger: Option<Arc<dyn QueueReservationLedger>>,
}

impl QueueTransfer {
    /// Returns the generation the frames belong to.
    #[must_use]
    pub const fn generation(&self) -> ConnectionGeneration {
        self.generation
    }

    /// Returns the transferred item count.
    #[must_use]
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns the transferred logical bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Takes the backing permit so the queue can hold it beside its storage.
    pub fn take_backing(&mut self) -> Option<MemoryPermit> {
        self.backing.take()
    }

    /// Releases the logical counts and any remaining permit as one operation,
    /// for a commit that arrives after transport cancellation began (spec
    /// 21.3, lines 4104-4106).
    pub fn discard(mut self) {
        if let Some(ledger) = self.ledger.take() {
            ledger.rollback(self.frame_count, self.total_bytes);
        }
        self.backing = None;
    }
}

/// Encoded frames bound to one prepared reservation.
///
/// The only constructor checks every frame length against the reservation's
/// demand, so `ClientSink::commit` never inspects the frames again.
pub struct BoundedSharedClientFrames {
    token: ReservationToken,
    frames: Vec<Arc<RenderedMessage<MemoryPermit>>>,
}

impl BoundedSharedClientFrames {
    /// Binds encoded frames to the reservation they were measured for.
    pub fn for_reservation(
        reservation: &ClientQueueReservation,
        frames: Vec<Arc<RenderedMessage<MemoryPermit>>>,
    ) -> Result<Self, RuntimeError> {
        let expected = reservation.demand().frame_bytes();
        if frames.len() != expected.len() {
            return Err(RuntimeError::InvalidValue);
        }
        for (frame, bytes) in frames.iter().zip(expected) {
            if frame.as_bytes().len() != *bytes {
                return Err(RuntimeError::InvalidValue);
            }
        }
        Ok(Self {
            token: reservation.token(),
            frames,
        })
    }

    /// Returns the token of the reservation these frames belong to.
    #[must_use]
    pub const fn token(&self) -> ReservationToken {
        self.token
    }

    /// Consumes the frames in output order.
    #[must_use]
    pub fn into_frames(self) -> Vec<Arc<RenderedMessage<MemoryPermit>>> {
        self.frames
    }

    /// Returns the number of frames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns whether the group is empty, which construction forbids.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

/// The output owner one connection exposes to StateCore.
pub trait ClientSink: Send + Sync {
    /// Returns the live queue generation.
    fn generation(&self) -> ConnectionGeneration;

    /// Reserves the whole demand or reports the sink closed or full.
    fn try_reserve(
        &self,
        demand: ClientQueueDemand,
    ) -> Result<TentativeClientQueueReservation, SinkReserveError>;

    /// Creates the backing allocation the reservation charged, consuming
    /// exactly the matching permit.
    fn prepare(
        &self,
        tentative: TentativeClientQueueReservation,
        backing: Option<MemoryPermit>,
    ) -> Result<ClientQueueReservation, QueueAllocationError>;

    /// Enqueues the frames into the prepared slots without allocating.
    fn commit(&self, reservation: ClientQueueReservation, frames: BoundedSharedClientFrames);

    /// Marks the connection closing after a full-queue exclusion.
    fn begin_slow_consumer_close(&self);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::budget::{BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge};

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

    fn demand(frames: &[usize]) -> Result<ClientQueueDemand, RuntimeError> {
        ClientQueueDemand::new(frames.to_vec())
    }

    #[test]
    fn demands_reject_empty_oversized_and_over_ceiling_groups() -> Result<(), RuntimeError> {
        assert_eq!(demand(&[]).err(), Some(RuntimeError::InvalidValue));
        assert_eq!(demand(&[0]).err(), Some(RuntimeError::InvalidValue));
        assert_eq!(
            demand(&[MAX_PHYSICAL_LINE_BYTES + 1]).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            ClientQueueDemand::new(vec![1; MAX_DEMAND_FRAMES + 1]).err(),
            Some(RuntimeError::LimitExceeded)
        );
        assert_eq!(
            ClientQueueDemand::new(vec![MAX_PHYSICAL_LINE_BYTES; MAX_DEMAND_FRAMES]).err(),
            Some(RuntimeError::LimitExceeded)
        );
        let accepted = demand(&[MAX_PHYSICAL_LINE_BYTES, 1])?;
        assert_eq!(accepted.frame_count(), 2);
        assert_eq!(accepted.total_bytes(), MAX_PHYSICAL_LINE_BYTES + 1);
        assert_eq!(accepted.frame_bytes(), &[MAX_PHYSICAL_LINE_BYTES, 1]);
        Ok(())
    }

    #[test]
    fn dropping_a_tentative_reservation_rolls_back_exactly_once() -> Result<(), RuntimeError> {
        let ledger = Arc::new(CountingLedger::default());
        let tentative = TentativeClientQueueReservation::new(
            ConnectionGeneration::new(7),
            demand(&[10, 20])?,
            0,
            ledger.clone(),
        );
        assert_eq!(tentative.generation(), ConnectionGeneration::new(7));
        assert_eq!(tentative.backing_charge(), 0);
        assert_eq!(tentative.demand().frame_count(), 2);
        drop(tentative);
        assert_eq!(ledger.frames.load(Ordering::SeqCst), 2);
        assert_eq!(ledger.bytes.load(Ordering::SeqCst), 30);
        Ok(())
    }

    #[test]
    fn prepare_requires_exactly_the_matching_permit() -> Result<(), RuntimeError> {
        let budget = MemoryBudget::new(100_000);
        let mut batch = budget
            .try_acquire_batch(BoundedMemoryCharges::new(vec![MemoryCharge::fixed(8_192)])?)?;
        let ledger = Arc::new(CountingLedger::default());
        let base = demand(&[100])?;
        let charged = || {
            TentativeClientQueueReservation::new(
                ConnectionGeneration::new(1),
                base.clone(),
                4_096,
                ledger.clone(),
            )
        };

        let wrong_size = batch.split_exact(8_192).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            ClientQueueReservation::prepare(charged(), Some(wrong_size)).err(),
            Some(QueueAllocationError::PermitMismatch)
        );
        assert_eq!(
            ClientQueueReservation::prepare(charged(), None).err(),
            Some(QueueAllocationError::PermitMismatch)
        );
        assert_eq!(
            ledger.frames.load(Ordering::SeqCst),
            2,
            "each mismatch rolled back"
        );

        let zero_charge = TentativeClientQueueReservation::new(
            ConnectionGeneration::new(1),
            demand(&[100])?,
            0,
            ledger.clone(),
        );
        let stray = batch.split_exact(0).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            ClientQueueReservation::prepare(zero_charge, Some(stray)).err(),
            Some(QueueAllocationError::PermitMismatch)
        );
        assert_eq!(
            budget.available(),
            100_000,
            "every mismatched permit returned its bytes and the batch is fully split"
        );
        assert_eq!(batch.total(), 0);
        Ok(())
    }

    #[test]
    fn a_committed_transfer_disarms_rollback_and_discard_releases_once() -> Result<(), RuntimeError>
    {
        let budget = MemoryBudget::new(100_000);
        let mut batch = budget
            .try_acquire_batch(BoundedMemoryCharges::new(vec![MemoryCharge::fixed(4_096)])?)?;
        let ledger = Arc::new(CountingLedger::default());
        let tentative = TentativeClientQueueReservation::new(
            ConnectionGeneration::new(3),
            demand(&[50, 60])?,
            4_096,
            ledger.clone(),
        );
        let permit = batch.split_exact(4_096).ok_or(RuntimeError::InvalidValue)?;
        let prepared = ClientQueueReservation::prepare(tentative, Some(permit))
            .map_err(|_| RuntimeError::InvalidValue)?;
        assert_eq!(prepared.generation(), ConnectionGeneration::new(3));
        assert_eq!(prepared.demand().total_bytes(), 110);
        let token = prepared.token();

        let mut transfer = prepared.into_transfer();
        assert_eq!(transfer.generation(), ConnectionGeneration::new(3));
        assert_eq!(transfer.frame_count(), 2);
        assert_eq!(transfer.total_bytes(), 110);
        assert_eq!(
            ledger.frames.load(Ordering::SeqCst),
            0,
            "commit disarmed rollback"
        );
        let backing = transfer.take_backing().ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(backing.bytes(), 4_096);
        assert!(transfer.take_backing().is_none());
        transfer.discard();
        assert_eq!(ledger.frames.load(Ordering::SeqCst), 2);
        assert_eq!(ledger.bytes.load(Ordering::SeqCst), 110);
        drop(backing);
        drop(batch);
        assert_eq!(budget.available(), 100_000);
        assert_ne!(token, ReservationToken(0));
        Ok(())
    }
}
