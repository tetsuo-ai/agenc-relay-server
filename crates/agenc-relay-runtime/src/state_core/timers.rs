//! The one indexed timer heap owned by StateCore and the wall-clock drift
//! monitor (spec 21.6, lines 4219-4238).
//!
//! Every deadline is an entry `(monotonic_deadline, timer_kind, typed_id,
//! generation)` in one min-heap; there is no task per timer. Rescheduling or
//! cancelling a key bumps its generation, and entries whose generation is
//! stale are ignored when they surface.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

use agenc_relay_types::{
    AccountId, ChannelInstanceId, InviteId, MonotonicTick, ServerId, TransactionId, UserId,
    UtcSecond,
};

use crate::RuntimeError;
use crate::connection::sink::ConnectionGeneration;

/// Ceiling on heap entries, stale ones included: eight per hard-maximum
/// client connection (spec line 2641) plus the 1,000,000 network-wide
/// invitations (spec line 2653) rounded to a power of two.
pub const MAX_TIMER_ENTRIES: usize = 4_194_304;
/// The secret-channel minimum response time, five milliseconds (spec line
/// 1918).
pub const SECRET_CHANNEL_FLOOR_MILLIS: u64 = 5;
/// Wall-versus-monotonic comparison interval, one minute (spec line 4229).
pub const DRIFT_CHECK_INTERVAL_MILLIS: u64 = 60_000;
/// Largest wall-versus-monotonic disagreement treated as agreement (spec
/// line 4236).
pub const DRIFT_TOLERANCE_SECONDS: u64 = 1;
/// Continuous disagreement that marks wall time untrusted (spec line 4231).
pub const DRIFT_DISTRUST_MILLIS: u64 = 300_000;
/// Continuous agreement required to trust wall time again (spec line 4235).
pub const DRIFT_RECOVERY_MILLIS: u64 = 600_000;

/// Closed timer kinds (spec lines 4219-4222).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimerKind {
    /// TLS-complete to registration-complete deadline (spec line 517).
    RegistrationDeadline,
    /// Idle time before the server PING (spec line 519).
    Ping,
    /// PING to PONG deadline (spec line 520).
    Pong,
    /// Invitation expiry.
    InviteExpiry,
    /// Nickname or queue reservation expiry.
    Reservation,
    /// Sanction expiry.
    Sanction,
    /// Account-deletion challenge expiry.
    DeletionChallenge,
    /// Fragment assembly deadline.
    Fragment,
    /// Response batch expiry.
    Batch,
    /// History retention boundary.
    HistoryExpiry,
    /// Idempotency row expiry.
    IdempotencyExpiry,
    /// Federation reconnect trigger.
    Reconnect,
    /// The five-millisecond secret-channel response floor.
    SecretChannelFloor,
    /// The fixed 30-second pre-commit command deadline (spec line 2624).
    CommandDeadline,
    /// The fixed origin grace interval after a federation link is lost.
    FederationGrace,
    /// One paced retry after definite edge journal admission refusal.
    FederationJournalRetry,
    /// The pacing step between snapshot entry sends.
    FederationSnapshotSend,
    /// The fixed snapshot token lifetime.
    FederationSnapshotExpiry,
    /// One paced retained-cursor validation or durable reconciliation step.
    FederationResumeRetry,
    /// The companion ECAP negotiation deadline of one link.
    CompanionProfileDeadline,
    /// A companion ESTATE snapshot token lifetime.
    CompanionSnapshotExpiry,
    /// Bounded offline companion replay expiry and storage-refusal retry.
    CompanionReplayMaintenance,
    /// Bounded durable mailbox expiry, including idle nodes without federation peers.
    CompanionMailboxMaintenance,
    /// Bounded expiry of completed companion request results and replay metadata.
    CompanionRequestMaintenance,
    /// Bounded physical deletion of expired unowned companion objects.
    CompanionObjectMaintenance,
    /// The reserved retry wake for an edge's pending witness metadata.
    CompanionWitnessRetry,
    /// The wake that repeats an unanswered `EWITNESS REQUEST` (12.5.1).
    CompanionWitnessResolution,
    /// Expiry of process-local mailbox cursors and their immutable backing.
    MailboxSnapshotExpiry,
    /// Expiry of process-local companion listing cursors and their immutable cuts.
    ListingSnapshotExpiry,
    /// Expiry of process-local base federation directory query backing.
    DirectoryQueryExpiry,
}

/// Typed identity a timer entry names; never a protocol string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TimedId {
    /// One connection generation.
    Connection(ConnectionGeneration),
    /// One registered session.
    Session(UserId),
    /// One account.
    Account(AccountId),
    /// One channel instance.
    Channel(ChannelInstanceId),
    /// One invitation.
    Invite(InviteId),
    /// One transaction.
    Transaction(TransactionId),
    /// One federation peer.
    Peer(ServerId),
    /// One process-local batch or sequence number.
    Sequence(u64),
    /// A process-wide timer with no owner.
    Global,
}

/// The generation an entry was scheduled under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerGeneration(u64);

impl TimerGeneration {
    /// Returns the primitive generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One due timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerEntry {
    /// The monotonic deadline that passed.
    pub deadline: MonotonicTick,
    /// The timer kind.
    pub kind: TimerKind,
    /// The typed owner.
    pub id: TimedId,
    /// The generation the entry was scheduled under.
    pub generation: TimerGeneration,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct HeapEntry {
    deadline: MonotonicTick,
    kind: TimerKind,
    id: TimedId,
    generation: u64,
}

/// The indexed min-heap of every StateCore deadline.
pub struct TimerHeap {
    heap: BinaryHeap<Reverse<HeapEntry>>,
    live: HashMap<(TimerKind, TimedId), u64>,
    next_generation: u64,
    ceiling: usize,
}

impl TimerHeap {
    /// Creates an empty heap under the default ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(MAX_TIMER_ENTRIES)
    }

    /// Creates an empty heap under an explicit ceiling.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            live: HashMap::new(),
            next_generation: 1,
            ceiling,
        }
    }

    /// Schedules or replaces the timer for `(kind, id)`.
    ///
    /// An earlier entry for the same key becomes stale and is ignored when
    /// it surfaces. Stale entries are compacted away when the heap reaches
    /// its ceiling; a heap that is still full afterwards refuses.
    pub fn schedule(
        &mut self,
        deadline: MonotonicTick,
        kind: TimerKind,
        id: TimedId,
    ) -> Result<TimerGeneration, RuntimeError> {
        if self.heap.len() >= self.ceiling {
            self.compact();
        }
        if self.heap.len() >= self.ceiling {
            return Err(RuntimeError::LimitExceeded);
        }
        let generation = self.next_generation;
        self.next_generation = generation.checked_add(1).ok_or(RuntimeError::Overflow)?;
        self.live.insert((kind, id), generation);
        self.heap.push(Reverse(HeapEntry {
            deadline,
            kind,
            id,
            generation,
        }));
        Ok(TimerGeneration(generation))
    }

    /// Cancels the live timer for `(kind, id)`; returns whether one existed.
    pub fn cancel(&mut self, kind: TimerKind, id: TimedId) -> bool {
        self.live.remove(&(kind, id)).is_some()
    }

    /// Pops the earliest live entry whose deadline is at or before `now`.
    pub fn pop_due(&mut self, now: MonotonicTick) -> Option<TimerEntry> {
        loop {
            let Reverse(head) = self.heap.peek().copied()?;
            if head.deadline > now {
                return None;
            }
            self.heap.pop();
            if self.take_if_live(head) {
                return Some(TimerEntry {
                    deadline: head.deadline,
                    kind: head.kind,
                    id: head.id,
                    generation: TimerGeneration(head.generation),
                });
            }
        }
    }

    /// Returns the earliest live deadline, discarding stale heads.
    pub fn next_deadline(&mut self) -> Option<MonotonicTick> {
        loop {
            let Reverse(head) = self.heap.peek().copied()?;
            if self.is_live(head) {
                return Some(head.deadline);
            }
            self.heap.pop();
        }
    }

    /// Returns the number of heap entries, stale ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns whether no entry is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Returns the number of live keys.
    #[must_use]
    pub fn live_len(&self) -> usize {
        self.live.len()
    }

    fn is_live(&self, entry: HeapEntry) -> bool {
        self.live.get(&(entry.kind, entry.id)) == Some(&entry.generation)
    }

    fn take_if_live(&mut self, entry: HeapEntry) -> bool {
        if self.is_live(entry) {
            self.live.remove(&(entry.kind, entry.id));
            return true;
        }
        false
    }

    fn compact(&mut self) {
        let live = &self.live;
        let retained: Vec<Reverse<HeapEntry>> = self
            .heap
            .drain()
            .filter(|Reverse(entry)| live.get(&(entry.kind, entry.id)) == Some(&entry.generation))
            .collect();
        self.heap = BinaryHeap::from(retained);
    }
}

impl Default for TimerHeap {
    fn default() -> Self {
        Self::new()
    }
}

/// What one drift observation changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriftTransition {
    /// Trust did not change.
    Unchanged,
    /// Wall time became untrusted; raise the operator alert and pause
    /// time-based destructive work (spec lines 4231-4234).
    Distrusted,
    /// Wall time became trusted again (spec lines 4235-4236).
    Trusted,
}

/// Compares wall elapsed time with monotonic elapsed time.
///
/// While trusted, the monitor measures the wall clock against the anchor
/// taken when trust was last established. A disagreement above five minutes
/// withdraws trust immediately. Smaller disagreement above one second
/// that persists for five minutes withdraws trust. While untrusted, the
/// first agreeing observation re-anchors, and ten continuous minutes of
/// agreement with a wall value no lower than the last accepted one restore
/// trust. A backward jump can therefore never revive an expiry early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriftMonitor {
    anchor_monotonic: MonotonicTick,
    anchor_wall: UtcSecond,
    last_accepted_wall: UtcSecond,
    last_check: MonotonicTick,
    trusted: bool,
    disagreement_since: Option<MonotonicTick>,
    agreement_since: Option<MonotonicTick>,
}

impl DriftMonitor {
    /// Starts trusted from one simultaneous reading of both clocks.
    #[must_use]
    pub const fn new(monotonic: MonotonicTick, wall: UtcSecond) -> Self {
        Self {
            anchor_monotonic: monotonic,
            anchor_wall: wall,
            last_accepted_wall: wall,
            last_check: monotonic,
            trusted: true,
            disagreement_since: None,
            agreement_since: None,
        }
    }

    /// Returns whether wall time may drive retention, expiry, and
    /// credential decisions.
    #[must_use]
    pub const fn wall_trusted(self) -> bool {
        self.trusted
    }

    /// Returns the last wall value accepted while trusted.
    #[must_use]
    pub const fn last_accepted_wall(self) -> UtcSecond {
        self.last_accepted_wall
    }

    /// Returns whether a minute has passed since the last observation.
    #[must_use]
    pub fn is_due(self, monotonic: MonotonicTick) -> bool {
        monotonic
            .get()
            .checked_sub(self.last_check.get())
            .is_some_and(|elapsed| elapsed >= DRIFT_CHECK_INTERVAL_MILLIS)
    }

    /// Records one observation; `None` means the wall clock was unreadable,
    /// which counts as disagreement.
    pub fn observe(
        &mut self,
        monotonic: MonotonicTick,
        wall: Option<UtcSecond>,
    ) -> DriftTransition {
        self.last_check = monotonic;
        let agrees = wall.is_some_and(|wall| self.agrees(monotonic, wall));
        if self.trusted {
            return self.observe_trusted(monotonic, wall, agrees);
        }
        self.observe_untrusted(monotonic, wall, agrees)
    }

    /// Rejects a large new jump at a retention boundary between periodic observations.
    #[must_use]
    pub fn accepts_wall(self, monotonic: MonotonicTick, wall: UtcSecond) -> bool {
        self.trusted
            && wall >= self.last_accepted_wall
            && self.disagreement_seconds(monotonic, wall) <= 300
    }

    fn disagreement_seconds(self, monotonic: MonotonicTick, wall: UtcSecond) -> u64 {
        let elapsed = monotonic.get().saturating_sub(self.anchor_monotonic.get()) / 1_000;
        self.anchor_wall
            .get()
            .saturating_add(elapsed)
            .abs_diff(wall.get())
    }

    fn agrees(self, monotonic: MonotonicTick, wall: UtcSecond) -> bool {
        let monotonic_elapsed = monotonic.get().saturating_sub(self.anchor_monotonic.get()) / 1_000;
        let expected = self.anchor_wall.get().saturating_add(monotonic_elapsed);
        expected.abs_diff(wall.get()) <= DRIFT_TOLERANCE_SECONDS
    }

    fn observe_trusted(
        &mut self,
        monotonic: MonotonicTick,
        wall: Option<UtcSecond>,
        agrees: bool,
    ) -> DriftTransition {
        if agrees {
            self.disagreement_since = None;
            if let Some(wall) = wall {
                self.last_accepted_wall = wall;
            }
            return DriftTransition::Unchanged;
        }
        let severe = wall.is_some_and(|wall| self.disagreement_seconds(monotonic, wall) > 300);
        if severe {
            self.trusted = false;
            self.disagreement_since = None;
            self.agreement_since = None;
            return DriftTransition::Distrusted;
        }
        let since = *self.disagreement_since.get_or_insert(monotonic);
        if monotonic.get().saturating_sub(since.get()) >= DRIFT_DISTRUST_MILLIS {
            self.trusted = false;
            self.disagreement_since = None;
            self.agreement_since = None;
            return DriftTransition::Distrusted;
        }
        DriftTransition::Unchanged
    }

    fn observe_untrusted(
        &mut self,
        monotonic: MonotonicTick,
        wall: Option<UtcSecond>,
        agrees_with_anchor: bool,
    ) -> DriftTransition {
        let Some(wall) = wall else {
            self.agreement_since = None;
            return DriftTransition::Unchanged;
        };
        let continuing = self.agreement_since.is_some() && agrees_with_anchor;
        if !continuing {
            // Start or restart the agreement window from this reading.
            self.anchor_monotonic = monotonic;
            self.anchor_wall = wall;
            self.agreement_since = Some(monotonic);
            return DriftTransition::Unchanged;
        }
        let Some(since) = self.agreement_since else {
            return DriftTransition::Unchanged;
        };
        if wall < self.last_accepted_wall {
            self.agreement_since = None;
            return DriftTransition::Unchanged;
        }
        if monotonic.get().saturating_sub(since.get()) >= DRIFT_RECOVERY_MILLIS {
            self.trusted = true;
            self.agreement_since = None;
            self.last_accepted_wall = wall;
            return DriftTransition::Trusted;
        }
        DriftTransition::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::AccountRandomId;

    use super::*;

    fn tick(millis: u64) -> MonotonicTick {
        MonotonicTick::from_ticks(millis)
    }

    fn wall(seconds: u64) -> UtcSecond {
        UtcSecond::from_unix_seconds(seconds)
    }

    fn user(byte: u8) -> TimedId {
        TimedId::Session(UserId::from_bytes([byte; 16]))
    }

    #[test]
    fn the_heap_pops_in_deadline_order_and_ignores_stale_generations() -> Result<(), RuntimeError> {
        let mut heap = TimerHeap::new();
        assert!(heap.is_empty());
        assert!(heap.next_deadline().is_none());
        heap.schedule(tick(300), TimerKind::Ping, user(1))?;
        let first = heap.schedule(tick(100), TimerKind::Pong, user(2))?;
        heap.schedule(tick(200), TimerKind::Ping, user(3))?;
        // Rescheduling the first key makes its earlier entry stale.
        let replaced = heap.schedule(tick(250), TimerKind::Ping, user(1))?;
        assert_ne!(first.get(), replaced.get());
        assert_eq!(heap.len(), 4);
        assert_eq!(heap.live_len(), 3);
        assert!(heap.pop_due(tick(99)).is_none());
        assert_eq!(heap.next_deadline(), Some(tick(100)));
        let due = heap.pop_due(tick(100)).ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(due.kind, TimerKind::Pong);
        assert_eq!(due.id, user(2));
        assert_eq!(due.generation, first);
        assert!(heap.cancel(TimerKind::Ping, user(3)));
        assert!(!heap.cancel(TimerKind::Ping, user(3)));
        let due = heap
            .pop_due(tick(1_000))
            .ok_or(RuntimeError::InvalidValue)?;
        assert_eq!(
            (due.kind, due.id, due.deadline),
            (TimerKind::Ping, user(1), tick(250))
        );
        assert!(
            heap.pop_due(tick(1_000)).is_none(),
            "the stale 300 entry is skipped"
        );
        assert!(heap.is_empty());
        assert_eq!(heap.live_len(), 0);
        Ok(())
    }

    #[test]
    fn the_ceiling_compacts_stale_entries_before_refusing() -> Result<(), RuntimeError> {
        let mut heap = TimerHeap::with_ceiling(3);
        for _ in 0..3 {
            heap.schedule(tick(10), TimerKind::Batch, TimedId::Sequence(1))?;
        }
        assert_eq!(heap.len(), 3);
        heap.schedule(tick(20), TimerKind::Batch, TimedId::Sequence(2))?;
        assert_eq!(heap.len(), 2, "two stale entries were compacted");
        heap.schedule(tick(30), TimerKind::Batch, TimedId::Sequence(3))?;
        assert_eq!(
            heap.schedule(tick(40), TimerKind::Batch, TimedId::Sequence(4))
                .err(),
            Some(RuntimeError::LimitExceeded)
        );
        assert_eq!(heap.next_deadline(), Some(tick(10)));
        let defaulted = TimerHeap::default();
        assert!(defaulted.is_empty());
        let ids = [
            TimedId::Connection(ConnectionGeneration::new(1)),
            TimedId::Account(AccountId::from_random(AccountRandomId::from_bytes([1; 16]))),
            TimedId::Channel(ChannelInstanceId::from_bytes([1; 16])),
            TimedId::Invite(InviteId::from_bytes([1; 16])),
            TimedId::Transaction(TransactionId::from_bytes([1; 16])),
            TimedId::Peer(ServerId::from_bytes([1; 16])),
            TimedId::Global,
        ];
        assert!(ids.windows(2).all(|pair| pair.first() != pair.last()));
        assert_eq!(SECRET_CHANNEL_FLOOR_MILLIS, 5);
        Ok(())
    }

    #[test]
    fn drift_is_distrusted_after_five_minutes_and_recovers_after_ten() {
        let mut monitor = DriftMonitor::new(tick(0), wall(1_000));
        assert!(monitor.wall_trusted());
        assert!(!monitor.is_due(tick(59_999)));
        assert!(monitor.is_due(tick(60_000)));
        // Exact agreement and the one-second tolerance keep trust.
        assert_eq!(
            monitor.observe(tick(60_000), Some(wall(1_060))),
            DriftTransition::Unchanged
        );
        assert_eq!(
            monitor.observe(tick(120_000), Some(wall(1_121))),
            DriftTransition::Unchanged
        );
        assert_eq!(monitor.last_accepted_wall(), wall(1_121));
        // A ten-minute forward jump withdraws trust at the first observation.
        assert_eq!(
            monitor.observe(tick(180_000), Some(wall(1_780))),
            DriftTransition::Distrusted
        );
        assert!(!monitor.wall_trusted());
        assert_eq!(monitor.last_accepted_wall(), wall(1_121));
        // Agreement relative to the new anchor for ten continuous minutes.
        assert_eq!(
            monitor.observe(tick(540_000), Some(wall(2_140))),
            DriftTransition::Unchanged
        );
        assert_eq!(
            monitor.observe(tick(1_139_999), Some(wall(2_740))),
            DriftTransition::Unchanged
        );
        assert!(!monitor.wall_trusted());
        assert_eq!(
            monitor.observe(tick(1_140_000), Some(wall(2_740))),
            DriftTransition::Trusted
        );
        assert!(monitor.wall_trusted());
        assert_eq!(monitor.last_accepted_wall(), wall(2_740));
    }

    #[test]
    fn five_minutes_of_mild_disagreement_withdraw_trust() {
        let mut monitor = DriftMonitor::new(tick(0), wall(5_000));
        // Two seconds of skew: beyond the tolerance, below the severe bound.
        assert_eq!(
            monitor.observe(tick(60_000), Some(wall(5_062))),
            DriftTransition::Unchanged
        );
        assert!(monitor.wall_trusted());
        assert_eq!(
            monitor.observe(tick(359_999), Some(wall(5_362))),
            DriftTransition::Unchanged
        );
        assert!(monitor.wall_trusted());
        assert_eq!(
            monitor.observe(tick(360_000), Some(wall(5_362))),
            DriftTransition::Distrusted
        );
        assert!(!monitor.wall_trusted());
    }

    #[test]
    fn recovery_restarts_on_disagreement_unreadable_clock_or_backward_wall() {
        let mut monitor = DriftMonitor::new(tick(0), wall(5_000));
        assert_eq!(
            monitor.observe(tick(360_000), Some(wall(9_360))),
            DriftTransition::Distrusted
        );
        // Window starts at 420 s; an unreadable clock resets it.
        assert_eq!(
            monitor.observe(tick(420_000), Some(wall(9_420))),
            DriftTransition::Unchanged
        );
        assert_eq!(
            monitor.observe(tick(480_000), None),
            DriftTransition::Unchanged
        );
        assert_eq!(
            monitor.observe(tick(540_000), Some(wall(9_540))),
            DriftTransition::Unchanged
        );
        // Another jump mid-window restarts it at 600 s.
        assert_eq!(
            monitor.observe(tick(600_000), Some(wall(9_660))),
            DriftTransition::Unchanged
        );
        assert_eq!(
            monitor.observe(tick(1_140_000), Some(wall(10_200))),
            DriftTransition::Unchanged
        );
        assert!(
            !monitor.wall_trusted(),
            "only nine minutes since the restart"
        );
        assert_eq!(
            monitor.observe(tick(1_200_000), Some(wall(10_260))),
            DriftTransition::Trusted
        );
        // A backward wall below the last accepted value never restores trust.
        let mut backward = DriftMonitor::new(tick(0), wall(50_000));
        for step in 1..=6 {
            backward.observe(tick(step * 60_000), Some(wall(1_000 + step * 60)));
        }
        assert!(!backward.wall_trusted());
        assert_eq!(
            backward.observe(tick(420_000), Some(wall(1_420))),
            DriftTransition::Unchanged
        );
        for step in 8..=13 {
            assert_eq!(
                backward.observe(tick(step * 60_000), Some(wall(1_000 + step * 60))),
                DriftTransition::Unchanged
            );
        }
        assert_eq!(
            backward.observe(tick(1_200_000), Some(wall(2_200))),
            DriftTransition::Unchanged
        );
        assert!(!backward.wall_trusted());
        let trusted_none = DriftMonitor::new(tick(0), wall(1)).observe(tick(60_000), None);
        assert_eq!(trusted_none, DriftTransition::Unchanged);
    }
}
