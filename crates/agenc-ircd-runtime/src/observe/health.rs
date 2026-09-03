//! Readiness and liveness (spec 25.3, lines 6708-6712).
//!
//! Readiness is the conjunction of the startup facts the spec names for a
//! core node: configuration, keys, storage recovery, and StateCore.
//! Liveness says only that the supervisor and the StateCore loop are
//! progressing. Both are read by the admin owner through typed snapshots
//! and are never served on a public port.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agenc_ircd_types::MonotonicTick;

/// The supervisor is stale after this many milliseconds without progress.
///
/// Six times the five-second quiesce phase (spec line 4257) so a shutdown
/// in progress is still live.
pub const SUPERVISOR_STALE_MILLIS: u64 = 30_000;
/// StateCore is stale after this many milliseconds without progress: twice
/// the 30-second pre-commit deadline (spec line 2624) so one slow batch does
/// not read as a hang.
pub const STATE_CORE_STALE_MILLIS: u64 = 60_000;

/// The startup facts readiness requires (spec line 6708).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessStage {
    /// Configuration validated.
    Configuration,
    /// Secret material loaded and checked.
    Keys,
    /// Storage recovery completed.
    StorageRecovered,
    /// StateCore reconstruction completed.
    StateCore,
    /// Federation synchronization reached the state the node role requires:
    /// immediately on a coordinator or a core-only node, and an ACTIVE
    /// coordinator link on an edge.
    Federation,
}

/// Readiness flags set once by their owners.
#[derive(Default)]
pub struct ReadinessGate {
    configuration: AtomicBool,
    keys: AtomicBool,
    storage_recovered: AtomicBool,
    state_core: AtomicBool,
    federation: AtomicBool,
}

impl ReadinessGate {
    /// Creates a gate with every stage pending.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            configuration: AtomicBool::new(false),
            keys: AtomicBool::new(false),
            storage_recovered: AtomicBool::new(false),
            state_core: AtomicBool::new(false),
            federation: AtomicBool::new(false),
        }
    }

    /// Marks one stage ready.
    pub fn mark(&self, stage: ReadinessStage) {
        self.flag(stage).store(true, Ordering::Release);
    }

    /// Clears one stage, for example when storage enters indeterminate
    /// state.
    pub fn clear(&self, stage: ReadinessStage) {
        self.flag(stage).store(false, Ordering::Release);
    }

    /// Returns whether every stage is ready.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.snapshot().ready()
    }

    /// Copies every flag.
    #[must_use]
    pub fn snapshot(&self) -> ReadinessSnapshot {
        ReadinessSnapshot {
            configuration: self.configuration.load(Ordering::Acquire),
            keys: self.keys.load(Ordering::Acquire),
            storage_recovered: self.storage_recovered.load(Ordering::Acquire),
            state_core: self.state_core.load(Ordering::Acquire),
            federation: self.federation.load(Ordering::Acquire),
        }
    }

    const fn flag(&self, stage: ReadinessStage) -> &AtomicBool {
        match stage {
            ReadinessStage::Configuration => &self.configuration,
            ReadinessStage::Keys => &self.keys,
            ReadinessStage::StorageRecovered => &self.storage_recovered,
            ReadinessStage::StateCore => &self.state_core,
            ReadinessStage::Federation => &self.federation,
        }
    }
}

/// One copy of the readiness flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessSnapshot {
    /// Configuration validated.
    pub configuration: bool,
    /// Keys loaded.
    pub keys: bool,
    /// Storage recovered.
    pub storage_recovered: bool,
    /// StateCore reconstructed.
    pub state_core: bool,
    /// Federation synchronization reached the role's required state.
    pub federation: bool,
}

impl ReadinessSnapshot {
    /// Returns the conjunction (spec line 6708).
    #[must_use]
    pub const fn ready(self) -> bool {
        self.configuration
            && self.keys
            && self.storage_recovered
            && self.state_core
            && self.federation
    }
}

/// Progress counters and last-progress ticks of the two loops liveness
/// covers (spec line 6710).
#[derive(Default)]
pub struct Liveness {
    supervisor_progress: AtomicU64,
    supervisor_tick: AtomicU64,
    state_core_progress: AtomicU64,
    state_core_tick: AtomicU64,
}

impl Liveness {
    /// Creates counters at zero progress.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            supervisor_progress: AtomicU64::new(0),
            supervisor_tick: AtomicU64::new(0),
            state_core_progress: AtomicU64::new(0),
            state_core_tick: AtomicU64::new(0),
        }
    }

    /// Records one supervisor loop iteration at `now`.
    pub fn record_supervisor(&self, now: MonotonicTick) {
        self.supervisor_progress.fetch_add(1, Ordering::AcqRel);
        self.supervisor_tick.fetch_max(now.get(), Ordering::AcqRel);
    }

    /// Records one StateCore loop iteration at `now`.
    pub fn record_state_core(&self, now: MonotonicTick) {
        self.state_core_progress.fetch_add(1, Ordering::AcqRel);
        self.state_core_tick.fetch_max(now.get(), Ordering::AcqRel);
    }

    /// Returns whether both loops progressed within their staleness bounds.
    #[must_use]
    pub fn is_live(&self, now: MonotonicTick) -> bool {
        self.snapshot(now).live()
    }

    /// Copies the counters and evaluates staleness at `now`.
    #[must_use]
    pub fn snapshot(&self, now: MonotonicTick) -> LivenessSnapshot {
        let supervisor_progress = self.supervisor_progress.load(Ordering::Acquire);
        let state_core_progress = self.state_core_progress.load(Ordering::Acquire);
        let supervisor_tick = self.supervisor_tick.load(Ordering::Acquire);
        let state_core_tick = self.state_core_tick.load(Ordering::Acquire);
        LivenessSnapshot {
            supervisor_progress,
            state_core_progress,
            supervisor_live: supervisor_progress != 0
                && within(now, supervisor_tick, SUPERVISOR_STALE_MILLIS),
            state_core_live: state_core_progress != 0
                && within(now, state_core_tick, STATE_CORE_STALE_MILLIS),
        }
    }
}

fn within(now: MonotonicTick, last: u64, bound: u64) -> bool {
    now.get().saturating_sub(last) < bound
}

/// One copy of the liveness facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessSnapshot {
    /// Supervisor iterations since start.
    pub supervisor_progress: u64,
    /// StateCore iterations since start.
    pub state_core_progress: u64,
    /// The supervisor progressed within its bound.
    pub supervisor_live: bool,
    /// StateCore progressed within its bound.
    pub state_core_live: bool,
}

impl LivenessSnapshot {
    /// Returns whether both loops are live.
    #[must_use]
    pub const fn live(self) -> bool {
        self.supervisor_live && self.state_core_live
    }
}

/// The complete health view handed to the admin owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    /// The readiness flags.
    pub readiness: ReadinessSnapshot,
    /// The liveness facts.
    pub liveness: LivenessSnapshot,
}

impl HealthSnapshot {
    /// Combines both views at `now`.
    #[must_use]
    pub fn capture(readiness: &ReadinessGate, liveness: &Liveness, now: MonotonicTick) -> Self {
        Self {
            readiness: readiness.snapshot(),
            liveness: liveness.snapshot(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tick(millis: u64) -> MonotonicTick {
        MonotonicTick::from_ticks(millis)
    }

    #[test]
    fn readiness_is_the_conjunction_of_every_stage_and_can_be_cleared() {
        let gate = ReadinessGate::new();
        assert!(!gate.ready());
        let stages = [
            ReadinessStage::Configuration,
            ReadinessStage::Keys,
            ReadinessStage::StorageRecovered,
            ReadinessStage::StateCore,
            ReadinessStage::Federation,
        ];
        for (index, stage) in stages.iter().enumerate() {
            gate.mark(*stage);
            assert_eq!(gate.ready(), index == stages.len() - 1, "{stage:?}");
        }
        gate.clear(ReadinessStage::StorageRecovered);
        assert!(!gate.ready());
        let snapshot = gate.snapshot();
        assert!(snapshot.configuration && snapshot.keys && snapshot.state_core);
        assert!(!snapshot.storage_recovered);
        let defaulted = ReadinessGate::default();
        assert!(!defaulted.ready());
    }

    #[test]
    fn liveness_tracks_progress_and_goes_stale_at_the_exact_bounds() {
        let liveness = Liveness::new();
        assert!(!liveness.is_live(tick(0)));
        liveness.record_supervisor(tick(1_000));
        liveness.record_state_core(tick(1_000));
        assert!(liveness.is_live(tick(1_000)));
        assert!(liveness.is_live(tick(1_000 + SUPERVISOR_STALE_MILLIS - 1)));
        assert!(!liveness.is_live(tick(1_000 + SUPERVISOR_STALE_MILLIS)));
        liveness.record_supervisor(tick(1_000 + SUPERVISOR_STALE_MILLIS));
        assert!(liveness.is_live(tick(1_000 + SUPERVISOR_STALE_MILLIS)));
        assert!(!liveness.is_live(tick(1_000 + STATE_CORE_STALE_MILLIS)));
        liveness.record_state_core(tick(500));
        let snapshot = liveness.snapshot(tick(2_000));
        assert_eq!(snapshot.supervisor_progress, 2);
        assert_eq!(snapshot.state_core_progress, 2);
        assert!(
            snapshot.live(),
            "an older tick never moves the high-water mark backwards"
        );
        let health =
            HealthSnapshot::capture(&ReadinessGate::default(), &Liveness::default(), tick(0));
        assert!(!health.readiness.ready());
        assert!(!health.liveness.supervisor_live);
        assert!(!health.liveness.state_core_live);
    }
}
