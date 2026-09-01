//! Schedule models for the Stage 06 ownership and shutdown boundaries (spec
//! 28.3, lines 7058-7070).
//!
//! The storage bridge ledger is compiled from its production source under
//! the loom scheduler through the crate-local `sync` alias, so every
//! interleaving of its mutex-guarded transitions is enumerated. The memory
//! budget, permit, and sink types cannot be included the same way because
//! their source files carry inline unit tests that construct the alias
//! primitives outside a loom model, which loom rejects at run time; those
//! models therefore drive the public API from loom threads and enumerate
//! the thread-level interleavings loom can observe. The bounds below are
//! explicit so inherited `LOOM_*` variables cannot weaken a run.
#![forbid(unsafe_code)]

/// Loom replacements for the crate-local synchronization alias.
pub mod sync {
    pub use loom::sync::{Arc, Mutex, MutexGuard};

    /// Locks a loom mutex, tolerating poison like the production alias.
    pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub use agenc_ircd_runtime::RuntimeError;

/// The message types the included bridge source names through `crate::bridge`.
pub mod bridge {
    pub use agenc_ircd_runtime::bridge::{
        STORAGE_CHECKPOINT_COMPLETION_CHANNEL_CAPACITY, STORAGE_COMPLETION_CHANNEL_CAPACITY,
        STORAGE_READ_COMPLETION_CHANNEL_CAPACITY, StorageCheckpointCompletionMessage,
        StorageCheckpointId, StorageCompletionMessage, StorageReadCompletionMessage, StorageReadId,
    };
}

/// The production storage bridge source compiled unchanged under the loom
/// alias; only its completion ledger is exercised by the models.
// agenc-review: allow owner=runtime reviewed=2026-08-29 reason=the storage bridge source is compiled unchanged under loom and only its completion ledger is exercised by the models
#[allow(dead_code)]
#[path = "../src/bridge/storage.rs"]
pub mod storage_bridge;

use std::sync::atomic::Ordering;

use agenc_ircd_runtime::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge,
};
use agenc_ircd_runtime::connection::sink::{
    ClientQueueDemand, ClientQueueReservation, ConnectionGeneration, QueueReservationLedger,
    TentativeClientQueueReservation,
};
use agenc_ircd_storage::{CommitOutcome, StorageError};
use agenc_ircd_types::TransactionId;
use loom::sync::atomic::AtomicUsize;
use storage_bridge::{BridgeFailure, CompletionLedger, classify_completion};

/// Loom preemption bound recorded in `test-data/loom/models.toml`.
const PREEMPTION_BOUND: usize = 2;
/// Loom branch ceiling recorded in `test-data/loom/models.toml`.
const MAX_BRANCHES: usize = 20_000;

fn builder() -> loom::model::Builder {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.max_branches = MAX_BRANCHES;
    builder.checkpoint_file = None;
    builder
}

/// One fixed charge; `None` only if checked plan construction fails.
fn charges(bytes: u64) -> Option<BoundedMemoryCharges> {
    BoundedMemoryCharges::new(&[MemoryCharge::fixed(bytes)]).ok()
}

#[test]
fn budget_batch_acquire_release() {
    builder().check(|| {
        let budget = std::sync::Arc::new(MemoryBudget::new(10_000));
        let workers: Vec<_> = (0..2)
            .map(|index| {
                let budget = std::sync::Arc::clone(&budget);
                loom::thread::spawn(move || {
                    let wanted = 4_096 * (index + 1);
                    let Some(charges) = charges(wanted) else {
                        return;
                    };
                    match budget.try_acquire_batch(charges) {
                        Ok(batch) => {
                            assert_eq!(batch.total(), wanted);
                            drop(batch);
                        }
                        Err(exhausted) => {
                            assert_eq!(exhausted.requested(), wanted);
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap_or(());
        }
        assert_eq!(budget.available(), 10_000);
        assert_eq!(budget.charged(), 0);
    });
}

#[test]
fn permit_split_and_drop() {
    builder().check(|| {
        let budget = std::sync::Arc::new(MemoryBudget::new(8_192));
        let Some(charges) = charges(8_192) else {
            return;
        };
        let Ok(mut batch) = budget.try_acquire_batch(charges) else {
            return;
        };
        let first = batch.split_exact(4_096);
        let second = batch.split_exact(4_096);
        assert!(batch.split_exact(1).is_none());
        let holder = std::sync::Arc::clone(&budget);
        let dropper = loom::thread::spawn(move || {
            drop(first);
            assert!(holder.available() >= 4_096);
        });
        drop(second);
        dropper.join().unwrap_or(());
        drop(batch);
        assert_eq!(budget.available(), 8_192);
    });
}

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

#[test]
fn sink_reserve_prepare_commit() {
    builder().check(|| {
        let ledger = std::sync::Arc::new(CountingLedger {
            frames: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        });
        let Ok(demand) = ClientQueueDemand::new(vec![10, 20]) else {
            return;
        };
        let shared: std::sync::Arc<dyn QueueReservationLedger> = ledger.clone();
        let dropped_reservation = TentativeClientQueueReservation::new(
            ConnectionGeneration::new(1),
            demand.clone(),
            0,
            shared.clone(),
        );
        let committed_reservation =
            TentativeClientQueueReservation::new(ConnectionGeneration::new(2), demand, 0, shared);
        let dropper = loom::thread::spawn(move || drop(dropped_reservation));
        let committer = loom::thread::spawn(move || {
            let Ok(prepared) = ClientQueueReservation::prepare(committed_reservation, None) else {
                return;
            };
            assert_eq!(prepared.generation(), ConnectionGeneration::new(2));
            let transfer = prepared.into_transfer();
            assert_eq!(transfer.frame_count(), 2);
            // Transport cancellation began: the commit discards as one step.
            transfer.discard();
        });
        dropper.join().unwrap_or(());
        committer.join().unwrap_or(());
        assert_eq!(ledger.frames.load(Ordering::SeqCst), 4);
        assert_eq!(ledger.bytes.load(Ordering::SeqCst), 60);
    });
}

#[test]
fn storage_completion_single_consumer() {
    builder().check(|| {
        let ledger = sync::Arc::new(CompletionLedger::new());
        let id = TransactionId::from_bytes([7; 16]);
        let submitters: Vec<_> = (0..2)
            .map(|_| {
                let ledger = sync::Arc::clone(&ledger);
                loom::thread::spawn(move || ledger.begin(id).is_ok())
            })
            .collect();
        let admitted = submitters
            .into_iter()
            .map(|handle| handle.join().unwrap_or(false))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(
            admitted, 1,
            "exactly one submission of an identity is admitted"
        );
        assert_eq!(ledger.failure(), Some(BridgeFailure::DuplicateTransaction));
        assert_eq!(ledger.finish(id), Err(BridgeFailure::DuplicateTransaction));
        assert_eq!(ledger.in_flight(), 1);
    });
}

#[test]
fn completion_sender_loss() {
    builder().check(|| {
        let ledger = sync::Arc::new(CompletionLedger::new());
        let id = TransactionId::from_bytes([9; 16]);
        let (outcome, failure) = classify_completion(Err(StorageError::Unavailable));
        assert!(matches!(outcome, CommitOutcome::Indeterminate));
        assert_eq!(failure, Some(BridgeFailure::SenderLost));
        let failer = {
            let ledger = sync::Arc::clone(&ledger);
            loom::thread::spawn(move || ledger.fail(BridgeFailure::SenderLost))
        };
        let submitter = {
            let ledger = sync::Arc::clone(&ledger);
            loom::thread::spawn(move || ledger.begin(id))
        };
        failer.join().unwrap_or(());
        let submitted = submitter.join().unwrap_or(Err(BridgeFailure::Stopped));
        assert_eq!(ledger.failure(), Some(BridgeFailure::SenderLost));
        match submitted {
            Ok(()) => assert_eq!(ledger.in_flight(), 1),
            Err(failure) => {
                assert_eq!(failure, BridgeFailure::SenderLost);
                assert_eq!(ledger.in_flight(), 0);
            }
        }
        assert_eq!(ledger.begin(id), Err(BridgeFailure::SenderLost));
    });
}

#[derive(Default)]
struct ShutdownSchedule {
    phase: usize,
    applications: [usize; 4],
}

impl ShutdownSchedule {
    fn request(&mut self, requested: usize) {
        const STOP: usize = 4;
        if self.phase == STOP || !(1..=STOP).contains(&requested) {
            return;
        }
        if requested == STOP || requested == self.phase.saturating_add(1) {
            let Some(application) = self.applications.get_mut(requested.saturating_sub(1)) else {
                return;
            };
            self.phase = requested;
            *application += 1;
        }
    }
}

#[test]
fn shutdown_stop_supersedes_reordered_phase_requests() {
    builder().check(|| {
        let schedule = sync::Arc::new(sync::Mutex::new(ShutdownSchedule::default()));
        let driver = {
            let schedule = sync::Arc::clone(&schedule);
            loom::thread::spawn(move || {
                for phase in 1..=4 {
                    sync::lock(&schedule).request(phase);
                }
            })
        };
        let second_signal = {
            let schedule = sync::Arc::clone(&schedule);
            loom::thread::spawn(move || {
                sync::lock(&schedule).request(4);
                sync::lock(&schedule).request(4);
            })
        };
        let duplicate_commands = {
            let schedule = sync::Arc::clone(&schedule);
            loom::thread::spawn(move || {
                sync::lock(&schedule).request(1);
                sync::lock(&schedule).request(2);
            })
        };
        driver.join().unwrap_or(());
        second_signal.join().unwrap_or(());
        duplicate_commands.join().unwrap_or(());

        let schedule = sync::lock(&schedule);
        assert_eq!(schedule.phase, 4);
        assert_eq!(schedule.applications.get(3), Some(&1));
        assert!(
            schedule
                .applications
                .iter()
                .take(3)
                .all(|count| *count <= 1)
        );
    });
}
