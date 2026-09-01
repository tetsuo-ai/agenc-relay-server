//! The storage bridge: one named thread that waits on blocking storage
//! completions and forwards every outcome to the sole StateCore receiver
//! (spec 21.5, lines 4173-4210; 21.7, lines 4242-4250).
//!
//! `StoragePort::try_commit` never blocks, but its completion is consumed
//! with a blocking `wait`. That wait must not run on a Tokio worker, so the
//! bridge thread owns it and hands each outcome into a bounded Tokio
//! completion channel. The commit lane has exactly two slots (spec line
//! 4084); read and checkpoint results use separate fixed-capacity lanes.
//! Every receiver belongs to StateCore alone. A lost sender, lost receiver,
//! duplicate transaction, or unknown completion is reported as an
//! indeterminate failure and the bridge stops (spec lines 4207-4210).
//!
//! This module keeps its tests in `tests/bridge_storage.rs` so the file can
//! be compiled unchanged under the loom scheduler for the schedule models.

use std::collections::BTreeSet;
use std::fmt;
use std::thread::{self, JoinHandle};

use agenc_ircd_storage::{
    CheckpointOutcome, CommitOutcome, ReadPlan, ReadResult, StorageCompletion, StorageError,
    StorageMutationBatch, StoragePort,
};
use agenc_ircd_types::TransactionId;
use tokio::sync::mpsc;

use crate::RuntimeError;
use crate::bridge::{
    STORAGE_CHECKPOINT_COMPLETION_CHANNEL_CAPACITY, STORAGE_COMPLETION_CHANNEL_CAPACITY,
    STORAGE_READ_COMPLETION_CHANNEL_CAPACITY, StorageCheckpointCompletionMessage,
    StorageCheckpointId, StorageCompletionMessage, StorageReadCompletionMessage, StorageReadId,
};
use crate::sync::{Arc, Mutex, lock};

/// Completions the bridge thread may hold ahead of the storage owner: the
/// same two slots as the storage request queue (spec line 4083).
pub const STORAGE_HANDOFF_CAPACITY: usize = 2;
/// The bridge thread name.
pub const STORAGE_BRIDGE_THREAD_NAME: &str = "agenc-ircd-storage-bridge";

/// A failure of the bridge itself; every variant is `Indeterminate` for the
/// state owner (spec line 4209).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeFailure {
    /// Both handoff slots are occupied; StateCore submitted a third batch.
    HandoffFull,
    /// A transaction identity was submitted while it was still in flight,
    /// or a completion named an identity that was never in flight.
    DuplicateTransaction,
    /// The storage owner dropped the completion sender before answering.
    SenderLost,
    /// StateCore dropped its receiver while outcomes were pending.
    ReceiverLost,
    /// The bridge already failed and refuses further work.
    Stopped,
}

impl fmt::Display for BridgeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandoffFull => formatter.write_str("storage bridge handoff is full"),
            Self::DuplicateTransaction => {
                formatter.write_str("storage bridge saw a duplicate transaction")
            }
            Self::SenderLost => formatter.write_str("storage owner dropped a completion"),
            Self::ReceiverLost => formatter.write_str("state owner dropped its completions"),
            Self::Stopped => formatter.write_str("storage bridge has stopped"),
        }
    }
}

/// Why a submission was refused before any completion existed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    /// The bridge refused; StateCore must treat this as indeterminate.
    Bridge(BridgeFailure),
    /// The storage owner refused the batch before admitting it (a full
    /// queue or a closed owner); nothing irreversible began.
    Storage(StorageError),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bridge(failure) => fmt::Display::fmt(failure, formatter),
            Self::Storage(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for BridgeFailure {}

impl std::error::Error for SubmitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bridge(failure) => Some(failure),
            Self::Storage(error) => Some(error),
        }
    }
}

struct LedgerState {
    in_flight: BTreeSet<TransactionId>,
    reads_in_flight: BTreeSet<StorageReadId>,
    checkpoint_in_flight: Option<StorageCheckpointId>,
    failed: Option<BridgeFailure>,
}

/// The set of transactions between submission and completion.
///
/// The ledger is the only state shared between the submitting thread and
/// the bridge thread. It is written with the crate-local mutex alias so the
/// schedule models can run it under loom.
pub struct CompletionLedger {
    state: Mutex<LedgerState>,
}

impl CompletionLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState {
                in_flight: BTreeSet::new(),
                reads_in_flight: BTreeSet::new(),
                checkpoint_in_flight: None,
                failed: None,
            }),
        }
    }

    /// Records a submission; a duplicate identity fails the ledger.
    pub fn begin(&self, transaction_id: TransactionId) -> Result<(), BridgeFailure> {
        let mut state = lock(&self.state);
        if let Some(failure) = state.failed {
            return Err(failure);
        }
        if !state.in_flight.insert(transaction_id) {
            state.failed = Some(BridgeFailure::DuplicateTransaction);
            return Err(BridgeFailure::DuplicateTransaction);
        }
        Ok(())
    }

    /// Forgets a submission the storage owner never admitted.
    pub fn abandon(&self, transaction_id: TransactionId) {
        lock(&self.state).in_flight.remove(&transaction_id);
    }

    fn begin_read(&self, read_id: StorageReadId) -> Result<(), StorageError> {
        let mut state = lock(&self.state);
        if state.failed.is_some() {
            return Err(StorageError::Unavailable);
        }
        if state.checkpoint_in_flight.is_some() {
            return Err(StorageError::QueueFull);
        }
        if !state.reads_in_flight.insert(read_id) {
            state.failed = Some(BridgeFailure::DuplicateTransaction);
            return Err(StorageError::Unavailable);
        }
        Ok(())
    }

    fn abandon_read(&self, read_id: StorageReadId) {
        lock(&self.state).reads_in_flight.remove(&read_id);
    }

    fn finish_read(&self, read_id: StorageReadId) -> Result<(), BridgeFailure> {
        let mut state = lock(&self.state);
        if let Some(failure) = state.failed {
            return Err(failure);
        }
        if !state.reads_in_flight.remove(&read_id) {
            state.failed = Some(BridgeFailure::DuplicateTransaction);
            return Err(BridgeFailure::DuplicateTransaction);
        }
        Ok(())
    }

    fn begin_checkpoint(&self, checkpoint_id: StorageCheckpointId) -> Result<(), StorageError> {
        let mut state = lock(&self.state);
        if state.failed.is_some() {
            return Err(StorageError::Unavailable);
        }
        if !state.in_flight.is_empty()
            || !state.reads_in_flight.is_empty()
            || state.checkpoint_in_flight.is_some()
        {
            return Err(StorageError::QueueFull);
        }
        state.checkpoint_in_flight = Some(checkpoint_id);
        Ok(())
    }

    fn abandon_checkpoint(&self, checkpoint_id: StorageCheckpointId) {
        let mut state = lock(&self.state);
        if state.checkpoint_in_flight == Some(checkpoint_id) {
            state.checkpoint_in_flight = None;
        }
    }

    fn finish_checkpoint(&self, checkpoint_id: StorageCheckpointId) -> Result<(), BridgeFailure> {
        let mut state = lock(&self.state);
        if let Some(failure) = state.failed {
            return Err(failure);
        }
        if state.checkpoint_in_flight != Some(checkpoint_id) {
            state.failed = Some(BridgeFailure::DuplicateTransaction);
            return Err(BridgeFailure::DuplicateTransaction);
        }
        state.checkpoint_in_flight = None;
        Ok(())
    }

    /// Records a completion; an unknown identity fails the ledger.
    pub fn finish(&self, transaction_id: TransactionId) -> Result<(), BridgeFailure> {
        let mut state = lock(&self.state);
        if let Some(failure) = state.failed {
            return Err(failure);
        }
        if !state.in_flight.remove(&transaction_id) {
            state.failed = Some(BridgeFailure::DuplicateTransaction);
            return Err(BridgeFailure::DuplicateTransaction);
        }
        Ok(())
    }

    /// Marks the bridge failed; the first failure is retained.
    pub fn fail(&self, failure: BridgeFailure) {
        let mut state = lock(&self.state);
        if state.failed.is_none() {
            state.failed = Some(failure);
        }
    }

    /// Returns the retained failure, if any.
    #[must_use]
    pub fn failure(&self) -> Option<BridgeFailure> {
        lock(&self.state).failed
    }

    /// Returns the number of submissions awaiting completion.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        lock(&self.state).in_flight.len()
    }
}

impl Default for CompletionLedger {
    fn default() -> Self {
        Self::new()
    }
}

enum PendingCompletion {
    Commit {
        transaction_id: TransactionId,
        completion: StorageCompletion<CommitOutcome>,
    },
    Read {
        read_id: StorageReadId,
        completion: StorageCompletion<ReadResult>,
    },
    Checkpoint {
        checkpoint_id: StorageCheckpointId,
        completion: StorageCompletion<CheckpointOutcome>,
    },
}

/// The submitting half of the bridge, owned by StateCore.
pub struct StorageBridge {
    port: StoragePort,
    handoff: Option<mpsc::Sender<PendingCompletion>>,
    ledger: Arc<CompletionLedger>,
    thread: Option<JoinHandle<()>>,
    next_read_id: u64,
    next_checkpoint_id: u64,
}

/// A started bridge and its three sole StateCore completion receivers.
pub type StartedStorageBridge = (
    StorageBridge,
    mpsc::Receiver<StorageCompletionMessage>,
    mpsc::Receiver<StorageReadCompletionMessage>,
    mpsc::Receiver<StorageCheckpointCompletionMessage>,
);

impl StorageBridge {
    /// Starts the bridge thread and returns the sole commit, read, and
    /// checkpoint completion receivers.
    pub fn start(port: StoragePort) -> Result<StartedStorageBridge, RuntimeError> {
        let (handoff, mut pending) = mpsc::channel(STORAGE_HANDOFF_CAPACITY);
        let (outcomes, receiver) = mpsc::channel(STORAGE_COMPLETION_CHANNEL_CAPACITY);
        let (read_outcomes, read_receiver) =
            mpsc::channel(STORAGE_READ_COMPLETION_CHANNEL_CAPACITY);
        let (checkpoint_outcomes, checkpoint_receiver) =
            mpsc::channel(STORAGE_CHECKPOINT_COMPLETION_CHANNEL_CAPACITY);
        let ledger = Arc::new(CompletionLedger::new());
        let thread_ledger = Arc::clone(&ledger);
        let thread = thread::Builder::new()
            .name(STORAGE_BRIDGE_THREAD_NAME.to_owned())
            .spawn(move || {
                bridge_loop(
                    &mut pending,
                    &outcomes,
                    &read_outcomes,
                    &checkpoint_outcomes,
                    &thread_ledger,
                );
            })
            .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))?;
        Ok((
            Self {
                port,
                handoff: Some(handoff),
                ledger,
                thread: Some(thread),
                next_read_id: 1,
                next_checkpoint_id: 1,
            },
            receiver,
            read_receiver,
            checkpoint_receiver,
        ))
    }

    /// Submits one complete batch without blocking and hands its completion
    /// to the bridge thread.
    ///
    /// The returned identity is the one StateCore must match against the
    /// forwarded outcome (spec line 6544).
    pub fn submit(&self, batch: StorageMutationBatch) -> Result<TransactionId, SubmitError> {
        let transaction_id = batch.transaction_id();
        self.ledger
            .begin(transaction_id)
            .map_err(SubmitError::Bridge)?;
        let Some(handoff) = &self.handoff else {
            self.ledger.fail(BridgeFailure::Stopped);
            return Err(SubmitError::Bridge(BridgeFailure::Stopped));
        };
        let permit = match handoff.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.ledger.abandon(transaction_id);
                return Err(SubmitError::Storage(StorageError::QueueFull));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.ledger.abandon(transaction_id);
                self.ledger.fail(BridgeFailure::Stopped);
                return Err(SubmitError::Bridge(BridgeFailure::Stopped));
            }
        };
        let completion = match self.port.try_commit(batch) {
            Ok(completion) => completion,
            Err(error) => {
                self.ledger.abandon(transaction_id);
                return Err(SubmitError::Storage(error));
            }
        };
        permit.send(PendingCompletion::Commit {
            transaction_id,
            completion,
        });
        Ok(transaction_id)
    }

    /// Submits one bounded read without blocking and assigns its completion a
    /// process-local identity. A refused handoff is determinate because reads
    /// do not mutate storage.
    pub fn submit_read(&mut self, plan: ReadPlan) -> Result<StorageReadId, StorageError> {
        if self.ledger.failure().is_some() {
            return Err(StorageError::Unavailable);
        }
        let next = self
            .next_read_id
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let read_id = StorageReadId::new(self.next_read_id);
        self.ledger.begin_read(read_id)?;
        let Some(handoff) = &self.handoff else {
            self.ledger.abandon_read(read_id);
            return Err(StorageError::Unavailable);
        };
        let permit = match handoff.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.ledger.abandon_read(read_id);
                return Err(StorageError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.ledger.abandon_read(read_id);
                return Err(StorageError::Unavailable);
            }
        };
        let completion = match self.port.try_read(plan) {
            Ok(completion) => completion,
            Err(error) => {
                self.ledger.abandon_read(read_id);
                return Err(error);
            }
        };
        permit.send(PendingCompletion::Read {
            read_id,
            completion,
        });
        self.next_read_id = next;
        Ok(read_id)
    }

    /// Submits one integrity checkpoint at a StateCore safe point.
    pub fn submit_checkpoint(&mut self) -> Result<StorageCheckpointId, StorageError> {
        let next = self
            .next_checkpoint_id
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        let checkpoint_id = StorageCheckpointId::new(self.next_checkpoint_id);
        self.ledger.begin_checkpoint(checkpoint_id)?;
        let Some(handoff) = &self.handoff else {
            self.ledger.abandon_checkpoint(checkpoint_id);
            return Err(StorageError::Unavailable);
        };
        let permit = match handoff.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.ledger.abandon_checkpoint(checkpoint_id);
                return Err(StorageError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.ledger.abandon_checkpoint(checkpoint_id);
                return Err(StorageError::Unavailable);
            }
        };
        let completion = match self.port.try_checkpoint() {
            Ok(completion) => completion,
            Err(error) => {
                self.ledger.abandon_checkpoint(checkpoint_id);
                return Err(error);
            }
        };
        permit.send(PendingCompletion::Checkpoint {
            checkpoint_id,
            completion,
        });
        self.next_checkpoint_id = next;
        Ok(checkpoint_id)
    }

    /// Returns the retained bridge failure, if any.
    #[must_use]
    pub fn failure(&self) -> Option<BridgeFailure> {
        self.ledger.failure()
    }

    /// Returns the number of batches awaiting their outcome.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.ledger.in_flight()
    }

    /// Borrows the storage port for reads and backups.
    #[must_use]
    pub const fn port(&self) -> &StoragePort {
        &self.port
    }

    /// Closes the handoff and joins the bridge thread after it forwards
    /// every pending outcome.
    pub fn shutdown(mut self) -> Result<(), RuntimeError> {
        drop(self.handoff.take());
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| RuntimeError::Storage(StorageError::Unavailable))
    }
}

impl Drop for StorageBridge {
    /// Dropping closes the handoff and joins the thread, blocking until every
    /// pending outcome was forwarded or the receiver is gone; call
    /// [`StorageBridge::shutdown`] to observe the join result.
    fn drop(&mut self) {
        drop(self.handoff.take());
        if let Some(thread) = self.thread.take() {
            let _join_result = thread.join();
        }
    }
}

/// Maps one awaited completion to the outcome StateCore receives.
///
/// A completion whose sender was lost can only be reported as
/// `Indeterminate`: the storage owner may or may not have persisted the
/// batch (spec lines 4207-4210).
#[must_use]
pub fn classify_completion(
    waited: Result<CommitOutcome, StorageError>,
) -> (CommitOutcome, Option<BridgeFailure>) {
    match waited {
        Ok(outcome) => (outcome, None),
        Err(_) => (
            CommitOutcome::Indeterminate,
            Some(BridgeFailure::SenderLost),
        ),
    }
}

fn bridge_loop(
    pending: &mut mpsc::Receiver<PendingCompletion>,
    outcomes: &mpsc::Sender<StorageCompletionMessage>,
    read_outcomes: &mpsc::Sender<StorageReadCompletionMessage>,
    checkpoint_outcomes: &mpsc::Sender<StorageCheckpointCompletionMessage>,
    ledger: &CompletionLedger,
) {
    while let Some(next) = pending.blocking_recv() {
        let keep_running = match next {
            PendingCompletion::Commit {
                transaction_id,
                completion,
            } => forward_commit(transaction_id, completion, outcomes, ledger),
            PendingCompletion::Read {
                read_id,
                completion,
            } => forward_read(read_id, completion, read_outcomes, ledger),
            PendingCompletion::Checkpoint {
                checkpoint_id,
                completion,
            } => forward_checkpoint(checkpoint_id, completion, checkpoint_outcomes, ledger),
        };
        if !keep_running {
            return;
        }
    }
}

fn forward_commit(
    transaction_id: TransactionId,
    completion: StorageCompletion<CommitOutcome>,
    outcomes: &mpsc::Sender<StorageCompletionMessage>,
    ledger: &CompletionLedger,
) -> bool {
    let (outcome, failure) = classify_completion(completion.wait());
    if let Err(mismatch) = ledger.finish(transaction_id) {
        ledger.fail(mismatch);
        return false;
    }
    if let Some(failure) = failure {
        ledger.fail(failure);
    }
    let message = StorageCompletionMessage {
        transaction_id,
        outcome,
    };
    if outcomes.blocking_send(message).is_err() {
        ledger.fail(BridgeFailure::ReceiverLost);
        return false;
    }
    failure.is_none()
}

fn forward_read(
    read_id: StorageReadId,
    completion: StorageCompletion<ReadResult>,
    read_outcomes: &mpsc::Sender<StorageReadCompletionMessage>,
    ledger: &CompletionLedger,
) -> bool {
    let result = completion.wait();
    if let Err(mismatch) = ledger.finish_read(read_id) {
        ledger.fail(mismatch);
        return false;
    }
    let message = StorageReadCompletionMessage { read_id, result };
    if read_outcomes.blocking_send(message).is_err() {
        ledger.fail(BridgeFailure::ReceiverLost);
        return false;
    }
    true
}

fn forward_checkpoint(
    checkpoint_id: StorageCheckpointId,
    completion: StorageCompletion<CheckpointOutcome>,
    checkpoint_outcomes: &mpsc::Sender<StorageCheckpointCompletionMessage>,
    ledger: &CompletionLedger,
) -> bool {
    let (outcome, failure) = match completion.wait() {
        Ok(outcome) => (outcome, None),
        Err(_) => (
            CheckpointOutcome::Indeterminate,
            Some(BridgeFailure::SenderLost),
        ),
    };
    if let Err(mismatch) = ledger.finish_checkpoint(checkpoint_id) {
        ledger.fail(mismatch);
        return false;
    }
    if let Some(failure) = failure {
        ledger.fail(failure);
    }
    let message = StorageCheckpointCompletionMessage {
        checkpoint_id,
        outcome,
    };
    if checkpoint_outcomes.blocking_send(message).is_err() {
        ledger.fail(BridgeFailure::ReceiverLost);
        return false;
    }
    failure.is_none()
}

/// Performs one bounded consistent read, blocking the calling thread.
///
/// Reconstruction calls this before the runtime serves traffic; a caller
/// inside the async runtime must use `spawn_blocking` (spec line 4242).
pub fn read_blocking(port: &StoragePort, plan: ReadPlan) -> Result<ReadResult, RuntimeError> {
    let completion = port.try_read(plan)?;
    Ok(completion.wait()?)
}
