//! Bounded single-thread ownership port for all blocking storage operations.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};

use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_types::TransactionId;

use crate::{
    BackupDestination, BackupReceipt, CheckpointOutcome, CommitOutcome, ReadPlan, ReadResult,
    RecoveredStorageState, StorageError, StorageMutationBatch, StorageStatistics,
    engine::{
        EngineCommitFailure, StorageEngine, StorageLimitCell, StorageOpenConfig,
        StorageRuntimeLimits, storage_limit_pair,
    },
};

/// Fixed number of complete requests admitted ahead of the storage owner.
pub const STORAGE_REQUEST_QUEUE_CAPACITY: usize = 2;
/// Fixed number of results retained by an individual completion.
pub const STORAGE_COMPLETION_QUEUE_CAPACITY: usize = 2;
/// Operating-system thread that performs the blocking storage-owner join.
pub const STORAGE_SHUTDOWN_THREAD_NAME: &str = "agenc-ircd-storage-shutdown";

enum StorageRequest {
    Commit {
        batch: StorageMutationBatch,
        completion: SyncSender<Result<CommitOutcome, StorageError>>,
    },
    Read {
        plan: ReadPlan,
        completion: SyncSender<Result<ReadResult, StorageError>>,
    },
    Statistics {
        completion: SyncSender<Result<StorageStatistics, StorageError>>,
    },
    Backup {
        destination: BackupDestination,
        signing_key: Ed25519SecretKey,
        created_at: u64,
        backup_id: [u8; 16],
        completion: SyncSender<Result<BackupReceipt, StorageError>>,
    },
    Checkpoint {
        completion: SyncSender<Result<CheckpointOutcome, StorageError>>,
    },
    LimitsChanged,
    Shutdown {
        completion: SyncSender<Result<(), StorageError>>,
    },
}

/// Sole StateCore-owned writer for the live storage-limit cell.
pub struct StorageLimitWriter {
    limits: StorageLimitCell,
    requests: SyncSender<StorageRequest>,
}

impl StorageLimitWriter {
    /// Reports whether the retained manifest ledger needs a checkpoint.
    pub fn checkpoint_due(&self) -> Result<bool, StorageError> {
        self.limits.checkpoint_due()
    }

    /// Installs an unaudited candidate after checking authoritative current-use floors.
    pub fn activate(
        &self,
        candidate: StorageRuntimeLimits,
    ) -> Result<StorageRuntimeLimits, StorageError> {
        let previous = self.limits.activate(candidate)?;
        if let Err(error) = self.notify_owner() {
            self.limits.restore_unreserved(previous);
            return Err(error);
        }
        Ok(previous)
    }

    /// Reserves an audited candidate for one exact projected outcome commit.
    pub fn reserve(
        &self,
        token: TransactionId,
        candidate: StorageRuntimeLimits,
        projected_logical_database_bytes: u64,
        projected_backup_stream_bytes: u64,
    ) -> Result<(), StorageError> {
        self.limits.reserve(
            token,
            candidate,
            projected_logical_database_bytes,
            projected_backup_stream_bytes,
        )?;
        if let Err(error) = self.notify_owner() {
            let _rolled_back = self.limits.rollback(token);
            return Err(error);
        }
        Ok(())
    }

    /// Makes one audited reservation permanent after its exact outcome commit.
    pub fn finalize(&self, token: TransactionId) -> Result<(), StorageError> {
        self.limits.finalize(token)?;
        self.notify_owner()
    }

    /// Replaces one audited reservation with another and wakes the owner once.
    ///
    /// A rollback followed by a reserve would queue two wake notices ahead of the outcome
    /// commit the caller submits next, and the request queue holds two entries: a commit
    /// that finds both slots taken is refused as full. The owner reads the limit cell when
    /// it wakes, so one notice carries both changes.
    pub fn replace_reservation(
        &self,
        replaced: TransactionId,
        token: TransactionId,
        candidate: StorageRuntimeLimits,
        projected_logical_database_bytes: u64,
        projected_backup_stream_bytes: u64,
    ) -> Result<(), StorageError> {
        self.limits.rollback(replaced)?;
        self.limits.reserve(
            token,
            candidate,
            projected_logical_database_bytes,
            projected_backup_stream_bytes,
        )?;
        if let Err(error) = self.notify_owner() {
            let _rolled_back = self.limits.rollback(token);
            return Err(error);
        }
        Ok(())
    }

    /// Restores the prior limits when an audited outcome did not commit.
    pub fn rollback(&self, token: TransactionId) -> Result<(), StorageError> {
        self.limits.rollback(token)?;
        self.notify_owner()
    }

    fn notify_owner(&self) -> Result<(), StorageError> {
        match self.requests.try_send(StorageRequest::LimitsChanged) {
            Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
            Err(TrySendError::Disconnected(_)) => Err(StorageError::Unavailable),
        }
    }
}

/// Cloneable, nonblocking submission half of the storage-owner boundary.
#[derive(Clone)]
pub struct StoragePort {
    requests: SyncSender<StorageRequest>,
}

impl StoragePort {
    /// Submits one complete owned mutation batch without waiting for queue space.
    pub fn try_commit(
        &self,
        batch: StorageMutationBatch,
    ) -> Result<StorageCompletion<CommitOutcome>, StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        self.requests
            .try_send(StorageRequest::Commit { batch, completion })
            .map_err(map_submission_error)?;
        Ok(StorageCompletion { receiver })
    }

    /// Submits one complete bounded read plan without waiting for queue space.
    pub fn try_read(&self, plan: ReadPlan) -> Result<StorageCompletion<ReadResult>, StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        self.requests
            .try_send(StorageRequest::Read { plan, completion })
            .map_err(map_submission_error)?;
        Ok(StorageCompletion { receiver })
    }

    /// Submits one coherent read-only statistics sample without waiting for
    /// queue space.
    pub fn try_statistics(&self) -> Result<StorageCompletion<StorageStatistics>, StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        self.requests
            .try_send(StorageRequest::Statistics { completion })
            .map_err(map_submission_error)?;
        Ok(StorageCompletion { receiver })
    }

    /// Submits a complete signed-backup job for a new mode-0600 empty file.
    pub fn try_backup(
        &self,
        destination: BackupDestination,
        signing_key: Ed25519SecretKey,
        created_at: u64,
        backup_id: [u8; 16],
    ) -> Result<StorageCompletion<BackupReceipt>, StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        self.requests
            .try_send(StorageRequest::Backup {
                destination,
                signing_key,
                created_at,
                backup_id,
                completion,
            })
            .map_err(map_submission_error)?;
        Ok(StorageCompletion { receiver })
    }

    /// Submits one explicit integrity checkpoint without waiting for queue space.
    pub fn try_checkpoint(&self) -> Result<StorageCompletion<CheckpointOutcome>, StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        self.requests
            .try_send(StorageRequest::Checkpoint { completion })
            .map_err(map_submission_error)?;
        Ok(StorageCompletion { receiver })
    }
}

/// One owned result handle. Dropping it never cancels work already admitted.
pub struct StorageCompletion<T> {
    receiver: Receiver<Result<T, StorageError>>,
}

impl<T> StorageCompletion<T> {
    /// Waits outside the async runtime for the owner to consume the request.
    pub fn wait(self) -> Result<T, StorageError> {
        self.receiver
            .recv()
            .map_err(|_| StorageError::Unavailable)?
    }

    /// Polls once without blocking.
    pub fn try_take(&self) -> Result<Option<Result<T, StorageError>>, StorageError> {
        match self.receiver.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(StorageError::Unavailable),
        }
    }
}

/// Lifetime owner of the joined blocking storage thread.
pub struct StorageOwner {
    requests: SyncSender<StorageRequest>,
    thread: Option<JoinHandle<()>>,
    shutdown_sender: Option<SyncSender<StorageShutdownWork>>,
    shutdown_thread: Option<JoinHandle<Result<(), StorageError>>>,
    recovered: RecoveredStorageState,
    limit_writer: Option<StorageLimitWriter>,
}

struct StorageShutdownWork {
    requests: SyncSender<StorageRequest>,
    thread: JoinHandle<()>,
}

impl StorageShutdownWork {
    fn run(self) -> Result<(), StorageError> {
        let (completion, receiver) = sync_channel(1);
        let shutdown_result = if self
            .requests
            .send(StorageRequest::Shutdown { completion })
            .is_ok()
        {
            match receiver.recv() {
                Ok(result) => result,
                Err(_) => Ok(()),
            }
        } else {
            Ok(())
        };
        self.thread.join().map_err(|_| StorageError::Unavailable)?;
        shutdown_result
    }
}

/// Pollable ownership of a storage thread prepared for bounded shutdown.
///
/// The named helper is created before the database owner starts, so shutdown
/// never needs to create an operating-system thread while resources are low.
pub struct StorageShutdown {
    work: Option<StorageShutdownWork>,
    sender: Option<SyncSender<StorageShutdownWork>>,
    thread: Option<JoinHandle<Result<(), StorageError>>>,
    result: Option<Result<(), StorageError>>,
}

impl StorageShutdown {
    /// Starts the blocking owner close on its named helper thread.
    pub fn start(&mut self) -> Result<(), StorageError> {
        if self.work.is_none() {
            return self.result.unwrap_or(Ok(()));
        }
        let work = self.work.take().ok_or(StorageError::Unavailable)?;
        let Some(sender) = self.sender.take() else {
            self.work = Some(work);
            return Err(StorageError::Unavailable);
        };
        match sender.try_send(work) {
            Ok(()) => {
                drop(sender);
                Ok(())
            }
            Err(TrySendError::Full(work) | TrySendError::Disconnected(work)) => {
                self.work = Some(work);
                Err(StorageError::Unavailable)
            }
        }
    }

    /// Polls once, joining only after the helper reports it has finished.
    pub fn try_complete(&mut self) -> Option<Result<(), StorageError>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        let thread = self.thread.as_ref()?;
        if !thread.is_finished() {
            return None;
        }
        let result = self
            .thread
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or(Err(StorageError::Unavailable));
        self.result = Some(result);
        Some(result)
    }

    fn wait(mut self) -> Result<(), StorageError> {
        if let Err(start_error) = self.start() {
            let cleanup = self.work.take().ok_or(StorageError::Unavailable)?.run();
            drop(self.sender.take());
            let helper = self
                .thread
                .take()
                .map(|thread| thread.join().map_err(|_| StorageError::Unavailable))
                .transpose()?;
            cleanup?;
            if let Some(result) = helper {
                result?;
            }
            return Err(start_error);
        }
        if let Some(result) = self.result {
            return result;
        }
        self.thread
            .take()
            .ok_or(StorageError::Unavailable)?
            .join()
            .map_err(|_| StorageError::Unavailable)?
    }
}

impl StorageOwner {
    /// Starts the sole storage thread and completes full startup validation before returning.
    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=startup handshake owns every thread-success and join failure branch
    pub fn start(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let initial_limits = StorageRuntimeLimits::from_engine(config.limits)?;
        let (limit_cell, limit_reader) = storage_limit_pair(initial_limits);
        let (requests, receiver) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (shutdown_sender, shutdown_receiver) = sync_channel(1);
        let shutdown_thread = thread::Builder::new()
            .name(STORAGE_SHUTDOWN_THREAD_NAME.to_owned())
            .spawn(move || match shutdown_receiver.recv() {
                Ok(work) => StorageShutdownWork::run(work),
                Err(_) => Ok(()),
            })
            .map_err(|_| StorageError::Unavailable)?;
        let limit_writer = StorageLimitWriter {
            limits: limit_cell,
            requests: requests.clone(),
        };
        let (startup_sender, startup_receiver) = sync_channel(1);
        let Ok(thread) = thread::Builder::new()
            .name("agenc-ircd-storage-owner".to_owned())
            .spawn(move || {
                let engine = StorageEngine::open_with_runtime_limits(config, limit_reader)
                    .and_then(|engine| {
                        let recovered = engine.startup_scan()?;
                        Ok((engine, recovered))
                    });
                match engine {
                    Ok((mut engine, recovered)) => {
                        if startup_sender.send(Ok(recovered)).is_err() {
                            return;
                        }
                        run_owner(&mut engine, &receiver);
                    }
                    Err(error) => {
                        let _ = startup_sender.send(Err(error));
                    }
                }
            })
        else {
            drop(shutdown_sender);
            let _ = shutdown_thread.join();
            return Err(StorageError::Unavailable);
        };
        match startup_receiver.recv() {
            Ok(Ok(recovered)) => Ok(Self {
                requests,
                thread: Some(thread),
                shutdown_sender: Some(shutdown_sender),
                shutdown_thread: Some(shutdown_thread),
                recovered,
                limit_writer: Some(limit_writer),
            }),
            Ok(Err(error)) => {
                let work = StorageShutdownWork { requests, thread };
                if let Err(send_error) = shutdown_sender.send(work) {
                    let _ = send_error.0.run();
                }
                let _ = shutdown_thread.join();
                Err(error)
            }
            Err(_) => {
                let work = StorageShutdownWork { requests, thread };
                if let Err(send_error) = shutdown_sender.send(work) {
                    let _ = send_error.0.run();
                }
                let _ = shutdown_thread.join();
                Err(StorageError::Unavailable)
            }
        }
    }

    /// Returns another bounded submission handle.
    #[must_use]
    pub fn port(&self) -> StoragePort {
        StoragePort {
            requests: self.requests.clone(),
        }
    }

    /// Returns the state reconstructed before the owner accepted work.
    #[must_use]
    pub const fn recovered_state(&self) -> &RecoveredStorageState {
        &self.recovered
    }

    /// Transfers the sole live-limit writer to the StateCore composition.
    pub fn take_limit_writer(&mut self) -> Result<StorageLimitWriter, StorageError> {
        self.limit_writer.take().ok_or(StorageError::Unavailable)
    }

    /// Transfers the owner into a pollable shutdown value without blocking.
    #[must_use]
    pub fn into_shutdown(mut self) -> StorageShutdown {
        let work = self.thread.take().map(|thread| StorageShutdownWork {
            requests: self.requests.clone(),
            thread,
        });
        StorageShutdown {
            result: (work.is_none() && self.shutdown_thread.is_none()).then_some(Ok(())),
            work,
            sender: self.shutdown_sender.take(),
            thread: self.shutdown_thread.take(),
        }
    }

    /// Drains prior requests, closes the owner, and joins the blocking thread.
    pub fn shutdown(self) -> Result<(), StorageError> {
        self.into_shutdown().wait()
    }

    fn join_owner(&mut self) -> Result<(), StorageError> {
        let work = self.thread.take().map(|thread| StorageShutdownWork {
            requests: self.requests.clone(),
            thread,
        });
        if work.is_none() && self.shutdown_thread.is_none() {
            return Ok(());
        }
        StorageShutdown {
            result: None,
            work,
            sender: self.shutdown_sender.take(),
            thread: self.shutdown_thread.take(),
        }
        .wait()
    }
}

impl Drop for StorageOwner {
    /// Performs the same joined shutdown as [`StorageOwner::shutdown`] and discards its result.
    ///
    /// The owner thread cancels any backup still in its phases (its holder receives
    /// `Unavailable` and no artifact is published), finishes any active checkpoint, then runs
    /// one complete checkpoint scan when manifests are retained. An audited reload reservation
    /// skips that final scan so startup reconciliation can resolve the reservation. The close
    /// then persists the allocator state within its own bounded allowance. Callers that need
    /// the outcome must call `shutdown` instead.
    fn drop(&mut self) {
        let _ = self.join_owner();
    }
}

/// Bookkeeping carried across owner iterations.
struct OwnerState {
    deferred: VecDeque<StorageRequest>,
    backup_completion: Option<SyncSender<Result<BackupReceipt, StorageError>>>,
    checkpoint_completion: Option<SyncSender<Result<CheckpointOutcome, StorageError>>>,
}

impl OwnerState {
    fn new() -> Self {
        Self {
            deferred: VecDeque::with_capacity(STORAGE_REQUEST_QUEUE_CAPACITY),
            backup_completion: None,
            checkpoint_completion: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnerStep {
    Continue,
    Stop,
}

fn run_owner(engine: &mut StorageEngine, requests: &Receiver<StorageRequest>) {
    let mut state = OwnerState::new();
    while owner_step(engine, requests, &mut state) == OwnerStep::Continue {}
    // An owner that stops without a clean shutdown still takes the close duty within an
    // allowance; whatever its outcome, the next open repairs exactly as after a crash.
    if !engine.close_handled() {
        engine.close_bounded(false);
    }
}

/// Runs one owner iteration in priority order: a backup slice, a checkpoint slice, a deferred
/// request, then one blocking request.
// agenc-review: focus owner=storage reviewed=2026-09-01 reason=explicit request priority keeps backup and checkpoint slices bounded
fn owner_step(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
) -> OwnerStep {
    engine.take_runtime_limit_change();
    if engine.backup_is_active() {
        return service_active_backup(engine, requests, state);
    }
    if engine.checkpoint_is_active() {
        return service_active_checkpoint(engine, requests, state);
    }
    if let Some(request) = state.deferred.pop_front() {
        return dispatch_or_start_backup(engine, request, state);
    }
    let Ok(request) = requests.recv() else {
        return OwnerStep::Stop;
    };
    dispatch_or_start_backup(engine, request, state)
}

/// The long-running job the owner is currently slicing.
#[derive(Clone, Copy)]
enum ActiveJob {
    Backup,
    Checkpoint,
}

/// Admits at most one queued request beside an active job and defers work that would compete with
/// that job's storage ordering.
fn admit_request_beside(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
    job: ActiveJob,
) -> OwnerStep {
    if state.deferred.len() >= STORAGE_REQUEST_QUEUE_CAPACITY {
        return OwnerStep::Continue;
    }
    let request = match requests.try_recv() {
        Ok(request) => request,
        Err(TryRecvError::Empty) => return OwnerStep::Continue,
        // An accepted long-running job still finishes for its completion holder after every
        // submission port is gone.
        Err(TryRecvError::Disconnected) => return OwnerStep::Continue,
    };
    if defers_beside(job, &request) {
        state.deferred.push_back(request);
        return OwnerStep::Continue;
    }
    dispatch_request(engine, request, state)
}

const fn defers_beside(job: ActiveJob, request: &StorageRequest) -> bool {
    matches!(
        (job, request),
        (_, StorageRequest::Backup { .. })
            | (ActiveJob::Backup, StorageRequest::Checkpoint { .. })
            | (ActiveJob::Checkpoint, StorageRequest::Commit { .. })
            | (ActiveJob::Checkpoint, StorageRequest::Checkpoint { .. })
            | (ActiveJob::Checkpoint, StorageRequest::LimitsChanged)
            | (ActiveJob::Checkpoint, StorageRequest::Shutdown { .. })
    )
}

fn service_active_backup(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
) -> OwnerStep {
    if admit_request_beside(engine, requests, state, ActiveJob::Backup) == OwnerStep::Stop {
        return OwnerStep::Stop;
    }
    match engine.service_backup() {
        Ok(Some(receipt)) => finish_backup(state, Ok(receipt)),
        Ok(None) => {}
        Err(error) => finish_backup(state, Err(error)),
    }
    OwnerStep::Continue
}

fn finish_backup(state: &mut OwnerState, result: Result<BackupReceipt, StorageError>) {
    if let Some(completion) = state.backup_completion.take() {
        let _ = completion.send(result);
    }
}

fn service_active_checkpoint(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
) -> OwnerStep {
    if admit_request_beside(engine, requests, state, ActiveJob::Checkpoint) == OwnerStep::Stop {
        return OwnerStep::Stop;
    }
    match engine.service_checkpoint() {
        Ok(Some(receipt)) => {
            finish_checkpoint(state, CheckpointOutcome::Installed(receipt));
            OwnerStep::Continue
        }
        Ok(None) => OwnerStep::Continue,
        Err(EngineCommitFailure::Rejected(error)) => {
            engine.abandon_checkpoint();
            finish_checkpoint(state, CheckpointOutcome::Rejected(error));
            OwnerStep::Continue
        }
        Err(EngineCommitFailure::Indeterminate) => {
            finish_checkpoint(state, CheckpointOutcome::Indeterminate);
            OwnerStep::Stop
        }
    }
}

fn finish_checkpoint(state: &mut OwnerState, outcome: CheckpointOutcome) {
    if let Some(completion) = state.checkpoint_completion.take() {
        let _ = completion.send(Ok(outcome));
    }
}

fn dispatch_or_start_backup(
    engine: &mut StorageEngine,
    request: StorageRequest,
    state: &mut OwnerState,
) -> OwnerStep {
    engine.refresh_runtime_limits();
    let StorageRequest::Backup {
        destination,
        signing_key,
        created_at,
        backup_id,
        completion,
    } = request
    else {
        return dispatch_request(engine, request, state);
    };
    match engine.start_backup(destination, signing_key, created_at, backup_id) {
        Ok(()) => {
            state.backup_completion = Some(completion);
        }
        Err(error) => {
            let _ = completion.send(Err(error));
        }
    }
    OwnerStep::Continue
}

// agenc-review: focus owner=storage reviewed=2026-09-01 reason=exhaustive closed request dispatch keeps checkpoint completion and indeterminate shutdown in one auditable match
fn dispatch_request(
    engine: &mut StorageEngine,
    request: StorageRequest,
    state: &mut OwnerState,
) -> OwnerStep {
    engine.refresh_runtime_limits();
    match request {
        StorageRequest::Commit { batch, completion } => {
            let result = engine.commit(batch);
            let closes_owner = matches!(result, CommitOutcome::Indeterminate);
            let _ = completion.send(Ok(result));
            if closes_owner {
                OwnerStep::Stop
            } else {
                OwnerStep::Continue
            }
        }
        StorageRequest::Read { plan, completion } => {
            let _ = completion.send(engine.read(&plan));
            OwnerStep::Continue
        }
        StorageRequest::Statistics { completion } => {
            let _ = completion.send(engine.statistics());
            OwnerStep::Continue
        }
        StorageRequest::Backup { completion, .. } => {
            let _ = completion.send(Err(StorageError::QueueFull));
            OwnerStep::Continue
        }
        StorageRequest::Checkpoint { completion } => {
            if !engine.checkpoint_cut_would_advance() {
                let _ = completion.send(Ok(CheckpointOutcome::NotNeeded));
                return OwnerStep::Continue;
            }
            match engine.start_checkpoint() {
                Ok(()) => {
                    state.checkpoint_completion = Some(completion);
                }
                Err(error) => {
                    let _ = completion.send(Ok(CheckpointOutcome::Rejected(error)));
                }
            }
            OwnerStep::Continue
        }
        StorageRequest::LimitsChanged => OwnerStep::Continue,
        StorageRequest::Shutdown { completion } => {
            // A backup still in its phases is cancelled, not waited for: the
            // job drops its temporary and scratch, its holder learns the
            // owner is closing, and the bounded shutdown checkpoint starts.
            if engine.backup_is_active() {
                engine.abandon_backup();
                finish_backup(state, Err(StorageError::Unavailable));
            }
            let result = finish_for_shutdown(engine);
            let _ = completion.send(result);
            OwnerStep::Stop
        }
    }
}

/// Finishes the owner's durable work for a clean stop: any active checkpoint, the final
/// checkpoint scan unless an audited reload reservation defers it, and the bounded close that
/// persists the allocator state within Section 19.3's `G`.
fn finish_for_shutdown(engine: &mut StorageEngine) -> Result<(), StorageError> {
    if !engine.runtime_limit_reservation_active() {
        while engine.checkpoint_is_active() {
            engine.service_checkpoint().map_err(checkpoint_error)?;
        }
        engine.checkpoint_for_shutdown().map_err(checkpoint_error)?;
    }
    engine.close_bounded(true);
    Ok(())
}

fn checkpoint_error(error: EngineCommitFailure) -> StorageError {
    match error {
        EngineCommitFailure::Rejected(error) => error,
        EngineCommitFailure::Indeterminate => StorageError::Unavailable,
    }
}

fn map_submission_error<T>(error: TrySendError<T>) -> StorageError {
    match error {
        TrySendError::Full(_) => StorageError::QueueFull,
        TrySendError::Disconnected(_) => StorageError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests::EngineFixture;
    use crate::{
        StorageFaultBoundary, StorageFaultCase, StorageFaultInjector, StorageFaultSite, TableId,
    };
    use std::os::unix::fs::PermissionsExt as _;

    type Completion<T> = Receiver<Result<T, StorageError>>;

    #[test]
    fn an_unavailable_helper_retains_and_synchronously_joins_the_owner() {
        let (requests, receiver) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let owner = std::thread::spawn(move || {
            if let Ok(StorageRequest::Shutdown { completion }) = receiver.recv() {
                let _ = completion.send(Ok(()));
            }
        });
        let mut shutdown = StorageShutdown {
            work: Some(StorageShutdownWork {
                requests,
                thread: owner,
            }),
            sender: None,
            thread: None,
            result: None,
        };
        assert_eq!(shutdown.start(), Err(StorageError::Unavailable));
        assert!(shutdown.work.is_some(), "the real owner remains retained");
        assert_eq!(shutdown.wait(), Err(StorageError::Unavailable));
    }

    fn read_request(byte: u8) -> Result<(StorageRequest, Completion<ReadResult>), StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        let plan = ReadPlan::exact(TableId::Account, EngineFixture::account_key(byte)?);
        Ok((StorageRequest::Read { plan, completion }, receiver))
    }

    fn commit_request(batch: StorageMutationBatch) -> (StorageRequest, Completion<CommitOutcome>) {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        (StorageRequest::Commit { batch, completion }, receiver)
    }

    fn checkpoint_request() -> (StorageRequest, Completion<CheckpointOutcome>) {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        (StorageRequest::Checkpoint { completion }, receiver)
    }

    fn queue(
        sender: &SyncSender<StorageRequest>,
        request: StorageRequest,
    ) -> Result<(), StorageError> {
        sender.try_send(request).map_err(map_submission_error)
    }

    fn take<T>(completion: &Completion<T>) -> Result<T, StorageError> {
        completion.recv().map_err(|_| StorageError::Unavailable)?
    }

    fn commit_first_account(engine: &mut StorageEngine, byte: u8) -> Result<(), StorageError> {
        let batch = EngineFixture::advancing_batch(engine, byte)?;
        match engine.commit(batch) {
            CommitOutcome::Committed(_) => Ok(()),
            CommitOutcome::Rejected(error) => Err(error),
            CommitOutcome::Indeterminate => Err(StorageError::Unavailable),
        }
    }

    #[test]
    fn statistics_request_samples_current_state_and_the_exact_construction_sibling()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let state_path = fixture.path().to_path_buf();
        let output_name = state_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StorageError::FilesystemRejected(
                crate::FilesystemCause::UnsafePath,
            ))?;
        let staging = state_path
            .parent()
            .ok_or(StorageError::FilesystemRejected(
                crate::FilesystemCause::UnsafePath,
            ))?
            .join(format!(
                ".{output_name}{}",
                crate::construction_directory::STAGING_SUFFIX
            ));
        std::fs::create_dir(&staging).map_err(crate::filesystem_rejected)?;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))
            .map_err(crate::filesystem_rejected)?;

        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 9)?;
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        let mut state = OwnerState::new();
        assert_eq!(
            dispatch_request(
                engine,
                StorageRequest::Statistics { completion },
                &mut state,
            ),
            OwnerStep::Continue
        );
        let values = take(&receiver)?.values();
        std::fs::remove_dir(&staging).map_err(crate::filesystem_rejected)?;

        assert!(values[0] > 0);
        assert!(values[1] > 0);
        assert!(values[2] >= values[0]);
        assert!(values[3] > values[0]);
        assert!(values[4] >= values[3]);
        assert_eq!(values[5], 1);
        assert_eq!(values[6], 1);
        assert_eq!(values[7], 1);
        assert!(values[9] > 0);
        assert_eq!(values[13], 1);
        Ok(())
    }

    fn drive_checkpoint(
        engine: &mut StorageEngine,
        requests: &Receiver<StorageRequest>,
        state: &mut OwnerState,
    ) -> Result<(), StorageError> {
        for _ in 0..1_000 {
            if !engine.checkpoint_is_active() {
                return Ok(());
            }
            assert_eq!(owner_step(engine, requests, state), OwnerStep::Continue);
        }
        Err(StorageError::StaleState)
    }

    #[test]
    fn due_checkpoint_starts_before_queued_requests_and_interleaves_them()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 1)?;
        engine.mark_checkpoint_due();
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (checkpoint, checkpoint_completion) = checkpoint_request();
        let (read, read_completion) = read_request(1)?;
        queue(&sender, checkpoint)?;
        queue(&sender, read)?;
        let mut state = OwnerState::new();

        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.checkpoint_is_active());
        assert!(read_completion.try_recv().is_err());
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert_eq!(take(&read_completion)?.records.len(), 1);
        drive_checkpoint(engine, &requests, &mut state)?;
        assert!(!engine.checkpoint_due());
        assert!(matches!(
            take(&checkpoint_completion)?,
            CheckpointOutcome::Installed(_)
        ));

        drop(sender);
        assert_eq!(owner_step(engine, &requests, &mut state), OwnerStep::Stop);
        Ok(())
    }

    #[test]
    fn a_due_fact_does_not_start_an_owner_checkpoint_without_a_request() -> Result<(), StorageError>
    {
        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 7)?;
        engine.mark_checkpoint_due();
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (read, read_completion) = read_request(7)?;
        queue(&sender, read)?;
        let mut state = OwnerState::new();

        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert_eq!(take(&read_completion)?.records.len(), 1);
        assert!(engine.checkpoint_due());
        assert!(!engine.checkpoint_is_active());

        drop(sender);
        assert_eq!(owner_step(engine, &requests, &mut state), OwnerStep::Stop);
        Ok(())
    }

    #[test]
    fn rejected_checkpoint_keeps_the_owner_serving_until_a_commit_lifts_suppression()
    -> Result<(), StorageError> {
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::CheckpointScan,
                boundary: StorageFaultBoundary::Before,
            },
            u64::MAX,
        )?;
        let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 2)?;
        engine.mark_checkpoint_due();
        faults.arm_after_current(1)?;
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (checkpoint, checkpoint_completion) = checkpoint_request();
        queue(&sender, checkpoint)?;
        let mut state = OwnerState::new();

        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.checkpoint_is_active());
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        faults.verify_fired()?;
        assert!(!engine.checkpoint_is_active());
        assert!(matches!(
            take(&checkpoint_completion)?,
            CheckpointOutcome::Rejected(StorageError::DatabaseRejected)
        ));

        let (read, read_completion) = read_request(2)?;
        queue(&sender, read)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(!engine.checkpoint_is_active());
        assert_eq!(take(&read_completion)?.records.len(), 1);

        let (stale, stale_completion) = commit_request(EngineFixture::stale_batch(engine, 3)?);
        queue(&sender, stale)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(matches!(
            take(&stale_completion)?,
            CommitOutcome::Rejected(StorageError::StaleState)
        ));

        let (commit, commit_completion) =
            commit_request(EngineFixture::advancing_batch(engine, 3)?);
        queue(&sender, commit)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(matches!(
            take(&commit_completion)?,
            CommitOutcome::Committed(_)
        ));

        let (checkpoint, checkpoint_completion) = checkpoint_request();
        queue(&sender, checkpoint)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.checkpoint_is_active());
        drive_checkpoint(engine, &requests, &mut state)?;
        assert!(!engine.checkpoint_due());
        assert!(matches!(
            take(&checkpoint_completion)?,
            CheckpointOutcome::Installed(_)
        ));
        drop(sender);
        Ok(())
    }

    #[test]
    fn backup_queued_beside_a_checkpoint_is_deferred_until_the_checkpoint_installs()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let backup_directory = fixture.path().join("backups");
        std::fs::create_dir(&backup_directory).map_err(crate::filesystem_rejected)?;
        std::fs::set_permissions(&backup_directory, std::fs::Permissions::from_mode(0o700))
            .map_err(crate::filesystem_rejected)?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 5)?;
        engine.mark_checkpoint_due();
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (checkpoint, checkpoint_completion) = checkpoint_request();
        queue(&sender, checkpoint)?;
        let mut state = OwnerState::new();
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.checkpoint_is_active());

        let (completion, backup_completion) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        queue(
            &sender,
            StorageRequest::Backup {
                destination: BackupDestination::new(&backup_directory, "deferred.backup")?,
                signing_key: Ed25519SecretKey::from_bytes([31; 32]),
                created_at: 1,
                backup_id: [32; 16],
                completion,
            },
        )?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert_eq!(state.deferred.len(), 1);
        assert!(!engine.backup_is_active());
        drive_checkpoint(engine, &requests, &mut state)?;
        assert!(matches!(
            take(&checkpoint_completion)?,
            CheckpointOutcome::Installed(_)
        ));

        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.backup_is_active());
        assert!(state.deferred.is_empty());
        for _ in 0..1_000 {
            if !engine.backup_is_active() {
                break;
            }
            assert_eq!(
                owner_step(engine, &requests, &mut state),
                OwnerStep::Continue
            );
        }
        let _receipt = take(&backup_completion)?;
        assert!(backup_directory.join("deferred.backup").exists());
        drop(sender);
        Ok(())
    }

    #[test]
    fn indeterminate_checkpoint_installation_stops_the_owner() -> Result<(), StorageError> {
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::CheckpointInstall,
                boundary: StorageFaultBoundary::After,
            },
            u64::MAX,
        )?;
        let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 4)?;
        engine.mark_checkpoint_due();
        faults.arm_after_current(1)?;
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (checkpoint, checkpoint_completion) = checkpoint_request();
        queue(&sender, checkpoint)?;
        let mut state = OwnerState::new();
        let mut outcome = OwnerStep::Continue;
        for _ in 0..1_000 {
            if outcome == OwnerStep::Stop {
                break;
            }
            outcome = owner_step(engine, &requests, &mut state);
        }
        assert_eq!(outcome, OwnerStep::Stop);
        faults.verify_fired()?;
        assert!(matches!(
            take(&checkpoint_completion)?,
            CheckpointOutcome::Indeterminate
        ));
        assert_eq!(engine.start_checkpoint(), Err(StorageError::Unavailable));
        drop(sender);
        Ok(())
    }

    #[test]
    fn shutdown_skips_the_checkpoint_while_a_reload_limit_reservation_exists()
    -> Result<(), StorageError> {
        const CHECKPOINT_TARGET: u64 = 10_000;

        let mut fixture = EngineFixture::create()?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 8)?;
        let statistics = engine.statistics()?;
        let values = statistics.values();
        let current = StorageRuntimeLimits::new(values[2], values[4], CHECKPOINT_TARGET)?;
        let (writer, reader) = storage_limit_pair(current);
        engine.replace_runtime_limit_reader(reader);
        let token = TransactionId::from_bytes([88; 16]);
        writer.reserve(
            token,
            current,
            statistics.logical_database_bytes(),
            statistics.backup_stream_bytes(),
        )?;

        assert!(engine.checkpoint_cut_would_advance());
        finish_for_shutdown(engine)?;
        assert!(engine.checkpoint_cut_would_advance());

        writer.rollback(token)?;
        finish_for_shutdown(engine)?;
        assert!(!engine.checkpoint_cut_would_advance());
        Ok(())
    }

    #[test]
    fn completion_distinguishes_pending_success_failure_and_disconnect() {
        let (sender, receiver) = sync_channel(1);
        let completion = StorageCompletion { receiver };
        assert_eq!(completion.try_take(), Ok(None));
        assert!(sender.send(Ok(7_u8)).is_ok());
        assert_eq!(completion.try_take(), Ok(Some(Ok(7))));
        drop(sender);
        assert_eq!(completion.try_take(), Err(StorageError::Unavailable));

        let (sender, receiver) = sync_channel(1);
        assert!(sender.send(Err(StorageError::StaleState)).is_ok());
        assert_eq!(
            StorageCompletion::<u8> { receiver }.wait(),
            Err(StorageError::StaleState)
        );

        let (sender, receiver) = sync_channel::<Result<u8, StorageError>>(1);
        drop(sender);
        assert_eq!(
            StorageCompletion { receiver }.wait(),
            Err(StorageError::Unavailable)
        );
    }

    #[test]
    fn submission_and_checkpoint_errors_preserve_failure_classification() {
        let (sender, receiver) = sync_channel(1);
        assert!(sender.try_send(1_u8).is_ok());
        assert_eq!(
            sender.try_send(2).err().map(map_submission_error),
            Some(StorageError::QueueFull)
        );
        drop(receiver);
        assert_eq!(
            sender.try_send(3).err().map(map_submission_error),
            Some(StorageError::Unavailable)
        );

        assert_eq!(
            checkpoint_error(EngineCommitFailure::Rejected(StorageError::LimitExceeded)),
            StorageError::LimitExceeded
        );
        assert_eq!(
            checkpoint_error(EngineCommitFailure::Indeterminate),
            StorageError::Unavailable
        );
    }
}

#[cfg(test)]
#[path = "owner/tests/backup_phases.rs"]
mod backup_phase_tests;

#[cfg(test)]
#[path = "owner/tests/limit_notices.rs"]
mod limit_notice_tests;
