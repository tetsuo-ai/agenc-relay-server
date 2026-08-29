//! Bounded single-thread ownership port for all blocking storage operations.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};

use agenc_ircd_crypto::Ed25519SecretKey;

use crate::{
    BackupDestination, BackupReceipt, CommitOutcome, ReadPlan, ReadResult, RecoveredStorageState,
    StorageError, StorageMutationBatch,
    engine::{EngineCommitFailure, StorageEngine, StorageOpenConfig},
};

/// Fixed number of complete requests admitted ahead of the storage owner.
pub const STORAGE_REQUEST_QUEUE_CAPACITY: usize = 2;
/// Fixed number of results retained by an individual completion.
pub const STORAGE_COMPLETION_QUEUE_CAPACITY: usize = 2;

enum StorageRequest {
    Commit {
        batch: StorageMutationBatch,
        completion: SyncSender<Result<CommitOutcome, StorageError>>,
    },
    Read {
        plan: ReadPlan,
        completion: SyncSender<Result<ReadResult, StorageError>>,
    },
    Backup {
        destination: BackupDestination,
        signing_key: Ed25519SecretKey,
        created_at: u64,
        backup_id: [u8; 16],
        completion: SyncSender<Result<BackupReceipt, StorageError>>,
    },
    Shutdown {
        completion: SyncSender<Result<(), StorageError>>,
    },
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
    recovered: RecoveredStorageState,
}

impl StorageOwner {
    /// Starts the sole storage thread and completes full startup validation before returning.
    // agenc-review: focus owner=storage reviewed=2026-08-27 reason=startup handshake owns every thread-success and join failure branch
    pub fn start(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let (requests, receiver) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
        let (startup_sender, startup_receiver) = sync_channel(1);
        let thread = thread::Builder::new()
            .name("agenc-ircd-storage-owner".to_owned())
            .spawn(move || {
                let engine = StorageEngine::open(config).and_then(|engine| {
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
            .map_err(|_| StorageError::Unavailable)?;
        match startup_receiver.recv() {
            Ok(Ok(recovered)) => Ok(Self {
                requests,
                thread: Some(thread),
                recovered,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
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

    /// Drains prior requests, closes the owner, and joins the blocking thread.
    pub fn shutdown(mut self) -> Result<(), StorageError> {
        self.join_owner()
    }

    fn join_owner(&mut self) -> Result<(), StorageError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
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
        thread.join().map_err(|_| StorageError::Unavailable)?;
        shutdown_result
    }
}

impl Drop for StorageOwner {
    /// Performs the same joined shutdown as [`StorageOwner::shutdown`] and discards its result.
    ///
    /// The owner thread finishes any active checkpoint, runs one complete checkpoint scan when
    /// manifests are retained, and only then exits, so dropping blocks for that whole scan and
    /// waits behind any deferred backup. Callers that need the outcome, including an
    /// indeterminate failure, must call `shutdown` instead.
    fn drop(&mut self) {
        let _ = self.join_owner();
    }
}

/// Bookkeeping carried across owner iterations.
struct OwnerState {
    deferred: VecDeque<StorageRequest>,
    backup_completion: Option<SyncSender<Result<BackupReceipt, StorageError>>>,
    /// A checkpoint was rejected before its transaction began. Retrying at once would spin on
    /// the same rejection, so due checkpoints wait for the next successful commit.
    checkpoint_suppressed: bool,
}

impl OwnerState {
    fn new() -> Self {
        Self {
            deferred: VecDeque::with_capacity(STORAGE_REQUEST_QUEUE_CAPACITY),
            backup_completion: None,
            checkpoint_suppressed: false,
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
}

/// Runs one owner iteration in priority order: a backup slice, a checkpoint slice, a deferred
/// request, a due checkpoint start, then one blocking request.
// agenc-review: focus owner=storage reviewed=2026-08-29 reason=exhaustive request dispatch centralizes cancellation consumption checkpoint suppression and indeterminate closure
fn owner_step(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
) -> OwnerStep {
    if engine.backup_is_active() {
        return service_active_backup(engine, requests, state);
    }
    if engine.checkpoint_is_active() {
        return service_active_checkpoint(engine, requests, state);
    }
    if let Some(request) = state.deferred.pop_front() {
        return dispatch_or_start_backup(engine, request, state);
    }
    if engine.checkpoint_due() && !state.checkpoint_suppressed {
        // Starting first keeps sustained submission from starving the checkpoint; the active
        // branch above interleaves requests with scan slices. A failed start changed nothing
        // durable, so it only waits for the next successful commit.
        state.checkpoint_suppressed = engine.start_checkpoint().is_err();
        return OwnerStep::Continue;
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

/// Admits at most one queued request beside an active job, deferring the kinds that cannot run
/// next to it: a second backup beside either job, and shutdown beside a backup.
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
        // A backup still finishes for its completion holder after every port is gone; an
        // abandoned checkpoint scan loses nothing durable.
        Err(TryRecvError::Disconnected) => {
            return match job {
                ActiveJob::Backup => OwnerStep::Continue,
                ActiveJob::Checkpoint => OwnerStep::Stop,
            };
        }
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
        (_, StorageRequest::Backup { .. }) | (ActiveJob::Backup, StorageRequest::Shutdown { .. })
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
        Ok(_installed) => OwnerStep::Continue,
        Err(EngineCommitFailure::Rejected(_error)) => {
            // Nothing irreversible began: drop the job, keep serving, and stop retrying until a
            // commit succeeds so a full disk or a rejected scan cannot spin the idle loop.
            engine.abandon_checkpoint();
            state.checkpoint_suppressed = true;
            OwnerStep::Continue
        }
        Err(EngineCommitFailure::Indeterminate) => OwnerStep::Stop,
    }
}

fn dispatch_or_start_backup(
    engine: &mut StorageEngine,
    request: StorageRequest,
    state: &mut OwnerState,
) -> OwnerStep {
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

fn dispatch_request(
    engine: &mut StorageEngine,
    request: StorageRequest,
    state: &mut OwnerState,
) -> OwnerStep {
    match request {
        StorageRequest::Commit { batch, completion } => {
            let result = engine.commit(batch);
            // A successful commit lifts any checkpoint suppression.
            state.checkpoint_suppressed &= !matches!(result, CommitOutcome::Committed(_));
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
        StorageRequest::Backup { completion, .. } => {
            let _ = completion.send(Err(StorageError::QueueFull));
            OwnerStep::Continue
        }
        StorageRequest::Shutdown { completion } => {
            let result = finish_for_shutdown(engine);
            let _ = completion.send(result);
            OwnerStep::Stop
        }
    }
}

fn finish_for_shutdown(engine: &mut StorageEngine) -> Result<(), StorageError> {
    while engine.checkpoint_is_active() {
        engine.service_checkpoint().map_err(checkpoint_error)?;
    }
    engine.checkpoint_for_shutdown().map_err(checkpoint_error)
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
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::engine::tests::EngineFixture;
    use crate::{
        StorageFaultBoundary, StorageFaultCase, StorageFaultInjector, StorageFaultSite, TableId,
    };

    type Completion<T> = Receiver<Result<T, StorageError>>;

    fn read_request(byte: u8) -> Result<(StorageRequest, Completion<ReadResult>), StorageError> {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        let plan = ReadPlan::exact(TableId::Account, EngineFixture::account_key(byte)?);
        Ok((StorageRequest::Read { plan, completion }, receiver))
    }

    fn commit_request(batch: StorageMutationBatch) -> (StorageRequest, Completion<CommitOutcome>) {
        let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
        (StorageRequest::Commit { batch, completion }, receiver)
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
        let (read, read_completion) = read_request(1)?;
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
        assert!(!state.checkpoint_suppressed);

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
        assert!(state.checkpoint_suppressed);

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
        assert!(state.checkpoint_suppressed);

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
        assert!(!state.checkpoint_suppressed);

        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(engine.checkpoint_is_active());
        drive_checkpoint(engine, &requests, &mut state)?;
        assert!(!engine.checkpoint_due());
        drop(sender);
        Ok(())
    }

    #[test]
    fn backup_queued_beside_a_checkpoint_is_deferred_until_the_checkpoint_installs()
    -> Result<(), StorageError> {
        let mut fixture = EngineFixture::create()?;
        let backup_directory = fixture.path().join("backups");
        std::fs::create_dir(&backup_directory).map_err(|_| StorageError::FilesystemRejected)?;
        std::fs::set_permissions(&backup_directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| StorageError::FilesystemRejected)?;
        let engine = fixture.engine_mut()?;
        commit_first_account(engine, 5)?;
        engine.mark_checkpoint_due();
        let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
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
        assert!(!state.checkpoint_suppressed);
        drop(sender);
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
