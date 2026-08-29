//! Bounded single-thread ownership port for all blocking storage operations.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};

use agenc_ircd_crypto::Ed25519SecretKey;

use crate::{
    BackupDestination, BackupReceipt, CommitOutcome, ReadPlan, ReadResult, StorageError,
    StorageMutationBatch,
    engine::{StorageEngine, StorageOpenConfig},
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
                    let _capacity = engine.startup_scan()?;
                    Ok(engine)
                });
                match engine {
                    Ok(mut engine) => {
                        if startup_sender.send(Ok(())).is_err() {
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
            Ok(Ok(())) => Ok(Self {
                requests,
                thread: Some(thread),
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
    fn drop(&mut self) {
        let _ = self.join_owner();
    }
}

// agenc-review: focus owner=storage reviewed=2026-08-27 reason=exhaustive request dispatch centralizes cancellation consumption and indeterminate closure
fn run_owner(engine: &mut StorageEngine, requests: &Receiver<StorageRequest>) {
    let mut deferred = VecDeque::with_capacity(STORAGE_REQUEST_QUEUE_CAPACITY);
    let mut backup_completion: Option<SyncSender<Result<BackupReceipt, StorageError>>> = None;
    loop {
        if engine.backup_is_active() {
            if deferred.len() < STORAGE_REQUEST_QUEUE_CAPACITY {
                match requests.try_recv() {
                    Ok(
                        request @ (StorageRequest::Backup { .. } | StorageRequest::Shutdown { .. }),
                    ) => {
                        deferred.push_back(request);
                    }
                    Ok(request) => {
                        if !dispatch_request(engine, request) {
                            return;
                        }
                    }
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
                }
            }
            match engine.service_backup() {
                Ok(Some(receipt)) => {
                    if let Some(completion) = backup_completion.take() {
                        let _ = completion.send(Ok(receipt));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    if let Some(completion) = backup_completion.take() {
                        let _ = completion.send(Err(error));
                    }
                }
            }
            continue;
        }
        if engine.checkpoint_is_active() {
            if deferred.len() < STORAGE_REQUEST_QUEUE_CAPACITY {
                match requests.try_recv() {
                    Ok(request @ StorageRequest::Backup { .. }) => {
                        deferred.push_back(request);
                    }
                    Ok(request) => {
                        if !dispatch_request(engine, request) {
                            return;
                        }
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            if engine.service_checkpoint().is_err() {
                return;
            }
            continue;
        }
        if let Some(request) = deferred.pop_front() {
            if !dispatch_or_start_backup(engine, request, &mut backup_completion) {
                return;
            }
            continue;
        }
        let Ok(checkpoint_due) = engine.checkpoint_due() else {
            return;
        };
        if checkpoint_due {
            match requests.try_recv() {
                Ok(request) => {
                    if !dispatch_or_start_backup(engine, request, &mut backup_completion) {
                        return;
                    }
                }
                Err(TryRecvError::Empty) => {
                    if engine.start_checkpoint().is_err() {
                        return;
                    }
                }
                Err(TryRecvError::Disconnected) => return,
            }
            continue;
        }
        let Ok(request) = requests.recv() else {
            return;
        };
        if !dispatch_or_start_backup(engine, request, &mut backup_completion) {
            return;
        }
    }
}

fn dispatch_or_start_backup(
    engine: &mut StorageEngine,
    request: StorageRequest,
    backup_completion: &mut Option<SyncSender<Result<BackupReceipt, StorageError>>>,
) -> bool {
    let StorageRequest::Backup {
        destination,
        signing_key,
        created_at,
        backup_id,
        completion,
    } = request
    else {
        return dispatch_request(engine, request);
    };
    match engine.start_backup(destination, signing_key, created_at, backup_id) {
        Ok(()) => {
            *backup_completion = Some(completion);
        }
        Err(error) => {
            let _ = completion.send(Err(error));
        }
    }
    true
}

fn dispatch_request(engine: &mut StorageEngine, request: StorageRequest) -> bool {
    match request {
        StorageRequest::Commit { batch, completion } => {
            let result = engine.commit(batch);
            let closes_owner = matches!(result, CommitOutcome::Indeterminate);
            let _ = completion.send(Ok(result));
            !closes_owner
        }
        StorageRequest::Read { plan, completion } => {
            let _ = completion.send(engine.read(&plan));
            true
        }
        StorageRequest::Backup { completion, .. } => {
            let _ = completion.send(Err(StorageError::QueueFull));
            true
        }
        StorageRequest::Shutdown { completion } => {
            let result = finish_for_shutdown(engine);
            let _ = completion.send(result);
            false
        }
    }
}

fn finish_for_shutdown(engine: &mut StorageEngine) -> Result<(), StorageError> {
    while engine.checkpoint_is_active() {
        engine.service_checkpoint().map_err(checkpoint_error)?;
    }
    engine.checkpoint_for_shutdown().map_err(checkpoint_error)
}

fn checkpoint_error(error: crate::engine::EngineCommitFailure) -> StorageError {
    match error {
        crate::engine::EngineCommitFailure::Rejected(error) => error,
        crate::engine::EngineCommitFailure::Indeterminate => StorageError::Unavailable,
    }
}

fn map_submission_error<T>(error: TrySendError<T>) -> StorageError {
    match error {
        TrySendError::Full(_) => StorageError::QueueFull,
        TrySendError::Disconnected(_) => StorageError::Unavailable,
    }
}
