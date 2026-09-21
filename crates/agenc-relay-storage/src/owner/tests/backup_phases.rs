#![forbid(unsafe_code)]

//! Owner-level fairness and cancellation for the sliced backup phases.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use agenc_relay_crypto::Ed25519SecretKey;

use super::*;
use crate::engine::backup_job::BACKUP_SLICE_BYTES;
use crate::engine::tests::EngineFixture;
use crate::{BackupDestination, TableId};

type Completion<T> = Receiver<Result<T, StorageError>>;

const PHASES: [&str; 7] = [
    "accounting",
    "resolving",
    "admitting",
    "copying",
    "sealing",
    "verifying",
    "publishing",
];

fn queue(sender: &SyncSender<StorageRequest>, request: StorageRequest) -> Result<(), StorageError> {
    sender.try_send(request).map_err(map_submission_error)
}

fn take<T>(completion: &Completion<T>) -> Result<T, StorageError> {
    completion.recv().map_err(|_| StorageError::Unavailable)?
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

fn backup_request(
    directory: &Path,
    name: &str,
    backup_id: u8,
) -> Result<(StorageRequest, Completion<BackupReceipt>), StorageError> {
    let (completion, receiver) = sync_channel(STORAGE_COMPLETION_QUEUE_CAPACITY);
    Ok((
        StorageRequest::Backup {
            destination: BackupDestination::new(directory, name)?,
            signing_key: Ed25519SecretKey::from_bytes([61; 32]),
            created_at: 1,
            backup_id: [backup_id; 16],
            completion,
        },
        receiver,
    ))
}

fn backup_directory(fixture: &EngineFixture, name: &str) -> Result<PathBuf, StorageError> {
    let directory = fixture.path().join(name);
    fs::create_dir(&directory).map_err(crate::filesystem_rejected)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(crate::filesystem_rejected)?;
    Ok(directory)
}

fn directory_names(directory: &Path) -> Result<Vec<String>, StorageError> {
    let mut names = fs::read_dir(directory)
        .map_err(crate::filesystem_rejected)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn scratch_names(state_directory: &Path) -> Result<Vec<String>, StorageError> {
    Ok(directory_names(state_directory)?
        .into_iter()
        .filter(|name| name.starts_with(".agenc-recovery-scratch-v1-"))
        .collect())
}

fn commit_account(engine: &mut StorageEngine, byte: u8) -> Result<(), StorageError> {
    match engine.commit(EngineFixture::advancing_batch(engine, byte)?) {
        CommitOutcome::Committed(_) => Ok(()),
        CommitOutcome::Rejected(error) => Err(error),
        CommitOutcome::Indeterminate => Err(StorageError::Unavailable),
    }
}

fn drive_backup(
    engine: &mut StorageEngine,
    requests: &Receiver<StorageRequest>,
    state: &mut OwnerState,
) -> Result<(), StorageError> {
    for _ in 0..100_000 {
        if !engine.backup_is_active() {
            return Ok(());
        }
        if owner_step(engine, requests, state) != OwnerStep::Continue {
            return Err(StorageError::Unavailable);
        }
    }
    Err(StorageError::LimitExceeded)
}

#[test]
fn reads_and_commits_are_served_between_slices_of_every_phase() -> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "fair-backups")?;
    let engine = fixture.engine_mut()?;
    for byte in 1..=10 {
        commit_account(engine, byte)?;
    }
    let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
    let mut state = OwnerState::new();

    // One quiescent backup names the cut's exact row count.
    let (quiescent, quiescent_completion) = backup_request(&directory, "quiescent.backup", 1)?;
    queue(&sender, quiescent)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    drive_backup(engine, &requests, &mut state)?;
    let quiescent = take(&quiescent_completion)?;

    let (backup, backup_completion) = backup_request(&directory, "fair.backup", 1)?;
    queue(&sender, backup)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    assert!(engine.backup_is_active());
    engine.set_backup_slice_budget(2, BACKUP_SLICE_BYTES)?;
    let mut served: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    let mut next_byte = 100_u8;
    while engine.backup_is_active() {
        let phase = engine.backup_phase().ok_or(StorageError::StaleState)?;
        let (read, read_completion) = read_request(1)?;
        queue(&sender, read)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert_eq!(take(&read_completion)?.records.len(), 1, "{phase}");
        served.entry(phase).or_insert((0, 0)).0 += 1;
        if !engine.backup_is_active() {
            break;
        }
        let phase = engine.backup_phase().ok_or(StorageError::StaleState)?;
        let (commit, commit_completion) =
            commit_request(EngineFixture::advancing_batch(engine, next_byte)?);
        next_byte = next_byte.checked_add(1).ok_or(StorageError::Overflow)?;
        queue(&sender, commit)?;
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
        assert!(
            matches!(take(&commit_completion)?, CommitOutcome::Committed(_)),
            "{phase}"
        );
        served.entry(phase).or_insert((0, 0)).1 += 1;
    }
    let receipt = take(&backup_completion)?;
    assert_eq!(receipt.record_count, quiescent.record_count);
    assert_eq!(receipt.stream_digest, quiescent.stream_digest);
    // Every phase, including the one-step ones, had a request served beside
    // it; the sliced passes had both reads and commits.
    for phase in PHASES {
        let (reads, commits) = served.get(phase).copied().unwrap_or((0, 0));
        assert!(
            reads + commits > 0,
            "nothing served beside {phase}: {served:?}"
        );
    }
    for phase in ["accounting", "copying", "verifying"] {
        let (reads, commits) = served.get(phase).copied().unwrap_or((0, 0));
        assert!(
            reads > 0 && commits > 0,
            "{phase} was not interleaved: {served:?}"
        );
    }
    assert!(
        directory_names(&directory)?
            .iter()
            .all(|name| !name.starts_with(".agenc-backup-tmp-v1-"))
    );
    drop(sender);
    assert_eq!(owner_step(engine, &requests, &mut state), OwnerStep::Stop);
    Ok(())
}

#[test]
fn shutdown_cancels_an_active_backup_and_removes_its_temporary() -> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "shutdown-backups")?;
    let state_directory = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    for byte in 1..=6 {
        commit_account(engine, byte)?;
    }
    let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
    let mut state = OwnerState::new();
    let (backup, backup_completion) = backup_request(&directory, "cancelled.backup", 1)?;
    queue(&sender, backup)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    engine.set_backup_slice_budget(2, BACKUP_SLICE_BYTES)?;
    while engine.backup_phase() != Some("copying") {
        assert_eq!(
            owner_step(engine, &requests, &mut state),
            OwnerStep::Continue
        );
    }
    assert_eq!(directory_names(&directory)?.len(), 1);
    assert!(backup_completion.try_recv().is_err());

    let (completion, shutdown_completion) = sync_channel(1);
    queue(&sender, StorageRequest::Shutdown { completion })?;
    assert_eq!(owner_step(engine, &requests, &mut state), OwnerStep::Stop);
    assert_eq!(take(&backup_completion), Err(StorageError::Unavailable));
    take(&shutdown_completion)?;
    assert!(!engine.backup_is_active());
    assert!(state.backup_completion.is_none());
    assert_eq!(directory_names(&directory)?, Vec::<String>::new());
    assert_eq!(scratch_names(&state_directory)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_dropped_receiver_neither_cancels_nor_leaks_the_backup() -> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "dropped-backups")?;
    let state_directory = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    for byte in 1..=3 {
        commit_account(engine, byte)?;
    }
    let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
    let mut state = OwnerState::new();
    let (backup, backup_completion) = backup_request(&directory, "unwatched.backup", 1)?;
    queue(&sender, backup)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    drop(backup_completion);
    drive_backup(engine, &requests, &mut state)?;
    assert!(state.backup_completion.is_none());
    assert_eq!(
        directory_names(&directory)?,
        vec!["unwatched.backup".to_owned()]
    );
    assert!(
        fs::metadata(directory.join("unwatched.backup"))
            .map_err(crate::filesystem_rejected)?
            .len()
            > 0
    );
    assert_eq!(scratch_names(&state_directory)?, Vec::<String>::new());
    drop(sender);
    assert_eq!(owner_step(engine, &requests, &mut state), OwnerStep::Stop);
    Ok(())
}

#[test]
fn a_competing_backup_waits_for_the_slot_and_a_misrouted_one_is_refused() -> Result<(), StorageError>
{
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "competing-backups")?;
    let engine = fixture.engine_mut()?;
    for byte in 1..=4 {
        commit_account(engine, byte)?;
    }
    let (sender, requests) = sync_channel(STORAGE_REQUEST_QUEUE_CAPACITY);
    let mut state = OwnerState::new();
    let (first, first_completion) = backup_request(&directory, "first.backup", 1)?;
    let (second, second_completion) = backup_request(&directory, "second.backup", 2)?;
    queue(&sender, first)?;
    queue(&sender, second)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    assert!(engine.backup_is_active());
    engine.set_backup_slice_budget(2, BACKUP_SLICE_BYTES)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    assert_eq!(state.deferred.len(), 1);
    assert!(second_completion.try_recv().is_err());
    drive_backup(engine, &requests, &mut state)?;
    let first = take(&first_completion)?;
    assert_eq!(
        owner_step(engine, &requests, &mut state),
        OwnerStep::Continue
    );
    assert!(engine.backup_is_active());
    assert!(state.deferred.is_empty());
    drive_backup(engine, &requests, &mut state)?;
    let second = take(&second_completion)?;
    assert_eq!(second.record_count, first.record_count);
    assert_eq!(
        directory_names(&directory)?,
        vec!["first.backup".to_owned(), "second.backup".to_owned()]
    );

    let (misrouted, misrouted_completion) = backup_request(&directory, "third.backup", 3)?;
    assert_eq!(
        dispatch_request(engine, misrouted, &mut state),
        OwnerStep::Continue
    );
    assert_eq!(take(&misrouted_completion), Err(StorageError::QueueFull));
    drop(sender);
    Ok(())
}
