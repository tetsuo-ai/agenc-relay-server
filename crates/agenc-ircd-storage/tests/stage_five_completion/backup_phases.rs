#![forbid(unsafe_code)]

//! Online backup phases through the real storage owner: the exact
//! authenticated length, one cut under interleaved commits, refusals at
//! every pass boundary, the `R(F) + O` admission boundaries, and restart
//! cleanup.

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use agenc_ircd_crypto::{Ed25519SecretKey, RollbackGuardRootKey, StorageMasterKey};
use agenc_ircd_storage::{
    BackupDestination, BackupReceipt, BackupTrustKey, CommitOutcome, FilesystemCause,
    PersistentRecordValue, RecordMutation, StateDirectory, StorageAccountingLimits, StorageError,
    StorageFaultBoundary, StorageFaultCase, StorageFaultInjector, StorageFaultSite,
    StorageMutationBatch, StorageMutationHead, StorageOwner, StoragePort, StoredKey, TableId,
    verify_backup,
};
use agenc_ircd_types::{AccountRandomId, TransactionId};

use super::{
    InitializedLiveFixture, TestDirectory, initialized_live_fixture, live_open_config, test_limits,
};

const SIGNING_KEY: [u8; 32] = [209; 32];
const BACKUP_TEMPORARY_PREFIX: &str = ".agenc-backup-tmp-v1-";
const SCRATCH_PREFIX: &str = ".agenc-recovery-scratch-v1-";

fn directory_names(directory: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn names_with_prefix(directory: &Path, prefix: &str) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(directory_names(directory)?
        .into_iter()
        .filter(|name| name.starts_with(prefix))
        .collect())
}

fn account_key(index: u32) -> Result<StoredKey, Box<dyn Error>> {
    let mut bytes = [0_u8; 16];
    bytes
        .get_mut(..4)
        .ok_or("short account id")?
        .copy_from_slice(&index.to_be_bytes());
    Ok(StoredKey::new(
        AccountRandomId::from_bytes(bytes).to_text().into_bytes(),
    )?)
}

fn account_plaintext() -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(PersistentRecordValue::new(
        TableId::Account,
        1,
        1,
        1,
        None,
        Vec::new(),
        crate::domain_records::live_body(TableId::Account, 1)?,
    )?
    .encode()?)
}

/// Commits `count` account rows in one batch against the owner's current head.
fn commit_accounts(
    port: &StoragePort,
    first: u32,
    count: u32,
    transaction: u8,
) -> Result<(), Box<dyn Error>> {
    let values = port.try_statistics()?.wait()?.values();
    let head = StorageMutationHead {
        transaction_id: TransactionId::from_bytes([transaction; 16]),
        expected_storage_commit_sequence: values[7],
        expected_state_generation: values[5],
        resulting_state_generation: values[5] + 1,
        state_advancing_plan_count: 1,
        expected_account_service_response_count: values[8],
        resulting_account_service_response_count: values[8] + 1,
    };
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: values[0],
        current_backup_stream_bytes: values[3],
        database_max_bytes: values[2],
        backup_max_bytes: values[4],
    };
    let mutations = (first..first + count)
        .map(|index| {
            Ok(RecordMutation::put(
                TableId::Account,
                account_key(index)?,
                1,
                None,
                account_plaintext()?,
            )?)
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let outcome = port
        .try_commit(StorageMutationBatch::new(head, 1, accounting, mutations)?)?
        .wait()?;
    match outcome {
        CommitOutcome::Committed(_) => Ok(()),
        CommitOutcome::Rejected(error) => Err(error.into()),
        CommitOutcome::Indeterminate => Err("indeterminate commit".into()),
    }
}

fn backup(
    port: &StoragePort,
    directory: &Path,
    name: &str,
    backup_id: u8,
) -> Result<BackupReceipt, StorageError> {
    port.try_backup(
        BackupDestination::new(directory, name)?,
        Ed25519SecretKey::from_bytes(SIGNING_KEY),
        1_700_000_000,
        [backup_id; 16],
    )?
    .wait()
}

fn verified_bytes(path: &Path, receipt: &BackupReceipt) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let verified = verify_backup(
        bytes.as_slice(),
        &StorageMasterKey::from_bytes([207; 32]),
        &RollbackGuardRootKey::from_bytes([208; 32]),
        &[BackupTrustKey::new(
            Ed25519SecretKey::from_bytes(SIGNING_KEY).public_key(),
        )?],
        receipt.stream_bytes,
    )?;
    assert_eq!(u64::try_from(bytes.len())?, receipt.stream_bytes);
    assert_eq!(verified.stream_bytes, receipt.stream_bytes);
    assert_eq!(verified.trailer.record_count, receipt.record_count);
    assert_eq!(verified.trailer.stream_digest, receipt.stream_digest);
    Ok(bytes)
}

fn open_owner(fixture: &InitializedLiveFixture) -> Result<StorageOwner, Box<dyn Error>> {
    Ok(StorageOwner::start(live_open_config(
        StateDirectory::open(fixture.directory.path(), &[fixture.qualification])?,
    ))?)
}

#[test]
fn a_backup_that_fits_writes_the_authenticated_length_and_one_cut_survives_interleaved_commits()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let owner = open_owner(&fixture)?;
    let port = owner.port();
    // More rows than one production slice holds, so every pass takes at
    // least two slices under the real budget.
    commit_accounts(&port, 1, 4_200, 1)?;
    let authenticated_length = port.try_statistics()?.wait()?.backup_stream_bytes();
    let backups = TestDirectory::create()?;

    let single_cut = backup(&port, backups.path(), "single-cut.backup", 1)?;
    assert_eq!(single_cut.stream_bytes, authenticated_length);
    let single_cut_bytes = verified_bytes(&backups.path().join("single-cut.backup"), &single_cut)?;

    // The cut is captured before the commits submitted behind it are served.
    let interleaved = port.try_backup(
        BackupDestination::new(backups.path(), "interleaved.backup")?,
        Ed25519SecretKey::from_bytes(SIGNING_KEY),
        1_700_000_000,
        [1; 16],
    )?;
    for round in 0..3_u32 {
        commit_accounts(&port, 10_000 + round, 1, 10 + u8::try_from(round)?)?;
    }
    let interleaved = interleaved.wait()?;
    let interleaved_bytes =
        verified_bytes(&backups.path().join("interleaved.backup"), &interleaved)?;
    assert_eq!(interleaved.record_count, single_cut.record_count);
    assert!(
        interleaved_bytes == single_cut_bytes,
        "interleaved stream differs"
    );
    assert!(port.try_statistics()?.wait()?.backup_stream_bytes() > authenticated_length);

    // Each interleaved commit added its account row and its manifest row.
    let later = backup(&port, backups.path(), "later.backup", 2)?;
    assert_eq!(later.record_count, single_cut.record_count + 6);
    assert_eq!(
        directory_names(backups.path())?,
        vec![
            "interleaved.backup".to_owned(),
            "later.backup".to_owned(),
            "single-cut.backup".to_owned(),
        ]
    );
    assert_eq!(
        names_with_prefix(fixture.directory.path(), SCRATCH_PREFIX)?,
        Vec::<String>::new()
    );
    owner.shutdown()?;
    Ok(())
}

#[test]
fn a_refusal_at_each_pass_boundary_leaves_no_temporary_and_the_same_name_retries()
-> Result<(), Box<dyn Error>> {
    // Every row is observed once per pass: accounting, copy, verification.
    for (pass, boundary) in [
        (0, StorageFaultBoundary::Before),
        (1, StorageFaultBoundary::After),
        (2, StorageFaultBoundary::Before),
    ] {
        let fixture = initialized_live_fixture()?;
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::BackupRecord,
                boundary,
            },
            u64::MAX,
        )?;
        let owner = StorageOwner::start(live_open_config(StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?))?;
        let port = owner.port();
        commit_accounts(&port, 1, 7, 1)?;
        let backups = TestDirectory::create()?;
        let clean = backup(&port, backups.path(), "clean.backup", 1)?;
        faults.arm_after_current(clean.record_count * pass + 1)?;
        assert_eq!(
            backup(&port, backups.path(), "retry.backup", 2),
            Err(StorageError::DatabaseRejected),
            "pass {pass}"
        );
        faults.verify_fired()?;
        assert_eq!(
            directory_names(backups.path())?,
            vec!["clean.backup".to_owned()],
            "pass {pass}"
        );
        assert_eq!(
            names_with_prefix(fixture.directory.path(), SCRATCH_PREFIX)?,
            Vec::<String>::new()
        );
        let retry = backup(&port, backups.path(), "retry.backup", 2)?;
        assert_eq!(retry.record_count, clean.record_count);
        assert_eq!(retry.stream_bytes, clean.stream_bytes);
        verified_bytes(&backups.path().join("retry.backup"), &retry)?;
        owner.shutdown()?;
    }
    Ok(())
}

struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug)]
enum Boundary {
    /// Available bytes are `R(F) + O - 1`: refused before any output.
    MinusOne,
    /// Available bytes are exactly `R(F) + O`: admitted.
    Equal,
    /// Available bytes are `R(F) + O + 1`: admitted.
    PlusOne,
}

impl Boundary {
    /// The fixed reserve that places `R(F) + O` at this offset from the
    /// sampled available bytes.
    fn reserve(self, available: u64, output_length: u64) -> Option<u64> {
        let base = available.checked_sub(output_length)?;
        match self {
            Self::MinusOne => base.checked_add(1),
            Self::Equal => Some(base),
            Self::PlusOne => base.checked_sub(1),
        }
    }

    const fn admits(self) -> bool {
        !matches!(self, Self::MinusOne)
    }
}

fn filesystem_sample(directory: &Path) -> Result<(u64, u64), Box<dyn Error>> {
    let statistics = rustix::fs::statvfs(directory)?;
    Ok((
        statistics
            .f_bavail
            .checked_mul(statistics.f_frsize)
            .ok_or("available overflow")?,
        statistics
            .f_blocks
            .checked_mul(statistics.f_frsize)
            .ok_or("total overflow")?,
    ))
}

#[test]
fn output_admission_holds_at_the_reserve_plus_the_authenticated_length()
-> Result<(), Box<dyn Error>> {
    const ATTEMPTS: u32 = 8;
    let fixture = initialized_live_fixture()?;
    let output_length = fixture.backup_stream_bytes;
    let backups = TestDirectory::create()?;
    // Startup admits its own scratch at `R(F) + G` on the state filesystem,
    // so a reserve placed one byte around `R(F) + O` on the backup filesystem
    // only opens when the state directory lives on a different, roomier one.
    let state = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("backup-boundary-state-{}", std::process::id()));
    let _ = fs::remove_dir_all(&state);
    fs::create_dir_all(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let _cleanup = RemoveOnDrop(state.clone());
    for entry in fs::read_dir(fixture.directory.path())? {
        let entry = entry?;
        let target = state.join(entry.file_name());
        fs::copy(entry.path(), &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    }
    let qualification = super::signed_qualification(StateDirectory::probe(&state)?)?;
    let (state_available, _) = filesystem_sample(&state)?;
    let (backup_available, _) = filesystem_sample(backups.path())?;
    if fs::metadata(&state)?.dev() == fs::metadata(backups.path())?.dev()
        || state_available / 2 < backup_available
    {
        eprintln!("skipping: no separate, roomier filesystem for the state directory");
        return Ok(());
    }
    let (_, total) = filesystem_sample(backups.path())?;
    let percent_reserve = total
        .checked_mul(1)
        .and_then(|bytes| bytes.checked_add(99))
        .ok_or("overflow")?
        / 100;
    for boundary in [Boundary::MinusOne, Boundary::Equal, Boundary::PlusOne] {
        let mut settled = false;
        for attempt in 1..=ATTEMPTS {
            let (available, _) = filesystem_sample(backups.path())?;
            let Some(reserve) = boundary.reserve(available, output_length) else {
                eprintln!(
                    "skipping {boundary:?}: {available} available bytes cannot hold the boundary"
                );
                settled = true;
                break;
            };
            if reserve < percent_reserve.max(test_limits().fixed_reserve_bytes) {
                eprintln!("skipping {boundary:?}: reserve {reserve} below the configurable floor");
                settled = true;
                break;
            }
            let mut config = live_open_config(StateDirectory::open(&state, &[qualification])?);
            config.limits.fixed_reserve_bytes = reserve;
            let owner = StorageOwner::start(config)?;
            let name = format!("boundary-{boundary:?}-{attempt}.backup");
            let outcome = backup(&owner.port(), backups.path(), &name, 1);
            owner.shutdown()?;
            let admitted = match outcome {
                Ok(receipt) => {
                    assert_eq!(receipt.stream_bytes, output_length);
                    verified_bytes(&backups.path().join(&name), &receipt)?;
                    true
                }
                Err(StorageError::FilesystemRejected(FilesystemCause::InsufficientCapacity)) => {
                    assert!(!backups.path().join(&name).exists());
                    false
                }
                Err(error) => return Err(format!("{boundary:?}: {error}").into()),
            };
            assert_eq!(
                names_with_prefix(backups.path(), BACKUP_TEMPORARY_PREFIX)?,
                Vec::<String>::new()
            );
            if admitted == boundary.admits() {
                settled = true;
                break;
            }
            // Another writer moved the free space between the sample and the
            // admission; sample again.
            eprintln!("{boundary:?} attempt {attempt}: free space moved, retrying");
        }
        assert!(settled, "{boundary:?} never observed a quiet filesystem");
    }
    Ok(())
}

#[test]
fn a_restart_between_phases_sweeps_every_temporary_and_the_next_backup_publishes()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let backups = TestDirectory::create()?;
    // What a kill between phases leaves behind: a backup temporary and a
    // scratch, both random-named under their fixed prefixes.
    for (directory, prefix) in [
        (backups.path(), BACKUP_TEMPORARY_PREFIX),
        (fixture.directory.path(), SCRATCH_PREFIX),
    ] {
        let stale = directory.join(format!("{prefix}{}", "b".repeat(32)));
        fs::write(&stale, b"left behind")?;
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600))?;
    }
    let owner = open_owner(&fixture)?;
    assert_eq!(
        names_with_prefix(fixture.directory.path(), SCRATCH_PREFIX)?,
        Vec::<String>::new(),
        "the open did not sweep the stale scratch"
    );
    let port = owner.port();
    commit_accounts(&port, 1, 5, 1)?;
    let receipt = backup(&port, backups.path(), "swept.backup", 1)?;
    verified_bytes(&backups.path().join("swept.backup"), &receipt)?;
    assert_eq!(
        directory_names(backups.path())?,
        vec!["swept.backup".to_owned()],
        "the stale temporary survived publication"
    );

    // An orderly stop while a backup may still be in its phases either
    // cancels it or lets it publish; it never leaves a temporary, and the
    // restarted owner publishes a fresh name.
    let pending = port.try_backup(
        BackupDestination::new(backups.path(), "stopped.backup")?,
        Ed25519SecretKey::from_bytes(SIGNING_KEY),
        1_700_000_000,
        [2; 16],
    )?;
    owner.shutdown()?;
    match pending.wait() {
        Ok(receipt) => {
            verified_bytes(&backups.path().join("stopped.backup"), &receipt)?;
        }
        Err(StorageError::Unavailable) => assert!(!backups.path().join("stopped.backup").exists()),
        Err(error) => return Err(error.into()),
    }
    assert_eq!(
        names_with_prefix(backups.path(), BACKUP_TEMPORARY_PREFIX)?,
        Vec::<String>::new()
    );
    assert_eq!(
        names_with_prefix(fixture.directory.path(), SCRATCH_PREFIX)?,
        Vec::<String>::new()
    );
    let owner = open_owner(&fixture)?;
    let receipt = backup(&owner.port(), backups.path(), "restarted.backup", 3)?;
    assert_eq!(receipt.record_count, receipt.record_count);
    verified_bytes(&backups.path().join("restarted.backup"), &receipt)?;
    owner.shutdown()?;
    Ok(())
}
