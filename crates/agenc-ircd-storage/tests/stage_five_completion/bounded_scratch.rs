//! Stage 10 STO-04 evidence through the real storage owner: every recovery and reference
//! scratch transaction is admitted against the exact filesystem and bounded before it begins, a
//! checkpoint reads its cut back before it publishes anything, a refused admission is a
//! determinate rejection that leaves the database, the guard and the owner exactly as they were,
//! a large record set verifies in several bounded slices, and a scratch an interrupted
//! verification left behind is removed on the next open and never trusted.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use agenc_ircd_storage::{
    CheckpointOutcome, CommitOutcome, MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
    PersistentRecordValue, RecordMutation, SCRATCH_SLICE_BYTES, SCRATCH_SLICE_ROWS, ScratchUsage,
    StateDirectory, StorageAccountingLimits, StorageError, StorageFaultBoundary, StorageFaultCase,
    StorageFaultInjector, StorageFaultSite, StorageMutationBatch, StorageMutationHead,
    StorageOwner, StoragePort, StoredKey, TableId,
};
use agenc_ircd_types::{AccountRandomId, TransactionId};

use crate::stage_five_completion::{
    InitializedLiveFixture, initialized_live_fixture, live_open_config, test_limits,
};

const SCRATCH_PREFIX: &str = ".agenc-recovery-scratch-v1-";

fn scratch_entries(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    names.retain(|name| name.starts_with(SCRATCH_PREFIX));
    names.sort();
    Ok(names)
}

fn capacity_admission_faults() -> Result<StorageFaultInjector, StorageError> {
    StorageFaultInjector::new(
        StorageFaultCase {
            site: StorageFaultSite::CapacityAdmission,
            boundary: StorageFaultBoundary::Before,
        },
        u64::MAX,
    )
}

/// Every scratch the owner reports was bounded by `G`, admitted transaction by transaction, and
/// peaked an order of magnitude inside the allowance with a resident buffer of at most one byte
/// budget plus the row that crossed it.
fn assert_bounded(usage: ScratchUsage, label: &str) -> Result<(), Box<dyn Error>> {
    if usage.transactions < 2
        || usage.reclamations < usage.transactions
        || usage.allowance_bytes != MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
        || usage.cache_bytes != 8 * 1_048_576
        || usage.creation_bytes == 0
        || usage.peak_file_bytes < usage.creation_bytes
        || usage.peak_transaction_bytes == 0
        || usage.peak_transaction_bytes > MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH / 8
        || usage.charged_bytes < usage.peak_transaction_bytes
        || usage.peak_buffer_bytes == 0
        || usage.peak_buffer_bytes > u64::try_from(SCRATCH_SLICE_BYTES)? + 8_192
    {
        return Err(format!("{label}: scratch usage is not bounded as required: {usage:?}").into());
    }
    Ok(())
}

/// Submits state-advancing account batches of any row count and carries the accounting head
/// every batch must repeat, exactly as the daemon's own projection does.
struct AccountDriver {
    port: StoragePort,
    commit_sequence: u64,
    state_generation: u64,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
    next_account: u64,
}

impl AccountDriver {
    fn new(port: StoragePort, fixture: &InitializedLiveFixture) -> Self {
        Self {
            port,
            commit_sequence: 0,
            state_generation: 0,
            logical_database_bytes: fixture.logical_database_bytes,
            backup_stream_bytes: fixture.backup_stream_bytes,
            next_account: 1,
        }
    }

    fn account_key(index: u64) -> Result<StoredKey, Box<dyn Error>> {
        let mut id = [0_u8; 16];
        for (slot, byte) in id.iter_mut().skip(8).zip(index.to_be_bytes()) {
            *slot = byte;
        }
        Ok(StoredKey::new(
            AccountRandomId::from_bytes(id).to_text().into_bytes(),
        )?)
    }

    /// Commits one batch of `rows` new account rows under one plan.
    fn commit(&mut self, rows: u64) -> Result<CommitOutcome, Box<dyn Error>> {
        let mut transaction = [0_u8; 16];
        for (slot, byte) in transaction
            .iter_mut()
            .skip(8)
            .zip(self.next_account.to_be_bytes())
        {
            *slot = byte;
        }
        let head = StorageMutationHead {
            transaction_id: TransactionId::from_bytes(transaction),
            expected_storage_commit_sequence: self.commit_sequence,
            expected_state_generation: self.state_generation,
            resulting_state_generation: self
                .state_generation
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        };
        let mut mutations = Vec::new();
        for _row in 0..rows {
            let key = Self::account_key(self.next_account)?;
            self.next_account = self
                .next_account
                .checked_add(1)
                .ok_or(StorageError::Overflow)?;
            let body = crate::domain_records::live_body(TableId::Account, 1)?;
            mutations.push(RecordMutation::put(
                TableId::Account,
                key,
                1,
                None,
                PersistentRecordValue::new(TableId::Account, 1, 1, 1, None, Vec::new(), body)?
                    .encode()?,
            )?);
        }
        let batch = StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                current_logical_database_bytes: self.logical_database_bytes,
                current_backup_stream_bytes: self.backup_stream_bytes,
                database_max_bytes: test_limits().database_max_bytes,
                backup_max_bytes: test_limits().backup_max_bytes,
            },
            mutations,
        )?;
        let outcome = self.port.try_commit(batch)?.wait()?;
        if let CommitOutcome::Committed(receipt) = &outcome {
            self.commit_sequence = receipt.storage_commit_sequence;
            self.state_generation = receipt.state_generation;
            let statistics = self.port.try_statistics()?.wait()?;
            self.logical_database_bytes = statistics.logical_database_bytes();
            self.backup_stream_bytes = statistics.backup_stream_bytes();
        }
        Ok(outcome)
    }

    /// Adopts the commit sequence and the accounting a checkpoint installation changed, as
    /// the daemon's projection does from the receipt.
    fn observe_checkpoint(&mut self, receipt: &agenc_ircd_storage::CheckpointReceipt) {
        self.commit_sequence = receipt.storage_commit_sequence;
        self.logical_database_bytes = receipt.logical_database_bytes;
        self.backup_stream_bytes = receipt.backup_stream_bytes;
    }

    fn commit_certainly(&mut self, rows: u64) -> Result<(), Box<dyn Error>> {
        match self.commit(rows)? {
            CommitOutcome::Committed(_) => Ok(()),
            CommitOutcome::Rejected(error) => {
                Err(format!("a priming commit was rejected: {error}").into())
            }
            CommitOutcome::Indeterminate => Err("a priming commit was indeterminate".into()),
        }
    }
}

fn reopen_and_verify(
    fixture: &InitializedLiveFixture,
) -> Result<(ScratchUsage, ScratchUsage), Box<dyn Error>> {
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))?;
    let recovered = owner.recovered_state();
    let usage = (
        recovered.verification_scratch(),
        recovered.reference_scratch(),
    );
    owner.shutdown()?;
    Ok(usage)
}

#[test]
fn a_refused_checkpoint_scratch_admission_rejects_without_publishing_and_keeps_the_owner_usable()
-> Result<(), Box<dyn Error>> {
    let mut installed_at = None;
    for occurrence in 1..=16_u64 {
        let fixture = initialized_live_fixture()?;
        let faults = capacity_admission_faults()?;
        let owner = StorageOwner::start(live_open_config(StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?))?;
        let mut driver = AccountDriver::new(owner.port(), &fixture);
        driver.commit_certainly(1)?;
        let guard_path = fixture.directory.path().join("rollback.guard");
        let guard_before = fs::read(&guard_path)?;
        faults.arm_after_current(occurrence)?;
        let outcome = owner.port().try_checkpoint()?.wait()?;
        if faults.verify_fired().is_err() {
            let CheckpointOutcome::Installed(receipt) = outcome else {
                return Err(format!("unarmed checkpoint did not install: {outcome:?}").into());
            };
            assert_bounded(receipt.readback_scratch, "installed readback")?;
            owner.shutdown()?;
            installed_at = Some(occurrence);
            break;
        }
        if !matches!(
            outcome,
            CheckpointOutcome::Rejected(StorageError::DatabaseRejected)
        ) {
            return Err(format!(
                "admission {occurrence} was not a determinate rejection: {outcome:?}"
            )
            .into());
        }
        // Nothing was published: the guard is byte-identical and no scratch entry remains.
        if fs::read(&guard_path)? != guard_before {
            return Err(format!("admission {occurrence} replaced the guard").into());
        }
        if !scratch_entries(fixture.directory.path())?.is_empty() {
            return Err(format!("admission {occurrence} left a scratch entry").into());
        }
        // The owner stays usable: the same checkpoint installs once its samples are admitted
        // again, the next commit goes through, and the directory reopens with a bounded
        // verification.
        let CheckpointOutcome::Installed(receipt) = owner.port().try_checkpoint()?.wait()? else {
            return Err(format!("admission {occurrence} left the checkpoint refused").into());
        };
        assert_bounded(receipt.readback_scratch, "retried readback")?;
        driver.observe_checkpoint(&receipt);
        driver.commit_certainly(1)?;
        owner.shutdown()?;
        let (verification, references) = reopen_and_verify(&fixture)?;
        assert_bounded(verification, "reopened verification")?;
        assert_bounded(references, "reopened references")?;
    }
    if !installed_at.is_some_and(|occurrence| occurrence >= 3) {
        return Err(format!("too few scratch admissions were refused: {installed_at:?}").into());
    }
    Ok(())
}

#[test]
fn a_refused_startup_scratch_admission_fails_closed_and_leaves_no_scratch_behind()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    {
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            fixture.directory.path(),
            &[fixture.qualification],
        )?))?;
        let mut driver = AccountDriver::new(owner.port(), &fixture);
        driver.commit_certainly(2)?;
        owner.shutdown()?;
    }
    for occurrence in 1..=2_u64 {
        let faults = capacity_admission_faults()?;
        let state_directory = StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults.clone(),
        )?;
        faults.arm_after_current(occurrence)?;
        let result = StorageOwner::start(live_open_config(state_directory));
        if !matches!(result, Err(StorageError::DatabaseRejected)) {
            return Err(format!(
                "startup admission {occurrence} did not fail closed: {:?}",
                result.map(|owner| owner.recovered_state().storage_commit_sequence())
            )
            .into());
        }
        faults.verify_fired()?;
        if !scratch_entries(fixture.directory.path())?.is_empty() {
            return Err(format!("startup admission {occurrence} left a scratch entry").into());
        }
    }
    let (verification, references) = reopen_and_verify(&fixture)?;
    assert_bounded(verification, "verification")?;
    assert_bounded(references, "references")?;
    Ok(())
}

#[test]
fn many_records_verify_in_several_bounded_slices_at_checkpoint_and_startup()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))?;
    let mut driver = AccountDriver::new(owner.port(), &fixture);
    let rows_per_batch = 512_u64;
    let batches = u64::try_from(SCRATCH_SLICE_ROWS)? / rows_per_batch + 2;
    for _batch in 0..batches {
        driver.commit_certainly(rows_per_batch)?;
    }
    let CheckpointOutcome::Installed(receipt) = owner.port().try_checkpoint()?.wait()? else {
        return Err("the checkpoint over the large record set did not install".into());
    };
    // Creation plus at least two current-row slices: the full current set was never one
    // transaction, and the largest one stayed far inside the allowance.
    assert_bounded(receipt.readback_scratch, "checkpoint readback")?;
    if receipt.readback_scratch.transactions < 3 {
        return Err(format!(
            "the readback used too few slices: {:?}",
            receipt.readback_scratch
        )
        .into());
    }
    // One more batch after the cut, so the clean shutdown installs a second bounded
    // checkpoint over the larger set before the reopen verifies it again.
    driver.observe_checkpoint(&receipt);
    driver.commit_certainly(rows_per_batch)?;
    owner.shutdown()?;
    let (verification, references) = reopen_and_verify(&fixture)?;
    assert_bounded(verification, "startup verification")?;
    assert_bounded(references, "startup references")?;
    if verification.transactions < 3 || references.transactions < 3 {
        return Err(format!("startup used too few slices: {verification:?} {references:?}").into());
    }
    Ok(())
}

#[test]
fn a_scratch_left_by_an_interrupted_verification_is_removed_on_reopen_and_never_trusted()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    {
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            fixture.directory.path(),
            &[fixture.qualification],
        )?))?;
        let mut driver = AccountDriver::new(owner.port(), &fixture);
        driver.commit_certainly(3)?;
        owner.shutdown()?;
    }
    // A kill in the middle of a verification leaves its scratch entry behind; an unrelated
    // entry of the directory must survive the cleanup that removes it.
    let stale = fixture
        .directory
        .path()
        .join(format!("{SCRATCH_PREFIX}{}", "c".repeat(32)));
    let unrelated = fixture.directory.path().join("unrelated.keep");
    for (path, bytes) in [(&stale, 65_536_usize), (&unrelated, 16)] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&vec![0xC3_u8; bytes])?;
    }
    let (verification, references) = reopen_and_verify(&fixture)?;
    // The reopen rebuilt its own scratch from nothing, removed the stale entry, and kept the
    // unrelated one.
    assert_bounded(verification, "verification after a stale scratch")?;
    assert_bounded(references, "references after a stale scratch")?;
    if stale.exists() {
        return Err("the stale scratch entry survived the reopen".into());
    }
    if !unrelated.exists() {
        return Err("the cleanup removed an unrelated entry".into());
    }
    if !scratch_entries(fixture.directory.path())?.is_empty() {
        return Err("the reopen left a scratch entry of its own".into());
    }
    Ok(())
}

/// Offset of the configured reserve from the exact `available - G` point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Boundary {
    /// Available space is one byte below `R(F) + G`.
    MinusOne,
    /// Available space is exactly `R(F) + G`.
    Equal,
    /// Available space is one byte above `R(F) + G`.
    PlusOne,
}

const BOUNDARY_ATTEMPTS: usize = 24;

/// Opens the real owner with a reserve that puts the filesystem at `boundary`, on a sample the
/// open itself did not move, and returns it with whether its scratch verification was deferred.
fn open_at_boundary(
    fixture: &InitializedLiveFixture,
    boundary: Boundary,
) -> Result<(StorageOwner, bool), Box<dyn Error>> {
    for _attempt in 0..BOUNDARY_ATTEMPTS {
        let before = StateDirectory::open(fixture.directory.path(), &[fixture.qualification])?
            .capacity(0, 0)?
            .available_bytes;
        let exact = before
            .checked_sub(MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH)
            .ok_or("the test filesystem is smaller than the growth allowance")?;
        let mut limits = test_limits();
        limits.fixed_reserve_bytes = match boundary {
            Boundary::MinusOne => exact.checked_add(1).ok_or(StorageError::Overflow)?,
            Boundary::Equal => exact,
            Boundary::PlusOne => exact.checked_sub(1).ok_or(StorageError::Overflow)?,
        };
        let mut config = live_open_config(StateDirectory::open(
            fixture.directory.path(),
            &[fixture.qualification],
        )?);
        config.limits = limits;
        // Section 19.3: whatever the boundary, the owner opens.
        let owner = StorageOwner::start(config)?;
        let statistics = owner.port().try_statistics()?.wait()?;
        if statistics.filesystem_available_bytes() != before
            || statistics.filesystem_reserve_bytes() != limits.fixed_reserve_bytes
        {
            let _ = owner.shutdown();
            std::thread::sleep(std::time::Duration::from_millis(50));
            continue;
        }
        let deferred = owner.recovered_state().verification_scratch().transactions == 0;
        return Ok((owner, deferred));
    }
    Err("filesystem capacity did not settle for a boundary observation".into())
}

#[test]
fn the_owner_opens_at_all_three_reserve_boundaries_and_only_the_commit_is_refused()
-> Result<(), Box<dyn Error>> {
    for boundary in [Boundary::MinusOne, Boundary::Equal, Boundary::PlusOne] {
        let fixture = initialized_live_fixture()?;
        let (owner, deferred) = open_at_boundary(&fixture, boundary)?;
        let mut driver = AccountDriver::new(owner.port(), &fixture);
        let outcome = driver.commit(1)?;
        match boundary {
            Boundary::MinusOne => {
                if !deferred {
                    return Err("one byte below the gate did not defer the scratch".into());
                }
                if !matches!(
                    outcome,
                    CommitOutcome::Rejected(StorageError::FilesystemRejected(
                        agenc_ircd_storage::FilesystemCause::InsufficientCapacity
                    ))
                ) {
                    return Err("one byte below the gate was not refused at the commit".into());
                }
            }
            Boundary::Equal | Boundary::PlusOne => {
                if deferred {
                    return Err(format!("{boundary:?} deferred a scratch it could admit").into());
                }
                if !matches!(outcome, CommitOutcome::Committed(_)) {
                    return Err(format!("{boundary:?} did not admit the commit").into());
                }
            }
        }
        if !scratch_entries(fixture.directory.path())?.is_empty() {
            return Err(format!("{boundary:?} left a scratch entry").into());
        }
        // A shutdown checkpoint under the same pressure may be refused; the open is the claim.
        let _ = owner.shutdown();
    }
    Ok(())
}

#[test]
fn a_deferred_verification_runs_and_gates_the_first_write_once_space_returns()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    {
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            fixture.directory.path(),
            &[fixture.qualification],
        )?))?;
        let mut driver = AccountDriver::new(owner.port(), &fixture);
        driver.commit_certainly(3)?;
        owner.shutdown()?;
    }
    // Eight MiB of ballast hold the filesystem one byte below the gate; removing them is the
    // space returning.
    let ballast = fixture.directory.path().join("ballast.keep");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ballast)?;
        file.write_all(&vec![0xB5_u8; 8 * 1_048_576])?;
        file.sync_all()?;
    }
    let (owner, deferred) = open_at_boundary(&fixture, Boundary::MinusOne)?;
    if !deferred {
        return Err("the open below the gate did not defer its scratch verification".into());
    }
    let statistics = owner.port().try_statistics()?.wait()?;
    let mut driver = AccountDriver::new(owner.port(), &fixture);
    driver.commit_sequence = owner.recovered_state().storage_commit_sequence();
    driver.state_generation = owner.recovered_state().state_generation();
    driver.logical_database_bytes = statistics.logical_database_bytes();
    driver.backup_stream_bytes = statistics.backup_stream_bytes();
    driver.next_account = 100;
    if !matches!(
        driver.commit(1)?,
        CommitOutcome::Rejected(StorageError::FilesystemRejected(
            agenc_ircd_storage::FilesystemCause::InsufficientCapacity
        ))
    ) {
        return Err("a write was accepted while the verification was owed".into());
    }
    fs::remove_file(&ballast)?;
    // The first write after the space returned pays the owed verification in fresh bounded
    // scratch, leaves no entry, and commits.
    driver.commit_certainly(1)?;
    if !scratch_entries(fixture.directory.path())?.is_empty() {
        return Err("the deferred verification left a scratch entry".into());
    }
    driver.commit_certainly(1)?;
    let _ = owner.shutdown();
    Ok(())
}
