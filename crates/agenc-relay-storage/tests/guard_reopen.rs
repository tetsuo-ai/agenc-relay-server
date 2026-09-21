//! Stage 10 STO-10 evidence: the database/guard publication window across an abandoned owner.
//!
//! Every durable storage operation publishes its control state twice, and both publications make
//! the in-database nonce-reservation record durable before they replace the on-disk rollback
//! guard. The guard can therefore only lag its record, never lead it, and only ever by one
//! publication step. These cases abandon a real storage owner at each of those boundaries,
//! reopen the same directory, and require the exact prior or successor state; they then push the
//! guard one step further behind and require the reopen to refuse.

#![forbid(unsafe_code)]

use std::error::Error;

use agenc_relay_storage::{
    CommitOutcome, PersistentRecordValue, ROLLBACK_GUARD_BYTES, RecordMutation, StateDirectory,
    StorageAccountingLimits, StorageError, StorageFaultBoundary, StorageFaultCase,
    StorageFaultInjector, StorageFaultSite, StorageMutationBatch, StorageMutationHead,
    StorageOwner, StoragePort, StoredKey, TableId,
};
use agenc_relay_types::{AccountRandomId, TransactionId};

use crate::stage_five_completion::{
    InitializedLiveFixture, initialized_live_fixture, live_open_config, test_limits,
};

/// The boundaries one guard publication passes, in the order `replace_guard` reaches them.
/// Abandoning before the rename leaves the previous guard published; abandoning after it leaves
/// the new guard published. Both sides leave the interrupted operation unfinished.
const GUARD_BOUNDARIES: [StorageFaultSite; 5] = [
    StorageFaultSite::GuardTemporaryCreate,
    StorageFaultSite::GuardWrite,
    StorageFaultSite::GuardFileSync,
    StorageFaultSite::GuardRename,
    StorageFaultSite::GuardDirectorySync,
];

/// The first guard publication of a durable operation, which anchors its reserved nonce block
/// before any nonce is drawn.
const RESERVED_PUBLICATION: u64 = 1;

/// The second guard publication of a durable operation, which names the data the operation's
/// transaction has already made durable.
const COMMITTED_PUBLICATION: u64 = 2;

/// The durable operation whose publication window an abandonment interrupts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableOperation {
    /// One ordinary application transaction submitted through the commit port.
    Commit,
    /// One explicitly requested integrity checkpoint installation.
    Checkpoint,
}

/// Submits state-advancing single-record batches and carries the accounting head every batch
/// must repeat, exactly as the daemon's own projection does.
struct CommitDriver {
    port: StoragePort,
    commit_sequence: u64,
    state_generation: u64,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
    transaction: u64,
}

impl CommitDriver {
    /// Seeds the head from the accounting the freshly initialized fixture reported.
    fn new(port: StoragePort, fixture: &InitializedLiveFixture) -> Self {
        Self {
            port,
            commit_sequence: 0,
            state_generation: 0,
            logical_database_bytes: fixture.logical_database_bytes,
            backup_stream_bytes: fixture.backup_stream_bytes,
            transaction: 1,
        }
    }

    /// Builds the next batch: one new account row under a seed-derived key.
    fn batch(&mut self, seed: u8) -> Result<StorageMutationBatch, Box<dyn Error>> {
        let mut transaction = [0_u8; 16];
        for (slot, byte) in transaction
            .iter_mut()
            .skip(8)
            .zip(self.transaction.to_be_bytes())
        {
            *slot = byte;
        }
        self.transaction = self
            .transaction
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
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
        let key = AccountRandomId::from_bytes([seed; 16])
            .to_text()
            .into_bytes();
        let body = crate::domain_records::live_body(TableId::Account, 1)?;
        Ok(StorageMutationBatch::new(
            head,
            1,
            StorageAccountingLimits {
                current_logical_database_bytes: self.logical_database_bytes,
                current_backup_stream_bytes: self.backup_stream_bytes,
                database_max_bytes: test_limits().database_max_bytes,
                backup_max_bytes: test_limits().backup_max_bytes,
            },
            vec![RecordMutation::put(
                TableId::Account,
                StoredKey::new(key)?,
                1,
                None,
                PersistentRecordValue::new(TableId::Account, 1, 1, 1, None, Vec::new(), body)?
                    .encode()?,
            )?],
        )?)
    }

    /// Submits one batch and refreshes the head from the receipt and the owner's statistics.
    fn commit(&mut self, seed: u8) -> Result<CommitOutcome, Box<dyn Error>> {
        let batch = self.batch(seed)?;
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

    /// Submits `count` batches and refuses anything but a certain commit for each of them.
    fn prime(&mut self, count: u8) -> Result<(), Box<dyn Error>> {
        for index in 0..count {
            let outcome = self.commit(10_u8.wrapping_add(index))?;
            if !matches!(outcome, CommitOutcome::Committed(_)) {
                return Err("a priming commit did not report a certain success".into());
            }
        }
        Ok(())
    }
}

/// One closed state directory and the commit sequence its owner had reached before the
/// operation under test.
struct ClosedDirectory {
    fixture: InitializedLiveFixture,
    prior_commit_sequence: u64,
}

impl ClosedDirectory {
    /// Reads the published guard through an ordinary writer-authoritative open.
    fn guard(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let directory =
            StateDirectory::open(self.fixture.directory.path(), &[self.fixture.qualification])?;
        Ok(directory.read_guard(ROLLBACK_GUARD_BYTES)?)
    }

    /// Publishes `bytes` as the guard, which drives the pair further apart than the publication
    /// order alone ever could.
    fn force_guard(&self, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        let directory =
            StateDirectory::open(self.fixture.directory.path(), &[self.fixture.qualification])?;
        directory.replace_guard(bytes)?;
        Ok(())
    }

    /// Reopens the directory and returns the commit sequence startup reconstructed.
    fn reopen(&self) -> Result<u64, StorageError> {
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            self.fixture.directory.path(),
            &[self.fixture.qualification],
        )?))?;
        let sequence = owner.recovered_state().storage_commit_sequence();
        owner.shutdown()?;
        Ok(sequence)
    }

    /// Returns the commit sequence one successful operation past the prior state.
    fn successor(&self) -> Result<u64, StorageError> {
        self.prior_commit_sequence
            .checked_add(1)
            .ok_or(StorageError::Overflow)
    }
}

/// Runs `prior` certain commits, then abandons the next durable operation at the selected
/// boundary of the selected guard publication.
///
/// The abandonment is the storage owner's own indeterminate failure, which closes the owner
/// without any shutdown checkpoint, so the directory retains exactly the durable prefix a kill
/// at that boundary would have left behind.
fn abandon_at_publication(
    site: StorageFaultSite,
    boundary: StorageFaultBoundary,
    publication: u64,
    operation: DurableOperation,
) -> Result<ClosedDirectory, Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, u64::MAX)?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open_with_faults(
        fixture.directory.path(),
        &[fixture.qualification],
        faults.clone(),
    )?))?;
    let mut driver = CommitDriver::new(owner.port(), &fixture);
    driver.prime(2)?;
    let prior_commit_sequence = driver.commit_sequence;
    faults.arm_after_current(publication)?;
    if operation == DurableOperation::Commit {
        let outcome = driver.commit(100)?;
        if matches!(outcome, CommitOutcome::Committed(_)) {
            return Err("the abandoned commit reported a certain success".into());
        }
    } else {
        let _outcome = owner.port().try_checkpoint()?.wait()?;
    }
    faults.verify_fired()?;
    let _ = owner.shutdown();
    Ok(ClosedDirectory {
        fixture,
        prior_commit_sequence,
    })
}

/// Every boundary of the reserved publication leaves the database at its prior commit, because
/// the transaction that carries the new data has not begun.
fn assert_reserved_publication_reopens(operation: DurableOperation) -> Result<(), Box<dyn Error>> {
    for site in GUARD_BOUNDARIES {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let closed = abandon_at_publication(site, boundary, RESERVED_PUBLICATION, operation)?;
            assert_eq!(
                closed.reopen(),
                Ok(closed.prior_commit_sequence),
                "{operation:?} reserved publication {site:?} {boundary:?} lost its prior state",
            );
        }
    }
    Ok(())
}

/// Every boundary of the committed publication leaves the database exactly one operation ahead
/// of the guard, which is the reconcilable disagreement the reopen repairs from the record.
fn assert_committed_publication_reopens(operation: DurableOperation) -> Result<(), Box<dyn Error>> {
    for site in GUARD_BOUNDARIES {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let closed = abandon_at_publication(site, boundary, COMMITTED_PUBLICATION, operation)?;
            assert_eq!(
                closed.reopen(),
                Ok(closed.successor()?),
                "{operation:?} committed publication {site:?} {boundary:?} lost its successor",
            );
        }
    }
    Ok(())
}

#[test]
fn every_commit_guard_publication_boundary_reopens_at_its_prior_or_successor_state()
-> Result<(), Box<dyn Error>> {
    assert_reserved_publication_reopens(DurableOperation::Commit)?;
    assert_committed_publication_reopens(DurableOperation::Commit)
}

#[test]
fn every_checkpoint_guard_publication_boundary_reopens_at_its_prior_or_successor_state()
-> Result<(), Box<dyn Error>> {
    assert_reserved_publication_reopens(DurableOperation::Checkpoint)?;
    assert_committed_publication_reopens(DurableOperation::Checkpoint)
}

#[test]
fn a_guard_one_publication_step_behind_its_committed_database_reconciles_from_the_record()
-> Result<(), Box<dyn Error>> {
    let closed = abandon_at_publication(
        StorageFaultSite::GuardTemporaryCreate,
        StorageFaultBoundary::Before,
        COMMITTED_PUBLICATION,
        DurableOperation::Commit,
    )?;
    let lagging = closed.guard()?;
    assert_eq!(
        closed.reopen(),
        Ok(closed.successor()?),
        "the reopen did not adopt the committed record its guard had fallen behind",
    );
    let repaired = closed.guard()?;
    assert_ne!(
        repaired, lagging,
        "the reopen kept a guard its own record had already outrun",
    );
    // The repaired directory is now an exact pair, so a further reopen neither refuses it nor
    // rewrites its guard again.
    let settled = closed.reopen()?;
    let settled_guard = closed.guard()?;
    assert_eq!(
        closed.reopen(),
        Ok(settled),
        "the repaired pair did not reopen as an exact pair",
    );
    assert_eq!(
        closed.guard()?,
        settled_guard,
        "an exact pair rewrote a guard it had no reason to replace",
    );
    Ok(())
}

#[test]
fn a_guard_two_publication_steps_behind_its_committed_database_still_refuses()
-> Result<(), Box<dyn Error>> {
    let reference = abandon_at_publication(
        StorageFaultSite::GuardTemporaryCreate,
        StorageFaultBoundary::Before,
        RESERVED_PUBLICATION,
        DurableOperation::Commit,
    )?;
    let one_step_further_back = reference.guard()?;
    let closed = abandon_at_publication(
        StorageFaultSite::GuardTemporaryCreate,
        StorageFaultBoundary::Before,
        COMMITTED_PUBLICATION,
        DurableOperation::Commit,
    )?;
    closed.force_guard(&one_step_further_back)?;
    assert_eq!(
        closed.reopen(),
        Err(StorageError::StaleState),
        "a guard two publication steps behind its record was trusted",
    );
    Ok(())
}

#[test]
fn an_exact_pair_reopens_without_rewriting_its_guard() -> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let owner = StorageOwner::start(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))?;
    let mut driver = CommitDriver::new(owner.port(), &fixture);
    driver.prime(2)?;
    let prior_commit_sequence = driver.commit_sequence;
    owner.shutdown()?;
    let closed = ClosedDirectory {
        fixture,
        prior_commit_sequence,
    };
    let published = closed.guard()?;
    let sequence = closed.reopen()?;
    assert!(
        sequence >= closed.prior_commit_sequence,
        "the clean reopen lost a committed transaction",
    );
    assert_eq!(
        closed.guard()?,
        published,
        "an exact pair rewrote a guard it had no reason to replace",
    );
    assert_eq!(closed.reopen(), Ok(sequence));
    Ok(())
}
