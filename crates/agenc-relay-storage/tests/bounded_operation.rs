//! Stage 10 STO-03 evidence: one physical growth allowance across every durable operation of
//! the real storage owner.
//!
//! Every durable operation the owner performs, the nonce reservation, both guard replacements,
//! the main transaction, a checkpoint installation, the deferred freed-page cleanup and the
//! close, is charged against one allowance derived from Section 19.3's `G`, inside the unchanged
//! `R(F) + G` free-space gate. These cases drive the real owner: an operation that fits is
//! charged once and cleans up after itself, the boundary is exact to the byte, an operation that
//! exceeds its allowance is refused with nothing written while the next writer commits, a
//! refusal during preparation rolls back and leaves the burned nonce block burned, an uncertain
//! publication keeps Section 21.5's indeterminate outcome through the bounded handle, deferred
//! cleanup resumes after a restart, the close persists within its allowance or leaves the
//! repair to the next open, a bounded database grows past the allowance's own size, and a
//! database laid out with unbounded regions is refused before it is opened.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;

use agenc_relay_storage::{
    AllowancePhase, CheckpointOutcome, CommitOutcome, ExistingRecord, LIVE_DATABASE_REGION_BYTES,
    MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH, PersistentRecordValue, ReadPlan, RecordMutation,
    SealedRecord, StateDirectory, StorageAccountingLimits, StorageError, StorageFaultBoundary,
    StorageFaultCase, StorageFaultInjector, StorageFaultSite, StorageMutationBatch,
    StorageMutationHead, StorageOwner, StoragePort, StorageStatistics, StoredKey, TableId,
    guard_replacement_charge,
};
use agenc_relay_types::{AccountRandomId, TransactionId};

use crate::stage_five_completion::{
    InitializedLiveFixture, initialized_live_fixture, live_open_config, test_limits,
};

/// Section 19.3's `G`, the allowance every operation of an uncapped owner receives.
const G: u64 = MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;

/// The opaque body the allocation-heavy operations carry: one authentication transaction row
/// of eight MiB, which a single legal batch admits.
const OPAQUE_BODY_BYTES: usize = 8 * 1_024 * 1_024;

/// Rows of the deletion whose freed leaves must survive a restart: enough distinct leaf pages
/// that reclaiming them is unmistakable beside the handful an ordinary operation frees.
const BACKLOG_ROWS: u64 = 2_048;

/// The least reclaimed extents that prove the backlog, not merely the operation's own frees,
/// was drained: an ordinary operation frees well under this many.
const BACKLOG_EXTENTS: u64 = 128;

/// Bytes of the opaque body every backlog row carries, a few rows per leaf page.
const BACKLOG_BODY_BYTES: usize = 512;

/// Index of `storage_commit_sequence` in the normative `STATS STORAGE` field order.
const COMMIT_SEQUENCE_FIELD: usize = 7;

/// Index of `nonce_draw_high_water` in the normative `STATS STORAGE` field order.
const NONCE_HIGH_WATER_FIELD: usize = 9;

/// Index of `database_file_bytes` in the normative `STATS STORAGE` field order.
const FILE_BYTES_FIELD: usize = 1;

/// Rows a range read may page at once.
const RANGE_PAGE: u16 = 1_024;

fn account_key(seed: u8) -> Result<StoredKey, StorageError> {
    StoredKey::new(
        AccountRandomId::from_bytes([seed; 16])
            .to_text()
            .into_bytes(),
    )
}

/// A sixteen-byte authentication-transaction key: eight zero bytes then the big-endian index.
fn opaque_key(index: u64) -> Result<StoredKey, StorageError> {
    let mut bytes = [0_u8; 16];
    for (slot, byte) in bytes.iter_mut().skip(8).zip(index.to_be_bytes()) {
        *slot = byte;
    }
    StoredKey::new(bytes.to_vec())
}

fn opaque_value(body: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    PersistentRecordValue::new(TableId::AuthTransaction, 1, 1, 1, None, Vec::new(), body)?.encode()
}

/// Submits batches through the port and carries the accounting head every batch must repeat,
/// exactly as the daemon's own projection does.
struct Driver {
    port: StoragePort,
    commit_sequence: u64,
    state_generation: u64,
    logical_database_bytes: u64,
    backup_stream_bytes: u64,
    transaction: u64,
}

impl Driver {
    /// Opens the fixture's directory with `faults` and seeds the head from the recovered state.
    fn open(
        fixture: &InitializedLiveFixture,
        faults: StorageFaultInjector,
    ) -> Result<(StorageOwner, Self), Box<dyn Error>> {
        let state_directory = StateDirectory::open_with_faults(
            fixture.directory.path(),
            &[fixture.qualification],
            faults,
        )?;
        let owner = StorageOwner::start(live_open_config(state_directory))?;
        let recovered = owner.recovered_state();
        let driver = Self {
            port: owner.port(),
            commit_sequence: recovered.storage_commit_sequence(),
            state_generation: recovered.state_generation(),
            logical_database_bytes: recovered.logical_database_bytes(),
            backup_stream_bytes: recovered.backup_stream_bytes(),
            transaction: recovered
                .storage_commit_sequence()
                .checked_mul(1_000)
                .and_then(|base| base.checked_add(1))
                .ok_or(StorageError::Overflow)?,
        };
        Ok((owner, driver))
    }

    fn head(&mut self) -> Result<StorageMutationHead, StorageError> {
        let mut bytes = [0_u8; 16];
        for (slot, byte) in bytes.iter_mut().skip(8).zip(self.transaction.to_be_bytes()) {
            *slot = byte;
        }
        self.transaction = self
            .transaction
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        Ok(StorageMutationHead {
            transaction_id: TransactionId::from_bytes(bytes),
            expected_storage_commit_sequence: self.commit_sequence,
            expected_state_generation: self.state_generation,
            resulting_state_generation: self
                .state_generation
                .checked_add(1)
                .ok_or(StorageError::Overflow)?,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: 0,
            resulting_account_service_response_count: 0,
        })
    }

    fn accounting(&self) -> StorageAccountingLimits {
        StorageAccountingLimits {
            current_logical_database_bytes: self.logical_database_bytes,
            current_backup_stream_bytes: self.backup_stream_bytes,
            database_max_bytes: test_limits().database_max_bytes,
            backup_max_bytes: test_limits().backup_max_bytes,
        }
    }

    fn batch(
        &mut self,
        mutations: Vec<RecordMutation>,
    ) -> Result<StorageMutationBatch, Box<dyn Error>> {
        Ok(StorageMutationBatch::new(
            self.head()?,
            1,
            self.accounting(),
            mutations,
        )?)
    }

    /// One new live account row under a seed-derived key: the smallest legal operation.
    fn account_batch(&mut self, seed: u8) -> Result<StorageMutationBatch, Box<dyn Error>> {
        let body = crate::domain_records::live_body(TableId::Account, 1)?;
        let value = PersistentRecordValue::new(TableId::Account, 1, 1, 1, None, Vec::new(), body)?
            .encode()?;
        self.batch(vec![RecordMutation::put(
            TableId::Account,
            account_key(seed)?,
            1,
            None,
            value,
        )?])
    }

    /// One eight MiB authentication-transaction row under `index`.
    fn opaque_batch(&mut self, index: u64) -> Result<StorageMutationBatch, Box<dyn Error>> {
        let value = opaque_value(vec![u8::try_from(index % 251)?; OPAQUE_BODY_BYTES])?;
        self.batch(vec![RecordMutation::put(
            TableId::AuthTransaction,
            opaque_key(index)?,
            1,
            None,
            value,
        )?])
    }

    /// `BACKLOG_ROWS` small authentication-transaction rows, spread over many leaf pages.
    fn backlog_insert_batch(&mut self) -> Result<StorageMutationBatch, Box<dyn Error>> {
        let mut mutations = Vec::new();
        for index in 0..BACKLOG_ROWS {
            mutations.push(RecordMutation::put(
                TableId::AuthTransaction,
                opaque_key(index)?,
                1,
                None,
                opaque_value(vec![u8::try_from(index % 251)?; BACKLOG_BODY_BYTES])?,
            )?);
        }
        self.batch(mutations)
    }

    /// Deletes every backlog row, naming each existing record exactly as the owner stores it.
    fn backlog_delete_batch(&mut self) -> Result<StorageMutationBatch, Box<dyn Error>> {
        let mut mutations = Vec::new();
        let mut start = opaque_key(0)?;
        let end = opaque_key(u64::MAX)?;
        loop {
            let result = self
                .port
                .try_read(ReadPlan::range(
                    TableId::AuthTransaction,
                    start.clone(),
                    end.clone(),
                    RANGE_PAGE,
                )?)?
                .wait()?;
            let mut last = None;
            for record in &result.records {
                let sealed = SealedRecord::decode(&record.sealed_record)?;
                mutations.push(RecordMutation::delete(
                    TableId::AuthTransaction,
                    record.key.clone(),
                    ExistingRecord::new(
                        sealed.record_schema(),
                        sealed.record_id()?,
                        record.sealed_record.len(),
                    )?,
                ));
                last = Some(record.key.clone());
            }
            let Some(last) = last.filter(|_| result.truncated) else {
                break;
            };
            let mut next = last.as_bytes().to_vec();
            next.push(0);
            start = StoredKey::new(next)?;
        }
        if mutations.len() != usize::try_from(BACKLOG_ROWS)? {
            return Err("the backlog rows were not all read back".into());
        }
        self.batch(mutations)
    }

    /// Submits one batch and refreshes the head from the receipt and the owner's statistics.
    fn commit(&mut self, batch: StorageMutationBatch) -> Result<CommitOutcome, Box<dyn Error>> {
        let outcome = self.port.try_commit(batch)?.wait()?;
        if let CommitOutcome::Committed(receipt) = &outcome {
            self.commit_sequence = receipt.storage_commit_sequence;
            self.state_generation = receipt.state_generation;
            let statistics = self.statistics()?;
            self.logical_database_bytes = statistics.logical_database_bytes();
            self.backup_stream_bytes = statistics.backup_stream_bytes();
        }
        Ok(outcome)
    }

    fn statistics(&self) -> Result<StorageStatistics, Box<dyn Error>> {
        Ok(self.port.try_statistics()?.wait()?)
    }

    fn field(&self, index: usize) -> Result<u64, Box<dyn Error>> {
        self.statistics()?
            .values()
            .get(index)
            .copied()
            .ok_or_else(|| "statistics field is missing".into())
    }

    fn present(&self, table: TableId, key: StoredKey) -> Result<bool, Box<dyn Error>> {
        Ok(!self
            .port
            .try_read(ReadPlan::exact(table, key))?
            .wait()?
            .records
            .is_empty())
    }
}

fn committed(outcome: CommitOutcome) -> Result<(), Box<dyn Error>> {
    match outcome {
        CommitOutcome::Committed(_) => Ok(()),
        CommitOutcome::Rejected(error) => Err(format!("commit rejected: {error}").into()),
        CommitOutcome::Indeterminate => Err("commit indeterminate".into()),
    }
}

/// The redb bytes the first small commit of a fresh owner charges, measured once so that the
/// same deterministic operation can be replayed against exactly that cap and one byte less.
fn first_account_commit_redb_charge() -> Result<u64, Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    let charged = driver.statistics()?.last_operation_charged_bytes();
    let guards = guard_replacement_charge(fixture.qualification.tuple().block_size)?
        .checked_mul(2)
        .ok_or(StorageError::Overflow)?;
    owner.shutdown()?;
    Ok(charged.checked_sub(guards).ok_or(StorageError::Overflow)?)
}

#[test]
fn an_operation_that_fits_is_charged_once_and_cleans_up_after_itself() -> Result<(), Box<dyn Error>>
{
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    let before = driver.statistics()?;
    assert_eq!(before.last_operation_charged_bytes(), 0);
    assert!(before.deferred_cleanup_pending());
    assert_eq!(before.reclaimed_pages_since_open(), 0);

    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    let after = driver.statistics()?;
    assert!(after.last_operation_charged_bytes() > 0);
    assert!(after.last_operation_charged_bytes() <= G);
    assert!(!after.deferred_cleanup_pending());
    assert!(after.reclaimed_pages_since_open() >= 1);
    assert!(driver.present(TableId::Account, account_key(2)?)?);

    // A checkpoint is one more operation under its own allowance with its own cleanup.
    assert!(matches!(
        owner.port().try_checkpoint()?.wait()?,
        CheckpointOutcome::Installed(_)
    ));
    let checkpointed = driver.statistics()?;
    assert!(checkpointed.last_operation_charged_bytes() > 0);
    assert!(checkpointed.last_operation_charged_bytes() <= G);
    assert!(!checkpointed.deferred_cleanup_pending());
    assert!(checkpointed.reclaimed_pages_since_open() > after.reclaimed_pages_since_open());
    owner.shutdown()?;
    Ok(())
}

#[test]
fn the_allowance_boundary_is_exact_to_the_byte_through_the_owner() -> Result<(), Box<dyn Error>> {
    let charge = first_account_commit_redb_charge()?;

    // Exactly the charge: the operation commits, and nothing is left for its deferred cleanup,
    // which is refused and waits for a later operation.
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(
        &fixture,
        StorageFaultInjector::disabled().with_growth_cap(charge),
    )?;
    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    let statistics = driver.statistics()?;
    assert!(statistics.deferred_cleanup_pending());
    assert_eq!(statistics.reclaimed_pages_since_open(), 0);
    assert!(driver.present(TableId::Account, account_key(2)?)?);
    owner.shutdown()?;

    // One byte less: refused during preparation with nothing written and nothing charged.
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(
        &fixture,
        StorageFaultInjector::disabled().with_growth_cap(charge - 1),
    )?;
    let high_water = owner.recovered_state().nonce_draw_high_water();
    let seal_count = u64::from(driver.account_batch(2)?.seal_count());
    let batch = driver.account_batch(2)?;
    assert!(matches!(
        driver.commit(batch)?,
        CommitOutcome::Rejected(StorageError::AllowanceRefused(AllowancePhase::Preparation))
    ));
    let statistics = driver.statistics()?;
    assert_eq!(statistics.last_operation_charged_bytes(), 0);
    assert_eq!(
        statistics.logical_database_bytes(),
        fixture.logical_database_bytes
    );
    assert_eq!(driver.field(COMMIT_SEQUENCE_FIELD)?, 0);
    assert!(!driver.present(TableId::Account, account_key(2)?)?);
    owner.shutdown()?;

    // The reopen reconciles the burned reservation; the next writer commits and its nonces
    // start after the burned block, which is never reused.
    let (reopened, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    assert_eq!(reopened.recovered_state().storage_commit_sequence(), 0);
    assert_eq!(
        reopened.recovered_state().nonce_draw_high_water(),
        high_water
    );
    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    assert_eq!(driver.field(COMMIT_SEQUENCE_FIELD)?, 1);
    assert_eq!(
        driver.field(NONCE_HIGH_WATER_FIELD)?,
        high_water + seal_count + seal_count
    );
    assert!(driver.present(TableId::Account, account_key(2)?)?);
    reopened.shutdown()?;
    Ok(())
}

#[test]
fn an_operation_that_exceeds_its_allowance_is_refused_and_the_next_writer_commits()
-> Result<(), Box<dyn Error>> {
    // Four small commits' worth of redb allocation admits a small row but never an eight MiB
    // body, whose first allocation is refused before anything is prepared.
    let cap = first_account_commit_redb_charge()?
        .checked_mul(4)
        .ok_or(StorageError::Overflow)?;
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(
        &fixture,
        StorageFaultInjector::disabled().with_growth_cap(cap),
    )?;
    let batch = driver.opaque_batch(7)?;
    assert!(matches!(
        driver.commit(batch)?,
        CommitOutcome::Rejected(StorageError::AllowanceRefused(AllowancePhase::Mutation))
    ));
    assert!(!driver.present(TableId::AuthTransaction, opaque_key(7)?)?);
    assert_eq!(driver.field(COMMIT_SEQUENCE_FIELD)?, 0);
    assert_eq!(driver.statistics()?.last_operation_charged_bytes(), 0);

    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    assert!(driver.present(TableId::Account, account_key(2)?)?);
    assert_eq!(driver.field(COMMIT_SEQUENCE_FIELD)?, 1);
    assert!(matches!(
        owner.port().try_checkpoint()?.wait()?,
        CheckpointOutcome::Installed(_)
    ));
    owner.shutdown()?;
    Ok(())
}

#[test]
fn an_uncertain_publication_stays_indeterminate_through_the_bounded_handle()
-> Result<(), Box<dyn Error>> {
    // The first occurrence of each phase flush belongs to the nonce reservation, the second to
    // the main transaction; both publish through the bounded handle.
    for site in [
        StorageFaultSite::TransactionPhaseOne,
        StorageFaultSite::TransactionPhaseTwo,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            for occurrence in [1, 2] {
                let fixture = initialized_live_fixture()?;
                let faults =
                    StorageFaultInjector::new(StorageFaultCase { site, boundary }, u64::MAX)?;
                let (owner, mut driver) = Driver::open(&fixture, faults.clone())?;
                faults.arm_after_current(occurrence)?;
                let batch = driver.account_batch(2)?;
                assert!(
                    matches!(driver.commit(batch)?, CommitOutcome::Indeterminate),
                    "{site:?} {boundary:?} occurrence {occurrence}"
                );
                faults.verify_fired()?;
                owner.shutdown()?;

                let (reopened, driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
                let present = driver.present(TableId::Account, account_key(2)?)?;
                let sequence = reopened.recovered_state().storage_commit_sequence();
                assert!(
                    (sequence == 0 && !present) || (sequence == 1 && present),
                    "{site:?} {boundary:?} occurrence {occurrence}: sequence {sequence}, present {present}"
                );
                reopened.shutdown()?;
            }
        }
    }
    Ok(())
}

#[test]
fn deferred_cleanup_resumes_after_a_restart() -> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture()?;
    let faults = StorageFaultInjector::new(
        StorageFaultCase {
            site: StorageFaultSite::GuardDirectorySync,
            boundary: StorageFaultBoundary::After,
        },
        u64::MAX,
    )?;
    let (owner, mut driver) = Driver::open(&fixture, faults.clone())?;
    let batch = driver.backlog_insert_batch()?;
    committed(driver.commit(batch)?)?;
    assert!(!driver.statistics()?.deferred_cleanup_pending());

    // The deletion's committed guard is published, then the owner is cut off before the
    // deferred cleanup of that operation runs, so its freed leaves wait in the database.
    let batch = driver.backlog_delete_batch()?;
    faults.arm_after_current(2)?;
    assert!(matches!(
        driver.commit(batch)?,
        CommitOutcome::Indeterminate
    ));
    faults.verify_fired()?;
    owner.shutdown()?;

    // The reopen finds the deletion durable and the backlog pending; the first operation's
    // cleanup drains it beside its own frees.
    let (reopened, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    assert_eq!(reopened.recovered_state().storage_commit_sequence(), 2);
    assert!(!driver.present(TableId::AuthTransaction, opaque_key(0)?)?);
    let before = driver.statistics()?;
    assert!(before.deferred_cleanup_pending());
    assert_eq!(before.reclaimed_pages_since_open(), 0);
    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    let after = driver.statistics()?;
    assert!(
        after.reclaimed_pages_since_open() >= BACKLOG_EXTENTS,
        "reclaimed {} extents",
        after.reclaimed_pages_since_open()
    );
    assert!(!after.deferred_cleanup_pending());
    reopened.shutdown()?;
    Ok(())
}

#[test]
fn a_clean_close_persists_within_its_allowance_and_a_failed_close_leaves_the_repair_to_the_next_open()
-> Result<(), Box<dyn Error>> {
    // A close within its allowance leaves the next open clean.
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    let batch = driver.account_batch(2)?;
    committed(driver.commit(batch)?)?;
    owner.shutdown()?;
    let (reopened, _driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    assert!(!reopened.recovered_state().database_repaired());
    // The clean stop installed its final checkpoint after the one commit.
    assert_eq!(reopened.recovered_state().storage_commit_sequence(), 2);
    reopened.shutdown()?;

    // A close that cannot persist never fails the shutdown and never runs unmetered: the
    // checkpoint is already installed, so the next database sync belongs to the close, and
    // failing it leaves the repair to the next open, which finds the committed state intact.
    let faults = StorageFaultInjector::new(
        StorageFaultCase {
            site: StorageFaultSite::DatabaseSync,
            boundary: StorageFaultBoundary::Before,
        },
        u64::MAX,
    )?;
    let (interrupted, mut driver) = Driver::open(&fixture, faults.clone())?;
    let batch = driver.account_batch(3)?;
    committed(driver.commit(batch)?)?;
    assert!(matches!(
        interrupted.port().try_checkpoint()?.wait()?,
        CheckpointOutcome::Installed(_)
    ));
    faults.arm_after_current(1)?;
    interrupted.shutdown()?;
    faults.verify_fired()?;
    let (repaired, driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    assert!(repaired.recovered_state().database_repaired());
    assert_eq!(repaired.recovered_state().storage_commit_sequence(), 4);
    assert!(driver.present(TableId::Account, account_key(2)?)?);
    assert!(driver.present(TableId::Account, account_key(3)?)?);
    repaired.shutdown()?;
    Ok(())
}

#[test]
fn a_bounded_database_grows_past_the_allowance_under_exactly_g() -> Result<(), Box<dyn Error>> {
    // Every operation of an uncapped owner receives exactly `G`; eight MiB rows grow the file
    // through every region step until it is larger than the allowance itself.
    let fixture = initialized_live_fixture()?;
    let (owner, mut driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    let mut index = 0_u64;
    let mut largest_charge = 0_u64;
    while driver.field(FILE_BYTES_FIELD)? <= G {
        if index >= 64 {
            return Err("the database did not grow past the allowance in 64 operations".into());
        }
        let batch = driver.opaque_batch(index)?;
        committed(driver.commit(batch)?)?;
        let charged = driver.statistics()?.last_operation_charged_bytes();
        assert!(charged <= G, "operation {index} charged {charged}");
        largest_charge = largest_charge.max(charged);
        index += 1;
    }
    // Past the first region the file grows by whole regions, each charged at its full length
    // to the one operation that needed it; a step is at most two regions, half the allowance,
    // so the largest operation still left room for its own rows.
    assert!(largest_charge >= LIVE_DATABASE_REGION_BYTES);
    assert!(largest_charge < G);
    assert!(driver.present(TableId::AuthTransaction, opaque_key(0)?)?);
    assert!(driver.present(TableId::AuthTransaction, opaque_key(index - 1)?)?);
    owner.shutdown()?;

    let (reopened, driver) = Driver::open(&fixture, StorageFaultInjector::disabled())?;
    assert!(!reopened.recovered_state().database_repaired());
    // The close of a database of several regions stayed inside its allowance as well, and the
    // clean stop installed its final checkpoint after the last row.
    assert_eq!(
        reopened.recovered_state().storage_commit_sequence(),
        index + 1
    );
    assert!(driver.present(TableId::AuthTransaction, opaque_key(index - 1)?)?);
    reopened.shutdown()?;
    Ok(())
}

#[test]
fn a_database_laid_out_with_unbounded_regions_is_refused_before_it_is_opened()
-> Result<(), Box<dyn Error>> {
    // The redb 4.2.0 header of a database laid out with the upstream default region: the magic
    // number, the god byte and padding, then the page size and the data pages per region.
    let fixture = initialized_live_fixture()?;
    let mut header = vec![
        b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A, 0, 0, 0,
    ];
    header.extend_from_slice(&4_096_u32.to_le_bytes());
    header.extend_from_slice(&1_u32.to_le_bytes());
    header.extend_from_slice(&1_048_576_u32.to_le_bytes());
    header.resize(64, 0);
    fs::write(fixture.directory.path().join("database.redb"), header)?;

    let state_directory = StateDirectory::open(fixture.directory.path(), &[fixture.qualification])?;
    assert_eq!(
        StorageOwner::start(live_open_config(state_directory))
            .err()
            .map(|error| error.to_string()),
        Some(StorageError::UnboundedRegion(4_294_967_296).to_string())
    );
    assert!(
        StorageError::UnboundedRegion(4_294_967_296)
            .to_string()
            .contains(&LIVE_DATABASE_REGION_BYTES.to_string())
    );
    Ok(())
}
