//! STO-04 evidence: recovery and reference scratch is admitted and bounded before any
//! publication, a checkpoint reads its cut back before it publishes, a refused admission is a
//! determinate rejection that leaves the owner usable, and startup proves the recovered state
//! within the same bound from either directory authority.
#![forbid(unsafe_code)]

use super::*;
use crate::MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH;
use crate::scratch::SCRATCH_SLICE_BYTES;

const SCRATCH_PREFIX: &str = ".agenc-recovery-scratch-v1-";
/// Capacity observations retry for roughly five seconds at most: 10 ms doubling to a 100 ms
/// ceiling over 48 attempts, because other tests share the filesystem.
const CAPACITY_RETRY_ATTEMPTS: usize = 48;
const CAPACITY_RETRY_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);
const CAPACITY_RETRY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

fn scratch_entries(path: &Path) -> Result<Vec<String>, StorageError> {
    let mut names = std::fs::read_dir(path)
        .map_err(crate::filesystem_rejected)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(crate::filesystem_rejected)
        })
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

/// Drives one due checkpoint to its receipt or its first failure, abandoning a rejected job
/// exactly as the owner does.
fn run_checkpoint(engine: &mut StorageEngine) -> Result<CheckpointReceipt, EngineCommitFailure> {
    engine.mark_checkpoint_due();
    engine.start_checkpoint().map_err(rejected)?;
    loop {
        match engine.service_checkpoint() {
            Ok(Some(receipt)) => return Ok(receipt),
            Ok(None) => {}
            Err(failure) => {
                if matches!(failure, EngineCommitFailure::Rejected(_)) {
                    engine.abandon_checkpoint();
                }
                return Err(failure);
            }
        }
    }
}

/// Every scratch is bounded by `G`, admitted transaction by transaction, and its peak stays an
/// order of magnitude inside the allowance; the resident buffer never exceeds one byte budget
/// plus the row that crossed it.
fn assert_bounded(usage: ScratchUsage) -> Result<(), StorageError> {
    assert!(usage.transactions >= 2, "{usage:?}");
    assert!(usage.reclamations >= usage.transactions, "{usage:?}");
    assert_eq!(
        usage.allowance_bytes,
        MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
    );
    assert_eq!(usage.cache_bytes, 8 * 1_048_576);
    assert!(usage.creation_bytes > 0, "{usage:?}");
    assert!(usage.peak_file_bytes >= usage.creation_bytes, "{usage:?}");
    assert!(usage.peak_transaction_bytes > 0, "{usage:?}");
    assert!(
        usage.peak_transaction_bytes <= MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH / 8,
        "{usage:?}"
    );
    assert!(
        usage.charged_bytes >= usage.peak_transaction_bytes,
        "{usage:?}"
    );
    let buffer_ceiling = u64::try_from(SCRATCH_SLICE_BYTES)
        .map_err(|_| StorageError::Overflow)?
        .checked_add(
            u64::try_from(crate::MAX_STORED_KEY_BYTES).map_err(|_| StorageError::Overflow)?,
        )
        .and_then(|bytes| bytes.checked_add(4_096))
        .ok_or(StorageError::Overflow)?;
    assert!(usage.peak_buffer_bytes > 0, "{usage:?}");
    assert!(usage.peak_buffer_bytes <= buffer_ceiling, "{usage:?}");
    Ok(())
}

#[test]
fn a_refused_checkpoint_readback_admission_rejects_before_any_publication_and_keeps_the_owner_usable()
-> Result<(), StorageError> {
    let mut installed_at = None;
    for occurrence in 1..=16_u64 {
        let faults = capacity_admission_faults()?;
        let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
        let path = fixture.path().to_path_buf();
        let engine = fixture.engine_mut()?;
        let batch = EngineFixture::advancing_batch(engine, 41)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
        let state_before = *engine.state_meta.tbs();
        let guard_before = engine.guard.complete_hash()?;
        faults.arm_after_current(occurrence)?;
        let outcome = run_checkpoint(engine);
        if faults.verify_fired().is_err() {
            // Past the last admission the readback and the transaction sample: the checkpoint
            // installed with its readback metered.
            let receipt = outcome.map_err(|_| StorageError::Unavailable)?;
            assert_bounded(receipt.readback_scratch)?;
            installed_at = Some(occurrence);
            break;
        }
        assert!(
            matches!(
                outcome,
                Err(EngineCommitFailure::Rejected(
                    StorageError::DatabaseRejected
                ))
            ),
            "admission {occurrence} was not a determinate rejection"
        );
        assert_eq!(
            *engine.state_meta.tbs(),
            state_before,
            "admission {occurrence} changed the state"
        );
        assert_eq!(engine.guard.complete_hash()?, guard_before);
        assert_eq!(scratch_entries(&path)?, Vec::<String>::new());
        // The owner stays usable: the same checkpoint installs once its samples are admitted
        // again, the ledger verifies, and the next commit goes through.
        let receipt = run_checkpoint(engine).map_err(|_| StorageError::Unavailable)?;
        assert_bounded(receipt.readback_scratch)?;
        engine.verify_integrity_ledger()?;
        let batch = EngineFixture::advancing_batch(engine, 42)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
        assert_eq!(scratch_entries(&path)?, Vec::<String>::new());
    }
    // Creation, the table transaction, its reclamation, the current-row slice, its
    // reclamation and the checkpoint transaction's own sample were each refused in turn before
    // one run passed them all.
    assert!(
        installed_at.is_some_and(|occurrence| occurrence >= 6),
        "{installed_at:?}"
    );
    Ok(())
}

#[test]
fn a_readback_that_does_not_reproduce_the_scan_closes_the_owner_without_publishing()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let path = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    let batch = EngineFixture::advancing_batch(engine, 43)?;
    assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
    engine.mark_checkpoint_due();
    engine.start_checkpoint()?;
    let completed = loop {
        let job = engine
            .checkpoint_job
            .as_mut()
            .ok_or(StorageError::StaleState)?;
        if let Some(completed) = job.service(
            &engine.master_key,
            engine.binding,
            engine.header.tbs().storage_key_generation,
        )? {
            break completed;
        }
    };
    engine.checkpoint_job = None;

    // Substitute one current tracked record behind the scan's back: the same key, an envelope
    // that still decodes, a different record identifier, and no manifest that says so.
    let key = EngineFixture::account_key(43)?;
    let mut encoded = engine
        .store
        .read_record(TableId::Account, key.as_bytes())?
        .ok_or(StorageError::StaleState)?;
    let byte = encoded.get_mut(48).ok_or(StorageError::InvalidEncoding)?;
    *byte ^= 0x5a;
    let reservation = engine.reservation.encode()?;
    engine
        .store
        .commit_records(
            &[RedbWrite {
                table: TableId::Account,
                key: key.as_bytes(),
                value: Some(&encoded),
            }],
            &reservation,
            full_allowance(),
        )
        .map_err(|_| StorageError::DatabaseRejected)?;
    let state_before = *engine.state_meta.tbs();
    let guard_before = engine.guard.complete_hash()?;

    // The readback finds the ledger does not reproduce the scan, before any reservation, guard
    // or transaction: the owner closes through the fatal exit, nothing was published, and the
    // scratch is gone.
    assert!(matches!(
        engine.install_scanned_checkpoint(completed),
        Err(EngineCommitFailure::Indeterminate)
    ));
    assert_eq!(*engine.state_meta.tbs(), state_before);
    assert_eq!(engine.guard.complete_hash()?, guard_before);
    assert_eq!(
        engine.verify_integrity_ledger(),
        Err(StorageError::StaleState)
    );
    assert_eq!(scratch_entries(&path)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn startup_reconstruction_is_admitted_bounded_and_metered_by_both_authorities()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let path = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    for byte in [44, 45, 46] {
        let batch = EngineFixture::advancing_batch(engine, byte)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
    }
    let recovered = engine.startup_scan()?;
    let verification = recovered.verification_scratch();
    let references = recovered.reference_scratch();
    assert_bounded(verification)?;
    assert_bounded(references)?;
    // Creation, one current-row slice and one reverse chunk per replayed manifest.
    assert!(verification.transactions >= 5, "{verification:?}");
    assert_eq!(scratch_entries(&path)?, Vec::<String>::new());

    drop(fixture.engine.take());
    std::fs::remove_file(path.join("writer.lock")).map_err(crate::filesystem_rejected)?;
    let before = directory_fingerprint(&path)?;
    let inspected = StorageEngine::open_inspection(inspection_config(&path)?)?.startup_scan()?;
    assert_recovered_durable_facts_match(inspected, recovered);
    assert_bounded(inspected.verification_scratch())?;
    assert_bounded(inspected.reference_scratch())?;
    assert_eq!(
        inspected.verification_scratch().transactions,
        verification.transactions
    );
    // The anonymous scratch of an inspection never appears in the directory.
    assert_eq!(directory_fingerprint(&path)?, before);
    Ok(())
}

#[test]
fn a_refused_startup_scratch_admission_fails_closed_and_leaves_no_entry() -> Result<(), StorageError>
{
    for occurrence in 1..=4_u64 {
        let faults = capacity_admission_faults()?;
        let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
        let path = fixture.path().to_path_buf();
        let engine = fixture.engine_mut()?;
        let batch = EngineFixture::advancing_batch(engine, 47)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
        faults.arm_after_current(occurrence)?;
        assert_eq!(
            engine.startup_scan().map(|_recovered| ()),
            Err(StorageError::DatabaseRejected),
            "admission {occurrence}"
        );
        faults.verify_fired()?;
        assert_eq!(scratch_entries(&path)?, Vec::<String>::new());
        // With the sample admitted again the same startup verifies from a fresh scratch.
        let recovered = engine.startup_scan()?;
        assert_bounded(recovered.verification_scratch())?;
        assert_bounded(recovered.reference_scratch())?;
        assert_eq!(scratch_entries(&path)?, Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn the_scratch_gate_admits_at_exactly_the_reserve_plus_the_allowance() -> Result<(), StorageError> {
    let fixture = EngineFixture::create()?;
    let engine = fixture.engine()?;
    let allowance = AllocationAllowance::new(1_048_576);
    for (delta, admitted) in [(1_i8, false), (0, true), (-1, true)] {
        let mut backoff = CAPACITY_RETRY_INITIAL_BACKOFF;
        let mut settled = false;
        for _attempt in 0..CAPACITY_RETRY_ATTEMPTS {
            let before = engine.state_directory.capacity(0, 0)?.available_bytes;
            let exact = before
                .checked_sub(allowance.bytes())
                .ok_or(StorageError::Overflow)?;
            let reserve = match delta {
                1 => exact.checked_add(1).ok_or(StorageError::Overflow)?,
                0 => exact,
                _ => exact.checked_sub(1).ok_or(StorageError::Overflow)?,
            };
            let gate = ScratchGate {
                directory: &engine.state_directory,
                fixed_reserve_bytes: reserve,
                reserve_percent: 0,
            };
            let result = gate.admit_scratch(allowance);
            let after = engine.state_directory.capacity(0, 0)?.available_bytes;
            if before != after {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(CAPACITY_RETRY_MAX_BACKOFF);
                continue;
            }
            if admitted {
                assert_eq!(result, Ok(()), "delta {delta}");
            } else {
                assert_eq!(
                    result,
                    Err(StorageError::FilesystemRejected(
                        crate::FilesystemCause::InsufficientCapacity
                    )),
                    "delta {delta}"
                );
            }
            settled = true;
            break;
        }
        assert!(
            settled,
            "filesystem capacity did not settle for delta {delta}"
        );
    }
    Ok(())
}
