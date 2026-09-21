#![forbid(unsafe_code)]

//! Engine-level phase tests: one cut, bounded slices, determinate refusals.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use agenc_relay_crypto::{Ed25519SecretKey, RollbackGuardRootKey, StorageMasterKey};
use agenc_relay_types::{AccountRandomId, TransactionId};

use super::*;
use crate::engine::tests::EngineFixture;
use crate::{
    BackupTrustKey, CommitOutcome, PersistentRecordValue, RecordMutation, StorageAccountingLimits,
    StorageFaultCase, StorageFaultInjector, StorageMutationBatch, StorageMutationHead,
    verify_backup,
};

const MASTER_KEY: [u8; 32] = [27; 32];
const GUARD_ROOT_KEY: [u8; 32] = [28; 32];
const SIGNING_KEY: [u8; 32] = [91; 32];
const BACKUP_TEMPORARY_PREFIX: &str = ".agenc-backup-tmp-v1-";
const SCRATCH_PREFIX: &str = ".agenc-recovery-scratch-v1-";
const PHASES: [&str; 7] = [
    "accounting",
    "resolving",
    "admitting",
    "copying",
    "sealing",
    "verifying",
    "publishing",
];

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

fn names_with_prefix(directory: &Path, prefix: &str) -> Result<Vec<String>, StorageError> {
    Ok(directory_names(directory)?
        .into_iter()
        .filter(|name| name.starts_with(prefix))
        .collect())
}

fn account_key(index: u32) -> Result<StoredKey, StorageError> {
    let mut bytes = [0_u8; 16];
    bytes
        .get_mut(..4)
        .ok_or(StorageError::Overflow)?
        .copy_from_slice(&index.to_be_bytes());
    StoredKey::new(AccountRandomId::from_bytes(bytes).to_text().into_bytes())
}

fn domain_plaintext(
    table: TableId,
    references: Vec<RecordReference>,
    body: Vec<u8>,
) -> Result<Vec<u8>, StorageError> {
    PersistentRecordValue::new(table, 1, 1, 1, None, references, body)?.encode()
}

fn account_plaintext() -> Result<Vec<u8>, StorageError> {
    domain_plaintext(
        TableId::Account,
        Vec::new(),
        crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
    )
}

fn commit(engine: &mut StorageEngine, mutations: Vec<RecordMutation>) -> Result<(), StorageError> {
    let state = *engine.state_meta.tbs();
    let head = StorageMutationHead {
        transaction_id: TransactionId::from_bytes(
            state
                .storage_commit_sequence
                .to_be_bytes()
                .repeat(2)
                .try_into()
                .map_err(|_| StorageError::Overflow)?,
        ),
        expected_storage_commit_sequence: state.storage_commit_sequence,
        expected_state_generation: state.state_generation,
        resulting_state_generation: state.state_generation + 1,
        state_advancing_plan_count: 1,
        expected_account_service_response_count: state.account_service_response_count,
        resulting_account_service_response_count: state.account_service_response_count + 1,
    };
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: state.logical_database_bytes,
        current_backup_stream_bytes: state.backup_stream_bytes,
        database_max_bytes: engine.limits.database_max_bytes,
        backup_max_bytes: engine.limits.backup_max_bytes,
    };
    match engine.commit(StorageMutationBatch::new(head, 1, accounting, mutations)?) {
        CommitOutcome::Committed(_) => Ok(()),
        CommitOutcome::Rejected(error) => Err(error),
        CommitOutcome::Indeterminate => Err(StorageError::Unavailable),
    }
}

fn insert_accounts(engine: &mut StorageEngine, first: u32, count: u32) -> Result<(), StorageError> {
    let mutations = (first..first.checked_add(count).ok_or(StorageError::Overflow)?)
        .map(|index| {
            RecordMutation::put(
                TableId::Account,
                account_key(index)?,
                1,
                None,
                account_plaintext()?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    commit(engine, mutations)
}

fn start(
    engine: &mut StorageEngine,
    directory: &Path,
    name: &str,
    backup_id: u8,
) -> Result<(), StorageError> {
    engine.start_backup(
        BackupDestination::new(directory, name)?,
        Ed25519SecretKey::from_bytes(SIGNING_KEY),
        1_800_000_000,
        [backup_id; 16],
    )
}

fn drive(engine: &mut StorageEngine) -> Result<BackupReceipt, StorageError> {
    for _ in 0..100_000 {
        if let Some(receipt) = engine.service_backup()? {
            return Ok(receipt);
        }
    }
    Err(StorageError::LimitExceeded)
}

fn drive_to_phase(engine: &mut StorageEngine, phase: &str) -> Result<(), StorageError> {
    for _ in 0..100_000 {
        if engine.backup_phase() == Some(phase) {
            return Ok(());
        }
        if engine.service_backup()?.is_some() {
            return Err(StorageError::StaleState);
        }
    }
    Err(StorageError::LimitExceeded)
}

fn verified_bytes(path: &Path, receipt: &BackupReceipt) -> Result<Vec<u8>, StorageError> {
    let bytes = fs::read(path).map_err(crate::filesystem_rejected)?;
    let verified = verify_backup(
        bytes.as_slice(),
        &StorageMasterKey::from_bytes(MASTER_KEY),
        &RollbackGuardRootKey::from_bytes(GUARD_ROOT_KEY),
        &[BackupTrustKey::new(
            Ed25519SecretKey::from_bytes(SIGNING_KEY).public_key(),
        )?],
        receipt.stream_bytes,
    )?;
    if (
        verified.stream_bytes,
        verified.trailer.record_count,
        verified.trailer.stream_digest,
        u64::try_from(bytes.len()).map_err(|_| StorageError::Overflow)?,
    ) != (
        receipt.stream_bytes,
        receipt.record_count,
        receipt.stream_digest,
        receipt.stream_bytes,
    ) {
        return Err(StorageError::AuthenticationFailed);
    }
    Ok(bytes)
}

fn quiescent_backup(
    engine: &mut StorageEngine,
    directory: &Path,
    name: &str,
    backup_id: u8,
) -> Result<(BackupReceipt, Vec<u8>), StorageError> {
    start(engine, directory, name, backup_id)?;
    let receipt = drive(engine)?;
    let bytes = verified_bytes(&directory.join(name), &receipt)?;
    Ok((receipt, bytes))
}

#[test]
fn the_incremental_stream_equals_the_single_cut_stream_despite_interleaved_commits()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "cut-backups")?;
    let engine = fixture.engine_mut()?;
    // The minimum database backs up before any row is added.
    let (minimum, _) = quiescent_backup(engine, &directory, "minimum.backup", 1)?;
    insert_accounts(engine, 1, 12)?;
    let (single_cut, single_cut_bytes) =
        quiescent_backup(engine, &directory, "single-cut.backup", 2)?;
    assert!(single_cut.record_count > minimum.record_count);

    // The same cut, same creation time and identity, but the owner commits a
    // new row between every slice of every phase.
    let commit_sequence_at_start = engine.state_meta.tbs().storage_commit_sequence;
    start(engine, &directory, "interleaved.backup", 2)?;
    engine.set_backup_slice_budget(3, BACKUP_SLICE_BYTES)?;
    let mut slices_per_phase = std::collections::BTreeMap::new();
    let mut interleaved = None;
    for index in 0_u32..100_000 {
        let phase = engine.backup_phase().ok_or(StorageError::StaleState)?;
        *slices_per_phase.entry(phase).or_insert(0_u32) += 1;
        insert_accounts(engine, 1_000 + index, 1)?;
        if let Some(receipt) = engine.service_backup()? {
            interleaved = Some(receipt);
            break;
        }
    }
    let interleaved = interleaved.ok_or(StorageError::LimitExceeded)?;
    assert!(engine.state_meta.tbs().storage_commit_sequence > commit_sequence_at_start);
    for phase in PHASES {
        assert!(
            slices_per_phase.contains_key(phase),
            "phase {phase} never serviced"
        );
    }
    for phase in ["accounting", "copying", "verifying"] {
        assert!(
            slices_per_phase.get(phase).copied().unwrap_or(0) >= 2,
            "{phase} ran in one slice: {slices_per_phase:?}"
        );
    }
    let interleaved_bytes = verified_bytes(&directory.join("interleaved.backup"), &interleaved)?;
    assert_eq!(interleaved.record_count, single_cut.record_count);
    assert_eq!(interleaved.stream_bytes, single_cut.stream_bytes);
    assert_eq!(interleaved.stream_digest, single_cut.stream_digest);
    assert!(interleaved_bytes == single_cut_bytes, "streams differ");

    // A cut taken after the interleaved commits sees them.
    let (later, _) = quiescent_backup(engine, &directory, "later.backup", 3)?;
    assert!(later.record_count > single_cut.record_count);
    assert_eq!(
        directory_names(&directory)?,
        vec![
            "interleaved.backup".to_owned(),
            "later.backup".to_owned(),
            "minimum.backup".to_owned(),
            "single-cut.backup".to_owned(),
        ]
    );
    Ok(())
}

#[test]
fn a_refusal_in_any_phase_removes_the_temporary_and_the_same_name_publishes_on_retry()
-> Result<(), StorageError> {
    // Every row is observed once per pass (accounting, copy, verification),
    // so the first occurrence of each later pass is one past the rows before it.
    for (phase, boundary, pass) in [
        ("accounting", StorageFaultBoundary::Before, 0),
        ("accounting", StorageFaultBoundary::After, 0),
        ("copying", StorageFaultBoundary::Before, 1),
        ("copying", StorageFaultBoundary::After, 1),
        ("verifying", StorageFaultBoundary::Before, 2),
        ("verifying", StorageFaultBoundary::After, 2),
    ] {
        let faults = StorageFaultInjector::new(
            StorageFaultCase {
                site: StorageFaultSite::BackupRecord,
                boundary,
            },
            u64::MAX,
        )?;
        let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
        let directory = backup_directory(&fixture, "refused-backups")?;
        let state_directory = fixture.path().to_path_buf();
        let engine = fixture.engine_mut()?;
        insert_accounts(engine, 1, 5)?;
        let (clean, _) = quiescent_backup(engine, &directory, "clean.backup", 1)?;
        let rows = clean.record_count;
        faults.arm_after_current(rows * pass + 1)?;
        start(engine, &directory, "refused.backup", 2)?;
        let mut seen = Vec::new();
        let outcome = loop {
            seen.push(engine.backup_phase());
            match engine.service_backup() {
                Ok(None) => {}
                Ok(Some(_)) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        assert_eq!(outcome, Err(StorageError::DatabaseRejected), "{phase}");
        assert_eq!(
            seen.last().copied().flatten(),
            Some(phase),
            "{phase}: {seen:?}"
        );
        faults.verify_fired()?;
        assert!(!engine.backup_is_active());
        assert_eq!(
            directory_names(&directory)?,
            vec!["clean.backup".to_owned()],
            "{phase} left an artifact"
        );
        assert_eq!(
            names_with_prefix(&state_directory, SCRATCH_PREFIX)?,
            Vec::<String>::new()
        );
        // The injector is spent; the same name publishes.
        let (retry, retry_bytes) = quiescent_backup(engine, &directory, "refused.backup", 2)?;
        assert_eq!(retry.record_count, rows);
        assert_eq!(retry.stream_bytes, clean.stream_bytes);
        assert_eq!(retry_bytes.len() as u64, retry.stream_bytes);
    }
    Ok(())
}

#[test]
fn publication_faults_retract_and_the_scratch_never_survives_a_failure() -> Result<(), StorageError>
{
    for site in [
        StorageFaultSite::BackupFileSync,
        StorageFaultSite::BackupRename,
        StorageFaultSite::BackupDirectorySync,
    ] {
        for boundary in [StorageFaultBoundary::Before, StorageFaultBoundary::After] {
            let faults = StorageFaultInjector::new(StorageFaultCase { site, boundary }, 1)?;
            let mut fixture = EngineFixture::create_with_faults(faults.clone())?;
            let directory = backup_directory(&fixture, "publication-backups")?;
            let state_directory = fixture.path().to_path_buf();
            let engine = fixture.engine_mut()?;
            insert_accounts(engine, 1, 3)?;
            start(engine, &directory, "published.backup", 1)?;
            assert_eq!(
                drive(engine),
                Err(StorageError::DatabaseRejected),
                "{site:?} {boundary:?}"
            );
            faults.verify_fired()?;
            assert_eq!(directory_names(&directory)?, Vec::<String>::new());
            assert_eq!(
                names_with_prefix(&state_directory, SCRATCH_PREFIX)?,
                Vec::<String>::new()
            );
            let (receipt, _) = quiescent_backup(engine, &directory, "published.backup", 2)?;
            assert!(receipt.record_count > 0);
        }
    }
    Ok(())
}

#[test]
fn a_scratch_allowance_refusal_is_determinate_and_a_following_backup_publishes()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "allowance-backups")?;
    let state_directory = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    insert_accounts(engine, 1, 4)?;
    start(engine, &directory, "refused.backup", 1)?;
    engine.set_backup_scratch_allowance(1)?;
    let refused = drive(engine);
    assert!(
        matches!(refused, Err(StorageError::AllowanceRefused(_))),
        "{refused:?}"
    );
    assert!(!engine.backup_is_active());
    assert_eq!(directory_names(&directory)?, Vec::<String>::new());
    assert_eq!(
        names_with_prefix(&state_directory, SCRATCH_PREFIX)?,
        Vec::<String>::new()
    );

    let (receipt, _) = quiescent_backup(engine, &directory, "refused.backup", 3)?;
    assert!(receipt.record_count > 0);
    Ok(())
}

#[test]
fn limit_exhaustion_refuses_accounting_before_output_and_verification_before_publication()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "limit-backups")?;
    let engine = fixture.engine_mut()?;
    insert_accounts(engine, 1, 6)?;
    let (clean, _) = quiescent_backup(engine, &directory, "clean.backup", 1)?;

    start(engine, &directory, "exhausted.backup", 2)?;
    engine.set_backup_maximum_bytes(clean.stream_bytes - 1)?;
    assert_eq!(drive(engine), Err(StorageError::LimitExceeded));
    assert_eq!(
        directory_names(&directory)?,
        vec!["clean.backup".to_owned()]
    );

    start(engine, &directory, "exhausted.backup", 2)?;
    drive_to_phase(engine, "copying")?;
    engine.set_backup_maximum_bytes(clean.stream_bytes - 1)?;
    let outcome = drive(engine);
    assert_eq!(outcome, Err(StorageError::LimitExceeded));
    assert_eq!(
        directory_names(&directory)?,
        vec!["clean.backup".to_owned()]
    );

    let (exact, _) = quiescent_backup(engine, &directory, "exhausted.backup", 3)?;
    assert_eq!(exact.stream_bytes, clean.stream_bytes);
    Ok(())
}

#[test]
fn a_dangling_reference_is_refused_during_resolution_before_any_output() -> Result<(), StorageError>
{
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "reference-backups")?;
    let state_directory = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    let missing = RecordReference::new(TableId::OpaqueRecord, account_key(77)?)?;
    commit(
        engine,
        vec![RecordMutation::put(
            TableId::Account,
            account_key(7)?,
            1,
            None,
            domain_plaintext(
                TableId::Account,
                vec![missing],
                crate::domain_records::fixtures::live_body(TableId::Account, 1)?,
            )?,
        )?],
    )?;
    start(engine, &directory, "dangling.backup", 1)?;
    let mut seen = Vec::new();
    let outcome = loop {
        seen.push(engine.backup_phase());
        match engine.service_backup() {
            Ok(None) => {}
            Ok(Some(_)) => break Ok(()),
            Err(error) => break Err(error),
        }
    };
    assert_eq!(outcome, Err(StorageError::StaleState));
    assert_eq!(seen.last().copied().flatten(), Some("resolving"));
    assert_eq!(directory_names(&directory)?, Vec::<String>::new());
    assert_eq!(
        names_with_prefix(&state_directory, SCRATCH_PREFIX)?,
        Vec::<String>::new()
    );
    Ok(())
}

#[test]
fn the_largest_legal_record_forms_its_own_slice_in_every_pass() -> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "large-backups")?;
    let engine = fixture.engine_mut()?;
    commit(
        engine,
        vec![RecordMutation::put(
            TableId::AuthTransaction,
            StoredKey::new(vec![9; 16])?,
            1,
            None,
            domain_plaintext(
                TableId::AuthTransaction,
                Vec::new(),
                vec![0; crate::MAX_DOMAIN_RECORD_BODY_BYTES],
            )?,
        )?],
    )?;
    insert_accounts(engine, 1, 2)?;
    start(engine, &directory, "large.backup", 1)?;
    engine.set_backup_slice_budget(BACKUP_SLICE_RECORDS, 1_048_576)?;
    let mut slices_per_phase = std::collections::BTreeMap::new();
    let receipt = loop {
        let phase = engine.backup_phase().ok_or(StorageError::StaleState)?;
        *slices_per_phase.entry(phase).or_insert(0_u32) += 1;
        if let Some(receipt) = engine.service_backup()? {
            break receipt;
        }
    };
    for phase in ["accounting", "copying", "verifying"] {
        assert!(
            slices_per_phase.get(phase).copied().unwrap_or(0) >= 2,
            "{slices_per_phase:?}"
        );
    }
    let bytes = verified_bytes(&directory.join("large.backup"), &receipt)?;
    assert!(bytes.len() > crate::MAX_DOMAIN_RECORD_BODY_BYTES);
    Ok(())
}

#[test]
fn the_snapshot_slot_admits_one_job_and_a_restart_in_any_phase_leaves_nothing_behind()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "restart-backups")?;
    let state_directory = fixture.path().to_path_buf();
    let engine = fixture.engine_mut()?;
    insert_accounts(engine, 1, 6)?;
    start(engine, &directory, "slot.backup", 1)?;
    assert_eq!(
        start(engine, &directory, "second.backup", 2),
        Err(StorageError::QueueFull)
    );
    assert_eq!(engine.start_checkpoint(), Err(StorageError::QueueFull));
    engine.abandon_backup();
    assert!(!engine.backup_is_active());
    engine.mark_checkpoint_due();
    engine.start_checkpoint()?;
    assert_eq!(
        start(engine, &directory, "slot.backup", 1),
        Err(StorageError::QueueFull)
    );
    engine.abandon_checkpoint();

    for phase in PHASES {
        let engine = fixture.engine_mut()?;
        start(engine, &directory, "restart.backup", 3)?;
        engine.set_backup_slice_budget(2, BACKUP_SLICE_BYTES)?;
        drive_to_phase(engine, phase)?;
        if phase == "accounting" {
            // The scratch is created by the first accounting slice.
            assert_eq!(engine.service_backup()?, None);
            assert_eq!(engine.backup_phase(), Some("accounting"));
        }
        let temporaries = names_with_prefix(&directory, BACKUP_TEMPORARY_PREFIX)?;
        let scratches = names_with_prefix(&state_directory, SCRATCH_PREFIX)?;
        match phase {
            "accounting" | "resolving" => {
                assert!(temporaries.is_empty(), "{phase} created output early");
                assert_eq!(scratches.len(), 1, "{phase} has no scratch");
            }
            "admitting" => {
                assert!(temporaries.is_empty() && scratches.is_empty(), "{phase}");
            }
            _ => {
                assert_eq!(temporaries.len(), 1, "{phase} has no temporary");
                assert!(scratches.is_empty(), "{phase} kept the scratch");
            }
        }
        fixture.reopen()?;
        assert_eq!(
            directory_names(&directory)?,
            Vec::<String>::new(),
            "{phase}"
        );
        assert_eq!(
            names_with_prefix(&state_directory, SCRATCH_PREFIX)?,
            Vec::<String>::new()
        );
    }
    let engine = fixture.engine_mut()?;
    let (receipt, _) = quiescent_backup(engine, &directory, "restart.backup", 4)?;
    assert!(receipt.record_count > 0);
    assert_eq!(
        directory_names(&directory)?,
        vec!["restart.backup".to_owned()]
    );
    Ok(())
}

#[test]
fn scratch_keys_are_fixed_width_and_ordered() -> Result<(), StorageError> {
    assert_eq!(reference_key(1, 2)?, [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2]);
    assert!(reference_key(0, 1)? < reference_key(1, 0)?);
    assert_eq!(
        reference_key(0, usize::MAX).map(|_| ()),
        Err(StorageError::Overflow)
    );
    let key = StoredKey::new(vec![7; 3])?;
    assert_eq!(
        scratch_identity(TableId::Account, &key)?,
        vec![0, 1, 7, 7, 7]
    );
    Ok(())
}

#[test]
fn a_backup_started_while_verification_is_owed_completes_and_leaves_the_debt_owed()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    let directory = backup_directory(&fixture, "owed-backups")?;
    let engine = fixture.engine_mut()?;
    insert_accounts(engine, 1, 5)?;
    // What an open below the scratch gate records: the verification is owed.
    engine
        .verification_deferred
        .store(true, std::sync::atomic::Ordering::Release);
    let (receipt, bytes) = quiescent_backup(engine, &directory, "owed.backup", 1)?;
    assert!(receipt.record_count > 0);
    assert_eq!(bytes.len() as u64, receipt.stream_bytes);
    assert!(
        engine.verification_is_deferred(),
        "a backup paid or cleared the owed verification"
    );
    Ok(())
}
