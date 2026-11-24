#![forbid(unsafe_code)]

//! Appendix C.7 charges sealed rows and anonymous extents to the same owner.

use super::*;
use agenc_relay_e2ee::{ArcWireObject, ArcWireObjectKind, TlsEncode};
use agenc_relay_storage::e2ee_records::{
    EXPIRY_PROGRESS_ROW_KIND, OBJECT_RECORD_KIND, ObjectExpiryProgressRow, ObjectRow,
};
use agenc_relay_storage::{CompanionDisk, CompanionDiskAccounting};

const BLOCK: u64 = 4096;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn directory(fixture: &InitializedLiveFixture) -> Result<StateDirectory, StorageError> {
    StateDirectory::open(fixture.directory.path(), &[fixture.qualification])
}

fn open(fixture: &InitializedLiveFixture, disk: &CompanionDisk) -> TestResult<StorageOwner> {
    Ok(StorageOwner::start_with_companion_disk(
        live_open_config(directory(fixture)?),
        Some(disk.clone()),
    )?)
}

fn rows() -> TestResult<Vec<(TableId, StoredKey, Vec<u8>)>> {
    let bytes = ArcWireObject::new(ArcWireObjectKind::WelcomeMls, vec![43; 1000])?.encode()?;
    let object = ObjectRow::new(bytes)?;
    let progress = ObjectExpiryProgressRow::default();
    [
        (
            TableId::E2eeObject,
            OBJECT_RECORD_KIND,
            object.key()?,
            object.encode()?,
        ),
        (
            TableId::E2eeState,
            EXPIRY_PROGRESS_ROW_KIND,
            ObjectExpiryProgressRow::key()?,
            progress.encode()?,
        ),
    ]
    .into_iter()
    .map(|(table, kind, key, body)| {
        Ok((
            table,
            key,
            PersistentRecordValue::new(table, kind, 1, 0, None, Vec::new(), body)?.encode()?,
        ))
    })
    .collect()
}

fn batch(
    owner: &StorageOwner,
    mut mutations: Vec<RecordMutation>,
) -> TestResult<StorageMutationBatch> {
    let cut = owner.recovered_state();
    if let Some(accounting) = cut.companion_disk_accounting()
        && let Some(next) = accounting.project(&mutations)?
    {
        let key = CompanionDiskAccounting::key()?;
        let present = owner
            .port()
            .try_read(ReadPlan::exact(TableId::E2eeState, key.clone()))?
            .wait()?;
        let before = match present.records.first() {
            Some(rec) => {
                let record = SealedRecord::decode(&rec.sealed_record)?;
                Some(ExistingRecord::new(
                    record.record_schema(),
                    record.record_id()?,
                    rec.sealed_record.len(),
                )?)
            }
            None => None,
        };
        mutations.push(RecordMutation::put(
            TableId::E2eeState,
            key,
            1,
            before,
            next.record(cut.state_generation() + 1)?.encode()?,
        )?);
    }
    bare_batch(owner, mutations)
}

fn bare_batch(
    owner: &StorageOwner,
    mutations: Vec<RecordMutation>,
) -> TestResult<StorageMutationBatch> {
    let cut = owner.recovered_state();
    Ok(StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([61; 16]),
            expected_storage_commit_sequence: cut.storage_commit_sequence(),
            expected_state_generation: cut.state_generation(),
            resulting_state_generation: cut.state_generation() + 1,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: cut.account_service_response_count(),
            resulting_account_service_response_count: cut.account_service_response_count(),
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: cut.logical_database_bytes(),
            current_backup_stream_bytes: cut.backup_stream_bytes(),
            database_max_bytes: test_limits().database_max_bytes,
            backup_max_bytes: test_limits().backup_max_bytes,
        },
        mutations,
    )?)
}

pub(super) fn put_both(owner: &StorageOwner) -> TestResult<CommitOutcome> {
    let writes = puts()?;
    Ok(owner.port().try_commit(batch(owner, writes)?)?.wait()?)
}

fn puts() -> TestResult<Vec<RecordMutation>> {
    Ok(rows()?
        .into_iter()
        .map(|(table, key, plaintext)| RecordMutation::put(table, key, 1, None, plaintext))
        .collect::<Result<_, _>>()?)
}

fn verified_backup(owner: &StorageOwner) -> TestResult {
    let sink = TestDirectory::create()?;
    let name = "qualified.agenc";
    let signer = Ed25519SecretKey::from_bytes([83; 32]);
    let trust = BackupTrustKey::new(signer.public_key())?;
    let receipt = owner
        .port()
        .try_backup(
            BackupDestination::new(sink.path(), name)?,
            signer,
            1_000,
            [84; 16],
        )?
        .wait()?;
    let verified = verify_backup(
        fs::File::open(sink.path().join(name))?,
        &StorageMasterKey::from_bytes([207; 32]),
        &RollbackGuardRootKey::from_bytes([208; 32]),
        &[trust],
        test_limits().backup_max_bytes,
    )?;
    assert_eq!(verified.stream_bytes, receipt.stream_bytes);
    assert_eq!(verified.trailer.record_count, receipt.record_count);
    Ok(())
}

#[test]
fn live_extents_and_both_sealed_tables_obey_the_same_limit_before_and_after_restart() -> TestResult
{
    let fixture = initialized_live_fixture()?;
    let disk = CompanionDisk::new(5 * BLOCK)?;
    let state_directory = directory(&fixture)?;
    let allocator = state_directory.companion_spool_directory(0, 0)?;
    let owner = StorageOwner::start_with_companion_disk(
        live_open_config(state_directory),
        Some(disk.clone()),
    )?;
    let extent = disk.reserve_extent(2 * BLOCK + 1)?;
    let file = allocator.allocate(2 * BLOCK + 1)?;
    assert!(matches!(
        put_both(&owner)?,
        CommitOutcome::Rejected(StorageError::LimitExceeded)
    ));
    for (table, key, _) in rows()? {
        let read = owner.port().try_read(ReadPlan::exact(table, key))?.wait()?;
        assert_eq!(read.storage_commit_sequence, 0);
        assert!(read.records.is_empty());
    }
    drop(file);
    drop(extent);
    let extent = disk.reserve_extent(2 * BLOCK)?;
    let file = allocator.allocate(2 * BLOCK)?;
    assert!(matches!(put_both(&owner)?, CommitOutcome::Committed(_)));
    assert!(matches!(
        disk.reserve_extent(1),
        Err(StorageError::LimitExceeded)
    ));
    drop(file);
    drop(extent);
    owner.shutdown()?;

    let small = CompanionDisk::new(3 * BLOCK - 1)?;
    assert!(matches!(
        StorageOwner::start_with_companion_disk(
            live_open_config(directory(&fixture)?),
            Some(small)
        ),
        Err(StorageError::LimitExceeded)
    ));
    let disk = CompanionDisk::new(5 * BLOCK)?;
    let live = disk.reserve_extent(2 * BLOCK + 1)?;
    assert!(matches!(
        StorageOwner::start_with_companion_disk(
            live_open_config(directory(&fixture)?),
            Some(disk.clone())
        ),
        Err(StorageError::LimitExceeded)
    ));
    drop(live);
    let owner = open(&fixture, &disk)?;
    assert_eq!(
        owner
            .recovered_state()
            .companion_disk_accounting()
            .ok_or("active accounting")?
            .sealed_bytes(),
        3 * BLOCK
    );
    verified_backup(&owner)?;
    assert!(matches!(
        disk.reserve_extent(2 * BLOCK + 1),
        Err(StorageError::LimitExceeded)
    ));
    let fitting = disk.reserve_extent(2 * BLOCK)?;
    let deletes = rows()?
        .into_iter()
        .map(|(table, key, _)| {
            let present = read_existing_record(&owner.port(), table, key.clone())?;
            Ok(RecordMutation::delete(table, key, present))
        })
        .collect::<TestResult<_>>()?;
    assert!(matches!(
        owner.port().try_commit(batch(&owner, deletes)?)?.wait()?,
        CommitOutcome::Committed(_)
    ));
    assert!(disk.reserve_extent(2 * BLOCK).is_ok());
    drop(fitting);
    owner.shutdown()?;
    let disk = CompanionDisk::new(5 * BLOCK)?;
    let owner = open(&fixture, &disk)?;
    assert!(disk.reserve_extent(4 * BLOCK).is_ok());
    assert_eq!(
        owner
            .recovered_state()
            .companion_disk_accounting()
            .ok_or("active accounting")?
            .sealed_bytes(),
        BLOCK
    );
    owner.shutdown()?;
    Ok(())
}

#[test]
fn legacy_rows_seed_a_counter_only_with_the_first_verified_new_allocation() -> TestResult {
    let fixture = initialized_live_fixture()?;
    let legacy = StorageOwner::start(live_open_config(directory(&fixture)?))?;
    assert!(
        legacy
            .recovered_state()
            .companion_disk_accounting()
            .is_none()
    );
    assert!(matches!(put_both(&legacy)?, CommitOutcome::Committed(_)));
    verified_backup(&legacy)?;
    legacy.shutdown()?;
    let disk = CompanionDisk::new(6 * BLOCK)?;
    let owner = open(&fixture, &disk)?;
    let current = owner
        .recovered_state()
        .companion_disk_accounting()
        .ok_or("legacy aggregate from scan")?;
    assert_eq!(current.sealed_bytes(), 2 * BLOCK);
    let key = ObjectExpiryProgressRow::key()?;
    let deleting = || -> TestResult<Vec<RecordMutation>> {
        Ok(vec![RecordMutation::delete(
            TableId::E2eeState,
            key.clone(),
            read_existing_record(&owner.port(), TableId::E2eeState, key.clone())?,
        )])
    };
    let invalid = bare_batch(&owner, deleting()?)?;
    assert!(matches!(
        owner.port().try_commit(invalid)?.wait()?,
        CommitOutcome::Rejected(StorageError::StaleState)
    ));
    // This well-formed aggregate predicts another allocation history, so it
    // cannot authorize any change to the source store.
    let wrong = CompanionDiskAccounting::default()
        .project(&puts()?)?
        .ok_or("wrong aggregate")?;
    let mut mismatched = deleting()?;
    mismatched.push(RecordMutation::put(
        TableId::E2eeState,
        CompanionDiskAccounting::key()?,
        1,
        None,
        wrong.record(2)?.encode()?,
    )?);
    assert!(matches!(
        owner
            .port()
            .try_commit(bare_batch(&owner, mismatched)?)?
            .wait()?,
        CommitOutcome::Rejected(StorageError::StaleState)
    ));
    read_existing_record(&owner.port(), TableId::E2eeState, key.clone())?;
    assert!(matches!(
        owner
            .port()
            .try_commit(batch(&owner, deleting()?)?)?
            .wait()?,
        CommitOutcome::Committed(_)
    ));
    owner.shutdown()?;
    let owner = StorageOwner::start(live_open_config(directory(&fixture)?))?;
    assert_eq!(
        owner
            .recovered_state()
            .companion_disk_accounting()
            .ok_or("installed aggregate")?
            .sealed_bytes(),
        2 * BLOCK
    );
    read_existing_record(
        &owner.port(),
        TableId::E2eeState,
        CompanionDiskAccounting::key()?,
    )?;
    verified_backup(&owner)?;
    owner.shutdown()?;
    Ok(())
}

#[test]
fn restore_rebuilds_the_aggregate_from_the_rows_selected_for_the_new_epoch() -> TestResult {
    super::stopped_daemon_restore(true)
}

pub(super) fn verify_restored(source: &InitializedLiveFixture, output: &Path) -> TestResult {
    let mut config = live_open_config(StateDirectory::open(output, &[source.qualification])?);
    config.rollback_guard_root_key = RollbackGuardRootKey::from_bytes([153; 32]);
    let disk = CompanionDisk::new(64 * 1024)?;
    let owner = StorageOwner::start_with_companion_disk(config, Some(disk))?;
    let read = owner
        .port()
        .try_read(ReadPlan::exact(
            TableId::E2eeState,
            CompanionDiskAccounting::key()?,
        ))?
        .wait()?;
    assert!(read.records.is_empty());
    let actual = owner
        .recovered_state()
        .companion_disk_accounting()
        .ok_or("restored aggregate")?
        .sealed_bytes();
    assert_eq!(actual, 2 * BLOCK);
    owner.shutdown()?;
    Ok(())
}

#[test]
fn startup_rejects_a_properly_sealed_aggregate_for_a_different_record_set() -> TestResult {
    let aggregate = CompanionDiskAccounting::default()
        .project(&puts()?)?
        .ok_or("wrong aggregate")?;
    let login_key = LoginIndexKey::from_bytes([203; 32]);
    let login = LoginIndexKeyState::stable(1, login_key.key_id(NetworkId::from_bytes([201; 32])))?;
    let fixture = initialized_live_fixture_from(vec![
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_relay_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            login.encode()?,
        )?,
        InitialStorageRecord::new(
            TableId::E2eeState,
            CompanionDiskAccounting::key()?,
            1,
            aggregate.record(1)?.encode()?,
        )?,
    ])?;
    assert!(matches!(
        StorageOwner::start(live_open_config(directory(&fixture)?)),
        Err(StorageError::StaleState)
    ));
    Ok(())
}

#[test]
fn an_indeterminate_charge_stays_closed_until_a_new_owner_authenticates_its_actual_rows()
-> TestResult {
    let fixture = initialized_live_fixture()?;
    let disk = CompanionDisk::new(3 * BLOCK)?;
    let faults = StorageFaultInjector::new(
        StorageFaultCase {
            site: StorageFaultSite::Manifest,
            boundary: StorageFaultBoundary::After,
        },
        u64::MAX,
    )?;
    let state = StateDirectory::open_with_faults(
        fixture.directory.path(),
        &[fixture.qualification],
        faults.clone(),
    )?;
    let owner =
        StorageOwner::start_with_companion_disk(live_open_config(state), Some(disk.clone()))?;
    faults.arm_after_current(1)?;
    assert!(matches!(put_both(&owner)?, CommitOutcome::Indeterminate));
    faults.verify_fired()?;
    assert!(matches!(
        disk.reserve_extent(1),
        Err(StorageError::Unavailable)
    ));
    let _shutdown = owner.shutdown();
    let owner = open(&fixture, &disk)?;
    assert_eq!(owner.recovered_state().state_generation(), 1);
    for (table, key, _) in rows()? {
        read_existing_record(&owner.port(), table, key)?;
    }
    assert!(disk.reserve_extent(0).is_ok());
    assert!(matches!(
        disk.reserve_extent(1),
        Err(StorageError::LimitExceeded)
    ));
    owner.shutdown()?;
    Ok(())
}
