//! Stopped cleanup crosses real receipts before the login count is signed.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use agenc_ircd_storage::{StorageAccountingLimits, StorageMutationBatch, StorageMutationHead};

mod rows;

fn install(fixture: &fixture::FaultFixture) -> TestResult {
    let live = fixture
        .open(fixture.stable()?, StorageFaultInjector::disabled())
        .map_err(|error| format!("open initial fixture: {error}"))?;
    assert_eq!(fixture.config.network.network_id.as_bytes(), &[1; 32]);
    let head = live.reconstruction.head;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([71; 16]),
            expected_storage_commit_sequence: head.storage_commit_sequence,
            expected_state_generation: head.state_generation,
            resulting_state_generation: head
                .state_generation
                .checked_add(1)
                .ok_or("generation overflow")?,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: head.account_service_response_count,
            resulting_account_service_response_count: head.account_service_response_count,
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: head.logical_database_bytes,
            current_backup_stream_bytes: head.backup_stream_bytes,
            database_max_bytes: fixture.config.storage.database_max_bytes,
            backup_max_bytes: fixture.config.storage.backup_max_bytes,
        },
        rows::records().map_err(|error| format!("encode stale START rows: {error}"))?,
    )
    .map_err(|error| format!("construct stale START seed batch: {error}"))?;
    transaction::submit(&live.owner.port(), batch)
        .map_err(|error| format!("commit stale START seed batch: {error}"))?;
    live.owner
        .shutdown()
        .map_err(|error| format!("close seeded fixture: {error}"))?;
    Ok(())
}

fn table(live: &LiveStorage, table: TableId) -> TestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let result = live
        .owner
        .port()
        .try_read(ReadPlan::range(
            table,
            StoredKey::new(vec![0])?,
            StoredKey::new(vec![255; agenc_ircd_storage::MAX_STORED_KEY_BYTES])?,
            16,
        )?)?
        .wait()?;
    assert!(!result.truncated);
    Ok(result
        .records
        .into_iter()
        .map(|row| (row.key.as_bytes().to_vec(), row.sealed_record))
        .collect())
}

fn exact(live: &LiveStorage, table: TableId, key: StoredKey) -> TestResult<Vec<u8>> {
    let result = live
        .owner
        .port()
        .try_read(ReadPlan::exact(table, key))?
        .wait()?;
    assert_eq!(result.records.len(), 1);
    Ok(result
        .records
        .first()
        .ok_or("retained row")?
        .sealed_record
        .clone())
}

#[test]
fn stopped_start_retires_only_its_typed_creation_authority_before_counting() -> TestResult {
    let fixture = fixture::FaultFixture::new()
        .map_err(|error| format!("initialize stale START fixture: {error}"))?;
    install(&fixture)?;
    let stable = fixture.stable()?;
    let mut live = fixture
        .open(stable, StorageFaultInjector::disabled())
        .map_err(|error| format!("authenticate seeded START reconstruction: {error}"))?;
    let cleanups = live
        .reconstruction
        .account_service
        .startup_transaction_cleanups();
    assert_eq!(
        cleanups
            .iter()
            .map(|row| row.transaction_id())
            .collect::<Vec<_>>(),
        vec![rows::CREATION, rows::REJECTED, rows::AUTHENTICATION]
    );
    let creation = cleanups.first().ok_or("creation cleanup")?;
    assert!(creation.login_key() == Some(&rows::owned_login()?));
    assert_eq!(
        creation.invitation_id().map(|id| id.as_bytes().to_vec()),
        Some(rows::owned_invite()?.as_bytes().to_vec())
    );
    assert!(
        cleanups
            .iter()
            .skip(1)
            .all(|row| row.login_key().is_none() && row.invitation_id().is_none())
    );
    assert!(
        scan::scan_login_index(&live, stable, Some(fixture.new_key_id())).is_err(),
        "the uncleaned creation reservation must block rotation"
    );
    let accounts = table(&live, TableId::Account)?;
    let opaque = table(&live, TableId::OpaqueRecord)?;
    let login = exact(&live, TableId::LoginIndex, rows::survivor_login()?)?;
    let invite = exact(&live, TableId::RegistrationInvite, rows::survivor_invite()?)?;
    let before = live.reconstruction.head;
    cleanup::cleanup_transactions(&mut live, &fixture.config)
        .map_err(|error| format!("settle typed START cleanup: {error}"))?;
    assert!(table(&live, TableId::AuthTransaction)?.is_empty());
    assert_eq!(table(&live, TableId::Account)?, accounts);
    assert_eq!(table(&live, TableId::OpaqueRecord)?, opaque);
    assert_eq!(
        table(&live, TableId::LoginIndex)?,
        vec![(rows::survivor_login()?.as_bytes().to_vec(), login)]
    );
    assert_eq!(
        table(&live, TableId::RegistrationInvite)?,
        vec![(rows::survivor_invite()?.as_bytes().to_vec(), invite)]
    );
    assert!(table(&live, TableId::Audit)?.is_empty());
    assert_eq!(
        live.reconstruction.head.storage_commit_sequence,
        before
            .storage_commit_sequence
            .checked_add(3)
            .ok_or("commit overflow")?
    );
    assert_eq!(
        live.reconstruction.head.state_generation,
        before
            .state_generation
            .checked_add(3)
            .ok_or("generation overflow")?
    );
    let after = scan::scan_login_index(&live, stable, Some(fixture.new_key_id()))
        .map_err(|error| format!("count cleaned login index: {error}"))?;
    assert_eq!(after, stable.start_rotation(fixture.new_key_id(), 1)?);
    let receipt = transaction::commit_rotation(
        &mut live,
        &fixture.config,
        MaintenanceOperation::LoginIndexRotateStart,
        stable,
        after,
        60,
    )
    .map_err(|error| format!("commit rotation after typed cleanup: {error}"))?;
    assert_eq!(
        receipt.storage.storage_commit_sequence,
        before
            .storage_commit_sequence
            .checked_add(4)
            .ok_or("commit overflow")?
    );
    assert_eq!(
        receipt.audit.tbs().position().preceding_state_generation(),
        before
            .state_generation
            .checked_add(3)
            .ok_or("generation overflow")?
    );
    let audit_rows = table(&live, TableId::Audit)?;
    assert_eq!(audit_rows.len(), 1);
    live.owner
        .shutdown()
        .map_err(|error| format!("close cleaned rotated fixture: {error}"))?;
    let reopened = fixture
        .open(after, StorageFaultInjector::disabled())
        .map_err(|error| format!("authenticate final rotation reconstruction: {error}"))?;
    assert!(
        reopened
            .reconstruction
            .account_service
            .startup_transaction_cleanups()
            .is_empty()
    );
    assert_eq!(table(&reopened, TableId::Audit)?, audit_rows);
    assert_eq!(table(&reopened, TableId::Account)?, accounts);
    assert_eq!(table(&reopened, TableId::OpaqueRecord)?, opaque);
    reopened.owner.shutdown()?;
    Ok(())
}
