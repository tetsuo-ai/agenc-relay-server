//! Redeemed invitation ownership must survive the actual sealed storage restart.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use agenc_ircd_storage::{
    OPAQUE_FAKE_RECORD_KEY, RecordMutation, RecordReference, StorageAccountingLimits,
    StorageMutationBatch, StorageMutationHead,
};
use agenc_ircd_types::AccountId;
use agenc_ircd_types::{AccountRandomId, InviteId};

fn account_key(seed: u8) -> TestResult<StoredKey> {
    Ok(KeyDeriver::account_key(AccountId::from_random(
        AccountRandomId::from_bytes([seed; 16]),
    ))?)
}

fn invitation_key() -> TestResult<StoredKey> {
    Ok(StoredKey::new(
        InviteId::from_bytes([74; 16]).as_bytes().to_vec(),
    )?)
}

fn record(
    table: TableId,
    key: StoredKey,
    expires_at: Option<u64>,
    references: Vec<RecordReference>,
) -> TestResult<RecordMutation> {
    let value = PersistentRecordValue::new(table, 2, 1, 0, expires_at, references, Vec::new())?;
    Ok(RecordMutation::put(table, key, 1, None, value.encode()?)?)
}

fn seed(
    references: Vec<RecordReference>,
    extra_account: bool,
) -> TestResult<fixture::FaultFixture> {
    let fixture = fixture::FaultFixture::new()?;
    let live = fixture.open(fixture.stable()?, StorageFaultInjector::disabled())?;
    let mut records = vec![
        record(TableId::Account, account_key(72)?, None, Vec::new())?,
        record(
            TableId::RegistrationInvite,
            invitation_key()?,
            Some(3600),
            references,
        )?,
    ];
    if extra_account {
        records.push(record(
            TableId::Account,
            account_key(73)?,
            None,
            Vec::new(),
        )?);
    }
    let head = live.reconstruction.head;
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id: TransactionId::from_bytes([75; 16]),
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
        records,
    )?;
    let receipt = transaction::submit(&live.owner.port(), batch)?;
    assert_eq!(
        receipt.state_generation,
        head.state_generation
            .checked_add(1)
            .ok_or("generation overflow")?
    );
    live.owner.shutdown()?;
    Ok(fixture)
}

fn refusal(fixture: &fixture::FaultFixture) -> TestResult {
    let result = fixture.start_storage(fixture.stable()?, StorageFaultInjector::disabled());
    let error = match result {
        Ok(owner) => {
            owner.shutdown()?;
            return Err("malformed redeemed invitation passed actual storage startup".into());
        }
        Err(error) => error,
    };
    assert_eq!(error, StorageError::StaleState);
    Ok(())
}

#[test]
fn a_redeemed_invitation_with_one_account_owner_survives_actual_storage_restart() -> TestResult {
    let fixture = seed(
        vec![RecordReference::new(TableId::Account, account_key(72)?)?],
        false,
    )?;
    let owner = fixture
        .start_storage(fixture.stable()?, StorageFaultInjector::disabled())
        .map_err(|error| format!("canonical redeemed invitation storage restart: {error}"))?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes(MASTER),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let key = invitation_key()?;
    let result = owner
        .port()
        .try_read(ReadPlan::exact(TableId::RegistrationInvite, key.clone()))?
        .wait()?;
    assert!(!result.truncated);
    assert_eq!(result.records.len(), 1);
    let row = result
        .records
        .first()
        .ok_or("missing redeemed invitation")?;
    assert!(row.key == key);
    let sealed = SealedRecord::decode(&row.sealed_record)?;
    let plaintext = keys.open(TableId::RegistrationInvite, &key, &sealed)?;
    let value = PersistentRecordValue::decode(
        TableId::RegistrationInvite,
        plaintext.expose_for_storage_codec(),
    )?;
    assert_eq!(value.record_kind(), 2);
    assert_eq!(value.references().len(), 1);
    let reference = value.references().first().ok_or("missing account owner")?;
    assert_eq!(reference.table(), TableId::Account);
    assert!(reference.key() == &account_key(72)?);
    owner.shutdown()?;
    let live = fixture.open(fixture.stable()?, StorageFaultInjector::disabled())?;
    assert!(
        live.reconstruction
            .account_service
            .startup_transaction_cleanups()
            .is_empty()
    );
    live.owner.shutdown()?;
    Ok(())
}

#[test]
fn a_redeemed_invitation_without_an_account_owner_refuses_actual_storage_restart() -> TestResult {
    refusal(&seed(Vec::new(), false)?)
}

#[test]
fn a_redeemed_invitation_with_two_account_owners_refuses_actual_storage_restart() -> TestResult {
    refusal(&seed(
        vec![
            RecordReference::new(TableId::Account, account_key(72)?)?,
            RecordReference::new(TableId::Account, account_key(73)?)?,
        ],
        true,
    )?)
}

#[test]
fn a_redeemed_invitation_with_the_wrong_existing_target_refuses_actual_storage_restart()
-> TestResult {
    refusal(&seed(
        vec![RecordReference::new(
            TableId::OpaqueRecord,
            StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        )?],
        false,
    )?)
}
