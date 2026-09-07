//! The command must count the second index page without rewriting dormant entries.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_crypto::derive_login_index;
use agenc_ircd_storage::{
    CommitOutcome, LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, MAX_STORED_KEY_BYTES,
    RecordMutation, StorageAccountingLimits, StorageMutationBatch, StorageMutationHead,
};
use agenc_ircd_types::{AccountRandomId, TransactionId};

const ENTRY_COUNT: u64 = 257;

fn tombstone_pair(
    fixture: &NodeFixture,
    index: u64,
    revision: u64,
) -> TestResult<[RecordMutation; 2]> {
    let mut id = [41; 16];
    id.get_mut(8..)
        .ok_or_else(|| failure("short account ID"))?
        .copy_from_slice(&index.to_be_bytes());
    let account = AccountRandomId::from_bytes(id).to_account_id();
    let account_value = PersistentRecordValue::new(
        TableId::Account,
        2,
        revision,
        0,
        None,
        Vec::new(),
        Vec::new(),
    )?;
    let login = NormalizedLogin::prepare(&format!("retired{index:04}"))?;
    let key = LoginIndexStoredKey::new(
        1,
        derive_login_index(
            &LoginIndexKey::from_bytes([fixture.seed.wrapping_add(9); 32]),
            NETWORK_ID,
            &login,
        )?,
    )?;
    let value = LoginIndexValue::new(
        &key,
        LoginIndexValueKind::DeletionTombstone {
            deleted_account_id: account,
            expires_at: 4_000_000_000,
        },
    )?;
    Ok([
        RecordMutation::put(
            TableId::Account,
            KeyDeriver::account_key(account)?,
            1,
            None,
            account_value.encode()?,
        )?,
        RecordMutation::put(TableId::LoginIndex, key.encode()?, 1, None, value.encode()?)?,
    ])
}

fn seed_tombstones(fixture: &NodeFixture) -> TestResult {
    let owner = open_owner(fixture, [fixture.seed.wrapping_add(9); 32], None)?;
    let recovered = owner.recovered_state();
    let revision = recovered
        .state_generation()
        .checked_add(1)
        .ok_or_else(|| failure("revision overflow"))?;
    let mut writes = Vec::new();
    for index in 0..ENTRY_COUNT {
        writes.extend(tombstone_pair(fixture, index, revision)?);
    }
    let transaction_id = TransactionId::from_bytes([91; 16]);
    let batch = StorageMutationBatch::new(
        StorageMutationHead {
            transaction_id,
            expected_storage_commit_sequence: recovered.storage_commit_sequence(),
            expected_state_generation: recovered.state_generation(),
            resulting_state_generation: revision,
            state_advancing_plan_count: 1,
            expected_account_service_response_count: recovered.account_service_response_count(),
            resulting_account_service_response_count: recovered.account_service_response_count(),
        },
        1,
        StorageAccountingLimits {
            current_logical_database_bytes: recovered.logical_database_bytes(),
            current_backup_stream_bytes: recovered.backup_stream_bytes(),
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
        },
        writes,
    )?;
    match owner.port().try_commit(batch)?.wait()? {
        CommitOutcome::Committed(receipt) => {
            assert_eq!(receipt.transaction_id, transaction_id);
            assert_eq!(receipt.state_generation, revision);
        }
        _ => return Err(failure("tombstone fixture commit did not complete")),
    }
    owner.shutdown()?;
    Ok(())
}

fn login_rows(
    fixture: &NodeFixture,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
) -> TestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let owner = open_owner(fixture, current, previous)?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let result = owner
        .port()
        .try_read(ReadPlan::range(
            TableId::LoginIndex,
            StoredKey::new(vec![0])?,
            StoredKey::new(vec![255; MAX_STORED_KEY_BYTES])?,
            4096,
        )?)?
        .wait()?;
    assert!(!result.truncated);
    assert_eq!(
        result.storage_commit_sequence,
        recovered.storage_commit_sequence()
    );
    assert_eq!(result.records.len(), usize::try_from(ENTRY_COUNT)?);
    let mut rows = Vec::new();
    for row in result.records {
        assert_eq!(row.table, TableId::LoginIndex);
        let sealed = SealedRecord::decode(&row.sealed_record)?;
        let opened = keys.open(row.table, &row.key, &sealed)?;
        rows.push((
            row.key.as_bytes().to_vec(),
            opened.expose_for_storage_codec().to_vec(),
        ));
    }
    owner.shutdown()?;
    Ok(rows)
}

#[test]
fn start_counts_the_complete_index_and_finish_preserves_dormant_entries() -> TestResult {
    let network = build_network()?;
    let fixture = &network.coordinator;
    let old_key = [fixture.seed.wrapping_add(9); 32];
    seed_tombstones(fixture)?;
    let before_rows = login_rows(fixture, old_key, None)?;
    let before = inspect(fixture, old_key, None, 0)?;
    let new_key = fixture.data_dir.join("keys/login-index-next.key");
    write_private(&new_key, &NEW_KEY)?;
    let output = rotation(fixture, Some(&new_key))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let started = inspect(fixture, NEW_KEY, Some(old_key), 1)?;
    assert_eq!(started.state.previous(), Some((1, ENTRY_COUNT)));
    assert_eq!(started.generation, before.generation + 1);
    assert_eq!(started.opaque, before.opaque);
    assert_eq!(
        started
            .events
            .first()
            .ok_or_else(|| failure("start audit event missing"))?
            .tbs()
            .transition()
            .resulting()
            .previous()
            .ok_or_else(|| failure("audit previous tuple missing"))?
            .2,
        ENTRY_COUNT
    );
    assert_eq!(login_rows(fixture, NEW_KEY, Some(old_key))?, before_rows);
    install_key_mapping(fixture, &new_key, true)?;
    let refused = rotation(fixture, None)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let retained = inspect(fixture, NEW_KEY, Some(old_key), 1)?;
    assert_eq!(retained.state, started.state);
    assert_eq!(retained.generation, started.generation);
    assert_eq!(retained.commit, started.commit);
    assert_eq!(retained.events, started.events);
    assert_eq!(login_rows(fixture, NEW_KEY, Some(old_key))?, before_rows);
    Ok(())
}
