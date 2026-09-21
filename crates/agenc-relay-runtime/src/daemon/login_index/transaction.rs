//! The key mapping and maintenance append cross one durable boundary together.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_admin::{MaintenanceKeyState, MaintenanceTransition};
use agenc_relay_storage::{
    LOGIN_INDEX_KEY_STATE_KEY, LoginIndexTransitionBatch, PersistentRecordValue, SealedRecord,
    StorageAccountingLimits, StorageMutationBatch, StoredKey,
};

pub(super) fn commit_rotation(
    live: &mut LiveStorage,
    config: &Config,
    operation: MaintenanceOperation,
    before: LoginIndexKeyState,
    after: LoginIndexKeyState,
    created_at: u64,
) -> Result<LoginIndexRotationReceipt, LoginIndexRotationError> {
    let recovered = live.seed.storage();
    let scope = MaintenanceAuditScope::new(
        config.network.network_id,
        config.server.server_id,
        recovered.database_binding().database_instance_id(),
        recovered.database_binding().server_incarnation(),
        recovered.recovery_epoch(),
    );
    let transition = MaintenanceTransition::new(
        operation,
        maintenance_state(before)?,
        maintenance_state(after)?,
    )
    .map_err(|_| LoginIndexRotationError::Refused)?;
    let prepared = live.audit.prepare_maintenance_event(
        scope,
        transition,
        live.reconstruction.head,
        startup_transaction_id()?,
        created_at,
    )?;
    let batch = rotation_batch(live, config, before, after, &prepared)?;
    let expected = prepared.event().clone();
    let receipt = submit(&live.owner.port(), batch)?;
    live.audit
        .commit_maintenance_event(prepared, &receipt)
        .map_err(|_| LoginIndexRotationError::Indeterminate)?;
    readback(live, after, &expected, &receipt)
        .map_err(|_| LoginIndexRotationError::CommittedVerificationFailed)?;
    Ok(LoginIndexRotationReceipt {
        key_state: after,
        storage: receipt,
        audit: expected,
    })
}

fn rotation_batch(
    live: &LiveStorage,
    config: &Config,
    before: LoginIndexKeyState,
    after: LoginIndexKeyState,
    prepared: &crate::admin::PreparedMaintenanceAudit,
) -> Result<StorageMutationBatch, LoginIndexRotationError> {
    let head = live.reconstruction.head;
    let accounting = StorageAccountingLimits {
        current_logical_database_bytes: head.logical_database_bytes,
        current_backup_stream_bytes: head.backup_stream_bytes,
        database_max_bytes: config.storage.database_max_bytes,
        backup_max_bytes: config.storage.backup_max_bytes,
    };
    let key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let existing = live
        .reconstruction
        .index
        .existing(TableId::LoginIndexKeyState, &key)?
        .ok_or(LoginIndexRotationError::Refused)?;
    let batch = match after {
        LoginIndexKeyState::Transition {
            current_key_id,
            previous_entry_count,
            ..
        } => LoginIndexTransitionBatch::start(
            prepared.mutation_head(),
            accounting,
            before,
            current_key_id,
            previous_entry_count,
            existing,
            prepared.audit_mutation()?,
        )?,
        LoginIndexKeyState::Stable { .. } => LoginIndexTransitionBatch::finalize(
            prepared.mutation_head(),
            accounting,
            before,
            existing,
            prepared.audit_mutation()?,
        )?,
    };
    Ok(batch)
}

pub(super) fn submit(
    port: &StoragePort,
    batch: StorageMutationBatch,
) -> Result<CommitReceipt, LoginIndexRotationError> {
    let completion = port.try_commit(batch)?;
    match completion
        .wait()
        .map_err(|_| LoginIndexRotationError::Indeterminate)?
    {
        CommitOutcome::Committed(receipt) => Ok(receipt),
        CommitOutcome::Rejected(_) => Err(LoginIndexRotationError::Refused),
        CommitOutcome::Indeterminate => Err(LoginIndexRotationError::Indeterminate),
    }
}

fn maintenance_state(
    state: LoginIndexKeyState,
) -> Result<MaintenanceKeyState, LoginIndexRotationError> {
    let (previous_generation, previous_key_id, previous_count) = match state {
        LoginIndexKeyState::Stable { .. } => (0, [0; 32], 0),
        LoginIndexKeyState::Transition {
            previous_generation,
            previous_key_id,
            previous_entry_count,
            ..
        } => (
            previous_generation,
            *previous_key_id.as_bytes(),
            previous_entry_count,
        ),
    };
    MaintenanceKeyState::new(
        state.current_generation(),
        *state.current_key_id().as_bytes(),
        previous_generation,
        previous_key_id,
        previous_count,
    )
    .map_err(|_| LoginIndexRotationError::Refused)
}

fn readback(
    live: &LiveStorage,
    expected_state: LoginIndexKeyState,
    expected_audit: &MaintenanceAuditEvent,
    receipt: &CommitReceipt,
) -> Result<(), LoginIndexRotationError> {
    let key_state = exact_plaintext(
        live,
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        receipt.storage_commit_sequence,
    )?;
    if LoginIndexKeyState::decode(key_state.expose_for_storage_codec())? != expected_state {
        return Err(LoginIndexRotationError::Refused);
    }
    let sequence = expected_audit.tbs().position().audit_sequence();
    let audit = exact_plaintext(
        live,
        TableId::Audit,
        StoredKey::new(sequence.to_be_bytes().to_vec())?,
        receipt.storage_commit_sequence,
    )?;
    let value = PersistentRecordValue::decode(TableId::Audit, audit.expose_for_storage_codec())?;
    if value.record_kind() != 2
        || Some(value.revision()) != sequence.checked_add(1)
        || value.generation() != 0
        || value.expires_at().is_some()
        || !value.references().is_empty()
        || value.body()
            != expected_audit
                .encode()
                .map_err(|_| LoginIndexRotationError::Refused)?
    {
        return Err(LoginIndexRotationError::Refused);
    }
    Ok(())
}

fn exact_plaintext(
    live: &LiveStorage,
    table: TableId,
    key: StoredKey,
    commit: u64,
) -> Result<agenc_relay_crypto::OpenedStoragePlaintext, LoginIndexRotationError> {
    let result = live
        .owner
        .port()
        .try_read(ReadPlan::exact(table, key.clone()))?
        .wait()?;
    if result.storage_commit_sequence != commit || result.truncated || result.records.len() != 1 {
        return Err(LoginIndexRotationError::Refused);
    }
    let record = result
        .records
        .first()
        .ok_or(LoginIndexRotationError::Refused)?;
    if record.table != table || record.key != key {
        return Err(LoginIndexRotationError::Refused);
    }
    let sealed = SealedRecord::decode(&record.sealed_record)?;
    Ok(live.keys.open(table, &key, &sealed)?)
}
