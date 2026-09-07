//! A signed append remains private until its exact coupled storage receipt.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::state_core::durable::read_back_record;
use agenc_ircd_crypto::LoginIndexKey;
use agenc_ircd_storage::{
    LOGIN_INDEX_KEY_STATE_KEY, LoginIndexTransitionBatch, StorageAccountingLimits,
};
use agenc_ircd_types::TransactionId;

fn start_transition(core: &StateCoreFixture) -> TestResult<MaintenanceTransition> {
    let before = core.key_state;
    let next = LoginIndexKey::from_bytes([92; 32]).key_id(core.identity.network_id);
    let generation = before.current_generation();
    let key = *before.current_key_id().as_bytes();
    Ok(MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateStart,
        MaintenanceKeyState::new(generation, key, 0, [0; 32], 0)?,
        MaintenanceKeyState::new(
            generation.checked_add(1).ok_or("generation")?,
            *next.as_bytes(),
            generation,
            key,
            0,
        )?,
    )?)
}

fn prepare(
    core: &StateCoreFixture,
    authority: &AuditAuthority,
    transaction: u8,
) -> TestResult<PreparedMaintenanceAudit> {
    let source = core.audit_source()?;
    Ok(authority.prepare_maintenance_event(
        source.scope,
        start_transition(core)?,
        source.head,
        TransactionId::from_bytes([transaction; 16]),
        60,
    )?)
}

fn start_batch(
    core: &StateCoreFixture,
    prepared: &PreparedMaintenanceAudit,
    stale_head: bool,
) -> TestResult<StorageMutationBatch> {
    let source = core.audit_source()?;
    let key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let read = source
        .storage
        .try_read(ReadPlan::exact(TableId::LoginIndexKeyState, key.clone()))?
        .wait()?;
    let (_, _, before) = read_back_record(TableId::LoginIndexKeyState, key, read)?;
    let mut head = prepared.mutation_head();
    if stale_head {
        head.expected_storage_commit_sequence = head
            .expected_storage_commit_sequence
            .checked_add(1)
            .ok_or("head")?;
    }
    Ok(LoginIndexTransitionBatch::start(
        head,
        StorageAccountingLimits {
            current_logical_database_bytes: source.head.logical_database_bytes,
            current_backup_stream_bytes: source.head.backup_stream_bytes,
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 2_147_483_648,
        },
        core.key_state,
        LoginIndexKey::from_bytes([92; 32]).key_id(core.identity.network_id),
        0,
        before.ok_or("key-state before image")?,
        prepared.audit_mutation()?,
    )?)
}

#[tokio::test]
async fn maintenance_cursor_waits_for_the_actual_coupled_key_state_receipt() -> TestResult {
    let fixture = Fixture::new();
    let core = core(&[])?;
    let mut authority = fixture.authority(&core)?;
    let prepared = prepare(&core, &authority, 90)?;
    let event = prepared.event().clone();
    assert_eq!(authority.cursor, AuditChainCursor::genesis());
    let source = core.audit_source()?;
    let completion = source
        .storage
        .try_commit(start_batch(&core, &prepared, false)?)?;
    assert_eq!(authority.cursor, AuditChainCursor::genesis());
    let CommitOutcome::Committed(receipt) = completion.wait()? else {
        return Err("coupled maintenance commit".into());
    };
    authority.commit_maintenance_event(prepared, &receipt)?;
    assert_eq!(
        authority.cursor,
        AuditChainCursor::genesis().advance_event(&AuditEvent::Maintenance(event.clone()))?
    );
    assert_eq!(fixture.authority(&core)?.cursor, authority.cursor);
    let key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
    let rows = source
        .storage
        .try_read(ReadPlan::exact(TableId::LoginIndexKeyState, key.clone()))?
        .wait()?;
    let row = rows.records.first().ok_or("committed key state")?;
    let sealed = SealedRecord::decode(&row.sealed_record)?;
    let plain = source
        .keys
        .open(TableId::LoginIndexKeyState, &key, &sealed)?;
    let state = agenc_ircd_storage::LoginIndexKeyState::decode(plain.expose_for_storage_codec())?;
    assert_eq!(
        state,
        core.key_state.start_rotation(
            LoginIndexKey::from_bytes([92; 32]).key_id(core.identity.network_id),
            0
        )?
    );
    Ok(())
}

#[tokio::test]
async fn determinate_maintenance_refusal_preserves_the_exact_unpublished_owner() -> TestResult {
    let fixture = Fixture::new();
    let core = core(&[])?;
    let mut authority = fixture.authority(&core)?;
    let prepared = prepare(&core, &authority, 90)?;
    let encoded = prepared.event().encode()?;
    let source = core.audit_source()?;
    let rejected = source
        .storage
        .try_commit(start_batch(&core, &prepared, true)?)?
        .wait()?;
    assert!(matches!(rejected, CommitOutcome::Rejected(_)));
    assert_eq!(authority.cursor, AuditChainCursor::genesis());
    assert!(authority.is_reconciled());
    scan_events(&source.storage, &source.keys, |_| {
        Err(RuntimeError::InvalidValue)
    })?;
    assert_eq!(prepared.event().encode()?, encoded);
    let receipt = commit(&source.storage, start_batch(&core, &prepared, false)?)?;
    authority.commit_maintenance_event(prepared, &receipt)?;
    assert_eq!(authority.cursor.next_sequence, 1);
    Ok(())
}

#[tokio::test]
async fn maintenance_refuses_wrong_transaction_storage_or_state_receipts() -> TestResult {
    let fixture = Fixture::new();
    for field in 0..3 {
        let core = core(&[])?;
        let mut authority = fixture.authority(&core)?;
        let prepared = prepare(&core, &authority, 90)?;
        let source = core.audit_source()?;
        let mut receipt = commit(&source.storage, start_batch(&core, &prepared, false)?)?;
        match field {
            0 => receipt.transaction_id = TransactionId::from_bytes([91; 16]),
            1 => receipt.storage_commit_sequence += 1,
            _ => receipt.state_generation += 1,
        }
        assert!(
            authority
                .commit_maintenance_event(prepared, &receipt)
                .is_err()
        );
        assert_eq!(authority.cursor, AuditChainCursor::genesis());
        assert!(!authority.is_reconciled());
        assert!(prepare(&core, &authority, 92).is_err());
        assert_eq!(fixture.authority(&core)?.cursor.next_sequence, 1);
    }
    Ok(())
}

#[tokio::test]
async fn another_prepared_owner_cannot_reuse_an_already_advanced_cursor() -> TestResult {
    let fixture = Fixture::new();
    let core = core(&[])?;
    let mut authority = fixture.authority(&core)?;
    let first = prepare(&core, &authority, 90)?;
    let second = prepare(&core, &authority, 91)?;
    let receipt = commit(
        &core.audit_source()?.storage,
        start_batch(&core, &first, false)?,
    )?;
    authority.commit_maintenance_event(first, &receipt)?;
    let expected = authority.cursor;
    let replay = CommitReceipt {
        transaction_id: second.mutation_head().transaction_id,
        ..receipt
    };
    assert!(authority.commit_maintenance_event(second, &replay).is_err());
    assert_eq!(authority.cursor, expected);
    assert!(!authority.is_reconciled());
    Ok(())
}

#[tokio::test]
async fn maintenance_preparation_requires_current_scope_clock_and_reconciled_intent() -> TestResult
{
    let fixture = Fixture::new();
    let core = core(&[])?;
    let authority = fixture.authority(&core)?;
    let source = core.audit_source()?;
    let scope = source.scope;
    let wrong = MaintenanceAuditScope::new(
        scope.network_id(),
        scope.server_id(),
        DatabaseId::from_bytes([99; 16]),
        scope.server_incarnation(),
        scope.recovery_epoch(),
    );
    for (scope, time) in [(scope, 0), (scope, 100), (wrong, 60)] {
        assert!(
            authority
                .prepare_maintenance_event(
                    scope,
                    start_transition(&core)?,
                    source.head,
                    TransactionId::from_bytes([90; 16]),
                    time
                )
                .is_err()
        );
    }
    let intent = fixture.admin(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Intent,
        b"REHASH reload",
    )?;
    let waiting = super::core(&[intent])?;
    let unreconciled = fixture.authority(&waiting)?;
    assert!(!unreconciled.is_reconciled());
    assert!(prepare(&waiting, &unreconciled, 90).is_err());
    Ok(())
}
