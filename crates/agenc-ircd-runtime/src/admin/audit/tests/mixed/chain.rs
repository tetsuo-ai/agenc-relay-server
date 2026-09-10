//! Startup and retention share one sealed mixed chain.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::state_core::durable::{
    AccountingCeilings, DurableIndex, project_admin_audit_retention, read_back_record,
};
use agenc_ircd_types::TransactionId;

#[tokio::test]
async fn startup_audit_index_allows_retention_without_manual_row_insertion() -> TestResult {
    let fixture = Fixture::new();
    let events = fixture.chain()?;
    let mut core = core(&events)?;
    let mut authority = fixture.authority(&core)?;
    let tbs = authority
        .prepare_retention(80, 20)?
        .run()?
        .ok_or("expired prefix")?;
    let checkpoint = authority.sign_retention(tbs)?;
    let checkpoint_key =
        StoredKey::new(checkpoint.tbs().checkpoint_sequence.to_be_bytes().to_vec())?;
    let checkpoint_value = PersistentRecordValue::new(
        TableId::AuditCheckpoint,
        agenc_ircd_storage::LIVE_RECORD_KIND,
        checkpoint
            .tbs()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or("checkpoint revision")?,
        0,
        None,
        Vec::new(),
        checkpoint.encode()?,
    )?;
    let source = core.audit_source()?;
    let projected = project_admin_audit_retention(
        TransactionId::from_bytes([92; 16]),
        &checkpoint,
        core.context_mut()?.index(),
        &source.keys,
        source.head,
        AccountingCeilings {
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 2_147_483_648,
        },
    )?;
    let receipt = commit(&source.storage, projected.into_parts().0)?;
    assert_eq!(receipt.state_generation, source.head.state_generation);
    authority.commit_retention(&checkpoint)?;
    drop(source);
    core.audit_reopen()?;
    let restored = fixture.authority(&core)?;
    assert_eq!(restored.retained_first_sequence, 3);
    assert_eq!(restored.next_checkpoint_sequence, 1);
    // A subsequent startup also indexes the retained checkpoint so later
    // projection uses its exact authenticated before-image.
    let mut checkpoint_core = StateCoreFixture::with_registration_router_and_records(
        vec![7; 65_536],
        vec![InitialStorageRecord::new(
            TableId::AuditCheckpoint,
            checkpoint_key.clone(),
            DOMAIN_RECORD_SCHEMA,
            checkpoint_value.encode()?,
        )?],
    )?;
    assert!(
        checkpoint_core
            .context_mut()?
            .index()
            .existing(TableId::AuditCheckpoint, &checkpoint_key,)?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn sealed_mixed_chain_reconstructs_twice_without_rewriting_historical_scope() -> TestResult {
    let fixture = Fixture::new();
    let events = fixture.chain()?;
    let mut core = core(&events)?;
    let expected = events
        .iter()
        .try_fold(AuditChainCursor::genesis(), |cursor, event| {
            cursor.advance_event(event)
        })?;
    for _ in 0..2 {
        core.audit_reopen()?;
        let authority = fixture.authority(&core)?;
        assert!(authority.is_reconciled());
        assert_eq!(authority.cursor, expected);
        let (suspensions, quarantines) = authority.policy_seed().into_parts();
        assert!(suspensions.is_empty() && quarantines.is_empty());
        let source = core.audit_source()?;
        let mut retained = Vec::new();
        scan_events(&source.storage, &source.keys, |event| {
            retained.push(event);
            Ok(())
        })?;
        assert_eq!(retained, events);
    }
    Ok(())
}

#[tokio::test]
async fn mixed_retention_commits_exact_deletions_and_unchanged_checkpoint_bytes() -> TestResult {
    let fixture = Fixture::new();
    let events = fixture.chain()?;
    let mut core = core(&events)?;
    let mut authority = fixture.authority(&core)?;
    let tbs = authority
        .prepare_retention(80, 20)?
        .run()?
        .ok_or("expired prefix")?;
    assert_eq!(
        (
            tbs.deleted_first_sequence,
            tbs.deleted_last_sequence,
            tbs.deleted_count
        ),
        (0, 2, 3)
    );
    assert_eq!(
        tbs.deleted_last_event_hash,
        events.last().ok_or("last event")?.event_hash()
    );
    let checkpoint = authority.sign_retention(tbs)?;
    let checkpoint_bytes = checkpoint.encode()?;
    assert_eq!(
        AdminAuditCheckpoint::decode_exact(&checkpoint_bytes)?,
        checkpoint
    );
    let source = core.audit_source()?;
    let mut index = DurableIndex::new();
    for sequence in 0_u64..3 {
        let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
        let result = source
            .storage
            .try_read(ReadPlan::exact(TableId::Audit, key.clone()))?
            .wait()?;
        let (_, _, existing) = read_back_record(TableId::Audit, key.clone(), result)?;
        index.record_known(TableId::Audit, key, existing.ok_or("sealed event")?);
    }
    let projected = project_admin_audit_retention(
        TransactionId::from_bytes([91; 16]),
        &checkpoint,
        &index,
        &source.keys,
        source.head,
        AccountingCeilings {
            database_max_bytes: 1_073_741_824,
            backup_max_bytes: 2_147_483_648,
        },
    )?;
    let expected_cursor = authority.cursor;
    let receipt = commit(&source.storage, projected.into_parts().0)?;
    assert_eq!(receipt.state_generation, source.head.state_generation);
    authority.commit_retention(&checkpoint)?;
    drop(authority);
    drop(source);
    for _ in 0..2 {
        core.audit_reopen()?;
        let restored = fixture.authority(&core)?;
        assert_eq!(restored.cursor, expected_cursor);
        assert_eq!(restored.retained_first_sequence, 3);
        assert_eq!(restored.next_checkpoint_sequence, 1);
        let read = core.audit_source()?;
        let mut retained = Vec::new();
        scan_checkpoints(&read.storage, &read.keys, |value| {
            retained.push(value.encode().map_err(|_| RuntimeError::InvalidValue)?);
            Ok(())
        })?;
        assert_eq!(retained, vec![checkpoint_bytes.clone()]);
        scan_events(&read.storage, &read.keys, |_| {
            Err(RuntimeError::InvalidValue)
        })?;
        assert!(
            restored
                .prepare_export(AuditRange::new(0, 2)?, [8; 16])?
                .run()
                .is_ok()
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_maintenance_event_cannot_cross_an_unmatched_operator_intent() -> TestResult {
    let fixture = Fixture::new();
    let intent = fixture.admin(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Intent,
        b"REHASH reload",
    )?;
    let clean = core(core::slice::from_ref(&intent))?;
    assert!(!fixture.authority(&clean)?.is_reconciled());
    drop(clean);
    let cursor = AuditChainCursor::genesis().advance_event(&intent)?;
    let maintenance = fixture.maintenance(cursor, 51, fixture.scope())?;
    let core = core(&[intent, maintenance])?;
    assert!(fixture.authority(&core).is_err());
    Ok(())
}

#[tokio::test]
async fn sealed_maintenance_rejects_untrusted_time_and_wrong_network() -> TestResult {
    let fixture = Fixture::new();
    let scope = fixture.scope();
    let wrong_network = MaintenanceAuditScope::new(
        NetworkId::from_bytes([90; 32]),
        scope.server_id(),
        scope.database_instance_id(),
        scope.server_incarnation(),
        scope.recovery_epoch(),
    );
    for (scope, created_at) in [(scope, 0), (scope, 100), (wrong_network, 50)] {
        let event = fixture.maintenance(AuditChainCursor::genesis(), created_at, scope)?;
        let core = core(&[event])?;
        assert!(fixture.authority(&core).is_err());
    }
    Ok(())
}

#[test]
fn mixed_decoder_binds_outer_kind_and_sequence_without_changing_old_bytes() -> TestResult {
    let fixture = Fixture::new();
    for event in fixture.chain()? {
        let bytes = event.encode()?;
        assert_eq!(AuditEvent::decode_exact(&bytes)?, event);
        assert_eq!(
            mixed::decode_event(event.audit_sequence(), event.encoding(), &bytes)?,
            event
        );
        for kind in [0, 1, 2, 3] {
            assert_eq!(
                mixed::decode_event(event.audit_sequence(), kind, &bytes).is_ok(),
                kind == event.encoding()
            );
        }
        assert!(mixed::decode_event(event.audit_sequence() + 1, event.encoding(), &bytes).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AuditEvent::decode_exact(&trailing).is_err());
    }
    Ok(())
}
