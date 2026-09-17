#![forbid(unsafe_code)]

//! COV-01: the audit-authority reconciliation fences and the two export
//! coverage refusals the Stage 10 branch report recorded as never taken.
//!
//! Each case drives the owning `AuditAuthority` or `PreparedAuditExport`
//! boundary and pairs the refusal with the accepted form that differs in one
//! fact, so the refusal is proved to rest on that fact alone.

use super::*;

/// An authority that has not reconciled its persisted chain refuses to prepare
/// a retention job and refuses to sign a retention checkpoint, and refusing
/// leaves the chain position and the checkpoint position exactly as they were.
#[test]
fn an_unreconciled_authority_refuses_both_retention_steps() -> Result<(), RuntimeError> {
    let binding = binding();
    let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
    let operator_id = OperatorId::from_bytes([6; 16]);
    let command = command_event(binding, &operator_key, 0, b"MOTD")?;
    let mut authority = AuditAuthority::empty_for_test()?;
    authority.signing_not_before = 10;
    authority.signing_not_after = 100;
    let event = authority.prepare_event(
        binding,
        operator_id,
        &command,
        AdminAuditPhase::Observed,
        CREATED_AT,
    )?;
    authority.commit_event(&event)?;
    let tbs = AdminAuditCheckpointTbs {
        network_id: binding.network_id,
        server_id: binding.server_id,
        audit_signing_key_id: authority.signing_key_id,
        checkpoint_sequence: 0,
        created_at: CREATED_AT,
        deleted_first_sequence: 0,
        deleted_last_sequence: 0,
        deleted_count: 1,
        deleted_last_event_hash: event.event_hash(),
        next_retained_sequence: 1,
        previous_checkpoint_hash: [0; 32],
    };
    assert!(authority.is_reconciled());
    // The same checkpoint signs while the authority is reconciled.
    authority.sign_retention(tbs)?;

    authority.reconciled = false;
    assert!(!authority.is_reconciled());
    assert!(authority.prepare_retention(CREATED_AT, 1).is_err());
    assert!(authority.sign_retention(tbs).is_err());
    // Refusing never advanced the chain or the checkpoint position.
    assert_eq!(authority.cursor.next_sequence, 1);
    assert_eq!(authority.next_checkpoint_sequence, 0);
    assert_eq!(authority.retained_first_sequence, 0);
    Ok(())
}

/// A frozen export is released only by its own `Observed` event: an event that
/// records any other phase is refused before the batch is rendered.
#[test]
fn a_frozen_export_refuses_an_event_in_another_phase() -> Result<(), RuntimeError> {
    let binding = binding();
    let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
    let operator_key = Ed25519SecretKey::from_bytes([5; 32]);
    let operator_id = OperatorId::from_bytes([6; 16]);
    let fixture = EventFixture {
        binding,
        audit_key: &audit_key,
        operator_key: &operator_key,
        operator_id,
    };
    let range = AuditRange::new(0, 0).map_err(|_| RuntimeError::InvalidValue)?;
    let prepared = |trust, operators| PreparedAuditExport {
        binding,
        trust,
        operators,
        range,
        batch_id: [0; 16],
        expected_cursor: AuditChainCursor::genesis(),
        selection: ExportSelection::new(range),
    };

    for phase in [
        AdminAuditPhase::OutcomeSuccess,
        AdminAuditPhase::OutcomeFailure,
        AdminAuditPhase::CommittedMutation,
        AdminAuditPhase::Intent,
    ] {
        let event = fixture.event(AuditChainCursor::genesis(), 0, phase, b"AUDIT EXPORT 0 0")?;
        let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
        let operators = registry(operator_id, &operator_key)?;
        assert!(
            prepared(trust, operators)
                .finish_with_observed(&event)
                .is_err()
        );
    }

    // The same command in the `Observed` phase releases the batch.
    let observed = fixture.event(
        AuditChainCursor::genesis(),
        0,
        AdminAuditPhase::Observed,
        b"AUDIT EXPORT 0 0",
    )?;
    let trust = AuditTrust::new(&[trust_entry(&audit_key)?])?;
    let operators = registry(operator_id, &operator_key)?;
    let lines = prepared(trust, operators).finish_with_observed(&observed)?;
    assert_eq!(lines.len(), 3);
    Ok(())
}

/// A range that begins after the last assigned sequence must carry no records
/// at all: a checkpoint or event offered for a range the chain never reached is
/// refused rather than exported.
#[test]
fn an_export_range_beyond_the_chain_must_carry_no_records() -> Result<(), RuntimeError> {
    let binding = binding();
    let audit_key = Ed25519SecretKey::from_bytes([4; 32]);
    let entry = trust_entry(&audit_key)?;
    let checkpoint = AdminAuditCheckpoint::sign(
        AdminAuditCheckpointTbs {
            network_id: binding.network_id,
            server_id: binding.server_id,
            audit_signing_key_id: entry.key_id,
            checkpoint_sequence: 0,
            created_at: CREATED_AT,
            deleted_first_sequence: 0,
            deleted_last_sequence: 4,
            deleted_count: 5,
            deleted_last_event_hash: [8; 32],
            next_retained_sequence: 5,
            previous_checkpoint_hash: [0; 32],
        },
        &audit_key,
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    let beyond = AuditRange::new(6, 8).map_err(|_| RuntimeError::InvalidValue)?;

    // Nothing was assigned at or after sequence six, so an empty batch is the
    // only correct answer and any record is refused.
    verify_export_coverage(beyond, 6, &[], &[])?;
    assert!(verify_export_coverage(beyond, 6, &[checkpoint], &[]).is_err());
    Ok(())
}

/// Only the two audit body encodings in the audit table and the single
/// checkpoint encoding in the checkpoint table may be read back: every other
/// table and record-kind pair is refused, so a row of another kind can never
/// enter the verified chain.
#[test]
fn only_the_assigned_table_and_record_kind_pairs_are_readable() {
    for (table, kind) in [
        (TableId::Audit, 1_u16),
        (TableId::Audit, 2),
        (TableId::AuditCheckpoint, 1),
    ] {
        assert!(mixed::permitted_kind(table, kind), "{table:?}/{kind}");
    }
    for (table, kind) in [
        (TableId::Audit, 0_u16),
        (TableId::Audit, 3),
        (TableId::Audit, u16::MAX),
        (TableId::AuditCheckpoint, 0),
        (TableId::AuditCheckpoint, 2),
        (TableId::AuthTransaction, 1),
        (TableId::Account, 1),
    ] {
        assert!(!mixed::permitted_kind(table, kind), "{table:?}/{kind}");
    }
}
