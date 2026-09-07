//! Original signed legacy bytes are validated before migration can publish output.
#![cfg(test)]
#![forbid(unsafe_code)]

use agenc_ircd_admin::{AdminCommandTbs, AdminSessionId, OperatorRecord};
use agenc_ircd_types::{AdminPermission, AdminPermissionSet, NetworkId, ServerId};

use super::*;

type TestResult = crate::test_support::TestResult;

struct Fixture {
    audit: Ed25519SecretKey,
    operator: Ed25519SecretKey,
    operator_id: OperatorId,
    binding: AdminSessionBinding,
}

impl Fixture {
    fn new() -> Self {
        Self {
            audit: Ed25519SecretKey::from_bytes([4; 32]),
            operator: Ed25519SecretKey::from_bytes([5; 32]),
            operator_id: OperatorId::from_bytes([6; 16]),
            binding: AdminSessionBinding {
                network_id: NetworkId::from_bytes([1; 32]),
                server_id: ServerId::from_bytes([2; 16]),
            },
        }
    }

    fn validator(&self) -> Result<LegacyAuditSourceValidator, Box<dyn std::error::Error>> {
        let public = self.audit.public_key();
        let trust = AuditTrustManifestEntry {
            key_id: *audit_signing_key_id(public.as_bytes())?.as_bytes(),
            ed25519_public_key: *public.as_bytes(),
            not_before: 1,
            not_after: 100,
        };
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        let operator = OperatorRecord::new(
            self.operator_id,
            self.operator.public_key(),
            None,
            vec![1_000],
            Vec::new(),
            permissions,
            false,
        )?;
        Ok(LegacyAuditSourceValidator::new(
            self.binding,
            &[trust],
            OperatorRegistry::from_records(vec![operator])?,
        )?)
    }

    fn event(
        &self,
        cursor: AuditChainCursor,
        phase: AdminAuditPhase,
        command: &[u8],
    ) -> Result<AdminAuditEvent, Box<dyn std::error::Error>> {
        let command_tbs = AdminCommandTbs::new(
            self.binding.network_id,
            self.binding.server_id,
            AdminSessionId::from_bytes([3; 16]),
            0,
            None,
            command,
        )?;
        let operator_signature = command_tbs.sign(&self.operator)?;
        Ok(AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: self.binding.network_id,
                server_id: self.binding.server_id,
                audit_signing_key_id: *audit_signing_key_id(self.audit.public_key().as_bytes())?
                    .as_bytes(),
                audit_sequence: cursor.next_sequence,
                created_at: 50,
                operator_id: self.operator_id,
                command_tbs,
                operator_signature,
                phase,
                previous_event_hash: cursor.previous_event_hash,
            },
            &self.audit,
        )?)
    }

    fn checkpoint(
        &self,
        cursor: AuditChainCursor,
    ) -> Result<AdminAuditCheckpoint, Box<dyn std::error::Error>> {
        Ok(AdminAuditCheckpoint::sign(
            AdminAuditCheckpointTbs {
                network_id: self.binding.network_id,
                server_id: self.binding.server_id,
                audit_signing_key_id: *audit_signing_key_id(self.audit.public_key().as_bytes())?
                    .as_bytes(),
                checkpoint_sequence: 0,
                created_at: 50,
                deleted_first_sequence: 0,
                deleted_last_sequence: cursor.next_sequence - 1,
                deleted_count: cursor.next_sequence,
                deleted_last_event_hash: cursor.previous_event_hash,
                next_retained_sequence: cursor.next_sequence,
                previous_checkpoint_hash: [0; 32],
            },
            &self.audit,
        )?)
    }
}

fn observe_event(
    scan: &mut SourceAuditScan,
    context: &LegacyAuditSourceValidator,
    event: &AdminAuditEvent,
) -> TestResult {
    let sequence = event.tbs().audit_sequence;
    scan.observe(
        context,
        TableId::Audit,
        &StoredKey::new(sequence.to_be_bytes().to_vec())?,
        &PersistentRecordValue::new(
            TableId::Audit,
            1,
            sequence + 1,
            0,
            None,
            Vec::new(),
            event.encode()?,
        )?,
    )?;
    Ok(())
}

#[test]
fn retained_signed_events_require_the_later_checkpoint_anchor() -> TestResult {
    let fixture = Fixture::new();
    let context = fixture.validator()?;
    let anchor = AuditChainCursor {
        next_sequence: 5,
        previous_event_hash: [8; 32],
    };
    let first = fixture.event(anchor, AdminAuditPhase::Observed, b"MOTD")?;
    let original = first.encode()?;
    let second = fixture.event(anchor.advance(&first)?, AdminAuditPhase::Observed, b"TIME")?;
    let checkpoint = fixture.checkpoint(anchor)?;
    let mut scan = SourceAuditScan::new(&context);
    observe_event(&mut scan, &context, &first)?;
    observe_event(&mut scan, &context, &second)?;
    scan.checkpoint(&context, 0, &checkpoint.encode()?)?;
    scan.finish()?;
    assert_eq!(first.encode()?, original);
    Ok(())
}

#[test]
fn missing_or_different_signed_retention_anchors_refuse_source_completion() -> TestResult {
    let fixture = Fixture::new();
    let context = fixture.validator()?;
    let anchor = AuditChainCursor {
        next_sequence: 5,
        previous_event_hash: [8; 32],
    };
    let event = fixture.event(anchor, AdminAuditPhase::Observed, b"MOTD")?;
    for checkpoint in [
        None,
        Some(fixture.checkpoint(AuditChainCursor {
            previous_event_hash: [9; 32],
            ..anchor
        })?),
    ] {
        let mut scan = SourceAuditScan::new(&context);
        observe_event(&mut scan, &context, &event)?;
        if let Some(checkpoint) = checkpoint {
            scan.checkpoint(&context, 0, &checkpoint.encode()?)?;
        }
        assert!(scan.finish().is_err());
    }
    Ok(())
}

#[test]
fn signed_new_command_meanings_and_new_outer_encodings_are_not_legacy() -> TestResult {
    let fixture = Fixture::new();
    let context = fixture.validator()?;
    let event = fixture.event(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Observed,
        b"AUDIT EXPORT 0 0 maintenance-v1",
    )?;
    let mut scan = SourceAuditScan::new(&context);
    assert!(observe_event(&mut scan, &context, &event).is_err());
    let legacy = fixture.event(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Observed,
        b"MOTD",
    )?;
    let mut new_encoding = legacy.encode()?;
    *new_encoding.get_mut(1).ok_or(RuntimeError::InvalidValue)? = 2;
    let mut scan = SourceAuditScan::new(&context);
    assert!(scan.event(&context, 0, &new_encoding).is_err());
    Ok(())
}

#[test]
fn unsigned_changes_and_sequence_substitution_refuse_the_same_legacy_event() -> TestResult {
    let fixture = Fixture::new();
    let context = fixture.validator()?;
    let event = fixture.event(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Observed,
        b"MOTD",
    )?;
    let mut corrupt = event.encode()?;
    *corrupt.last_mut().ok_or(RuntimeError::InvalidValue)? ^= 1;
    let mut scan = SourceAuditScan::new(&context);
    assert!(scan.event(&context, 0, &corrupt).is_err());
    let mut scan = SourceAuditScan::new(&context);
    assert!(scan.event(&context, 1, &event.encode()?).is_err());
    let mut scan = SourceAuditScan::new(&context);
    observe_event(&mut scan, &context, &event)?;
    assert!(observe_event(&mut scan, &context, &event).is_err());
    Ok(())
}

#[test]
fn stopped_source_admission_requires_external_action_outcomes() -> TestResult {
    let fixture = Fixture::new();
    let context = fixture.validator()?;
    let intent = fixture.event(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Intent,
        b"REHASH :reconcile before migration",
    )?;
    let mut scan = SourceAuditScan::new(&context);
    observe_event(&mut scan, &context, &intent)?;
    assert!(scan.finish().is_err());
    let outcome = fixture.event(
        AuditChainCursor::genesis().advance(&intent)?,
        AdminAuditPhase::OutcomeSuccess,
        b"REHASH :reconcile before migration",
    )?;
    let mut scan = SourceAuditScan::new(&context);
    observe_event(&mut scan, &context, &intent)?;
    observe_event(&mut scan, &context, &outcome)?;
    scan.finish()?;
    Ok(())
}
