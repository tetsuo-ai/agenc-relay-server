//! Audit export has exact grammar, event labels, and complete trust checks.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_admin::{AdminError, render_export_batch};

#[test]
fn audit_export_has_exact_grammar_and_audit_permission() -> TestResult {
    let bytes = b"AUDIT EXPORT 0 3";
    let command = AdminCommand::parse(CanonicalCommand::check(bytes)?)?;
    assert!(command == AdminCommand::AuditExport(AuditRange::new(0, 3)?));
    assert_eq!(command.required_permission(), Some(AdminPermission::Audit));
    assert_eq!(command.verb(), "AUDIT");
    assert!(command.is_read_only());
    assert!(!command.needs_confirmation());
    for bytes in [
        b"AUDIT EXPORT 0 3 MAINTENANCE-V1".as_slice(),
        b"AUDIT EXPORT 0 3 maintenance-v1",
        b"AUDIT EXPORT 0 3 maintenance-v1 extra",
        b"AUDIT EXPORT 03 4 maintenance-v1",
        b"AUDIT EXPORT 4 3 maintenance-v1",
    ] {
        assert!(AdminCommand::parse(CanonicalCommand::check(bytes)?).is_err());
    }
    Ok(())
}

#[test]
fn mixed_renderer_checks_counts_order_and_complete_coverage() -> TestResult {
    let fixture = Fixture::new();
    let chain = fixture.chain()?;
    let range = AuditRange::new(0, 2)?;
    let complete = render_export_batch(&[7; 16], range, &[], &chain)?;
    assert_eq!(complete.len(), 5);
    assert!(
        complete
            .get(2)
            .ok_or("maintenance line")?
            .contains(" NOTE AUDIT MAINTENANCE ")
    );
    for events in [
        vec![
            chain.first().ok_or("first event")?.clone(),
            chain.get(2).ok_or("last event")?.clone(),
        ],
        vec![
            chain.first().ok_or("first event")?.clone(),
            chain.get(1).ok_or("maintenance event")?.clone(),
            chain.get(1).ok_or("maintenance event")?.clone(),
        ],
        vec![
            chain.get(1).ok_or("maintenance event")?.clone(),
            chain.first().ok_or("first event")?.clone(),
            chain.get(2).ok_or("last event")?.clone(),
        ],
    ] {
        assert!(render_export_batch(&[7; 16], range, &[], &events).is_err());
    }
    assert!(render_export_batch(&[7; 16], AuditRange::new(1, 2)?, &[], &chain).is_err());
    let empty = render_export_batch(&[7; 16], AuditRange::new(9, 10)?, &[], &[])?;
    assert_eq!(empty.len(), 2);
    assert!(empty.first().ok_or("empty batch")?.ends_with(" 9 10 0 0"));
    let excessive =
        vec![chain.get(1).ok_or("maintenance event")?.clone(); MAX_AUDIT_EXPORT_RECORDS + 1];
    assert_eq!(
        render_export_batch(&[7; 16], range, &[], &excessive),
        Err(AdminError::Limit)
    );
    Ok(())
}

#[test]
fn mixed_renderer_uses_original_checkpoint_bytes_for_a_deleted_prefix() -> TestResult {
    let fixture = Fixture::new();
    let chain = fixture.chain()?;
    let checkpoint = AdminAuditCheckpoint::sign(
        AdminAuditCheckpointTbs {
            network_id: fixture.scope().network_id(),
            server_id: fixture.scope().server_id(),
            audit_signing_key_id: fixture.trust()?.key_id,
            checkpoint_sequence: 0,
            created_at: 60,
            deleted_first_sequence: 0,
            deleted_last_sequence: 1,
            deleted_count: 2,
            deleted_last_event_hash: chain.get(1).ok_or("maintenance event")?.event_hash(),
            next_retained_sequence: 2,
            previous_checkpoint_hash: [0; 32],
        },
        &fixture.audit,
    )?;
    let id = agenc_ircd_admin::encode_base64url(&[7; 16]);
    let lines = render_export_batch(
        &[7; 16],
        AuditRange::new(0, 2)?,
        &[checkpoint],
        chain.get(2..).ok_or("retained tail")?,
    )?;
    assert_eq!(lines.len(), 4);
    assert!(lines.first().ok_or("batch start")?.ends_with(" 0 2 1 1"));
    assert_eq!(
        lines.get(1).ok_or("checkpoint line")?.as_str(),
        format!(
            "@batch={id} NOTE AUDIT CHECKPOINT {} :Audit checkpoint",
            agenc_ircd_admin::encode_base64url(&checkpoint.encode()?)
        )
    );
    assert!(render_export_batch(&[7; 16], AuditRange::new(0, 2)?, &[checkpoint], &chain).is_err());
    Ok(())
}

fn source(fixture: &Fixture, core: &StateCoreFixture) -> TestResult<AuditExportSource> {
    let recovered = core.audit_source()?;
    Ok(AuditExportSource {
        binding: AdminSessionBinding {
            network_id: fixture.scope().network_id(),
            server_id: fixture.scope().server_id(),
        },
        storage: recovered.storage,
        keys: recovered.keys,
        trust: AuditTrust::new(&[fixture.trust()?])?,
        operators: fixture.operators()?,
    })
}

#[tokio::test]
async fn audit_export_revalidates_unselected_tail_and_captured_cursor() -> TestResult {
    let fixture = Fixture::new();
    for invalid_tail in [true, false] {
        let mut chain = fixture.chain()?;
        let mut cursor = chain
            .iter()
            .try_fold(AuditChainCursor::genesis(), |cursor, event| {
                cursor.advance_event(event)
            })?;
        if invalid_tail {
            let last = chain.last_mut().ok_or("tail")?;
            let mut bytes = last.encode()?;
            *bytes.last_mut().ok_or("signature")? ^= 1;
            *last = AuditEvent::decode_exact(&bytes)?;
        } else {
            cursor.next_sequence += 1;
        }
        let core = core(&chain)?;
        assert!(matches!(
            source(&fixture, &core)?.freeze(AuditRange::new(1, 1)?, [7; 16], cursor, 0, [0; 32]),
            Err(RuntimeError::InvalidValue)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn observed_export_event_must_match_the_requested_range() -> TestResult {
    let fixture = Fixture::new();
    let core = core(&fixture.chain()?)?;
    let authority = fixture.authority(&core)?;
    for command in [b"AUDIT EXPORT 1 3".as_slice(), b"AUDIT EXPORT 0 4"] {
        let frozen = authority
            .prepare_export(AuditRange::new(0, 3)?, [7; 16])?
            .run()?;
        let AuditEvent::Admin(observed) =
            fixture.admin(authority.cursor, AdminAuditPhase::Observed, command)?
        else {
            return Err("observed admin event".into());
        };
        assert!(frozen.finish_with_observed(&observed).is_err());
    }
    Ok(())
}
