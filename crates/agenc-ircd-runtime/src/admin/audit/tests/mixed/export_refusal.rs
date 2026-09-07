//! An unsupported selected body cannot hide later invalid source evidence.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;

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

fn cursor(events: &[AuditEvent]) -> TestResult<AuditChainCursor> {
    Ok(events
        .iter()
        .try_fold(AuditChainCursor::genesis(), |cursor, event| {
            cursor.advance_event(event)
        })?)
}

#[tokio::test]
async fn unsupported_legacy_profile_cannot_hide_a_later_invalid_signature() -> TestResult {
    let fixture = Fixture::new();
    let mut events = fixture.chain()?;
    let expected = cursor(&events)?;
    let last = events.last_mut().ok_or("last audit event")?;
    let mut bytes = last.encode()?;
    *bytes.last_mut().ok_or("last signature byte")? ^= 1;
    *last = AuditEvent::decode_exact(&bytes)?;
    let core = core(&events)?;
    let result =
        source(&fixture, &core)?.freeze(AuditRange::new(1, 1)?, [7; 16], expected, 0, [0; 32]);
    assert!(matches!(
        result,
        Err(AuditExportFailure::Source(RuntimeError::InvalidValue))
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_legacy_profile_cannot_hide_a_later_unmatched_intent() -> TestResult {
    let fixture = Fixture::new();
    let mut events = fixture.chain()?;
    events.pop().ok_or("last observed audit event")?;
    events.push(fixture.admin(cursor(&events)?, AdminAuditPhase::Intent, b"REHASH reload")?);
    let expected = cursor(&events)?;
    let core = core(&events)?;
    let result =
        source(&fixture, &core)?.freeze(AuditRange::new(1, 1)?, [7; 16], expected, 0, [0; 32]);
    assert!(matches!(
        result,
        Err(AuditExportFailure::Source(RuntimeError::InvalidValue))
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_legacy_profile_still_checks_the_complete_captured_cursor() -> TestResult {
    let fixture = Fixture::new();
    let core = core(&fixture.chain()?)?;
    let mut job = fixture
        .authority(&core)?
        .prepare_export(AuditRange::new(1, 1)?, [7; 16])?;
    job.expected_cursor.next_sequence = job
        .expected_cursor
        .next_sequence
        .checked_add(1)
        .ok_or("cursor overflow")?;
    assert!(matches!(
        job.run(),
        Err(AuditExportFailure::Source(RuntimeError::InvalidValue))
    ));
    Ok(())
}
