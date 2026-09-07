//! Authenticated envelopes do not substitute for body, key, or signature checks.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;

#[tokio::test]
async fn sealed_mixed_records_bind_body_kind_sequence_key_and_revision() -> TestResult {
    let fixture = Fixture::new();
    let event = fixture.maintenance(AuditChainCursor::genesis(), 50, fixture.scope())?;
    for (kind, sequence, revision) in [(1, 0, 1), (2, 1, 2), (2, 0, 2)] {
        let core = StateCoreFixture::with_registration_router_and_records(
            vec![7; 65_536],
            vec![record(&event, kind, sequence, revision)?],
        )?;
        assert!(fixture.authority(&core).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn sealed_maintenance_requires_the_historical_key_and_strict_signature() -> TestResult {
    let fixture = Fixture::new();
    let different_key = Fixture {
        audit: Ed25519SecretKey::from_bytes([9; 32]),
        ..Fixture::new()
    };
    let untrusted = different_key.maintenance(AuditChainCursor::genesis(), 50, fixture.scope())?;
    let valid = fixture.maintenance(AuditChainCursor::genesis(), 50, fixture.scope())?;
    let mut invalid = valid.encode()?;
    *invalid.last_mut().ok_or("signature byte")? ^= 1;
    for event in [untrusted, AuditEvent::decode_exact(&invalid)?] {
        let core = core(&[event])?;
        assert!(fixture.authority(&core).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn maintenance_cannot_change_shared_chain_hash_or_skip_a_sequence() -> TestResult {
    let fixture = Fixture::new();
    let first = fixture.admin(
        AuditChainCursor::genesis(),
        AdminAuditPhase::Observed,
        b"MOTD",
    )?;
    let exact = AuditChainCursor::genesis().advance_event(&first)?;
    for cursor in [
        AuditChainCursor {
            previous_event_hash: [99; 32],
            ..exact
        },
        AuditChainCursor {
            next_sequence: 2,
            ..exact
        },
    ] {
        let event = fixture.maintenance(cursor, 50, fixture.scope())?;
        let core = core(&[first.clone(), event])?;
        assert!(fixture.authority(&core).is_err());
    }
    Ok(())
}
