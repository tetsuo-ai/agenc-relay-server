//! The closed wrapper preserves both original body encodings exactly.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::{AdminAuditEventTbs, AdminAuditPhase, AdminCommandTbs, AdminSessionId};
use agenc_relay_crypto::{Ed25519SecretKey, audit_signing_key_id};
use agenc_relay_types::OperatorId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn closed_audit_decoder_keeps_the_independently_signed_maintenance_fixture_exact() -> TestResult {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-data/stage-ten/maintenance-audit-start-v1.bin"
    ));
    let event = AuditEvent::decode_exact(bytes)?;
    let AuditEvent::Maintenance(maintenance) = &event else {
        return Err("maintenance arm".into());
    };
    maintenance.verify(
        NetworkId::from_bytes([1; 32]),
        ServerId::from_bytes([2; 16]),
        Ed25519SecretKey::from_bytes([7; 32]).public_key(),
    )?;
    assert_eq!(event.encode()?, bytes);
    assert_eq!(event.encoding(), 2);
    assert!(AdminAuditEvent::decode_exact(bytes).is_err());
    let cursor = AuditChainCursor {
        next_sequence: event.audit_sequence(),
        previous_event_hash: event.previous_event_hash(),
    };
    let next = cursor.advance_event(&event)?;
    assert_eq!(next.next_sequence, event.audit_sequence() + 1);
    assert_eq!(next.previous_event_hash, event.event_hash());
    assert!(next.advance_event(&event).is_err());
    for size in 0..bytes.len() {
        assert!(AuditEvent::decode_exact(bytes.get(..size).ok_or("prefix")?).is_err());
    }
    for encoding in [0, 3, u16::MAX] {
        let mut changed = bytes.to_vec();
        changed
            .get_mut(..2)
            .ok_or("encoding")?
            .copy_from_slice(&encoding.to_be_bytes());
        assert!(AuditEvent::decode_exact(&changed).is_err());
    }
    Ok(())
}

#[test]
fn closed_audit_decoder_keeps_the_legacy_event_and_cursor_bytes_exact() -> TestResult {
    let audit = Ed25519SecretKey::from_bytes([4; 32]);
    let operator = Ed25519SecretKey::from_bytes([5; 32]);
    let network = NetworkId::from_bytes([1; 32]);
    let server = ServerId::from_bytes([2; 16]);
    let command = AdminCommandTbs::new(
        network,
        server,
        AdminSessionId::from_bytes([3; 16]),
        0,
        None,
        b"MOTD",
    )?;
    let signature = command.sign(&operator)?;
    let admin = AdminAuditEvent::sign(
        AdminAuditEventTbs {
            network_id: network,
            server_id: server,
            audit_signing_key_id: *audit_signing_key_id(audit.public_key().as_bytes())?.as_bytes(),
            audit_sequence: 0,
            created_at: 50,
            operator_id: OperatorId::from_bytes([6; 16]),
            command_tbs: command,
            operator_signature: signature,
            phase: AdminAuditPhase::Observed,
            previous_event_hash: [0; 32],
        },
        &audit,
    )?;
    let old = admin.encode()?;
    let event = AuditEvent::decode_exact(&old)?;
    assert_eq!(event.encode()?, old);
    assert_eq!(event.encoding(), 1);
    assert_eq!(event.network_id(), network);
    assert_eq!(event.server_id(), server);
    assert_eq!(
        event.audit_signing_key_id(),
        admin.tbs().audit_signing_key_id
    );
    assert_eq!(event.created_at(), 50);
    assert_eq!(
        AuditChainCursor::genesis().advance_event(&event)?,
        AuditChainCursor::genesis().advance(&admin)?
    );
    Ok(())
}
