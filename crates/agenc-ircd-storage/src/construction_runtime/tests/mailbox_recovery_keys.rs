//! Declared recovery validates the exact mailbox row arm and key grammar.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee_records::{DeliveryGrant, MAILBOX_ROW_KIND, MailboxKind, MailboxRow};

fn rows() -> Result<[RecoveryRow; 3], StorageError> {
    let item = MailboxRow::Item {
        object_id: [31; 32],
        conversation_id: [0; 32],
        inserted_at: 10,
        expires_at: 200,
        grant: Some(DeliveryGrant {
            token: [32; 32],
            session_generation: 9,
            expires_at: 100,
        }),
    };
    let token = MailboxRow::Token {
        account_digest: [33; 32],
        device_id: [34; 16],
        kind: MailboxKind::Binding,
        sequence: 7,
        object_id: [31; 32],
        session_generation: 9,
        expires_at: 100,
    };
    let ack = MailboxRow::Ack {
        object_id: [35; 32],
        acknowledged_at: 20,
        retain_until: 200,
    };
    Ok([
        RecoveryRow {
            label: "cap80-restore-item-key",
            kind: MAILBOX_ROW_KIND,
            key: MailboxRow::item_key(&[33; 32], &[34; 16], MailboxKind::Binding, 7)?,
            body: item.encode()?,
        },
        RecoveryRow {
            label: "cap80-restore-token-key",
            kind: MAILBOX_ROW_KIND,
            key: MailboxRow::token_key(&[32; 32])?,
            body: token.encode()?,
        },
        RecoveryRow {
            label: "cap80-restore-ack-key",
            kind: MAILBOX_ROW_KIND,
            key: MailboxRow::ack_key(&[33; 32], &[34; 16], &[36; 32])?,
            body: ack.encode()?,
        },
    ])
}

#[test]
fn declared_recovery_preserves_each_valid_mailbox_row_exactly() -> Result<(), StorageError> {
    for row in rows()? {
        let restored = recover_selected(&row)?;
        assert_eq!(restored.body(), row.body);
        assert_eq!((restored.revision(), restored.generation()), (17, 4));
    }
    Ok(())
}

#[test]
fn declared_recovery_refuses_mailbox_keys_with_missing_or_extra_suffix_bytes()
-> Result<(), StorageError> {
    for row in rows()? {
        for change in [-1, 1] {
            let mut bytes = row.key.as_bytes().to_vec();
            if change < 0 {
                bytes.pop().ok_or(StorageError::InvalidEncoding)?;
            } else {
                bytes.push(0);
            }
            let malformed = RecoveryRow {
                key: StoredKey::new(bytes)?,
                body: row.body.clone(),
                ..row
            };
            assert_recovery_binding_refused(&malformed)?;
        }
    }
    Ok(())
}

#[test]
fn declared_recovery_refuses_mailbox_bodies_under_another_arm_key() -> Result<(), StorageError> {
    let values = rows()?;
    for index in 0..values.len() {
        let row = values.get(index).ok_or(StorageError::InvalidEncoding)?;
        let other = values
            .get((index + 1) % values.len())
            .ok_or(StorageError::InvalidEncoding)?;
        assert_recovery_binding_refused(&RecoveryRow {
            label: row.label,
            kind: row.kind,
            key: other.key.clone(),
            body: row.body.clone(),
        })?;
    }
    Ok(())
}
