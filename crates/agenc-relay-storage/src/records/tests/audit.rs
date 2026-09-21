#![forbid(unsafe_code)]

use super::*;

const SIGNED_START: &[u8] =
    include_bytes!("../../../../../test-data/stage-ten/maintenance-audit-start-v1.bin");

#[test]
fn maintenance_audit_records_require_the_current_schema() -> Result<(), StorageError> {
    let sequence = u64::from_be_bytes(
        SIGNED_START
            .get(84..92)
            .ok_or(StorageError::InvalidEncoding)?
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?,
    );
    let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
    let value = PersistentRecordValue::new(
        TableId::Audit,
        2,
        sequence.checked_add(1).ok_or(StorageError::Overflow)?,
        0,
        None,
        Vec::new(),
        SIGNED_START.to_vec(),
    )?;
    let plaintext = value.encode()?;
    assert_eq!(
        PersistentRecordValue::decode(TableId::Audit, &plaintext)?.body(),
        SIGNED_START
    );
    crate::AuthenticatedSourceRecord::checked(
        crate::SCHEMA_GENERATION,
        TableId::Audit,
        &key,
        1,
        &plaintext,
    )?;
    for generation in [0, 1, 2, 3, 4, 6] {
        assert_eq!(
            crate::AuthenticatedSourceRecord::checked(
                generation,
                TableId::Audit,
                &key,
                1,
                &plaintext
            )
            .map(|_| ()),
            Err(StorageError::UnsupportedVersion)
        );
    }
    Ok(())
}

#[test]
fn audit_kind_registration_keeps_checkpoints_and_unknown_arms_closed() {
    assert!(record_kind_is_valid(TableId::Audit, 1));
    assert!(!record_kind_is_valid(TableId::Audit, 0));
    assert!(!record_kind_is_valid(TableId::Audit, 3));
    assert!(record_kind_is_valid(TableId::AuditCheckpoint, 1));
    assert!(!record_kind_is_valid(TableId::AuditCheckpoint, 2));
}
