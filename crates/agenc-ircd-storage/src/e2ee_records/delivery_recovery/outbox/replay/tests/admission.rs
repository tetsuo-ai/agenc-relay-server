//! Generic admission is versioned independently of every predecessor source.
#![forbid(unsafe_code)]

use super::*;
use crate::PersistentRecordValue;
use crate::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;

#[test]
fn replay_ledger_is_admitted_only_under_generation_four() -> TestResult {
    for row in [
        ReplayLedgerRow::Owner(ReplayOwner::new(owner()?)?),
        ReplayLedgerRow::Range(AckRange::new(range()?)?),
    ] {
        let key = row.key()?;
        let value = PersistentRecordValue::new(
            TableId::E2eeState,
            DELIVERY_RECOVERY_ROW_KIND,
            1,
            0,
            None,
            Vec::new(),
            row.encode()?,
        )?;
        let plaintext = value.encode()?;
        crate::migration::validate_source_record(4, TableId::E2eeState, &key, 1, &plaintext)?;
        for generation in [1, 2, 3, 5] {
            assert!(
                crate::migration::validate_source_record(
                    generation,
                    TableId::E2eeState,
                    &key,
                    1,
                    &plaintext,
                )
                .is_err(),
                "generation {generation}"
            );
        }
        assert!(
            crate::migration_v3::validate_source(TableId::E2eeState, &key, 1, &plaintext).is_err()
        );
    }
    Ok(())
}

#[test]
fn versioned_key_namespaces_cannot_be_exchanged() -> TestResult {
    use crate::e2ee_records::delivery_recovery::{fixture_body, validate_at, validate_body};
    let old_body = fixture_body(7)?;
    let old = DeliveryRecoveryRow::decode(&old_body)?;
    let new = ReplayLedgerRow::Owner(ReplayOwner::new(owner()?)?);
    validate_body(&old_body)?;
    validate_body(&new.encode()?)?;
    assert!(validate_at(&old.key()?, &new.encode()?).is_err());
    assert!(validate_at(&new.key()?, &old_body).is_err());
    Ok(())
}
