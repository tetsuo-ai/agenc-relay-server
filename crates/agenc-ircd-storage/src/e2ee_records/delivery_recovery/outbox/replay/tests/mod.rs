//! Independent fixed bytes and refusal cases for the versioned replay ledger.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryRecoveryRow, DeliveryScopeFields,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scope() -> Result<DeliveryScope, StorageError> {
    DeliveryScope::new(DeliveryScopeFields {
        network_id: [1; 32],
        coordinator_server_id: [2; 16],
        coordinator_incarnation: [3; 16],
        coordinator_recovery_epoch: [4; 16],
        target_server_id: [5; 16],
        target_incarnation: [6; 16],
        covered_base_client_resync_epoch: 7,
    })
}

fn owner() -> Result<ReplayOwnerFields, StorageError> {
    Ok(ReplayOwnerFields {
        scope: scope()?,
        generation: 8,
        baseline: LastAcknowledged::BeforeFirst,
        through: 11,
        event_id: [0; 16],
        first_retained: 9,
        retained_rows: 3,
        retained_bytes: 768,
        trusted_unix_seconds: None,
    })
}

fn range() -> Result<AckRangeFields, StorageError> {
    Ok(AckRangeFields {
        scope: scope()?,
        generation: 8,
        first: 9,
        last: 11,
        event_id: [0; 16],
        acknowledgement: Acknowledgement::AcknowledgedTimeUnknown,
    })
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut bytes = Vec::new();
    for pair in compact.as_bytes().as_chunks::<2>().0 {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    if !compact.len().is_multiple_of(2) {
        return Err("odd golden hex length".into());
    }
    Ok(bytes)
}

#[test]
fn acknowledgement_range_matches_fixed_envelope_bytes() -> TestResult {
    let row = ReplayLedgerRow::Range(AckRange::new(range()?)?);
    let expected = hex("00010017000e0001000000a6 00020002
        0101010101010101010101010101010101010101010101010101010101010101
        02020202020202020202020202020202 03030303030303030303030303030303
        04040404040404040404040404040404 05050505050505050505050505050505
        06060606060606060606060606060606 0000000000000007 0000000000000008
        0000000000000009 000000000000000b 00000000000000000000000000000000 0001")?;
    assert_eq!(row.encode()?, expected);
    assert_eq!(ReplayLedgerRow::decode_at(&row.key()?, &expected)?, row);
    Ok(())
}

#[test]
fn owner_matches_fixed_envelope_bytes() -> TestResult {
    let row = ReplayLedgerRow::Owner(ReplayOwner::new(owner()?)?);
    let expected = hex("00010017000e0001000000b8 00020001
        0101010101010101010101010101010101010101010101010101010101010101
        02020202020202020202020202020202 03030303030303030303030303030303
        04040404040404040404040404040404 05050505050505050505050505050505
        06060606060606060606060606060606 0000000000000007 0000000000000008 0000
        000000000000000b 00000000000000000000000000000000
        0000000000000009 0000000000000003 0000000000000300 0000")?;
    assert_eq!(row.encode()?, expected);
    assert_eq!(ReplayLedgerRow::decode_at(&row.key()?, &expected)?, row);
    Ok(())
}

#[test]
fn full_clock_and_baseline_fields_round_trip_with_zero_event_identity() -> TestResult {
    let mut fields = owner()?;
    fields.baseline = LastAcknowledged::At {
        sequence: 8,
        event_id: [0; 16],
    };
    fields.trusted_unix_seconds = Some(0);
    let owner = ReplayLedgerRow::Owner(ReplayOwner::new(fields)?);
    assert_eq!(owner.encode()?.len(), MAX_BODY_BYTES + ENVELOPE_BYTES);
    assert_eq!(
        ReplayLedgerRow::decode_at(&owner.key()?, &owner.encode()?)?,
        owner
    );
    let mut fields = range()?;
    fields.acknowledgement = Acknowledgement::received_at(Some(0));
    let range = ReplayLedgerRow::Range(AckRange::new(fields)?);
    assert_eq!(
        ReplayLedgerRow::decode_at(&range.key()?, &range.encode()?)?,
        range
    );
    Ok(())
}

#[test]
fn wrong_keys_versions_arms_lengths_and_legacy_decoders_are_rejected() -> TestResult {
    for row in [
        ReplayLedgerRow::Owner(ReplayOwner::new(owner()?)?),
        ReplayLedgerRow::Range(AckRange::new(range()?)?),
    ] {
        let bytes = row.encode()?;
        assert!(DeliveryRecoveryRow::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(ReplayLedgerRow::decode(bytes.get(..end).ok_or("truncation")?).is_err());
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(ReplayLedgerRow::decode(&extended).is_err());
        for offset in [ENVELOPE_BYTES + 1, ENVELOPE_BYTES + 3] {
            let mut changed = bytes.clone();
            *changed.get_mut(offset).ok_or("tag offset")? = 255;
            assert!(ReplayLedgerRow::decode(&changed).is_err());
        }
        let mut key = row.key()?.as_bytes().to_vec();
        *key.last_mut().ok_or("key")? ^= 1;
        assert!(ReplayLedgerRow::decode_at(&StoredKey::new(key)?, &bytes).is_err());
        let mut key = row.key()?.as_bytes().to_vec();
        key.push(0);
        assert!(ReplayLedgerRow::decode_at(&StoredKey::new(key)?, &bytes).is_err());
    }
    Ok(())
}

#[test]
fn owner_rejects_impossible_suffix_totals_baselines_and_clock_overflow() -> TestResult {
    let valid = owner()?;
    for changed in [
        ReplayOwnerFields {
            first_retained: 13,
            ..valid
        },
        ReplayOwnerFields {
            retained_rows: 2,
            ..valid
        },
        ReplayOwnerFields {
            retained_bytes: 0,
            ..valid
        },
        ReplayOwnerFields {
            retained_bytes: 1_073_741_825,
            ..valid
        },
        ReplayOwnerFields {
            retained_bytes: 16_777_216,
            ..valid
        },
        ReplayOwnerFields {
            baseline: LastAcknowledged::At {
                sequence: 12,
                event_id: [0; 16],
            },
            ..valid
        },
        ReplayOwnerFields {
            baseline: LastAcknowledged::At {
                sequence: 11,
                event_id: [1; 16],
            },
            ..valid
        },
        ReplayOwnerFields {
            trusted_unix_seconds: Some(u64::MAX),
            ..valid
        },
        ReplayOwnerFields {
            through: u64::MAX,
            ..valid
        },
    ] {
        assert!(ReplayOwner::new(changed).is_err());
    }
    let empty = ReplayOwnerFields {
        first_retained: 12,
        retained_rows: 0,
        retained_bytes: 0,
        ..valid
    };
    assert!(ReplayOwner::new(empty).is_ok());
    Ok(())
}

#[test]
fn range_rejects_reversal_overflow_excess_rows_and_invalid_acknowledgement() -> TestResult {
    let valid = range()?;
    for changed in [
        AckRangeFields { first: 12, ..valid },
        AckRangeFields {
            first: 0,
            last: u64::MAX,
            ..valid
        },
        AckRangeFields {
            first: 0,
            last: 262_144,
            ..valid
        },
        AckRangeFields {
            acknowledgement: Acknowledgement::Unacknowledged,
            ..valid
        },
        AckRangeFields {
            acknowledgement: Acknowledgement::AcknowledgedAt {
                received_unix_seconds: 100,
                retain_until_unix_seconds: 101,
            },
            ..valid
        },
    ] {
        assert!(AckRange::new(changed).is_err());
    }
    assert!(
        AckRange::new(AckRangeFields {
            first: 0,
            last: 262_143,
            ..valid
        })
        .is_ok()
    );
    Ok(())
}

mod admission;
