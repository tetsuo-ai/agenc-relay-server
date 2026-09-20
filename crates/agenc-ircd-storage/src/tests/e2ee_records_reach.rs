//! Bound and consistency checks of the E2EE record codecs: key sets, routes,
//! package keys and the sequencer credential history refuse rows that are
//! empty, oversized or internally inconsistent.
#![forbid(unsafe_code)]

use super::fixtures::state_body;
use super::{
    KEYSET_ROW_KIND, KeySetRow, MAX_KEY_SET_CREDENTIALS, PackageRow, ROUTE_ROW_KIND, RouteRow,
    SequencerHistoryRow, prefix,
};
use crate::{StorageError, StoredKey};

#[test]
fn a_key_set_row_must_carry_at_least_one_and_at_most_the_bounded_credentials()
-> Result<(), StorageError> {
    let row = KeySetRow::decode(&state_body(KEYSET_ROW_KIND, 3)?)?;
    let empty = KeySetRow {
        credential_ids: Vec::new(),
        ..row.clone()
    };
    let refused = empty
        .encode()
        .and_then(|body| KeySetRow::decode(&body))
        .err();
    assert_eq!(refused, Some(StorageError::InvalidEncoding));
    let oversized = KeySetRow {
        credential_ids: vec![[5; 32]; MAX_KEY_SET_CREDENTIALS + 1],
        ..row.clone()
    };
    let refused = oversized
        .encode()
        .and_then(|body| KeySetRow::decode(&body))
        .err();
    assert_eq!(refused, Some(StorageError::LimitExceeded));
    assert_eq!(KeySetRow::decode(&row.encode()?)?, row);
    Ok(())
}

#[test]
fn a_route_row_refuses_an_empty_or_oversized_route_state() -> Result<(), StorageError> {
    let row = RouteRow::decode(&state_body(ROUTE_ROW_KIND, 4)?)?;
    let empty = RouteRow {
        route_state: Vec::new(),
        ..row.clone()
    };
    assert_eq!(empty.encode().err(), Some(StorageError::LimitExceeded));
    let oversized = RouteRow {
        route_state: vec![7; 1 << 22],
        ..row.clone()
    };
    assert_eq!(oversized.encode().err(), Some(StorageError::LimitExceeded));
    assert_eq!(RouteRow::decode(&row.encode()?)?, row);
    Ok(())
}

#[test]
fn a_package_key_needs_a_bounded_non_empty_reference() -> Result<(), StorageError> {
    let bare = StoredKey::new(prefix::PACKAGE.to_vec())?;
    assert_eq!(
        PackageRow::parse_package_key(&bare).err(),
        Some(StorageError::InvalidEncoding)
    );
    let mut long = prefix::PACKAGE.to_vec();
    long.extend_from_slice(&[1; 256]);
    assert_eq!(
        PackageRow::parse_package_key(&StoredKey::new(long)?).err(),
        Some(StorageError::InvalidEncoding)
    );
    assert_eq!(
        PackageRow::package_key(&[1; 256]).err(),
        Some(StorageError::InvalidEncoding)
    );
    assert_eq!(
        PackageRow::package_key(&[]).err(),
        Some(StorageError::InvalidEncoding)
    );
    let key = PackageRow::package_key(&[9; 255])?;
    assert_eq!(PackageRow::parse_package_key(&key)?, vec![9; 255]);
    Ok(())
}

#[test]
fn a_sequencer_history_row_must_be_internally_consistent() -> Result<(), StorageError> {
    let valid = SequencerHistoryRow {
        key_generation: 1,
        public_key: [3; 32],
        interval: (10, 20),
        previous_key_id: [0; 32],
        introduced_set: 1,
        retired_set: Some(2),
        released: true,
    };
    assert_eq!(SequencerHistoryRow::decode(&valid.encode()?)?, valid);
    let invalid = [
        SequencerHistoryRow {
            public_key: [0; 32],
            ..valid
        },
        SequencerHistoryRow {
            interval: (20, 20),
            ..valid
        },
        SequencerHistoryRow {
            retired_set: Some(1),
            ..valid
        },
        SequencerHistoryRow {
            retired_set: None,
            released: true,
            ..valid
        },
    ];
    for row in invalid {
        assert_eq!(row.encode().err(), Some(StorageError::InvalidEncoding));
    }
    let unreleased = SequencerHistoryRow {
        retired_set: None,
        released: false,
        ..valid
    };
    assert_eq!(
        SequencerHistoryRow::decode(&unreleased.encode()?)?,
        unreleased
    );
    Ok(())
}

#[test]
fn a_claim_row_refuses_an_oversized_key_package_reference() {
    let claim = |length: usize| super::PackageRow::Claim {
        target_account_digest: [1; 32],
        target_device_id: [2; 16],
        suite: 1,
        outcome: super::ClaimOutcome::Claimed,
        key_package_ref: vec![3; length],
        object_id: Some([4; 32]),
        retain_until: 5,
    };
    assert_eq!(claim(256).encode().err(), Some(StorageError::LimitExceeded));
    assert!(claim(255).encode().is_ok());
}
