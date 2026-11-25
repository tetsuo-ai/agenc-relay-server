//! Fixed row sizes, canonical registration and permanent old-format exclusion.
#![forbid(unsafe_code)]

use super::*;
use crate::{PersistentRecordValue, TableId, validate_record_plaintext};

fn reserved() -> RootClaimOwner {
    RootClaimOwner {
        network: NetworkId::from_bytes([1; 32]),
        account: AccountRandomId::from_bytes([3; 16]).to_account_id(),
        epoch: RecoveryEpoch::from_bytes([4; 16]),
        start: RequestId::from_bytes([5; 16]),
        owner: InitialRootClaimOwner::from_protected_bytes([7; 32]),
        state: RootClaimState::Reserved,
    }
}

#[test]
fn initial_root_owner_reserves_every_state_at_creation_and_rejects_crossed_slots()
-> Result<(), StorageError> {
    let original = reserved();
    let chosen = original.transition(RootClaimState::Chosen([10; 32]))?;
    let published = chosen.transition(RootClaimState::Published {
        fingerprint: [10; 32],
        object_id: [11; 32],
    })?;
    let key = RootClaimOwner::key(original.network, original.account)?;
    let other = RootClaimOwner::key(NetworkId::from_bytes([2; 32]), original.account)?;
    let marker = StoredKey::new(FORMAT_KEY.to_vec())?;
    let format = InitialRootRow::format()?;
    assert!(matches!(
        InitialRootRow::decode_keyed(&marker, &format)?,
        InitialRootRow::Format
    ));
    assert!(InitialRootRow::decode_keyed(&key, &format).is_err());
    for row in [&original, &chosen, &published] {
        let body = row.encode()?;
        assert_eq!(body.len(), WRAPPER_BYTES + OWNER_BYTES);
        assert!(
            matches!(InitialRootRow::decode_keyed(&key, &body)?, InitialRootRow::Owner(r) if &r == row)
        );
        assert!(InitialRootRow::decode_keyed(&other, &body).is_err());
        assert!(InitialRootRow::decode_keyed(&marker, &body).is_err());
        let value =
            PersistentRecordValue::new(TableId::E2eeState, KIND, 2, 0, None, Vec::new(), body)?;
        validate_record_plaintext(TableId::E2eeState, &key, 1, &value.encode()?)?;
    }
    assert!(chosen.transition(RootClaimState::Chosen([12; 32])).is_err());
    assert!(
        chosen
            .transition(RootClaimState::Published {
                fingerprint: [12; 32],
                object_id: [11; 32]
            })
            .is_err()
    );
    assert!(published.transition(RootClaimState::Reserved).is_err());
    Ok(())
}

#[test]
fn initial_root_format_rejects_unclassified_rows_and_unauthorized_field_combinations()
-> Result<(), StorageError> {
    let row = reserved();
    let key = RootClaimOwner::key(row.network, row.account)?;
    let body = row.encode()?;
    for from_end in [1, 33, 65] {
        let mut changed = body.clone();
        let offset = changed
            .len()
            .checked_sub(from_end)
            .ok_or(StorageError::Overflow)?;
        *changed
            .get_mut(offset)
            .ok_or(StorageError::InvalidEncoding)? = 9;
        assert!(InitialRootRow::decode(&changed).is_err());
    }
    let malformed = StoredKey::new([FORMAT_KEY, b"-other"].concat())?;
    assert!(InitialRootRow::decode_keyed(&malformed, &InitialRootRow::format()?).is_err());
    let expires = PersistentRecordValue::new(
        TableId::E2eeState,
        KIND,
        3,
        0,
        Some(3),
        Vec::new(),
        body.clone(),
    )?;
    let generated =
        PersistentRecordValue::new(TableId::E2eeState, KIND, 3, 1, None, Vec::new(), body)?;
    let reference = crate::RecordReference::new(
        TableId::Account,
        StoredKey::new(row.account.to_text().into_bytes())?,
    )?;
    let referenced = PersistentRecordValue::new(
        TableId::E2eeState,
        KIND,
        3,
        0,
        None,
        vec![reference],
        row.encode()?,
    )?;
    for invalid in [expires, generated, referenced] {
        assert!(InitialRootRow::check_record(&key, &invalid).is_err());
        assert!(
            validate_record_plaintext(TableId::E2eeState, &key, 1, &invalid.encode()?).is_err()
        );
    }
    let legacy = super::super::fixtures::state_body(super::super::DIRECTORY_ROW_KIND, 5)?;
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        super::super::DIRECTORY_ROW_KIND,
        3,
        0,
        None,
        Vec::new(),
        legacy,
    )?;
    assert!(validate_record_plaintext(TableId::E2eeState, &key, 1, &value.encode()?).is_err());
    Ok(())
}
