#![forbid(unsafe_code)]

use std::error::Error;

use agenc_relay_crypto::StorageDigest;
use agenc_relay_types::RecoveryEpoch;

use super::{e2ee_recovery_body, e2ee_restore_references};
use crate::e2ee_records::{
    OWNER_ROW_KIND, ObjectOwnerRow, ReplayKey, ReplayRow, RetentionClass, SequencerRow,
    UNDATED_SECOND,
};
use crate::{PersistentRecordValue, RecordReference, StoredKey, TableId};

type TestResult = Result<(), Box<dyn Error>>;

fn references(keys: &[&StoredKey]) -> Result<Vec<RecordReference>, Box<dyn Error>> {
    keys.iter()
        .map(|key| Ok(RecordReference::new(TableId::E2eeState, (*key).clone())?))
        .collect()
}

fn keys_of(references: &[RecordReference]) -> Vec<Vec<u8>> {
    references
        .iter()
        .map(|reference| reference.key().as_bytes().to_vec())
        .collect()
}

#[test]
fn a_restore_drops_owner_references_to_unrestored_rows_and_retires_undated() -> TestResult {
    let row = ObjectOwnerRow {
        kind: 25,
        size: 64,
        retention: RetentionClass::Replay,
        accepted_at: 1_700_000_000,
        reconstructed: false,
        retired_at: None,
    };
    let replay = ReplayRow::key(&ReplayKey {
        home_server_id: [2; 16],
        server_incarnation: [3; 16],
        origin_id: [4; 16],
        origin_generation: 0,
        operation_sequence: 1,
    })?;
    let record = SequencerRow::record_key(&[5; 32], 1)?;
    let value = |refs: Vec<RecordReference>| -> Result<PersistentRecordValue, Box<dyn Error>> {
        Ok(PersistentRecordValue::new(
            TableId::E2eeState,
            OWNER_ROW_KIND,
            1,
            0,
            None,
            refs,
            row.encode()?,
        )?)
    };
    let epoch = RecoveryEpoch::from_bytes([9; 16]);
    let guard = StorageDigest::from_bytes([8; 32]);
    // The replay owner is dropped; the record owner keeps the account live.
    let both = value(references(&[&replay, &record])?)?;
    let kept = e2ee_restore_references(&both);
    assert_eq!(keys_of(&kept), keys_of(&references(&[&record])?));
    let body = e2ee_recovery_body(&both, epoch, guard, &kept)?;
    assert_eq!(ObjectOwnerRow::decode(&body)?, row);
    // Every owner dropped: the account is retired at the undated second.
    let only_replay = value(references(&[&replay])?)?;
    let kept = e2ee_restore_references(&only_replay);
    assert!(kept.is_empty());
    let body = e2ee_recovery_body(&only_replay, epoch, guard, &kept)?;
    assert_eq!(
        ObjectOwnerRow::decode(&body)?.retired_at,
        Some(UNDATED_SECOND)
    );
    Ok(())
}
