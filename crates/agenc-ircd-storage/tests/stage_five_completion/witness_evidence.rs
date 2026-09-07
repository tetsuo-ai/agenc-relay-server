//! Chain-witness evidence survives the persistent envelope and sealed restart.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::{WITNESS_ROW_KIND, WitnessRow};

fn expected_witness() -> WitnessRow {
    WitnessRow {
        event_kind: agenc_ircd_e2ee::objects::federation::IrcFederationEventKind::CandidateEvent
            .value(),
        expected_sequence: 4,
        expected_head_id: [21; 32],
        observed_sequence: 6,
        observed_id: [22; 32],
        observed_predecessor_id: Some([23; 32]),
    }
}

fn witness_plaintext(row: &WitnessRow) -> Result<Vec<u8>, StorageError> {
    let body = row.encode()?;
    assert_eq!(WitnessRow::decode(&body)?, *row);
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        WITNESS_ROW_KIND,
        1,
        0,
        None,
        Vec::new(),
        body,
    );
    assert!(
        value.is_ok(),
        "the persistent registry refused a valid chain witness: {:?}",
        value.as_ref().err(),
    );
    value?.encode()
}

fn witness_initial_records(
    plaintext: Vec<u8>,
    key: StoredKey,
) -> Result<Vec<InitialStorageRecord>, StorageError> {
    let network = NetworkId::from_bytes([201; 32]);
    let login = LoginIndexKey::from_bytes([203; 32]);
    Ok(vec![
        InitialStorageRecord::new(
            TableId::LoginIndexKeyState,
            StoredKey::new(agenc_ircd_storage::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            LoginIndexKeyState::stable(1, login.key_id(network))?.encode()?,
        )?,
        InitialStorageRecord::new(TableId::E2eeState, key, 1, plaintext)?,
    ])
}

fn read_witness(port: &StoragePort, key: &StoredKey) -> Result<WitnessRow, Box<dyn Error>> {
    let result = port
        .try_read(ReadPlan::exact(TableId::E2eeState, key.clone()))?
        .wait()?;
    let [stored] = result.records.as_slice() else {
        return Err("the committed witness row is missing".into());
    };
    let sealed = SealedRecord::decode(&stored.sealed_record)?;
    let opened = sealed.open(
        &StorageMasterKey::from_bytes([207; 32]),
        DatabaseBinding::new(
            NetworkId::from_bytes([201; 32]),
            ServerId::from_bytes([202; 16]),
            ServerIncarnation::from_bytes([204; 16]),
            DatabaseId::from_bytes([205; 16]),
        ),
        TableId::E2eeState,
        1,
        1,
        key,
    )?;
    let value =
        PersistentRecordValue::decode(TableId::E2eeState, opened.expose_for_storage_codec())?;
    assert_eq!(value.record_kind(), WITNESS_ROW_KIND);
    Ok(WitnessRow::decode(value.body())?)
}

#[test]
fn a_chain_witness_is_admitted_sealed_and_recovered_after_restart() -> Result<(), Box<dyn Error>> {
    let expected = expected_witness();
    let key = WitnessRow::key(&[20; 32])?;
    let plaintext = witness_plaintext(&expected)?;
    validate_record_plaintext(TableId::E2eeState, &key, 1, &plaintext)?;
    let fixture = initialized_live_fixture_from(witness_initial_records(plaintext, key.clone())?)?;
    for _ in 0..2 {
        let owner = StorageOwner::start(live_open_config(StateDirectory::open(
            fixture.directory.path(),
            &[fixture.qualification],
        )?))?;
        assert_eq!(read_witness(&owner.port(), &key)?, expected);
        owner.shutdown()?;
    }
    Ok(())
}
