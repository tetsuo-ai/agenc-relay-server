//! A reload cross-checks the old conversation's ReInit records against the
//! positions that stored them.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn a_reload_refuses_reinit_records_stored_under_each_others_positions() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let sequences: Vec<u64> = fixture
        .harness
        .coordinator
        .state
        .conversations
        .get(&fixture.old)
        .map(|state| state.records.keys().copied().collect())
        .ok_or("old conversation")?;
    let [.., attempt, activation] = sequences.as_slice() else {
        return Err("two retained reinit records".into());
    };
    let keys = [
        agenc_relay_storage::e2ee_records::SequencerRow::record_key(&fixture.old, *attempt)?,
        agenc_relay_storage::e2ee_records::SequencerRow::record_key(&fixture.old, *activation)?,
    ];
    let body_of = |wanted: &agenc_relay_storage::StoredKey| {
        fixture
            .harness
            .writes
            .iter()
            .rev()
            .find_map(|write| match write {
                Write::Put {
                    table: agenc_relay_storage::TableId::E2eeState,
                    key,
                    plaintext,
                } if key == wanted => Some(plaintext.clone()),
                _ => None,
            })
    };
    let [attempt_key, activation_key] = keys;
    let attempt_body = body_of(&attempt_key).ok_or("attempt record row")?;
    let activation_body = body_of(&activation_key).ok_or("activation record row")?;
    for write in &mut fixture.harness.writes {
        if let Write::Put {
            table: agenc_relay_storage::TableId::E2eeState,
            key,
            plaintext,
        } = write
        {
            if *key == attempt_key {
                *plaintext = activation_body.clone();
            } else if *key == activation_key {
                *plaintext = attempt_body.clone();
            }
        }
    }
    assert!(fixture.harness.reloaded().is_err());
    Ok(())
}
