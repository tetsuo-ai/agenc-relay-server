//! A successor bind names exactly the conversation and group the activated
//! attempt authorized.

#![forbid(unsafe_code)]

use super::*;

const OTHER_GROUP: [u8; 32] = [12; 32];

#[test]
fn a_successor_bind_for_another_conversation_than_the_activated_one_is_refused() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let mut package = fixture.package.clone();
    let other = agenc_relay_e2ee::ids::conversation_id(&NETWORK, &OTHER_GROUP)?;
    package.binding.tbs.group_id = Opaque::from_slice(&OTHER_GROUP)?;
    package.binding.tbs.conversation_id = other;
    let mut params = fixture.reservation.to_vec();
    params.extend_from_slice(&other);
    params.extend_from_slice(&fixture.context);
    let bytes = wire(ArcWireObjectKind::ConversationBinding, &package)?;
    assert_eq!(
        code(fixture.harness.run(Op::BindGroup, &params, Some(&bytes))?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let original = fixture.package.clone();
    ok(fixture.bind(&original, fixture.context)?)?;
    Ok(())
}

#[test]
fn a_successor_bind_whose_group_differs_from_the_attempt_target_is_refused() -> TestResult {
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    // The attempt targets the edited binding exactly, but keeps the group the
    // builder authorized, so only the group comparison can refuse the bind.
    let mut fixture = Fixture::prepare_bound_with(harness, old, |package, _| {
        package.binding.tbs.group_id = Opaque::from_slice(&OTHER_GROUP)?;
        package.binding.tbs.conversation_id =
            agenc_relay_e2ee::ids::conversation_id(&NETWORK, &OTHER_GROUP)?;
        Ok(())
    })?;
    fixture.activate()?;
    let package = fixture.package.clone();
    assert_eq!(
        code(fixture.bind(&package, fixture.context)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn a_reload_refuses_reinit_records_stored_under_each_others_positions() -> TestResult {
    use crate::state_core::durable::AccountServiceDurableWrite as Write;
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let package = fixture.package.clone();
    ok(fixture.bind(&package, fixture.context)?)?;
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
