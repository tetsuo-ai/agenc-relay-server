//! A roster as many rows hold as one owner row can reference
//! (`MAX_RECORD_REFERENCES`) is retained by them: a batch that names it
//! adds no further holder and is admitted, and a restart keeps that many
//! holders, those its stored account records first.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::owners::Rebuild;
use crate::e2ee::coordinator::{CompanionCoordinator, ConversationState};
use agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage;
use agenc_relay_storage::e2ee_records::{OWNER_ROW_KIND, ObjectOwnerRow, object_key};
use agenc_relay_storage::{
    MAX_RECORD_REFERENCES, PersistentRecordValue, RecordReference, StoredKey,
};

/// The binding identifier of the binding package object `bytes`.
fn binding_id_of(bytes: &[u8]) -> TestResult<[u8; 32]> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let package = ArcConversationBindingPackage::decode_exact(object.body(), &mut budget)?;
    Ok(semantic_id_of(
        SemanticHashDomain::BindingId,
        &package.binding.tbs,
    )?)
}

/// The decoded record of one put.
fn record(write: &Write) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let (table, key, encoded) = write.encoded_record().ok_or("a put")?;
    Ok((key.clone(), PersistentRecordValue::decode(table, encoded)?))
}

#[test]
fn a_batch_naming_a_roster_at_the_reference_ceiling_adds_no_holder() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let roster = roster_object(&harness.principal.roster)?;
    let mut account = harness
        .coordinator
        .state
        .owners
        .account(&roster)
        .ok_or("its account")?
        .clone();
    let filler = MAX_RECORD_REFERENCES - account.owners.len();
    for index in 0..filler {
        account
            .owners
            .insert(format!("filler/{index:08}").into_bytes(), None);
    }
    harness
        .coordinator
        .state
        .owners
        .install(roster, account.clone());
    // A batch binds a route whose binding names that roster as a head.
    let bytes = harness.binding_bytes()?;
    let binding_id = binding_id_of(&bytes)?;
    let write = |bytes: &[u8]| {
        CompanionCoordinator::object_write(bytes).map_err(|code| format!("{code:?}"))
    };
    let bound = [85; 32];
    commit(
        &mut harness,
        vec![
            write(&bytes)?,
            write(&route_state(6)?)?,
            route_row(bound, binding_id, 6)?,
        ],
    )?;
    let ledger = &harness.coordinator.state.owners;
    assert_eq!(
        ledger.account(&roster).ok_or("its account")?.owners,
        account.owners
    );
    // The route row still acquires its package.
    let package = ledger
        .account(&object_id(&bytes))
        .ok_or("the package's account")?;
    assert!(package.owners.contains_key(&route_key(bound)?));
    Ok(())
}

#[test]
fn a_restart_holds_a_roster_for_at_most_the_reference_ceiling_of_rows() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let roster = roster_object(&harness.principal.roster)?;
    let package = harness.binding_bytes()?;
    let package_id = object_id(&package);
    let binding_id = binding_id_of(&package)?;
    let state = &mut harness.coordinator.state;
    CompanionCoordinator::retain_object(state, package).map_err(|code| format!("{code:?}"))?;
    // One more conversation than an owner row can reference restores a
    // route whose binding names that roster as a head.
    let mut conversations = Vec::new();
    let mut rebuild = Rebuild::default();
    for index in 0..=u32::try_from(MAX_RECORD_REFERENCES)? {
        let mut conversation = [0; 32];
        conversation[..4].copy_from_slice(&index.to_be_bytes());
        state.conversations.insert(
            conversation,
            ConversationState {
                binding_object_id: package_id,
                ..ConversationState::default()
            },
        );
        let (key, value) = record(&route_row(conversation, binding_id, 7)?)?;
        rebuild.admit_row(&key, &value);
        conversations.push(conversation);
    }
    // The stored account records three holders, the routes with the
    // highest keys.
    let recorded = conversations
        .iter()
        .rev()
        .take(3)
        .map(|conversation| route_key(*conversation))
        .collect::<TestResult<Vec<_>>>()?;
    let references = recorded
        .iter()
        .map(|key| RecordReference::new(TableId::E2eeState, StoredKey::new(key.clone())?))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = state.objects.get(&roster).ok_or("the roster")?.clone();
    let owner = ObjectOwnerRow {
        kind: ArcWireObjectKind::DeviceRoster.value(),
        size: u64::try_from(bytes.len())?,
        retention: RetentionClass::SecurityProof,
        accepted_at: NOW,
        reconstructed: false,
        retired_at: None,
    };
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        OWNER_ROW_KIND,
        1,
        0,
        None,
        references,
        owner.encode()?,
    )?;
    rebuild.admit_row(&ObjectOwnerRow::key(&roster)?, &value);
    let (key, value) =
        record(&CompanionCoordinator::object_write(&bytes).map_err(|code| format!("{code:?}"))?)?;
    assert_eq!(key.as_bytes(), object_key(&roster)?.as_bytes());
    rebuild.admit_object(&key, &value);
    rebuild.finish(state);
    let account = state.owners.account(&roster).ok_or("its account")?;
    assert_eq!(account.owners.len(), MAX_RECORD_REFERENCES);
    assert!(recorded.iter().all(|key| account.owners.contains_key(key)));
    // The others follow in key order up to the ceiling.
    let first = route_key(*conversations.first().ok_or("the first route")?)?;
    let past = route_key(
        *conversations
            .get(MAX_RECORD_REFERENCES - 3)
            .ok_or("the first route past the ceiling")?,
    )?;
    assert!(account.owners.contains_key(&first));
    assert!(!account.owners.contains_key(&past));
    Ok(())
}
