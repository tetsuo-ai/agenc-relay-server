//! A route row keeps every roster it acquired until its deletion, also one
//! that only a proof a later proof replaced named, so a restart keeps the
//! route rows a roster's stored account records as its holders, charged to
//! their conversations as live batches charged them. Only an account that
//! describes a resident roster object, and only a route row that was read
//! and restored, counts. A store whose owner rows record no such holder, as
//! one written before these holdings, gets each holding derived from the
//! statement that names the roster.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::owners::Rebuild;
use crate::e2ee::coordinator::{CompanionCoordinator, ConversationState};
use agenc_relay_storage::e2ee_records::{OWNER_ROW_KIND, ObjectOwnerRow};
use agenc_relay_storage::{PersistentRecordValue, RecordReference, StoredKey};

/// A device the derivation test enrolls for the policy it seats.
const SEATED: u8 = 13;

/// Replaces the attached device's proof for old leaf 0 with one at `epoch`
/// that names the principal's current roster.
fn replace_leaf_zero_proof(
    harness: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
) -> TestResult {
    let mut spec = support::MembershipSpec::continuing(
        &harness.principal,
        conversation,
        DEVICE,
        crate::e2ee::coordinator::tests::LEAF_SEED,
        0,
    );
    spec.epoch = epoch;
    let proof = support::membership_proof(&spec)?;
    harness.publish_membership(conversation, &proof)?;
    Ok(())
}

#[test]
fn a_roster_a_replaced_proof_named_stays_held_across_restarts() -> TestResult {
    use crate::e2ee::coordinator::tests::sequence::reinit_successor::{Authorized, LEAF_ZERO};
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness.activate_bootstrap(conversation)?;
    // Leaf 0's device replaces its proof at epoch 1 with one naming the
    // account's next roster, and at epoch 2 with one naming the roster after
    // that; the account then publishes once more.
    let same = certificates(&harness);
    let first = publish(&mut harness, same)?;
    replace_leaf_zero_proof(&mut harness, conversation, 1)?;
    let routine = Authorized {
        rule: ArcCommitAuthorizationRule::RoutineSelfUpdate,
        bits: 0,
        resulting_policy_id: None,
        target_digest: [0; 32],
    };
    harness.finalize_commit(conversation, routine, &[LEAF_ZERO])?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    replace_leaf_zero_proof(&mut harness, conversation, 2)?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    // No stored statement names the first replaced roster any more; the
    // route row that acquired it keeps holding it, charged to the
    // conversation.
    let stored: Vec<(u32, u64, u64)> = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .memberships
        .iter()
        .map(|entry| {
            let proof = &entry.proof;
            (proof.leaf_index, proof.epoch, proof.roster_generation)
        })
        .collect();
    assert_eq!(stored, vec![(0, 2, 2)]);
    let route = route_key(conversation)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&first));
    assert_held_by(&harness, first, std::slice::from_ref(&route))?;
    assert_charged(&harness, first, conversation)?;
    let charged = harness
        .coordinator
        .state
        .owners
        .conversation_bytes(&conversation);
    // A restart keeps the holding the route row's batches acquired, and
    // charges the conversation as before.
    let mut restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&restarted, first, std::slice::from_ref(&route))?;
    assert_charged(&restarted, first, conversation)?;
    let state = &restarted.coordinator.state;
    assert_eq!(state.owners.conversation_bytes(&conversation), charged);
    let later = PAST_EVERY_WINDOW + SEQUENCER_RECORD_RETENTION_SECONDS + 1;
    assert!(!expire(&mut restarted, later)?.contains(&first));
    let again = restarted.reloaded()?;
    assert!(again.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&again, first, std::slice::from_ref(&route))?;
    Ok(())
}

/// The decoded record of one put.
fn record(write: &Write) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let (table, key, encoded) = write.encoded_record().ok_or("a put")?;
    Ok((key.clone(), PersistentRecordValue::decode(table, encoded)?))
}

/// The owner row of `object` with `kind` and `size` that records
/// `holders`.
fn owner_row(
    object: [u8; 32],
    kind: ArcWireObjectKind,
    size: usize,
    holders: &[&Vec<u8>],
) -> TestResult<(StoredKey, PersistentRecordValue)> {
    let references = holders
        .iter()
        .map(|key| RecordReference::new(TableId::E2eeState, StoredKey::new((*key).clone())?))
        .collect::<Result<Vec<_>, _>>()?;
    let row = ObjectOwnerRow {
        kind: kind.value(),
        size: u64::try_from(size)?,
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
        row.encode()?,
    )?;
    Ok((ObjectOwnerRow::key(&object)?, value))
}

#[test]
fn a_restart_keeps_only_restored_route_holders_of_a_resident_roster() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let held = roster_object(&harness.principal.roster)?;
    let same = certificates(&harness);
    let resized = publish(&mut harness, same)?;
    let state = &mut harness.coordinator.state;
    let bytes = |id: &[u8; 32]| state.objects.get(id).cloned().ok_or("a roster");
    let (held_bytes, resized_bytes) = (bytes(&held)?, bytes(&resized)?);
    let other_bytes = route_state(9)?;
    let other = object_id(&other_bytes);
    // Route rows are read for a restored conversation and for one that is
    // not restored; a third conversation's route row is not read.
    let (restored, unrestored, unread) = ([91; 32], [92; 32], [93; 32]);
    let mut rebuild = Rebuild::default();
    for conversation in [restored, unrestored] {
        let (key, value) = record(&route_row(conversation, [7; 32], 8)?)?;
        rebuild.admit_row(&key, &value);
    }
    state
        .conversations
        .insert(restored, ConversationState::default());
    let keys = [
        route_key(restored)?,
        route_key(unrestored)?,
        route_key(unread)?,
    ];
    let objects = [
        (held, &held_bytes, ArcWireObjectKind::DeviceRoster, 0),
        (resized, &resized_bytes, ArcWireObjectKind::DeviceRoster, 1),
        (other, &other_bytes, ArcWireObjectKind::FederationState, 0),
    ];
    for (id, bytes, kind, extra) in objects {
        let write =
            CompanionCoordinator::object_write(bytes).map_err(|code| format!("{code:?}"))?;
        let (key, value) = record(&write)?;
        rebuild.admit_object(&key, &value);
        let (key, value) = owner_row(
            id,
            kind,
            bytes.len() + extra,
            &keys.iter().collect::<Vec<_>>(),
        )?;
        rebuild.admit_row(&key, &value);
    }
    rebuild.finish(state);
    // The roster keeps the restored route row as its holder, charged to its
    // conversation; the route rows not read or not restored hold nothing.
    let account = state.owners.account(&held).ok_or("the roster's account")?;
    assert_eq!(account.owners.keys().collect::<Vec<_>>(), vec![&keys[0]]);
    assert_eq!(account.conversations(), BTreeSet::from([restored]));
    assert_eq!(account.retired_at, None);
    // An account whose size is not the resident roster's, and one of
    // another kind, keep no recorded holder.
    for id in [resized, other] {
        let account = state.owners.account(&id).ok_or("an account")?;
        assert!(account.owners.is_empty());
    }
    Ok(())
}

/// Whether `write` puts an object's owner row.
fn is_owner_row(write: &Write) -> bool {
    matches!(
        write,
        Write::Put { table: TableId::E2eeState, key, .. } if ObjectOwnerRow::matches_key(key)
    )
}

#[test]
fn a_restart_without_owner_rows_derives_each_holding_from_its_statement() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let head = roster_object(&harness.principal.roster)?;
    // The next roster enrolls a device whose first proof names it; the
    // roster after that enrolls a device a new policy seats, which only
    // that roster verifies; a last roster replaces both.
    let proven = enroll(&mut harness, ENROLLED)?;
    harness.attach_as(ENROLLED)?;
    let proof = harness.leaf_proof(conversation, ENROLLED, ENROLLED_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &proof)?;
    let seated = enroll(&mut harness, SEATED)?;
    harness.attach_as(DEVICE)?;
    let operational = policy_id_of(&harness.operational_policy)?;
    let policy = seated_policy(&harness, conversation, operational, &[DEVICE, SEATED])?;
    harness.publish_policy(conversation, &policy)?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    // Without the owner rows nothing records a holder: the restart derives
    // the route row's holding of each roster from the binding, the proof
    // and the policy that name it.
    harness.writes.retain(|write| !is_owner_row(write));
    let restarted = harness.reloaded()?;
    let route = route_key(conversation)?;
    for roster in [head, proven, seated] {
        assert_held_by(&restarted, roster, std::slice::from_ref(&route))?;
        assert_charged(&restarted, roster, conversation)?;
    }
    Ok(())
}
