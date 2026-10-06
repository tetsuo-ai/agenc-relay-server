//! A conversation's route row holds the device rosters its statements name
//! (companion 9.3, 9.4, 13.7.3 and 15), charged to the conversation: the
//! roster heads its binding names, the roster each stored leaf proof names,
//! and, for each root a retained policy names, the earliest retained roster
//! of that root that verifies the policy. The row keeps a roster until its
//! deletion, also across restarts and once a later proof replaces the proof
//! that named it. A roster that no route row holds is collected once the
//! account has replaced it and the retention window has passed, so an
//! account's publications leave its current roster and the rosters route
//! rows hold, and nothing else; a first proof naming a collected roster is
//! refused.

#![forbid(unsafe_code)]

mod ceiling;
mod restart;

use super::*;
use crate::e2ee::coordinator::tests::support::{self, DeviceSpec};
use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::objects::conversation::ArcPolicy;
use agenc_relay_e2ee::objects::identity::{ArcDeviceCertificate, ArcDeviceRoster};
use agenc_relay_storage::e2ee_records::DirectoryRow;

/// A device the tests enroll after the binding.
const ENROLLED: u8 = 12;
/// The old leaf key the enrolled device holds.
const ENROLLED_LEAF_SEED: u8 = 32;

/// The key of the harness account's roster row.
fn roster_row(harness: &Harness) -> TestResult<Vec<u8>> {
    Ok(
        DirectoryRow::roster_key(&account_id_digest(&NETWORK, &harness.account)?)?
            .as_bytes()
            .to_vec(),
    )
}

/// The key of `conversation`'s route row.
fn route_key(conversation: [u8; 32]) -> TestResult<Vec<u8>> {
    Ok(RouteRow::key(&conversation)?.as_bytes().to_vec())
}

/// The retained object of `roster`.
fn roster_object(roster: &ArcDeviceRoster) -> TestResult<[u8; 32]> {
    Ok(object_id(&wire(ArcWireObjectKind::DeviceRoster, roster)?))
}

/// The certificates of the principal's current roster.
fn certificates(harness: &Harness) -> Vec<ArcDeviceCertificate> {
    let active = harness.principal.roster.tbs.active_devices.as_slice();
    active
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect()
}

/// Publishes the principal's next roster with `certificates`, which then
/// stands for the principal's current roster, and returns its object.
fn publish(harness: &mut Harness, certificates: Vec<ArcDeviceCertificate>) -> TestResult<[u8; 32]> {
    let principal = &harness.principal;
    let next = support::roster(
        &principal.root_secret,
        &principal.root,
        principal.roster.tbs.roster_generation + 1,
        support::roster_id(&principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &next)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    harness.principal.roster = next;
    Ok(object_id(&bytes))
}

/// Publishes the principal's next roster with the current devices and
/// `seed`, enrolled for that roster, and returns its object.
fn enroll(harness: &mut Harness, seed: u8) -> TestResult<[u8; 32]> {
    let mut device = DeviceSpec::new(seed);
    device.target_roster_generation = harness.principal.roster.tbs.roster_generation + 1;
    let principal = &harness.principal;
    let mut all = certificates(harness);
    all.push(support::certificate(
        &principal.root_secret,
        &principal.root,
        &device,
    )?);
    all.sort_by_key(|certificate| certificate.tbs.device_id);
    publish(harness, all)
}

/// The generation-two policy of `conversation` after `previous`, whose
/// council is `council`, each device named by its certificate in the
/// principal's current roster, approved by the bound device.
fn seated_policy(
    harness: &Harness,
    conversation: [u8; 32],
    previous: [u8; 32],
    council: &[u8],
) -> TestResult<ArcPolicy> {
    use agenc_relay_e2ee::objects::conversation::{ArcFinalityPrincipal, ArcPolicyApproval};
    let principals = std::slice::from_ref(&harness.principal);
    let mut spec = PolicySpec::bootstrap(principals, conversation, ArcConversationKind::Channel)
        .successor(previous);
    spec.generation = 2;
    spec.council = council.iter().map(|device| (0, *device)).collect();
    let mut tbs = support::policy_tbs(&spec)?;
    let active = harness.principal.roster.tbs.active_devices.as_slice();
    let mut seats = Vec::new();
    for member in tbs.finality_principals.as_slice() {
        let entry = active
            .iter()
            .find(|entry| entry.device_id == member.device_id)
            .ok_or("a seated device")?;
        seats.push(ArcFinalityPrincipal {
            device_certificate_id: semantic_id_of(
                SemanticHashDomain::DeviceCertificateId,
                &entry.certificate.tbs,
            )?,
            ..member.clone()
        });
    }
    tbs.finality_principals = TlsVec::new(seats)?;
    let approval = ArcPolicyApproval {
        signer_root_fingerprint: root_fingerprint(&harness.principal.root)?,
        signer_device_id: [DEVICE; 16],
        signer_device_certificate_id: certificate_id_of(&harness.principal, DEVICE)?,
        device_signature: sign(&key(DEVICE), SignatureDomain::PolicyApproval, &tbs)?,
    };
    Ok(ArcPolicy {
        tbs,
        approvals: TlsVec::new(vec![approval])?,
    })
}

/// Asserts that `object` is charged to `conversation` alone.
fn assert_charged(harness: &Harness, object: [u8; 32], conversation: [u8; 32]) -> TestResult {
    let account = harness
        .coordinator
        .state
        .owners
        .account(&object)
        .ok_or("its account")?;
    assert_eq!(account.conversations(), BTreeSet::from([conversation]));
    Ok(())
}

#[test]
fn a_policy_restores_after_the_roster_its_council_was_verified_under_expires() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    let named = roster_object(&harness.principal.roster)?;
    // The account's next roster revokes a council device, so only the
    // replaced roster holds the certificate the published policies name.
    crate::e2ee::coordinator::tests::retire_council_device(&mut harness, [SECOND_DEVICE; 16])?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .policies
        .clone();
    assert_eq!(before.len(), 2);
    let route = route_key(conversation)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&named));
    assert_held_by(&harness, named, std::slice::from_ref(&route))?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    let after = &restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?
        .policies;
    assert_eq!(after, &before);
    assert_held_by(&restarted, named, std::slice::from_ref(&route))?;
    Ok(())
}

#[test]
fn the_roster_a_binding_names_stays_held_after_the_account_replaces_it() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let named = roster_object(&harness.principal.roster)?;
    let route = route_key(conversation)?;
    // While the roster is current, the account's roster row owns it too;
    // the route row's rewrite at the bootstrap activation keeps it.
    harness.activate_bootstrap(conversation)?;
    assert_held_by(&harness, named, &[roster_row(&harness)?, route.clone()])?;
    assert_charged(&harness, named, conversation)?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&named));
    assert_held_by(&harness, named, std::slice::from_ref(&route))?;
    assert_charged(&harness, named, conversation)?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&restarted, named, std::slice::from_ref(&route))?;
    assert!(
        restarted
            .coordinator
            .state
            .conversations
            .contains_key(&conversation)
    );
    Ok(())
}

#[test]
fn a_bound_route_holds_the_roster_heads_its_binding_names() -> TestResult {
    let mut harness = Harness::new()?;
    // Bound without its policies or a leaf proof, the conversation names
    // its principal's roster only through its binding.
    let conversation = harness.bind_channel_unpublished()?;
    let head = roster_object(&harness.principal.roster)?;
    let route = route_key(conversation)?;
    assert_held_by(&harness, head, &[roster_row(&harness)?, route.clone()])?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&head));
    assert_held_by(&harness, head, std::slice::from_ref(&route))?;
    assert_charged(&harness, head, conversation)?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&restarted, head, std::slice::from_ref(&route))?;
    Ok(())
}

#[test]
fn a_replaced_roster_no_live_conversation_names_is_collected() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let named = roster_object(&harness.principal.roster)?;
    let mut replaced = Vec::new();
    for _ in 0..3 {
        let same = certificates(&harness);
        replaced.push(publish(&mut harness, same)?);
    }
    let current = replaced.pop().ok_or("the current roster")?;
    let resident = harness.coordinator.state.object_bytes;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    let state = &harness.coordinator.state;
    for roster in &replaced {
        assert!(collected.contains(roster));
        assert!(!state.objects.contains_key(roster));
        assert!(state.owners.account(roster).is_none());
    }
    assert!(state.object_bytes < resident);
    // The roster index forgets what expiry collected.
    let indexed = |roster: &[u8; 32]| state.roster_snapshots.values().any(|id| id == roster);
    assert!(replaced.iter().all(|roster| !indexed(roster)));
    assert!(indexed(&named) && indexed(&current));
    let route = route_key(conversation)?;
    assert_held_by(&harness, named, std::slice::from_ref(&route))?;
    assert_held_by(&harness, current, &[roster_row(&harness)?])?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    let objects = &restarted.coordinator.state.objects;
    assert!(replaced.iter().all(|roster| !objects.contains_key(roster)));
    assert_held_by(&restarted, named, std::slice::from_ref(&route))?;
    assert_held_by(&restarted, current, &[roster_row(&harness)?])?;
    Ok(())
}

#[test]
fn an_account_without_a_conversation_keeps_only_its_current_roster() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let mut published = vec![roster_object(&harness.principal.roster)?];
    for _ in 0..4 {
        let same = certificates(&harness);
        published.push(publish(&mut harness, same)?);
    }
    let current = published.pop().ok_or("the current roster")?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(published.iter().all(|roster| collected.contains(roster)));
    assert_held_by(&harness, current, &[roster_row(&harness)?])?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    let rosters: Vec<&[u8; 32]> = restarted
        .coordinator
        .state
        .objects
        .iter()
        .filter(|(_, bytes)| {
            agenc_relay_e2ee::object::ArcWireObject::peek(bytes)
                .is_ok_and(|(kind, _)| kind == ArcWireObjectKind::DeviceRoster)
        })
        .map(|(id, _)| id)
        .collect();
    assert_eq!(rosters, vec![&current]);
    Ok(())
}

#[test]
fn a_policy_holds_the_earliest_roster_that_verifies_it() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let head = roster_object(&harness.principal.roster)?;
    // The next roster enrolls a device the next policy seats on its council
    // beside the bound device; the head roster does not hold it.
    let enrolled = enroll(&mut harness, ENROLLED)?;
    let operational = policy_id_of(&harness.operational_policy)?;
    let seated = seated_policy(&harness, conversation, operational, &[DEVICE, ENROLLED])?;
    // A newer roster with the same devices does not change which roster
    // the policy holds: the earliest that verifies it.
    let same = certificates(&harness);
    let newer = publish(&mut harness, same)?;
    harness.publish_policy(conversation, &seated)?;
    let route = route_key(conversation)?;
    assert_held_by(&harness, enrolled, std::slice::from_ref(&route))?;
    assert_charged(&harness, enrolled, conversation)?;
    let held = harness
        .coordinator
        .state
        .owners
        .account(&newer)
        .ok_or("the newer roster's account")?;
    assert!(!held.owners.contains_key(&route));
    // The roster after that revokes the enrolled device; the roster that
    // held it stays retained, and every policy restores after a restart.
    let kept: Vec<ArcDeviceCertificate> = certificates(&harness)
        .into_iter()
        .filter(|certificate| certificate.tbs.device_id != [ENROLLED; 16])
        .collect();
    publish(&mut harness, kept)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&enrolled) && !collected.contains(&head));
    assert!(collected.contains(&newer));
    let policies = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .policies
        .clone();
    assert_eq!(policies.len(), 3);
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    let restored = &restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?
        .policies;
    assert_eq!(restored, &policies);
    assert_held_by(&restarted, enrolled, std::slice::from_ref(&route))?;
    Ok(())
}

#[test]
fn a_policy_stored_after_expiry_holds_the_earliest_resident_roster() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let enrolled = enroll(&mut harness, ENROLLED)?;
    let mut later = Vec::new();
    for _ in 0..2 {
        let same = certificates(&harness);
        later.push(publish(&mut harness, same)?);
    }
    let current = *later.last().ok_or("the current roster")?;
    // No statement names the enrolling roster or the one after it, so
    // expiry collects both; the policy then holds the earliest roster that
    // is still retained and verifies it.
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(collected.contains(&enrolled));
    let operational = policy_id_of(&harness.operational_policy)?;
    let seated = seated_policy(&harness, conversation, operational, &[DEVICE, ENROLLED])?;
    harness.publish_policy(conversation, &seated)?;
    let route = route_key(conversation)?;
    assert_held_by(&harness, current, &[roster_row(&harness)?, route.clone()])?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW + 1)?;
    assert!(!collected.contains(&current));
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&restarted, current, std::slice::from_ref(&route))?;
    let restored = &restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?
        .policies;
    assert_eq!(restored.len(), 3);
    Ok(())
}

#[test]
fn a_proof_holds_the_roster_it_names() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let enrolled = enroll(&mut harness, ENROLLED)?;
    harness.attach_as(ENROLLED)?;
    // The enrolled device's credential, and so its proof, names the roster
    // that enrolled it.
    let proof = harness.leaf_proof(conversation, ENROLLED, ENROLLED_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &proof)?;
    let route = route_key(conversation)?;
    assert_held_by(&harness, enrolled, &[roster_row(&harness)?, route.clone()])?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&enrolled));
    assert_held_by(&harness, enrolled, std::slice::from_ref(&route))?;
    assert_charged(&harness, enrolled, conversation)?;
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    let stored = restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?
        .memberships
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.roster_generation))
        .collect::<Vec<_>>();
    assert_eq!(stored, vec![(0, 0), (1, 1)]);
    assert_held_by(&restarted, enrolled, std::slice::from_ref(&route))?;
    Ok(())
}

#[test]
fn a_first_proof_naming_a_collected_roster_is_refused() -> TestResult {
    for collect in [false, true] {
        let mut harness = Harness::new()?;
        let conversation = harness.bind_channel()?;
        // The roster that enrolls a device is replaced before any statement
        // of the conversation names it, so object expiry collects it.
        let enrolled = enroll(&mut harness, ENROLLED)?;
        let enrolling = harness.principal.roster.clone();
        let same = certificates(&harness);
        publish(&mut harness, same)?;
        let collected = if collect {
            expire(&mut harness, PAST_EVERY_WINDOW)?
        } else {
            BTreeSet::new()
        };
        assert_eq!(collected.contains(&enrolled), collect);
        // The device's credential, and so its first proof, names the roster
        // that enrolled it.
        harness.attach_as(ENROLLED)?;
        let current = std::mem::replace(&mut harness.principal.roster, enrolling);
        let proof = harness.leaf_proof(conversation, ENROLLED, ENROLLED_LEAF_SEED, 1)?;
        harness.principal.roster = current;
        let bytes = wire(ArcWireObjectKind::LeafMembershipProof, &proof)?;
        let outcome = harness.run(Op::SubmitMembership, &conversation, Some(&bytes))?;
        let refused = collect.then_some(E2eeReplyCode::BindingAuthInvalid);
        assert_eq!(code(outcome), refused);
    }
    Ok(())
}

#[test]
fn a_deleted_route_row_releases_its_rosters_to_expiry() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let named = roster_object(&harness.principal.roster)?;
    let same = certificates(&harness);
    publish(&mut harness, same)?;
    // The replaced roster is held by the route row alone; the batch that
    // deletes the row retires it at its trusted second.
    let removed_at = PAST_EVERY_WINDOW;
    let mut writes = vec![Write::delete(
        TableId::E2eeState,
        RouteRow::key(&conversation)?,
    )?];
    let staged = harness
        .coordinator
        .stage_owners(
            &mut writes,
            removed_at,
            false,
            super::super::super::STATE_GENERATION,
        )
        .map_err(|code| format!("{code:?}"))?;
    staged.apply(&mut harness.coordinator.state);
    for write in &writes {
        harness.apply_logical_write(write)?;
    }
    let account = harness
        .coordinator
        .state
        .owners
        .account(&named)
        .ok_or("the account")?;
    assert!(account.owners.is_empty());
    assert_eq!(account.retired_at, Some(removed_at));
    let window = removed_at + SEQUENCER_RECORD_RETENTION_SECONDS;
    assert!(!expire(&mut harness, window - 1)?.contains(&named));
    assert!(expire(&mut harness, window)?.contains(&named));
    Ok(())
}

#[test]
fn a_policy_holds_no_roster_that_does_not_verify() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let original = wire(ArcWireObjectKind::DeviceRoster, &harness.principal.roster)?;
    let mut forged = harness.principal.roster.clone();
    let same = certificates(&harness);
    let current = publish(&mut harness, same)?;
    // The store loses the head roster, and a copy whose signature does not
    // verify takes its place.
    let original_key = agenc_relay_storage::e2ee_records::object_key(&object_id(&original))?;
    harness.writes.retain(|write| {
        !matches!(write, Write::Put { table: TableId::E2eeObject, key, .. } if *key == original_key)
    });
    if let Some(byte) = forged.root_signature.first_mut() {
        *byte ^= 1;
    }
    let forged = wire(ArcWireObjectKind::DeviceRoster, &forged)?;
    harness.writes.push(
        crate::e2ee::coordinator::CompanionCoordinator::object_write(&forged)
            .map_err(|code| format!("{code:?}"))?,
    );
    let restarted = harness.reloaded()?;
    // The policies verify under the current roster, the earliest that
    // verifies them, and the route row holds it; the copy that does not
    // verify is held only as the head the binding names.
    let restored = restarted
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?;
    assert_eq!(restored.policies.len(), 2);
    let route = route_key(conversation)?;
    assert_held_by(&restarted, current, &[roster_row(&harness)?, route])?;
    Ok(())
}

#[test]
fn a_statement_of_a_conversation_without_a_route_holds_nothing() -> TestResult {
    use crate::e2ee::coordinator::CompanionCoordinator;
    use agenc_relay_storage::e2ee_records::{SEQUENCER_ROW_KIND, SequencerRow};
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let enrolled = enroll(&mut harness, ENROLLED)?;
    // A batch stores a proof naming the enrolled roster for a conversation
    // that has no route, and one for the bound conversation whose route row
    // the same batch deletes.
    let unrouted = [86; 32];
    let mut writes = Vec::new();
    for (target, leaf) in [(unrouted, 0), (conversation, 1)] {
        let proof = harness.leaf_proof(target, ENROLLED, ENROLLED_LEAF_SEED, leaf)?;
        let bytes = wire(ArcWireObjectKind::LeafMembershipProof, &proof)?;
        writes
            .push(CompanionCoordinator::object_write(&bytes).map_err(|code| format!("{code:?}"))?);
        let row = SequencerRow::Membership {
            object_id: object_id(&bytes),
            epoch: 0,
            device_id: [ENROLLED; 16],
            disposition: 1,
        };
        writes.push(
            crate::e2ee::coordinator::request::state_row(
                TableId::E2eeState,
                SEQUENCER_ROW_KIND,
                SequencerRow::membership_key(&target, leaf, &[leaf.to_le_bytes()[0]; 32])?,
                row.encode()?,
            )
            .map_err(|code| format!("{code:?}"))?,
        );
    }
    writes.push(Write::delete(
        TableId::E2eeState,
        RouteRow::key(&conversation)?,
    )?);
    commit(&mut harness, writes)?;
    let account = harness
        .coordinator
        .state
        .owners
        .account(&enrolled)
        .ok_or("the enrolled roster's account")?;
    assert_eq!(
        account.owners.keys().collect::<Vec<_>>(),
        vec![&roster_row(&harness)?]
    );
    Ok(())
}
