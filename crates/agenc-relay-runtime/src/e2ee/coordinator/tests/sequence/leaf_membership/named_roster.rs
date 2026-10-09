//! A leaf-membership proof is verified against the retained roster snapshot
//! it names (companion 13.7.3), not against whatever roster the account
//! holds now: a continuing leaf keeps the credential it was authorized
//! under, so after a rotation its proof still names the predecessor. The
//! device must have been active in that named roster and must be
//! roster-active now, for a `continuing` and a `removed` proof alike, and
//! live admission decides exactly as startup reconstruction does.

#![forbid(unsafe_code)]

use super::super::super::support::{Principal, roster, roster_id};
use super::super::super::{ROOT_SEED, support};
use super::finalization::{finalize_both, rotate_roster};
use super::restart::{conversation_of, inject, memberships_of};
use super::*;
use agenc_relay_e2ee::objects::identity::{ArcDeviceRoster, ArcRootIdentity};

/// A third device of the principal, which publishes no proof of its own.
const THIRD_DEVICE: u8 = 9;

/// One root of the harness principal's account: its signing seed and its
/// identity.
struct AccountRoot {
    seed: u8,
    root: ArcRootIdentity,
}

impl AccountRoot {
    /// The principal's root at binding time.
    fn original(harness: &Harness) -> Self {
        Self {
            seed: ROOT_SEED,
            root: harness.principal.root.clone(),
        }
    }

    /// Publishes a continuous rotation of the principal's root to generation
    /// one (companion 8.2) and returns the new root.
    fn rotated(harness: &mut Harness) -> TestResult<Self> {
        let seed = ROOT_SEED + 1;
        let root = support::root(
            &support::key(seed),
            &harness.account,
            1,
            (0, 2_000_000),
            Some((&harness.principal.root_secret, &harness.principal.root)),
        )?;
        let bytes = wire(ArcWireObjectKind::RootIdentity, &root)?;
        ok(harness.run(Op::PublishIdentity, &[], Some(&bytes))?)?;
        Ok(Self { seed, root })
    }

    /// This root's roster `generation` following `previous` with only the
    /// `kept` devices active, signed but not published. Under the root that
    /// signed `previous`, it continues `previous` and each kept device keeps
    /// the certificate `previous` lists: a certificate continues unchanged,
    /// and a device a roster dropped was revoked there and never returns
    /// under that root, which uses a Device ID once (companion 8.3 and 8.4).
    /// The first roster of a rotated root starts that root's own lineage with
    /// an all-zero predecessor (companion 14) and issues every kept device a
    /// fresh certificate for `generation` (companion 8.2), which is how a
    /// device dropped under the old root becomes roster-active again
    /// (companion 13.7.3).
    fn successor(
        &self,
        generation: u64,
        previous: &ArcDeviceRoster,
        kept: &[u8],
    ) -> TestResult<ArcDeviceRoster> {
        let secret = support::key(self.seed);
        let continued = previous.tbs.root_fingerprint == support::root_fingerprint(&self.root)?;
        let held = previous.tbs.active_devices.as_slice();
        let mut certificates = kept
            .iter()
            .map(|seed| -> TestResult<_> {
                if continued {
                    let entry = held
                        .iter()
                        .find(|entry| entry.device_id == [*seed; 16])
                        .ok_or("under one root a dropped device never returns")?;
                    Ok(entry.certificate.clone())
                } else {
                    let mut device = support::DeviceSpec::new(*seed);
                    device.target_roster_generation = generation;
                    Ok(support::certificate(&secret, &self.root, &device)?)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        certificates.sort_by_key(|certificate| certificate.tbs.device_id);
        let previous_id = if continued {
            roster_id(previous)?
        } else {
            [0; 32]
        };
        Ok(roster(
            &secret,
            &self.root,
            generation,
            previous_id,
            (100, 100 + 6 * 24 * 3600),
            certificates,
            Vec::new(),
        )?)
    }

    /// The harness principal under this root, its statements naming `named`.
    fn naming(&self, harness: &Harness, named: &ArcDeviceRoster) -> Principal {
        Principal {
            root_secret: support::key(self.seed),
            root: self.root.clone(),
            roster: named.clone(),
            devices: harness.principal.devices.clone(),
        }
    }
}

/// Publishes `next` as the account's roster head.
fn publish(harness: &mut Harness, next: &ArcDeviceRoster) -> TestResult {
    let bytes = wire(ArcWireObjectKind::DeviceRoster, next)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    Ok(())
}

/// The devices whose claims continue while the directory still lists them.
fn continuing_devices(harness: &Harness, conversation: [u8; 32]) -> TestResult<Vec<[u8; 16]>> {
    let directory = &harness.coordinator.state.directory;
    let active = |account: &[u8; 24], device: &[u8; 16]| {
        agenc_relay_e2ee::ids::account_id_digest(&NETWORK, account)
            .ok()
            .and_then(|digest| directory.account(&digest))
            .is_some_and(|entry| entry.device_active(device))
    };
    Ok(conversation_of(harness, conversation)?
        .memberships
        .expected_continuing(active)
        .into_iter()
        .map(|entry| entry.proof.device_id)
        .collect())
}

#[test]
fn a_conforming_proof_naming_a_predecessor_roster_is_admitted() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // The account publishes its next complete roster with both devices
    // still active, as every roster proposal makes it do.
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    harness.attach_as(SECOND_DEVICE)?;
    // Device 8 proves the leaf it has held since generation zero: its
    // credential, and so its proof, names the generation-zero roster.
    let proof = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    let outcome = harness.run(
        Op::SubmitMembership,
        &conversation,
        Some(&proof_bytes(&proof)?),
    )?;
    assert_eq!(
        code(outcome),
        None,
        "a proof naming the retained predecessor roster must be admitted (companion 13.7.3)"
    );
    let stored: Vec<_> = conversation_of(&harness, conversation)?
        .memberships
        .iter()
        .map(|entry| (entry.proof.leaf_index, entry.proof.roster_generation))
        .collect();
    assert_eq!(stored, vec![(0, 0), (1, 0)]);
    Ok(())
}

#[test]
fn a_proof_naming_a_roster_that_was_never_retained_is_refused() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    harness.attach_as(SECOND_DEVICE)?;
    // The root signed this roster, but the server never retained it.
    let original = AccountRoot::original(&harness);
    let unpublished = original.successor(1, &harness.principal.roster, &[DEVICE, SECOND_DEVICE])?;
    let signer = original.naming(&harness, &unpublished);
    let spec =
        MembershipSpec::continuing(&signer, conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1);
    let never = proof_bytes(&membership_proof(&spec)?)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &never,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // Publishing it retains it, and the same bytes are then admitted.
    publish(&mut harness, &unpublished)?;
    ok(harness.run(Op::SubmitMembership, &conversation, Some(&never))?)?;
    Ok(())
}

#[test]
fn a_proof_naming_another_accounts_retained_roster_is_refused() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // Another account's roster is retained and indexed by the same server.
    let home = harness
        .coordinator
        .state
        .origins
        .get(&origin_key())
        .map(|origin| (origin.account_id, origin.account_digest))
        .ok_or("origin")?;
    attach_outsider(&mut harness)?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key()) {
        (origin.account_id, origin.account_digest) = home;
        origin.device = None;
    }
    harness.attach_as(SECOND_DEVICE)?;
    // Device 8 of the bound account names the outsider's retained roster.
    let foreign = harness
        .coordinator
        .state
        .principals
        .values()
        .map(|(_, roster)| roster.roster_id)
        .find(|id| roster_id(&harness.principal.roster).ok().as_ref() != Some(id))
        .ok_or("the outsider's roster head")?;
    let mut proof = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    proof.tbs.roster_id = foreign;
    resign(&mut proof, SECOND_DEVICE, SECOND_LEAF_SEED)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&proof)?,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn a_proof_naming_a_retained_roster_without_its_device_is_refused() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // Generation one drops device 8, revoking it under the original root,
    // and the rotated root's first roster, its generation zero, issues it a
    // new certificate, so it is roster-active now but was never active in
    // the original root's generation one.
    let original = AccountRoot::original(&harness);
    let without = original.successor(1, &harness.principal.roster, &[DEVICE])?;
    publish(&mut harness, &without)?;
    let rotated = AccountRoot::rotated(&mut harness)?;
    let restored = rotated.successor(0, &without, &[DEVICE, SECOND_DEVICE])?;
    publish(&mut harness, &restored)?;
    harness.attach_as(SECOND_DEVICE)?;
    let signer = original.naming(&harness, &without);
    let spec =
        MembershipSpec::continuing(&signer, conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1);
    let absent = proof_bytes(&membership_proof(&spec)?)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &absent,
        E2eeReplyCode::DeviceRequired,
    )?;
    // The roster it was active in, and the one it is active in now, both admit it.
    let held = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &held)?;
    Ok(())
}

#[test]
fn a_roster_active_device_states_removed_under_its_predecessor_roster() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let removal = finalize_both(&mut harness, conversation)?;
    rotate_roster(&mut harness, &[DEVICE, SECOND_DEVICE])?;
    harness.attach_as(SECOND_DEVICE)?;
    assert_eq!(
        continuing_devices(&harness, conversation)?,
        vec![DEVICE_ID, [SECOND_DEVICE; 16]]
    );
    // Its leaf is gone after the retained finalization; the credential that
    // held the leaf was authorized under generation zero.
    let mut removed = MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        SECOND_LEAF_SEED,
        1,
    );
    removed.epoch = 1;
    removed.removed = Some(removal);
    harness.publish_membership(conversation, &membership_proof(&removed)?)?;
    assert_eq!(continuing_devices(&harness, conversation)?, vec![DEVICE_ID]);
    Ok(())
}

#[test]
fn a_revoked_device_states_no_removed_proof_and_is_not_expected() -> TestResult {
    let (mut harness, conversation) = two_member_channel()?;
    let removal = finalize_both(&mut harness, conversation)?;
    harness.attach_as(SECOND_DEVICE)?;
    // The successor roster revokes device 8 while its origin still names it.
    rotate_roster(&mut harness, &[DEVICE])?;
    let mut removed = MembershipSpec::continuing(
        &harness.principal,
        conversation,
        SECOND_DEVICE,
        SECOND_LEAF_SEED,
        1,
    );
    removed.epoch = 1;
    removed.removed = Some(removal);
    let stated = proof_bytes(&membership_proof(&removed)?)?;
    // It was active in the roster the proof names, but it is revoked now.
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &stated,
        E2eeReplyCode::DeviceRequired,
    )?;
    // Revocation already took its claim out of the expected set.
    assert_eq!(continuing_devices(&harness, conversation)?, vec![DEVICE_ID]);
    Ok(())
}

#[test]
fn live_admission_and_reconstruction_agree_on_the_named_roster() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE, THIRD_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // Generation one drops devices 8 and 9; the rotated root's first
    // roster returns them, and its next one is never published.
    let original = AccountRoot::original(&harness);
    let without = original.successor(1, &harness.principal.roster, &[DEVICE])?;
    publish(&mut harness, &without)?;
    let everyone = [DEVICE, SECOND_DEVICE, THIRD_DEVICE];
    let rotated = AccountRoot::rotated(&mut harness)?;
    let restored = rotated.successor(0, &without, &everyone)?;
    publish(&mut harness, &restored)?;
    let unpublished = rotated.successor(1, &restored, &everyone)?;
    // Admitted live: device 8 names the retained generation-zero roster.
    harness.attach_as(SECOND_DEVICE)?;
    let held = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &held)?;
    // Refused live: device 9 names a roster that was never retained, and a
    // retained roster in which it was not active.
    harness.attach_as(THIRD_DEVICE)?;
    let signer = rotated.naming(&harness, &unpublished);
    let never = membership_proof(&MembershipSpec::continuing(
        &signer,
        conversation,
        THIRD_DEVICE,
        32,
        2,
    ))?;
    let signer = original.naming(&harness, &without);
    let inactive = membership_proof(&MembershipSpec::continuing(
        &signer,
        conversation,
        THIRD_DEVICE,
        33,
        3,
    ))?;
    for (proof, expected) in [
        (&never, E2eeReplyCode::BindingAuthInvalid),
        (&inactive, E2eeReplyCode::DeviceRequired),
    ] {
        refused(
            &mut harness,
            Op::SubmitMembership,
            &conversation,
            &proof_bytes(proof)?,
            expected,
        )?;
    }
    let live = conversation_of(&harness, conversation)?.memberships.clone();
    assert_eq!(
        memberships_of(&harness, conversation)?,
        vec![(0, true), (1, true)]
    );
    // A reload restores exactly what live admission stored.
    assert_eq!(
        conversation_of(&harness.reloaded()?, conversation)?.memberships,
        live
    );
    // Rows for the two refused proofs restore nothing: reconstruction
    // resolves the named roster from the same retained snapshots.
    inject(&mut harness, conversation, &never, 1)?;
    inject(&mut harness, conversation, &inactive, 1)?;
    assert_eq!(
        conversation_of(&harness.reloaded()?, conversation)?.memberships,
        live
    );
    // A reloaded coordinator admits and refuses the same inputs live.
    let mut reloaded = harness.reloaded()?;
    reloaded.attach_as(THIRD_DEVICE)?;
    for (proof, expected) in [
        (&never, E2eeReplyCode::BindingAuthInvalid),
        (&inactive, E2eeReplyCode::DeviceRequired),
    ] {
        refused(
            &mut reloaded,
            Op::SubmitMembership,
            &conversation,
            &proof_bytes(proof)?,
            expected,
        )?;
    }
    let third = reloaded.leaf_proof(conversation, THIRD_DEVICE, 34, 4)?;
    reloaded.publish_membership(conversation, &third)?;
    Ok(())
}

#[test]
fn a_proof_naming_a_predecessor_root_is_admitted_and_survives_a_reload() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    let conversation = harness.bind_channel()?;
    // A continuous root rotation reissues both certificates under the new
    // root; the device keys, and the leaves they authorized, are unchanged.
    let secret = support::key(ROOT_SEED + 1);
    let root = support::root(
        &secret,
        &harness.account,
        1,
        (0, 2_000_000),
        Some((&harness.principal.root_secret, &harness.principal.root)),
    )?;
    let bytes = wire(ArcWireObjectKind::RootIdentity, &root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&bytes))?)?;
    let certificates = [DEVICE, SECOND_DEVICE]
        .into_iter()
        .map(|seed| support::certificate(&secret, &root, &support::DeviceSpec::new(seed)))
        .collect::<Result<Vec<_>, _>>()?;
    // The continued root's first roster starts its own lineage at generation
    // zero (companion 14).
    let next = roster(
        &secret,
        &root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    publish(&mut harness, &next)?;
    harness.attach_as(SECOND_DEVICE)?;
    // The proof names the generation-zero root and roster of its credential.
    let held = harness.leaf_proof(conversation, SECOND_DEVICE, SECOND_LEAF_SEED, 1)?;
    harness.publish_membership(conversation, &held)?;
    // A root the account never held resolves nothing.
    let mut stranger = harness.leaf_proof(conversation, SECOND_DEVICE, 35, 5)?;
    stranger.tbs.root_fingerprint = [77; 32];
    resign(&mut stranger, SECOND_DEVICE, 35)?;
    refused(
        &mut harness,
        Op::SubmitMembership,
        &conversation,
        &proof_bytes(&stranger)?,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    assert_eq!(
        conversation_of(&harness.reloaded()?, conversation)?.memberships,
        conversation_of(&harness, conversation)?.memberships
    );
    Ok(())
}
