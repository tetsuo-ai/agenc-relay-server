#![forbid(unsafe_code)]

//! The retained leaf-membership set (companion 13.7.3): replacement,
//! duplicate and conflicting leaves, the authenticated quota, signer
//! lookup, and the expected ReInit continuing set.

use std::error::Error;

use super::*;
use crate::limits::MAX_GROUP_LEAVES;

type TestResult = Result<(), Box<dyn Error>>;

fn proof(
    leaf: u32,
    credential: u8,
    device: u8,
    epoch: u64,
    continuing: bool,
) -> VerifiedLeafMembership {
    VerifiedLeafMembership {
        leaf_membership_id: [leaf.to_be_bytes()[3]; 32],
        conversation_id: [3; 32],
        epoch,
        leaf_index: leaf,
        old_credential_hash: [credential; 32],
        leaf_key: [credential; 32],
        account_id: [b'a'; 24],
        root_fingerprint: [4; 32],
        device_id: [device; 16],
        roster_generation: 0,
        roster_id: [5; 32],
        disposition: if continuing {
            IrcLeafDispositionKind::Continuing
        } else {
            IrcLeafDispositionKind::Removed
        },
        removal_finalization_id: if continuing { [0; 32] } else { [6; 32] },
    }
}

fn object(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[test]
fn a_leaf_is_replaced_only_by_the_same_device_at_a_higher_epoch() -> TestResult {
    let mut set = LeafMembershipSet::default();
    let first = proof(0, 1, 7, 2, true);
    assert_eq!(set.admit(&object(1), &first), Ok(Admission::Stored));
    set.insert(object(1), first.clone());
    assert_eq!(set.admit(&object(1), &first), Ok(Admission::Unchanged));
    // A differing proof at the same epoch, an earlier epoch, or another
    // device's claim on the same leaf is a conflict.
    assert_eq!(
        set.admit(&object(2), &proof(0, 1, 7, 2, false)),
        Err(AdmissionRefusal::Conflict)
    );
    assert_eq!(
        set.admit(&object(3), &proof(0, 1, 7, 1, true)),
        Err(AdmissionRefusal::Conflict)
    );
    assert_eq!(
        set.admit(&object(4), &proof(0, 1, 8, 3, true)),
        Err(AdmissionRefusal::Conflict)
    );
    // A later removed proof from the same device replaces the leaf.
    let removed = proof(0, 1, 7, 3, false);
    assert_eq!(set.admit(&object(5), &removed), Ok(Admission::Stored));
    set.insert(object(5), removed);
    assert_eq!(set.len(), 1);
    assert!(set.signer(0, &[1; 32], 9).is_none());
    assert!(set.expected_continuing(|_, _| true).is_empty());
    Ok(())
}

#[test]
fn one_device_holds_at_most_one_continuing_leaf_per_epoch() -> TestResult {
    let mut set = LeafMembershipSet::default();
    set.insert(object(1), proof(0, 1, 7, 2, true));
    assert_eq!(
        set.admit(&object(2), &proof(1, 2, 7, 2, true)),
        Err(AdmissionRefusal::Conflict)
    );
    // Another epoch, or a removed proof, is not a duplicate continuing leaf.
    assert_eq!(
        set.admit(&object(3), &proof(1, 2, 7, 3, true)),
        Ok(Admission::Stored)
    );
    assert_eq!(
        set.admit(&object(4), &proof(1, 2, 7, 2, false)),
        Ok(Admission::Stored)
    );
    // Another device at the same epoch is independent.
    assert_eq!(
        set.admit(&object(5), &proof(1, 2, 8, 2, true)),
        Ok(Admission::Stored)
    );
    Ok(())
}

#[test]
fn the_quota_bounds_new_leaves_but_not_replacements() -> TestResult {
    let mut set = LeafMembershipSet::default();
    let leaves = usize::try_from(MAX_GROUP_LEAVES)?;
    for stored in 0..MAX_RETAINED_LEAF_MEMBERSHIPS {
        // Two credentials per possible leaf fill the quota exactly.
        let leaf = u32::try_from(stored % leaves)?;
        let credential = u8::try_from(stored / leaves)?;
        let device = u8::try_from(stored % 250)?;
        let mut id = [0; 32];
        if let Some(prefix) = id.get_mut(..8) {
            prefix.copy_from_slice(&u64::try_from(stored)?.to_be_bytes());
        }
        set.insert(id, proof(leaf, credential, device, 0, false));
    }
    assert_eq!(set.len(), MAX_RETAINED_LEAF_MEMBERSHIPS);
    assert_eq!(
        set.admit(&object(9), &proof(7, 250, 250, 0, true)),
        Err(AdmissionRefusal::QuotaExceeded)
    );
    // Replacing a retained leaf at a higher epoch is still admitted.
    assert_eq!(
        set.admit(&object(9), &proof(0, 0, 0, 1, false)),
        Ok(Admission::Stored)
    );
    Ok(())
}

#[test]
fn a_signer_is_a_continuing_proof_no_later_than_the_prior_epoch() -> TestResult {
    let mut set = LeafMembershipSet::default();
    set.insert(object(1), proof(0, 1, 7, 2, true));
    set.insert(object(2), proof(1, 2, 8, 2, false));
    assert_eq!(
        set.signer(0, &[1; 32], 2).map(|entry| entry.object_id),
        Some(object(1))
    );
    assert_eq!(
        set.signer(0, &[1; 32], 5).map(|entry| entry.object_id),
        Some(object(1))
    );
    assert!(
        set.signer(0, &[1; 32], 1).is_none(),
        "a later proof names no earlier signer"
    );
    assert!(set.signer(0, &[9; 32], 2).is_none(), "another credential");
    assert!(set.signer(2, &[1; 32], 2).is_none(), "another leaf");
    assert!(set.signer(1, &[2; 32], 2).is_none(), "a removed leaf");
    Ok(())
}

#[test]
fn one_device_states_one_claim_at_the_highest_epoch_it_reached() -> TestResult {
    let mut set = LeafMembershipSet::default();
    // Device 7 rotated its leaf key: both credentials stay retained under
    // leaf 0, and only the higher epoch is still claimed.
    set.insert(object(1), proof(0, 1, 7, 2, true));
    set.insert(object(2), proof(0, 9, 7, 5, true));
    // Device 8 continues at the only epoch it reached.
    set.insert(object(3), proof(1, 2, 8, 3, true));
    // Device 9 continues at leaf 2 but stated its own removal of leaf 3
    // later, so it claims nothing at all.
    set.insert(object(4), proof(2, 3, 9, 1, true));
    set.insert(object(5), proof(3, 4, 9, 4, false));
    let claimed = |active: fn(&[u8; 24], &[u8; 16]) -> bool| -> Vec<(u32, u8, u64)> {
        set.expected_continuing(active)
            .iter()
            .map(|entry| {
                (
                    entry.proof.leaf_index,
                    entry.proof.old_credential_hash[0],
                    entry.proof.epoch,
                )
            })
            .collect()
    };
    assert_eq!(claimed(|_, _| true), vec![(0, 9, 5), (1, 2, 3)]);
    // A superseded credential still identifies the ACKs of its own epoch.
    assert_eq!(
        set.signer(0, &[1; 32], 2).map(|entry| entry.object_id),
        Some(object(1))
    );
    // A revoked device states no claim.
    assert_eq!(claimed(|_, device| *device != [8; 16]), vec![(0, 9, 5)]);
    Ok(())
}

mod verification {
    use super::*;
    use crate::identity::{verify_root_identity, verify_roster};
    use crate::objects::membership::IrcLeafMembershipProofTbs;
    use crate::signature::RoleKey;
    use crate::test_support::{
        NETWORK, Principal, key, principal, public, root_fingerprint, roster_id, sign,
    };
    use crate::tls::Opaque;

    const CONVERSATION: [u8; 32] = [3; 32];
    const DEVICE: u8 = 7;
    const LEAF: u8 = 30;

    fn anchors(principal: &Principal) -> Result<(VerifiedRoot, VerifiedRoster), Box<dyn Error>> {
        let root = verify_root_identity(&NETWORK, &principal.root, None)?;
        let roster = verify_roster(&root, &principal.roster, None)?;
        Ok((root, roster))
    }

    fn tbs(principal: &Principal) -> Result<IrcLeafMembershipProofTbs, Box<dyn Error>> {
        Ok(IrcLeafMembershipProofTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: CONVERSATION,
            epoch: 0,
            leaf_index: 0,
            old_credential_hash: [1; 32],
            leaf_signature_scheme: ED25519_LEAF_SIGNATURE_SCHEME,
            leaf_signature_key: Opaque::from_slice(&public(&key(LEAF)))?,
            account_id: principal.root.tbs.account_id.clone(),
            device_id: [DEVICE; 16],
            root_generation: 0,
            root_fingerprint: root_fingerprint(&principal.root)?,
            roster_generation: 0,
            roster_id: roster_id(&principal.roster)?,
            credential_generation: 0,
            disposition: IrcLeafDispositionKind::Continuing,
            removal_finalization_id: [0; 32],
        })
    }

    /// Signs `tbs` with `device`, adding a possession signature by `leaf`
    /// unless the proof is removed.
    fn signed(
        tbs: IrcLeafMembershipProofTbs,
        device: u8,
        leaf: u8,
    ) -> Result<IrcLeafMembershipProof, Box<dyn Error>> {
        let possession = if tbs.disposition == IrcLeafDispositionKind::Continuing {
            sign(&key(leaf), SignatureDomain::LeafMembershipPossession, &tbs)?.to_vec()
        } else {
            Vec::new()
        };
        Ok(IrcLeafMembershipProof {
            device_signature: sign(&key(device), SignatureDomain::LeafMembership, &tbs)?,
            possession_signature: Opaque::new(possession)?,
            tbs,
        })
    }

    #[test]
    fn every_malformed_foreign_or_unsigned_proof_is_refused() -> TestResult {
        let owner = principal(40, &[b'a'; 24], &[DEVICE, 8])?;
        let other = principal(41, &[b'b'; 24], &[DEVICE])?;
        let (root, roster) = anchors(&owner)?;
        let (_, foreign_roster) = anchors(&other)?;
        let verify = |proof: &IrcLeafMembershipProof, roster: &VerifiedRoster| {
            verify_leaf_membership_proof(&NETWORK, &CONVERSATION, proof, &root, roster)
        };
        let base = tbs(&owner)?;
        let valid = signed(base.clone(), DEVICE, LEAF)?;
        assert_eq!(verify(&valid, &roster).map(|proof| proof.leaf_index), Ok(0));
        assert_eq!(
            verify(&valid, &foreign_roster).err(),
            Some(MembershipRefusal::Invalid),
            "a roster of another root"
        );
        let invalid_point = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|candidate| RoleKey::leaf(candidate).is_err())
            .ok_or("an invalid Ed25519 point")?;
        let mut removed = base.clone();
        removed.disposition = IrcLeafDispositionKind::Removed;
        removed.removal_finalization_id = [9; 32];
        assert_eq!(
            verify(&signed(removed.clone(), DEVICE, LEAF)?, &roster).map(|proof| proof.disposition),
            Ok(IrcLeafDispositionKind::Removed)
        );
        type Change = fn(&mut IrcLeafMembershipProofTbs, [u8; 32]) -> Result<(), Box<dyn Error>>;
        let changes: [(&str, Change, MembershipRefusal); 6] = [
            (
                "a leaf beyond the group",
                |tbs, _| {
                    tbs.leaf_index = MAX_GROUP_LEAVES;
                    Ok(())
                },
                MembershipRefusal::Invalid,
            ),
            (
                "a short account",
                |tbs, _| {
                    tbs.account_id = Opaque::new(vec![b'a'; 23])?;
                    Ok(())
                },
                MembershipRefusal::Invalid,
            ),
            (
                "a short leaf key",
                |tbs, _| {
                    tbs.leaf_signature_key = Opaque::new(vec![1; 31])?;
                    Ok(())
                },
                MembershipRefusal::Invalid,
            ),
            (
                "an invalid leaf point",
                |tbs, point| {
                    tbs.leaf_signature_key = Opaque::from_slice(&point)?;
                    Ok(())
                },
                MembershipRefusal::Invalid,
            ),
            (
                "a continuing proof naming a removal",
                |tbs, _| {
                    tbs.removal_finalization_id = [9; 32];
                    Ok(())
                },
                MembershipRefusal::Invalid,
            ),
            (
                "an inactive device",
                |tbs, _| {
                    tbs.device_id = [9; 16];
                    Ok(())
                },
                MembershipRefusal::DeviceInactive,
            ),
        ];
        for (name, change, expected) in changes {
            let mut changed = base.clone();
            change(&mut changed, invalid_point)?;
            assert_eq!(
                verify(&signed(changed, DEVICE, LEAF)?, &roster).err(),
                Some(expected),
                "{name}"
            );
        }
        // Disposition shape: a short possession, a removed proof carrying a
        // possession, and a removed proof naming no finalization.
        let mut short = valid.clone();
        short.possession_signature = Opaque::new(vec![1; 10])?;
        assert_eq!(
            verify(&short, &roster).err(),
            Some(MembershipRefusal::Invalid)
        );
        let mut carried = signed(removed.clone(), DEVICE, LEAF)?;
        carried.possession_signature = valid.possession_signature.clone();
        assert_eq!(
            verify(&carried, &roster).err(),
            Some(MembershipRefusal::Invalid)
        );
        let mut unnamed = removed;
        unnamed.removal_finalization_id = [0; 32];
        assert_eq!(
            verify(&signed(unnamed, DEVICE, LEAF)?, &roster).err(),
            Some(MembershipRefusal::Invalid)
        );
        // Signatures: another device's key, another leaf's possession.
        assert_eq!(
            verify(&signed(base.clone(), 8, LEAF)?, &roster).err(),
            Some(MembershipRefusal::SignatureInvalid)
        );
        assert_eq!(
            verify(&signed(base, DEVICE, 31)?, &roster).err(),
            Some(MembershipRefusal::SignatureInvalid)
        );
        Ok(())
    }

    #[test]
    fn one_device_signs_at_most_one_ack_of_a_set() -> TestResult {
        let owner = principal(40, &[b'a'; 24], &[DEVICE, 8])?;
        let (root, roster) = anchors(&owner)?;
        let mut set = LeafMembershipSet::default();
        for (leaf, device, leaf_key, epoch) in [
            (0_u32, DEVICE, LEAF, 0_u64),
            (1, DEVICE, 31, 1),
            (2, 8, 32, 0),
        ] {
            let mut proof = tbs(&owner)?;
            proof.leaf_index = leaf;
            proof.old_credential_hash = [u8::try_from(leaf)? + 1; 32];
            proof.device_id = [device; 16];
            proof.epoch = epoch;
            proof.leaf_signature_key = Opaque::from_slice(&public(&key(leaf_key)))?;
            let verified = verify_leaf_membership_proof(
                &NETWORK,
                &CONVERSATION,
                &signed(proof, device, leaf_key)?,
                &root,
                &roster,
            )
            .map_err(|refusal| format!("{refusal:?}"))?;
            set.insert([u8::try_from(leaf)?; 32], verified);
        }
        let content = [7_u8; 32];
        let ack = |leaf_key: u8| -> Result<[u8; 64], Box<dyn Error>> {
            Ok(sign(
                &key(leaf_key),
                SignatureDomain::CommitProcessed,
                &content,
            )?)
        };
        let mut signers = BTreeSet::new();
        let first = ack(LEAF)?;
        set.identify_distinct(
            &mut signers,
            0,
            &[1; 32],
            1,
            SignatureDomain::CommitProcessed,
            &content,
            &first,
        )?;
        let other_device = ack(32)?;
        set.identify_distinct(
            &mut signers,
            2,
            &[3; 32],
            1,
            SignatureDomain::CommitProcessed,
            &content,
            &other_device,
        )?;
        let same_device = ack(31)?;
        assert!(
            set.identify_distinct(
                &mut signers,
                1,
                &[2; 32],
                1,
                SignatureDomain::CommitProcessed,
                &content,
                &same_device
            )
            .is_err()
        );
        assert_eq!(signers.len(), 2);
        // A wrong label or key identifies no signer at all.
        let mut fresh = BTreeSet::new();
        assert!(
            set.identify_distinct(
                &mut fresh,
                0,
                &[1; 32],
                1,
                SignatureDomain::ReinitProcessed,
                &content,
                &first
            )
            .is_err()
        );
        assert!(fresh.is_empty());
        Ok(())
    }
}
