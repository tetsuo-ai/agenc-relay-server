#![forbid(unsafe_code)]

//! Independent leaf-membership vectors (companion 13.7.3): the proofs that
//! `scripts/generate-e2ee-vectors.py` encodes decode, verify against the
//! generator's root and roster, recompute the recorded identifiers, and
//! follow the admission and signer rules their manifest dispositions name.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use agenc_ircd_crypto::SignatureDomain;
use agenc_ircd_e2ee::identity::{
    VerifiedRoot, VerifiedRoster, verify_root_identity, verify_roster,
};
use agenc_ircd_e2ee::membership::{
    AdmissionRefusal, LeafMembershipSet, MembershipRefusal, verify_leaf_membership_proof,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind, ObjectId};
use agenc_ircd_e2ee::objects::identity::{IrcDeviceRoster, IrcRootIdentity};
use agenc_ircd_e2ee::objects::membership::{IrcLeafDispositionKind, IrcLeafMembershipProof};
use agenc_ircd_e2ee::objects::sequencing::IrcCommitAck;
use agenc_ircd_e2ee::{DecodeBudget, TlsDecode};

type TestResult = Result<(), Box<dyn Error>>;

const NETWORK: [u8; 32] = [1; 32];
const CONVERSATION: [u8; 32] = [0x43; 32];

fn vectors(set: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../test-data/vectors/e2ee/{set}"))
}

fn read(set: &str, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(vectors(set).join(name))?)
}

fn hex32(text: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(bytes.as_slice().try_into()?)
}

/// The value of `key` in the recovery manifest entry for `file`.
fn manifest(file: &str, key: &str) -> Result<String, Box<dyn Error>> {
    let text = fs::read_to_string(vectors("recovery").join("manifest.toml"))?;
    let entry = text
        .split("[[vectors]]")
        .find(|entry| entry.contains(&format!("file = \"{file}\"")))
        .ok_or("missing manifest entry")?;
    let line = entry
        .lines()
        .find(|line| line.starts_with(&format!("{key} = ")))
        .ok_or("missing manifest key")?;
    Ok(line
        .trim_start_matches(&format!("{key} = "))
        .trim_matches('"')
        .to_owned())
}

fn anchors() -> Result<(VerifiedRoot, VerifiedRoster), Box<dyn Error>> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let root =
        IrcRootIdentity::decode_exact(&read("identity", "root-generation-0.bin")?, &mut budget)?;
    let root = verify_root_identity(&NETWORK, &root, None)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let roster = IrcDeviceRoster::decode_exact(&read("identity", "roster.bin")?, &mut budget)?;
    let roster = verify_roster(&root, &roster, None)?;
    Ok((root, roster))
}

fn body<T: TlsDecode>(file: &str, kind: IrcWireObjectKind) -> Result<(T, Vec<u8>), Box<dyn Error>> {
    let bytes = read("recovery", file)?;
    assert_eq!(
        bytes.len().to_string(),
        manifest(file, "encoded_length")?,
        "{file}"
    );
    assert_eq!(
        ObjectId::compute(&bytes).as_bytes(),
        &hex32(&manifest(file, "object_id")?)?,
        "{file}"
    );
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = IrcWireObject::decode_kind(&bytes, Some(kind), &mut budget)?;
    Ok((T::decode_exact(object.body(), &mut budget)?, bytes))
}

#[test]
fn generator_membership_proofs_verify_and_recompute_their_identifiers() -> TestResult {
    let (root, roster) = anchors()?;
    let cases = [
        (
            "membership-continuing.bin",
            7_u8,
            0_u32,
            IrcLeafDispositionKind::Continuing,
        ),
        (
            "membership-removed.bin",
            8,
            1,
            IrcLeafDispositionKind::Removed,
        ),
    ];
    for (file, device, leaf, disposition) in cases {
        let (proof, _) =
            body::<IrcLeafMembershipProof>(file, IrcWireObjectKind::LeafMembershipProof)?;
        let verified =
            verify_leaf_membership_proof(&NETWORK, &CONVERSATION, &proof, &root, &roster)
                .map_err(|refusal| format!("{file}: {refusal:?}"))?;
        assert_eq!(
            verified.leaf_membership_id,
            hex32(&manifest(file, "leaf_membership_id")?)?,
            "{file}"
        );
        assert_eq!(verified.device_id, [device; 16], "{file}");
        assert_eq!(verified.leaf_index, leaf, "{file}");
        assert_eq!(verified.disposition, disposition, "{file}");
        assert_eq!(verified.epoch, 3, "{file}");
    }
    Ok(())
}

#[test]
fn generator_rejection_vectors_are_refused_for_their_stated_reason() -> TestResult {
    let (root, roster) = anchors()?;
    let (revoked, _) = body::<IrcLeafMembershipProof>(
        "reject-revoked-device.bin",
        IrcWireObjectKind::LeafMembershipProof,
    )?;
    assert_eq!(
        verify_leaf_membership_proof(&NETWORK, &CONVERSATION, &revoked, &root, &roster).err(),
        Some(MembershipRefusal::DeviceInactive)
    );
    let (continuing, continuing_bytes) = body::<IrcLeafMembershipProof>(
        "membership-continuing.bin",
        IrcWireObjectKind::LeafMembershipProof,
    )?;
    let continuing =
        verify_leaf_membership_proof(&NETWORK, &CONVERSATION, &continuing, &root, &roster)
            .map_err(|refusal| format!("{refusal:?}"))?;
    let mut set = LeafMembershipSet::default();
    set.insert(*ObjectId::compute(&continuing_bytes).as_bytes(), continuing);
    let (duplicate, duplicate_bytes) = body::<IrcLeafMembershipProof>(
        "reject-duplicate-continuing-leaf.bin",
        IrcWireObjectKind::LeafMembershipProof,
    )?;
    let duplicate =
        verify_leaf_membership_proof(&NETWORK, &CONVERSATION, &duplicate, &root, &roster)
            .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(
        set.admit(ObjectId::compute(&duplicate_bytes).as_bytes(), &duplicate),
        Err(AdmissionRefusal::Conflict)
    );
    // The ACK names leaf 3, for which no continuing proof is stored.
    let (ack, _) = body::<IrcCommitAck>(
        "commit-ack-without-membership.bin",
        IrcWireObjectKind::CommitAck,
    )?;
    assert!(
        set.signer(
            ack.tbs.old_leaf_index,
            &ack.tbs.old_credential_hash,
            ack.tbs.prior_epoch
        )
        .is_none()
    );
    // The stored leaf-0 proof identifies its own leaf, and only its key
    // verifies a signature under the registered ACK label.
    let signer = set
        .signer(0, &continuing_old_credential(&set)?, ack.tbs.prior_epoch)
        .ok_or("leaf 0 signer")?;
    assert!(
        signer
            .proof
            .verify_leaf_signature(
                SignatureDomain::CommitProcessed,
                &ack.tbs,
                ack.old_leaf_signature.as_slice()
            )
            .is_err()
    );
    Ok(())
}

fn continuing_old_credential(set: &LeafMembershipSet) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(set
        .iter()
        .find(|entry| entry.proof.leaf_index == 0)
        .ok_or("leaf 0")?
        .proof
        .old_credential_hash)
}

#[test]
fn a_tampered_generator_proof_is_refused() -> TestResult {
    let (root, roster) = anchors()?;
    let (proof, _) = body::<IrcLeafMembershipProof>(
        "membership-continuing.bin",
        IrcWireObjectKind::LeafMembershipProof,
    )?;
    let mut device = proof.clone();
    if let Some(byte) = device.device_signature.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(
        verify_leaf_membership_proof(&NETWORK, &CONVERSATION, &device, &root, &roster).err(),
        Some(MembershipRefusal::SignatureInvalid)
    );
    assert_eq!(
        verify_leaf_membership_proof(&NETWORK, &[0x44; 32], &proof, &root, &roster).err(),
        Some(MembershipRefusal::Invalid)
    );
    Ok(())
}
