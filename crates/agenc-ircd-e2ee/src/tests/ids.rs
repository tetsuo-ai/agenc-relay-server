#![forbid(unsafe_code)]

//! Semantic identifier tests: domain separation and composite inputs.

use std::error::Error;

use agenc_ircd_crypto::SemanticHashDomain;

use super::*;
use crate::objects::sequencing::IrcCommitAckTbs;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn identifiers_differ_by_domain_and_never_cover_signatures() -> TestResult {
    let tbs = IrcCommitAckTbs {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [2; 32],
        prior_epoch: 3,
        candidate_id: [4; 32],
        commit_object_id: [5; 32],
        old_leaf_index: 6,
        old_credential_hash: [7; 32],
        resulting_epoch: 4,
        resulting_group_context_digest: [8; 32],
        resulting_ratchet_tree_digest: [9; 32],
        finalization_authenticator: [10; 32],
    };
    let one = semantic_id_of(SemanticHashDomain::CandidateId, &tbs)?;
    let other = semantic_id_of(SemanticHashDomain::FinalizationId, &tbs)?;
    assert_ne!(one, other);
    let over = semantic_id_over(SemanticHashDomain::CandidateId, &tbs.encode()?)?;
    assert_eq!(one, over);
    let set = proof_set_digest(SemanticHashDomain::AcknowledgementSet, &[tbs.clone(), tbs])?;
    assert_ne!(set, one);
    Ok(())
}

#[test]
fn composite_inputs_are_encoded_as_specified() -> TestResult {
    let network = [3; 32];
    let account = [b'a'; 24];
    let digest = account_id_digest(&network, &account)?;
    let mut manual = Vec::new();
    manual.extend_from_slice(&network);
    manual.push(24);
    manual.extend_from_slice(&account);
    assert_eq!(
        digest,
        semantic_id_over(SemanticHashDomain::AccountId, &manual)?
    );
    assert_eq!(
        account_id_digest(&network, &[]),
        Err(E2eeError::LengthOutOfRange)
    );
    let conversation = conversation_id(&network, &[9; 32])?;
    assert_ne!(conversation, digest);
    let leaf = leaf_signature_key_digest(0x0807, &[1; 32])?;
    let mut leaf_manual = vec![0x08, 0x07, 32];
    leaf_manual.extend_from_slice(&[1; 32]);
    assert_eq!(
        leaf,
        semantic_id_over(SemanticHashDomain::LeafSignatureKey, &leaf_manual)?
    );
    let credential = resulting_leaf_credential_hash(7, &[0, 1, 2])?;
    let mut credential_manual = 7_u32.to_be_bytes().to_vec();
    credential_manual.extend_from_slice(&[0, 1, 2]);
    assert_eq!(
        credential,
        semantic_id_over(
            SemanticHashDomain::ResultingLeafCredential,
            &credential_manual
        )?
    );
    let snapshot = federation_snapshot_digest(5, 1, &[[2; 32], [3; 32]])?;
    let mut snapshot_manual = 5_u64.to_be_bytes().to_vec();
    snapshot_manual.extend_from_slice(&1_u64.to_be_bytes());
    snapshot_manual.extend_from_slice(&64_u32.to_be_bytes());
    snapshot_manual.extend_from_slice(&[2; 32]);
    snapshot_manual.extend_from_slice(&[3; 32]);
    assert_eq!(
        snapshot,
        semantic_id_over(SemanticHashDomain::FederationSnapshot, &snapshot_manual)?
    );
    let name = canonical_channel_name_hash(b"#room")?;
    let key_set = sequencer_key_set_digest(&[[4; 32]])?;
    assert_ne!(name, key_set);
    assert_eq!(
        old_credential_hash(b"cred")?,
        semantic_id_over(SemanticHashDomain::OldCredentialHash, b"cred")?
    );
    assert_eq!(
        initial_commit_digest(b"commit")?,
        semantic_id_over(SemanticHashDomain::ReinitInitialCommit, b"commit")?
    );
    assert_eq!(
        leaf_capabilities_digest(b"caps")?,
        semantic_id_over(SemanticHashDomain::LeafCapabilities, b"caps")?
    );
    Ok(())
}
