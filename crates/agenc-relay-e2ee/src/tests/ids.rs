#![forbid(unsafe_code)]

//! Semantic identifier tests: domain separation and composite inputs.

use std::error::Error;

use agenc_relay_crypto::SemanticHashDomain;

use super::*;
use crate::objects::sequencing::ArcCommitAckTbs;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn snapshot_hash_accepts_the_published_million_entry_cut() -> TestResult {
    let count = usize::try_from(crate::limits::MAX_FEDERATION_STATE_ENTRIES_PER_EDGE)?;
    let ids = vec![[7; 32]; count];
    let actual = federation_snapshot_digest(17, 23, &ids)?;
    let mut expected = agenc_relay_crypto::Sha256Stream::new();
    expected.update(b"ARC-MLS/1 federation snapshot");
    expected.update(&17_u64.to_be_bytes());
    expected.update(&23_u64.to_be_bytes());
    expected.update(&32_000_000_u32.to_be_bytes());
    for id in &ids {
        expected.update(id);
    }
    assert_eq!(actual, *expected.finish().as_bytes());
    Ok(())
}

#[test]
fn snapshot_iterator_preserves_framing_and_supplied_conversation_order() -> TestResult {
    for count in [0, 1, 255, 256, 257, 4_097] {
        let ids: Vec<_> = (0..count)
            .map(|index| u8::try_from(index % 256).map(|byte| [255 - byte; 32]))
            .collect::<Result<_, _>>()?;
        let mut bytes = 11_u64.to_be_bytes().to_vec();
        bytes.extend_from_slice(&19_u64.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(count * 32)?.to_be_bytes());
        for id in &ids {
            bytes.extend_from_slice(id);
        }
        let expected = semantic_id_over(SemanticHashDomain::FederationSnapshot, &bytes)?;
        assert_eq!(federation_snapshot_digest(11, 19, &ids)?, expected);
        assert_eq!(
            federation_snapshot_digest_iter(11, 19, count, ids.iter())?,
            expected
        );
    }
    let ids = [[9; 32], [1; 32]];
    assert_ne!(
        federation_snapshot_digest(11, 19, &ids)?,
        federation_snapshot_digest_iter(11, 19, 2, ids.iter().rev())?
    );
    Ok(())
}

#[test]
fn snapshot_iterator_refuses_wrong_counts_and_an_over_limit_declaration() {
    let ids = [[9; 32], [1; 32]];
    for count in [0, 1, 3, 1_000_001, usize::MAX] {
        assert_eq!(
            federation_snapshot_digest_iter(11, 19, count, ids.iter()),
            Err(E2eeError::LimitExceeded)
        );
    }
    let visited = std::cell::Cell::new(false);
    let observed = ids.iter().inspect(|_| visited.set(true));
    assert_eq!(
        federation_snapshot_digest_iter(11, 19, 1_000_001, observed),
        Err(E2eeError::LimitExceeded)
    );
    assert!(!visited.get());
}

#[test]
fn snapshot_digest_retains_exact_count_across_bounded_pages() -> TestResult {
    let ids: Vec<_> = (0_u16..513)
        .map(|number| {
            let mut id = [0; 32];
            id[..2].copy_from_slice(&number.to_be_bytes());
            id
        })
        .collect();
    let mut manual = 17_u64.to_be_bytes().to_vec();
    manual.extend_from_slice(&23_u64.to_be_bytes());
    manual.extend_from_slice(&16_416_u32.to_be_bytes());
    let mut digest = FederationSnapshotDigest::new(17, 23, ids.len())?;
    for page in ids.chunks(256) {
        for id in page {
            digest.push(id)?;
            manual.extend_from_slice(id);
        }
    }
    assert_eq!(digest.push(&[0; 32]), Err(E2eeError::LimitExceeded));
    assert_eq!(
        digest.finish()?,
        semantic_id_over(SemanticHashDomain::FederationSnapshot, &manual)?
    );
    let mut short = FederationSnapshotDigest::new(17, 23, 2)?;
    short.push(&[1; 32])?;
    assert_eq!(short.finish(), Err(E2eeError::LimitExceeded));
    Ok(())
}

#[test]
fn identifiers_differ_by_domain_and_never_cover_signatures() -> TestResult {
    let tbs = ArcCommitAckTbs {
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
