#![forbid(unsafe_code)]

//! Welcome and staged ReInit wrappers.

use std::error::Error;

use super::*;
use crate::objects::conversation::{ArcJoinTransitionProofRole, ArcJoinTransitionSubject};
use crate::objects::reinit::{ArcReInitAttemptReceipt, ArcReInitAttemptReceiptTbs};
use crate::objects::sequencing::ArcNormalJoinAuthorizationProof;
use crate::test_support::*;
use crate::tls::{Opaque, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

const CONVERSATION: [u8; 32] = [20; 32];
const REF: [u8; 32] = [4; 32];

fn target() -> WelcomeTarget {
    WelcomeTarget {
        account_id_digest: [40; 32],
        device_id: [7; 16],
    }
}

fn reference(subject_id: u8, role: ArcJoinTransitionProofRole) -> ArcJoinTransitionProofReference {
    ArcJoinTransitionProofReference {
        subject_kind: ArcJoinTransitionSubject::BindingSubject,
        subject_id: [subject_id; 32],
        proof_role: role,
        record_conversation_id: CONVERSATION,
        authorizing_record_id: [50; 32],
        authorizing_object_id: [51; 32],
    }
}

fn bundle() -> Result<ArcJoinTransitionProofBundle, E2eeError> {
    Ok(ArcJoinTransitionProofBundle {
        references: TlsVec::new(vec![
            reference(1, ArcJoinTransitionProofRole::FinalizedGroupTransition),
            reference(2, ArcJoinTransitionProofRole::ReinitTargetAuthorization),
            reference(2, ArcJoinTransitionProofRole::ReinitActivation),
        ])?,
    })
}

fn delivered(welcome_bytes: Vec<u8>) -> Result<ArcDeliveredWelcome, E2eeError> {
    Ok(ArcDeliveredWelcome {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: CONVERSATION,
        target_account_id_digest: [40; 32],
        target_device_id: [7; 16],
        authorization: ArcNormalJoinAuthorizationProof {
            finalization_id: [60; 32],
            finalization_object_id: [61; 32],
            added_key_package_ref: Opaque::new(REF.to_vec())?,
            resulting_leaf_index: 5,
            resulting_leaf_credential_hash: [62; 32],
        },
        transition_proofs: bundle()?,
        welcome_bytes: Opaque::new(welcome_bytes)?,
    })
}

fn staged(welcome_bytes: Vec<u8>) -> Result<ArcStagedReInit, E2eeError> {
    let tbs = ArcReInitAttemptReceiptTbs {
        profile_version: 1,
        network_id: NETWORK,
        old_conversation_id: CONVERSATION,
        old_reinit_state_id: [70; 32],
        route_sequence: 8,
        attempt_sequence: 1,
        predecessor_record_id: [71; 32],
        reinit_attempt_id: [72; 32],
        attempt_object_id: [73; 32],
        sequenced_at: 1_000,
        sequencer_key_id: [74; 32],
    };
    Ok(ArcStagedReInit {
        old_reinit_state_id: [70; 32],
        old_reinit_finalization_object_id: [75; 32],
        receipt: ArcReInitAttemptReceipt {
            tbs,
            sequencer_signature: [0; 64],
        },
        new_conversation_id: [21; 32],
        target_account_id_digest: [40; 32],
        target_device_id: [7; 16],
        transition_proofs: bundle()?,
        welcome_bytes: Opaque::new(welcome_bytes)?,
    })
}

#[test]
fn a_delivered_welcome_must_address_its_target_and_reference() -> TestResult {
    let mut budget = DecodeBudget::new(1 << 22, 1 << 12);
    let good = delivered(welcome_message(&[vec![9; 32], REF.to_vec()])?)?;
    let verified =
        verify_delivered_welcome(&NETWORK, &good, &CONVERSATION, &target(), &mut budget)?;
    assert_eq!(verified.leaf_index, 5);
    assert_eq!(verified.key_package_ref, REF);
    assert_eq!(verified.welcome.new_member_refs.len(), 2);
    assert_eq!(verified.references.len(), 3);
    assert_eq!(verified.finalization_id, [60; 32]);
    let verify = |welcome: &ArcDeliveredWelcome,
                  conversation: &[u8; 32],
                  target: &WelcomeTarget| {
        let mut budget = DecodeBudget::new(1 << 22, 1 << 12);
        verify_delivered_welcome(&NETWORK, welcome, conversation, target, &mut budget).map(|_| ())
    };
    assert_eq!(
        verify(&good, &[1; 32], &target()),
        Err(E2eeError::InvalidValue)
    );
    let other_device = WelcomeTarget {
        device_id: [8; 16],
        ..target()
    };
    assert_eq!(
        verify(&good, &CONVERSATION, &other_device),
        Err(E2eeError::InvalidValue)
    );
    let other_account = WelcomeTarget {
        account_id_digest: [41; 32],
        ..target()
    };
    assert_eq!(
        verify(&good, &CONVERSATION, &other_account),
        Err(E2eeError::InvalidValue)
    );
    let mut wrong_network = good.clone();
    wrong_network.network_id = [2; 32];
    assert_eq!(
        verify(&wrong_network, &CONVERSATION, &target()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut wrong_profile = good.clone();
    wrong_profile.profile_version = 2;
    assert_eq!(
        verify(&wrong_profile, &CONVERSATION, &target()),
        Err(E2eeError::ProfileMismatch)
    );
    let unaddressed = delivered(welcome_message(&[vec![9; 32]])?)?;
    assert_eq!(
        verify(&unaddressed, &CONVERSATION, &target()),
        Err(E2eeError::InvalidValue)
    );
    let not_a_welcome = delivered(private_message_bytes(&[1; 32], 1, &[])?)?;
    assert_eq!(
        verify(&not_a_welcome, &CONVERSATION, &target()),
        Err(E2eeError::WrongKind)
    );
    let mut unsorted = good.clone();
    let mut references = unsorted.transition_proofs.references.as_slice().to_vec();
    references.reverse();
    unsorted.transition_proofs.references = TlsVec::new(references)?;
    assert_eq!(
        verify(&unsorted, &CONVERSATION, &target()),
        Err(E2eeError::NonCanonical)
    );
    let mut duplicate = good;
    let first = reference(1, ArcJoinTransitionProofRole::FinalizedGroupTransition);
    duplicate.transition_proofs.references = TlsVec::new(vec![first.clone(), first])?;
    assert_eq!(
        verify(&duplicate, &CONVERSATION, &target()),
        Err(E2eeError::NonCanonical)
    );
    Ok(())
}

#[test]
fn a_staged_reinit_names_a_new_conversation() -> TestResult {
    let mut budget = DecodeBudget::new(1 << 22, 1 << 12);
    let good = staged(welcome_message(&[REF.to_vec()])?)?;
    let verified = verify_staged_reinit(&NETWORK, &good, &target(), &mut budget)?;
    assert_eq!(verified.old_conversation_id, CONVERSATION);
    assert_eq!(verified.new_conversation_id, [21; 32]);
    assert_eq!(verified.reinit_attempt_id, [72; 32]);
    assert_eq!(verified.references.len(), 3);
    let verify = |staged: &ArcStagedReInit, target: &WelcomeTarget| {
        let mut budget = DecodeBudget::new(1 << 22, 1 << 12);
        verify_staged_reinit(&NETWORK, staged, target, &mut budget).map(|_| ())
    };
    let mut same_conversation = good.clone();
    same_conversation.new_conversation_id = CONVERSATION;
    assert_eq!(
        verify(&same_conversation, &target()),
        Err(E2eeError::InvalidValue)
    );
    let mut mismatched_state = good.clone();
    mismatched_state.old_reinit_state_id = [1; 32];
    assert_eq!(
        verify(&mismatched_state, &target()),
        Err(E2eeError::InvalidValue)
    );
    let other_device = WelcomeTarget {
        device_id: [8; 16],
        ..target()
    };
    assert_eq!(verify(&good, &other_device), Err(E2eeError::InvalidValue));
    let other_account = WelcomeTarget {
        account_id_digest: [41; 32],
        ..target()
    };
    assert_eq!(verify(&good, &other_account), Err(E2eeError::InvalidValue));
    let mut wrong_network = good.clone();
    wrong_network.receipt.tbs.network_id = [2; 32];
    assert_eq!(
        verify(&wrong_network, &target()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut wrong_profile = good;
    wrong_profile.receipt.tbs.profile_version = 3;
    assert_eq!(
        verify(&wrong_profile, &target()),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        verify(
            &staged(private_message_bytes(&[1; 32], 3, &[])?)?,
            &target()
        ),
        Err(E2eeError::WrongKind)
    );
    Ok(())
}

#[test]
fn proof_bundles_are_canonical_and_bounded() -> TestResult {
    assert_eq!(verify_proof_bundle(&bundle()?)?.len(), 3);
    let empty = ArcJoinTransitionProofBundle {
        references: TlsVec::new(Vec::new())?,
    };
    assert_eq!(verify_proof_bundle(&empty)?, Vec::new());
    let per_reference = reference(1, ArcJoinTransitionProofRole::FinalizedGroupTransition)
        .encode()?
        .len();
    let count = (MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES - 3) / per_reference;
    let references = |count: usize| {
        (0..count)
            .map(|index| {
                let mut reference =
                    reference(0, ArcJoinTransitionProofRole::FinalizedGroupTransition);
                reference.subject_id = (index as u64)
                    .to_be_bytes()
                    .repeat(4)
                    .as_slice()
                    .try_into()?;
                Ok(reference)
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()
    };
    let largest = ArcJoinTransitionProofBundle {
        references: TlsVec::new(references(count)?)?,
    };
    assert!(largest.encode()?.len() <= MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES);
    assert_eq!(verify_proof_bundle(&largest)?.len(), count);
    assert_eq!(
        TlsVec::<ArcJoinTransitionProofReference, 0, 262_144>::new(references(count + 1)?)
            .map(|_| ()),
        Err(E2eeError::LengthOutOfRange),
        "the vector bound refuses the {}th reference before the bundle limit applies",
        count + 1
    );
    Ok(())
}
