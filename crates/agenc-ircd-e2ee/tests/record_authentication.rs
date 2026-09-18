#![forbid(unsafe_code)]
//! Public record ordering is authenticated independently of endpoint finality.

#[path = "record_authentication/shapes.rs"]
mod shapes;
#[path = "record_authentication/support.rs"]
mod support;

use agenc_ircd_crypto::{Ed25519SecretKey, SignatureDomain};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind, ObjectId};
use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
use agenc_ircd_e2ee::record_authentication::{authenticate_record, declared_sequenced_at};
use agenc_ircd_e2ee::{DecodeBudget, E2eeError, TlsEncode};
use support::{Case, KINDS, TestResult};

#[test]
fn every_record_arm_authenticates_its_registered_signature_and_semantic_id() -> TestResult {
    for kind in KINDS {
        let case = Case::new(kind)?;
        let authenticated = case.authenticate()?;
        assert_eq!(authenticated.semantic_id(), &case.semantic_id()?);
        assert_eq!(
            authenticated.object_id(),
            &ObjectId::compute(&case.bytes()?)
        );
    }
    Ok(())
}

/// A receipt states its own sequencing second; a terminal certificate
/// states the second of the receipt it embeds, the only signed time it
/// carries (companion 12.5.1 reads it for the successor overlap window).
#[test]
fn every_record_arm_states_the_sequencing_second_it_signed() -> TestResult {
    for kind in KINDS {
        let case = Case::new(kind)?;
        let expected = match kind {
            support::Kind::CandidateRecord
            | support::Kind::FinalizationRecord
            | support::Kind::AbortRecord => 7,
            support::Kind::ReinitAttemptRecord
            | support::Kind::ReinitActivationRecord
            | support::Kind::ReinitAbortRecord => 8,
        };
        assert_eq!(declared_sequenced_at(&case.record), expected, "{kind:?}");
    }
    Ok(())
}

#[test]
fn historical_context_must_match_every_outer_position_field() -> TestResult {
    let changes: [fn(&mut support::ExpectedRecord); 5] = [
        |expected| expected.network_id = [2; 32],
        |expected| expected.conversation_id = [21; 32],
        |expected| expected.route_sequence = 77,
        |expected| expected.predecessor_record_id = [99; 32],
        |expected| expected.sequencer_credential_id = [100; 32],
    ];
    for kind in KINDS {
        for change in changes {
            let mut case = Case::new(kind)?;
            case.authenticate()?;
            change(&mut case.expected);
            assert_eq!(
                case.authenticate(),
                Err(E2eeError::ProfileMismatch),
                "{kind:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn each_arm_rejects_every_other_sequencer_record_signature_domain() -> TestResult {
    let domains = [
        SignatureDomain::CandidateReceipt,
        SignatureDomain::CommitFinalization,
        SignatureDomain::CandidateAbort,
        SignatureDomain::ReinitAttemptReceipt,
        SignatureDomain::ReinitActivation,
        SignatureDomain::ReinitAttemptAbort,
    ];
    for kind in KINDS {
        for domain in domains {
            let mut case = Case::new(kind)?;
            if domain == case.domain() {
                continue;
            }
            case.sign_as(domain, &Ed25519SecretKey::from_bytes([60; 32]))?;
            assert_eq!(
                case.authenticate(),
                Err(E2eeError::SignatureInvalid),
                "{kind:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_different_key_cannot_sign_under_the_committed_credential_id() -> TestResult {
    for kind in KINDS {
        let mut case = Case::new(kind)?;
        case.sign_as(case.domain(), &Ed25519SecretKey::from_bytes([61; 32]))?;
        assert_eq!(
            case.authenticate(),
            Err(E2eeError::SignatureInvalid),
            "{kind:?}"
        );
    }
    Ok(())
}

#[test]
fn a_different_credential_is_rejected_even_when_its_public_key_is_the_same() -> TestResult {
    for kind in KINDS {
        let mut case = Case::new(kind)?;
        case.credential.credential_id = [101; 32];
        assert_eq!(case.authenticate(), Err(E2eeError::ProfileMismatch));
    }
    Ok(())
}

#[test]
fn a_real_signature_does_not_authorize_another_profile_version() -> TestResult {
    for kind in KINDS {
        let mut case = Case::new(kind)?;
        *case.outer_profile() = 2;
        case.resign()?;
        assert_eq!(case.authenticate(), Err(E2eeError::ProfileMismatch));
    }
    Ok(())
}

#[test]
fn terminal_ids_are_recomputed_after_sequencer_signature_verification() -> TestResult {
    for kind in support::TERMINALS {
        let mut case = Case::new(kind)?;
        *case.asserted_id()? = [102; 32];
        case.resign()?;
        assert_eq!(case.authenticate(), Err(E2eeError::InvalidValue));
    }
    Ok(())
}

#[test]
fn a_recomputed_terminal_id_cannot_hide_another_core_context() -> TestResult {
    for kind in support::TERMINALS {
        for field in 0..3 {
            let mut case = Case::new(kind)?;
            let (profile, network, conversation) = case.core_context()?;
            match field {
                0 => *profile = 2,
                1 => *network = [2; 32],
                _ => *conversation = [21; 32],
            }
            case.refresh_terminal_id()?;
            case.resign()?;
            assert_eq!(case.authenticate(), Err(E2eeError::ProfileMismatch));
        }
    }
    Ok(())
}

#[test]
fn an_attempt_receipt_requires_its_exact_complete_attempt_object() -> TestResult {
    let case = Case::new(support::Kind::ReinitAttemptRecord)?;
    let bytes = case.bytes()?;
    assert_eq!(
        authenticate_record(
            &bytes,
            None,
            &case.expected,
            &case.credential,
            &mut support::budget()
        ),
        Err(E2eeError::InvalidValue)
    );
    let mut other = case.attempt.clone().ok_or("attempt")?;
    other.initial_commit_bytes = agenc_ircd_e2ee::Opaque::new(vec![1; 100])?;
    let other = support::object(IrcWireObjectKind::ReinitAttempt, &other)?;
    assert_eq!(
        authenticate_record(
            &bytes,
            Some(&other),
            &case.expected,
            &case.credential,
            &mut support::budget()
        ),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_rebound_attempt_object_must_still_match_the_signed_receipt_context() -> TestResult {
    for field in 0..6 {
        let mut case = Case::new(support::Kind::ReinitAttemptRecord)?;
        let attempt = case.attempt.as_mut().ok_or("attempt")?;
        match field {
            0 => attempt.tbs.profile_version = 2,
            1 => attempt.tbs.network_id = [2; 32],
            2 => attempt.tbs.old_conversation_id = [21; 32],
            3 => attempt.tbs.old_reinit_state_id = [103; 32],
            4 => attempt.tbs.attempt_sequence = 3,
            _ => attempt.tbs.target_context_digest = [104; 32],
        }
        case.refresh_attempt_object_id()?;
        case.resign()?;
        assert!(case.authenticate().is_err(), "attempt field {field}");
    }
    Ok(())
}

#[test]
fn unused_attempt_evidence_is_rejected_for_every_other_arm() -> TestResult {
    let attempt = support::object(IrcWireObjectKind::ReinitAttempt, &shapes::reinit_attempt()?)?;
    for kind in KINDS {
        if kind == support::Kind::ReinitAttemptRecord {
            continue;
        }
        let case = Case::new(kind)?;
        assert_eq!(
            authenticate_record(
                &case.bytes()?,
                Some(&attempt),
                &case.expected,
                &case.credential,
                &mut support::budget()
            ),
            Err(E2eeError::InvalidValue)
        );
    }
    Ok(())
}

#[test]
fn informational_sequencing_time_does_not_choose_historical_authority() -> TestResult {
    for time in [0, u64::MAX] {
        let mut case = Case::new(support::Kind::CandidateRecord)?;
        let IrcSequencerRecord::Candidate(value) = &mut case.record else {
            return Err("candidate".into());
        };
        value.tbs.sequenced_at = time;
        case.resign()?;
        case.authenticate()?;
    }
    Ok(())
}

#[test]
fn input_kind_unknown_arm_trailing_bytes_and_decode_exhaustion_are_rejected() -> TestResult {
    let case = Case::new(support::Kind::CandidateRecord)?;
    let bytes = case.bytes()?;
    let attempt = support::object(IrcWireObjectKind::ReinitAttempt, &shapes::reinit_attempt()?)?;
    let mut trailing_object = bytes.clone();
    trailing_object.push(0);
    let mut trailing_record = case.record.encode()?;
    trailing_record.push(0);
    let trailing_record =
        IrcWireObject::new(IrcWireObjectKind::SequencerRecord, trailing_record)?.encode()?;
    let unknown = IrcWireObject::new(IrcWireObjectKind::SequencerRecord, vec![7])?.encode()?;
    for bad in [&attempt, &trailing_object, &trailing_record, &unknown] {
        assert!(
            authenticate_record(
                bad,
                None,
                &case.expected,
                &case.credential,
                &mut support::budget()
            )
            .is_err()
        );
    }
    for mut budget in [DecodeBudget::new(0, 1000), DecodeBudget::new(1 << 20, 0)] {
        assert!(
            authenticate_record(&bytes, None, &case.expected, &case.credential, &mut budget)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn alternative_signed_proofs_keep_one_semantic_id_and_distinct_object_ids() -> TestResult {
    let mut case = Case::new(support::Kind::FinalizationRecord)?;
    let first = case.authenticate()?;
    let IrcSequencerRecord::Finalization(value) = &mut case.record else {
        return Err("finalization".into());
    };
    value.tbs.request.votes = agenc_ircd_e2ee::TlsVec::new(Vec::new())?;
    case.resign()?;
    let second = case.authenticate()?;
    assert_eq!(first.semantic_id(), second.semantic_id());
    assert_ne!(first.object_id(), second.object_id());
    Ok(())
}

#[test]
fn an_external_anchor_and_a_later_sequence_require_exact_predecessors() -> TestResult {
    let mut case = Case::new(support::Kind::CandidateRecord)?;
    let first = case.authenticate()?;
    let IrcSequencerRecord::Candidate(value) = &mut case.record else {
        return Err("candidate".into());
    };
    value.tbs.route_sequence = 1;
    value.tbs.predecessor_record_id = *first.semantic_id();
    case.expected.route_sequence = 1;
    case.expected.predecessor_record_id = *first.semantic_id();
    case.resign()?;
    case.authenticate()?;
    case.expected.predecessor_record_id = *first.object_id().as_bytes();
    assert_eq!(case.authenticate(), Err(E2eeError::ProfileMismatch));
    Ok(())
}

#[test]
fn a_continuous_rotation_does_not_authorize_the_successor_at_an_older_position() -> TestResult {
    use agenc_ircd_e2ee::objects::conversation::{
        IrcSequencerCredential, IrcSequencerCredentialTbs,
    };
    use agenc_ircd_e2ee::sequencer::verify_sequencer_credential;
    let mut case = Case::new(support::Kind::CandidateRecord)?;
    let old_key = Ed25519SecretKey::from_bytes([60; 32]);
    let new_key = Ed25519SecretKey::from_bytes([61; 32]);
    let tbs = IrcSequencerCredentialTbs {
        profile_version: 1,
        network_id: [1; 32],
        key_generation: 1,
        sequencer_public_key: *new_key.public_key().as_bytes(),
        not_before: 7,
        not_after: 20,
        previous_key_id: case.credential.credential_id,
    };
    let signature = agenc_ircd_crypto::sign_canonical(
        &old_key,
        SignatureDomain::SequencerContinuity,
        &tbs.encode()?,
    )?;
    let successor = verify_sequencer_credential(
        &[1; 32],
        &IrcSequencerCredential {
            tbs,
            continuity_signature: agenc_ircd_e2ee::Opaque::new(signature.as_bytes().to_vec())?,
        },
        Some(&case.credential),
    )?;
    case.authenticate()?;
    let IrcSequencerRecord::Candidate(value) = &mut case.record else {
        return Err("candidate".into());
    };
    value.tbs.sequencer_key_id = successor.credential_id;
    case.sign_as(SignatureDomain::CandidateReceipt, &new_key)?;
    case.credential = successor;
    assert_eq!(case.authenticate(), Err(E2eeError::ProfileMismatch));
    // Only the caller's independently validated context transition can choose
    // the successor. Successful continuity alone did not change this input.
    case.expected.sequencer_credential_id = successor.credential_id;
    case.authenticate()?;
    Ok(())
}

#[test]
fn a_device_role_cannot_authenticate_a_sequencer_record_with_the_same_key_bytes() -> TestResult {
    use agenc_ircd_e2ee::signature::{RoleKey, SignerRole};
    for kind in KINDS {
        let mut case = Case::new(kind)?;
        case.credential.key = RoleKey::new(SignerRole::Device, *case.credential.key.as_bytes())?;
        assert_eq!(case.authenticate(), Err(E2eeError::SignatureInvalid));
    }
    Ok(())
}

#[test]
fn the_largest_initial_commit_is_bounded_and_a_short_decode_budget_refuses_it() -> TestResult {
    let mut case = Case::new(support::Kind::ReinitAttemptRecord)?;
    let attempt = case.attempt.as_mut().ok_or("attempt")?;
    let initial_commit = vec![42; agenc_ircd_e2ee::limits::MAX_REINIT_INITIAL_COMMIT_BYTES];
    attempt.initial_commit_bytes = agenc_ircd_e2ee::Opaque::new(initial_commit)?;
    case.refresh_attempt_object_id()?;
    case.resign()?;
    let bytes = case.bytes()?;
    let attempt = support::object(
        IrcWireObjectKind::ReinitAttempt,
        case.attempt.as_ref().ok_or("attempt")?,
    )?;
    // The immutable attempt TBS is unchanged; this verifies exact object binding,
    // not its controller authorization or the initial Commit digest.
    case.authenticate()?;
    let mut short = DecodeBudget::new(attempt.len(), 1 << 18);
    assert_eq!(
        authenticate_record(
            &bytes,
            Some(&attempt),
            &case.expected,
            &case.credential,
            &mut short
        ),
        Err(E2eeError::BudgetExceeded)
    );
    Ok(())
}
