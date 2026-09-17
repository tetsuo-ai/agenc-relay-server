#![forbid(unsafe_code)]

//! Commit authorization: the action bit table and controller approvals.

use std::error::Error;

use super::*;
use crate::objects::conversation::{
    IrcCommitAuthorizationRule as Rule, IrcMembershipPolicy, action_bits::*,
};
use crate::policy::verify_policy;
use crate::test_support::*;
use crate::tls::TlsVec;

type TestResult = Result<(), Box<dyn Error>>;

const CONVERSATION: [u8; 32] = [20; 32];

/// An independent statement of the Section 9.3 table.
fn expected_rule(bits: u32) -> Option<Rule> {
    if bits & !KNOWN != 0 {
        return None;
    }
    let transitions = u32::from(bits & REINIT != 0)
        + u32::from(bits & BINDING != 0)
        + u32::from(bits & CLOSE_INTENT != 0);
    if bits == 0 {
        Some(Rule::RoutineSelfUpdate)
    } else if bits == ADD_LEAF | ROSTER | PENDING_JOIN {
        Some(Rule::OpenVisibleAdd)
    } else if bits == PENDING_JOIN {
        Some(Rule::JoinConfirmation)
    } else if bits == ROSTER || bits == ROSTER | REMOVE_LEAF {
        Some(Rule::RosterRecovery)
    } else if bits == POLICY | BOOTSTRAP {
        Some(Rule::BootstrapActivation)
    } else if transitions > 1 || (transitions == 1 && bits.count_ones() > 1) {
        None
    } else {
        Some(Rule::ControlledTransition)
    }
}

#[test]
fn every_action_bit_combination_selects_at_most_one_rule() {
    let mut legal = 0;
    for bits in 0..=0x1fff_u32 {
        let expected = expected_rule(bits);
        assert_eq!(rule_for_bits(bits), expected, "bits {bits:#x}");
        if expected.is_some() {
            legal += 1;
        }
        for rule in Rule::ALL {
            let matches = rule_matches_bits(*rule, bits);
            let allowed = match expected {
                None => false,
                Some(Rule::RosterRecovery) => {
                    matches!(rule, Rule::RosterRecovery | Rule::ControlledTransition)
                }
                Some(Rule::OpenVisibleAdd) => {
                    matches!(rule, Rule::OpenVisibleAdd | Rule::ControlledTransition)
                }
                Some(selected) => selected == *rule,
            };
            assert_eq!(matches, allowed, "bits {bits:#x} rule {rule:?}");
        }
    }
    assert!(legal > 100);
    assert!(needs_transition_target(REINIT));
    assert!(needs_transition_target(BINDING));
    assert!(needs_transition_target(CLOSE_INTENT));
    assert!(!needs_transition_target(POLICY | PRIVATE_TOPIC));
}

fn candidate() -> CandidateBinding {
    CandidateBinding {
        network_id: NETWORK,
        conversation_id: CONVERSATION,
        prior_epoch: 0,
        prior_state_id: [50; 32],
        candidate_id: [52; 32],
        commit_object_id: [49; 32],
    }
}

#[test]
fn controlled_transitions_need_the_old_threshold() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let old_policy = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&PolicySpec {
            threshold: 2,
            approvers: vec![(0, 7), (1, 9)],
            ..PolicySpec::moderated(&principals, CONVERSATION)
        })?,
        &rosters,
        None,
    )?;
    let first = principals.first().ok_or("principal")?;
    let second = principals.get(1).ok_or("principal")?;
    let tbs = authorization_tbs(
        CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        PRIVATE_TOPIC,
    );
    let full = commit_authorization(tbs.clone(), &[(first, 7), (second, 9)])?;
    let verified = verify_commit_authorization(&full, &candidate(), &old_policy, &rosters)?;
    assert_eq!(verified.rule, Rule::ControlledTransition);
    assert_eq!(verified.approving_roots.len(), 2);
    let partial = commit_authorization(tbs.clone(), &[(first, 7)])?;
    assert_eq!(
        verify_commit_authorization(&partial, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    // A routine self update needs none.
    let routine = commit_authorization(
        authorization_tbs(
            CONVERSATION,
            old_policy.policy_id,
            Rule::RoutineSelfUpdate,
            0,
        ),
        &[],
    )?;
    assert_eq!(
        verify_commit_authorization(&routine, &candidate(), &old_policy, &rosters)?
            .approving_roots
            .len(),
        0
    );
    // Misclassification, unknown bits, and target presence.
    for (label, rule, bits, target) in [
        (
            "misclassified",
            Rule::RoutineSelfUpdate,
            PRIVATE_TOPIC,
            [0; 32],
        ),
        ("unknown bit", Rule::ControlledTransition, 0x1000, [0; 32]),
        (
            "reinit without target",
            Rule::ControlledTransition,
            REINIT,
            [0; 32],
        ),
        (
            "target without transition",
            Rule::ControlledTransition,
            PRIVATE_TOPIC,
            [1; 32],
        ),
        (
            "two transition classes",
            Rule::ControlledTransition,
            REINIT | BINDING,
            [1; 32],
        ),
    ] {
        let mut wrong = authorization_tbs(CONVERSATION, old_policy.policy_id, rule, bits);
        wrong.transition_target_digest = target;
        let authorization = commit_authorization(wrong, &[(first, 7), (second, 9)])?;
        assert_eq!(
            verify_commit_authorization(&authorization, &candidate(), &old_policy, &rosters)
                .map(|_| ()),
            Err(E2eeError::InvalidValue),
            "{label}"
        );
    }
    // A reinit with its target verifies.
    let mut reinit = authorization_tbs(
        CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        REINIT,
    );
    reinit.transition_target_digest = [8; 32];
    let authorization = commit_authorization(reinit, &[(first, 7), (second, 9)])?;
    assert_eq!(
        verify_commit_authorization(&authorization, &candidate(), &old_policy, &rosters)?
            .transition_target_digest,
        [8; 32]
    );
    // A policy change must name a new resulting policy id and vice versa.
    let mut same_policy = authorization_tbs(
        CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        POLICY,
    );
    same_policy.resulting_policy_id = old_policy.policy_id;
    let authorization = commit_authorization(same_policy.clone(), &[(first, 7), (second, 9)])?;
    assert_eq!(
        verify_commit_authorization(&authorization, &candidate(), &old_policy, &rosters)
            .map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    same_policy.resulting_policy_id = [3; 32];
    let authorization = commit_authorization(same_policy, &[(first, 7), (second, 9)])?;
    assert!(
        verify_commit_authorization(&authorization, &candidate(), &old_policy, &rosters).is_ok()
    );
    // Candidate field disagreement.
    let mut other_candidate = candidate();
    other_candidate.candidate_id = [1; 32];
    assert_eq!(
        verify_commit_authorization(&full, &other_candidate, &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    // Duplicate roots, a forged signature, and a non-controller signer.
    let mut duplicate = full.clone();
    let mut approvals = duplicate.approvals.as_slice().to_vec();
    if let Some(first_approval) = approvals.first().cloned() {
        approvals.push(first_approval);
    }
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    duplicate.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_commit_authorization(&duplicate, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::NonCanonical)
    );
    let mut forged = full;
    let mut approvals = forged.approvals.as_slice().to_vec();
    if let Some(first_approval) = approvals.first_mut() {
        first_approval.device_signature = [0; 64];
    }
    forged.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_commit_authorization(&forged, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::SignatureInvalid)
    );
    let outsider = principal(42, &[b'c'; 24], &[11])?;
    let foreign = commit_authorization(tbs, &[(first, 7), (&outsider, 11)])?;
    assert_eq!(
        verify_commit_authorization(&foreign, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn open_visible_adds_need_approval_only_under_a_moderated_policy() -> TestResult {
    let principals = vec![principal(40, &ACCOUNT, &[7])?];
    let rosters = principal_rosters(&principals)?;
    let bits = ADD_LEAF | ROSTER | PENDING_JOIN;
    for (membership, expected_ok) in [
        (IrcMembershipPolicy::OpenVisible, true),
        (IrcMembershipPolicy::Moderated, false),
    ] {
        let old_policy = verify_policy(
            &NETWORK,
            &CONVERSATION,
            &policy(&PolicySpec {
                membership,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            })?,
            &rosters,
            None,
        )?;
        assert_eq!(
            needs_controller_approval(Rule::OpenVisibleAdd, &old_policy),
            !expected_ok
        );
        let unapproved = commit_authorization(
            authorization_tbs(
                CONVERSATION,
                old_policy.policy_id,
                Rule::OpenVisibleAdd,
                bits,
            ),
            &[],
        )?;
        assert_eq!(
            verify_commit_authorization(&unapproved, &candidate(), &old_policy, &rosters).is_ok(),
            expected_ok,
            "{membership:?}"
        );
    }
    Ok(())
}

#[test]
fn approval_envelopes_share_one_authorization_id() -> TestResult {
    let principals = vec![principal(40, &ACCOUNT, &[7, 8])?];
    let rosters = principal_rosters(&principals)?;
    let old_policy = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&PolicySpec::moderated(&principals, CONVERSATION))?,
        &rosters,
        None,
    )?;
    let first = principals.first().ok_or("principal")?;
    let tbs = authorization_tbs(
        CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        PRIVATE_TOPIC,
    );
    let first_envelope = verify_approval_envelope(
        &approval_envelope(tbs.clone(), first, 7)?,
        &candidate(),
        &old_policy,
        &rosters,
    )?;
    let second_envelope = verify_approval_envelope(
        &approval_envelope(tbs.clone(), first, 8)?,
        &candidate(),
        &old_policy,
        &rosters,
    )?;
    assert_eq!(
        first_envelope.authorization_id,
        second_envelope.authorization_id
    );
    assert_ne!(
        first_envelope.signer_device_id,
        second_envelope.signer_device_id
    );
    let mut forged = approval_envelope(tbs, first, 7)?;
    forged.approval.device_signature = [1; 64];
    assert_eq!(
        verify_approval_envelope(&forged, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

#[path = "authorization/fences.rs"]
mod fences;
