#![forbid(unsafe_code)]

//! Policy validation and finality quorum arithmetic.

use std::collections::BTreeSet;
use std::error::Error;

use super::*;
use crate::objects::conversation::{ArcConversationKind, ArcMembershipPolicy};
use crate::test_support::*;
use crate::tls::{Opaque, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

const CONVERSATION: [u8; 32] = [20; 32];

#[test]
fn the_quorum_intersects_beyond_the_fault_bound_for_every_permitted_pair() -> TestResult {
    let mut cases = 0;
    for n in 1..=64_usize {
        for f in 0..=64_u16 {
            let result = finality_quorum(n, f);
            let permitted = n > 3 * usize::from(f);
            if !permitted {
                assert_eq!(result, Err(E2eeError::InvalidValue), "n={n} f={f}");
                continue;
            }
            let q = usize::from(result?);
            assert_eq!(q, (n + usize::from(f)) / 2 + 1, "n={n} f={f}");
            assert!(q <= n, "a quorum never exceeds the council");
            assert!(
                2 * q > n + usize::from(f),
                "2q - n > f fails at n={n} f={f}"
            );
            cases += 1;
        }
    }
    assert!(cases > 64);
    assert_eq!(finality_quorum(1, 0)?, 1);
    assert_eq!(finality_quorum(4, 1)?, 3);
    assert_eq!(finality_quorum(0, 0), Err(E2eeError::LimitExceeded));
    assert_eq!(finality_quorum(65, 0), Err(E2eeError::LimitExceeded));
    Ok(())
}

#[test]
fn a_moderated_policy_verifies_and_reports_its_sets() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let spec = PolicySpec::moderated(&principals, CONVERSATION);
    let verified = verify_policy(&NETWORK, &CONVERSATION, &policy(&spec)?, &rosters, None)?;
    assert_eq!(verified.generation, 0);
    assert_eq!(verified.controllers.len(), 2);
    assert_eq!(verified.council.len(), 3);
    assert_eq!(verified.quorum, 2);
    assert_eq!(verified.allowed_suites, vec![1, 3]);
    assert!(!verified.require_oob_verified_roots);
    let fingerprint = root_fingerprint(&principals.first().ok_or("principal")?.root)?;
    assert!(verified.is_controller(&fingerprint));
    assert!(!verified.is_controller(&[9; 32]));
    assert!(verified.council_member(&fingerprint, &[7; 16]).is_some());
    assert!(verified.council_member(&fingerprint, &[1; 16]).is_none());
    let mut retained = BTreeSet::new();
    retained.insert((fingerprint, [7; 16]));
    assert!(!verified.retains_quorum(&retained));
    retained.insert((fingerprint, [8; 16]));
    assert!(verified.retains_quorum(&retained));
    Ok(())
}

#[test]
fn every_policy_rule_has_a_negative() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7, 8])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let base = PolicySpec::moderated(&principals, CONVERSATION);
    let verify = |spec: &PolicySpec<'_>| -> Result<VerifiedPolicy, E2eeError> {
        verify_policy(&NETWORK, &CONVERSATION, &policy(spec)?, &rosters, None)
    };
    let cases: Vec<(&str, PolicySpec<'_>, E2eeError)> = vec![
        (
            "missing mandatory suite",
            PolicySpec {
                suites: vec![3],
                selected_suite: 3,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::ProfileMismatch,
        ),
        (
            "selected suite absent",
            PolicySpec {
                suites: vec![1],
                selected_suite: 3,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::ProfileMismatch,
        ),
        (
            "duplicate suite",
            PolicySpec {
                suites: vec![1, 1],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::ProfileMismatch,
        ),
        (
            "threshold zero",
            PolicySpec {
                threshold: 0,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "threshold above controllers",
            PolicySpec {
                threshold: 3,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "fixed direct with the wrong shape",
            PolicySpec {
                membership: ArcMembershipPolicy::FixedDirect,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "fault bound too high",
            PolicySpec {
                fault_bound: 1,
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "council device not active",
            PolicySpec {
                council: vec![(0, 7), (0, 3)],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "approvals below threshold",
            PolicySpec {
                threshold: 2,
                approvers: vec![(0, 7)],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "approval from a non-controller",
            PolicySpec {
                controllers: vec![0],
                approvers: vec![(1, 9)],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "generation one without a predecessor",
            PolicySpec {
                generation: 1,
                previous_policy_id: [1; 32],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
        (
            "wrong conversation",
            PolicySpec {
                conversation_id: [21; 32],
                ..PolicySpec::moderated(&principals, CONVERSATION)
            },
            E2eeError::InvalidValue,
        ),
    ];
    for (label, spec, expected) in cases {
        assert_eq!(verify(&spec).map(|_| ()), Err(expected), "{label}");
    }
    // A controller device without policy authority, an unsorted council, and a
    // forged signature.
    let good = policy(&base)?;
    let mut unsorted = good.clone();
    let mut council = unsorted.tbs.finality_principals.as_slice().to_vec();
    council.reverse();
    unsorted.tbs.finality_principals = TlsVec::new(council)?;
    assert_eq!(
        verify_policy(&NETWORK, &CONVERSATION, &unsorted, &rosters, None).map(|_| ()),
        Err(E2eeError::NonCanonical)
    );
    let mut forged = good.clone();
    let mut approvals = forged.approvals.as_slice().to_vec();
    if let Some(first) = approvals.first_mut() {
        first.device_signature = [0; 64];
    }
    forged.approvals = TlsVec::new(approvals)?;
    assert_eq!(
        verify_policy(&NETWORK, &CONVERSATION, &forged, &rosters, None).map(|_| ()),
        Err(E2eeError::SignatureInvalid)
    );
    let mut ragged = good.clone();
    ragged.tbs.controller_root_fingerprints = Opaque::new(vec![1; 33])?;
    assert_eq!(
        verify_policy(&NETWORK, &CONVERSATION, &ragged, &rosters, None).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    let mut too_many_leaves = good;
    too_many_leaves.tbs.max_group_leaves = 513;
    assert_eq!(
        verify_policy(&NETWORK, &CONVERSATION, &too_many_leaves, &rosters, None).map(|_| ()),
        Err(E2eeError::LimitExceeded)
    );
    // A device whose certificate lacks policy authority cannot approve.
    let mut limited = principal(42, &[b'c'; 24], &[11])?;
    let certificate = certificate(
        &limited.root_secret,
        &limited.root,
        &DeviceSpec {
            flags: 1,
            ..DeviceSpec::new(11)
        },
    )?;
    limited.roster = roster(
        &limited.root_secret,
        &limited.root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        vec![certificate],
        Vec::new(),
    )?;
    let limited_devices = vec![limited];
    let limited_rosters = principal_rosters(&limited_devices)?;
    let limited_spec = PolicySpec::moderated(&limited_devices, CONVERSATION);
    assert_eq!(
        verify_policy(
            &NETWORK,
            &CONVERSATION,
            &policy(&limited_spec)?,
            &limited_rosters,
            None
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_change_is_approved_under_the_old_policy() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let initial = verify_policy(
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
    // The successor drops the second controller; the old threshold of two still governs.
    let successor = PolicySpec {
        generation: 1,
        previous_policy_id: initial.policy_id,
        controllers: vec![0],
        threshold: 1,
        approvers: vec![(0, 7)],
        ..PolicySpec::moderated(&principals, CONVERSATION)
    };
    assert_eq!(
        verify_policy(
            &NETWORK,
            &CONVERSATION,
            &policy(&successor)?,
            &rosters,
            Some(&initial)
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "one approval cannot satisfy the old threshold of two"
    );
    let approved = PolicySpec {
        approvers: vec![(0, 7), (1, 9)],
        ..successor
    };
    let verified = verify_policy(
        &NETWORK,
        &CONVERSATION,
        &policy(&approved)?,
        &rosters,
        Some(&initial),
    )?;
    assert_eq!(verified.generation, 1);
    assert_eq!(verified.controllers.len(), 1);
    let skipped = PolicySpec {
        generation: 2,
        approvers: vec![(0, 7), (1, 9)],
        ..PolicySpec::moderated(&principals, CONVERSATION)
    };
    assert_eq!(
        verify_policy(
            &NETWORK,
            &CONVERSATION,
            &policy(&skipped)?,
            &rosters,
            Some(&initial)
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_fixed_direct_policy_needs_both_roots() -> TestResult {
    let principals = vec![
        principal(40, &ACCOUNT, &[7])?,
        principal(41, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let spec = PolicySpec {
        kind: ArcConversationKind::Direct,
        membership: ArcMembershipPolicy::FixedDirect,
        threshold: 2,
        approvers: vec![(0, 7), (1, 9)],
        ..PolicySpec::moderated(&principals, CONVERSATION)
    };
    let verified = verify_policy(&NETWORK, &CONVERSATION, &policy(&spec)?, &rosters, None)?;
    assert_eq!(verified.membership_policy, ArcMembershipPolicy::FixedDirect);
    let one_side = PolicySpec {
        approvers: vec![(0, 7)],
        ..spec
    };
    assert_eq!(
        verify_policy(&NETWORK, &CONVERSATION, &policy(&one_side)?, &rosters, None).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[path = "policy/fences.rs"]
mod fences;
