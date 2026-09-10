//! Controller counting uses verified policies and rosters, independent of MLS leaf membership.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::{account_bytes, support};
use agenc_ircd_e2ee::identity::{verify_root_identity, verify_roster};
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::policy::{VerifiedPolicy, verify_policy};
use agenc_ircd_e2ee::reinit_authorization::verify_reinit_attempt_authorization as verify;
use agenc_ircd_e2ee::route::PrincipalRosters;

struct Controllers {
    principals: Vec<support::Principal>,
    policy: VerifiedPolicy,
    rosters: PrincipalRosters,
    attempt: IrcReInitAttempt,
}

impl Controllers {
    fn new() -> TestResult<Self> {
        let (_, conversation, attempt) = prepared()?;
        let principals = vec![
            support::principal(40, &account_bytes(20)?, &[7, 8])?,
            support::principal(41, &account_bytes(21)?, &[9])?,
        ];
        let mut rosters = PrincipalRosters::new();
        for principal in &principals {
            let root = verify_root_identity(&NETWORK, &principal.root, None)?;
            let roster = verify_roster(&root, &principal.roster, None)?;
            rosters.insert(root.account_id, (root, roster));
        }
        let mut spec =
            support::PolicySpec::bootstrap(&principals, conversation, IrcConversationKind::Channel);
        spec.threshold = 2;
        let policy = verify_policy(
            &NETWORK,
            &conversation,
            &support::policy(&spec)?,
            &rosters,
            None,
        )?;
        Ok(Self {
            principals,
            policy,
            rosters,
            attempt,
        })
    }

    fn signed(&self, approvers: &[(usize, u8)]) -> TestResult<IrcReInitAttempt> {
        let mut attempt = self.attempt.clone();
        let mut approvals = Vec::new();
        for (index, device) in approvers {
            approvals.push(commit_approval(
                self.principals.get(*index).ok_or("principal")?,
                *device,
                &attempt.authorization.tbs,
                SignatureDomain::ReinitAttemptAuthorization,
            )?);
        }
        approvals.sort_by_key(|p| (p.signer_root_fingerprint, p.signer_device_id));
        attempt.authorization.approvals = TlsVec::new(approvals)?;
        Ok(attempt)
    }
}

#[test]
fn reinit_authorization_counts_distinct_controller_roots() -> TestResult {
    let fixture = Controllers::new()?;
    verify(
        &fixture.signed(&[(0, 7), (1, 9)])?,
        &fixture.policy,
        &fixture.rosters,
    )?;
    assert!(
        verify(
            &fixture.signed(&[(0, 7)])?,
            &fixture.policy,
            &fixture.rosters
        )
        .is_err()
    );
    assert!(
        verify(
            &fixture.signed(&[(0, 7), (0, 8)])?,
            &fixture.policy,
            &fixture.rosters
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reinit_authorization_rejects_unsorted_controller_proofs() -> TestResult {
    let fixture = Controllers::new()?;
    let mut attempt = fixture.signed(&[(0, 7), (1, 9)])?;
    let mut approvals = attempt.authorization.approvals.as_slice().to_vec();
    approvals.reverse();
    attempt.authorization.approvals = TlsVec::new(approvals)?;
    assert!(verify(&attempt, &fixture.policy, &fixture.rosters).is_err());
    Ok(())
}

#[test]
fn reinit_authorization_refuses_inactive_devices_and_removed_policy_authority() -> TestResult {
    let fixture = Controllers::new()?;
    let attempt = fixture.signed(&[(0, 7), (1, 9)])?;
    for missing in [false, true] {
        let mut rosters = fixture.rosters.clone();
        let roster = &mut rosters.get_mut(&account_bytes(20)?).ok_or("roster")?.1;
        if missing {
            roster.devices.remove(&[7; 16]);
        } else {
            roster.devices.get_mut(&[7; 16]).ok_or("device")?.flags = 0;
        }
        assert!(verify(&attempt, &fixture.policy, &rosters).is_err());
    }
    for wrong_scope in [false, true] {
        let mut policy = fixture.policy.clone();
        if wrong_scope {
            policy.conversation_id = [99; 32];
        } else {
            policy.controller_threshold = 0;
        }
        assert!(verify(&attempt, &policy, &fixture.rosters).is_err());
    }
    Ok(())
}

#[test]
fn reinit_authorization_does_not_count_a_shared_controller_key_twice() -> TestResult {
    let fixture = Controllers::new()?;
    let repeated = support::principal(41, &account_bytes(21)?, &[7])?;
    let root = verify_root_identity(&NETWORK, &repeated.root, None)?;
    let roster = verify_roster(&root, &repeated.roster, None)?;
    let mut rosters = fixture.rosters.clone();
    rosters.insert(root.account_id, (root, roster));
    let mut attempt = fixture.attempt.clone();
    let mut approvals = vec![
        commit_approval(
            fixture.principals.first().ok_or("principal")?,
            7,
            &attempt.authorization.tbs,
            SignatureDomain::ReinitAttemptAuthorization,
        )?,
        commit_approval(
            &repeated,
            7,
            &attempt.authorization.tbs,
            SignatureDomain::ReinitAttemptAuthorization,
        )?,
    ];
    approvals.sort_by_key(|p| (p.signer_root_fingerprint, p.signer_device_id));
    attempt.authorization.approvals = TlsVec::new(approvals)?;
    assert!(verify(&attempt, &fixture.policy, &rosters).is_err());
    Ok(())
}
