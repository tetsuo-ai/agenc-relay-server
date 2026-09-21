//! Controller thresholds and registered signature labels at the public close boundary.
#![forbid(unsafe_code)]
use super::*;
use crate::ids::semantic_id_of;
use crate::objects::conversation::{ArcCloseAuthorizationTbs, ArcCloseIntent};
use crate::policy::verify_policy;
use crate::test_support::*;
use crate::tls::TlsVec;
use agenc_relay_crypto::SemanticHashDomain;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CONVERSATION: [u8; 32] = [20; 32];

struct Fixture {
    principals: Vec<Principal>,
    policy: VerifiedPolicy,
    rosters: PrincipalRosters,
    tbs: ArcCloseAuthorizationTbs,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let principals = vec![
            principal(40, &ACCOUNT, &[7, 8])?,
            principal(41, &OTHER_ACCOUNT, &[9])?,
        ];
        let rosters = principal_rosters(&principals)?;
        let policy = verify_policy(
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
        let intent = ArcCloseIntent {
            reason_code: 1,
            validation_time: 500,
        };
        let tbs = ArcCloseAuthorizationTbs {
            profile_version: 1,
            network_id: NETWORK,
            conversation_id: CONVERSATION,
            binding_id: [21; 32],
            authorizing_terminal_id: [22; 32],
            close_intent_id: semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?,
            close_intent: intent,
        };
        Ok(Self {
            principals,
            policy,
            rosters,
            tbs,
        })
    }

    fn close(
        &self,
        approvers: &[(usize, u8)],
        domain: SignatureDomain,
    ) -> TestResult<ArcCloseAuthorization> {
        let mut approvals = Vec::new();
        for (index, device) in approvers {
            approvals.push(commit_approval(
                self.principals.get(*index).ok_or("principal")?,
                *device,
                &self.tbs,
                domain,
            )?);
        }
        approvals.sort_by_key(|value| (value.signer_root_fingerprint, value.signer_device_id));
        Ok(ArcCloseAuthorization {
            tbs: self.tbs.clone(),
            approvals: TlsVec::new(approvals)?,
        })
    }
}

#[test]
fn close_requires_the_full_distinct_controller_root_threshold() -> TestResult {
    let fixture = Fixture::new()?;
    let full = fixture.close(&[(0, 7), (1, 9)], SignatureDomain::CloseAuthorization)?;
    assert_eq!(
        verify_close_approvals(&full, &fixture.policy, &fixture.rosters)?,
        close_authorization_id(&full)?
    );
    let partial = fixture.close(&[(0, 7)], SignatureDomain::CloseAuthorization)?;
    assert_eq!(
        verify_close_approvals(&partial, &fixture.policy, &fixture.rosters),
        Err(E2eeError::InvalidValue)
    );
    let repeated = fixture.close(&[(0, 7), (0, 8)], SignatureDomain::CloseAuthorization)?;
    assert_eq!(
        verify_close_approvals(&repeated, &fixture.policy, &fixture.rosters),
        Err(E2eeError::NonCanonical)
    );
    Ok(())
}

#[test]
fn two_controller_roots_cannot_count_the_same_public_key_twice() -> TestResult {
    let fixture = Fixture::new()?;
    // An alternate signed roster is supplied to this validator directly. This
    // checks key counting, without claiming a runtime roster-chain transition.
    let repeated = principal(41, &OTHER_ACCOUNT, &[7])?;
    let mut rosters = fixture.rosters.clone();
    rosters.extend(principal_rosters(std::slice::from_ref(&repeated))?);
    let mut approvals = vec![
        commit_approval(
            fixture.principals.first().ok_or("principal")?,
            7,
            &fixture.tbs,
            SignatureDomain::CloseAuthorization,
        )?,
        commit_approval(
            &repeated,
            7,
            &fixture.tbs,
            SignatureDomain::CloseAuthorization,
        )?,
    ];
    approvals.sort_by_key(|value| (value.signer_root_fingerprint, value.signer_device_id));
    let close = ArcCloseAuthorization {
        tbs: fixture.tbs,
        approvals: TlsVec::new(approvals)?,
    };
    assert_eq!(
        verify_close_approvals(&close, &fixture.policy, &rosters),
        Err(E2eeError::NonCanonical)
    );
    Ok(())
}

#[test]
fn close_approvals_reject_another_signature_label_or_certificate_identity() -> TestResult {
    let fixture = Fixture::new()?;
    let wrong_label = fixture.close(&[(0, 7), (1, 9)], SignatureDomain::CommitAuthorization)?;
    assert!(verify_close_approvals(&wrong_label, &fixture.policy, &fixture.rosters).is_err());
    let mut wrong_certificate =
        fixture.close(&[(0, 7), (1, 9)], SignatureDomain::CloseAuthorization)?;
    let mut approvals = wrong_certificate.approvals.as_slice().to_vec();
    approvals
        .first_mut()
        .ok_or("approval")?
        .signer_device_certificate_id = [0; 32];
    wrong_certificate.approvals = TlsVec::new(approvals)?;
    assert!(verify_close_approvals(&wrong_certificate, &fixture.policy, &fixture.rosters).is_err());
    Ok(())
}

#[test]
fn close_refuses_missing_devices_removed_authority_and_invalid_policy_scope() -> TestResult {
    let fixture = Fixture::new()?;
    let close = fixture.close(&[(0, 7), (1, 9)], SignatureDomain::CloseAuthorization)?;
    for missing in [false, true] {
        let mut rosters = fixture.rosters.clone();
        let roster = &mut rosters.get_mut(&ACCOUNT).ok_or("roster")?.1;
        if missing {
            roster.devices.remove(&[7; 16]);
        } else {
            roster.devices.get_mut(&[7; 16]).ok_or("device")?.flags = 0;
        }
        assert!(verify_close_approvals(&close, &fixture.policy, &rosters).is_err());
    }
    let mut policy = fixture.policy.clone();
    policy.conversation_id = [99; 32];
    assert!(verify_close_approvals(&close, &policy, &fixture.rosters).is_err());
    policy.conversation_id = CONVERSATION;
    policy.controller_threshold = 0;
    assert!(verify_close_approvals(&close, &policy, &fixture.rosters).is_err());
    Ok(())
}

#[test]
fn close_signatures_bind_every_changed_request_context() -> TestResult {
    let fixture = Fixture::new()?;
    for change in 0..4 {
        let mut close = fixture.close(&[(0, 7), (1, 9)], SignatureDomain::CloseAuthorization)?;
        match change {
            0 => close.tbs.network_id = [91; 32],
            1 => close.tbs.binding_id = [92; 32],
            2 => close.tbs.authorizing_terminal_id = [93; 32],
            _ => {
                close.tbs.close_intent.validation_time = 501;
                close.tbs.close_intent_id =
                    semantic_id_of(SemanticHashDomain::CloseIntentId, &close.tbs.close_intent)?;
            }
        }
        assert!(verify_close_approvals(&close, &fixture.policy, &fixture.rosters).is_err());
    }
    Ok(())
}
