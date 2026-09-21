#![forbid(unsafe_code)]

//! One controller root states one approval, and two controller devices never
//! share one signature key, even when the approval list is already canonical.

use super::*;

type FenceResult = Result<(), Box<dyn Error>>;

const FENCE_CONVERSATION: [u8; 32] = CONVERSATION;

#[test]
fn one_root_approving_twice_through_two_devices_is_refused() -> FenceResult {
    let principals = vec![principal(50, &ACCOUNT, &[7, 8])?];
    let rosters = principal_rosters(&principals)?;
    let old_policy = verify_policy(
        &NETWORK,
        &FENCE_CONVERSATION,
        &policy(&PolicySpec {
            controllers: vec![0],
            threshold: 1,
            council: vec![(0, 7), (0, 8)],
            approvers: vec![(0, 7)],
            ..PolicySpec::moderated(&principals, FENCE_CONVERSATION)
        })?,
        &rosters,
        None,
    )?;
    let first = principals.first().ok_or("principal")?;
    let tbs = authorization_tbs(
        FENCE_CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        PRIVATE_TOPIC,
    );
    let single = commit_authorization(tbs.clone(), &[(first, 7)])?;
    assert_eq!(
        verify_commit_authorization(&single, &candidate(), &old_policy, &rosters)?
            .approving_roots
            .len(),
        1
    );

    let both = commit_authorization(tbs, &[(first, 7), (first, 8)])?;
    let listed = both.approvals.as_slice();
    assert_eq!(listed.len(), 2, "both approvals reach the authorization");
    let ordered = listed
        .windows(2)
        .all(|pair| match (pair.first(), pair.get(1)) {
            (Some(left), Some(right)) => {
                (left.signer_root_fingerprint, left.signer_device_id)
                    < (right.signer_root_fingerprint, right.signer_device_id)
            }
            _ => false,
        });
    assert!(ordered, "the list is already canonical by root and device");
    assert_eq!(
        verify_commit_authorization(&both, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::NonCanonical),
        "one root states one approval however many devices it holds"
    );
    Ok(())
}

#[test]
fn two_controller_roots_sharing_one_device_key_are_refused() -> FenceResult {
    // Both roots enrolled the same device key, which no roster check can see
    // on its own because each roster holds only its own certificate.
    let principals = vec![
        principal(51, &ACCOUNT, &[7])?,
        principal(52, &OTHER_ACCOUNT, &[7])?,
    ];
    let rosters = principal_rosters(&principals)?;
    let old_policy = verify_policy(
        &NETWORK,
        &FENCE_CONVERSATION,
        &policy(&PolicySpec {
            controllers: vec![0, 1],
            threshold: 1,
            council: vec![(0, 7)],
            approvers: vec![(0, 7)],
            ..PolicySpec::moderated(&principals, FENCE_CONVERSATION)
        })?,
        &rosters,
        None,
    )?;
    let first = principals.first().ok_or("principal")?;
    let second = principals.get(1).ok_or("principal")?;
    let tbs = authorization_tbs(
        FENCE_CONVERSATION,
        old_policy.policy_id,
        Rule::ControlledTransition,
        PRIVATE_TOPIC,
    );
    let single = commit_authorization(tbs.clone(), &[(first, 7)])?;
    assert_eq!(
        verify_commit_authorization(&single, &candidate(), &old_policy, &rosters)?
            .approving_roots
            .len(),
        1
    );

    let shared = commit_authorization(tbs, &[(first, 7), (second, 7)])?;
    let roots: Vec<[u8; 32]> = shared
        .approvals
        .as_slice()
        .iter()
        .map(|approval| approval.signer_root_fingerprint)
        .collect();
    assert_eq!(roots.len(), 2);
    assert_ne!(roots.first(), roots.get(1), "the two roots differ");
    assert_eq!(
        verify_commit_authorization(&shared, &candidate(), &old_policy, &rosters).map(|_| ()),
        Err(E2eeError::NonCanonical),
        "two distinct roots never count twice through one signature key"
    );
    Ok(())
}
