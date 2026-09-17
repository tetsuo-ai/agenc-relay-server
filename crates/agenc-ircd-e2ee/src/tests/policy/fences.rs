#![forbid(unsafe_code)]

//! Every profile, lineage and bound refusal differs from an accepted policy
//! by exactly one field, so the refusal rests on that field alone.

use super::*;
use crate::objects::conversation::{IrcPolicy, IrcPolicyApproval, IrcPolicyTbs};

type FenceResult = Result<(), Box<dyn Error>>;

const FENCE_CONVERSATION: [u8; 32] = [24; 32];
const OTHER_NETWORK: [u8; 32] = [77; 32];

fn fixture() -> Result<(Vec<Principal>, PrincipalRosters), Box<dyn Error>> {
    let principals = vec![
        principal(60, &ACCOUNT, &[7, 8])?,
        principal(61, &OTHER_ACCOUNT, &[9])?,
    ];
    let rosters = principal_rosters(&principals)?;
    Ok((principals, rosters))
}

#[test]
fn the_profile_fence_names_the_version_the_network_and_the_suite_set() -> FenceResult {
    let (principals, rosters) = fixture()?;
    let spec = PolicySpec::moderated(&principals, FENCE_CONVERSATION);
    let accepted = policy(&spec)?;
    assert_eq!(
        verify_policy(&NETWORK, &FENCE_CONVERSATION, &accepted, &rosters, None)?.generation,
        0
    );

    let mut future_profile = accepted.clone();
    future_profile.tbs.profile_version = PROFILE_VERSION.saturating_add(1);
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &future_profile,
            &rosters,
            None
        )
        .map(|_| ()),
        Err(E2eeError::ProfileMismatch),
        "a later profile version is refused before any set is resolved"
    );

    let mut future_mls = accepted.clone();
    future_mls.tbs.mls_version = MLS_VERSION_MLS10.saturating_add(1);
    assert_eq!(
        verify_policy(&NETWORK, &FENCE_CONVERSATION, &future_mls, &rosters, None).map(|_| ()),
        Err(E2eeError::ProfileMismatch),
        "a later MLS version is refused although the profile version matches"
    );

    assert_eq!(
        verify_policy(
            &OTHER_NETWORK,
            &FENCE_CONVERSATION,
            &accepted,
            &rosters,
            None
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a policy of one network is refused by another network"
    );

    let disabled = PolicySpec {
        suites: vec![SUITE_X25519_AES128GCM_SHA256_ED25519, 2],
        selected_suite: SUITE_X25519_AES128GCM_SHA256_ED25519,
        ..PolicySpec::moderated(&principals, FENCE_CONVERSATION)
    };
    assert!(
        !suite_is_enabled(2),
        "suite 2 is not enabled in profile one"
    );
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &policy(&disabled)?,
            &rosters,
            None
        )
        .map(|_| ()),
        Err(E2eeError::ProfileMismatch),
        "one disabled suite refuses the whole allowed set"
    );
    Ok(())
}

#[test]
fn the_lineage_fence_needs_the_zero_predecessor_or_the_exact_one() -> FenceResult {
    let (principals, rosters) = fixture()?;
    let base = PolicySpec::moderated(&principals, FENCE_CONVERSATION);
    let first = policy(&base)?;
    let previous = verify_policy(&NETWORK, &FENCE_CONVERSATION, &first, &rosters, None)?;

    let mut named_predecessor = first.clone();
    named_predecessor.tbs.previous_policy_id = [1; 32];
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &named_predecessor,
            &rosters,
            None
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "generation zero without a predecessor names no previous policy"
    );

    let successor = PolicySpec {
        generation: 1,
        previous_policy_id: previous.policy_id,
        ..PolicySpec::moderated(&principals, FENCE_CONVERSATION)
    };
    let accepted = policy(&successor)?;
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &accepted,
            &rosters,
            Some(&previous)
        )?
        .generation,
        1
    );

    let mut wrong_previous = accepted.clone();
    wrong_previous.tbs.previous_policy_id = [7; 32];
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &wrong_previous,
            &rosters,
            Some(&previous)
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a successor must name the identifier of the policy it replaces"
    );

    let mut changed_kind = accepted.clone();
    changed_kind.tbs.kind = IrcConversationKind::Direct;
    assert_eq!(
        verify_policy(
            &NETWORK,
            &FENCE_CONVERSATION,
            &changed_kind,
            &rosters,
            Some(&previous)
        )
        .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a generation never changes the conversation kind"
    );
    assert_eq!(previous.kind, IrcConversationKind::Channel);
    Ok(())
}

#[test]
fn the_bound_fence_admits_only_the_declared_device_and_leaf_ranges() -> FenceResult {
    let (principals, rosters) = fixture()?;
    let accepted = policy(&PolicySpec::moderated(&principals, FENCE_CONVERSATION))?;
    let verified = verify_policy(&NETWORK, &FENCE_CONVERSATION, &accepted, &rosters, None)?;
    assert_eq!(
        verified.max_devices_per_account,
        MAX_ACTIVE_DEVICES_PER_ACCOUNT
    );
    assert_eq!(verified.max_group_leaves, MAX_GROUP_LEAVES);

    let refusals: [(&str, u16, u32); 4] = [
        ("no device is permitted", 0, MAX_GROUP_LEAVES),
        (
            "one device beyond the cap",
            MAX_ACTIVE_DEVICES_PER_ACCOUNT.saturating_add(1),
            MAX_GROUP_LEAVES,
        ),
        ("no leaf is permitted", MAX_ACTIVE_DEVICES_PER_ACCOUNT, 0),
        (
            "one leaf beyond the cap",
            MAX_ACTIVE_DEVICES_PER_ACCOUNT,
            MAX_GROUP_LEAVES.saturating_add(1),
        ),
    ];
    for (label, devices, leaves) in refusals {
        let mut refused = accepted.clone();
        refused.tbs.max_devices_per_account = devices;
        refused.tbs.max_group_leaves = leaves;
        assert_eq!(
            verify_policy(&NETWORK, &FENCE_CONVERSATION, &refused, &rosters, None).map(|_| ()),
            Err(E2eeError::LimitExceeded),
            "{label}"
        );
    }

    // The same two fields at the bottom of their ranges are admitted under a
    // policy whose approvals cover the changed bytes, so each refusal above
    // rests on the bound alone and not on the mutation.
    let lowest = resigned(&principals, |tbs| {
        tbs.max_devices_per_account = 1;
        tbs.max_group_leaves = 1;
    })?;
    let bounded = verify_policy(&NETWORK, &FENCE_CONVERSATION, &lowest, &rosters, None)?;
    assert_eq!(bounded.max_devices_per_account, 1);
    assert_eq!(bounded.max_group_leaves, 1);
    Ok(())
}

/// Rebuilds the moderated policy with `edit` applied to its signed fields and
/// every approval recomputed, so an edited policy still carries real
/// signatures over the bytes it now declares.
fn resigned(
    principals: &[Principal],
    edit: impl FnOnce(&mut IrcPolicyTbs),
) -> Result<IrcPolicy, Box<dyn Error>> {
    let spec = PolicySpec::moderated(principals, FENCE_CONVERSATION);
    let mut tbs = policy_tbs(&spec)?;
    edit(&mut tbs);
    let mut approvals: Vec<IrcPolicyApproval> = Vec::new();
    for (index, device) in &spec.approvers {
        let principal = principals.get(*index).ok_or("principal")?;
        approvals.push(IrcPolicyApproval {
            signer_root_fingerprint: root_fingerprint(&principal.root)?,
            signer_device_id: [*device; 16],
            signer_device_certificate_id: certificate_id_of(principal, *device)?,
            device_signature: sign(&key(*device), SignatureDomain::PolicyApproval, &tbs)?,
        });
    }
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    Ok(IrcPolicy {
        tbs,
        approvals: TlsVec::new(approvals)?,
    })
}
