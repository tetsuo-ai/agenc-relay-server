use super::support::*;
use agenc_relay_e2ee::initial_authority::{
    InitialAuthorityEvidence, InitialPrincipalEvidence,
    proposal::{InitialBindingProposal, authenticate_initial_proposal},
};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::{ArcWireObjectKind, DecodeBudget, E2eeError, TlsVec};
use agenc_relay_testkit::e2ee_client::{PolicySpec, policy, policy_id_of};

fn check(f: &Fixture, budget: &mut DecodeBudget) -> Result<InitialBindingProposal, E2eeError> {
    let material = f.encoded()?;
    let principals: Vec<_> = material
        .principals
        .iter()
        .map(|(root, roster)| InitialPrincipalEvidence {
            root_object: root,
            roster_object: roster,
        })
        .collect();
    authenticate_initial_proposal(
        &material.expected,
        &InitialAuthorityEvidence {
            binding_object: &material.binding,
            context_core: &material.core,
            initial_policy_object: &material.policy,
            sequencer_credential: &material.credential,
            principals: &principals,
        },
        &object(ArcWireObjectKind::Policy, &f.operational)?,
        budget,
    )
}

fn unsigned(kind: ArcConversationKind) -> Result<Fixture, E2eeError> {
    let mut f = Fixture::with_kind(40, kind)?;
    let mut planned = f.package.initial_member_plan.entries.as_slice().to_vec();
    planned.push(
        agenc_relay_e2ee::objects::conversation::ArcInitialMemberPlanEntry {
            account_id: agenc_relay_e2ee::Opaque::from_slice(&OTHER)?,
            root_fingerprint: agenc_relay_testkit::e2ee_client::root_fingerprint(
                &f.principals.get(1).ok_or(E2eeError::InvalidValue)?.root,
            )?,
            device_id: [9; 16],
            capability_id: [209; 32],
        },
    );
    f.package.initial_member_plan.entries = TlsVec::new(planned)?;
    let id = agenc_relay_e2ee::route::verify_initial_member_plan(&f.package.initial_member_plan)?;
    f.core.initial_member_plan_id = id;
    f.package.binding.tbs.initial_member_plan_id = id;
    f.seal()?;
    f.package.binding.approvals = TlsVec::new(Vec::new())?;
    f.package.root_binding_locks = TlsVec::new(Vec::new())?;
    Ok(f)
}

#[test]
fn unsigned_channel_and_direct_proposals_preserve_the_pin_and_both_policies() -> TestResult {
    for kind in [ArcConversationKind::Channel, ArcConversationKind::Direct] {
        let f = unsigned(kind)?;
        let p = check(&f, &mut budget())?;
        assert_eq!(p.id(), f.expected.binding_id);
        assert_eq!(p.binding(), &f.package.binding.tbs);
        assert_eq!(p.plan(), &f.package.initial_member_plan);
        assert_eq!(p.core(), &f.core);
        assert_eq!(p.route().kind, kind);
        assert_eq!(p.principals().len(), 2);
        assert_eq!(p.initial_policy().policy_id, f.core.initial_policy_id);
        assert_eq!(
            p.operational_policy().policy_id,
            f.core.required_operational_policy_id
        );
        assert_eq!(p.sequencer().credential_id, f.core.sequencer_credential_id);
        assert!(
            p.validity()
                .covers(agenc_relay_e2ee::identity::ValidationTime(100))
        );
        assert!(f.verify().is_err());
        assert!(check(&f, &mut DecodeBudget::new(1, 1)).is_err());
    }
    Ok(())
}

#[test]
fn approval_and_root_lock_envelopes_cannot_be_imported_as_unsigned_proposals() -> TestResult {
    let mut f = Fixture::new()?;
    f.verify()?;
    assert!(check(&f, &mut budget()).is_err());
    let saved = f.package.binding.approvals.clone();
    f.package.binding.approvals = TlsVec::new(Vec::new())?;
    assert!(check(&f, &mut budget()).is_err());
    f.package.root_binding_locks = TlsVec::new(Vec::new())?;
    f.package.binding.approvals = saved;
    assert!(check(&f, &mut budget()).is_err());
    Ok(())
}

#[test]
fn proposals_require_the_independent_binding_pin_and_every_committed_object() -> TestResult {
    for change in 0..8 {
        let mut f = unsigned(ArcConversationKind::Channel)?;
        match change {
            0 => f.expected.binding_id = [7; 32],
            1 => f.expected.conversation_id = [7; 32],
            2 => f.core.route_binding = [7; 32],
            3 => f.package.binding.tbs.initial_member_plan_id = [7; 32],
            4 => {
                f.package.binding.tbs.channel_instance_id =
                    agenc_relay_e2ee::Opaque::from_slice(&[7; 16])?
            }
            5 => f.principals.reverse(),
            6 => f.credential.tbs.key_generation = 19,
            _ => f.core.initial_validation_time = u64::MAX,
        }
        if !matches!(change, 0 | 1) {
            f.seal()?;
        }
        assert!(
            check(&f, &mut budget()).is_err(),
            "proposal change {change}"
        );
    }
    Ok(())
}

#[test]
fn signatures_governing_both_policies_precede_device_review() -> TestResult {
    for step in 0..3 {
        let mut f = unsigned(ArcConversationKind::Direct)?;
        match step {
            0 | 1 => {
                let policy = if step == 0 {
                    &mut f.policy
                } else {
                    &mut f.operational
                };
                let mut approvals = policy.approvals.as_slice().to_vec();
                approvals
                    .first_mut()
                    .ok_or("policy approval")?
                    .device_signature[0] ^= 1;
                policy.approvals = TlsVec::new(approvals)?;
            }
            _ => {
                let principals = f.principals.iter().collect::<Vec<_>>();
                let mut spec = PolicySpec::operational(
                    &principals,
                    f.expected.conversation_id,
                    ArcConversationKind::Direct,
                    policy_id_of(&f.policy)?,
                )?;
                spec.membership =
                    agenc_relay_e2ee::objects::conversation::ArcMembershipPolicy::Moderated;
                f.operational = policy(&spec)?;
                f.core.required_operational_policy_id = policy_id_of(&f.operational)?;
                f.package.binding.tbs.required_operational_policy_id =
                    f.core.required_operational_policy_id;
                f.seal()?;
            }
        }
        assert!(check(&f, &mut budget()).is_err(), "policy {step}");
    }
    Ok(())
}

#[test]
fn an_operational_council_member_must_be_in_the_committed_device_plan() -> TestResult {
    let mut f = Fixture::new()?;
    f.package.binding.approvals = TlsVec::new(Vec::new())?;
    f.package.root_binding_locks = TlsVec::new(Vec::new())?;
    assert!(check(&f, &mut budget()).is_err());
    Ok(())
}

fn pin_plan(f: &mut Fixture) -> Result<(), E2eeError> {
    let id = agenc_relay_e2ee::route::verify_initial_member_plan(&f.package.initial_member_plan)?;
    f.core.initial_member_plan_id = id;
    f.package.binding.tbs.initial_member_plan_id = id;
    f.seal()
}

fn resign_policies(f: &mut Fixture) -> Result<(), E2eeError> {
    use agenc_relay_crypto::SignatureDomain;
    use agenc_relay_testkit::e2ee_client::{key, sign};
    f.operational.tbs.previous_policy_id = policy_id_of(&f.policy)?;
    for policy in [&mut f.policy, &mut f.operational] {
        let mut approvals = policy.approvals.as_slice().to_vec();
        for approval in &mut approvals {
            approval.device_signature = sign(
                &key(approval.signer_device_id[0]),
                SignatureDomain::PolicyApproval,
                &policy.tbs,
            )?;
        }
        policy.approvals = TlsVec::new(approvals)?;
    }
    f.core.initial_policy_id = policy_id_of(&f.policy)?;
    f.package.binding.tbs.initial_policy_id = f.core.initial_policy_id;
    f.core.required_operational_policy_id = policy_id_of(&f.operational)?;
    f.package.binding.tbs.required_operational_policy_id = f.core.required_operational_policy_id;
    f.seal()
}

#[test]
fn both_signed_policies_bound_every_planned_device_before_signing() -> TestResult {
    for initial in [true, false] {
        let mut f = unsigned(ArcConversationKind::Channel)?;
        let original = f.package.initial_member_plan.entries.as_slice();
        let second = original.get(1).ok_or("second device")?;
        let mut entries = original.to_vec();
        for d in [21, 22] {
            let mut external = second.clone();
            external.account_id = agenc_relay_e2ee::Opaque::from_slice(&[b'c'; 24])?;
            external.root_fingerprint = [33; 32];
            external.device_id = [d; 16];
            external.capability_id = [d; 32];
            entries.push(external);
        }
        f.package.initial_member_plan.entries = TlsVec::new(entries)?;
        pin_plan(&mut f)?;
        check(&f, &mut budget())?;
        let policy = if initial {
            &mut f.policy
        } else {
            &mut f.operational
        };
        policy.tbs.max_group_leaves = 3;
        resign_policies(&mut f)?;
        assert!(matches!(
            check(&f, &mut budget()),
            Err(E2eeError::LimitExceeded)
        ));
        let policy = if initial {
            &mut f.policy
        } else {
            &mut f.operational
        };
        policy.tbs.max_group_leaves = 4;
        policy.tbs.max_devices_per_account = 1;
        resign_policies(&mut f)?;
        assert!(matches!(
            check(&f, &mut budget()),
            Err(E2eeError::LimitExceeded)
        ));
    }
    Ok(())
}

#[test]
fn a_non_council_direct_invitee_must_name_a_bound_account_and_its_roster_device() -> TestResult {
    for change in 0..3 {
        let mut f = unsigned(ArcConversationKind::Direct)?;
        let mut entries = f.package.initial_member_plan.entries.as_slice().to_vec();
        let mut extra = entries.last().ok_or("member")?.clone();
        extra.device_id = [21; 16];
        extra.capability_id = [21; 32];
        if change == 0 {
            extra.account_id = agenc_relay_e2ee::Opaque::from_slice(&[b'c'; 24])?;
        } else if change == 1 {
            extra.root_fingerprint = [0xff; 32];
        }
        entries.push(extra);
        f.package.initial_member_plan.entries = TlsVec::new(entries)?;
        pin_plan(&mut f)?;
        assert!(check(&f, &mut budget()).is_err());
    }
    Ok(())
}

#[test]
fn a_live_non_council_device_cannot_replace_its_principal_root_in_the_plan() -> TestResult {
    use agenc_relay_testkit::e2ee_client::{principal, root_fingerprint, roster_id};
    let mut f = unsigned(ArcConversationKind::Direct)?;
    let updated = principal(41, &OTHER, &[9, 21])?;
    let actual_root = root_fingerprint(&updated.root)?;
    let mut pins = f.package.binding.tbs.principals.as_slice().to_vec();
    pins.get_mut(1).ok_or("principal pin")?.roster_id = roster_id(&updated.roster)?;
    f.package.binding.tbs.principals = TlsVec::new(pins)?;
    *f.principals.get_mut(1).ok_or("fixture principal")? = updated;
    let mut planned = f.package.initial_member_plan.entries.as_slice().to_vec();
    let mut extra = planned.last().ok_or("existing member")?.clone();
    extra.device_id = [21; 16];
    extra.capability_id = [21; 32];
    assert_eq!(extra.root_fingerprint, actual_root);
    planned.push(extra);
    f.package.initial_member_plan.entries = TlsVec::new(planned.clone())?;
    pin_plan(&mut f)?;
    let checked = check(&f, &mut budget())?;
    assert!(
        !checked
            .operational_policy()
            .council
            .iter()
            .any(|m| m.device_id == [21; 16])
    );
    planned.last_mut().ok_or("extra member")?.root_fingerprint = [0xff; 32];
    f.package.initial_member_plan.entries = TlsVec::new(planned)?;
    pin_plan(&mut f)?;
    assert!(check(&f, &mut budget()).is_err());
    Ok(())
}
