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
