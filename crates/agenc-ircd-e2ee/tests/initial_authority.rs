#![forbid(unsafe_code)]

//! Initial public authority and substitutions under a frozen source binding.

#[path = "initial_authority/support.rs"]
mod support;
use support::*;

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::{DecodeBudget, E2eeError, IrcWireObjectKind, Opaque, TlsVec};
use agenc_ircd_testkit::e2ee_client::*;

#[test]
fn one_device_key_cannot_supply_authority_under_two_roots() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.verify()?;
    let second = fixture.principals.get_mut(1).ok_or("principal")?;
    let cert = certificate(
        &second.root_secret,
        &second.root,
        &DeviceSpec {
            device_id: [9; 16],
            ..DeviceSpec::new(7)
        },
    )?;
    let cert_id = semantic_id_of(SemanticHashDomain::DeviceCertificateId, &cert.tbs)?;
    second.roster = roster(
        &second.root_secret,
        &second.root,
        0,
        [0; 32],
        (second.roster.tbs.not_before, second.roster.tbs.not_after),
        vec![cert],
        Vec::new(),
    )?;
    let roster_id = roster_id(&second.roster)?;
    let mut pins = fixture.package.binding.tbs.principals.as_slice().to_vec();
    pins.get_mut(1).ok_or("pin")?.roster_id = roster_id;
    fixture.package.binding.tbs.principals = TlsVec::new(pins)?;
    let mut locks = fixture.package.root_binding_locks.as_slice().to_vec();
    locks.get_mut(1).ok_or("lock")?.tbs.roster_id = roster_id;
    fixture.package.root_binding_locks = TlsVec::new(locks)?;
    let mut approvals = fixture.package.binding.approvals.as_slice().to_vec();
    approvals
        .iter_mut()
        .find(|approval| approval.signer_device_id == [9; 16])
        .ok_or("approval")?
        .signer_device_certificate_id = cert_id;
    fixture.package.binding.approvals = TlsVec::new(approvals)?;
    fixture.seal()?;
    let mut approvals = fixture.package.binding.approvals.as_slice().to_vec();
    approvals
        .iter_mut()
        .find(|approval| approval.signer_device_id == [9; 16])
        .ok_or("approval")?
        .device_signature = sign(
        &key(7),
        SignatureDomain::ConversationBinding,
        &fixture.package.binding.tbs,
    )?;
    fixture.package.binding.approvals = TlsVec::new(approvals)?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn the_bootstrap_creator_plan_entry_must_name_its_roster_account() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut entries = fixture
        .package
        .initial_member_plan
        .entries
        .as_slice()
        .to_vec();
    entries.first_mut().ok_or("entry")?.account_id = account_field(&OTHER)?;
    fixture.package.initial_member_plan.entries = TlsVec::new(entries)?;
    let id = semantic_id_of(
        SemanticHashDomain::InitialMemberPlanId,
        &fixture.package.initial_member_plan,
    )?;
    fixture.package.binding.tbs.initial_member_plan_id = id;
    fixture.core.initial_member_plan_id = id;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn initial_controllers_must_have_rosters_pinned_by_the_binding() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut roots = fixture
        .policy
        .tbs
        .controller_root_fingerprints
        .as_slice()
        .to_vec();
    let mut fingerprints = roots.as_chunks::<32>().0.to_vec();
    fingerprints.push([99; 32]);
    fingerprints.sort();
    roots = fingerprints.concat();
    fixture.policy.tbs.controller_root_fingerprints = Opaque::new(roots)?;
    let mut approvals = fixture.policy.approvals.as_slice().to_vec();
    for approval in &mut approvals {
        approval.device_signature = sign(
            &key(7),
            SignatureDomain::PolicyApproval,
            &fixture.policy.tbs,
        )?;
    }
    fixture.policy.approvals = TlsVec::new(approvals)?;
    let id = policy_id_of(&fixture.policy)?;
    fixture.core.initial_policy_id = id;
    fixture.package.binding.tbs.initial_policy_id = id;
    fixture.seal()?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn revalidates_initial_public_authority_under_an_independent_binding_pin() -> TestResult {
    let fixture = Fixture::new()?;
    let verified = fixture.verify()?;
    assert_eq!(verified.binding().binding_id, fixture.expected.binding_id);
    assert_eq!(verified.principals().len(), 2);
    assert_eq!(verified.policy().policy_id, fixture.core.initial_policy_id);
    assert_eq!(
        verified.sequencer().credential_id,
        fixture.core.sequencer_credential_id
    );
    assert_eq!(verified.validation_time().0, 100);
    assert_eq!(
        verified.required_operational_policy_id(),
        &fixture.core.required_operational_policy_id
    );
    Ok(())
}

#[test]
fn rejects_an_entirely_valid_substitute_authority_for_the_frozen_binding() -> TestResult {
    let original = Fixture::new()?;
    let mut substitute = Fixture::with_seed(42)?;
    substitute.verify()?;
    substitute.expected = original.expected;
    assert!(substitute.verify().is_err());
    Ok(())
}

#[test]
fn requires_every_independent_source_identity_field() -> TestResult {
    for change in 0..4 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => fixture.expected.binding_id = [0; 32],
            1 => fixture.expected.binding_id = [99; 32],
            2 => fixture.expected.conversation_id = [99; 32],
            _ => fixture.expected.network_id = [99; 32],
        }
        assert!(fixture.verify().is_err(), "source field {change}");
    }
    Ok(())
}

#[test]
fn refuses_replacement_and_recreated_bindings_without_preceding_terminals() -> TestResult {
    for recreated in [false, true] {
        let mut fixture = Fixture::new()?;
        if recreated {
            fixture
                .package
                .binding
                .tbs
                .semantic_route
                .semantic_incarnation = 1;
            fixture
                .package
                .binding
                .tbs
                .semantic_route
                .predecessor_close_id = [77; 32];
        } else {
            fixture.package.binding.tbs.binding_generation = 1;
            fixture.package.binding.tbs.previous_binding_id = [77; 32];
            fixture.package.binding.approvals = TlsVec::new(Vec::new())?;
            fixture.package.root_binding_locks = TlsVec::new(Vec::new())?;
        }
        fixture.seal()?;
        assert!(fixture.verify().is_err());
    }
    Ok(())
}

#[test]
fn rejects_missing_extra_reordered_and_duplicate_principal_evidence() -> TestResult {
    for change in 0..5 {
        let mut encoded = Fixture::new()?.encoded()?;
        match change {
            0 => {
                encoded.principals.pop();
            }
            1 => encoded.principals.reverse(),
            2 => {
                let first = encoded.principals.first().ok_or("principal")?.clone();
                encoded.principals.push(first);
            }
            3 => {
                let first = encoded.principals.first().ok_or("principal")?.clone();
                encoded.principals = vec![first; 2];
            }
            _ => encoded.principals.clear(),
        }
        assert!(
            encoded.verify(&mut budget()).is_err(),
            "principal evidence {change}"
        );
    }
    let mut encoded = Fixture::new()?.encoded()?;
    encoded.principals = vec![(Vec::new(), Vec::new()); 65];
    assert!(matches!(
        encoded.verify(&mut budget()),
        Err(E2eeError::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn rejects_newer_signed_rosters_even_when_the_same_device_remains_active() -> TestResult {
    let mut fixture = Fixture::new()?;
    let principal = fixture.principals.first_mut().ok_or("principal")?;
    principal.roster.tbs.previous_roster_id = roster_id(&principal.roster)?;
    principal.roster.tbs.roster_generation = 1;
    principal.roster.root_signature = sign(
        &principal.root_secret,
        SignatureDomain::DeviceRoster,
        &principal.roster.tbs,
    )?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn verifies_signatures_outside_the_pinned_tbs_hashes() -> TestResult {
    for change in 0..6 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => {
                fixture
                    .principals
                    .first_mut()
                    .ok_or("principal")?
                    .root
                    .self_signature = [0; 64]
            }
            1 => {
                fixture
                    .principals
                    .first_mut()
                    .ok_or("principal")?
                    .roster
                    .root_signature = [0; 64]
            }
            2 => {
                let mut approvals = fixture.package.binding.approvals.as_slice().to_vec();
                approvals.first_mut().ok_or("approval")?.device_signature = [0; 64];
                fixture.package.binding.approvals = TlsVec::new(approvals)?;
            }
            3 => {
                let mut locks = fixture.package.root_binding_locks.as_slice().to_vec();
                locks.first_mut().ok_or("lock")?.root_signature = [0; 64];
                fixture.package.root_binding_locks = TlsVec::new(locks)?;
            }
            4 => {
                let mut approvals = fixture.policy.approvals.as_slice().to_vec();
                approvals.first_mut().ok_or("approval")?.device_signature = [0; 64];
                fixture.policy.approvals = TlsVec::new(approvals)?;
            }
            _ => fixture.package.binding.approvals = TlsVec::new(Vec::new())?,
        }
        assert!(fixture.verify().is_err(), "signature {change}");
    }
    Ok(())
}

#[test]
fn checks_core_agreement_even_when_the_binding_commits_the_changed_core() -> TestResult {
    for change in 0..8 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => fixture.core.mls_version = 2,
            1 => fixture.core.initial_policy_id = [88; 32],
            2 => fixture.core.required_operational_policy_id = [88; 32],
            3 => fixture.core.sequencer_credential_id = [88; 32],
            4 => fixture.core.initial_bootstrap_pending = 0,
            5 => fixture.core.network_id = [88; 32],
            6 => fixture.core.group_id = Opaque::new(vec![88; 32])?,
            _ => fixture.core.route_binding = [88; 32],
        }
        fixture.seal()?;
        assert!(fixture.verify().is_err(), "core field {change}");
    }
    Ok(())
}

#[test]
fn a_valid_different_policy_cannot_replace_the_initial_policy_pin() -> TestResult {
    let mut fixture = Fixture::new()?;
    let refs = fixture.principals.iter().collect::<Vec<_>>();
    let mut spec = PolicySpec::bootstrap(
        &refs,
        fixture.expected.conversation_id,
        IrcConversationKind::Channel,
    )?;
    spec.council = vec![(1, 9)];
    fixture.policy = policy(&spec)?;
    assert!(fixture.verify().is_err());
    Ok(())
}

#[test]
fn initial_policy_must_have_the_planned_single_device_bootstrap_council() -> TestResult {
    for planned in [false, true] {
        let mut fixture = Fixture::new()?;
        let refs = fixture.principals.iter().collect::<Vec<_>>();
        let mut spec = PolicySpec::bootstrap(
            &refs,
            fixture.expected.conversation_id,
            IrcConversationKind::Channel,
        )?;
        spec.council = if planned {
            vec![(0, 7), (1, 9)]
        } else {
            vec![(1, 9)]
        };
        fixture.policy = policy(&spec)?;
        let id = policy_id_of(&fixture.policy)?;
        fixture.core.initial_policy_id = id;
        fixture.package.binding.tbs.initial_policy_id = id;
        fixture.seal()?;
        assert!(fixture.verify().is_err());
    }
    Ok(())
}

#[test]
fn a_successor_credential_cannot_replace_the_pinned_initial_credential() -> TestResult {
    for same_key in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.credential = sequencer_credential(
            &key(if same_key { 60 } else { 61 }),
            1,
            (100, 1_000_100),
            Some((&key(60), &fixture.credential)),
        )?;
        assert!(fixture.verify().is_err());
    }
    Ok(())
}

#[test]
fn initial_time_uses_inclusive_credential_bounds_and_no_current_clock() -> TestResult {
    for (time, accepted) in [(199, false), (200, true), (201, true), (202, false)] {
        let mut fixture = Fixture::new()?;
        fixture.credential = sequencer_credential(&key(60), 0, (200, 201), None)?;
        let id = semantic_id_of(SemanticHashDomain::SequencerKey, &fixture.credential.tbs)?;
        fixture.core.sequencer_credential_id = id;
        fixture.package.binding.tbs.sequencer_credential_id = id;
        fixture.core.initial_validation_time = time;
        fixture.seal()?;
        assert_eq!(fixture.verify().is_ok(), accepted, "time {time}");
    }
    Ok(())
}

#[test]
fn the_initial_roster_must_cover_the_committed_initial_time() -> TestResult {
    for before in [false, true] {
        let mut fixture = Fixture::new()?;
        let interval = &fixture.principals.first().ok_or("principal")?.roster.tbs;
        fixture.core.initial_validation_time = if before {
            interval.not_before.checked_sub(1).ok_or("time")?
        } else {
            interval.not_after.checked_add(1).ok_or("time")?
        };
        fixture.seal()?;
        assert!(fixture.verify().is_err());
    }
    Ok(())
}

#[test]
fn rejects_wrong_wire_arms_trailing_bytes_and_exhausted_shared_budgets() -> TestResult {
    for change in 0..7 {
        let fixture = Fixture::new()?;
        let mut encoded = fixture.encoded()?;
        match change {
            0 => encoded.binding.push(0),
            1 => encoded.core.push(0),
            2 => encoded.policy.push(0),
            3 => encoded.credential.push(0),
            4 => encoded.binding = object(IrcWireObjectKind::Policy, &fixture.policy)?,
            5 => encoded.principals.first_mut().ok_or("principal")?.0.push(0),
            _ => encoded.principals.first_mut().ok_or("principal")?.1.push(0),
        }
        assert!(encoded.verify(&mut budget()).is_err(), "encoding {change}");
    }
    let encoded = Fixture::new()?.encoded()?;
    for mut limit in [
        DecodeBudget::new(0, 65536),
        DecodeBudget::new(16 * 1024 * 1024, 0),
        DecodeBudget::new(encoded.binding.len(), 65536),
    ] {
        assert!(matches!(
            encoded.verify(&mut limit),
            Err(E2eeError::BudgetExceeded)
        ));
    }
    Ok(())
}

#[test]
fn exact_pins_allow_historical_rosters_without_their_directory_prefix() -> TestResult {
    let mut fixture = Fixture::new()?;
    let principal = fixture.principals.first_mut().ok_or("principal")?;
    principal.roster.tbs.previous_roster_id = roster_id(&principal.roster)?;
    principal.roster.tbs.roster_generation = 1;
    principal.roster.root_signature = sign(
        &principal.root_secret,
        SignatureDomain::DeviceRoster,
        &principal.roster.tbs,
    )?;
    let mut pins = fixture.package.binding.tbs.principals.as_slice().to_vec();
    let pin = pins.first_mut().ok_or("pin")?;
    pin.roster_id = roster_id(&principal.roster)?;
    pin.roster_generation = 1;
    let mut locks = fixture.package.root_binding_locks.as_slice().to_vec();
    let lock = locks.first_mut().ok_or("lock")?;
    lock.tbs.roster_id = pin.roster_id;
    lock.tbs.roster_generation = pin.roster_generation;
    fixture.package.binding.tbs.principals = TlsVec::new(pins)?;
    fixture.package.root_binding_locks = TlsVec::new(locks)?;
    fixture.seal()?;
    let verified = fixture.verify()?;
    assert_eq!(
        verified
            .principals()
            .get(&ACCOUNT)
            .ok_or("principal")?
            .1
            .generation,
        1
    );
    Ok(())
}

#[test]
fn a_direct_credential_pin_does_not_claim_predecessor_continuity() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.credential = sequencer_credential(
        &key(61),
        1,
        (100, 1_000_100),
        Some((&key(60), &fixture.credential)),
    )?;
    let id = semantic_id_of(SemanticHashDomain::SequencerKey, &fixture.credential.tbs)?;
    fixture.core.sequencer_credential_id = id;
    fixture.package.binding.tbs.sequencer_credential_id = id;
    fixture.seal()?;
    assert_eq!(fixture.verify()?.sequencer().credential_id, id);
    // The trusted binding authorizes this TBS directly. The API does not
    // claim that the earlier key chain or supplied continuity proof is valid.
    fixture.credential.continuity_signature = Opaque::new(vec![0; 64])?;
    assert_eq!(fixture.verify()?.sequencer().credential_id, id);
    fixture.credential.continuity_signature = Opaque::new(vec![0; 63])?;
    assert!(fixture.verify().is_err());
    Ok(())
}

/// Installs `credential` as the fixture's sequencer credential and re-pins it.
fn install_credential(
    fixture: &mut Fixture,
    credential: agenc_ircd_e2ee::objects::conversation::IrcSequencerCredential,
) -> TestResult {
    let id = semantic_id_of(SemanticHashDomain::SequencerKey, &credential.tbs)?;
    fixture.credential = credential;
    fixture.core.sequencer_credential_id = id;
    fixture.package.binding.tbs.sequencer_credential_id = id;
    fixture.seal()?;
    Ok(())
}

#[test]
fn evidence_must_match_the_pins_one_principal_at_a_time() -> TestResult {
    let mut short = Fixture::new()?;
    short.principals.pop();
    assert!(short.verify().is_err(), "fewer evidence pairs than pins");

    let mut fingerprint = Fixture::new()?;
    let mut pins = fingerprint
        .package
        .binding
        .tbs
        .principals
        .as_slice()
        .to_vec();
    pins.first_mut().ok_or("pin")?.root_fingerprint = [9; 32];
    fingerprint.package.binding.tbs.principals = TlsVec::new(pins)?;
    fingerprint.seal()?;
    assert!(fingerprint.verify().is_err(), "pinned root fingerprint");

    let mut generation = Fixture::new()?;
    let mut pins = generation
        .package
        .binding
        .tbs
        .principals
        .as_slice()
        .to_vec();
    pins.first_mut().ok_or("pin")?.roster_generation = 5;
    generation.package.binding.tbs.principals = TlsVec::new(pins)?;
    generation.seal()?;
    assert!(generation.verify().is_err(), "pinned roster generation");

    let mut late = Fixture::new()?;
    install_credential(
        &mut late,
        sequencer_credential(&key(60), 0, (0, 5_000_000), None)?,
    )?;
    late.core.initial_validation_time = 2_500_000;
    late.seal()?;
    assert!(
        late.verify().is_err(),
        "roots no longer cover the initial time"
    );
    Ok(())
}

#[test]
fn the_context_core_policy_ids_are_distinct_and_present() -> TestResult {
    for change in 0..3 {
        let mut fixture = Fixture::new()?;
        match change {
            0 => {
                fixture.core.initial_policy_id = [0; 32];
                fixture.package.binding.tbs.initial_policy_id = [0; 32];
            }
            1 => {
                fixture.core.required_operational_policy_id = [0; 32];
                fixture.package.binding.tbs.required_operational_policy_id = [0; 32];
            }
            _ => {
                let same = fixture.core.initial_policy_id;
                fixture.core.required_operational_policy_id = same;
                fixture.package.binding.tbs.required_operational_policy_id = same;
            }
        }
        fixture.seal()?;
        assert!(fixture.verify().is_err(), "core change {change}");
    }
    Ok(())
}

#[test]
fn the_initial_policy_must_match_the_binding_kind_and_carry_no_fault_bound() -> TestResult {
    for change in 0..2 {
        let mut fixture = Fixture::new()?;
        let refs = fixture.principals.iter().collect::<Vec<_>>();
        let mut spec = PolicySpec::bootstrap(
            &refs,
            fixture.expected.conversation_id,
            IrcConversationKind::Channel,
        )?;
        if change == 0 {
            spec.kind = IrcConversationKind::Direct;
        } else {
            spec.fault_bound = 1;
        }
        fixture.policy = policy(&spec)?;
        let id = policy_id_of(&fixture.policy)?;
        fixture.core.initial_policy_id = id;
        fixture.package.binding.tbs.initial_policy_id = id;
        fixture.seal()?;
        assert!(fixture.verify().is_err(), "policy change {change}");
    }
    Ok(())
}

#[test]
fn the_sequencer_credential_is_checked_field_by_field() -> TestResult {
    let mut profile = Fixture::new()?;
    let mut credential = sequencer_credential(&key(60), 0, (0, 1_000_000), None)?;
    credential.tbs.profile_version = 2;
    install_credential(&mut profile, credential)?;
    assert!(profile.verify().is_err(), "profile version");

    let mut network = Fixture::new()?;
    let mut credential = sequencer_credential(&key(60), 0, (0, 1_000_000), None)?;
    credential.tbs.network_id = [9; 32];
    install_credential(&mut network, credential)?;
    assert!(network.verify().is_err(), "network");

    let mut reversed = Fixture::new()?;
    install_credential(
        &mut reversed,
        sequencer_credential(&key(60), 0, (10, 5), None)?,
    )?;
    assert!(reversed.verify().is_err(), "reversed interval");

    let mut chained = Fixture::new()?;
    let previous = sequencer_credential(&key(61), 0, (0, 1_000_000), None)?;
    install_credential(
        &mut chained,
        sequencer_credential(&key(60), 0, (0, 1_000_000), Some((&key(61), &previous)))?,
    )?;
    assert!(
        chained.verify().is_err(),
        "generation zero with a predecessor"
    );

    let mut stray = Fixture::new()?;
    stray.credential.continuity_signature = Opaque::new(vec![1; 64])?;
    assert!(stray.verify().is_err(), "continuity without a predecessor");
    Ok(())
}
