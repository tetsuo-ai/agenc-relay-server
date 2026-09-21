#![forbid(unsafe_code)]

//! A record that installs nothing may carry no transition object, an
//! alternative is examined only against the exact position before the head,
//! and a close intent needs a nonzero target.

use super::*;

#[test]
fn a_routine_record_refuses_every_supplied_transition_object() -> TestResult {
    let genesis = Genesis::new()?;
    let (chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate, finalization) = log.routine_step([2; 32], &council)?;
    let policy_object = object(ArcWireObjectKind::Policy, &genesis.operational_policy)?;
    let with_policy = RecordReferences {
        policy_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    let with_binding = RecordReferences {
        binding_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    let with_credential = RecordReferences {
        sequencer_credential: Some(&policy_object),
        ..RecordReferences::default()
    };
    let with_attempt = RecordReferences {
        attempt_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    let with_root = RecordReferences {
        root_objects: &[&policy_object],
        ..RecordReferences::default()
    };
    let with_roster = RecordReferences {
        roster_objects: &[&policy_object],
        ..RecordReferences::default()
    };
    for (name, references) in [
        ("policy", &with_policy),
        ("binding", &with_binding),
        ("credential", &with_credential),
        ("attempt", &with_attempt),
        ("root", &with_root),
        ("roster", &with_roster),
    ] {
        let mut probe = chain.clone();
        assert!(
            probe
                .advance(&candidate.bytes, references, &mut budget())
                .is_err(),
            "candidate with {name}"
        );
        assert_eq!(probe.head(), chain.head(), "candidate with {name}");
    }
    let mut probe = chain.clone();
    adopt(&mut probe, &candidate)?;
    let head = *probe.head();
    for (name, references) in [
        ("policy", &with_policy),
        ("binding", &with_binding),
        ("credential", &with_credential),
        ("attempt", &with_attempt),
    ] {
        assert!(
            probe
                .advance(&finalization.bytes, references, &mut budget())
                .is_err(),
            "finalization with {name}"
        );
        assert_eq!(*probe.head(), head, "finalization with {name}");
    }
    assert!(matches!(
        adopt(&mut probe, &finalization)?,
        ChainStep::Finalized { .. }
    ));
    Ok(())
}

#[test]
fn an_alternative_is_examined_only_against_the_position_before_the_head() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let before = chain.clone();
    let base = log.clone_for_fork();
    let (candidate, _finalization) = log.routine_step([2; 32], &council)?;
    adopt(&mut chain, &candidate)?;
    let mut fork = base.clone_for_fork();
    let (alternative, _) = fork.candidate([3; 32])?;
    assert!(
        chain
            .examine_alternative(
                &before,
                &alternative.bytes,
                &RecordReferences::default(),
                &mut budget()
            )
            .is_ok(),
        "a sibling candidate at the head position is an alternative"
    );
    assert!(
        chain
            .examine_alternative(
                &genesis.chain()?,
                &alternative.bytes,
                &RecordReferences::default(),
                &mut budget()
            )
            .is_err(),
        "a chain behind the position before the head cannot examine it"
    );
    assert!(
        genesis
            .chain()?
            .examine_alternative(
                &before,
                &alternative.bytes,
                &RecordReferences::default(),
                &mut budget()
            )
            .is_err(),
        "a chain with no head sequence examines nothing"
    );
    Ok(())
}

#[test]
fn a_close_intent_needs_a_nonzero_target() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT,
        log.policy_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    let head = *chain.head();
    assert!(adopt(&mut chain, &record).is_err());
    assert_eq!(*chain.head(), head);
    assert_eq!(chain.lifecycle(), &Lifecycle::Active);
    Ok(())
}
