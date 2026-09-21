#![forbid(unsafe_code)]

//! A finalization's transitions are refused when the proof disagrees with its own
//! authorization, when the old council's quorum is missing, when the validation time lies outside
//! the sequencer credential, and when a policy, binding, bootstrap or lifecycle transition
//! names something other than the exact object or state it may install.

use super::*;

/// A fresh activated chain with one open candidate under the operational council.
fn open_candidate() -> Result<(Genesis, HistoricalChain, Log, Candidate), E2eeError> {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let (record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &record)?;
    Ok((genesis, chain, log, candidate))
}

fn routine_tbs(log: &Log, candidate: &Candidate) -> ArcCommitAuthorizationTbs {
    log.authorization_tbs(
        candidate,
        ArcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        log.policy_id,
        [0; 32],
    )
}

#[test]
fn a_proof_whose_authorization_was_swapped_after_the_acks_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let head = *chain.head();
    let (mut request, _) = log.finalization_request(
        &candidate,
        council.authorization(routine_tbs(&log, &candidate))?,
        &council,
    )?;
    // The swapped authorization commits other resulting digests; the core and ACKs
    // still agree with each other, so only the authorization binding disagrees.
    let mut other = routine_tbs(&log, &candidate);
    other.resulting_group_context_digest = [9; 32];
    other.resulting_ratchet_tree_digest = [10; 32];
    request.proof.authorization = council.authorization(other)?;
    request.proof.core.commit_authorization_id = semantic_id_of(
        SemanticHashDomain::CommitAuthorizationId,
        &request.proof.authorization.tbs,
    )?;
    let id = semantic_id_of(SemanticHashDomain::FinalizationId, &request.proof.core)?;
    let tbs = agenc_relay_e2ee::finality::vote_tbs(
        &log.slot(&candidate),
        candidate.id,
        agenc_relay_e2ee::finality::Terminal::finalize(id),
    );
    request.votes = agenc_relay_e2ee::tls::TlsVec::new(council.votes(&tbs)?)?;
    let policy_id = log.policy_id;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err());
    assert_eq!(*probe.head(), head);
    assert!(probe.candidate().is_some());
    Ok(())
}

#[test]
fn a_validation_time_outside_the_sequencer_credential_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let head = *chain.head();
    let mut tbs = routine_tbs(&log, &candidate);
    tbs.canonical_validation_time = 5_000_000;
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err());
    assert_eq!(*probe.head(), head);
    Ok(())
}

#[test]
fn a_bootstrap_activation_voted_only_by_the_resulting_council_is_refused() -> TestResult {
    let genesis = Genesis::new()?;
    let operational_id = policy_id_of(&genesis.operational_policy)?;
    let policy_object = object(ArcWireObjectKind::Policy, &genesis.operational_policy)?;
    let mut chain = genesis.chain()?;
    let mut log = Log::new(&genesis)?;
    let council = Council {
        genesis: &genesis,
        approvers: vec![(0, 7)],
        voters: vec![(1, 9)],
    };
    let (candidate_record, candidate) = log.candidate([1; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::BootstrapActivation,
        action_bits::POLICY | action_bits::BOOTSTRAP,
        operational_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, operational_id)?;
    let before = chain.head().record_id;
    assert!(
        chain
            .advance(
                &record.bytes,
                &RecordReferences {
                    policy_object: Some(&policy_object),
                    ..RecordReferences::default()
                },
                &mut budget(),
            )
            .is_err()
    );
    assert_eq!(chain.head().record_id, before);
    assert!(chain.bootstrap_pending());
    Ok(())
}

fn next_policy(genesis: &Genesis, log: &Log, threshold: u16) -> Result<ArcPolicy, E2eeError> {
    let refs = genesis.principals.iter().collect::<Vec<_>>();
    let mut spec = PolicySpec::operational(
        &refs,
        genesis.conversation,
        ArcConversationKind::Channel,
        policy_id_of(&genesis.bootstrap_policy)?,
    )?;
    spec.generation = 2;
    spec.previous_policy_id = log.policy_id;
    spec.threshold = threshold;
    policy(&spec)
}

#[test]
fn a_policy_object_that_is_not_the_certified_resulting_policy_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let certified = next_policy(&genesis, &log, 2)?;
    let sibling = next_policy(&genesis, &log, 1)?;
    let certified_id = policy_id_of(&certified)?;
    assert_ne!(certified_id, policy_id_of(&sibling)?);
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::POLICY,
        certified_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log
        .clone_for_fork()
        .finalization(request, id, certified_id)?;
    let sibling_object = object(ArcWireObjectKind::Policy, &sibling)?;
    let mut probe = chain.clone();
    assert!(
        probe
            .advance(
                &record.bytes,
                &RecordReferences {
                    policy_object: Some(&sibling_object),
                    ..RecordReferences::default()
                },
                &mut budget(),
            )
            .is_err(),
        "a valid successor policy that is not the certified one"
    );
    assert_eq!(probe.policy().policy_id, log.policy_id);
    Ok(())
}

#[test]
fn a_bootstrap_bit_after_activation_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let successor = next_policy(&genesis, &log, 2)?;
    let successor_id = policy_id_of(&successor)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::POLICY | action_bits::BOOTSTRAP,
        successor_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log
        .clone_for_fork()
        .finalization(request, id, successor_id)?;
    let successor_object = object(ArcWireObjectKind::Policy, &successor)?;
    let mut probe = chain.clone();
    assert!(
        probe
            .advance(
                &record.bytes,
                &RecordReferences {
                    policy_object: Some(&successor_object),
                    ..RecordReferences::default()
                },
                &mut budget(),
            )
            .is_err()
    );
    assert!(!probe.bootstrap_pending());
    assert_eq!(probe.policy().policy_id, log.policy_id);
    Ok(())
}

#[test]
fn roster_objects_beside_a_record_without_the_roster_bit_are_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let (request, id) = log.finalization_request(
        &candidate,
        council.authorization(routine_tbs(&log, &candidate))?,
        &council,
    )?;
    let policy_id = log.policy_id;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let roster_object = object(
        ArcWireObjectKind::DeviceRoster,
        &genesis.principal(1)?.roster,
    )?;
    let root_object = object(ArcWireObjectKind::RootIdentity, &genesis.principal(1)?.root)?;
    for (name, references) in [
        (
            "a roster",
            RecordReferences {
                roster_objects: &[&roster_object],
                ..RecordReferences::default()
            },
        ),
        (
            "a root",
            RecordReferences {
                root_objects: &[&root_object],
                ..RecordReferences::default()
            },
        ),
    ] {
        let mut probe = chain.clone();
        assert!(
            probe
                .advance(&record.bytes, &references, &mut budget())
                .is_err(),
            "{name}"
        );
        assert!(probe.candidate().is_some(), "{name}");
    }
    let mut probe = chain.clone();
    assert!(matches!(
        adopt(&mut probe, &record)?,
        ChainStep::Finalized { .. }
    ));
    Ok(())
}

#[test]
fn a_binding_package_that_is_not_the_next_generation_is_refused() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let refs = genesis.principals.iter().collect::<Vec<_>>();
    let authority = root_fingerprint(&genesis.principal(0)?.root)?;
    let mut skipped = binding_package(&BindingSpec {
        principals: &refs,
        route: channel_route(b"#room", authority)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: GROUP,
        generation: 2,
        previous_binding_id: genesis.expected.binding_id,
        lock_sequence: 0,
        previous_lock_ids: Vec::new(),
        plan_devices: vec![(&ACCOUNT, authority, 7)],
        initial_policy_id: genesis.package.binding.tbs.initial_policy_id,
        required_operational_policy_id: genesis.package.binding.tbs.required_operational_policy_id,
        sequencer_credential_id: genesis.package.binding.tbs.sequencer_credential_id,
    })?;
    skipped.binding.tbs.context_core_id = genesis.package.binding.tbs.context_core_id;
    let skipped_id = semantic_id_of(SemanticHashDomain::BindingId, &skipped.binding.tbs)?;
    let binding_object = object(ArcWireObjectKind::ConversationBinding, &skipped)?;
    let tbs = log.authorization_tbs(
        &candidate,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::BINDING,
        log.policy_id,
        skipped_id,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.clone_for_fork().finalization(request, id, policy_id)?;
    let mut probe = chain.clone();
    assert!(
        probe
            .advance(
                &record.bytes,
                &RecordReferences {
                    binding_object: Some(&binding_object),
                    ..RecordReferences::default()
                },
                &mut budget(),
            )
            .is_err()
    );
    assert_eq!(probe.binding().generation, 0);
    Ok(())
}

#[test]
fn a_lifecycle_move_needs_a_target_and_cannot_close_and_reinit_at_once() -> TestResult {
    let (genesis, chain, log, candidate) = open_candidate()?;
    let council = operational_council(&genesis);
    let policy_id = log.policy_id;
    for (name, bits, target) in [
        (
            "a close intent without a target",
            action_bits::CLOSE_INTENT,
            [0; 32],
        ),
        ("a reinit without a target", action_bits::REINIT, [0; 32]),
        (
            "a close intent and a reinit together",
            action_bits::CLOSE_INTENT | action_bits::REINIT,
            [5; 32],
        ),
    ] {
        let tbs = log.authorization_tbs(
            &candidate,
            ArcCommitAuthorizationRule::ControlledTransition,
            bits,
            policy_id,
            target,
        );
        let (request, id) =
            log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
        let record = log.clone_for_fork().finalization(request, id, policy_id)?;
        let mut probe = chain.clone();
        assert!(adopt(&mut probe, &record).is_err(), "{name}");
        assert_eq!(probe.lifecycle(), &Lifecycle::Active, "{name}");
        assert!(probe.candidate().is_some(), "{name}");
    }
    Ok(())
}
