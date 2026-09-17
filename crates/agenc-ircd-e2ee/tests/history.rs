#![forbid(unsafe_code)]

//! The historical public authority chain: real-signature transitions from
//! the pinned genesis binding through bootstrap, policy, roster, root,
//! sequencer, and binding transitions, candidate aborts, ReInit attempts
//! and terminals, and terminal close; refusals of every broken chain; and
//! conflict classification.

#[path = "history/support.rs"]
mod support;
use support::*;

#[path = "history/membership.rs"]
mod membership;

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_e2ee::history::{
    AlternativeRecord, ChainLimits, ChainStep, HistoricalChain, Lifecycle, RecordReferences,
};
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::objects::conversation::*;
use agenc_ircd_e2ee::objects::sequencing::IrcCommitAbortReason;
use agenc_ircd_e2ee::{DecodeBudget, E2eeError, IrcWireObjectKind, TlsEncode};
use agenc_ircd_testkit::e2ee_client::*;

/// The creator-only bootstrap council and the full operational council.
fn bootstrap_council(genesis: &Genesis) -> Council<'_> {
    Council {
        genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7), (0, 8), (1, 9)],
    }
}

fn operational_council(genesis: &Genesis) -> Council<'_> {
    Council {
        genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7), (1, 9)],
    }
}

/// Activates the bootstrap so the operational policy governs.
fn activated(genesis: &Genesis) -> Result<(HistoricalChain, Log), E2eeError> {
    let mut chain = genesis.chain()?;
    let mut log = Log::new(genesis)?;
    let council = bootstrap_council(genesis);
    let (candidate_record, candidate) = log.candidate([1; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let operational_id = policy_id_of(&genesis.operational_policy)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::BootstrapActivation,
        action_bits::POLICY | action_bits::BOOTSTRAP,
        operational_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, operational_id)?;
    let policy_object = object(IrcWireObjectKind::Policy, &genesis.operational_policy)?;
    chain.advance(
        &record.bytes,
        &RecordReferences {
            policy_object: Some(&policy_object),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    Ok((chain, log))
}

#[test]
fn the_chain_opens_at_the_pinned_genesis_anchor() -> TestResult {
    let genesis = Genesis::new()?;
    let chain = genesis.chain()?;
    assert_eq!(chain.head().sequence, None);
    assert_eq!(chain.head().record_id, genesis.genesis_id()?);
    assert_eq!(chain.accepted_state_id(), &genesis.genesis_id()?);
    assert_eq!(chain.epoch(), 0);
    assert!(chain.bootstrap_pending());
    assert_eq!(
        chain.policy().policy_id,
        policy_id_of(&genesis.bootstrap_policy)?
    );
    assert_eq!(chain.lifecycle(), &Lifecycle::Active);
    assert_eq!(chain.next_position()?.route_sequence, 0);
    Ok(())
}

#[test]
fn bootstrap_activation_needs_both_councils_and_installs_the_operational_policy() -> TestResult {
    let genesis = Genesis::new()?;
    let (chain, log) = activated(&genesis)?;
    assert!(!chain.bootstrap_pending());
    assert_eq!(
        chain.policy().policy_id,
        policy_id_of(&genesis.operational_policy)?
    );
    assert_eq!(chain.epoch(), 1);
    assert_eq!(chain.head().sequence, Some(1));
    assert_eq!(chain.accepted_state_id(), &log.accepted_state_id);

    // Without the resulting council's quorum the same certificate is refused,
    // and the chain keeps its state.
    let mut chain = genesis.chain()?;
    let mut log = Log::new(&genesis)?;
    let council = Council {
        genesis: &genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7)],
    };
    let (candidate_record, candidate) = log.candidate([1; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let operational_id = policy_id_of(&genesis.operational_policy)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::BootstrapActivation,
        action_bits::POLICY | action_bits::BOOTSTRAP,
        operational_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, operational_id)?;
    let policy_object = object(IrcWireObjectKind::Policy, &genesis.operational_policy)?;
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

#[test]
fn a_bootstrap_pending_group_finalizes_only_plan_adds_confirmations_and_activation() -> TestResult {
    let genesis = Genesis::new()?;
    let mut chain = genesis.chain()?;
    let mut log = Log::new(&genesis)?;
    let council = bootstrap_council(&genesis);
    let (candidate_record, candidate) = log.candidate([1; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::PRIVATE_TOPIC,
        log.policy_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    assert!(adopt(&mut chain, &record).is_err());
    assert!(chain.candidate().is_some());
    Ok(())
}

#[test]
fn routine_steps_advance_and_an_omitted_or_reordered_record_is_refused() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate, finalization) = log.routine_step([2; 32], &council)?;
    assert!(matches!(
        adopt(&mut chain, &candidate)?,
        ChainStep::Candidate(_)
    ));
    let step = adopt(&mut chain, &finalization)?;
    assert!(matches!(
        step,
        ChainStep::Finalized {
            quorum_votes: 2,
            resulting_epoch: 2,
            ..
        }
    ));
    assert_eq!(chain.head().record_id, finalization.id);

    // Omitting the candidate: its finalization cannot follow the head.
    let (candidate, finalization) = log.routine_step([3; 32], &council)?;
    assert!(adopt(&mut chain, &finalization).is_err());
    assert_eq!(chain.head().sequence, Some(3));
    // Reordered: the finalization before its candidate is refused, then the
    // right order succeeds.
    adopt(&mut chain, &candidate)?;
    adopt(&mut chain, &finalization)?;
    // Replaying an adopted record is a wrong position, not idempotent.
    assert!(adopt(&mut chain, &finalization).is_err());
    assert_eq!(chain.head().sequence, Some(5));
    Ok(())
}

#[test]
fn a_finalization_is_refused_without_an_independent_council_quorum() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    // The sequencer signs, but the votes are below the derived quorum.
    let short = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7)],
    };
    let (candidate, finalization) = log.routine_step([2; 32], &short)?;
    adopt(&mut chain, &candidate)?;
    assert!(adopt(&mut chain, &finalization).is_err());
    assert!(chain.candidate().is_some());

    // An invented vote by a device outside the council is refused even
    // though the sequencer certified the proof.
    let mut forged = log.clone_for_fork();
    let council = operational_council(&genesis);
    let tbs = forged.authorization_tbs(
        &candidate_of(&candidate)?,
        IrcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        forged.policy_id,
        [0; 32],
    );
    let (mut request, id) = forged.finalization_request(
        &candidate_of(&candidate)?,
        council.authorization(tbs)?,
        &council,
    )?;
    let mut votes = request.votes.as_slice().to_vec();
    if let Some(vote) = votes.first_mut() {
        vote.signer_device_id = [8; 16];
    }
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    request.votes = agenc_ircd_e2ee::TlsVec::new(votes)?;
    let policy_id = forged.policy_id;
    let record = forged.finalization(request, id, policy_id)?;
    assert!(adopt(&mut chain, &record).is_err());
    assert!(chain.candidate().is_some());
    Ok(())
}

/// The candidate a built record opened, reconstructed from its bytes.
fn candidate_of(record: &Built) -> Result<Candidate, E2eeError> {
    use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
    use agenc_ircd_e2ee::{IrcWireObject, TlsDecode};
    let object = IrcWireObject::decode_kind(
        &record.bytes,
        Some(IrcWireObjectKind::SequencerRecord),
        &mut budget(),
    )?;
    let IrcSequencerRecord::Candidate(receipt) =
        IrcSequencerRecord::decode_exact(object.body(), &mut budget())?
    else {
        return Err(E2eeError::InvalidValue);
    };
    Ok(Candidate {
        receipt,
        id: record.id,
    })
}

#[test]
fn an_abort_discards_the_candidate_and_the_next_candidate_increments_its_sequence() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &record)?;
    let abort = log.abort(&candidate, IrcCommitAbortReason::StagingTimeout, &council)?;
    assert!(matches!(
        adopt(&mut chain, &abort)?,
        ChainStep::Aborted {
            quorum_votes: 2,
            ..
        }
    ));
    assert!(chain.candidate().is_none());
    assert_eq!(chain.epoch(), 1);
    // The next candidate names the abort and carries sequence one.
    let (record, next) = log.candidate([3; 32])?;
    assert_eq!(next.receipt.tbs.candidate_sequence, 1);
    adopt(&mut chain, &record)?;
    // A candidate that restarts at sequence zero after the abort is refused.
    let mut stale = log.clone_for_fork();
    stale.candidate_sequence = 0;
    let (record, _) = stale.candidate([4; 32])?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err());
    Ok(())
}

#[test]
fn a_policy_transition_needs_the_old_controller_threshold_and_the_exact_object() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let refs = genesis.principals.iter().collect::<Vec<_>>();
    let mut spec = PolicySpec::operational(
        &refs,
        genesis.conversation,
        IrcConversationKind::Channel,
        policy_id_of(&genesis.bootstrap_policy)?,
    )?;
    spec.generation = 2;
    spec.previous_policy_id = log.policy_id;
    spec.threshold = 2;
    let next_policy = policy(&spec)?;
    let next_id = policy_id_of(&next_policy)?;
    let council = operational_council(&genesis);
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::POLICY,
        next_id,
        [0; 32],
    );
    // No controller approval at all: refused under the old threshold.
    let unapproved = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7), (1, 9)],
    };
    let (request, id) = log.finalization_request(
        &candidate,
        unapproved.authorization(tbs.clone())?,
        &unapproved,
    )?;
    let mut fork = log.clone_for_fork();
    let record = fork.finalization(request, id, next_id)?;
    let policy_object = object(IrcWireObjectKind::Policy, &next_policy)?;
    let references = RecordReferences {
        policy_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    assert!(
        chain
            .advance(&record.bytes, &references, &mut budget())
            .is_err()
    );
    // The wrong object for the certified resulting policy is refused.
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, next_id)?;
    let wrong = object(IrcWireObjectKind::Policy, &genesis.operational_policy)?;
    assert!(
        chain
            .advance(
                &record.bytes,
                &RecordReferences {
                    policy_object: Some(&wrong),
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    assert!(
        chain
            .advance(&record.bytes, &RecordReferences::default(), &mut budget())
            .is_err()
    );
    // The exact object installs the policy.
    let step = chain.advance(&record.bytes, &references, &mut budget())?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(transitions.policy_id, Some(next_id));
    assert_eq!(chain.policy().policy_id, next_id);
    assert_eq!(chain.policy().controller_threshold, 2);
    Ok(())
}

#[test]
fn a_transition_object_cannot_be_smuggled_beside_a_routine_record() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let (candidate, finalization) = log.routine_step([2; 32], &council)?;
    let policy_object = object(IrcWireObjectKind::Policy, &genesis.operational_policy)?;
    let references = RecordReferences {
        policy_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    assert!(
        chain
            .advance(&candidate.bytes, &references, &mut budget())
            .is_err()
    );
    adopt(&mut chain, &candidate)?;
    assert!(
        chain
            .advance(&finalization.bytes, &references, &mut budget())
            .is_err()
    );
    adopt(&mut chain, &finalization)?;
    Ok(())
}

#[test]
fn roster_and_root_transitions_replace_the_retained_heads() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    // Roster generation one for the second principal, reaffirming device 9.
    let other = genesis.principal(1)?;
    let reaffirmed = active_certificate(other, 9)?;
    let next_roster = roster(
        &other.root_secret,
        &other.root,
        1,
        roster_id(&other.roster)?,
        (other.roster.tbs.not_before, other.roster.tbs.not_after),
        vec![reaffirmed],
        Vec::new(),
    )?;
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::RosterRecovery,
        action_bits::ROSTER,
        log.policy_id,
        [0; 32],
    );
    let none = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7), (1, 9)],
    };
    let (request, id) = log.finalization_request(&candidate, none.authorization(tbs)?, &none)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    let roster_object = object(IrcWireObjectKind::DeviceRoster, &next_roster)?;
    // The roster must be carried with the ROSTER bit.
    assert!(adopt(&mut chain, &record).is_err());
    assert!(chain.candidate().is_some());
    let step = chain.advance(
        &record.bytes,
        &RecordReferences {
            roster_objects: &[&roster_object],
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(
        transitions.roster_heads,
        vec![(OTHER, roster_id(&next_roster)?)]
    );
    let (_, retained) = chain.principals().get(&OTHER).ok_or("principal")?;
    assert_eq!(retained.generation, 1);
    // A skipped roster generation is refused.
    let skipped = roster(
        &other.root_secret,
        &other.root,
        3,
        roster_id(&next_roster)?,
        (other.roster.tbs.not_before, other.roster.tbs.not_after),
        vec![active_certificate(other, 9)?],
        Vec::new(),
    )?;
    let (candidate_record, candidate) = log.candidate([3; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::RosterRecovery,
        action_bits::ROSTER,
        log.policy_id,
        [0; 32],
    );
    let (request, id) = log.finalization_request(&candidate, none.authorization(tbs)?, &none)?;
    let mut fork = log.clone_for_fork();
    let record = fork.finalization(request, id, policy_id)?;
    let skipped_object = object(IrcWireObjectKind::DeviceRoster, &skipped)?;
    assert!(
        chain
            .advance(
                &record.bytes,
                &RecordReferences {
                    roster_objects: &[&skipped_object],
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    assert!(chain.candidate().is_some());

    // Root continuity: the second principal continues its root, publishes a
    // fresh roster under it, and the policy names the new council device.
    let new_secret = key(45);
    let new_root = root(
        &new_secret,
        &OTHER,
        1,
        (0, 2_000_000),
        Some((&other.root_secret, &other.root)),
    )?;
    let new_certificate = certificate(&new_secret, &new_root, &DeviceSpec::new(9))?;
    let new_roster = roster(
        &new_secret,
        &new_root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        vec![new_certificate],
        Vec::new(),
    )?;
    let continued = Principal {
        root_secret: new_secret,
        root: new_root,
        roster: new_roster,
        devices: vec![9],
    };
    let creator = genesis.principal(0)?;
    let refs = [creator, &continued];
    let mut spec = PolicySpec::operational(
        &refs,
        genesis.conversation,
        IrcConversationKind::Channel,
        [0; 32],
    )?;
    spec.generation = 2;
    spec.previous_policy_id = log.policy_id;
    let next_policy = policy(&spec)?;
    let next_id = policy_id_of(&next_policy)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::ROSTER | action_bits::POLICY,
        next_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, next_id)?;
    let root_object = object(IrcWireObjectKind::RootIdentity, &continued.root)?;
    let roster_object = object(IrcWireObjectKind::DeviceRoster, &continued.roster)?;
    let policy_object = object(IrcWireObjectKind::Policy, &next_policy)?;
    // Without the roster under the continued root the transition is incomplete.
    assert!(
        chain
            .advance(
                &record.bytes,
                &RecordReferences {
                    root_objects: &[&root_object],
                    policy_object: Some(&policy_object),
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    let step = chain.advance(
        &record.bytes,
        &RecordReferences {
            root_objects: &[&root_object],
            roster_objects: &[&roster_object],
            policy_object: Some(&policy_object),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(
        transitions.roots,
        vec![(OTHER, root_fingerprint(&continued.root)?)]
    );
    let (retained_root, retained_roster) = chain.principals().get(&OTHER).ok_or("principal")?;
    assert_eq!(retained_root.generation, 1);
    assert_eq!(retained_roster.root_generation, 1);
    assert_eq!(chain.policy().policy_id, next_id);
    // The retired root's device can no longer vote: the new council governs.
    let stale = Council {
        genesis: &genesis,
        approvers: vec![(0, 7)],
        voters: vec![(0, 7), (1, 9)],
    };
    let (candidate_record, candidate) = log.candidate([4; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        log.policy_id,
        [0; 32],
    );
    let (request, id) = log.finalization_request(&candidate, stale.authorization(tbs)?, &stale)?;
    let record = log.finalization(request, id, next_id)?;
    assert!(adopt(&mut chain, &record).is_err());
    Ok(())
}

#[test]
fn a_sequencer_rotation_changes_the_committed_credential_for_later_positions() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let successor = sequencer_credential(
        &key(61),
        1,
        (100, 1_000_000),
        Some((&key(SEQUENCER_SEED), &genesis.credential)),
    )?;
    let successor_id = semantic_id_of(SemanticHashDomain::SequencerKey, &successor.tbs)?;
    // A record signed by the successor before the rotation is refused.
    let mut early = log.clone_for_fork();
    early.sequencer_seed = 61;
    early.credential_id = successor_id;
    let (record, _) = early.candidate([2; 32])?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err());

    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::SEQUENCER,
        log.policy_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    let credential_bytes = successor.encode()?;
    let step = chain.advance(
        &record.bytes,
        &RecordReferences {
            sequencer_credential: Some(&credential_bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(transitions.sequencer_credential_id, Some(successor_id));
    assert_eq!(chain.sequencer().credential_id, successor_id);
    assert_eq!(chain.next_position()?.sequencer_credential_id, successor_id);
    // The old key can no longer sign a later position; the new key can.
    let mut stale = log.clone_for_fork();
    let (record, _) = stale.candidate([3; 32])?;
    let mut probe = chain.clone();
    assert!(adopt(&mut probe, &record).is_err());
    log.sequencer_seed = 61;
    log.credential_id = successor_id;
    let (candidate, finalization) = log.routine_step([3; 32], &council)?;
    adopt(&mut chain, &candidate)?;
    adopt(&mut chain, &finalization)?;
    assert_eq!(chain.epoch(), 3);
    Ok(())
}

#[test]
fn a_binding_migration_installs_the_exact_successor_binding() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let refs = genesis.principals.iter().collect::<Vec<_>>();
    let authority = root_fingerprint(&genesis.principal(0)?.root)?;
    let mut successor = binding_package(&BindingSpec {
        principals: &refs,
        route: channel_route(b"#room", authority)?,
        channel_instance_id: Some([1; 16]),
        conversation_nonce: None,
        group_id: GROUP,
        generation: 1,
        previous_binding_id: genesis.expected.binding_id,
        lock_sequence: 0,
        previous_lock_ids: Vec::new(),
        plan_devices: vec![(&ACCOUNT, authority, 7)],
        initial_policy_id: genesis.package.binding.tbs.initial_policy_id,
        required_operational_policy_id: genesis.package.binding.tbs.required_operational_policy_id,
    })?;
    successor.binding.tbs.sequencer_credential_id =
        genesis.package.binding.tbs.sequencer_credential_id;
    successor.binding.tbs.context_core_id = genesis.package.binding.tbs.context_core_id;
    let successor_id = semantic_id_of(SemanticHashDomain::BindingId, &successor.binding.tbs)?;
    let binding_object = object(IrcWireObjectKind::ConversationBinding, &successor)?;
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    // The authorization must commit the exact successor binding ID.
    let wrong = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::BINDING,
        log.policy_id,
        [77; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(wrong)?, &council)?;
    let mut fork = log.clone_for_fork();
    let policy_id = log.policy_id;
    let record = fork.finalization(request, id, policy_id)?;
    assert!(
        chain
            .advance(
                &record.bytes,
                &RecordReferences {
                    binding_object: Some(&binding_object),
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::BINDING,
        log.policy_id,
        successor_id,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let record = log.finalization(request, id, policy_id)?;
    let step = chain.advance(
        &record.bytes,
        &RecordReferences {
            binding_object: Some(&binding_object),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(transitions.binding_id, Some(successor_id));
    assert_eq!(chain.binding().binding_id, successor_id);
    assert_eq!(chain.binding().generation, 1);
    Ok(())
}

#[test]
fn a_closing_transition_then_an_exact_close_authorization_ends_the_lineage() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let intent = IrcCloseIntent {
        reason_code: 1,
        validation_time: VALIDATION_TIME,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    // A close before the closing transition is refused.
    let (early, _) = log.close(genesis.expected.binding_id, intent.clone(), &council)?;
    assert!(chain.close(&early, &mut budget()).is_err());
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT,
        log.policy_id,
        intent_id,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    let step = adopt(&mut chain, &record)?;
    let ChainStep::Finalized { transitions, .. } = step else {
        return Err("finalized".into());
    };
    assert_eq!(transitions.close_intent_id, Some(intent_id));
    assert_eq!(
        chain.lifecycle(),
        &Lifecycle::Closing {
            close_intent_id: intent_id
        }
    );
    // No candidate may follow a closing group.
    let mut fork = log.clone_for_fork();
    let (late, _) = fork.candidate([3; 32])?;
    assert!(adopt(&mut chain, &late).is_err());
    // A forged intent, another binding, or a stale terminal is refused.
    let forged = IrcCloseIntent {
        reason_code: 2,
        validation_time: VALIDATION_TIME,
    };
    let (wrong_intent, _) = log.close(genesis.expected.binding_id, forged, &council)?;
    assert!(chain.close(&wrong_intent, &mut budget()).is_err());
    let (wrong_binding, _) = log.close([9; 32], intent.clone(), &council)?;
    assert!(chain.close(&wrong_binding, &mut budget()).is_err());
    let (wrong_domain, _) = log.close_signed(
        genesis.expected.binding_id,
        intent.clone(),
        &council,
        agenc_ircd_crypto::SignatureDomain::CommitAuthorization,
    )?;
    assert!(chain.close(&wrong_domain, &mut budget()).is_err());
    assert!(chain.close(&early, &mut budget()).is_err());
    let (close, close_id) = log.close(genesis.expected.binding_id, intent, &council)?;
    assert_eq!(chain.close(&close, &mut budget())?, close_id);
    assert_eq!(chain.lifecycle(), &Lifecycle::Closed { close_id });
    assert!(chain.is_terminal());
    assert_eq!(chain.head().sequence, Some(4));
    assert_eq!(chain.head().record_id, close_id);
    assert!(chain.close(&close, &mut budget()).is_err());
    Ok(())
}

#[test]
fn a_reinit_runs_attempt_abort_attempt_and_activation_to_its_terminal() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let council = operational_council(&genesis);
    let target = [72; 32];
    let (candidate_record, candidate) = log.candidate([2; 32])?;
    adopt(&mut chain, &candidate_record)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::ControlledTransition,
        action_bits::REINIT,
        log.policy_id,
        target,
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let policy_id = log.policy_id;
    let record = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &record)?;
    let old_reinit_state_id = record.id;
    assert!(
        matches!(chain.lifecycle(), Lifecycle::Reinit(state) if state.old_reinit_state_id == old_reinit_state_id && state.target_context_digest == target)
    );
    // No ordinary candidate may follow the ReInit Commit.
    let mut fork = log.clone_for_fork();
    let (late, _) = fork.candidate([3; 32])?;
    assert!(adopt(&mut chain, &late).is_err());
    // The receipt needs its exact attempt object.
    let (attempt_bytes, receipt_record, receipt, attempt) =
        log.reinit_attempt(old_reinit_state_id, 0, target, &council)?;
    assert!(adopt(&mut chain, &receipt_record).is_err());
    let step = chain.advance(
        &receipt_record.bytes,
        &RecordReferences {
            attempt_object: Some(&attempt_bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    assert!(matches!(step, ChainStep::ReinitAttempted(open) if open.attempt_sequence == 0));
    // A wrong target digest is refused at the next attempt after an abort.
    let abort = log.reinit_abort(&receipt, &attempt, 5, &council)?;
    assert!(matches!(
        adopt(&mut chain, &abort)?,
        ChainStep::ReinitAborted {
            quorum_votes: 2,
            ..
        }
    ));
    let mut wrong = log.clone_for_fork();
    let (wrong_bytes, wrong_record, _, _) =
        wrong.reinit_attempt(old_reinit_state_id, 1, [99; 32], &council)?;
    assert!(
        chain
            .advance(
                &wrong_record.bytes,
                &RecordReferences {
                    attempt_object: Some(&wrong_bytes),
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    let (attempt_bytes, receipt_record, receipt, attempt) =
        log.reinit_attempt(old_reinit_state_id, 1, target, &council)?;
    chain.advance(
        &receipt_record.bytes,
        &RecordReferences {
            attempt_object: Some(&attempt_bytes),
            ..RecordReferences::default()
        },
        &mut budget(),
    )?;
    let activation = log.reinit_activation(&receipt, &attempt, &council)?;
    let step = adopt(&mut chain, &activation)?;
    assert!(
        matches!(step, ChainStep::ReinitActivated { new_conversation_id, quorum_votes: 2, .. } if new_conversation_id == [70; 32])
    );
    assert!(chain.is_terminal());
    assert!(
        matches!(chain.lifecycle(), Lifecycle::Activated { reinit_activation_id, .. } if *reinit_activation_id == activation.id)
    );
    let mut fork = log.clone_for_fork();
    let (after, _, _, _) = fork.reinit_attempt(old_reinit_state_id, 2, target, &council)?;
    assert!(
        chain
            .advance(
                &receipt_record.bytes,
                &RecordReferences {
                    attempt_object: Some(&after),
                    ..RecordReferences::default()
                },
                &mut budget()
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn two_valid_successors_are_a_conflict_and_alternative_proofs_are_not() -> TestResult {
    let genesis = Genesis::new()?;
    let (mut chain, mut log) = activated(&genesis)?;
    let before = chain.clone();
    let (record_a, candidate_a) = log.candidate([2; 32])?;
    adopt(&mut chain, &record_a)?;
    // A second receipt at the same position for a different Commit, signed
    // by the committed credential, is a fork.
    let mut branch = log.clone_for_fork();
    branch.route_sequence = 2;
    branch.head = chain.accepted_state_id().to_owned();
    let (record_b, _) = branch.candidate([3; 32])?;
    let verdict = chain.examine_alternative(
        &before,
        &record_b.bytes,
        &RecordReferences::default(),
        &mut budget(),
    )?;
    assert!(
        matches!(verdict, AlternativeRecord::Conflict { installed_record_id, conflicting_record_id, .. } if installed_record_id == record_a.id && conflicting_record_id == record_b.id)
    );
    // The same receipt bytes are the same record.
    let same = chain.examine_alternative(
        &before,
        &record_a.bytes,
        &RecordReferences::default(),
        &mut budget(),
    )?;
    assert!(matches!(same, AlternativeRecord::SameRecord { .. }));
    // A receipt signed by the wrong key is malformed evidence, not a fork.
    let mut forged = log.clone_for_fork();
    forged.route_sequence = 2;
    forged.head = chain.accepted_state_id().to_owned();
    forged.sequencer_seed = 61;
    let (record_c, _) = forged.candidate([4; 32])?;
    assert!(
        chain
            .examine_alternative(
                &before,
                &record_c.bytes,
                &RecordReferences::default(),
                &mut budget()
            )
            .is_err()
    );
    // Two finalizations of one candidate that carry different valid vote
    // subsets are alternative proofs of one semantic terminal.
    let before = chain.clone();
    let full = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7), (0, 8), (1, 9)],
    };
    let tbs = log.authorization_tbs(
        &candidate_a,
        IrcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        log.policy_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate_a, full.authorization(tbs.clone())?, &full)?;
    let policy_id = log.policy_id;
    let mut other = log.clone_for_fork();
    let installed = log.finalization(request, id, policy_id)?;
    adopt(&mut chain, &installed)?;
    let subset = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7), (1, 9)],
    };
    let (request, id) =
        other.finalization_request(&candidate_a, subset.authorization(tbs)?, &subset)?;
    let alternative = other.finalization(request, id, policy_id)?;
    assert_ne!(alternative.bytes, installed.bytes);
    assert_eq!(alternative.id, installed.id);
    let verdict = chain.examine_alternative(
        &before,
        &alternative.bytes,
        &RecordReferences::default(),
        &mut budget(),
    )?;
    assert!(matches!(verdict, AlternativeRecord::SameRecord { .. }));
    // An under-quorum alternative is refused, not classified.
    let short = Council {
        genesis: &genesis,
        approvers: Vec::new(),
        voters: vec![(0, 7)],
    };
    let mut third = log.clone_for_fork();
    third.route_sequence = 3;
    third.head = candidate_a.id;
    third.epoch = 1;
    third.accepted_state_id = *before.accepted_state_id();
    let tbs = third.authorization_tbs(
        &candidate_a,
        IrcCommitAuthorizationRule::RoutineSelfUpdate,
        0,
        policy_id,
        [0; 32],
    );
    let (request, id) =
        third.finalization_request(&candidate_a, short.authorization(tbs)?, &short)?;
    let under = third.finalization(request, id, policy_id)?;
    assert!(
        chain
            .examine_alternative(
                &before,
                &under.bytes,
                &RecordReferences::default(),
                &mut budget()
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn a_chain_from_another_genesis_refuses_this_history_at_its_first_record() -> TestResult {
    let genesis = Genesis::new()?;
    let mut log = Log::new(&genesis)?;
    let (record, _) = log.candidate([1; 32])?;
    let mut chain = genesis.chain()?;
    adopt(&mut chain, &record)?;
    // The same record under a pin for a different group: wrong source head.
    let other = Genesis::with_group([26; 32])?;
    let mut foreign = other.chain()?;
    assert!(adopt(&mut foreign, &record).is_err());
    assert_eq!(foreign.head().sequence, None);
    // A record naming itself as its predecessor never fits a position.
    let mut cyclic = log.clone_for_fork();
    cyclic.head = [0; 32];
    let (looped, _) = cyclic.candidate([2; 32])?;
    assert!(adopt(&mut chain, &looped).is_err());
    Ok(())
}

#[test]
fn limits_budgets_and_truncated_evidence_leave_the_chain_unchanged() -> TestResult {
    let genesis = Genesis::new()?;
    let mut log = Log::new(&genesis)?;
    let council = bootstrap_council(&genesis);
    let (first, candidate) = log.candidate([1; 32])?;
    let operational_id = policy_id_of(&genesis.operational_policy)?;
    let tbs = log.authorization_tbs(
        &candidate,
        IrcCommitAuthorizationRule::BootstrapActivation,
        action_bits::POLICY | action_bits::BOOTSTRAP,
        operational_id,
        [0; 32],
    );
    let (request, id) =
        log.finalization_request(&candidate, council.authorization(tbs)?, &council)?;
    let second = log.finalization(request, id, operational_id)?;
    let policy_object = object(IrcWireObjectKind::Policy, &genesis.operational_policy)?;
    let references = RecordReferences {
        policy_object: Some(&policy_object),
        ..RecordReferences::default()
    };
    let mut chain = HistoricalChain::open(
        &NETWORK,
        &genesis.conversation,
        &genesis.authority()?,
        ChainLimits { max_records: 1 },
    )?;
    adopt(&mut chain, &first)?;
    assert_eq!(
        chain.advance(&second.bytes, &references, &mut budget()),
        Err(E2eeError::LimitExceeded)
    );
    assert_eq!(chain.head().sequence, Some(0));
    // Truncated, wrong-kind, and over-budget evidence changes nothing.
    let mut chain = genesis.chain()?;
    adopt(&mut chain, &first)?;
    let head = chain.head().record_id;
    let truncated = second
        .bytes
        .get(..second.bytes.len() / 2)
        .ok_or("truncate")?;
    assert!(
        chain
            .advance(truncated, &references, &mut budget())
            .is_err()
    );
    assert!(
        chain
            .advance(&policy_object, &references, &mut budget())
            .is_err()
    );
    let mut tiny = DecodeBudget::new(64, 4);
    assert_eq!(
        chain.advance(&second.bytes, &references, &mut tiny),
        Err(E2eeError::BudgetExceeded)
    );
    assert_eq!(chain.head().record_id, head);
    assert!(chain.candidate().is_some());
    chain.advance(&second.bytes, &references, &mut budget())?;
    assert_eq!(chain.head().sequence, Some(1));
    Ok(())
}

fn resumed_from(
    genesis: &Genesis,
    chain: &HistoricalChain,
) -> Result<agenc_ircd_e2ee::history::ResumedChain, E2eeError> {
    Ok(agenc_ircd_e2ee::history::ResumedChain {
        binding: chain.binding().clone(),
        principals: chain.principals().clone(),
        policy: chain.policy().clone(),
        sequencer: *chain.sequencer(),
        required_operational_policy_id: policy_id_of(&genesis.operational_policy)?,
        bootstrap_pending: chain.bootstrap_pending(),
        epoch: chain.epoch(),
        accepted_state_id: *chain.accepted_state_id(),
        head: *chain.head(),
        candidate: chain.candidate().copied(),
        next_candidate_sequence: chain.candidate().map_or(0, |candidate| {
            candidate.candidate_sequence.saturating_add(1)
        }),
        lifecycle: *chain.lifecycle(),
    })
}

#[test]
fn a_chain_resumes_from_validated_heads_and_refuses_disagreeing_facts() -> TestResult {
    let genesis = Genesis::new()?;
    // The genesis anchor: no record yet, the head is the accepted state.
    let fresh = genesis.chain()?;
    let resumed = HistoricalChain::resume(
        &NETWORK,
        &genesis.conversation,
        resumed_from(&genesis, &fresh)?,
        ChainLimits::DEFAULT,
    )?;
    assert_eq!(resumed.head(), fresh.head());
    assert_eq!(resumed.next_position()?.route_sequence, 0);
    // A recorded head after the bootstrap activation.
    let (activated, _) = activated(&genesis)?;
    let resumed = HistoricalChain::resume(
        &NETWORK,
        &genesis.conversation,
        resumed_from(&genesis, &activated)?,
        ChainLimits::DEFAULT,
    )?;
    assert_eq!(resumed.epoch(), 1);
    assert_eq!(resumed.next_position()?.route_sequence, 2);
    // An open candidate agreeing with the head.
    let mut open = genesis.chain()?;
    let mut log = Log::new(&genesis)?;
    let (candidate_record, _) = log.candidate([1; 32])?;
    adopt(&mut open, &candidate_record)?;
    let facts = resumed_from(&genesis, &open)?;
    let resumed = HistoricalChain::resume(
        &NETWORK,
        &genesis.conversation,
        facts.clone(),
        ChainLimits::DEFAULT,
    )?;
    assert_eq!(resumed.candidate(), open.candidate());
    // Facts that disagree with the head are refused.
    let candidate = facts.candidate.ok_or("open candidate")?;
    let disagreeing = [
        agenc_ircd_e2ee::history::OpenCandidate {
            route_sequence: candidate.route_sequence + 1,
            ..candidate
        },
        agenc_ircd_e2ee::history::OpenCandidate {
            candidate_id: [9; 32],
            ..candidate
        },
        agenc_ircd_e2ee::history::OpenCandidate {
            predecessor_record_id: [9; 32],
            ..candidate
        },
    ];
    for wrong in disagreeing {
        let mut facts = resumed_from(&genesis, &open)?;
        facts.candidate = Some(wrong);
        assert_eq!(
            HistoricalChain::resume(&NETWORK, &genesis.conversation, facts, ChainLimits::DEFAULT)
                .err(),
            Some(E2eeError::InvalidValue)
        );
    }
    let mut other_conversation = resumed_from(&genesis, &fresh)?;
    other_conversation.accepted_state_id = *fresh.accepted_state_id();
    assert_eq!(
        HistoricalChain::resume(&NETWORK, &[9; 32], other_conversation, ChainLimits::DEFAULT).err(),
        Some(E2eeError::InvalidValue)
    );
    let mut wrong_anchor = resumed_from(&genesis, &fresh)?;
    wrong_anchor.head.record_id = [9; 32];
    assert_eq!(
        HistoricalChain::resume(
            &NETWORK,
            &genesis.conversation,
            wrong_anchor,
            ChainLimits::DEFAULT
        )
        .err(),
        Some(E2eeError::InvalidValue)
    );
    Ok(())
}
