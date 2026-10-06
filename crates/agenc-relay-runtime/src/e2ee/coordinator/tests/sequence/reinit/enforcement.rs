//! The ReInit phase begins at the finalization of a ReInit Commit and the
//! sequencer checks every attempt against it (companion 13.8 steps 2 and 4):
//! the old group then takes no ordinary candidate and no application object;
//! an attempt on any other accepted state is `E2EE_FINALITY_REQUIRED` before
//! any other attempt check; and an attempt that does not carry the target the
//! finalized authorization committed, or does not match it, is
//! `E2EE_BINDING_AUTH_INVALID`. Every refusal retains nothing, and a restart
//! restores the phase and its authorized target from the finalization record.

#![forbid(unsafe_code)]

use super::super::reinit_successor::{
    Authorized, LEAF_ZERO, creator_entry, creator_plan, successor, successor_on,
};
use super::*;
use crate::e2ee::coordinator::tests::support::private_message_bytes;
use crate::e2ee::coordinator::tests::{GROUP, INSTANCE, wire_raw};
use agenc_relay_e2ee::limits::MAX_BINDING_PRINCIPALS;
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcCommitAuthorizationRule, ArcKeyPackagePlan, action_bits,
};
use agenc_relay_e2ee::reinit_target::ReinitPredecessor;
use agenc_relay_e2ee::route::channel_route_binding;
use agenc_relay_e2ee::tls::TlsEncode;

/// What a refused request must leave untouched.
#[derive(Debug, Eq, PartialEq)]
struct Retained {
    logs:
        std::collections::BTreeMap<[u8; 32], agenc_relay_domain::e2ee::sequencer_log::SequencerLog>,
    conversations:
        std::collections::BTreeMap<[u8; 32], crate::e2ee::coordinator::ConversationState>,
    objects: usize,
    writes: usize,
}

fn retained(harness: &Harness) -> Retained {
    let state = &harness.coordinator.state;
    Retained {
        logs: state.logs.clone(),
        conversations: state.conversations.clone(),
        objects: state.objects.len(),
        writes: harness.writes.len(),
    }
}

/// Submits `bytes` as an attempt on `conversation` and requires the refusal
/// `expected` with nothing retained.
fn refused(
    harness: &mut Harness,
    conversation: [u8; 32],
    bytes: &[u8],
    expected: E2eeReplyCode,
) -> TestResult {
    let before = retained(harness);
    assert_eq!(
        code(harness.run(Op::SubmitReinitAttempt, &conversation, Some(bytes))?),
        Some(expected)
    );
    assert_eq!(retained(harness), before);
    Ok(())
}

fn accepted_state(harness: &Harness, conversation: [u8; 32]) -> TestResult<[u8; 32]> {
    Ok(*harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id())
}

/// An application object of the bound `#room`.
fn application(conversation: [u8; 32]) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: channel_route_binding(&NETWORK, &INSTANCE)?,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&GROUP, 1, &aad)?,
    )?;
    let mut send = conversation.to_vec();
    send.extend_from_slice(&INSTANCE);
    Ok((send, message))
}

#[test]
fn an_attempt_outside_the_reinit_phase_is_refused_first() -> TestResult {
    // At the genesis anchor.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let genesis = accepted_state(&harness, conversation)?;
    let (_, bytes) = attempt(&harness, conversation, genesis, 0)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    // After an ordinary finalization; an attempt that also carries an
    // unauthorized target is refused for the missing finalization first.
    harness.activate_bootstrap(conversation)?;
    let finalized = accepted_state(&harness, conversation)?;
    let (mut mismatched, bytes) = attempt(&harness, conversation, finalized, 0)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    mismatched.tbs.target_context_digest = [9; 32];
    attempt_authority::authorize_attempt(&harness, &mut mismatched)?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &mismatched)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    // So is one whose successor names a conversation that exists.
    mismatched.tbs.new_conversation_id = conversation;
    attempt_authority::authorize_attempt(&harness, &mut mismatched)?;
    let bytes = wire(ArcWireObjectKind::ReinitAttempt, &mismatched)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    Ok(())
}

#[test]
fn a_reinit_bit_beside_another_bit_closes_the_group_but_admits_no_attempt() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let target = successor(&harness, conversation, creator_plan(&harness)?)?;
    let finalization = harness.finalize_commit(
        conversation,
        Authorized {
            rule: ArcCommitAuthorizationRule::ControlledTransition,
            bits: action_bits::REINIT | action_bits::ROSTER,
            resulting_policy_id: None,
            target_digest: target.digest,
        },
        &[LEAF_ZERO],
    )?;
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?;
    assert_eq!(
        log.phase(),
        Phase::Reinit {
            old_reinit_state_id: finalization
        }
    );
    assert_eq!(
        harness
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("state")?
            .reinit,
        None
    );
    harness.reinit = Some(target);
    let (_, bytes) = attempt(&harness, conversation, finalization, 0)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    // A restart keeps the group closed and the finalization unauthorized.
    let mut restored = harness.reloaded()?;
    refused(
        &mut restored,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )?;
    let commit = super::super::commit_bytes(&restored, conversation, 1, 90)?;
    assert_eq!(
        code(restored.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    Ok(())
}

/// One edit of an attempt that makes it not match the finalized ReInit.
type AttemptEdit = (
    &'static str,
    fn(&Harness, &mut ArcReInitAttempt) -> TestResult,
);

#[test]
fn an_attempt_that_does_not_match_the_authorized_target_is_refused() -> TestResult {
    let edits: [AttemptEdit; 10] = [
        ("another old ReInit state", |_, attempt| {
            attempt.tbs.old_reinit_state_id = [9; 32];
            Ok(())
        }),
        ("another target digest", |_, attempt| {
            attempt.tbs.target_context_digest = [9; 32];
            Ok(())
        }),
        ("a target replaced after finality", |harness, attempt| {
            let other = successor_on(
                harness,
                attempt.tbs.old_conversation_id,
                creator_plan(harness)?,
                [12; 32],
            )?;
            attempt.target = other.target;
            Ok(())
        }),
        (
            "a replaced target named consistently",
            |harness, attempt| {
                let other = successor_on(
                    harness,
                    attempt.tbs.old_conversation_id,
                    creator_plan(harness)?,
                    [12; 32],
                )?;
                attempt.tbs.new_conversation_id = other.conversation;
                attempt.tbs.target_group_id = other.target.target_group_id.clone();
                attempt.tbs.target_context_digest = other.digest;
                attempt.tbs.target_binding_id = other.binding_id;
                attempt.target = other.target;
                Ok(())
            },
        ),
        ("another successor conversation", |_, attempt| {
            attempt.tbs.new_conversation_id = [9; 32];
            Ok(())
        }),
        ("an existing conversation as the successor", |_, attempt| {
            attempt.tbs.new_conversation_id = attempt.tbs.old_conversation_id;
            Ok(())
        }),
        ("another target binding", |_, attempt| {
            attempt.tbs.target_binding_id = [9; 32];
            Ok(())
        }),
        ("another initial member plan", |_, attempt| {
            attempt.tbs.initial_member_plan_id = [9; 32];
            Ok(())
        }),
        ("another suite", |_, attempt| {
            attempt.tbs.target_suite = 3;
            Ok(())
        }),
        (
            "a KeyPackage plan that forms another plan",
            |harness, attempt| {
                let mut entry = creator_entry(harness)?;
                entry.capability_id = [99; 32];
                attempt.key_package_plan = ArcKeyPackagePlan {
                    entries: TlsVec::new(vec![entry])?,
                };
                Ok(())
            },
        ),
    ];
    for (name, edit) in edits {
        let mut harness = Harness::new()?;
        let conversation = harness.bind_channel_for_reinit()?;
        let old_state = accepted_state(&harness, conversation)?;
        let (mut changed, bytes) = attempt(&harness, conversation, old_state, 0)?;
        edit(&harness, &mut changed)?;
        attempt_authority::authorize_attempt(&harness, &mut changed)?;
        let wrong = wire(ArcWireObjectKind::ReinitAttempt, &changed)?;
        refused(
            &mut harness,
            conversation,
            &wrong,
            E2eeReplyCode::BindingAuthInvalid,
        )
        .map_err(|error| format!("{name}: {error}"))?;
        // The unchanged attempt is then admitted.
        let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
        assert!(
            matches!(outcome.result, ResultBody::ReinitStaged(..)),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn an_authorized_target_that_does_not_describe_the_successor_is_refused() -> TestResult {
    // The finalized authorization commits the digest of a target whose
    // extension list carries no context: the attempt hashes to the
    // authorized digest and repeats the target, but the target fails the
    // structural rules against the old binding.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let mut target = successor(&harness, conversation, creator_plan(&harness)?)?;
    target.target.encoded_target_extensions = Opaque::new(vec![0])?;
    target.digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &target.target)?;
    harness.finalize_commit(
        conversation,
        Authorized::reinit(target.digest),
        &[LEAF_ZERO],
    )?;
    harness.reinit = Some(target);
    let old_state = accepted_state(&harness, conversation)?;
    let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::BindingAuthInvalid,
    )
}

#[test]
fn the_old_group_refuses_ordinary_candidates_and_application_objects_after_reinit_finality()
-> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness.activate_bootstrap(conversation)?;
    // Before the ReInit Commit, the activated group takes both.
    let (send, message) = application(conversation)?;
    assert_eq!(
        ok(harness.run(Op::ApplicationChannel, &send, Some(&message))?)?.result,
        ResultBody::AcceptedEvent
    );
    harness.finalize_reinit(conversation)?;
    for restart in [false, true] {
        if restart {
            harness = harness.reloaded()?;
        }
        let epoch = harness
            .coordinator
            .state
            .logs
            .get(&conversation)
            .ok_or("log")?
            .accepted_epoch();
        let before = retained(&harness);
        let commit = super::super::commit_bytes(&harness, conversation, epoch, 90)?;
        assert_eq!(
            code(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?),
            Some(E2eeReplyCode::RouteInvalid),
            "candidate, restart {restart}"
        );
        let (send, message) = application(conversation)?;
        assert_eq!(
            code(harness.run(Op::ApplicationChannel, &send, Some(&message))?),
            Some(E2eeReplyCode::RouteInvalid),
            "application, restart {restart}"
        );
        assert_eq!(retained(&harness), before);
    }
    Ok(())
}

#[test]
fn a_restart_restores_the_reinit_phase_and_its_authorized_target() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_for_reinit()?;
    let old_state = accepted_state(&harness, conversation)?;
    let before = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .reinit
        .ok_or("the authorized ReInit")?;
    assert_eq!(before.finalization_id(), &old_state);
    let digest = harness.reinit.as_ref().ok_or("successor")?.digest;
    assert_eq!(before.target_context_digest(), &digest);
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .cloned()
        .ok_or("log")?;
    let mut restored = harness.reloaded()?;
    assert_eq!(
        restored.coordinator.state.logs.get(&conversation),
        Some(&log)
    );
    assert_eq!(
        restored
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("restored state")?
            .reinit,
        Some(before)
    );
    // The restored phase admits the authorized attempt, and only it.
    let (mut wrong, bytes) = attempt(&restored, conversation, old_state, 0)?;
    wrong.tbs.target_context_digest = [9; 32];
    attempt_authority::authorize_attempt(&restored, &mut wrong)?;
    let wrong = wire(ArcWireObjectKind::ReinitAttempt, &wrong)?;
    refused(
        &mut restored,
        conversation,
        &wrong,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    let outcome = ok(restored.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitStaged(..)));
    // An open attempt and a later restart keep the authorized target.
    let reopened = restored.reloaded()?;
    assert_eq!(
        reopened
            .coordinator
            .state
            .conversations
            .get(&conversation)
            .ok_or("reopened state")?
            .reinit,
        Some(before)
    );
    Ok(())
}

#[test]
fn an_authorized_target_of_another_finalization_admits_no_attempt() -> TestResult {
    // The authority recorded with the phase names the finalization that is
    // the accepted state; one naming any other finalization is refused as
    // finality required, whatever the attempt carries.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_for_reinit()?;
    let old_state = accepted_state(&harness, conversation)?;
    let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
    let mut other = Harness::new()?;
    let elsewhere = other.bind_channel()?;
    other.activate_bootstrap(elsewhere)?;
    other.finalize_reinit(elsewhere)?;
    let foreign = other
        .coordinator
        .state
        .conversations
        .get(&elsewhere)
        .ok_or("other state")?
        .reinit;
    assert!(foreign.is_some());
    assert_ne!(
        foreign.map(|authorized| *authorized.finalization_id()),
        Some(old_state)
    );
    harness
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("state")?
        .reinit = foreign;
    refused(
        &mut harness,
        conversation,
        &bytes,
        E2eeReplyCode::FinalityRequired,
    )
}

#[test]
fn the_carried_target_is_checked_against_the_retained_facts_of_the_old_binding() -> TestResult {
    // The principal's roster moves on after the binding. The attempt is
    // checked against the facts the coordinator retained when it verified
    // the binding, so it is admitted when neither the roster snapshot the
    // binding names nor the binding object is resident.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_for_reinit()?;
    let certificates = harness
        .principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect();
    let successor_roster = crate::e2ee::coordinator::tests::support::roster(
        &harness.principal.root_secret,
        &harness.principal.root,
        1,
        crate::e2ee::coordinator::tests::support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let roster_bytes = wire(ArcWireObjectKind::DeviceRoster, &successor_roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster_bytes))?)?;
    let old_state = accepted_state(&harness, conversation)?;
    let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
    let roster_snapshot = harness
        .coordinator
        .state
        .roster_snapshots
        .get(&crate::e2ee::coordinator::tests::support::roster_id(
            &harness.principal.roster,
        )?)
        .copied()
        .ok_or("the original roster snapshot")?;
    let binding_object = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .binding_object_id;
    for missing in [
        vec![roster_snapshot],
        vec![binding_object],
        vec![roster_snapshot, binding_object],
    ] {
        let mut stripped = harness.reloaded()?;
        for object in missing {
            assert!(stripped.coordinator.state.objects.remove(&object).is_some());
        }
        let outcome = ok(stripped.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
        assert!(matches!(outcome.result, ResultBody::ReinitStaged(..)));
    }
    Ok(())
}

#[test]
fn an_attempt_is_refused_unless_the_retained_facts_describe_its_predecessor() -> TestResult {
    // The carried target must describe the successor of the binding whose
    // facts the coordinator retained. Facts of another binding, no facts,
    // or more principals than a binding admits refuse the attempt,
    // retaining nothing.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel_for_reinit()?;
    let old_state = accepted_state(&harness, conversation)?;
    let (_, bytes) = attempt(&harness, conversation, old_state, 0)?;
    let binding_id = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("state")?
        .binding_object_id;
    let package = crate::e2ee::coordinator::ops::route_successor::binding_object(
        &harness.coordinator.state,
        &binding_id,
    )
    .ok_or("binding")?;
    type TbsEdit = fn(&mut agenc_relay_e2ee::objects::conversation::ArcConversationBindingTbs);
    let edits: [(&str, TbsEdit); 3] = [
        ("generation", |tbs| tbs.binding_generation += 1),
        ("route binding", |tbs| tbs.route_binding[0] ^= 1),
        ("route lock", |tbs| tbs.semantic_route_lock_id[0] ^= 1),
    ];
    for (name, edit) in edits {
        let mut tbs = package.binding.tbs.clone();
        edit(&mut tbs);
        let mut edited = harness.reloaded()?;
        edited
            .coordinator
            .state
            .conversations
            .get_mut(&conversation)
            .ok_or("state")?
            .reinit_facts = Some(ReinitPredecessor::of_binding_tbs(&tbs)?);
        refused(
            &mut edited,
            conversation,
            &bytes,
            E2eeReplyCode::BindingAuthInvalid,
        )
        .map_err(|error| format!("{name}: {error}"))?;
    }
    let mut factless = harness.reloaded()?;
    factless
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("state")?
        .reinit_facts = None;
    refused(
        &mut factless,
        conversation,
        &bytes,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // More principals than a binding admits.
    let mut crowded = harness.reloaded()?;
    let accounts = &mut crowded
        .coordinator
        .state
        .conversations
        .get_mut(&conversation)
        .ok_or("state")?
        .principal_accounts;
    for index in 0..MAX_BINDING_PRINCIPALS {
        accounts.push([u8::try_from(index)?; 24]);
    }
    refused(
        &mut crowded,
        conversation,
        &bytes,
        E2eeReplyCode::BindingAuthInvalid,
    )?;
    // The untouched store admits the attempt.
    let outcome = ok(harness.run(Op::SubmitReinitAttempt, &conversation, Some(&bytes))?)?;
    assert!(matches!(outcome.result, ResultBody::ReinitStaged(..)));
    Ok(())
}
