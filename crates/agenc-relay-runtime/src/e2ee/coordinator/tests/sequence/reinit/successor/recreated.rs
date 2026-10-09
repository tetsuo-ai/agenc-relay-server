//! A route a ReInit migrated, then closed and recreated at its next
//! semantic incarnation (companion 9.4 and 13.8): the successor installed
//! by the activation closes by an authorized `EGROUP CLOSE`, and incarnation
//! one binds on a fresh channel instance naming that close. A restart
//! restores the successor's tombstone behind incarnation one exactly as the
//! live path left them, whatever the order of the restore and the
//! successor's reselection, so a second incarnation one naming the same
//! close is a fork before and after it.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::sequence::leaf_membership::{commit_ack_as, credential_of};
use crate::e2ee::coordinator::tests::sequence::{COMMIT_CONTENT_TYPE, vote};
use crate::e2ee::coordinator::tests::support::{
    BindingSpec, MembershipSpec, PolicySpec, authorization_tbs, binding_package, channel_route,
    commit_approval, commit_authorization, membership_proof, policy, policy_id_of,
    private_message_at_epoch, sign,
};
use crate::e2ee::coordinator::tests::{LEAF_SEED, wire_raw};
use agenc_relay_e2ee::objects::aad::ArcCommitAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcCloseAuthorization, ArcCloseAuthorizationTbs, ArcCloseIntent, ArcCommitAuthorizationRule,
    ArcConversationKind, ArcMembershipPolicy, action_bits,
};
use agenc_relay_e2ee::objects::sequencing::{
    ArcCandidateReceipt, ArcFinalizationCoreTbs, ArcFinalizationProof, ArcFinalizationRequest,
};

/// The channel instances and groups of incarnation one and of the forks.
const NEXT_INSTANCE: [u8; 16] = [91; 16];
const NEXT_GROUP: [u8; 32] = [201; 32];
const LIVE_FORK_INSTANCE: [u8; 16] = [93; 16];
const LIVE_FORK_GROUP: [u8; 32] = [202; 32];
const RESTORED_FORK_INSTANCE: [u8; 16] = [95; 16];
const RESTORED_FORK_GROUP: [u8; 32] = [203; 32];

/// The generation-zero binding of incarnation one of the harness channel's
/// route on `instance`, in `group_id`, naming `close_id`, its root lock
/// continuing the root's lock chain that the coordinator retains; and its
/// conversation.
fn incarnation_one(
    harness: &Harness,
    close_id: [u8; 32],
    instance: [u8; 16],
    group_id: [u8; 32],
) -> TestResult<(Vec<u8>, [u8; 32])> {
    let principals = std::slice::from_ref(&harness.principal);
    let conversation = agenc_relay_e2ee::ids::conversation_id(&NETWORK, &group_id)?;
    let mut bootstrap =
        PolicySpec::bootstrap(principals, conversation, ArcConversationKind::Channel);
    bootstrap.membership = ArcMembershipPolicy::Moderated;
    bootstrap.controllers = vec![0];
    bootstrap.council = vec![(0, DEVICE)];
    bootstrap.approvers = vec![(0, DEVICE)];
    let initial = policy(&bootstrap)?;
    let operational = policy(&bootstrap.successor(policy_id_of(&initial)?))?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let mut route = channel_route(b"#room", fingerprint)?;
    route.semantic_incarnation = 1;
    route.predecessor_close_id = close_id;
    let mut package = binding_package(&BindingSpec {
        principals,
        route,
        channel_instance_id: Some(instance),
        conversation_nonce: None,
        group_id,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices: vec![(&harness.account, fingerprint, DEVICE)],
        initial_policy_id: policy_id_of(&initial)?,
        required_operational_policy_id: policy_id_of(&operational)?,
        sequencer_credential_id: harness.pinned_credential(),
    })?;
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &harness.account)?;
    let head = harness
        .coordinator
        .state
        .binding_locks
        .get(&(digest, fingerprint))
        .and_then(|chain| chain.last_key_value());
    let mut locks = package.root_binding_locks.as_slice().to_vec();
    let lock = locks.first_mut().ok_or("the root lock")?;
    if let Some((sequence, entry)) = head {
        lock.tbs.root_binding_sequence = sequence.checked_add(1).ok_or("lock sequence")?;
        lock.tbs.previous_root_binding_lock_id = entry.lock_id;
    }
    lock.root_signature = sign(
        &harness.principal.root_secret,
        SignatureDomain::RootBindingLock,
        &lock.tbs,
    )?;
    package.root_binding_locks = TlsVec::new(locks)?;
    Ok((
        wire(ArcWireObjectKind::ConversationBinding, &package)?,
        conversation,
    ))
}

/// Finalizes the active-to-closing transition of `conversation` committing
/// `intent_id`, acknowledged by the continuing leaf zero and voted by the
/// council; the authorization's result digests equal the core's, as close
/// admission requires. Returns the finalization identifier.
fn finalize_closing(
    harness: &mut Harness,
    conversation: [u8; 32],
    intent_id: [u8; 32],
) -> TestResult<[u8; 32]> {
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?;
    let old_policy_id = state.current_policy_id;
    let validation_time = state.last_validation_time.saturating_add(1);
    let (group_id, route_binding) = (state.group_id.clone(), state.route_binding);
    let council = state
        .policies
        .get(&old_policy_id)
        .ok_or("the current policy")?
        .policy
        .clone();
    let log = harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("the sequencer log")?;
    let epoch = log.accepted_epoch();
    let prior_state_id = *log.accepted_state_id();
    let aad = ArcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding,
        validation_time,
        prior_state_id,
    }
    .encode()?;
    let commit = wire_raw(
        ArcWireObjectKind::CommitMls,
        private_message_at_epoch(&group_id, epoch, COMMIT_CONTENT_TYPE, &aad)?,
    )?;
    let outcome = ok(harness.run(Op::SubmitCandidate, &conversation, Some(&commit))?)?;
    let event = outcome.events.first().ok_or("the candidate event")?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let receipt = ArcCandidateReceipt::decode_exact(&event.encoded_result, &mut budget)?;
    let candidate_id = semantic_id_of(SemanticHashDomain::CandidateId, &receipt.tbs)?;
    let commit_object_id = object_id(&commit);
    let ack = commit_ack_as(
        conversation,
        epoch,
        candidate_id,
        commit_object_id,
        0,
        credential_of(0),
        LEAF_SEED,
        SignatureDomain::CommitProcessed,
    )?;
    let mut tbs = authorization_tbs(
        conversation,
        old_policy_id,
        ArcCommitAuthorizationRule::ControlledTransition,
        action_bits::CLOSE_INTENT,
    );
    tbs.prior_epoch = epoch;
    tbs.prior_state_id = prior_state_id;
    tbs.candidate_id = candidate_id;
    tbs.commit_object_id = commit_object_id;
    tbs.canonical_validation_time = validation_time;
    tbs.resulting_policy_id = old_policy_id;
    tbs.transition_target_digest = intent_id;
    tbs.resulting_group_context_digest = [2; 32];
    tbs.resulting_ratchet_tree_digest = [3; 32];
    let authorization = commit_authorization(tbs, &[(&harness.principal, DEVICE)])?;
    let core = ArcFinalizationCoreTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        prior_epoch: epoch,
        prior_state_id,
        candidate_id,
        commit_object_id,
        resulting_epoch: epoch.saturating_add(1),
        old_policy_id,
        commit_authorization_id: semantic_id_of(
            SemanticHashDomain::CommitAuthorizationId,
            &authorization.tbs,
        )?,
        acknowledgement_set_digest: agenc_relay_e2ee::ids::proof_set_digest(
            SemanticHashDomain::AcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?,
        resulting_group_context_digest: [2; 32],
        resulting_ratchet_tree_digest: [3; 32],
        finalization_authenticator: [4; 32],
    };
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let votes = harness
        .devices
        .iter()
        .filter(|device| {
            council
                .council_member(&fingerprint, &[**device; 16])
                .is_some()
        })
        .map(|device| {
            vote(
                harness,
                *device,
                &receipt,
                candidate_id,
                Terminal::finalize(finalization_id),
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let request = wire(
        ArcWireObjectKind::FinalizationRequest,
        &ArcFinalizationRequest {
            proof: ArcFinalizationProof {
                core,
                receipt,
                authorization,
                acknowledgements: TlsVec::new(vec![ack])?,
            },
            votes: TlsVec::new(votes)?,
        },
    )?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&request))?)?;
    Ok(finalization_id)
}

/// Closes `conversation` by `EGROUP CLOSE` after its finalized closing
/// transition, with its controller's approval; returns the close
/// identifier.
fn close(harness: &mut Harness, conversation: [u8; 32]) -> TestResult<[u8; 32]> {
    let intent = ArcCloseIntent {
        reason_code: 1,
        validation_time: 90,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    let terminal = finalize_closing(harness, conversation, intent_id)?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .binding;
    let tbs = ArcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        binding_id: binding,
        authorizing_terminal_id: terminal,
        close_intent: intent,
        close_intent_id: intent_id,
    };
    let close = ArcCloseAuthorization {
        approvals: TlsVec::new(vec![commit_approval(
            &harness.principal,
            DEVICE,
            &tbs,
            SignatureDomain::CloseAuthorization,
        )?])?,
        tbs,
    };
    let close_id = agenc_relay_e2ee::route::close_authorization_id(&close)?;
    let bytes = wire(ArcWireObjectKind::CloseAuthorization, &close)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&1_u16.to_be_bytes());
    ok(harness.run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    Ok(close_id)
}

/// Reserves channel `instance` of `#room`.
fn reserve(harness: &mut Harness, instance: [u8; 16]) -> TestResult<[u8; 16]> {
    let mut parameters = instance.to_vec();
    parameters.push(5);
    parameters.extend_from_slice(b"#room");
    match ok(harness.run(Op::ReserveChannel, &parameters, None)?)?.result {
        ResultBody::Reserved(reservation, _) => Ok(reservation),
        _ => Err("a channel reservation".into()),
    }
}

/// Binds `bytes` for `conversation` to `reservation`; the reply code of a
/// refusal.
fn bind(
    harness: &mut Harness,
    reservation: [u8; 16],
    conversation: [u8; 32],
    bytes: &[u8],
) -> TestResult<Result<(), E2eeReplyCode>> {
    let mut parameters = reservation.to_vec();
    parameters.extend_from_slice(&conversation);
    parameters.extend_from_slice(&[44; 32]);
    Ok(harness
        .run(Op::BindGroup, &parameters, Some(bytes))?
        .map(|_| ())
        .map_err(|fail| fail.code))
}

#[test]
fn a_closed_successors_next_incarnation_stays_current_across_a_restart() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let (old, new) = (fixture.old, fixture.new);
    let mut harness = fixture.harness;
    // The successor's continuing leaf at its epoch one acknowledges the
    // closing transition.
    let mut membership = MembershipSpec::continuing(&harness.principal, new, DEVICE, LEAF_SEED, 0);
    membership.epoch = 1;
    harness
        .publish_membership(new, &membership_proof(&membership)?)
        .map_err(|error| format!("membership: {error}"))?;
    let close_id = close(&mut harness, new)?;
    let reservation = reserve(&mut harness, NEXT_INSTANCE)?;
    let (package, next) = incarnation_one(&harness, close_id, NEXT_INSTANCE, NEXT_GROUP)?;
    bind(&mut harness, reservation, next, &package)?
        .map_err(|code| format!("incarnation one: {code:?}"))?;
    let bound = *harness
        .coordinator
        .state
        .routes
        .route(&ConversationId(next))
        .ok_or("incarnation one's route")?;
    let successor = *harness
        .coordinator
        .state
        .routes
        .route(&ConversationId(new))
        .ok_or("the successor's route")?;
    assert_eq!(bound.incarnation, 1);
    assert_eq!(bound.lineage, successor.lineage);
    assert_eq!(
        successor.lifecycle,
        agenc_relay_domain::e2ee::RouteLifecycle::Tombstone { close_id }
    );
    // A restart restores the route table exactly as the live path left it,
    // every index included, whatever the order of the restore and of the
    // successor's reselection.
    let mut restarted = harness.reloaded()?;
    assert_eq!(
        restarted.coordinator.state.routes,
        harness.coordinator.state.routes
    );
    let restored = &restarted.coordinator.state.routes;
    assert!(restored.is_current(&ConversationId(next)));
    assert!(restored.is_current(&ConversationId(new)));
    assert!(!restored.is_current(&ConversationId(old)));
    // Live and after the restart, a second incarnation one naming the same
    // close is a fork.
    for (target, instance, group) in [
        (&mut harness, LIVE_FORK_INSTANCE, LIVE_FORK_GROUP),
        (&mut restarted, RESTORED_FORK_INSTANCE, RESTORED_FORK_GROUP),
    ] {
        let reservation = reserve(target, instance)?;
        let (fork, fork_conversation) = incarnation_one(target, close_id, instance, group)?;
        assert_eq!(
            bind(target, reservation, fork_conversation, &fork)?,
            Err(E2eeReplyCode::GroupConflict)
        );
    }
    Ok(())
}
