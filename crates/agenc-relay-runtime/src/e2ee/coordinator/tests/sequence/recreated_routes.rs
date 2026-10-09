//! Recreated routes through the coordinator's handlers (companion 9.4,
//! 11.3, 11.4 and 11.5): after an authorized close, a channel route binds its
//! next semantic incarnation on a fresh channel instance and a direct pair is
//! reserved and bound again, each under its own semantic lock and naming the
//! close; the new group bootstraps and carries application objects and
//! Commits, live and after restarts; and every refusal the route table made
//! before stays.

#![forbid(unsafe_code)]

mod row_mismatch;

use agenc_relay_domain::e2ee::{ConversationId, DirectPair, RouteLifecycle};
use agenc_relay_e2ee::ids::conversation_id;
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_e2ee::objects::conversation::{
    ArcCloseAuthorization, ArcCloseAuthorizationTbs, ArcCloseIntent, ArcConversationBindingPackage,
    ArcPolicy, ArcReservation, ArcSemanticRouteTbs,
};
use agenc_relay_e2ee::tls::{Opaque, TlsDecode, TlsVec};
use agenc_relay_types::{AccountId, ChannelInstanceId};

use super::super::support::{
    BindingSpec, PolicySpec, Principal, binding_package, channel_route, commit_approval, policy,
    policy_id_of, principal, private_message_bytes, root_fingerprint,
};
use super::recovery_pending::close_authorization::finish;
use super::reinit::successor::reconstruction::reconstruct;
use super::*;
use crate::e2ee::coordinator::ops::Fail;
use crate::e2ee::coordinator::request::Outcome;
use crate::e2ee::coordinator::tests::{ROOT_SEED, account_bytes, account_param, origin_key};

/// The group and channel instance of the channel's next incarnation.
const SECOND_GROUP: [u8; 32] = [34; 32];
const SECOND_INSTANCE: [u8; 16] = [9; 16];
/// The group and channel instance of its incarnation after that.
const THIRD_GROUP: [u8; 32] = [38; 32];
const THIRD_INSTANCE: [u8; 16] = [12; 16];
/// The groups of a direct pair's first and next incarnation.
const DIRECT_GROUP: [u8; 32] = [35; 32];
const SECOND_DIRECT_GROUP: [u8; 32] = [36; 32];
/// The direct peer's root and only device.
const PEER_ROOT_SEED: u8 = 41;
const PEER_DEVICE: u8 = 11;
/// The validation time of every close intent.
const CLOSE_TIME: u64 = 30;

/// The harness principal, as a value of its own.
fn creator(harness: &Harness) -> TestResult<Principal> {
    Ok(principal(ROOT_SEED, &harness.account, &harness.devices)?)
}

/// The two policies of a new group of `principals` in `conversation`: the
/// creator-only bootstrap policy and its successor, both with the creator's
/// device as the whole council, so the single-device fixtures finalize.
fn policies(
    principals: &[Principal],
    conversation: [u8; 32],
    kind: ArcConversationKind,
) -> TestResult<[ArcPolicy; 2]> {
    let mut bootstrap = PolicySpec::bootstrap(principals, conversation, kind);
    bootstrap.membership = agenc_relay_e2ee::objects::conversation::ArcMembershipPolicy::Moderated;
    bootstrap.controllers = vec![0];
    bootstrap.council = vec![(0, DEVICE)];
    bootstrap.approvers = vec![(0, DEVICE)];
    let initial = policy(&bootstrap)?;
    let operational = policy(&bootstrap.successor(policy_id_of(&initial)?))?;
    Ok([initial, operational])
}

/// Re-signs every root lock of `package` to continue the head of its root's
/// lock chain that the coordinator retains (companion 9.4).
fn rechain(
    harness: &Harness,
    package: &mut ArcConversationBindingPackage,
    principals: &[Principal],
) -> TestResult {
    let mut locks = package.root_binding_locks.as_slice().to_vec();
    for lock in &mut locks {
        let account: [u8; 24] = lock.tbs.account_id.as_slice().try_into()?;
        let signer = principals
            .iter()
            .find(|principal| principal.root.tbs.account_id.as_slice() == account)
            .ok_or("the lock's principal")?;
        let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &account)?;
        let head = harness
            .coordinator
            .state
            .binding_locks
            .get(&(digest, lock.tbs.root_fingerprint))
            .and_then(|chain| chain.last_key_value());
        if let Some((sequence, entry)) = head {
            lock.tbs.root_binding_sequence = sequence.checked_add(1).ok_or("lock sequence")?;
            lock.tbs.previous_root_binding_lock_id = entry.lock_id;
        }
        lock.root_signature = sign(
            &signer.root_secret,
            SignatureDomain::RootBindingLock,
            &lock.tbs,
        )?;
    }
    package.root_binding_locks = TlsVec::new(locks)?;
    Ok(())
}

/// One new group to bind: its reservation's concrete route, its package and
/// policies, and its conversation.
struct Group {
    conversation: [u8; 32],
    bytes: Vec<u8>,
    policies: [ArcPolicy; 2],
}

/// The semantic route `route` at `incarnation`, naming `predecessor`.
fn at_incarnation(
    mut route: ArcSemanticRouteTbs,
    incarnation: u64,
    predecessor: [u8; 32],
) -> ArcSemanticRouteTbs {
    route.semantic_incarnation = incarnation;
    route.predecessor_close_id = predecessor;
    route
}

/// The generation-zero binding of `group` on `route`, by `principals`, on
/// the channel `instance` or direct `nonce`, its locks continuing each root's
/// chain.
fn group(
    harness: &Harness,
    principals: &[Principal],
    route: ArcSemanticRouteTbs,
    concrete: (Option<[u8; 16]>, Option<[u8; 32]>),
    group_id: [u8; 32],
) -> TestResult<Group> {
    let conversation = conversation_id(&NETWORK, &group_id)?;
    let policies = policies(principals, conversation, route.kind)?;
    let plan_devices = principals
        .iter()
        .map(|principal| {
            let device = *principal.devices.first().ok_or("a device")?;
            let account: &[u8; 24] = principal.root.tbs.account_id.as_slice().try_into()?;
            Ok((account, root_fingerprint(&principal.root)?, device))
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut package = binding_package(&BindingSpec {
        principals,
        route,
        channel_instance_id: concrete.0,
        conversation_nonce: concrete.1,
        group_id,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        plan_devices,
        initial_policy_id: policy_id_of(&policies[0])?,
        required_operational_policy_id: policy_id_of(&policies[1])?,
        sequencer_credential_id: harness.pinned_credential(),
    })?;
    rechain(harness, &mut package, principals)?;
    Ok(Group {
        conversation,
        bytes: wire(ArcWireObjectKind::ConversationBinding, &package)?,
        policies,
    })
}

/// Reserves channel `instance` of `#room` and returns the reservation.
fn reserve_channel(
    harness: &mut Harness,
    instance: [u8; 16],
) -> TestResult<Result<[u8; 16], Fail>> {
    let mut parameters = instance.to_vec();
    parameters.push(5);
    parameters.extend_from_slice(b"#room");
    Ok(harness
        .run(Op::ReserveChannel, &parameters, None)?
        .map(|outcome| match outcome.result {
            ResultBody::Reserved(reservation, _) => reservation,
            _ => [0; 16],
        }))
}

/// A direct reservation and the conversation nonce it names.
type DirectReservation = ([u8; 16], [u8; 32]);

/// Reserves the direct route to `peer`.
fn reserve_direct(
    harness: &mut Harness,
    peer: &[u8; 24],
) -> TestResult<Result<DirectReservation, Fail>> {
    let outcome = match harness.run(Op::ReserveDirect, &account_param(peer), None)? {
        Ok(outcome) => outcome,
        Err(fail) => return Ok(Err(fail)),
    };
    let ResultBody::Reserved(reservation, _) = outcome.result else {
        return Err("a direct reservation".into());
    };
    let response = outcome.responses.first().ok_or("the reservation object")?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &response.bytes,
        Some(ArcWireObjectKind::Reservation),
        &mut budget,
    )?;
    let reserved = ArcReservation::decode_exact(object.body(), &mut budget)?;
    let nonce = reserved.tbs.conversation_nonce.as_slice().try_into()?;
    Ok(Ok((reservation, nonce)))
}

/// Binds `group` to `reservation`.
fn bind(
    harness: &mut Harness,
    reservation: [u8; 16],
    group: &Group,
) -> TestResult<Result<Outcome, Fail>> {
    let mut parameters = reservation.to_vec();
    parameters.extend_from_slice(&group.conversation);
    parameters.extend_from_slice(&[44; 32]);
    harness.run(Op::BindGroup, &parameters, Some(&group.bytes))
}

/// Binds `group` and publishes its policies and the attached device's leaf
/// proof, as a client does before its first Commit.
fn bind_and_publish(harness: &mut Harness, reservation: [u8; 16], group: &Group) -> TestResult {
    let outcome = ok(bind(harness, reservation, group)?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Bound { conversation_id, .. } if conversation_id == group.conversation
    ));
    for policy in &group.policies {
        harness.publish_policy(group.conversation, policy)?;
    }
    harness.publish_leaf_zero(group.conversation)?;
    Ok(())
}

/// Finalizes the closing transition of `conversation` at `epoch` and closes
/// it with its controller's approval; returns the close identifier and the
/// close's request parameters and object.
fn close_with(
    harness: &mut Harness,
    conversation: [u8; 32],
    epoch: u64,
) -> TestResult<([u8; 32], Vec<u8>, Vec<u8>)> {
    let intent = ArcCloseIntent {
        reason_code: 1,
        validation_time: CLOSE_TIME,
    };
    let intent_id = semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?;
    let terminal = finish(harness, conversation, epoch, Some(intent_id))?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?
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
    let bytes = wire(ArcWireObjectKind::CloseAuthorization, &close)?;
    let close_id = agenc_relay_e2ee::route::close_authorization_id(&close)?;
    let mut parameters = conversation.to_vec();
    parameters.extend_from_slice(&1_u16.to_be_bytes());
    let outcome = ok(harness.run(Op::CloseGroup, &parameters, Some(&bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Closed {
            conversation_id: conversation,
            close_id
        }
    );
    Ok((close_id, parameters, bytes))
}

/// [`close_with`] returning the close identifier only.
fn close(harness: &mut Harness, conversation: [u8; 32], epoch: u64) -> TestResult<[u8; 32]> {
    Ok(close_with(harness, conversation, epoch)?.0)
}

/// Sends one application object on `conversation`, a channel's on its
/// `instance`.
fn application(
    harness: &mut Harness,
    conversation: [u8; 32],
    instance: Option<[u8; 16]>,
) -> TestResult<Result<Outcome, Fail>> {
    let state = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let latest = *harness
        .coordinator
        .state
        .logs
        .get(&conversation)
        .ok_or("log")?
        .accepted_state_id();
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: state.route_binding,
        latest_state_id: latest,
    }
    .encode()?;
    let message = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(&state.group_id, 1, &aad)?,
    )?;
    let mut parameters = conversation.to_vec();
    let opcode = match instance {
        Some(instance) => {
            parameters.extend_from_slice(&instance);
            Op::ApplicationChannel
        }
        None => Op::ApplicationDirect,
    };
    harness.run(opcode, &parameters, Some(&message))
}

/// The bootstrap activation, one application object and one routine
/// Commit of a freshly bound group: the group operates.
fn operate(
    harness: &mut Harness,
    conversation: [u8; 32],
    instance: Option<[u8; 16]>,
) -> TestResult {
    assert_eq!(
        code(application(harness, conversation, instance)?),
        Some(E2eeReplyCode::FinalityRequired),
        "application waits for the bootstrap activation"
    );
    finish(harness, conversation, 0, None)?;
    traffic(harness, conversation, instance, 1)
}

/// One application object and one routine Commit at `epoch`.
fn traffic(
    harness: &mut Harness,
    conversation: [u8; 32],
    instance: Option<[u8; 16]>,
    epoch: u64,
) -> TestResult {
    let outcome = ok(application(harness, conversation, instance)?)?;
    assert_eq!(outcome.result, ResultBody::AcceptedEvent);
    finish(harness, conversation, epoch, None)?;
    Ok(())
}

/// The route the table holds for `conversation`.
fn route_of(
    harness: &Harness,
    conversation: [u8; 32],
) -> TestResult<agenc_relay_domain::e2ee::RouteEntry> {
    Ok(*harness
        .coordinator
        .state
        .routes
        .route(&ConversationId(conversation))
        .ok_or("route")?)
}

/// The harness channel closed at epoch one after its bootstrap.
fn closed_channel() -> TestResult<(Harness, [u8; 32], [u8; 32])> {
    let mut harness = Harness::new()?;
    let first = harness.bind_channel()?;
    finish(&mut harness, first, 0, None)?;
    let close_id = close(&mut harness, first, 1)?;
    Ok((harness, first, close_id))
}

/// The next incarnation of the harness channel's route on the fresh
/// instance, naming `predecessor` at `incarnation`.
fn next_channel(harness: &Harness, incarnation: u64, predecessor: [u8; 32]) -> TestResult<Group> {
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let route = at_incarnation(
        channel_route(b"#room", fingerprint)?,
        incarnation,
        predecessor,
    );
    group(
        harness,
        &[creator(harness)?],
        route,
        (Some(SECOND_INSTANCE), None),
        SECOND_GROUP,
    )
}

#[test]
fn a_closed_channel_route_binds_its_next_incarnation_on_a_fresh_instance() -> TestResult {
    let (mut harness, first, close_id) = closed_channel()?;
    let closed = route_of(&harness, first)?;
    assert_eq!(closed.lifecycle, RouteLifecycle::Tombstone { close_id });
    // The closed instance keeps its tombstone and takes no reservation.
    assert_eq!(
        refusal(reserve_channel(&mut harness, INSTANCE)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    // A restart between the close and the next incarnation changes nothing.
    let mut harness = harness.reloaded()?;
    assert_eq!(route_of(&harness, first)?, closed);
    let reservation = ok_reservation(reserve_channel(&mut harness, SECOND_INSTANCE)?)?;
    let next = next_channel(&harness, 1, close_id)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    let second = route_of(&harness, next.conversation)?;
    assert_eq!(second.incarnation, 1);
    assert_eq!(second.lineage, closed.lock);
    assert_ne!(second.lock, closed.lock);
    assert!(
        !harness
            .coordinator
            .state
            .routes
            .channel_plaintext_allowed(&ChannelInstanceId::from_bytes(INSTANCE))
    );
    let row = harness
        .coordinator
        .state
        .conversations
        .get(&next.conversation)
        .ok_or("conversation")?;
    assert_eq!(row.predecessor_close_id, Some(close_id));
    // The new group bootstraps and operates, live and after a restart.
    operate(&mut harness, next.conversation, Some(SECOND_INSTANCE))?;
    let mut harness = harness.reloaded()?;
    assert_eq!(route_of(&harness, next.conversation)?, second);
    assert_eq!(route_of(&harness, first)?, closed);
    traffic(&mut harness, next.conversation, Some(SECOND_INSTANCE), 2)?;
    // The recreated route closes in turn, and its row keeps the close it
    // follows after a restart.
    let second_close = close(&mut harness, next.conversation, 3)?;
    let mut harness = harness.reloaded()?;
    let closed_second = route_of(&harness, next.conversation)?;
    assert_eq!(
        closed_second.lifecycle,
        RouteLifecycle::Tombstone {
            close_id: second_close
        }
    );
    assert_eq!(closed_second.incarnation, 1);
    assert_eq!(
        harness
            .coordinator
            .state
            .conversations
            .get(&next.conversation)
            .ok_or("conversation")?
            .predecessor_close_id,
        Some(close_id)
    );
    // After that restart the route's lineage still ends at the later close:
    // incarnation two binds naming it, not the earlier close, and survives a
    // restart too.
    let reservation = ok_reservation(reserve_channel(&mut harness, THIRD_INSTANCE)?)?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let stale = group(
        &harness,
        &[creator(&harness)?],
        at_incarnation(channel_route(b"#room", fingerprint)?, 2, close_id),
        (Some(THIRD_INSTANCE), None),
        THIRD_GROUP,
    )?;
    assert_eq!(
        code(bind(&mut harness, reservation, &stale)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let third = group(
        &harness,
        &[creator(&harness)?],
        at_incarnation(channel_route(b"#room", fingerprint)?, 2, second_close),
        (Some(THIRD_INSTANCE), None),
        THIRD_GROUP,
    )?;
    bind_and_publish(&mut harness, reservation, &third)?;
    let harness = harness.reloaded()?;
    let restored = route_of(&harness, third.conversation)?;
    assert_eq!(restored.incarnation, 2);
    assert_eq!(restored.lineage, closed.lock);
    assert_eq!(
        harness
            .coordinator
            .state
            .conversations
            .get(&third.conversation)
            .ok_or("conversation")?
            .predecessor_close_id,
        Some(second_close)
    );
    Ok(())
}

/// The reply code a refused reservation names.
fn refusal<T>(outcome: Result<T, Fail>) -> Option<E2eeReplyCode> {
    outcome.err().map(|fail| fail.code)
}

fn ok_reservation<T>(outcome: Result<T, Fail>) -> TestResult<T> {
    outcome.map_err(|fail| format!("refused with {:?}", fail.code).into())
}

#[test]
fn a_recreated_channel_route_keeps_every_refusal() -> TestResult {
    let mut harness = Harness::new()?;
    let first = harness.bind_channel()?;
    finish(&mut harness, first, 0, None)?;
    // While the first incarnation is live its route takes no next one.
    let reservation = ok_reservation(reserve_channel(&mut harness, SECOND_INSTANCE)?)?;
    let early = next_channel(&harness, 1, [9; 32])?;
    assert_eq!(
        code(bind(&mut harness, reservation, &early)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    let (close_id, parameters, bytes) = close_with(&mut harness, first, 1)?;
    // A replayed close finds no live route.
    assert_eq!(
        code(harness.run(Op::CloseGroup, &parameters, Some(&bytes))?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    // A wrong close, a skipped incarnation, a replay of incarnation zero, and
    // a later incarnation without a close are no successor.
    for (incarnation, predecessor) in [(1, [8; 32]), (2, close_id), (0, [0; 32]), (1, [0; 32])] {
        let refused = next_channel(&harness, incarnation, predecessor)?;
        assert_eq!(
            code(bind(&mut harness, reservation, &refused)?),
            Some(E2eeReplyCode::BindingAuthInvalid),
            "incarnation {incarnation}"
        );
    }
    let next = next_channel(&harness, 1, close_id)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    // The close has opened one incarnation: another group naming it again is
    // a fork of that incarnation.
    let reservation = ok_reservation(reserve_channel(&mut harness, [10; 16])?)?;
    let fingerprint = root_fingerprint(&harness.principal.root)?;
    let again = group(
        &harness,
        &[creator(&harness)?],
        at_incarnation(channel_route(b"#room", fingerprint)?, 1, close_id),
        (Some([10; 16]), None),
        [37; 32],
    )?;
    assert_eq!(
        code(bind(&mut harness, reservation, &again)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    Ok(())
}

/// The harness account and a peer with a published root and roster: the
/// origin is declared under the peer's account for the peer's publications
/// (an account switch on that connection), then back.
fn direct_peer(harness: &mut Harness) -> TestResult<Principal> {
    let peer_account = account_bytes(10)?;
    assert!(
        harness.account.as_slice() < peer_account.as_slice(),
        "the harness account creates the pair"
    );
    let peer = principal(PEER_ROOT_SEED, &peer_account, &[PEER_DEVICE])?;
    let origin_key = origin_key();
    let saved = harness
        .coordinator
        .state
        .origins
        .get(&origin_key)
        .cloned()
        .ok_or("origin")?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key) {
        origin.account_id = Some(peer_account);
        origin.account_digest = Some(agenc_relay_e2ee::ids::account_id_digest(
            &NETWORK,
            &peer_account,
        )?);
        origin.device = None;
    }
    let root = wire(ArcWireObjectKind::RootIdentity, &peer.root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&root))?)?;
    let roster = wire(ArcWireObjectKind::DeviceRoster, &peer.roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster))?)?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key) {
        origin.account_id = saved.account_id;
        origin.account_digest = saved.account_digest;
        origin.device = saved.device;
    }
    Ok(peer)
}

/// The direct semantic route of the harness account and `peer` at
/// `incarnation`, naming `predecessor`.
fn direct_route(
    harness: &Harness,
    peer: &Principal,
    incarnation: u64,
    predecessor: [u8; 32],
) -> TestResult<ArcSemanticRouteTbs> {
    Ok(ArcSemanticRouteTbs {
        profile_version: 1,
        network_id: NETWORK,
        kind: ArcConversationKind::Direct,
        direct_account_a: Opaque::from_slice(&harness.account)?,
        direct_account_b: Opaque::from_slice(peer.root.tbs.account_id.as_slice())?,
        canonical_channel_name: Opaque::new(Vec::new())?,
        channel_authority_root_fingerprint: [0; 32],
        semantic_incarnation: incarnation,
        predecessor_close_id: predecessor,
    })
}

/// The direct group of the pair at `incarnation` on the reserved `nonce`.
fn direct_group(
    harness: &Harness,
    peer: &Principal,
    (incarnation, predecessor): (u64, [u8; 32]),
    nonce: [u8; 32],
    group_id: [u8; 32],
) -> TestResult<Group> {
    let peer_copy = principal(
        PEER_ROOT_SEED,
        &peer.root.tbs.account_id.as_slice().try_into()?,
        &[PEER_DEVICE],
    )?;
    group(
        harness,
        &[creator(harness)?, peer_copy],
        direct_route(harness, peer, incarnation, predecessor)?,
        (None, Some(nonce)),
        group_id,
    )
}

#[test]
fn a_closed_direct_pair_is_reserved_and_bound_again() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let peer = direct_peer(&mut harness)?;
    let peer_account: [u8; 24] = peer.root.tbs.account_id.as_slice().try_into()?;
    let pair = DirectPair::new(
        AccountId::parse_wire_bytes(&harness.account)?,
        AccountId::parse_wire_bytes(&peer_account)?,
    )?;
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    let first = direct_group(&harness, &peer, (0, [0; 32]), nonce, DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &first)?;
    operate(&mut harness, first.conversation, None)?;
    // The live pair, and the closing one, take no other reservation.
    assert_eq!(
        refusal(reserve_direct(&mut harness, &peer_account)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    let close_id = close(&mut harness, first.conversation, 2)?;
    let closed = route_of(&harness, first.conversation)?;
    assert!(
        !harness
            .coordinator
            .state
            .routes
            .direct_plaintext_allowed(&pair)
    );
    // After the authorized close, and after a restart, the creator reserves
    // the pair again and binds the next incarnation naming that close.
    let mut harness = harness.reloaded()?;
    assert_eq!(route_of(&harness, first.conversation)?, closed);
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    let wrong = direct_group(&harness, &peer, (1, [8; 32]), nonce, SECOND_DIRECT_GROUP)?;
    assert_eq!(
        code(bind(&mut harness, reservation, &wrong)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let replay = direct_group(&harness, &peer, (0, [0; 32]), nonce, SECOND_DIRECT_GROUP)?;
    assert_eq!(
        code(bind(&mut harness, reservation, &replay)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let next = direct_group(&harness, &peer, (1, close_id), nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    let second = route_of(&harness, next.conversation)?;
    assert_eq!(second.incarnation, 1);
    assert_eq!(second.lineage, closed.lock);
    assert_eq!(
        harness.coordinator.state.routes.direct_route(&pair),
        Some(&second)
    );
    // The pair's query answers the live incarnation.
    let query = ok(harness.run(Op::QueryDirect, &account_param(&peer_account), None)?)?;
    assert!(matches!(
        query.result,
        ResultBody::Bound { conversation_id, .. } if conversation_id == next.conversation
    ));
    operate(&mut harness, next.conversation, None)?;
    // A live next incarnation keeps the pair.
    assert_eq!(
        refusal(reserve_direct(&mut harness, &peer_account)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    // A restart restores both incarnations and indexes the live one.
    let mut harness = harness.reloaded()?;
    assert_eq!(route_of(&harness, next.conversation)?, second);
    assert_eq!(route_of(&harness, first.conversation)?, closed);
    assert_eq!(
        harness.coordinator.state.routes.direct_route(&pair),
        Some(&second)
    );
    assert!(
        harness
            .coordinator
            .state
            .routes
            .is_current(&ConversationId(next.conversation))
    );
    assert!(
        !harness
            .coordinator
            .state
            .routes
            .is_current(&ConversationId(first.conversation))
    );
    traffic(&mut harness, next.conversation, None, 2)?;
    assert_eq!(
        code(application(&mut harness, first.conversation, None)?),
        Some(E2eeReplyCode::RouteInvalid)
    );
    Ok(())
}

/// A harness whose coordinator is rebuilt from every row `harness` wrote,
/// sealed into a storage fixture and read back as a restart reads it.
async fn sealed_restart(harness: &Harness) -> TestResult<Harness> {
    let (coordinator, result) = Box::pin(reconstruct(&harness.writes)).await?;
    result.map_err(|fault| format!("restore: {fault:?}"))?;
    let mut fresh = harness.reloaded()?;
    fresh.coordinator = coordinator;
    let device = harness.device();
    if let Some(origin) = fresh.coordinator.state.origins.get_mut(&origin_key()) {
        origin.next_sequence = harness.sequence;
        origin.device = device;
    }
    Ok(fresh)
}

#[tokio::test]
async fn a_recreated_direct_pair_restarts_through_the_sealed_store() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let peer = direct_peer(&mut harness)?;
    let peer_account: [u8; 24] = peer.root.tbs.account_id.as_slice().try_into()?;
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    let first = direct_group(&harness, &peer, (0, [0; 32]), nonce, DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &first)?;
    operate(&mut harness, first.conversation, None)?;
    let close_id = close(&mut harness, first.conversation, 2)?;
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    let next = direct_group(&harness, &peer, (1, close_id), nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &next)?;
    operate(&mut harness, next.conversation, None)?;
    let live = route_of(&harness, next.conversation)?;
    let closed = route_of(&harness, first.conversation)?;
    let mut restarted = sealed_restart(&harness).await?;
    assert_eq!(route_of(&restarted, next.conversation)?, live);
    assert_eq!(route_of(&restarted, first.conversation)?, closed);
    let pair = DirectPair::new(
        AccountId::parse_wire_bytes(&restarted.account)?,
        AccountId::parse_wire_bytes(&peer_account)?,
    )?;
    assert_eq!(
        restarted.coordinator.state.routes.direct_route(&pair),
        Some(&live)
    );
    traffic(&mut restarted, next.conversation, None, 2)?;
    assert_eq!(
        refusal(reserve_direct(&mut restarted, &peer_account)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    Ok(())
}
