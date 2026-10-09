//! Companion 9.4 and 11.4 through the production daemons: an encrypted
//! direct conversation is closed by an authorized `EGROUP CLOSE`, and the
//! pair, reserved again, binds its next semantic incarnation naming that
//! close, bootstraps and carries traffic both ways. After a coordinator
//! restart and then an edge restart the restored incarnation carries
//! traffic, then closes in its turn, and the incarnation after it binds and
//! carries traffic. While an incarnation is live the pair takes no other
//! reservation and plaintext between the two accounts is refused; a closed
//! incarnation takes no traffic. Both accounts use edge A.
#![forbid(unsafe_code)]

use super::close_authority::{CertificationTransition, authorization};
use super::recovery_submission::{attach_when_active, settle};
use super::stage_ten_drills::wait_for_account_authority;
use super::*;

/// The group of incarnation two, bound after the restarts.
const THIRD_DIRECT_GROUP: [u8; 32] = [77; 32];

/// One account's client session and keys.
struct Party {
    client: ArcClient,
    keys: Principal,
    nickname: &'static str,
    login: &'static str,
    account: AccountId,
    /// The account request seed of its session after the edge restart.
    rejoin_seed: u8,
}

/// Requests `EGROUP RESERVE DIRECT` of the pair from `creator` and returns
/// the labeled reply.
fn reserve(creator: &mut Party, peer: &Party) -> TestResult<Vec<String>> {
    let label = creator.keys.label();
    creator.client.send(&format!(
        "@label={label} EGROUP RESERVE DIRECT {}",
        base64url_encode(&peer.keys.account)
    ))?;
    labeled_reply(&mut creator.client, &label)
}

/// Another reservation of the pair is refused while an incarnation is live.
fn pair_held(creator: &mut Party, peer: &Party) -> TestResult {
    let held = reserve(creator, peer)?;
    assert_contains(&held, "FAIL EGROUP E2EE_GROUP_CONFLICT")
}

/// Reserves the pair and binds its incarnation `incarnation` naming
/// `predecessor` in `group`. Each root binds only this pair's
/// incarnations, so its binding lock's sequence is the incarnation and the
/// lock continues the one `previous` holds.
fn bind_direct(
    creator: &mut Party,
    peer: &Party,
    (incarnation, predecessor): (u64, [u8; 32]),
    previous: Option<&BoundConversation>,
    group: [u8; 32],
) -> TestResult<BoundConversation> {
    // The creator's edge may still be activating its encrypted profile.
    let reply = settle("the direct reservation", || {
        let reply = reserve(creator, peer)?;
        assert_contains(&reply, " EGROUP RESERVED ")?;
        Ok(reply)
    })?;
    let reservation = reservation_of(&reply)?;
    let nonce: [u8; 32] = reservation
        .tbs
        .conversation_nonce
        .as_slice()
        .try_into()
        .map_err(|_| failure("the direct reservation names its nonce"))?;
    let (first, second) = (creator.keys.account, peer.keys.account);
    let route = ArcSemanticRouteTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        kind: ArcConversationKind::Direct,
        direct_account_a: Opaque::from_slice(&first)?,
        direct_account_b: Opaque::from_slice(&second)?,
        canonical_channel_name: Opaque::new(Vec::new())?,
        channel_authority_root_fingerprint: [0; 32],
        semantic_incarnation: incarnation,
        predecessor_close_id: predecessor,
    };
    let principals = [&creator.keys.keys, &peer.keys.keys];
    let policies = policies_for(
        &principals,
        e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &group)?,
        ArcConversationKind::Direct,
    )?;
    let previous_lock_ids = match previous {
        Some(previous) => builders::lock_ids(&previous.package)?,
        None => Vec::new(),
    };
    let package = builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route,
        channel_instance_id: None,
        conversation_nonce: Some(nonce),
        group_id: group,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: incarnation,
        previous_lock_ids,
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
        sequencer_credential_id: active_sequencer_credential_id()?,
        plan_devices: vec![
            (
                &creator.keys.account,
                builders::root_fingerprint(&creator.keys.keys.root)?,
                creator.keys.device,
            ),
            (
                &peer.keys.account,
                builders::root_fingerprint(&peer.keys.keys.root)?,
                peer.keys.device,
            ),
        ],
    })?;
    let route_binding =
        e2ee::route::direct_route_binding(NETWORK_ID.as_bytes(), &nonce, &first, &second)?;
    bind(
        &mut creator.client,
        &mut creator.keys,
        &reservation,
        package,
        route_binding,
        group,
        policies,
    )
}

/// One application object each way on `bound` at `epoch`.
fn exchange(
    creator: &mut Party,
    peer: &mut Party,
    bound: &BoundConversation,
    latest: [u8; 32],
    epoch: u64,
) -> TestResult {
    let note = send_application(&mut creator.client, &mut creator.keys, bound, latest, epoch)?;
    assert_eq!(receive_application(&mut peer.client, bound)?, note);
    let reply = send_application(&mut peer.client, &mut peer.keys, bound, latest, epoch)?;
    assert_eq!(receive_application(&mut creator.client, bound)?, reply);
    Ok(())
}

/// Plaintext from the creator to the peer's nickname is refused.
fn plaintext_refused(creator: &mut Party, peer: &Party, text: &str) -> TestResult {
    creator
        .client
        .send(&format!("PRIVMSG {} :{text}", peer.nickname))?;
    let refused = creator
        .client
        .read_until(|line| line.contains("E2EE_REQUIRED"))?;
    assert_contains(&refused, "FAIL PRIVMSG E2EE_REQUIRED")
}

/// Finalizes the closing transition of `bound` after `prior` with both
/// council members' votes and closes it with both controller roots'
/// approvals, as the fixed direct policy requires (companion 9.3 and 11.5);
/// returns the close identifier, which the peer sees broadcast.
fn close_direct(
    creator: &mut Party,
    peer: &mut Party,
    bound: &BoundConversation,
    prior: (u64, [u8; 32]),
) -> TestResult<[u8; 32]> {
    let intent_id = authorization(&creator.keys, bound, prior.1)?
        .tbs
        .close_intent_id;
    let aad = ArcCommitAad {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        validation_time: VALIDATION_TIME + 1,
        prior_state_id: prior.1,
    }
    .encode()?;
    let commit = builders::private_message_at_epoch(&bound.group_id, prior.0, MLS_COMMIT, &aad)?;
    let policy = builders::policy_id_of(&bound.policies[1])?;
    let terminal = super::real_clients::certify_commit(
        &mut creator.client,
        &mut creator.keys,
        &[&peer.keys],
        bound,
        &commit,
        prior,
        (policy, policy),
        CertificationTransition::Close(intent_id),
    )?;
    let mut close = authorization(&creator.keys, bound, terminal.finalization_id)?;
    let mut approvals = close.approvals.as_slice().to_vec();
    approvals.push(builders::commit_approval(
        &peer.keys.keys,
        peer.keys.device,
        &close.tbs,
        SignatureDomain::CloseAuthorization,
    )?);
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    close.approvals = TlsVec::new(approvals)?;
    let close_id = e2ee::route::close_authorization_id(&close)?;
    let conversation = base64url_encode(&bound.conversation);
    let label = creator.keys.label();
    send_object(
        &mut creator.client,
        &label,
        &format!("EGROUP CLOSE {conversation} 1"),
        &wire_object(ArcWireObjectKind::CloseAuthorization, &close)?,
    )?;
    let reply = labeled_reply(&mut creator.client, &label)?;
    let completion = std::slice::from_ref(only_completion(&reply, "CLOSED")?);
    assert_eq!(hash_at(completion, "CLOSED", 4)?, close_id);
    let broadcast = peer
        .client
        .read_until(|line| line.contains(" EGROUP CLOSED "))?;
    assert_eq!(hash_at(&broadcast, "CLOSED", 4)?, close_id);
    Ok(close_id)
}

/// An application object on the closed `bound` is refused.
fn closed_refuses_traffic(creator: &mut Party, bound: &BoundConversation) -> TestResult {
    let late = raw_object(
        ArcWireObjectKind::ApplicationMls,
        builders::private_message_with_ciphertext(
            &bound.group_id,
            2,
            MLS_APPLICATION,
            &[],
            &[9; 300],
        )?,
    )?;
    let label = creator.keys.label();
    send_object(
        &mut creator.client,
        &label,
        &bound.application_command(),
        &late,
    )?;
    let refused = labeled_reply(&mut creator.client, &label)?;
    assert_contains(&refused, "E2EE_ROUTE_INVALID")
}

/// Logs `party` in again on edge A after the edge's restart and attaches
/// its device once the edge's encrypted profile is active.
fn rejoin(network: &Network, party: &mut Party) -> TestResult {
    party.client = authenticated_session(
        &network.edge_a,
        party.nickname,
        party.login,
        party.rejoin_seed,
        party.account,
    )?;
    attach_when_active(&mut party.client, &mut party.keys)
}

/// A group whose conversation identifier sorts before `DIRECT_GROUP`'s, so
/// a restore in identifier order, the coordinator's or an edge's from its
/// rows, meets the next incarnation before the closed one.
fn group_sorting_first() -> TestResult<[u8; 32]> {
    let first = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &DIRECT_GROUP)?;
    for seed in 79_u8..=250 {
        if e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &[seed; 32])? < first {
            return Ok([seed; 32]);
        }
    }
    Err(failure("a group that sorts first"))
}

#[test]
fn a_closed_direct_conversation_is_recreated_across_coordinator_and_edge_restarts() -> TestResult {
    super::encrypted_clients::run_network(recreation_across_restarts)
}

fn recreation_across_restarts(
    network: &Network,
    coordinator: &mut DaemonProcess,
    edge_a: &mut DaemonProcess,
    _edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    let (alice, alice_account) = step(
        "alice session",
        authenticated_client(&network.edge_a, "alice", "alice-account", 41),
    )?;
    let (bob, bob_account) = step(
        "bob session",
        authenticated_client(&network.edge_a, "bob", "bob-account", 51),
    )?;
    let mut alice = Party {
        client: alice,
        keys: Principal::new(ALICE_ROOT, ALICE_DEVICE, alice_account)?,
        nickname: "alice",
        login: "alice-account",
        account: alice_account,
        rejoin_seed: 47,
    };
    let mut bob = Party {
        client: bob,
        keys: Principal::new(BOB_ROOT, BOB_DEVICE, bob_account)?,
        nickname: "bob",
        login: "bob-account",
        account: bob_account,
        rejoin_seed: 57,
    };
    step(
        "alice attach",
        publish_and_attach(&mut alice.client, &mut alice.keys),
    )?;
    step(
        "bob attach",
        publish_and_attach(&mut bob.client, &mut bob.keys),
    )?;
    // The smaller account of the pair creates every incarnation.
    let (mut creator, mut peer) = if alice.keys.account <= bob.keys.account {
        (alice, bob)
    } else {
        (bob, alice)
    };

    // Incarnation zero binds, bootstraps and carries traffic; while it is
    // live the pair takes no other reservation and refuses plaintext.
    let first = step(
        "first bind",
        bind_direct(&mut creator, &peer, (0, [0; 32]), None, DIRECT_GROUP),
    )?;
    let first_terminal = step(
        "first activation",
        activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &first,
            &[&peer.keys],
        ),
    )?;
    step(
        "first traffic",
        exchange(&mut creator, &mut peer, &first, first_terminal, 1),
    )?;
    step(
        "first plaintext",
        plaintext_refused(&mut creator, &peer, "in the clear"),
    )?;
    step("live reservation", pair_held(&mut creator, &peer))?;

    // An authorized close ends it; it then takes no traffic.
    let close_id = step(
        "close",
        close_direct(&mut creator, &mut peer, &first, (1, first_terminal)),
    )?;
    step(
        "closed traffic",
        closed_refuses_traffic(&mut creator, &first),
    )?;

    // The pair is reserved again, and its next incarnation binds naming the
    // close, bootstraps and carries traffic; the pair is held again.
    let second = step(
        "next bind",
        bind_direct(
            &mut creator,
            &peer,
            (1, close_id),
            Some(&first),
            group_sorting_first()?,
        ),
    )?;
    let second_terminal = step(
        "next activation",
        activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &second,
            &[&peer.keys],
        ),
    )?;
    step(
        "next traffic",
        exchange(&mut creator, &mut peer, &second, second_terminal, 1),
    )?;
    step(
        "next plaintext",
        plaintext_refused(&mut creator, &peer, "still in the clear"),
    )?;
    step("next reservation", pair_held(&mut creator, &peer))?;

    // A coordinator restart restores both incarnations: the live one
    // carries traffic again, plaintext and another reservation of the pair
    // are still refused, and the closed one still takes no traffic.
    let before_a = links_established(&network.edge_a);
    let before_b = links_established(&network.edge_b);
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped for the restart: {status}"
    );
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    step("relink a", wait_for_link(&network.edge_a, before_a))?;
    step("relink b", wait_for_link(&network.edge_b, before_b))?;
    step(
        "creator attach after restart",
        attach_when_active(&mut creator.client, &mut creator.keys),
    )?;
    step(
        "peer attach after restart",
        attach_when_active(&mut peer.client, &mut peer.keys),
    )?;
    let resumed = step(
        "traffic after restart",
        send_application_when_active(
            &mut creator.client,
            &mut creator.keys,
            &second,
            second_terminal,
        ),
    )?;
    assert_eq!(
        step(
            "receipt after restart",
            receive_application(&mut peer.client, &second)
        )?,
        resumed
    );
    let answer = step(
        "answer after restart",
        send_application(
            &mut peer.client,
            &mut peer.keys,
            &second,
            second_terminal,
            1,
        ),
    )?;
    assert_eq!(
        step(
            "answer receipt after restart",
            receive_application(&mut creator.client, &second)
        )?,
        answer
    );
    step(
        "plaintext after restart",
        plaintext_refused(&mut creator, &peer, "in the clear after the restart"),
    )?;
    step(
        "closed traffic after restart",
        closed_refuses_traffic(&mut creator, &first),
    )?;
    step("reservation after restart", pair_held(&mut creator, &peer))?;

    // An edge restart restores both incarnations from the edge's own rows:
    // the accounts log in again and attach, plaintext between them is still
    // refused, and the live incarnation carries traffic.
    let status = edge_a.stop()?;
    assert!(status.success(), "edge A stopped for its restart: {status}");
    let before_edge = links_established(&network.edge_a);
    *edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    step("edge relink", wait_for_link(&network.edge_a, before_edge))?;
    step(
        "edge authority",
        wait_for_account_authority(&network.edge_a),
    )?;
    step("creator rejoin", rejoin(network, &mut creator))?;
    step("peer rejoin", rejoin(network, &mut peer))?;
    step(
        "plaintext after the edge restart",
        plaintext_refused(&mut creator, &peer, "in the clear after the edge restart"),
    )?;
    let resumed = step(
        "traffic after the edge restart",
        send_application_when_active(&mut peer.client, &mut peer.keys, &second, second_terminal),
    )?;
    assert_eq!(
        step(
            "receipt after the edge restart",
            receive_application(&mut creator.client, &second)
        )?,
        resumed
    );

    // The restored incarnation closes in its turn, and the one after it,
    // naming that close, binds, bootstraps and carries traffic.
    let second_close = step(
        "close after restart",
        close_direct(&mut creator, &mut peer, &second, (1, second_terminal)),
    )?;
    step(
        "second closed traffic",
        closed_refuses_traffic(&mut creator, &second),
    )?;
    let third = step(
        "third bind",
        bind_direct(
            &mut creator,
            &peer,
            (2, second_close),
            Some(&second),
            THIRD_DIRECT_GROUP,
        ),
    )?;
    let third_terminal = step(
        "third activation",
        activate_bootstrap_with(
            &mut creator.client,
            &mut creator.keys,
            &third,
            &[&peer.keys],
        ),
    )?;
    step(
        "third traffic",
        exchange(&mut creator, &mut peer, &third, third_terminal, 1),
    )?;
    step(
        "third plaintext",
        plaintext_refused(&mut creator, &peer, "in the clear once more"),
    )?;
    step("third reservation", pair_held(&mut creator, &peer))
}
