//! Companion 11.7 and 12.5 through the production daemons, on the
//! requester's own edge: a commit ACK, a finalization, an abort and a close
//! each answer the requesting connection with its one labeled result, while
//! carol, another member attached on that edge, and bob, on the other edge,
//! read every untagged copy the requester does not. MLS bodies and leaf
//! ACKs are synthetic; controller signatures, council votes and transport
//! are real.
#![forbid(unsafe_code)]
use super::*;

/// carol's root and device seeds: a third principal, outside the council.
const CAROL_ROOT: u8 = 81;
const CAROL_DEVICE: u8 = 82;

#[test]
fn a_member_on_the_requesters_edge_reads_each_copy_the_requester_does_not() -> TestResult {
    encrypted_clients::run_network(|network, _coordinator, _edge_a, _edge_b| {
        copies_on_the_requesters_edge(network)
    })
}

/// Binds `#room` from alice with bob, attaches carol to it on alice's edge,
/// and walks alice's activation, abort, close transition and close in the
/// order the other two members read their copies.
fn copies_on_the_requesters_edge(network: &Network) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    stage_ten_drills::wait_for_account_authority(&network.edge_a)?;
    stage_ten_drills::wait_for_account_authority(&network.edge_b)?;
    let (mut alice, alice_account) =
        authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
    let (mut bob, bob_account) = authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
    // carol's account is created on the coordinator's own client listener,
    // sealed under the coordinator epoch edge A pins.
    let carol_account = {
        let mut creation = ArcClient::connect(&network.coordinator)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, &network.edge_a, "carol-account", 61)?
    };
    let mut carol =
        authenticated_session(&network.edge_a, "carol", "carol-account", 63, carol_account)?;
    let mut alice_keys = Principal::new(ALICE_ROOT, ALICE_DEVICE, alice_account)?;
    let mut bob_keys = Principal::new(BOB_ROOT, BOB_DEVICE, bob_account)?;
    let mut carol_keys = Principal::new(CAROL_ROOT, CAROL_DEVICE, carol_account)?;
    step(
        "alice attach",
        publish_and_attach(&mut alice, &mut alice_keys),
    )?;
    step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;
    step(
        "carol attach",
        publish_and_attach(&mut carol, &mut carol_keys),
    )?;
    alice.send("JOIN #room")?;
    alice.read_until(|line| line.contains(" 366 alice #room "))?;
    alice.send("CHANCTL REGISTER #room")?;
    alice.read_until(|line| line.contains(" NOTE CHANCTL UPDATED #room "))?;
    bob.send("JOIN #room")?;
    bob.read_until(|line| line.contains(" 366 bob #room "))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #room"))?;
    let bound = step(
        "channel bind",
        reserve_and_bind(&mut alice, &mut alice_keys, &bob_keys),
    )?;
    // carol joins the bound channel on alice's edge with her device
    // attached, so the edge counts her among the eligible local sinks.
    carol.send("JOIN #room")?;
    step(
        "carol join",
        carol.read_until(|line| line.contains(" 366 carol #room ")),
    )?;
    alice.read_until(|line| line.starts_with(":carol!") && line.contains(" JOIN #room"))?;
    let conversation = base64url_encode(&bound.conversation);

    // alice finalizes the bootstrap activation; the helper requires her
    // reply to name it only in its labeled completion.
    let activation = step(
        "activation",
        activate_bootstrap_with(&mut alice, &mut alice_keys, &bound, &[&bob_keys]),
    )?;
    let finalized = format!(
        " EGROUP FINALIZED {conversation} 1 {} ",
        base64url_encode(&activation)
    );
    read_copy(&mut carol, "carol", &finalized)?;
    read_copy(&mut bob, "bob", &finalized)?;

    // alice sequences a candidate and withdraws it with both council votes.
    let prior = (1, activation);
    let withdrawn = step(
        "withdrawn candidate",
        real_clients::sequence_candidate(
            &mut alice,
            &mut alice_keys,
            &bound,
            &commit_at(&bound, prior, &[3; 300])?,
            prior.1,
        ),
    )?;
    let aborted = step(
        "abort",
        real_clients::abort_candidate(
            &mut alice,
            &mut alice_keys,
            &[&bob_keys],
            &bound,
            withdrawn,
            prior.0,
        ),
    )?;
    for (who, sink) in [("carol", &mut carol), ("bob", &mut bob)] {
        let copy = read_copy(sink, who, &format!(" EGROUP ABORTED {conversation} "))?;
        assert_same_terminal(std::slice::from_ref(&copy), std::slice::from_ref(&aborted))?;
    }

    // alice acknowledges and finalizes a close-intent Commit at the same
    // position, then closes the conversation under it.
    let close_intent = close_authority::authorization(&alice_keys, &bound, prior.1)?
        .tbs
        .close_intent_id;
    let policy = builders::policy_id_of(&bound.policies[1])?;
    let certified = step(
        "close transition",
        real_clients::certify_commit(
            &mut alice,
            &mut alice_keys,
            &[&bob_keys],
            &bound,
            &commit_at(&bound, prior, &[2; 300])?,
            prior,
            (policy, policy),
            close_authority::CertificationTransition::Close(close_intent),
        ),
    )?;
    let candidate = semantic_id_of(SemanticHashDomain::CandidateId, &certified.receipt.tbs)?;
    let close_id = step(
        "close",
        close_conversation(
            &mut alice,
            &mut alice_keys,
            &bound,
            certified.finalization_id,
        ),
    )?;
    let copies = [
        format!(
            " EGROUP ACK {conversation} {} ",
            base64url_encode(&candidate)
        ),
        format!(
            " EGROUP FINALIZED {conversation} 2 {} ",
            base64url_encode(&certified.finalization_id)
        ),
        format!(
            " EGROUP CLOSED {conversation} {}",
            base64url_encode(&close_id)
        ),
    ];
    for (who, sink) in [("carol", &mut carol), ("bob", &mut bob)] {
        for expected in &copies {
            read_copy(sink, who, expected)?;
        }
    }
    Ok(())
}

/// One synthetic Commit at the accepted `prior` position, under the Section
/// 9.5 Commit authenticated data the close scenarios use; its opaque
/// `ciphertext` tells it apart from another Commit at the same position.
fn commit_at(
    bound: &BoundConversation,
    prior: (u64, [u8; 32]),
    ciphertext: &[u8],
) -> TestResult<Vec<u8>> {
    let aad = ArcCommitAad {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        validation_time: VALIDATION_TIME + 1,
        prior_state_id: prior.1,
    }
    .encode()?;
    Ok(builders::private_message_with_ciphertext(
        &bound.group_id,
        prior.0,
        MLS_COMMIT,
        &aad,
        ciphertext,
    )?)
}

/// Reads on `sink` up to the next line containing `expected` and requires
/// that line to be an untagged copy: the requester's label never reaches
/// another sink (companion 11.7 and 12.5).
fn read_copy(sink: &mut ArcClient, who: &str, expected: &str) -> TestResult<String> {
    let lines = step(
        &format!("{who} reads{expected}"),
        sink.read_until(|line| line.contains(expected)),
    )?;
    let copy = lines
        .last()
        .ok_or_else(|| failure(format!("{who} read nothing")))?;
    if tag_value(copy, "label").is_some() {
        return Err(failure(format!("{who} read a labeled copy: {copy}")));
    }
    Ok(copy.clone())
}
