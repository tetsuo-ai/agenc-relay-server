//! ENC-10 scenario C (companion 13.8 and 13.7.3): a real RFC 9420 ReInit.
//! Two mls-rs endpoints close the old group with a real ReInit proposal and
//! build the resumption successor, while the daemon certifies the ReInit
//! Commit, sequences the attempt, admits one acknowledgement per continuing
//! leaf and activates the successor. A leaf removed in an earlier finalized
//! epoch carries a removal proof for that epoch, leaves the expected
//! continuing set and must rejoin, and an activation whose acknowledgements
//! do not cover the continuing set is refused without changing anything.
//!
//! openmls 0.9 exposes no ReInit proposal or resumption successor, so both
//! endpoints of this scenario are mls-rs; the cross-library evidence is in
//! the recovery and rotation scenarios and in the interoperability matrix.
#![forbid(unsafe_code)]

use super::*;

use e2ee::finality::{ReinitVoteSlot, reinit_vote_tbs};
use e2ee::objects::conversation::{ArcKeyPackagePlan, ArcKeyPackagePlanEntry};
use e2ee::objects::reinit::{
    ArcReInitAbortCoreTbs, ArcReInitAbortRequest, ArcReInitAck, ArcReInitAckKind, ArcReInitAckTbs,
    ArcReInitActivationCoreTbs, ArcReInitActivationRequest, ArcReInitAttempt,
    ArcReInitAttemptAuthorization, ArcReInitAttemptAuthorizationTbs, ArcReInitAttemptReceipt,
    ArcReInitAttemptTbs, ArcReInitDispositionVoteTbs, ArcReInitTargetTbs,
};
use e2ee::objects::sequencing::{ArcFinalityVote, ArcSequencerRecord};
use mls_rs::CipherSuite as RsSuite;
use mls_rs::ProtocolVersion as RsVersion;
use mls_rs::client_builder::MlsConfig;
use mls_rs::time::MlsTime;

/// The MLS group identifier the ReInit target names.
const SUCCESSOR_GROUP: [u8; 32] = [0x7C; 32];
/// The plaintext the successor group carries once it is activated.
const SUCCESSOR_TEXT: &str = "minutes of the re-initialised group";
/// The exporter label the activation authenticator uses (companion 13.8).
const EXPORTER_LABEL: &[u8] = b"ARC-MLS/1 reinit activation";
/// The reason an attempt abort names; any nonzero code is an abort
/// (companion 13.8).
const ABORT_REASON: u16 = 1;

/// The immutable target the old ReInit Commit commits to.
struct Target {
    tbs: ArcReInitTargetTbs,
    digest: [u8; 32],
    conversation: [u8; 32],
    binding_id: [u8; 32],
    plan_id: [u8; 32],
}

/// The public results of the successor state every acknowledgement repeats.
#[derive(Clone, Copy)]
struct Results {
    group_info: [u8; 32],
    context: [u8; 32],
    tree: [u8; 32],
    exporter: [u8; 32],
}

/// The continuing leaves of one attempt and the packages they carry.
struct Continuing<'a> {
    creator: &'a OldLeaf,
    joiner: &'a OldLeaf,
    joiner_reference: Vec<u8>,
}

#[test]
fn a_reinit_activates_only_with_every_continuing_leaf_acknowledged() -> TestResult {
    // The ReInit lifecycle stops no daemon: every step runs on the network
    // the wrapper started and stops with it.
    run_network(|network, _coordinator, _edge_a, _edge_b| reinit_with_real_clients(network))
}

// agenc-review: allow owner=tests reviewed=2026-09-17 reason=one ReInit lifecycle names the old group both endpoints the target the attempt every acknowledgement and the successor together, and splitting it would hide the order the companion fixes
#[allow(clippy::too_many_lines)]
fn reinit_with_real_clients(network: &Network) -> TestResult {
    let mut clients = bind_channel(network)?;
    let alice_interval = clients.alice_interval();
    let bob_interval = clients.bob_interval();
    let alice_leaf = real_leaf(&clients.alice_keys, alice_interval, ALICE_LEAF, 0)?;
    let alice_client =
        real_clients::mls_rs_client_with_leaf(&clients.alice_keys, alice_interval, ALICE_LEAF)?;
    let mut group = alice_client
        .group_builder()?
        .with_group_id(clients.bound.group_id.to_vec())
        .build()?;
    let mut head = (0_u64, clients.genesis);
    let mut time = clients.now;
    let policies = clients.policies;
    let operational = (policies.1, policies.1);

    // The bootstrap activation of the old group, from a real mls-rs Commit.
    let activation = commit(&mut group, &clients, head, time, |builder| Ok(builder))?;
    let activated = certify(
        &mut clients,
        &activation,
        head,
        policies,
        &alice_leaf,
        close_authority::CertificationTransition::Bootstrap,
    )?;
    group.apply_pending_commit()?;
    head = (1, activated.finalization_id);
    time = time.saturating_add(1);

    // An openmls leaf of bob joins the mls-rs group and is then removed in
    // its own finalized epoch: its removal proof names that finalization, so
    // the expected continuing set of any later attempt no longer holds it.
    let removed_member =
        real_clients::OpenMlsMember::with_leaf(&clients.bob_keys, bob_interval, BOB_LEAF)?;
    let (lost_leaf, mut lost_group) = join_openmls_member(
        &mut clients,
        &mut group,
        (&mut head, &mut time),
        (&alice_leaf, &removed_member, bob_interval),
    )?;
    let removal = remove_leaf(
        &mut clients,
        &mut group,
        &mut head,
        &mut time,
        (&alice_leaf, &lost_leaf),
    )?;
    {
        let epoch = head.0;
        let Clients {
            bob,
            bob_keys,
            bound,
            ..
        } = &mut clients;
        publish_membership(bob, bob_keys, bound, epoch, &lost_leaf, Some(removal))?;
    }

    // bob rejoins with the leaf that will continue into the successor.
    let (bob_leaf, mut bob_group) = join_member(
        &mut clients,
        &mut group,
        &mut head,
        &mut time,
        (&alice_leaf, BOB_REJOIN_LEAF, bob_interval),
    )?;
    {
        let epoch = head.0;
        let Clients {
            bob,
            bob_keys,
            bound,
            ..
        } = &mut clients;
        publish_membership(bob, bob_keys, bound, epoch, &bob_leaf, None)?;
    }

    // The ReInit Commit: a real ReInit proposal closes the old group.
    let target = target_of(&clients, head.1)?;
    let reinit = commit(&mut group, &clients, head, time, |builder| {
        Ok(builder.reinit(
            Some(SUCCESSOR_GROUP.to_vec()),
            RsVersion::MLS_10,
            RsSuite::CURVE25519_AES128,
            Default::default(),
        )?)
    })?;
    let old_state = certify(
        &mut clients,
        &reinit,
        head,
        operational,
        &alice_leaf,
        close_authority::CertificationTransition::Reinit(target.digest),
    )?
    .finalization_id;
    group.apply_pending_commit()?;
    bob_group.process_incoming_message(mls_rs::MlsMessage::from_bytes(&reinit)?)?;
    let target = target_of(&clients, old_state)?;

    // Both endpoints resume: alice creates the successor with bob's fresh
    // package, and bob consumes the one-use Welcome it produced.
    let bob_resumed = bob_group.get_reinit_client(None, None)?;
    let bob_package = bob_resumed.generate_key_package(Some(MlsTime::from(bob_interval.0)))?;
    let joiner_reference = package_reference(&bob_package.to_bytes()?)?;
    let alice_resumed = group.get_reinit_client(None, None)?;
    let (successor, welcomes) = alice_resumed.commit(
        vec![bob_package],
        Default::default(),
        Some(MlsTime::from(alice_interval.0)),
    )?;
    let welcome = welcomes
        .first()
        .ok_or_else(|| failure("the successor commit produced a Welcome"))?
        .clone();
    let (mut bob_successor, _info) = bob_resumed.join(&welcome, None, None)?;
    assert_eq!(bob_successor.current_epoch(), 1);
    let results = results_of(&successor, old_state)?;
    let initial_commit = successor.group_info_message(true)?.to_bytes()?;

    // The attempt is staged under the old-policy controller's authorization.
    let continuing = Continuing {
        creator: &alice_leaf,
        joiner: &bob_leaf,
        joiner_reference,
    };
    let attempt = build_attempt(
        &clients,
        &target,
        &continuing,
        (old_state, &initial_commit, results),
    )?;
    let attempt_id = step("stage the attempt", stage_attempt(&mut clients, &attempt))?;
    let receipt = step("fetch the attempt receipt", attempt_receipt(&mut clients))?;
    assert_eq!(receipt.tbs.reinit_attempt_id, attempt_id);

    // One acknowledgement per continuing leaf, each from the device its own
    // proof names and naming its own plan entry.
    let creator_ack = step(
        "creator acknowledgement",
        acknowledge_creator(&mut clients, &attempt, attempt_id, results),
    )?;
    let joiner_ack = step(
        "joiner acknowledgement",
        acknowledge_joiner(
            &mut clients,
            &attempt,
            attempt_id,
            (results, &continuing, bob_successor.current_member_index()),
        ),
    )?;

    // An activation that covers only the creator leaves a continuing leaf
    // unacknowledged and is refused; the attempt and its receipt stand.
    let refused = step(
        "refused activation",
        submit_activation(
            &mut clients,
            &attempt,
            &receipt,
            (vec![creator_ack.clone()], &[]),
        ),
    )?;
    assert_contains(&refused, "FAIL EGROUP E2EE_BINDING_AUTH_INVALID")?;
    assert!(
        !refused
            .iter()
            .any(|line| line.contains(" EGROUP REINIT-ACTIVATED "))
    );
    let activated = step(
        "activation",
        submit_activation(
            &mut clients,
            &attempt,
            &receipt,
            (vec![creator_ack, joiner_ack], &[0, 1]),
        ),
    )?;
    let completion = std::slice::from_ref(only_completion(&activated, "REINIT-ACTIVATED")?);
    assert_eq!(
        hash_at(completion, "REINIT-ACTIVATED", 3)?,
        clients.bound.conversation
    );
    assert_eq!(
        hash_at(completion, "REINIT-ACTIVATED", 4)?,
        target.conversation
    );
    // bob, on the other edge, reads the activation as the untagged broadcast.
    let lines = step(
        "bob reads the activation broadcast",
        clients
            .bob
            .read_until(|line| line.contains(" EGROUP REINIT-ACTIVATED ")),
    )?;
    assert_same_terminal(&lines, completion)?;

    // What each endpoint can derive: the continuing joiner reads the
    // successor's minutes, and the removed leaf's state derives nothing.
    let aad = real_clients::application_aad(&clients.bound, old_state)?;
    let content = real_clients::padded_content(
        &clients.bound,
        &clients.alice_keys,
        0,
        old_state,
        SUCCESSOR_TEXT,
    )?;
    let encrypted = successor
        .clone()
        .encrypt_application_message(&content, aad)?
        .to_bytes()?;
    assert_eq!(
        mls_rs_text(&mut bob_successor, &encrypted)?.as_deref(),
        Some(SUCCESSOR_TEXT),
        "the continuing leaf reads the successor group's minutes"
    );
    assert!(
        removed_member.decrypt(&mut lost_group, &encrypted).is_err(),
        "the openmls leaf removed before the ReInit derives nothing from the successor"
    );
    require_recorded(&REINIT_RULES)
}

/// Companion 11.7, 12.5 and 13.8 through the production daemons: the two
/// council votes of one attempt abort arrive in separate requests. alice's
/// vote alone is below the quorum and is answered `PENDING`; bob's completes
/// the abort and is answered `REINIT-ABORTED`; and alice, whose request is
/// still open only as `PENDING`, then reads the untagged `REINIT-ABORTED`
/// broadcast naming the same abort.
#[test]
fn a_reinit_attempt_aborts_when_its_second_vote_arrives() -> TestResult {
    run_network(|network, _coordinator, _edge_a, _edge_b| reinit_abort_with_real_clients(network))
}

fn reinit_abort_with_real_clients(network: &Network) -> TestResult {
    let mut clients = bind_channel(network)?;
    let staged = stage_two_leaf_attempt(&mut clients)?;
    let core = abort_core(&staged);
    let abort_id = semantic_id_of(SemanticHashDomain::ReinitAbortId, &core)?;
    let conversation = clients.bound.conversation;

    let (first, request_object) = step(
        "alice's abort vote",
        submit_abort(&mut clients, &staged, &core, Voter::Alice),
    )?;
    let pending = std::slice::from_ref(completion_line(&first)?);
    assert_contains(pending, " EGROUP PENDING ")?;
    assert_eq!(hash_at(pending, "PENDING", 3)?, conversation);
    assert_eq!(
        pending
            .first()
            .and_then(|line| words(line).get(4).cloned())
            .as_deref(),
        Some("REINIT-ABORT"),
        "{pending:?}"
    );
    assert_eq!(hash_at(pending, "PENDING", 5)?, request_object);

    let (second, _) = step(
        "bob's abort vote",
        submit_abort(&mut clients, &staged, &core, Voter::Bob),
    )?;
    let completion = std::slice::from_ref(only_completion(&second, "REINIT-ABORTED")?);
    assert_eq!(hash_at(completion, "REINIT-ABORTED", 3)?, conversation);
    assert_eq!(hash_at(completion, "REINIT-ABORTED", 4)?, staged.attempt_id);
    assert_eq!(hash_at(completion, "REINIT-ABORTED", 5)?, abort_id);

    // The earlier PENDING requester reads the terminal as the untagged
    // broadcast, naming the abort bob's labeled completion names.
    let lines = step(
        "alice reads the abort broadcast",
        clients
            .alice
            .read_until(|line| line.contains(" EGROUP REINIT-ABORTED ")),
    )?;
    assert_same_terminal(&lines, completion)
}

/// Builds and returns one real mls-rs Commit of the old group under the
/// Section 9.5 Commit authenticated data of its position.
fn commit<C: MlsConfig>(
    group: &mut mls_rs::Group<C>,
    clients: &Clients,
    head: (u64, [u8; 32]),
    time: u64,
    shape: impl FnOnce(
        mls_rs::group::CommitBuilder<'_, C>,
    ) -> TestResult<mls_rs::group::CommitBuilder<'_, C>>,
) -> TestResult<Vec<u8>> {
    let aad = real_clients::commit_aad(&clients.bound, head.1, time)?;
    let builder = shape(group.commit_builder().authenticated_data(aad))?;
    Ok(builder.build()?.commit_message.to_bytes()?)
}

/// Certifies one Commit of the old group from alice through the coordinator.
fn certify(
    clients: &mut Clients,
    commit: &[u8],
    head: (u64, [u8; 32]),
    policies: ([u8; 32], [u8; 32]),
    leaf: &OldLeaf,
    transition: close_authority::CertificationTransition,
) -> TestResult<real_clients::Certified> {
    let certified = {
        let Clients {
            alice,
            alice_keys,
            bob_keys,
            bound,
            ..
        } = &mut *clients;
        real_clients::certify_commit_with_leaf(
            alice,
            alice_keys,
            &[&*bob_keys],
            bound,
            commit,
            head,
            policies,
            transition,
            leaf,
        )?
    };
    clients
        .bob
        .read_until(|line| line.contains(" EGROUP FINALIZED "))?;
    Ok(certified)
}

/// bob publishes a real KeyPackage under `seed`, alice adds it, and bob's
/// endpoint joins through the Welcome the same Commit produced.
fn join_member<G: MlsConfig + Clone>(
    clients: &mut Clients,
    group: &mut mls_rs::Group<G>,
    head: &mut (u64, [u8; 32]),
    time: &mut u64,
    plan: (&OldLeaf, [u8; 32], (u64, u64)),
) -> TestResult<(OldLeaf, mls_rs::Group<impl MlsConfig + use<G>>)> {
    let (alice_leaf, seed, interval) = plan;
    let joiner = real_clients::mls_rs_client_with_leaf(&clients.bob_keys, interval, seed)?;
    let package = joiner.generate_key_package_message(
        Default::default(),
        Default::default(),
        Some(MlsTime::from(interval.0)),
    )?;
    let aad = real_clients::commit_aad(&clients.bound, head.1, *time)?;
    let output = group
        .commit_builder()
        .authenticated_data(aad)
        .add_member(package)?
        .build()?;
    let certified = certify(
        clients,
        &output.commit_message.to_bytes()?,
        *head,
        (clients.policies.1, clients.policies.1),
        alice_leaf,
        close_authority::CertificationTransition::Add,
    )?;
    group.apply_pending_commit()?;
    *head = (head.0.saturating_add(1), certified.finalization_id);
    *time = time.saturating_add(1);
    let welcome = output
        .welcome_messages
        .first()
        .ok_or_else(|| failure("the Add produced a Welcome"))?;
    let (joined, _info) = joiner.join_group(None, welcome, None)?;
    let index = joined.current_member_index();
    Ok((real_leaf(&clients.bob_keys, interval, seed, index)?, joined))
}

/// bob's openmls endpoint publishes a real KeyPackage, alice's mls-rs group
/// adds it, and it joins through the Welcome that Commit produced.
fn join_openmls_member<G: MlsConfig>(
    clients: &mut Clients,
    group: &mut mls_rs::Group<G>,
    position: (&mut (u64, [u8; 32]), &mut u64),
    plan: (&OldLeaf, &real_clients::OpenMlsMember, (u64, u64)),
) -> TestResult<(OldLeaf, openmls::prelude::MlsGroup)> {
    let (head, time) = position;
    let (alice_leaf, member, interval) = plan;
    let package = member.key_package()?;
    {
        let Clients {
            bob,
            bob_keys,
            alice,
            alice_keys,
            ..
        } = &mut *clients;
        real_clients::publish_package(bob, bob_keys, &package, interval.1)?;
        let claimed = real_clients::claim_package_with(alice, alice_keys, bob_keys, [80; 16])?;
        assert_eq!(claimed, package, "the claimed bytes are bob's own package");
    }
    let aad = real_clients::commit_aad(&clients.bound, head.1, *time)?;
    let output = group
        .commit_builder()
        .authenticated_data(aad)
        .add_member(mls_rs::MlsMessage::from_bytes(&package)?)?
        .build()?;
    let certified = certify(
        clients,
        &output.commit_message.to_bytes()?,
        *head,
        (clients.policies.1, clients.policies.1),
        alice_leaf,
        close_authority::CertificationTransition::Add,
    )?;
    group.apply_pending_commit()?;
    *head = (head.0.saturating_add(1), certified.finalization_id);
    *time = time.saturating_add(1);
    let welcome = output
        .welcome_messages
        .first()
        .ok_or_else(|| failure("the Add produced a Welcome"))?
        .to_bytes()?;
    let joined = member.join(&welcome)?;
    let index = joined.own_leaf_index().u32();
    Ok((
        real_leaf(&clients.bob_keys, interval, BOB_LEAF, index)?,
        joined,
    ))
}

/// Removes `leaf` from the old group with a real Commit and returns the
/// finalization the removal proof of that leaf's last epoch must name.
fn remove_leaf(
    clients: &mut Clients,
    group: &mut mls_rs::Group<impl MlsConfig>,
    head: &mut (u64, [u8; 32]),
    time: &mut u64,
    leaves: (&OldLeaf, &OldLeaf),
) -> TestResult<[u8; 32]> {
    let (alice_leaf, removed) = leaves;
    let aad = real_clients::commit_aad(&clients.bound, head.1, *time)?;
    let output = group
        .commit_builder()
        .authenticated_data(aad)
        .remove_member(removed.index)?
        .build()?;
    let certified = certify(
        clients,
        &output.commit_message.to_bytes()?,
        *head,
        (clients.policies.1, clients.policies.1),
        alice_leaf,
        close_authority::CertificationTransition::Remove,
    )?;
    group.apply_pending_commit()?;
    *head = (head.0.saturating_add(1), certified.finalization_id);
    *time = time.saturating_add(1);
    Ok(certified.finalization_id)
}

/// The immutable ReInit target of the successor group, with the binding and
/// initial member plan it commits to.
fn target_of(clients: &Clients, old_state: [u8; 32]) -> TestResult<Target> {
    let principals = [&clients.alice_keys.keys, &clients.bob_keys.keys];
    let fingerprint = builders::root_fingerprint(&clients.alice_keys.keys.root)?;
    let conversation = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &SUCCESSOR_GROUP)?;
    let policies = policies_for(&principals, conversation, ArcConversationKind::Channel)?;
    let package = builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route: builders::channel_route(b"#room", fingerprint)?,
        channel_instance_id: clients.bound.instance,
        conversation_nonce: None,
        group_id: SUCCESSOR_GROUP,
        generation: 1,
        previous_binding_id: clients.bound.binding_id,
        lock_sequence: 0,
        previous_lock_ids: Vec::new(),
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
        sequencer_credential_id: active_sequencer_credential_id()?,
        plan_devices: vec![
            (
                &clients.alice_keys.account,
                fingerprint,
                clients.alice_keys.device,
            ),
            (
                &clients.bob_keys.account,
                builders::root_fingerprint(&clients.bob_keys.keys.root)?,
                clients.bob_keys.device,
            ),
        ],
    })?;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
    let plan_id = semantic_id_of(
        SemanticHashDomain::InitialMemberPlanId,
        &package.initial_member_plan,
    )?;
    let tbs = ArcReInitTargetTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: clients.bound.conversation,
        old_reinit_state_id: old_state,
        new_conversation_id: conversation,
        target_group_id: Opaque::new(SUCCESSOR_GROUP.to_vec())?,
        target_version: 1,
        target_suite: 1,
        target_context_core_id: CONTEXT_CORE_ID,
        target_binding_id: binding_id,
        initial_member_plan_id: plan_id,
        encoded_target_extensions: Opaque::new(vec![0])?,
    };
    let digest = semantic_id_of(SemanticHashDomain::ReinitTarget, &tbs)?;
    Ok(Target {
        tbs,
        digest,
        conversation,
        binding_id,
        plan_id,
    })
}

/// The public results of the successor state. The four result digests are
/// endpoint-defined: the companion registers no Section 2.2 formula for
/// them, so each binds real successor material, and the exporter
/// authenticator is the one the companion does fix.
fn results_of(
    successor: &mls_rs::Group<impl MlsConfig>,
    old_state: [u8; 32],
) -> TestResult<Results> {
    let info = successor.clone().group_info_message(true)?.to_bytes()?;
    let tree = successor.export_tree().to_bytes()?;
    let exporter = successor.export_secret(EXPORTER_LABEL, &old_state, 32)?;
    Ok(Results {
        group_info: *e2ee::ObjectId::compute(&info).as_bytes(),
        context: *e2ee::ObjectId::compute(successor.group_id()).as_bytes(),
        tree: *e2ee::ObjectId::compute(&tree).as_bytes(),
        exporter: exporter
            .to_vec()
            .try_into()
            .map_err(|_| failure("the exporter returns thirty-two bytes"))?,
    })
}

/// The daemon's KeyPackageRef of a published package.
fn package_reference(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut budget = DecodeBudget::new(1 << 16, 1 << 14);
    let e2ee::mls_outer::MlsOuterMessage::KeyPackage(parsed) =
        e2ee::mls_outer::parse_mls_message(bytes, &mut budget)?
    else {
        return Err(failure("the resumption package is a key package"));
    };
    Ok(parsed.key_package_ref.to_vec())
}

/// The complete attempt object: the key-package plan of both continuing
/// leaves, the successor's initial state bytes, and the old-policy
/// controller authorization every field of which the attempt repeats.
fn build_attempt(
    clients: &Clients,
    target: &Target,
    continuing: &Continuing<'_>,
    state: ([u8; 32], &[u8], Results),
) -> TestResult<ArcReInitAttempt> {
    let (old_state, initial_commit, results) = state;
    let plan = key_package_plan(clients, continuing)?;
    let authorization_tbs = ArcReInitAttemptAuthorizationTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: clients.bound.conversation,
        old_reinit_state_id: old_state,
        attempt_sequence: 0,
        creator_old_leaf_index: continuing.creator.index,
        creator_old_credential_hash: continuing.creator.credential_hash,
        new_conversation_id: target.conversation,
        target_context_digest: target.digest,
        target_binding_id: target.binding_id,
        initial_member_plan_id: target.plan_id,
        key_package_plan_id: semantic_id_of(SemanticHashDomain::KeyPackagePlanId, &plan)?,
        initial_commit_digest: e2ee::ids::initial_commit_digest(initial_commit)?,
        new_group_info_digest: results.group_info,
        new_group_context_digest: results.context,
        new_ratchet_tree_digest: results.tree,
        new_exporter_authenticator: results.exporter,
    };
    let approval = builders::commit_approval(
        &clients.alice_keys.keys,
        clients.alice_keys.device,
        &authorization_tbs,
        SignatureDomain::ReinitAttemptAuthorization,
    )?;
    let tbs = ArcReInitAttemptTbs {
        profile_version: 1,
        network_id: authorization_tbs.network_id,
        old_conversation_id: authorization_tbs.old_conversation_id,
        new_conversation_id: authorization_tbs.new_conversation_id,
        old_reinit_state_id: authorization_tbs.old_reinit_state_id,
        attempt_sequence: authorization_tbs.attempt_sequence,
        creator_old_leaf_index: authorization_tbs.creator_old_leaf_index,
        creator_old_credential_hash: authorization_tbs.creator_old_credential_hash,
        target_group_id: target.tbs.target_group_id.clone(),
        target_version: target.tbs.target_version,
        target_suite: target.tbs.target_suite,
        target_context_digest: authorization_tbs.target_context_digest,
        target_binding_id: authorization_tbs.target_binding_id,
        initial_member_plan_id: authorization_tbs.initial_member_plan_id,
        key_package_plan_id: authorization_tbs.key_package_plan_id,
        initial_commit_digest: authorization_tbs.initial_commit_digest,
        attempt_authorization_id: semantic_id_of(
            SemanticHashDomain::ReinitAttemptAuthorizationId,
            &authorization_tbs,
        )?,
        new_group_info_digest: authorization_tbs.new_group_info_digest,
        new_group_context_digest: authorization_tbs.new_group_context_digest,
        new_ratchet_tree_digest: authorization_tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: authorization_tbs.new_exporter_authenticator,
    };
    let creator_signature = builders::sign(
        &continuing.creator.secret,
        SignatureDomain::ReinitAttempt,
        &tbs,
    )?;
    Ok(ArcReInitAttempt {
        tbs,
        key_package_plan: plan,
        initial_commit_bytes: Opaque::new(initial_commit.to_vec())?,
        authorization: ArcReInitAttemptAuthorization {
            tbs: authorization_tbs,
            approvals: TlsVec::new(vec![approval])?,
        },
        creator_old_leaf_signature: Opaque::from_slice(&creator_signature)?,
    })
}

/// The canonical key-package plan: the creator with an empty reserved
/// reference and every other continuing leaf with its own.
fn key_package_plan(
    clients: &Clients,
    continuing: &Continuing<'_>,
) -> TestResult<ArcKeyPackagePlan> {
    let creator = ArcKeyPackagePlanEntry {
        account_id: Opaque::from_slice(&clients.alice_keys.account)?,
        root_fingerprint: builders::root_fingerprint(&clients.alice_keys.keys.root)?,
        device_id: [clients.alice_keys.device; 16],
        capability_id: [clients.alice_keys.device.wrapping_add(200); 32],
        key_package_ref: Opaque::new(Vec::new())?,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key_digest: e2ee::ids::leaf_signature_key_digest(
            0x0807,
            &builders::public(&continuing.creator.secret),
        )?,
        creator: 1,
    };
    let joiner = ArcKeyPackagePlanEntry {
        account_id: Opaque::from_slice(&clients.bob_keys.account)?,
        root_fingerprint: builders::root_fingerprint(&clients.bob_keys.keys.root)?,
        device_id: [clients.bob_keys.device; 16],
        capability_id: [clients.bob_keys.device.wrapping_add(200); 32],
        key_package_ref: Opaque::new(continuing.joiner_reference.clone())?,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key_digest: e2ee::ids::leaf_signature_key_digest(
            0x0807,
            &builders::public(&continuing.joiner.secret),
        )?,
        creator: 0,
    };
    let mut entries = vec![creator, joiner];
    entries.sort_by_key(|entry| entry.device_id);
    Ok(ArcKeyPackagePlan {
        entries: TlsVec::new(entries)?,
    })
}

/// Submits the attempt from alice's attached device and returns the ReInit
/// attempt identifier the coordinator staged.
fn stage_attempt(clients: &mut Clients, attempt: &ArcReInitAttempt) -> TestResult<[u8; 32]> {
    let object = wire_object(ArcWireObjectKind::ReinitAttempt, attempt)?;
    let token = base64url_encode(&clients.bound.conversation);
    let label = clients.alice_keys.label();
    send_object(
        &mut clients.alice,
        &label,
        &format!("EGROUP SUBMIT REINIT ATTEMPT {token}"),
        &object,
    )?;
    let reply = labeled_reply(&mut clients.alice, &label)?;
    let completion = std::slice::from_ref(only_completion(&reply, "REINIT-STAGED")?);
    assert_eq!(
        hash_at(completion, "REINIT-STAGED", 3)?,
        clients.bound.conversation
    );
    assert_eq!(
        hash_at(completion, "REINIT-STAGED", 5)?,
        *e2ee::ObjectId::compute(&object).as_bytes()
    );
    hash_at(completion, "REINIT-STAGED", 4)
}

/// The requester's labeled completion, which `labeled_reply` returns last.
/// The unlabeled broadcast or notice that can arrive before it is not the
/// command's result (companion 11.7), so a reply token is checked here.
fn completion_line(reply: &[String]) -> TestResult<&String> {
    reply
        .last()
        .filter(|line| tag_value(line, "label").is_some())
        .ok_or_else(|| failure(format!("no labeled completion in {reply:?}")))
}

/// The requester's labeled `verb` completion, required to be the only line
/// of its reply naming `verb`: companion 11.7 and 12.5 answer the requesting
/// connection with exactly one labeled scalar and send the untagged
/// broadcast of the same result only to the other eligible sinks.
fn only_completion<'a>(reply: &'a [String], verb: &str) -> TestResult<&'a String> {
    let completion = completion_line(reply)?;
    let token = format!(" EGROUP {verb} ");
    if !completion.contains(&token) {
        return Err(failure(format!(
            "the labeled completion is not {verb}: {reply:?}"
        )));
    }
    let naming = reply.iter().filter(|line| line.contains(&token)).count();
    if naming != 1 {
        return Err(failure(format!(
            "the requester received {naming} {verb} lines, not one labeled completion: {reply:?}"
        )));
    }
    Ok(completion)
}

/// Requires the last of `lines`, which another sink read, to be the
/// untagged broadcast of the terminal `completion` names: the same verb and
/// identifiers, without a label.
fn assert_same_terminal(lines: &[String], completion: &[String]) -> TestResult {
    let broadcast = lines
        .last()
        .ok_or_else(|| failure("no terminal broadcast was read"))?;
    if tag_value(broadcast, "label").is_some() {
        return Err(failure(format!("the broadcast is labeled: {broadcast}")));
    }
    let terminal = |line: &String| words(line).get(1..).map(<[String]>::to_vec);
    assert_eq!(
        terminal(broadcast),
        completion.first().and_then(terminal),
        "the broadcast and the labeled completion name the same terminal"
    );
    Ok(())
}

/// Reads the attempt receipt the coordinator sequenced for the conversation.
fn attempt_receipt(clients: &mut Clients) -> TestResult<ArcReInitAttemptReceipt> {
    let token = base64url_encode(&clients.bound.conversation);
    let label = clients.alice_keys.label();
    clients
        .alice
        .send(&format!("@label={label} EGROUP FETCH RECEIPTS {token} 0 *"))?;
    let reply = labeled_reply(&mut clients.alice, &label)?;
    let mut budget = DecodeBudget::new(1 << 22, 1 << 16);
    for bytes in super::super::recovery_submission::page_objects(&reply)? {
        let object = ArcWireObject::decode_kind(
            &bytes,
            Some(ArcWireObjectKind::SequencerRecord),
            &mut budget,
        )?;
        if let ArcSequencerRecord::ReinitAttempt(receipt) =
            ArcSequencerRecord::decode_exact(object.body(), &mut budget)?
        {
            return Ok(receipt);
        }
    }
    Err(failure("the conversation retains a ReInit attempt receipt"))
}

/// The creator's `creator_state` acknowledgement, signed by its old leaf.
fn acknowledge_creator(
    clients: &mut Clients,
    attempt: &ArcReInitAttempt,
    attempt_id: [u8; 32],
    results: Results,
) -> TestResult<ArcReInitAck> {
    let tbs = ArcReInitAckTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: attempt.tbs.old_conversation_id,
        new_conversation_id: attempt.tbs.new_conversation_id,
        old_reinit_state_id: attempt.tbs.old_reinit_state_id,
        reinit_attempt_id: attempt_id,
        ack_kind: ArcReInitAckKind::CreatorState,
        new_group_info_digest: results.group_info,
        new_group_context_digest: results.context,
        new_ratchet_tree_digest: results.tree,
        new_exporter_authenticator: results.exporter,
        old_leaf_index: attempt.tbs.creator_old_leaf_index,
        old_credential_hash: attempt.tbs.creator_old_credential_hash,
        new_leaf_index: 0,
        key_package_ref: Opaque::new(Vec::new())?,
    };
    let leaf = Ed25519SecretKey::from_bytes(ALICE_LEAF);
    let ack = signed_ack(tbs, &leaf)?;
    let conversation = clients.bound.conversation;
    let label = clients.alice_keys.label();
    submit_ack(&mut clients.alice, &label, conversation, &ack)?;
    Ok(ack)
}

/// The continuing joiner's `welcome_join` acknowledgement, naming its own
/// reserved reference and signed by its old leaf.
fn acknowledge_joiner(
    clients: &mut Clients,
    attempt: &ArcReInitAttempt,
    attempt_id: [u8; 32],
    state: (Results, &Continuing<'_>, u32),
) -> TestResult<ArcReInitAck> {
    let (results, continuing, new_leaf_index) = state;
    let tbs = ArcReInitAckTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: attempt.tbs.old_conversation_id,
        new_conversation_id: attempt.tbs.new_conversation_id,
        old_reinit_state_id: attempt.tbs.old_reinit_state_id,
        reinit_attempt_id: attempt_id,
        ack_kind: ArcReInitAckKind::WelcomeJoin,
        new_group_info_digest: results.group_info,
        new_group_context_digest: results.context,
        new_ratchet_tree_digest: results.tree,
        new_exporter_authenticator: results.exporter,
        old_leaf_index: continuing.joiner.index,
        old_credential_hash: continuing.joiner.credential_hash,
        new_leaf_index,
        key_package_ref: Opaque::new(continuing.joiner_reference.clone())?,
    };
    let ack = signed_ack(tbs, &continuing.joiner.secret)?;
    let conversation = clients.bound.conversation;
    let label = clients.bob_keys.label();
    submit_ack(&mut clients.bob, &label, conversation, &ack)?;
    Ok(ack)
}

/// One acknowledgement signed by the old leaf key it names.
fn signed_ack(tbs: ArcReInitAckTbs, leaf: &Ed25519SecretKey) -> TestResult<ArcReInitAck> {
    Ok(ArcReInitAck {
        old_leaf_signature: Opaque::from_slice(&builders::sign(
            leaf,
            SignatureDomain::ReinitProcessed,
            &tbs,
        )?)?,
        tbs,
    })
}

/// Submits one standalone ReInit acknowledgement.
fn submit_ack(
    client: &mut ArcClient,
    label: &str,
    conversation: [u8; 32],
    ack: &ArcReInitAck,
) -> TestResult {
    let object = wire_object(ArcWireObjectKind::ReinitAck, ack)?;
    send_object(
        client,
        label,
        &format!(
            "EGROUP SUBMIT REINIT ACK {}",
            base64url_encode(&conversation)
        ),
        &object,
    )?;
    let reply = labeled_reply(client, label)?;
    assert_contains(
        std::slice::from_ref(completion_line(&reply)?),
        " EGROUP REINIT-ACKED ",
    )?;
    // The submitter receives only its labeled REINIT-ACKED; the untagged
    // REINIT-ACK notice of its own ACK goes to the other sessions (11.7).
    let own = base64url_encode(e2ee::ObjectId::compute(&object).as_bytes());
    if reply
        .iter()
        .any(|line| line.contains(" EGROUP REINIT-ACK ") && line.contains(&own))
    {
        return Err(failure(format!(
            "the submitter received the notice of its own ACK: {reply:?}"
        )));
    }
    Ok(())
}

/// Submits one activation request carrying `acks` and the votes of the
/// council devices named by `voters`, and returns the reply lines.
fn submit_activation(
    clients: &mut Clients,
    attempt: &ArcReInitAttempt,
    receipt: &ArcReInitAttemptReceipt,
    proof: (Vec<ArcReInitAck>, &[u8]),
) -> TestResult<Vec<String>> {
    let (mut acks, voters) = proof;
    acks.sort_by_key(|ack| ack.tbs.old_leaf_index);
    let digests: Vec<_> = acks.iter().map(|ack| ack.tbs.clone()).collect();
    let core = ArcReInitActivationCoreTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: attempt.tbs.old_conversation_id,
        new_conversation_id: attempt.tbs.new_conversation_id,
        old_reinit_state_id: attempt.tbs.old_reinit_state_id,
        attempt_sequence: attempt.tbs.attempt_sequence,
        reinit_attempt_id: receipt.tbs.reinit_attempt_id,
        new_group_info_digest: attempt.tbs.new_group_info_digest,
        new_group_context_digest: attempt.tbs.new_group_context_digest,
        new_ratchet_tree_digest: attempt.tbs.new_ratchet_tree_digest,
        new_exporter_authenticator: attempt.tbs.new_exporter_authenticator,
        acknowledgement_set_digest: e2ee::ids::proof_set_digest(
            SemanticHashDomain::ReinitAcknowledgementSet,
            &digests,
        )?,
    };
    let terminal = Terminal::finalize(semantic_id_of(
        SemanticHashDomain::ReinitActivationId,
        &core,
    )?);
    let slot = ReinitVoteSlot {
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: attempt.tbs.old_conversation_id,
        old_reinit_state_id: attempt.tbs.old_reinit_state_id,
        attempt_sequence: attempt.tbs.attempt_sequence,
        predecessor_record_id: receipt.tbs.predecessor_record_id,
    };
    let tbs = reinit_vote_tbs(&slot, receipt.tbs.reinit_attempt_id, terminal);
    let mut votes = Vec::new();
    for index in voters {
        let principal = match index {
            0 => &clients.alice_keys,
            _ => &clients.bob_keys,
        };
        votes.push(reinit_vote(principal, &tbs)?);
    }
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    let request = ArcReInitActivationRequest {
        core,
        receipt: receipt.clone(),
        attempt: attempt.clone(),
        acknowledgements: TlsVec::new(acks)?,
        votes: TlsVec::new(votes)?,
    };
    let object = wire_object(ArcWireObjectKind::ReinitActivationRequest, &request)?;
    let token = base64url_encode(&clients.bound.conversation);
    let label = clients.alice_keys.label();
    send_object(
        &mut clients.alice,
        &label,
        &format!("EGROUP SUBMIT REINIT ACTIVATE {token}"),
        &object,
    )?;
    labeled_reply(&mut clients.alice, &label)
}

/// One ReInit disposition vote of a council device.
fn reinit_vote(
    principal: &Principal,
    tbs: &ArcReInitDispositionVoteTbs,
) -> TestResult<ArcFinalityVote> {
    Ok(ArcFinalityVote {
        signer_root_fingerprint: builders::root_fingerprint(&principal.keys.root)?,
        signer_device_id: [principal.device; 16],
        signer_device_certificate_id: builders::certificate_id_of(
            &principal.keys,
            principal.device,
        )?,
        device_signature: builders::sign(
            &builders::key(principal.device),
            SignatureDomain::ReinitDisposition,
            tbs,
        )?,
    })
}

/// One staged attempt of the two-leaf successor: alice creates it and bob's
/// continuing leaf joins it through its Welcome.
struct Staged {
    attempt: ArcReInitAttempt,
    attempt_id: [u8; 32],
    receipt: ArcReInitAttemptReceipt,
}

/// Activates the old group, adds bob's continuing leaf, closes the group
/// with a real ReInit Commit, resumes both endpoints and stages the
/// successor's attempt under the old-policy controller's authorization.
fn stage_two_leaf_attempt(clients: &mut Clients) -> TestResult<Staged> {
    let alice_interval = clients.alice_interval();
    let bob_interval = clients.bob_interval();
    let alice_leaf = real_leaf(&clients.alice_keys, alice_interval, ALICE_LEAF, 0)?;
    let alice_client =
        real_clients::mls_rs_client_with_leaf(&clients.alice_keys, alice_interval, ALICE_LEAF)?;
    let mut group = alice_client
        .group_builder()?
        .with_group_id(clients.bound.group_id.to_vec())
        .build()?;
    let mut head = (0_u64, clients.genesis);
    let mut time = clients.now;
    let policies = clients.policies;

    let activation = commit(&mut group, clients, head, time, |builder| Ok(builder))?;
    let activated = certify(
        clients,
        &activation,
        head,
        policies,
        &alice_leaf,
        close_authority::CertificationTransition::Bootstrap,
    )?;
    group.apply_pending_commit()?;
    head = (1, activated.finalization_id);
    time = time.saturating_add(1);

    let (bob_leaf, mut bob_group) = join_member(
        clients,
        &mut group,
        &mut head,
        &mut time,
        (&alice_leaf, BOB_REJOIN_LEAF, bob_interval),
    )?;
    {
        let epoch = head.0;
        let Clients {
            bob,
            bob_keys,
            bound,
            ..
        } = &mut *clients;
        publish_membership(bob, bob_keys, bound, epoch, &bob_leaf, None)?;
    }

    let target = target_of(clients, head.1)?;
    let reinit = commit(&mut group, clients, head, time, |builder| {
        Ok(builder.reinit(
            Some(SUCCESSOR_GROUP.to_vec()),
            RsVersion::MLS_10,
            RsSuite::CURVE25519_AES128,
            Default::default(),
        )?)
    })?;
    let old_state = certify(
        clients,
        &reinit,
        head,
        (policies.1, policies.1),
        &alice_leaf,
        close_authority::CertificationTransition::Reinit(target.digest),
    )?
    .finalization_id;
    group.apply_pending_commit()?;
    bob_group.process_incoming_message(mls_rs::MlsMessage::from_bytes(&reinit)?)?;
    let target = target_of(clients, old_state)?;

    let bob_resumed = bob_group.get_reinit_client(None, None)?;
    let bob_package = bob_resumed.generate_key_package(Some(MlsTime::from(bob_interval.0)))?;
    let joiner_reference = package_reference(&bob_package.to_bytes()?)?;
    let alice_resumed = group.get_reinit_client(None, None)?;
    let (successor, _welcomes) = alice_resumed.commit(
        vec![bob_package],
        Default::default(),
        Some(MlsTime::from(alice_interval.0)),
    )?;
    let results = results_of(&successor, old_state)?;
    let initial_commit = successor.group_info_message(true)?.to_bytes()?;
    let continuing = Continuing {
        creator: &alice_leaf,
        joiner: &bob_leaf,
        joiner_reference,
    };
    let attempt = build_attempt(
        clients,
        &target,
        &continuing,
        (old_state, &initial_commit, results),
    )?;
    let attempt_id = step("stage the attempt", stage_attempt(clients, &attempt))?;
    let receipt = step("fetch the attempt receipt", attempt_receipt(clients))?;
    assert_eq!(receipt.tbs.reinit_attempt_id, attempt_id);
    Ok(Staged {
        attempt,
        attempt_id,
        receipt,
    })
}

/// The abort core of the staged attempt under [`ABORT_REASON`].
fn abort_core(staged: &Staged) -> ArcReInitAbortCoreTbs {
    ArcReInitAbortCoreTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        old_conversation_id: staged.attempt.tbs.old_conversation_id,
        old_reinit_state_id: staged.attempt.tbs.old_reinit_state_id,
        attempt_sequence: staged.attempt.tbs.attempt_sequence,
        slot_predecessor_record_id: staged.receipt.tbs.predecessor_record_id,
        reinit_attempt_id: staged.receipt.tbs.reinit_attempt_id,
        reason_code: ABORT_REASON,
        evidence_digest: [0; 32],
    }
}

/// The council device whose vote one abort request carries, submitted from
/// that device's own client.
#[derive(Clone, Copy)]
enum Voter {
    Alice,
    Bob,
}

/// Submits the abort of the staged attempt carrying only `voter`'s vote and
/// returns the reply lines and the request's object identifier.
fn submit_abort(
    clients: &mut Clients,
    staged: &Staged,
    core: &ArcReInitAbortCoreTbs,
    voter: Voter,
) -> TestResult<(Vec<String>, [u8; 32])> {
    let terminal = Terminal::abort(
        semantic_id_of(SemanticHashDomain::ReinitAbortId, core)?,
        core.reason_code,
    )?;
    let slot = ReinitVoteSlot {
        network_id: core.network_id,
        old_conversation_id: core.old_conversation_id,
        old_reinit_state_id: core.old_reinit_state_id,
        attempt_sequence: core.attempt_sequence,
        predecessor_record_id: core.slot_predecessor_record_id,
    };
    let tbs = reinit_vote_tbs(&slot, core.reinit_attempt_id, terminal);
    let (client, principal) = match voter {
        Voter::Alice => (&mut clients.alice, &mut clients.alice_keys),
        Voter::Bob => (&mut clients.bob, &mut clients.bob_keys),
    };
    let request = ArcReInitAbortRequest {
        core: core.clone(),
        receipt: staged.receipt.clone(),
        attempt: staged.attempt.clone(),
        votes: TlsVec::new(vec![reinit_vote(principal, &tbs)?])?,
    };
    let object = wire_object(ArcWireObjectKind::ReinitAbortRequest, &request)?;
    let label = principal.label();
    send_object(
        client,
        &label,
        &format!(
            "EGROUP SUBMIT REINIT ABORT {}",
            base64url_encode(&core.old_conversation_id)
        ),
        &object,
    )?;
    let reply = labeled_reply(client, &label)?;
    Ok((reply, *e2ee::ObjectId::compute(&object).as_bytes()))
}
