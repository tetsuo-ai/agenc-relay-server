//! ENC-10 scenario C (companion 13.8 and 13.7.3): a real RFC 9420 ReInit.
//! Two mls-rs endpoints close the old group with a real ReInit proposal and
//! build the resumption successor, while the daemon certifies the ReInit
//! Commit, sequences the attempt, admits one acknowledgement per continuing
//! leaf and activates the successor. A leaf removed in an earlier finalized
//! epoch carries a removal proof for that epoch, leaves the expected
//! continuing set and must rejoin, and an activation whose acknowledgements
//! do not cover the continuing set is refused without changing anything.
//!
//! The ReInit target is built once, before the old ReInit Commit: it covers
//! no state of the old group, so the digest the old authorization commits is
//! the digest every attempt names, and every attempt carries that target
//! byte for byte. Its extension list carries the successor context companion
//! 13.8 describes, so the daemon's sequencer accepts the attempt only after
//! the target hashes to the authorized digest, the attempt repeats it, the
//! KeyPackage plan forms its member plan, and the context describes the
//! successor of the bound route. The daemon's own records are then replayed
//! through the shared historical chain, resumed at the accepted state before
//! the ReInit candidate, with that target bound to the finalization.
//!
//! openmls 0.9 exposes no ReInit proposal or resumption successor, so both
//! endpoints of this scenario are mls-rs; the cross-library evidence is in
//! the recovery and rotation scenarios and in the interoperability matrix.
//! mls-rs 0.56 `ReinitClient::commit` returns neither the successor initial
//! Commit nor a way to set its authenticated data, so the attempt still
//! carries the successor GroupInfo message as its initial Commit bytes, and
//! the mls-rs ReInit Proposal's own extension list stays empty because these
//! endpoints advertise no ARC extension capability, so they never rebuild
//! the target from the Proposal; that reconstruction from real extensions and
//! the initial Commit's authenticated data are covered by the independent
//! vectors in `test-data/vectors/e2ee/reinit`. Those GroupInfo
//! bytes do not satisfy the companion's successor initial-Commit rule
//! (`AuthorizedReinit::check_initial_commit` refuses anything but a
//! `PrivateMessage` Commit), and `HistoricalChain` does not apply that rule,
//! so the replay proves one target, not the initial Commit.
#![forbid(unsafe_code)]

use super::*;

use e2ee::finality::{ReinitVoteSlot, reinit_vote_tbs};
use e2ee::history::{
    ChainHead, ChainLimits, ChainStep, HistoricalChain, Lifecycle, RecordReferences, ResumedChain,
};
use e2ee::identity::{verify_root_identity, verify_roster};
use e2ee::objects::conversation::{ArcKeyPackagePlan, ArcKeyPackagePlanEntry};
use e2ee::objects::reinit::{
    ArcReInitAbortCoreTbs, ArcReInitAbortRequest, ArcReInitAck, ArcReInitAckKind, ArcReInitAckTbs,
    ArcReInitActivationCoreTbs, ArcReInitActivationRequest, ArcReInitAttempt,
    ArcReInitAttemptAuthorization, ArcReInitAttemptAuthorizationTbs, ArcReInitAttemptReceipt,
    ArcReInitAttemptTbs, ArcReInitDispositionVoteTbs, ArcReInitTargetTbs,
};
use e2ee::objects::sequencing::{ArcFinalityVote, ArcSequencerRecord};
use e2ee::policy::verify_policy;
use e2ee::record_authentication::declared_position;
use e2ee::reinit_target::AuthorizedReinit;
use e2ee::route::{PrincipalRosters, verify_binding_package};
use e2ee::sequencer::verify_sequencer_credential;
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

/// The immutable target the old ReInit Commit commits to, built once.
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

    // The ReInit Commit: a real ReInit proposal closes the old group. Its
    // target exists before the Commit and never changes afterwards.
    let target = target_of(&clients)?;
    let before_reinit = head;
    let reinit = commit(&mut group, &clients, head, time, |builder| {
        Ok(builder.reinit(
            Some(SUCCESSOR_GROUP.to_vec()),
            RsVersion::MLS_10,
            RsSuite::CURVE25519_AES128,
            Default::default(),
        )?)
    })?;
    let certified = certify(
        &mut clients,
        &reinit,
        head,
        operational,
        &alice_leaf,
        close_authority::CertificationTransition::Reinit(target.digest),
    )?;
    let old_state = certified.finalization_id;
    group.apply_pending_commit()?;
    bob_group.process_incoming_message(mls_rs::MlsMessage::from_bytes(&reinit)?)?;

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
    step(
        "shared history verification",
        verify_through_history(
            network,
            &mut clients,
            &target,
            &certified,
            before_reinit,
            &attempt,
        ),
    )?;
    require_recorded(&REINIT_RULES)
}

/// Companion 11.7, 12.5 and 13.8 through the production daemons: the two
/// council votes of one attempt abort arrive in separate requests. alice's
/// vote alone is below the quorum and is answered `PENDING`; bob's completes
/// the abort and is answered `REINIT-ABORTED`; and alice, answered
/// `PENDING` earlier, then reads the untagged `REINIT-ABORTED` broadcast
/// naming the same abort. The coordinator correlates the abort event only
/// on the copy for bob's edge, the home of the request that completed it,
/// so alice's edge renders its copy as the broadcast.
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

/// An empty RFC 9420 `RequiredCapabilities`: three empty vectors.
const REQUIRED_CAPABILITIES: [u8; 3] = [0, 0, 0];
/// The successor context's initial validation time.
const SUCCESSOR_VALIDATION_TIME: u64 = 60;

/// The immutable ReInit target of the successor group, with the binding and
/// initial member plan it commits to. It names no state of the old group:
/// its extension list carries the successor context companion 13.8
/// describes (the replacement of the bound `#room` binding on the same
/// route, the successor's generation-zero policy of both principals, the
/// coordinator's sequencer credential and both principals' roster heads)
/// and an empty `required_capabilities` extension.
fn target_of(clients: &Clients) -> TestResult<Target> {
    let network = *NETWORK_ID.as_bytes();
    let principals = [&clients.alice_keys.keys, &clients.bob_keys.keys];
    let conversation = e2ee::ids::conversation_id(&network, &SUCCESSOR_GROUP)?;
    let policy = builders::policy(&builders::PolicySpec::bootstrap(
        &principals,
        conversation,
        ArcConversationKind::Channel,
    )?)?;
    let policy_id = builders::policy_id_of(&policy)?;
    let sequencer = builders::sequencer_credential_in(
        network,
        &Ed25519SecretKey::from_bytes([35; 32]),
        0,
        (0, 4_000_000_000),
        None,
    )?;
    let plan = successor_plan(clients)?;
    let plan_id = semantic_id_of(SemanticHashDomain::InitialMemberPlanId, &plan)?;
    let old = &clients.bound.package.binding.tbs;
    let mut binding = old.clone();
    binding.binding_generation = old.binding_generation.saturating_add(1);
    binding.previous_binding_id = clients.bound.binding_id;
    binding.group_id = Opaque::from_slice(&SUCCESSOR_GROUP)?;
    binding.conversation_id = conversation;
    binding.cipher_suite = 1;
    binding.initial_policy_id = policy_id;
    binding.required_operational_policy_id = policy_id;
    binding.initial_member_plan_id = plan_id;
    binding.sequencer_credential_id =
        semantic_id_of(SemanticHashDomain::SequencerKey, &sequencer.tbs)?;
    let core = e2ee::objects::conversation::ArcContextCoreTbs {
        profile_version: 1,
        mls_version: 1,
        cipher_suite: 1,
        group_id: Opaque::from_slice(&SUCCESSOR_GROUP)?,
        network_id: network,
        conversation_id: conversation,
        kind: binding.kind,
        semantic_route_lock_id: binding.semantic_route_lock_id,
        route_binding: binding.route_binding,
        initial_validation_time: SUCCESSOR_VALIDATION_TIME,
        initial_policy_id: policy_id,
        required_operational_policy_id: policy_id,
        initial_bootstrap_pending: 0,
        initial_member_plan_id: plan_id,
        sequencer_credential_id: binding.sequencer_credential_id,
        encoded_required_capabilities: Opaque::from_slice(&REQUIRED_CAPABILITIES)?,
    };
    let core_id = e2ee::context::context_core_id(&core)?;
    binding.context_core_id = core_id;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &binding)?;
    let mut roster_heads = [&clients.alice_keys, &clients.bob_keys]
        .into_iter()
        .map(|principal| {
            Ok(e2ee::objects::conversation::ArcRosterHead {
                account_id_digest: e2ee::ids::account_id_digest(&network, &principal.account)?,
                root_generation: principal.keys.root.tbs.root_generation,
                root_fingerprint: builders::root_fingerprint(&principal.keys.root)?,
                roster_generation: principal.keys.roster.tbs.roster_generation,
                roster_id: builders::roster_id(&principal.keys.roster)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    roster_heads.sort_by_key(|head| {
        (
            head.account_id_digest,
            head.root_generation,
            head.root_fingerprint,
        )
    });
    let context = e2ee::objects::conversation::ArcMlsContext {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        kind: binding.kind,
        route_binding: binding.route_binding,
        initial_validation_time: SUCCESSOR_VALIDATION_TIME,
        policy,
        sequencer,
        current_binding: e2ee::objects::conversation::ArcConversationBinding {
            tbs: binding,
            approvals: TlsVec::new(Vec::new())?,
        },
        lifecycle: e2ee::objects::conversation::ArcConversationLifecycle {
            kind: e2ee::objects::conversation::ArcConversationLifecycleKind::ActiveConversation,
            close_intent_id: [0; 32],
        },
        private_topic: Opaque::new(Vec::new())?,
        bootstrap_pending: 0,
        roster_heads: TlsVec::new(roster_heads)?,
        pending_joins: TlsVec::new(Vec::new())?,
    };
    let mut body = Vec::new();
    for (extension_type, data) in [
        (
            e2ee::reinit_target::REQUIRED_CAPABILITIES_EXTENSION,
            REQUIRED_CAPABILITIES.to_vec(),
        ),
        (e2ee::limits::ARC_MLS_CONTEXT_EXTENSION, context.encode()?),
    ] {
        body.extend_from_slice(&extension_type.to_be_bytes());
        builders::opaque_v(&mut body, &data)?;
    }
    let mut extensions = Vec::new();
    builders::opaque_v(&mut extensions, &body)?;
    let tbs = ArcReInitTargetTbs {
        profile_version: 1,
        network_id: network,
        old_conversation_id: clients.bound.conversation,
        new_conversation_id: conversation,
        target_group_id: Opaque::new(SUCCESSOR_GROUP.to_vec())?,
        target_version: 1,
        target_suite: 1,
        target_context_core_id: core_id,
        target_binding_id: binding_id,
        initial_member_plan_id: plan_id,
        encoded_target_extensions: Opaque::new(extensions)?,
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

/// The semantic initial member plan of both continuing leaves, in the
/// canonical order the attempt's KeyPackage plan repeats: alice's and bob's
/// devices with their capabilities.
fn successor_plan(
    clients: &Clients,
) -> TestResult<e2ee::objects::conversation::ArcInitialMemberPlan> {
    let mut entries = [&clients.alice_keys, &clients.bob_keys]
        .into_iter()
        .map(|principal| {
            Ok(e2ee::objects::conversation::ArcInitialMemberPlanEntry {
                account_id: Opaque::from_slice(&principal.account)?,
                root_fingerprint: builders::root_fingerprint(&principal.keys.root)?,
                device_id: [principal.device; 16],
                capability_id: [principal.device.wrapping_add(200); 32],
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    entries.sort_by_key(|entry| {
        (
            entry.account_id.clone(),
            entry.root_fingerprint,
            entry.device_id,
        )
    });
    Ok(e2ee::objects::conversation::ArcInitialMemberPlan {
        entries: TlsVec::new(entries)?,
    })
}

/// The public results of the successor state. The three result digests are
/// object-identifier hashes of successor material (the GroupInfo message,
/// the group ID and the exported tree), not the Section 2.2
/// `group_info_digest`, `group_context_digest` and `ratchet_tree_digest`
/// formulas, which this fixture does not compute; the exporter authenticator
/// uses the label and context the companion fixes.
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
        target: target.tbs.clone(),
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
    // Canonical by the semantic plan's device tuple (companion 9.4), so the
    // tuples form the target's initial member plan in this order.
    let mut entries = vec![creator, joiner];
    entries.sort_by_key(|entry| {
        (
            entry.account_id.clone(),
            entry.root_fingerprint,
            entry.device_id,
        )
    });
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
    assert_no_own_notice(&reply, "REINIT-ACK", &object)
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

    // The target exists before the ReInit Commit and never changes.
    let target = target_of(clients)?;
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

/// Every retained record of the old conversation from `first` on, with its
/// route sequence and complete object bytes.
fn conversation_records(
    clients: &mut Clients,
    first: u64,
) -> TestResult<Vec<(u64, Vec<u8>, ArcSequencerRecord)>> {
    let token = base64url_encode(&clients.bound.conversation);
    let label = clients.alice_keys.label();
    clients.alice.send(&format!(
        "@label={label} EGROUP FETCH RECEIPTS {token} {first} *"
    ))?;
    let reply = labeled_reply(&mut clients.alice, &label)?;
    let mut records = Vec::new();
    for bytes in super::super::recovery_submission::page_objects(&reply)? {
        let mut budget = DecodeBudget::new(1 << 22, 1 << 16);
        let object = ArcWireObject::decode_kind(
            &bytes,
            Some(ArcWireObjectKind::SequencerRecord),
            &mut budget,
        )?;
        let record = ArcSequencerRecord::decode_exact(object.body(), &mut budget)?;
        records.push((declared_position(&record).route_sequence, bytes, record));
    }
    records.sort_by_key(|(sequence, _, _)| *sequence);
    Ok(records)
}

/// The shared historical chain resumed at `head`, the accepted state before
/// the old ReInit candidate, from the binding, both policies, both rosters
/// and the coordinator's generation-zero sequencer credential, which the
/// conversation was bound with.
fn resumed_chain(
    fixture: &Network,
    clients: &Clients,
    head: (u64, [u8; 32]),
    position: (u64, [u8; 32]),
) -> TestResult<HistoricalChain> {
    let network = *NETWORK_ID.as_bytes();
    let conversation = clients.bound.conversation;
    let mut principals = PrincipalRosters::new();
    for principal in [&clients.alice_keys, &clients.bob_keys] {
        let root = verify_root_identity(&network, &principal.keys.root, None)?;
        let roster = verify_roster(&root, &principal.keys.roster, None)?;
        principals.insert(principal.account, (root, roster));
    }
    let binding = verify_binding_package(&network, &clients.bound.package, &principals)?;
    let [bootstrap, operational] = &clients.bound.policies;
    let bootstrap = verify_policy(&network, &conversation, bootstrap, &principals, None)?;
    let policy = verify_policy(
        &network,
        &conversation,
        operational,
        &principals,
        Some(&bootstrap),
    )?;
    let credential = builders::sequencer_credential_in(
        network,
        &Ed25519SecretKey::from_bytes([fixture.coordinator.seed.wrapping_add(15); 32]),
        0,
        (0, 4_000_000_000),
        None,
    )?;
    let sequencer = verify_sequencer_credential(&network, &credential, None)?;
    let (sequence, predecessor_record_id) = position;
    let resumed = ResumedChain {
        binding,
        principals,
        required_operational_policy_id: policy.policy_id,
        policy,
        head: ChainHead {
            sequence: Some(sequence),
            record_id: head.1,
            object_id: None,
            predecessor_record_id,
            credential_id: sequencer.credential_id,
        },
        sequencer,
        bootstrap_pending: false,
        epoch: head.0,
        accepted_state_id: head.1,
        candidate: None,
        next_candidate_sequence: 0,
        lifecycle: Lifecycle::Active,
    };
    Ok(HistoricalChain::resume(
        &network,
        &conversation,
        resumed,
        ChainLimits::DEFAULT,
    )?)
}

/// Replays the daemon's ReInit records through the shared historical chain
/// (companion 13.8): the finalization commits the one target's digest, a
/// replaced target never binds, the bound target matches the attempt, and
/// the activation ends the old lineage.
fn verify_through_history(
    network: &Network,
    clients: &mut Clients,
    target: &Target,
    reinit: &real_clients::Certified,
    before: (u64, [u8; 32]),
    attempt: &ArcReInitAttempt,
) -> TestResult {
    let candidate = reinit.receipt.tbs.route_sequence;
    let first = candidate
        .checked_sub(1)
        .ok_or_else(|| failure("the ReInit candidate follows a finalization"))?;
    let records = conversation_records(clients, first)?;
    let record_at = |sequence: u64| {
        records
            .iter()
            .find(|(at, _, _)| *at == sequence)
            .ok_or_else(|| failure(format!("the daemon retains record {sequence}")))
    };
    let (_, _, previous) = record_at(first)?;
    let ArcSequencerRecord::Finalization(previous) = previous else {
        return Err(failure(
            "the record before the ReInit candidate is a finalization",
        ));
    };
    assert_eq!(previous.tbs.finalization_id, before.1);
    let mut chain = resumed_chain(
        network,
        clients,
        before,
        (first, previous.tbs.predecessor_record_id),
    )?;
    let mut budget = DecodeBudget::new(1 << 24, 1 << 18);
    let none = RecordReferences::default();
    chain.advance(&record_at(candidate)?.1, &none, &mut budget)?;
    let finalization = record_at(candidate.saturating_add(1))?;
    let step = chain.advance(&finalization.1, &none, &mut budget)?;
    assert!(matches!(
        step,
        ChainStep::Finalized { finalization_id, ref transitions, .. }
            if finalization_id == reinit.finalization_id
                && transitions.reinit_target_digest == Some(target.digest)
    ));

    // The authorization commits the one target; a target replaced after
    // finalization matches neither the digest nor the chain.
    let ArcSequencerRecord::Finalization(certificate) = &finalization.2 else {
        return Err(failure("the ReInit record is a finalization"));
    };
    let authorized = AuthorizedReinit::from_proof(&certificate.tbs.request.proof)?;
    assert_eq!(authorized.finalization_id(), &reinit.finalization_id);
    assert_eq!(authorized.prior_state_id(), &before.1);
    // The attempt carries that one target byte for byte.
    assert_eq!(attempt.target, target.tbs);
    authorized.check_target(&attempt.target)?;
    let mut replaced = target.tbs.clone();
    replaced.target_binding_id = [9; 32];
    assert!(authorized.check_target(&replaced).is_err());
    assert!(chain.bind_reinit_target(&replaced).is_err());
    chain.bind_reinit_target(&target.tbs)?;

    let attempt_object = wire_object(ArcWireObjectKind::ReinitAttempt, attempt)?;
    let step = chain.advance(
        &record_at(candidate.saturating_add(2))?.1,
        &RecordReferences {
            attempt_object: Some(&attempt_object),
            ..RecordReferences::default()
        },
        &mut budget,
    )?;
    assert!(matches!(step, ChainStep::ReinitAttempted(_)));
    // Once the attempt is open no target binds, not even this one: the
    // attempt was adopted before it, so the binding would vouch for nothing.
    assert!(chain.clone().bind_reinit_target(&target.tbs).is_err());
    let step = chain.advance(
        &record_at(candidate.saturating_add(3))?.1,
        &none,
        &mut budget,
    )?;
    assert!(matches!(
        step,
        ChainStep::ReinitActivated { new_conversation_id, .. }
            if new_conversation_id == target.conversation
    ));
    assert!(chain.is_terminal());
    Ok(())
}
