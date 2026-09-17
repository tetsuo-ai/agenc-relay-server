//! The Stage 10 sequencer key rotation drill (S10-008) and the ordinary
//! smoke test that keeps its configuration honest outside the native
//! campaign.
//!
//! The drill walks the workflow ENC-07 fixed and the operator guide
//! documents. The active key keeps the generation it already holds while
//! the incoming key is configured as `sequencer_successor_private_key_file`
//! beside a two-credential document; a finalized `SEQUENCER` transition
//! moves a conversation's pin to the successor; and only then does the
//! predecessor move to `sequencer_retired_private_key_file`, where the one
//! route that never transitioned keeps it required until the overlap
//! deadline. Every step is checked by what a client observes: which
//! credential signed the receipt, which credential a new binding may pin,
//! and whether the daemon came up at all.
#![forbid(unsafe_code)]

use agenc_ircd_crypto::{Ed25519PublicKey, Ed25519Signature, verify_canonical};
use e2ee::objects::conversation::IrcSequencerCredential;

use super::super::recovery_submission::attach_when_active;
use super::*;

/// The successor sequencer key the rotation advertises.
const SUCCESSOR_KEY: [u8; 32] = [0x71; 32];
/// The validity interval every sequencer credential of the fixture carries.
const CREDENTIAL_INTERVAL: (u64, u64) = (0, 4_000_000_000);
/// The conversation that transitions: the fixture's `#room` binding.
const ROOM_CHANNEL: &str = "#room";
/// The channel bound before the rotation and deliberately left pinned to
/// the predecessor, so the retired signer is still required after the
/// retirement and the blocked-route report has something to name.
const HELD_CHANNEL: &str = "#held";
/// The MLS group identifier the held channel carries.
const HELD_GROUP: [u8; 32] = [0x7A; 32];
/// The channel bound after the retirement, to show which credential a new
/// binding may pin.
const ROTATED_CHANNEL: &str = "#rotated";
/// The MLS group identifier that channel carries.
const ROTATED_GROUP: [u8; 32] = [0x7C; 32];
/// The coordinator's generation-zero signer file, as the fixture writes it.
const ACTIVE_KEY_FILE: &str = "sequencer.key";
/// The file the incoming signer is installed under.
const SUCCESSOR_KEY_FILE: &str = "sequencer-successor.key";
/// The set generation the two-credential overlap document carries.
const OVERLAP_GENERATION: u64 = 1;
/// The set generation the successor-only retirement document carries.
const RETIREMENT_GENERATION: u64 = 2;
/// The login names the two encrypted drill clients authenticate under.
const ALICE_LOGIN: &str = "rotation-alice";
const BOB_LOGIN: &str = "rotation-bob";
/// The account request seeds of those two logins.
const ALICE_SEED: u8 = 190;
const BOB_SEED: u8 = 200;

// ---------------------------------------------------------------------------
// Advertised key sets
// ---------------------------------------------------------------------------

/// One advertised sequencer key set, as every node's files must hold it.
struct KeyPlan<'a> {
    /// The credentials document every node advertises.
    document: &'a [u8],
    /// The file name the document is written under.
    name: &'a str,
    /// The coordinator's active signer: its file name and seed.
    active: (&'a str, [u8; 32]),
    /// The coordinator's successor signer, when the set advertises one.
    successor: Option<(&'a str, [u8; 32])>,
    /// The coordinator's retired-retained signer, when the live state still
    /// requires one.
    retired: Option<(&'a str, [u8; 32])>,
}

/// The coordinator's generation-zero sequencer seed: its seed plus fifteen,
/// exactly as the fixture writes it.
fn generation_zero_seed(network: &Network) -> [u8; 32] {
    [network.coordinator.seed.wrapping_add(15); 32]
}

/// The coordinator's generation-zero sequencer key.
fn generation_zero_key(network: &Network) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes(generation_zero_seed(network))
}

/// The generation-zero credential a binding pins before the rotation.
fn generation_zero_credential(network: &Network) -> TestResult<IrcSequencerCredential> {
    Ok(builders::sequencer_credential_in(
        *NETWORK_ID.as_bytes(),
        &generation_zero_key(network),
        0,
        CREDENTIAL_INTERVAL,
        None,
    )?)
}

/// The successor credential the rotation chains from generation zero.
fn successor_credential(network: &Network) -> TestResult<IrcSequencerCredential> {
    let previous = generation_zero_key(network);
    let credential = generation_zero_credential(network)?;
    Ok(builders::sequencer_credential_in(
        *NETWORK_ID.as_bytes(),
        &Ed25519SecretKey::from_bytes(SUCCESSOR_KEY),
        1,
        CREDENTIAL_INTERVAL,
        Some((&previous, &credential)),
    )?)
}

/// The Section 2.2 identifier of one sequencer credential.
fn credential_id(credential: &IrcSequencerCredential) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::SequencerKey,
        &credential.tbs,
    )?)
}

/// The two-credential document of the overlap: the active credential first,
/// the successor second (operator guide, "Rotate the sequencer credential").
fn overlap_document(network: &Network) -> TestResult<Vec<u8>> {
    Ok(builders::sequencer_rotation_document(
        *NETWORK_ID.as_bytes(),
        &generation_zero_key(network),
        &Ed25519SecretKey::from_bytes(SUCCESSOR_KEY),
        CREDENTIAL_INTERVAL,
    )?)
}

/// The successor-only document that retires the predecessor.
fn retirement_document(network: &Network) -> TestResult<Vec<u8>> {
    Ok(builders::sequencer_retirement_document(
        *NETWORK_ID.as_bytes(),
        &generation_zero_key(network),
        &Ed25519SecretKey::from_bytes(SUCCESSOR_KEY),
        CREDENTIAL_INTERVAL,
        RETIREMENT_GENERATION,
    )?)
}

/// Rewrites one optional coordinator signer line. The operator template
/// leaves both optional signers commented out, so installing one replaces
/// that line and clearing one puts a comment back in its place.
fn set_optional_signer(
    keys: &Path,
    config: &mut String,
    field: &str,
    signer: Option<(&str, [u8; 32])>,
) -> TestResult {
    let line = config
        .lines()
        .find(|line| line.trim_start_matches("# ").starts_with(field))
        .map(str::to_owned)
        .ok_or_else(|| failure(format!("the coordinator config names {field}")))?;
    let replacement = match signer {
        Some((name, seed)) => {
            let path = keys.join(name);
            write_replace(&path, &seed)?;
            format!("{field} = \"{}\"", protected_path_text(&path)?)
        }
        None => format!("# {field} = \"unused\""),
    };
    replace_once(config, &line, &replacement)
}

/// Installs the coordinator's three signer lines for `plan`.
fn install_coordinator_signers(
    fixture: &NodeFixture,
    keys: &Path,
    config: &mut String,
    plan: &KeyPlan<'_>,
) -> TestResult {
    let active = keys.join(plan.active.0);
    write_replace(&active, &plan.active.1)?;
    let previous = current_key_file(fixture, "sequencer_private_key_file")?;
    replace_once(
        config,
        &format!(
            "sequencer_private_key_file = \"{}\"",
            protected_path_text(&previous)?
        ),
        &format!(
            "sequencer_private_key_file = \"{}\"",
            protected_path_text(&active)?
        ),
    )?;
    set_optional_signer(
        keys,
        config,
        "sequencer_successor_private_key_file",
        plan.successor,
    )?;
    set_optional_signer(
        keys,
        config,
        "sequencer_retired_private_key_file",
        plan.retired,
    )
}

/// Installs `plan` on every node: the advertised document everywhere, and
/// the coordinator's active, successor and retired signers.
fn install_keys(network: &Network, plan: &KeyPlan<'_>) -> TestResult {
    for (index, fixture) in [&network.coordinator, &network.edge_a, &network.edge_b]
        .into_iter()
        .enumerate()
    {
        let keys = fixture.data_dir.join("keys");
        let credentials = keys.join(plan.name);
        write_replace(&credentials, plan.document)?;
        let mut config = fs::read_to_string(&fixture.config_path)?;
        let previous = current_key_file(fixture, "sequencer_credentials_file")?;
        replace_once(
            &mut config,
            &format!(
                "sequencer_credentials_file = \"{}\"",
                protected_path_text(&previous)?
            ),
            &format!(
                "sequencer_credentials_file = \"{}\"",
                protected_path_text(&credentials)?
            ),
        )?;
        if index == 0 {
            install_coordinator_signers(fixture, &keys, &mut config, plan)?;
        }
        fs::write(&fixture.config_path, config)?;
    }
    Ok(())
}

/// The retirement key set: the successor is now the active signer and the
/// predecessor is retained at the retired path.
fn retirement_plan(document: &[u8], retired: Option<[u8; 32]>) -> KeyPlan<'_> {
    KeyPlan {
        document,
        name: "sequencer-credentials-g2.bin",
        active: (SUCCESSOR_KEY_FILE, SUCCESSOR_KEY),
        successor: None,
        retired: retired.map(|seed| (ACTIVE_KEY_FILE, seed)),
    }
}

/// The key set ENC-07 refuses, and the one this drill used to install: the
/// active key pointed at a generation the advertised set does not authorize
/// yet, with no successor configured at all.
fn refused_plan(document: &[u8]) -> KeyPlan<'_> {
    KeyPlan {
        document,
        name: "sequencer-credentials-g1.bin",
        active: (SUCCESSOR_KEY_FILE, SUCCESSOR_KEY),
        successor: None,
        retired: None,
    }
}

/// The overlap key set: the active key keeps the generation and the bytes
/// it already holds, the incoming key is the successor, and every node
/// advertises the two-credential document.
fn overlap_plan_for<'a>(network: &Network, document: &'a [u8]) -> KeyPlan<'a> {
    KeyPlan {
        document,
        name: "sequencer-credentials-g1.bin",
        active: (ACTIVE_KEY_FILE, generation_zero_seed(network)),
        successor: Some((SUCCESSOR_KEY_FILE, SUCCESSOR_KEY)),
        retired: None,
    }
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Requires that `receipt` names `expected` and that its sequencer
/// signature verifies under exactly that credential's public key: what a
/// client reads to see which key the conversation pins right now.
fn receipt_signed_by(
    receipt: &IrcCandidateReceipt,
    expected: &IrcSequencerCredential,
) -> TestResult {
    if receipt.tbs.sequencer_key_id != credential_id(expected)? {
        return Err(failure("the receipt names another sequencer credential"));
    }
    verify_canonical(
        Ed25519PublicKey::from_bytes(expected.tbs.sequencer_public_key)?,
        SignatureDomain::CandidateReceipt,
        &receipt.tbs.encode()?,
        Ed25519Signature::from_bytes(receipt.sequencer_signature),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The two encrypted clients
// ---------------------------------------------------------------------------

/// The drill's two encrypted clients with their published principals.
struct Clients {
    alice: IrcClient,
    bob: IrcClient,
    alice_keys: Principal,
    bob_keys: Principal,
    alice_account: AccountId,
    bob_account: AccountId,
}

impl Clients {
    /// Creates both accounts, publishes both identities, and attaches both
    /// devices.
    fn open(network: &Network) -> TestResult<Self> {
        let (mut alice, alice_account) =
            authenticated_client(&network.edge_a, "alice", ALICE_LOGIN, ALICE_SEED)?;
        let (mut bob, bob_account) =
            authenticated_client(&network.edge_b, "bob", BOB_LOGIN, BOB_SEED)?;
        let mut alice_keys =
            Principal::new_valid_at(ALICE_ROOT, ALICE_DEVICE, alice_account, VALIDATION_TIME)?;
        let mut bob_keys =
            Principal::new_valid_at(BOB_ROOT, BOB_DEVICE, bob_account, VALIDATION_TIME)?;
        publish_and_attach(&mut alice, &mut alice_keys)?;
        publish_and_attach(&mut bob, &mut bob_keys)?;
        Ok(Self {
            alice,
            bob,
            alice_keys,
            bob_keys,
            alice_account,
            bob_account,
        })
    }

    /// Logs both accounts back in after a restart and re-attaches the same
    /// retained device identities; a client session never survives one.
    fn resume(&mut self, network: &Network) -> TestResult {
        let (alice, _) =
            account_login_named(&network.edge_a, self.alice_account, "alice", ALICE_LOGIN)?;
        let (bob, _) = account_login_named(&network.edge_b, self.bob_account, "bob", BOB_LOGIN)?;
        self.alice = alice;
        self.bob = bob;
        attach_when_active(&mut self.alice, &mut self.alice_keys)?;
        attach_when_active(&mut self.bob, &mut self.bob_keys)
    }

    /// Re-joins `channel` from both clients after a restart. A client
    /// session never survives one, and a submission on a channel
    /// conversation needs its members present.
    fn rejoin(&mut self, channel: &str) -> TestResult {
        self.alice.send(&format!("JOIN {channel}"))?;
        self.alice
            .read_until(|line| line.contains(&format!(" 366 alice {channel} ")))?;
        self.bob.send(&format!("JOIN {channel}"))?;
        self.bob
            .read_until(|line| line.contains(&format!(" 366 bob {channel} ")))?;
        Ok(())
    }

    /// Joins `channel` from both clients and registers it from alice, the
    /// shape a channel binding requires.
    fn open_channel(&mut self, channel: &str) -> TestResult {
        self.alice.send(&format!("JOIN {channel}"))?;
        self.alice
            .read_until(|line| line.contains(&format!(" 366 alice {channel} ")))?;
        self.alice.send(&format!("CHANCTL REGISTER {channel}"))?;
        self.alice
            .read_until(|line| line.contains(&format!(" NOTE CHANCTL UPDATED {channel} ")))?;
        self.bob.send(&format!("JOIN {channel}"))?;
        self.bob
            .read_until(|line| line.contains(&format!(" 366 bob {channel} ")))?;
        self.alice.read_until(|line| {
            line.starts_with(":bob!") && line.contains(&format!(" JOIN {channel}"))
        })?;
        Ok(())
    }

    /// Reserves `channel` from alice.
    fn reserve(&mut self, channel: &str) -> TestResult<IrcReservation> {
        let label = self.alice_keys.label();
        self.alice
            .send(&format!("@label={label} EGROUP RESERVE CHANNEL {channel}"))?;
        let reply = labeled_reply(&mut self.alice, &label)?;
        assert_contains(&reply, " EGROUP RESERVED ")?;
        reservation_of(&reply)
    }
}

/// One channel binding this drill submits by hand, so the credential it
/// pins and the lock sequence it claims are both explicit.
struct ChannelPlan<'a> {
    channel: &'a str,
    group: [u8; 32],
    reservation: &'a IrcReservation,
    lock_sequence: u64,
    previous_locks: builders::LockIds,
    credential: [u8; 32],
}

/// The binding package of `plan`, signed by both principals.
fn channel_package(
    clients: &Clients,
    plan: &ChannelPlan<'_>,
) -> TestResult<IrcConversationBindingPackage> {
    let instance: [u8; 16] = plan
        .reservation
        .tbs
        .channel_instance_id
        .as_slice()
        .try_into()
        .map_err(|_| failure("the reservation names the channel instance"))?;
    let fingerprint = builders::root_fingerprint(&clients.alice_keys.keys.root)?;
    let peer_fingerprint = builders::root_fingerprint(&clients.bob_keys.keys.root)?;
    let principals = [&clients.alice_keys.keys, &clients.bob_keys.keys];
    let conversation = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &plan.group)?;
    let policies = policies_for(&principals, conversation, IrcConversationKind::Channel)?;
    Ok(builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route: builders::channel_route(plan.channel.as_bytes(), fingerprint)?,
        channel_instance_id: Some(instance),
        conversation_nonce: None,
        group_id: plan.group,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: plan.lock_sequence,
        previous_lock_ids: plan.previous_locks.clone(),
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
        sequencer_credential_id: plan.credential,
        plan_devices: vec![
            (
                &clients.alice_keys.account,
                fingerprint,
                clients.alice_keys.device,
            ),
            (
                &clients.bob_keys.account,
                peer_fingerprint,
                clients.bob_keys.device,
            ),
        ],
    })?)
}

/// Submits the binding of `plan` and returns the package with the reply
/// lines, so the caller decides whether a refusal or a bind is expected.
fn submit_binding(
    clients: &mut Clients,
    plan: &ChannelPlan<'_>,
) -> TestResult<(IrcConversationBindingPackage, Vec<String>)> {
    let package = channel_package(clients, plan)?;
    let conversation = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &plan.group)?;
    let binding = wire_object(IrcWireObjectKind::ConversationBinding, &package)?;
    let label = clients.alice_keys.label();
    send_object(
        &mut clients.alice,
        &label,
        &format!(
            "EGROUP BIND {} {} {}",
            base64url_encode(&plan.reservation.tbs.reservation_id),
            base64url_encode(&conversation),
            base64url_encode(&[44; 32])
        ),
        &binding,
    )?;
    let reply = labeled_reply(&mut clients.alice, &label)?;
    Ok((package, reply))
}

// ---------------------------------------------------------------------------
// Commits
// ---------------------------------------------------------------------------

/// The genesis state identifier of a freshly bound conversation.
fn genesis_state(bound: &BoundConversation) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::GroupGenesisId,
        &IrcGroupGenesisTbs {
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            group_id: Opaque::new(bound.group_id.to_vec())?,
            binding_id: bound.binding_id,
            context_core_id: CONTEXT_CORE_ID,
        },
    )?)
}

/// One Commit body for `bound` at `epoch` continuing `prior`.
fn commit_at(
    bound: &BoundConversation,
    epoch: u64,
    prior: [u8; 32],
    validation_time: u64,
) -> TestResult<Vec<u8>> {
    let aad = IrcCommitAad {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        validation_time,
        prior_state_id: prior,
    }
    .encode()?;
    Ok(builders::private_message_at_epoch(
        &bound.group_id,
        epoch,
        MLS_COMMIT,
        &aad,
    )?)
}

/// Certifies one Commit of `bound` from alice with bob as the co-voter.
fn certify(
    clients: &mut Clients,
    bound: &BoundConversation,
    prior: (u64, [u8; 32]),
    policies: ([u8; 32], [u8; 32]),
    transition: close_authority::CertificationTransition,
) -> TestResult<real_clients::Certified> {
    let validation_time = VALIDATION_TIME.saturating_add(prior.0);
    let commit = commit_at(bound, prior.0, prior.1, validation_time)?;
    let Clients {
        alice,
        alice_keys,
        bob_keys,
        ..
    } = clients;
    real_clients::certify_commit(
        alice,
        alice_keys,
        &[&*bob_keys],
        bound,
        &commit,
        prior,
        policies,
        transition,
    )
}

// ---------------------------------------------------------------------------
// The drill
// ---------------------------------------------------------------------------

/// What the pre-rotation phase leaves behind for the rest of the drill.
struct Seeded {
    /// The conversation that transitions to the successor.
    room: BoundConversation,
    /// The locks of the held binding, which the post-retirement binding
    /// continues.
    held_locks: builders::LockIds,
    /// The accepted head of the transitioning conversation.
    head: (u64, [u8; 32]),
    /// The bootstrap and operational policy identifiers of that
    /// conversation.
    policies: ([u8; 32], [u8; 32]),
}

/// Binds and activates `#room`, then binds `#held` and leaves it pinned to
/// the generation-zero credential.
fn seed_conversations(
    drill: &mut Drill,
    network: &Network,
    clients: &mut Clients,
) -> TestResult<Seeded> {
    let zero = generation_zero_credential(network)?;
    clients.open_channel(ROOM_CHANNEL)?;
    let room = {
        let Clients {
            alice,
            alice_keys,
            bob_keys,
            ..
        } = clients;
        reserve_and_bind(alice, alice_keys, bob_keys)?
    };
    let policies = (
        builders::policy_id_of(&room.policies[0])?,
        builders::policy_id_of(&room.policies[1])?,
    );
    let genesis = genesis_state(&room)?;
    let activated = certify(
        clients,
        &room,
        (0, genesis),
        policies,
        close_authority::CertificationTransition::Bootstrap,
    )?;
    receipt_signed_by(&activated.receipt, &zero)?;
    clients.open_channel(HELD_CHANNEL)?;
    let reservation = clients.reserve(HELD_CHANNEL)?;
    let (held, reply) = submit_binding(
        clients,
        &ChannelPlan {
            channel: HELD_CHANNEL,
            group: HELD_GROUP,
            reservation: &reservation,
            lock_sequence: 1,
            previous_locks: builders::lock_ids(&room.package)?,
            credential: credential_id(&zero)?,
        },
    )?;
    assert_contains(&reply, " EGROUP BOUND ")?;
    drill.fact("activation_receipt_credential", "generation_zero");
    drill.step(
        "bind",
        format!(
            "{ROOM_CHANNEL} activated and {HELD_CHANNEL} bound under the generation-zero credential"
        ),
    );
    Ok(Seeded {
        room,
        held_locks: builders::lock_ids(&held)?,
        head: (1, activated.finalization_id),
        policies,
    })
}

/// Installs the overlap key set, restarts every node on it, finalizes the
/// `SEQUENCER` transition, and shows the pin moved: the transition itself
/// is receipted under the predecessor and the next record under the
/// successor.
fn rotate(
    drill: &mut Drill,
    network: &Network,
    nodes: &mut DrillNodes,
    clients: &mut Clients,
    seeded: &mut Seeded,
) -> TestResult {
    let zero = generation_zero_credential(network)?;
    let successor = successor_credential(network)?;
    let document = overlap_document(network)?;
    let before = e2ee_acknowledgements(&network.edge_a);
    restart_on(
        network,
        nodes,
        clients,
        &overlap_plan_for(network, &document),
    )?;
    drill.fact("overlap_set_generation", OVERLAP_GENERATION);
    drill.step(
        "overlap",
        "the active key kept its generation and the incoming key installed as the successor",
    );
    let operational = (seeded.policies.1, seeded.policies.1);
    let moved = certify(
        clients,
        &seeded.room,
        seeded.head,
        operational,
        close_authority::CertificationTransition::Sequencer,
    )?;
    receipt_signed_by(&moved.receipt, &zero)?;
    seeded.head = (2, moved.finalization_id);
    let after = certify(
        clients,
        &seeded.room,
        seeded.head,
        operational,
        close_authority::CertificationTransition::Add,
    )?;
    receipt_signed_by(&after.receipt, &successor)?;
    seeded.head = (3, after.finalization_id);
    drill.fact("transition_receipt_credential", "generation_zero");
    drill.fact("post_transition_receipt_credential", "successor");
    drill.fact(
        "profile_reacknowledged",
        e2ee_acknowledgements(&network.edge_a) > before,
    );
    drill.step(
        "transition",
        "the finalized SEQUENCER transition signed under the predecessor and moved the pin",
    );
    Ok(())
}

/// Installs the retirement key set with the predecessor retained at the
/// retired path, restarts every node, and shows what a new binding may pin.
fn retire(
    drill: &mut Drill,
    network: &Network,
    nodes: &mut DrillNodes,
    clients: &mut Clients,
    seeded: &Seeded,
) -> TestResult<bool> {
    let zero = generation_zero_credential(network)?;
    let successor = successor_credential(network)?;
    let document = retirement_document(network)?;
    let retired = Some(generation_zero_seed(network));
    restart_on(
        network,
        nodes,
        clients,
        &retirement_plan(&document, retired),
    )?;
    let log = network.coordinator.log_text();
    let blocked = log.contains("event=e2ee_routes_blocked");
    let missing = log.contains("event=e2ee_retired_signer_missing");
    drill.fact("blocked_route_reported", blocked);
    drill.fact("retired_signer_missing", missing);
    drill.step(
        "retire",
        format!(
            "predecessor retained at sequencer_retired_private_key_file: blocked route reported={blocked}, signer missing={missing}"
        ),
    );
    clients.open_channel(ROTATED_CHANNEL)?;
    let reservation = clients.reserve(ROTATED_CHANNEL)?;
    let mut plan = ChannelPlan {
        channel: ROTATED_CHANNEL,
        group: ROTATED_GROUP,
        reservation: &reservation,
        lock_sequence: 2,
        previous_locks: seeded.held_locks.clone(),
        credential: credential_id(&zero)?,
    };
    let (_, refused) = submit_binding(clients, &plan)?;
    assert_contains(&refused, "FAIL EGROUP E2EE_BINDING_AUTH_INVALID")?;
    let bound = refused.iter().any(|line| line.contains(" EGROUP BOUND "));
    // The refusal changed nothing: the same reservation still binds once the
    // package pins the credential the advertised set now issues.
    plan.credential = credential_id(&successor)?;
    let (_, accepted) = submit_binding(clients, &plan)?;
    assert_contains(&accepted, " EGROUP BOUND ")?;
    drill.fact("retired_pin_refused", !bound);
    drill.fact("successor_pin_bound", true);
    drill.fact("transitioned_head_epoch", seeded.head.0);
    drill.step(
        "pin",
        "a binding pinning the retired credential refused; the same reservation bound under the successor",
    );
    Ok(blocked && !missing && !bound)
}

/// Stops every node, installs `plan`, starts everything again, and brings
/// both clients back: a changed credentials file is restart-only.
fn restart_on(
    network: &Network,
    nodes: &mut DrillNodes,
    clients: &mut Clients,
    plan: &KeyPlan<'_>,
) -> TestResult {
    clients.alice.send("QUIT :rotation")?;
    clients.bob.send("QUIT :rotation")?;
    thread::sleep(Duration::from_millis(500));
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    install_keys(network, plan)?;
    nodes.restart_all(network)?;
    // The coordinator stages its signer reconciliation as the first startup
    // batch and the federation loader resumes on it, so the link settles a
    // moment after it is first established.
    thread::sleep(STARTUP_SETTLE);
    clients.resume(network)?;
    clients.rejoin(ROOM_CHANNEL)?;
    clients.rejoin(HELD_CHANNEL)
}

pub(super) fn run(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let mut clients = Clients::open(&network)?;
    let mut seeded = seed_conversations(drill, &network, &mut clients)?;
    rotate(drill, &network, &mut nodes, &mut clients, &mut seeded)?;
    let retired = retire(drill, &network, &mut nodes, &mut clients, &seeded)?;
    clients.alice.send("QUIT :drill complete")?;
    clients.bob.send("QUIT :drill complete")?;
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(retired && clean.iter().all(|c| *c))
}

// ---------------------------------------------------------------------------
// The ordinary signal
// ---------------------------------------------------------------------------

/// The three daemons of the smoke test.
struct SmokeNodes {
    coordinator: DaemonProcess,
    edge_a: DaemonProcess,
    edge_b: DaemonProcess,
}

impl SmokeNodes {
    /// Starts every node and waits for both edges to reach their
    /// coordinator, counting from the link totals `before`.
    fn start(network: &Network, before: (usize, usize)) -> TestResult<Self> {
        let nodes = Self {
            coordinator: DaemonProcess::start(&network.coordinator.config_path)?,
            edge_a: DaemonProcess::start(&network.edge_a.config_path)?,
            edge_b: DaemonProcess::start(&network.edge_b.config_path)?,
        };
        wait_for_link(&network.edge_a, before.0)?;
        wait_for_link(&network.edge_b, before.1)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)?;
        Ok(nodes)
    }

    fn links(network: &Network) -> (usize, usize) {
        (
            links_established(&network.edge_a),
            links_established(&network.edge_b),
        )
    }

    fn stop(&mut self) -> TestResult {
        for daemon in [&mut self.edge_a, &mut self.edge_b, &mut self.coordinator] {
            let status = daemon.stop()?;
            if !status.success() {
                return Err(failure(format!("a drill node exited with {status}")));
            }
        }
        Ok(())
    }
}

/// The ordinary suite's signal for the drill: every key set the drill
/// installs is one the daemon accepts, and the set ENC-07 refuses still
/// refuses. The drill itself is `#[ignore]`d for the qualification driver,
/// so without this test a normative change to the accepted key-set shapes
/// is invisible until the native campaign runs.
#[test]
fn sequencer_rotation_key_sets_are_the_ones_the_daemon_accepts() -> TestResult {
    let network = drill_network()?;
    let mut nodes = SmokeNodes::start(&network, (0, 0))?;
    let mut clients = Clients::open(&network)?;
    clients.open_channel(ROOM_CHANNEL)?;
    // One route pinned to the generation-zero credential, which never
    // transitions: it is what keeps the retired signer required later.
    {
        let Clients {
            alice,
            alice_keys,
            bob_keys,
            ..
        } = &mut clients;
        reserve_and_bind(alice, alice_keys, bob_keys)?;
    }
    let overlap = overlap_document(&network)?;
    let retirement = retirement_document(&network)?;
    let retired = generation_zero_seed(&network);
    let mut before = SmokeNodes::links(&network);
    nodes.stop()?;
    // The shape ENC-07 refuses: the active key pointed at the incoming
    // generation with no successor configured.
    install_keys(&network, &refused_plan(&overlap))?;
    let mut refused = DaemonProcess::start(&network.coordinator.config_path)?;
    let status = refused.wait()?;
    assert!(
        !status.success(),
        "the daemon refuses an active key the advertised set does not authorize yet: {status}"
    );
    // The shape the operator guide documents, and the one the drill builds.
    install_keys(&network, &overlap_plan_for(&network, &overlap))?;
    nodes = SmokeNodes::start(&network, before)?;
    before = SmokeNodes::links(&network);
    nodes.stop()?;
    // The retirement shape with the predecessor retained: the route bound
    // above still pins it, so the retired signer is required, not released.
    install_keys(&network, &retirement_plan(&retirement, Some(retired)))?;
    nodes = SmokeNodes::start(&network, before)?;
    let log = network.coordinator.log_text();
    assert!(
        log.contains("event=e2ee_routes_blocked"),
        "the retirement blocks the route that still pins the predecessor"
    );
    assert!(
        !log.contains("event=e2ee_retired_signer_missing"),
        "the retained predecessor key is installed, not reported missing"
    );
    nodes.stop()
}
