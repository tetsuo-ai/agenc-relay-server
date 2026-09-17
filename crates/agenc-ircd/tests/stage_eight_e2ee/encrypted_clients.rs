//! ENC-10 (issue #71): real openmls and mls-rs endpoints drive the repaired
//! encrypted recovery, rotation and ReInit paths through the daemon's client
//! surface. Every scenario asserts what plaintext each client can and cannot
//! derive, what the server refuses, and that a refusal changes nothing.
#![forbid(unsafe_code)]

use super::*;

use mls_rs::MlsMessage;
use mls_rs::client_builder::MlsConfig;
use mls_rs::group::ReceivedMessage;
use mls_rs::time::MlsTime;
use openmls::prelude::{LeafNodeParameters, MlsGroup};

#[path = "encrypted_clients/recovery.rs"]
mod recovery;
#[path = "encrypted_clients/reinit.rs"]
mod reinit;
#[path = "encrypted_clients/rotation.rs"]
mod rotation;

/// The interoperability matrix rules the three ENC-10 scenarios record.
pub(super) const RULES: [&str; 9] = [
    "lifecycle-lost-state-rejoins-as-a-new-leaf",
    "lifecycle-rejoined-leaf-reads-only-its-epoch",
    "lifecycle-declared-recovery-adopts-the-real-lineage",
    "lifecycle-sequencer-pin-moves-to-the-successor",
    "lifecycle-credentials-file-opens-above-generation-zero",
    "lifecycle-retired-leaf-reads-nothing-after-removal",
    "lifecycle-reinit-successor-activated-under-full-coverage",
    "lifecycle-reinit-refused-without-every-continuing-ack",
    "lifecycle-removed-leaf-leaves-the-expected-continuing-set",
];

/// The rules the recovery scenario records.
pub(super) const RECOVERY_RULES: [&str; 3] = [
    "lifecycle-lost-state-rejoins-as-a-new-leaf",
    "lifecycle-rejoined-leaf-reads-only-its-epoch",
    "lifecycle-declared-recovery-adopts-the-real-lineage",
];

/// The rules the rotation scenario records.
pub(super) const ROTATION_RULES: [&str; 3] = [
    "lifecycle-sequencer-pin-moves-to-the-successor",
    "lifecycle-credentials-file-opens-above-generation-zero",
    "lifecycle-retired-leaf-reads-nothing-after-removal",
];

/// The rules the ReInit scenario records.
pub(super) const REINIT_RULES: [&str; 3] = [
    "lifecycle-reinit-successor-activated-under-full-coverage",
    "lifecycle-reinit-refused-without-every-continuing-ack",
    "lifecycle-removed-leaf-leaves-the-expected-continuing-set",
];

/// The leaf signature key alice's MLS library holds in the first group.
pub(super) const ALICE_LEAF: [u8; 32] = [0xA1; 32];
/// The leaf signature key bob's MLS library holds before it loses state.
pub(super) const BOB_LEAF: [u8; 32] = [0xB1; 32];
/// The leaf signature key bob's replacement MLS state holds.
pub(super) const BOB_REJOIN_LEAF: [u8; 32] = [0xB2; 32];

/// The two encrypted clients and the channel they bound: alice on edge A
/// and bob on edge B, both authenticated, attached, joined to `#room`, and
/// named by the generation-zero binding package.
pub(super) struct Clients {
    pub(super) alice: IrcClient,
    pub(super) alice_keys: Principal,
    pub(super) alice_account: AccountId,
    pub(super) bob: IrcClient,
    pub(super) bob_keys: Principal,
    pub(super) bob_account: AccountId,
    pub(super) bound: BoundConversation,
    /// The wall-clock second the rosters and MLS leaves are valid around.
    pub(super) now: u64,
    /// The bootstrap and operational policy identifiers of the binding.
    pub(super) policies: ([u8; 32], [u8; 32]),
    /// The external genesis anchor the first candidate names.
    pub(super) genesis: [u8; 32],
}

impl Clients {
    /// The leaf lifetime alice's endpoint advertises: the MLS libraries check
    /// it against their own clock, so it opens just before `now`.
    pub(super) fn alice_interval(&self) -> (u64, u64) {
        (
            self.now.saturating_sub(3_599),
            self.now.saturating_add(real_clients::LEAF_LIFETIME),
        )
    }

    /// The leaf lifetime bob's endpoint advertises. mls-rs opens a leaf at
    /// exactly the timestamp it is given, with no margin of its own.
    pub(super) fn bob_interval(&self) -> (u64, u64) {
        let start = self.now.saturating_sub(60);
        (start, start.saturating_add(real_clients::LEAF_LIFETIME))
    }
}

/// Brings both edges up, registers and attaches alice and bob, joins them to
/// `#room` and binds the channel from alice.
pub(super) fn bind_channel(network: &Network) -> TestResult<Clients> {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    stage_ten_drills::wait_for_account_authority(&network.edge_a)?;
    stage_ten_drills::wait_for_account_authority(&network.edge_b)?;
    let now = real_clients::wall_clock_seconds()?;
    let (mut alice, alice_account) =
        authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
    let (mut bob, bob_account) = authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
    let mut alice_keys = Principal::new_valid_at(ALICE_ROOT, ALICE_DEVICE, alice_account, now)?;
    let mut bob_keys = Principal::new_valid_at(BOB_ROOT, BOB_DEVICE, bob_account, now)?;
    step(
        "alice attach",
        publish_and_attach(&mut alice, &mut alice_keys),
    )?;
    step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;
    join_room(&mut alice, &mut bob)?;
    let bound = step(
        "channel bind",
        reserve_and_bind(&mut alice, &mut alice_keys, &bob_keys),
    )?;
    let policies = (
        builders::policy_id_of(&bound.policies[0])?,
        builders::policy_id_of(&bound.policies[1])?,
    );
    let genesis = genesis_anchor(&bound)?;
    Ok(Clients {
        alice,
        alice_keys,
        alice_account,
        bob,
        bob_keys,
        bob_account,
        bound,
        now,
        policies,
        genesis,
    })
}

/// Joins both clients to the registered channel and waits until each sees
/// the other, so the encrypted carrier has both members.
fn join_room(alice: &mut IrcClient, bob: &mut IrcClient) -> TestResult {
    alice.send("JOIN #room")?;
    alice.read_until(|line| line.contains(" 366 alice #room "))?;
    alice.send("CHANCTL REGISTER #room")?;
    alice.read_until(|line| line.contains(" NOTE CHANCTL UPDATED #room "))?;
    bob.send("JOIN #room")?;
    bob.read_until(|line| line.contains(" 366 bob #room "))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #room"))?;
    Ok(())
}

/// The external genesis anchor of `bound`: the accepted state the first
/// candidate of the conversation names (companion 9.5).
pub(super) fn genesis_anchor(bound: &BoundConversation) -> TestResult<[u8; 32]> {
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

/// The old-leaf evidence of a real MLS endpoint: the signature key its
/// library holds, that leaf's index in the group, and the digest of the
/// basic credential the leaf carries, so every companion proof and ACK the
/// endpoint signs is bound to the leaf it actually operates.
pub(super) fn real_leaf(
    owner: &Principal,
    interval: (u64, u64),
    seed: [u8; 32],
    index: u32,
) -> TestResult<OldLeaf> {
    let secret = Ed25519SecretKey::from_bytes(seed);
    let credential =
        real_clients::credential_identity(owner, interval, &builders::public(&secret))?;
    OldLeaf::real(secret, index, &credential)
}

/// Starts the three daemons, runs `scenario`, and stops them. A failure is
/// reported with all three logs attached, as every other daemon suite does.
pub(super) fn run_network(
    scenario: impl FnOnce(
        &Network,
        &mut DaemonProcess,
        &mut DaemonProcess,
        &mut DaemonProcess,
    ) -> TestResult,
) -> TestResult {
    // The local admin socket is what `wait_for_account_authority` reads, and
    // the restore drills stop a daemon through it.
    let network = build_network_with(Some(CapacityPlan {
        max_connections: 32,
        connections_per_address: 32,
        memory_budget_bytes: STAGE_EIGHT_MEMORY_BUDGET_BYTES,
    }))?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = scenario(&network, &mut coordinator, &mut edge_a, &mut edge_b);
    let stopped_a = edge_a.stop();
    let stopped_b = edge_b.stop();
    let stopped_core = coordinator.stop();
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge a log ---\n{}\n--- edge b log ---\n{}",
            network.coordinator.log_text(),
            network.edge_a.log_text(),
            network.edge_b.log_text()
        )));
    }
    for (label, status) in [
        ("edge a", stopped_a),
        ("edge b", stopped_b),
        ("coordinator", stopped_core),
    ] {
        let status = status.map_err(|error| failure(format!("{label}: {error}")))?;
        if !status.success() {
            return Err(failure(format!("{label} exited with {status}")));
        }
    }
    Ok(())
}

/// The live encrypted conversation driven by real endpoints: alice's openmls
/// group and the accepted head every next Commit follows.
pub(super) struct Live {
    pub(super) clients: Clients,
    pub(super) creator: real_clients::OpenMlsMember,
    pub(super) group: MlsGroup,
    pub(super) alice_leaf: OldLeaf,
    /// The accepted epoch and state identifier the next Commit names.
    pub(super) head: (u64, [u8; 32]),
    /// The canonical validation time the next Commit's authenticated data
    /// names. The historical chain re-verifies every root and roster at it,
    /// so the whole lineage sits inside the fixture's roster window.
    pub(super) time: u64,
}

impl Live {
    /// Opens alice's real openmls group on the bound channel.
    pub(super) fn open(clients: Clients) -> TestResult<Self> {
        let interval = clients.alice_interval();
        let alice_leaf = real_leaf(&clients.alice_keys, interval, ALICE_LEAF, 0)?;
        let creator =
            real_clients::OpenMlsMember::with_leaf(&clients.alice_keys, interval, ALICE_LEAF)?;
        let group = creator.create_group(&clients.bound.group_id)?;
        let head = (0, clients.genesis);
        let time = clients.now;
        Ok(Self {
            clients,
            creator,
            group,
            alice_leaf,
            head,
            time,
        })
    }

    /// Places the Section 9.5 Commit authenticated data of the next
    /// transition on alice's group.
    pub(super) fn arm_commit(&mut self) -> TestResult {
        let aad = real_clients::commit_aad(&self.clients.bound, self.head.1, self.time)?;
        self.group.set_aad(aad);
        Ok(())
    }

    /// Certifies alice's pending Commit through the coordinator, merges it
    /// locally, and advances the accepted head.
    pub(super) fn certify(
        &mut self,
        commit: &[u8],
        transition: close_authority::CertificationTransition,
        policies: ([u8; 32], [u8; 32]),
    ) -> TestResult<real_clients::Certified> {
        let head = self.head;
        let leaf = &self.alice_leaf;
        let certified = {
            let Clients {
                alice,
                alice_keys,
                bob_keys,
                bound,
                ..
            } = &mut self.clients;
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
        self.clients
            .bob
            .read_until(|line| line.contains(" EGROUP FINALIZED "))?;
        self.group.merge_pending_commit(&self.creator.provider)?;
        self.head = (head.0.saturating_add(1), certified.finalization_id);
        self.time = self.time.saturating_add(1);
        assert_eq!(self.group.epoch().as_u64(), self.head.0);
        Ok(certified)
    }

    /// Encrypts `text` as Section 7.5 padded content and relays it to bob's
    /// edge, returning the exact MLS bytes that edge delivered.
    pub(super) fn relay(&mut self, text: &str, sequence: u64) -> TestResult<Vec<u8>> {
        let head = self.head.1;
        let aad = real_clients::application_aad(&self.clients.bound, head)?;
        let content = real_clients::padded_content(
            &self.clients.bound,
            &self.clients.alice_keys,
            sequence,
            head,
            text,
        )?;
        self.group.set_aad(aad);
        let encrypted = self
            .group
            .create_message(&self.creator.provider, &self.creator.signer, &content)?
            .to_bytes()?;
        let Clients {
            alice,
            alice_keys,
            bob,
            bound,
            ..
        } = &mut self.clients;
        real_clients::relay_application(alice, alice_keys, bob, bound, &encrypted)
    }
}

/// The plaintext an mls-rs member derives from one delivered application
/// message, or the error its library raised instead.
pub(super) fn mls_rs_text<C: MlsConfig>(
    group: &mut mls_rs::Group<C>,
    bytes: &[u8],
) -> TestResult<Option<String>> {
    let message = MlsMessage::from_bytes(bytes)?;
    match group.process_incoming_message(message) {
        Ok(ReceivedMessage::ApplicationMessage(description)) => {
            Ok(Some(real_clients::content_text(description.data())?))
        }
        Ok(_) => Err(failure("mls-rs received other than application content")),
        Err(_) => Ok(None),
    }
}

/// alice's first real Commit activates the bootstrap under the creator-only
/// policy and installs the required operational policy.
pub(super) fn activate_bootstrap(
    live: &mut Live,
    policies: ([u8; 32], [u8; 32]),
) -> TestResult<real_clients::Certified> {
    update_commit(
        live,
        close_authority::CertificationTransition::Bootstrap,
        policies,
    )
}

/// Certifies one real Update Commit of alice's group as `transition`.
pub(super) fn update_commit(
    live: &mut Live,
    transition: close_authority::CertificationTransition,
    policies: ([u8; 32], [u8; 32]),
) -> TestResult<real_clients::Certified> {
    live.arm_commit()?;
    let update = live.group.self_update(
        &live.creator.provider,
        &live.creator.signer,
        LeafNodeParameters::default(),
    )?;
    let commit = update.commit().to_bytes()?;
    live.certify(&commit, transition, policies)
}

/// bob publishes a real KeyPackage, alice claims and adds it, and bob's
/// mls-rs endpoint joins through the delivered Welcome and attests to the
/// leaf it received.
pub(super) fn add_bob(
    live: &mut Live,
    interval: (u64, u64),
) -> TestResult<(mls_rs::Group<impl MlsConfig + use<>>, OldLeaf)> {
    add_member(live, interval, BOB_LEAF, [77; 16])
}

/// bob publishes a real KeyPackage under the leaf key `seed`, alice claims
/// and adds it, and bob's mls-rs endpoint joins through the delivered
/// Welcome and attests to the leaf it received.
pub(super) fn add_member(
    live: &mut Live,
    interval: (u64, u64),
    seed: [u8; 32],
    nonce: [u8; 16],
) -> TestResult<(mls_rs::Group<impl MlsConfig + use<>>, OldLeaf)> {
    let joiner = real_clients::mls_rs_client_with_leaf(&live.clients.bob_keys, interval, seed)?;
    let package = joiner
        .generate_key_package_message(
            Default::default(),
            Default::default(),
            Some(MlsTime::from(interval.0)),
        )?
        .to_bytes()?;
    let mut group = join_through_welcome(live, &joiner, &package, interval.1, nonce)?;
    let index = group.current_member_index();
    let leaf = real_leaf(&live.clients.bob_keys, interval, seed, index)?;
    let epoch = live.head.0;
    let Clients {
        bob,
        bob_keys,
        bound,
        ..
    } = &mut live.clients;
    publish_membership(bob, bob_keys, bound, epoch, &leaf, None)?;
    let _ = &mut group;
    Ok((group, leaf))
}

/// Claims `package`, certifies the Add, delivers the Welcome through the
/// device mailbox, and returns the joined mls-rs group.
pub(super) fn join_through_welcome<C: MlsConfig>(
    live: &mut Live,
    joiner: &mls_rs::Client<C>,
    package: &[u8],
    expires_at: u64,
    nonce: [u8; 16],
) -> TestResult<mls_rs::Group<C>> {
    let reference = {
        let Clients {
            bob,
            bob_keys,
            alice,
            alice_keys,
            ..
        } = &mut live.clients;
        let reference = real_clients::publish_package(bob, bob_keys, package, expires_at)?;
        let claimed = real_clients::claim_package_with(alice, alice_keys, bob_keys, nonce)?;
        assert_eq!(claimed, package, "the claimed bytes are bob's own package");
        reference
    };
    let imported = live.creator.import_key_package(package)?;
    live.arm_commit()?;
    let (commit, welcome, _info) =
        live.group
            .add_members(&live.creator.provider, &live.creator.signer, &[imported])?;
    let policies = live.clients.policies;
    let added = live.certify(
        &commit.to_bytes()?,
        close_authority::CertificationTransition::Add,
        (policies.1, policies.1),
    )?;
    let welcome_bytes = welcome.to_bytes()?;
    let delivered = {
        let Clients {
            alice,
            alice_keys,
            bob,
            bob_keys,
            bound,
            ..
        } = &mut live.clients;
        real_clients::deliver_welcome(
            alice,
            alice_keys,
            bob,
            bob_keys,
            bound,
            &added,
            &reference,
            &welcome_bytes,
        )?
    };
    let (group, _info) = joiner.join_group(None, &MlsMessage::from_bytes(&delivered)?, None)?;
    assert_eq!(group.current_epoch(), live.head.0);
    Ok(group)
}
