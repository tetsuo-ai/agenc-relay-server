//! ENC-10 scenario B (companion 9.2.1, 13.5 and 13.7.3): the coordinator's
//! sequencer key rotates and then retires across three advertised
//! generations while a real openmls and mls-rs conversation keeps running.
//! After the retirement the coordinator opens a credentials file above
//! generation zero, a bind that still pins the retired credential is
//! refused, and a member retired from the group receives the ciphertext but
//! derives no plaintext past its retirement.
#![forbid(unsafe_code)]

use super::*;

use agenc_relay_crypto::{Ed25519PublicKey, Ed25519Signature, verify_canonical};
use e2ee::objects::conversation::ArcSequencerCredential;
use openmls::prelude::LeafNodeIndex;

use super::super::recovery_submission::attach_when_active;
use super::super::stage_ten_capacity::current_key_file;
use super::super::stage_ten_drills::{account_login_named, wait_for_account_authority};

/// The successor sequencer key the rotation advertises.
const SUCCESSOR_KEY: [u8; 32] = [0x51; 32];
/// The validity interval every sequencer credential of the fixture carries.
const CREDENTIAL_INTERVAL: (u64, u64) = (0, 4_000_000_000);
/// The plaintext alice sends while bob still holds a leaf.
const BEFORE_TEXT: &str = "minutes while bob holds a leaf";
/// The plaintext alice sends after bob's leaf is retired.
const RETIRED_TEXT: &str = "minutes after bob's leaf is retired";
/// The plaintext alice sends once bob has rejoined past the retirement.
const AFTER_TEXT: &str = "minutes bob hears again after the key retirement";
/// The channel bound after the retirement, to show which credential a new
/// binding may pin.
const SECOND_CHANNEL: &str = "#rotated";
/// The MLS group identifier that second channel carries.
const SECOND_GROUP: [u8; 32] = [0x5C; 32];

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
}

/// The coordinator's generation-zero sequencer key: its seed plus fifteen,
/// exactly as the fixture writes it.
fn generation_zero_key(network: &Network) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes([network.coordinator.seed.wrapping_add(15); 32])
}

/// The generation-zero credential the binding pins at bind time.
fn generation_zero_credential(network: &Network) -> TestResult<ArcSequencerCredential> {
    Ok(builders::sequencer_credential_in(
        *NETWORK_ID.as_bytes(),
        &generation_zero_key(network),
        0,
        CREDENTIAL_INTERVAL,
        None,
    )?)
}

/// The successor credential the rotation chains from generation zero.
fn successor_credential(network: &Network) -> TestResult<ArcSequencerCredential> {
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
fn credential_id(credential: &ArcSequencerCredential) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::SequencerKey,
        &credential.tbs,
    )?)
}

/// Requires that `receipt` names `expected` and that its sequencer signature
/// verifies under exactly that credential's public key: what a client reads
/// to see which key the conversation pins right now.
fn receipt_signed_by(
    receipt: &ArcCandidateReceipt,
    expected: &ArcSequencerCredential,
) -> TestResult {
    assert_eq!(receipt.tbs.sequencer_key_id, credential_id(expected)?);
    verify_canonical(
        Ed25519PublicKey::from_bytes(expected.tbs.sequencer_public_key)?,
        SignatureDomain::CandidateReceipt,
        &receipt.tbs.encode()?,
        Ed25519Signature::from_bytes(receipt.sequencer_signature),
    )?;
    Ok(())
}

/// Rewrites the coordinator's successor signer line: the operator template
/// leaves it commented out, so installing one replaces that comment and
/// retiring one puts a comment back in its place.
fn set_successor(
    keys: &Path,
    config: &mut String,
    successor: Option<(&str, [u8; 32])>,
) -> TestResult {
    let line = config
        .lines()
        .find(|line| {
            line.trim_start_matches("# ")
                .starts_with("sequencer_successor_private_key_file")
        })
        .map(str::to_owned)
        .ok_or_else(|| failure("the coordinator config names the successor signer"))?;
    let replacement = match successor {
        Some((name, seed)) => {
            let path = keys.join(name);
            write_private(&path, &seed)?;
            format!(
                "sequencer_successor_private_key_file = \"{}\"",
                protected_path_text(&path)?
            )
        }
        None => "# sequencer_successor_private_key_file = \"retired\"".to_owned(),
    };
    replace_once(config, &line, &replacement)
}

/// Installs `plan` on every node: the advertised document everywhere, and
/// the coordinator's active and successor signers.
fn install_keys(network: &Network, plan: &KeyPlan<'_>) -> TestResult {
    for (index, fixture) in [&network.coordinator, &network.edge_a, &network.edge_b]
        .into_iter()
        .enumerate()
    {
        let keys = fixture.data_dir.join("keys");
        let credentials = keys.join(plan.name);
        write_private(&credentials, plan.document)?;
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
            let active = keys.join(plan.active.0);
            if !active.exists() {
                write_private(&active, &plan.active.1)?;
            }
            let previous = current_key_file(fixture, "sequencer_private_key_file")?;
            replace_once(
                &mut config,
                &format!(
                    "sequencer_private_key_file = \"{}\"",
                    protected_path_text(&previous)?
                ),
                &format!(
                    "sequencer_private_key_file = \"{}\"",
                    protected_path_text(&active)?
                ),
            )?;
            set_successor(&keys, &mut config, plan.successor)?;
        }
        fs::write(&fixture.config_path, config)?;
    }
    Ok(())
}

/// Stops every daemon, installs `plan`, and starts them again with both
/// clients logged in, attached and back in the channel. Client sessions do
/// not survive an edge restart, so each returns as a new connection of the
/// same account with the same retained device identity.
fn restart_with(
    network: &Network,
    daemons: (&mut DaemonProcess, &mut DaemonProcess, &mut DaemonProcess),
    live: &mut Live,
    plan: &KeyPlan<'_>,
) -> TestResult {
    let (coordinator, edge_a, edge_b) = daemons;
    live.clients.alice.send("QUIT :rotation")?;
    live.clients.bob.send("QUIT :rotation")?;
    // The edges retire both sessions before they are stopped.
    thread::sleep(Duration::from_millis(500));
    for (label, daemon) in [
        ("edge a", &mut *edge_a),
        ("edge b", &mut *edge_b),
        ("coordinator", &mut *coordinator),
    ] {
        let status = daemon.stop()?;
        assert!(
            status.success(),
            "{label} stopped for the rotation: {status}"
        );
    }
    install_keys(network, plan)?;
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    *edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    *edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    for fixture in [&network.edge_a, &network.edge_b] {
        wait_for_link(fixture, 0)?;
        wait_for_account_authority(fixture)?;
    }
    let (alice, _) = account_login_named(
        &network.edge_a,
        live.clients.alice_account,
        "alice",
        "alice-account",
    )?;
    let (bob, _) = account_login_named(
        &network.edge_b,
        live.clients.bob_account,
        "bob",
        "bob-account",
    )?;
    live.clients.alice = alice;
    live.clients.bob = bob;
    attach_when_active(&mut live.clients.alice, &mut live.clients.alice_keys)?;
    attach_when_active(&mut live.clients.bob, &mut live.clients.bob_keys)?;
    live.clients.alice.send("JOIN #room")?;
    live.clients
        .alice
        .read_until(|line| line.contains(" 366 alice #room "))?;
    live.clients.bob.send("JOIN #room")?;
    live.clients
        .bob
        .read_until(|line| line.contains(" 366 bob #room "))?;
    Ok(())
}

#[test]
fn sequencer_rotation_and_leaf_retirement_hold_the_encrypted_channel() -> TestResult {
    run_network(rotate_with_real_clients)
}

fn rotate_with_real_clients(
    network: &Network,
    coordinator: &mut DaemonProcess,
    edge_a: &mut DaemonProcess,
    edge_b: &mut DaemonProcess,
) -> TestResult {
    let clients = bind_channel(network)?;
    let bob_interval = clients.bob_interval();
    let mut live = Live::open(clients)?;
    let policies = live.clients.policies;
    let operational = (policies.1, policies.1);
    let generation_zero = generation_zero_credential(network)?;
    let successor = successor_credential(network)?;

    let activated = step(
        "bootstrap activation",
        activate_bootstrap(&mut live, policies),
    )?;
    receipt_signed_by(&activated.receipt, &generation_zero)?;
    let (mut bob_group, bob_leaf) = step(
        "add bob",
        add_member(&mut live, bob_interval, BOB_LEAF, [77; 16]),
    )?;
    let before = step("relay before rotation", live.relay(BEFORE_TEXT, 0))?;
    assert_eq!(
        mls_rs_text(&mut bob_group, &before)?.as_deref(),
        Some(BEFORE_TEXT)
    );

    step(
        "rotate to generation one",
        restart_with(
            network,
            (coordinator, edge_a, edge_b),
            &mut live,
            &KeyPlan {
                document: &builders::sequencer_rotation_document(
                    *NETWORK_ID.as_bytes(),
                    &generation_zero_key(network),
                    &Ed25519SecretKey::from_bytes(SUCCESSOR_KEY),
                    CREDENTIAL_INTERVAL,
                )?,
                name: "sequencer-credentials-g1.bin",
                active: ("sequencer.key", [0; 32]),
                successor: Some(("sequencer-successor.key", SUCCESSOR_KEY)),
            },
        ),
    )?;

    // The transition is itself signed under the old credential and moves the
    // pin; every later record signs under the successor.
    let moved = step(
        "sequencer transition",
        update_commit(
            &mut live,
            close_authority::CertificationTransition::Sequencer,
            operational,
        ),
    )?;
    receipt_signed_by(&moved.receipt, &generation_zero)?;

    let retired = step(
        "retire bob's leaf",
        retire_leaf(&mut live, &bob_leaf, operational),
    )?;
    receipt_signed_by(&retired.receipt, &successor)?;

    // The edge still forwards the ciphertext to the retired member; what it
    // cannot do is derive the plaintext of an epoch it was removed from.
    let after_retirement = step("relay after retirement", live.relay(RETIRED_TEXT, 1))?;
    assert_eq!(
        mls_rs_text(&mut bob_group, &after_retirement)?,
        None,
        "the retired leaf derives no plaintext past its retirement"
    );

    step(
        "retire generation zero",
        restart_with(
            network,
            (coordinator, edge_a, edge_b),
            &mut live,
            &KeyPlan {
                document: &builders::sequencer_retirement_document(
                    *NETWORK_ID.as_bytes(),
                    &generation_zero_key(network),
                    &Ed25519SecretKey::from_bytes(SUCCESSOR_KEY),
                    CREDENTIAL_INTERVAL,
                    2,
                )?,
                name: "sequencer-credentials-g2.bin",
                active: ("sequencer-successor.key", SUCCESSOR_KEY),
                successor: None,
            },
        ),
    )?;

    step(
        "bind under the retired credential",
        refuse_retired_pin(&mut live, &generation_zero, &successor),
    )?;
    step(
        "rejoin past the retirement",
        rejoin_past_retirement(&mut live, bob_interval, &successor, operational),
    )?;
    require_recorded(&ROTATION_RULES)
}

/// Removes bob's leaf with a real Commit and records the removal proof for
/// that leaf's last epoch, then shows the retired leaf cannot be re-attested
/// as continuing at the same epoch while its removal stands unchanged.
fn retire_leaf(
    live: &mut Live,
    leaf: &OldLeaf,
    policies: ([u8; 32], [u8; 32]),
) -> TestResult<real_clients::Certified> {
    live.arm_commit()?;
    let (commit, _welcome, _info) = live.group.remove_members(
        &live.creator.provider,
        &live.creator.signer,
        &[LeafNodeIndex::new(leaf.index)],
    )?;
    let certified = live.certify(
        &commit.to_bytes()?,
        close_authority::CertificationTransition::Remove,
        policies,
    )?;
    let epoch = live.head.0;
    let removal = Some(certified.finalization_id);
    let Clients {
        bob,
        bob_keys,
        bound,
        ..
    } = &mut live.clients;
    let stored = publish_membership(bob, bob_keys, bound, epoch, leaf, removal)?;
    // A continuing proof of the same leaf at the same epoch conflicts, and
    // the byte-identical removal still repeats the stored identifier, so the
    // refusal left the retained proof exactly as it was.
    let proof = leaf_membership(bob_keys, bound.conversation, epoch, leaf, None)?;
    let object = wire_object(ArcWireObjectKind::LeafMembershipProof, &proof)?;
    let label = bob_keys.label();
    send_object(
        bob,
        &label,
        &format!(
            "EGROUP SUBMIT MEMBERSHIP {}",
            base64url_encode(&bound.conversation)
        ),
        &object,
    )?;
    assert_contains(
        &labeled_reply(bob, &label)?,
        "FAIL EGROUP E2EE_OPERATION_CONFLICT",
    )?;
    assert_eq!(
        publish_membership(bob, bob_keys, bound, epoch, leaf, removal)?,
        stored
    );
    Ok(certified)
}

/// A second channel bound while it still pins the retired generation-zero
/// credential is refused, and the same reservation binds under the successor
/// the advertised set now issues.
fn refuse_retired_pin(
    live: &mut Live,
    retired: &ArcSequencerCredential,
    successor: &ArcSequencerCredential,
) -> TestResult {
    open_second_channel(live)?;
    let reservation = reserve_second_channel(live)?;
    let refused = bind_second_channel(live, &reservation, credential_id(retired)?)?;
    assert_contains(&refused, "FAIL EGROUP E2EE_BINDING_AUTH_INVALID")?;
    assert!(!refused.iter().any(|line| line.contains(" EGROUP BOUND ")));
    // The refusal changed nothing: the same reservation still binds once the
    // package pins the credential the advertised set now issues.
    let accepted = bind_second_channel(live, &reservation, credential_id(successor)?)?;
    assert_contains(&accepted, " EGROUP BOUND ")?;
    Ok(())
}

/// Joins and registers the second channel from both clients.
fn open_second_channel(live: &mut Live) -> TestResult {
    let Clients { alice, bob, .. } = &mut live.clients;
    alice.send(&format!("JOIN {SECOND_CHANNEL}"))?;
    alice.read_until(|line| line.contains(&format!(" 366 alice {SECOND_CHANNEL} ")))?;
    alice.send(&format!("CHANCTL REGISTER {SECOND_CHANNEL}"))?;
    alice.read_until(|line| line.contains(&format!(" NOTE CHANCTL UPDATED {SECOND_CHANNEL} ")))?;
    bob.send(&format!("JOIN {SECOND_CHANNEL}"))?;
    bob.read_until(|line| line.contains(&format!(" 366 bob {SECOND_CHANNEL} ")))?;
    alice.read_until(|line| {
        line.starts_with(":bob!") && line.contains(&format!(" JOIN {SECOND_CHANNEL}"))
    })?;
    Ok(())
}

/// Reserves the second channel from alice.
fn reserve_second_channel(live: &mut Live) -> TestResult<ArcReservation> {
    let Clients {
        alice, alice_keys, ..
    } = &mut live.clients;
    let label = alice_keys.label();
    alice.send(&format!(
        "@label={label} EGROUP RESERVE CHANNEL {SECOND_CHANNEL}"
    ))?;
    let reply = labeled_reply(alice, &label)?;
    assert_contains(&reply, " EGROUP RESERVED ")?;
    reservation_of(&reply)
}

/// Binds the reserved second channel with a package that pins `credential`,
/// returning the reply lines.
fn bind_second_channel(
    live: &mut Live,
    reservation: &ArcReservation,
    credential: [u8; 32],
) -> TestResult<Vec<String>> {
    let previous = builders::lock_ids(&live.clients.bound.package)?;
    let Clients {
        alice,
        alice_keys,
        bob_keys,
        ..
    } = &mut live.clients;
    let instance: [u8; 16] = reservation
        .tbs
        .channel_instance_id
        .as_slice()
        .try_into()
        .map_err(|_| failure("the reservation names the channel instance"))?;
    let fingerprint = builders::root_fingerprint(&alice_keys.keys.root)?;
    let principals = [&alice_keys.keys, &bob_keys.keys];
    let conversation = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &SECOND_GROUP)?;
    let policies = policies_for(&principals, conversation, ArcConversationKind::Channel)?;
    let package = builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route: builders::channel_route(SECOND_CHANNEL.as_bytes(), fingerprint)?,
        channel_instance_id: Some(instance),
        conversation_nonce: None,
        group_id: SECOND_GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 1,
        previous_lock_ids: previous,
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
        sequencer_credential_id: credential,
        plan_devices: vec![
            (&alice_keys.account, fingerprint, alice_keys.device),
            (
                &bob_keys.account,
                builders::root_fingerprint(&bob_keys.keys.root)?,
                bob_keys.device,
            ),
        ],
    })?;
    let binding = wire_object(ArcWireObjectKind::ConversationBinding, &package)?;
    let label = alice_keys.label();
    send_object(
        alice,
        &label,
        &format!(
            "EGROUP BIND {} {} {}",
            base64url_encode(&reservation.tbs.reservation_id),
            base64url_encode(&conversation),
            base64url_encode(&[44; 32])
        ),
        &binding,
    )?;
    labeled_reply(alice, &label)
}

/// bob rejoins the channel group with a fresh leaf after the retirement and
/// reads the minutes of the epoch he joined, while the record that carries
/// him still signs under the successor credential.
fn rejoin_past_retirement(
    live: &mut Live,
    interval: (u64, u64),
    successor: &ArcSequencerCredential,
    policies: ([u8; 32], [u8; 32]),
) -> TestResult {
    let (mut group, leaf) = add_member(live, interval, BOB_REJOIN_LEAF, [79; 16])?;
    let epoch = live.head.0;
    {
        let Clients {
            bob,
            bob_keys,
            bound,
            ..
        } = &mut live.clients;
        publish_membership(bob, bob_keys, bound, epoch, &leaf, None)?;
    }
    let after = live.relay(AFTER_TEXT, 2)?;
    assert_eq!(
        mls_rs_text(&mut group, &after)?.as_deref(),
        Some(AFTER_TEXT),
        "the rejoined leaf reads the minutes of the epoch it joined"
    );
    let certified = update_commit(
        live,
        close_authority::CertificationTransition::Add,
        policies,
    )?;
    receipt_signed_by(&certified.receipt, successor)
}
