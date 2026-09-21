//! ENC-10 scenario A (companion 13.7 and 13.7.4): a member whose live MLS
//! state is lost must not continue with its old leaf. It rejoins as a new
//! leaf, derives exactly the plaintext its new epoch entitles it to and
//! nothing from before the loss, and the lineage those real endpoints
//! produced is then re-proved to a coordinator restored from a signed backup
//! through the repaired recovery-submission carrier.
#![forbid(unsafe_code)]

use super::*;

use agenc_relay_storage::E2eeRecoveryKind;
use e2ee::objects::recovery::ArcRecoveryElementKind;
use mls_rs::client_builder::MlsConfig;
use mls_rs::time::MlsTime;
use openmls::prelude::{LeafNodeIndex, LeafNodeParameters};

use super::super::recovery_submission::{
    Submitter, attach_when_active, fetch_records, read_gate, settle,
};
use super::super::stage_ten_drills::{
    RestorePlan, account_login_named, repin_coordinator_epoch, restore_node,
    wait_for_account_authority, write_backup,
};

/// The plaintext alice sends before bob loses his MLS state.
const BEFORE_TEXT: &str = "minutes bob heard as leaf one";
/// The plaintext alice sends after bob rejoins as a new leaf.
const AFTER_TEXT: &str = "minutes bob hears as his replacement leaf";

/// The public lineage the live endpoints produced, exactly as a restored
/// coordinator must re-prove it before it may install a terminal.
struct Lineage {
    /// Every retained sequencer record of the conversation in route order.
    records: Vec<(u64, Vec<u8>)>,
    /// The operational policy object the bootstrap activation references.
    policy: Vec<u8>,
    /// The finalized close authorization object and its identifier.
    close: (Vec<u8>, [u8; 32]),
}

#[test]
fn a_recovering_member_rejoins_and_reads_only_the_history_it_is_entitled_to() -> TestResult {
    run_network(recover_with_real_clients)
}

fn recover_with_real_clients(
    network: &Network,
    coordinator: &mut DaemonProcess,
    edge_a: &mut DaemonProcess,
    edge_b: &mut DaemonProcess,
) -> TestResult {
    let mut clients = bind_channel(network)?;
    let backup = step(
        "signed backup",
        take_backup(network, coordinator, &mut clients),
    )?;
    let (mut clients, lineage) = step("encrypted lifetime", live_lifetime(clients))?;
    step(
        "declared recovery",
        restore_and_recover(
            network,
            (coordinator, edge_a, edge_b),
            &mut clients,
            &backup,
            &lineage,
        ),
    )?;
    require_recorded(&RECOVERY_RULES)
}

/// Stops the coordinator, writes a signed current-format backup of the route
/// before any record exists, and brings the network back with both devices
/// attached again.
fn take_backup(
    network: &Network,
    coordinator: &mut DaemonProcess,
    clients: &mut Clients,
) -> TestResult<PathBuf> {
    let before_a = links_established(&network.edge_a);
    let before_b = links_established(&network.edge_b);
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped for the backup: {status}"
    );
    let (backup, records, _) = write_backup(&network.coordinator, "enc-ten.backup", 1)?;
    assert!(records > 0);
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, before_a)?;
    wait_for_link(&network.edge_b, before_b)?;
    attach_when_active(&mut clients.alice, &mut clients.alice_keys)?;
    attach_when_active(&mut clients.bob, &mut clients.bob_keys)?;
    Ok(backup)
}

/// Runs the whole encrypted lifetime with real endpoints and returns the
/// public lineage it produced.
fn live_lifetime(clients: Clients) -> TestResult<(Clients, Lineage)> {
    let bob_interval = clients.bob_interval();
    let policy = wire_object(ArcWireObjectKind::Policy, &clients.bound.policies[1])?;
    let mut live = Live::open(clients)?;
    let policies = live.clients.policies;
    step(
        "bootstrap activation",
        activate_bootstrap(&mut live, policies),
    )?;
    let (mut bob_group, bob_leaf) = step("add bob", add_bob(&mut live, bob_interval))?;

    // What bob is entitled to as leaf one: the minutes of his own epoch.
    let before = step("relay before", live.relay(BEFORE_TEXT, 0))?;
    let heard = mls_rs_text(&mut bob_group, &before)?;
    assert_eq!(heard.as_deref(), Some(BEFORE_TEXT));

    // bob loses his live MLS state. Companion 13.7 forbids continuing with
    // the old leaf, so it is removed and he rejoins under a fresh one.
    drop(bob_group);
    let mut rejoined = step("rejoin bob", rejoin_bob(&mut live, &bob_leaf, bob_interval))?;

    let after = step("relay after", live.relay(AFTER_TEXT, 1))?;
    assert_eq!(
        mls_rs_text(&mut rejoined, &after)?.as_deref(),
        Some(AFTER_TEXT),
        "the rejoined leaf reads the minutes of the epoch it joined"
    );
    assert_eq!(
        mls_rs_text(&mut rejoined, &before)?,
        None,
        "the rejoined leaf derives no plaintext from before it lost state"
    );

    let close = step("close lineage", close_lineage(&mut live))?;
    let records = {
        let Clients {
            alice,
            alice_keys,
            bound,
            ..
        } = &mut live.clients;
        fetch_records(alice, alice_keys, bound)?
    };
    assert_eq!(
        records
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        (0..10).collect::<Vec<_>>(),
        "five certified Commits leave ten records in route order"
    );
    Ok((
        live.clients,
        Lineage {
            records,
            policy,
            close,
        },
    ))
}

/// Removes bob's lost leaf, records the removal proof for its last epoch,
/// and adds his replacement leaf through a second Welcome.
fn rejoin_bob(
    live: &mut Live,
    lost: &OldLeaf,
    interval: (u64, u64),
) -> TestResult<mls_rs::Group<impl MlsConfig + use<>>> {
    live.arm_commit()?;
    let (commit, _welcome, _info) = live.group.remove_members(
        &live.creator.provider,
        &live.creator.signer,
        &[LeafNodeIndex::new(lost.index)],
    )?;
    let policies = live.clients.policies;
    let removed = live.certify(
        &commit.to_bytes()?,
        close_authority::CertificationTransition::Remove,
        (policies.1, policies.1),
    )?;
    // The removal proof holds for the leaf's last epoch: it names the
    // finalization that removed it (companion 13.7.3).
    let epoch = live.head.0;
    {
        let Clients {
            bob,
            bob_keys,
            bound,
            ..
        } = &mut live.clients;
        publish_membership(
            bob,
            bob_keys,
            bound,
            epoch,
            lost,
            Some(removed.finalization_id),
        )?;
    }
    let joiner =
        real_clients::mls_rs_client_with_leaf(&live.clients.bob_keys, interval, BOB_REJOIN_LEAF)?;
    let package = joiner
        .generate_key_package_message(
            Default::default(),
            Default::default(),
            Some(MlsTime::from(interval.0)),
        )?
        .to_bytes()?;
    let group = join_through_welcome(live, &joiner, &package, interval.1, [78; 16])?;
    let index = group.current_member_index();
    let leaf = real_leaf(&live.clients.bob_keys, interval, BOB_REJOIN_LEAF, index)?;
    let epoch = live.head.0;
    let Clients {
        bob,
        bob_keys,
        bound,
        ..
    } = &mut live.clients;
    publish_membership(bob, bob_keys, bound, epoch, &leaf, None)?;
    Ok(group)
}

/// Certifies the closing transition and the finalized public close, and
/// returns the close authorization object and its identifier.
fn close_lineage(live: &mut Live) -> TestResult<(Vec<u8>, [u8; 32])> {
    live.arm_commit()?;
    let closing = live.group.self_update(
        &live.creator.provider,
        &live.creator.signer,
        LeafNodeParameters::default(),
    )?;
    let commit = closing.commit().to_bytes()?;
    let policies = live.clients.policies;
    let close_time = live.time;
    let intent = close_authority::authorization_at(
        &live.clients.alice_keys,
        &live.clients.bound,
        live.head.1,
        close_time,
    )?;
    let terminal = live.certify(
        &commit,
        close_authority::CertificationTransition::Close(intent.tbs.close_intent_id),
        (policies.1, policies.1),
    )?;
    let close = close_authority::authorization_at(
        &live.clients.alice_keys,
        &live.clients.bound,
        terminal.finalization_id,
        close_time,
    )?;
    let bytes = wire_object(ArcWireObjectKind::CloseAuthorization, &close)?;
    let Clients {
        alice,
        alice_keys,
        bob,
        bound,
        ..
    } = &mut live.clients;
    let close_id = close_conversation_at(
        alice,
        alice_keys,
        bound,
        terminal.finalization_id,
        close_time,
    )?;
    bob.read_until(|line| line.contains(" EGROUP CLOSED "))?;
    Ok((bytes, close_id))
}

/// Restores the coordinator from the signed backup under a new recovery
/// epoch and re-proves the lineage through the recovery-submission carrier.
fn restore_and_recover(
    network: &Network,
    daemons: (&mut DaemonProcess, &mut DaemonProcess, &mut DaemonProcess),
    clients: &mut Clients,
    backup: &Path,
    lineage: &Lineage,
) -> TestResult {
    let (coordinator, edge_a, edge_b) = daemons;
    clients.alice.send("QUIT :recovery")?;
    clients.bob.send("QUIT :recovery")?;
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
            "{label} stopped before the restore: {status}"
        );
    }
    let outcome = restore_node(
        &network.coordinator,
        &RestorePlan {
            backup,
            new_master: false,
            disaster: true,
            generation: 2,
        },
    )?;
    repin_coordinator_epoch(network, &outcome.epoch)?;
    let gate = read_gate(&network.coordinator, clients.bound.conversation)?;
    assert_eq!(gate.state(), E2eeRecoveryKind::Pending);
    assert_eq!(
        gate.restored_binding_id().as_bytes(),
        &clients.bound.binding_id
    );
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    *edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    *edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    for fixture in [&network.edge_a, &network.edge_b] {
        wait_for_link(fixture, 0)?;
        wait_for_account_authority(fixture)?;
    }
    let (mut alice, _) = account_login_named(
        &network.edge_a,
        clients.alice_account,
        "alice",
        "alice-account",
    )?;
    attach_when_active(&mut alice, &mut clients.alice_keys)?;
    let anchor = *gate.restored_sequencer_head_id().as_bytes();
    let conversation = clients.bound.conversation;
    let mut submitter = Submitter {
        client: &mut alice,
        user: &mut clients.alice_keys,
        gate,
        conversation,
    };
    upload_lineage(&mut submitter, anchor, lineage)?;
    let conversation = clients.bound.conversation;
    refuse_after_close(
        network,
        coordinator,
        (&mut alice, &mut clients.alice_keys),
        conversation,
        lineage,
    )
}

/// Uploads every element of `lineage` from the attached device and reaches
/// the permanent closed terminal.
fn upload_lineage(
    submitter: &mut Submitter<'_>,
    anchor: [u8; 32],
    lineage: &Lineage,
) -> TestResult {
    let mut predecessor = anchor;
    let mut probed = false;
    let first = lineage
        .records
        .first()
        .map(|(_, bytes)| bytes.clone())
        .ok_or_else(|| failure("the lineage holds at least one record"))?;
    for (sequence, record) in &lineage.records {
        if *sequence == 1 {
            let reply = submitter.deliver(
                (1, predecessor),
                ArcRecoveryElementKind::ReferenceElement,
                ArcWireObjectKind::Policy,
                &lineage.policy,
            )?;
            assert_contains(&reply, " EGROUP RECOVERY-EXTENDED ")?;
        }
        if *sequence == 4 && !probed {
            // A complete record that does not continue the chain at this
            // position installs nothing, and the genuine record is still
            // accepted at the same position afterwards.
            probed = true;
            let reply = submitter.deliver(
                (*sequence, predecessor),
                ArcRecoveryElementKind::RecordElement,
                ArcWireObjectKind::SequencerRecord,
                &first,
            )?;
            assert_contains(&reply, "FAIL EGROUP E2EE_BINDING_AUTH_INVALID")?;
        }
        predecessor = submitter.extend((*sequence, predecessor), record)?;
    }
    assert!(probed, "the refusal probe ran inside the lineage");
    let position = u64::try_from(lineage.records.len())?;
    let reply = submitter.deliver(
        (position, predecessor),
        ArcRecoveryElementKind::CloseElement,
        ArcWireObjectKind::CloseAuthorization,
        &lineage.close.0,
    )?;
    assert_contains(&reply, " EGROUP RECOVERY-CLOSED ")?;
    assert_eq!(hash_at(&reply, "RECOVERY-CLOSED", 4)?, lineage.close.1);
    Ok(())
}

/// Closed is permanent: the durable gate reads closed after a stop and the
/// restarted coordinator refuses every later submission.
fn refuse_after_close(
    network: &Network,
    coordinator: &mut DaemonProcess,
    alice: (&mut ArcClient, &mut Principal),
    conversation: [u8; 32],
    lineage: &Lineage,
) -> TestResult {
    let (alice, keys) = alice;
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped after the close: {status}"
    );
    let closed = read_gate(&network.coordinator, conversation)?;
    assert_eq!(closed.state(), E2eeRecoveryKind::Closed);
    let before = links_established(&network.edge_a);
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, before)?;
    attach_when_active(alice, keys)?;
    let record = lineage
        .records
        .first()
        .map(|(_, bytes)| bytes.clone())
        .ok_or_else(|| failure("the lineage holds at least one record"))?;
    let submitter = Submitter {
        client: alice,
        user: keys,
        gate: closed,
        conversation,
    };
    let position = u64::try_from(lineage.records.len())?.saturating_add(1);
    let submission = submitter.submission(
        (position, lineage.close.1),
        ArcRecoveryElementKind::RecordElement,
        ArcWireObjectKind::SequencerRecord,
        &record,
    )?;
    let token = base64url_encode(&conversation);
    let Submitter { client, user, .. } = submitter;
    settle("the refused submission after the close", || {
        let label = user.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT RECOVERY {token}"),
            &submission,
        )?;
        assert_contains(&labeled_reply(client, &label)?, "E2EE_ROUTE_INVALID")
    })?;
    client.send("QUIT :recovered")?;
    Ok(())
}
