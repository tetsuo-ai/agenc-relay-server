//! Companion 13.7.4 through the real daemon: a coordinator restored from a
//! signed backup under a new recovery epoch holds the route `pending`, an
//! attached principal device uploads the previously signed chain and its
//! finalized close through `EGROUP SUBMIT RECOVERY` and
//! `RECOVERY-ELEMENT` with every signing key unavailable to the server, and
//! the route becomes permanently `closed`, surviving a restart.
#![forbid(unsafe_code)]

use super::stage_ten_capacity::{current_key_file, current_state_dir};
use super::stage_ten_drills::{
    RestorePlan, account_login_named, engine_limits, node_keys, read_key, repin_coordinator_epoch,
    restore_node, wait_for_account_authority, write_backup,
};
use super::*;
use agenc_ircd_runtime::state_core::durable::KeyDeriver;
use agenc_ircd_storage::e2ee_records::recovery_gate_key;
use agenc_ircd_storage::{
    E2eeRecoveryGate, E2eeRecoveryKind, PersistentRecordValue, ReadPlan, SealedRecord,
    StorageOpenConfig, StorageOwner, TableId,
};
use e2ee::objects::recovery::{
    IrcRecoveryElementKind, IrcRecoverySubmission, IrcRecoverySubmissionTbs,
};
use e2ee::objects::sequencing::IrcSequencerRecord;
use e2ee::wire::fragment::FragmentTag;
use std::collections::BTreeMap;

/// The durable gate of `conversation` in the coordinator's current state
/// directory, read while the daemon is stopped.
fn read_gate(fixture: &NodeFixture, conversation: [u8; 32]) -> TestResult<E2eeRecoveryGate> {
    let (master, guard, login) = node_keys(fixture);
    let master = read_key(&current_key_file(fixture, "master_key_file")?).unwrap_or(master);
    let guard = read_key(&current_key_file(fixture, "rollback_guard_key_file")?).unwrap_or(guard);
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(
            &current_state_dir(fixture)?,
            &embedded_storage_qualifications()?,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(guard),
        login_index_key: LoginIndexKey::from_bytes(login),
        previous_login_index_key: None,
        limits: engine_limits(),
    })?;
    let result = (|| {
        let recovered = owner.recovered_state();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes(master),
            recovered.database_binding(),
            recovered.storage_key_generation(),
        )?;
        let key = recovery_gate_key(&conversation)?;
        let read = owner
            .port()
            .try_read(ReadPlan::exact(TableId::E2eeState, key.clone()))?
            .wait()?;
        let row = read
            .records
            .into_iter()
            .find(|row| row.key == key)
            .ok_or_else(|| failure("the restored coordinator holds no gate for the route"))?;
        let sealed = SealedRecord::decode(&row.sealed_record)?;
        let opened = keys.open(TableId::E2eeState, &row.key, &sealed)?;
        let value =
            PersistentRecordValue::decode(TableId::E2eeState, opened.expose_for_storage_codec())?;
        Ok(E2eeRecoveryGate::decode(value.body())?)
    })();
    owner.shutdown()?;
    result
}

/// Every object of one paged reply, reassembled from its fragment tags.
fn page_objects(lines: &[String]) -> TestResult<Vec<Vec<u8>>> {
    let mut parts: BTreeMap<[u8; 32], Vec<FragmentTag>> = BTreeMap::new();
    for line in lines {
        let Some(value) = tag_value(line, SERVER_FRAGMENT_TAG) else {
            continue;
        };
        let fragment = FragmentTag::parse(&value)?;
        parts
            .entry(*fragment.object_id.as_bytes())
            .or_default()
            .push(fragment);
    }
    Ok(parts
        .into_values()
        .map(|mut fragments| {
            fragments.sort_by_key(|fragment| fragment.part);
            fragments
                .into_iter()
                .flat_map(|fragment| fragment.segment)
                .collect()
        })
        .collect())
}

/// The route sequence a retained record occupies.
fn record_sequence(bytes: &[u8]) -> TestResult<u64> {
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object =
        IrcWireObject::decode_kind(bytes, Some(IrcWireObjectKind::SequencerRecord), &mut budget)?;
    Ok(
        match IrcSequencerRecord::decode_exact(object.body(), &mut budget)? {
            IrcSequencerRecord::Candidate(receipt) => receipt.tbs.route_sequence,
            IrcSequencerRecord::Finalization(certificate) => certificate.tbs.route_sequence,
            IrcSequencerRecord::Abort(certificate) => certificate.tbs.route_sequence,
            _ => return Err(failure("unexpected record kind in the lineage")),
        },
    )
}

/// The retained records of `bound`, in route order.
fn fetch_records(
    client: &mut IrcClient,
    user: &mut Principal,
    bound: &BoundConversation,
) -> TestResult<Vec<(u64, Vec<u8>)>> {
    let label = user.label();
    client.send(&format!(
        "@label={label} EGROUP FETCH RECEIPTS {} 0 *",
        base64url_encode(&bound.conversation)
    ))?;
    let reply = labeled_reply(client, &label)?;
    let mut records = page_objects(&reply)?
        .into_iter()
        .map(|bytes| Ok((record_sequence(&bytes)?, bytes)))
        .collect::<TestResult<Vec<_>>>()?;
    records.sort_by_key(|(sequence, _)| *sequence);
    Ok(records)
}

/// Re-attaches the user's device after the coordinator restored: the
/// identity and roster are retained, the attachment session is new.
fn attach_again(client: &mut IrcClient, user: &mut Principal) -> TestResult {
    let label = user.label();
    client.send(&format!(
        "@label={label} EKEY ATTACH BEGIN {}",
        user.device_token()
    ))?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY ATTACH-CHALLENGE ")?;
    let bytes = batch_object(&reply)?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = IrcWireObject::decode_kind(
        &bytes,
        Some(IrcWireObjectKind::DeviceAttachChallenge),
        &mut budget,
    )?;
    let challenge = IrcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
    let device_signature = builders::sign(
        &builders::key(user.device),
        agenc_ircd_crypto::SignatureDomain::DeviceAttachPossession,
        &challenge.tbs,
    )?;
    let attach = wire_object(
        IrcWireObjectKind::DeviceAttach,
        &IrcDeviceAttach {
            challenge,
            device_signature,
        },
    )?;
    let label = user.label();
    send_object(
        client,
        &label,
        &format!("EKEY ATTACH FINISH {}", user.device_token()),
        &attach,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY ATTACHED ")?;
    Ok(())
}

/// Whether a refusal names a state the edge leaves on its own once its
/// session, origin, and attachment facts have settled after a restart.
fn transitional(error: &TestError) -> bool {
    let text = error.to_string();
    [
        "E2EE_SYNCING",
        "E2EE_ACCOUNT_REQUIRED",
        "E2EE_DEVICE_REQUIRED",
    ]
    .iter()
    .any(|code| text.contains(code))
}

/// Retries `attempt` while it fails transitionally, within the network wait.
fn settle<T>(what: &str, mut attempt: impl FnMut() -> TestResult<T>) -> TestResult<T> {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error) if transitional(&error) => {
                if Instant::now() >= deadline {
                    return Err(failure(format!("{what} never settled: {error}")));
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Re-attaches once the edge's encrypted profile is active after a
/// coordinator restart; transitional refusals are retried.
fn attach_when_active(client: &mut IrcClient, user: &mut Principal) -> TestResult {
    settle("the attach after the restart", || {
        attach_again(client, user)
    })
}

struct Submitter<'a> {
    client: &'a mut IrcClient,
    user: &'a mut Principal,
    gate: E2eeRecoveryGate,
    conversation: [u8; 32],
}

impl Submitter<'_> {
    fn submission(
        &self,
        position: (u64, [u8; 32]),
        kind: IrcRecoveryElementKind,
        object_kind: IrcWireObjectKind,
        element: &[u8],
    ) -> TestResult<Vec<u8>> {
        let tbs = IrcRecoverySubmissionTbs {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: self.conversation,
            recovery_epoch: *self.gate.recovery_epoch().as_bytes(),
            restored_binding_id: *self.gate.restored_binding_id().as_bytes(),
            restored_accepted_state_id: *self.gate.restored_accepted_state_id().as_bytes(),
            restored_sequencer_head_id: *self.gate.restored_sequencer_head_id().as_bytes(),
            source_rollback_guard_hash: *self.gate.source_rollback_guard_hash().as_bytes(),
            route_sequence: position.0,
            predecessor_record_id: position.1,
            element_kind: kind,
            element_object_kind: object_kind,
            element_object_id: *e2ee::ObjectId::compute(element).as_bytes(),
            account_id: Opaque::new(self.user.account.to_vec())?,
            device_id: [self.user.device; 16],
        };
        let device_signature = builders::sign(
            &builders::key(self.user.device),
            agenc_ircd_crypto::SignatureDomain::RecoverySubmission,
            &tbs,
        )?;
        wire_object(
            IrcWireObjectKind::RecoverySubmission,
            &IrcRecoverySubmission {
                tbs,
                device_signature,
            },
        )
    }

    /// Submits and delivers one element; returns the element reply lines.
    fn deliver(
        &mut self,
        position: (u64, [u8; 32]),
        kind: IrcRecoveryElementKind,
        object_kind: IrcWireObjectKind,
        element: &[u8],
    ) -> TestResult<Vec<String>> {
        let submission = self.submission(position, kind, object_kind, element)?;
        let conversation = base64url_encode(&self.conversation);
        let reply = settle("the recovery submission", || {
            let label = self.user.label();
            send_object(
                self.client,
                &label,
                &format!("EGROUP SUBMIT RECOVERY {conversation}"),
                &submission,
            )?;
            let reply = labeled_reply(self.client, &label)?;
            assert_contains(&reply, " EGROUP RECOVERY-ACCEPTED ")?;
            Ok(reply)
        })?;
        let submission_id = hash_at(&reply, "RECOVERY-ACCEPTED", 4)?;
        let label = self.user.label();
        send_object(
            self.client,
            &label,
            &format!(
                "EGROUP SUBMIT RECOVERY-ELEMENT {conversation} {}",
                base64url_encode(&submission_id)
            ),
            element,
        )?;
        labeled_reply(self.client, &label)
    }

    /// Submits a record for `position` and expects `RECOVERY-EXTENDED`;
    /// returns the installed record identifier.
    fn extend(&mut self, position: (u64, [u8; 32]), record: &[u8]) -> TestResult<[u8; 32]> {
        let reply = self.deliver(
            position,
            IrcRecoveryElementKind::RecordElement,
            IrcWireObjectKind::SequencerRecord,
            record,
        )?;
        assert_contains(&reply, " EGROUP RECOVERY-EXTENDED ")?;
        let line = reply
            .iter()
            .find(|line| line.contains(" RECOVERY-EXTENDED "))
            .ok_or_else(|| failure("extended line"))?;
        let sequence: u64 = words(line)
            .get(4)
            .ok_or_else(|| failure("route sequence"))?
            .parse()?;
        assert_eq!(sequence, position.0);
        hash_at(&reply, "RECOVERY-EXTENDED", 5)
    }
}

fn daemons_stopped(daemons: [(&str, TestResult<ExitStatus>); 3]) -> TestResult {
    for (label, status) in daemons {
        let status = status.map_err(|error| failure(format!("{label}: {error}")))?;
        if !status.success() {
            return Err(failure(format!("{label} exited with {status}")));
        }
    }
    Ok(())
}

#[test]
fn a_restored_coordinator_adopts_the_signed_lineage_and_closes_permanently() -> TestResult {
    let network = build_network_with(Some(CapacityPlan {
        max_connections: 32,
        connections_per_address: 32,
    }))?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = recover_through_the_daemon(&network, &mut coordinator, &mut edge_a, &mut edge_b);
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
    daemons_stopped([
        ("edge a", stopped_a),
        ("edge b", stopped_b),
        ("coordinator", stopped_core),
    ])
}

fn recover_through_the_daemon(
    network: &Network,
    coordinator: &mut DaemonProcess,
    edge_a: &mut DaemonProcess,
    edge_b: &mut DaemonProcess,
) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    wait_for_account_authority(&network.edge_a)?;
    wait_for_account_authority(&network.edge_b)?;
    let (mut alice, alice_account) =
        authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
    let (mut bob, bob_account) = authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
    // The lineage is re-verified at the records' validation time, so the
    // roots and rosters must cover it (companion 9.2 and 9.3).
    let mut alice_keys =
        Principal::new_valid_at(ALICE_ROOT, ALICE_DEVICE, alice_account, VALIDATION_TIME)?;
    let mut bob_keys = Principal::new_valid_at(BOB_ROOT, BOB_DEVICE, bob_account, VALIDATION_TIME)?;
    step(
        "alice attach",
        publish_and_attach(&mut alice, &mut alice_keys),
    )?;
    step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;
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

    // The backup captures the route before any record: the restored head is
    // the genesis anchor and every later record must be recovered.
    let before_a = links_established(&network.edge_a);
    let before_b = links_established(&network.edge_b);
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped for the backup: {status}"
    );
    let (backup, records, _) = write_backup(&network.coordinator, "recovery.backup", 1)?;
    assert!(records > 0);
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, before_a)?;
    wait_for_link(&network.edge_b, before_b)?;
    step(
        "alice re-attach",
        attach_when_active(&mut alice, &mut alice_keys),
    )?;
    step("bob re-attach", attach_when_active(&mut bob, &mut bob_keys))?;

    // The live lineage: bootstrap activation, a closing transition and the
    // finalized close, all signed by keys the restored server never holds.
    let finalization_id = step(
        "channel activation",
        activate_bootstrap_with(&mut alice, &mut alice_keys, &bound, &[&bob_keys]),
    )?;
    bob.read_until(|line| line.contains(" EGROUP FINALIZED "))?;
    let intent = close_authority::authorization(&alice_keys, &bound, finalization_id)?;
    let aad = IrcCommitAad {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        validation_time: VALIDATION_TIME + 1,
        prior_state_id: finalization_id,
    }
    .encode()?;
    let commit = builders::private_message_at_epoch(&bound.group_id, 1, MLS_COMMIT, &aad)?;
    let policy = builders::policy_id_of(&bound.policies[1])?;
    let terminal = real_clients::certify_commit(
        &mut alice,
        &mut alice_keys,
        &[&bob_keys],
        &bound,
        &commit,
        (1, finalization_id),
        (policy, policy),
        close_authority::CertificationTransition::Close(intent.tbs.close_intent_id),
    )?;
    bob.read_until(|line| line.contains(" EGROUP FINALIZED "))?;
    let records = step(
        "fetch receipts",
        fetch_records(&mut alice, &mut alice_keys, &bound),
    )?;
    assert_eq!(
        records
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    let close = close_authority::authorization(&alice_keys, &bound, terminal.finalization_id)?;
    let close_bytes = wire_object(IrcWireObjectKind::CloseAuthorization, &close)?;
    let close_id = step(
        "close",
        close_conversation(
            &mut alice,
            &mut alice_keys,
            &bound,
            terminal.finalization_id,
        ),
    )?;
    bob.read_until(|line| line.contains(" EGROUP CLOSED "))?;
    let policy_bytes = wire_object(IrcWireObjectKind::Policy, &bound.policies[1])?;
    alice.send("QUIT :backup taken")?;
    bob.send("QUIT :backup taken")?;
    // The edges retire both sessions before they are stopped.
    thread::sleep(Duration::from_millis(500));

    // The coordinator loses its state and is restored from the earlier
    // backup under a new recovery epoch: the route comes back pending at
    // the genesis anchor while every later record is only in the clients'
    // hands.
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
            backup: &backup,
            new_master: false,
            disaster: true,
            generation: 2,
        },
    )?;
    repin_coordinator_epoch(network, &outcome.epoch)?;
    // The restore installs the restored directory; the gate is read from it
    // before the daemons start again.
    let gate = step(
        "read gate",
        read_gate(&network.coordinator, bound.conversation),
    )?;
    assert_eq!(gate.state(), E2eeRecoveryKind::Pending);
    assert_eq!(gate.restored_binding_id().as_bytes(), &bound.binding_id);
    let stderr_dir = network.coordinator.data_dir.join("restored-stderr");
    create_directory(&stderr_dir, 0o700)?;
    *coordinator = step(
        "coordinator restart",
        DaemonProcess::start_logged(
            &network.coordinator.config_path,
            None,
            Some(&stderr_dir.join("coordinator.stderr")),
        ),
    )?;
    *edge_a = step(
        "edge a start",
        DaemonProcess::start_logged(
            &network.edge_a.config_path,
            None,
            Some(&stderr_dir.join("edge-a.stderr")),
        ),
    )?;
    *edge_b = step(
        "edge b start",
        DaemonProcess::start_logged(
            &network.edge_b.config_path,
            None,
            Some(&stderr_dir.join("edge-b.stderr")),
        ),
    )?;
    let restarted = [
        ("edge a", &network.edge_a, "edge-a.stderr"),
        ("edge b", &network.edge_b, "edge-b.stderr"),
    ];
    for (label, fixture, stderr_name) in restarted {
        let ready = wait_for_link(fixture, 0).and_then(|()| wait_for_account_authority(fixture));
        if let Err(error) = ready {
            let stderr = fs::read_to_string(stderr_dir.join(stderr_name)).unwrap_or_default();
            let coordinator_stderr =
                fs::read_to_string(stderr_dir.join("coordinator.stderr")).unwrap_or_default();
            let log = fixture.log_text();
            let stderr: String = stderr.lines().rev().take(8).collect::<Vec<_>>().join("\n");
            let tail: Vec<&str> = log
                .lines()
                .filter(|line| line.contains("federation") || line.contains("error="))
                .filter(|line| !line.contains("admin_local"))
                .rev()
                .take(12)
                .collect();
            let coordinator_log = network.coordinator.log_text();
            let coordinator_tail: Vec<&str> = coordinator_log
                .lines()
                .filter(|line| line.contains("federation") || line.contains("error="))
                .rev()
                .take(12)
                .collect();
            return Err(failure(format!(
                "{label} after restore: {error}\nstderr: {stderr}\ncoordinator stderr: {coordinator_stderr}\nlog tail: {tail:#?}\ncoordinator log tail: {coordinator_tail:#?}"
            )));
        }
    }
    let (mut alice, _) = step(
        "alice login after restore",
        account_login_named(&network.edge_a, alice_account, "alice", "alice-account"),
    )?;
    step(
        "alice attach after restore",
        attach_when_active(&mut alice, &mut alice_keys),
    )?;

    // Upload the lineage: every record at its position, the operational
    // policy the bootstrap activation names as a reference first.
    let anchor = *gate.restored_sequencer_head_id().as_bytes();
    let mut submitter = Submitter {
        client: &mut alice,
        user: &mut alice_keys,
        gate,
        conversation: bound.conversation,
    };
    let mut predecessor = anchor;
    for (sequence, record) in &records {
        if *sequence == 1 {
            let reply = submitter.deliver(
                (1, predecessor),
                IrcRecoveryElementKind::ReferenceElement,
                IrcWireObjectKind::Policy,
                &policy_bytes,
            )?;
            assert_contains(&reply, " EGROUP RECOVERY-EXTENDED ")?;
        }
        predecessor = submitter.extend((*sequence, predecessor), record)?;
    }
    let reply = submitter.deliver(
        (4, predecessor),
        IrcRecoveryElementKind::CloseElement,
        IrcWireObjectKind::CloseAuthorization,
        &close_bytes,
    )?;
    assert_contains(&reply, " EGROUP RECOVERY-CLOSED ")?;
    assert_eq!(hash_at(&reply, "RECOVERY-CLOSED", 4)?, close_id);

    // Closed is permanent: it is what the durable gate holds after a stop,
    // and a restarted coordinator refuses every further submission.
    let status = coordinator.stop()?;
    assert!(
        status.success(),
        "coordinator stopped after the close: {status}"
    );
    let closed = read_gate(&network.coordinator, bound.conversation)?;
    assert_eq!(closed.state(), E2eeRecoveryKind::Closed);
    let before_a = links_established(&network.edge_a);
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, before_a)?;
    step(
        "alice attach after restart",
        attach_when_active(&mut alice, &mut alice_keys),
    )?;
    let submitter = Submitter {
        client: &mut alice,
        user: &mut alice_keys,
        gate: closed,
        conversation: bound.conversation,
    };
    let submission = submitter.submission(
        (5, close_id),
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
        &records.first().ok_or_else(|| failure("first record"))?.1,
    )?;
    let conversation = base64url_encode(&bound.conversation);
    let Submitter { client, user, .. } = submitter;
    settle("the refused submission after the close", || {
        let label = user.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT RECOVERY {conversation}"),
            &submission,
        )?;
        let refused = labeled_reply(client, &label)?;
        assert_contains(&refused, "E2EE_ROUTE_INVALID")
    })?;
    client.send("QUIT :recovered")?;
    Ok(())
}
