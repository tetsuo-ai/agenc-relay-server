//! Exercise stopped key rotation and live lazy migration through the actual daemon.
#![forbid(unsafe_code)]

use super::super::stage_ten_login_index::{
    install_key_mapping, open_owner, read_plaintext, rotation, rotation_commit,
};
use super::*;
use agenc_ircd_admin::{AuditChainCursor, AuditEvent, MaintenanceOperation};
use agenc_ircd_runtime::state_core::durable::KeyDeriver;
use agenc_ircd_storage::{LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, ReadPlan};

const NEW_KEY: [u8; 32] = [219; 32];
const DORMANT_LOGIN: &str = "rotation-dormant";

#[derive(Debug, Eq, PartialEq)]
struct Evidence {
    state: LoginIndexKeyState,
    generation: u64,
    commit: u64,
    opaque: BTreeMap<Vec<u8>, Vec<u8>>,
    logins: BTreeMap<AccountId, u32>,
    audit: Vec<AuditEvent>,
}

pub(super) fn run(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let active = seed_state(&network)?;
    let (mut dormant, dormant_id) =
        authenticated_client(&network.edge_b, "rotation-seed", DORMANT_LOGIN, 180)?;
    dormant.send("QUIT :seeded")?;
    drop(dormant);
    stop_coordinator(&mut nodes)?;
    let fixture = &network.coordinator;
    let old = [fixture.seed.wrapping_add(9); 32];
    let before = inspect(fixture, old, None)?;
    assert_eq!(
        before.logins,
        BTreeMap::from([(active, 1), (dormant_id, 1)])
    );
    let new_file = fixture.data_dir.join("keys/login-index-next.key");
    write_private(&new_file, &NEW_KEY)?;
    let start = command_succeeded(rotation(fixture, Some(&new_file))?)?;
    let started = inspect(fixture, NEW_KEY, Some(old))?;
    assert_rotation(
        &before,
        &started,
        start,
        MaintenanceOperation::LoginIndexRotateStart,
    )?;
    assert_eq!(started.state.previous(), Some((1, 2)));
    assert_eq!(started.logins, before.logins);
    install_key_mapping(fixture, &new_file, true)?;
    drill.step(
        "start",
        "signed rotation retained both old-generation login entries",
    );
    migrate_one(
        &network,
        &mut nodes,
        active,
        DRILL_ACCOUNT_LOGIN,
        "rotation-active",
    )?;
    let partial = inspect(fixture, NEW_KEY, Some(old))?;
    assert_eq!(partial.state.previous(), Some((1, 1)));
    assert_eq!(
        partial.logins,
        BTreeMap::from([(active, 2), (dormant_id, 1)])
    );
    assert_eq!(partial.opaque, before.opaque);
    let refused = rotation(fixture, None)?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(inspect(fixture, NEW_KEY, Some(old))?, partial);
    drill.fact("dormant_entry_blocks_finish", true);
    migrate_one(
        &network,
        &mut nodes,
        dormant_id,
        DORMANT_LOGIN,
        "rotation-dormant",
    )?;
    let migrated = inspect(fixture, NEW_KEY, Some(old))?;
    assert_eq!(migrated.state.previous(), Some((1, 0)));
    assert_eq!(
        migrated.logins,
        BTreeMap::from([(active, 2), (dormant_id, 2)])
    );
    assert_eq!(migrated.opaque, before.opaque);
    let finish = command_succeeded(rotation(fixture, None)?)?;
    install_key_mapping(fixture, &new_file, false)?;
    let finished = inspect(fixture, NEW_KEY, None)?;
    assert_rotation(
        &migrated,
        &finished,
        finish,
        MaintenanceOperation::LoginIndexRotateFinish,
    )?;
    assert_eq!(finished.state.previous(), None);
    assert_eq!(finished.logins, migrated.logins);
    drill.fact("opaque_credentials_preserved", true);
    drill.fact("maintenance_audit_events", 2);
    nodes.restart(&network, 0)?;
    authenticate_pair(&network, active, dormant_id)?;
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(clean.into_iter().all(|stopped| stopped))
}

fn stop_coordinator(nodes: &mut DrillNodes) -> TestResult {
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    Ok(())
}

fn migrate_one(
    network: &Network,
    nodes: &mut DrillNodes,
    account: AccountId,
    login: &str,
    nickname: &str,
) -> TestResult {
    nodes.restart(network, 0)?;
    let (mut client, _) = account_login_named(&network.edge_b, account, nickname, login)?;
    client.send("QUIT :migration committed")?;
    drop(client);
    stop_coordinator(nodes)
}

fn authenticate_pair(network: &Network, active: AccountId, dormant: AccountId) -> TestResult {
    for (account, login, nickname) in [
        (active, DRILL_ACCOUNT_LOGIN, "rotation-final-a"),
        (dormant, DORMANT_LOGIN, "rotation-final-b"),
    ] {
        let (mut client, _) = account_login_named(&network.edge_b, account, nickname, login)?;
        client.send("QUIT :new key verified")?;
    }
    Ok(())
}

fn command_succeeded(output: std::process::Output) -> TestResult<u64> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    rotation_commit(&output)
}

fn inspect(
    fixture: &NodeFixture,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
) -> TestResult<Evidence> {
    let owner = open_owner(fixture, current, previous)?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let result = (|| {
        Ok(Evidence {
            state: LoginIndexKeyState::decode(&read_plaintext(
                &owner,
                &keys,
                TableId::LoginIndexKeyState,
                StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            )?)?,
            generation: recovered.state_generation(),
            commit: recovered.storage_commit_sequence(),
            opaque: read_table(&owner, &keys, TableId::OpaqueRecord)?,
            logins: read_logins(&owner, &keys)?,
            audit: read_audit(fixture, &owner, &keys)?,
        })
    })();
    owner.shutdown()?;
    result
}

fn read_table(
    owner: &StorageOwner,
    keys: &KeyDeriver,
    table: TableId,
) -> TestResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let result = owner
        .port()
        .try_read(ReadPlan::range(
            table,
            StoredKey::new(vec![0])?,
            StoredKey::new(vec![0xff; agenc_ircd_storage::MAX_STORED_KEY_BYTES])?,
            256,
        )?)?
        .wait()?;
    assert!(
        !result.truncated,
        "drill evidence exceeded its 256-row bound"
    );
    assert_eq!(
        result.storage_commit_sequence,
        owner.recovered_state().storage_commit_sequence()
    );
    assert_eq!(
        result.records.len() as u64,
        owner.recovered_state().table_record_count(table)
    );
    let mut values = BTreeMap::new();
    for row in result.records {
        assert_eq!(row.table, table);
        let sealed = agenc_ircd_storage::SealedRecord::decode(&row.sealed_record)?;
        let opened = keys.open(table, &row.key, &sealed)?;
        assert!(
            values
                .insert(
                    row.key.as_bytes().to_vec(),
                    opened.expose_for_storage_codec().to_vec()
                )
                .is_none()
        );
    }
    Ok(values)
}

fn read_logins(owner: &StorageOwner, keys: &KeyDeriver) -> TestResult<BTreeMap<AccountId, u32>> {
    let mut values = BTreeMap::new();
    for (key, bytes) in read_table(owner, keys, TableId::LoginIndex)? {
        let key = LoginIndexStoredKey::decode(&key)?;
        let value = LoginIndexValue::decode(&bytes, &key)?;
        let LoginIndexValueKind::Live { account_id, .. } = value.kind() else {
            return Err(failure("rotation drill retained a non-live index entry"));
        };
        assert!(values.insert(*account_id, key.generation()).is_none());
    }
    Ok(values)
}

fn read_audit(
    fixture: &NodeFixture,
    owner: &StorageOwner,
    keys: &KeyDeriver,
) -> TestResult<Vec<AuditEvent>> {
    let audit_key = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]).public_key();
    let operator_key =
        Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(12); 32]).public_key();
    let mut cursor = AuditChainCursor {
        next_sequence: 0,
        previous_event_hash: [0; 32],
    };
    let mut events = Vec::new();
    for (key, bytes) in read_table(owner, keys, TableId::Audit)? {
        let value = PersistentRecordValue::decode(TableId::Audit, &bytes)?;
        let event = AuditEvent::decode_exact(value.body())?;
        assert_eq!(key, event.audit_sequence().to_be_bytes());
        assert_eq!(value.record_kind(), event.encoding());
        assert_eq!(value.revision(), event.audit_sequence() + 1);
        assert_eq!(value.generation(), 0);
        assert!(value.references().is_empty());
        assert_eq!(value.expires_at(), None);
        assert_eq!(event.network_id(), NETWORK_ID);
        assert_eq!(event.server_id(), fixture.server_id);
        match &event {
            AuditEvent::Admin(event) => event.verify(audit_key, operator_key)?,
            AuditEvent::Maintenance(event) => {
                event.verify(NETWORK_ID, fixture.server_id, audit_key)?
            }
        }
        cursor = cursor.advance_event(&event)?;
        events.push(event);
    }
    Ok(events)
}

fn assert_rotation(
    before: &Evidence,
    after: &Evidence,
    receipt: u64,
    operation: MaintenanceOperation,
) -> TestResult {
    assert_eq!(receipt, before.commit + 1);
    assert_eq!(after.commit, receipt + 1);
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.opaque, before.opaque);
    assert_eq!(after.audit.len(), before.audit.len() + 1);
    assert_eq!(
        after.audit.get(..before.audit.len()),
        Some(before.audit.as_slice())
    );
    let Some(AuditEvent::Maintenance(event)) = after.audit.last() else {
        return Err(failure("rotation omitted its signed maintenance event"));
    };
    assert_eq!(event.tbs().transition().operation(), operation);
    assert_eq!(
        event.tbs().position().preceding_state_generation(),
        before.generation
    );
    assert_eq!(
        event.tbs().position().resulting_state_generation(),
        after.generation
    );
    assert_eq!(
        event.tbs().transition().resulting().current_generation(),
        after.state.current_generation()
    );
    assert_eq!(
        event
            .tbs()
            .transition()
            .resulting()
            .previous()
            .map(|(generation, _, count)| (generation, count)),
        after.state.previous()
    );
    Ok(())
}
