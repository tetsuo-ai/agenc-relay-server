#![forbid(unsafe_code)]

//! Authenticated stopped-state evidence for the capacity rotation scenario.

use super::*;
use crate::stage_ten_login_index::{install_key_mapping, open_owner, read_plaintext, rotation};
use agenc_ircd_runtime::state_core::durable::KeyDeriver;

struct State {
    key_state: LoginIndexKeyState,
    commit: u64,
    entries: u64,
}

pub(super) fn run(campaign: &mut Campaign<'_>) -> TestResult {
    campaign.shared.maintenance.store(true, Ordering::Relaxed);
    stop_coordinator(campaign)?;
    let fixture = &campaign.network.coordinator;
    let before = configured_state(fixture)?;
    if before.key_state.previous().is_some() || before.entries != 1 {
        return Err(failure(
            "rotation needs one stable existing campaign account",
        ));
    }
    let previous_generation = before.key_state.current_generation();
    let next_generation = previous_generation
        .checked_add(1)
        .ok_or("key generation overflow")?;
    let next_file = fixture
        .data_dir
        .join(format!("keys/login-index-{next_generation}.key"));
    let mut next_key = [0; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut next_key)?;
    write_private(&next_file, &next_key)?;
    let start_commit = command_commit(rotation(fixture, Some(&next_file))?)?;
    install_key_mapping(fixture, &next_file, true)?;
    let started = configured_state(fixture)?;
    // The command checkpoints its newly committed ledger during owner shutdown.
    let start_closed = start_commit
        .checked_add(1)
        .ok_or("start checkpoint overflow")?;
    if started.commit != start_closed
        || started.commit <= before.commit
        || started.entries != before.entries
        || started.key_state.current_generation() != next_generation
        || started.key_state.previous() != Some((previous_generation, before.entries))
        || started.key_state.current_key_id() == before.key_state.current_key_id()
    {
        return Err(failure(format!(
            "rotation start state mismatch: commit={}/{} generation={}/{} previous={:?} entries={}/{} key_changed={}",
            started.commit,
            start_closed,
            started.key_state.current_generation(),
            next_generation,
            started.key_state.previous(),
            started.entries,
            before.entries,
            started.key_state.current_key_id() != before.key_state.current_key_id()
        )));
    }

    restart_and_login(campaign, "old login-index entry migrated")?;
    stop_coordinator(campaign)?;
    let migrated = configured_state(fixture)?;
    if migrated.key_state.current_generation() != next_generation
        || migrated.key_state.current_key_id() != started.key_state.current_key_id()
        || migrated.key_state.previous() != Some((previous_generation, 0))
        || migrated.entries != before.entries
    {
        return Err(failure(
            "live login did not migrate the existing index entry",
        ));
    }
    let finish_commit = command_commit(rotation(fixture, None)?)?;
    install_key_mapping(fixture, &next_file, false)?;
    let finished = configured_state(fixture)?;
    let finish_closed = finish_commit
        .checked_add(1)
        .ok_or("finish checkpoint overflow")?;
    if finished.commit != finish_closed
        || finished.commit <= migrated.commit
        || finished.key_state.previous().is_some()
        || finished.key_state.current_generation() != next_generation
        || finished.key_state.current_key_id() != started.key_state.current_key_id()
        || finished.entries != before.entries
    {
        return Err(failure(
            "rotation finish did not commit the exact stable key state",
        ));
    }
    restart_and_login(campaign, "completed login-index rotation verified")?;
    campaign.shared.maintenance.store(false, Ordering::Relaxed);
    campaign.scenarios.index_transition = campaign
        .scenarios
        .index_transition
        .checked_add(1)
        .ok_or("rotation scenario count overflow")?;
    campaign.note(format!(
        "login-index rotation: generation {previous_generation} -> {next_generation}; start commit {}; finish commit {}",
        start_commit, finish_commit
    ));
    Ok(())
}

fn stop_coordinator(campaign: &mut Campaign<'_>) -> TestResult {
    let status = campaign.nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    Ok(())
}

fn restart_and_login(campaign: &mut Campaign<'_>, reason: &str) -> TestResult {
    let before_a = links_established(&campaign.network.edge_a);
    let before_b = links_established(&campaign.network.edge_b);
    campaign
        .nodes
        .restart_coordinator(&campaign.network.coordinator.config_path)?;
    campaign.wait_relinks(before_a, before_b)?;
    let mut client = campaign.opaque_login(1)?;
    client.send(&format!("QUIT :{reason}"))?;
    Ok(())
}

fn command_commit(output: std::process::Output) -> TestResult<u64> {
    if !output.status.success() {
        return Err(failure(format!(
            "rotation command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let text = std::str::from_utf8(&output.stdout)?;
    let mut values = text
        .lines()
        .flat_map(|line| line.split("; "))
        .filter_map(|field| field.strip_prefix("storage commit sequence: "));
    let commit = values
        .next()
        .ok_or_else(|| failure("missing rotation receipt"))?
        .parse()?;
    if values.next().is_some() {
        return Err(failure("ambiguous rotation receipt"));
    }
    Ok(commit)
}

fn read_key(path: &Path) -> TestResult<[u8; 32]> {
    let bytes = fs::read(path)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| failure("login-index key file has the wrong length"))
}

fn configured_state(fixture: &NodeFixture) -> TestResult<State> {
    let configured = agenc_ircd_config::load_maintenance_config(&fixture.config_path)?;
    let current = read_key(&configured.login_index_key_file)?;
    let previous = configured
        .login_index_previous_key_file
        .as_deref()
        .map(read_key)
        .transpose()?;
    inspect(fixture, current, previous)
}

fn inspect(
    fixture: &NodeFixture,
    current: [u8; 32],
    previous: Option<[u8; 32]>,
) -> TestResult<State> {
    let owner = open_owner(fixture, current, previous)?;
    let result = (|| {
        let recovered = owner.recovered_state();
        let keys = KeyDeriver::new(
            StorageMasterKey::from_bytes([fixture.seed.wrapping_add(7); 32]),
            recovered.database_binding(),
            recovered.storage_key_generation(),
        )?;
        Ok(State {
            commit: recovered.storage_commit_sequence(),
            entries: recovered.table_record_count(TableId::LoginIndex),
            key_state: LoginIndexKeyState::decode(&read_plaintext(
                &owner,
                &keys,
                TableId::LoginIndexKeyState,
                StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            )?)?,
        })
    })();
    owner.shutdown()?;
    result
}
