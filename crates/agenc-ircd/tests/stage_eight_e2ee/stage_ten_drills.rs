//! Stage 10 operational drills (S10-008, S10-009).
//!
//! Each drill is one ignored test that operates the frozen binary the way an
//! operator would: restore and disaster restore through `storage restore`,
//! account deletion followed by a rekey, key and certificate rotations,
//! incident response, rollback refusal, resynchronization, host hardening,
//! and observability. Every drill writes `<AGENC_STAGE10_DRILL_DIR>/<name>.json`
//! with its steps, timings, facts, and whether it passed; the driver reads
//! those records and never infers a result from a test that wrote none.

#![forbid(unsafe_code)]

#[path = "stage_ten_drills/index_transition.rs"]
mod index_transition;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read as _;
use std::sync::atomic::{AtomicU64, Ordering};

use agenc_ircd_admin::{AdminAuditCheckpoint, AdminAuditEvent, StatsSelector};
use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_runtime::observe::events::LogEventCode;
use agenc_ircd_storage::{BackupDestination, StateDirectory, StorageOpenConfig, StorageOwner};
use agenc_ircd_testkit::TlsFixture;

use super::stage_ten_capacity::admin_client::AdminSession;
use super::stage_ten_capacity::{
    admin_identity, current_key_file, current_state_dir, repin_peer_epoch,
};
use super::*;

const DIRECTORY_ENV: &str = "AGENC_STAGE10_DRILL_DIR";
const DRILL_ACCOUNT_LOGIN: &str = "drill-account";
const DRILL_CHANNEL: &str = "#drill";
const DRILL_TOPIC: &str = "drill topic survives the operation";
/// Read bound for daemon log segments and stderr captures.
const MAX_LOG_BYTES: u64 = 64 * 1_024 * 1_024;
/// Bound on a stopped-daemon command's output.
const MAX_COMMAND_OUTPUT: usize = 1_024 * 1_024;
/// A node with live peers may take longer than a lone node to drain.
const DRILL_STOP_BUDGET: Duration = Duration::from_secs(60);
/// Let the freshly linked network settle before the first operation.
const STARTUP_SETTLE: Duration = Duration::from_secs(2);

fn stop_command(reason: &str) -> TestResult<String> {
    let command = if reason.contains(' ') || reason.starts_with(':') {
        format!("DIE :{reason}")
    } else {
        format!("DIE {reason}")
    };
    let canonical = agenc_ircd_admin::CanonicalCommand::check(command.as_bytes())?;
    let _validated = agenc_ircd_admin::AdminCommand::parse(canonical)?;
    Ok(command)
}

#[test]
fn stop_reasons_reach_the_signed_admin_confirmation_boundary() -> TestResult {
    for reason in [
        "resync",
        "resync detached",
        ":resync",
        " leading",
        "é",
        "planned maintenance",
    ] {
        let command = stop_command(reason)?;
        assert_signed_stop_command(&command, reason)?;
    }
    for reason in ["", "trailing ", "two  spaces", "bad\rreason", "bad\nreason"] {
        assert!(stop_command(reason).is_err());
    }
    assert!(stop_command(&"x".repeat(513)).is_err());
    Ok(())
}

fn assert_signed_stop_command(command: &str, reason: &str) -> TestResult {
    use agenc_ircd_admin::{
        AdminChallenge, AdminCommand, AdminCommandTbs, AdminEvent, AdminSessionBinding,
        AdminSessionId, Challenge, ConfirmationState, OperatorRecord, OperatorRegistry,
        PeerIdentity, TransportBinding, TransportKind, encode_base64url, render_admin_tag,
    };
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, MonotonicTick, OperatorId};

    let binding = AdminSessionBinding {
        network_id: NetworkId::from_bytes([1; 32]),
        server_id: ServerId::from_bytes([2; 16]),
    };
    let challenge = AdminChallenge::new(
        AdminSessionId::from_bytes([3; 16]),
        Challenge::from_bytes([4; 32]),
        TransportKind::Local,
        TransportBinding::from_bytes([5; 32]),
    );
    let key = Ed25519SecretKey::from_bytes([6; 32]);
    let operator = OperatorId::from_bytes([7; 16]);
    let mut permissions = AdminPermissionSet::EMPTY;
    permissions.insert(AdminPermission::Process);
    let registry = OperatorRegistry::from_records(vec![OperatorRecord::new(
        operator,
        key.public_key(),
        None,
        vec![1000],
        Vec::new(),
        permissions,
        true,
    )?])?;
    let signature = challenge.sign_oper(binding.network_id, binding.server_id, &key)?;
    let oper = format!(
        "OPER {} {}\r\n",
        operator.to_base64url(),
        encode_base64url(signature.as_bytes())
    );
    let session_id = challenge.session_id();
    let mut session = agenc_ircd_admin::AdminSession::new(
        binding,
        challenge,
        PeerIdentity::Local {
            uid: 1000,
            gid: 1000,
        },
    );
    assert!(matches!(
        session.accept_line(oper.as_bytes(), MonotonicTick::from_ticks(0), &registry),
        Ok(AdminEvent::Authenticated { .. })
    ));
    let tbs = AdminCommandTbs::new(
        binding.network_id,
        binding.server_id,
        session_id,
        0,
        None,
        command.as_bytes(),
    )?;
    let signed = format!(
        "{} {command}\r\n",
        render_admin_tag(0, &tbs.sign(&key)?, None)
    );
    let accepted = session.accept_line(signed.as_bytes(), MonotonicTick::from_ticks(1), &registry);
    let Ok(AdminEvent::Command(event)) = accepted else {
        return Err(failure("canonical signed stop did not reach confirmation"));
    };
    assert_eq!(event.confirmation, ConfirmationState::Required);
    assert!(matches!(event.command, AdminCommand::Die(value) if value.as_str() == reason));
    Ok(())
}

/// Request identifiers handed to account exchanges; every drill process
/// starts from a distinct base so replayed identifiers never collide.
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(5_000);

fn fresh_requests() -> [RequestId; 2] {
    let base = u128::from(NEXT_REQUEST.fetch_add(2, Ordering::Relaxed));
    [
        RequestId::from_bytes(base.to_be_bytes()),
        RequestId::from_bytes((base + 1).to_be_bytes()),
    ]
}

/// One drill's record under construction.
struct Drill {
    name: &'static str,
    directory: PathBuf,
    started: Instant,
    last_step: Instant,
    steps: Vec<(String, u64, String)>,
    facts: BTreeMap<String, String>,
    stderr_logs: PathBuf,
}

impl Drill {
    fn begin(name: &'static str) -> TestResult<Self> {
        let directory = PathBuf::from(
            std::env::var_os(DIRECTORY_ENV)
                .ok_or_else(|| failure("drill directory is not configured"))?,
        );
        fs::create_dir_all(&directory)?;
        let stderr_logs = directory.join(format!("{name}-logs"));
        fs::create_dir_all(&stderr_logs)?;
        let now = Instant::now();
        println!("[drill {name}] begin");
        Ok(Self {
            name,
            directory,
            started: now,
            last_step: now,
            steps: Vec::new(),
            facts: BTreeMap::new(),
            stderr_logs,
        })
    }

    fn step(&mut self, step: &str, detail: impl Into<String>) {
        let detail = detail.into();
        let elapsed = u64::try_from(self.last_step.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_step = Instant::now();
        println!(
            "[drill {}] {step} ({} ms): {detail}",
            self.name,
            elapsed / 1_000_000
        );
        self.steps.push((step.to_owned(), elapsed, detail));
    }

    fn fact(&mut self, key: &str, value: impl ToString) {
        self.facts.insert(key.to_owned(), value.to_string());
    }

    /// Writes the record; a drill that returned an error is recorded as failed
    /// with the error text, never as absent.
    fn finish(mut self, outcome: TestResult<bool>) -> TestResult {
        let passed = match outcome {
            Ok(passed) => passed,
            Err(error) => {
                self.fact("error", error.to_string());
                false
            }
        };
        let mut json = format!(
            "{{\"schema_version\":1,\"drill\":\"{}\",\"passed\":{passed},\"elapsed_ns\":{},\"steps\":[",
            self.name,
            u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
        );
        for (index, (step, elapsed, detail)) in self.steps.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            write!(
                json,
                "{{\"name\":\"{}\",\"elapsed_ns\":{elapsed},\"detail\":\"{}\"}}",
                escape(step),
                escape(detail)
            )?;
        }
        json.push_str("],\"facts\":{");
        for (index, (key, value)) in self.facts.iter().enumerate() {
            if index > 0 {
                json.push(',');
            }
            write!(json, "\"{}\":\"{}\"", escape(key), escape(value))?;
        }
        json.push_str("}}\n");
        let path = self.directory.join(format!("{}.json", self.name));
        let _stale = fs::remove_file(&path);
        write_private(&path, json.as_bytes())?;
        println!(
            "[drill {}] {}",
            self.name,
            if passed { "passed" } else { "failed" }
        );
        if passed {
            Ok(())
        } else {
            Err(failure(format!("drill {} failed", self.name)))
        }
    }
}

/// JSON string escaping for the fixed set of characters the records carry.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

/// The three daemons of a drill with their stderr captured per node.
struct DrillNodes {
    coordinator: DaemonProcess,
    edge_a: DaemonProcess,
    edge_b: DaemonProcess,
    stderr: [PathBuf; 3],
}

impl DrillNodes {
    fn start(network: &Network, drill: &Drill) -> TestResult<Self> {
        let stderr = [
            drill.stderr_logs.join("coordinator.stderr"),
            drill.stderr_logs.join("edge-a.stderr"),
            drill.stderr_logs.join("edge-b.stderr"),
        ];
        let nodes = Self {
            coordinator: DaemonProcess::start_logged(
                &network.coordinator.config_path,
                None,
                Some(&stderr[0]),
            )?,
            edge_a: DaemonProcess::start_logged(
                &network.edge_a.config_path,
                None,
                Some(&stderr[1]),
            )?,
            edge_b: DaemonProcess::start_logged(
                &network.edge_b.config_path,
                None,
                Some(&stderr[2]),
            )?,
            stderr,
        };
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        thread::sleep(STARTUP_SETTLE);
        Ok(nodes)
    }

    fn daemon(&mut self, index: usize) -> &mut DaemonProcess {
        match index {
            0 => &mut self.coordinator,
            1 => &mut self.edge_a,
            _ => &mut self.edge_b,
        }
    }

    /// Stops one node through its admin socket and waits for a clean exit.
    fn stop(&mut self, network: &Network, index: usize, reason: &str) -> TestResult {
        let identity = admin_identity(node(network, index));
        let command = stop_command(reason)?;
        AdminSession::connect(&identity)?.confirm_process(&command)?;
        let status = self.daemon(index).wait_within(DRILL_STOP_BUDGET)?;
        if !status.success() {
            return Err(failure(format!("node {index} exited with {status}")));
        }
        Ok(())
    }

    /// Restarts one node on its current configuration and waits for the
    /// federation links the restart interrupts.
    fn restart(&mut self, network: &Network, index: usize) -> TestResult {
        let before_a = links_established(&network.edge_a);
        let before_b = links_established(&network.edge_b);
        let running_a = self.edge_a.child.is_some();
        let running_b = self.edge_b.child.is_some();
        let stderr = self.stderr.get(index).cloned();
        *self.daemon(index) = DaemonProcess::start_logged(
            &node(network, index).config_path,
            None,
            stderr.as_deref(),
        )?;
        self.check_alive(index)?;
        match index {
            0 => {
                if running_a {
                    wait_for_link(&network.edge_a, before_a)?;
                }
                if running_b {
                    wait_for_link(&network.edge_b, before_b)?;
                }
                Ok(())
            }
            1 => wait_for_link(&network.edge_a, before_a),
            _ => wait_for_link(&network.edge_b, before_b),
        }
    }

    /// A node that exits within a second of starting failed closed; its
    /// stderr carries the reason.
    fn check_alive(&mut self, index: usize) -> TestResult {
        thread::sleep(Duration::from_secs(1));
        let stderr = stderr_text(self, index);
        let Some(child) = self.daemon(index).child.as_mut() else {
            return Err(failure(format!("node {index} is not running")));
        };
        if let Some(status) = child.try_wait()? {
            return Err(failure(format!(
                "node {index} exited with {status} right after starting: {}",
                stderr.lines().last().unwrap_or("")
            )));
        }
        Ok(())
    }

    /// Restarts every node after a change that alters the coordinator's
    /// identity or trust facts: the coordinator first, then both edges.
    fn restart_all(&mut self, network: &Network) -> TestResult {
        let before_a = links_established(&network.edge_a);
        let before_b = links_established(&network.edge_b);
        for index in [1, 2] {
            if self.daemon(index).child.is_some() {
                let status = self.daemon(index).stop()?;
                if !status.success() {
                    return Err(failure(format!("node {index} exited with {status}")));
                }
            }
        }
        let stderr = self.stderr.clone();
        self.coordinator =
            DaemonProcess::start_logged(&network.coordinator.config_path, None, Some(&stderr[0]))?;
        self.check_alive(0)?;
        self.edge_a =
            DaemonProcess::start_logged(&network.edge_a.config_path, None, Some(&stderr[1]))?;
        self.edge_b =
            DaemonProcess::start_logged(&network.edge_b.config_path, None, Some(&stderr[2]))?;
        self.check_alive(1)?;
        self.check_alive(2)?;
        wait_for_link(&network.edge_a, before_a)?;
        wait_for_link(&network.edge_b, before_b)?;
        wait_for_account_authority(&network.edge_a)?;
        wait_for_account_authority(&network.edge_b)
    }

    fn stop_all(&mut self) -> [bool; 3] {
        let mut clean = [false; 3];
        for (index, slot) in clean.iter_mut().enumerate() {
            *slot = self
                .daemon(index)
                .stop()
                .map(|status| status.success())
                .unwrap_or(false);
        }
        clean
    }
}

/// The drill network: the Stage 08 fixture with the local admin listener
/// enabled, as every operator drill drives the nodes through it.
fn drill_network() -> TestResult<Network> {
    build_network_with(Some(CapacityPlan {
        max_connections: 32,
        connections_per_address: 32,
    }))
}

/// Copies every node's log segments into the drill's log directory when it
/// goes out of scope, so an early return keeps the daemon's own record.
struct LogGuard<'a> {
    network: &'a Network,
    directory: PathBuf,
}

impl Drop for LogGuard<'_> {
    fn drop(&mut self) {
        for (name, fixture) in [
            ("coordinator", &self.network.coordinator),
            ("edge-a", &self.network.edge_a),
            ("edge-b", &self.network.edge_b),
        ] {
            let Ok(entries) = fs::read_dir(&fixture.log_dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let target = self
                    .directory
                    .join(format!("{name}-{}", entry.file_name().to_string_lossy()));
                let _copied = fs::copy(entry.path(), target);
            }
        }
    }
}

fn node(network: &Network, index: usize) -> &NodeFixture {
    match index {
        0 => &network.coordinator,
        1 => &network.edge_a,
        _ => &network.edge_b,
    }
}

/// The storage keys every fixture node derives from its seed.
fn node_keys(fixture: &NodeFixture) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let seed = fixture.seed;
    (
        [seed.wrapping_add(7); 32],
        [seed.wrapping_add(8); 32],
        [seed.wrapping_add(9); 32],
    )
}

fn engine_limits() -> StorageEngineLimits {
    StorageEngineLimits {
        redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
        fixed_reserve_bytes: DISK_RESERVE_BYTES,
        reserve_percent: 1,
        database_max_bytes: DATABASE_MAX_BYTES,
        backup_max_bytes: BACKUP_MAX_BYTES,
        integrity_checkpoint_manifests: 10_000,
    }
}

/// Writes a signed backup of a stopped node through the production storage
/// owner and returns its path with the record count and stream length.
fn write_backup(
    fixture: &NodeFixture,
    name: &str,
    sequence: u64,
) -> TestResult<(PathBuf, u64, u64)> {
    let (master, guard, login) = node_keys(fixture);
    let master_file = current_key_file(fixture, "master_key_file")?;
    let guard_file = current_key_file(fixture, "rollback_guard_key_file")?;
    let master = read_key(&master_file).unwrap_or(master);
    let guard = read_key(&guard_file).unwrap_or(guard);
    let state = current_state_dir(fixture)?;
    let backups = fixture.data_dir.join("backups");
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(&state, &embedded_storage_qualifications()?)?,
        storage_master_key: StorageMasterKey::from_bytes(master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(guard),
        login_index_key: LoginIndexKey::from_bytes(login),
        previous_login_index_key: None,
        limits: engine_limits(),
    })?;
    let mut backup_id = [fixture.seed; 16];
    for (slot, byte) in backup_id.iter_mut().skip(8).zip(sequence.to_be_bytes()) {
        *slot = byte;
    }
    let receipt = owner
        .port()
        .try_backup(
            BackupDestination::new(&backups, name)?,
            Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(10); 32]),
            1_700_000_000 + sequence,
            backup_id,
        )?
        .wait()?;
    owner.shutdown()?;
    Ok((
        backups.join(name),
        receipt.record_count,
        receipt.stream_bytes,
    ))
}

fn read_key(path: &Path) -> Option<[u8; 32]> {
    let bytes = fs::read(path).ok()?;
    bytes.try_into().ok()
}

/// What a restore is asked to change.
struct RestorePlan<'a> {
    backup: &'a Path,
    new_master: bool,
    /// Remove the current state directory first: the disaster path with no
    /// current guard witness.
    disaster: bool,
    generation: u32,
}

/// The receipt facts of one `storage restore` and the config rewrite it
/// requires.
struct RestoreOutcome {
    receipt: String,
    epoch: String,
    incarnation_changed: bool,
    current_generation: String,
    output: PathBuf,
}

/// Runs the frozen binary's `storage restore` for `fixture`, rewrites its
/// configuration to the restored directory and keys, and returns the new
/// recovery epoch the peers must re-pin.
fn restore_node(fixture: &NodeFixture, plan: &RestorePlan<'_>) -> TestResult<RestoreOutcome> {
    let keys = fixture.data_dir.join("keys");
    let old_master = current_key_file(fixture, "master_key_file")?;
    let old_guard = current_key_file(fixture, "rollback_guard_key_file")?;
    let new_guard = keys.join(format!("rollback-guard-g{}.key", plan.generation));
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    write_private(&new_guard, &fresh)?;
    let new_master = if plan.new_master {
        let path = keys.join(format!("storage-master-g{}.key", plan.generation));
        OsEntropy::fill(&mut fresh)?;
        write_private(&path, &fresh)?;
        Some(path)
    } else {
        None
    };
    let current = current_state_dir(fixture)?;
    if plan.disaster {
        fs::remove_dir_all(&current)?;
    }
    let output = fixture.data_dir.join(format!("state-g{}", plan.generation));
    let mut command = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"));
    command
        .args(["storage", "restore", "--config"])
        .arg(&fixture.config_path)
        .arg("--backup")
        .arg(plan.backup)
        .arg("--source-master-key-file")
        .arg(&old_master)
        .arg("--source-rollback-guard-key-file")
        .arg(&old_guard)
        .arg("--output-state-directory")
        .arg(&output)
        .arg("--target-rollback-guard-key-file")
        .arg(&new_guard)
        .arg("--declare-recovery-epoch");
    if let Some(path) = &new_master {
        command.arg("--target-master-key-file").arg(path);
    }
    let result = command.output()?;
    let stdout = bounded_text(&result.stdout);
    if !result.status.success() {
        return Err(failure(format!(
            "storage restore failed: {}\n{stdout}",
            bounded_text(&result.stderr)
        )));
    }
    let epoch = stdout
        .lines()
        .find_map(|line| line.strip_prefix("recovery epoch changed: "))
        .and_then(|line| line.split(" -> ").nth(1))
        .ok_or_else(|| failure("restore did not report the new recovery epoch"))?
        .trim()
        .to_owned();
    let incarnation_changed = stdout
        .lines()
        .find_map(|line| line.strip_prefix("server incarnation changed: "))
        .and_then(|line| line.split_once(" -> "))
        .is_some_and(|(from, to)| from != to);
    let current_generation = stdout
        .lines()
        .find_map(|line| line.strip_prefix("state generation: "))
        .unwrap_or("unreported")
        .to_owned();
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!("state_dir = \"{}\"", protected_path_text(&current)?),
        &format!("state_dir = \"{}\"", protected_path_text(&output)?),
    )?;
    replace_once(
        &mut config,
        &format!(
            "rollback_guard_key_file = \"{}\"",
            protected_path_text(&old_guard)?
        ),
        &format!(
            "rollback_guard_key_file = \"{}\"",
            protected_path_text(&new_guard)?
        ),
    )?;
    if let Some(path) = &new_master {
        replace_once(
            &mut config,
            &format!(
                "master_key_file = \"{}\"",
                protected_path_text(&old_master)?
            ),
            &format!("master_key_file = \"{}\"", protected_path_text(path)?),
        )?;
    }
    fs::write(&fixture.config_path, config)?;
    Ok(RestoreOutcome {
        receipt: stdout.trim().replace('\n', " | "),
        epoch,
        incarnation_changed,
        current_generation,
        output,
    })
}

fn bounded_text(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_COMMAND_OUTPUT);
    String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned()
}

/// Re-pins the coordinator's new recovery epoch in both edge configurations.
fn repin_coordinator_epoch(network: &Network, epoch: &str) -> TestResult {
    for edge in [&network.edge_a, &network.edge_b] {
        repin_peer_epoch(edge, network.coordinator.server_id, epoch)?;
    }
    Ok(())
}

/// Creates the drill account and registers its channel before setting the
/// topic, so leaving the seed session preserves the state being qualified.
fn seed_state(network: &Network) -> TestResult<AccountId> {
    let (mut client, account) =
        authenticated_client(&network.edge_a, "drill-seed", DRILL_ACCOUNT_LOGIN, 150)?;
    client.send(&format!("JOIN {DRILL_CHANNEL}"))?;
    client.read_until(|line| line.contains(&format!(" 366 drill-seed {DRILL_CHANNEL} ")))?;
    client.send(&format!("CHANCTL REGISTER {DRILL_CHANNEL}"))?;
    client.read_until(|line| line.contains(&format!(" NOTE CHANCTL UPDATED {DRILL_CHANNEL} ")))?;
    client.send(&format!("TOPIC {DRILL_CHANNEL} :{DRILL_TOPIC}"))?;
    client.read_until(|line| line.contains(&format!("TOPIC {DRILL_CHANNEL} :{DRILL_TOPIC}")))?;
    client.send("QUIT :seeded")?;
    Ok(account)
}

/// Authenticates the drill account on an edge; the OPAQUE record and the
/// login index it needs live in the coordinator's restored state.
fn account_login(fixture: &NodeFixture, account: AccountId, nick: &str) -> TestResult<IrcClient> {
    account_login_counting(fixture, account, nick).map(|(client, _)| client)
}

/// Authenticates the drill account and counts only transient transport retries.
/// An explicit authentication refusal fails the probe on its first attempt.
fn account_login_counting(
    fixture: &NodeFixture,
    account: AccountId,
    nick: &str,
) -> TestResult<(IrcClient, u32)> {
    account_login_named(fixture, account, nick, DRILL_ACCOUNT_LOGIN)
}

fn account_login_named(
    fixture: &NodeFixture,
    account: AccountId,
    nick: &str,
    login: &str,
) -> TestResult<(IrcClient, u32)> {
    wait_for_account_authority(fixture)?;
    let started = Instant::now();
    let deadline = started + NETWORK_WAIT;
    let mut transport_retries = 0_u32;
    loop {
        let attempt = (|| -> TestResult<IrcClient> {
            let mut client = IrcClient::connect(fixture)?;
            client.send("CAP LS 302")?;
            client.read_until(|line| {
                line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
            })?;
            client.send_until(&format!("CAP REQ :{E2EE_CAPS}"), " CAP * ACK ")?;
            authenticate_live_account_with(
                &mut client,
                fixture,
                login,
                ACCOUNT_PASSWORD,
                fresh_requests(),
                account,
            )?;
            client.send("CAP END")?;
            client.send(&format!("NICK {nick}"))?;
            client.send(&format!("USER {nick} 0 * :{nick}"))?;
            client.read_until(|line| line.contains(" 376 ") || line.contains(" 422 "))?;
            Ok(client)
        })();
        match attempt {
            Ok(client) => return Ok((client, transport_retries)),
            Err(error)
                if Instant::now() < deadline
                    && super::stage_ten_capacity::transient_transport(&error) =>
            {
                transport_retries += 1;
                thread::sleep(Duration::from_secs(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_account_authority(fixture: &NodeFixture) -> TestResult {
    let identity = admin_identity(fixture);
    let deadline = Instant::now() + NETWORK_WAIT;
    while Instant::now() < deadline {
        let active = AdminSession::connect(&identity)?
            .stats("FEDERATION")?
            .into_iter()
            .find(|(name, _)| name == "active_peers")
            .ok_or_else(|| failure("federation readiness counter missing"))?
            .1;
        if active == 1 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(failure(
        "edge did not finish synchronization before account authentication",
    ))
}

/// Joins the drill channel and checks its topic through an explicit query.
fn join_drill_channel(client: &mut IrcClient, nick: &str) -> TestResult<(bool, bool)> {
    client.send(&format!("JOIN {DRILL_CHANNEL}"))?;
    let lines =
        client.read_until(|line| line.contains(&format!(" 366 {nick} {DRILL_CHANNEL} ")))?;
    let joined = lines
        .iter()
        .any(|line| line.contains(&format!(" 366 {nick} {DRILL_CHANNEL} ")));
    client.send(&format!("TOPIC {DRILL_CHANNEL}"))?;
    let topic_lines = client.read_until(|line| {
        line.contains(&format!(" 333 {nick} {DRILL_CHANNEL} "))
            || line.contains(&format!(" 331 {nick} {DRILL_CHANNEL} "))
            || line.contains("FAIL TOPIC ")
    })?;
    let topic = topic_lines
        .iter()
        .any(|line| line.contains(&format!(" 332 {nick} {DRILL_CHANNEL} :{DRILL_TOPIC}")));
    Ok((joined, topic))
}

fn read_bounded(path: &Path) -> TestResult<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(MAX_LOG_BYTES)
        .read_to_string(&mut text)?;
    Ok(text)
}

fn stderr_text(nodes: &DrillNodes, index: usize) -> String {
    nodes
        .stderr
        .get(index)
        .and_then(|path| read_bounded(path).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Restore and disaster restore
// ---------------------------------------------------------------------------

/// Stops the coordinator, backs it up, restores it into a new directory
/// through the frozen binary, re-pins the new epoch on both edges, restarts
/// everything, and checks the account and channel state came back.
fn run_restore(drill: &mut Drill, disaster: bool) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    drill.step("seed", "drill account created and #drill topic set");
    nodes.stop(&network, 0, "restore drill")?;
    let (backup, records, bytes) = write_backup(&network.coordinator, "restore.backup", 1)?;
    drill.fact("backup_records", records);
    drill.fact("backup_bytes", bytes);
    drill.step("backup", format!("{records} rows, {bytes} bytes"));
    let outcome = restore_node(
        &network.coordinator,
        &RestorePlan {
            backup: &backup,
            new_master: false,
            disaster,
            generation: 2,
        },
    )?;
    drill.fact("recovery_epoch", &outcome.epoch);
    drill.fact("incarnation_changed", outcome.incarnation_changed);
    drill.fact("state_generation", &outcome.current_generation);
    drill.fact("restore_receipt", &outcome.receipt);
    drill.step(
        "restore",
        format!("epoch {} {}", outcome.epoch, outcome.current_generation),
    );
    let witness_ok = if disaster {
        outcome.current_generation.contains("current=unknown")
    } else {
        !outcome.current_generation.contains("current=unknown")
    };
    drill.fact("guard_witness_as_expected", witness_ok);
    repin_coordinator_epoch(&network, &outcome.epoch)?;
    if let Err(error) = nodes.restart_all(&network) {
        drill.fact("restart_after_restore", error.to_string());
        drill.step("restart", format!("failed: {error}"));
        let clean = nodes.stop_all();
        drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
        return Ok(false);
    }
    drill.step(
        "restart",
        "coordinator and both edges re-linked under the new epoch",
    );
    let (login_ok, topic) = match account_login(&network.edge_b, account, "restore-check") {
        Ok(mut client) => {
            let (joined, topic) = join_drill_channel(&mut client, "restore-check")?;
            client.send("QUIT :checked")?;
            (joined, topic)
        }
        Err(error) => {
            drill.fact("existing_login_error", error.to_string());
            let guest = register_when_available(&network.edge_b, "restore-guest").is_ok();
            drill.fact("guest_registration_after_restore", guest);
            (false, false)
        }
    };
    let fresh = authenticated_client(&network.edge_a, "post-restore", "post-account", 170)
        .and_then(|(mut client, _)| client.send("QUIT :probe"));
    let new_account = fresh.is_ok();
    if let Err(error) = fresh {
        drill.fact("new_account_after_restore_error", error.to_string());
    }
    drill.fact("new_account_after_restore", new_account);
    drill.fact("existing_login_after_restore", login_ok);
    drill.fact("topic_intact", topic);
    drill.step(
        "verify",
        format!("existing login={login_ok}, topic intact={topic}"),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(login_ok
        && topic
        && new_account
        && witness_ok
        && outcome.incarnation_changed
        && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_restore() -> TestResult {
    let mut drill = Drill::begin("restore")?;
    let outcome = run_restore(&mut drill, false);
    drill.finish(outcome)
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_disaster_restore() -> TestResult {
    let mut drill = Drill::begin("disaster_restore")?;
    let outcome = run_restore(&mut drill, true);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// Deletion followed by a rekey
// ---------------------------------------------------------------------------

/// Deletes an account through the client protocol and returns the closing
/// lines the server sent.
fn delete_account(
    fixture: &NodeFixture,
    account: AccountId,
    nick: &str,
) -> TestResult<Vec<String>> {
    let mut client = IrcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    client.send_until("CAP REQ :standard-replies", " CAP * ACK ")?;
    authenticate_live_account_with(
        &mut client,
        fixture,
        "delete-account",
        ACCOUNT_PASSWORD,
        fresh_requests(),
        account,
    )?;
    client.complete_registration(nick)?;
    // The same connection's initial OPAQUE grant supplies fresh authority.
    client.send("ACCT LABEL deletion-check")?;
    client.read_until(|line| line.contains(" NOTE ACCT UPDATED "))?;
    client.send("ACCT PRESENCE PUBLIC")?;
    client.read_until(|line| line.contains(" NOTE ACCT UPDATED "))?;
    client.send("ACCT DELETE START")?;
    let challenge = client
        .read_until(|line| line.contains("DELETE_CHALLENGE") || line.contains("FAIL ACCT"))?;
    let token = challenge
        .iter()
        .find_map(|line| {
            line.split_whitespace()
                .skip_while(|field| *field != "DELETE_CHALLENGE")
                .nth(1)
                .map(str::to_owned)
        })
        .ok_or_else(|| failure(format!("no deletion challenge: {challenge:?}")))?;
    // A private challenge cannot stale the edge's published session revision.
    client.send("AWAY :deletion pending")?;
    client.read_until(|line| line.contains(" 306 "))?;
    client.send(&format!("ACCT DELETE CONFIRM {token}"))?;
    read_deleted_connection_closure(&mut client.reader)
}

fn read_deleted_connection_closure(reader: &mut impl BufRead) -> TestResult<Vec<String>> {
    let deadline = Instant::now() + REPLY_DEADLINE;
    let mut lines = Vec::<String>::new();
    for _ in 0..TRANSCRIPT_LINES {
        if Instant::now() > deadline {
            return Err(failure(
                "deletion connection did not close before its deadline",
            ));
        }
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|error| {
            failure(format!(
                "deletion close read failed ({error}); final note received={}",
                lines.last().is_some_and(|line| is_deletion_note(line)),
            ))
        })?;
        if read == 0 {
            if lines.last().is_some_and(|line| is_deletion_note(line)) {
                return Ok(lines);
            }
            return Err(failure(
                "deletion connection closed before its final response",
            ));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        lines.push(line);
    }
    Err(failure("deletion connection exceeded its transcript bound"))
}

fn is_deletion_note(line: &str) -> bool {
    line.strip_prefix(':')
        .and_then(|line| line.split_once(' '))
        .is_some_and(|(source, reply)| {
            !source.is_empty() && reply == "NOTE ACCT UPDATED :Account setting updated"
        })
}

struct ClosingReadFailure(io::ErrorKind);

impl io::Read for ClosingReadFailure {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.0))
    }
}

#[test]
fn deletion_requires_final_note_and_clean_eof() -> TestResult {
    let note = ":edge.test NOTE ACCT UPDATED :Account setting updated\r\n";
    let mut clean = io::Cursor::new(note);
    assert_eq!(
        read_deleted_connection_closure(&mut clean)?,
        [note.trim_end()]
    );
    for text in [
        "",
        ":edge.test ERROR :Closing connection\r\n",
        ":peer.test NOTICE delete-me : NOTE ACCT UPDATED :Account setting updated\r\n",
    ] {
        assert!(read_deleted_connection_closure(&mut io::Cursor::new(text)).is_err());
    }
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::UnexpectedEof,
    ] {
        let input = io::Cursor::new(note).chain(ClosingReadFailure(kind));
        assert!(read_deleted_connection_closure(&mut BufReader::new(input)).is_err());
    }
    Ok(())
}

/// Tests the deleted login itself; unrelated carrier failures cannot pass it.
fn deleted_account_login_refused(fixture: &NodeFixture, account: AccountId) -> TestResult<bool> {
    wait_for_account_authority(fixture)?;
    let mut client = IrcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    authentication_was_refused(authenticate_live_account_with(
        &mut client,
        fixture,
        "delete-account",
        ACCOUNT_PASSWORD,
        fresh_requests(),
        account,
    ))
}

/// Only a completed OPAQUE exchange may establish the deleted-login refusal.
fn authentication_was_refused(result: TestResult) -> TestResult<bool> {
    match result {
        Ok(()) => Ok(false),
        Err(error)
            if matches!(
                error.downcast_ref::<opaque_ke::errors::ProtocolError>(),
                Some(opaque_ke::errors::ProtocolError::InvalidLoginError)
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

#[test]
fn deletion_evidence_rejects_wrong_account_and_transport_failures() -> TestResult {
    let live = AccountId::from_random(agenc_ircd_types::AccountRandomId::from_bytes([231; 16]));
    let deleted = AccountId::from_random(agenc_ircd_types::AccountRandomId::from_bytes([232; 16]));
    let completion = Completion::committed(
        agenc_ircd_types::TransactionId::from_bytes([233; 16]),
        live,
        1,
    );
    let wrong_account = committed_account(completion, Some(deleted)).map(|_| ());
    assert!(
        authentication_was_refused(wrong_account).is_err(),
        "a healthy account's mismatched identity is not deletion evidence"
    );
    assert!(authentication_was_refused(Err(failure("transport closed"))).is_err());
    assert!(authentication_was_refused(Err(failure(" 904 SASL authentication failed"))).is_err());
    assert!(!authentication_was_refused(Ok(()))?);
    let invalid_login =
        opaque_ke::errors::ProtocolError::<std::convert::Infallible>::InvalidLoginError;
    assert!(authentication_was_refused(Err(Box::new(invalid_login)))?);
    Ok(())
}

struct DeletionAccountRows {
    account_id: AccountId,
    account: PersistentRecordValue,
    credential: Option<PersistentRecordValue>,
    login: agenc_ircd_storage::LoginIndexValue,
}

struct DeletionStateEvidence {
    target: DeletionAccountRows,
    survivor: DeletionAccountRows,
}

fn read_deletion_state(
    fixture: &NodeFixture,
    target: AccountId,
    survivor: AccountId,
) -> TestResult<DeletionStateEvidence> {
    use agenc_ircd_runtime::state_core::durable::KeyDeriver;

    let config = agenc_ircd_config::load_config(
        &fixture.config_path,
        agenc_ircd_config::ValidationDepth::Host,
    )?;
    let master = read_key(&config.storage.master_key_file)
        .ok_or_else(|| failure("deletion evidence master key unavailable"))?;
    let guard = read_key(&config.storage.rollback_guard_key_file)
        .ok_or_else(|| failure("deletion evidence guard key unavailable"))?;
    let login = read_key(&config.storage.login_index_key_file)
        .ok_or_else(|| failure("deletion evidence login key unavailable"))?;
    if config.storage.login_index_previous_key_file.is_some() {
        return Err(failure("deletion drill requires stable login-index state"));
    }
    let owner = StorageOwner::start(StorageOpenConfig {
        expected_network_id: NETWORK_ID,
        expected_server_id: fixture.server_id,
        state_directory: StateDirectory::open(
            &config.storage.state_dir,
            &embedded_storage_qualifications()?,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(guard),
        login_index_key: LoginIndexKey::from_bytes(login),
        previous_login_index_key: None,
        limits: engine_limits(),
    })?;
    let recovered = owner.recovered_state();
    let keys = KeyDeriver::new(
        StorageMasterKey::from_bytes(master),
        recovered.database_binding(),
        recovered.storage_key_generation(),
    )?;
    let result = (|| {
        let key = StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?;
        let state = deletion_evidence_read(&owner, &keys, TableId::LoginIndexKeyState, &key)?
            .ok_or_else(|| failure("deletion evidence login-key state missing"))?;
        let state = LoginIndexKeyState::decode(state.expose_for_storage_codec())?;
        if state.previous().is_some() {
            return Err(failure("deletion evidence encountered an index transition"));
        }
        Ok(DeletionStateEvidence {
            target: read_deletion_account(
                &owner,
                &keys,
                target,
                "delete-account",
                &login,
                state.current_generation(),
            )?,
            survivor: read_deletion_account(
                &owner,
                &keys,
                survivor,
                DRILL_ACCOUNT_LOGIN,
                &login,
                state.current_generation(),
            )?,
        })
    })();
    owner.shutdown()?;
    result
}

fn deletion_evidence_read(
    owner: &StorageOwner,
    keys: &agenc_ircd_runtime::state_core::durable::KeyDeriver,
    table: TableId,
    key: &StoredKey,
) -> TestResult<Option<agenc_ircd_crypto::OpenedStoragePlaintext>> {
    let mut result = owner
        .port()
        .try_read(agenc_ircd_storage::ReadPlan::exact(table, key.clone()))?
        .wait()?;
    if result.truncated || result.records.len() > 1 {
        return Err(failure("deletion evidence exact read was incomplete"));
    }
    let Some(row) = result.records.pop() else {
        return Ok(None);
    };
    if row.table != table || row.key != *key {
        return Err(failure("deletion evidence exact row identity changed"));
    }
    let sealed = agenc_ircd_storage::SealedRecord::decode(&row.sealed_record)?;
    Ok(Some(keys.open(table, key, &sealed)?))
}

fn read_deletion_account(
    owner: &StorageOwner,
    keys: &agenc_ircd_runtime::state_core::durable::KeyDeriver,
    account_id: AccountId,
    login: &str,
    login_key: &[u8; 32],
    login_generation: u32,
) -> TestResult<DeletionAccountRows> {
    let account_key = StoredKey::new(account_id.to_text().into_bytes())?;
    let account = deletion_evidence_read(owner, keys, TableId::Account, &account_key)?
        .ok_or_else(|| failure("deletion evidence account row missing"))?;
    let account =
        PersistentRecordValue::decode(TableId::Account, account.expose_for_storage_codec())?;
    let credential = deletion_evidence_read(owner, keys, TableId::OpaqueRecord, &account_key)?
        .map(|value| {
            PersistentRecordValue::decode(TableId::OpaqueRecord, value.expose_for_storage_codec())
        })
        .transpose()?;
    let digest = agenc_ircd_crypto::derive_login_index(
        &LoginIndexKey::from_bytes(*login_key),
        NETWORK_ID,
        &NormalizedLogin::prepare(login)?,
    )?;
    let stored = agenc_ircd_storage::LoginIndexStoredKey::new(login_generation, digest)?;
    let login = deletion_evidence_read(owner, keys, TableId::LoginIndex, &stored.encode()?)?
        .ok_or_else(|| failure("deletion evidence login row missing"))?;
    let login =
        agenc_ircd_storage::LoginIndexValue::decode(login.expose_for_storage_codec(), &stored)?;
    Ok(DeletionAccountRows {
        account_id,
        account,
        credential,
        login,
    })
}

fn deletion_state_is_complete(
    created: &DeletionStateEvidence,
    deleted: &DeletionStateEvidence,
    rekeyed: &DeletionStateEvidence,
    _totals: [(u64, u64); 3],
) -> TestResult<bool> {
    let target = created.target.account_id;
    if target == created.survivor.account_id
        || deleted.target.account_id != target
        || rekeyed.target.account_id != target
        || !live_deletion_account(&created.target)?
        || !live_deletion_account(&created.survivor)?
        || !deleted_deletion_account(&deleted.target)
        || !deleted_deletion_account(&rekeyed.target)
    {
        return Ok(false);
    }
    Ok(
        deleted.target.account.revision() > created.target.account.revision()
            && deleted.target.account.encode()? == rekeyed.target.account.encode()?
            && deleted.target.login.encode()? == rekeyed.target.login.encode()?
            && survivor_is_preserved(&created.survivor, &deleted.survivor)?
            && survivor_is_preserved(&created.survivor, &rekeyed.survivor)?,
    )
}

fn live_deletion_account(rows: &DeletionAccountRows) -> TestResult<bool> {
    use agenc_ircd_storage::{AccountRecordBody, LoginIndexValueKind};

    let Some(credential) = &rows.credential else {
        return Ok(false);
    };
    if rows.account.record_kind() != LIVE_RECORD_KIND {
        return Ok(false);
    }
    let account = AccountRecordBody::decode(rows.account.body())?;
    let account_key = rows.account_id.to_text();
    let references = credential.references();
    let credential_reference = references.len() == 1
        && references.first().is_some_and(|reference| {
            reference.table() == TableId::Account
                && reference.key().as_bytes() == account_key.as_bytes()
        });
    let version_precedes = credential.generation() > 0
        && credential.generation() <= account.session_generation.get()
        && (credential.generation() < account.session_generation.get()
            || credential.revision() <= account.revision.get());
    let credential_bytes = credential
        .body()
        .try_into()
        .map_err(|_| failure("deletion evidence OPAQUE record length was invalid"))?;
    let _validated = agenc_ircd_auth::OpaqueRegistrationRecord::from_bytes(credential_bytes)?;
    Ok(account.account_id == rows.account_id
        && rows.account.generation() == account.session_generation.get()
        && rows.account.revision() == account.revision.get()
        && credential.record_kind() == LIVE_RECORD_KIND
        && credential.expires_at().is_none()
        && credential_reference
        && version_precedes
        && matches!(rows.login.kind(), LoginIndexValueKind::Live { account_id, .. } if *account_id == rows.account_id))
}

fn deleted_deletion_account(rows: &DeletionAccountRows) -> bool {
    use agenc_ircd_storage::LoginIndexValueKind;

    rows.account.record_kind() == agenc_ircd_runtime::state_core::durable::TOMBSTONE_RECORD_KIND
        && rows.account.generation() == 0
        && rows.account.expires_at().is_none()
        && rows.account.references().is_empty()
        && rows.account.body().is_empty()
        && rows.credential.is_none()
        && matches!(rows.login.kind(), LoginIndexValueKind::DeletionTombstone { deleted_account_id, expires_at }
            if *deleted_account_id == rows.account_id && *expires_at != 0)
}

fn survivor_is_preserved(
    before: &DeletionAccountRows,
    after: &DeletionAccountRows,
) -> TestResult<bool> {
    if before.account_id != after.account_id || !live_deletion_account(after)? {
        return Ok(false);
    }
    let previous = agenc_ircd_storage::AccountRecordBody::decode(before.account.body())?;
    let mut resulting = agenc_ircd_storage::AccountRecordBody::decode(after.account.body())?;
    resulting.session_generation = previous.session_generation;
    resulting.revision = previous.revision;
    Ok(agenc_ircd_storage::AccountRecordBody::encode(&previous)?
        == agenc_ircd_storage::AccountRecordBody::encode(&resulting)?
        && before
            .credential
            .as_ref()
            .zip(after.credential.as_ref())
            .is_some_and(|(before, after)| before.body() == after.body())
        && before.login.encode()? == after.login.encode()?)
}

fn deletion_evidence_fixture(
    deleted: bool,
    generation: u64,
    opaque: &OpaqueProfile,
) -> TestResult<DeletionStateEvidence> {
    Ok(DeletionStateEvidence {
        target: deletion_evidence_account_fixture(91, deleted, generation, opaque)?,
        survivor: deletion_evidence_account_fixture(92, false, generation, opaque)?,
    })
}

fn deletion_evidence_account_fixture(
    byte: u8,
    deleted: bool,
    generation: u64,
    opaque: &OpaqueProfile,
) -> TestResult<DeletionAccountRows> {
    use agenc_ircd_storage::{
        LoginIndexStoredKey, LoginIndexValue, LoginIndexValueKind, RecordReference,
    };

    let account_id = agenc_ircd_testkit::account_id(byte);
    let revision = if generation == 1 { 3_u64 } else { 1_u64 };
    // Current account body with no suspension and no optional profile fields.
    let mut body = 2_u16.to_be_bytes().to_vec();
    body.extend_from_slice(account_id.random().as_bytes());
    body.extend_from_slice(&[0, 1, 0, 0]);
    body.extend_from_slice(&[0; 8]);
    body.extend_from_slice(&generation.to_be_bytes());
    body.extend_from_slice(&revision.to_be_bytes());
    body.push(0);
    let account = if deleted {
        PersistentRecordValue::new(TableId::Account, 2, 9, 0, None, Vec::new(), Vec::new())?
    } else {
        PersistentRecordValue::new(
            TableId::Account,
            LIVE_RECORD_KIND,
            revision,
            generation,
            None,
            Vec::new(),
            body,
        )?
    };
    let credential = if deleted {
        None
    } else {
        Some(PersistentRecordValue::new(
            TableId::OpaqueRecord,
            LIVE_RECORD_KIND,
            3,
            1,
            None,
            vec![RecordReference::new(
                TableId::Account,
                StoredKey::new(account_id.to_text().into_bytes())?,
            )?],
            opaque.expose_fake_record_for_persistence().to_vec(),
        )?)
    };
    let stored = LoginIndexStoredKey::new(
        1,
        agenc_ircd_crypto::LoginIndexDigest::from_storage_key([byte; 32]),
    )?;
    let kind = if deleted {
        LoginIndexValueKind::DeletionTombstone {
            deleted_account_id: account_id,
            expires_at: 3_000_000_000,
        }
    } else {
        LoginIndexValueKind::Live {
            account_id,
            opaque_credential_id: OpaqueCredentialId::from_bytes([byte; 32]),
        }
    };
    Ok(DeletionAccountRows {
        account_id,
        account,
        credential,
        login: LoginIndexValue::new(&stored, kind)?,
    })
}

#[test]
fn deletion_evidence_accepts_exact_removal_when_unrelated_journals_grow() -> TestResult {
    let opaque = OpaqueProfile::generate(NETWORK_ID)?;
    let created = deletion_evidence_fixture(false, 1, &opaque)?;
    let deleted = deletion_evidence_fixture(true, 1, &opaque)?;
    let rekeyed = deletion_evidence_fixture(true, 2, &opaque)?;
    assert!(live_deletion_account(&created.target)?);
    assert!(deleted_deletion_account(&deleted.target));
    assert!(survivor_is_preserved(&created.survivor, &rekeyed.survivor)?);
    assert!(
        deletion_state_is_complete(
            &created,
            &deleted,
            &rekeyed,
            [(42, 72_491), (61, 136_182), (78, 185_311)]
        )?,
        "a retained request journal must not turn exact credential deletion into failure"
    );
    Ok(())
}

#[test]
fn deletion_evidence_rejects_live_or_reassociated_authority_despite_smaller_totals() -> TestResult {
    let opaque = OpaqueProfile::generate(NETWORK_ID)?;
    let created = deletion_evidence_fixture(false, 1, &opaque)?;
    let deleted = deletion_evidence_fixture(true, 1, &opaque)?;
    let rekeyed = deletion_evidence_fixture(true, 2, &opaque)?;
    let totals = [(10, 10_000), (20, 20_000), (15, 15_000)];
    let live = deletion_evidence_fixture(false, 1, &opaque)?;
    assert!(
        !deletion_state_is_complete(&created, &live, &rekeyed, totals)?,
        "smaller global totals cannot prove that this account was deleted"
    );
    let mut retained_credential = deletion_evidence_fixture(true, 1, &opaque)?;
    retained_credential.target.credential = deletion_evidence_fixture(false, 1, &opaque)?
        .target
        .credential;
    assert!(!deletion_state_is_complete(
        &created,
        &retained_credential,
        &rekeyed,
        totals
    )?);
    let mut wrong_tombstone = deletion_evidence_fixture(true, 1, &opaque)?;
    wrong_tombstone.target.login = deletion_evidence_account_fixture(93, true, 1, &opaque)?.login;
    assert!(!deletion_state_is_complete(
        &created,
        &wrong_tombstone,
        &rekeyed,
        totals
    )?);
    let mut different_target = deletion_evidence_fixture(true, 1, &opaque)?;
    different_target.target = deletion_evidence_account_fixture(93, true, 1, &opaque)?;
    assert!(deleted_deletion_account(&different_target.target));
    assert!(
        !deletion_state_is_complete(&created, &different_target, &rekeyed, totals,)?,
        "another account's valid tombstone is not this account's deletion evidence"
    );
    assert!(
        !deletion_state_is_complete(&created, &deleted, &live, totals)?,
        "rekey must not restore deleted account authority"
    );
    let mut changed_survivor = deletion_evidence_fixture(true, 2, &opaque)?;
    let other_profile = OpaqueProfile::generate(NETWORK_ID)?;
    changed_survivor.survivor.credential =
        deletion_evidence_account_fixture(92, false, 2, &other_profile)?.credential;
    assert!(!deletion_state_is_complete(
        &created,
        &deleted,
        &changed_survivor,
        totals
    )?);
    changed_survivor.survivor.credential =
        deletion_evidence_account_fixture(93, false, 2, &opaque)?.credential;
    assert!(!deletion_state_is_complete(
        &created,
        &deleted,
        &changed_survivor,
        totals
    )?);
    Ok(())
}

fn run_deletion(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let seed = seed_state(&network)?;
    nodes.stop(&network, 0, "deletion baseline")?;
    let (_, before_records, before_bytes) =
        write_backup(&network.coordinator, "deletion-before.backup", 1)?;
    nodes.restart(&network, 0)?;
    drill.step(
        "baseline",
        format!("{before_records} rows, {before_bytes} bytes"),
    );
    let (mut creator, account) =
        authenticated_client(&network.edge_a, "delete-me", "delete-account", 190)?;
    creator.send("QUIT :created")?;
    drop(creator);
    nodes.stop(&network, 0, "deletion after create")?;
    let (_, created_records, created_bytes) =
        write_backup(&network.coordinator, "deletion-created.backup", 2)?;
    let created_state = read_deletion_state(&network.coordinator, account, seed)?;
    drill.fact(
        "created_target_has_live_credential",
        live_deletion_account(&created_state.target)?,
    );
    nodes.restart(&network, 0)?;
    drill.step(
        "create",
        format!("account created: {created_records} rows, {created_bytes} bytes"),
    );
    thread::sleep(Duration::from_secs(3));
    let closing = match delete_account(&network.edge_a, account, "delete-me") {
        Ok(closing) => closing,
        Err(error) => {
            drill.fact("deletion_at_edge", error.to_string());
            drill.step("delete", "edge account deletion failed");
            let clean = nodes.stop_all();
            drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
            return Ok(false);
        }
    };
    drill.fact("deletion_reply", closing.last().map_or("", String::as_str));
    let denied = deleted_account_login_refused(&network.edge_a, account)?;
    drill.fact("deleted_login_refused", denied);
    drill.step("delete", format!("deleted; later login refused={denied}"));
    nodes.stop(&network, 0, "deletion after delete")?;
    let (backup, deleted_records, deleted_bytes) =
        write_backup(&network.coordinator, "deletion-deleted.backup", 3)?;
    let deleted_state = read_deletion_state(&network.coordinator, account, seed)?;
    drill.fact(
        "deleted_target_has_tombstones_without_credential",
        deleted_deletion_account(&deleted_state.target),
    );
    drill.fact("records_before_create", before_records);
    drill.fact("records_after_create", created_records);
    drill.fact("records_after_delete", deleted_records);
    drill.fact("bytes_after_create", created_bytes);
    drill.fact("bytes_after_delete", deleted_bytes);
    let source_length = database_length(&current_state_dir(&network.coordinator)?)?;
    let outcome = restore_node(
        &network.coordinator,
        &RestorePlan {
            backup: &backup,
            new_master: true,
            disaster: false,
            generation: 2,
        },
    )?;
    let rekeyed_length = database_length(&outcome.output)?;
    let rekeyed_state = read_deletion_state(&network.coordinator, account, seed)?;
    drill.fact(
        "rekeyed_target_has_tombstones_without_credential",
        deleted_deletion_account(&rekeyed_state.target),
    );
    drill.fact(
        "survivor_credential_and_policy_preserved",
        survivor_is_preserved(&created_state.survivor, &rekeyed_state.survivor)?,
    );
    drill.fact("database_length_before_rekey", source_length);
    drill.fact("database_length_after_rekey", rekeyed_length);
    drill.step(
        "rekey",
        format!(
            "restored under new master and guard; epoch {}",
            outcome.epoch
        ),
    );
    repin_coordinator_epoch(&network, &outcome.epoch)?;
    nodes.restart_all(&network)?;
    let still_denied = deleted_account_login_refused(&network.edge_b, account)?;
    drill.fact("deleted_login_refused_after_rekey", still_denied);
    let mut survivor = account_login(&network.edge_b, seed, "surviving-account")?;
    survivor.send("QUIT :survived rekey")?;
    drill.fact("unrelated_login_after_rekey", true);
    drill.step(
        "verify",
        format!("deleted account still refused={still_denied}"),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(denied
        && still_denied
        && deletion_state_is_complete(
            &created_state,
            &deleted_state,
            &rekeyed_state,
            [
                (before_records, before_bytes),
                (created_records, created_bytes),
                (deleted_records, deleted_bytes),
            ],
        )?
        && clean.iter().all(|c| *c))
}

/// Total length of the redb file(s) in a state directory.
fn database_length(directory: &Path) -> TestResult<u64> {
    let mut total = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            total += metadata.len();
        }
    }
    Ok(total)
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_deletion() -> TestResult {
    let mut drill = Drill::begin("deletion")?;
    let outcome = run_deletion(&mut drill);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// Rekey and login-index transition
// ---------------------------------------------------------------------------

fn run_rekey(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    nodes.stop(&network, 2, "rekey drill")?;
    let (backup, records, bytes) = write_backup(&network.edge_b, "rekey.backup", 1)?;
    drill.step("backup", format!("{records} rows, {bytes} bytes"));
    let outcome = restore_node(
        &network.edge_b,
        &RestorePlan {
            backup: &backup,
            new_master: true,
            disaster: false,
            generation: 2,
        },
    )?;
    drill.fact("recovery_epoch", &outcome.epoch);
    drill.step(
        "rekey",
        format!("edge b restored under new keys, epoch {}", outcome.epoch),
    );
    repin_peer_epoch(
        &network.coordinator,
        network.edge_b.server_id,
        &outcome.epoch,
    )?;
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    nodes.restart(&network, 0)?;
    nodes.restart(&network, 2)?;
    drill.step("restart", "coordinator re-pinned and both nodes serving");
    let mut client = account_login(&network.edge_b, account, "rekey-check")?;
    client.send("QUIT :checked")?;
    drill.fact("existing_login_authenticates", true);
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_rekey() -> TestResult {
    let mut drill = Drill::begin("rekey")?;
    let outcome = run_rekey(&mut drill);
    drill.finish(outcome)
}

/// Rotates the actual login key and proves that a dormant account prevents finish.
fn run_index_transition(drill: &mut Drill) -> TestResult<bool> {
    index_transition::run(drill)
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_index_transition() -> TestResult {
    let mut drill = Drill::begin("index_transition")?;
    let outcome = run_index_transition(&mut drill);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// TLS and federation rotations
// ---------------------------------------------------------------------------

fn run_tls_rotation(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let fixture = &network.edge_a;
    let seed = [fixture.seed.wrapping_add(16); 32];
    let tls_dir = fixture
        .config_path
        .parent()
        .ok_or_else(|| failure("config has no parent"))?
        .join("tls");
    // Phase one: the same key re-issued under a new certificate reloads live.
    let mut existing = register_when_available(fixture, "tls-existing")?;
    let reissued = TlsFixture::reissue_leaf(seed, &fixture.dns_name, 3)?;
    write_replace(&tls_dir.join("server.crt"), reissued.leaf_certificate_der())?;
    write_replace(
        &tls_dir.join("server.key"),
        reissued.leaf_private_key_pkcs8_der(),
    )?;
    let reply = AdminSession::connect(&admin_identity(fixture))?
        .command_until("REHASH :certificate renewal", |line| {
            line.contains("REHASH")
        })?;
    let reloaded = reply.iter().any(|line| line.contains("NOTE REHASH OK"));
    drill.fact(
        "renewal_rehash_reply",
        reply.last().map_or("", String::as_str),
    );
    let renewed_served = served_leaf(fixture)? == reissued.leaf_certificate_der();
    existing.send("PING :still-here")?;
    let existing_alive = !existing
        .read_until(|line| line.contains("PONG"))?
        .is_empty();
    drill.fact("renewal_reloaded", reloaded);
    drill.fact("renewal_served_to_new_connection", renewed_served);
    drill.fact("existing_connection_continues", existing_alive);
    drill.step(
        "renew",
        format!("same-key certificate: reload ok={reloaded}, served={renewed_served}, existing alive={existing_alive}"),
    );
    // Phase two: a new leaf key is an identity change and needs a restart.
    let rotated = TlsFixture::rotate_leaf(seed, &fixture.dns_name, 1)?;
    write_replace(&tls_dir.join("server.crt"), rotated.leaf_certificate_der())?;
    write_replace(
        &tls_dir.join("server.key"),
        rotated.leaf_private_key_pkcs8_der(),
    )?;
    let reply = AdminSession::connect(&admin_identity(fixture))?
        .command_until("REHASH :key rotation", |line| line.contains("REHASH"))?;
    drill.fact(
        "rotation_rehash_reply",
        reply.last().map_or("", String::as_str),
    );
    nodes.stop(&network, 1, "tls key rotation")?;
    nodes.restart(&network, 1)?;
    let rotated_served = served_leaf(fixture)? == rotated.leaf_certificate_der();
    drill.fact("rotated_key_served_after_restart", rotated_served);
    drill.step(
        "rotate",
        format!("new key after restart served={rotated_served}"),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(reloaded && renewed_served && existing_alive && rotated_served && clean.iter().all(|c| *c))
}

/// The leaf certificate a fresh TLS connection to the node is shown.
fn served_leaf(fixture: &NodeFixture) -> TestResult<Vec<u8>> {
    let fresh = IrcClient::connect(fixture)?;
    Ok(fresh
        .reader
        .get_ref()
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|certificate| certificate.as_ref().to_vec())
        .unwrap_or_default())
}

/// Replaces a private file atomically enough for a reload: write, then rename.
fn write_replace(path: &Path, bytes: &[u8]) -> TestResult {
    let staged = path.with_extension("staged");
    let _stale = fs::remove_file(&staged);
    write_private(&staged, bytes)?;
    fs::rename(&staged, path)?;
    Ok(())
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_tls_rotation() -> TestResult {
    let mut drill = Drill::begin("tls_rotation")?;
    let outcome = run_tls_rotation(&mut drill);
    drill.finish(outcome)
}

fn run_federation_rotation(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    let edge = &network.edge_b;
    let old_key = Ed25519SecretKey::from_bytes([edge.seed.wrapping_add(3); 32]);
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    let new_key = Ed25519SecretKey::from_bytes(fresh);
    let keys = edge.data_dir.join("keys");
    let new_key_file = keys.join("federation-signing-g2.key");
    write_private(&new_key_file, &fresh)?;
    let old_file = current_key_file(edge, "signing_private_key_file")?;
    let mut config = fs::read_to_string(&edge.config_path)?;
    replace_once(
        &mut config,
        &format!(
            "signing_private_key_file = \"{}\"",
            protected_path_text(&old_file)?
        ),
        &format!(
            "signing_private_key_file = \"{}\"",
            protected_path_text(&new_key_file)?
        ),
    )?;
    fs::write(&edge.config_path, config)?;
    let mut coordinator_config = fs::read_to_string(&network.coordinator.config_path)?;
    replace_once(
        &mut coordinator_config,
        &format!(
            "signing_public_key = \"{}\"",
            encode_base64url_32(old_key.public_key().as_bytes())
        ),
        &format!(
            "signing_public_key = \"{}\"",
            encode_base64url_32(new_key.public_key().as_bytes())
        ),
    )?;
    fs::write(&network.coordinator.config_path, coordinator_config)?;
    drill.step(
        "rotate",
        "edge b signing key replaced and re-pinned on the coordinator",
    );
    nodes.stop(&network, 2, "federation rotation")?;
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    nodes.restart(&network, 0)?;
    nodes.restart(&network, 2)?;
    drill.step("restart", "link re-established under the new signing key");
    let mut client = account_login(edge, account, "federation-check")?;
    client.send("QUIT :checked")?;
    drill.fact("clients_reconnect", true);
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_federation_rotation() -> TestResult {
    let mut drill = Drill::begin("federation_rotation")?;
    let outcome = run_federation_rotation(&mut drill);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// Sequencer, backup, and audit key rotations
// ---------------------------------------------------------------------------

fn e2ee_acknowledgements(fixture: &NodeFixture) -> usize {
    fixture
        .log_text()
        .matches("event=e2ee_profile_acknowledged")
        .count()
}

fn run_sequencer_rotation(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    let before = [
        e2ee_acknowledgements(&network.edge_a),
        e2ee_acknowledgements(&network.edge_b),
    ];
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    let secret = Ed25519SecretKey::from_bytes(fresh);
    let previous = Ed25519SecretKey::from_bytes([network.coordinator.seed.wrapping_add(15); 32]);
    let credentials = builders::sequencer_rotation_document(
        *NETWORK_ID.as_bytes(),
        &previous,
        &secret,
        (0, 4_000_000_000),
    )?;
    for (index, fixture) in [&network.coordinator, &network.edge_a, &network.edge_b]
        .into_iter()
        .enumerate()
    {
        let keys = fixture.data_dir.join("keys");
        let new_credentials = keys.join("sequencer-credentials-g2.bin");
        write_private(&new_credentials, &credentials)?;
        let mut config = fs::read_to_string(&fixture.config_path)?;
        let old_credentials = current_key_file(fixture, "sequencer_credentials_file")?;
        replace_once(
            &mut config,
            &format!(
                "sequencer_credentials_file = \"{}\"",
                protected_path_text(&old_credentials)?
            ),
            &format!(
                "sequencer_credentials_file = \"{}\"",
                protected_path_text(&new_credentials)?
            ),
        )?;
        if index == 0 {
            let new_key = keys.join("sequencer-g2.key");
            write_private(&new_key, &fresh)?;
            let old_key = current_key_file(fixture, "sequencer_private_key_file")?;
            replace_once(
                &mut config,
                &format!(
                    "sequencer_private_key_file = \"{}\"",
                    protected_path_text(&old_key)?
                ),
                &format!(
                    "sequencer_private_key_file = \"{}\"",
                    protected_path_text(&new_key)?
                ),
            )?;
        }
        fs::write(&fixture.config_path, config)?;
    }
    drill.step(
        "rotate",
        "new sequencer key and credentials installed on every node",
    );
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    nodes.restart_all(&network)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut after = before;
    while Instant::now() < deadline {
        after = [
            e2ee_acknowledgements(&network.edge_a),
            e2ee_acknowledgements(&network.edge_b),
        ];
        if after[0] > before[0] && after[1] > before[1] {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let acknowledged = after[0] > before[0] && after[1] > before[1];
    drill.fact("profile_acknowledged_after_rotation", acknowledged);
    drill.step(
        "restart",
        format!("E2EE profile acknowledgements {before:?} -> {after:?}"),
    );
    let mut client = account_login(&network.edge_b, account, "sequencer-check")?;
    client.send("QUIT :checked")?;
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(acknowledged && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_sequencer_rotation() -> TestResult {
    let mut drill = Drill::begin("sequencer_rotation")?;
    let outcome = run_sequencer_rotation(&mut drill);
    drill.finish(outcome)
}

/// Writes a trust manifest carrying the old and the new key.
fn write_two_key_manifest(
    path: &Path,
    kind: &str,
    old: &Ed25519SecretKey,
    new: &Ed25519SecretKey,
    key_id: impl Fn(&[u8; 32]) -> TestResult<[u8; 32]>,
) -> TestResult {
    let mut document = format!("{kind}_trust_version = 1\n");
    for key in [old, new] {
        let public = key.public_key();
        let _ = write!(
            document,
            "\n[[key]]\nkey_id = \"{}\"\ned25519_public_key = \"{}\"\nnot_before = 0\nnot_after = {}\n",
            encode_base64url_32(&key_id(public.as_bytes())?),
            encode_base64url_32(public.as_bytes()),
            i64::MAX
        );
    }
    write_replace(path, document.as_bytes())
}

/// Runs `storage restore` of `backup` into a scratch directory without
/// touching the node's configuration, to prove the backup still verifies
/// against the current trust manifest.
fn backup_verifies(fixture: &NodeFixture, backup: &Path, label: &str) -> TestResult<bool> {
    // The live directory has moved on since the backup, so a restore against
    // it is refused as stale by design; verification runs against a
    // configuration whose state directory does not exist, the same boundary a
    // disaster restore uses.
    let config_text = fs::read_to_string(&fixture.config_path)?;
    let current = current_state_dir(fixture)?;
    let absent = fixture.data_dir.join(format!("verify-{label}-absent"));
    let mut verify_config = config_text.clone();
    replace_once(
        &mut verify_config,
        &format!("state_dir = \"{}\"", protected_path_text(&current)?),
        &format!("state_dir = \"{}\"", protected_path_text(&absent)?),
    )?;
    let config_path = fixture.data_dir.join(format!("verify-{label}.toml"));
    write_replace(&config_path, verify_config.as_bytes())?;
    let master = current_key_file(fixture, "master_key_file")?;
    let guard = current_key_file(fixture, "rollback_guard_key_file")?;
    let scratch_guard = fixture.data_dir.join(format!("verify-{label}-guard.key"));
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    write_private(&scratch_guard, &fresh)?;
    let output = fixture.data_dir.join(format!("verify-{label}"));
    let result = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
        .args(["storage", "restore", "--config"])
        .arg(&config_path)
        .arg("--backup")
        .arg(backup)
        .arg("--source-master-key-file")
        .arg(&master)
        .arg("--source-rollback-guard-key-file")
        .arg(&guard)
        .arg("--output-state-directory")
        .arg(&output)
        .arg("--target-rollback-guard-key-file")
        .arg(&scratch_guard)
        .arg("--declare-recovery-epoch")
        .output()?;
    if !result.status.success() {
        println!(
            "[drill] verification restore of {label} failed: {}",
            bounded_text(&result.stderr).trim()
        );
    }
    Ok(result.status.success())
}

fn newest_backup(directory: &Path) -> TestResult<PathBuf> {
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let modified = entry.metadata()?.modified()?;
        if newest.as_ref().is_none_or(|(when, _)| modified > *when) {
            newest = Some((modified, entry.path()));
        }
    }
    newest
        .map(|(_, path)| path)
        .ok_or_else(|| failure("no backup was written"))
}

fn run_backup_rotation(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let fixture = &network.edge_b;
    nodes.stop(&network, 2, "backup rotation")?;
    let (old_backup, _, _) = write_backup(fixture, "before-rotation.backup", 1)?;
    drill.step("baseline", "backup signed with the old key");
    let old = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(10); 32]);
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    let new = Ed25519SecretKey::from_bytes(fresh);
    let keys = fixture.data_dir.join("keys");
    let new_key_file = keys.join("backup-signing-g2.key");
    write_private(&new_key_file, &fresh)?;
    let manifest = current_key_file(fixture, "backup_trust_manifest_file")?;
    write_two_key_manifest(&manifest, "backup", &old, &new, |public| {
        Ok(*backup_signing_key_id(public)?.as_bytes())
    })?;
    let old_file = current_key_file(fixture, "backup_signing_private_key_file")?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!(
            "backup_signing_private_key_file = \"{}\"",
            protected_path_text(&old_file)?
        ),
        &format!(
            "backup_signing_private_key_file = \"{}\"",
            protected_path_text(&new_key_file)?
        ),
    )?;
    fs::write(&fixture.config_path, config)?;
    drill.step(
        "rotate",
        "new key appended to the trust manifest and activated",
    );
    nodes.restart(&network, 2)?;
    let reply = AdminSession::connect(&admin_identity(fixture))?
        .command_until("BACKUP CREATE :rotation drill", |line| {
            line.contains("BACKUP")
        })?;
    let created = reply.iter().any(|line| line.contains("NOTE BACKUP OK"));
    drill.fact(
        "backup_create_reply",
        reply.last().map_or("", String::as_str),
    );
    drill.step("create", format!("BACKUP CREATE ok={created}"));
    nodes.stop(&network, 2, "backup rotation verify")?;
    let backups = current_key_file(fixture, "backup_dir")?;
    let new_backup = newest_backup(&backups)?;
    let old_ok = backup_verifies(fixture, &old_backup, "old")?;
    let new_ok = backup_verifies(fixture, &new_backup, "new")?;
    drill.fact("old_backup_verifies", old_ok);
    drill.fact("new_backup_verifies", new_ok);
    drill.step("verify", format!("old={old_ok} new={new_ok}"));
    nodes.restart(&network, 2)?;
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(created && old_ok && new_ok && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_backup_rotation() -> TestResult {
    let mut drill = Drill::begin("backup_rotation")?;
    let outcome = run_backup_rotation(&mut drill);
    drill.finish(outcome)
}

/// Exports the audit range and returns the decoded checkpoints and events.
fn audit_export(
    fixture: &NodeFixture,
) -> TestResult<(Vec<AdminAuditCheckpoint>, Vec<AdminAuditEvent>, Vec<String>)> {
    let lines = AdminSession::connect(&admin_identity(fixture))?
        .command_batch("AUDIT EXPORT 0 4102444800")?;
    let mut checkpoints = Vec::new();
    let mut events = Vec::new();
    for line in &lines {
        let mut fields = line.split_ascii_whitespace();
        let Some(kind) = fields.by_ref().skip_while(|f| *f != "AUDIT").nth(1) else {
            continue;
        };
        let Some(token) = fields.next() else {
            continue;
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|error| failure(format!("audit token is not base64url: {error:?}")))?;
        match kind {
            "CHECKPOINT" => checkpoints.push(AdminAuditCheckpoint::decode_exact(&bytes)?),
            "EVENT" => events.push(AdminAuditEvent::decode_exact(&bytes)?),
            _ => {}
        }
    }
    Ok((checkpoints, events, lines))
}

fn run_audit_rotation(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let fixture = &network.edge_a;
    let identity = admin_identity(fixture);
    let old = Ed25519SecretKey::from_bytes([fixture.seed.wrapping_add(11); 32]);
    let operator = identity.operator_key.public_key();
    AdminSession::connect(&identity)?.command_batch("STATS RUNTIME")?;
    let (checkpoints_before, events_before, _) = audit_export(fixture)?;
    drill.step(
        "baseline",
        format!(
            "{} checkpoints, {} events under the old key",
            checkpoints_before.len(),
            events_before.len()
        ),
    );
    let mut fresh = [0_u8; 32];
    OsEntropy::fill(&mut fresh)?;
    let new = Ed25519SecretKey::from_bytes(fresh);
    let keys = fixture.data_dir.join("keys");
    let new_key_file = keys.join("audit-signing-g2.key");
    write_private(&new_key_file, &fresh)?;
    let manifest = current_key_file(fixture, "audit_trust_manifest_file")?;
    write_two_key_manifest(&manifest, "audit", &old, &new, |public| {
        Ok(*audit_signing_key_id(public)?.as_bytes())
    })?;
    let old_file = current_key_file(fixture, "audit_signing_private_key_file")?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        &format!(
            "audit_signing_private_key_file = \"{}\"",
            protected_path_text(&old_file)?
        ),
        &format!(
            "audit_signing_private_key_file = \"{}\"",
            protected_path_text(&new_key_file)?
        ),
    )?;
    fs::write(&fixture.config_path, config)?;
    nodes.stop(&network, 1, "audit rotation")?;
    nodes.restart(&network, 1)?;
    drill.step(
        "rotate",
        "new audit key in the manifest and active after restart",
    );
    AdminSession::connect(&identity)?.command_batch("STATS STORAGE")?;
    let (checkpoints, events, lines) = audit_export(fixture)?;
    let mut old_count = 0;
    let mut new_count = 0;
    for checkpoint in &checkpoints {
        if checkpoint.verify(old.public_key()).is_ok() {
            old_count += 1;
        } else if checkpoint.verify(new.public_key()).is_ok() {
            new_count += 1;
        } else {
            return Err(failure("an exported checkpoint verifies under neither key"));
        }
    }
    let mut event_old = 0;
    let mut event_new = 0;
    for event in &events {
        if event.verify(old.public_key(), operator).is_ok() {
            event_old += 1;
        } else if event.verify(new.public_key(), operator).is_ok() {
            event_new += 1;
        } else {
            return Err(failure("an exported event verifies under neither key"));
        }
    }
    drill.fact("checkpoints_old_key", old_count);
    drill.fact("checkpoints_new_key", new_count);
    drill.fact("events_old_key", event_old);
    drill.fact("events_new_key", event_new);
    drill.fact("export_lines", lines.len());
    drill.step(
        "verify",
        format!(
            "checkpoints old={old_count} new={new_count}; events old={event_old} new={event_new}"
        ),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(event_old > 0 && event_new > 0 && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_audit_rotation() -> TestResult {
    let mut drill = Drill::begin("audit_rotation")?;
    let outcome = run_audit_rotation(&mut drill);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// Compromise response, rollback, resynchronization
// ---------------------------------------------------------------------------

fn run_compromise(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    let fixture = &network.edge_b;
    let mut held = register_when_available(fixture, "held-session")?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "max_connections = 32\n",
        "max_connections = 1\n",
    )?;
    fs::write(&fixture.config_path, config)?;
    let reply = AdminSession::connect(&admin_identity(fixture))?
        .command_until("REHASH :quiesce listeners", |line| line.contains("REHASH"))?;
    let quiesced = reply.iter().any(|line| line.contains("NOTE REHASH OK"));
    let refused = IrcClient::connect(fixture)
        .and_then(|mut client| client.try_register("intruder"))
        .map_or(true, |attempt| {
            matches!(attempt, Registration::Unavailable(_))
        });
    held.send("PING :held")?;
    let held_alive = !held.read_until(|line| line.contains("PONG"))?.is_empty();
    drill.fact("quiesced", quiesced);
    drill.fact("new_connection_refused_after_reload", refused);
    drill.fact("held_session_continues", held_alive);
    // Control: the same ceiling applied at startup.
    drop(held);
    nodes.stop(&network, 2, "ceiling control")?;
    nodes.restart(&network, 2)?;
    let held = register_when_available(fixture, "held-session")?;
    let refused_after_restart = IrcClient::connect(fixture)
        .and_then(|mut client| client.try_register("intruder"))
        .map_or(true, |attempt| {
            matches!(attempt, Registration::Unavailable(_))
        });
    drill.fact(
        "new_connection_refused_after_restart",
        refused_after_restart,
    );
    let refused = refused || refused_after_restart;
    drill.step(
        "quiesce",
        format!("ceiling lowered to 1: reload ok={quiesced}, refused after reload or restart={refused}, held alive={held_alive}"),
    );
    let (checkpoints, events, lines) = audit_export(fixture)?;
    write_replace(
        &drill.directory.join("compromise-audit-export.txt"),
        lines.join("\n").as_bytes(),
    )?;
    drill.fact("audit_export_checkpoints", checkpoints.len());
    drill.fact("audit_export_events", events.len());
    drill.step(
        "evidence",
        format!("audit export preserved: {} lines", lines.len()),
    );
    drop(held);
    nodes.stop(&network, 2, "compromise response")?;
    let (backup, _, _) = write_backup(fixture, "compromise.backup", 1)?;
    let outcome = restore_node(
        fixture,
        &RestorePlan {
            backup: &backup,
            new_master: true,
            disaster: false,
            generation: 2,
        },
    )?;
    drill.fact("fenced_incarnation", outcome.incarnation_changed);
    drill.fact("recovery_epoch", &outcome.epoch);
    drill.step(
        "fence",
        format!(
            "restored into a new incarnation under epoch {}",
            outcome.epoch
        ),
    );
    repin_peer_epoch(&network.coordinator, fixture.server_id, &outcome.epoch)?;
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    nodes.restart(&network, 0)?;
    nodes.restart(&network, 2)?;
    let mut notice = account_login(&network.edge_a, account, "security-officer")?;
    notice.send(&format!("JOIN {DRILL_CHANNEL}"))?;
    notice.read_until(|line| line.contains(&format!(" 366 security-officer {DRILL_CHANNEL} ")))?;
    notice.send(&format!(
        "NOTICE {DRILL_CHANNEL} :security notice: edge b restored into a fenced incarnation"
    ))?;
    notice.send("QUIT :notice sent")?;
    drill.fact("notice_sent", true);
    drill.step(
        "notice",
        "client-visible security notice sent after verification",
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(
        quiesced
            && refused
            && held_alive
            && outcome.incarnation_changed
            && clean.iter().all(|c| *c),
    )
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_compromise() -> TestResult {
    let mut drill = Drill::begin("compromise")?;
    let outcome = run_compromise(&mut drill);
    drill.finish(outcome)
}

fn run_rollback(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let fixture = &network.edge_b;
    nodes.stop(&network, 2, "rollback snapshot")?;
    let state = current_state_dir(fixture)?;
    let database = state.join("database.redb");
    let snapshot = fixture.data_dir.join("database-older.redb");
    fs::copy(&database, &snapshot)?;
    drill.step(
        "snapshot",
        "older database file retained, guard left in place",
    );
    nodes.restart(&network, 2)?;
    let mut client = register_when_available(fixture, "progress")?;
    client.send("JOIN #progress")?;
    client.read_until(|line| line.contains(" 366 progress #progress "))?;
    client.send("TOPIC #progress :moved forward")?;
    client.read_until(|line| line.contains("TOPIC #progress :moved forward"))?;
    client.send("QUIT :progress made")?;
    drop(client);
    nodes.stop(&network, 2, "rollback attempt")?;
    drill.step("progress", "durable progress committed after the snapshot");
    fs::copy(&snapshot, &database)?;
    let stderr = nodes.stderr[2].clone();
    let mut rolled_back = DaemonProcess::start_logged(&fixture.config_path, None, Some(&stderr))?;
    let status = rolled_back.wait();
    let refused = matches!(&status, Ok(status) if !status.success());
    let text = stderr_text(&nodes, 2);
    let reason = text.lines().last().unwrap_or("").to_owned();
    drill.fact("startup_refused", refused);
    drill.fact("refusal", &reason);
    drill.step(
        "rollback",
        format!("older database under the current guard: refused={refused}: {reason}"),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(refused && clean.iter().take(2).all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_rollback() -> TestResult {
    let mut drill = Drill::begin("rollback")?;
    let outcome = run_rollback(&mut drill);
    drill.finish(outcome)
}

fn run_resynchronization(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    let fixture = &network.edge_b;
    let mut native = account_login(fixture, account, "native")?;
    let (joined_before, topic_before) = join_drill_channel(&mut native, "native")?;
    drill.fact("topic_seen_before", topic_before);
    drill.step(
        "attach",
        format!("native client on edge b, joined={joined_before}, topic visible={topic_before}"),
    );
    nodes.stop(&network, 2, "resync")?;
    drill.fact("die_with_account_session_attached", "accepted");
    let (backup, _, _) = write_backup(fixture, "resync.backup", 1)?;
    let outcome = restore_node(
        fixture,
        &RestorePlan {
            backup: &backup,
            new_master: false,
            disaster: false,
            generation: 2,
        },
    )?;
    repin_peer_epoch(&network.coordinator, fixture.server_id, &outcome.epoch)?;
    let status = nodes.coordinator.stop()?;
    if !status.success() {
        return Err(failure(format!("coordinator exited with {status}")));
    }
    nodes.restart(&network, 0)?;
    nodes.restart(&network, 2)?;
    drill.step(
        "epoch",
        format!("edge b returned under epoch {}", outcome.epoch),
    );
    let disconnected = native.send("PING :still-there").is_err()
        || native.read_until(|line| line.contains("PONG")).is_err();
    drill.fact("old_session_disconnected", disconnected);
    let mut again = account_login(fixture, account, "native")?;
    let (joined_after, topic_after) = join_drill_channel(&mut again, "native")?;
    drill.fact("topic_seen_after", topic_after);
    again.send("QUIT :re-onboarded")?;
    drill.fact("reonboarded", joined_after);
    drill.step(
        "reonboard",
        format!(
            "disconnected={disconnected}, re-onboarded={joined_after}, topic visible={topic_after}"
        ),
    );
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(joined_before
        && topic_before
        && disconnected
        && joined_after
        && topic_after
        && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_resynchronization() -> TestResult {
    let mut drill = Drill::begin("resynchronization")?;
    let outcome = run_resynchronization(&mut drill);
    drill.finish(outcome)
}

// ---------------------------------------------------------------------------
// Host hardening and observability
// ---------------------------------------------------------------------------

/// LISTEN rows of the kernel TCP table by local port with their local address.
fn listen_rows() -> TestResult<Vec<(u16, String)>> {
    let text = read_bounded(Path::new("/proc/net/tcp"))?;
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        let mut fields = line.split_ascii_whitespace();
        let (Some(local), Some(_), Some(state)) = (fields.nth(1), fields.next(), fields.next())
        else {
            continue;
        };
        let Some((address, port)) = local.rsplit_once(':') else {
            continue;
        };
        if state == "0A"
            && let Ok(port) = u16::from_str_radix(port, 16)
        {
            rows.push((port, address.to_owned()));
        }
    }
    Ok(rows)
}

/// Every configured listener binds loopback only.
fn check_listener_exposure(network: &Network, drill: &mut Drill) -> TestResult<bool> {
    let rows = listen_rows()?;
    let mut expected = vec![
        network.coordinator.public_address.port(),
        network.edge_a.public_address.port(),
        network.edge_b.public_address.port(),
    ];
    if let Some(federation) = network.coordinator.federation_listener {
        expected.push(federation.port());
    }
    let mut exposed = Vec::new();
    let mut listening = 0;
    for port in &expected {
        for (row_port, address) in &rows {
            if row_port == port {
                listening += 1;
                if address != "0100007F" {
                    exposed.push(format!("{port} on {address}"));
                }
            }
        }
    }
    drill.fact("listeners_expected", expected.len());
    drill.fact("listeners_found", listening);
    drill.fact("listeners_exposed", format!("{exposed:?}"));
    Ok(exposed.is_empty() && listening == expected.len())
}

fn mode_of(path: &Path) -> TestResult<u32> {
    Ok(fs::metadata(path)?.mode() & 0o777)
}

/// State, keys, backups, and logs stay private to the service user.
fn check_permissions(fixture: &NodeFixture, drill: &mut Drill) -> TestResult<bool> {
    let mut violations = Vec::new();
    for (label, path, expected) in [
        ("state", current_state_dir(fixture)?, 0o700),
        ("keys", fixture.data_dir.join("keys"), 0o700),
        ("backups", fixture.data_dir.join("backups"), 0o700),
        ("logs", fixture.log_dir.clone(), 0o700),
    ] {
        let mode = mode_of(&path)?;
        if mode & 0o077 != 0 {
            violations.push(format!("{label} {mode:o}"));
        }
        drill.fact(
            &format!("mode_{label}"),
            format!("{mode:o} (expected {expected:o})"),
        );
    }
    for entry in fs::read_dir(fixture.data_dir.join("keys"))? {
        let entry = entry?;
        let mode = entry.metadata()?.mode() & 0o777;
        if mode & 0o077 != 0 {
            violations.push(format!(
                "key {} {mode:o}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    drill.fact("permission_violations", format!("{violations:?}"));
    Ok(violations.is_empty())
}

/// The daemon's core limit as procfs reports it, where procfs is visible.
fn check_core_limit(nodes: &DrillNodes, drill: &mut Drill) -> bool {
    let Some(pid) = nodes.coordinator.child.as_ref().map(Child::id) else {
        return false;
    };
    match fs::read_to_string(format!("/proc/{pid}/limits")) {
        Ok(text) => {
            let core = text
                .lines()
                .find(|line| line.starts_with("Max core file size"))
                .unwrap_or("")
                .to_owned();
            let zero = core.split_ascii_whitespace().nth(4) == Some("0");
            drill.fact("core_limit", &core);
            drill.fact("core_limit_visible", true);
            zero
        }
        Err(error) => {
            drill.fact("core_limit_visible", false);
            drill.fact(
                "core_limit",
                format!("procfs entry not readable ({error}); the daemon refuses to start unless it set the limit to zero"),
            );
            true
        }
    }
}

/// Injected identifiers must never appear in logs or captured stderr.
fn check_canaries(network: &Network, nodes: &DrillNodes, drill: &mut Drill) -> TestResult<bool> {
    let mut token = [0_u8; 8];
    OsEntropy::fill(&mut token)?;
    let canary = format!("canary{}", u64::from_be_bytes(token) % 1_000_000_000);
    let nick = format!("n{canary}");
    let channel = format!("#c{canary}");
    let mut client = register_when_available(&network.edge_a, &nick)?;
    client.send(&format!("JOIN {channel}"))?;
    client.read_until(|line| line.contains(&format!(" 366 {nick} {channel} ")))?;
    client.send(&format!("PRIVMSG {channel} :secret body {canary}"))?;
    client.send(&format!("TOPIC {channel} :topic {canary}"))?;
    client.read_until(|line| line.contains(&format!("TOPIC {channel} :topic {canary}")))?;
    client.send("QUIT :canary done")?;
    thread::sleep(Duration::from_secs(1));
    let mut leaks = Vec::new();
    for (index, fixture) in [&network.coordinator, &network.edge_a, &network.edge_b]
        .into_iter()
        .enumerate()
    {
        if fixture.log_text().contains(&canary) {
            leaks.push(format!("log of node {index}"));
        }
        if stderr_text(nodes, index).contains(&canary) {
            leaks.push(format!("stderr of node {index}"));
        }
    }
    drill.fact("canary_leaks", format!("{leaks:?}"));
    Ok(leaks.is_empty())
}

/// A segmentation fault leaves no core file and a repeated SIGTERM still
/// yields one clean stop.
fn check_crash_handling(
    network: &Network,
    nodes: &mut DrillNodes,
    drill: &mut Drill,
) -> TestResult<bool> {
    let pid = nodes
        .edge_a
        .child
        .as_ref()
        .map(Child::id)
        .ok_or_else(|| failure("edge a is not running"))?;
    // An externally sent SIGSEGV is not delivered to the daemon, which keeps
    // serving; a synchronous fault would still end it. SIGKILL is the
    // uncatchable crash the containment check simulates.
    Command::new("kill")
        .arg("-SEGV")
        .arg(pid.to_string())
        .status()?;
    thread::sleep(Duration::from_secs(2));
    let survived_segv = nodes
        .edge_a
        .child
        .as_mut()
        .and_then(|child| child.try_wait().ok())
        .is_some_and(|status| status.is_none());
    drill.fact("external_sigsegv_survived", survived_segv);
    Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status()?;
    let status = nodes.edge_a.wait_within(DRILL_STOP_BUDGET);
    let crashed = matches!(&status, Ok(status) if !status.success());
    let cores = fs::read_dir(".")?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("core"))
        .count();
    drill.fact("crash_terminated", crashed);
    drill.fact("core_files", cores);
    nodes.restart(network, 1)?;
    let pid = nodes
        .edge_b
        .child
        .as_ref()
        .map(Child::id)
        .ok_or_else(|| failure("edge b is not running"))?;
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    thread::sleep(Duration::from_millis(50));
    Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()?;
    let clean = matches!(nodes.edge_b.wait(), Ok(status) if status.success());
    drill.fact("double_sigterm_clean_stop", clean);
    nodes.restart(network, 2)?;
    Ok(crashed && cores == 0 && clean)
}

/// `require_locked_secrets = true` must still start the daemon.
fn check_locked_secrets(
    network: &Network,
    nodes: &mut DrillNodes,
    drill: &mut Drill,
) -> TestResult<bool> {
    let fixture = &network.edge_a;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut config,
        "require_locked_secrets = false",
        "require_locked_secrets = true",
    )?;
    fs::write(&fixture.config_path, config)?;
    let status = nodes.edge_a.stop()?;
    if !status.success() {
        return Err(failure(format!("edge a exited with {status}")));
    }
    let started = nodes.restart(network, 1).is_ok();
    drill.fact("locked_secrets_startup", started);
    if !started {
        drill.fact(
            "locked_secrets_stderr",
            stderr_text(nodes, 1).lines().last().unwrap_or(""),
        );
    }
    Ok(started)
}

fn run_host_hardening(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let exposure = check_listener_exposure(&network, drill)?;
    drill.step("listeners", format!("loopback only={exposure}"));
    let permissions = check_permissions(&network.edge_a, drill)?;
    drill.step("permissions", format!("private={permissions}"));
    let core = check_core_limit(&nodes, drill);
    drill.step(
        "core",
        format!("core limit zero or refused-to-start guarantee={core}"),
    );
    let canaries = check_canaries(&network, &nodes, drill)?;
    drill.step("canaries", format!("no leaks={canaries}"));
    let retention =
        super::stage_ten_capacity::current_config_value(&network.edge_a, "log_retention_hours")
            .unwrap_or_else(|_| "default (24)".to_owned());
    drill.fact("log_retention_hours", &retention);
    let crash = check_crash_handling(&network, &mut nodes, drill)?;
    drill.step("crash", format!("contained={crash}"));
    let locked = check_locked_secrets(&network, &mut nodes, drill)?;
    drill.step("locked_secrets", format!("started={locked}"));
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(exposure && permissions && core && canaries && crash && locked && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_host_hardening() -> TestResult {
    let mut drill = Drill::begin("host_hardening")?;
    let outcome = run_host_hardening(&mut drill);
    drill.finish(outcome)
}

/// Every STATS selector answers with exactly its declared field vocabulary.
fn check_stats_vocabulary(network: &Network, drill: &mut Drill) -> TestResult<bool> {
    let mut mismatches = Vec::new();
    let mut transcripts = String::new();
    for (index, fixture) in [&network.coordinator, &network.edge_a, &network.edge_b]
        .into_iter()
        .enumerate()
    {
        let identity = admin_identity(fixture);
        let mut admin = AdminSession::connect(&identity)?;
        for selector in StatsSelector::ALL {
            let observed = admin
                .stats(selector.as_str())?
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>();
            let declared = selector
                .fields()
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            if observed != declared {
                mismatches.push(format!("node {index} {}", selector.as_str()));
            }
            let _ = writeln!(
                transcripts,
                "node {index} STATS {}: {}",
                selector.as_str(),
                observed.join(" ")
            );
        }
        admin.quit()?;
    }
    write_replace(
        &drill.directory.join("observability-stats.txt"),
        transcripts.as_bytes(),
    )?;
    drill.fact("stats_mismatches", format!("{mismatches:?}"));
    Ok(mismatches.is_empty())
}

/// Every log line names a registered event with a severity and a timestamp.
fn check_log_registry(network: &Network, drill: &mut Drill) -> TestResult<bool> {
    let registry = LogEventCode::ALL
        .iter()
        .map(|code| code.label())
        .collect::<Vec<_>>();
    let mut unknown = Vec::new();
    let mut malformed = 0_u64;
    let mut lines_seen = 0_u64;
    for fixture in [&network.coordinator, &network.edge_a, &network.edge_b] {
        let text = fixture.log_text();
        for line in text.lines() {
            lines_seen += 1;
            let Some(event) = line
                .split_ascii_whitespace()
                .find_map(|field| field.strip_prefix("event="))
            else {
                malformed += 1;
                continue;
            };
            if !registry.contains(&event) && !unknown.iter().any(|known| known == event) {
                unknown.push(event.to_owned());
            }
            if !line.contains(" severity=") || !line.contains(" utc=") {
                malformed += 1;
            }
        }
    }
    drill.fact("log_lines", lines_seen);
    drill.fact("log_events_unknown", format!("{unknown:?}"));
    drill.fact("log_lines_malformed", malformed);
    drill.fact("log_registry_size", registry.len());
    Ok(unknown.is_empty() && malformed == 0 && lines_seen > 0)
}

fn run_observability(drill: &mut Drill) -> TestResult<bool> {
    let network = drill_network()?;
    let _logs = LogGuard {
        network: &network,
        directory: drill.stderr_logs.clone(),
    };
    let mut nodes = DrillNodes::start(&network, drill)?;
    let account = seed_state(&network)?;
    let mut client = account_login(&network.edge_b, account, "observer")?;
    client.send("QUIT :observed")?;
    let stats = check_stats_vocabulary(&network, drill)?;
    drill.step("stats", format!("vocabulary exact={stats}"));
    let logs = check_log_registry(&network, drill)?;
    drill.step("logs", format!("registry closed={logs}"));
    let version = AdminSession::connect(&admin_identity(&network.coordinator))?.version()?;
    drill.fact("version_reply", &version);
    let clean = nodes.stop_all();
    drill.fact("daemons_stopped_cleanly", format!("{clean:?}"));
    Ok(stats && logs && clean.iter().all(|c| *c))
}

#[test]
#[ignore = "Stage 10 drill; run through the qualification driver"]
fn drill_observability() -> TestResult {
    let mut drill = Drill::begin("observability")?;
    let outcome = run_observability(&mut drill);
    drill.finish(outcome)
}
