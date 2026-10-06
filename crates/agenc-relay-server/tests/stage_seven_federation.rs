//! End-to-end Stage 07 federation: one coordinator and two edge daemons of
//! the production binary over real mutual TLS, with clients registered on
//! the edges, cross-edge channel traffic, a coordinator restart, and the
//! fail-closed partition behaviour of an edge.
#![forbid(unsafe_code)]

#[path = "support/loopback_ports.rs"]
mod loopback_ports;

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agenc_relay_auth::OpaqueProfile;
use agenc_relay_config::{
    DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName, InitProfile, InitValues, NodeRole,
    OperatorTemplate, encode_base64url_32, render_template,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, audit_signing_key_id, backup_signing_key_id,
};
use agenc_relay_runtime::tls::{CLIENT_ALPN, TrustStore, build_client_config};
use agenc_relay_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, SCHEMA_GENERATION,
    StateDirectory, StorageEngineLimits, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StoredKey, TableId, embedded_storage_qualifications,
    initialize_storage,
};
use agenc_relay_testkit::TlsFixture;
use agenc_relay_types::{
    DatabaseId, NetworkId, OperatorId, RecoveryEpoch, ServerId, ServerIncarnation,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;
type TlsClient = StreamOwned<ClientConnection, TcpStream>;

const DATABASE_MAX_BYTES: u64 = 1_073_741_824;
const BACKUP_MAX_BYTES: u64 = 2_147_483_648;
const DISK_RESERVE_BYTES: u64 = 67_108_864;
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
/// The edge registers a client only once its coordinator link is ACTIVE;
/// registration attempts before that fail closed and are retried.
const NETWORK_WAIT: Duration = Duration::from_secs(60);
const NETWORK_ID: NetworkId = NetworkId::from_bytes([1; 32]);

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn failure(message: impl Into<String>) -> TestError {
    message.into().into()
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create() -> TestResult<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| failure("HOME is unavailable"))?;
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(home).join(format!(
            ".agenc-relay-stage-seven-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn create_directory(path: &Path, mode: u32) -> TestResult {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> TestResult {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_trust_manifest(
    path: &Path,
    kind: &str,
    key_id: [u8; 32],
    public_key: [u8; 32],
) -> TestResult {
    let document = format!(
        "{kind}_trust_version = 1\n\n[[key]]\nkey_id = \"{}\"\ned25519_public_key = \"{}\"\nnot_before = 0\nnot_after = {}\n",
        encode_base64url_32(&key_id),
        encode_base64url_32(&public_key),
        i64::MAX,
    );
    write_private(path, document.as_bytes())
}

fn reserve_loopback_address() -> TestResult<SocketAddr> {
    Ok(loopback_ports::reserve()?)
}

fn replace_once(document: &mut String, old: &str, new: &str) -> TestResult {
    if document.matches(old).count() != 1 {
        return Err(failure(format!(
            "configuration template occurrence mismatch for {old:?}"
        )));
    }
    *document = document.replacen(old, new, 1);
    Ok(())
}

/// Wraps one DER certificate as a PEM block so several anchors can share
/// one trust store document.
fn pem_certificate(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn protected_path_text(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| failure("fixture path is not valid UTF-8"))
}

/// The durable identity of one node: chosen from its seed byte.
struct NodeIdentity {
    seed: u8,
    role: NodeRole,
    name: &'static str,
    server_id: ServerId,
    incarnation: ServerIncarnation,
    recovery_epoch: RecoveryEpoch,
    signing_seed: [u8; 32],
    signing: Ed25519SecretKey,
    federation_tls: TlsFixture,
}

impl NodeIdentity {
    fn new(seed: u8, role: NodeRole, name: &'static str) -> TestResult<Self> {
        let server_id = ServerId::from_bytes([seed; 16]);
        Ok(Self {
            seed,
            role,
            name,
            server_id,
            incarnation: ServerIncarnation::from_bytes([seed.wrapping_add(1); 16]),
            recovery_epoch: RecoveryEpoch::from_bytes([seed.wrapping_add(2); 16]),
            signing_seed: [seed.wrapping_add(3); 32],
            signing: Ed25519SecretKey::from_bytes([seed.wrapping_add(3); 32]),
            federation_tls: TlsFixture::mint_federation([seed.wrapping_add(4); 32], server_id)?,
        })
    }

    /// The `[[federation.peer]]` entry another node keeps for this one.
    fn peer_entry(&self, endpoints: &str) -> String {
        format!(
            "[[federation.peer]]\nserver_id = \"{}\"\nserver_name = \"{}\"\nrole = \"{}\"\nrecovery_epoch = \"{}\"\nendpoints = [{endpoints}]\ncertificate_spki_sha256 = \"{}\"\nsigning_public_key = \"{}\"\nenabled = true\n\n",
            self.server_id.to_base64url(),
            self.name,
            self.role.as_str(),
            self.recovery_epoch.to_base64url(),
            encode_base64url_32(self.federation_tls.leaf_spki_sha256()),
            encode_base64url_32(self.signing.public_key().as_bytes()),
        )
    }
}

/// One running node's on-disk fixture.
struct NodeFixture {
    _root: TestRoot,
    config_path: PathBuf,
    log_dir: PathBuf,
    public_address: SocketAddr,
    federation_address: Option<SocketAddr>,
    dns_name: String,
    client_tls: TlsFixture,
}

struct NodePlan<'a> {
    identity: &'a NodeIdentity,
    coordinator: &'a NodeIdentity,
    federation_address: Option<SocketAddr>,
    peers: &'a [&'a NodeIdentity],
}

impl NodeFixture {
    // agenc-review: focus owner=tests reviewed=2026-09-03 reason=the node fixture writes every key trust store certificate and configuration override of one daemon in one place so the three nodes stay byte-identical apart from their identities
    fn create(plan: &NodePlan<'_>) -> TestResult<Self> {
        let identity = plan.identity;
        let root = TestRoot::create()?;
        let etc = root.path().join("etc");
        let tls_dir = etc.join("tls");
        let data_dir = root.path().join("data");
        let keys_dir = data_dir.join("keys");
        let trust_dir = data_dir.join("trust");
        let state_dir = data_dir.join("state");
        let backup_dir = data_dir.join("backups");
        let runtime_dir = root.path().join("run");
        for path in [
            &etc,
            &tls_dir,
            &data_dir,
            &keys_dir,
            &trust_dir,
            &state_dir,
            &backup_dir,
        ] {
            create_directory(path, 0o700)?;
        }
        create_directory(&runtime_dir, 0o750)?;

        let seed = identity.seed;
        let operator_id = OperatorId::from_bytes([seed.wrapping_add(5); 16]);
        let database_id = DatabaseId::from_bytes([seed.wrapping_add(6); 16]);
        let storage_master = [seed.wrapping_add(7); 32];
        let rollback_guard = [seed.wrapping_add(8); 32];
        let login_index = [seed.wrapping_add(9); 32];
        let backup_signing = [seed.wrapping_add(10); 32];
        let audit_signing = [seed.wrapping_add(11); 32];
        let operator_signing = [seed.wrapping_add(12); 32];
        let account_hpke = [seed.wrapping_add(13); 32];
        let opaque_fake_credential = [seed.wrapping_add(14); 32];
        let sequencer = [seed.wrapping_add(15); 32];
        let opaque = OpaqueProfile::generate(NETWORK_ID)?;
        for (name, bytes) in [
            ("storage-master.key", storage_master.as_slice()),
            ("rollback-guard.key", rollback_guard.as_slice()),
            ("login-index-g1.key", login_index.as_slice()),
            ("federation-signing.key", identity.signing_seed.as_slice()),
            ("backup-signing.key", backup_signing.as_slice()),
            ("audit-signing.key", audit_signing.as_slice()),
            ("operator-signing.key", operator_signing.as_slice()),
            ("account-service-hpke.key", account_hpke.as_slice()),
            (
                "opaque-fake-credential.key",
                opaque_fake_credential.as_slice(),
            ),
            ("sequencer.key", sequencer.as_slice()),
        ] {
            write_private(&keys_dir.join(name), bytes)?;
        }
        write_private(
            &keys_dir.join("opaque-server-setup.key"),
            opaque.expose_setup_for_persistence(),
        )?;
        let backup_key = Ed25519SecretKey::from_bytes(backup_signing);
        let audit_key = Ed25519SecretKey::from_bytes(audit_signing);
        write_trust_manifest(
            &trust_dir.join("backup-trust.toml"),
            "backup",
            *backup_signing_key_id(backup_key.public_key().as_bytes())?.as_bytes(),
            *backup_key.public_key().as_bytes(),
        )?;
        write_trust_manifest(
            &trust_dir.join("audit-trust.toml"),
            "audit",
            *audit_signing_key_id(audit_key.public_key().as_bytes())?.as_bytes(),
            *audit_key.public_key().as_bytes(),
        )?;
        initialize_database(
            &state_dir,
            identity,
            database_id,
            storage_master,
            rollback_guard,
            login_index,
            &opaque,
        )?;

        let dns_name = format!("{}.client", identity.name);
        let client_tls = TlsFixture::mint([seed.wrapping_add(16); 32], &dns_name)?;
        write_private(
            &tls_dir.join("server.crt"),
            client_tls.leaf_certificate_der(),
        )?;
        write_private(
            &tls_dir.join("server.key"),
            client_tls.leaf_private_key_pkcs8_der(),
        )?;
        write_private(
            &tls_dir.join("federation.crt"),
            identity.federation_tls.leaf_certificate_der(),
        )?;
        write_private(
            &tls_dir.join("federation.key"),
            identity.federation_tls.leaf_private_key_pkcs8_der(),
        )?;
        // The private CA bundle holds every peer's federation CA; each
        // fixture mints its own, so the bundle is their concatenation.
        let mut bundle = String::new();
        for peer in plan.peers {
            bundle.push_str(&pem_certificate(peer.federation_tls.ca_certificate_der()));
        }
        let ca_path = tls_dir.join("federation-ca.pem");
        write_private(&ca_path, bundle.as_bytes())?;

        let public_address = reserve_loopback_address()?;
        let uid = fs::metadata(root.path())?.uid();
        let hpke = AccountHpkePrivateKey::from_bytes(account_hpke)?;
        let values = InitValues {
            profile: InitProfile::Public,
            network_id: NETWORK_ID,
            server_id: identity.server_id,
            role: identity.role,
            coordinator_server_id: plan.coordinator.server_id,
            server_name: DnsName::parse(identity.name)?,
            display_name: DisplayLabel::parse("StageSeven")?,
            data_dir: data_dir.clone(),
            runtime_dir: runtime_dir.clone(),
            tls_dir: tls_dir.clone(),
            dns_name: Some(DnsName::parse(&dns_name)?),
            account_service_hpke_public_key: *hpke.public_key()?.as_bytes(),
            operator: OperatorTemplate {
                local_uid: 0,
                operator_id,
                signing_public_key: *Ed25519SecretKey::from_bytes(operator_signing)
                    .public_key()
                    .as_bytes(),
            },
        };
        let mut config = render_template(&values)?;
        apply_common_overrides(&mut config, public_address, uid)?;
        apply_federation_overrides(&mut config, plan, &tls_dir, &ca_path)?;
        let config_path = etc.join("config.toml");
        write_private(&config_path, config.as_bytes())?;
        Ok(Self {
            _root: root,
            config_path,
            log_dir: data_dir.join("logs"),
            public_address,
            federation_address: plan.federation_address,
            dns_name,
            client_tls,
        })
    }

    fn client_config(&self) -> TestResult<Arc<ClientConfig>> {
        Ok(build_client_config(
            TrustStore::parse(self.client_tls.ca_certificate_der())?,
            Some(CLIENT_ALPN),
            None,
        )?)
    }

    fn log_text(&self) -> String {
        let Ok(entries) = fs::read_dir(&self.log_dir) else {
            return String::new();
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        paths.sort();
        let mut text = String::new();
        for path in paths.into_iter().take(16) {
            if let Ok(bytes) = fs::read(path) {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
        }
        text
    }
}

fn apply_common_overrides(config: &mut String, public: SocketAddr, uid: u32) -> TestResult {
    replace_once(
        config,
        "memory_budget_bytes = 6442450944",
        "memory_budget_bytes = 1073741824",
    )?;
    replace_once(
        config,
        "registration = \"closed\"",
        "registration = \"open\"",
    )?;
    replace_once(
        config,
        "quiesce_seconds = 5\ndrain_seconds = 20\nflush_seconds = 10\nstop_seconds = 5",
        "quiesce_seconds = 2\ndrain_seconds = 4\nflush_seconds = 4\nstop_seconds = 8",
    )?;
    replace_once(
        config,
        "enabled = false\npurpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"\nmax_connections = 50000",
        &format!(
            "enabled = true\npurpose = \"client_tls\"\nbind = \"{public}\"\nmax_connections = 32"
        ),
    )?;
    replace_once(
        config,
        "allowed_uids = [0]",
        &format!("allowed_uids = [{uid}]"),
    )?;
    replace_once(
        config,
        "database_max_bytes = 85899345920\nbackup_max_bytes = 107374182400",
        &format!(
            "database_max_bytes = {DATABASE_MAX_BYTES}\nbackup_max_bytes = {BACKUP_MAX_BYTES}"
        ),
    )?;
    replace_once(
        config,
        "disk_reserve_bytes = 1073741824\ndisk_reserve_percent = 5",
        &format!("disk_reserve_bytes = {DISK_RESERVE_BYTES}\ndisk_reserve_percent = 1"),
    )?;
    replace_once(
        config,
        "integrity_checkpoint_manifests = 100000",
        "integrity_checkpoint_manifests = 10000",
    )?;
    replace_once(config, "local_uids = [0]", &format!("local_uids = [{uid}]"))?;
    replace_once(
        config,
        "\n[privacy]",
        "\n[limits.rate.preauth_command]\nrefill_tokens = 10\nrefill_seconds = 1\nburst = 50\n\n[limits.rate.registered_command]\nrefill_tokens = 40\nrefill_seconds = 1\nburst = 200\n\n[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10\n\n[privacy]",
    )
}

/// Enables federation: the private CA bundle, the peer table, and the
/// federation listener entry. A coordinator serves the listener; an edge
/// keeps it disabled and dials with its certificate (spec C.3).
fn apply_federation_overrides(
    config: &mut String,
    plan: &NodePlan<'_>,
    tls_dir: &Path,
    ca_path: &Path,
) -> TestResult {
    replace_once(
        config,
        "enabled = false\nsigning_private_key_file",
        &format!(
            "enabled = true\nprivate_ca_file = \"{}\"\nsigning_private_key_file",
            protected_path_text(ca_path)?
        ),
    )?;
    let mut peers = String::new();
    for peer in plan.peers {
        let endpoints = match (plan.identity.role, peer.role) {
            (NodeRole::Edge, NodeRole::Coordinator) => {
                let address = plan
                    .federation_address
                    .ok_or_else(|| failure("an edge needs its coordinator address"))?;
                format!("\"tcp:{address}\"")
            }
            _ => String::new(),
        };
        peers.push_str(&peer.peer_entry(&endpoints));
    }
    replace_once(
        config,
        "connect_timeout_seconds = 10\n\n",
        &format!("connect_timeout_seconds = 10\n\n{peers}"),
    )?;
    let (enabled, bind) = match (plan.identity.role, plan.federation_address) {
        (NodeRole::Coordinator, Some(address)) => (true, address.to_string()),
        _ => (false, "127.0.0.1:1".to_owned()),
    };
    let listener = format!(
        "[[listeners.endpoint]]\nname = \"federation\"\nenabled = {enabled}\npurpose = \"federation\"\nbind = \"{bind}\"\nmax_connections = 64\ntls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\nclient_ca_file = \"{}\"\n\n",
        protected_path_text(&tls_dir.join("federation.crt"))?,
        protected_path_text(&tls_dir.join("federation.key"))?,
        protected_path_text(ca_path)?,
    );
    replace_once(
        config,
        "[[listeners.endpoint]]\nname = \"admin-local\"",
        &format!("{listener}[[listeners.endpoint]]\nname = \"admin-local\""),
    )
}

fn initialize_database(
    state_dir: &Path,
    identity: &NodeIdentity,
    database_id: DatabaseId,
    storage_master: [u8; 32],
    rollback_guard: [u8; 32],
    login_index: [u8; 32],
    opaque: &OpaqueProfile,
) -> TestResult {
    let login_key = LoginIndexKey::from_bytes(login_index);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(NETWORK_ID))?;
    let key_state_record = InitialStorageRecord::new(
        TableId::LoginIndexKeyState,
        StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
        1,
        key_state.encode()?,
    )?;
    let fake_record = PersistentRecordValue::new(
        TableId::OpaqueRecord,
        LIVE_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        opaque.expose_fake_record_for_persistence().to_vec(),
    )?;
    let fake_record = InitialStorageRecord::new(
        TableId::OpaqueRecord,
        StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        1,
        fake_record.encode()?,
    )?;
    let qualifications = embedded_storage_qualifications()?;
    let state_directory = StateDirectory::open(state_dir, &qualifications)?;
    let outcome = initialize_storage(StorageInitializationConfig {
        state_directory,
        header_tbs: DatabaseHeaderTbs::new(
            NETWORK_ID,
            identity.server_id,
            identity.incarnation,
            database_id,
            1,
            SCHEMA_GENERATION,
            identity.recovery_epoch,
        )?,
        storage_master_key: StorageMasterKey::from_bytes(storage_master),
        rollback_guard_root_key: RollbackGuardRootKey::from_bytes(rollback_guard),
        mode: StorageInitializationMode::Live,
        initial_records: vec![key_state_record, fake_record],
        account_service_response_count: 0,
        state_generation: 1,
        predecessor_guard_hash: StorageDigest::from_bytes([0; 32]),
        limits: StorageEngineLimits {
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: DISK_RESERVE_BYTES,
            reserve_percent: 1,
            database_max_bytes: DATABASE_MAX_BYTES,
            backup_max_bytes: BACKUP_MAX_BYTES,
            integrity_checkpoint_manifests: 10_000,
        },
    })?;
    if !matches!(outcome, StorageInitializationOutcome::Complete { .. }) {
        return Err(failure("storage initialization became indeterminate"));
    }
    Ok(())
}

struct DaemonProcess {
    child: Option<Child>,
}

impl DaemonProcess {
    fn start(config_path: &Path) -> TestResult<Self> {
        let child = Command::new(env!("CARGO_BIN_EXE_arcd"))
            .arg("serve")
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self { child: Some(child) })
    }

    /// Ends the process abruptly, as a crash would.
    fn kill(&mut self) -> TestResult {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| failure("daemon was already joined"))?;
        child.kill()?;
        let _status = child.wait()?;
        Ok(())
    }

    fn stop(&mut self) -> TestResult<ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| failure("daemon was already joined"))?;
        let pid = i32::try_from(child.id())?;
        let terminated = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()?;
        if !terminated.success() {
            return Err(failure("could not signal the daemon"));
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                self.child = None;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _terminated = child.kill();
                let _status = child.wait();
                self.child = None;
                return Err(failure("daemon did not stop within its total budget"));
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _terminated = child.kill();
            let _status = child.wait();
        }
    }
}

struct ArcClient {
    reader: BufReader<TlsClient>,
}

impl ArcClient {
    fn connect(fixture: &NodeFixture) -> TestResult<Self> {
        let deadline = Instant::now() + START_TIMEOUT;
        let socket = loop {
            match TcpStream::connect(fixture.public_address) {
                Ok(socket) => break socket,
                Err(error) if Instant::now() < deadline => {
                    let _transient = error;
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => {
                    return Err(failure(format!("public listener did not start: {error}")));
                }
            }
        };
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let name = ServerName::try_from(fixture.dns_name.clone())?;
        let connection = ClientConnection::new(fixture.client_config()?, name)?;
        let mut stream = StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(Self {
            reader: BufReader::new(stream),
        })
    }

    fn send(&mut self, command: &str) -> TestResult {
        self.reader.get_mut().write_all(command.as_bytes())?;
        self.reader.get_mut().write_all(b"\r\n")?;
        self.reader.get_mut().flush()?;
        Ok(())
    }

    fn read_until(&mut self, mut complete: impl FnMut(&str) -> bool) -> TestResult<Vec<String>> {
        let mut lines = Vec::new();
        for _ in 0..256 {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).map_err(|error| {
                failure(format!(
                    "read failed ({error}) before the expected reply; received {lines:?}"
                ))
            })?;
            if read == 0 {
                return Err(failure(format!(
                    "transport closed before the expected reply; received {lines:?}"
                )));
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let done = complete(&line);
            lines.push(line);
            if done {
                return Ok(lines);
            }
        }
        Err(failure("reply exceeded the 256-line transcript bound"))
    }

    /// Registers `nickname`; a `NETWORK_UNAVAILABLE` refusal means the edge
    /// link is not ACTIVE yet and the attempt ends with the connection.
    fn try_register(&mut self, nickname: &str) -> TestResult<Registration> {
        self.send(&format!("NICK {nickname}"))?;
        self.send(&format!("USER {nickname} 0 * :{nickname} Person"))?;
        let mut lines = Vec::new();
        for _ in 0..256 {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return Ok(Registration::Unavailable(lines)),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    return Ok(Registration::Unavailable(lines));
                }
                Err(error) => return Err(error.into()),
            }
            let line = line.trim_end_matches(['\r', '\n']).to_owned();
            let welcome = line.contains(" 376 ") || line.contains(" 422 ");
            let unavailable = line.contains("NETWORK_UNAVAILABLE");
            lines.push(line);
            if welcome {
                return Ok(Registration::Welcome(lines));
            }
            if unavailable {
                return Ok(Registration::Unavailable(lines));
            }
        }
        Err(failure("registration exceeded the 256-line bound"))
    }
}

enum Registration {
    Welcome(Vec<String>),
    Unavailable(Vec<String>),
}

/// Counts the link-established events an edge has logged so far.
fn links_established(fixture: &NodeFixture) -> usize {
    fixture
        .log_text()
        .matches("event=federation_link_established")
        .count()
}

/// Waits until the edge logs one more established link than `before`.
fn wait_for_link(fixture: &NodeFixture, before: usize) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    while links_established(fixture) <= before {
        if Instant::now() >= deadline {
            return Err(failure("edge never established its coordinator link"));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Connects and registers on an edge, retrying until its link is ACTIVE.
/// Attempts are spaced so the per-address admission limit never trips.
fn register_when_available(fixture: &NodeFixture, nickname: &str) -> TestResult<ArcClient> {
    welcome_when_available(fixture, nickname).map(|(client, _)| client)
}

/// Registers like `register_when_available` and also returns the welcome
/// lines, through the end of the MOTD group.
fn welcome_when_available(
    fixture: &NodeFixture,
    nickname: &str,
) -> TestResult<(ArcClient, Vec<String>)> {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        let mut client = match ArcClient::connect(fixture) {
            Ok(client) => client,
            Err(error) if Instant::now() < deadline => {
                let _transient = error;
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(error) => return Err(error),
        };
        let attempt = match client.try_register(nickname) {
            Ok(attempt) => attempt,
            Err(error) if Instant::now() < deadline => {
                let _transient = error;
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(error) => return Err(error),
        };
        match attempt {
            Registration::Welcome(lines) => {
                if !lines
                    .iter()
                    .any(|line| line.contains(&format!(" 001 {nickname} ")))
                {
                    return Err(failure(format!("registration lacked 001: {lines:?}")));
                }
                return Ok((client, lines));
            }
            Registration::Unavailable(lines) => {
                if Instant::now() >= deadline {
                    return Err(failure(format!(
                        "edge never reached ACTIVE for {nickname}: {lines:?}"
                    )));
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Whether `user` and `host` are a public cloak framed as Architecture 7.4
/// specifies, `u-<10 base32>` and `h-<16 base32>.invalid` (AUD-18), checked
/// independently of the daemon's formatter.
fn is_framed_cloak(user: &str, host: &str) -> bool {
    fn base32(text: &str, length: usize) -> bool {
        text.len() == length
            && text
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    }
    user.strip_prefix("u-").is_some_and(|user| base32(user, 10))
        && host
            .strip_prefix("h-")
            .and_then(|host| host.strip_suffix(".invalid"))
            .is_some_and(|host| base32(host, 16))
}

/// Requires a line `:<nickname>!<user>@<host><rest>` with a framed cloak.
fn assert_remote_mask(lines: &[String], nickname: &str, rest: &str) -> TestResult {
    let framed = lines.iter().any(|line| {
        line.strip_prefix(':')
            .and_then(|line| line.strip_suffix(rest))
            .and_then(|source| source.strip_prefix(nickname))
            .and_then(|source| source.strip_prefix('!'))
            .and_then(|source| source.split_once('@'))
            .is_some_and(|(user, host)| is_framed_cloak(user, host))
    });
    if framed {
        Ok(())
    } else {
        Err(failure(format!(
            "no framed {nickname} mask before {rest:?}: {lines:?}"
        )))
    }
}

/// Requires a WHOIS 311 for `nickname` whose user and host fields are framed.
fn assert_remote_whois(lines: &[String], nickname: &str) -> TestResult {
    let framed = lines.iter().any(|line| {
        matches!(
            line.split(' ').collect::<Vec<_>>().as_slice(),
            [_, "311", _, target, user, host, ..]
                if *target == nickname && is_framed_cloak(user, host)
        )
    });
    if framed {
        Ok(())
    } else {
        Err(failure(format!(
            "no framed WHOIS fields for {nickname}: {lines:?}"
        )))
    }
}

fn assert_contains(lines: &[String], expected: &str) -> TestResult {
    if lines.iter().any(|line| line.contains(expected)) {
        Ok(())
    } else {
        Err(failure(format!(
            "reply did not contain {expected:?}: {lines:?}"
        )))
    }
}

struct Network {
    coordinator: NodeFixture,
    edge_a: NodeFixture,
    edge_b: NodeFixture,
}

fn build_network() -> TestResult<Network> {
    let coordinator = NodeIdentity::new(20, NodeRole::Coordinator, "core.test")?;
    let edge_a = NodeIdentity::new(40, NodeRole::Edge, "edge-a.test")?;
    let edge_b = NodeIdentity::new(60, NodeRole::Edge, "edge-b.test")?;
    let federation_address = reserve_loopback_address()?;
    Ok(Network {
        coordinator: NodeFixture::create(&NodePlan {
            identity: &coordinator,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&edge_a, &edge_b],
        })?,
        edge_a: NodeFixture::create(&NodePlan {
            identity: &edge_a,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&coordinator],
        })?,
        edge_b: NodeFixture::create(&NodePlan {
            identity: &edge_b,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&coordinator],
        })?,
    })
}

#[test]
fn clients_on_two_edges_share_channels_through_the_coordinator() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = exercise_network(&network, &mut coordinator);
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

// agenc-review: focus owner=tests reviewed=2026-09-03 reason=one linear end-to-end transcript across three processes keeps the ordering of relay restart and partition checks readable in place
fn exercise_network(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    let mut alice = register_when_available(&network.edge_a, "alice")?;
    let mut bob = register_when_available(&network.edge_b, "bob")?;

    // Cross-edge JOIN, NAMES, PRIVMSG, TOPIC, and KICK.
    alice.send("JOIN #fed")?;
    let joined = alice.read_until(|line| line.contains(" 366 alice #fed "))?;
    assert_contains(&joined, " JOIN #fed")?;
    assert_contains(&joined, " 353 alice = #fed :~alice")?;
    bob.send("JOIN #fed")?;
    let joined = bob.read_until(|line| line.contains(" 366 bob #fed "))?;
    assert_contains(&joined, "alice")?;
    let seen = alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #fed"))?;
    assert_contains(&seen, " JOIN #fed")?;
    bob.send("PRIVMSG #fed :hello from edge b")?;
    let relayed = alice.read_until(|line| line.contains("PRIVMSG #fed :hello from edge b"))?;
    // AUD-18: edge A renders bob, a user homed on edge B, with the framed
    // Architecture 7.4 mask, and the WHOIS reply the coordinator renders for
    // edge A frames bob's user and host fields.
    assert_remote_mask(&relayed, "bob", " PRIVMSG #fed :hello from edge b")?;
    alice.send("WHOIS bob")?;
    let whois = alice.read_until(|line| line.contains(" 318 alice bob "))?;
    assert_remote_whois(&whois, "bob")?;
    alice.send("TOPIC #fed :federated topic")?;
    let topic = bob.read_until(|line| line.contains("TOPIC #fed :federated topic"))?;
    assert_contains(&topic, ":alice!")?;
    exercise_federated_modes(&mut alice, &mut bob)?;
    alice.send("KICK #fed bob :moving on")?;
    let kicked = bob.read_until(|line| line.contains("KICK #fed bob :moving on"))?;
    assert_contains(&kicked, ":alice!")?;
    bob.send("JOIN #fed")?;
    bob.read_until(|line| line.contains(" 366 bob #fed "))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #fed"))?;

    // Local work never leaves the edge: PING answers while the link stays
    // up and after it is lost.
    alice.send("PING :probe")?;
    alice.read_until(|line| line.ends_with("PONG :probe") || line.contains(" PONG "))?;

    // A coordinator crash partitions both edges: global work fails closed
    // with NETWORK_UNAVAILABLE and nothing is queued.
    let links_a = links_established(&network.edge_a);
    let links_b = links_established(&network.edge_b);
    coordinator.kill()?;
    let refused = wait_for_partition(&mut alice)?;
    assert_contains(&refused, "FAIL PRIVMSG NETWORK_UNAVAILABLE")?;
    alice.send("PING :still local")?;
    alice.read_until(|line| line.contains("PONG"))?;

    // The coordinator restarts from its durable state; both edges resume
    // or resynchronize and traffic flows again.
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    wait_for_link(&network.edge_a, links_a)?;
    wait_for_link(&network.edge_b, links_b)?;
    let mut carol = register_when_available(&network.edge_a, "carol")?;
    let mut dave = register_when_available(&network.edge_b, "dave")?;
    carol.send("JOIN #after")?;
    carol.read_until(|line| line.contains(" 366 carol #after "))?;
    dave.send("JOIN #after")?;
    dave.read_until(|line| line.contains(" 366 dave #after "))?;
    carol.read_until(|line| line.starts_with(":dave!") && line.contains(" JOIN #after"))?;
    dave.send("PRIVMSG #after :back again")?;
    carol.read_until(|line| line.contains("PRIVMSG #after :back again"))?;

    // Privacy canaries: no log names a client or the peer address.
    for (label, fixture) in [
        ("coordinator", &network.coordinator),
        ("edge a", &network.edge_a),
        ("edge b", &network.edge_b),
    ] {
        let text = fixture.log_text();
        for needle in [
            "alice",
            "bob",
            "carol",
            "dave",
            "#fed",
            "hello from edge b",
            "federated-key",
        ] {
            if text.contains(needle) {
                return Err(failure(format!("{label} log leaked {needle:?}")));
            }
        }
        if let Some(address) = network.coordinator.federation_address
            && text.contains(&address.to_string())
        {
            return Err(failure(format!(
                "{label} log leaked the federation address"
            )));
        }
    }
    Ok(())
}

fn exercise_federated_modes(alice: &mut ArcClient, bob: &mut ArcClient) -> TestResult {
    alice.send("CAP REQ :standard-replies")?;
    alice.read_until(|line| line.contains(" ACK "))?;
    for (command, expected) in [
        ("MODE #fed +l 3", " MODE #fed +l 3"),
        ("MODE #fed +v :bob", " MODE #fed +v bob"),
        ("MODE #fed +k :federated-key", " MODE #fed +k "),
        ("MODE #fed +k :federated-key-two", " MODE #fed +k "),
    ] {
        alice.send(command)?;
        let acknowledged = alice
            .read_until(|line| {
                line.contains(" MODE #fed ") || line.contains(" FAIL ") || line.contains(" 4")
            })
            .map_err(|error| failure(format!("alice awaiting {expected:?}: {error}")))?;
        assert_contains(&acknowledged, expected)?;
        bob.read_until(|line| line.contains(expected))
            .map_err(|error| failure(format!("bob awaiting {expected:?}: {error}")))?;
    }
    bob.send("PART #fed")?;
    bob.read_until(|line| line.contains(" PART #fed"))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" PART #fed"))?;
    bob.send("JOIN #fed federated-key-two")?;
    bob.read_until(|line| line.contains(" 366 bob #fed "))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #fed"))?;
    for (command, expected) in [
        ("MODE #fed -k", " MODE #fed -k"),
        ("MODE #fed -l", " MODE #fed -l"),
    ] {
        alice.send(command)?;
        bob.read_until(|line| line.contains(expected))?;
        alice.read_until(|line| line.contains(expected))?;
    }
    Ok(())
}

/// Sends channel messages until the edge reports the network unavailable;
/// a message sent before the edge noticed the loss may still be refused
/// only on the next attempt.
fn wait_for_partition(client: &mut ArcClient) -> TestResult<Vec<String>> {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        client.send("PRIVMSG #fed :are you there")?;
        client.send("PING :partition")?;
        let lines = client.read_until(|line| line.contains("PONG"))?;
        if lines
            .iter()
            .any(|line| line.contains("NETWORK_UNAVAILABLE"))
        {
            return Ok(lines);
        }
        if Instant::now() >= deadline {
            return Err(failure(format!(
                "edge never reported the partition: {lines:?}"
            )));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// AUD-16 on a federated network. An edge sends a JOIN to its coordinator as
/// a request with a durable record and fetches the NAMES pages itself, so it
/// never prepares the snapshot this defect stranded; there the edge's own JOIN
/// continuation, plain or labeled, must still answer and then release the
/// command behind it. A JOIN of a local `&` channel by a client of the
/// coordinator itself writes nothing durable and projects nothing to the
/// edges, so the coordinator applies it in the step that admits it, as a
/// core-only node does; it must still answer, plain or labeled, before the
/// TIME behind it. The edge is checked first, so a failure on the coordinator
/// still shows that the edge's path passed.
#[test]
fn joins_on_a_coordinator_and_its_edge_answer_before_the_next_command() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let outcome = wait_for_link(&network.edge_a, 0)
        .and_then(|()| {
            exercise_edge_join_continuation(&network)
                .map_err(|error| failure(format!("on the edge: {error}")))
        })
        .and_then(|()| {
            exercise_coordinator_local_join(&network)
                .map_err(|error| failure(format!("on the coordinator: {error}")))
        });
    let stopped_a = edge_a.stop();
    let stopped_core = coordinator.stop();
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge a log ---\n{}",
            network.coordinator.log_text(),
            network.edge_a.log_text()
        )));
    }
    for (label, status) in [("edge a", stopped_a), ("coordinator", stopped_core)] {
        let status = status.map_err(|error| failure(format!("{label}: {error}")))?;
        if !status.success() {
            return Err(failure(format!("{label} exited with {status}")));
        }
    }
    Ok(())
}

fn exercise_edge_join_continuation(network: &Network) -> TestResult {
    let mut erin = register_when_available(&network.edge_a, "erin")?;
    erin.send("JOIN #plain")?;
    erin.send("AWAY :behind a join")?;
    let replies = erin.read_until(|line| line.contains(" 306 erin "))?;
    assert_contains(&replies, " 353 erin = #plain :")?;
    let names = position_of(&replies, |line| line.contains(" 366 erin #plain "))?;
    let away = position_of(&replies, |line| line.contains(" 306 erin "))?;
    require_before(&replies, names, away, "the 366 must precede the AWAY reply")?;

    erin.send("CAP REQ :message-tags batch labeled-response")?;
    erin.read_until(|line| line.contains(" ACK "))?;
    erin.send("@label=join JOIN #labeled")?;
    erin.send("@label=away AWAY")?;
    let replies = erin.read_until(|line| line.contains(" 305 erin "))?;
    assert_contains(&replies, "@label=join ")?;
    assert_contains(&replies, " 366 erin #labeled ")?;
    let ended = position_of(&replies, |line| line.contains(" BATCH -"))?;
    let away = position_of(&replies, |line| {
        line.starts_with("@label=away ") && line.contains(" 305 erin ")
    })?;
    require_before(
        &replies,
        ended,
        away,
        "the JOIN's label batch must end before the AWAY reply",
    )
}

fn exercise_coordinator_local_join(network: &Network) -> TestResult {
    let mut cora = register_when_available(&network.coordinator, "cora")?;
    cora.send("JOIN &plain")?;
    cora.send("TIME")?;
    let replies = cora.read_until(|line| line.contains(" 391 cora "))?;
    assert_contains(&replies, " JOIN &plain")?;
    assert_contains(&replies, " 353 cora = &plain :")?;
    let names = position_of(&replies, |line| line.contains(" 366 cora &plain "))?;
    let time = position_of(&replies, |line| line.contains(" 391 cora "))?;
    require_before(&replies, names, time, "the 366 must precede the TIME reply")?;

    cora.send("CAP REQ :message-tags batch labeled-response")?;
    cora.read_until(|line| line.contains(" ACK "))?;
    cora.send("@label=join JOIN &labeled")?;
    cora.send("@label=time TIME")?;
    let labeled_time = |line: &str| line.starts_with("@label=time ") && line.contains(" 391 cora ");
    let replies = cora.read_until(labeled_time)?;
    assert_contains(&replies, "@label=join ")?;
    assert_contains(&replies, " JOIN &labeled")?;
    assert_contains(&replies, " 353 cora = &labeled :")?;
    assert_contains(&replies, " 366 cora &labeled ")?;
    let ended = position_of(&replies, |line| line.contains(" BATCH -"))?;
    let time = position_of(&replies, labeled_time)?;
    require_before(
        &replies,
        ended,
        time,
        "the JOIN's label batch must end before the TIME reply",
    )
}

fn position_of(lines: &[String], found: impl Fn(&str) -> bool) -> TestResult<usize> {
    lines
        .iter()
        .position(|line| found(line))
        .ok_or_else(|| failure(format!("expected reply is missing: {lines:?}")))
}

/// Requires the reply at index `first` to precede the reply at index `then`,
/// as a failure the caller reports with both daemons' logs.
fn require_before(lines: &[String], first: usize, then: usize, rule: &str) -> TestResult {
    if first < then {
        Ok(())
    } else {
        Err(failure(format!("{rule}: {lines:?}")))
    }
}

/// The information queries an edge answers itself (BLJ-R1, decision D-28):
/// `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN` and `INFO`, plain and
/// labeled, each followed by `PING`, are answered and the connection stays
/// open; `LINKS` reaches the coordinator's directory. After the coordinator
/// is killed the edge still answers the six (Section 20.10), while `LINKS`
/// fails closed.
#[test]
fn an_edge_answers_its_information_queries_and_keeps_the_connection() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let outcome = wait_for_link(&network.edge_a, 0)
        .and_then(|()| exercise_edge_information(&network, &mut coordinator));
    let stopped_a = edge_a.stop();
    let stopped_core = coordinator.stop();
    if let Err(error) = outcome {
        return Err(failure(format!(
            "{error}\n--- coordinator log ---\n{}\n--- edge a log ---\n{}",
            network.coordinator.log_text(),
            network.edge_a.log_text()
        )));
    }
    let status = stopped_a.map_err(|error| failure(format!("edge a: {error}")))?;
    if !status.success() {
        return Err(failure(format!("edge a exited with {status}")));
    }
    // The scenario killed the coordinator, so it has nothing left to stop.
    if stopped_core.is_ok() {
        return Err(failure("the coordinator outlived its kill"));
    }
    Ok(())
}

/// Each query with the numeric that ends its reply; the fixture configures
/// no MOTD.
const EDGE_INFORMATION: [(&str, &str); 6] = [
    ("MOTD", " 422 "),
    ("LUSERS", " 255 "),
    ("VERSION", " 374 "),
    ("TIME", " 391 "),
    ("ADMIN", " 374 "),
    ("INFO", " 374 "),
];

fn exercise_edge_information(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    let mut iris = register_when_available(&network.edge_a, "iris")?;
    edge_information_round(&mut iris, "active")?;
    iris.send("CAP REQ :message-tags batch labeled-response")?;
    iris.read_until(|line| line.contains(" ACK "))?;
    labeled_edge_information_round(&mut iris, "active")?;
    // LINKS is the coordinator's directory query; its reply follows the
    // coordinator's single-node rendering.
    iris.send("LINKS")?;
    iris.read_until(|line| line.contains(" 374 iris :End of INFO"))?;
    iris.send("PING :links")?;
    iris.read_until(|line| line.ends_with(" :links"))?;

    coordinator.kill()?;
    let refused = wait_for_partition(&mut iris)?;
    assert_contains(&refused, "FAIL PRIVMSG NETWORK_UNAVAILABLE")?;
    edge_information_round(&mut iris, "partitioned")?;
    labeled_edge_information_round(&mut iris, "partitioned")?;
    iris.send("LINKS")?;
    iris.read_until(|line| line.contains("FAIL LINKS NETWORK_UNAVAILABLE"))?;
    iris.send("PING :still-open")?;
    iris.read_until(|line| line.ends_with(" :still-open"))?;
    Ok(())
}

/// Sends the six queries and a PING and reads until every reply and the
/// PONG arrived. The PING is answered at once, while the queries wait behind
/// whatever the connection still has in flight (right after registration,
/// the origin update that carries its session), so the PONG may come first;
/// the replies themselves arrive in order.
fn edge_information_round(client: &mut ArcClient, phase: &str) -> TestResult {
    for (query, _) in EDGE_INFORMATION {
        client.send(query)?;
    }
    let marker = format!(" :information-{phase}");
    client.send(&format!("PING{marker}"))?;
    let mut answered = 0;
    let mut ponged = false;
    let replies = client.read_until(|line| {
        ponged |= line.ends_with(&marker);
        if let Some((_, ending)) = EDGE_INFORMATION.get(answered)
            && line.starts_with(":edge-a.test")
            && line.contains(ending)
        {
            answered += 1;
        }
        ponged && answered == EDGE_INFORMATION.len()
    })?;
    if replies.iter().any(|line| line.contains(" FAIL ")) {
        return Err(failure(format!("{phase}: refused: {replies:?}")));
    }
    Ok(())
}

/// The same with a label on each query: each reply is one labeled line or
/// one labeled batch, and each ends before the next begins.
fn labeled_edge_information_round(client: &mut ArcClient, phase: &str) -> TestResult {
    for (query, _) in EDGE_INFORMATION {
        client.send(&format!("@label={} {query}", query.to_ascii_lowercase()))?;
    }
    let marker = format!(" :labeled-{phase}");
    client.send(&format!("PING{marker}"))?;
    let mut answered = 0;
    let mut ponged = false;
    let replies = client.read_until(|line| {
        ponged |= line.ends_with(&marker);
        if let Some((query, ending)) = EDGE_INFORMATION.get(answered) {
            let label = query.to_ascii_lowercase();
            let single = line.starts_with(&format!("@label={label} ")) && line.contains(ending);
            let batch_end = line.ends_with(&format!(" BATCH -{label}"));
            if single || batch_end {
                answered += 1;
            }
        }
        ponged && answered == EDGE_INFORMATION.len()
    })?;
    if replies.iter().any(|line| line.contains(" FAIL ")) {
        return Err(failure(format!("{phase}: refused: {replies:?}")));
    }
    Ok(())
}

/// An edge answers `LUSERS` in one fixed form that holds no count (decision
/// D-35, which replaces the counted form of D-28): two edges serving
/// different clients and channels send the same reply apart from the server
/// prefix and the nickname, and neither a JOIN and a PART on an edge nor the
/// loss of the coordinator changes it. The coordinator keeps its counted
/// reply over the whole network.
#[test]
fn edges_answer_lusers_in_one_fixed_form() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = wait_for_link(&network.edge_a, 0)
        .and_then(|()| wait_for_link(&network.edge_b, 0))
        .and_then(|()| exercise_static_lusers(&network, &mut coordinator));
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
    for (label, status) in [("edge a", stopped_a), ("edge b", stopped_b)] {
        let status = status.map_err(|error| failure(format!("{label}: {error}")))?;
        if !status.success() {
            return Err(failure(format!("{label} exited with {status}")));
        }
    }
    // The scenario killed the coordinator, so it has nothing left to stop.
    if stopped_core.is_ok() {
        return Err(failure("the coordinator outlived its kill"));
    }
    Ok(())
}

/// The fixed `LUSERS` reply, with the server prefix and the nickname written
/// as `lusers` writes them.
const STATIC_LUSERS: [&str; 2] = [
    ":<server> 251 <nick> :User counts are not published by this server",
    ":<server> 255 <nick> :Local counts are not published by this server",
];

fn exercise_static_lusers(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    // Edge A serves one client and no channel, edge B two clients and a
    // channel.
    let mut lena = register_when_available(&network.edge_a, "lena")?;
    let mut omar = register_when_available(&network.edge_b, "omar")?;
    let _pia = register_when_available(&network.edge_b, "pia")?;
    omar.send("JOIN #b-side")?;
    omar.read_until(|line| line.contains(" 366 omar #b-side "))?;
    let on_a = lusers(&mut lena, "edge-a.test", "lena")?;
    let on_b = lusers(&mut omar, "edge-b.test", "omar")?;
    if on_a != on_b {
        return Err(failure(format!("the edges differ: {on_a:?} {on_b:?}")));
    }
    require_static(&on_a, "edge a")?;
    // The coordinator counts the whole network: the three edge clients, its
    // own client and the channel on edge B.
    let mut cora = register_when_available(&network.coordinator, "cora")?;
    require_counted(&mut cora, 4, 1, "the coordinator")?;
    // A JOIN and a PART on edge A leave its reply as it was, while the
    // coordinator counts the new channel.
    lena.send("JOIN #a-side")?;
    lena.read_until(|line| line.contains(" 366 lena #a-side "))?;
    require_static(&lusers(&mut lena, "edge-a.test", "lena")?, "after a JOIN")?;
    require_counted(&mut cora, 4, 2, "the coordinator after a JOIN")?;
    lena.send("PART #a-side")?;
    lena.read_until(|line| line.contains(" PART #a-side"))?;
    require_static(&lusers(&mut lena, "edge-a.test", "lena")?, "after a PART")?;
    // So does the loss of the coordinator.
    coordinator.kill()?;
    let refused = wait_for_partition(&mut lena)?;
    assert_contains(&refused, "FAIL PRIVMSG NETWORK_UNAVAILABLE")?;
    require_static(&lusers(&mut lena, "edge-a.test", "lena")?, "partitioned")
}

/// Sends `LUSERS` and returns its reply lines with the server prefix and the
/// nickname replaced, so that replies compare across edges.
fn lusers(client: &mut ArcClient, server: &str, nickname: &str) -> TestResult<Vec<String>> {
    client.send("LUSERS")?;
    let end = format!(":{server} 255 {nickname} ");
    let lines = client.read_until(|line| line.starts_with(&end))?;
    let mut reply = Vec::new();
    for line in &lines {
        for code in ["251", "252", "253", "254", "255", "265", "266"] {
            if let Some(rest) = line.strip_prefix(&format!(":{server} {code} {nickname} ")) {
                reply.push(format!(":<server> {code} <nick> {rest}"));
            }
        }
    }
    Ok(reply)
}

/// Sends `LUSERS` and a `PING` to the coordinator's client `cora` and
/// requires the reply read through its `266` to be the counted form for
/// `users` sessions and `channels` channels network-wide.
fn require_counted(
    cora: &mut ArcClient,
    users: usize,
    channels: usize,
    moment: &str,
) -> TestResult {
    cora.send("LUSERS")?;
    cora.send("PING :counted")?;
    let lines = cora.read_until(|line| line.ends_with(" :counted"))?;
    let reply: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|line| {
            ["251", "252", "253", "254", "255", "265", "266"]
                .iter()
                .any(|code| line.starts_with(&format!(":core.test {code} cora ")))
        })
        .collect();
    let expected = [
        format!(":core.test 251 cora :There are {users} users on one server"),
        ":core.test 252 cora 0 :operator(s) online".to_owned(),
        ":core.test 253 cora 0 :unknown connection(s)".to_owned(),
        format!(":core.test 254 cora {channels} :channels formed"),
        format!(":core.test 255 cora :There are {users} users on one server"),
        format!(":core.test 265 cora {users} {users} :Current local users {users}, max {users}"),
        format!(":core.test 266 cora {users} {users} :Current local users {users}, max {users}"),
    ];
    if reply
        .iter()
        .copied()
        .eq(expected.iter().map(String::as_str))
    {
        Ok(())
    } else {
        Err(failure(format!(
            "{moment}: LUSERS is not the counted form for {users} users and {channels} channels: {reply:?}"
        )))
    }
}

fn require_static(reply: &[String], moment: &str) -> TestResult {
    if reply.iter().map(String::as_str).eq(STATIC_LUSERS) {
        Ok(())
    } else {
        Err(failure(format!(
            "{moment}: LUSERS is not the fixed form: {reply:?}"
        )))
    }
}

/// A labeled channel `PRIVMSG` or `NOTICE` from a client of an edge gets
/// exactly one labeled logical response, as a client of the coordinator
/// does (Architecture 9.5): a labeled `ACK` without `echo-message`, and its
/// labeled echo with it. Every other member's copy, on the same edge, on the
/// other edge and on the coordinator, carries no label.
#[test]
fn an_edge_gives_a_labeled_channel_message_one_labeled_response() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = wait_for_link(&network.edge_a, 0)
        .and_then(|()| wait_for_link(&network.edge_b, 0))
        .and_then(|()| exercise_labeled_channel_messages(&network));
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

/// The labeled messages the client of edge A sends to `#echo`, each with
/// whether it negotiated `echo-message` by then.
const LABELED_CHANNEL_MESSAGES: [(&str, &str, bool); 4] = [
    ("p1", "PRIVMSG #echo :privmsg without echo", false),
    ("n1", "NOTICE #echo :notice without echo", false),
    ("p2", "PRIVMSG #echo :privmsg with echo", true),
    ("n2", "NOTICE #echo :notice with echo", true),
];

fn exercise_labeled_channel_messages(network: &Network) -> TestResult {
    let mut iris = register_when_available(&network.edge_a, "iris")?;
    let mut jon = register_when_available(&network.edge_a, "jon")?;
    let mut lia = register_when_available(&network.edge_b, "lia")?;
    let mut kai = register_when_available(&network.coordinator, "kai")?;
    for client in [&mut iris, &mut jon] {
        client.send("CAP REQ :message-tags batch labeled-response")?;
        client.read_until(|line| line.contains(" ACK "))?;
    }
    for (client, nickname) in [
        (&mut kai, "kai"),
        (&mut iris, "iris"),
        (&mut jon, "jon"),
        (&mut lia, "lia"),
    ] {
        client.send("JOIN #echo")?;
        client.read_until(|line| line.contains(&format!(" 366 {nickname} #echo ")))?;
    }
    let mut echoing = false;
    for (label, message, echo) in LABELED_CHANNEL_MESSAGES {
        if echo && !echoing {
            iris.send("CAP REQ :echo-message")?;
            iris.read_until(|line| line.contains(" ACK "))?;
            echoing = true;
        }
        let lines = labeled_exchange(&mut iris, label, message)?;
        let text = message.split_once(" :").map_or("", |(_, text)| text);
        let labeled: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains(&format!("label={label}")))
            .collect();
        let response = match labeled.as_slice() {
            [response] => response.as_str(),
            _ => {
                return Err(failure(format!(
                    "{message}: not one labeled response: {lines:?}"
                )));
            }
        };
        let single = if echo {
            let echoed = response
                .strip_prefix(&format!("@label={label} :iris!"))
                .is_some_and(|rest| rest.ends_with(&format!(" {message}")));
            echoed
                && lines
                    .iter()
                    .filter(|line| line.ends_with(&format!(" :{text}")))
                    .count()
                    == 1
        } else {
            response == format!("@label={label} :edge-a.test ACK")
                && lines
                    .iter()
                    .all(|line| !line.ends_with(&format!(" :{text}")))
        };
        if !single {
            return Err(failure(format!(
                "{message}: the response is not its labeled {}: {lines:?}",
                if echo { "echo" } else { "ACK" }
            )));
        }
    }
    // Every other member, on edge A, on edge B and on the coordinator,
    // received the four messages without a label.
    for (client, nickname) in [(&mut jon, "jon"), (&mut lia, "lia"), (&mut kai, "kai")] {
        let mut received = 0;
        let lines = client.read_until(|line| {
            if LABELED_CHANNEL_MESSAGES
                .iter()
                .any(|(_, message, _)| line.ends_with(&format!(" {message}")))
            {
                received += 1;
            }
            received == LABELED_CHANNEL_MESSAGES.len()
        })?;
        if lines
            .iter()
            .any(|line| line.contains("label=") || line.contains("batch="))
        {
            return Err(failure(format!(
                "{nickname}: a copy carries a label: {lines:?}"
            )));
        }
    }
    Ok(())
}

/// Sends `message` labeled `label`, then a `PING`, and reads until both the
/// `PONG` and a line with the label arrived; a second `PING` then lets any
/// further line about the message arrive before it. Returns every line read.
fn labeled_exchange(client: &mut ArcClient, label: &str, message: &str) -> TestResult<Vec<String>> {
    client.send(&format!("@label={label} {message}"))?;
    client.send(&format!("PING :sent-{label}"))?;
    let (sent, tag) = (format!(" :sent-{label}"), format!("@label={label} "));
    let (mut ponged, mut labeled) = (false, false);
    let mut lines = client.read_until(|line| {
        ponged |= line.ends_with(&sent);
        labeled |= line.starts_with(&tag);
        ponged && labeled
    })?;
    client.send(&format!("PING :settled-{label}"))?;
    let settled = format!(" :settled-{label}");
    lines.extend(client.read_until(|line| line.ends_with(&settled))?);
    Ok(lines)
}

/// Every welcome's `RPL_LUSER*` counters are the figures of its node's own
/// `LUSERS` reply (Architecture 10.2 step 3): two edges serving different
/// clients send the same fixed form, with no count, apart from the server
/// prefix and the nickname, and the coordinator's welcome counts what its
/// `LUSERS` reply counts, the whole network's sessions, as clients join on
/// the coordinator and on the edges.
#[test]
fn welcome_counters_match_each_nodes_lusers_reply() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = wait_for_link(&network.edge_a, 0)
        .and_then(|()| wait_for_link(&network.edge_b, 0))
        .and_then(|()| exercise_welcome_counters(&network));
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

fn exercise_welcome_counters(network: &Network) -> TestResult {
    // Edge A serves one client, edge B two.
    let (mut uma, welcome_a) = welcome_when_available(&network.edge_a, "uma")?;
    let _vic = register_when_available(&network.edge_b, "vic")?;
    let (mut wes, welcome_b) = welcome_when_available(&network.edge_b, "wes")?;
    let on_a = welcome_counters(&welcome_a, "edge-a.test", "uma");
    let on_b = welcome_counters(&welcome_b, "edge-b.test", "wes");
    if on_a != on_b {
        return Err(failure(format!(
            "the edges' welcomes differ: {on_a:?} {on_b:?}"
        )));
    }
    require_static(&on_a, "edge a's welcome")?;
    // Each edge's welcome is its LUSERS reply.
    require_static(&lusers(&mut uma, "edge-a.test", "uma")?, "edge a")?;
    require_static(&lusers(&mut wes, "edge-b.test", "wes")?, "edge b")?;
    // The coordinator counts the edges' three clients with its own, in its
    // welcome as in its LUSERS reply, as clients join on both.
    let _xia = coordinator_counts(network, "xia", 4)?;
    let (_yan, welcome) = welcome_when_available(&network.edge_a, "yan")?;
    require_static(
        &welcome_counters(&welcome, "edge-a.test", "yan"),
        "a later welcome on edge a",
    )?;
    let _zed = coordinator_counts(network, "zed", 6)?;
    Ok(())
}

/// The `RPL_LUSER*` lines of a welcome with the server prefix and the
/// nickname replaced, as `lusers` writes them.
fn welcome_counters(lines: &[String], server: &str, nickname: &str) -> Vec<String> {
    let mut counters = Vec::new();
    for line in lines {
        for code in ["251", "252", "253", "254", "255", "265", "266"] {
            if let Some(rest) = line.strip_prefix(&format!(":{server} {code} {nickname} ")) {
                counters.push(format!(":<server> {code} <nick> {rest}"));
            }
        }
    }
    counters
}

/// Registers `nickname` on the coordinator and requires its welcome and its
/// `LUSERS` reply to count `users` sessions.
fn coordinator_counts(network: &Network, nickname: &str, users: usize) -> TestResult<ArcClient> {
    let (mut client, welcome) = welcome_when_available(&network.coordinator, nickname)?;
    let expected = [format!(
        ":<server> 251 <nick> :There are {users} users and 0 services on 1 servers"
    )];
    let counters = welcome_counters(&welcome, "core.test", nickname);
    if counters != expected {
        return Err(failure(format!(
            "{nickname}'s welcome does not count {users} users: {counters:?}"
        )));
    }
    client.send("LUSERS")?;
    let reply = client.read_until(|line| line.contains(&format!(" 266 {nickname} ")))?;
    let summary = format!(":core.test 251 {nickname} :There are {users} users on one server");
    if !reply.contains(&summary) {
        return Err(failure(format!(
            "{nickname}'s LUSERS does not count {users} users: {reply:?}"
        )));
    }
    Ok(client)
}
