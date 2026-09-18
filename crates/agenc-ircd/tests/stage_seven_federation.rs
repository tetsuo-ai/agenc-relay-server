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

use agenc_ircd_auth::OpaqueProfile;
use agenc_ircd_config::{
    DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName, InitProfile, InitValues, NodeRole,
    OperatorTemplate, encode_base64url_32, render_template,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, audit_signing_key_id, backup_signing_key_id,
};
use agenc_ircd_runtime::tls::{CLIENT_ALPN, TrustStore, build_client_config};
use agenc_ircd_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, SCHEMA_GENERATION,
    StateDirectory, StorageEngineLimits, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StoredKey, TableId, embedded_storage_qualifications,
    initialize_storage,
};
use agenc_ircd_testkit::TlsFixture;
use agenc_ircd_types::{
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
            ".agenc-ircd-stage-seven-test-{}-{sequence}",
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
        let child = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
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

struct IrcClient {
    reader: BufReader<TlsClient>,
}

impl IrcClient {
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
fn register_when_available(fixture: &NodeFixture, nickname: &str) -> TestResult<IrcClient> {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        let mut client = match IrcClient::connect(fixture) {
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
                return Ok(client);
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
    assert_contains(&relayed, ":bob!")?;
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

fn exercise_federated_modes(alice: &mut IrcClient, bob: &mut IrcClient) -> TestResult {
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
fn wait_for_partition(client: &mut IrcClient) -> TestResult<Vec<String>> {
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
