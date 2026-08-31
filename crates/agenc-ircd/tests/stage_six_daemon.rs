//! End-to-end Stage 06 transcript against the production binary, real Unix
//! and TLS transports, and an authenticated on-disk database.
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agenc_ircd_admin::{
    AdminChallenge, AdminCommandTbs, AdminSessionId, Challenge, ConfirmationToken,
    TransportBinding, TransportKind, decode_fixed_base64url, encode_base64url, render_admin_tag,
};
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
    AccountRandomId, ChannelInstanceId, DatabaseId, NetworkId, OperatorId, RecoveryEpoch, ServerId,
    ServerIncarnation, UserId,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;
type TlsClient = StreamOwned<ClientConnection, TcpStream>;

const DNS_NAME: &str = "node.test";
const DATABASE_MAX_BYTES: u64 = 1_073_741_824;
const BACKUP_MAX_BYTES: u64 = 2_147_483_648;
const DISK_RESERVE_BYTES: u64 = 67_108_864;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const START_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn failure(message: impl Into<String>) -> TestError {
    io::Error::other(message.into()).into()
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create() -> TestResult<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| failure("HOME is unavailable"))?;
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(home).join(format!(
            ".agenc-ircd-stage-six-test-{}-{sequence}",
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

struct LiveFixture {
    _root: TestRoot,
    config_path: PathBuf,
    log_dir: PathBuf,
    admin_socket: PathBuf,
    public_address: SocketAddr,
    network_id: NetworkId,
    server_id: ServerId,
    operator_id: OperatorId,
    operator_key: Ed25519SecretKey,
    tls: TlsFixture,
}

impl LiveFixture {
    fn create() -> TestResult<Self> {
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

        let network_id = NetworkId::from_bytes([1; 32]);
        let server_id = ServerId::from_bytes([2; 16]);
        let operator_id = OperatorId::from_bytes([3; 16]);
        let server_incarnation = ServerIncarnation::from_bytes([4; 16]);
        let database_id = DatabaseId::from_bytes([5; 16]);
        let recovery_epoch = RecoveryEpoch::from_bytes([6; 16]);
        let storage_master = [7; 32];
        let rollback_guard = [8; 32];
        let login_index = [9; 32];
        let federation_signing = [10; 32];
        let backup_signing = [11; 32];
        let audit_signing = [12; 32];
        let operator_signing = [13; 32];
        let account_hpke = [14; 32];
        let opaque_fake_credential = [15; 32];
        let sequencer = [16; 32];
        let opaque = OpaqueProfile::generate(network_id)?;

        for (name, bytes) in [
            ("storage-master.key", storage_master.as_slice()),
            ("rollback-guard.key", rollback_guard.as_slice()),
            ("login-index-g1.key", login_index.as_slice()),
            ("federation-signing.key", federation_signing.as_slice()),
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
            network_id,
            server_id,
            server_incarnation,
            database_id,
            recovery_epoch,
            storage_master,
            rollback_guard,
            login_index,
            &opaque,
        )?;

        let tls = TlsFixture::mint([17; 32], DNS_NAME)?;
        write_private(&tls_dir.join("server.crt"), tls.leaf_certificate_der())?;
        write_private(
            &tls_dir.join("server.key"),
            tls.leaf_private_key_pkcs8_der(),
        )?;

        let public_address = reserve_loopback_address()?;
        let admin_socket = runtime_dir.join("admin.sock");
        let uid = fs::metadata(root.path())?.uid();
        let hpke = AccountHpkePrivateKey::from_bytes(account_hpke)?;
        let values = InitValues {
            profile: InitProfile::Public,
            network_id,
            server_id,
            role: NodeRole::Coordinator,
            coordinator_server_id: server_id,
            server_name: DnsName::parse(DNS_NAME)?,
            display_name: DisplayLabel::parse("StageSix")?,
            data_dir: data_dir.clone(),
            runtime_dir: runtime_dir.clone(),
            tls_dir,
            dns_name: Some(DnsName::parse(DNS_NAME)?),
            account_service_hpke_public_key: *hpke.public_key()?.as_bytes(),
            operator: OperatorTemplate {
                operator_id,
                signing_public_key: *Ed25519SecretKey::from_bytes(operator_signing)
                    .public_key()
                    .as_bytes(),
            },
        };
        let mut config = render_template(&values)?;
        replace_once(
            &mut config,
            "memory_budget_bytes = 4294967296",
            "memory_budget_bytes = 1073741824",
        )?;
        replace_once(
            &mut config,
            "quiesce_seconds = 5\ndrain_seconds = 20\nflush_seconds = 10\nstop_seconds = 5",
            "quiesce_seconds = 2\ndrain_seconds = 4\nflush_seconds = 4\nstop_seconds = 8",
        )?;
        replace_once(
            &mut config,
            "enabled = false\npurpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"\nmax_connections = 50000",
            &format!(
                "enabled = true\npurpose = \"client_tls\"\nbind = \"{public_address}\"\nmax_connections = 32"
            ),
        )?;
        replace_once(
            &mut config,
            "enabled = false\npurpose = \"admin_local\"",
            "enabled = true\npurpose = \"admin_local\"",
        )?;
        replace_once(
            &mut config,
            "allowed_uids = [0]",
            &format!("allowed_uids = [{uid}]"),
        )?;
        replace_once(
            &mut config,
            "database_max_bytes = 85899345920\nbackup_max_bytes = 107374182400",
            &format!(
                "database_max_bytes = {DATABASE_MAX_BYTES}\nbackup_max_bytes = {BACKUP_MAX_BYTES}"
            ),
        )?;
        replace_once(
            &mut config,
            "disk_reserve_bytes = 1073741824\ndisk_reserve_percent = 5",
            &format!("disk_reserve_bytes = {DISK_RESERVE_BYTES}\ndisk_reserve_percent = 1"),
        )?;
        replace_once(
            &mut config,
            "integrity_checkpoint_manifests = 100000",
            "integrity_checkpoint_manifests = 10000",
        )?;
        replace_once(
            &mut config,
            "local_uids = [0]",
            &format!("local_uids = [{uid}]"),
        )?;
        replace_once(
            &mut config,
            "permissions = [\"observe\", \"configure\", \"sessions\", \"accounts\", \"channels\", \"backup\", \"audit\", \"process\"]",
            "permissions = [\"observe\", \"configure\", \"sessions\", \"accounts\", \"channels\", \"federation\", \"backup\", \"audit\", \"process\"]",
        )?;
        replace_once(
            &mut config,
            "\n[privacy]",
            "\n[limits.rate.registered_command]\nrefill_tokens = 40\nrefill_seconds = 1\nburst = 200\n\n[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10\n\n[privacy]",
        )?;
        let config_path = etc.join("config.toml");
        write_private(&config_path, config.as_bytes())?;

        Ok(Self {
            _root: root,
            config_path,
            log_dir: data_dir.join("logs"),
            admin_socket,
            public_address,
            network_id,
            server_id,
            operator_id,
            operator_key: Ed25519SecretKey::from_bytes(operator_signing),
            tls,
        })
    }

    fn client_config(&self) -> TestResult<Arc<ClientConfig>> {
        Ok(build_client_config(
            TrustStore::parse(self.tls.ca_certificate_der())?,
            Some(CLIENT_ALPN),
            None,
        )?)
    }

    fn log_excerpt(&self) -> String {
        let Ok(entries) = fs::read_dir(&self.log_dir) else {
            return String::from("<log directory unavailable>");
        };
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        paths.sort();
        let mut excerpt = String::new();
        for path in paths.into_iter().take(16) {
            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            let remaining = 65_536_usize.saturating_sub(excerpt.len());
            let Some(slice) = bytes.get(..bytes.len().min(remaining)) else {
                continue;
            };
            excerpt.push_str(&String::from_utf8_lossy(slice));
            if excerpt.len() >= 65_536 {
                break;
            }
        }
        excerpt
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

#[allow(clippy::too_many_arguments)]
fn initialize_database(
    state_dir: &Path,
    network_id: NetworkId,
    server_id: ServerId,
    server_incarnation: ServerIncarnation,
    database_id: DatabaseId,
    recovery_epoch: RecoveryEpoch,
    storage_master: [u8; 32],
    rollback_guard: [u8; 32],
    login_index: [u8; 32],
    opaque: &OpaqueProfile,
) -> TestResult {
    let login_key = LoginIndexKey::from_bytes(login_index);
    let key_state = LoginIndexKeyState::stable(1, login_key.key_id(network_id))?;
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
            network_id,
            server_id,
            server_incarnation,
            database_id,
            1,
            SCHEMA_GENERATION,
            recovery_epoch,
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

fn reserve_loopback_address() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
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

    fn wait(&mut self) -> TestResult<ExitStatus> {
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| failure("daemon was already joined"))?;
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

struct AdminClient<'a> {
    reader: BufReader<UnixStream>,
    fixture: &'a LiveFixture,
    session_id: AdminSessionId,
    counter: u64,
}

impl<'a> AdminClient<'a> {
    fn connect(fixture: &'a LiveFixture) -> TestResult<Self> {
        let stream = connect_admin(&fixture.admin_socket)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut reader = BufReader::new(stream);
        let challenge_line = read_line(&mut reader)?;
        let tokens = challenge_line.split_ascii_whitespace().collect::<Vec<_>>();
        if tokens.get(..7).is_none_or(|prefix| {
            prefix.first() != Some(&"NOTE")
                || prefix.get(1) != Some(&"OPER")
                || prefix.get(2) != Some(&"CHALLENGE")
                || prefix.get(5) != Some(&"local")
        }) {
            return Err(failure(format!(
                "unexpected administrative challenge: {challenge_line}"
            )));
        }
        let session_id = AdminSessionId::from_bytes(decode_fixed_base64url::<16>(
            tokens
                .get(3)
                .ok_or_else(|| failure("challenge session missing"))?
                .as_bytes(),
        )?);
        let challenge = Challenge::from_bytes(decode_fixed_base64url::<32>(
            tokens
                .get(4)
                .ok_or_else(|| failure("challenge nonce missing"))?
                .as_bytes(),
        )?);
        let binding = TransportBinding::from_bytes(decode_fixed_base64url::<32>(
            tokens
                .get(6)
                .ok_or_else(|| failure("challenge binding missing"))?
                .as_bytes(),
        )?);
        let challenge = AdminChallenge::new(session_id, challenge, TransportKind::Local, binding);

        reader.get_mut().write_all(b"PING bootstrap\r\n")?;
        reader.get_mut().flush()?;
        assert_eq!(read_line(&mut reader)?, "PONG :bootstrap");
        let proof =
            challenge.sign_oper(fixture.network_id, fixture.server_id, &fixture.operator_key)?;
        let oper = format!(
            "OPER {} {}\r\n",
            fixture.operator_id.to_base64url(),
            encode_base64url(proof.as_bytes())
        );
        reader.get_mut().write_all(oper.as_bytes())?;
        reader.get_mut().flush()?;
        Ok(Self {
            reader,
            fixture,
            session_id,
            counter: 0,
        })
    }

    fn send(&mut self, command: &str, confirmation: Option<&ConfirmationToken>) -> TestResult {
        let confirmation_hash = confirmation.map(ConfirmationToken::hash).transpose()?;
        let tbs = AdminCommandTbs::new(
            self.fixture.network_id,
            self.fixture.server_id,
            self.session_id,
            self.counter,
            confirmation_hash,
            command.as_bytes(),
        )?;
        let signature = tbs.sign(&self.fixture.operator_key)?;
        let tag = render_admin_tag(self.counter, &signature, confirmation);
        let line = format!("{tag} {command}\r\n");
        self.reader.get_mut().write_all(line.as_bytes())?;
        self.reader.get_mut().flush()?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| failure("admin command counter overflow"))?;
        Ok(())
    }

    fn command_line(&mut self, command: &str) -> TestResult<String> {
        self.send(command, None)?;
        read_line(&mut self.reader)
    }

    fn command_until(&mut self, command: &str, ending: &str) -> TestResult<Vec<String>> {
        self.send(command, None)?;
        read_until(&mut self.reader, |line| line.contains(ending))
    }

    fn command_batch(&mut self, command: &str) -> TestResult<Vec<String>> {
        self.send(command, None)?;
        read_until(&mut self.reader, |line| line.starts_with("BATCH -"))
    }

    fn confirm_process(&mut self, command: &str) -> TestResult {
        self.send(command, None)?;
        let line = read_line(&mut self.reader)?;
        let token_text = line
            .split_ascii_whitespace()
            .nth(3)
            .ok_or_else(|| failure(format!("confirmation token missing: {line}")))?;
        let token = ConfirmationToken::parse(token_text.as_bytes())?;
        self.send(command, Some(&token))
    }

    fn quit(mut self) -> TestResult {
        self.send("QUIT", None)?;
        let mut byte = [0_u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => Ok(()),
            Ok(_) => Err(failure("admin QUIT returned unexpected output")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn connect_admin(path: &Path) -> TestResult<UnixStream> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                let _transient = error;
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(failure(format!("admin listener did not start: {error}")));
            }
        }
    }
}

struct IrcClient {
    reader: BufReader<TlsClient>,
}

impl IrcClient {
    fn connect(fixture: &LiveFixture) -> TestResult<Self> {
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
        let name = ServerName::try_from(DNS_NAME.to_owned())?;
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

    fn send_until(&mut self, command: &str, ending: &str) -> TestResult<Vec<String>> {
        self.send(command)?;
        read_until(&mut self.reader, |line| line.contains(ending))
    }

    fn register(&mut self) -> TestResult<Vec<String>> {
        self.send("CAP LS 302")?;
        self.send("CAP REQ :account-notify account-tag away-notify batch cap-notify echo-message labeled-response message-ids message-tags server-time setname standard-replies")?;
        self.send("NICK LiveUser")?;
        self.send("USER live 0 * :Live User")?;
        self.send("CAP END")?;
        read_until(&mut self.reader, |line| {
            line.contains(" 376 ") || line.contains(" 422 ")
        })
    }

    fn shutdown_lines(&mut self) -> TestResult<Vec<String>> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return Ok(lines),
                Ok(_) => {
                    lines.push(line.trim_end_matches(['\r', '\n']).to_owned());
                    if lines.len() > 128 {
                        return Err(failure("shutdown transcript exceeded 128 lines"));
                    }
                }
                Err(error)
                    if !lines.is_empty()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                                | io::ErrorKind::UnexpectedEof
                        ) =>
                {
                    return Ok(lines);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

fn read_line<R: BufRead>(reader: &mut R) -> TestResult<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(failure("transport closed before the expected reply"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_until<R: BufRead>(
    reader: &mut R,
    mut complete: impl FnMut(&str) -> bool,
) -> TestResult<Vec<String>> {
    let mut lines = Vec::new();
    for _ in 0..256 {
        let line = match read_line(reader) {
            Ok(line) => line,
            Err(error) => {
                return Err(failure(format!(
                    "reply ended before its terminator ({error}); received {lines:?}"
                )));
            }
        };
        let done = complete(&line);
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
    Err(failure("reply exceeded the 256-line transcript bound"))
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

fn exercise_client(fixture: &LiveFixture) -> TestResult<IrcClient> {
    let mut client = IrcClient::connect(fixture)?;
    let registered = client.register()?;
    assert_contains(&registered, " 001 LiveUser ")?;

    let public_oper = client.send_until("OPER root password", " 481 ")?;
    assert_contains(&public_oper, " 481 ")?;
    assert_contains(&client.send_until("MOTD", " 422 ")?, " 422 ")?;
    assert_contains(&client.send_until("VERSION", " 374 ")?, "agenc-ircd-0.0.0")?;
    assert_contains(&client.send_until("TIME", " 391 ")?, " 391 ")?;
    assert_contains(&client.send_until("INFO", " 374 ")?, " 374 ")?;
    assert_contains(
        &client.send_until("LINKS", " 374 ")?,
        "topology is not publicly exposed",
    )?;
    assert_contains(&client.send_until("LUSERS", " 255 ")?, " 255 ")?;

    assert_contains(&client.send_until("JOIN #live", " 366 ")?, " 366 ")?;
    assert_contains(&client.send_until("MODE #live", " 329 ")?, " 324 ")?;
    assert_contains(
        &client.send_until("MODE #live +imt", " MODE #live ")?,
        " MODE #live ",
    )?;
    assert_contains(
        &client.send_until("TOPIC #live :production topic", " TOPIC #live ")?,
        " TOPIC #live ",
    )?;
    assert_contains(&client.send_until("TOPIC #live", " 333 ")?, " 332 ")?;
    assert_contains(&client.send_until("NAMES #live", " 366 ")?, " 353 ")?;
    assert_contains(&client.send_until("LIST", " 323 ")?, " 322 ")?;
    assert_contains(&client.send_until("WHO #live", " 315 ")?, " 352 ")?;
    assert_contains(&client.send_until("WHOIS LiveUser", " 318 ")?, " 311 ")?;
    assert_contains(&client.send_until("WHOWAS Nobody", " 369 ")?, " 406 ")?;
    assert_contains(
        &client.send_until("ISON LiveUser Nobody", " 303 ")?,
        "LiveUser",
    )?;
    assert_contains(
        &client.send_until("USERHOST LiveUser", " 303 ")?,
        "LiveUser",
    )?;
    assert_contains(&client.send_until("MODE LiveUser", " 221 ")?, " 221 ")?;

    assert_contains(
        &client.send_until("PRIVMSG #live :hello production", " PRIVMSG #live ")?,
        "hello production",
    )?;
    assert_contains(
        &client.send_until("NOTICE #live :notice production", " NOTICE #live ")?,
        "notice production",
    )?;
    assert_contains(
        &client.send_until("@+typing=active TAGMSG #live", " TAGMSG #live")?,
        " TAGMSG #live",
    )?;
    assert_contains(&client.send_until("AWAY :out to lunch", " 306 ")?, " 306 ")?;
    assert_contains(&client.send_until("AWAY", " 305 ")?, " 305 ")?;
    assert_contains(
        &client.send_until("SETNAME :Live Operator", " SETNAME ")?,
        "Live Operator",
    )?;
    assert_contains(
        &client.send_until("NICK LiveRenamed", " NICK ")?,
        "LiveRenamed",
    )?;
    assert_contains(
        &client.send_until("PART #live :leaving now", " PART #live ")?,
        "leaving now",
    )?;
    assert_contains(&client.send_until("JOIN #live", " 366 ")?, " 366 ")?;
    Ok(client)
}

fn exercise_admin(fixture: &LiveFixture) -> TestResult<AdminClient<'_>> {
    let mut admin = AdminClient::connect(fixture)?;
    assert_eq!(admin.command_line("PING live")?, "PONG :live");
    admin.send("PONG live", None)?;
    assert_eq!(admin.command_line("PING after-pong")?, "PONG :after-pong");

    assert_eq!(admin.command_line("MOTD")?, "422 * :MOTD File is missing");
    assert_contains(
        &admin.command_until("VERSION", " 374 ")?,
        "agenc-ircd-0.0.0",
    )?;
    assert_contains(&[admin.command_line("TIME")?], " 391 ")?;
    let info = admin.command_until("INFO", " 374 ")?;
    assert_eq!(info.len(), 2);
    assert_eq!(
        info.first().map(String::as_str),
        Some(":agenc-ircd 371 * :health readiness=1 liveness=1")
    );
    assert_contains(
        &admin.command_until("LINKS", " 374 ")?,
        "topology is not exposed",
    )?;

    for (selector, fields) in [
        ("RUNTIME", 9_usize),
        ("STORAGE", 14),
        ("FEDERATION", 7),
        ("QUEUES", 10),
        ("RATES", 8),
        ("E2EE", 9),
    ] {
        let lines = admin.command_batch(&format!("STATS {selector}"))?;
        assert_eq!(lines.len(), fields + 2);
        assert_contains(&lines, &format!("agenc.ag/stats {selector} {fields} "))?;
        if selector == "E2EE" {
            for line in lines.iter().skip(1).take(fields) {
                assert!(line.ends_with(" 0 :Statistic value"));
            }
        }
    }

    let user = UserId::from_bytes([31; 16]).to_base64url();
    assert_contains(
        &[admin.command_line(&format!("KILL {user} :test target"))?],
        "FAIL KILL INVALID_TARGET",
    )?;
    let account = AccountRandomId::from_bytes([32; 16])
        .to_account_id()
        .to_text();
    assert_contains(
        &[admin.command_line(&format!("ACCOUNT SUSPEND {account} 60 :test target"))?],
        "FAIL ACCOUNT INVALID_TARGET",
    )?;
    assert_contains(
        &[admin.command_line(&format!("ACCOUNT RESTORE {account} :test target"))?],
        "FAIL ACCOUNT INVALID_TARGET",
    )?;
    let channel = ChannelInstanceId::from_bytes([33; 16]).to_base64url();
    assert_contains(
        &[admin.command_line(&format!("CHANNEL QUARANTINE {channel} :test target"))?],
        "FAIL CHANNEL INVALID_TARGET",
    )?;
    let peer = ServerId::from_bytes([34; 16]).to_base64url();
    for (verb, command) in [
        ("CONNECT", format!("CONNECT {peer} :test target")),
        ("SQUIT", format!("SQUIT {peer} :test target")),
        ("PEER", format!("PEER QUARANTINE {peer} :test target")),
    ] {
        assert_eq!(
            admin.command_line(&command)?,
            format!("FAIL {verb} UNAVAILABLE :Command unavailable")
        );
    }

    assert_eq!(
        admin.command_line("REHASH :test reload")?,
        "NOTE REHASH OK :Configuration unchanged"
    );
    assert_eq!(
        admin.command_line("BACKUP CREATE :test backup")?,
        "NOTE BACKUP OK :Backup created"
    );
    let export = admin.command_batch("AUDIT EXPORT 0 0")?;
    assert_contains(&export, "agenc.ag/audit 0 0")?;
    Ok(admin)
}

#[test]
fn production_daemon_serves_restarts_reconciles_and_stops() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut first = DaemonProcess::start(&fixture.config_path)?;
    let mut client = exercise_client(&fixture)?;
    let mut admin = exercise_admin(&fixture)?;

    let disposable = AdminClient::connect(&fixture)?;
    disposable.quit()?;
    admin.confirm_process("RESTART :test restart")?;
    let shutdown = client.shutdown_lines()?;
    assert_contains(&shutdown, "ERROR :Server shutting down")?;
    let restart_status = first.wait()?;
    if restart_status.code() != Some(75) {
        return Err(failure(format!(
            "restart exited with {restart_status}; logs: {}",
            fixture.log_excerpt()
        )));
    }

    let mut second = DaemonProcess::start(&fixture.config_path)?;
    let mut admin = AdminClient::connect(&fixture)?;
    let info = admin.command_until("INFO", " 374 ")?;
    assert_eq!(
        info.first().map(String::as_str),
        Some(":agenc-ircd 371 * :health readiness=1 liveness=1")
    );
    admin.confirm_process("DIE :test shutdown")?;
    assert!(second.wait()?.success());

    let onboarding = Command::new(env!("CARGO_BIN_EXE_agenc-ircd"))
        .arg("print-onboarding")
        .arg("--config")
        .arg(&fixture.config_path)
        .output()?;
    assert!(onboarding.status.success());
    assert!(onboarding.stderr.is_empty());
    assert_contains(
        &[String::from_utf8(onboarding.stdout)?],
        &fixture.network_id.to_base64url(),
    )?;
    Ok(())
}
