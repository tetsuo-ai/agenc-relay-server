//! End-to-end Stage 06 transcript against the production binary, real Unix
//! and TLS transports, and an authenticated on-disk database.
#![forbid(unsafe_code)]

#[path = "support/loopback_ports.rs"]
mod loopback_ports;

#[path = "stage_six_daemon/idle_capacity.rs"]
mod idle_capacity;

#[path = "stage_six_daemon/pipelined_commands.rs"]
mod pipelined_commands;
#[path = "stage_six_daemon/runtime_regressions.rs"]
mod runtime_regressions;
#[path = "stage_six_daemon/service_user.rs"]
mod service_user;

#[path = "stage_six_daemon/stage_ten.rs"]
mod stage_ten;

#[path = "stage_six_daemon/stage_ten_tor.rs"]
mod stage_ten_tor;

#[path = "stage_six_daemon/welcome_burst.rs"]
mod welcome_burst;

#[cfg(feature = "history")]
#[path = "stage_six_daemon/history.rs"]
mod history;

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use agenc_relay_admin::{
    AdminChallenge, AdminCommandTbs, AdminSessionId, Challenge, ConfirmationToken,
    TransportBinding, TransportKind, decode_fixed_base64url, encode_base64url, render_admin_tag,
};
use agenc_relay_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountRequestPayload,
    AccountServiceEnvelope, AccountServiceResponse, AccountServiceResponsePayload,
    AuthenticationFinish, AuthenticationStart, Completion, CreationFinish, CreationStart,
    CredentialChangeFinish, CredentialChangeStart, OpaqueKe1, OpaqueKe3, OpaqueProfile,
    OpaqueRegistrationRequest, encode_request_plaintext, finish_registration,
    open_and_parse_response,
};
use agenc_relay_config::{
    DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName, InitProfile, InitValues, NodeRole,
    OperatorTemplate, SecretSet, ValidationDepth, encode_base64url_32, load_config,
    render_template,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, AccountRequestBinding, AccountResponseOpenToken, Ed25519SecretKey,
    LoginIndexKey, OsEntropy, RollbackGuardRootKey, StorageDigest, StorageMasterKey,
    audit_signing_key_id, backup_signing_key_id, seal_account_request,
};
use agenc_relay_runtime::tls::{
    ADMIN_ALPN, CLIENT_ALPN, CertChain, PrivateKey, TrustStore, build_client_config,
};
use agenc_relay_storage::{
    DatabaseHeaderTbs, InitialStorageRecord, LIVE_RECORD_KIND, LOGIN_INDEX_KEY_STATE_KEY,
    LoginIndexKeyState, OPAQUE_FAKE_RECORD_KEY, PersistentRecordValue, SCHEMA_GENERATION,
    StateDirectory, StorageEngineLimits, StorageInitializationConfig, StorageInitializationMode,
    StorageInitializationOutcome, StoredKey, TableId, embedded_storage_qualifications,
    initialize_storage,
};
use agenc_relay_testkit::TlsFixture;
use agenc_relay_types::{
    AccountId, AccountRandomId, AccountServiceCompletionStatus, ChannelInstanceId, DatabaseId,
    NetworkId, NormalizedLogin, OpaqueCredentialId, OperatorId, RecoveryEpoch, RequestId, ServerId,
    ServerIncarnation, UserId,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    Ristretto255, TripleDh,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult<T = ()> = Result<T, TestError>;
type TlsClient = StreamOwned<ClientConnection, TcpStream>;

const DNS_NAME: &str = "node.test";
const ADMIN_EXPORTER_LABEL: &[u8] = b"EXPORTER-agenc-chat-admin-v1";
const CORE_V1_TRANSCRIPT: &str =
    include_str!("../../../test-data/transcripts/stage-six-core-v1.transcript");
const CORE_V1_TRANSCRIPT_STEPS: usize = 4;
const MAX_CORE_V1_TRANSCRIPT_STEP_BYTES: usize = 4_610;
const DATABASE_MAX_BYTES: u64 = 1_073_741_824;
const BACKUP_MAX_BYTES: u64 = 2_147_483_648;
const DISK_RESERVE_BYTES: u64 = 67_108_864;
/// The software name the daemon reports, which follows the workspace version.
const SOFTWARE_NAME: &str = concat!("arcd-", env!("CARGO_PKG_VERSION"));
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a fixture waits for a daemon it started to open its listener. A debug daemon on
/// a host running several times more test threads than cores needed more than 20 seconds
/// (issue #175); the wait ends as soon as the listener answers, so a generous bound costs a
/// passing test nothing.
const START_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
/// Fresh connections the guest helpers open before giving up on a silent close.
const FRESH_CONNECTION_ATTEMPTS: usize = 4;
/// Pause between those attempts.
const FRESH_CONNECTION_PAUSE: Duration = Duration::from_millis(250);
/// Test-only retention: when this variable names a directory, a fixture that
/// ends in a panic or a returned error keeps its bounded daemon logs and a
/// diagnostics record there (private modes, no keys, databases, or
/// configuration). A fixture that succeeds always cleans up.
const RETAIN_ENV: &str = "AGENC_RELAY_STAGE_SIX_RETAIN_DIR";
/// Test-only strictness: when set, every fresh-connection helper makes one
/// attempt, so a silent close after TLS fails the test instead of retrying.
const STRICT_ADMISSION_ENV: &str = "AGENC_RELAY_STAGE_SIX_STRICT_ADMISSION";
/// Upper bound on the daemon log bytes one failed fixture retains.
const RETAINED_LOG_BYTES: usize = 4 * 1_048_576;
/// Upper bound on the diagnostics entries one fixture records.
const DIAGNOSTIC_ENTRIES: usize = 256;
const ACCOUNT_HPKE_PRIVATE: [u8; 32] = [14; 32];
const ACCOUNT_PASSWORD: &[u8] = b"stage six live account password";
const REPLACEMENT_PASSWORD: &[u8] = b"stage six replacement password";
const TEST_ARGON2_SALT: [u8; 16] = [0; 16];
const AUTH_CHUNK_CHARACTERS: usize = 400;
const ACCOUNT_REQUEST_CHARACTERS: usize = 6_302;
const ACCOUNT_RESPONSE_CHARACTERS: usize = 5_790;
const SASL_REQUEST_CHARACTERS: usize = 6_304;
const SASL_RESPONSE_CHARACTERS: usize = 5_792;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestOpaqueSuite;

impl CipherSuite for TestOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = TestArgon2id;
}

#[derive(Default)]
struct TestArgon2id;

impl Ksf for TestArgon2id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        if input.len() != 64 {
            return Err(InternalError::KsfError);
        }
        let parameters =
            Params::new(65_536, 3, 4, Some(64)).map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut output = GenericArray::default();
        argon2
            .hash_password_into(&input, &TEST_ARGON2_SALT, &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

struct TestOpaqueRng {
    failed: bool,
}

impl TestOpaqueRng {
    const fn new() -> Self {
        Self { failed: false }
    }

    fn fill_or_latch(&mut self, destination: &mut [u8]) {
        if self.failed || OsEntropy::fill(destination).is_err() {
            destination.fill(0);
            self.failed = true;
        }
    }

    fn require_success(&self) -> TestResult {
        if self.failed {
            Err(failure("test OPAQUE entropy was unavailable"))
        } else {
            Ok(())
        }
    }
}

impl RngCore for TestOpaqueRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_or_latch(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_or_latch(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.fill_or_latch(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_or_latch(destination);
        Ok(())
    }
}

impl CryptoRng for TestOpaqueRng {}

fn failure(message: impl Into<String>) -> TestError {
    io::Error::other(message.into()).into()
}

fn opaque_context(network_id: NetworkId) -> Vec<u8> {
    let mut context = b"agenc-chat account authentication v1".to_vec();
    context.extend_from_slice(network_id.as_bytes());
    context
}

fn opaque_identifiers<'a>(
    network_id: &'a NetworkId,
    credential_id: &'a OpaqueCredentialId,
) -> Identifiers<'a> {
    Identifiers {
        client: Some(credential_id.expose_for_account_service()),
        server: Some(network_id.as_bytes()),
    }
}

fn seal_account_payload(
    network_id: NetworkId,
    request_seed: u8,
    payload: AccountRequestPayload,
) -> TestResult<(
    [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
    AccountResponseOpenToken,
)> {
    let private_key = AccountHpkePrivateKey::from_bytes(ACCOUNT_HPKE_PRIVATE)?;
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        network_id,
        RecoveryEpoch::from_bytes([6; 16]),
        public_key.key_id(),
        RequestId::from_bytes([request_seed; 16]),
        payload.message_kind(),
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    Ok((*envelope.as_bytes(), token))
}

fn open_account_payload(
    token: AccountResponseOpenToken,
    bytes: Vec<u8>,
) -> TestResult<AccountServiceResponsePayload> {
    let encoded: [u8; ACCOUNT_SERVICE_RESPONSE_BYTES] = bytes
        .try_into()
        .map_err(|_| failure("account response had the wrong exact length"))?;
    let response = AccountServiceResponse::parse(encoded)?;
    Ok(open_and_parse_response(token, &response)?)
}

/// What a fixture knows about its own run: phase markers, every connection
/// attempt with its reason, the daemon child's exit, and the first failure.
#[derive(Default)]
struct Diagnostics {
    phases: Vec<String>,
    attempts: Vec<String>,
    child_exit: Option<String>,
    first_failure: Option<String>,
}

impl Diagnostics {
    fn push_bounded(entries: &mut Vec<String>, text: String) {
        if entries.len() < DIAGNOSTIC_ENTRIES {
            entries.push(text);
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("child_exit: ");
        out.push_str(self.child_exit.as_deref().unwrap_or("<not joined>"));
        out.push_str("\nfirst_failure: ");
        out.push_str(self.first_failure.as_deref().unwrap_or("<none>"));
        out.push_str("\nphases:\n");
        for phase in &self.phases {
            out.push_str("  ");
            out.push_str(phase);
            out.push('\n');
        }
        out.push_str("attempts:\n");
        for attempt in &self.attempts {
            out.push_str("  ");
            out.push_str(attempt);
            out.push('\n');
        }
        out
    }
}

fn strict_admission() -> bool {
    std::env::var_os(STRICT_ADMISSION_ENV).is_some_and(|value| !value.is_empty())
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create() -> TestResult<Self> {
        let home = std::env::var_os("HOME").ok_or_else(|| failure("HOME is unavailable"))?;
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(home).join(format!(
            ".agenc-relay-stage-six-test-{}-{sequence}",
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
    diagnostics: Arc<Mutex<Diagnostics>>,
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
                local_uid: 0,
                operator_id,
                signing_public_key: *Ed25519SecretKey::from_bytes(operator_signing)
                    .public_key()
                    .as_bytes(),
            },
        };
        let mut config = render_template(&values)?;
        replace_once(
            &mut config,
            "memory_budget_bytes = 6442450944",
            "memory_budget_bytes = 1073741824",
        )?;
        replace_once(
            &mut config,
            "registration = \"closed\"",
            "registration = \"open\"",
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
            "\n[limits.rate.preauth_command]\nrefill_tokens = 10\nrefill_seconds = 1\nburst = 50\n\n[limits.rate.registered_command]\nrefill_tokens = 40\nrefill_seconds = 1\nburst = 200\n\n[limits.rate.expensive_query]\nrefill_tokens = 2\nrefill_seconds = 1\nburst = 10\n\n[privacy]",
        )?;
        let config_path = etc.join("config.toml");
        write_private(&config_path, config.as_bytes())?;

        Ok(Self {
            _root: root,
            diagnostics: Arc::default(),
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

    /// Records a phase marker for the diagnostics record.
    fn phase(&self, text: &str) {
        if let Ok(mut diagnostics) = self.diagnostics.lock() {
            Diagnostics::push_bounded(&mut diagnostics.phases, text.to_owned());
        }
    }

    /// Records one connection attempt and its outcome.
    fn attempt(&self, text: String) {
        if let Ok(mut diagnostics) = self.diagnostics.lock() {
            Diagnostics::push_bounded(&mut diagnostics.attempts, text);
        }
    }

    /// Records the first failure; later failures do not replace it.
    fn record_failure(&self, text: String) {
        if let Ok(mut diagnostics) = self.diagnostics.lock()
            && diagnostics.first_failure.is_none()
        {
            diagnostics.first_failure = Some(text);
        }
    }

    /// Runs one test body so a returned error is recorded before the
    /// fixture drops; the drop then retains the diagnostics when enabled.
    fn run(self, body: impl FnOnce(&Self) -> TestResult) -> TestResult {
        let outcome = body(&self);
        if let Err(error) = &outcome {
            self.record_failure(error.to_string());
        }
        outcome
    }

    fn retain_directory() -> Option<PathBuf> {
        let value = std::env::var_os(RETAIN_ENV)?;
        if value.is_empty() {
            return None;
        }
        Some(PathBuf::from(value))
    }

    /// Copies the bounded daemon logs and the diagnostics record into a
    /// private directory under the retention root. Only the daemon's own
    /// structured logs are copied; they carry no addresses, logins, or
    /// keys by construction (spec 25.2).
    fn preserve(&self, retain: &Path) -> io::Result<()> {
        let name = self
            ._root
            .path()
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| "fixture".into());
        let target = retain.join(name);
        fs::create_dir_all(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        let rendered = self
            .diagnostics
            .lock()
            .map(|diagnostics| diagnostics.render())
            .unwrap_or_else(|_| String::from("<diagnostics poisoned>\n"));
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        options
            .open(target.join("diagnostics.txt"))?
            .write_all(rendered.as_bytes())?;
        let mut remaining = RETAINED_LOG_BYTES;
        let mut paths = fs::read_dir(&self.log_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            if remaining == 0 {
                break;
            }
            let bytes = fs::read(&path)?;
            let take = bytes.len().min(remaining);
            let Some(slice) = bytes.get(..take) else {
                continue;
            };
            let Some(file_name) = path.file_name() else {
                continue;
            };
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            options.open(target.join(file_name))?.write_all(slice)?;
            remaining = remaining.saturating_sub(take);
        }
        Ok(())
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

struct AdminTlsMaterial {
    address: SocketAddr,
    server: TlsFixture,
    operator: TlsFixture,
}

fn prepare_admin_tls(fixture: &LiveFixture) -> TestResult<AdminTlsMaterial> {
    let server = TlsFixture::mint([18; 32], DNS_NAME)?;
    let operator = TlsFixture::mint([19; 32], "operator.test")?;
    let tls_dir = fixture._root.path().join("etc/tls");
    let server_certificate = tls_dir.join("admin-server.crt");
    let server_key = tls_dir.join("admin-server.key");
    let operator_ca = tls_dir.join("admin-operator-ca.crt");
    write_private(&server_certificate, server.leaf_certificate_der())?;
    write_private(&server_key, server.leaf_private_key_pkcs8_der())?;
    write_private(&operator_ca, operator.ca_certificate_der())?;

    let address = reserve_loopback_address()?;
    let mut config = fs::read_to_string(&fixture.config_path)?;
    let listener = format!(
        "\n[[listeners.endpoint]]\nname = \"admin-tls\"\nenabled = true\npurpose = \"admin_tls\"\nbind = \"{address}\"\nmax_connections = 4\ntls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\nclient_ca_file = \"{}\"\n",
        protected_path_text(&server_certificate)?,
        protected_path_text(&server_key)?,
        protected_path_text(&operator_ca)?,
    );
    replace_once(&mut config, "\n[tls]", &format!("{listener}\n[tls]"))?;
    replace_once(
        &mut config,
        "\nlocal_uids = [",
        &format!(
            "\ncertificate_spki_sha256 = \"{}\"\nlocal_uids = [",
            encode_base64url_32(operator.leaf_spki_sha256())
        ),
    )?;
    fs::write(&fixture.config_path, config)?;

    Ok(AdminTlsMaterial {
        address,
        server,
        operator,
    })
}

fn protected_path_text(path: &Path) -> TestResult<&str> {
    path.to_str()
        .ok_or_else(|| failure("test TLS path was not UTF-8"))
}

fn admin_tls_client_config(material: &AdminTlsMaterial) -> TestResult<Arc<ClientConfig>> {
    Ok(build_client_config(
        TrustStore::parse(material.server.ca_certificate_der())?,
        Some(ADMIN_ALPN),
        Some((
            CertChain::parse(material.operator.leaf_certificate_der())?,
            PrivateKey::parse(material.operator.leaf_private_key_pkcs8_der())?,
        )),
    )?)
}

struct TlsAdminClient<'a> {
    reader: BufReader<TlsClient>,
    fixture: &'a LiveFixture,
    session_id: AdminSessionId,
    counter: u64,
}

impl<'a> TlsAdminClient<'a> {
    fn connect(fixture: &'a LiveFixture, material: &AdminTlsMaterial) -> TestResult<Self> {
        let socket = connect_tcp(material.address, "admin TLS listener")?;
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        let name = ServerName::try_from(DNS_NAME.to_owned())?;
        let connection = ClientConnection::new(admin_tls_client_config(material)?, name)?;
        let mut stream = StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        if stream.conn.alpn_protocol() != Some(ADMIN_ALPN) {
            return Err(failure("admin TLS did not negotiate the exact ALPN"));
        }

        let mut reader = BufReader::new(stream);
        let challenge_line = read_line(&mut reader)?;
        let (challenge, session_id, binding) = parse_tls_admin_challenge(&challenge_line)?;
        let mut context = Vec::with_capacity(64);
        context.extend_from_slice(fixture.network_id.as_bytes());
        context.extend_from_slice(fixture.server_id.as_bytes());
        context.extend_from_slice(session_id.as_bytes());
        let mut exporter = [0_u8; 32];
        reader.get_ref().conn.export_keying_material(
            &mut exporter,
            ADMIN_EXPORTER_LABEL,
            Some(&context),
        )?;
        if binding.as_bytes() != &exporter {
            return Err(failure(
                "admin challenge did not carry the client-derived TLS exporter",
            ));
        }

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

    fn send(&mut self, command: &str) -> TestResult {
        let tbs = AdminCommandTbs::new(
            self.fixture.network_id,
            self.fixture.server_id,
            self.session_id,
            self.counter,
            None,
            command.as_bytes(),
        )?;
        let signature = tbs.sign(&self.fixture.operator_key)?;
        let tag = render_admin_tag(self.counter, &signature, None);
        self.reader
            .get_mut()
            .write_all(format!("{tag} {command}\r\n").as_bytes())?;
        self.reader.get_mut().flush()?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| failure("admin TLS command counter overflow"))?;
        Ok(())
    }

    fn quit(mut self) -> TestResult {
        self.send("QUIT")?;
        let mut byte = [0_u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => Ok(()),
            Ok(_) => Err(failure("admin TLS QUIT returned unexpected output")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

fn parse_tls_admin_challenge(
    challenge_line: &str,
) -> TestResult<(AdminChallenge, AdminSessionId, TransportBinding)> {
    let tokens = challenge_line.split_ascii_whitespace().collect::<Vec<_>>();
    if tokens.get(..7).is_none_or(|prefix| {
        prefix.first() != Some(&"NOTE")
            || prefix.get(1) != Some(&"OPER")
            || prefix.get(2) != Some(&"CHALLENGE")
            || prefix.get(5) != Some(&"tls")
    }) {
        return Err(failure(format!(
            "unexpected administrative TLS challenge: {challenge_line}"
        )));
    }
    let session_id = AdminSessionId::from_bytes(decode_fixed_base64url::<16>(
        tokens
            .get(3)
            .ok_or_else(|| failure("TLS challenge session missing"))?
            .as_bytes(),
    )?);
    let nonce = Challenge::from_bytes(decode_fixed_base64url::<32>(
        tokens
            .get(4)
            .ok_or_else(|| failure("TLS challenge nonce missing"))?
            .as_bytes(),
    )?);
    let binding = TransportBinding::from_bytes(decode_fixed_base64url::<32>(
        tokens
            .get(6)
            .ok_or_else(|| failure("TLS challenge binding missing"))?
            .as_bytes(),
    )?);
    Ok((
        AdminChallenge::new(session_id, nonce, TransportKind::Tls, binding),
        session_id,
        binding,
    ))
}

fn connect_tcp(address: SocketAddr, label: &str) -> TestResult<TcpStream> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) if Instant::now() < deadline => {
                let _transient = error;
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(failure(format!("{label} did not start: {error}"))),
        }
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

// agenc-review: allow owner=tests reviewed=2026-08-31 reason=the exact startup database fixture carries each independent persisted identity and secret explicitly
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

impl Drop for LiveFixture {
    fn drop(&mut self) {
        let panicking = thread::panicking();
        if panicking {
            self.record_failure(String::from("test panicked"));
        }
        let failed = self
            .diagnostics
            .lock()
            .map(|diagnostics| diagnostics.first_failure.is_some())
            .unwrap_or(true);
        if !failed {
            return;
        }
        if let Some(retain) = Self::retain_directory() {
            let _preserved = self.preserve(&retain);
        }
    }
}

struct DaemonProcess {
    child: Option<Child>,
    diagnostics: Option<Arc<Mutex<Diagnostics>>>,
}

impl DaemonProcess {
    fn start(config_path: &Path) -> TestResult<Self> {
        Self::spawn(config_path, None)
    }

    /// Starts the daemon and reports its exit into the fixture diagnostics.
    fn start_for(fixture: &LiveFixture) -> TestResult<Self> {
        Self::spawn(&fixture.config_path, Some(Arc::clone(&fixture.diagnostics)))
    }

    fn spawn(config_path: &Path, diagnostics: Option<Arc<Mutex<Diagnostics>>>) -> TestResult<Self> {
        let child = Command::new(env!("CARGO_BIN_EXE_arcd"))
            .arg("serve")
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            child: Some(child),
            diagnostics,
        })
    }

    fn record_exit(&self, text: String) {
        if let Some(diagnostics) = &self.diagnostics
            && let Ok(mut diagnostics) = diagnostics.lock()
        {
            diagnostics.child_exit = Some(text);
        }
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
                self.record_exit(format!("joined: {status}"));
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let _terminated = child.kill();
                let status = child.wait();
                self.child = None;
                self.record_exit(format!("killed after the stop budget: {status:?}"));
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
            let status = child.wait();
            self.record_exit(format!("killed at drop without a join: {status:?}"));
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

#[cfg(feature = "wss")]
#[path = "stage_six_daemon/wss.rs"]
mod wss;

#[derive(Clone, Copy)]
enum ClientTransport {
    Tcp,
    #[cfg(feature = "wss")]
    TextWebSocket,
    #[cfg(feature = "wss")]
    BinaryWebSocket,
}

trait ClientIo: io::Read + io::Write {}
impl<T: io::Read + io::Write> ClientIo for T {}

struct ArcClient {
    reader: BufReader<Box<dyn ClientIo>>,
}

#[derive(Clone, Copy)]
enum AccountCarrier {
    Create,
    Credentials,
}

impl AccountCarrier {
    const fn command(self) -> &'static str {
        match self {
            Self::Create => "ACCTCREATE",
            Self::Credentials => "ACCTCRED",
        }
    }
}

#[derive(Clone, Copy)]
enum AccountPhase {
    Start,
    Finish,
}

impl AccountPhase {
    const fn command(self) -> &'static str {
        match self {
            Self::Start => "START",
            Self::Finish => "FINISH",
        }
    }

    const fn response(self) -> &'static str {
        match self {
            Self::Start => "CHALLENGE",
            Self::Finish => "COMPLETE",
        }
    }
}

impl ArcClient {
    fn connect(fixture: &LiveFixture) -> TestResult<Self> {
        Self::connect_transport(fixture, ClientTransport::Tcp)
    }

    fn connect_transport(fixture: &LiveFixture, transport: ClientTransport) -> TestResult<Self> {
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
        let client_config = fixture.client_config()?;
        #[cfg(feature = "wss")]
        let client_config = if matches!(
            transport,
            ClientTransport::TextWebSocket | ClientTransport::BinaryWebSocket
        ) {
            let mut config = (*client_config).clone();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        } else {
            client_config
        };
        let connection = ClientConnection::new(client_config, name)?;
        let mut stream = StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        let stream: Box<dyn ClientIo> = match transport {
            ClientTransport::Tcp => Box::new(stream),
            #[cfg(feature = "wss")]
            ClientTransport::TextWebSocket | ClientTransport::BinaryWebSocket => {
                Box::new(wss::WebSocketClient::upgrade(stream, transport)?)
            }
        };
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

    fn negotiate_sasl(&mut self) -> TestResult {
        self.send("CAP LS 302")?;
        let advertised = read_until(&mut self.reader, |line| {
            line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :")
        })?;
        assert_contains(&advertised, "sasl=AGENC-OPAQUE")?;
        assert_contains(&advertised, "agenc.ag/account-create=v1")?;
        assert_contains(&advertised, "agenc.ag/account-credentials=v1")?;
        let acknowledged = self.send_until(
            "CAP REQ :agenc.ag/account-create agenc.ag/account-credentials sasl",
            " CAP * ACK ",
        )?;
        assert_contains(&acknowledged, "agenc.ag/account-create")?;
        assert_contains(&acknowledged, "agenc.ag/account-credentials")?;
        assert_contains(&acknowledged, "sasl")
    }

    fn complete_registration(&mut self, nickname: &str) -> TestResult<Vec<String>> {
        self.send(&format!("NICK {nickname}"))?;
        self.send(&format!("USER {nickname} 0 * :Stage Six Account"))?;
        self.send("CAP END")?;
        read_until(&mut self.reader, |line| {
            line.contains(" 376 ") || line.contains(" 422 ")
        })
    }

    fn account_exchange(
        &mut self,
        carrier: AccountCarrier,
        phase: AccountPhase,
        envelope: &[u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
        token: AccountResponseOpenToken,
    ) -> TestResult<AccountServiceResponsePayload> {
        let command = carrier.command();
        self.send(&format!(
            "{command} {} {ACCOUNT_SERVICE_ENVELOPE_BYTES}",
            phase.command()
        ))?;
        let ready = read_line_for(&mut self.reader, "account carrier READY")?;
        let ready_marker = format!(
            " {command} READY {} {ACCOUNT_SERVICE_ENVELOPE_BYTES}",
            phase.command()
        );
        if !ready.contains(&ready_marker) {
            return Err(failure(format!(
                "account carrier did not enter the requested phase: {ready}"
            )));
        }

        let encoded_request = URL_SAFE_NO_PAD.encode(envelope);
        if encoded_request.len() != ACCOUNT_REQUEST_CHARACTERS {
            return Err(failure("account request had the wrong encoded length"));
        }
        for chunk in encoded_request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
            self.send(&format!("{command} DATA {}", std::str::from_utf8(chunk)?))?;
        }
        self.send(&format!("{command} END"))?;

        let response_start = read_line_for(&mut self.reader, "account carrier response header")
            .map_err(|error| {
                failure(format!(
                    "{command} {} response header: {error}",
                    phase.command()
                ))
            })?;
        let response_marker = format!(
            " {command} {} {ACCOUNT_SERVICE_RESPONSE_BYTES}",
            phase.response()
        );
        if !response_start.contains(&response_marker) {
            return Err(failure(format!(
                "account carrier response header was invalid: {response_start}"
            )));
        }

        let mut encoded_response = String::with_capacity(ACCOUNT_RESPONSE_CHARACTERS);
        let mut ended = false;
        for _ in 0..16 {
            let line = read_line_for(&mut self.reader, "account carrier response body")?;
            let mut fields = line.split_ascii_whitespace();
            let valid_prefix = fields.next().is_some_and(|prefix| prefix.starts_with(':'));
            let valid_command = fields.next() == Some(command);
            match fields.next() {
                Some("DATA") if valid_prefix && valid_command => {
                    let Some(chunk) = fields.next() else {
                        return Err(failure("account response omitted a DATA chunk"));
                    };
                    if fields.next().is_some()
                        || encoded_response.len().saturating_add(chunk.len())
                            > ACCOUNT_RESPONSE_CHARACTERS
                    {
                        return Err(failure("account response DATA framing was invalid"));
                    }
                    encoded_response.push_str(chunk);
                }
                Some("END") if valid_prefix && valid_command && fields.next().is_none() => {
                    ended = true;
                    break;
                }
                _ => return Err(failure("account response framing was invalid")),
            }
        }
        if !ended || encoded_response.len() != ACCOUNT_RESPONSE_CHARACTERS {
            return Err(failure(
                "account response did not have its exact bounded shape",
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded_response.as_bytes())
            .map_err(|_| failure("account response Base64url was invalid"))?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded_response {
            return Err(failure("account response was not canonical Base64url"));
        }
        open_account_payload(token, decoded)
    }

    fn begin_sasl(&mut self) -> TestResult {
        self.send("AUTHENTICATE AGENC-OPAQUE")?;
        let line = read_line_for(&mut self.reader, "SASL mechanism acknowledgement")?;
        if line.ends_with(" AUTHENTICATE +") {
            Ok(())
        } else {
            Err(failure(format!(
                "SASL carrier did not accept AGENC-OPAQUE: {line}"
            )))
        }
    }

    fn sasl_exchange(
        &mut self,
        envelope: &[u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
        token: AccountResponseOpenToken,
    ) -> TestResult<AccountServiceResponsePayload> {
        let encoded_request = STANDARD.encode(envelope);
        if encoded_request.len() != SASL_REQUEST_CHARACTERS {
            return Err(failure("SASL request had the wrong encoded length"));
        }
        for chunk in encoded_request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
            self.send(&format!("AUTHENTICATE {}", std::str::from_utf8(chunk)?))?;
        }

        let mut encoded_response = String::with_capacity(SASL_RESPONSE_CHARACTERS);
        for chunk_index in 0..15 {
            let line = read_line(&mut self.reader).map_err(|error| {
                failure(format!(
                    "SASL response ended after {chunk_index} chunks and {} characters: {error}",
                    encoded_response.len()
                ))
            })?;
            let mut fields = line.split_ascii_whitespace();
            let valid_prefix = fields.next().is_some_and(|prefix| prefix.starts_with(':'));
            let valid_command = fields.next() == Some("AUTHENTICATE");
            let Some(chunk) = fields.next() else {
                return Err(failure("SASL response omitted a payload chunk"));
            };
            if !valid_prefix
                || !valid_command
                || fields.next().is_some()
                || encoded_response.len().saturating_add(chunk.len()) > SASL_RESPONSE_CHARACTERS
            {
                return Err(failure("SASL response framing was invalid"));
            }
            encoded_response.push_str(chunk);
            if encoded_response.len() == SASL_RESPONSE_CHARACTERS {
                break;
            }
        }
        if encoded_response.len() != SASL_RESPONSE_CHARACTERS {
            return Err(failure("SASL response had the wrong encoded length"));
        }
        let decoded = STANDARD
            .decode(encoded_response.as_bytes())
            .map_err(|_| failure("SASL response Base64 was invalid"))?;
        if STANDARD.encode(&decoded) != encoded_response {
            return Err(failure("SASL response was not canonical Base64"));
        }
        open_account_payload(token, decoded)
    }

    fn expect_closed_without_output(&mut self) -> TestResult {
        let mut byte = [0_u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => Ok(()),
            Ok(_) => Err(failure("closed account session returned unexpected output")),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn register(&mut self) -> TestResult<Vec<String>> {
        self.send("CAP LS 302")?;
        self.send("CAP REQ :account-notify account-tag away-notify batch cap-notify echo-message labeled-response message-ids message-tags server-time setname standard-replies agenc.ag/account-controls agenc.ag/channel-controls")?;
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

#[derive(Clone, Copy)]
enum CoreV1TranscriptOperation {
    Client,
    Server,
}

struct CoreV1TranscriptStep {
    operation: CoreV1TranscriptOperation,
    payload: Vec<u8>,
}

fn parse_core_v1_transcript() -> TestResult<Vec<CoreV1TranscriptStep>> {
    let mut steps = Vec::new();
    for line in CORE_V1_TRANSCRIPT.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if steps.len() >= CORE_V1_TRANSCRIPT_STEPS {
            return Err(failure("Stage 06 core-v1 transcript has too many steps"));
        }
        let mut fields = line.split('|');
        let (Some(evidence), Some(operation), Some(encoding), Some(payload)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(failure("Stage 06 core-v1 transcript row is incomplete"));
        };
        if fields.next().is_some() || evidence != "EVID-S06-004-TRANSPORTS" || encoding != "hex" {
            return Err(failure("Stage 06 core-v1 transcript metadata is invalid"));
        }
        let operation = match operation {
            "client" => CoreV1TranscriptOperation::Client,
            "server" => CoreV1TranscriptOperation::Server,
            _ => return Err(failure("Stage 06 core-v1 transcript operation is invalid")),
        };
        if !payload.len().is_multiple_of(2)
            || payload.len() > MAX_CORE_V1_TRANSCRIPT_STEP_BYTES.saturating_mul(2)
            || !payload
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(failure("Stage 06 core-v1 transcript payload is invalid"));
        }
        let (pairs, remainder) = payload.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(failure("Stage 06 core-v1 transcript hex is incomplete"));
        }
        let mut decoded = Vec::new();
        decoded.try_reserve_exact(pairs.len())?;
        for pair in pairs {
            let text = std::str::from_utf8(pair)?;
            decoded.push(
                u8::from_str_radix(text, 16)
                    .map_err(|_| failure("Stage 06 core-v1 transcript hex is invalid"))?,
            );
        }
        steps.try_reserve(1)?;
        steps.push(CoreV1TranscriptStep {
            operation,
            payload: decoded,
        });
    }
    Ok(steps)
}

fn exercise_core_v1_fixture(fixture: &LiveFixture) -> TestResult {
    let transcript = parse_core_v1_transcript()?;
    if transcript.len() != CORE_V1_TRANSCRIPT_STEPS {
        return Err(failure("Stage 06 core-v1 transcript step count changed"));
    }
    let mut client = ArcClient::connect(fixture)?;
    assert_contains(&client.register()?, " 001 LiveUser ")?;
    for step in transcript {
        if !step.payload.ends_with(b"\r\n") {
            return Err(failure("Stage 06 core-v1 transcript metadata is invalid"));
        }
        match step.operation {
            CoreV1TranscriptOperation::Client => {
                client.reader.get_mut().write_all(&step.payload)?;
                client.reader.get_mut().flush()?;
            }
            CoreV1TranscriptOperation::Server => {
                let mut actual = vec![0_u8; step.payload.len()];
                client.reader.read_exact(&mut actual)?;
                if actual != step.payload {
                    return Err(failure(format!(
                        "production core-v1 transcript bytes changed: expected {:?}, received {actual:?}",
                        step.payload
                    )));
                }
            }
        }
    }
    Ok(())
}

fn exercise_tls_admin(fixture: &LiveFixture, material: &AdminTlsMaterial) -> TestResult {
    let mut admin = TlsAdminClient::connect(fixture, material)?;
    admin.send("PING tls-first")?;
    admin.send("INFO")?;
    admin.send("PING tls-last")?;
    let replies = [
        read_line(&mut admin.reader)?,
        read_line(&mut admin.reader)?,
        read_line(&mut admin.reader)?,
        read_line(&mut admin.reader)?,
    ];
    assert_eq!(
        replies,
        [
            "PONG :tls-first",
            ":arcd 371 * :health readiness=1 liveness=1",
            ":arcd 374 * :End of INFO",
            "PONG :tls-last",
        ]
    );
    admin.quit()
}

fn read_line<R: BufRead>(reader: &mut R) -> TestResult<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(failure("transport closed before the expected reply"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn read_line_for<R: BufRead>(reader: &mut R, stage: &str) -> TestResult<String> {
    read_line(reader).map_err(|error| failure(format!("{stage}: {error}")))
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

fn committed_account(completion: Completion, expected: Option<AccountId>) -> TestResult<AccountId> {
    if completion.status() != AccountServiceCompletionStatus::Committed {
        return Err(failure("account-service operation was rejected"));
    }
    let account_id = completion
        .account_id()
        .ok_or_else(|| failure("committed account-service operation omitted its account"))?;
    if expected.is_some_and(|expected| expected != account_id) {
        return Err(failure(
            "account-service completion named an unexpected account",
        ));
    }
    Ok(account_id)
}

fn create_live_account(client: &mut ArcClient, fixture: &LiveFixture) -> TestResult<AccountId> {
    let mut rng = TestOpaqueRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, ACCOUNT_PASSWORD)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture.network_id,
        41,
        AccountRequestPayload::CreationStart(CreationStart {
            network_id: fixture.network_id,
            login: NormalizedLogin::prepare("stage-six-account")?,
            registration_request,
            invitation: None,
        }),
    )?;
    let challenge = client.account_exchange(
        AccountCarrier::Create,
        AccountPhase::Start,
        &start_envelope,
        start_token,
    )?;
    let AccountServiceResponsePayload::CreationChallenge {
        transaction_id,
        credential_id,
        response,
    } = challenge
    else {
        return Err(failure("account creation returned the wrong challenge"));
    };
    let registration_finish = registration.state.finish(
        &mut rng,
        ACCOUNT_PASSWORD,
        RegistrationResponse::<TestOpaqueSuite>::deserialize(
            response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(&fixture.network_id, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let registration_record = finish_registration(
        registration_finish
            .message
            .serialize()
            .as_slice()
            .try_into()?,
    )?;
    rng.require_success()?;

    let (finish_envelope, finish_token) = seal_account_payload(
        fixture.network_id,
        42,
        AccountRequestPayload::CreationFinish(CreationFinish {
            network_id: fixture.network_id,
            transaction_id,
            registration_record,
        }),
    )?;
    let completion = client.account_exchange(
        AccountCarrier::Create,
        AccountPhase::Finish,
        &finish_envelope,
        finish_token,
    )?;
    let AccountServiceResponsePayload::CreationCompletion(completion) = completion else {
        return Err(failure("account creation returned the wrong completion"));
    };
    let account_id = committed_account(completion, None)?;
    let note = read_line_for(&mut client.reader, "account creation receipt")?;
    if !note.contains(&format!(
        " NOTE ACCTCREATE CREATED {} :Account created",
        account_id.to_text()
    )) {
        return Err(failure("account creation omitted its committed receipt"));
    }
    Ok(account_id)
}

fn authenticate_live_account(
    client: &mut ArcClient,
    fixture: &LiveFixture,
    password: &[u8],
    request_seed: u8,
    expected_account: AccountId,
) -> TestResult {
    let mut rng = TestOpaqueRng::new();
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture.network_id,
        request_seed,
        AccountRequestPayload::AuthenticationStart(AuthenticationStart {
            network_id: fixture.network_id,
            login: NormalizedLogin::prepare("stage-six-account")?,
            ke1,
        }),
    )?;
    client.begin_sasl()?;
    let challenge = client.sasl_exchange(&start_envelope, start_token)?;
    let AccountServiceResponsePayload::AuthenticationChallenge {
        transaction_id,
        credential_id,
        ke2,
    } = challenge
    else {
        return Err(failure("authentication returned the wrong challenge"));
    };
    let context = opaque_context(fixture.network_id);
    let login_finish = login.state.finish(
        &mut rng,
        password,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&fixture.network_id, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(login_finish.message.serialize().as_slice().try_into()?)?;
    rng.require_success()?;
    let finish_seed = request_seed
        .checked_add(1)
        .ok_or_else(|| failure("authentication request seed overflow"))?;
    let (finish_envelope, finish_token) = seal_account_payload(
        fixture.network_id,
        finish_seed,
        AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
            network_id: fixture.network_id,
            transaction_id,
            ke3,
        }),
    )?;
    let completion = client.sasl_exchange(&finish_envelope, finish_token)?;
    let AccountServiceResponsePayload::AuthenticationCompletion(completion) = completion else {
        return Err(failure("authentication returned the wrong completion"));
    };
    let _account = committed_account(completion, Some(expected_account))?;
    let numeric = read_line_for(&mut client.reader, "SASL completion numeric")?;
    if !numeric.contains(" 903 ") {
        return Err(failure("successful authentication omitted numeric 903"));
    }
    Ok(())
}

fn replace_live_credential(
    client: &mut ArcClient,
    fixture: &LiveFixture,
    account_id: AccountId,
) -> TestResult {
    let mut rng = TestOpaqueRng::new();
    let registration =
        ClientRegistration::<TestOpaqueSuite>::start(&mut rng, REPLACEMENT_PASSWORD)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture.network_id,
        45,
        AccountRequestPayload::CredentialChangeStart(CredentialChangeStart {
            network_id: fixture.network_id,
            account_id,
            registration_request,
        }),
    )?;
    let challenge = client.account_exchange(
        AccountCarrier::Credentials,
        AccountPhase::Start,
        &start_envelope,
        start_token,
    )?;
    let AccountServiceResponsePayload::CredentialChangeChallenge {
        transaction_id,
        credential_id,
        response,
    } = challenge
    else {
        return Err(failure("credential change returned the wrong challenge"));
    };
    let registration_finish = registration.state.finish(
        &mut rng,
        REPLACEMENT_PASSWORD,
        RegistrationResponse::<TestOpaqueSuite>::deserialize(
            response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(&fixture.network_id, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let registration_record = finish_registration(
        registration_finish
            .message
            .serialize()
            .as_slice()
            .try_into()?,
    )?;
    rng.require_success()?;
    let (finish_envelope, finish_token) = seal_account_payload(
        fixture.network_id,
        46,
        AccountRequestPayload::CredentialChangeFinish(CredentialChangeFinish {
            network_id: fixture.network_id,
            transaction_id,
            registration_record,
        }),
    )?;
    let completion = client.account_exchange(
        AccountCarrier::Credentials,
        AccountPhase::Finish,
        &finish_envelope,
        finish_token,
    )?;
    let AccountServiceResponsePayload::CredentialChangeCompletion(completion) = completion else {
        return Err(failure("credential change returned the wrong completion"));
    };
    let _account = committed_account(completion, Some(account_id))?;
    let note = read_line_for(&mut client.reader, "credential replacement receipt")?;
    if !note.contains(" NOTE ACCTCRED CHANGED :Account credential changed; reconnect required") {
        return Err(failure("credential change omitted its committed receipt"));
    }
    client.expect_closed_without_output()
}

fn connect_registered_account(
    fixture: &LiveFixture,
    nickname: &str,
    request_seed: u8,
    account_id: AccountId,
) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    authenticate_live_account(
        &mut client,
        fixture,
        REPLACEMENT_PASSWORD,
        request_seed,
        account_id,
    )?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok(client)
}

fn exercise_account_client(fixture: &LiveFixture) -> TestResult<(ArcClient, AccountId)> {
    let account_id = {
        let mut creation_client = ArcClient::connect(fixture)?;
        creation_client.negotiate_sasl()?;
        create_live_account(&mut creation_client, fixture)?
    };

    let mut client = ArcClient::connect(fixture)?;
    client.negotiate_sasl()?;
    authenticate_live_account(&mut client, fixture, ACCOUNT_PASSWORD, 43, account_id)?;
    let registered = client.complete_registration("AccountSeed")?;
    assert_contains(&registered, " 001 AccountSeed ")?;
    replace_live_credential(&mut client, fixture, account_id)?;

    let client = connect_registered_account(fixture, "AccountLive", 47, account_id)?;
    Ok((client, account_id))
}

fn exercise_client(fixture: &LiveFixture) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    let registered = client.register()?;
    assert_contains(&registered, " 001 LiveUser ")?;

    let public_oper = client.send_until("OPER root password", " 481 ")?;
    assert_contains(&public_oper, " 481 ")?;
    assert_contains(&client.send_until("MOTD", " 422 ")?, " 422 ")?;
    assert_contains(&client.send_until("VERSION", " 374 ")?, SOFTWARE_NAME)?;
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
    // RUN-06 (#60): a concealed or missing target answers no earlier than
    // the configured floor, and the delayed answer keeps its place in the
    // connection's order: the refusal precedes the next command's reply.
    client.send("TOPIC #absent")?;
    client.send("PING :floor-order")?;
    let floored = read_until(&mut client.reader, |line| {
        line.ends_with("PONG :floor-order")
    })?;
    let refusal = floored.iter().position(|line| line.contains("#absent"));
    let pong = floored
        .iter()
        .position(|line| line.ends_with("PONG :floor-order"));
    assert!(
        refusal.is_some() && pong.is_some() && refusal < pong,
        "the floored refusal must precede the next reply: {floored:?}"
    );
    assert_contains(&client.send_until("LIST", " 323 ")?, " 322 ")?;
    assert_contains(&client.send_until("WHO #live", " 315 ")?, " 352 ")?;
    assert_contains(&client.send_until("WHOIS LiveUser", " 318 ")?, " 311 ")?;
    assert_contains(&client.send_until("WHOWAS Nobody", " 369 ")?, " 406 ")?;
    assert_contains(
        &client.send_until("ISON LiveUser Nobody", " 303 ")?,
        "LiveUser",
    )?;
    assert_contains(
        &client.send_until("USERHOST LiveUser", " 302 ")?,
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

fn exercise_admin(fixture: &LiveFixture, live_account: AccountId) -> TestResult<AdminClient<'_>> {
    let mut admin = AdminClient::connect(fixture)?;
    assert_eq!(admin.command_line("PING live")?, "PONG :live");
    admin.send("PONG live", None)?;
    assert_eq!(admin.command_line("PING after-pong")?, "PONG :after-pong");

    assert_eq!(admin.command_line("MOTD")?, "422 * :MOTD File is missing");
    assert_contains(&admin.command_until("VERSION", " 374 ")?, SOFTWARE_NAME)?;
    assert_contains(&[admin.command_line("TIME")?], " 391 ")?;
    let info = admin.command_until("INFO", " 374 ")?;
    assert_eq!(info.len(), 2);
    assert_eq!(
        info.first().map(String::as_str),
        Some(":arcd 371 * :health readiness=1 liveness=1")
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
    assert_eq!(
        admin.command_line(&format!(
            "ACCOUNT SUSPEND {} 60 :live policy test",
            live_account.to_text()
        ))?,
        "NOTE ACCOUNT OK :Account suspended"
    );
    assert_eq!(
        admin.command_line(&format!(
            "ACCOUNT RESTORE {} :live policy test",
            live_account.to_text()
        ))?,
        "NOTE ACCOUNT OK :Account restored"
    );
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
fn stopped_runtime_check_prepares_listener_tls_material() -> TestResult {
    let fixture = LiveFixture::create()?;
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    agenc_relay_runtime::daemon::check_configuration(&config, &secrets)?;

    let certificate = config
        .listeners
        .iter()
        .find_map(|listener| listener.tls.as_ref())
        .ok_or_else(|| failure("fixture has no TLS listener"))?
        .certificate_file
        .clone();
    fs::write(certificate, b"not a certificate")?;
    assert!(agenc_relay_runtime::daemon::check_configuration(&config, &secrets).is_err());
    Ok(())
}

#[test]
fn stopped_runtime_check_rejects_cross_purpose_public_identity_reuse() -> TestResult {
    let fixture = LiveFixture::create()?;
    let original = fs::read_to_string(&fixture.config_path)?;
    let mut document = original.clone();
    let operator_public = fixture.operator_key.public_key();
    let audit_public = Ed25519SecretKey::from_bytes([12; 32]).public_key();
    replace_once(
        &mut document,
        &format!(
            "signing_public_key = \"{}\"",
            encode_base64url_32(operator_public.as_bytes())
        ),
        &format!(
            "signing_public_key = \"{}\"",
            encode_base64url_32(audit_public.as_bytes())
        ),
    )?;
    fs::write(&fixture.config_path, document)?;

    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    assert!(agenc_relay_runtime::daemon::check_configuration(&config, &secrets).is_err());

    fs::write(&fixture.config_path, &original)?;
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    let setup: &[u8; agenc_relay_auth::OPAQUE_SERVER_SETUP_BYTES] = secrets
        .opaque_server_setup()
        .ok_or_else(|| failure("fixture has no OPAQUE setup"))?
        .expose()
        .try_into()
        .map_err(|_| failure("fixture OPAQUE setup has the wrong length"))?;
    let parsed_setup = opaque_ke::ServerSetup::<TestOpaqueSuite>::deserialize(setup)?;
    let opaque_public: [u8; 32] = parsed_setup
        .keypair()
        .public()
        .serialize()
        .as_slice()
        .try_into()?;
    let mut document = original;
    replace_once(
        &mut document,
        "\nlocal_uids = [",
        &format!(
            "\ncertificate_spki_sha256 = \"{}\"\nlocal_uids = [",
            encode_base64url_32(&opaque_public)
        ),
    )?;
    fs::write(&fixture.config_path, document)?;
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    assert!(agenc_relay_runtime::daemon::check_configuration(&config, &secrets).is_err());
    Ok(())
}

#[test]
fn stopped_runtime_check_allows_own_trust_alias_and_rejects_cross_purpose_trust() -> TestResult {
    let fixture = LiveFixture::create()?;
    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    agenc_relay_runtime::daemon::check_configuration(&config, &secrets)?;

    let backup_public = Ed25519SecretKey::from_bytes([11; 32]).public_key();
    let audit_id = audit_signing_key_id(backup_public.as_bytes())?;
    let manifest = format!(
        "audit_trust_version = 1\n\n[[key]]\nkey_id = \"{}\"\ned25519_public_key = \"{}\"\nnot_before = 0\nnot_after = {}\n",
        encode_base64url_32(audit_id.as_bytes()),
        encode_base64url_32(backup_public.as_bytes()),
        i64::MAX,
    );
    fs::write(&config.moderation.audit_trust_manifest_file, manifest)?;
    assert!(agenc_relay_runtime::daemon::check_configuration(&config, &secrets).is_err());
    Ok(())
}

#[test]
fn stopped_runtime_check_rejects_reused_admin_and_federation_ca_identity() -> TestResult {
    let fixture = LiveFixture::create()?;
    let admin_tls = prepare_admin_tls(&fixture)?;
    let federation_ca = fixture
        ._root
        .path()
        .join("etc/tls/federation-reused-ca.crt");
    write_private(&federation_ca, admin_tls.operator.ca_certificate_der())?;
    let mut document = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut document,
        "[federation]\n",
        &format!(
            "[federation]\nprivate_ca_file = \"{}\"\n",
            protected_path_text(&federation_ca)?
        ),
    )?;
    fs::write(&fixture.config_path, document)?;

    let config = load_config(&fixture.config_path, ValidationDepth::Host)?;
    let secrets = SecretSet::load(&config)?;
    assert!(agenc_relay_runtime::daemon::check_configuration(&config, &secrets).is_err());
    Ok(())
}

#[test]
fn production_serve_rejects_structural_config_before_binding() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut document = fs::read_to_string(&fixture.config_path)?;
    replace_once(
        &mut document,
        "config_version = 1\n",
        "config_version = 1\nunknown_stage_six_key = true\n",
    )?;
    fs::write(&fixture.config_path, document)?;

    let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_path)
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("configuration key is outside the closed schema"));
    assert!(!fixture.admin_socket.exists());
    let listener = TcpListener::bind(fixture.public_address)?;
    drop(listener);
    Ok(())
}

/// QA-04: a listener the operating system refuses to bind must name the
/// configured address and the refusal, not a generic runtime invariant.
#[test]
fn production_serve_names_the_address_and_the_os_error_of_a_refused_bind() -> TestResult {
    let fixture = LiveFixture::create()?;
    let holder = TcpListener::bind(fixture.public_address)?;
    let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
        .arg("serve")
        .arg("--config")
        .arg(&fixture.config_path)
        .output()?;
    drop(holder);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains("listener startup failed: listener socket could not be bound"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("address={}", fixture.public_address)),
        "{stderr}"
    );
    assert!(stderr.contains("error=EADDRINUSE"), "{stderr}");
    assert!(!stderr.contains("violates its invariant"), "{stderr}");
    Ok(())
}

#[test]
fn production_daemon_core_v1_and_admin_mtls_are_byte_exact() -> TestResult {
    let fixture = LiveFixture::create()?;
    let admin_tls = prepare_admin_tls(&fixture)?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    exercise_core_v1_fixture(&fixture).map_err(|error| {
        failure(format!(
            "core-v1 byte transcript failed: {error}; logs: {}",
            fixture.log_excerpt()
        ))
    })?;
    exercise_tls_admin(&fixture, &admin_tls).map_err(|error| {
        failure(format!(
            "composed admin mTLS transcript failed: {error}; logs: {}",
            fixture.log_excerpt()
        ))
    })?;

    let mut control = AdminClient::connect(&fixture)?;
    control.confirm_process("DIE :transcript complete")?;
    let status = daemon.wait()?;
    if !status.success() {
        return Err(failure(format!(
            "transcript daemon exited with {status}; logs: {}",
            fixture.log_excerpt()
        )));
    }
    Ok(())
}

#[test]
fn production_daemon_serves_restarts_reconciles_and_stops() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut first = DaemonProcess::start(&fixture.config_path)?;
    let mut client = exercise_client(&fixture)?;
    let (mut account_client, account_id) = match exercise_account_client(&fixture) {
        Ok(result) => result,
        Err(error) => {
            return Err(failure(format!(
                "account transcript failed: {error}; logs: {}",
                fixture.log_excerpt()
            )));
        }
    };
    let mut admin = exercise_admin(&fixture, account_id)?;
    account_client.expect_closed_without_output()?;
    let mut restored_account =
        connect_registered_account(&fixture, "AccountRestored", 49, account_id).map_err(
            |error| {
                failure(format!(
                    "post-restore account reconnect failed: {error}; logs: {}",
                    fixture.log_excerpt()
                ))
            },
        )?;

    let disposable = AdminClient::connect(&fixture)?;
    disposable.quit()?;
    admin.confirm_process("RESTART :test restart")?;
    let shutdown = client.shutdown_lines()?;
    assert_contains(&shutdown, "ERROR :Server shutting down")?;
    let account_shutdown = restored_account.shutdown_lines()?;
    assert_contains(&account_shutdown, "ERROR :Server shutting down")?;
    let restart_status = first.wait()?;
    if restart_status.code() != Some(75) {
        return Err(failure(format!(
            "restart exited with {restart_status}; logs: {}",
            fixture.log_excerpt()
        )));
    }

    let mut second = DaemonProcess::start(&fixture.config_path)?;
    let mut persisted_account =
        connect_registered_account(&fixture, "AccountPersisted", 51, account_id).map_err(
            |error| {
                failure(format!(
                    "post-restart account reconnect failed: {error}; logs: {}",
                    fixture.log_excerpt()
                ))
            },
        )?;
    let mut admin = AdminClient::connect(&fixture)?;
    let info = admin.command_until("INFO", " 374 ")?;
    assert_eq!(
        info.first().map(String::as_str),
        Some(":arcd 371 * :health readiness=1 liveness=1")
    );
    admin.confirm_process("DIE :test shutdown")?;
    let account_shutdown = persisted_account.shutdown_lines()?;
    assert_contains(&account_shutdown, "ERROR :Server shutting down")?;
    assert!(second.wait()?.success());

    let onboarding = Command::new(env!("CARGO_BIN_EXE_arcd"))
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

/// Reads lines until `complete` matches or the server closes the transport,
/// returning whatever arrived; failure paths may end either way.
fn read_leniently(client: &mut ArcClient, mut complete: impl FnMut(&str) -> bool) -> Vec<String> {
    let mut lines = Vec::new();
    for _ in 0..256 {
        let mut line = String::new();
        match client.reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = line.trim_end_matches(['\r', '\n']).to_owned();
                let done = complete(&line);
                lines.push(line);
                if done {
                    break;
                }
            }
        }
    }
    lines
}

/// Sends every line, then a PING, and collects the replies up to the PONG or
/// the transport close.
fn send_and_sync(client: &mut ArcClient, lines: &[String]) -> TestResult<Vec<String>> {
    for line in lines {
        client.send(line)?;
    }
    client.send("PING :sync")?;
    let mut replies = read_leniently(client, |line| line.ends_with("PONG :sync"));
    replies.retain(|line| !line.ends_with("PONG :sync"));
    Ok(replies)
}

/// Connects and registers a guest, reconnecting a bounded number of times
/// when the daemon closes the fresh connection before its first reply.
/// Registers a guest on a fresh connection. A silent close after the TLS
/// handshake is retried a bounded number of times only in the recovery
/// scenarios that call this helper, every attempt is recorded with its
/// reason, and the strict-admission variable makes it a single attempt so the
/// close fails the test instead of being retried away.
fn connect_registered_guest(fixture: &LiveFixture) -> TestResult<(ArcClient, Vec<String>)> {
    let attempts = if strict_admission() {
        1
    } else {
        FRESH_CONNECTION_ATTEMPTS
    };
    let mut reasons = Vec::new();
    for attempt in 1..=attempts {
        let mut client = ArcClient::connect(fixture)?;
        match client.register() {
            Ok(registered) => {
                fixture.attempt(format!(
                    "guest registration attempt {attempt}/{attempts}: registered"
                ));
                return Ok((client, registered));
            }
            Err(error) if error.to_string().contains("received []") => {
                fixture.attempt(format!(
                    "guest registration attempt {attempt}/{attempts}: silent close after TLS before the first reply ({error})"
                ));
                reasons.push(format!("attempt {attempt}: {error}"));
                if attempt < attempts {
                    std::thread::sleep(FRESH_CONNECTION_PAUSE);
                }
            }
            Err(error) => {
                fixture.attempt(format!(
                    "guest registration attempt {attempt}/{attempts}: {error}"
                ));
                return Err(error);
            }
        }
    }
    Err(failure(format!(
        "guest registration never received a reply after {attempts} attempt(s): {}",
        reasons.join("; ")
    )))
}

fn is_sasl_numeric(line: &str) -> bool {
    [" 903 ", " 904 ", " 905 ", " 906 ", " 907 "]
        .iter()
        .any(|numeric| line.contains(numeric))
}

/// Sends one SASL request envelope as AUTHENTICATE chunks and returns the
/// replies up to a complete sealed response, the first SASL numeric, or the
/// transport close.
fn sasl_exchange_lines(
    client: &mut ArcClient,
    envelope: &[u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
) -> TestResult<Vec<String>> {
    let encoded_request = STANDARD.encode(envelope);
    for chunk in encoded_request.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
        client.send(&format!("AUTHENTICATE {}", std::str::from_utf8(chunk)?))?;
    }
    let mut received = 0;
    Ok(read_leniently(client, |line| {
        let mut fields = line.split_ascii_whitespace().skip(1);
        if fields.next() == Some("AUTHENTICATE") {
            received += fields.next().map_or(0, str::len);
            return received >= SASL_RESPONSE_CHARACTERS;
        }
        is_sasl_numeric(line)
    }))
}

fn authentication_start_envelope(
    fixture: &LiveFixture,
    password: &[u8],
    request_seed: u8,
) -> TestResult<(
    [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
    AccountResponseOpenToken,
    ClientLogin<TestOpaqueSuite>,
    TestOpaqueRng,
)> {
    let mut rng = TestOpaqueRng::new();
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (envelope, token) = seal_account_payload(
        fixture.network_id,
        request_seed,
        AccountRequestPayload::AuthenticationStart(AuthenticationStart {
            network_id: fixture.network_id,
            login: NormalizedLogin::prepare("stage-six-account")?,
            ke1,
        }),
    )?;
    Ok((envelope, token, login.state, rng))
}

#[test]
fn production_daemon_account_edges_cover_replay_mismatch_logout_and_deletion() -> TestResult {
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let account_id = {
        let mut creation = ArcClient::connect(&fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, &fixture)?
    };

    // A finish that names the wrong transaction is refused and the carrier
    // connection does not survive it.
    let (start_envelope, start_token, login_state, mut rng) =
        authentication_start_envelope(&fixture, ACCOUNT_PASSWORD, 70)?;
    let mut mismatch = ArcClient::connect(&fixture)?;
    mismatch.negotiate_sasl()?;
    mismatch.begin_sasl()?;
    let challenge = mismatch.sasl_exchange(&start_envelope, start_token)?;
    let AccountServiceResponsePayload::AuthenticationChallenge {
        credential_id, ke2, ..
    } = challenge
    else {
        return Err(failure("authentication returned the wrong challenge"));
    };
    let context = opaque_context(fixture.network_id);
    let login_finish = login_state.finish(
        &mut rng,
        ACCOUNT_PASSWORD,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&fixture.network_id, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(login_finish.message.serialize().as_slice().try_into()?)?;
    let (wrong_finish, _token) = seal_account_payload(
        fixture.network_id,
        71,
        AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
            network_id: fixture.network_id,
            transaction_id: agenc_relay_types::TransactionId::from_bytes([77; 16]),
            ke3,
        }),
    )?;
    let rejected = sasl_exchange_lines(&mut mismatch, &wrong_finish)?;
    assert!(
        !rejected.is_empty(),
        "wrong transaction finish produced no reply"
    );
    drop(mismatch);

    // The identical start envelope from another connection is a replay on a
    // different route.
    let mut replay = ArcClient::connect(&fixture)?;
    replay.negotiate_sasl()?;
    replay.begin_sasl()?;
    // A replayed request on a different route fails closed: the server may
    // answer with a numeric or simply close without output.
    let _replayed = sasl_exchange_lines(&mut replay, &start_envelope)?;
    drop(replay);

    // Each protocol misuse fails closed on its own connection: an abort with
    // nothing pending, an invalid chunk, and carrier misuse.
    let mut idle_abort = ArcClient::connect(&fixture)?;
    idle_abort.negotiate_sasl()?;
    let _aborted = send_and_sync(&mut idle_abort, &["AUTHENTICATE *".to_owned()])?;
    drop(idle_abort);

    let mut bad_chunk = ArcClient::connect(&fixture)?;
    bad_chunk.negotiate_sasl()?;
    bad_chunk.begin_sasl()?;
    let _invalid = send_and_sync(&mut bad_chunk, &["AUTHENTICATE !!!".to_owned()])?;
    drop(bad_chunk);

    let mut carrier = ArcClient::connect(&fixture)?;
    carrier.negotiate_sasl()?;
    let _misused = send_and_sync(
        &mut carrier,
        &[
            "ACCTCREATE DATA AAAA".to_owned(),
            "ACCTCREATE START 12".to_owned(),
            format!("ACCTCREATE START {ACCOUNT_SERVICE_ENVELOPE_BYTES}"),
            "ACCTCREATE END".to_owned(),
        ],
    )?;
    drop(carrier);

    // Authentication and logout use their own connection so the deletion
    // exercise has its two permitted same-connection SASL attempts.
    let mut client = ArcClient::connect(&fixture)?;
    client.negotiate_sasl()?;
    // Account control notes are standard replies.
    let acknowledged = client.send_until(
        "CAP REQ :standard-replies agenc.ag/account-controls agenc.ag/channel-controls",
        " CAP * ACK ",
    )?;
    assert_contains(&acknowledged, "standard-replies")?;
    assert_contains(&acknowledged, "agenc.ag/account-controls")?;
    authenticate_live_account(&mut client, &fixture, ACCOUNT_PASSWORD, 80, account_id)?;
    let registered = client.complete_registration("EdgeUser")?;
    assert_contains(&registered, " 001 EdgeUser ")?;
    client.send("AUTHENTICATE *")?;
    assert_eq!(
        client.send_until("PING :logout-complete", " PONG ")?,
        [":node.test PONG :logout-complete"]
    );
    client.send("QUIT :logout complete")?;
    assert_eq!(
        read_line(&mut client.reader)?,
        ":node.test ERROR :logout complete"
    );
    let mut extra = [0_u8; 1];
    assert_eq!(
        client.reader.read(&mut extra)?,
        0,
        "logout connection did not end cleanly"
    );
    drop(client);

    let mut client = ArcClient::connect(&fixture)?;
    client.negotiate_sasl()?;
    let acknowledged = client.send_until(
        "CAP REQ :standard-replies agenc.ag/account-controls agenc.ag/channel-controls",
        " CAP * ACK ",
    )?;
    assert_contains(&acknowledged, "standard-replies")?;
    assert_contains(&acknowledged, "agenc.ag/account-controls")?;
    authenticate_live_account(&mut client, &fixture, ACCOUNT_PASSWORD, 82, account_id)?;
    assert_contains(
        &client.complete_registration("DeleteUser")?,
        " 001 DeleteUser ",
    )?;
    let token = account_deletion_challenge(&mut client)?;
    let mut wrong_token = decode_fixed_base64url::<16>(token.as_bytes())?;
    let first = wrong_token
        .first_mut()
        .ok_or_else(|| failure("empty deletion token"))?;
    *first ^= 1;
    client.send(&format!(
        "ACCT DELETE CONFIRM {}",
        encode_base64url(&wrong_token)
    ))?;
    assert_eq!(
        read_line_for(&mut client.reader, "wrong deletion token refusal")?,
        ":node.test FAIL ACCT BAD_STATE :Command is not valid in the current state"
    );
    assert_eq!(
        client.send_until("PING :deletion-refusal-survives", " PONG ")?,
        [":node.test PONG :deletion-refusal-survives"]
    );
    authenticate_live_account(&mut client, &fixture, ACCOUNT_PASSWORD, 84, account_id).map_err(
        |error| {
            failure(format!(
                "fresh authentication after wrong deletion token: {error}"
            ))
        },
    )?;
    let fresh_token = account_deletion_challenge(&mut client)?;
    assert_ne!(
        fresh_token, token,
        "fresh authentication reused a consumed challenge"
    );
    client.send(&format!("ACCT DELETE CONFIRM {fresh_token}"))?;
    require_committed_account_deletion(&mut client.reader)?;
    drop(client);

    // The deleted account can no longer authenticate.
    let mut late = ArcClient::connect(&fixture)?;
    late.negotiate_sasl()?;
    require_deleted_account_login_refusal(authenticate_live_account(
        &mut late,
        &fixture,
        ACCOUNT_PASSWORD,
        90,
        account_id,
    ))?;
    drop(late);

    let mut admin = AdminClient::connect(&fixture)?;
    admin.confirm_process("DIE :edge shutdown")?;
    assert!(daemon.wait()?.success());
    Ok(())
}

fn account_deletion_challenge(client: &mut ArcClient) -> TestResult<String> {
    client.send("ACCT DELETE START")?;
    let line = read_line_for(&mut client.reader, "deletion challenge")?;
    let token = line
        .strip_prefix(":node.test NOTE ACCT DELETE_CHALLENGE ")
        .and_then(|line| line.strip_suffix(" :Confirm account deletion"))
        .ok_or_else(|| failure(format!("unexpected deletion challenge: {line:?}")))?;
    let _validated = decode_fixed_base64url::<16>(token.as_bytes())?;
    Ok(token.to_owned())
}

fn require_committed_account_deletion(reader: &mut impl BufRead) -> TestResult {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line != ":node.test NOTE ACCT UPDATED :Account setting updated\r\n" {
        return Err(failure(format!(
            "deletion omitted its committed NOTE: {line:?}"
        )));
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(failure(
            "account deletion returned output after its final NOTE",
        ));
    }
    Ok(())
}

fn require_deleted_account_login_refusal(result: TestResult) -> TestResult {
    match result {
        Err(error)
            if matches!(
                error.downcast_ref::<opaque_ke::errors::ProtocolError>(),
                Some(opaque_ke::errors::ProtocolError::InvalidLoginError)
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => Err(failure("deleted account authenticated successfully")),
    }
}

struct DeletionEofFault(io::ErrorKind);

impl io::Read for DeletionEofFault {
    fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
        Err(self.0.into())
    }
}

#[test]
fn local_deletion_evidence_rejects_refusal_replies_and_successful_logins() -> TestResult {
    let note = ":node.test NOTE ACCT UPDATED :Account setting updated\r\n";
    for transcript in [
        ":node.test FAIL ACCT BAD_STATE :Command is not valid in the current state\r\n".to_owned(),
        ":node.test ERROR :Connection closed\r\n".to_owned(),
        format!("{note}:node.test ERROR :Connection closed\r\n"),
        String::new(),
    ] {
        assert!(require_committed_account_deletion(&mut io::Cursor::new(transcript)).is_err());
    }
    require_committed_account_deletion(&mut io::Cursor::new(note))?;
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::TimedOut,
    ] {
        let stream = io::Cursor::new(note).chain(DeletionEofFault(kind));
        assert!(require_committed_account_deletion(&mut BufReader::new(stream)).is_err());
    }
    assert!(require_deleted_account_login_refusal(Ok(())).is_err());
    assert!(
        require_deleted_account_login_refusal(Err(failure(" 904 SASL authentication failed")))
            .is_err()
    );
    assert!(
        require_deleted_account_login_refusal(Err(Box::new(io::Error::from(
            io::ErrorKind::ConnectionReset
        ))))
        .is_err()
    );
    let live = AccountId::from_random(AccountRandomId::from_bytes([181; 16]));
    let other = AccountId::from_random(AccountRandomId::from_bytes([182; 16]));
    let completion = Completion::committed(
        agenc_relay_types::TransactionId::from_bytes([183; 16]),
        live,
        1,
    );
    let mismatched = committed_account(completion, Some(other)).map(|_| ());
    assert!(require_deleted_account_login_refusal(mismatched).is_err());
    require_deleted_account_login_refusal(Err(Box::new(
        opaque_ke::errors::ProtocolError::<std::convert::Infallible>::InvalidLoginError,
    )))
}

#[test]
fn production_daemon_credential_and_lookup_edges_fail_closed() -> TestResult {
    LiveFixture::create()?.run(credential_and_lookup_edges)
}

fn credential_and_lookup_edges(fixture: &LiveFixture) -> TestResult {
    let mut daemon = DaemonProcess::start_for(fixture)?;
    fixture.phase("account creation");
    let account_id = {
        let mut creation = ArcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture)?
    };

    // Creating the same login twice is refused after the index lookup.
    fixture.phase("duplicate login");
    let mut duplicate = ArcClient::connect(fixture)?;
    duplicate.negotiate_sasl()?;
    let outcome = create_live_account(&mut duplicate, fixture);
    assert!(outcome.is_err(), "a duplicate login was created");
    drop(duplicate);

    // An unknown login still receives a challenge from the fake record and
    // the finish then fails closed.
    fixture.phase("unknown login");
    let mut unknown = ArcClient::connect(fixture)?;
    unknown
        .negotiate_sasl()
        .map_err(|error| failure(format!("unknown negotiate: {error}")))?;
    let mut rng = TestOpaqueRng::new();
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, ACCOUNT_PASSWORD)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture.network_id,
        100,
        AccountRequestPayload::AuthenticationStart(AuthenticationStart {
            network_id: fixture.network_id,
            login: NormalizedLogin::prepare("nobody-here")?,
            ke1,
        }),
    )?;
    unknown
        .begin_sasl()
        .map_err(|error| failure(format!("unknown begin: {error}")))?;
    let challenge = unknown
        .sasl_exchange(&start_envelope, start_token)
        .map_err(|error| failure(format!("unknown start: {error}")))?;
    let AccountServiceResponsePayload::AuthenticationChallenge {
        transaction_id,
        credential_id,
        ke2,
    } = challenge
    else {
        return Err(failure("unknown login did not receive a challenge"));
    };
    let context = opaque_context(fixture.network_id);
    let finish = login.state.finish(
        &mut rng,
        ACCOUNT_PASSWORD,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&fixture.network_id, &credential_id),
            Some(&TestArgon2id),
        ),
    );
    // The client cannot complete against a fake record; send a structurally
    // valid but unrelated finish instead so the server-side check runs.
    let ke3 = match finish {
        Ok(finish) => OpaqueKe3::from_bytes(finish.message.serialize().as_slice().try_into()?)?,
        Err(_) => OpaqueKe3::from_bytes([7; agenc_relay_auth::OPAQUE_KE3_BYTES])?,
    };
    let (finish_envelope, _token) = seal_account_payload(
        fixture.network_id,
        101,
        AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
            network_id: fixture.network_id,
            transaction_id,
            ke3,
        }),
    )?;
    let _refused = sasl_exchange_lines(&mut unknown, &finish_envelope)?;
    drop(unknown);

    // Credential change before authentication, for another account, and
    // with the wrong transaction.
    fixture.phase("credential change edges");
    let mut early = ArcClient::connect(fixture)?;
    early
        .negotiate_sasl()
        .map_err(|error| failure(format!("early negotiate: {error}")))?;
    let mut rng = TestOpaqueRng::new();
    let registration =
        ClientRegistration::<TestOpaqueSuite>::start(&mut rng, REPLACEMENT_PASSWORD)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (foreign_start, _token) = seal_account_payload(
        fixture.network_id,
        102,
        AccountRequestPayload::CredentialChangeStart(CredentialChangeStart {
            network_id: fixture.network_id,
            account_id: agenc_relay_testkit::account_id(200),
            registration_request,
        }),
    )?;
    let command = AccountCarrier::Credentials.command();
    early.send(&format!(
        "{command} {} {ACCOUNT_SERVICE_ENVELOPE_BYTES}",
        AccountPhase::Start.command()
    ))?;
    let _early = read_leniently(&mut early, |line| {
        line.contains(" READY ") || line.contains("FAIL ")
    });
    drop(early);

    let mut client = ArcClient::connect(fixture)?;
    client
        .negotiate_sasl()
        .map_err(|error| failure(format!("client negotiate: {error}")))?;
    authenticate_live_account(&mut client, fixture, ACCOUNT_PASSWORD, 104, account_id)
        .map_err(|error| failure(format!("client auth: {error}")))?;
    let registered = client
        .complete_registration("CredUser")
        .map_err(|error| failure(format!("client register: {error}")))?;
    assert_contains(&registered, " 001 CredUser ")?;
    client.send(&format!(
        "{command} {} {ACCOUNT_SERVICE_ENVELOPE_BYTES}",
        AccountPhase::Start.command()
    ))?;
    let ready = read_leniently(&mut client, |line| {
        line.contains(" READY ") || line.contains("FAIL ")
    });
    if ready.iter().any(|line| line.contains(" READY ")) {
        let encoded = URL_SAFE_NO_PAD.encode(foreign_start);
        for chunk in encoded.as_bytes().chunks(AUTH_CHUNK_CHARACTERS) {
            client.send(&format!("{command} DATA {}", std::str::from_utf8(chunk)?))?;
        }
        client.send(&format!("{command} END"))?;
        let _foreign = read_leniently(&mut client, |line| {
            line.contains(&format!(" {command} END")) || line.contains("FAIL ")
        });
    }
    drop(client);

    // A registered guest cannot log out of an account or delete one; each
    // refusal may close the connection, so each gets its own.
    fixture.phase("guest refusals");
    let (mut guest, registered) = connect_registered_guest(fixture)
        .map_err(|error| failure(format!("guest register: {error}")))?;
    assert_contains(&registered, " 001 LiveUser ")?;
    let _logout = send_and_sync(&mut guest, &["AUTHENTICATE *".to_owned()]);
    drop(guest);
    let (mut deleter, registered) = connect_registered_guest(fixture)
        .map_err(|error| failure(format!("deleter register: {error}")))?;
    assert_contains(&registered, " 001 LiveUser ")?;
    deleter.send("ACCT DELETE START")?;
    let _deletion = read_leniently(&mut deleter, |line| {
        line.contains("FAIL ") || line.contains(" ACCT ") || line.contains(" 4")
    });
    drop(deleter);

    // Account settings from an authenticated session are acknowledged.
    fixture.phase("account settings");
    let mut settings = ArcClient::connect(fixture)?;
    settings
        .negotiate_sasl()
        .map_err(|error| failure(format!("settings negotiate: {error}")))?;
    let acknowledged = settings
        .send_until(
            "CAP REQ :standard-replies agenc.ag/account-controls agenc.ag/channel-controls",
            " CAP * ACK ",
        )
        .map_err(|error| failure(format!("settings cap: {error}")))?;
    assert_contains(&acknowledged, "standard-replies")?;
    assert_contains(&acknowledged, "agenc.ag/account-controls")?;
    authenticate_live_account(&mut settings, fixture, ACCOUNT_PASSWORD, 106, account_id)
        .map_err(|error| failure(format!("settings auth: {error}")))?;
    let registered = settings
        .complete_registration("SettingsUser")
        .map_err(|error| failure(format!("settings register: {error}")))?;
    assert_contains(&registered, " 001 SettingsUser ")?;
    for line in [
        "ACCT PRESENCE PUBLIC",
        "ACCT GUEST-DM ALLOW",
        "ACCT DIRECT-MESSAGES CONTACTS",
        "ACCT LABEL :Settings",
        "ACCT LABEL *",
        "ACCT NICK SettingsUser",
        "ACCT CONTACT ADD SettingsUser",
        "ACCT CONTACT DEL SettingsUser",
        "ACCT BOGUS",
    ] {
        if settings.send(line).is_err() {
            break;
        }
        let _reply = read_leniently(&mut settings, |reply| {
            reply.contains(" ACCT ") || reply.contains("FAIL ") || reply.contains(" 4")
        });
    }
    drop(settings);

    fixture.phase("shutdown");
    let mut admin = AdminClient::connect(fixture)?;
    admin.confirm_process("DIE :credential edge shutdown")?;
    assert!(daemon.wait()?.success(), "{}", fixture.log_excerpt());
    Ok(())
}

#[path = "stage_six_daemon/profile_matrix.rs"]
mod profile_matrix;
