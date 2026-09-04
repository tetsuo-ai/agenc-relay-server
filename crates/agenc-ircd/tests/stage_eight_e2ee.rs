//! End-to-end Stage 07 federation: one coordinator and two edge daemons of
//! the production binary over real mutual TLS, with clients registered on
//! the edges, cross-edge channel traffic, a coordinator restart, and the
//! fail-closed partition behaviour of an edge.
#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agenc_ircd_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountRequestPayload,
    AccountServiceEnvelope, AccountServiceResponse, AccountServiceResponsePayload,
    AuthenticationFinish, AuthenticationStart, Completion, CreationFinish, CreationStart,
    OpaqueKe1, OpaqueKe3, OpaqueProfile, OpaqueRegistrationRequest, encode_request_plaintext,
    finish_registration, open_and_parse_response,
};
use agenc_ircd_config::{
    DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName, InitProfile, InitValues, NodeRole,
    OperatorTemplate, encode_base64url_32, render_template,
};
use agenc_ircd_crypto::{
    AccountHpkePrivateKey, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, audit_signing_key_id, backup_signing_key_id,
};
use agenc_ircd_crypto::{
    AccountRequestBinding, AccountResponseOpenToken, OsEntropy, seal_account_request,
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
use agenc_ircd_testkit::crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_testkit::e2ee;
use agenc_ircd_testkit::e2ee::finality::{Terminal, VoteSlot, vote_tbs};
use agenc_ircd_testkit::e2ee::ids::semantic_id_of;
use agenc_ircd_testkit::e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_testkit::e2ee::objects::aad::{IrcApplicationAad, IrcCommitAad};
use agenc_ircd_testkit::e2ee::objects::attach::{IrcDeviceAttach, IrcDeviceAttachChallenge};
use agenc_ircd_testkit::e2ee::objects::conversation::{
    IrcCloseAuthorization, IrcCloseAuthorizationTbs, IrcCloseIntent, IrcCommitAuthorizationRule,
    IrcCommitAuthorizationTbs, IrcConversationBindingPackage, IrcConversationKind, IrcReservation,
    IrcSemanticRouteTbs, action_bits,
};
use agenc_ircd_testkit::e2ee::objects::sequencing::{
    IrcCandidateReceipt, IrcCommitAck, IrcCommitAckTbs, IrcFinalizationCoreTbs,
    IrcFinalizationProof, IrcFinalizationRequest, IrcGroupGenesisTbs,
};
use agenc_ircd_testkit::e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_ircd_testkit::e2ee::wire::fragment::{
    CLIENT_FRAGMENT_TAG, FragmentTag, RECEIPT_TAG, ReceiptTag, SERVER_FRAGMENT_TAG, fragment_object,
};
use agenc_ircd_testkit::e2ee::wire::tokens::{base64url_decode, base64url_encode};
use agenc_ircd_testkit::e2ee_client as builders;
use agenc_ircd_types::{
    AccountId, AccountServiceCompletionStatus, DatabaseId, NetworkId, NormalizedLogin,
    OpaqueCredentialId, OperatorId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
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
        let hpke = AccountHpkePrivateKey::from_bytes([plan.coordinator.seed.wrapping_add(13); 32])?;
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
                operator_id,
                signing_public_key: *Ed25519SecretKey::from_bytes(operator_signing)
                    .public_key()
                    .as_bytes(),
            },
        };
        let mut config = render_template(&values)?;
        apply_common_overrides(&mut config, public_address, uid)?;
        apply_federation_overrides(&mut config, plan, &tls_dir, &ca_path)?;
        let sequencer = Ed25519SecretKey::from_bytes([plan.coordinator.seed.wrapping_add(15); 32]);
        let credentials = builders::sequencer_credentials_document(
            *NETWORK_ID.as_bytes(),
            &sequencer,
            (0, 4_000_000_000),
        )?;
        let credentials_path = keys_dir.join("sequencer-credentials.bin");
        write_private(&credentials_path, &credentials)?;
        apply_e2ee_overrides(&mut config, plan, &keys_dir, &credentials_path)?;
        let config_path = etc.join("config.toml");
        write_private(&config_path, config.as_bytes())?;
        Ok(Self {
            _root: root,
            config_path,
            log_dir: data_dir.join("logs"),
            public_address,
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
        "memory_budget_bytes = 4294967296",
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

/// The coordinator's account-service HPKE private key (its seed plus 13).
const ACCOUNT_HPKE_PRIVATE: [u8; 32] = [33; 32];
/// The coordinator's recovery epoch (its seed plus 2); every sealed account
/// envelope binds to it.
const COORDINATOR_RECOVERY_EPOCH: RecoveryEpoch = RecoveryEpoch::from_bytes([22; 16]);
const ACCOUNT_PASSWORD: &[u8] = b"stage eight account password";
const TEST_ARGON2_SALT: [u8; 16] = [0; 16];
const AUTH_CHUNK_CHARACTERS: usize = 400;
const ACCOUNT_REQUEST_CHARACTERS: usize = 6_302;
const ACCOUNT_RESPONSE_CHARACTERS: usize = 5_790;
const SASL_REQUEST_CHARACTERS: usize = 6_304;
const SASL_RESPONSE_CHARACTERS: usize = 5_792;
const ALICE_ROOT: u8 = 61;
const ALICE_DEVICE: u8 = 62;
const BOB_ROOT: u8 = 71;
const BOB_DEVICE: u8 = 72;
const GROUP: [u8; 32] = [77; 32];
const DIRECT_GROUP: [u8; 32] = [78; 32];
const E2EE_CAPS: &str = "sasl agenc.ag/account-create message-tags echo-message batch labeled-response standard-replies account-tag agenc.ag/e2ee-mls";

/// Enables the encrypted profile: the coordinator names its sequencer key
/// and the credentials document, every node names the credentials document.
fn apply_e2ee_overrides(
    config: &mut String,
    plan: &NodePlan<'_>,
    keys_dir: &Path,
    credentials_path: &Path,
) -> TestResult {
    let coordinator_id = plan.coordinator.server_id.to_base64url();
    let block = format!(
        "[e2ee]\n# Disabled until the sequencer credentials are published; false is core-only.\nenabled = false\ncoordinator_server_id = \"{coordinator_id}\"\n"
    );
    let mut enabled = format!(
        "[e2ee]\nenabled = true\ncoordinator_server_id = \"{coordinator_id}\"\nsequencer_credentials_file = \"{}\"\n",
        protected_path_text(credentials_path)?
    );
    if plan.identity.role == NodeRole::Coordinator {
        enabled.push_str(&format!(
            "sequencer_private_key_file = \"{}\"\n",
            protected_path_text(&keys_dir.join("sequencer.key"))?
        ));
    }
    replace_once(config, &block, &enabled)?;
    if plan.identity.role == NodeRole::Coordinator {
        let commented_key = format!(
            "# sequencer_private_key_file = \"{}\"\n",
            protected_path_text(&keys_dir.join("sequencer.key"))?
        );
        replace_once(config, &commented_key, "")?;
        let commented_credentials = format!(
            "# sequencer_credentials_file = \"{}\"\n",
            protected_path_text(&keys_dir.join("sequencer-credentials.toml"))?
        );
        replace_once(config, &commented_credentials, "")?;
    }
    Ok(())
}

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
        COORDINATOR_RECOVERY_EPOCH,
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
#[derive(Clone, Copy)]
enum AccountCarrier {
    Create,
}

impl AccountCarrier {
    const fn command(self) -> &'static str {
        match self {
            Self::Create => "ACCTCREATE",
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
impl IrcClient {
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
                return Err(failure(format!(
                    "SASL response framing was invalid: {line}"
                )));
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

fn create_live_account(
    client: &mut IrcClient,
    _fixture: &NodeFixture,
    login_name: &str,
    request_seed: u8,
) -> TestResult<AccountId> {
    let mut rng = TestOpaqueRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, ACCOUNT_PASSWORD)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (start_envelope, start_token) = seal_account_payload(
        NETWORK_ID,
        request_seed,
        AccountRequestPayload::CreationStart(CreationStart {
            network_id: NETWORK_ID,
            login: NormalizedLogin::prepare(login_name)?,
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
            opaque_identifiers(&NETWORK_ID, &credential_id),
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

    let finish_seed = request_seed
        .checked_add(1)
        .ok_or_else(|| failure("creation request seed overflow"))?;
    let (finish_envelope, finish_token) = seal_account_payload(
        NETWORK_ID,
        finish_seed,
        AccountRequestPayload::CreationFinish(CreationFinish {
            network_id: NETWORK_ID,
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
    client: &mut IrcClient,
    _fixture: &NodeFixture,
    login_name: &str,
    password: &[u8],
    request_seed: u8,
    expected_account: AccountId,
) -> TestResult {
    let mut rng = TestOpaqueRng::new();
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (start_envelope, start_token) = seal_account_payload(
        NETWORK_ID,
        request_seed,
        AccountRequestPayload::AuthenticationStart(AuthenticationStart {
            network_id: NETWORK_ID,
            login: NormalizedLogin::prepare(login_name)?,
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
    let context = opaque_context(NETWORK_ID);
    let login_finish = login.state.finish(
        &mut rng,
        password,
        CredentialResponse::<TestOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&NETWORK_ID, &credential_id),
            Some(&TestArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(login_finish.message.serialize().as_slice().try_into()?)?;
    rng.require_success()?;
    let finish_seed = request_seed
        .checked_add(1)
        .ok_or_else(|| failure("authentication request seed overflow"))?;
    let (finish_envelope, finish_token) = seal_account_payload(
        NETWORK_ID,
        finish_seed,
        AccountRequestPayload::AuthenticationFinish(AuthenticationFinish {
            network_id: NETWORK_ID,
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

/// One E2EE principal: its signing keys, its account, and a label counter.
struct Principal {
    keys: builders::Principal,
    device: u8,
    account: [u8; 24],
    labels: u32,
}

impl Principal {
    fn new(root: u8, device: u8, account_id: AccountId) -> TestResult<Self> {
        let text = account_id.to_text();
        let account: [u8; 24] = text
            .as_bytes()
            .try_into()
            .map_err(|_| failure("account text is 24 bytes"))?;
        Ok(Self {
            keys: builders::principal(root, &account, &[device])?,
            device,
            account,
            labels: 0,
        })
    }

    fn label(&mut self) -> String {
        self.labels += 1;
        format!("l{}", self.labels)
    }

    fn device_token(&self) -> String {
        base64url_encode(&[self.device; 16])
    }
}

/// Wraps a companion body as its wire object.
fn wire_object(kind: IrcWireObjectKind, value: &impl TlsEncode) -> TestResult<Vec<u8>> {
    Ok(IrcWireObject::new(kind, value.encode()?)?.encode()?)
}

/// Sends `command` with `object` attached as client fragment tags; every
/// fragment carries the label so the last one completes the request.
fn send_object(client: &mut IrcClient, label: &str, command: &str, object: &[u8]) -> TestResult {
    for fragment in fragment_object(object)? {
        client.send(&format!(
            "@label={label};{CLIENT_FRAGMENT_TAG}={} {command}",
            fragment.render()
        ))?;
    }
    Ok(())
}

/// The value of one tag on a line, when the line carries a tag section.
fn tag_value(line: &str, key: &str) -> Option<String> {
    let tags = line.strip_prefix('@')?.split(' ').next()?;
    tags.split(';').find_map(|tag| {
        let (name, value) = tag.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

/// Reads the labeled reply: one line, or a whole `agenc.ag/e2ee-objects`
/// batch when the reply opens one.
fn labeled_reply(client: &mut IrcClient, label: &str) -> TestResult<Vec<String>> {
    let mut batch_id: Option<String> = None;
    client
        .read_until(|line| {
            if let Some(id) = &batch_id {
                return line.contains(&format!(" BATCH -{id}"));
            }
            if tag_value(line, "label").as_deref() != Some(label) {
                return false;
            }
            if let Some(rest) = line.split(" BATCH +").nth(1) {
                batch_id = rest.split(' ').next().map(str::to_owned);
                return false;
            }
            true
        })
        .map_err(|error| failure(format!("waiting for label {label}: {error}")))
}

/// Reassembles the object a reply carried in its fragment tags: the server
/// tag on batch lines, the preserved client-only tag on live echoes.
fn batch_object(lines: &[String]) -> TestResult<Vec<u8>> {
    let mut fragments: Vec<FragmentTag> = lines
        .iter()
        .filter_map(|line| {
            tag_value(line, SERVER_FRAGMENT_TAG).or_else(|| tag_value(line, CLIENT_FRAGMENT_TAG))
        })
        .map(|value| FragmentTag::parse(&value))
        .collect::<Result<_, _>>()?;
    if fragments.is_empty() {
        return Err(failure(format!("no object in {lines:?}")));
    }
    fragments.sort_by_key(|fragment| fragment.part);
    Ok(fragments
        .into_iter()
        .flat_map(|fragment| fragment.segment)
        .collect())
}

/// The whitespace-separated words after the line's prefix.
fn words(line: &str) -> Vec<String> {
    let body = match line.strip_prefix('@') {
        Some(rest) => rest.split_once(' ').map_or("", |(_, body)| body),
        None => line,
    };
    body.split(' ').map(str::to_owned).collect()
}

/// The 32-byte hash token at `index` of the reply line naming `verb`.
fn hash_at(lines: &[String], verb: &str, index: usize) -> TestResult<[u8; 32]> {
    let line = lines
        .iter()
        .find(|line| {
            words(line).get(1).is_some_and(|word| word == verb)
                || line.contains(&format!(" {verb} "))
        })
        .ok_or_else(|| failure(format!("no {verb} line in {lines:?}")))?;
    let word = words(line)
        .get(index)
        .cloned()
        .ok_or_else(|| failure(format!("no token {index} in {line}")))?;
    let bytes = base64url_decode(&word)?;
    bytes
        .try_into()
        .map_err(|_| failure(format!("token {word} is not 32 bytes")))
}

/// Registers an authenticated client on `fixture`: one connection creates
/// the account and a second authenticates and registers.
fn authenticated_client(
    fixture: &NodeFixture,
    nickname: &str,
    login: &str,
    request_seed: u8,
) -> TestResult<(IrcClient, AccountId)> {
    let account_id = {
        let mut creation = IrcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture, login, request_seed)?
    };
    let mut client = IrcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let acknowledged = client.send_until(&format!("CAP REQ :{E2EE_CAPS}"), " CAP * ACK ")?;
    assert_contains(&acknowledged, "agenc.ag/e2ee-mls")?;
    let auth_seed = request_seed
        .checked_add(2)
        .ok_or_else(|| failure("authentication request seed overflow"))?;
    authenticate_live_account(
        &mut client,
        fixture,
        login,
        ACCOUNT_PASSWORD,
        auth_seed,
        account_id,
    )?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok((client, account_id))
}

/// Publishes the identity and roster and attaches the device.
fn publish_and_attach(client: &mut IrcClient, user: &mut Principal) -> TestResult {
    let root = wire_object(IrcWireObjectKind::RootIdentity, &user.keys.root)?;
    let label = user.label();
    send_object(client, &label, "EKEY PUBLISH IDENTITY", &root)?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY STORED IDENTITY ")?;
    let roster = wire_object(IrcWireObjectKind::DeviceRoster, &user.keys.roster)?;
    let label = user.label();
    send_object(client, &label, "EKEY PUBLISH ROSTER", &roster)?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY STORED ROSTER ")?;

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

/// What the binder learns from a successful `EGROUP BIND`.
struct BoundConversation {
    conversation: [u8; 32],
    binding_id: [u8; 32],
    route_binding: [u8; 32],
    group_id: [u8; 32],
    /// The channel instance of a channel route.
    instance: Option<[u8; 16]>,
    binding: Vec<u8>,
    package: IrcConversationBindingPackage,
}

impl BoundConversation {
    /// The application carrier command of this conversation.
    fn application_command(&self) -> String {
        match self.instance {
            Some(_) => "TAGMSG #room".to_owned(),
            None => format!("EDIRECT {}", base64url_encode(&self.conversation)),
        }
    }

    /// The text every forwarded application line of this conversation carries.
    fn application_marker(&self) -> String {
        match self.instance {
            Some(_) => " TAGMSG #room".to_owned(),
            None => format!(" EDIRECT {}", base64url_encode(&self.conversation)),
        }
    }
}

/// Decodes the reservation object of a `RESERVED` batch.
fn reservation_of(reply: &[String]) -> TestResult<IrcReservation> {
    let bytes = batch_object(reply)?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object =
        IrcWireObject::decode_kind(&bytes, Some(IrcWireObjectKind::Reservation), &mut budget)?;
    Ok(IrcReservation::decode_exact(object.body(), &mut budget)?)
}

/// Sends the binding package of `reservation` and returns the bound facts.
fn bind(
    client: &mut IrcClient,
    binder: &mut Principal,
    reservation: &IrcReservation,
    package: IrcConversationBindingPackage,
    route_binding: [u8; 32],
    group_id: [u8; 32],
) -> TestResult<BoundConversation> {
    let binding = wire_object(IrcWireObjectKind::ConversationBinding, &package)?;
    let conversation = e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &group_id)?;
    let label = binder.label();
    send_object(
        client,
        &label,
        &format!(
            "EGROUP BIND {} {} {}",
            base64url_encode(&reservation.tbs.reservation_id),
            base64url_encode(&conversation),
            base64url_encode(&[44; 32])
        ),
        &binding,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EGROUP BOUND ")?;
    assert_eq!(hash_at(&reply, "BOUND", 3)?, conversation);
    Ok(BoundConversation {
        conversation,
        binding_id: hash_at(&reply, "BOUND", 4)?,
        route_binding,
        group_id,
        instance: reservation
            .tbs
            .channel_instance_id
            .as_slice()
            .try_into()
            .ok(),
        binding,
        package,
    })
}

/// Reserves and binds a direct conversation between the two principals
/// from `client`; the roots chain their binding locks after `previous`.
fn reserve_and_bind_direct(
    client: &mut IrcClient,
    binder: &mut Principal,
    peer: &Principal,
    previous: &BoundConversation,
) -> TestResult<BoundConversation> {
    let label = binder.label();
    client.send(&format!(
        "@label={label} EGROUP RESERVE DIRECT {}",
        base64url_encode(&peer.account)
    ))?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EGROUP RESERVED ")?;
    let reservation = reservation_of(&reply)?;
    let nonce: [u8; 32] = reservation
        .tbs
        .conversation_nonce
        .as_slice()
        .try_into()
        .map_err(|_| failure("the direct reservation names its nonce"))?;
    let (first, second) = if binder.account <= peer.account {
        (binder.account, peer.account)
    } else {
        (peer.account, binder.account)
    };
    let route = IrcSemanticRouteTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        kind: IrcConversationKind::Direct,
        direct_account_a: Opaque::from_slice(&first)?,
        direct_account_b: Opaque::from_slice(&second)?,
        canonical_channel_name: Opaque::new(Vec::new())?,
        channel_authority_root_fingerprint: [0; 32],
        semantic_incarnation: 0,
        predecessor_close_id: [0; 32],
    };
    let principals = [&binder.keys, &peer.keys];
    let package = builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route,
        channel_instance_id: None,
        conversation_nonce: Some(nonce),
        group_id: DIRECT_GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 1,
        previous_lock_ids: builders::lock_ids(&previous.package)?,
        plan_devices: vec![
            (
                &binder.account,
                builders::root_fingerprint(&binder.keys.root)?,
                binder.device,
            ),
            (
                &peer.account,
                builders::root_fingerprint(&peer.keys.root)?,
                peer.device,
            ),
        ],
    })?;
    let route_binding =
        e2ee::route::direct_route_binding(NETWORK_ID.as_bytes(), &nonce, &first, &second)?;
    bind(
        client,
        binder,
        &reservation,
        package,
        route_binding,
        DIRECT_GROUP,
    )
}

/// Reserves and binds `#room` for both principals from `client`.
fn reserve_and_bind(
    client: &mut IrcClient,
    binder: &mut Principal,
    peer: &Principal,
) -> TestResult<BoundConversation> {
    let label = binder.label();
    client.send(&format!("@label={label} EGROUP RESERVE CHANNEL #room"))?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EGROUP RESERVED ")?;
    let reservation = reservation_of(&reply)?;
    let instance: [u8; 16] = reservation
        .tbs
        .channel_instance_id
        .as_slice()
        .try_into()
        .map_err(|_| failure("the reservation names the channel instance"))?;
    let fingerprint = builders::root_fingerprint(&binder.keys.root)?;
    let principals = [&binder.keys, &peer.keys];
    let package = builders::binding_package(&builders::BindingSpec {
        principals: &principals,
        route: builders::channel_route(b"#room", fingerprint)?,
        channel_instance_id: Some(instance),
        conversation_nonce: None,
        group_id: GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 0,
        previous_lock_ids: Vec::new(),
        plan_devices: vec![
            (&binder.account, fingerprint, binder.device),
            (
                &peer.account,
                builders::root_fingerprint(&peer.keys.root)?,
                peer.device,
            ),
        ],
    })?;
    let route_binding = e2ee::route::channel_route_binding(NETWORK_ID.as_bytes(), &instance)?;
    bind(client, binder, &reservation, package, route_binding, GROUP)
}

/// The context core identifier the test binding package carries.
const CONTEXT_CORE_ID: [u8; 32] = [30; 32];
/// The initial and required operational policy identifiers of the package.
const INITIAL_POLICY_ID: [u8; 32] = [27; 32];
const OPERATIONAL_POLICY_ID: [u8; 32] = [28; 32];
const VALIDATION_TIME: u64 = 1_700_000_000;
/// MLS content types (RFC 9420 section 6).
const MLS_APPLICATION: u8 = 1;
const MLS_COMMIT: u8 = 3;

/// Wraps raw MLS bytes as the wire object of `kind`.
fn raw_object(kind: IrcWireObjectKind, bytes: Vec<u8>) -> TestResult<Vec<u8>> {
    Ok(IrcWireObject::new(kind, bytes)?.encode()?)
}

/// Reassembles the object the server fragment tags of `lines` carry.
fn fragments_object(lines: &[String]) -> TestResult<Vec<u8>> {
    batch_object(lines)
}

/// Runs the bootstrap activation round on `bound` from the binder: one
/// Commit candidate sequenced by the coordinator, then its finalization
/// with the binder's council vote; returns the finalization identifier,
/// which is the next accepted state.
fn activate_bootstrap(
    client: &mut IrcClient,
    binder: &mut Principal,
    bound: &BoundConversation,
) -> TestResult<[u8; 32]> {
    let network = *NETWORK_ID.as_bytes();
    let conversation = bound.conversation;
    let route_binding = bound.route_binding;
    let genesis = IrcGroupGenesisTbs {
        network_id: network,
        conversation_id: conversation,
        group_id: Opaque::new(bound.group_id.to_vec())?,
        binding_id: bound.binding_id,
        context_core_id: CONTEXT_CORE_ID,
    };
    let accepted = semantic_id_of(SemanticHashDomain::GroupGenesisId, &genesis)?;

    let commit_aad = IrcCommitAad {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        route_binding,
        validation_time: VALIDATION_TIME,
        prior_state_id: accepted,
    }
    .encode()?;
    let commit = raw_object(
        IrcWireObjectKind::CommitMls,
        builders::private_message_at_epoch(&bound.group_id, 0, MLS_COMMIT, &commit_aad)?,
    )?;
    let commit_object_id = *e2ee::ObjectId::compute(&commit).as_bytes();
    let conversation_token = base64url_encode(&conversation);
    let label = binder.label();
    send_object(
        client,
        &label,
        &format!("EGROUP SUBMIT CANDIDATE {conversation_token}"),
        &commit,
    )?;
    let echo = labeled_reply(client, &label)?;
    assert_contains(&echo, " EGROUP CANDIDATE ")?;
    assert_eq!(fragments_object(&echo)?, commit);
    let receipt_tag = echo
        .iter()
        .find_map(|line| tag_value(line, RECEIPT_TAG))
        .ok_or_else(|| failure("the candidate echo carries the receipt tag"))?;
    let receipt_tag = ReceiptTag::parse(&receipt_tag)?;
    let candidate_id = receipt_tag.candidate_id;
    assert_eq!(hash_at(&echo, "CANDIDATE", 5)?, candidate_id);
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let receipt = IrcCandidateReceipt::decode_exact(&receipt_tag.receipt, &mut budget)?;
    assert_eq!(receipt.tbs.commit_object_id, commit_object_id);
    assert_eq!(receipt.tbs.prior_state_id, accepted);

    let authorization = builders::commit_authorization(
        IrcCommitAuthorizationTbs {
            profile_version: 1,
            network_id: network,
            conversation_id: conversation,
            prior_epoch: 0,
            prior_state_id: accepted,
            candidate_id,
            commit_object_id,
            canonical_validation_time: VALIDATION_TIME,
            old_policy_id: INITIAL_POLICY_ID,
            authorization_rule: IrcCommitAuthorizationRule::BootstrapActivation,
            action_bits: action_bits::POLICY | action_bits::BOOTSTRAP,
            resulting_policy_id: OPERATIONAL_POLICY_ID,
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            transition_target_digest: [0; 32],
        },
        &[(&binder.keys, binder.device)],
    )?;
    let core = IrcFinalizationCoreTbs {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        prior_epoch: 0,
        prior_state_id: accepted,
        candidate_id,
        commit_object_id,
        resulting_epoch: 1,
        old_policy_id: INITIAL_POLICY_ID,
        commit_authorization_id: semantic_id_of(
            SemanticHashDomain::CommitAuthorizationId,
            &authorization.tbs,
        )?,
        acknowledgement_set_digest: [3; 32],
        resulting_group_context_digest: [1; 32],
        resulting_ratchet_tree_digest: [2; 32],
        finalization_authenticator: [4; 32],
    };
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
    let ack = IrcCommitAck {
        tbs: IrcCommitAckTbs {
            profile_version: 1,
            network_id: network,
            conversation_id: conversation,
            prior_epoch: 0,
            candidate_id,
            commit_object_id,
            old_leaf_index: 0,
            old_credential_hash: [5; 32],
            resulting_epoch: 1,
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            finalization_authenticator: [4; 32],
        },
        old_leaf_signature: Opaque::new(vec![6; 64])?,
    };
    let slot = VoteSlot {
        network_id: network,
        conversation_id: conversation,
        prior_epoch: 0,
        prior_state_id: accepted,
        candidate_sequence: receipt.tbs.candidate_sequence,
        predecessor_record_id: receipt.tbs.predecessor_record_id,
    };
    let vote = builders::finality_vote(
        &binder.keys,
        binder.device,
        &vote_tbs(&slot, candidate_id, Terminal::finalize(finalization_id)),
    )?;
    let request = IrcFinalizationRequest {
        proof: IrcFinalizationProof {
            core,
            receipt,
            authorization,
            acknowledgements: TlsVec::new(vec![ack])?,
        },
        votes: TlsVec::new(vec![vote])?,
    };
    let request = wire_object(IrcWireObjectKind::FinalizationRequest, &request)?;
    let label = binder.label();
    send_object(
        client,
        &label,
        &format!("EGROUP SUBMIT FINALIZATION {conversation_token}"),
        &request,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(
        &reply,
        &format!(" EGROUP FINALIZED {conversation_token} 1 "),
    )?;
    assert_eq!(hash_at(&reply, "FINALIZED", 5)?, finalization_id);
    Ok(finalization_id)
}

/// Sends one application message on the bound channel from `sender` and
/// returns the object bytes, after checking the labeled echo.
fn send_application(
    sender: &mut IrcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    latest_state_id: [u8; 32],
    epoch: u64,
) -> TestResult<Vec<u8>> {
    let network = *NETWORK_ID.as_bytes();
    let aad = IrcApplicationAad {
        profile_version: 1,
        network_id: network,
        conversation_id: bound.conversation,
        route_binding: bound.route_binding,
        latest_state_id,
    }
    .encode()?;
    let ciphertext: Vec<u8> = principal
        .account
        .iter()
        .cycle()
        .take(300)
        .copied()
        .collect();
    let message = raw_object(
        IrcWireObjectKind::ApplicationMls,
        builders::private_message_with_ciphertext(
            &bound.group_id,
            epoch,
            MLS_APPLICATION,
            &aad,
            &ciphertext,
        )?,
    )?;
    let label = principal.label();
    send_object(sender, &label, &bound.application_command(), &message)?;
    let echo = labeled_reply(sender, &label)?;
    assert_contains(&echo, &bound.application_marker())?;
    assert_eq!(fragments_object(&echo)?, message);
    Ok(message)
}

/// Reads the next forwarded application message of `bound` from `client`.
fn receive_application(client: &mut IrcClient, bound: &BoundConversation) -> TestResult<Vec<u8>> {
    let marker = bound.application_marker();
    let lines = client.read_until(|line| line.contains(&marker))?;
    let forwarded: Vec<String> = lines
        .into_iter()
        .filter(|line| line.contains(&marker))
        .collect();
    fragments_object(&forwarded)
}

/// Closes `bound` from `client` under the finalization `terminal` and
/// returns the close identifier.
fn close_conversation(
    client: &mut IrcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    terminal: [u8; 32],
) -> TestResult<[u8; 32]> {
    let intent = IrcCloseIntent {
        reason_code: 1,
        validation_time: VALIDATION_TIME + 1,
    };
    let tbs = IrcCloseAuthorizationTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: bound.conversation,
        binding_id: bound.binding_id,
        authorizing_terminal_id: terminal,
        close_intent_id: semantic_id_of(SemanticHashDomain::CloseIntentId, &intent)?,
        close_intent: intent,
    };
    let approval = builders::commit_approval(
        &principal.keys,
        principal.device,
        &tbs,
        SignatureDomain::CloseAuthorization,
    )?;
    let close = IrcCloseAuthorization {
        tbs,
        approvals: TlsVec::new(vec![approval])?,
    };
    let close_id = e2ee::route::close_authorization_id(&close)?;
    let object = wire_object(IrcWireObjectKind::CloseAuthorization, &close)?;
    let conversation = base64url_encode(&bound.conversation);
    let label = principal.label();
    send_object(
        client,
        &label,
        &format!("EGROUP CLOSE {conversation} 1"),
        &object,
    )?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, &format!(" EGROUP CLOSED {conversation} "))?;
    assert_eq!(hash_at(&reply, "CLOSED", 4)?, close_id);
    Ok(close_id)
}

/// Sends application lines until the edge reports the coordinator link
/// down with `E2EE_SYNCING`; the link loss takes a moment to surface.
fn wait_for_e2ee_partition(
    client: &mut IrcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    message: &[u8],
) -> TestResult {
    let deadline = Instant::now() + NETWORK_WAIT;
    loop {
        let label = principal.label();
        send_object(client, &label, &bound.application_command(), message)?;
        let reply = labeled_reply(client, &label)?;
        if reply
            .iter()
            .any(|line| line.contains("FAIL") && line.contains("E2EE_SYNCING"))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(failure(format!(
                "the edge never reported the partition; last reply {reply:?}"
            )));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Binds a direct conversation from the smaller account, activates it, and
/// exchanges one message each way; returns the conversation and the first
/// message.
fn direct_round(
    smaller: (&mut IrcClient, &mut Principal),
    larger: (&mut IrcClient, &mut Principal),
    previous: &BoundConversation,
) -> TestResult<(BoundConversation, Vec<u8>)> {
    let (first, first_keys) = smaller;
    let (second, second_keys) = larger;
    let direct = step(
        "direct bind",
        reserve_and_bind_direct(first, first_keys, second_keys, previous),
    )?;
    let terminal = step(
        "direct activation",
        activate_bootstrap(first, first_keys, &direct),
    )?;
    let note = step(
        "direct note",
        send_application(first, first_keys, &direct, terminal, 1),
    )?;
    assert_eq!(
        step("direct note receipt", receive_application(second, &direct))?,
        note
    );
    let reply = step(
        "direct reply",
        send_application(second, second_keys, &direct, terminal, 1),
    )?;
    assert_eq!(
        step("direct reply receipt", receive_application(first, &direct))?,
        reply
    );
    Ok((direct, note))
}

/// Names the scenario step a failure belongs to.
fn step<T>(name: &str, result: TestResult<T>) -> TestResult<T> {
    result.map_err(|error| failure(format!("{name}: {error}")))
}

/// Fails when a daemon log names anything a client sent or is.
fn assert_private_logs(network: &Network, secrets: &[String]) -> TestResult {
    for (name, fixture) in [
        ("coordinator", &network.coordinator),
        ("edge a", &network.edge_a),
        ("edge b", &network.edge_b),
    ] {
        let text = fixture.log_text();
        for secret in secrets {
            if text.contains(secret.as_str()) {
                return Err(failure(format!("{name} log leaks {secret}")));
            }
        }
    }
    Ok(())
}

/// Delivers the binding package to `target`'s device mailbox from
/// `sender`; `receiver` fetches the page and acknowledges the item.
fn exchange_binding_mailbox(
    sender: &mut IrcClient,
    sender_keys: &mut Principal,
    receiver: &mut IrcClient,
    receiver_keys: &mut Principal,
    binding: &[u8],
) -> TestResult {
    let label = sender_keys.label();
    send_object(
        sender,
        &label,
        &format!(
            "EKEY DELIVER BINDING {} {}",
            base64url_encode(&receiver_keys.account),
            receiver_keys.device_token()
        ),
        binding,
    )?;
    let reply = labeled_reply(sender, &label)?;
    assert_contains(&reply, " EKEY STORED BINDING ")?;
    let object_id = *e2ee::ObjectId::compute(binding).as_bytes();
    assert_eq!(hash_at(&reply, "BINDING", 4)?, object_id);

    let label = receiver_keys.label();
    receiver.send(&format!("@label={label} EKEY FETCH MAILBOX BINDING *"))?;
    let page = labeled_reply(receiver, &label)?;
    assert_contains(&page, " EKEY MAILBOX ")?;
    let token = hash_at(&page, "MAILBOX", 3)?;
    assert_eq!(hash_at(&page, "MAILBOX", 5)?, object_id);
    assert_eq!(fragments_object(&page)?, binding);

    let label = receiver_keys.label();
    receiver.send(&format!(
        "@label={label} EKEY ACK MAILBOX {} {}",
        base64url_encode(&token),
        base64url_encode(&object_id)
    ))?;
    let acked = labeled_reply(receiver, &label)?;
    assert_contains(&acked, " EKEY ACKED ")?;

    let label = receiver_keys.label();
    receiver.send(&format!("@label={label} EKEY FETCH MAILBOX BINDING *"))?;
    let empty = labeled_reply(receiver, &label)?;
    assert_contains(&empty, " EKEY EMPTY ")?;
    Ok(())
}

#[test]
fn encrypted_clients_on_two_edges_bind_a_channel_through_the_coordinator() -> TestResult {
    let network = build_network()?;
    let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
    let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
    let outcome = exercise_encrypted_network(&network, &mut coordinator);
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

fn exercise_encrypted_network(network: &Network, coordinator: &mut DaemonProcess) -> TestResult {
    wait_for_link(&network.edge_a, 0)?;
    wait_for_link(&network.edge_b, 0)?;
    let _probe = register_when_available(&network.edge_a, "probe")?;
    let (mut alice, alice_account) =
        authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
    let (mut bob, bob_account) = authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
    let mut alice_keys = Principal::new(ALICE_ROOT, ALICE_DEVICE, alice_account)?;
    let mut bob_keys = Principal::new(BOB_ROOT, BOB_DEVICE, bob_account)?;
    step(
        "alice attach",
        publish_and_attach(&mut alice, &mut alice_keys),
    )?;
    step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;

    alice.send("JOIN #room")?;
    alice.read_until(|line| line.contains(" 366 alice #room "))?;
    // A binding needs a registered channel with history off and no topic.
    alice.send("CHANCTL REGISTER #room")?;
    alice.read_until(|line| line.contains(" NOTE CHANCTL UPDATED #room "))?;
    bob.send("JOIN #room")?;
    bob.read_until(|line| line.contains(" 366 bob #room "))?;
    alice.read_until(|line| line.starts_with(":bob!") && line.contains(" JOIN #room"))?;
    let bound = step(
        "channel bind",
        reserve_and_bind(&mut alice, &mut alice_keys, &bob_keys),
    )?;
    assert_ne!(bound.conversation, [0; 32]);

    // A bound channel refuses plaintext on both edges.
    alice.send("PRIVMSG #room :hello in the clear")?;
    let refused = alice.read_until(|line| line.contains("E2EE_REQUIRED"))?;
    assert_contains(&refused, "FAIL PRIVMSG E2EE_REQUIRED")?;
    bob.send("NOTICE #room :also in the clear")?;
    let refused = bob.read_until(|line| line.contains("E2EE_REQUIRED"))?;
    assert_contains(&refused, "FAIL NOTICE E2EE_REQUIRED")?;

    // Application traffic waits for the bootstrap activation certificate.
    let genesis_state = [0; 32];
    let label = alice_keys.label();
    let early = {
        let network = *NETWORK_ID.as_bytes();
        let aad = IrcApplicationAad {
            profile_version: 1,
            network_id: network,
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            latest_state_id: genesis_state,
        }
        .encode()?;
        raw_object(
            IrcWireObjectKind::ApplicationMls,
            builders::private_message_at_epoch(&GROUP, 0, MLS_APPLICATION, &aad)?,
        )?
    };
    send_object(&mut alice, &label, "TAGMSG #room", &early)?;
    let refused = labeled_reply(&mut alice, &label)?;
    assert_contains(&refused, "FAIL TAGMSG E2EE_FINALITY_REQUIRED")?;

    let finalization_id = step(
        "channel activation",
        activate_bootstrap(&mut alice, &mut alice_keys, &bound),
    )?;
    let broadcast = bob.read_until(|line| line.contains(" EGROUP FINALIZED "))?;
    assert_contains(
        &broadcast,
        &format!(
            " EGROUP FINALIZED {} 1 ",
            base64url_encode(&bound.conversation)
        ),
    )?;

    // Application messages fan out across the edges and echo to the sender.
    let message = step(
        "channel message",
        send_application(&mut alice, &mut alice_keys, &bound, finalization_id, 1),
    )?;
    assert_eq!(
        step(
            "channel message receipt",
            receive_application(&mut bob, &bound)
        )?,
        message
    );
    let answer = step(
        "channel answer",
        send_application(&mut bob, &mut bob_keys, &bound, finalization_id, 1),
    )?;
    assert_eq!(
        step(
            "channel answer receipt",
            receive_application(&mut alice, &bound)
        )?,
        answer
    );

    // The device mailbox carries the binding package to the peer device.
    step(
        "binding mailbox",
        exchange_binding_mailbox(
            &mut alice,
            &mut alice_keys,
            &mut bob,
            &mut bob_keys,
            &bound.binding,
        ),
    )?;

    // A direct conversation binds under the roots' next binding locks and
    // carries traffic between the two edges without a channel. The smaller
    // account of the pair reserves the route.
    let (direct, note) = if alice_keys.account <= bob_keys.account {
        direct_round(
            (&mut alice, &mut alice_keys),
            (&mut bob, &mut bob_keys),
            &bound,
        )?
    } else {
        direct_round(
            (&mut bob, &mut bob_keys),
            (&mut alice, &mut alice_keys),
            &bound,
        )?
    };

    // Closing the channel conversation tombstones the route: the peer sees
    // the broadcast, encrypted traffic is refused, and plaintext stays refused.
    let close_id = step(
        "close",
        close_conversation(&mut alice, &mut alice_keys, &bound, finalization_id),
    )?;
    let broadcast = step(
        "close broadcast",
        bob.read_until(|line| line.contains(" EGROUP CLOSED ")),
    )?;
    assert_eq!(hash_at(&broadcast, "CLOSED", 4)?, close_id);
    let late = raw_object(
        IrcWireObjectKind::ApplicationMls,
        builders::private_message_with_ciphertext(
            &bound.group_id,
            1,
            MLS_APPLICATION,
            &[],
            &[9; 300],
        )?,
    )?;
    let label = alice_keys.label();
    send_object(&mut alice, &label, &bound.application_command(), &late)?;
    let refused = step("tombstone traffic", labeled_reply(&mut alice, &label))?;
    assert_contains(&refused, "FAIL TAGMSG E2EE_ROUTE_INVALID")?;
    bob.send("PRIVMSG #room :after the close")?;
    let refused = step(
        "tombstone plaintext",
        bob.read_until(|line| line.contains("E2EE_REQUIRED")),
    )?;
    assert_contains(&refused, "FAIL PRIVMSG E2EE_REQUIRED")?;

    // No log names a client, an account, a channel, or an object.
    let secrets = vec![
        "alice".to_owned(),
        "bob".to_owned(),
        "#room".to_owned(),
        alice_account.to_text().to_owned(),
        bob_account.to_text().to_owned(),
        base64url_encode(&message),
        base64url_encode(&bound.conversation),
    ];
    assert_private_logs(network, &secrets)?;

    // A coordinator crash partitions the encrypted profile: the edge refuses
    // encrypted traffic with E2EE_SYNCING and nothing is queued. The
    // coordinator restarts from its durable state and both edges resume.
    let links_a = links_established(&network.edge_a);
    let links_b = links_established(&network.edge_b);
    coordinator.kill()?;
    step(
        "partition",
        wait_for_e2ee_partition(&mut bob, &mut bob_keys, &direct, &note),
    )?;
    *coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
    step("relink a", wait_for_link(&network.edge_a, links_a))?;
    step("relink b", wait_for_link(&network.edge_b, links_b))?;
    let mut carol = step(
        "register after restart",
        register_when_available(&network.edge_a, "carol"),
    )?;
    carol.send("JOIN #after")?;
    step(
        "join after restart",
        carol.read_until(|line| line.contains(" 366 carol #after ")),
    )?;
    Ok(())
}
