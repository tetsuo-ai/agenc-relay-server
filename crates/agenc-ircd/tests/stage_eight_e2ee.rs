//! End-to-end Stage 07 federation: one coordinator and two edge daemons of
//! the production binary over real mutual TLS, with clients registered on
//! the edges, cross-edge channel traffic, a coordinator restart, and the
//! fail-closed partition behaviour of an edge.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    IrcCommitAuthorizationTbs, IrcConversationBindingPackage, IrcConversationKind, IrcPolicy,
    IrcReservation, IrcSemanticRouteTbs, action_bits,
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

#[path = "stage_eight_e2ee/close_authority.rs"]
mod close_authority;
#[path = "stage_eight_e2ee/stage_ten_capacity.rs"]
mod stage_ten_capacity;
#[path = "stage_eight_e2ee/stage_ten_drills.rs"]
mod stage_ten_drills;
#[path = "stage_eight_e2ee/stage_ten_login_index.rs"]
mod stage_ten_login_index;
#[path = "stage_eight_e2ee/stage_ten_migration.rs"]
mod stage_ten_migration;
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
/// The edge registers a client only once its coordinator link is ACTIVE;
/// registration attempts before that fail closed and are retried.
const NETWORK_WAIT: Duration = Duration::from_secs(60);
const TRANSCRIPT_LINES: usize = 256;
const REPLY_DEADLINE: Duration = Duration::from_secs(60);
const NETWORK_ID: NetworkId = NetworkId::from_bytes([1; 32]);

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Claims outlive the probe sockets and every fixture restart. Parallel fixture
// builders cannot choose an address already assigned elsewhere in this process.
static LOOPBACK_ADDRESS_CLAIMS: Mutex<BTreeSet<SocketAddr>> = Mutex::new(BTreeSet::new());
const LOOPBACK_ADDRESS_ATTEMPTS: usize = 128;

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
    let mut claims = LOOPBACK_ADDRESS_CLAIMS
        .lock()
        .map_err(|_| failure("loopback address claims are poisoned"))?;
    reserve_loopback_address_with(&mut claims, || {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    })
}

fn reserve_loopback_address_with(
    claims: &mut BTreeSet<SocketAddr>,
    mut select: impl FnMut() -> TestResult<SocketAddr>,
) -> TestResult<SocketAddr> {
    for _ in 0..LOOPBACK_ADDRESS_ATTEMPTS {
        let address = select()?;
        if claims.insert(address) {
            return Ok(address);
        }
    }
    Err(failure(
        "loopback address selection exhausted its distinct candidates",
    ))
}

#[test]
fn loopback_address_selection_skips_every_prior_fixture_claim() -> TestResult {
    let first: SocketAddr = "127.0.0.1:32000".parse()?;
    let second: SocketAddr = "127.0.0.1:32001".parse()?;
    let mut candidates = [first, first, second].into_iter();
    let mut select = || {
        candidates
            .next()
            .ok_or_else(|| failure("selector exhausted"))
    };
    let mut claims = BTreeSet::new();
    assert_eq!(
        reserve_loopback_address_with(&mut claims, &mut select)?,
        first
    );
    assert_eq!(
        reserve_loopback_address_with(&mut claims, &mut select)?,
        second
    );
    assert_eq!(claims.len(), 2);
    Ok(())
}

#[test]
fn loopback_address_selection_bounds_repeated_candidates() -> TestResult {
    let address: SocketAddr = "127.0.0.1:32000".parse()?;
    let mut claims = BTreeSet::from([address]);
    let mut attempts = 0;
    let result = reserve_loopback_address_with(&mut claims, || {
        attempts += 1;
        Ok(address)
    });
    assert!(
        result.is_err(),
        "an already claimed endpoint must never be returned"
    );
    assert_eq!(attempts, LOOPBACK_ADDRESS_ATTEMPTS);
    assert_eq!(claims, BTreeSet::from([address]));
    Ok(())
}

#[test]
fn loopback_address_selection_preserves_binding_errors_and_claims() -> TestResult {
    let address: SocketAddr = "127.0.0.1:32000".parse()?;
    let mut claims = BTreeSet::from([address]);
    let mut attempts = 0;
    let error = reserve_loopback_address_with(&mut claims, || {
        attempts += 1;
        Err(io::Error::from(io::ErrorKind::PermissionDenied).into())
    })
    .err()
    .ok_or_else(|| failure("binding error was discarded"))?;
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(attempts, 1);
    assert_eq!(claims, BTreeSet::from([address]));
    Ok(())
}

#[test]
fn loopback_address_claims_are_unique_across_parallel_fixtures() -> TestResult {
    let addresses = thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    (0..16)
                        .map(|_| reserve_loopback_address())
                        .collect::<TestResult<Vec<_>>>()
                })
            })
            .collect();
        let mut addresses = BTreeSet::new();
        for worker in workers {
            for address in worker
                .join()
                .map_err(|_| failure("address worker failed"))??
            {
                assert!(
                    addresses.insert(address),
                    "parallel fixtures reused {address}"
                );
            }
        }
        Ok::<_, TestError>(addresses)
    })?;
    assert_eq!(addresses.len(), 64);
    Ok(())
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
    /// The identity seed, admin socket, key material, and directories the
    /// Stage 10 campaign and drills need to operate the node like an operator.
    seed: u8,
    server_id: ServerId,
    admin_socket: PathBuf,
    data_dir: PathBuf,
    operator_id: OperatorId,
    /// The federation listener this node binds; only the coordinator has one.
    federation_listener: Option<SocketAddr>,
    /// The OPAQUE fake registration record the database was initialized with,
    /// so a drill can rebuild the same database at another schema generation.
    opaque_fake_record: Vec<u8>,
}

struct NodePlan<'a> {
    identity: &'a NodeIdentity,
    coordinator: &'a NodeIdentity,
    federation_address: Option<SocketAddr>,
    peers: &'a [&'a NodeIdentity],
    /// Stage 10 campaign settings; `None` keeps the Stage 08 configuration.
    capacity: Option<CapacityPlan>,
}

/// Overrides the campaign applies on top of the Stage 08 configuration.
#[derive(Clone, Copy)]
struct CapacityPlan {
    /// Client listener ceiling.
    max_connections: u64,
    /// Direct connections admitted from one address. Every campaign client
    /// arrives from loopback, so the per-address abuse ceiling must clear the
    /// per-edge share of the campaign or half the clients are refused.
    connections_per_address: u64,
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
        if let Some(capacity) = plan.capacity {
            apply_capacity_overrides(&mut config, capacity)?;
        }
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
            seed,
            server_id: identity.server_id,
            admin_socket: runtime_dir.join("admin.sock"),
            data_dir,
            operator_id,
            federation_listener: match plan.identity.role {
                NodeRole::Coordinator => plan.federation_address,
                _ => None,
            },
            opaque_fake_record: opaque.expose_fake_record_for_persistence().to_vec(),
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

/// Enables the local admin socket and raises the client ceiling for the
/// Stage 10 campaign; nothing else differs from the Stage 08 node.
fn apply_capacity_overrides(config: &mut String, capacity: CapacityPlan) -> TestResult {
    replace_once(
        config,
        "enabled = false\npurpose = \"admin_local\"",
        "enabled = true\npurpose = \"admin_local\"",
    )?;
    replace_once(
        config,
        "max_connections = 32\n",
        &format!("max_connections = {}\n", capacity.max_connections),
    )?;
    replace_once(
        config,
        "# direct_connections_per_address = 16 (1..256)\n",
        &format!(
            "direct_connections_per_address = {}\n",
            capacity.connections_per_address
        ),
    )?;
    // New-connection and handshake buckets are keyed by the source /24, which
    // every campaign client shares; both sit at their configuration maxima.
    // The pre-authentication bucket is already at its maximum, so the
    // campaign paces registrations under it instead.
    replace_once(
        config,
        "\n[privacy]",
        "\n[limits.rate.new_direct]\nrefill_tokens = 16\nrefill_seconds = 1\nburst = 64\n\n\
[limits.rate.tls_handshake]\nrefill_tokens = 32\nrefill_seconds = 1\nburst = 128\n\n[privacy]",
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
    let header = DatabaseHeaderTbs::new(
        NETWORK_ID,
        identity.server_id,
        identity.incarnation,
        database_id,
        1,
        SCHEMA_GENERATION,
        identity.recovery_epoch,
    )?;
    initialize_database_with_header(
        state_dir,
        header,
        storage_master,
        rollback_guard,
        login_index,
        opaque.expose_fake_record_for_persistence(),
    )
}

/// Initializes a fixture database under `header`; a generation-1 header goes
/// through the storage crate's legacy fixture constructor so the migration
/// drill can start from a real predecessor database.
fn initialize_database_with_header(
    state_dir: &Path,
    header: DatabaseHeaderTbs,
    storage_master: [u8; 32],
    rollback_guard: [u8; 32],
    login_index: [u8; 32],
    fake_record: &[u8],
) -> TestResult {
    let schema_generation = header.schema_generation;
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
        fake_record.to_vec(),
    )?;
    let fake_record = InitialStorageRecord::new(
        TableId::OpaqueRecord,
        StoredKey::new(OPAQUE_FAKE_RECORD_KEY.to_vec())?,
        1,
        fake_record.encode()?,
    )?;
    let qualifications = embedded_storage_qualifications()?;
    let state_directory = StateDirectory::open(state_dir, &qualifications)?;
    let config = StorageInitializationConfig {
        state_directory,
        header_tbs: header,
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
    };
    let outcome = if schema_generation == SCHEMA_GENERATION {
        initialize_storage(config)?
    } else {
        agenc_ircd_storage::initialize_legacy_storage(config)?
    };
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
        Self::start_in(config_path, None)
    }

    /// Starts the daemon, optionally inside a cgroup v2 leaf. The shell moves
    /// itself into the leaf and then replaces itself with the daemon, so the
    /// daemon keeps the pid the test signals and every page it charges lands
    /// in the leaf.
    fn start_in(config_path: &Path, cgroup_leaf: Option<&Path>) -> TestResult<Self> {
        Self::start_logged(config_path, cgroup_leaf, None)
    }

    /// Like `start_in`, appending the daemon's stderr to `stderr_log` when one
    /// is given, so a fail-closed exit keeps its reason with the campaign.
    fn start_logged(
        config_path: &Path,
        cgroup_leaf: Option<&Path>,
        stderr_log: Option<&Path>,
    ) -> TestResult<Self> {
        let daemon = env!("CARGO_BIN_EXE_agenc-ircd");
        let mut command = match cgroup_leaf {
            Some(leaf) => {
                let mut command = Command::new("/bin/sh");
                command
                    .arg("-c")
                    .arg("printf '%d\\n' \"$$\" > \"$1/cgroup.procs\" && exec \"$2\" serve --config \"$3\"")
                    .arg("agenc-campaign-node")
                    .arg(leaf)
                    .arg(daemon)
                    .arg(config_path);
                command
            }
            None => {
                let mut command = Command::new(daemon);
                command.arg("serve").arg("--config").arg(config_path);
                command
            }
        };
        let stderr = match stderr_log {
            Some(path) => Stdio::from(
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(path)?,
            ),
            None => Stdio::inherit(),
        };
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
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

    /// Waits for a daemon that was asked to stop through its admin socket.
    fn wait(&mut self) -> TestResult<ExitStatus> {
        self.wait_within(STOP_TIMEOUT)
    }

    /// Like `wait`, with a caller-chosen budget.
    fn wait_within(&mut self, budget: Duration) -> TestResult<ExitStatus> {
        let deadline = Instant::now() + budget;
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

    fn read_until(&mut self, complete: impl FnMut(&str) -> bool) -> TestResult<Vec<String>> {
        self.read_until_within(TRANSCRIPT_LINES, complete)
    }

    /// Reads until `complete` accepts a line, `limit` lines have arrived, or
    /// `REPLY_DEADLINE` passes; probes inside a busy channel pass a limit that
    /// covers the traffic interleaved before a reply, and the deadline keeps
    /// a never-matching predicate from reading traffic forever.
    fn read_until_within(
        &mut self,
        limit: usize,
        mut complete: impl FnMut(&str) -> bool,
    ) -> TestResult<Vec<String>> {
        let deadline = Instant::now() + REPLY_DEADLINE;
        let mut lines = Vec::new();
        for _ in 0..limit {
            if Instant::now() > deadline {
                return Err(failure(format!(
                    "reply did not arrive within {REPLY_DEADLINE:?}; first lines {:?}; last lines {:?}",
                    lines.iter().take(5).collect::<Vec<_>>(),
                    lines.iter().rev().take(3).collect::<Vec<_>>()
                )));
            }
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
        Err(failure(format!(
            "reply exceeded the {limit}-line transcript bound; first lines {:?}; last lines {:?}",
            lines.iter().take(5).collect::<Vec<_>>(),
            lines.iter().rev().take(3).collect::<Vec<_>>()
        )))
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
    build_network_with(None)
}

/// One coordinator and two edges, optionally configured for the campaign.
fn build_network_with(capacity: Option<CapacityPlan>) -> TestResult<Network> {
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
            capacity,
        })?,
        edge_a: NodeFixture::create(&NodePlan {
            identity: &edge_a,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&coordinator],
            capacity,
        })?,
        edge_b: NodeFixture::create(&NodePlan {
            identity: &edge_b,
            coordinator: &coordinator,
            federation_address: Some(federation_address),
            peers: &[&coordinator],
            capacity,
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

/// The start and finish request identities one account exchange consumes.
/// Stage 08 tests derive them from one byte; the Stage 10 campaign supplies
/// fresh identities so thousands of exchanges never replay a request.
fn account_requests(request_seed: u8) -> TestResult<[RequestId; 2]> {
    let finish_seed = request_seed
        .checked_add(1)
        .ok_or_else(|| failure("account request seed overflow"))?;
    Ok([
        RequestId::from_bytes([request_seed; 16]),
        RequestId::from_bytes([finish_seed; 16]),
    ])
}

fn seal_account_payload(
    fixture: &NodeFixture,
    network_id: NetworkId,
    request: RequestId,
    payload: AccountRequestPayload,
) -> TestResult<(
    [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
    AccountResponseOpenToken,
)> {
    let private_key = AccountHpkePrivateKey::from_bytes(ACCOUNT_HPKE_PRIVATE)?;
    let public_key = private_key.public_key()?;
    let binding = AccountRequestBinding::new(
        network_id,
        account_recovery_epoch(fixture, network_id)?,
        public_key.key_id(),
        request,
        payload.message_kind(),
    );
    let plaintext = encode_request_plaintext(&payload)?;
    let (sealed, token) = seal_account_request(public_key, binding, plaintext.expose_for_hpke())?;
    let envelope = AccountServiceEnvelope::from_sealed(sealed)?;
    Ok((*envelope.as_bytes(), token))
}

/// Uses the same validated epoch pin as the edge's coordinator trust record.
fn account_recovery_epoch(
    fixture: &NodeFixture,
    network_id: NetworkId,
) -> TestResult<RecoveryEpoch> {
    let config = agenc_ircd_config::load_config(
        &fixture.config_path,
        agenc_ircd_config::ValidationDepth::Document,
    )?;
    if config.network.network_id != network_id {
        return Err(failure("account request network differs from the fixture"));
    }
    config
        .federation
        .peers
        .iter()
        .find(|peer| {
            peer.enabled
                && peer.role == NodeRole::Coordinator
                && peer.server_id == config.network.coordinator_server_id
        })
        .map(|peer| peer.recovery_epoch)
        .ok_or_else(|| failure("fixture lacks an enabled coordinator epoch pin"))
}

#[test]
fn account_envelopes_follow_the_current_coordinator_epoch_pin() -> TestResult {
    let network = build_network()?;
    let old_epoch = COORDINATOR_RECOVERY_EPOCH;
    let new_epoch = RecoveryEpoch::from_bytes([215; 16]);
    let private_key = AccountHpkePrivateKey::from_bytes(ACCOUNT_HPKE_PRIVATE)?;
    let payload = || -> TestResult<AccountRequestPayload> {
        Ok(AccountRequestPayload::AuthenticationFinish(
            AuthenticationFinish {
                network_id: NETWORK_ID,
                transaction_id: agenc_ircd_types::TransactionId::from_bytes([217; 16]),
                ke3: OpaqueKe3::from_bytes([0; agenc_ircd_auth::OPAQUE_KE3_BYTES])?,
            },
        ))
    };
    let (old_bytes, _) = seal_account_payload(
        &network.edge_a,
        NETWORK_ID,
        RequestId::from_bytes([213; 16]),
        payload()?,
    )?;
    stage_ten_capacity::repin_peer_epoch(
        &network.edge_a,
        network.coordinator.server_id,
        &new_epoch.to_base64url(),
    )?;
    let (new_bytes, _) = seal_account_payload(
        &network.edge_a,
        NETWORK_ID,
        RequestId::from_bytes([214; 16]),
        payload()?,
    )?;
    let old_envelope = AccountServiceEnvelope::parse(old_bytes)?;
    let new_envelope = AccountServiceEnvelope::parse(new_bytes)?;
    let open = |epoch, envelope: &AccountServiceEnvelope| {
        agenc_ircd_auth::open_and_parse_request(
            &private_key,
            epoch,
            NETWORK_ID,
            envelope.message_kind(),
            envelope,
        )
    };
    assert!(open(old_epoch, &old_envelope).is_ok());
    assert!(open(new_epoch, &old_envelope).is_err());
    assert!(open(new_epoch, &new_envelope).is_ok());
    assert!(open(old_epoch, &new_envelope).is_err());
    Ok(())
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
    fixture: &NodeFixture,
    login_name: &str,
    request_seed: u8,
) -> TestResult<AccountId> {
    create_live_account_with(client, fixture, login_name, account_requests(request_seed)?)
}

fn create_live_account_with(
    client: &mut IrcClient,
    fixture: &NodeFixture,
    login_name: &str,
    requests: [RequestId; 2],
) -> TestResult<AccountId> {
    let [start_request, finish_request] = requests;
    let mut rng = TestOpaqueRng::new();
    let registration = ClientRegistration::<TestOpaqueSuite>::start(&mut rng, ACCOUNT_PASSWORD)?;
    let registration_request = OpaqueRegistrationRequest::from_bytes(
        registration.message.serialize().as_slice().try_into()?,
    )?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        start_request,
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

    let (finish_envelope, finish_token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        finish_request,
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
    fixture: &NodeFixture,
    login_name: &str,
    password: &[u8],
    request_seed: u8,
    expected_account: AccountId,
) -> TestResult {
    authenticate_live_account_with(
        client,
        fixture,
        login_name,
        password,
        account_requests(request_seed)?,
        expected_account,
    )
}

fn authenticate_live_account_with(
    client: &mut IrcClient,
    fixture: &NodeFixture,
    login_name: &str,
    password: &[u8],
    requests: [RequestId; 2],
    expected_account: AccountId,
) -> TestResult {
    let [start_request, finish_request] = requests;
    let mut rng = TestOpaqueRng::new();
    let login = ClientLogin::<TestOpaqueSuite>::start(&mut rng, password)?;
    let ke1 = OpaqueKe1::from_bytes(login.message.serialize().as_slice().try_into()?)?;
    let (start_envelope, start_token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        start_request,
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
    let (finish_envelope, finish_token) = seal_account_payload(
        fixture,
        NETWORK_ID,
        finish_request,
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

    /// A principal whose roster is valid around the wall-clock second `now`,
    /// for MLS libraries that check leaf lifetimes against their clock.
    fn new_valid_at(root: u8, device: u8, account_id: AccountId, now: u64) -> TestResult<Self> {
        let text = account_id.to_text();
        let account: [u8; 24] = text
            .as_bytes()
            .try_into()
            .map_err(|_| failure("account text is 24 bytes"))?;
        Ok(Self {
            keys: builders::principal_valid_at(root, &account, &[device], now)?,
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
    /// The generation-zero bootstrap policy and the generation-one
    /// operational policy the binding commits to (companion 9.3).
    policies: [IrcPolicy; 2],
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
/// The bootstrap and operational policies of a conversation whose creator
/// is the first principal.
fn policies_for(
    principals: &[&builders::Principal],
    conversation: [u8; 32],
    kind: IrcConversationKind,
) -> TestResult<[IrcPolicy; 2]> {
    let initial = builders::policy(&builders::PolicySpec::bootstrap(
        principals,
        conversation,
        kind,
    )?)?;
    let operational = builders::policy(&builders::PolicySpec::operational(
        principals,
        conversation,
        kind,
        builders::policy_id_of(&initial)?,
    )?)?;
    Ok([initial, operational])
}

/// Publishes the bound conversation's two policies (companion 9.3) and
/// checks that each `STORED POLICY` reply names the policy and its object.
fn publish_policies(
    client: &mut IrcClient,
    binder: &mut Principal,
    bound: &BoundConversation,
) -> TestResult {
    let conversation_token = base64url_encode(&bound.conversation);
    for policy in &bound.policies {
        let bytes = wire_object(IrcWireObjectKind::Policy, policy)?;
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT POLICY {conversation_token}"),
            &bytes,
        )?;
        let reply = labeled_reply(client, &label)?;
        assert_contains(
            &reply,
            &format!(" EGROUP STORED POLICY {conversation_token} "),
        )?;
        assert_eq!(
            hash_at(&reply, "STORED", 5)?,
            builders::policy_id_of(policy)?
        );
        assert_eq!(
            hash_at(&reply, "STORED", 6)?,
            *e2ee::ObjectId::compute(&bytes).as_bytes()
        );
    }
    Ok(())
}

fn bind(
    client: &mut IrcClient,
    binder: &mut Principal,
    reservation: &IrcReservation,
    package: IrcConversationBindingPackage,
    route_binding: [u8; 32],
    group_id: [u8; 32],
    policies: [IrcPolicy; 2],
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
    let bound = BoundConversation {
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
        policies,
    };
    publish_policies(client, binder, &bound)?;
    Ok(bound)
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
    let policies = policies_for(
        &principals,
        e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &DIRECT_GROUP)?,
        IrcConversationKind::Direct,
    )?;
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
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
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
        policies,
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
    let policies = policies_for(
        &principals,
        e2ee::ids::conversation_id(NETWORK_ID.as_bytes(), &GROUP)?,
        IrcConversationKind::Channel,
    )?;
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
        initial_policy_id: builders::policy_id_of(&policies[0])?,
        required_operational_policy_id: builders::policy_id_of(&policies[1])?,
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
    bind(
        client,
        binder,
        &reservation,
        package,
        route_binding,
        GROUP,
        policies,
    )
}

/// The context core identifier the test binding package carries.
const CONTEXT_CORE_ID: [u8; 32] = [30; 32];
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
    let initial_policy_id = builders::policy_id_of(&bound.policies[0])?;
    let operational_policy_id = builders::policy_id_of(&bound.policies[1])?;

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
            old_policy_id: initial_policy_id,
            authorization_rule: IrcCommitAuthorizationRule::BootstrapActivation,
            action_bits: action_bits::POLICY | action_bits::BOOTSTRAP,
            resulting_policy_id: operational_policy_id,
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            transition_target_digest: [0; 32],
        },
        &[(&binder.keys, binder.device)],
    )?;
    let mut core = IrcFinalizationCoreTbs {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        prior_epoch: 0,
        prior_state_id: accepted,
        candidate_id,
        commit_object_id,
        resulting_epoch: 1,
        old_policy_id: initial_policy_id,
        commit_authorization_id: semantic_id_of(
            SemanticHashDomain::CommitAuthorizationId,
            &authorization.tbs,
        )?,
        acknowledgement_set_digest: [3; 32],
        resulting_group_context_digest: [1; 32],
        resulting_ratchet_tree_digest: [2; 32],
        finalization_authenticator: [4; 32],
    };
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
    core.acknowledgement_set_digest = e2ee::ids::proof_set_digest(
        SemanticHashDomain::AcknowledgementSet,
        std::slice::from_ref(&ack.tbs),
    )?;
    let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
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
    // An identical retry returns the committed result under the new label.
    let retry_label = binder.label();
    send_object(
        client,
        &retry_label,
        &format!("EGROUP SUBMIT FINALIZATION {conversation_token}"),
        &request,
    )?;
    let replay = labeled_reply(client, &retry_label)?;
    assert_contains(
        &replay,
        &format!(" EGROUP FINALIZED {conversation_token} 1 "),
    )?;
    assert_eq!(hash_at(&replay, "FINALIZED", 5)?, finalization_id);
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
    let message = send_application_variant(sender, principal, bound, latest_state_id, epoch, 0)?;
    let retry_label = principal.label();
    send_object(sender, &retry_label, &bound.application_command(), &message)?;
    let echo = labeled_reply(sender, &retry_label)?;
    assert_contains(&echo, &bound.application_marker())?;
    assert_eq!(fragments_object(&echo)?, message);
    Ok(message)
}

/// Sends one application message whose ciphertext ends in `variant`, so a
/// load round submits a distinct object.
fn send_application_variant(
    sender: &mut IrcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    latest_state_id: [u8; 32],
    epoch: u64,
    variant: u8,
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
        .take(299)
        .copied()
        .chain(std::iter::once(variant))
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
    let close = close_authority::authorization(principal, bound, terminal)?;
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
/// exchanges one message each way; returns the conversation, the first
/// message, and the activation identifier later messages name.
fn direct_round(
    smaller: (&mut IrcClient, &mut Principal),
    larger: (&mut IrcClient, &mut Principal),
    previous: &BoundConversation,
) -> TestResult<(BoundConversation, Vec<u8>, [u8; 32])> {
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
    Ok((direct, note, terminal))
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
    let (direct, note, direct_terminal) = if alice_keys.account <= bob_keys.account {
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
        close_authority::close_after_public_transition(
            &mut alice,
            &mut alice_keys,
            &bob_keys,
            &bound,
            (1, finalization_id),
        ),
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

    // The restarted coordinator reloaded the direct route, the accounts'
    // roots and rosters, and the device attachments from its durable rows:
    // the direct conversation carries traffic again once the edges resync,
    // and the closed channel stays a tombstone.
    let resumed = step(
        "direct after restart",
        send_application_when_active(&mut bob, &mut bob_keys, &direct, direct_terminal),
    )?;
    assert_eq!(
        step(
            "direct receipt after restart",
            receive_application(&mut alice, &direct)
        )?,
        resumed
    );
    bob.send("PRIVMSG #room :after the restart")?;
    let refused = step(
        "tombstone after restart",
        bob.read_until(|line| line.contains("E2EE_REQUIRED")),
    )?;
    assert_contains(&refused, "FAIL PRIVMSG E2EE_REQUIRED")?;
    Ok(())
}

/// Sends one application message once the edge's encrypted profile is
/// active again after a coordinator restart; `E2EE_SYNCING` is retried.
fn send_application_when_active(
    sender: &mut IrcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    latest_state_id: [u8; 32],
) -> TestResult<Vec<u8>> {
    let deadline = Instant::now() + NETWORK_WAIT;
    let mut attempt: u8 = 0;
    loop {
        attempt = attempt.wrapping_add(1);
        match send_application_variant(sender, principal, bound, latest_state_id, 1, attempt) {
            Ok(message) => return Ok(message),
            Err(error) if error.to_string().contains("E2EE_SYNCING") => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(failure("the edge never left E2EE_SYNCING".to_owned()));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Companion Section 21 gate 3: two independent MLS libraries drive the
// encrypted lifecycle through the daemon's client surface.

mod real_clients {
    //! openmls creates the channel group and commits through the coordinator;
    //! mls-rs publishes a KeyPackage, is added through a claimed package and
    //! a delivered Welcome, and both exchange Section 7.5 padded application
    //! content that the other library decrypts and checks.

    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use agenc_ircd_testkit::client_policy::{
        ClientTrust, DisplayError, TrustState, render_decrypted_text,
    };
    use agenc_ircd_testkit::e2ee::ids::{account_id_digest, leaf_capabilities_digest};
    use agenc_ircd_testkit::e2ee::mls_outer::{MlsOuterMessage, parse_mls_message};
    use agenc_ircd_testkit::e2ee::objects::content::{
        IrcEncryptedContent, IrcEncryptedContentType,
    };
    use agenc_ircd_testkit::e2ee::objects::conversation::IrcJoinTransitionProofBundle;
    use agenc_ircd_testkit::e2ee::objects::sequencing::{
        IrcDeliveredWelcome, IrcNormalJoinAuthorizationProof,
    };
    use mls_rs::client_builder::MlsConfig;
    use mls_rs::group::ReceivedMessage;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential as RsBasicCredential, BasicIdentityProvider};
    use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
    use mls_rs::time::MlsTime;
    use mls_rs::{CipherSuite as RsSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;
    use openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
    use openmls::key_packages::Lifetime as OpenMlsLifetime;
    use openmls::prelude::tls_codec::Deserialize as _;
    use openmls::prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, GroupId,
        KeyPackage as OpenMlsKeyPackage, LeafNodeParameters, MlsGroup, MlsMessageBodyIn,
        MlsMessageIn, OpenMlsProvider, ProcessedMessageContent, ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::*;

    /// The wire suite both libraries use here.
    const SUITE: u16 = 1;
    /// How long each leaf lives past `now`.
    const LEAF_LIFETIME: u64 = 24 * 3_600;
    /// The interop matrix rules this test records.
    const RULES: [&str; 8] = [
        "lifecycle-openmls-commit-sequenced",
        "lifecycle-openmls-finalized-under-published-quorum",
        "lifecycle-mls-rs-package-published-and-claimed",
        "lifecycle-openmls-add-finalized-by-two-councils",
        "lifecycle-welcome-delivered-and-joined-by-mls-rs",
        "lifecycle-padded-content-openmls-to-mls-rs",
        "lifecycle-padded-content-mls-rs-to-openmls",
        "lifecycle-closed-after-real-traffic",
    ];

    fn wall_clock_seconds() -> TestResult<u64> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// The leaf capabilities both libraries are configured to advertise,
    /// hashed as the leaf authorization commits to them.
    fn capabilities_hash() -> TestResult<[u8; 32]> {
        Ok(leaf_capabilities_digest(&builders::encoded_capabilities(
            &builders::default_capabilities(),
        )?)?)
    }

    fn leaf_spec(device: u8, interval: (u64, u64)) -> TestResult<builders::LeafSpec> {
        Ok(builders::LeafSpec {
            device_seed: device,
            leaf_seed: 0,
            suite: SUITE,
            interval,
            capabilities_hash: capabilities_hash()?,
            last_resort: 0,
            credential_generation: 0,
        })
    }

    /// The basic-credential identity of a leaf: the encoded credential bundle
    /// whose leaf authorization names `leaf_public_key`.
    fn credential_identity(
        principal: &Principal,
        interval: (u64, u64),
        leaf_public_key: &[u8],
    ) -> TestResult<Vec<u8>> {
        let authorization = builders::leaf_authorization_for_key(
            &principal.keys.roster,
            &leaf_spec(principal.device, interval)?,
            leaf_public_key,
        )?;
        Ok(
            builders::credential_bundle(&principal.keys, principal.device, authorization)?
                .encode()?,
        )
    }

    fn commit_aad(
        bound: &BoundConversation,
        prior_state_id: [u8; 32],
        time: u64,
    ) -> TestResult<Vec<u8>> {
        Ok(IrcCommitAad {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            validation_time: time,
            prior_state_id,
        }
        .encode()?)
    }

    fn application_aad(
        bound: &BoundConversation,
        latest_state_id: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        Ok(IrcApplicationAad {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            latest_state_id,
        }
        .encode()?)
    }

    /// Padded application content from `sender` (Sections 7.5 and 10).
    fn padded_content(
        bound: &BoundConversation,
        sender: &Principal,
        sequence: u64,
        head: [u8; 32],
        text: &str,
    ) -> TestResult<Vec<u8>> {
        padded_content_bound(bound, bound.route_binding, sender, sequence, head, text)
    }

    /// Like `padded_content`, but under a caller-chosen route binding so a
    /// receiver can observe a binding it never accepted.
    fn padded_content_bound(
        bound: &BoundConversation,
        route_binding: [u8; 32],
        sender: &Principal,
        sequence: u64,
        head: [u8; 32],
        text: &str,
    ) -> TestResult<Vec<u8>> {
        let mut content = IrcEncryptedContent {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding,
            sender_device_id: [sender.device; 16],
            leaf_credential_generation: 0,
            sender_sequence: sequence,
            message_id: [u8::try_from(sequence)? ^ sender.device; 16],
            sequencer_record_chain_head: head,
            content_type: IrcEncryptedContentType::Text,
            body: Opaque::new(text.as_bytes().to_vec())?,
            zero_padding: Opaque::new(Vec::new())?,
        };
        content.pad()?;
        Ok(content.encode()?)
    }

    /// Decodes received content, checking its padding and shape, and returns
    /// the text.
    fn content_text(bytes: &[u8]) -> TestResult<String> {
        let mut budget = DecodeBudget::new(1 << 16, 64);
        let content = IrcEncryptedContent::decode_checked(bytes, &mut budget)?;
        assert_eq!(content.content_type, IrcEncryptedContentType::Text);
        Ok(String::from_utf8(content.body.as_slice().to_vec())?)
    }

    /// The MLS bytes inside a forwarded application object.
    fn mls_body(object: &[u8], kind: IrcWireObjectKind) -> TestResult<Vec<u8>> {
        let mut budget = DecodeBudget::new(1 << 20, 1 << 10);
        Ok(IrcWireObject::decode_kind(object, Some(kind), &mut budget)?
            .body()
            .to_vec())
    }

    /// What a certified Commit leaves behind.
    pub(super) struct Certified {
        pub(super) finalization_id: [u8; 32],
        record_id: [u8; 32],
    }

    /// Sequences `commit` as the candidate of `bound`, acknowledges it, and
    /// finalizes it with the votes of the binder and `co_voters` under
    /// `old_policy_id` (companion 12.1 to 12.4).
    // agenc-review: allow owner=tests reviewed=2026-09-04 reason=one certification names the client the binder its co-voters the conversation the commit the prior position both policies and the rule together
    #[allow(clippy::too_many_arguments)]
    pub(super) fn certify_commit(
        client: &mut IrcClient,
        binder: &mut Principal,
        co_voters: &[&Principal],
        bound: &BoundConversation,
        commit: &[u8],
        prior: (u64, [u8; 32]),
        policies: ([u8; 32], [u8; 32]),
        transition: close_authority::CertificationTransition,
    ) -> TestResult<Certified> {
        let network = *NETWORK_ID.as_bytes();
        let conversation = bound.conversation;
        let (prior_epoch, prior_state_id) = prior;
        let (old_policy_id, resulting_policy_id) = policies;
        let (rule, actions, target) = transition.fields();
        let canonical_validation_time =
            close_authority::candidate_validation_time(bound, &prior_state_id, commit)?;
        let commit = raw_object(IrcWireObjectKind::CommitMls, commit.to_vec())?;
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
        let receipt_tag = echo
            .iter()
            .find_map(|line| tag_value(line, RECEIPT_TAG))
            .ok_or_else(|| failure("the candidate echo carries the receipt tag"))?;
        let receipt_tag = ReceiptTag::parse(&receipt_tag)?;
        let candidate_id = receipt_tag.candidate_id;
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let receipt = IrcCandidateReceipt::decode_exact(&receipt_tag.receipt, &mut budget)?;
        assert_eq!(receipt.tbs.commit_object_id, commit_object_id);
        assert_eq!(receipt.tbs.prior_state_id, prior_state_id);
        let resulting_epoch = prior_epoch + 1;

        let authorization = builders::commit_authorization(
            IrcCommitAuthorizationTbs {
                profile_version: 1,
                network_id: network,
                conversation_id: conversation,
                prior_epoch,
                prior_state_id,
                candidate_id,
                commit_object_id,
                canonical_validation_time,
                old_policy_id,
                authorization_rule: rule,
                action_bits: actions,
                resulting_policy_id,
                resulting_group_context_digest: [1; 32],
                resulting_ratchet_tree_digest: [2; 32],
                transition_target_digest: target,
            },
            &[(&binder.keys, binder.device)],
        )?;
        let mut core = IrcFinalizationCoreTbs {
            profile_version: 1,
            network_id: network,
            conversation_id: conversation,
            prior_epoch,
            prior_state_id,
            candidate_id,
            commit_object_id,
            resulting_epoch,
            old_policy_id,
            commit_authorization_id: semantic_id_of(
                SemanticHashDomain::CommitAuthorizationId,
                &authorization.tbs,
            )?,
            acknowledgement_set_digest: [3; 32],
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            finalization_authenticator: [4; 32],
        };
        let ack = IrcCommitAck {
            tbs: IrcCommitAckTbs {
                profile_version: 1,
                network_id: network,
                conversation_id: conversation,
                prior_epoch,
                candidate_id,
                commit_object_id,
                old_leaf_index: 0,
                old_credential_hash: [5; 32],
                resulting_epoch,
                resulting_group_context_digest: [1; 32],
                resulting_ratchet_tree_digest: [2; 32],
                finalization_authenticator: [4; 32],
            },
            old_leaf_signature: Opaque::new(vec![6; 64])?,
        };
        core.acknowledgement_set_digest = e2ee::ids::proof_set_digest(
            SemanticHashDomain::AcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?;
        let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
        let ack_object = wire_object(IrcWireObjectKind::CommitAck, &ack)?;
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT ACK {conversation_token}"),
            &ack_object,
        )?;
        let acked = labeled_reply(client, &label)?;
        assert_contains(&acked, " EGROUP ACKED ")?;

        let slot = VoteSlot {
            network_id: network,
            conversation_id: conversation,
            prior_epoch,
            prior_state_id,
            candidate_sequence: receipt.tbs.candidate_sequence,
            predecessor_record_id: receipt.tbs.predecessor_record_id,
        };
        let tbs = vote_tbs(&slot, candidate_id, Terminal::finalize(finalization_id));
        let mut votes = vec![builders::finality_vote(&binder.keys, binder.device, &tbs)?];
        for voter in co_voters {
            votes.push(builders::finality_vote(&voter.keys, voter.device, &tbs)?);
        }
        votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
        let request = IrcFinalizationRequest {
            proof: IrcFinalizationProof {
                core,
                receipt,
                authorization,
                acknowledgements: TlsVec::new(vec![ack])?,
            },
            votes: TlsVec::new(votes)?,
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
            &format!(" EGROUP FINALIZED {conversation_token} {resulting_epoch} "),
        )?;
        assert_eq!(hash_at(&reply, "FINALIZED", 5)?, finalization_id);
        Ok(Certified {
            finalization_id,
            record_id: hash_at(&reply, "FINALIZED", 6)?,
        })
    }

    /// The openmls member: alice, the channel creator.
    struct OpenMlsMember {
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        credential: CredentialWithKey,
        capabilities: Capabilities,
        lifetime: OpenMlsLifetime,
    }

    impl OpenMlsMember {
        fn new(principal: &Principal, interval: (u64, u64)) -> TestResult<Self> {
            let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let provider = OpenMlsRustCrypto::default();
            let signer = SignatureKeyPair::new(suite.signature_algorithm())?;
            signer.store(provider.storage())?;
            let identity = credential_identity(principal, interval, signer.public())?;
            let credential = CredentialWithKey {
                credential: BasicCredential::new(identity).into(),
                signature_key: signer.to_public_vec().into(),
            };
            let capabilities = Capabilities::new(
                Some(&[ProtocolVersion::Mls10]),
                Some(&[
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ]),
                Some(&[]),
                Some(&[]),
                Some(&[CredentialType::Basic]),
            );
            Ok(Self {
                provider,
                signer,
                credential,
                capabilities,
                lifetime: OpenMlsLifetime::init(interval.0, interval.1),
            })
        }

        fn create_group(&self, group_id: &[u8; 32]) -> TestResult<MlsGroup> {
            Ok(MlsGroup::builder()
                .with_group_id(GroupId::from_slice(group_id))
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .use_ratchet_tree_extension(true)
                .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .with_capabilities(self.capabilities.clone())
                .lifetime(self.lifetime)
                .build(&self.provider, &self.signer, self.credential.clone())?)
        }

        fn import_key_package(&self, bytes: &[u8]) -> TestResult<OpenMlsKeyPackage> {
            let message = MlsMessageIn::tls_deserialize_exact(bytes)?;
            let MlsMessageBodyIn::KeyPackage(package) = message.extract() else {
                return Err(failure("the claimed object is not a key package"));
            };
            Ok(package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?)
        }

        fn decrypt(&self, group: &mut MlsGroup, bytes: &[u8]) -> TestResult<(Vec<u8>, Vec<u8>)> {
            let message = MlsMessageIn::tls_deserialize_exact(bytes)?;
            let processed =
                group.process_message(&self.provider, message.try_into_protocol_message()?)?;
            let aad = processed.aad().to_vec();
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(application) => {
                    Ok((application.into_bytes(), aad))
                }
                _ => Err(failure("openmls did not receive an application message")),
            }
        }
    }

    /// The mls-rs member: bob, added through a Welcome.
    fn mls_rs_client(
        principal: &Principal,
        interval: (u64, u64),
    ) -> TestResult<Client<impl MlsConfig + use<>>> {
        let crypto = RustCryptoProvider::with_enabled_cipher_suites(vec![
            RsSuite::CURVE25519_AES128,
            RsSuite::CURVE25519_CHACHA,
        ]);
        let cipher_suite = crypto
            .cipher_suite_provider(RsSuite::CURVE25519_AES128)
            .ok_or_else(|| failure("mls-rs lacks the profile suite"))?;
        let (secret, public) = cipher_suite.signature_key_generate()?;
        let identity_bytes = credential_identity(principal, interval, public.as_ref())?;
        let identity = SigningIdentity::new(
            RsBasicCredential::new(identity_bytes).into_credential(),
            public,
        );
        let rules = DefaultMlsRules::new()
            .with_commit_options(CommitOptions::new().with_ratchet_tree_extension(true))
            .with_encryption_options(EncryptionOptions::new(true, Default::default()));
        Ok(Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto)
            .mls_rules(rules)
            .key_package_lifetime(Duration::from_secs(LEAF_LIFETIME))
            .signing_identity(identity, secret, RsSuite::CURVE25519_AES128)
            .build())
    }

    /// Publishes `package` for `owner` and returns the daemon's KeyPackageRef.
    fn publish_package(
        client: &mut IrcClient,
        owner: &mut Principal,
        package: &[u8],
        expires_at: u64,
    ) -> TestResult<Vec<u8>> {
        let object = raw_object(IrcWireObjectKind::KeyPackageMls, package.to_vec())?;
        let label = owner.label();
        send_object(
            client,
            &label,
            &format!(
                "EKEY PUBLISH PACKAGE {} {SUITE} NORMAL {expires_at}",
                owner.device_token()
            ),
            &object,
        )?;
        let reply = labeled_reply(client, &label)?;
        assert_contains(&reply, " EKEY STORED PACKAGE ")?;
        assert_eq!(
            hash_at(&reply, "PACKAGE", 4)?,
            *e2ee::ObjectId::compute(&object).as_bytes()
        );
        let mut budget = DecodeBudget::new(1 << 16, 1 << 14);
        let MlsOuterMessage::KeyPackage(parsed) = parse_mls_message(package, &mut budget)? else {
            return Err(failure("the published object is not a key package"));
        };
        Ok(parsed.key_package_ref.to_vec())
    }

    /// Claims one package of `target` for `claimant` and returns its MLS bytes.
    fn claim_package(
        client: &mut IrcClient,
        claimant: &mut Principal,
        target: &Principal,
    ) -> TestResult<Vec<u8>> {
        let label = claimant.label();
        client.send(&format!(
            "@label={label} EKEY CLAIM PACKAGE {} {} {SUITE} {}",
            base64url_encode(&target.account),
            target.device_token(),
            base64url_encode(&[77; 16])
        ))?;
        let reply = labeled_reply(client, &label)?;
        assert_contains(&reply, " EKEY CLAIMED ")?;
        mls_body(&batch_object(&reply)?, IrcWireObjectKind::KeyPackageMls)
    }

    /// Delivers `welcome` to `target` under the finalization that added it,
    /// fetches it from the target's mailbox, and returns the Welcome bytes.
    // agenc-review: allow owner=tests reviewed=2026-09-04 reason=one delivery names both clients both principals the conversation the certification the package reference and the welcome together
    #[allow(clippy::too_many_arguments)]
    fn deliver_welcome(
        sender: &mut IrcClient,
        sender_keys: &mut Principal,
        receiver: &mut IrcClient,
        target: &mut Principal,
        bound: &BoundConversation,
        certified: &Certified,
        key_package_ref: &[u8],
        welcome: &[u8],
    ) -> TestResult<Vec<u8>> {
        let delivered = IrcDeliveredWelcome {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            target_account_id_digest: account_id_digest(NETWORK_ID.as_bytes(), &target.account)?,
            target_device_id: [target.device; 16],
            authorization: IrcNormalJoinAuthorizationProof {
                finalization_id: certified.finalization_id,
                finalization_object_id: certified.record_id,
                added_key_package_ref: Opaque::new(key_package_ref.to_vec())?,
                resulting_leaf_index: 1,
                resulting_leaf_credential_hash: [0; 32],
            },
            transition_proofs: IrcJoinTransitionProofBundle {
                references: TlsVec::new(Vec::new())?,
            },
            welcome_bytes: Opaque::new(welcome.to_vec())?,
        };
        let object = wire_object(IrcWireObjectKind::WelcomeMls, &delivered)?;
        let label = sender_keys.label();
        send_object(
            sender,
            &label,
            &format!(
                "EKEY DELIVER WELCOME {} {} {} {}",
                base64url_encode(&target.account),
                target.device_token(),
                base64url_encode(&bound.conversation),
                base64url_encode(&certified.finalization_id)
            ),
            &object,
        )?;
        let reply = labeled_reply(sender, &label)?;
        assert_contains(&reply, " EKEY STORED WELCOME ")?;
        let object_id = *e2ee::ObjectId::compute(&object).as_bytes();

        let label = target.label();
        receiver.send(&format!("@label={label} EKEY FETCH MAILBOX WELCOME *"))?;
        let page = labeled_reply(receiver, &label)?;
        assert_contains(&page, " EKEY MAILBOX ")?;
        let token = hash_at(&page, "MAILBOX", 3)?;
        assert_eq!(fragments_object(&page)?, object);
        let label = target.label();
        receiver.send(&format!(
            "@label={label} EKEY ACK MAILBOX {} {}",
            base64url_encode(&token),
            base64url_encode(&object_id)
        ))?;
        let acked = labeled_reply(receiver, &label)?;
        assert_contains(&acked, " EKEY ACKED ")?;
        Ok(welcome.to_vec())
    }

    /// Sends real MLS application bytes on the bound channel and returns the
    /// forwarded copy the other edge delivers.
    fn relay_application(
        sender: &mut IrcClient,
        sender_keys: &mut Principal,
        receiver: &mut IrcClient,
        bound: &BoundConversation,
        mls_bytes: &[u8],
    ) -> TestResult<Vec<u8>> {
        let object = raw_object(IrcWireObjectKind::ApplicationMls, mls_bytes.to_vec())?;
        let label = sender_keys.label();
        send_object(sender, &label, &bound.application_command(), &object)?;
        let echo = labeled_reply(sender, &label)?;
        assert_eq!(fragments_object(&echo)?, object);
        let forwarded = receive_application(receiver, bound)?;
        assert_eq!(forwarded, object);
        mls_body(&forwarded, IrcWireObjectKind::ApplicationMls)
    }

    /// The recorded lifecycle outcomes of the interop matrix.
    fn recorded_lifecycle() -> TestResult<BTreeMap<String, String>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("conformance/e2ee-interop-matrix.toml"))?;
        let mut matrix = BTreeMap::new();
        let mut id: Option<String> = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"').to_owned();
            match key.trim() {
                "id" if value.starts_with("lifecycle-") => id = Some(value),
                "outcome" => {
                    if let Some(id) = id.take() {
                        matrix.insert(id, value);
                    }
                }
                _ => {}
            }
        }
        Ok(matrix)
    }

    #[test]
    fn real_mls_clients_run_the_encrypted_lifecycle_through_the_daemon() -> TestResult {
        let network = build_network()?;
        let mut coordinator = DaemonProcess::start(&network.coordinator.config_path)?;
        let mut edge_a = DaemonProcess::start(&network.edge_a.config_path)?;
        let mut edge_b = DaemonProcess::start(&network.edge_b.config_path)?;
        let outcome = exercise_real_clients(&network);
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

    fn exercise_real_clients(network: &Network) -> TestResult {
        wait_for_link(&network.edge_a, 0)?;
        wait_for_link(&network.edge_b, 0)?;
        let _probe = register_when_available(&network.edge_a, "probe")?;
        let now = wall_clock_seconds()?;
        let (mut alice, alice_account) =
            authenticated_client(&network.edge_a, "alice", "alice-account", 41)?;
        let (mut bob, bob_account) =
            authenticated_client(&network.edge_b, "bob", "bob-account", 51)?;
        let mut alice_keys = Principal::new_valid_at(ALICE_ROOT, ALICE_DEVICE, alice_account, now)?;
        let mut bob_keys = Principal::new_valid_at(BOB_ROOT, BOB_DEVICE, bob_account, now)?;
        step(
            "alice attach",
            publish_and_attach(&mut alice, &mut alice_keys),
        )?;
        step("bob attach", publish_and_attach(&mut bob, &mut bob_keys))?;

        // Both leaves live from one hour ago until tomorrow, inside the
        // rosters that were issued around `now`.
        let alice_interval = (now - 3_599, now + LEAF_LIFETIME);
        // mls-rs opens a leaf at the timestamp it is given, with no margin.
        let bob_timestamp = now - 60;
        let bob_interval = (bob_timestamp, bob_timestamp + LEAF_LIFETIME);
        let creator = OpenMlsMember::new(&alice_keys, alice_interval)?;
        let joiner = mls_rs_client(&bob_keys, bob_interval)?;
        let bob_package = joiner
            .generate_key_package_message(
                Default::default(),
                Default::default(),
                Some(MlsTime::from(bob_timestamp)),
            )?
            .to_bytes()?;

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
        let initial_policy_id = builders::policy_id_of(&bound.policies[0])?;
        let operational_policy_id = builders::policy_id_of(&bound.policies[1])?;
        let genesis = semantic_id_of(
            SemanticHashDomain::GroupGenesisId,
            &IrcGroupGenesisTbs {
                network_id: *NETWORK_ID.as_bytes(),
                conversation_id: bound.conversation,
                group_id: Opaque::new(bound.group_id.to_vec())?,
                binding_id: bound.binding_id,
                context_core_id: CONTEXT_CORE_ID,
            },
        )?;

        // openmls creates the group and its first Commit activates the
        // bootstrap under the creator-only policy.
        let mut group = creator.create_group(&bound.group_id)?;
        group.set_aad(commit_aad(&bound, genesis, VALIDATION_TIME)?);
        let activation = group.self_update(
            &creator.provider,
            &creator.signer,
            LeafNodeParameters::default(),
        )?;
        let activated = step(
            "openmls activation commit",
            certify_commit(
                &mut alice,
                &mut alice_keys,
                &[],
                &bound,
                &activation.commit().to_bytes()?,
                (0, genesis),
                (initial_policy_id, operational_policy_id),
                close_authority::CertificationTransition::Bootstrap,
            ),
        )?;
        group.merge_pending_commit(&creator.provider)?;
        assert_eq!(group.epoch().as_u64(), 1);
        bob.read_until(|line| line.contains(" EGROUP FINALIZED "))?;

        // A padded application message from the real group reaches the
        // other edge as ciphertext.
        let first = padded_content(
            &bound,
            &alice_keys,
            0,
            activated.finalization_id,
            "before the add",
        )?;
        group.set_aad(application_aad(&bound, activated.finalization_id)?);
        let encrypted = group
            .create_message(&creator.provider, &creator.signer, &first)?
            .to_bytes()?;
        step(
            "openmls application relay",
            relay_application(&mut alice, &mut alice_keys, &mut bob, &bound, &encrypted),
        )?;

        // bob publishes his real package once his origin is settled; alice
        // claims it and adds him, and the operational council of both
        // devices finalizes the Add.
        let bob_reference = step(
            "bob publishes a real key package",
            publish_package(&mut bob, &mut bob_keys, &bob_package, bob_interval.1),
        )?;
        let claimed = step(
            "alice claims bob's package",
            claim_package(&mut alice, &mut alice_keys, &bob_keys),
        )?;
        assert_eq!(claimed, bob_package);
        let package = creator.import_key_package(&claimed)?;
        group.set_aad(commit_aad(
            &bound,
            activated.finalization_id,
            VALIDATION_TIME + 1,
        )?);
        let (commit, welcome, _info) =
            group.add_members(&creator.provider, &creator.signer, &[package])?;
        let added = step(
            "openmls add commit",
            certify_commit(
                &mut alice,
                &mut alice_keys,
                &[&bob_keys],
                &bound,
                &commit.to_bytes()?,
                (1, activated.finalization_id),
                (operational_policy_id, operational_policy_id),
                close_authority::CertificationTransition::Add,
            ),
        )?;
        group.merge_pending_commit(&creator.provider)?;
        assert_eq!(group.epoch().as_u64(), 2);
        bob.read_until(|line| line.contains(" EGROUP FINALIZED "))?;

        // The Welcome travels through the device mailbox and mls-rs joins.
        let welcome_bytes = step(
            "welcome delivery",
            deliver_welcome(
                &mut alice,
                &mut alice_keys,
                &mut bob,
                &mut bob_keys,
                &bound,
                &added,
                &bob_reference,
                &welcome.to_bytes()?,
            ),
        )?;
        let (mut bob_group, _info) =
            joiner.join_group(None, &MlsMessage::from_bytes(&welcome_bytes)?, None)?;
        assert_eq!(bob_group.current_epoch(), 2);

        // Padded content crosses the libraries in both directions.
        let text = "hello from openmls";
        let content = padded_content(&bound, &alice_keys, 1, added.finalization_id, text)?;
        let aad = application_aad(&bound, added.finalization_id)?;
        group.set_aad(aad.clone());
        let encrypted = group
            .create_message(&creator.provider, &creator.signer, &content)?
            .to_bytes()?;
        let received = step(
            "openmls to mls-rs relay",
            relay_application(&mut alice, &mut alice_keys, &mut bob, &bound, &encrypted),
        )?;
        let ReceivedMessage::ApplicationMessage(description) =
            bob_group.process_incoming_message(MlsMessage::from_bytes(&received)?)?
        else {
            return Err(failure("mls-rs did not receive an application message"));
        };
        assert_eq!(description.authenticated_data, aad);
        assert_eq!(content_text(description.data())?, text);

        let reply_text = "hello from mls-rs";
        let reply = padded_content(&bound, &bob_keys, 0, added.finalization_id, reply_text)?;
        let encrypted = bob_group
            .encrypt_application_message(&reply, aad.clone())?
            .to_bytes()?;
        let received = step(
            "mls-rs to openmls relay",
            relay_application(&mut bob, &mut bob_keys, &mut alice, &bound, &encrypted),
        )?;
        let (decrypted, received_aad) = creator.decrypt(&mut group, &received)?;
        assert_eq!(received_aad, aad);
        assert_eq!(content_text(&decrypted)?, reply_text);

        // Decrypted text is data: CTCP markers, terminal controls, HTML, bidi
        // controls, and a leading command prefix render inert through the
        // test client's display policy after a real cross-library decrypt.
        let mut trust = ClientTrust::first_contact();
        assert_eq!(trust.state(), TrustState::UnverifiedEncrypted);
        trust.observe_transparency();
        assert_eq!(trust.state(), TrustState::TransparencyObserved);
        let hostile =
            "/quit \u{1}ACTION dance\u{1} <script>alert(1)</script> \u{1b}[31mred \u{202e}rtl";
        let reply = padded_content(&bound, &bob_keys, 1, added.finalization_id, hostile)?;
        let encrypted = bob_group
            .encrypt_application_message(&reply, aad.clone())?
            .to_bytes()?;
        let received = step(
            "hostile text relay",
            relay_application(&mut bob, &mut bob_keys, &mut alice, &bound, &encrypted),
        )?;
        let (decrypted, _) = creator.decrypt(&mut group, &received)?;
        let rendered = render_decrypted_text(content_text(&decrypted)?.as_bytes())?;
        assert!(
            !rendered
                .as_str()
                .contains(['\u{1}', '\u{1b}', '<', '>', '\u{202e}'])
        );
        assert!(rendered.as_str().starts_with(
            "/quit \\u{0001}ACTION dance\\u{0001} &lt;script&gt;alert(1)&lt;/script&gt; \\u{001b}[31mred \\u{202e}rtl"
        ));

        // A decrypted message under a route binding this client never accepted
        // is an unexpected security change: sending stays blocked until the new
        // bindings are authenticated out of band and the change is reviewed.
        let foreign = padded_content_bound(
            &bound,
            [0xff; 32],
            &bob_keys,
            2,
            added.finalization_id,
            "binding changed",
        )?;
        let encrypted = bob_group
            .encrypt_application_message(&foreign, aad.clone())?
            .to_bytes()?;
        let received = step(
            "foreign binding relay",
            relay_application(&mut bob, &mut bob_keys, &mut alice, &bound, &encrypted),
        )?;
        let (decrypted, _) = creator.decrypt(&mut group, &received)?;
        let mut budget = DecodeBudget::new(1 << 16, 64);
        let observed = IrcEncryptedContent::decode_checked(&decrypted, &mut budget)?;
        assert_ne!(observed.route_binding, bound.route_binding);
        trust.unexpected_security_change();
        assert_eq!(trust.state(), TrustState::SecurityChanged);
        assert!(!trust.state().permits_sending());
        assert_eq!(
            trust.accept_reviewed_change(),
            Err(DisplayError::ReviewRequired)
        );
        trust.authenticate_out_of_band();
        assert_eq!(trust.state(), TrustState::SecurityChanged);
        trust.accept_reviewed_change()?;
        assert_eq!(trust.state(), TrustState::VerifiedEncrypted);
        assert!(trust.state().permits_sending());

        // The server's public close checks use a separate synthetic closing
        // candidate. The MLS exchange above does not validate that lifecycle.
        step(
            "close after real traffic",
            close_authority::close_after_public_transition(
                &mut alice,
                &mut alice_keys,
                &bob_keys,
                &bound,
                (2, added.finalization_id),
            ),
        )?;

        let recorded = recorded_lifecycle()?;
        for rule in RULES {
            assert_eq!(
                recorded.get(rule).map(String::as_str),
                Some("agree"),
                "rule {rule} is recorded as agree in the interop matrix"
            );
        }
        assert_eq!(recorded.len(), RULES.len());
        Ok(())
    }
}
