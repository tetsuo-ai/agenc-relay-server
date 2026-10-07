//! End-to-end Stage 07 federation: one coordinator and two edge daemons of
//! the production binary over real mutual TLS, with clients registered on
//! the edges, cross-edge channel traffic, a coordinator restart, and the
//! fail-closed partition behaviour of an edge.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use agenc_relay_auth::profile::{
    AgencOpaqueSuite, FallibleOpaqueRng, FixedArgon2id, opaque_context, opaque_identifiers,
};
use agenc_relay_auth::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountRequestPayload,
    AccountServiceEnvelope, AccountServiceResponse, AccountServiceResponsePayload,
    AuthenticationFinish, AuthenticationStart, Completion, CreationFinish, CreationStart,
    OpaqueKe1, OpaqueKe3, OpaqueProfile, OpaqueRegistrationRequest, encode_request_plaintext,
    finish_registration, open_and_parse_response,
};
use agenc_relay_config::{
    DEFAULT_REDB_CACHE_BYTES, DisplayLabel, DnsName, InitProfile, InitValues, NodeRole,
    OperatorTemplate, encode_base64url_32, render_template,
};
use agenc_relay_crypto::{
    AccountHpkePrivateKey, Ed25519SecretKey, LoginIndexKey, RollbackGuardRootKey, StorageDigest,
    StorageMasterKey, audit_signing_key_id, backup_signing_key_id,
};
use agenc_relay_crypto::{
    AccountRequestBinding, AccountResponseOpenToken, OsEntropy, seal_account_request,
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
use agenc_relay_testkit::crypto::{SemanticHashDomain, SignatureDomain};
use agenc_relay_testkit::e2ee;
use agenc_relay_testkit::e2ee::finality::{Terminal, VoteSlot, vote_tbs};
use agenc_relay_testkit::e2ee::ids::semantic_id_of;
use agenc_relay_testkit::e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_testkit::e2ee::objects::aad::{ArcApplicationAad, ArcCommitAad};
use agenc_relay_testkit::e2ee::objects::attach::{ArcDeviceAttach, ArcDeviceAttachChallenge};
use agenc_relay_testkit::e2ee::objects::conversation::{
    ArcCloseAuthorization, ArcCloseAuthorizationTbs, ArcCloseIntent, ArcCommitAuthorization,
    ArcCommitAuthorizationRule, ArcCommitAuthorizationTbs, ArcConversationBindingPackage,
    ArcConversationKind, ArcPolicy, ArcReservation, ArcSemanticRouteTbs, action_bits,
};
use agenc_relay_testkit::e2ee::objects::membership::{
    ArcLeafDispositionKind, ArcLeafMembershipProof, ArcLeafMembershipProofTbs,
};
use agenc_relay_testkit::e2ee::objects::sequencing::{
    ArcCandidateReceipt, ArcCommitAck, ArcCommitAckTbs, ArcFinalizationCoreTbs,
    ArcFinalizationProof, ArcFinalizationRequest, ArcGroupGenesisTbs,
};
use agenc_relay_testkit::e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_relay_testkit::e2ee::wire::fragment::{
    CLIENT_FRAGMENT_TAG, FragmentTag, RECEIPT_TAG, ReceiptTag, SERVER_FRAGMENT_TAG, fragment_object,
};
use agenc_relay_testkit::e2ee::wire::tokens::{base64url_decode, base64url_encode};
use agenc_relay_testkit::e2ee_client as builders;
use agenc_relay_types::{
    AccountId, AccountServiceCompletionStatus, DatabaseId, NetworkId, NormalizedLogin,
    OpaqueCredentialId, OperatorId, RecoveryEpoch, RequestId, ServerId, ServerIncarnation,
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
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

#[path = "stage_eight_e2ee/claim_restart.rs"]
mod claim_restart;
#[path = "stage_eight_e2ee/cli_provisioning.rs"]
mod cli_provisioning;
#[path = "stage_eight_e2ee/close_authority.rs"]
mod close_authority;
#[path = "stage_eight_e2ee/credential_bounds.rs"]
mod credential_bounds;
#[path = "stage_eight_e2ee/credential_replacement.rs"]
mod credential_replacement;
#[path = "stage_eight_e2ee/encrypted_clients.rs"]
mod encrypted_clients;
#[path = "stage_eight_e2ee/link_faults.rs"]
mod link_faults;
#[path = "stage_eight_e2ee/login_after_registration.rs"]
mod login_after_registration;
#[path = "support/loopback_ports.rs"]
mod loopback_ports;
#[path = "stage_eight_e2ee/mixed_profile.rs"]
mod mixed_profile;
#[path = "stage_eight_e2ee/origin_deletion.rs"]
mod origin_deletion;
#[path = "stage_eight_e2ee/recovery_submission.rs"]
mod recovery_submission;
#[path = "stage_eight_e2ee/requester_copies.rs"]
mod requester_copies;
#[path = "stage_eight_e2ee/stage_ten_capacity.rs"]
mod stage_ten_capacity;
#[path = "stage_eight_e2ee/stage_ten_drills.rs"]
mod stage_ten_drills;
#[path = "stage_eight_e2ee/stage_ten_login_index.rs"]
mod stage_ten_login_index;
#[path = "stage_eight_e2ee/welcome_recovery.rs"]
mod welcome_recovery;
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
/// The edge registers a client only once its coordinator link is ACTIVE;
/// registration attempts before that fail closed and are retried.
const NETWORK_WAIT: Duration = Duration::from_secs(60);
const TRANSCRIPT_LINES: usize = 256;
const REPLY_DEADLINE: Duration = Duration::from_secs(60);
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
    /// arrives from one of the generator's loopback source addresses, so this
    /// stays at the Section 19.2 hard maximum and the generator spreads its
    /// population over enough addresses to stay under it.
    connections_per_address: u64,
    /// `server.memory_budget_bytes`. The Stage 08 fixture lowers the budget to
    /// one GiB, which no advertised capacity claim can rest on; a campaign
    /// restores the Appendix C.2 default so `B`, `H`, `D` and `C` are the
    /// published values.
    memory_budget_bytes: u64,
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
                local_uid: 0,
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

/// The lowered `server.memory_budget_bytes` every Stage 08 fixture node runs.
/// Only a capacity campaign restores the Appendix C.2 default.
const STAGE_EIGHT_MEMORY_BUDGET_BYTES: u64 = 1_073_741_824;

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

/// Enables the local admin socket and raises the client ceiling for the
/// Stage 10 campaign; nothing else differs from the Stage 08 node.
fn apply_capacity_overrides(config: &mut String, capacity: CapacityPlan) -> TestResult {
    replace_once(
        config,
        "memory_budget_bytes = 1073741824",
        &format!("memory_budget_bytes = {}", capacity.memory_budget_bytes),
    )?;
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

/// Initializes a current-format fixture database under the supplied header.
fn initialize_database_with_header(
    state_dir: &Path,
    header: DatabaseHeaderTbs,
    storage_master: [u8; 32],
    rollback_guard: [u8; 32],
    login_index: [u8; 32],
    fake_record: &[u8],
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
    let outcome = initialize_storage(config)?;
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
        let daemon = env!("CARGO_BIN_EXE_arcd");
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

struct ArcClient {
    reader: BufReader<TlsClient>,
    /// The session's client-side copy of the Section 16 E2EE command bucket.
    e2ee_tokens: f64,
    /// When the bucket was last refilled.
    e2ee_refilled: Instant,
    /// Decoded bytes the dedicated ingress bucket still holds.
    e2ee_bytes: f64,
    /// SASL completed on this connection, so its welcome burst ends with the
    /// authenticated account state (architecture 10.2 step 6).
    logged_in: bool,
    /// The nickname the connection registered under; a login after
    /// registration follows its `903` with `900` (architecture 11.4).
    registered: Option<String>,
    /// The last `900` the connection read.
    account_state: Option<String>,
}

/// Companion Section 16 admits four E2EE command lines a second per session
/// with a burst of twenty, charged before any parsing. A command line and
/// the fragment zero of an object cost one such token; the continuation
/// fragments behind an admitted fragment zero are charged by decoded bytes
/// instead (ENC-16). These suites submit far more objects than a person
/// would, so each charged line waits for its credit before it is written and
/// a refusal in a scenario is never the admission bucket.
const E2EE_LINE_TOKENS_PER_SECOND: f64 = 4.0;
/// The burst these suites allow themselves. The server refills in whole
/// periods while this pacer refills continuously, so it keeps well inside
/// the published burst of twenty rather than tracking it exactly.
const E2EE_LINE_BURST: f64 = 8.0;
/// The dedicated ingress bucket refills `MIN_ADMITTED_E2EE_INGRESS_RATE`
/// decoded bytes a second per account and device.
const E2EE_INGRESS_BYTES_PER_SECOND: f64 = 65_536.0;
/// Half the published burst of one live object, for the same reason the
/// line burst stays inside twenty: the server credits whole seconds.
const E2EE_INGRESS_BURST: f64 = 131_072.0;

/// What one client line is charged before the server parses it.
enum E2eeCharge {
    /// Not an E2EE line.
    Free,
    /// One E2EE command token: a command line or a fragment zero.
    Line,
    /// The decoded bytes of a continuation fragment.
    Bytes(f64),
}

/// How the server charges `line`: any `EKEY`, `EGROUP` or `EDIRECT` line and
/// any fragment zero is one command line; a later fragment of the object
/// this client is sending pays its decoded bytes.
fn e2ee_charge(line: &str) -> E2eeCharge {
    let fragment =
        tag_value(line, CLIENT_FRAGMENT_TAG).and_then(|value| FragmentTag::parse(&value).ok());
    if let Some(fragment) = fragment {
        return match fragment.part {
            0 => E2eeCharge::Line,
            // A segment is at most 2,940 bytes, exact in an `f64`.
            _ => E2eeCharge::Bytes(f64::from(
                u16::try_from(fragment.segment.len()).unwrap_or(u16::MAX),
            )),
        };
    }
    let body = line.strip_prefix('@').map_or(line, |rest| {
        rest.split_once(' ').map_or("", |(_, body)| body)
    });
    let verb = body.split(' ').next().unwrap_or_default();
    if line.contains(CLIENT_FRAGMENT_TAG) || matches!(verb, "EKEY" | "EGROUP" | "EDIRECT") {
        E2eeCharge::Line
    } else {
        E2eeCharge::Free
    }
}

/// Connects to `target` from an explicit loopback source address.
///
/// `std::net` cannot bind a source address before connecting, and the
/// workspace pins `rustix` without its network feature, so the campaign
/// generator borrows tokio's socket builder for exactly this one step and
/// hands the connected descriptor back as a blocking `std` stream. The
/// reactor lives only for the connect.
fn connect_from_source(source: Ipv4Addr, target: SocketAddr) -> TestResult<TcpStream> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    let stream = runtime.block_on(async move {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(IpAddr::V4(source), 0))?;
        socket.connect(target).await?.into_std()
    })?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

impl ArcClient {
    fn connect(fixture: &NodeFixture) -> TestResult<Self> {
        Self::connect_from(fixture, None)
    }

    /// Connects, optionally from one generator source address.
    fn connect_from(fixture: &NodeFixture, source: Option<Ipv4Addr>) -> TestResult<Self> {
        let deadline = Instant::now() + START_TIMEOUT;
        let socket = loop {
            let attempt = match source {
                Some(address) => connect_from_source(address, fixture.public_address)
                    .map_err(|error| io::Error::other(error.to_string())),
                None => TcpStream::connect(fixture.public_address),
            };
            match attempt {
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
            e2ee_tokens: E2EE_LINE_BURST,
            e2ee_refilled: Instant::now(),
            e2ee_bytes: E2EE_INGRESS_BURST,
            logged_in: false,
            registered: None,
            account_state: None,
        })
    }

    /// Waits until the bucket the server charges this line against holds its
    /// credit, so the suite measures the encrypted lifecycle rather than the
    /// admission rate: one command token for a command line or a fragment
    /// zero, decoded bytes for a continuation fragment.
    fn pace_e2ee(&mut self, command: &str) {
        let charge = e2ee_charge(command);
        if matches!(charge, E2eeCharge::Free) {
            return;
        }
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.e2ee_refilled).as_secs_f64();
            self.e2ee_refilled = now;
            self.e2ee_tokens =
                (self.e2ee_tokens + elapsed * E2EE_LINE_TOKENS_PER_SECOND).min(E2EE_LINE_BURST);
            self.e2ee_bytes =
                (self.e2ee_bytes + elapsed * E2EE_INGRESS_BYTES_PER_SECOND).min(E2EE_INGRESS_BURST);
            match charge {
                E2eeCharge::Bytes(bytes) if self.e2ee_bytes >= bytes => {
                    self.e2ee_bytes -= bytes;
                    return;
                }
                E2eeCharge::Line if self.e2ee_tokens >= 1.0 => {
                    self.e2ee_tokens -= 1.0;
                    return;
                }
                _ => thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn send(&mut self, command: &str) -> TestResult {
        self.pace_e2ee(command);
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
                self.registered = Some(nickname.to_owned());
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

/// The credential every binding pins: the coordinator's active sequencer
/// credential, as `NodeFixture::create` writes it for the seed-20
/// coordinator of every network here.
fn active_sequencer_credential_id() -> TestResult<[u8; 32]> {
    let sequencer = Ed25519SecretKey::from_bytes([20_u8.wrapping_add(15); 32]);
    Ok(builders::sequencer_credential_id(
        *NETWORK_ID.as_bytes(),
        &sequencer,
        (0, 4_000_000_000),
    )?)
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
const E2EE_CAPS: &str = "sasl agenc.ag/account-create message-tags echo-message batch labeled-response standard-replies agenc.ag/account-controls agenc.ag/channel-controls account-tag agenc.ag/e2ee-mls";

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

fn require_entropy(rng: &FallibleOpaqueRng<OsEntropy>) -> TestResult {
    if rng.succeeded() {
        Ok(())
    } else {
        Err(failure("test OPAQUE entropy was unavailable"))
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
    let config = agenc_relay_config::load_config(
        &fixture.config_path,
        agenc_relay_config::ValidationDepth::Document,
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
                transaction_id: agenc_relay_types::TransactionId::from_bytes([217; 16]),
                ke3: OpaqueKe3::from_bytes([0; agenc_relay_auth::OPAQUE_KE3_BYTES])?,
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
        agenc_relay_auth::open_and_parse_request(
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
        self.read_welcome(nickname)
    }

    /// Reads the welcome burst through the MOTD group and, after a SASL
    /// login, the authenticated account state that ends it.
    fn read_welcome(&mut self, nickname: &str) -> TestResult<Vec<String>> {
        let mut welcome = read_until(&mut self.reader, |line| {
            line.contains(" 376 ") || line.contains(" 422 ")
        })?;
        if self.logged_in {
            let account_state = read_account_state(&mut self.reader, nickname)?;
            self.account_state = Some(account_state.clone());
            welcome.push(account_state);
        }
        self.registered = Some(nickname.to_owned());
        Ok(welcome)
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
    client: &mut ArcClient,
    fixture: &NodeFixture,
    login_name: &str,
    request_seed: u8,
) -> TestResult<AccountId> {
    create_live_account_with(client, fixture, login_name, account_requests(request_seed)?)
}

fn create_live_account_with(
    client: &mut ArcClient,
    fixture: &NodeFixture,
    login_name: &str,
    requests: [RequestId; 2],
) -> TestResult<AccountId> {
    let [start_request, finish_request] = requests;
    let mut rng = FallibleOpaqueRng::new(OsEntropy);
    let registration = ClientRegistration::<AgencOpaqueSuite>::start(&mut rng, ACCOUNT_PASSWORD)?;
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
        RegistrationResponse::<AgencOpaqueSuite>::deserialize(
            response.expose_for_account_response(),
        )?,
        ClientRegistrationFinishParameters::new(
            opaque_identifiers(&NETWORK_ID, &credential_id),
            Some(&FixedArgon2id),
        ),
    )?;
    let registration_record = finish_registration(
        registration_finish
            .message
            .serialize()
            .as_slice()
            .try_into()?,
    )?;
    require_entropy(&rng)?;

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
    client: &mut ArcClient,
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
    client: &mut ArcClient,
    fixture: &NodeFixture,
    login_name: &str,
    password: &[u8],
    requests: [RequestId; 2],
    expected_account: AccountId,
) -> TestResult {
    let [start_request, finish_request] = requests;
    let mut rng = FallibleOpaqueRng::new(OsEntropy);
    let login = ClientLogin::<AgencOpaqueSuite>::start(&mut rng, password)?;
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
    let context = opaque_context(&NETWORK_ID);
    let login_finish = login.state.finish(
        &mut rng,
        password,
        CredentialResponse::<AgencOpaqueSuite>::deserialize(ke2.expose_for_account_response())?,
        ClientLoginFinishParameters::new(
            Some(&context),
            opaque_identifiers(&NETWORK_ID, &credential_id),
            Some(&FixedArgon2id),
        ),
    )?;
    let ke3 = OpaqueKe3::from_bytes(login_finish.message.serialize().as_slice().try_into()?)?;
    require_entropy(&rng)?;
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
    client.logged_in = true;
    if let Some(nickname) = client.registered.clone() {
        // A registered session's login follows 903 with 900 (11.4).
        client.account_state = Some(read_account_state(&mut client.reader, &nickname)?);
    }
    Ok(())
}

/// The `900` that ends an authenticated registration's welcome burst
/// (architecture 10.2 step 6): the session's own mask and its account's
/// public label, or `*`.
fn read_account_state<R: BufRead>(reader: &mut R, nickname: &str) -> TestResult<String> {
    let line = read_line_for(reader, "authenticated account state")?;
    if !line.contains(&format!(" 900 {nickname} {nickname}!"))
        || !line.ends_with(" :You are now logged in")
    {
        return Err(failure(format!(
            "an authenticated welcome did not end with its account state: {line}"
        )));
    }
    Ok(line)
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
fn wire_object(kind: ArcWireObjectKind, value: &impl TlsEncode) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(kind, value.encode()?)?.encode()?)
}

/// Sends `command` with `object` attached as client fragment tags; every
/// fragment carries the label so the last one completes the request.
fn send_object(client: &mut ArcClient, label: &str, command: &str, object: &[u8]) -> TestResult {
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
fn labeled_reply(client: &mut ArcClient, label: &str) -> TestResult<Vec<String>> {
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

/// The requester's labeled completion, which `labeled_reply` returns last.
/// The unlabeled broadcast or notice that can arrive before it is not the
/// command's result (companion 11.7), so a reply token is checked here.
fn completion_line(reply: &[String]) -> TestResult<&String> {
    reply
        .last()
        .filter(|line| tag_value(line, "label").is_some())
        .ok_or_else(|| failure(format!("no labeled completion in {reply:?}")))
}

/// The verb and identifiers a result line names, without its tags and
/// prefix.
fn result_words(line: &str) -> Option<Vec<String>> {
    words(line).get(1..).map(<[String]>::to_vec)
}

/// The requester's labeled `verb` completion, required to be the only line
/// of its reply naming that result: companion 11.7 and 12.5 answer the
/// requesting connection with exactly one labeled scalar and send the
/// untagged broadcast of the same result only to the other eligible sinks.
/// A line naming another result is earlier traffic the connection had not
/// read yet.
fn only_completion<'a>(reply: &'a [String], verb: &str) -> TestResult<&'a String> {
    let completion = completion_line(reply)?;
    let token = format!(" EGROUP {verb} ");
    if !completion.contains(&token) {
        return Err(failure(format!(
            "the labeled completion is not {verb}: {reply:?}"
        )));
    }
    let result = result_words(completion);
    let naming = reply
        .iter()
        .filter(|line| line.contains(&token) && result_words(line) == result)
        .count();
    if naming != 1 {
        return Err(failure(format!(
            "the requester received {naming} {verb} lines naming its result, not one labeled completion: {reply:?}"
        )));
    }
    Ok(completion)
}

/// Requires the reply to an ACK submission to carry no `verb` notice of the
/// submitted ACK `object`: the submitter receives only its labeled `ACKED`
/// or `REINIT-ACKED`, and the untagged notice goes to the other sessions
/// (companion 11.7 and 12.5).
fn assert_no_own_notice(reply: &[String], verb: &str, object: &[u8]) -> TestResult {
    let own = base64url_encode(e2ee::ObjectId::compute(object).as_bytes());
    let token = format!(" EGROUP {verb} ");
    if reply
        .iter()
        .any(|line| line.contains(&token) && line.contains(&own))
    {
        return Err(failure(format!(
            "the submitter received the notice of its own ACK: {reply:?}"
        )));
    }
    Ok(())
}

/// Requires the last of `lines`, which another sink read, to be the
/// untagged broadcast of the terminal `completion` names: the same verb and
/// identifiers, without a label.
fn assert_same_terminal(lines: &[String], completion: &[String]) -> TestResult {
    let broadcast = lines
        .last()
        .ok_or_else(|| failure("no terminal broadcast was read"))?;
    if tag_value(broadcast, "label").is_some() {
        return Err(failure(format!("the broadcast is labeled: {broadcast}")));
    }
    assert_eq!(
        result_words(broadcast),
        completion.first().and_then(|line| result_words(line)),
        "the broadcast and the labeled completion name the same terminal"
    );
    Ok(())
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

/// The old leaf key the binder's device holds as leaf 0 of a new group.
const BINDER_LEAF_SEED: u8 = 158;

/// The old MLS leaf one device proves and acknowledges with: the exact
/// signature key its endpoint holds, that leaf's index in the group, and the
/// `old_credential_hash` of the credential the leaf carries (companion 2.2).
/// Every membership proof and every ACK signature built from it is the
/// endpoint's own (companion 13.7.3).
struct OldLeaf {
    secret: Ed25519SecretKey,
    index: u32,
    credential_hash: [u8; 32],
}

impl OldLeaf {
    /// Leaf zero of the binder under the fixed public-envelope test key, with
    /// the fixed credential digest those suites also place in every ACK.
    fn binder_default() -> Self {
        Self {
            secret: builders::key(BINDER_LEAF_SEED),
            index: 0,
            credential_hash: [5; 32],
        }
    }

    /// The leaf an MLS library holds under `secret` at group position
    /// `index`, whose `Credential` the library encodes as `credential`: the
    /// basic credential type followed by `identity<V>`, hashed through the
    /// shared leaf credential helper.
    fn real(secret: Ed25519SecretKey, index: u32, credential: &[u8]) -> TestResult<Self> {
        Ok(Self {
            secret,
            index,
            credential_hash: e2ee::mls_outer::EncodedBasicCredential::parse(credential)?
                .old_credential_hash()?,
        })
    }
}

/// The proof `owner`'s device publishes for `leaf` at `epoch` (companion
/// 13.7.3): a continuing proof carries the leaf key's own possession
/// signature and an all-zero removal identifier, and a removed proof carries
/// an empty possession field and names the finalization that removed it.
fn leaf_membership(
    owner: &Principal,
    conversation: [u8; 32],
    epoch: u64,
    leaf: &OldLeaf,
    removal: Option<[u8; 32]>,
) -> TestResult<ArcLeafMembershipProof> {
    let tbs = ArcLeafMembershipProofTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        conversation_id: conversation,
        epoch,
        leaf_index: leaf.index,
        old_credential_hash: leaf.credential_hash,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key: Opaque::from_slice(&builders::public(&leaf.secret))?,
        account_id: owner.keys.root.tbs.account_id.clone(),
        device_id: [owner.device; 16],
        root_generation: owner.keys.root.tbs.root_generation,
        root_fingerprint: builders::root_fingerprint(&owner.keys.root)?,
        roster_generation: owner.keys.roster.tbs.roster_generation,
        roster_id: builders::roster_id(&owner.keys.roster)?,
        credential_generation: 0,
        disposition: match removal {
            Some(_) => ArcLeafDispositionKind::Removed,
            None => ArcLeafDispositionKind::Continuing,
        },
        removal_finalization_id: removal.unwrap_or([0; 32]),
    };
    let possession = match removal {
        Some(_) => Vec::new(),
        None => builders::sign(
            &leaf.secret,
            SignatureDomain::LeafMembershipPossession,
            &tbs,
        )?
        .to_vec(),
    };
    Ok(ArcLeafMembershipProof {
        device_signature: builders::sign(
            &builders::key(owner.device),
            SignatureDomain::LeafMembership,
            &tbs,
        )?,
        possession_signature: Opaque::new(possession)?,
        tbs,
    })
}

/// Publishes one leaf-membership proof and checks that `STORED MEMBERSHIP`
/// names the recomputed proof and object identifiers.
fn publish_membership(
    client: &mut ArcClient,
    owner: &mut Principal,
    bound: &BoundConversation,
    epoch: u64,
    leaf: &OldLeaf,
    removal: Option<[u8; 32]>,
) -> TestResult<[u8; 32]> {
    let proof = leaf_membership(owner, bound.conversation, epoch, leaf, removal)?;
    let object = wire_object(ArcWireObjectKind::LeafMembershipProof, &proof)?;
    let conversation_token = base64url_encode(&bound.conversation);
    let membership_id = semantic_id_of(SemanticHashDomain::LeafMembershipId, &proof.tbs)?;
    let label = owner.label();
    send_object(
        client,
        &label,
        &format!("EGROUP SUBMIT MEMBERSHIP {conversation_token}"),
        &object,
    )?;
    assert_contains(
        &labeled_reply(client, &label)?,
        &format!(
            " EGROUP STORED MEMBERSHIP {conversation_token} {} {}",
            base64url_encode(&membership_id),
            base64url_encode(e2ee::ObjectId::compute(&object).as_bytes())
        ),
    )?;
    Ok(membership_id)
}

/// Registers an authenticated client on `fixture`: one connection creates
/// the account and a second authenticates and registers.
fn authenticated_client(
    fixture: &NodeFixture,
    nickname: &str,
    login: &str,
    request_seed: u8,
) -> TestResult<(ArcClient, AccountId)> {
    let account_id = {
        let mut creation = ArcClient::connect(fixture)?;
        creation.negotiate_sasl()?;
        create_live_account(&mut creation, fixture, login, request_seed)?
    };
    let auth_seed = request_seed
        .checked_add(2)
        .ok_or_else(|| failure("authentication request seed overflow"))?;
    let client = authenticated_session(fixture, nickname, login, auth_seed, account_id)?;
    Ok((client, account_id))
}

/// Authenticates a new connection on `fixture` as the existing
/// `account_id` under the account requests of `request_seed`, and registers
/// it as `nickname`.
fn authenticated_session(
    fixture: &NodeFixture,
    nickname: &str,
    login: &str,
    request_seed: u8,
    account_id: AccountId,
) -> TestResult<ArcClient> {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))?;
    let acknowledged = client.send_until(&format!("CAP REQ :{E2EE_CAPS}"), " CAP * ACK ")?;
    assert_contains(&acknowledged, "agenc.ag/e2ee-mls")?;
    authenticate_live_account(
        &mut client,
        fixture,
        login,
        ACCOUNT_PASSWORD,
        request_seed,
        account_id,
    )?;
    let registered = client.complete_registration(nickname)?;
    assert_contains(&registered, &format!(" 001 {nickname} "))?;
    Ok(client)
}

/// Publishes the identity and roster and attaches the device.
fn publish_and_attach(client: &mut ArcClient, user: &mut Principal) -> TestResult {
    let root = wire_object(ArcWireObjectKind::RootIdentity, &user.keys.root)?;
    let label = user.label();
    send_object(client, &label, "EKEY PUBLISH IDENTITY", &root)?;
    let reply = labeled_reply(client, &label)?;
    assert_contains(&reply, " EKEY STORED IDENTITY ")?;
    let roster = wire_object(ArcWireObjectKind::DeviceRoster, &user.keys.roster)?;
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
    let object = ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::DeviceAttachChallenge),
        &mut budget,
    )?;
    let challenge = ArcDeviceAttachChallenge::decode_exact(object.body(), &mut budget)?;
    let device_signature = builders::sign(
        &builders::key(user.device),
        agenc_relay_crypto::SignatureDomain::DeviceAttachPossession,
        &challenge.tbs,
    )?;
    let attach = wire_object(
        ArcWireObjectKind::DeviceAttach,
        &ArcDeviceAttach {
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
    package: ArcConversationBindingPackage,
    /// The generation-zero bootstrap policy and the generation-one
    /// operational policy the binding commits to (companion 9.3).
    policies: [ArcPolicy; 2],
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
fn reservation_of(reply: &[String]) -> TestResult<ArcReservation> {
    let bytes = batch_object(reply)?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object =
        ArcWireObject::decode_kind(&bytes, Some(ArcWireObjectKind::Reservation), &mut budget)?;
    Ok(ArcReservation::decode_exact(object.body(), &mut budget)?)
}

/// Sends the binding package of `reservation` and returns the bound facts.
/// The bootstrap and operational policies of a conversation whose creator
/// is the first principal.
fn policies_for(
    principals: &[&builders::Principal],
    conversation: [u8; 32],
    kind: ArcConversationKind,
) -> TestResult<[ArcPolicy; 2]> {
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
    client: &mut ArcClient,
    binder: &mut Principal,
    bound: &BoundConversation,
) -> TestResult {
    let conversation_token = base64url_encode(&bound.conversation);
    for policy in &bound.policies {
        let bytes = wire_object(ArcWireObjectKind::Policy, policy)?;
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
    client: &mut ArcClient,
    binder: &mut Principal,
    reservation: &ArcReservation,
    package: ArcConversationBindingPackage,
    route_binding: [u8; 32],
    group_id: [u8; 32],
    policies: [ArcPolicy; 2],
) -> TestResult<BoundConversation> {
    let binding = wire_object(ArcWireObjectKind::ConversationBinding, &package)?;
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
    client: &mut ArcClient,
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
    let route = ArcSemanticRouteTbs {
        profile_version: 1,
        network_id: *NETWORK_ID.as_bytes(),
        kind: ArcConversationKind::Direct,
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
        ArcConversationKind::Direct,
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
        sequencer_credential_id: active_sequencer_credential_id()?,
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
    client: &mut ArcClient,
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
        ArcConversationKind::Channel,
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
        sequencer_credential_id: active_sequencer_credential_id()?,
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

/// The recorded lifecycle outcomes of the interoperability matrix.
fn recorded_lifecycle() -> TestResult<std::collections::BTreeMap<String, String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join("conformance/e2ee-interop-matrix.toml"))?;
    let mut matrix = std::collections::BTreeMap::new();
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

/// Requires every rule of `rules` to be recorded as `agree`, and requires the
/// matrix to record no lifecycle rule that no suite of this binary claims, so
/// a deviation is visible rather than hidden.
fn require_recorded(rules: &[&str]) -> TestResult {
    let recorded = recorded_lifecycle()?;
    for rule in rules {
        assert_eq!(
            recorded.get(*rule).map(String::as_str),
            Some("agree"),
            "rule {rule} is recorded as agree in the interoperability matrix"
        );
    }
    let claimed = real_clients::RULES.len() + encrypted_clients::RULES.len();
    assert_eq!(
        recorded.len(),
        claimed,
        "every recorded lifecycle rule belongs to one of the real-client suites"
    );
    Ok(())
}

/// The context core identifier the test binding package carries.
const CONTEXT_CORE_ID: [u8; 32] = [30; 32];
const VALIDATION_TIME: u64 = 1_700_000_000;
/// MLS content types (RFC 9420 section 6).
const MLS_APPLICATION: u8 = 1;
const MLS_COMMIT: u8 = 3;

/// Wraps raw MLS bytes as the wire object of `kind`.
fn raw_object(kind: ArcWireObjectKind, bytes: Vec<u8>) -> TestResult<Vec<u8>> {
    Ok(ArcWireObject::new(kind, bytes)?.encode()?)
}

/// Reassembles the object the server fragment tags of `lines` carry.
fn fragments_object(lines: &[String]) -> TestResult<Vec<u8>> {
    batch_object(lines)
}

/// Runs the bootstrap activation round on `bound` from the binder: one
/// Commit candidate sequenced by the coordinator, then its finalization
/// with the binder's council vote; returns the finalization identifier,
/// which is the next accepted state.
/// Activates the bootstrap with the finality votes of `co_voters` beside
/// the binder's: both councils vote on a bootstrap activation (companion
/// 9.5), so every principal of the resulting council signs.
fn activate_bootstrap_with(
    client: &mut ArcClient,
    binder: &mut Principal,
    bound: &BoundConversation,
    co_voters: &[&Principal],
) -> TestResult<[u8; 32]> {
    let network = *NETWORK_ID.as_bytes();
    let conversation = bound.conversation;
    let route_binding = bound.route_binding;
    let genesis = ArcGroupGenesisTbs {
        network_id: network,
        conversation_id: conversation,
        group_id: Opaque::new(bound.group_id.to_vec())?,
        binding_id: bound.binding_id,
        context_core_id: CONTEXT_CORE_ID,
    };
    let accepted = semantic_id_of(SemanticHashDomain::GroupGenesisId, &genesis)?;
    let initial_policy_id = builders::policy_id_of(&bound.policies[0])?;
    let operational_policy_id = builders::policy_id_of(&bound.policies[1])?;

    let commit_aad = ArcCommitAad {
        profile_version: 1,
        network_id: network,
        conversation_id: conversation,
        route_binding,
        validation_time: VALIDATION_TIME,
        prior_state_id: accepted,
    }
    .encode()?;
    let commit = raw_object(
        ArcWireObjectKind::CommitMls,
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
    let receipt = ArcCandidateReceipt::decode_exact(&receipt_tag.receipt, &mut budget)?;
    assert_eq!(receipt.tbs.commit_object_id, commit_object_id);
    assert_eq!(receipt.tbs.prior_state_id, accepted);

    let authorization = builders::commit_authorization(
        ArcCommitAuthorizationTbs {
            profile_version: 1,
            network_id: network,
            conversation_id: conversation,
            prior_epoch: 0,
            prior_state_id: accepted,
            candidate_id,
            commit_object_id,
            canonical_validation_time: VALIDATION_TIME,
            old_policy_id: initial_policy_id,
            authorization_rule: ArcCommitAuthorizationRule::BootstrapActivation,
            action_bits: action_bits::POLICY | action_bits::BOOTSTRAP,
            resulting_policy_id: operational_policy_id,
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            transition_target_digest: [0; 32],
        },
        &[(&binder.keys, binder.device)],
    )?;
    let mut core = ArcFinalizationCoreTbs {
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
    let ack = ArcCommitAck {
        tbs: ArcCommitAckTbs {
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
    // The binder's device attests to its old leaf 0 before the finalization
    // embeds that leaf's ACK (companion 13.7.3).
    let leaf = OldLeaf::binder_default();
    publish_membership(client, binder, bound, 0, &leaf, None)?;
    let ack = ArcCommitAck {
        old_leaf_signature: Opaque::from_slice(&builders::sign(
            &leaf.secret,
            SignatureDomain::CommitProcessed,
            &ack.tbs,
        )?)?,
        tbs: ack.tbs,
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
    let tbs = vote_tbs(&slot, candidate_id, Terminal::finalize(finalization_id));
    let mut votes = vec![builders::finality_vote(&binder.keys, binder.device, &tbs)?];
    for voter in co_voters {
        votes.push(builders::finality_vote(&voter.keys, voter.device, &tbs)?);
    }
    votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
    let request = ArcFinalizationRequest {
        proof: ArcFinalizationProof {
            core,
            receipt,
            authorization,
            acknowledgements: TlsVec::new(vec![ack])?,
        },
        votes: TlsVec::new(votes)?,
    };
    let request = wire_object(ArcWireObjectKind::FinalizationRequest, &request)?;
    let label = binder.label();
    send_object(
        client,
        &label,
        &format!("EGROUP SUBMIT FINALIZATION {conversation_token}"),
        &request,
    )?;
    let reply = labeled_reply(client, &label)?;
    let completion = std::slice::from_ref(only_completion(&reply, "FINALIZED")?);
    assert_contains(
        completion,
        &format!(" EGROUP FINALIZED {conversation_token} 1 "),
    )?;
    assert_eq!(hash_at(completion, "FINALIZED", 5)?, finalization_id);
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
    sender: &mut ArcClient,
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
    sender: &mut ArcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    latest_state_id: [u8; 32],
    epoch: u64,
    variant: u8,
) -> TestResult<Vec<u8>> {
    let network = *NETWORK_ID.as_bytes();
    let aad = ArcApplicationAad {
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
        ArcWireObjectKind::ApplicationMls,
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
fn receive_application(client: &mut ArcClient, bound: &BoundConversation) -> TestResult<Vec<u8>> {
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
    client: &mut ArcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    terminal: [u8; 32],
) -> TestResult<[u8; 32]> {
    close_conversation_at(client, principal, bound, terminal, VALIDATION_TIME + 1)
}

/// Closes `bound` under a close intent that names `validation_time`.
fn close_conversation_at(
    client: &mut ArcClient,
    principal: &mut Principal,
    bound: &BoundConversation,
    terminal: [u8; 32],
    validation_time: u64,
) -> TestResult<[u8; 32]> {
    let close = close_authority::authorization_at(principal, bound, terminal, validation_time)?;
    let close_id = e2ee::route::close_authorization_id(&close)?;
    let object = wire_object(ArcWireObjectKind::CloseAuthorization, &close)?;
    let conversation = base64url_encode(&bound.conversation);
    let label = principal.label();
    send_object(
        client,
        &label,
        &format!("EGROUP CLOSE {conversation} 1"),
        &object,
    )?;
    let reply = labeled_reply(client, &label)?;
    let completion = std::slice::from_ref(only_completion(&reply, "CLOSED")?);
    assert_contains(completion, &format!(" EGROUP CLOSED {conversation} "))?;
    assert_eq!(hash_at(completion, "CLOSED", 4)?, close_id);
    Ok(close_id)
}

/// Sends application lines until the edge reports the coordinator link
/// down with `E2EE_SYNCING`; the link loss takes a moment to surface.
fn wait_for_e2ee_partition(
    client: &mut ArcClient,
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
    smaller: (&mut ArcClient, &mut Principal),
    larger: (&mut ArcClient, &mut Principal),
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
        activate_bootstrap_with(first, first_keys, &direct, &[&*second_keys]),
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
    sender: &mut ArcClient,
    sender_keys: &mut Principal,
    receiver: &mut ArcClient,
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
        let aad = ArcApplicationAad {
            profile_version: 1,
            network_id: network,
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            latest_state_id: genesis_state,
        }
        .encode()?;
        raw_object(
            ArcWireObjectKind::ApplicationMls,
            builders::private_message_at_epoch(&GROUP, 0, MLS_APPLICATION, &aad)?,
        )?
    };
    send_object(&mut alice, &label, "TAGMSG #room", &early)?;
    let refused = labeled_reply(&mut alice, &label)?;
    assert_contains(&refused, "FAIL TAGMSG E2EE_FINALITY_REQUIRED")?;

    let finalization_id = step(
        "channel activation",
        activate_bootstrap_with(&mut alice, &mut alice_keys, &bound, &[&bob_keys]),
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
        ArcWireObjectKind::ApplicationMls,
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
    sender: &mut ArcClient,
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

    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use agenc_relay_testkit::client_policy::{
        ClientTrust, DisplayError, TrustState, render_decrypted_text,
    };
    use agenc_relay_testkit::e2ee::ids::{account_id_digest, leaf_capabilities_digest};
    use agenc_relay_testkit::e2ee::mls_outer::{MlsOuterMessage, parse_mls_message};
    use agenc_relay_testkit::e2ee::objects::content::{
        ArcEncryptedContent, ArcEncryptedContentType,
    };
    use agenc_relay_testkit::e2ee::objects::conversation::ArcJoinTransitionProofBundle;
    use agenc_relay_testkit::e2ee::objects::sequencing::{
        ArcAbortCoreTbs, ArcAbortRequest, ArcCommitAbortReason, ArcDeliveredWelcome,
        ArcNormalJoinAuthorizationProof,
    };
    use mls_rs::client_builder::MlsConfig;
    use mls_rs::crypto::{SignaturePublicKey as RsPublicKey, SignatureSecretKey as RsSecretKey};
    use mls_rs::group::ReceivedMessage;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential as RsBasicCredential, BasicIdentityProvider};
    use mls_rs::mls_rs_codec::MlsEncode as _;
    use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
    use mls_rs::time::MlsTime;
    use mls_rs::{CipherSuite as RsSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;
    use openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
    use openmls::key_packages::Lifetime as OpenMlsLifetime;
    use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
    use openmls::prelude::{
        BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey, GroupId,
        KeyPackage as OpenMlsKeyPackage, LeafNodeParameters, MlsGroup, MlsGroupJoinConfig,
        MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, OpenMlsProvider, ProcessedMessageContent,
        ProtocolVersion, StagedWelcome,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::*;

    /// The wire suite both libraries use here.
    pub(super) const SUITE: u16 = 1;
    /// How long each leaf lives past `now`.
    pub(super) const LEAF_LIFETIME: u64 = 24 * 3_600;
    /// The interoperability matrix rules this test records.
    pub(super) const RULES: [&str; 8] = [
        "lifecycle-openmls-commit-sequenced",
        "lifecycle-openmls-finalized-under-published-quorum",
        "lifecycle-mls-rs-package-published-and-claimed",
        "lifecycle-openmls-add-finalized-by-two-councils",
        "lifecycle-welcome-delivered-and-joined-by-mls-rs",
        "lifecycle-padded-content-openmls-to-mls-rs",
        "lifecycle-padded-content-mls-rs-to-openmls",
        "lifecycle-closed-after-real-traffic",
    ];

    pub(super) fn wall_clock_seconds() -> TestResult<u64> {
        Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
    }

    /// The leaf capabilities both libraries are configured to advertise,
    /// hashed as the leaf authorization commits to them.
    pub(super) fn capabilities_hash() -> TestResult<[u8; 32]> {
        Ok(leaf_capabilities_digest(&builders::encoded_capabilities(
            &builders::default_capabilities(),
        )?)?)
    }

    pub(super) fn leaf_spec(device: u8, interval: (u64, u64)) -> TestResult<builders::LeafSpec> {
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
    pub(super) fn credential_identity(
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

    /// The `Credential` a leaf of `principal` carries under
    /// `leaf_public_key`, as both libraries encode it: the basic credential
    /// type followed by `identity<V>`, whose identity is
    /// [`credential_identity`].
    pub(super) fn encoded_credential(
        principal: &Principal,
        interval: (u64, u64),
        leaf_public_key: &[u8],
    ) -> TestResult<Vec<u8>> {
        let identity = credential_identity(principal, interval, leaf_public_key)?;
        let openmls = openmls::prelude::Credential::from(BasicCredential::new(identity.clone()))
            .tls_serialize_detached()?;
        let mls_rs = RsBasicCredential::new(identity)
            .into_credential()
            .mls_encode_to_vec()?;
        if openmls != mls_rs {
            return Err(failure(
                "openmls and mls-rs encode the leaf credential differently",
            ));
        }
        Ok(openmls)
    }

    pub(super) fn commit_aad(
        bound: &BoundConversation,
        prior_state_id: [u8; 32],
        time: u64,
    ) -> TestResult<Vec<u8>> {
        Ok(ArcCommitAad {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            validation_time: time,
            prior_state_id,
        }
        .encode()?)
    }

    pub(super) fn application_aad(
        bound: &BoundConversation,
        latest_state_id: [u8; 32],
    ) -> TestResult<Vec<u8>> {
        Ok(ArcApplicationAad {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding: bound.route_binding,
            latest_state_id,
        }
        .encode()?)
    }

    /// Padded application content from `sender` (Sections 7.5 and 10).
    pub(super) fn padded_content(
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
    pub(super) fn padded_content_bound(
        bound: &BoundConversation,
        route_binding: [u8; 32],
        sender: &Principal,
        sequence: u64,
        head: [u8; 32],
        text: &str,
    ) -> TestResult<Vec<u8>> {
        let mut content = ArcEncryptedContent {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            route_binding,
            sender_device_id: [sender.device; 16],
            leaf_credential_generation: 0,
            sender_sequence: sequence,
            message_id: [u8::try_from(sequence)? ^ sender.device; 16],
            sequencer_record_chain_head: head,
            content_type: ArcEncryptedContentType::Text,
            body: Opaque::new(text.as_bytes().to_vec())?,
            zero_padding: Opaque::new(Vec::new())?,
        };
        content.pad()?;
        Ok(content.encode()?)
    }

    /// Decodes received content, checking its padding and shape, and returns
    /// the text.
    pub(super) fn content_text(bytes: &[u8]) -> TestResult<String> {
        let mut budget = DecodeBudget::new(1 << 16, 64);
        let content = ArcEncryptedContent::decode_checked(bytes, &mut budget)?;
        assert_eq!(content.content_type, ArcEncryptedContentType::Text);
        Ok(String::from_utf8(content.body.as_slice().to_vec())?)
    }

    /// The MLS bytes inside a forwarded application object.
    pub(super) fn mls_body(object: &[u8], kind: ArcWireObjectKind) -> TestResult<Vec<u8>> {
        let mut budget = DecodeBudget::new(1 << 20, 1 << 10);
        Ok(ArcWireObject::decode_kind(object, Some(kind), &mut budget)?
            .body()
            .to_vec())
    }

    /// What a certified Commit leaves behind, including the receipt the
    /// coordinator signed for its candidate: a client reads the credential
    /// the conversation pins from there (companion 9.2.1).
    pub(super) struct Certified {
        pub(super) finalization_id: [u8; 32],
        pub(super) record_id: [u8; 32],
        pub(super) receipt: ArcCandidateReceipt,
    }

    /// The candidate the coordinator sequenced for one submitted Commit.
    pub(super) struct Sequenced {
        pub(super) candidate_id: [u8; 32],
        commit_object_id: [u8; 32],
        pub(super) receipt: ArcCandidateReceipt,
        canonical_validation_time: u64,
    }

    /// Submits `commit` as the next candidate of `bound` and reads back the
    /// receipt the coordinator signed for it (companion 12.2).
    pub(super) fn sequence_candidate(
        client: &mut ArcClient,
        binder: &mut Principal,
        bound: &BoundConversation,
        commit: &[u8],
        prior_state_id: [u8; 32],
    ) -> TestResult<Sequenced> {
        let canonical_validation_time =
            close_authority::candidate_validation_time(bound, &prior_state_id, commit)?;
        let commit = raw_object(ArcWireObjectKind::CommitMls, commit.to_vec())?;
        let commit_object_id = *e2ee::ObjectId::compute(&commit).as_bytes();
        let conversation_token = base64url_encode(&bound.conversation);
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
        let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
        let receipt = ArcCandidateReceipt::decode_exact(&receipt_tag.receipt, &mut budget)?;
        assert_eq!(receipt.tbs.commit_object_id, commit_object_id);
        assert_eq!(receipt.tbs.prior_state_id, prior_state_id);
        Ok(Sequenced {
            candidate_id: receipt_tag.candidate_id,
            commit_object_id,
            receipt,
            canonical_validation_time,
        })
    }

    /// Acknowledges `sequenced` with `leaf`'s own key after publishing that
    /// leaf's continuing proof. An ACK that no stored leaf key verifies
    /// identifies no signer and is refused first, so the accepted ACK is
    /// identified by the proof alone (companion 13.7.3).
    fn acknowledge(
        client: &mut ArcClient,
        binder: &mut Principal,
        bound: &BoundConversation,
        sequenced: &Sequenced,
        prior_epoch: u64,
        leaf: &OldLeaf,
    ) -> TestResult<ArcCommitAck> {
        let conversation_token = base64url_encode(&bound.conversation);
        let tbs = ArcCommitAckTbs {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            prior_epoch,
            candidate_id: sequenced.candidate_id,
            commit_object_id: sequenced.commit_object_id,
            old_leaf_index: leaf.index,
            old_credential_hash: leaf.credential_hash,
            resulting_epoch: prior_epoch.saturating_add(1),
            resulting_group_context_digest: [1; 32],
            resulting_ratchet_tree_digest: [2; 32],
            finalization_authenticator: [4; 32],
        };
        let unproven = wire_object(
            ArcWireObjectKind::CommitAck,
            &ArcCommitAck {
                tbs: tbs.clone(),
                old_leaf_signature: Opaque::new(vec![6; 64])?,
            },
        )?;
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT ACK {conversation_token}"),
            &unproven,
        )?;
        assert_contains(
            &labeled_reply(client, &label)?,
            "FAIL EGROUP E2EE_BINDING_AUTH_INVALID",
        )?;
        publish_membership(client, binder, bound, prior_epoch, leaf, None)?;
        let ack = ArcCommitAck {
            old_leaf_signature: Opaque::from_slice(&builders::sign(
                &leaf.secret,
                SignatureDomain::CommitProcessed,
                &tbs,
            )?)?,
            tbs,
        };
        let object = wire_object(ArcWireObjectKind::CommitAck, &ack)?;
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT ACK {conversation_token}"),
            &object,
        )?;
        let reply = labeled_reply(client, &label)?;
        only_completion(&reply, "ACKED")?;
        assert_no_own_notice(&reply, "ACK", &object)?;
        Ok(ack)
    }

    /// The authorization and finalization core of one certified Commit.
    fn certificate_core(
        bound: &BoundConversation,
        sequenced: &Sequenced,
        prior: (u64, [u8; 32]),
        policies: ([u8; 32], [u8; 32]),
        transition: close_authority::CertificationTransition,
        binder: &Principal,
    ) -> TestResult<(ArcCommitAuthorization, ArcFinalizationCoreTbs)> {
        let (prior_epoch, prior_state_id) = prior;
        let (old_policy_id, resulting_policy_id) = policies;
        let (rule, actions, target) = transition.fields();
        let authorization = builders::commit_authorization(
            ArcCommitAuthorizationTbs {
                profile_version: 1,
                network_id: *NETWORK_ID.as_bytes(),
                conversation_id: bound.conversation,
                prior_epoch,
                prior_state_id,
                candidate_id: sequenced.candidate_id,
                commit_object_id: sequenced.commit_object_id,
                canonical_validation_time: sequenced.canonical_validation_time,
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
        let core = ArcFinalizationCoreTbs {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            prior_epoch,
            prior_state_id,
            candidate_id: sequenced.candidate_id,
            commit_object_id: sequenced.commit_object_id,
            resulting_epoch: prior_epoch.saturating_add(1),
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
        Ok((authorization, core))
    }

    /// Submits the finalization request of `sequenced` with `ack` and the
    /// votes of the binder and `co_voters` (companion 12.4).
    // agenc-review: allow owner=tests reviewed=2026-09-17 reason=one finalization names the client the binder its co-voters the conversation the sequenced candidate its authorization core and the accepted acknowledgement together
    #[allow(clippy::too_many_arguments)]
    fn finalize(
        client: &mut ArcClient,
        binder: &mut Principal,
        co_voters: &[&Principal],
        bound: &BoundConversation,
        sequenced: Sequenced,
        authorization: ArcCommitAuthorization,
        mut core: ArcFinalizationCoreTbs,
        ack: ArcCommitAck,
    ) -> TestResult<Certified> {
        core.acknowledgement_set_digest = e2ee::ids::proof_set_digest(
            SemanticHashDomain::AcknowledgementSet,
            std::slice::from_ref(&ack.tbs),
        )?;
        let finalization_id = semantic_id_of(SemanticHashDomain::FinalizationId, &core)?;
        let resulting_epoch = core.resulting_epoch;
        let slot = VoteSlot {
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            prior_epoch: core.prior_epoch,
            prior_state_id: core.prior_state_id,
            candidate_sequence: sequenced.receipt.tbs.candidate_sequence,
            predecessor_record_id: sequenced.receipt.tbs.predecessor_record_id,
        };
        let tbs = vote_tbs(
            &slot,
            sequenced.candidate_id,
            Terminal::finalize(finalization_id),
        );
        let mut votes = vec![builders::finality_vote(&binder.keys, binder.device, &tbs)?];
        for voter in co_voters {
            votes.push(builders::finality_vote(&voter.keys, voter.device, &tbs)?);
        }
        votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
        let receipt = sequenced.receipt.clone();
        let request = ArcFinalizationRequest {
            proof: ArcFinalizationProof {
                core,
                receipt: sequenced.receipt,
                authorization,
                acknowledgements: TlsVec::new(vec![ack])?,
            },
            votes: TlsVec::new(votes)?,
        };
        let request = wire_object(ArcWireObjectKind::FinalizationRequest, &request)?;
        let conversation_token = base64url_encode(&bound.conversation);
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT FINALIZATION {conversation_token}"),
            &request,
        )?;
        let reply = labeled_reply(client, &label)?;
        let completion = std::slice::from_ref(only_completion(&reply, "FINALIZED")?);
        assert_contains(
            completion,
            &format!(" EGROUP FINALIZED {conversation_token} {resulting_epoch} "),
        )?;
        assert_eq!(hash_at(completion, "FINALIZED", 5)?, finalization_id);
        Ok(Certified {
            finalization_id,
            record_id: hash_at(completion, "FINALIZED", 6)?,
            receipt,
        })
    }

    /// Aborts `sequenced` with one request that carries the votes of the
    /// binder and `co_voters` (companion 12.4), and returns the binder's
    /// labeled `ABORTED` completion, the only line of its reply that names
    /// the abort.
    pub(super) fn abort_candidate(
        client: &mut ArcClient,
        binder: &mut Principal,
        co_voters: &[&Principal],
        bound: &BoundConversation,
        sequenced: Sequenced,
        prior_epoch: u64,
    ) -> TestResult<String> {
        let core = ArcAbortCoreTbs {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            prior_state_id: sequenced.receipt.tbs.prior_state_id,
            candidate_id: sequenced.candidate_id,
            prior_epoch,
            reason: ArcCommitAbortReason::SenderWithdrawn,
            evidence_digest: [0; 32],
        };
        let abort_id = semantic_id_of(SemanticHashDomain::AbortId, &core)?;
        let slot = VoteSlot {
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            prior_epoch,
            prior_state_id: core.prior_state_id,
            candidate_sequence: sequenced.receipt.tbs.candidate_sequence,
            predecessor_record_id: sequenced.receipt.tbs.predecessor_record_id,
        };
        let terminal = Terminal::abort(abort_id, u16::from(core.reason.value()))?;
        let tbs = vote_tbs(&slot, sequenced.candidate_id, terminal);
        let mut votes = vec![builders::finality_vote(&binder.keys, binder.device, &tbs)?];
        for voter in co_voters {
            votes.push(builders::finality_vote(&voter.keys, voter.device, &tbs)?);
        }
        votes.sort_by_key(|vote| (vote.signer_root_fingerprint, vote.signer_device_id));
        let request = wire_object(
            ArcWireObjectKind::AbortRequest,
            &ArcAbortRequest {
                core,
                receipt: sequenced.receipt,
                votes: TlsVec::new(votes)?,
            },
        )?;
        let conversation_token = base64url_encode(&bound.conversation);
        let label = binder.label();
        send_object(
            client,
            &label,
            &format!("EGROUP SUBMIT ABORT {conversation_token}"),
            &request,
        )?;
        let reply = labeled_reply(client, &label)?;
        let completion = std::slice::from_ref(only_completion(&reply, "ABORTED")?);
        assert_contains(
            completion,
            &format!(" EGROUP ABORTED {conversation_token} "),
        )?;
        assert_eq!(hash_at(completion, "ABORTED", 4)?, sequenced.candidate_id);
        assert_eq!(hash_at(completion, "ABORTED", 5)?, abort_id);
        completion
            .first()
            .cloned()
            .ok_or_else(|| failure("no labeled ABORTED completion"))
    }

    /// Sequences `commit` as the candidate of `bound`, acknowledges it, and
    /// finalizes it with the votes of the binder and `co_voters` under
    /// `old_policy_id` (companion 12.1 to 12.4). The binder acknowledges
    /// with the fixed public-envelope leaf key.
    // agenc-review: allow owner=tests reviewed=2026-09-04 reason=one certification names the client the binder its co-voters the conversation the commit the prior position both policies and the rule together
    #[allow(clippy::too_many_arguments)]
    pub(super) fn certify_commit(
        client: &mut ArcClient,
        binder: &mut Principal,
        co_voters: &[&Principal],
        bound: &BoundConversation,
        commit: &[u8],
        prior: (u64, [u8; 32]),
        policies: ([u8; 32], [u8; 32]),
        transition: close_authority::CertificationTransition,
    ) -> TestResult<Certified> {
        certify_commit_with_leaf(
            client,
            binder,
            co_voters,
            bound,
            commit,
            prior,
            policies,
            transition,
            &OldLeaf::binder_default(),
        )
    }

    /// Like [`certify_commit`], with the acknowledging old leaf named
    /// explicitly, so a real MLS endpoint attests to and signs for the exact
    /// leaf its library holds.
    // agenc-review: allow owner=tests reviewed=2026-09-17 reason=one certification names the client the binder its co-voters the conversation the commit the prior position both policies the rule and the acknowledging old leaf together
    #[allow(clippy::too_many_arguments)]
    pub(super) fn certify_commit_with_leaf(
        client: &mut ArcClient,
        binder: &mut Principal,
        co_voters: &[&Principal],
        bound: &BoundConversation,
        commit: &[u8],
        prior: (u64, [u8; 32]),
        policies: ([u8; 32], [u8; 32]),
        transition: close_authority::CertificationTransition,
        leaf: &OldLeaf,
    ) -> TestResult<Certified> {
        let sequenced = sequence_candidate(client, binder, bound, commit, prior.1)?;
        let (authorization, core) =
            certificate_core(bound, &sequenced, prior, policies, transition, binder)?;
        let ack = acknowledge(client, binder, bound, &sequenced, prior.0, leaf)?;
        finalize(
            client,
            binder,
            co_voters,
            bound,
            sequenced,
            authorization,
            core,
            ack,
        )
    }

    /// The openmls member: alice, the channel creator.
    pub(super) struct OpenMlsMember {
        pub(super) provider: OpenMlsRustCrypto,
        pub(super) signer: SignatureKeyPair,
        credential: CredentialWithKey,
        capabilities: Capabilities,
        lifetime: OpenMlsLifetime,
    }

    impl OpenMlsMember {
        pub(super) fn new(principal: &Principal, interval: (u64, u64)) -> TestResult<Self> {
            Self::build(
                principal,
                interval,
                SignatureKeyPair::new(
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
                )?,
            )
        }

        /// The same member holding the exact leaf signature key `seed` names,
        /// so the endpoint's leaf-membership proof and every ACK it signs
        /// carry the key its own MLS leaf advertises (companion 13.7.3).
        pub(super) fn with_leaf(
            principal: &Principal,
            interval: (u64, u64),
            seed: [u8; 32],
        ) -> TestResult<Self> {
            let public = builders::public(&Ed25519SecretKey::from_bytes(seed));
            Self::build(
                principal,
                interval,
                SignatureKeyPair::from_raw(
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
                    seed.to_vec(),
                    public.to_vec(),
                ),
            )
        }

        fn build(
            principal: &Principal,
            interval: (u64, u64),
            signer: SignatureKeyPair,
        ) -> TestResult<Self> {
            let provider = OpenMlsRustCrypto::default();
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

        pub(super) fn create_group(&self, group_id: &[u8; 32]) -> TestResult<MlsGroup> {
            Ok(MlsGroup::builder()
                .with_group_id(GroupId::from_slice(group_id))
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .use_ratchet_tree_extension(true)
                .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .with_capabilities(self.capabilities.clone())
                .lifetime(self.lifetime)
                .build(&self.provider, &self.signer, self.credential.clone())?)
        }

        /// A publishable KeyPackage of this member, carrying exactly the
        /// capabilities and lifetime its leaf authorization commits to.
        pub(super) fn key_package(&self) -> TestResult<Vec<u8>> {
            let bundle = OpenMlsKeyPackage::builder()
                .leaf_node_capabilities(self.capabilities.clone())
                .key_package_lifetime(self.lifetime)
                .build(
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    &self.provider,
                    &self.signer,
                    self.credential.clone(),
                )?;
            Ok(MlsMessageOut::from(bundle.key_package().clone()).to_bytes()?)
        }

        /// Joins the group a delivered Welcome names.
        pub(super) fn join(&self, welcome: &[u8]) -> TestResult<MlsGroup> {
            let message = MlsMessageIn::tls_deserialize_exact(welcome)?;
            let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
                return Err(failure("the delivered object is not a welcome"));
            };
            let staged = StagedWelcome::new_from_welcome(
                &self.provider,
                &MlsGroupJoinConfig::default(),
                welcome,
                None,
            )?;
            Ok(staged.into_group(&self.provider)?)
        }

        pub(super) fn import_key_package(&self, bytes: &[u8]) -> TestResult<OpenMlsKeyPackage> {
            let message = MlsMessageIn::tls_deserialize_exact(bytes)?;
            let MlsMessageBodyIn::KeyPackage(package) = message.extract() else {
                return Err(failure("the claimed object is not a key package"));
            };
            Ok(package.validate(self.provider.crypto(), ProtocolVersion::Mls10)?)
        }

        pub(super) fn decrypt(
            &self,
            group: &mut MlsGroup,
            bytes: &[u8],
        ) -> TestResult<(Vec<u8>, Vec<u8>)> {
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
    pub(super) fn mls_rs_client(
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
        mls_rs_client_from(principal, interval, crypto, secret, public)
    }

    /// The mls-rs member holding the exact leaf signature key `seed` names.
    /// mls-rs stores an Ed25519 secret as the seed followed by its public
    /// key, so the endpoint and the companion objects share one key.
    pub(super) fn mls_rs_client_with_leaf(
        principal: &Principal,
        interval: (u64, u64),
        seed: [u8; 32],
    ) -> TestResult<Client<impl MlsConfig + use<>>> {
        let crypto = RustCryptoProvider::with_enabled_cipher_suites(vec![
            RsSuite::CURVE25519_AES128,
            RsSuite::CURVE25519_CHACHA,
        ]);
        let public = builders::public(&Ed25519SecretKey::from_bytes(seed));
        let mut secret = seed.to_vec();
        secret.extend_from_slice(&public);
        mls_rs_client_from(
            principal,
            interval,
            crypto,
            secret.into(),
            public.to_vec().into(),
        )
    }

    fn mls_rs_client_from(
        principal: &Principal,
        interval: (u64, u64),
        crypto: RustCryptoProvider,
        secret: RsSecretKey,
        public: RsPublicKey,
    ) -> TestResult<Client<impl MlsConfig + use<>>> {
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
    pub(super) fn publish_package(
        client: &mut ArcClient,
        owner: &mut Principal,
        package: &[u8],
        expires_at: u64,
    ) -> TestResult<Vec<u8>> {
        let object = raw_object(ArcWireObjectKind::KeyPackageMls, package.to_vec())?;
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
    pub(super) fn claim_package(
        client: &mut ArcClient,
        claimant: &mut Principal,
        target: &Principal,
    ) -> TestResult<Vec<u8>> {
        claim_package_with(client, claimant, target, [77; 16])
    }

    /// Claims one package of `target` under the claim nonce `nonce`, so a
    /// second claim for the same device is a distinct request. The claimant
    /// then asks `CLAIM STATUS` for the same operation, as after a lost
    /// reply, and receives the stored result of the claim: the target's
    /// device, reference and object, not its own device (companion 11.6).
    pub(super) fn claim_package_with(
        client: &mut ArcClient,
        claimant: &mut Principal,
        target: &Principal,
        nonce: [u8; 16],
    ) -> TestResult<Vec<u8>> {
        let label = claimant.label();
        client.send(&format!(
            "@label={label} EKEY CLAIM PACKAGE {} {} {SUITE} {}",
            base64url_encode(&target.account),
            target.device_token(),
            base64url_encode(&nonce)
        ))?;
        let reply = labeled_reply(client, &label)?;
        assert_contains(&reply, " EKEY CLAIMED ")?;
        let claimed = claimed_words(&reply)?;
        assert_eq!(claimed.get(3), Some(&target.device_token()), "{claimed:?}");
        let object = batch_object(&reply)?;
        let label = claimant.label();
        client.send(&format!(
            "@label={label} EKEY CLAIM STATUS {}",
            base64url_encode(&nonce)
        ))?;
        let status = labeled_reply(client, &label)?;
        assert_eq!(claimed_words(&status)?, claimed, "{status:?}");
        assert_eq!(batch_object(&status)?, object);
        mls_body(&object, ArcWireObjectKind::KeyPackageMls)
    }

    /// The words of the `EKEY CLAIMED` metadata line of a claim reply.
    pub(super) fn claimed_words(reply: &[String]) -> TestResult<Vec<String>> {
        reply
            .iter()
            .map(|line| words(line))
            .find(|words| {
                words.get(1).is_some_and(|word| word == "EKEY")
                    && words.get(2).is_some_and(|word| word == "CLAIMED")
            })
            .ok_or_else(|| failure(format!("no EKEY CLAIMED line in {reply:?}")))
    }

    /// Delivers `welcome` to `target` under the finalization that added it,
    /// fetches it from the target's mailbox, and returns the Welcome bytes.
    // agenc-review: allow owner=tests reviewed=2026-09-04 reason=one delivery names both clients both principals the conversation the certification the package reference and the welcome together
    #[allow(clippy::too_many_arguments)]
    pub(super) fn deliver_welcome(
        sender: &mut ArcClient,
        sender_keys: &mut Principal,
        receiver: &mut ArcClient,
        target: &mut Principal,
        bound: &BoundConversation,
        certified: &Certified,
        key_package_ref: &[u8],
        welcome: &[u8],
    ) -> TestResult<Vec<u8>> {
        let delivered = ArcDeliveredWelcome {
            profile_version: 1,
            network_id: *NETWORK_ID.as_bytes(),
            conversation_id: bound.conversation,
            target_account_id_digest: account_id_digest(NETWORK_ID.as_bytes(), &target.account)?,
            target_device_id: [target.device; 16],
            authorization: ArcNormalJoinAuthorizationProof {
                finalization_id: certified.finalization_id,
                finalization_object_id: certified.record_id,
                added_key_package_ref: Opaque::new(key_package_ref.to_vec())?,
                resulting_leaf_index: 1,
                resulting_leaf_credential_hash: [0; 32],
            },
            transition_proofs: ArcJoinTransitionProofBundle {
                references: TlsVec::new(Vec::new())?,
            },
            welcome_bytes: Opaque::new(welcome.to_vec())?,
        };
        let object = wire_object(ArcWireObjectKind::WelcomeMls, &delivered)?;
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
    pub(super) fn relay_application(
        sender: &mut ArcClient,
        sender_keys: &mut Principal,
        receiver: &mut ArcClient,
        bound: &BoundConversation,
        mls_bytes: &[u8],
    ) -> TestResult<Vec<u8>> {
        let object = raw_object(ArcWireObjectKind::ApplicationMls, mls_bytes.to_vec())?;
        let label = sender_keys.label();
        send_object(sender, &label, &bound.application_command(), &object)?;
        let echo = labeled_reply(sender, &label)?;
        assert_eq!(fragments_object(&echo)?, object);
        let forwarded = receive_application(receiver, bound)?;
        assert_eq!(forwarded, object);
        mls_body(&forwarded, ArcWireObjectKind::ApplicationMls)
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
            &ArcGroupGenesisTbs {
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
                &[&bob_keys],
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
        let observed = ArcEncryptedContent::decode_checked(&decrypted, &mut budget)?;
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

        require_recorded(&RULES)?;
        Ok(())
    }
}
