#![forbid(unsafe_code)]

//! Strict configuration parsing and host-policy validation.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use agenc_ircd_types::{NetworkId, ServerId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use toml::{Table, Value};

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MIN_STORAGE_BYTES: u64 = 1_073_741_824;
const MAX_STORAGE_BYTES: u64 = 1_099_511_627_776;
const MIN_DISK_RESERVE_BYTES: u64 = 67_108_864;
const MIN_CHECKPOINT_MANIFESTS: u64 = 10_000;
const MAX_CHECKPOINT_MANIFESTS: u64 = 1_000_000;
const DEFAULT_REDB_CACHE_BYTES: usize = 67_108_864;

const ROOT_KEYS: &[&str] = &[
    "accounts",
    "config_version",
    "e2ee",
    "federation",
    "limits",
    "listeners",
    "moderation",
    "network",
    "privacy",
    "server",
    "storage",
    "tls",
];
const NETWORK_KEYS: &[&str] = &[
    "coordinator_server_id",
    "display_name",
    "dns_name",
    "dns_port",
    "network_id",
    "onion_address",
    "onion_port",
    "onion_tls_spki_sha256",
    "role",
];
const SERVER_KEYS: &[&str] = &[
    "crypto_worker_threads",
    "data_dir",
    "drain_seconds",
    "flush_seconds",
    "memory_budget_bytes",
    "name",
    "quiesce_seconds",
    "require_locked_secrets",
    "runtime_dir",
    "server_id",
    "stop_seconds",
    "tokio_worker_threads",
];
const LISTENERS_KEYS: &[&str] = &["endpoint"];
const LISTENER_KEYS: &[&str] = &[
    "allow_missing_origin",
    "allowed_gids",
    "allowed_origins",
    "allowed_uids",
    "bind",
    "client_ca_file",
    "enabled",
    "max_connections",
    "name",
    "purpose",
    "tls_certificate_file",
    "tls_private_key_file",
];
const TLS_KEYS: &[&str] = &[
    "group_policy",
    "require_ocsp_staple",
    "session_tickets",
    "ticket_lifetime_seconds",
    "ticket_rotation_seconds",
];
const FEDERATION_KEYS: &[&str] = &[
    "connect_timeout_seconds",
    "enabled",
    "max_peers",
    "peer",
    "private_ca_file",
    "reconnect_max_seconds",
    "signing_private_key_file",
    "tor_socks_endpoint",
];
const FEDERATION_PEER_KEYS: &[&str] = &[
    "certificate_spki_sha256",
    "enabled",
    "endpoints",
    "recovery_epoch",
    "role",
    "server_id",
    "server_name",
    "signing_public_key",
];
const STORAGE_KEYS: &[&str] = &[
    "backup_dir",
    "backup_max_bytes",
    "backup_signing_private_key_file",
    "backup_trust_manifest_file",
    "database_max_bytes",
    "disk_reserve_bytes",
    "disk_reserve_percent",
    "integrity_checkpoint_manifests",
    "login_index_key_file",
    "login_index_previous_key_file",
    "master_key_file",
    "rollback_guard_key_file",
    "state_dir",
];
const ACCOUNTS_KEYS: &[&str] = &[
    "accept_clients",
    "access_token_key_file",
    "account_service_hpke_private_key_file",
    "account_service_hpke_public_key",
    "allow_guests",
    "auth_transaction_seconds",
    "create_transaction_seconds",
    "credential_change_transaction_seconds",
    "default_allow_guest_dm",
    "default_direct_messages",
    "default_public_presence",
    "invite_verification_key_file",
    "max_contacts",
    "max_reserved_nicknames",
    "opaque_fake_credential_key_file",
    "opaque_server_setup_file",
    "registration",
];
const LIMIT_KEYS: &[&str] = &[
    "base_outbox_bytes_per_edge",
    "base_outbox_objects_per_edge",
    "channel_key_jobs",
    "channels_per_session",
    "client_connections",
    "client_control_output_bytes",
    "client_output_bytes",
    "direct_connections_per_address",
    "federation_output_bytes",
    "global_channels",
    "invites_global",
    "invites_per_channel",
    "invites_per_principal",
    "local_channels",
    "members_per_channel",
    "opaque_jobs",
    "parsed_arena_bytes",
    "query_snapshot_bytes_global",
    "query_snapshot_rows",
    "query_snapshot_rows_global",
    "query_snapshots_per_session",
    "rate",
    "requests_per_connection",
    "response_batch_bytes",
    "response_batches_per_connection",
    "sessions_per_account",
    "tls_handshakes",
];
const RATE_NAMES: &[&str] = &[
    "account_creation",
    "account_message",
    "channel_key_attempt",
    "channel_message",
    "expensive_query",
    "guest_message",
    "new_direct",
    "new_onion",
    "opaque_attempt",
    "preauth_command",
    "registered_command",
    "tls_handshake",
];
const RATE_KEYS: &[&str] = &["burst", "refill_seconds", "refill_tokens"];
const PRIVACY_KEYS: &[&str] = &[
    "history_default",
    "history_enabled",
    "log_retention_hours",
    "motd_file",
    "public_info_file",
    "secret_lookup_floor_milliseconds",
    "whowas_records",
    "whowas_retention_seconds",
];
const MODERATION_KEYS: &[&str] = &[
    "account_sanction_days",
    "audit_retention_days",
    "audit_signing_private_key_file",
    "audit_trust_manifest_file",
    "free_reason_bytes",
    "session_sanction_hours",
];
const E2EE_KEYS: &[&str] = &[
    "coordinator_server_id",
    "directory_bytes_per_account",
    "enabled",
    "federation_peer_burst_bytes",
    "federation_peer_bytes_per_second",
    "global_disk_bytes",
    "mailbox_bytes_per_account",
    "max_devices_per_account",
    "max_group_leaves",
    "profile_version",
    "sequencer_credentials_file",
    "sequencer_private_key_file",
    "stored_bytes_per_conversation",
];

/// Stable failures returned while parsing maintenance configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The file could not be opened, was not a protected regular file, or exceeded its limit.
    FileRejected,
    /// TOML syntax or the closed table shape was invalid.
    InvalidDocument,
    /// A required value was absent or had the wrong TOML type.
    MissingValue,
    /// A scalar or cross-field storage constraint was invalid.
    InvalidValue,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FileRejected => "configuration file rejected",
            Self::InvalidDocument => "configuration document rejected",
            Self::MissingValue => "required configuration value missing",
            Self::InvalidValue => "configuration value rejected",
        })
    }
}

impl std::error::Error for ConfigError {}

/// Storage values required by stopped-daemon maintenance commands.
pub struct MaintenanceStorageConfig {
    /// Permanent network identity.
    pub network_id: NetworkId,
    /// Permanent local server identity.
    pub server_id: ServerId,
    /// Configured live state directory used for restore-boundary comparison.
    pub state_directory: PathBuf,
    /// Configured current storage master-key file.
    pub storage_master_key_file: PathBuf,
    /// Configured current rollback-guard root-key file.
    pub rollback_guard_key_file: PathBuf,
    /// Configured current login-index key file.
    pub login_index_key_file: PathBuf,
    /// Configured previous login-index key file during a transition.
    pub login_index_previous_key_file: Option<PathBuf>,
    /// Offline-authorized backup verification keys.
    pub backup_trust_manifest_file: PathBuf,
    /// Cache bytes used by the offline redb owner.
    pub redb_cache_bytes: usize,
    /// Fixed free-space reserve.
    pub fixed_reserve_bytes: u64,
    /// Percentage free-space reserve.
    pub reserve_percent: u8,
    /// Logical database ceiling.
    pub database_max_bytes: u64,
    /// Signed backup stream ceiling.
    pub backup_max_bytes: u64,
    /// Soft integrity checkpoint threshold.
    pub integrity_checkpoint_manifests: u64,
}

/// One validated row from the offline backup trust manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTrustManifestEntry {
    /// Claimed derived key identifier.
    pub key_id: [u8; 32],
    /// Canonical Ed25519 public key.
    pub ed25519_public_key: [u8; 32],
    /// Inclusive first accepted backup creation second.
    pub not_before: u64,
    /// Exclusive last accepted backup creation second.
    pub not_after: u64,
}

/// Parses the closed configuration and returns only stopped-daemon storage fields.
pub fn load_maintenance_config(path: &Path) -> Result<MaintenanceStorageConfig, ConfigError> {
    let text = read_protected_text(path, MAX_CONFIG_BYTES)?;
    parse_maintenance_config(&text)
}

/// Parses a protected canonical backup trust manifest.
pub fn load_backup_trust_manifest(
    path: &Path,
) -> Result<Vec<BackupTrustManifestEntry>, ConfigError> {
    let text = read_protected_text(path, MAX_CONFIG_BYTES)?;
    let root = text
        .parse::<Table>()
        .map_err(|_| ConfigError::InvalidDocument)?;
    require_exact_keys(&root, &["backup_trust_version", "key"])?;
    if require_u64(&root, "backup_trust_version")? != 1 {
        return Err(ConfigError::InvalidValue);
    }
    let rows = root
        .get("key")
        .and_then(Value::as_array)
        .ok_or(ConfigError::MissingValue)?;
    if rows.is_empty() || rows.len() > 1_024 {
        return Err(ConfigError::InvalidValue);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(rows.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    let mut key_ids = BTreeSet::new();
    for row in rows {
        let table = row.as_table().ok_or(ConfigError::InvalidDocument)?;
        require_exact_keys(
            table,
            &["ed25519_public_key", "key_id", "not_after", "not_before"],
        )?;
        let key_id = parse_base64url_32(require_string(table, "key_id")?)?;
        let ed25519_public_key = parse_base64url_32(require_string(table, "ed25519_public_key")?)?;
        let not_before = require_u64(table, "not_before")?;
        let not_after = require_u64(table, "not_after")?;
        if not_before >= not_after || !key_ids.insert(key_id) {
            return Err(ConfigError::InvalidValue);
        }
        entries.push(BackupTrustManifestEntry {
            key_id,
            ed25519_public_key,
            not_before,
            not_after,
        });
    }
    Ok(entries)
}

fn parse_maintenance_config(text: &str) -> Result<MaintenanceStorageConfig, ConfigError> {
    let root = text
        .parse::<Table>()
        .map_err(|_| ConfigError::InvalidDocument)?;
    require_exact_keys(&root, ROOT_KEYS)?;
    if require_u64(&root, "config_version")? != 1 {
        return Err(ConfigError::InvalidValue);
    }
    validate_closed_shape(&root)?;
    let identity = parse_maintenance_identity(&root)?;
    let limits = parse_maintenance_limits(require_table(&root, "storage")?)?;
    Ok(MaintenanceStorageConfig {
        network_id: identity.network_id,
        server_id: identity.server_id,
        state_directory: identity.state_directory,
        storage_master_key_file: identity.storage_master_key_file,
        rollback_guard_key_file: identity.rollback_guard_key_file,
        login_index_key_file: identity.login_index_key_file,
        login_index_previous_key_file: identity.login_index_previous_key_file,
        backup_trust_manifest_file: identity.backup_trust_manifest_file,
        redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
        fixed_reserve_bytes: limits.fixed_reserve_bytes,
        reserve_percent: limits.reserve_percent,
        database_max_bytes: limits.database_max_bytes,
        backup_max_bytes: limits.backup_max_bytes,
        integrity_checkpoint_manifests: limits.integrity_checkpoint_manifests,
    })
}

struct MaintenanceIdentity {
    network_id: NetworkId,
    server_id: ServerId,
    state_directory: PathBuf,
    storage_master_key_file: PathBuf,
    rollback_guard_key_file: PathBuf,
    login_index_key_file: PathBuf,
    login_index_previous_key_file: Option<PathBuf>,
    backup_trust_manifest_file: PathBuf,
}

fn parse_maintenance_identity(root: &Table) -> Result<MaintenanceIdentity, ConfigError> {
    let network = require_table(root, "network")?;
    let server = require_table(root, "server")?;
    let storage = require_table(root, "storage")?;
    let network_id = NetworkId::parse(require_string(network, "network_id")?)
        .map_err(|_| ConfigError::InvalidValue)?;
    let server_id = ServerId::parse(require_string(server, "server_id")?)
        .map_err(|_| ConfigError::InvalidValue)?;
    let data_dir = require_absolute_path(server, "data_dir")?;
    let state_dir = require_absolute_path(storage, "state_dir")?;
    if !state_dir.starts_with(&data_dir) || state_dir == data_dir {
        return Err(ConfigError::InvalidValue);
    }
    let login_index_key_file = require_absolute_path(storage, "login_index_key_file")?;
    let storage_master_key_file = require_absolute_path(storage, "master_key_file")?;
    let rollback_guard_key_file = require_absolute_path(storage, "rollback_guard_key_file")?;
    let login_index_previous_key_file =
        optional_absolute_path(storage, "login_index_previous_key_file")?;
    let backup_trust_manifest_file = require_absolute_path(storage, "backup_trust_manifest_file")?;
    Ok(MaintenanceIdentity {
        network_id,
        server_id,
        state_directory: state_dir,
        storage_master_key_file,
        rollback_guard_key_file,
        login_index_key_file,
        login_index_previous_key_file,
        backup_trust_manifest_file,
    })
}

struct MaintenanceLimits {
    fixed_reserve_bytes: u64,
    reserve_percent: u8,
    database_max_bytes: u64,
    backup_max_bytes: u64,
    integrity_checkpoint_manifests: u64,
}

fn parse_maintenance_limits(storage: &Table) -> Result<MaintenanceLimits, ConfigError> {
    let database_max_bytes = integer_or_default(
        storage,
        "database_max_bytes",
        85_899_345_920,
        MIN_STORAGE_BYTES,
        MAX_STORAGE_BYTES,
    )?;
    let backup_max_bytes = integer_or_default(
        storage,
        "backup_max_bytes",
        107_374_182_400,
        MIN_STORAGE_BYTES,
        MAX_STORAGE_BYTES,
    )?;
    if database_max_bytes > backup_max_bytes {
        return Err(ConfigError::InvalidValue);
    }
    let fixed_reserve_bytes = integer_or_default(
        storage,
        "disk_reserve_bytes",
        1_073_741_824,
        MIN_DISK_RESERVE_BYTES,
        MAX_STORAGE_BYTES,
    )?;
    let reserve_percent = u8::try_from(integer_or_default(
        storage,
        "disk_reserve_percent",
        5,
        1,
        25,
    )?)
    .map_err(|_| ConfigError::InvalidValue)?;
    let integrity_checkpoint_manifests = integer_or_default(
        storage,
        "integrity_checkpoint_manifests",
        100_000,
        MIN_CHECKPOINT_MANIFESTS,
        MAX_CHECKPOINT_MANIFESTS,
    )?;
    Ok(MaintenanceLimits {
        fixed_reserve_bytes,
        reserve_percent,
        database_max_bytes,
        backup_max_bytes,
        integrity_checkpoint_manifests,
    })
}

fn validate_closed_shape(root: &Table) -> Result<(), ConfigError> {
    for (name, keys) in [
        ("network", NETWORK_KEYS),
        ("server", SERVER_KEYS),
        ("listeners", LISTENERS_KEYS),
        ("tls", TLS_KEYS),
        ("federation", FEDERATION_KEYS),
        ("storage", STORAGE_KEYS),
        ("accounts", ACCOUNTS_KEYS),
        ("limits", LIMIT_KEYS),
        ("privacy", PRIVACY_KEYS),
        ("moderation", MODERATION_KEYS),
        ("e2ee", E2EE_KEYS),
    ] {
        require_exact_or_optional_keys(require_table(root, name)?, keys)?;
    }
    validate_table_array(
        require_table(root, "listeners")?,
        "endpoint",
        LISTENER_KEYS,
        1,
        16,
    )?;
    validate_table_array(
        require_table(root, "federation")?,
        "peer",
        FEDERATION_PEER_KEYS,
        0,
        64,
    )?;
    let limits = require_table(root, "limits")?;
    if let Some(rate) = limits.get("rate") {
        let rate = rate.as_table().ok_or(ConfigError::InvalidDocument)?;
        require_exact_or_optional_keys(rate, RATE_NAMES)?;
        for value in rate.values() {
            let table = value.as_table().ok_or(ConfigError::InvalidDocument)?;
            require_exact_keys(table, RATE_KEYS)?;
        }
    }
    Ok(())
}

fn validate_table_array(
    parent: &Table,
    name: &str,
    allowed: &[&str],
    minimum: usize,
    maximum: usize,
) -> Result<(), ConfigError> {
    let Some(value) = parent.get(name) else {
        return if minimum == 0 {
            Ok(())
        } else {
            Err(ConfigError::MissingValue)
        };
    };
    let rows = value.as_array().ok_or(ConfigError::InvalidDocument)?;
    if !(minimum..=maximum).contains(&rows.len()) {
        return Err(ConfigError::InvalidValue);
    }
    for row in rows {
        require_exact_or_optional_keys(
            row.as_table().ok_or(ConfigError::InvalidDocument)?,
            allowed,
        )?;
    }
    Ok(())
}

fn read_protected_text(path: &Path, maximum: u64) -> Result<String, ConfigError> {
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::FileRejected);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ConfigError::FileRejected)?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
        || mode & 0o022 != 0
    {
        return Err(ConfigError::FileRejected);
    }
    fs::read_to_string(path).map_err(|_| ConfigError::FileRejected)
}

fn is_unsafe_component(component: Component<'_>) -> bool {
    matches!(component, Component::CurDir | Component::ParentDir)
}

fn require_table<'a>(table: &'a Table, name: &str) -> Result<&'a Table, ConfigError> {
    table
        .get(name)
        .and_then(Value::as_table)
        .ok_or(ConfigError::MissingValue)
}

fn require_string<'a>(table: &'a Table, name: &str) -> Result<&'a str, ConfigError> {
    table
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::MissingValue)
}

fn require_u64(table: &Table, name: &str) -> Result<u64, ConfigError> {
    let value = table
        .get(name)
        .and_then(Value::as_integer)
        .ok_or(ConfigError::MissingValue)?;
    u64::try_from(value).map_err(|_| ConfigError::InvalidValue)
}

fn integer_or_default(
    table: &Table,
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let value = match table.get(name) {
        Some(_) => require_u64(table, name)?,
        None => default,
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::InvalidValue);
    }
    Ok(value)
}

fn require_absolute_path(table: &Table, name: &str) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(require_string(table, name)?);
    if !path.is_absolute() || path.components().any(is_unsafe_component) {
        return Err(ConfigError::InvalidValue);
    }
    Ok(path)
}

fn optional_absolute_path(table: &Table, name: &str) -> Result<Option<PathBuf>, ConfigError> {
    match table.get(name) {
        None => Ok(None),
        Some(_) => require_absolute_path(table, name).map(Some),
    }
}

fn require_exact_keys(table: &Table, expected: &[&str]) -> Result<(), ConfigError> {
    if table.len() != expected.len() {
        return Err(ConfigError::InvalidDocument);
    }
    require_exact_or_optional_keys(table, expected)
}

fn require_exact_or_optional_keys(table: &Table, allowed: &[&str]) -> Result<(), ConfigError> {
    if table.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ConfigError::InvalidDocument);
    }
    Ok(())
}

fn parse_base64url_32(text: &str) -> Result<[u8; 32], ConfigError> {
    if text.len() != 43 {
        return Err(ConfigError::InvalidValue);
    }
    let mut bytes = [0_u8; 32];
    let decoded = URL_SAFE_NO_PAD
        .decode_slice(text, &mut bytes)
        .map_err(|_| ConfigError::InvalidValue)?;
    if decoded != bytes.len() || URL_SAFE_NO_PAD.encode(bytes) != text {
        return Err(ConfigError::InvalidValue);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn minimal_config() -> String {
        format!(
            r#"config_version = 1

[network]
network_id = "{}"

[server]
server_id = "{}"
data_dir = "/srv/agenc"

[listeners]
[[listeners.endpoint]]

[tls]
[federation]
[storage]
state_dir = "/srv/agenc/state"
master_key_file = "/etc/agenc/master.key"
rollback_guard_key_file = "/etc/agenc/guard.key"
login_index_key_file = "/etc/agenc/login.key"
backup_trust_manifest_file = "/etc/agenc/backup-trust.toml"

[accounts]
[limits]
[privacy]
[moderation]
[e2ee]
"#,
            NetworkId::from_bytes([1_u8; 32]).to_base64url(),
            ServerId::from_bytes([2_u8; 16]).to_base64url(),
        )
    }

    fn protected_file(contents: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "agenc-config-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let path = directory.join("input.toml");
        fs::write(&path, contents)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }

    fn remove_test_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        fs::remove_file(path)?;
        fs::remove_dir(path.parent().ok_or("test file has no parent")?)?;
        Ok(())
    }

    #[test]
    fn maintenance_projection_accepts_defaults_and_checked_overrides() -> Result<(), ConfigError> {
        let config = parse_maintenance_config(&minimal_config())?;
        assert_eq!(config.network_id, NetworkId::from_bytes([1_u8; 32]));
        assert_eq!(config.server_id, ServerId::from_bytes([2_u8; 16]));
        assert_eq!(config.redb_cache_bytes, DEFAULT_REDB_CACHE_BYTES);
        assert_eq!(config.reserve_percent, 5);
        assert_eq!(config.integrity_checkpoint_manifests, 100_000);

        let configured = minimal_config().replace(
            "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"",
            "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"\n\
             login_index_previous_key_file = \"/etc/agenc/previous.key\"\n\
             database_max_bytes = 1073741824\n\
             backup_max_bytes = 1073741825\n\
             disk_reserve_bytes = 67108864\n\
             disk_reserve_percent = 25\n\
             integrity_checkpoint_manifests = 10000",
        );
        let config = parse_maintenance_config(&configured)?;
        assert_eq!(config.database_max_bytes, 1_073_741_824);
        assert_eq!(config.backup_max_bytes, 1_073_741_825);
        assert_eq!(config.reserve_percent, 25);
        assert!(config.login_index_previous_key_file.is_some());
        Ok(())
    }

    #[test]
    fn maintenance_projection_rejects_shape_identity_path_and_limit_errors() {
        let base = minimal_config();
        for invalid in [
            base.replace("config_version = 1", "config_version = 2"),
            base.replace("[network]", "unknown = true\n\n[network]"),
            base.replace("network_id =", "network_id_typo ="),
            base.replace("/srv/agenc/state", "relative-state"),
            base.replace("/srv/agenc/state", "/srv/agenc"),
            base.replace(
                "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"",
                "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"\n\
                 database_max_bytes = 1073741825\nbackup_max_bytes = 1073741824",
            ),
            base.replace(
                "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"",
                "backup_trust_manifest_file = \"/etc/agenc/backup-trust.toml\"\n\
                 disk_reserve_percent = 0",
            ),
            base.replace("[[listeners.endpoint]]", ""),
            base.replace("[limits]", "[limits]\nrate = \"bad\""),
        ] {
            assert!(parse_maintenance_config(&invalid).is_err());
        }
    }

    #[test]
    fn protected_file_and_trust_manifest_enforce_permissions_and_canonical_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = URL_SAFE_NO_PAD.encode([3_u8; 32]);
        let manifest = format!(
            "backup_trust_version = 1\n\n[[key]]\nkey_id = \"{key}\"\n\
             ed25519_public_key = \"{key}\"\nnot_before = 10\nnot_after = 20\n"
        );
        let path = protected_file(&manifest)?;
        let entries = load_backup_trust_manifest(&path)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.first().ok_or(ConfigError::InvalidValue)?.not_before,
            10
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o622))?;
        assert_eq!(
            load_backup_trust_manifest(&path),
            Err(ConfigError::FileRejected)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, manifest.replace("not_after = 20", "not_after = 10"))?;
        assert_eq!(
            load_backup_trust_manifest(&path),
            Err(ConfigError::InvalidValue)
        );
        remove_test_file(&path)?;
        Ok(())
    }

    #[test]
    fn trust_manifest_rejects_duplicates_unknown_fields_and_noncanonical_base64()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = URL_SAFE_NO_PAD.encode([4_u8; 32]);
        let row = format!(
            "[[key]]\nkey_id = \"{key}\"\ned25519_public_key = \"{key}\"\n\
             not_before = 1\nnot_after = 2\n"
        );
        for manifest in [
            "backup_trust_version = 1\n".to_owned(),
            format!("backup_trust_version = 2\n{row}"),
            format!("backup_trust_version = 1\n{row}{row}"),
            format!("backup_trust_version = 1\n{row}unknown = 1\n"),
            format!(
                "backup_trust_version = 1\n[[key]]\nkey_id = \"short\"\n\
                 ed25519_public_key = \"{key}\"\nnot_before = 1\nnot_after = 2\n"
            ),
        ] {
            let path = protected_file(&manifest)?;
            assert!(load_backup_trust_manifest(&path).is_err());
            remove_test_file(&path)?;
        }
        Ok(())
    }

    #[test]
    fn maintenance_boundaries_reject_every_unsafe_file_and_collection_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = minimal_config();
        assert_eq!(
            parse_maintenance_config(&base.replace("/srv/agenc/state", "/srv/elsewhere/state"))
                .map(|_| ()),
            Err(ConfigError::InvalidValue)
        );

        assert_eq!(
            read_protected_text(Path::new("relative.toml"), MAX_CONFIG_BYTES),
            Err(ConfigError::FileRejected)
        );
        assert_eq!(
            read_protected_text(Path::new("/tmp/../unsafe.toml"), MAX_CONFIG_BYTES),
            Err(ConfigError::FileRejected)
        );

        let directory = protected_file("placeholder")?;
        let parent = directory
            .parent()
            .ok_or("protected test file has no parent")?
            .to_path_buf();
        fs::remove_file(&directory)?;
        assert_eq!(
            read_protected_text(&parent, MAX_CONFIG_BYTES),
            Err(ConfigError::FileRejected)
        );
        let oversized = parent.join("oversized.toml");
        let file = fs::File::create(&oversized)?;
        file.set_len(MAX_CONFIG_BYTES + 1)?;
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            read_protected_text(&oversized, MAX_CONFIG_BYTES),
            Err(ConfigError::FileRejected)
        );
        fs::remove_file(&oversized)?;
        fs::remove_dir(parent)?;

        let empty = protected_file("backup_trust_version = 1\nkey = []\n")?;
        assert_eq!(
            load_backup_trust_manifest(&empty),
            Err(ConfigError::InvalidValue)
        );
        remove_test_file(&empty)?;

        let key = URL_SAFE_NO_PAD.encode([5_u8; 32]);
        let row = format!(
            "{{ key_id = \"{key}\", ed25519_public_key = \"{key}\", not_before = 1, not_after = 2 }}"
        );
        let oversized_rows = format!(
            "backup_trust_version = 1\nkey = [{}]\n",
            std::iter::repeat_n(row, 1_025)
                .collect::<Vec<_>>()
                .join(",")
        );
        let oversized_manifest = protected_file(&oversized_rows)?;
        assert_eq!(
            load_backup_trust_manifest(&oversized_manifest),
            Err(ConfigError::InvalidValue)
        );
        remove_test_file(&oversized_manifest)?;

        assert_eq!(
            parse_base64url_32(&"!".repeat(43)),
            Err(ConfigError::InvalidValue)
        );
        Ok(())
    }
}
