//! The `[storage]` table (spec C.5 9008-9021, 9040-9064).

use std::path::PathBuf;

use toml::Table;

use crate::bounds::{
    BACKUP_MAX_BYTES, DATABASE_MAX_BYTES, DISK_RESERVE_BYTES, DISK_RESERVE_PERCENT,
    INTEGRITY_CHECKPOINT_MANIFESTS,
};
use crate::document::{check_keys, optional_unsigned, string};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::federation::optional_path;
use crate::paths::PathResolver;

pub(crate) const STORAGE_KEYS: &[&str] = &[
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

/// The validated `[storage]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageConfig {
    /// Dedicated mode-0700 state directory under `server.data_dir`.
    pub state_dir: PathBuf,
    /// Exact 32-byte storage master key file.
    pub master_key_file: PathBuf,
    /// Exact 32-byte rollback-guard root key file.
    pub rollback_guard_key_file: PathBuf,
    /// Exact 32-byte current login-index key file.
    pub login_index_key_file: PathBuf,
    /// Previous login-index key file, present only during a transition.
    pub login_index_previous_key_file: Option<PathBuf>,
    /// Dedicated backup directory.
    pub backup_dir: PathBuf,
    /// Dedicated Ed25519 backup-signing key file.
    pub backup_signing_private_key_file: PathBuf,
    /// Offline-authorized backup trust manifest.
    pub backup_trust_manifest_file: PathBuf,
    /// Logical live-state ceiling.
    pub database_max_bytes: u64,
    /// Signed backup stream ceiling.
    pub backup_max_bytes: u64,
    /// Fixed free-space reserve.
    pub disk_reserve_bytes: u64,
    /// Percentage free-space reserve.
    pub disk_reserve_percent: u8,
    /// Soft integrity checkpoint target.
    pub integrity_checkpoint_manifests: u64,
}

const TABLE: &str = "storage";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<StorageConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, STORAGE_KEYS))?;
    let paths = parse_paths(table, resolver, sink);
    let database_max_bytes = bounded(table, "database_max_bytes", DATABASE_MAX_BYTES, sink);
    let backup_max_bytes = bounded(table, "backup_max_bytes", BACKUP_MAX_BYTES, sink);
    let disk_reserve_bytes = bounded(table, "disk_reserve_bytes", DISK_RESERVE_BYTES, sink);
    let disk_reserve_percent = bounded(table, "disk_reserve_percent", DISK_RESERVE_PERCENT, sink)
        .and_then(|value| sink.field(key("disk_reserve_percent"), u8_value(value)));
    let integrity_checkpoint_manifests = bounded(
        table,
        "integrity_checkpoint_manifests",
        INTEGRITY_CHECKPOINT_MANIFESTS,
        sink,
    );
    let paths = paths?;
    Some(StorageConfig {
        state_dir: paths.state_dir,
        master_key_file: paths.master_key_file,
        rollback_guard_key_file: paths.rollback_guard_key_file,
        login_index_key_file: paths.login_index_key_file,
        login_index_previous_key_file: paths.login_index_previous_key_file,
        backup_dir: paths.backup_dir,
        backup_signing_private_key_file: paths.backup_signing_private_key_file,
        backup_trust_manifest_file: paths.backup_trust_manifest_file,
        database_max_bytes: database_max_bytes?,
        backup_max_bytes: backup_max_bytes?,
        disk_reserve_bytes: disk_reserve_bytes?,
        disk_reserve_percent: disk_reserve_percent?,
        integrity_checkpoint_manifests: integrity_checkpoint_manifests?,
    })
}

fn u8_value(value: u64) -> Result<u8, ConfigError> {
    u8::try_from(value).map_err(|_| ConfigError::InvalidValue)
}

struct StoragePaths {
    state_dir: PathBuf,
    master_key_file: PathBuf,
    rollback_guard_key_file: PathBuf,
    login_index_key_file: PathBuf,
    login_index_previous_key_file: Option<PathBuf>,
    backup_dir: PathBuf,
    backup_signing_private_key_file: PathBuf,
    backup_trust_manifest_file: PathBuf,
}

fn parse_paths(
    table: &Table,
    resolver: &PathResolver,
    sink: &mut IssueSink,
) -> Option<StoragePaths> {
    let mut required = |field: &'static str| {
        sink.field(
            SchemaKey::new(TABLE, field),
            string(table, field).and_then(|text| resolver.resolve(text)),
        )
    };
    let state_dir = required("state_dir");
    let master_key_file = required("master_key_file");
    let rollback_guard_key_file = required("rollback_guard_key_file");
    let login_index_key_file = required("login_index_key_file");
    let backup_dir = required("backup_dir");
    let backup_signing_private_key_file = required("backup_signing_private_key_file");
    let backup_trust_manifest_file = required("backup_trust_manifest_file");
    let login_index_previous_key_file = sink.field(
        SchemaKey::new(TABLE, "login_index_previous_key_file"),
        optional_path(table, "login_index_previous_key_file", resolver),
    );
    Some(StoragePaths {
        state_dir: state_dir?,
        master_key_file: master_key_file?,
        rollback_guard_key_file: rollback_guard_key_file?,
        login_index_key_file: login_index_key_file?,
        login_index_previous_key_file: login_index_previous_key_file?,
        backup_dir: backup_dir?,
        backup_signing_private_key_file: backup_signing_private_key_file?,
        backup_trust_manifest_file: backup_trust_manifest_file?,
    })
}

fn bounded(
    table: &Table,
    field: &'static str,
    bound: crate::scalar::Bound,
    sink: &mut IssueSink,
) -> Option<u64> {
    sink.field(
        SchemaKey::new(TABLE, field),
        optional_unsigned(table, field).and_then(|value| bound.resolve(value)),
    )
}
