//! The stopped-daemon maintenance projection of the full configuration.

use std::path::{Path, PathBuf};

use agenc_ircd_types::{NetworkId, ServerId};

use crate::bounds::DEFAULT_REDB_CACHE_BYTES;
use crate::config::{Config, ValidationDepth, load_config};
use crate::error::ConfigError;

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

impl From<&Config> for MaintenanceStorageConfig {
    fn from(config: &Config) -> Self {
        let storage = &config.storage;
        Self {
            network_id: config.network.network_id,
            server_id: config.server.server_id,
            state_directory: storage.state_dir.clone(),
            storage_master_key_file: storage.master_key_file.clone(),
            rollback_guard_key_file: storage.rollback_guard_key_file.clone(),
            login_index_key_file: storage.login_index_key_file.clone(),
            login_index_previous_key_file: storage.login_index_previous_key_file.clone(),
            backup_trust_manifest_file: storage.backup_trust_manifest_file.clone(),
            redb_cache_bytes: DEFAULT_REDB_CACHE_BYTES,
            fixed_reserve_bytes: storage.disk_reserve_bytes,
            reserve_percent: storage.disk_reserve_percent,
            database_max_bytes: storage.database_max_bytes,
            backup_max_bytes: storage.backup_max_bytes,
            integrity_checkpoint_manifests: storage.integrity_checkpoint_manifests,
        }
    }
}

/// Parses the closed configuration and returns only stopped-daemon storage fields.
pub fn load_maintenance_config(path: &Path) -> Result<MaintenanceStorageConfig, ConfigError> {
    load_config(path, ValidationDepth::Document)
        .map(|config| MaintenanceStorageConfig::from(&config))
        .map_err(|report| report.first_error())
}
