//! Stopped restore supplies the same legacy audit policy as explicit migration.
#![forbid(unsafe_code)]

use agenc_ircd_config::MaintenanceStorageConfig;
use agenc_ircd_storage::{
    RestoreCommandReceipt, RestoreCommandRequest, StorageQualification,
    execute_validated_restore_command,
};

use super::OfflineError;

/// Restores only a fully admitted source under its unchanged schema generation.
pub fn execute_stopped_restore(
    request: RestoreCommandRequest,
    config: &MaintenanceStorageConfig,
    qualifications: &[StorageQualification],
) -> Result<RestoreCommandReceipt, OfflineError> {
    if request.network_id != config.network_id || request.server_id != config.server_id {
        return Err(OfflineError::InvalidRequest);
    }
    let mut validator = super::migration::legacy_audit_source_validator(config)?;
    execute_validated_restore_command(request, qualifications, &mut validator)
        .map_err(|_| OfflineError::Storage)
}
