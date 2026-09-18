//! Stopped restore of a verified current-format backup.
#![forbid(unsafe_code)]

use agenc_ircd_config::MaintenanceStorageConfig;
use agenc_ircd_storage::{
    FilesystemCause, RestoreCommandReceipt, RestoreCommandRequest, StorageError,
    StorageQualification, execute_restore_command,
};

use super::OfflineError;

/// Restores only a fully admitted source under its unchanged schema generation.
///
/// A free-space refusal is reported apart from every other storage failure: it wrote
/// nothing, and the same command with `--resume` continues once space is available.
pub fn execute_stopped_restore(
    request: RestoreCommandRequest,
    config: &MaintenanceStorageConfig,
    qualifications: &[StorageQualification],
) -> Result<RestoreCommandReceipt, OfflineError> {
    if request.network_id != config.network_id || request.server_id != config.server_id {
        return Err(OfflineError::InvalidRequest);
    }
    execute_restore_command(request, qualifications).map_err(|error| match error {
        StorageError::FilesystemRejected(FilesystemCause::InsufficientCapacity) => {
            OfflineError::InsufficientCapacity
        }
        _ => OfflineError::Storage,
    })
}
