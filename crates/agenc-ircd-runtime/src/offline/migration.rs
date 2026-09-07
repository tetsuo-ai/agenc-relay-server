//! The schema-three migration always supplies the reviewed audit source policy.
#![forbid(unsafe_code)]

use agenc_ircd_admin::{AdminSessionBinding, OperatorRecord, OperatorRegistry};
use agenc_ircd_config::{MaintenanceStorageConfig, load_audit_trust_manifest};
use agenc_ircd_crypto::Ed25519PublicKey;
use agenc_ircd_storage::{
    MigrationCommandReceipt, MigrationCommandRequest, StorageQualification,
    execute_validated_migration_command,
};

use super::{LegacyAuditSourceValidator, OfflineError};

/// Runs the explicit schema-two-to-three profile with complete legacy audit admission.
pub fn execute_schema_three_migration(
    request: MigrationCommandRequest,
    config: &MaintenanceStorageConfig,
    qualifications: &[StorageQualification],
) -> Result<MigrationCommandReceipt, OfflineError> {
    if request.target_schema_generation != 3
        || request.network_id != config.network_id
        || request.server_id != config.server_id
    {
        return Err(OfflineError::InvalidRequest);
    }
    let mut validator = legacy_audit_source_validator(config)?;
    execute_validated_migration_command(request, qualifications, &mut validator)
        .map_err(|_| OfflineError::Storage)
}

pub(super) fn legacy_audit_source_validator(
    config: &MaintenanceStorageConfig,
) -> Result<LegacyAuditSourceValidator, OfflineError> {
    let trust = load_audit_trust_manifest(&config.audit_trust_manifest_file)
        .map_err(|_| OfflineError::Configuration)?;
    let mut records = Vec::with_capacity(config.operators.len());
    for operator in &config.operators {
        records.push(
            OperatorRecord::new(
                operator.operator_id,
                Ed25519PublicKey::from_bytes(operator.signing_public_key)
                    .map_err(|_| OfflineError::Configuration)?,
                operator.certificate_spki_sha256,
                operator.local_uids.clone(),
                operator.local_gids.clone(),
                operator.permissions,
                operator.enabled,
            )
            .map_err(|_| OfflineError::Configuration)?,
        );
    }
    let operators =
        OperatorRegistry::from_records(records).map_err(|_| OfflineError::Configuration)?;
    LegacyAuditSourceValidator::new(
        AdminSessionBinding {
            network_id: config.network_id,
            server_id: config.server_id,
        },
        &trust,
        operators,
    )
    .map_err(|_| OfflineError::Configuration)
}
