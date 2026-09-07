//! Authenticated staging access for explicitly selected offline target schemas.
#![forbid(unsafe_code)]

use super::{ConstructionSourceDatabase, ConstructionTarget};
use crate::construction_schema::ConstructionSchema;
use crate::engine::StorageEngine;
use crate::migration_profile::MigrationProfile;
use crate::{DatabaseHeader, StorageError, StorageOpenConfig};

impl ConstructionSourceDatabase {
    /// Authenticates the configured database under the already admitted source schema.
    /// This handle is used only for exact restore-boundary comparison.
    pub(crate) fn open_restore_boundary(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<Self, StorageError> {
        let engine = StorageEngine::open_construction_target(config, schema)?;
        let _capacity = engine.startup_scan()?;
        Ok(Self { engine })
    }

    pub(crate) fn open_migration_profile(
        config: StorageOpenConfig,
        profile: MigrationProfile,
    ) -> Result<Self, StorageError> {
        let engine = StorageEngine::open_migration_profile(config, profile)?;
        let _capacity = engine.startup_scan()?;
        Ok(Self { engine })
    }
}

impl ConstructionTarget {
    /// The returned staging owner already has a validated construction marker.
    pub(crate) fn open_stopped(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<Self, StorageError> {
        let engine = StorageEngine::open_construction_target(config, schema)?;
        let marker = engine.construction_scan()?;
        marker.identity.validate()?;
        if marker.identity.target_schema_generation != schema.generation() {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(Self { engine })
    }

    /// Header discovery gives no write owner or completion authorization.
    /// Installation still requires the complete expected operation identity.
    pub(crate) fn completed_header_stopped(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<DatabaseHeader, StorageError> {
        let engine = StorageEngine::open_construction_target(config, schema)?;
        let _capacity = engine.startup_scan()?;
        Ok(engine.construction_source_header())
    }
}
