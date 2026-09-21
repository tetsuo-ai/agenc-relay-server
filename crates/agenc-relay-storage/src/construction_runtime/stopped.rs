//! Authenticated staging access for explicitly selected offline target schemas.
#![forbid(unsafe_code)]

use super::{ConstructionSourceDatabase, ConstructionTarget};
use crate::construction_schema::ConstructionSchema;
use crate::engine::StorageEngine;
use crate::{ConstructionAdmission, DatabaseHeader, StorageError, StorageOpenConfig};

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
}

impl ConstructionTarget {
    /// The returned staging owner already has a validated construction marker; every
    /// target transaction it runs is gated by `admission`.
    pub(crate) fn open_stopped(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
        admission: ConstructionAdmission,
    ) -> Result<Self, StorageError> {
        let engine = Self::open_marked_stopped(config, schema)?;
        Ok(Self { engine, admission })
    }

    /// Reads the header of a staging database that still carries a validated marker,
    /// without taking write authority over it.
    pub(crate) fn marker_header_stopped(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<DatabaseHeader, StorageError> {
        Self::open_marked_stopped(config, schema).map(|engine| engine.construction_source_header())
    }

    fn open_marked_stopped(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<StorageEngine, StorageError> {
        let engine = StorageEngine::open_construction_target(config, schema)?;
        let marker = engine.construction_scan()?;
        marker.identity.validate()?;
        if marker.identity.target_schema_generation != schema.generation() {
            return Err(StorageError::ResumeMismatch);
        }
        Ok(engine)
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
