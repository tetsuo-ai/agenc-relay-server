//! Authenticated offline opens with an explicit closed source or target profile.
#![forbid(unsafe_code)]

use super::{
    EngineOpenConfig, EngineStateDirectory, StorageEngine, StorageRuntimeLimits, storage_limit_pair,
};
use crate::construction_schema::ConstructionSchema;
use crate::{StorageError, StorageOpenConfig};

impl StorageEngine {
    pub(crate) fn open_construction_target(
        config: StorageOpenConfig,
        schema: ConstructionSchema,
    ) -> Result<Self, StorageError> {
        Self::open_stopped_generation(config, schema.generation())
    }

    fn open_stopped_generation(
        config: StorageOpenConfig,
        expected_schema_generation: u64,
    ) -> Result<Self, StorageError> {
        let initial = StorageRuntimeLimits::from_engine(config.limits)?;
        let (_writer, reader) = storage_limit_pair(initial);
        Self::open_authenticated(
            EngineOpenConfig {
                expected_schema_generation,
                expected_network_id: config.expected_network_id,
                expected_server_id: config.expected_server_id,
                state_directory: EngineStateDirectory::Writable(config.state_directory),
                storage_master_key: config.storage_master_key,
                rollback_guard_root_key: config.rollback_guard_root_key,
                login_index_key: config.login_index_key,
                previous_login_index_key: config.previous_login_index_key,
                limits: config.limits,
            },
            reader,
        )
    }
}
