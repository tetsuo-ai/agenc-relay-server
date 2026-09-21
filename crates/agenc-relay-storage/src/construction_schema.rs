//! Closed target generations for stopped construction, never service admission.
#![forbid(unsafe_code)]

use crate::StorageError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConstructionSchema {
    Five,
}

impl ConstructionSchema {
    pub(crate) fn from_generation(generation: u64) -> Result<Self, StorageError> {
        match generation {
            crate::SCHEMA_GENERATION => Ok(Self::Five),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }

    pub(crate) const fn generation(self) -> u64 {
        match self {
            Self::Five => crate::SCHEMA_GENERATION,
        }
    }

    pub(crate) fn header(
        self,
        source: &crate::DatabaseHeaderTbs,
        instance: agenc_relay_types::DatabaseId,
        key_generation: u32,
    ) -> Result<crate::DatabaseHeaderTbs, StorageError> {
        if key_generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(crate::DatabaseHeaderTbs {
            database_instance_id: instance,
            storage_key_generation: key_generation,
            schema_generation: self.generation(),
            ..*source
        })
    }
}
