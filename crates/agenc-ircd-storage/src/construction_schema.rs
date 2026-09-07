//! Closed target generations for stopped construction, never service admission.
#![forbid(unsafe_code)]

use crate::StorageError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConstructionSchema {
    Two,
    Three,
}

impl ConstructionSchema {
    pub(crate) fn from_generation(generation: u64) -> Result<Self, StorageError> {
        match generation {
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            _ => Err(StorageError::UnsupportedVersion),
        }
    }

    pub(crate) const fn generation(self) -> u64 {
        match self {
            Self::Two => 2,
            Self::Three => 3,
        }
    }

    pub(crate) fn header(
        self,
        source: &crate::DatabaseHeaderTbs,
        instance: agenc_ircd_types::DatabaseId,
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
