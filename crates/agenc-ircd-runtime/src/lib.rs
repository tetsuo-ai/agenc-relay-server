#![forbid(unsafe_code)]

//! Supervision, listeners, state ownership, and bounded queue plumbing.

use agenc_ircd_storage::{RecoveredStorageState, StorageError, StorageOwner, TableId};

/// Durable startup facts accepted before Stage 06 creates live runtime owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateCoreSeed {
    storage: RecoveredStorageState,
}

impl StateCoreSeed {
    /// Constructs a seed only from a storage owner that completed recovery.
    pub fn from_storage(owner: &StorageOwner) -> Result<Self, StorageError> {
        let storage = *owner.recovered_state();
        if storage.table_record_count(TableId::KeyCheck) != 1
            || storage.table_record_count(TableId::StateMeta) != 1
            || storage.table_record_count(TableId::LoginIndexKeyState) != 1
            || storage.table_record_count(TableId::StorageConstruction) != 0
        {
            return Err(StorageError::StaleState);
        }
        Ok(Self { storage })
    }

    /// Returns the authenticated state generation used to fence runtime plans.
    #[must_use]
    pub const fn state_generation(self) -> u64 {
        self.storage.state_generation()
    }

    /// Returns the authenticated account-service response count.
    #[must_use]
    pub const fn account_service_response_count(self) -> u64 {
        self.storage.account_service_response_count()
    }

    /// Borrows all reconstructed storage facts.
    #[must_use]
    pub const fn storage(&self) -> &RecoveredStorageState {
        &self.storage
    }
}
