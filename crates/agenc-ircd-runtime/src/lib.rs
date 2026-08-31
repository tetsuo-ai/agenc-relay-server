#![forbid(unsafe_code)]

//! Supervision, listeners, state ownership, and bounded queue plumbing.
//!
//! The foundation modules in this crate define the ownership boundaries that
//! Architecture section 21 fixes for the single-node runtime: one process-wide
//! memory budget with RAII permits, cancellation tokens for the supervised
//! task tree, the client sink contract, the StateCore inbox, the storage and
//! crypto bridge messages, and the closed log event registry.

mod account_service;
mod admin;
pub mod admission;
pub mod bridge;
pub mod budget;
pub mod cancel;
pub mod channels;
mod client_render;
pub mod clock;
mod command_convert;
pub mod connection;
pub mod daemon;
mod error;
pub mod listener;
mod mutation_render;
pub mod observe;
pub mod offline;
pub mod purpose;
mod query_render;
pub mod registration;
pub mod runtime_config;
pub mod state_core;
pub mod supervisor;
mod sync;
pub mod tls;

pub use error::RuntimeError;

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
