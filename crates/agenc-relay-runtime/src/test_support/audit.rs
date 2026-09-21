//! The audit tests read the same sealed owner the live fixture reconstructed.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::HeadCounters;
use agenc_relay_admin::MaintenanceAuditScope;
use agenc_relay_crypto::DatabaseBinding;
use agenc_relay_storage::StoragePort;

pub(crate) struct AuditFixtureSource {
    pub(crate) scope: MaintenanceAuditScope,
    pub(crate) keys: KeyDeriver,
    pub(crate) storage: StoragePort,
    pub(crate) head: HeadCounters,
}

impl StateCoreFixture {
    /// Drops the idle core and actually closes/reopens the sealed storage owner.
    pub(crate) fn audit_reopen(&mut self) -> TestResult {
        drop(self.state.take());
        drop(self.storage_receivers.take());
        drop(self.crypto_completions.take());
        self.owner
            .take()
            .ok_or("storage owner was taken")?
            .shutdown()?;
        let qualification = signed_test_qualification(StateDirectory::probe(&self._directory.0)?)?;
        self.owner = Some(open_test_storage(
            &self.identity,
            &self._directory,
            &qualification,
        )?);
        Ok(())
    }

    /// Uses the authenticated database binding, never a replacement identity.
    pub(crate) fn audit_source(&self) -> TestResult<AuditFixtureSource> {
        let owner = self.owner.as_ref().ok_or("storage owner was taken")?;
        let recovered = owner.recovered_state();
        let database = recovered.database_binding();
        let scope = MaintenanceAuditScope::new(
            self.identity.network_id,
            self.identity.server_id,
            database.database_instance_id(),
            database.server_incarnation(),
            recovered.recovery_epoch(),
        );
        if database
            != DatabaseBinding::new(
                scope.network_id(),
                scope.server_id(),
                scope.server_incarnation(),
                scope.database_instance_id(),
            )
        {
            return Err("fixture identity differs from authenticated storage".into());
        }
        Ok(AuditFixtureSource {
            scope,
            keys: KeyDeriver::new(
                StorageMasterKey::from_bytes(STORAGE_MASTER),
                database,
                recovered.storage_key_generation(),
            )?,
            storage: owner.port(),
            head: HeadCounters::from_recovered(recovered),
        })
    }
}
