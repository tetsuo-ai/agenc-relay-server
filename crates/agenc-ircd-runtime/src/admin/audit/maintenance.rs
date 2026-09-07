//! The stopped driver owns one exact maintenance append until its durable receipt.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::HeadCounters;
use agenc_ircd_admin::{
    AuditEvent, MaintenanceAuditEvent, MaintenanceAuditEventTbs, MaintenanceAuditPosition,
    MaintenanceAuditScope, MaintenanceTransition,
};
use agenc_ircd_crypto::DatabaseBinding;
use agenc_ircd_storage::{CommitReceipt, RecordMutation, StorageMutationHead};
use agenc_ircd_types::TransactionId;

/// A single-use signed append and its exact expected receipt.
pub(crate) struct PreparedMaintenanceAudit {
    event: MaintenanceAuditEvent,
    cursor: AuditChainCursor,
    transaction_id: TransactionId,
    head: HeadCounters,
}

impl PreparedMaintenanceAudit {
    pub(crate) const fn event(&self) -> &MaintenanceAuditEvent {
        &self.event
    }

    pub(crate) fn mutation_head(&self) -> StorageMutationHead {
        StorageMutationHead {
            transaction_id: self.transaction_id,
            expected_storage_commit_sequence: self.head.storage_commit_sequence,
            expected_state_generation: self.head.state_generation,
            resulting_state_generation: self.event.tbs().position().resulting_state_generation(),
            state_advancing_plan_count: 1,
            expected_account_service_response_count: self.head.account_service_response_count,
            resulting_account_service_response_count: self.head.account_service_response_count,
        }
    }

    /// The driver may couple only this exact append with its key-state mutation.
    pub(crate) fn audit_mutation(&self) -> Result<RecordMutation, RuntimeError> {
        let sequence = self.event.tbs().position().audit_sequence();
        let revision = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
        let value = PersistentRecordValue::new(
            TableId::Audit,
            2,
            revision,
            0,
            None,
            Vec::new(),
            self.event
                .encode()
                .map_err(|_| RuntimeError::InvalidValue)?,
        )?;
        Ok(RecordMutation::put(
            TableId::Audit,
            StoredKey::new(sequence.to_be_bytes().to_vec())?,
            DOMAIN_RECORD_SCHEMA,
            None,
            value.encode()?,
        )?)
    }
}

pub(super) fn session_binding(
    scope: MaintenanceAuditScope,
    keys: &KeyDeriver,
) -> Result<AdminSessionBinding, RuntimeError> {
    let expected = DatabaseBinding::new(
        scope.network_id(),
        scope.server_id(),
        scope.server_incarnation(),
        scope.database_instance_id(),
    );
    if keys.binding() != expected {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(AdminSessionBinding {
        network_id: scope.network_id(),
        server_id: scope.server_id(),
    })
}

impl AuditAuthority {
    /// Prepares from the driver's authenticated current scope/head and complete key scan.
    pub(crate) fn prepare_maintenance_event(
        &self,
        scope: MaintenanceAuditScope,
        transition: MaintenanceTransition,
        head: HeadCounters,
        transaction_id: TransactionId,
        created_at: u64,
    ) -> Result<PreparedMaintenanceAudit, RuntimeError> {
        if !self.is_reconciled()
            || scope != self.scope
            || created_at < self.signing_not_before
            || created_at >= self.signing_not_after
        {
            return Err(RuntimeError::InvalidValue);
        }
        head.storage_commit_sequence
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        let resulting = head
            .state_generation
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        let position = MaintenanceAuditPosition::new(
            self.cursor.next_sequence,
            created_at,
            head.state_generation,
            resulting,
            self.cursor.previous_event_hash,
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
        let tbs = MaintenanceAuditEventTbs::new(scope, self.signing_key_id, position, transition)
            .map_err(|_| RuntimeError::InvalidValue)?;
        let event = MaintenanceAuditEvent::sign(tbs, &self.signing_key)
            .map_err(|_| RuntimeError::InvalidValue)?;
        Ok(PreparedMaintenanceAudit {
            event,
            cursor: self.cursor,
            transaction_id,
            head,
        })
    }

    /// Only the exact durable receipt may release this append into the audit cursor.
    pub(crate) fn commit_maintenance_event(
        &mut self,
        prepared: PreparedMaintenanceAudit,
        receipt: &CommitReceipt,
    ) -> Result<(), RuntimeError> {
        let result = self.validate_maintenance_receipt(&prepared, receipt);
        match result {
            Ok(next) => {
                self.cursor = next;
                Ok(())
            }
            Err(error) => {
                self.reconciled = false;
                Err(error)
            }
        }
    }

    fn validate_maintenance_receipt(
        &self,
        prepared: &PreparedMaintenanceAudit,
        receipt: &CommitReceipt,
    ) -> Result<AuditChainCursor, RuntimeError> {
        let event = &prepared.event;
        if !self.is_reconciled()
            || self.cursor != prepared.cursor
            || receipt.transaction_id != prepared.transaction_id
            || Some(receipt.storage_commit_sequence)
                != prepared.head.storage_commit_sequence.checked_add(1)
            || receipt.state_generation != event.tbs().position().resulting_state_generation()
            || event.tbs().audit_signing_key_id() != self.signing_key_id
            || event.tbs().position().created_at() < self.signing_not_before
            || event.tbs().position().created_at() >= self.signing_not_after
        {
            return Err(RuntimeError::InvalidValue);
        }
        event
            .verify_scope(self.scope, self.signing_key.public_key())
            .map_err(|_| RuntimeError::InvalidValue)?;
        self.cursor
            .advance_event(&AuditEvent::Maintenance(event.clone()))
            .map_err(|_| RuntimeError::InvalidValue)
    }
}
