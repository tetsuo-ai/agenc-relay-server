//! Mixed chains are tested through sealed storage and the real audit authority.
#![forbid(unsafe_code)]
#![cfg(test)]

mod chain;
mod export_profile;
mod export_refusal;
mod receipt;
mod refusal;
mod transport;

use super::*;
use crate::test_support::{StateCoreFixture, TestResult};
use agenc_ircd_admin::{
    AdminCommandTbs, AdminSessionId, MaintenanceAuditEvent, MaintenanceAuditEventTbs,
    MaintenanceAuditPosition, MaintenanceKeyState, MaintenanceOperation, MaintenanceTransition,
    OperatorRecord,
};
use agenc_ircd_storage::{
    CommitOutcome, CommitReceipt, InitialStorageRecord, StorageMutationBatch,
};
use agenc_ircd_types::{
    AdminPermission, AdminPermissionSet, DatabaseId, NetworkId, RecoveryEpoch, ServerId,
    ServerIncarnation,
};

struct Fixture {
    audit: Ed25519SecretKey,
    operator: Ed25519SecretKey,
    operator_id: OperatorId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            audit: Ed25519SecretKey::from_bytes([4; 32]),
            operator: Ed25519SecretKey::from_bytes([5; 32]),
            operator_id: OperatorId::from_bytes([6; 16]),
        }
    }

    fn scope(&self) -> MaintenanceAuditScope {
        MaintenanceAuditScope::new(
            NetworkId::from_bytes([31; 32]),
            ServerId::from_bytes([32; 16]),
            DatabaseId::from_bytes([38; 16]),
            ServerIncarnation::from_bytes([33; 16]),
            RecoveryEpoch::from_bytes([34; 16]),
        )
    }

    fn operators(&self) -> TestResult<OperatorRegistry> {
        let mut permissions = AdminPermissionSet::EMPTY;
        permissions.insert(AdminPermission::Observe);
        permissions.insert(AdminPermission::Audit);
        permissions.insert(AdminPermission::Configure);
        Ok(OperatorRegistry::from_records(vec![OperatorRecord::new(
            self.operator_id,
            self.operator.public_key(),
            None,
            vec![1_000],
            Vec::new(),
            permissions,
            true,
        )?])?)
    }

    fn trust(&self) -> TestResult<AuditTrustManifestEntry> {
        Ok(AuditTrustManifestEntry {
            key_id: *audit_signing_key_id(self.audit.public_key().as_bytes())?.as_bytes(),
            ed25519_public_key: *self.audit.public_key().as_bytes(),
            not_before: 1,
            not_after: 100,
        })
    }

    fn admin(
        &self,
        cursor: AuditChainCursor,
        phase: AdminAuditPhase,
        command: &[u8],
    ) -> TestResult<AuditEvent> {
        let scope = self.scope();
        let command_tbs = AdminCommandTbs::new(
            scope.network_id(),
            scope.server_id(),
            AdminSessionId::from_bytes([3; 16]),
            cursor.next_sequence,
            None,
            command,
        )?;
        let operator_signature = command_tbs.sign(&self.operator)?;
        Ok(AuditEvent::Admin(AdminAuditEvent::sign(
            AdminAuditEventTbs {
                network_id: scope.network_id(),
                server_id: scope.server_id(),
                audit_signing_key_id: self.trust()?.key_id,
                audit_sequence: cursor.next_sequence,
                created_at: 50,
                operator_id: self.operator_id,
                command_tbs,
                operator_signature,
                phase,
                previous_event_hash: cursor.previous_event_hash,
            },
            &self.audit,
        )?))
    }

    fn maintenance(
        &self,
        cursor: AuditChainCursor,
        created_at: u64,
        scope: MaintenanceAuditScope,
    ) -> TestResult<AuditEvent> {
        Ok(AuditEvent::Maintenance(MaintenanceAuditEvent::sign(
            MaintenanceAuditEventTbs::new(
                scope,
                self.trust()?.key_id,
                MaintenanceAuditPosition::new(
                    cursor.next_sequence,
                    created_at,
                    10,
                    11,
                    cursor.previous_event_hash,
                )?,
                transition()?,
            )?,
            &self.audit,
        )?))
    }

    fn chain(&self) -> TestResult<Vec<AuditEvent>> {
        let first = self.admin(
            AuditChainCursor::genesis(),
            AdminAuditPhase::Observed,
            b"MOTD",
        )?;
        // Original historical database facts must survive a current-scope reconstruction.
        let historical = MaintenanceAuditScope::new(
            self.scope().network_id(),
            self.scope().server_id(),
            DatabaseId::from_bytes([81; 16]),
            ServerIncarnation::from_bytes([82; 16]),
            RecoveryEpoch::from_bytes([83; 16]),
        );
        let second = self.maintenance(
            AuditChainCursor::genesis().advance_event(&first)?,
            49,
            historical,
        )?;
        let cursor = AuditChainCursor::genesis()
            .advance_event(&first)?
            .advance_event(&second)?;
        Ok(vec![
            first,
            second,
            self.admin(cursor, AdminAuditPhase::Observed, b"MOTD")?,
        ])
    }

    fn authority(&self, core: &StateCoreFixture) -> TestResult<AuditAuthority> {
        let source = core.audit_source()?;
        Ok(AuditAuthority::reconstruct(
            source.scope,
            Ed25519SecretKey::from_bytes([4; 32]),
            &[self.trust()?],
            source.storage,
            source.keys,
            &self.operators()?,
            60,
        )?)
    }
}

fn transition() -> TestResult<MaintenanceTransition> {
    Ok(MaintenanceTransition::new(
        MaintenanceOperation::LoginIndexRotateStart,
        MaintenanceKeyState::new(1, [11; 32], 0, [0; 32], 0)?,
        MaintenanceKeyState::new(2, [12; 32], 1, [11; 32], 7)?,
    )?)
}

fn records(events: &[AuditEvent]) -> TestResult<Vec<InitialStorageRecord>> {
    events
        .iter()
        .map(|event| {
            record(
                event,
                event.encoding(),
                event.audit_sequence(),
                event
                    .audit_sequence()
                    .checked_add(1)
                    .ok_or("audit revision")?,
            )
        })
        .collect()
}

fn record(
    event: &AuditEvent,
    kind: u16,
    sequence: u64,
    revision: u64,
) -> TestResult<InitialStorageRecord> {
    let value = PersistentRecordValue::new(
        TableId::Audit,
        kind,
        revision,
        0,
        None,
        Vec::new(),
        event.encode()?,
    )?;
    Ok(InitialStorageRecord::new(
        TableId::Audit,
        StoredKey::new(sequence.to_be_bytes().to_vec())?,
        DOMAIN_RECORD_SCHEMA,
        value.encode()?,
    )?)
}

fn core(events: &[AuditEvent]) -> TestResult<StateCoreFixture> {
    StateCoreFixture::with_registration_router_and_records(vec![7; 65_536], records(events)?)
}

fn commit(storage: &StoragePort, batch: StorageMutationBatch) -> TestResult<CommitReceipt> {
    match storage.try_commit(batch)?.wait()? {
        CommitOutcome::Committed(receipt) => Ok(receipt),
        CommitOutcome::Rejected(error) => Err(error.into()),
        CommitOutcome::Indeterminate => Err("indeterminate test commit".into()),
    }
}
