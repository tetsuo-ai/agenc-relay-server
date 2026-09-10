//! Exact encoding-two signed facts for stopped maintenance.
#![forbid(unsafe_code)]

use super::{MaintenanceTransition, map_crypto};
use crate::AdminError;
use crate::codec::{Reader, Writer};
use agenc_ircd_crypto::maintenance_audit_event_hash;
use agenc_ircd_types::{DatabaseId, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

/// Exact maintenance TBS length, including its encoding discriminator.
pub const MAINTENANCE_AUDIT_TBS_BYTES: usize = 358;

/// Immutable historical identity of the database on which maintenance committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceAuditScope {
    network_id: NetworkId,
    server_id: ServerId,
    database_instance_id: DatabaseId,
    server_incarnation: ServerIncarnation,
    recovery_epoch: RecoveryEpoch,
}

impl MaintenanceAuditScope {
    /// Binds the original identities without substituting a replacement database scope.
    #[must_use]
    pub const fn new(
        network_id: NetworkId,
        server_id: ServerId,
        database_instance_id: DatabaseId,
        server_incarnation: ServerIncarnation,
        recovery_epoch: RecoveryEpoch,
    ) -> Self {
        Self {
            network_id,
            server_id,
            database_instance_id,
            server_incarnation,
            recovery_epoch,
        }
    }
    /// Returns the signed network identity.
    #[must_use]
    pub const fn network_id(self) -> NetworkId {
        self.network_id
    }
    /// Returns the signed server identity.
    #[must_use]
    pub const fn server_id(self) -> ServerId {
        self.server_id
    }
    /// Returns the original database identity.
    #[must_use]
    pub const fn database_instance_id(self) -> DatabaseId {
        self.database_instance_id
    }
    /// Returns the original server incarnation.
    #[must_use]
    pub const fn server_incarnation(self) -> ServerIncarnation {
        self.server_incarnation
    }
    /// Returns the original recovery epoch.
    #[must_use]
    pub const fn recovery_epoch(self) -> RecoveryEpoch {
        self.recovery_epoch
    }
}

/// Validated audit position and the single state-generation advance it records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceAuditPosition {
    audit_sequence: u64,
    created_at: u64,
    preceding_state_generation: u64,
    resulting_state_generation: u64,
    previous_event_hash: [u8; 32],
}

impl MaintenanceAuditPosition {
    /// Requires an available audit successor and exactly one state-generation advance.
    pub fn new(
        audit_sequence: u64,
        created_at: u64,
        preceding_state_generation: u64,
        resulting_state_generation: u64,
        previous_event_hash: [u8; 32],
    ) -> Result<Self, AdminError> {
        let value = Self {
            audit_sequence,
            created_at,
            preceding_state_generation,
            resulting_state_generation,
            previous_event_hash,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), AdminError> {
        if self.audit_sequence.checked_add(1).is_none()
            || self.preceding_state_generation.checked_add(1)
                != Some(self.resulting_state_generation)
            || (self.audit_sequence == 0 && self.previous_event_hash != [0; 32])
        {
            return Err(AdminError::Audit);
        }
        Ok(())
    }
    /// Returns the sequence in the shared gapless audit chain.
    #[must_use]
    pub const fn audit_sequence(self) -> u64 {
        self.audit_sequence
    }
    /// Returns the original Unix second.
    #[must_use]
    pub const fn created_at(self) -> u64 {
        self.created_at
    }
    /// Returns the state generation before maintenance.
    #[must_use]
    pub const fn preceding_state_generation(self) -> u64 {
        self.preceding_state_generation
    }
    /// Returns the state generation of the atomic receipt.
    #[must_use]
    pub const fn resulting_state_generation(self) -> u64 {
        self.resulting_state_generation
    }
    /// Returns the predecessor event hash.
    #[must_use]
    pub const fn previous_event_hash(self) -> [u8; 32] {
        self.previous_event_hash
    }
}

/// Complete validated maintenance TBS. No field carries operator or secret-key authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceAuditEventTbs {
    scope: MaintenanceAuditScope,
    audit_signing_key_id: [u8; 32],
    position: MaintenanceAuditPosition,
    transition: MaintenanceTransition,
}

impl MaintenanceAuditEventTbs {
    /// Combines validated transition facts and their historical commit position.
    pub fn new(
        scope: MaintenanceAuditScope,
        audit_signing_key_id: [u8; 32],
        position: MaintenanceAuditPosition,
        transition: MaintenanceTransition,
    ) -> Result<Self, AdminError> {
        let value = Self {
            scope,
            audit_signing_key_id,
            position,
            transition,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), AdminError> {
        self.position.validate()?;
        self.transition.validate()
    }
    /// Returns the signed historical scope.
    #[must_use]
    pub const fn scope(&self) -> MaintenanceAuditScope {
        self.scope
    }
    /// Returns the trusted audit-key selector carried by the event.
    #[must_use]
    pub const fn audit_signing_key_id(&self) -> [u8; 32] {
        self.audit_signing_key_id
    }
    /// Returns the shared audit position and state advance.
    #[must_use]
    pub const fn position(&self) -> MaintenanceAuditPosition {
        self.position
    }
    /// Returns the exact before/after transition.
    #[must_use]
    pub const fn transition(&self) -> MaintenanceTransition {
        self.transition
    }

    /// Encodes the exact 358-byte structure in network byte order.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        self.validate()?;
        let mut writer = Writer::with_ceiling(MAINTENANCE_AUDIT_TBS_BYTES);
        writer.put_u16(2)?;
        writer.put_u16(1)?;
        writer.put_fixed(self.scope.network_id.as_bytes())?;
        writer.put_fixed(self.scope.server_id.as_bytes())?;
        writer.put_fixed(&self.audit_signing_key_id)?;
        writer.put_u64(self.position.audit_sequence)?;
        writer.put_u64(self.position.created_at)?;
        writer.put_fixed(self.scope.database_instance_id.as_bytes())?;
        writer.put_fixed(self.scope.server_incarnation.as_bytes())?;
        writer.put_fixed(self.scope.recovery_epoch.as_bytes())?;
        writer.put_u64(self.position.preceding_state_generation)?;
        writer.put_u64(self.position.resulting_state_generation)?;
        self.transition.put(&mut writer)?;
        writer.put_fixed(&self.position.previous_event_hash)?;
        Ok(writer.finish())
    }

    pub(super) fn take(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        if reader.u16()? != 2 || reader.u16()? != 1 {
            return Err(AdminError::Audit);
        }
        let network = NetworkId::from_bytes(reader.fixed()?);
        let server = ServerId::from_bytes(reader.fixed()?);
        let key_id = reader.fixed()?;
        let sequence = reader.u64()?;
        let created = reader.u64()?;
        let scope = MaintenanceAuditScope::new(
            network,
            server,
            DatabaseId::from_bytes(reader.fixed()?),
            ServerIncarnation::from_bytes(reader.fixed()?),
            RecoveryEpoch::from_bytes(reader.fixed()?),
        );
        let preceding = reader.u64()?;
        let resulting = reader.u64()?;
        let transition = MaintenanceTransition::take(reader)?;
        let position = MaintenanceAuditPosition::new(
            sequence,
            created,
            preceding,
            resulting,
            reader.fixed()?,
        )?;
        Self::new(scope, key_id, position, transition)
    }

    /// Decodes one exact TBS and refuses unknown arms or trailing data.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        if bytes.len() != MAINTENANCE_AUDIT_TBS_BYTES {
            return Err(AdminError::Audit);
        }
        let mut reader = Reader::new(bytes);
        let value = Self::take(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }

    /// Hashes the complete canonical TBS under its dedicated maintenance domain.
    pub fn hash(&self) -> Result<[u8; 32], AdminError> {
        maintenance_audit_event_hash(&self.encode()?)
            .map(|digest| *digest.as_bytes())
            .map_err(map_crypto)
    }
}
