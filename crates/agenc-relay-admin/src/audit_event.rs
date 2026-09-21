//! The closed audit chain carries unchanged administration or maintenance bodies.
#![forbid(unsafe_code)]

use crate::{AdminAuditEvent, AdminError, AuditChainCursor, MaintenanceAuditEvent};
use agenc_relay_types::{NetworkId, ServerId};

#[cfg(test)]
mod tests;

/// One exact signed body in the shared audit chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditEvent {
    /// The unchanged encoding-one operator and server signed event.
    Admin(AdminAuditEvent),
    /// The encoding-two event signed only by the dedicated maintenance audit key.
    Maintenance(MaintenanceAuditEvent),
}

impl AuditEvent {
    /// Decodes exactly one assigned body encoding without adding an outer wrapper.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let encoding = bytes.get(..2).ok_or(AdminError::Audit)?;
        match encoding {
            [0, 1] => AdminAuditEvent::decode_exact(bytes).map(Self::Admin),
            [0, 2] => MaintenanceAuditEvent::decode_exact(bytes).map(Self::Maintenance),
            _ => Err(AdminError::Audit),
        }
    }

    /// Returns the selected body bytes without changing any signed field.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        match self {
            Self::Admin(event) => event.encode(),
            Self::Maintenance(event) => event.encode(),
        }
    }

    /// Returns the exact body discriminator, also used by the persistent outer kind.
    #[must_use]
    pub const fn encoding(&self) -> u16 {
        match self {
            Self::Admin(_) => 1,
            Self::Maintenance(_) => 2,
        }
    }

    /// Returns the signed network identity.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        match self {
            Self::Admin(event) => event.tbs().network_id,
            Self::Maintenance(event) => event.tbs().scope().network_id(),
        }
    }

    /// Returns the signed server identity.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        match self {
            Self::Admin(event) => event.tbs().server_id,
            Self::Maintenance(event) => event.tbs().scope().server_id(),
        }
    }

    /// Returns the selector that must resolve through the caller's trusted manifest.
    #[must_use]
    pub const fn audit_signing_key_id(&self) -> [u8; 32] {
        match self {
            Self::Admin(event) => event.tbs().audit_signing_key_id,
            Self::Maintenance(event) => event.tbs().audit_signing_key_id(),
        }
    }

    /// Returns the common gapless audit sequence.
    #[must_use]
    pub const fn audit_sequence(&self) -> u64 {
        match self {
            Self::Admin(event) => event.tbs().audit_sequence,
            Self::Maintenance(event) => event.tbs().position().audit_sequence(),
        }
    }

    /// Returns the signed Unix second used for historical key selection.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        match self {
            Self::Admin(event) => event.tbs().created_at,
            Self::Maintenance(event) => event.tbs().position().created_at(),
        }
    }

    /// Returns the predecessor in the common chain, independent of event encoding.
    #[must_use]
    pub const fn previous_event_hash(&self) -> [u8; 32] {
        match self {
            Self::Admin(event) => event.tbs().previous_event_hash,
            Self::Maintenance(event) => event.tbs().position().previous_event_hash(),
        }
    }

    /// Returns this event's stored hash; decoding alone does not authenticate it.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        match self {
            Self::Admin(event) => event.event_hash(),
            Self::Maintenance(event) => event.event_hash(),
        }
    }
}

impl AuditChainCursor {
    /// Checks the exact common position after the caller has verified the selected body.
    pub fn advance_event(self, event: &AuditEvent) -> Result<Self, AdminError> {
        self.advance_position(
            event.audit_sequence(),
            event.previous_event_hash(),
            event.event_hash(),
        )
    }
}
