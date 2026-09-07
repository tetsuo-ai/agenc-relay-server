//! Signed stopped-maintenance events, separate from operator-signed administration.
#![forbid(unsafe_code)]

mod state;
mod tbs;

pub use state::{MaintenanceKeyState, MaintenanceOperation, MaintenanceTransition};
pub use tbs::{
    MAINTENANCE_AUDIT_TBS_BYTES, MaintenanceAuditEventTbs, MaintenanceAuditPosition,
    MaintenanceAuditScope,
};

use crate::AdminError;
use crate::codec::{Reader, Writer};
use agenc_ircd_crypto::{
    CryptoError, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain,
    audit_signing_key_id, sign_canonical, verify_canonical,
};
use agenc_ircd_types::{NetworkId, ServerId};

/// Exact encoded event size: the fixed TBS, its hash, and its strict Ed25519 signature.
pub const MAINTENANCE_AUDIT_EVENT_BYTES: usize = MAINTENANCE_AUDIT_TBS_BYTES + 32 + 64;

/// One maintenance event authenticated by a configured audit signing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceAuditEvent {
    tbs: MaintenanceAuditEventTbs,
    event_hash: [u8; 32],
    server_signature: Ed25519Signature,
}

impl MaintenanceAuditEvent {
    /// Signs only when the exact TBS key selector names this dedicated audit key.
    pub fn sign(
        tbs: MaintenanceAuditEventTbs,
        audit_key: &Ed25519SecretKey,
    ) -> Result<Self, AdminError> {
        require_key(tbs.audit_signing_key_id(), audit_key.public_key())?;
        let event_hash = tbs.hash()?;
        let server_signature = sign_canonical(
            audit_key,
            SignatureDomain::MaintenanceAuditEvent,
            &event_hash,
        )
        .map_err(map_crypto)?;
        Ok(Self {
            tbs,
            event_hash,
            server_signature,
        })
    }

    /// Borrows the immutable signed facts.
    #[must_use]
    pub const fn tbs(&self) -> &MaintenanceAuditEventTbs {
        &self.tbs
    }
    /// Returns the hash consumed by the common audit chain.
    #[must_use]
    pub const fn event_hash(&self) -> [u8; 32] {
        self.event_hash
    }

    /// Encodes the exact event without changing any signed historical identity.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(MAINTENANCE_AUDIT_EVENT_BYTES);
        writer.put_fixed(&self.tbs.encode()?)?;
        writer.put_fixed(&self.event_hash)?;
        writer.put_fixed(self.server_signature.as_bytes())?;
        Ok(writer.finish())
    }

    /// Decodes the closed encoding-two body; callers must then verify its trusted signature.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        if bytes.len() != MAINTENANCE_AUDIT_EVENT_BYTES {
            return Err(AdminError::Audit);
        }
        let mut reader = Reader::new(bytes);
        let tbs = MaintenanceAuditEventTbs::take(&mut reader)?;
        let event_hash = reader.fixed()?;
        let server_signature = Ed25519Signature::from_bytes(reader.fixed()?);
        reader.finish()?;
        Ok(Self {
            tbs,
            event_hash,
            server_signature,
        })
    }

    /// Verifies against externally trusted network/server/key identities. The owner
    /// must also check historical key validity and shared-chain ordering. Historical
    /// database/incarnation/epoch are preserved across rekey and declared recovery.
    pub fn verify(
        &self,
        network: NetworkId,
        server: ServerId,
        audit_key: Ed25519PublicKey,
    ) -> Result<(), AdminError> {
        if self.tbs.scope().network_id() != network || self.tbs.scope().server_id() != server {
            return Err(AdminError::Audit);
        }
        require_key(self.tbs.audit_signing_key_id(), audit_key)?;
        if self.tbs.hash()? != self.event_hash {
            return Err(AdminError::Audit);
        }
        verify_canonical(
            audit_key,
            SignatureDomain::MaintenanceAuditEvent,
            &self.event_hash,
            self.server_signature,
        )
        .map_err(map_crypto)
    }

    /// Adds exact current-operation scope binding when the caller owns that scope.
    /// Historical replay uses verify without substituting the replacement database.
    pub fn verify_scope(
        &self,
        scope: MaintenanceAuditScope,
        audit_key: Ed25519PublicKey,
    ) -> Result<(), AdminError> {
        if self.tbs.scope() != scope {
            return Err(AdminError::Audit);
        }
        self.verify(scope.network_id(), scope.server_id(), audit_key)
    }
}

fn require_key(expected: [u8; 32], key: Ed25519PublicKey) -> Result<(), AdminError> {
    if audit_signing_key_id(key.as_bytes())
        .map_err(map_crypto)?
        .as_bytes()
        != &expected
    {
        return Err(AdminError::Audit);
    }
    Ok(())
}

fn map_crypto(error: CryptoError) -> AdminError {
    match error {
        CryptoError::AuthenticationFailed => AdminError::Signature,
        CryptoError::Overflow => AdminError::Overflow,
        _ => AdminError::Audit,
    }
}

#[cfg(test)]
mod tests;
