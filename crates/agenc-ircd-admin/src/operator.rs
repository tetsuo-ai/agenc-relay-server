//! Enrolled operator records and the exact selection rule (spec 4366-4374,
//! 4395-4397, Appendix C.7 9258-9276).

use agenc_ircd_crypto::Ed25519PublicKey;
use agenc_ircd_types::{AdminPermissionSet, OperatorId};

use crate::AdminError;

/// Appendix C.7 allows 1..64 operator records.
pub const MAX_OPERATOR_RECORDS: usize = 64;
/// Appendix C.3 allows 1..64 allowlisted UIDs per local listener.
pub const MAX_OPERATOR_UIDS: usize = 64;
/// Appendix C.3 allows 0..64 allowlisted GIDs per local listener.
pub const MAX_OPERATOR_GIDS: usize = 64;

/// One enabled or disabled operator as configured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRecord {
    operator_id: OperatorId,
    signing_key: Ed25519PublicKey,
    certificate_spki_sha256: Option<[u8; 32]>,
    local_uids: Vec<u32>,
    local_gids: Vec<u32>,
    permissions: AdminPermissionSet,
    enabled: bool,
}

impl OperatorRecord {
    /// Builds a record, enforcing the allowlist ceilings and nonempty permissions.
    pub fn new(
        operator_id: OperatorId,
        signing_key: Ed25519PublicKey,
        certificate_spki_sha256: Option<[u8; 32]>,
        local_uids: Vec<u32>,
        local_gids: Vec<u32>,
        permissions: AdminPermissionSet,
        enabled: bool,
    ) -> Result<Self, AdminError> {
        if local_uids.len() > MAX_OPERATOR_UIDS || local_gids.len() > MAX_OPERATOR_GIDS {
            return Err(AdminError::Limit);
        }
        if permissions.is_empty() || has_duplicates(&local_uids) || has_duplicates(&local_gids) {
            return Err(AdminError::Operator);
        }
        Ok(Self {
            operator_id,
            signing_key,
            certificate_spki_sha256,
            local_uids,
            local_gids,
            permissions,
            enabled,
        })
    }

    /// Returns the operator identity.
    #[must_use]
    pub const fn operator_id(&self) -> OperatorId {
        self.operator_id
    }

    /// Returns the enrolled signing key.
    #[must_use]
    pub const fn signing_key(&self) -> Ed25519PublicKey {
        self.signing_key
    }

    /// Returns the granted permission set.
    #[must_use]
    pub const fn permissions(&self) -> AdminPermissionSet {
        self.permissions
    }

    /// Whether the record is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    fn admits(&self, identity: &PeerIdentity) -> bool {
        match identity {
            PeerIdentity::Local { uid, gid } => {
                self.local_uids.contains(uid) || self.local_gids.contains(gid)
            }
            PeerIdentity::Pin(pin) => self.certificate_spki_sha256 == Some(*pin),
        }
    }
}

/// The transport credential presented before OPER (spec 4366-4371).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerIdentity {
    /// Unix socket peer credentials.
    Local {
        /// Effective peer UID.
        uid: u32,
        /// Effective peer GID.
        gid: u32,
    },
    /// Remote client certificate SPKI SHA-256.
    Pin([u8; 32]),
}

/// The closed set of configured operators with uniqueness proven at build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorRegistry {
    records: Vec<OperatorRecord>,
}

impl OperatorRegistry {
    /// Validates that every id, key, pin, UID, and GID selects at most one
    /// record, so a credential can never be ambiguous (spec 4395-4397).
    pub fn from_records(records: Vec<OperatorRecord>) -> Result<Self, AdminError> {
        if records.is_empty() || records.len() > MAX_OPERATOR_RECORDS {
            return Err(AdminError::Limit);
        }
        let ids: Vec<OperatorId> = records.iter().map(OperatorRecord::operator_id).collect();
        let keys: Vec<[u8; 32]> = records.iter().map(|r| *r.signing_key.as_bytes()).collect();
        let pins: Vec<[u8; 32]> = records
            .iter()
            .filter_map(|r| r.certificate_spki_sha256)
            .collect();
        let uids: Vec<u32> = records.iter().flat_map(|r| r.local_uids.clone()).collect();
        let gids: Vec<u32> = records.iter().flat_map(|r| r.local_gids.clone()).collect();
        if has_duplicates(&ids)
            || has_duplicates(&keys)
            || has_duplicates(&pins)
            || has_duplicates(&uids)
            || has_duplicates(&gids)
        {
            return Err(AdminError::Operator);
        }
        Ok(Self { records })
    }

    /// Selects the one enabled record that the operator id, the presented
    /// transport credential, and (later) the signing key all name.
    pub fn select(
        &self,
        operator_id: OperatorId,
        identity: &PeerIdentity,
    ) -> Result<&OperatorRecord, AdminError> {
        let record = self
            .records
            .iter()
            .find(|record| record.operator_id == operator_id)
            .ok_or(AdminError::Operator)?;
        if !record.enabled || !record.admits(identity) {
            return Err(AdminError::Operator);
        }
        Ok(record)
    }

    /// Returns the immutable verification key for historical audit
    /// verification, regardless of the record's current enable flag.
    pub fn verification_key(
        &self,
        operator_id: OperatorId,
    ) -> Result<Ed25519PublicKey, AdminError> {
        self.records
            .iter()
            .find(|record| record.operator_id == operator_id)
            .map(OperatorRecord::signing_key)
            .ok_or(AdminError::Operator)
    }

    /// Returns the number of configured records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no record is configured (never true for a built registry).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn has_duplicates<T: Ord + Clone>(values: &[T]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|pair| pair.first() == pair.get(1))
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::Ed25519SecretKey;
    use agenc_ircd_types::{AdminPermission, AdminPermissionSet, OperatorId};

    use super::{OperatorRecord, OperatorRegistry, PeerIdentity};
    use crate::AdminError;

    fn permissions() -> AdminPermissionSet {
        let mut set = AdminPermissionSet::EMPTY;
        set.insert(AdminPermission::Observe);
        set
    }

    fn record(
        seed: u8,
        uids: &[u32],
        gids: &[u32],
        pin: Option<u8>,
        enabled: bool,
    ) -> Result<OperatorRecord, AdminError> {
        OperatorRecord::new(
            OperatorId::from_bytes([seed; 16]),
            Ed25519SecretKey::from_bytes([seed; 32]).public_key(),
            pin.map(|byte| [byte; 32]),
            uids.to_vec(),
            gids.to_vec(),
            permissions(),
            enabled,
        )
    }

    #[test]
    fn selection_requires_the_same_enabled_record_for_every_credential() -> Result<(), AdminError> {
        let registry = OperatorRegistry::from_records(vec![
            record(1, &[1000], &[], Some(9), true)?,
            record(2, &[], &[2000], None, true)?,
            record(3, &[3000], &[], None, false)?,
        ])?;
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
        let one = OperatorId::from_bytes([1; 16]);
        let by_uid = PeerIdentity::Local { uid: 1000, gid: 5 };
        assert_eq!(registry.select(one, &by_uid)?.operator_id(), one);
        assert!(registry.select(one, &PeerIdentity::Pin([9; 32])).is_ok());
        assert_eq!(
            registry.select(one, &PeerIdentity::Pin([8; 32])),
            Err(AdminError::Operator)
        );
        assert_eq!(
            registry.select(one, &PeerIdentity::Local { uid: 1001, gid: 5 }),
            Err(AdminError::Operator)
        );
        let two = OperatorId::from_bytes([2; 16]);
        assert!(
            registry
                .select(two, &PeerIdentity::Local { uid: 7, gid: 2000 })
                .is_ok()
        );
        assert_eq!(
            registry.select(two, &PeerIdentity::Local { uid: 1000, gid: 5 }),
            Err(AdminError::Operator)
        );
        let three = OperatorId::from_bytes([3; 16]);
        assert_eq!(
            registry.select(three, &PeerIdentity::Local { uid: 3000, gid: 0 }),
            Err(AdminError::Operator)
        );
        let unknown = OperatorId::from_bytes([4; 16]);
        assert_eq!(registry.select(unknown, &by_uid), Err(AdminError::Operator));
        let selected = registry.select(one, &by_uid)?;
        assert!(selected.enabled());
        assert!(selected.permissions().contains(AdminPermission::Observe));
        assert_eq!(
            selected.signing_key(),
            Ed25519SecretKey::from_bytes([1; 32]).public_key()
        );
        Ok(())
    }

    #[test]
    fn registries_reject_every_ambiguous_credential() -> Result<(), AdminError> {
        assert_eq!(
            OperatorRegistry::from_records(vec![]).err(),
            Some(AdminError::Limit)
        );
        let duplicate_id = vec![
            record(1, &[1], &[], None, true)?,
            record(1, &[2], &[], None, true)?,
        ];
        assert_eq!(
            OperatorRegistry::from_records(duplicate_id).err(),
            Some(AdminError::Operator)
        );
        let mut shared_key = record(2, &[3], &[], None, true)?;
        shared_key.operator_id = OperatorId::from_bytes([7; 16]);
        let duplicate_key = vec![record(2, &[4], &[], None, true)?, shared_key];
        assert_eq!(
            OperatorRegistry::from_records(duplicate_key).err(),
            Some(AdminError::Operator)
        );
        let duplicate_pin = vec![
            record(1, &[], &[], Some(1), true)?,
            record(2, &[], &[], Some(1), true)?,
        ];
        assert_eq!(
            OperatorRegistry::from_records(duplicate_pin).err(),
            Some(AdminError::Operator)
        );
        let duplicate_uid = vec![
            record(1, &[5], &[], None, true)?,
            record(2, &[5], &[], None, true)?,
        ];
        assert_eq!(
            OperatorRegistry::from_records(duplicate_uid).err(),
            Some(AdminError::Operator)
        );
        let duplicate_gid = vec![
            record(1, &[], &[6], None, true)?,
            record(2, &[], &[6], None, true)?,
        ];
        assert_eq!(
            OperatorRegistry::from_records(duplicate_gid).err(),
            Some(AdminError::Operator)
        );
        assert_eq!(
            record(1, &[1, 1], &[], None, true).err(),
            Some(AdminError::Operator)
        );
        assert_eq!(
            record(1, &[1; 65], &[], None, true).err(),
            Some(AdminError::Limit)
        );
        assert_eq!(
            record(1, &[], &[1; 65], None, true).err(),
            Some(AdminError::Limit)
        );
        let no_permissions = OperatorRecord::new(
            OperatorId::from_bytes([1; 16]),
            Ed25519SecretKey::from_bytes([1; 32]).public_key(),
            None,
            vec![1],
            vec![],
            AdminPermissionSet::EMPTY,
            true,
        );
        assert_eq!(no_permissions.err(), Some(AdminError::Operator));
        let too_many: Result<Vec<_>, _> = (0..65_u8)
            .map(|seed| record(seed, &[u32::from(seed)], &[], None, true))
            .collect();
        assert_eq!(
            OperatorRegistry::from_records(too_many?).err(),
            Some(AdminError::Limit)
        );
        Ok(())
    }
}
