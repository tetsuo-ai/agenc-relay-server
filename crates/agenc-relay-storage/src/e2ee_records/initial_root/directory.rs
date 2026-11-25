//! Attributable account directory rows and their actual sealed sizes (architecture C.7).
#![forbid(unsafe_code)]

use super::{KIND, VERSION};
use crate::codec::{Decoder, Encoder};
use crate::e2ee_records::{AttachRow, DirectoryRow, ObjectOwnerRow, PackageRow, prefix};
use crate::{PersistentRecordValue, RecordMutation, StorageError, StoredKey, TableId};

/// A guarded account's fixed-size companion disk subtotal.
pub const PREFIX: &[u8] = b"initial-root-directory/v1/";
/// The account digest used by the directory's authenticated storage keys.
pub type AccountDigest = [u8; 32];
/// The complete immutable object's SHA-256 identifier.
pub type ObjectDigest = [u8; 32];

/// One independently rebuilt and checked per-account subtotal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subtotal {
    /// Account directory charged by this row.
    pub account: AccountDigest,
    /// All charged sealed rows in bytes, rounded separately to 4 KiB.
    pub bytes: u64,
}

impl Subtotal {
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let result = Self {
            account: input.array()?,
            bytes: input.u64()?,
        };
        result.check()?;
        Ok(result)
    }

    fn check(self) -> Result<(), StorageError> {
        if self.bytes == 0 || !self.bytes.is_multiple_of(4096) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    /// Returns the immutable scoped accounting key.
    pub fn key(self) -> Result<StoredKey, StorageError> {
        super::super::key_of(&[PREFIX, &self.account])
    }

    /// The accounting row written with the allocation or release.
    pub fn record(self, revision: u64) -> Result<PersistentRecordValue, StorageError> {
        self.check()?;
        let mut out = Encoder::with_capacity(43, 43)?;
        out.put_u16(VERSION)?;
        out.put_fixed(&[2])?;
        out.put_fixed(&self.account)?;
        out.put_u64(self.bytes)?;
        let body = super::super::wrap(KIND, out.finish())?;
        PersistentRecordValue::new(
            TableId::E2eeState,
            KIND,
            revision,
            0,
            None,
            Vec::new(),
            body,
        )
    }
}

/// An actual directory row identified by an authenticated owner reference.
pub enum Payer {
    /// The account digest is part of the canonical row key.
    Account(AccountDigest),
    /// Stock uses a KeyPackageRef key. Only its stored package row names the publisher.
    Stock(StoredKey),
}

fn payer(key: &StoredKey) -> Result<Option<Payer>, StorageError> {
    let bytes = key.as_bytes();
    let digest = if bytes.starts_with(prefix::IDENTITY) {
        DirectoryRow::parse_identity_key(key)?
    } else if bytes.starts_with(prefix::ROSTER) {
        DirectoryRow::parse_roster_key(key)?
    } else if bytes.starts_with(prefix::CAPABILITY) {
        DirectoryRow::parse_capability_key(key)?.0
    } else if bytes.starts_with(prefix::BINDING_LOCK) {
        DirectoryRow::parse_binding_lock_key(key)?.0
    } else if bytes.starts_with(prefix::ATTACH) {
        AttachRow::parse_key(key)?.0
    } else if bytes.starts_with(prefix::CLAIM) {
        PackageRow::parse_claim_key(key)?.0
    } else if bytes.starts_with(prefix::PACKAGE) {
        PackageRow::parse_package_key(key)?;
        return Ok(Some(Payer::Stock(key.clone())));
    } else {
        return Ok(None);
    };
    Ok(Some(Payer::Account(digest)))
}

/// How one physical row can be attributed. Raw incoming or unreferenced object bytes
/// cannot choose an account. Only the committed directory ownership references count.
pub enum Allocation {
    /// The metadata row belongs to the account named in its key.
    Account(AccountDigest),
    /// A retained stock row, or its deletion. The payer is its verified publisher.
    Stock(Option<AccountDigest>),
    /// The immutable object. Its account owners come from the separate ownership row.
    Object(ObjectDigest),
    /// Its durable metadata row, with the currently retained directory references.
    Ownership(ObjectDigest, Vec<Payer>),
}

impl Allocation {
    /// Classifies an authenticated record on restore without copying any table-22 body.
    pub fn stored(
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<Option<Self>, StorageError> {
        Self::classify(table, key, Some(value))
    }

    /// Classifies a verified normal mutation. Irrelevant payloads never enter a decoder.
    pub fn change(mutation: &RecordMutation) -> Result<Option<Self>, StorageError> {
        let key = mutation.key();
        let selected = mutation.table() == TableId::E2eeState
            && (key.as_bytes().starts_with(prefix::OWNER)
                || key.as_bytes().starts_with(prefix::PACKAGE));
        let value = if selected {
            mutation
                .plaintext()
                .map(|raw| PersistentRecordValue::decode(TableId::E2eeState, raw))
                .transpose()?
        } else {
            None
        };
        Self::classify(mutation.table(), key, value.as_ref())
    }

    fn classify(
        table: TableId,
        key: &StoredKey,
        value: Option<&PersistentRecordValue>,
    ) -> Result<Option<Self>, StorageError> {
        if table == TableId::E2eeObject {
            return Ok(Some(Self::Object(
                key.as_bytes()
                    .try_into()
                    .map_err(|_| StorageError::InvalidEncoding)?,
            )));
        }
        if table != TableId::E2eeState {
            return Ok(None);
        }
        if key.as_bytes().starts_with(prefix::OWNER) {
            let id = ObjectOwnerRow::parse_key(key)?;
            let mut owners = Vec::new();
            for reference in value
                .into_iter()
                .flat_map(PersistentRecordValue::references)
            {
                if reference.table() == TableId::E2eeState
                    && let Some(owner) = payer(reference.key())?
                {
                    owners.push(owner);
                }
            }
            return Ok(Some(Self::Ownership(id, owners)));
        }
        match payer(key)? {
            Some(Payer::Account(digest)) => Ok(Some(Self::Account(digest))),
            Some(Payer::Stock(_)) => {
                let digest = value
                    .map(|row| match PackageRow::decode(row.body())? {
                        PackageRow::Package { account_digest, .. } => Ok(account_digest),
                        _ => Err(StorageError::InvalidEncoding),
                    })
                    .transpose()?;
                Ok(Some(Self::Stock(digest)))
            }
            None => Ok(None),
        }
    }
}

/// The exact architecture C.7 charge for one existing sealed row.
pub fn sealed_charge(key: &StoredKey, envelope_bytes: usize) -> Result<u64, StorageError> {
    crate::companion_disk::row_charge(TableId::E2eeState, key.as_bytes().len(), envelope_bytes)
}

/// The old and new charges of this exact projected mutation; an absent row uses zero.
pub fn changed_charge(mutation: &RecordMutation) -> Result<(u64, u64), StorageError> {
    let before = mutation
        .before()
        .map(|record| record.sealed_record_bytes() as usize);
    let after = mutation.resulting_sealed_bytes()?;
    let charge = |bytes| sealed_charge(mutation.key(), bytes);
    Ok((
        before.map(charge).transpose()?.unwrap_or(0),
        after.map(charge).transpose()?.unwrap_or(0),
    ))
}
