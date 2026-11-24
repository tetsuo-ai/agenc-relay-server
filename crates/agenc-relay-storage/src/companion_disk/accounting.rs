#![forbid(unsafe_code)]

//! The sealed aggregate covers every table-22 and table-23 envelope, including
//! its own fixed-size row. Anonymous extents belong to the running process.

use super::{BLOCK, row_charge};
use crate::{
    PersistentRecordValue, ProtocolRecordBody, RecordMutation, StorageError, StoredKey, TableId,
};

pub(crate) const KIND: u16 = 23;
pub(crate) const KEY: &[u8] = b"companion-disk/v1";

/// The last authenticated aggregate, or the verified total of a legacy store
/// whose first companion mutation will create the accounting record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompanionDiskAccounting {
    pub(super) sealed: u64,
    pub(super) persisted: bool,
}

impl CompanionDiskAccounting {
    /// Exact logical bytes occupied by sealed companion rows.
    pub const fn sealed_bytes(self) -> u64 {
        self.sealed
    }

    pub(crate) const fn persisted(self) -> bool {
        self.persisted
    }

    /// The stable table-23 key for the accounting record.
    pub fn key() -> Result<StoredKey, StorageError> {
        StoredKey::new(KEY.to_vec())
    }

    /// Projects one ordinary storage batch without reading or modifying live
    /// state. When present, the returned value must join that same batch.
    pub fn project(self, mutations: &[RecordMutation]) -> Result<Option<Self>, StorageError> {
        let delta = Delta::read(mutations)?;
        if delta.counter.is_some() {
            return Err(StorageError::InvalidEncoding);
        }
        delta.project(self)
    }

    /// Canonical fixed-size accounting record at the owning batch revision.
    pub fn record(self, revision: u64) -> Result<PersistentRecordValue, StorageError> {
        if !self.persisted || self.sealed < BLOCK || !self.sealed.is_multiple_of(BLOCK) {
            return Err(StorageError::InvalidEncoding);
        }
        let body = ProtocolRecordBody::new(
            TableId::E2eeState,
            KIND,
            1,
            self.sealed.to_be_bytes().to_vec(),
        )?
        .encode()?;
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

    pub(crate) fn decode(body: &[u8]) -> Result<Self, StorageError> {
        // ProtocolRecordBody has a fixed twelve-byte header. Cap the input
        // before its checked decoder materializes any inner bytes.
        if body.len() != 20 {
            return Err(StorageError::InvalidEncoding);
        }
        let body = ProtocolRecordBody::decode(TableId::E2eeState, KIND, body)?;
        let sealed = u64::from_be_bytes(
            body.canonical_object()
                .try_into()
                .map_err(|_| StorageError::InvalidEncoding)?,
        );
        if sealed < BLOCK || !sealed.is_multiple_of(BLOCK) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            sealed,
            persisted: true,
        })
    }

    pub(crate) fn check_record(
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<Self, StorageError> {
        if key.as_bytes() != KEY
            || value.record_kind() != KIND
            || !value.references().is_empty()
            || value.expires_at().is_some()
            || value.generation() != 0
        {
            return Err(StorageError::InvalidEncoding);
        }
        Self::decode(value.body())
    }

    pub(super) fn checked_update(
        self,
        mutations: &[RecordMutation],
        revision: u64,
    ) -> Result<Self, StorageError> {
        let delta = Delta::read(mutations)?;
        match (delta.project(self)?, delta.counter) {
            (None, None) => Ok(self),
            (Some(expected), Some(counter)) if counter.before().is_some() == self.persisted => {
                let plaintext = counter.plaintext().ok_or(StorageError::InvalidEncoding)?;
                let stored = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
                if stored.revision() != revision
                    || Self::check_record(counter.key(), &stored)? != expected
                {
                    return Err(StorageError::StaleState);
                }
                Ok(expected)
            }
            _ => Err(StorageError::StaleState),
        }
    }
}

struct Delta<'a> {
    removed: u64,
    added: u64,
    touched: bool,
    counter: Option<&'a RecordMutation>,
}

impl<'a> Delta<'a> {
    fn read(mutations: &'a [RecordMutation]) -> Result<Self, StorageError> {
        let mut result = Self {
            removed: 0,
            added: 0,
            touched: false,
            counter: None,
        };
        for m in mutations
            .iter()
            .filter(|m| matches!(m.table(), TableId::E2eeObject | TableId::E2eeState))
        {
            if m.table() == TableId::E2eeState && m.key().as_bytes() == KEY {
                if result.counter.replace(m).is_some() {
                    return Err(StorageError::InvalidEncoding);
                }
                continue;
            }
            result.touched = true;
            let key = m.key().as_bytes().len();
            if let Some(before) = m.before() {
                let length = usize::try_from(before.sealed_record_bytes())
                    .map_err(|_| StorageError::Overflow)?;
                result.removed = result
                    .removed
                    .checked_add(row_charge(m.table(), key, length)?)
                    .ok_or(StorageError::Overflow)?;
            }
            if let Some(length) = m.resulting_sealed_bytes()? {
                result.added = result
                    .added
                    .checked_add(row_charge(m.table(), key, length)?)
                    .ok_or(StorageError::Overflow)?;
            }
        }
        Ok(result)
    }

    fn project(
        &self,
        current: CompanionDiskAccounting,
    ) -> Result<Option<CompanionDiskAccounting>, StorageError> {
        if !self.touched || (current.persisted && self.removed == self.added) {
            return Ok(None);
        }
        let self_charge = if current.persisted { 0 } else { BLOCK };
        let sealed = current
            .sealed
            .checked_sub(self.removed)
            .ok_or(StorageError::StaleState)?
            .checked_add(self.added)
            .and_then(|n| n.checked_add(self_charge))
            .ok_or(StorageError::Overflow)?;
        Ok(Some(CompanionDiskAccounting {
            sealed,
            persisted: true,
        }))
    }
}

#[derive(Default)]
pub(crate) struct Scan {
    sealed: u64,
    counter: Option<CompanionDiskAccounting>,
}

impl Scan {
    pub(crate) fn observe(
        &mut self,
        table: TableId,
        key: &StoredKey,
        envelope: usize,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        self.sealed = self
            .sealed
            .checked_add(row_charge(table, key.as_bytes().len(), envelope)?)
            .ok_or(StorageError::Overflow)?;
        if table == TableId::E2eeState && key.as_bytes() == KEY {
            let value = PersistentRecordValue::decode(table, plaintext)?;
            self.counter = Some(CompanionDiskAccounting::check_record(key, &value)?);
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<CompanionDiskAccounting, StorageError> {
        if self.counter.is_some_and(|r| r.sealed != self.sealed) {
            return Err(StorageError::StaleState);
        }
        Ok(CompanionDiskAccounting {
            sealed: self.sealed,
            persisted: self.counter.is_some(),
        })
    }
}
