//! Schema-three mailbox sequence owners outlive every queued item and token.

#![forbid(unsafe_code)]

use super::MailboxKind;
use crate::codec::{Decoder, Encoder};
use crate::{ProtocolRecordBody, StorageError, StoredKey, TableId};

/// The schema-three E2eeState mailbox sequence owner kind.
pub const MAILBOX_SEQUENCE_ROW_KIND: u16 = 15;
/// Exact sequence-owner key prefix.
pub const PREFIX: &[u8] = b"mailbox-sequence/v1/";
const INNER_BYTES: usize = 60;
const WRAPPED_BYTES: usize = INNER_BYTES + 12;

/// The next unused item sequence for one stable mailbox scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxSequenceRow {
    account_digest: [u8; 32],
    device_id: [u8; 16],
    kind: MailboxKind,
    next_sequence: u64,
}

impl MailboxSequenceRow {
    /// Creates the nonzero floor written with the first or a later delivery.
    pub fn new(
        account_digest: [u8; 32],
        device_id: [u8; 16],
        kind: MailboxKind,
        next_sequence: u64,
    ) -> Result<Self, StorageError> {
        if next_sequence == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            account_digest,
            device_id,
            kind,
            next_sequence,
        })
    }

    /// Returns the mailbox account digest.
    #[must_use]
    pub const fn account_digest(&self) -> &[u8; 32] {
        &self.account_digest
    }

    /// Returns the mailbox target device.
    #[must_use]
    pub const fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// Returns the mailbox object kind.
    #[must_use]
    pub const fn kind(&self) -> MailboxKind {
        self.kind
    }

    /// Returns the next sequence that a new delivery would consume.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the exact stable owner key; no sequence is part of this key.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        super::key_of(&[
            PREFIX,
            &self.account_digest,
            &self.device_id,
            &self.kind.wire_value().to_be_bytes(),
        ])
    }

    /// Encodes the fixed-size schema-three owner body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(INNER_BYTES, INNER_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(&self.account_digest)?;
        encoder.put_fixed(&self.device_id)?;
        encoder.put_u16(self.kind.wire_value())?;
        encoder.put_u64(self.next_sequence)?;
        ProtocolRecordBody::new(
            TableId::E2eeState,
            MAILBOX_SEQUENCE_ROW_KIND,
            1,
            encoder.finish(),
        )?
        .encode()
    }

    /// Decodes only a complete fixed-size body, before allocating its inner copy.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() != WRAPPED_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let inner =
            ProtocolRecordBody::decode(TableId::E2eeState, MAILBOX_SEQUENCE_ROW_KIND, body)?;
        let mut decoder = Decoder::new(inner.canonical_object());
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let account = decoder.array()?;
        let device = decoder.array()?;
        let kind = MailboxKind::from_wire(decoder.u16()?)?;
        let next = decoder.u64()?;
        decoder.finish()?;
        Self::new(account, device, kind, next)
    }

    /// Requires the authenticated key to name the same owner as the body.
    pub fn decode_keyed(key: &StoredKey, body: &[u8]) -> Result<Self, StorageError> {
        let row = Self::decode(body)?;
        if row.key()? != *key {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_owner_round_trips_every_mailbox_kind_and_exhaustion() -> Result<(), StorageError> {
        for kind in [
            MailboxKind::Application,
            MailboxKind::Binding,
            MailboxKind::Welcome,
            MailboxKind::StagedReinit,
        ] {
            for next in [1, u64::MAX] {
                let row = MailboxSequenceRow::new([1; 32], [2; 16], kind, next)?;
                let key = row.key()?;
                let encoded = row.encode()?;
                assert_eq!(key.as_bytes().len(), 70);
                assert_eq!(encoded.len(), WRAPPED_BYTES);
                assert_eq!(MailboxSequenceRow::decode_keyed(&key, &encoded)?, row);
            }
        }
        assert!(MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Binding, 0).is_err());
        Ok(())
    }

    #[test]
    fn sequence_owner_refuses_other_scopes_and_nonexact_lengths() -> Result<(), StorageError> {
        let row = MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Binding, 3)?;
        let encoded = row.encode()?;
        let key = row.key()?;
        for other in [
            MailboxSequenceRow::new([3; 32], [2; 16], MailboxKind::Binding, 3)?,
            MailboxSequenceRow::new([1; 32], [3; 16], MailboxKind::Binding, 3)?,
            MailboxSequenceRow::new([1; 32], [2; 16], MailboxKind::Welcome, 3)?,
        ] {
            assert!(MailboxSequenceRow::decode_keyed(&other.key()?, &encoded).is_err());
        }
        let mut shortened = encoded.clone();
        shortened.pop();
        assert!(MailboxSequenceRow::decode_keyed(&key, &shortened).is_err());
        let mut extended = encoded;
        extended.push(0);
        assert!(MailboxSequenceRow::decode_keyed(&key, &extended).is_err());
        assert!(MailboxSequenceRow::decode(&vec![0; 1 << 20]).is_err());
        Ok(())
    }
}
