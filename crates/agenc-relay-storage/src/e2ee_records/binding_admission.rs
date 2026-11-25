//! The durable routing handoff for an old-group-finalized binding change.
#![forbid(unsafe_code)]

use crate::codec::{Decoder, Encoder};
use crate::{StorageError, StoredKey};

/// Table-23 record kind for an installed same-group binding generation.
pub const KIND: u16 = 24;
/// One immutable admission per conversation and binding generation.
pub const PREFIX: &[u8] = b"binding-admission/v1/";
const INNER_BYTES: usize = 2 + 6 * 32 + 2 * 8;
const WRAPPED_BYTES: usize = INNER_BYTES + 12;

/// The public objects and the submitting endpoint's private-context commitment
/// accepted together when the route moved. The terminal is the log wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingAdmissionRow {
    /// The MLS conversation preserved across the migration.
    pub conversation_id: [u8; 32],
    /// Successor binding generation, at least one.
    pub generation: u64,
    /// Sequence at which the old group finalized the change.
    pub route_sequence: u64,
    /// Complete predecessor package, retained for previous epochs.
    pub previous_binding_object: [u8; 32],
    /// Exact successor package installed by BIND.
    pub binding_object: [u8; 32],
    /// Exact signed old-group finalization on the sequencer timeline.
    pub terminal_record_object: [u8; 32],
    /// ContextHash of the private ArcMlsContext, asserted by the submitting endpoint.
    pub context_digest: [u8; 32],
    /// Hash of the accepted registered BIND request, including the grant and sender.
    pub request_object: [u8; 32],
}

impl BindingAdmissionRow {
    /// Stable key. Sequence and grant cannot introduce a second row for a generation.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        super::key_of(&[
            PREFIX,
            &self.conversation_id,
            &self.generation.to_be_bytes(),
        ])
    }

    fn check(&self) -> Result<(), StorageError> {
        if self.generation == 0
            || self.route_sequence == 0
            || self.previous_binding_object == self.binding_object
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    /// Encodes the fixed-size v1 record.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = Encoder::with_capacity(INNER_BYTES, INNER_BYTES)?;
        encoder.put_u16(1)?;
        encoder.put_fixed(&self.conversation_id)?;
        encoder.put_u64(self.generation)?;
        encoder.put_u64(self.route_sequence)?;
        for value in [
            &self.previous_binding_object,
            &self.binding_object,
            &self.terminal_record_object,
            &self.context_digest,
            &self.request_object,
        ] {
            encoder.put_fixed(value)?;
        }
        super::wrap(KIND, encoder.finish())
    }

    /// Decodes one exact admission with bounded allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != WRAPPED_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let inner = super::unwrap(KIND, bytes)?;
        let mut decoder = Decoder::new(&inner);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let row = Self {
            conversation_id: decoder.array()?,
            generation: decoder.u64()?,
            route_sequence: decoder.u64()?,
            previous_binding_object: decoder.array()?,
            binding_object: decoder.array()?,
            terminal_record_object: decoder.array()?,
            context_digest: decoder.array()?,
            request_object: decoder.array()?,
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }

    /// Binds the stored value to the same conversation and generation as its key.
    pub fn decode_keyed(key: &StoredKey, bytes: &[u8]) -> Result<Self, StorageError> {
        let row = Self::decode(bytes)?;
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
    fn admission_round_trips_only_for_its_exact_generation() -> Result<(), StorageError> {
        let row = BindingAdmissionRow {
            conversation_id: [1; 32],
            generation: 2,
            route_sequence: 11,
            previous_binding_object: [2; 32],
            binding_object: [3; 32],
            terminal_record_object: [4; 32],
            context_digest: [5; 32],
            request_object: [6; 32],
        };
        let bytes = row.encode()?;
        let key = row.key()?;
        assert_eq!(super::super::record_kind_for_key(&key)?, KIND);
        assert_eq!(BindingAdmissionRow::decode_keyed(&key, &bytes)?, row);
        for wrong in [
            BindingAdmissionRow {
                generation: 3,
                ..row
            },
            BindingAdmissionRow {
                conversation_id: [7; 32],
                ..row
            },
        ] {
            assert!(BindingAdmissionRow::decode_keyed(&wrong.key()?, &bytes).is_err());
        }
        for invalid in [
            BindingAdmissionRow {
                generation: 0,
                ..row
            },
            BindingAdmissionRow {
                route_sequence: 0,
                ..row
            },
            BindingAdmissionRow {
                previous_binding_object: row.binding_object,
                ..row
            },
        ] {
            assert!(invalid.encode().is_err());
        }
        assert!(
            BindingAdmissionRow::decode(bytes.get(1..).ok_or(StorageError::InvalidEncoding)?)
                .is_err()
        );
        Ok(())
    }
}
