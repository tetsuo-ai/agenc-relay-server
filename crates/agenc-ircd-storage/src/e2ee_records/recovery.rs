//! Accepted recovery submissions and the records they installed
//! (companion 13.7.4): state record kinds 17 and 18 of table 23.
//!
//! A `recovery-submission/v1/<conversation><submission-id>` row retains one
//! accepted submission under the pending gate: who submitted it, what
//! element it names at which position, when it was accepted, and the
//! outcome its element produced. A `recovery-record/v1/<conversation><seq>`
//! row records one sequencer record a `record_element` installed beyond the
//! restored head while the gate stayed `pending`; the restored route and its
//! own rows are untouched until `closed` installs them together.

use super::{
    HASH_BYTES, ID_BYTES, PAGE_LIMIT, RECOVERY_RECORD_ROW_KIND, RECOVERY_SUBMISSION_ROW_KIND,
    decoder, encoder, key_of, prefix, prefix_range, put_bool, slice_array, suffix, take_bool,
    unwrap, wrap,
};
use crate::{ReadPlan, StorageError, StoredKey};

const ACCOUNT_BYTES: usize = 24;

/// What an accepted submission's element produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    /// The element has not arrived.
    Open,
    /// The record element extended the head with `record_id`.
    Extended {
        /// The installed record.
        record_id: [u8; HASH_BYTES],
    },
    /// The close element installed `closed` with `close_id`.
    Closed {
        /// The installed close.
        close_id: [u8; HASH_BYTES],
    },
    /// A second valid record at an installed position installed `conflict`.
    Conflict {
        /// The record already installed at the position.
        installed_record_id: [u8; HASH_BYTES],
        /// The competing record.
        conflicting_record_id: [u8; HASH_BYTES],
    },
    /// A reference element was retained for its position.
    Referenced,
}

impl RecoveryOutcome {
    fn wire(self) -> (u16, [u8; HASH_BYTES], [u8; HASH_BYTES]) {
        match self {
            Self::Open => (0, [0; HASH_BYTES], [0; HASH_BYTES]),
            Self::Extended { record_id } => (1, record_id, [0; HASH_BYTES]),
            Self::Closed { close_id } => (2, close_id, [0; HASH_BYTES]),
            Self::Conflict {
                installed_record_id,
                conflicting_record_id,
            } => (3, installed_record_id, conflicting_record_id),
            Self::Referenced => (4, [0; HASH_BYTES], [0; HASH_BYTES]),
        }
    }

    fn from_wire(
        tag: u16,
        first: [u8; HASH_BYTES],
        second: [u8; HASH_BYTES],
    ) -> Result<Self, StorageError> {
        let zero = [0; HASH_BYTES];
        Ok(match (tag, first == zero, second == zero) {
            (0, true, true) => Self::Open,
            (1, false, true) => Self::Extended { record_id: first },
            (2, false, true) => Self::Closed { close_id: first },
            (3, false, false) => Self::Conflict {
                installed_record_id: first,
                conflicting_record_id: second,
            },
            (4, true, true) => Self::Referenced,
            _ => return Err(StorageError::InvalidEncoding),
        })
    }

    /// Whether the element arrived.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        !matches!(self, Self::Open)
    }
}

/// One accepted recovery submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverySubmissionRow {
    /// The submitting account.
    pub account_id: [u8; ACCOUNT_BYTES],
    /// The submitting device.
    pub device_id: [u8; ID_BYTES],
    /// The `IrcRecoveryElementKind` wire value.
    pub element_kind: u8,
    /// The element's `IrcWireObjectKind` wire value.
    pub element_object_kind: u8,
    /// The element's object identifier.
    pub element_object_id: [u8; HASH_BYTES],
    /// The route sequence the element occupies.
    pub route_sequence: u64,
    /// The record the element succeeds.
    pub predecessor_record_id: [u8; HASH_BYTES],
    /// The trusted second the submission was accepted.
    pub accepted_at: u64,
    /// The submission object.
    pub submission_object_id: [u8; HASH_BYTES],
    /// Whether the element object is retained under this row.
    pub element_retained: bool,
    /// What the element produced.
    pub outcome: RecoveryOutcome,
}

impl RecoverySubmissionRow {
    /// The `recovery-submission/v1/<conversation><submission-id>` key.
    pub fn key(
        conversation_id: &[u8; HASH_BYTES],
        submission_id: &[u8; HASH_BYTES],
    ) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::RECOVERY_SUBMISSION, conversation_id, submission_id])
    }

    /// The conversation and submission identifiers of a key.
    pub fn parse_key(
        key: &StoredKey,
    ) -> Result<([u8; HASH_BYTES], [u8; HASH_BYTES]), StorageError> {
        let rest = suffix(key, prefix::RECOVERY_SUBMISSION, HASH_BYTES * 2)?;
        Ok((slice_array(rest, 0)?, slice_array(rest, HASH_BYTES)?))
    }

    /// The read plan over every row of this kind.
    pub fn range() -> Result<ReadPlan, StorageError> {
        let start = key_of(&[prefix::RECOVERY_SUBMISSION])?;
        prefix_range(start.as_bytes(), PAGE_LIMIT)
    }

    fn check(&self) -> Result<(), StorageError> {
        let valid = (1..=3).contains(&self.element_kind)
            && self.element_object_kind != 0
            && self.element_object_id != [0; HASH_BYTES]
            && self.accepted_at != 0
            && self.submission_object_id != [0; HASH_BYTES]
            && (self.element_retained || !self.outcome.is_complete());
        if valid {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Encodes the checked row into its wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = encoder()?;
        encoder.put_fixed(&self.account_id)?;
        encoder.put_fixed(&self.device_id)?;
        encoder.put_u16(u16::from(self.element_kind))?;
        encoder.put_u16(u16::from(self.element_object_kind))?;
        encoder.put_fixed(&self.element_object_id)?;
        encoder.put_u64(self.route_sequence)?;
        encoder.put_fixed(&self.predecessor_record_id)?;
        encoder.put_u64(self.accepted_at)?;
        encoder.put_fixed(&self.submission_object_id)?;
        put_bool(&mut encoder, self.element_retained)?;
        let (tag, first, second) = self.outcome.wire();
        encoder.put_u16(tag)?;
        encoder.put_fixed(&first)?;
        encoder.put_fixed(&second)?;
        wrap(RECOVERY_SUBMISSION_ROW_KIND, encoder.finish())
    }

    /// Decodes and checks one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(RECOVERY_SUBMISSION_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let account_id = decoder.array()?;
        let device_id = decoder.array()?;
        let element_kind =
            u8::try_from(decoder.u16()?).map_err(|_| StorageError::InvalidEncoding)?;
        let element_object_kind =
            u8::try_from(decoder.u16()?).map_err(|_| StorageError::InvalidEncoding)?;
        let element_object_id = decoder.array()?;
        let route_sequence = decoder.u64()?;
        let predecessor_record_id = decoder.array()?;
        let accepted_at = decoder.u64()?;
        let submission_object_id = decoder.array()?;
        let element_retained = take_bool(&mut decoder)?;
        let tag = decoder.u16()?;
        let first = decoder.array()?;
        let second = decoder.array()?;
        decoder.finish()?;
        let row = Self {
            account_id,
            device_id,
            element_kind,
            element_object_kind,
            element_object_id,
            route_sequence,
            predecessor_record_id,
            accepted_at,
            submission_object_id,
            element_retained,
            outcome: RecoveryOutcome::from_wire(tag, first, second)?,
        };
        row.check()?;
        Ok(row)
    }
}

/// One sequencer record a recovery installed beyond the restored head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryRecordRow {
    /// The record's semantic identifier.
    pub record_id: [u8; HASH_BYTES],
    /// The retained record object.
    pub record_object_id: [u8; HASH_BYTES],
    /// The record it succeeds.
    pub predecessor_record_id: [u8; HASH_BYTES],
    /// The `IrcSequencerRecordKind` wire value.
    pub record_kind: u8,
    /// The submission that carried it.
    pub submission_id: [u8; HASH_BYTES],
}

impl RecoveryRecordRow {
    /// The `recovery-record/v1/<conversation><route-sequence>` key.
    pub fn key(
        conversation_id: &[u8; HASH_BYTES],
        route_sequence: u64,
    ) -> Result<StoredKey, StorageError> {
        key_of(&[
            prefix::RECOVERY_RECORD,
            conversation_id,
            &route_sequence.to_be_bytes(),
        ])
    }

    /// The conversation and route sequence of a key.
    pub fn parse_key(key: &StoredKey) -> Result<([u8; HASH_BYTES], u64), StorageError> {
        let rest = suffix(key, prefix::RECOVERY_RECORD, HASH_BYTES + 8)?;
        Ok((
            slice_array(rest, 0)?,
            u64::from_be_bytes(slice_array(rest, HASH_BYTES)?),
        ))
    }

    /// The read plan over every row of this kind.
    pub fn range() -> Result<ReadPlan, StorageError> {
        let start = key_of(&[prefix::RECOVERY_RECORD])?;
        prefix_range(start.as_bytes(), PAGE_LIMIT)
    }

    fn check(&self) -> Result<(), StorageError> {
        let valid = self.record_id != [0; HASH_BYTES]
            && self.record_object_id != [0; HASH_BYTES]
            && (1..=6).contains(&self.record_kind)
            && self.submission_id != [0; HASH_BYTES];
        if valid {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }

    /// Encodes the checked row into its wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = encoder()?;
        encoder.put_fixed(&self.record_id)?;
        encoder.put_fixed(&self.record_object_id)?;
        encoder.put_fixed(&self.predecessor_record_id)?;
        encoder.put_u16(u16::from(self.record_kind))?;
        encoder.put_fixed(&self.submission_id)?;
        wrap(RECOVERY_RECORD_ROW_KIND, encoder.finish())
    }

    /// Decodes and checks one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(RECOVERY_RECORD_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let row = Self {
            record_id: decoder.array()?,
            record_object_id: decoder.array()?,
            predecessor_record_id: decoder.array()?,
            record_kind: u8::try_from(decoder.u16()?).map_err(|_| StorageError::InvalidEncoding)?,
            submission_id: decoder.array()?,
        };
        decoder.finish()?;
        row.check()?;
        Ok(row)
    }
}
