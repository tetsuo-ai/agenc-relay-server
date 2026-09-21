//! Table 23 object ownership accounts (companion 15 and 16).
//!
//! Every retained table-22 object has one `owner/v1/<object-id>` row: its
//! retention class, the trusted times it was accepted and, once nothing
//! names it any more, retired, and its size. The rows that own the object
//! travel as the record's typed references, so storage validates every one
//! of them, and the runtime derives the same set from the owning rows
//! themselves; this body holds only what those rows cannot say.

#![forbid(unsafe_code)]

use super::{
    HASH_BYTES, PAGE_LIMIT, decoder, encoder, key_of, prefix, prefix_range, put_bool, slice_array,
    suffix, take_bool, unwrap, wrap,
};
use crate::{ReadPlan, StorageError, StoredKey};
use agenc_relay_e2ee::object::ArcWireObjectKind;

/// The E2eeState object ownership account kind.
pub const OWNER_ROW_KIND: u16 = 16;
/// The second recorded for an acceptance or retirement whose trusted time is
/// unknown: a restore that dropped every owner, a reconstructed account
/// persisted, or a last owner retired, by a batch without a trusted clock.
/// Nothing ages by this value; the next dated batch replaces it.
pub const UNDATED_SECOND: u64 = u64::MAX;

/// How long an unowned object stays before physical cleanup may take it
/// (companion 15: `SEQUENCER_RECORD_RETENTION`, `SECURITY_PROOF_RETENTION`,
/// `WELCOME_RETENTION`, and the replay bounds of Section 16).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RetentionClass {
    /// Ordinary sequencer material: retained `SEQUENCER_RECORD_RETENTION`
    /// after its last owner retires.
    Ordinary = 1,
    /// A security proof of a live lineage: retained while the lineage lives
    /// and `WELCOME_RETENTION` after its final close.
    SecurityProof = 2,
    /// A mailbox payload: retained `WELCOME_RETENTION` after its last owner.
    Mailbox = 3,
    /// A replay result, response or delivered event: retained by the
    /// published replay bounds after its last owner.
    Replay = 4,
}

impl RetentionClass {
    /// Every class, in wire order.
    pub const ALL: [Self; 4] = [
        Self::Ordinary,
        Self::SecurityProof,
        Self::Mailbox,
        Self::Replay,
    ];

    /// The wire discriminant.
    #[must_use]
    pub const fn wire(self) -> u16 {
        self as u16
    }

    /// Decodes a wire discriminant.
    pub fn from_wire(value: u16) -> Result<Self, StorageError> {
        Self::ALL
            .into_iter()
            .find(|class| class.wire() == value)
            .ok_or(StorageError::InvalidEncoding)
    }
}

/// The ownership account of one retained object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectOwnerRow {
    /// The `ArcWireObjectKind` wire value of the object.
    pub kind: u8,
    /// The complete encoded object length.
    pub size: u64,
    /// The retention class the owning rows imply.
    pub retention: RetentionClass,
    /// The trusted time (seconds) the object was accepted, or, when
    /// `reconstructed`, the trusted time the account was rebuilt: a floor
    /// under every age, never an upload time or cache residency.
    pub accepted_at: u64,
    /// Whether `accepted_at` is a reconstruction floor rather than the
    /// acceptance itself.
    pub reconstructed: bool,
    /// The trusted time the last owner retired; `None` while owned.
    pub retired_at: Option<u64>,
}

impl ObjectOwnerRow {
    /// The `owner/v1/<object-id>` key.
    pub fn key(object_id: &[u8; HASH_BYTES]) -> Result<StoredKey, StorageError> {
        key_of(&[prefix::OWNER, object_id])
    }

    /// Splits an owner key.
    pub fn parse_key(key: &StoredKey) -> Result<[u8; HASH_BYTES], StorageError> {
        slice_array(suffix(key, prefix::OWNER, HASH_BYTES)?, 0)
    }

    /// Every ownership account, one page at a time from `after`.
    pub fn range() -> Result<ReadPlan, StorageError> {
        let start = key_of(&[prefix::OWNER])?;
        prefix_range(start.as_bytes(), PAGE_LIMIT)
    }

    /// Whether `key` is an owner key.
    #[must_use]
    pub fn matches_key(key: &StoredKey) -> bool {
        Self::parse_key(key).is_ok()
    }

    /// The object kind, when the stored value names one.
    pub fn object_kind(&self) -> Result<ArcWireObjectKind, StorageError> {
        ArcWireObjectKind::from_value(self.kind).map_err(|_| StorageError::InvalidEncoding)
    }

    /// Encodes the wrapped body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.check()?;
        let mut encoder = encoder()?;
        encoder.put_u16(u16::from(self.kind))?;
        encoder.put_u64(self.size)?;
        encoder.put_u16(self.retention.wire())?;
        encoder.put_u64(self.accepted_at)?;
        put_bool(&mut encoder, self.reconstructed)?;
        encoder.put_u64(self.retired_at.unwrap_or(0))?;
        wrap(OWNER_ROW_KIND, encoder.finish())
    }

    /// Decodes one wrapped body.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(OWNER_ROW_KIND, body)?;
        let mut decoder = decoder(&inner)?;
        let kind = u8::try_from(decoder.u16()?).map_err(|_| StorageError::InvalidEncoding)?;
        let size = decoder.u64()?;
        let retention = RetentionClass::from_wire(decoder.u16()?)?;
        let accepted_at = decoder.u64()?;
        let reconstructed = take_bool(&mut decoder)?;
        let retired_at = match decoder.u64()? {
            0 => None,
            at => Some(at),
        };
        decoder.finish()?;
        let row = Self {
            kind,
            size,
            retention,
            accepted_at,
            reconstructed,
            retired_at,
        };
        row.check()?;
        Ok(row)
    }

    fn check(&self) -> Result<(), StorageError> {
        let kind = self.object_kind()?;
        let maximum =
            u64::try_from(kind.maximum_object_bytes()).map_err(|_| StorageError::Overflow)?;
        let sized = self.size != 0 && self.size <= maximum;
        let aged = self.accepted_at != 0
            && self
                .retired_at
                .is_none_or(|retired| retired >= self.accepted_at);
        if sized && aged {
            Ok(())
        } else {
            Err(StorageError::InvalidEncoding)
        }
    }
}
