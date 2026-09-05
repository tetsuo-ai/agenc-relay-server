//! Bounded body-free facts needed to reconstruct an exact history result.

use agenc_ircd_domain::{ChannelNameValue, ChannelScope};

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

use super::{HistoryAuthorizationBinding, MAX_HISTORY_QUERY_MESSAGES, text};

/// A canonical history request fits this bound, independently of the generic object ceiling.
pub const MAX_HISTORY_REQUEST_BYTES: usize = 1_024;

/// Complete request binding retained without a client label or response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRequestIdentity {
    /// Exact home/incarnation/origin/generation/operation-sequence key.
    pub replay_key: [u8; 64],
    /// Original request identity.
    pub request_id: [u8; 16],
    /// Digest of the exact canonical request bytes.
    pub request_object_id: [u8; 32],
    /// Only the canonical history request, never a response or message object.
    pub request_object: Vec<u8>,
}

impl HistoryRequestIdentity {
    pub(super) fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        if self.request_object.is_empty() || self.request_object.len() > MAX_HISTORY_REQUEST_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        encoder.put_fixed(&self.replay_key)?;
        encoder.put_fixed(&self.request_id)?;
        encoder.put_fixed(&self.request_object_id)?;
        encoder.put_vector_u32(&self.request_object)
    }

    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let record = Self {
            replay_key: decoder.array()?,
            request_id: decoder.array()?,
            request_object_id: decoder.array()?,
            request_object: decoder.vector_u32(MAX_HISTORY_REQUEST_BYTES)?.to_vec(),
        };
        if record.request_object.is_empty() {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(record)
    }
}

/// Immutable history-row facts; they never pin a body past its retention boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRowReference {
    /// Sequence component of the table-19 key.
    pub channel_sequence: u64,
    /// Original MessageId, checked again when its body is fetched.
    pub message_id: [u8; 16],
    /// Original acceptance timestamp.
    pub received_unix_milliseconds: u64,
    /// Immutable body expiry.
    pub expires_unix_milliseconds: u64,
}

impl HistoryRowReference {
    fn encode(self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u64(self.channel_sequence)?;
        encoder.put_fixed(&self.message_id)?;
        encoder.put_u64(self.received_unix_milliseconds)?;
        encoder.put_u64(self.expires_unix_milliseconds)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Ok(Self {
            channel_sequence: decoder.u64()?,
            message_id: decoder.array()?,
            received_unix_milliseconds: decoder.u64()?,
            expires_unix_milliseconds: decoder.u64()?,
        })
    }
}

/// The frozen presentation and selected identities of one successful history page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPageMetadata {
    /// Principal and policy epoch that authorized the immutable selection.
    pub authorization: HistoryAuthorizationBinding,
    /// Immutable target, not a name-only lookup.
    pub channel_id: [u8; 16],
    /// The target spelling returned in the original page.
    pub channel_name: String,
    /// Original query snapshot identity.
    pub snapshot_token: [u8; 32],
    /// Authoritative state cut used to select rows.
    pub state_cut: u64,
    /// Zero-based page sequence.
    pub page_sequence: u32,
    /// Exact successor cursor supplied by this page.
    pub next_cursor: Option<[u8; 32]>,
    /// Selected rows, in final ascending delivery order.
    pub selected: Vec<HistoryRowReference>,
    /// Original authoritative creation time.
    pub created_unix_milliseconds: u64,
    /// Original absolute query expiry; replay never extends it.
    pub deadline_unix_milliseconds: u64,
}

impl HistoryPageMetadata {
    /// Validates a bounded ordered snapshot without accessing message bodies.
    pub fn validate(&self) -> Result<(), StorageError> {
        self.authorization.validate()?;
        let channel = ChannelNameValue::parse(&self.channel_name)
            .map_err(|_| StorageError::InvalidEncoding)?;
        if channel.scope() != ChannelScope::Global
            || self.state_cut == 0
            || self.selected.len() > MAX_HISTORY_QUERY_MESSAGES
            || self.deadline_unix_milliseconds <= self.created_unix_milliseconds
        {
            return Err(StorageError::InvalidEncoding);
        }
        let mut previous = 0;
        for row in &self.selected {
            if row.channel_sequence <= previous
                || row.channel_sequence > self.state_cut
                || row.expires_unix_milliseconds <= row.received_unix_milliseconds
            {
                return Err(StorageError::InvalidEncoding);
            }
            previous = row.channel_sequence;
        }
        Ok(())
    }

    pub(super) fn encode(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.validate()?;
        self.authorization.encode(encoder)?;
        encoder.put_fixed(&self.channel_id)?;
        encoder.put_vector_u32(self.channel_name.as_bytes())?;
        encoder.put_fixed(&self.snapshot_token)?;
        encoder.put_u64(self.state_cut)?;
        encoder.put_u32(self.page_sequence)?;
        put_optional_hash(encoder, self.next_cursor)?;
        encoder.put_u64(self.created_unix_milliseconds)?;
        encoder.put_u64(self.deadline_unix_milliseconds)?;
        encoder.put_u16(u16::try_from(self.selected.len()).map_err(|_| StorageError::Overflow)?)?;
        for row in &self.selected {
            row.encode(encoder)?;
        }
        Ok(())
    }

    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let mut record = Self {
            authorization: HistoryAuthorizationBinding::decode(decoder)?,
            channel_id: decoder.array()?,
            channel_name: text(decoder, 64)?,
            snapshot_token: decoder.array()?,
            state_cut: decoder.u64()?,
            page_sequence: decoder.u32()?,
            next_cursor: take_optional_hash(decoder)?,
            created_unix_milliseconds: decoder.u64()?,
            deadline_unix_milliseconds: decoder.u64()?,
            selected: Vec::new(),
        };
        let count = usize::from(decoder.u16()?);
        if count > MAX_HISTORY_QUERY_MESSAGES {
            return Err(StorageError::LimitExceeded);
        }
        record
            .selected
            .try_reserve_exact(count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..count {
            record.selected.push(HistoryRowReference::decode(decoder)?);
        }
        record.validate()?;
        Ok(record)
    }
}

pub(super) fn put_optional_hash(
    encoder: &mut Encoder,
    hash: Option<[u8; 32]>,
) -> Result<(), StorageError> {
    match hash {
        None => encoder.put_u16(0),
        Some(hash) => {
            encoder.put_u16(1)?;
            encoder.put_fixed(&hash)
        }
    }
}

pub(super) fn take_optional_hash(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; 32]>, StorageError> {
    match decoder.u16()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.array()?)),
        _ => Err(StorageError::InvalidEncoding),
    }
}
