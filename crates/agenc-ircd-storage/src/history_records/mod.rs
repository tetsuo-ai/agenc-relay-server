//! Typed plaintext history records and metadata-only query recovery.

mod authorization;
mod control;
mod inventory;
mod message;
mod metadata;
mod results;
pub(crate) use inventory::HistoryInventory;

pub use authorization::HistoryAuthorizationBinding;
pub use metadata::{
    HistoryPageMetadata, HistoryRequestIdentity, HistoryRowReference, MAX_HISTORY_REQUEST_BYTES,
};
pub use results::{
    HISTORY_COORDINATOR_RESULT_KIND, HISTORY_EDGE_REQUEST_KIND, HistoryCoordinatorResultRecord,
    HistoryEdgePhase, HistoryEdgeRequestRecord, HistoryResultStatus,
    MAX_HISTORY_RESULT_RECORD_BYTES,
};

pub(crate) fn validate_result_binding(
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), StorageError> {
    let expected = match value.record_kind() {
        HISTORY_COORDINATOR_RESULT_KIND => {
            HistoryCoordinatorResultRecord::decode(value.body())?
                .request
                .replay_key
        }
        HISTORY_EDGE_REQUEST_KIND => {
            HistoryEdgeRequestRecord::decode(value.body())?
                .request
                .replay_key
        }
        _ => return Err(StorageError::UnsupportedVersion),
    };
    if key.as_bytes() != expected {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

pub use control::{HistoryControlRecord, HistoryPurgeState};
pub use message::HistoryMessageRecord;

use agenc_ircd_types::ChannelInstanceId;

use crate::codec::Decoder;
use crate::{PersistentRecordValue, StorageError, StoredKey};

/// The positive-sequence history message arm.
pub const HISTORY_MESSAGE_KIND: u16 = 1;
/// The sequence-zero per-channel accounting and purge arm.
pub const HISTORY_CONTROL_KIND: u16 = 2;
/// Maximum encoded history message body, including its immutable public metadata.
pub const MAX_HISTORY_RECORD_BYTES: usize = 16_384;
/// Maximum number of messages selected by one history command.
pub const MAX_HISTORY_QUERY_MESSAGES: usize = 100;
/// Version of both table-19 body encodings in schema generation two.
const HISTORY_BODY_VERSION: u16 = 1;

/// Constructs the fixed table-19 key of one positive-sequence message.
pub fn history_message_key(
    channel_id: ChannelInstanceId,
    channel_sequence: u64,
) -> Result<StoredKey, StorageError> {
    if channel_sequence == 0 {
        return Err(StorageError::InvalidEncoding);
    }
    history_key(channel_id, channel_sequence)
}

/// Constructs the reserved sequence-zero key for a channel's control record.
pub fn history_control_key(channel_id: ChannelInstanceId) -> Result<StoredKey, StorageError> {
    history_key(channel_id, 0)
}

fn history_key(channel_id: ChannelInstanceId, sequence: u64) -> Result<StoredKey, StorageError> {
    let mut key = Vec::new();
    key.try_reserve_exact(24)
        .map_err(|_| StorageError::AllocationFailed)?;
    key.extend_from_slice(channel_id.as_bytes());
    key.extend_from_slice(&sequence.to_be_bytes());
    StoredKey::new(key)
}

/// Decodes the fixed channel/sequence key without assigning an arm to sequence zero.
pub fn parse_history_key(key: &StoredKey) -> Result<(ChannelInstanceId, u64), StorageError> {
    let mut decoder = Decoder::new(key.as_bytes());
    let channel = ChannelInstanceId::from_bytes(decoder.array()?);
    let sequence = decoder.u64()?;
    decoder.finish()?;
    Ok((channel, sequence))
}

pub(crate) fn validate_body(kind: u16, body: &[u8]) -> Result<(), StorageError> {
    match kind {
        HISTORY_MESSAGE_KIND => HistoryMessageRecord::decode(body).map(|_| ()),
        HISTORY_CONTROL_KIND => HistoryControlRecord::decode(body).map(|_| ()),
        _ => Err(StorageError::UnsupportedVersion),
    }
}

pub(crate) fn validate_binding(
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), StorageError> {
    let (channel, sequence) = parse_history_key(key)?;
    match value.record_kind() {
        HISTORY_MESSAGE_KIND => {
            let message = HistoryMessageRecord::decode(value.body())?;
            if channel != message.channel_id
                || sequence != message.channel_sequence
                || value.expires_at() != Some(message.expires_unix_milliseconds.div_ceil(1_000))
            {
                return Err(StorageError::StaleState);
            }
        }
        HISTORY_CONTROL_KIND => {
            let control = HistoryControlRecord::decode(value.body())?;
            if channel != control.channel_id || sequence != 0 || value.expires_at().is_some() {
                return Err(StorageError::StaleState);
            }
        }
        _ => return Err(StorageError::UnsupportedVersion),
    }
    Ok(())
}

fn version(decoder: &mut Decoder<'_>) -> Result<(), StorageError> {
    if decoder.u16()? != HISTORY_BODY_VERSION {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(())
}

fn text(decoder: &mut Decoder<'_>, maximum: usize) -> Result<String, StorageError> {
    let bytes = decoder.vector_u32(maximum)?;
    let input = std::str::from_utf8(bytes).map_err(|_| StorageError::InvalidEncoding)?;
    let mut value = String::new();
    value
        .try_reserve_exact(input.len())
        .map_err(|_| StorageError::AllocationFailed)?;
    value.push_str(input);
    Ok(value)
}
