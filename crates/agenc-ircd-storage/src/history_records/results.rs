//! History query recovery stores identities and hashes, never message bodies.

use crate::codec::{Decoder, Encoder};
use crate::{ProtocolRecordBody, StorageError, TableId};

use super::metadata::{put_optional_hash, take_optional_hash};
use super::{HistoryAuthorizationBinding, HistoryPageMetadata, HistoryRequestIdentity, version};

/// Coordinator metadata-only history result arm of table 13.
pub const HISTORY_COORDINATOR_RESULT_KIND: u16 = 5;
/// Edge metadata-only history request/rendering arm of table 13.
pub const HISTORY_EDGE_REQUEST_KIND: u16 = 6;
/// Complete metadata body ceiling, including its protocol wrapper.
pub const MAX_HISTORY_RESULT_RECORD_BYTES: usize = 8_192;

/// A successful history page can undergo only one terminal expiry transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryResultStatus {
    /// The exact page may be reconstructed while every original gate still holds.
    Available,
    /// Every later retry returns the same history_expired object.
    Expired {
        /// Digest of the canonical terminal result reconstructed from request and original ID.
        result_object_id: [u8; 32],
    },
}

/// Durable coordinator outcome retaining no plaintext response frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCoordinatorResultRecord {
    /// Exact request and replay binding.
    pub request: HistoryRequestIdentity,
    /// Digest the successful page must reproduce byte-for-byte.
    pub original_result_object_id: [u8; 32],
    /// Original page selection and authorization facts.
    pub page: HistoryPageMetadata,
    /// Available or permanently expired; never re-execute the selector.
    pub status: HistoryResultStatus,
}

impl HistoryCoordinatorResultRecord {
    /// Encodes the table/kind-bound metadata body.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = encoder()?;
        self.request.encode(&mut encoder)?;
        encoder.put_fixed(&self.original_result_object_id)?;
        self.page.encode(&mut encoder)?;
        match self.status {
            HistoryResultStatus::Available => encoder.put_u16(0)?,
            HistoryResultStatus::Expired { result_object_id } => {
                encoder.put_u16(1)?;
                encoder.put_fixed(&result_object_id)?;
            }
        }
        wrap(HISTORY_COORDINATOR_RESULT_KIND, encoder.finish())
    }

    /// Decodes only bounded metadata; response body fields do not exist in this arm.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(HISTORY_COORDINATOR_RESULT_KIND, body)?;
        let mut decoder = Decoder::new(inner.canonical_object());
        version(&mut decoder)?;
        let record = Self {
            request: HistoryRequestIdentity::decode(&mut decoder)?,
            original_result_object_id: decoder.array()?,
            page: HistoryPageMetadata::decode(&mut decoder)?,
            status: match decoder.u16()? {
                0 => HistoryResultStatus::Available,
                1 => HistoryResultStatus::Expired {
                    result_object_id: decoder.array()?,
                },
                _ => return Err(StorageError::InvalidEncoding),
            },
        };
        decoder.finish()?;
        Ok(record)
    }
}

/// Edge request lifecycle without retained message frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryEdgePhase {
    /// No complete response has arrived.
    Pending,
    /// A complete page arrived and its identity was committed.
    Received,
    /// The page was already released to its local connection.
    Rendered,
    /// A terminal history_expired result was committed.
    Expired,
}

impl HistoryEdgePhase {
    const fn value(self) -> u16 {
        match self {
            Self::Pending => 0,
            Self::Received => 1,
            Self::Rendered => 2,
            Self::Expired => 3,
        }
    }

    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Received),
            2 => Ok(Self::Rendered),
            3 => Ok(Self::Expired),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// Edge recovery of a history operation without persisting a history page body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEdgeRequestRecord {
    /// Exact request bytes for retransmission under the same operation sequence.
    pub request: HistoryRequestIdentity,
    /// Original successful result hash, learned from a page or its expiry successor.
    pub original_result_object_id: Option<[u8; 32]>,
    /// Exact terminal result hash, if expiry was received.
    pub expired_result_object_id: Option<[u8; 32]>,
    /// The page's authorization binding, absent until a page actually arrives.
    pub authorization: Option<HistoryAuthorizationBinding>,
    /// Absolute original query deadline.
    pub deadline_unix_milliseconds: u64,
    /// Committed local rendering state.
    pub phase: HistoryEdgePhase,
    /// The originating connection disappeared and cannot receive output.
    pub sink_gone: bool,
}

impl HistoryEdgeRequestRecord {
    /// Validates the result/authorization presence permitted by the current phase.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.deadline_unix_milliseconds == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        if let Some(binding) = self.authorization {
            binding.validate()?;
        }
        let valid = match self.phase {
            HistoryEdgePhase::Pending => {
                self.original_result_object_id.is_none()
                    && self.expired_result_object_id.is_none()
                    && self.authorization.is_none()
            }
            HistoryEdgePhase::Received | HistoryEdgePhase::Rendered => {
                self.original_result_object_id.is_some()
                    && self.expired_result_object_id.is_none()
                    && self.authorization.is_some()
            }
            HistoryEdgePhase::Expired => {
                self.original_result_object_id.is_some() && self.expired_result_object_id.is_some()
            }
        };
        if !valid {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    /// Encodes the table/kind-bound body without a message/result byte vector.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = encoder()?;
        self.request.encode(&mut encoder)?;
        put_optional_hash(&mut encoder, self.original_result_object_id)?;
        put_optional_hash(&mut encoder, self.expired_result_object_id)?;
        match self.authorization {
            None => encoder.put_u16(0)?,
            Some(binding) => {
                encoder.put_u16(1)?;
                binding.encode(&mut encoder)?;
            }
        }
        encoder.put_u64(self.deadline_unix_milliseconds)?;
        encoder.put_u16(self.phase.value())?;
        encoder.put_u16(u16::from(self.sink_gone))?;
        wrap(HISTORY_EDGE_REQUEST_KIND, encoder.finish())
    }

    /// Decodes and checks a complete edge history record.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        let inner = unwrap(HISTORY_EDGE_REQUEST_KIND, body)?;
        let mut decoder = Decoder::new(inner.canonical_object());
        version(&mut decoder)?;
        let record = Self {
            request: HistoryRequestIdentity::decode(&mut decoder)?,
            original_result_object_id: take_optional_hash(&mut decoder)?,
            expired_result_object_id: take_optional_hash(&mut decoder)?,
            authorization: match decoder.u16()? {
                0 => None,
                1 => Some(HistoryAuthorizationBinding::decode(&mut decoder)?),
                _ => return Err(StorageError::InvalidEncoding),
            },
            deadline_unix_milliseconds: decoder.u64()?,
            phase: HistoryEdgePhase::decode(decoder.u16()?)?,
            sink_gone: match decoder.u16()? {
                0 => false,
                1 => true,
                _ => return Err(StorageError::InvalidEncoding),
            },
        };
        decoder.finish()?;
        record.validate()?;
        Ok(record)
    }
}

fn encoder() -> Result<Encoder, StorageError> {
    let mut encoder = Encoder::with_capacity(
        MAX_HISTORY_RESULT_RECORD_BYTES - 12,
        MAX_HISTORY_RESULT_RECORD_BYTES - 12,
    )?;
    encoder.put_u16(super::HISTORY_BODY_VERSION)?;
    Ok(encoder)
}

fn wrap(kind: u16, body: Vec<u8>) -> Result<Vec<u8>, StorageError> {
    ProtocolRecordBody::new(TableId::RequestResult, kind, 1, body)?.encode()
}

fn unwrap(kind: u16, body: &[u8]) -> Result<ProtocolRecordBody, StorageError> {
    if body.len() > MAX_HISTORY_RESULT_RECORD_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    ProtocolRecordBody::decode(TableId::RequestResult, kind, body)
}
