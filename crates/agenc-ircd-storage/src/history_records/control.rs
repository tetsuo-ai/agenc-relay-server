//! Durable history accounting and restartable purge progress.

use agenc_ircd_types::ChannelInstanceId;

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

use super::{HISTORY_BODY_VERSION, version};

const MAX_CONTROL_BYTES: usize = 128;
const MAX_CHANNEL_MESSAGES: u64 = 65_536;
const MAX_CHANNEL_LOGICAL_BYTES: u64 = 67_108_864;

/// A purge retains its exact operation identity until its final outcome commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryPurgeState {
    /// No purge remains to finish.
    Idle,
    /// The frozen cutoff is already unavailable; physical deletion continues.
    Active {
        /// Last sequence included in this purge.
        cutoff_sequence: u64,
        /// Last sequence examined by a committed deletion batch.
        last_scanned_sequence: u64,
        /// Identity correlating the signed intent and its durable outcome.
        operation_id: [u8; 32],
        /// Sequence of the signed administrative intent.
        audit_intent_sequence: u64,
    },
}

/// Sequence-zero accounting for one immutable channel instance.
#[derive(Clone, Eq, PartialEq)]
pub struct HistoryControlRecord {
    /// Exact owner of this history namespace.
    pub channel_id: ChannelInstanceId,
    /// Positive authority epoch; ordinary message writes do not advance it.
    pub history_authorization_generation: u64,
    /// Greatest message sequence ever inserted while this control exists.
    pub high_water_sequence: u64,
    /// Physically retained messages, including hidden rows awaiting purge.
    pub retained_message_count: u64,
    /// Exact logical charges of the physically retained message rows.
    pub retained_logical_bytes: u64,
    /// Messages through this sequence cannot be returned, even before deletion.
    pub purged_through: u64,
    /// Durable progress of the current administrative purge.
    pub purge: HistoryPurgeState,
}

impl HistoryControlRecord {
    /// Creates an empty control when explicit history policy is enabled.
    pub fn empty(
        channel_id: ChannelInstanceId,
        history_authorization_generation: u64,
    ) -> Result<Self, StorageError> {
        let record = Self {
            channel_id,
            history_authorization_generation,
            high_water_sequence: 0,
            retained_message_count: 0,
            retained_logical_bytes: 0,
            purged_through: 0,
            purge: HistoryPurgeState::Idle,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates internal accounting and purge bounds; startup also checks actual rows.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.history_authorization_generation == 0
            || self.retained_message_count > MAX_CHANNEL_MESSAGES
            || self.retained_logical_bytes > MAX_CHANNEL_LOGICAL_BYTES
            || self.retained_message_count > self.high_water_sequence
            || self.purged_through > self.high_water_sequence
            || (self.retained_message_count == 0) != (self.retained_logical_bytes == 0)
        {
            return Err(StorageError::InvalidEncoding);
        }
        self.validate_purge()
    }

    fn validate_purge(&self) -> Result<(), StorageError> {
        if let HistoryPurgeState::Active {
            cutoff_sequence,
            last_scanned_sequence,
            operation_id,
            audit_intent_sequence: _,
        } = self.purge
            && (cutoff_sequence > self.purged_through
                || last_scanned_sequence > cutoff_sequence
                || operation_id == [0; 32])
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    /// Encodes the version-one control body, without a persistent-record envelope.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(MAX_CONTROL_BYTES, MAX_CONTROL_BYTES)?;
        encoder.put_u16(HISTORY_BODY_VERSION)?;
        encoder.put_fixed(self.channel_id.as_bytes())?;
        encoder.put_u64(self.history_authorization_generation)?;
        encoder.put_u64(self.high_water_sequence)?;
        encoder.put_u64(self.retained_message_count)?;
        encoder.put_u64(self.retained_logical_bytes)?;
        encoder.put_u64(self.purged_through)?;
        match self.purge {
            HistoryPurgeState::Idle => encoder.put_u16(0)?,
            HistoryPurgeState::Active {
                cutoff_sequence,
                last_scanned_sequence,
                operation_id,
                audit_intent_sequence,
            } => {
                encoder.put_u16(1)?;
                encoder.put_u64(cutoff_sequence)?;
                encoder.put_u64(last_scanned_sequence)?;
                encoder.put_fixed(&operation_id)?;
                encoder.put_u64(audit_intent_sequence)?;
            }
        }
        Ok(encoder.finish())
    }

    /// Decodes and validates a complete control body, rejecting unknown extensions.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() > MAX_CONTROL_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(body);
        version(&mut decoder)?;
        let record = Self {
            channel_id: ChannelInstanceId::from_bytes(decoder.array()?),
            history_authorization_generation: decoder.u64()?,
            high_water_sequence: decoder.u64()?,
            retained_message_count: decoder.u64()?,
            retained_logical_bytes: decoder.u64()?,
            purged_through: decoder.u64()?,
            purge: match decoder.u16()? {
                0 => HistoryPurgeState::Idle,
                1 => HistoryPurgeState::Active {
                    cutoff_sequence: decoder.u64()?,
                    last_scanned_sequence: decoder.u64()?,
                    operation_id: decoder.array()?,
                    audit_intent_sequence: decoder.u64()?,
                },
                _ => return Err(StorageError::UnsupportedVersion),
            },
        };
        decoder.finish()?;
        record.validate()?;
        Ok(record)
    }
}
