//! Exact accepted scope and explicit before-first delivery cursors.
#![forbid(unsafe_code)]

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Accepted companion delivery scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryScopeFields {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Coordinator server identity.
    pub coordinator_server_id: [u8; 16],
    /// Coordinator incarnation.
    pub coordinator_incarnation: [u8; 16],
    /// Coordinator recovery epoch.
    pub coordinator_recovery_epoch: [u8; 16],
    /// Target server identity.
    pub target_server_id: [u8; 16],
    /// Target incarnation.
    pub target_incarnation: [u8; 16],
    /// Base resynchronization epoch captured at cut creation.
    pub covered_base_client_resync_epoch: u64,
}

/// Validated accepted companion delivery scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryScope {
    fields: DeliveryScopeFields,
}

impl DeliveryScope {
    /// Validates one complete set of fields.
    pub fn new(fields: DeliveryScopeFields) -> Result<Self, StorageError> {
        Ok(Self { fields })
    }

    /// Returns network identity.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.fields.network_id
    }

    /// Returns coordinator server identity.
    #[must_use]
    pub const fn coordinator_server_id(&self) -> [u8; 16] {
        self.fields.coordinator_server_id
    }

    /// Returns coordinator incarnation.
    #[must_use]
    pub const fn coordinator_incarnation(&self) -> [u8; 16] {
        self.fields.coordinator_incarnation
    }

    /// Returns coordinator recovery epoch.
    #[must_use]
    pub const fn coordinator_recovery_epoch(&self) -> [u8; 16] {
        self.fields.coordinator_recovery_epoch
    }

    /// Returns target server identity.
    #[must_use]
    pub const fn target_server_id(&self) -> [u8; 16] {
        self.fields.target_server_id
    }

    /// Returns target incarnation.
    #[must_use]
    pub const fn target_incarnation(&self) -> [u8; 16] {
        self.fields.target_incarnation
    }

    /// Returns base resynchronization epoch captured at cut creation.
    #[must_use]
    pub const fn covered_base_client_resync_epoch(&self) -> u64 {
        self.fields.covered_base_client_resync_epoch
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_fixed(&self.fields.network_id)?;
        encoder.put_fixed(&self.fields.coordinator_server_id)?;
        encoder.put_fixed(&self.fields.coordinator_incarnation)?;
        encoder.put_fixed(&self.fields.coordinator_recovery_epoch)?;
        encoder.put_fixed(&self.fields.target_server_id)?;
        encoder.put_fixed(&self.fields.target_incarnation)?;
        encoder.put_u64(self.fields.covered_base_client_resync_epoch)?;
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(DeliveryScopeFields {
            network_id: decoder.array()?,
            coordinator_server_id: decoder.array()?,
            coordinator_incarnation: decoder.array()?,
            coordinator_recovery_epoch: decoder.array()?,
            target_server_id: decoder.array()?,
            target_incarnation: decoder.array()?,
            covered_base_client_resync_epoch: decoder.u64()?,
        })
    }
}

/// Durable cursor position, without an event-ID sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LastAcknowledged {
    /// No event in this generation has been acknowledged.
    BeforeFirst,
    /// Exact acknowledged event, including a valid sequence zero.
    At {
        /// Delivery sequence.
        sequence: u64,
        /// Event identity; all-zero bytes remain an ordinary identifier.
        event_id: [u8; 16],
    },
}

/// One generation's assigned sequence ceiling and durable ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryCursor {
    generation: u64,
    next_sequence: u64,
    last_ack: LastAcknowledged,
}

impl DeliveryCursor {
    /// Refuses an ACK of an event that has not been assigned.
    pub fn new(
        generation: u64,
        next_sequence: u64,
        last_ack: LastAcknowledged,
    ) -> Result<Self, StorageError> {
        if matches!(last_ack, LastAcknowledged::At { sequence, .. } if sequence >= next_sequence) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            generation,
            next_sequence,
            last_ack,
        })
    }

    /// Returns the delivery generation, which may be zero.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the next sequence to assign.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the exact last acknowledged position.
    #[must_use]
    pub const fn last_ack(&self) -> LastAcknowledged {
        self.last_ack
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_u64(self.generation)?;
        encoder.put_u64(self.next_sequence)?;
        match self.last_ack {
            LastAcknowledged::BeforeFirst => encoder.put_u16(0),
            LastAcknowledged::At { sequence, event_id } => {
                encoder.put_u16(1)?;
                encoder.put_u64(sequence)?;
                encoder.put_fixed(&event_id)
            }
        }
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let generation = decoder.u64()?;
        let next_sequence = decoder.u64()?;
        let last_ack = match decoder.u16()? {
            0 => LastAcknowledged::BeforeFirst,
            1 => LastAcknowledged::At {
                sequence: decoder.u64()?,
                event_id: decoder.array()?,
            },
            _ => return Err(StorageError::InvalidEncoding),
        };
        Self::new(generation, next_sequence, last_ack)
    }
}
