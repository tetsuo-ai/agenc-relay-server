//! A retained copy's bounded byte count and original acknowledgement metadata.
#![forbid(unsafe_code)]

use super::{Acknowledgement, CompanionFault};
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::{
    MAX_EVENT_BYTES, MAX_PAYLOAD_BYTES,
};

/// Scope and object identities must be checked by the owner of the source read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::e2ee::coordinator::delivery_owner) struct Row {
    pub(super) sequence: u64,
    pub(super) event_id: [u8; 16],
    pub(super) bytes: u64,
    pub(super) acknowledgement: Acknowledgement,
}

impl Row {
    pub(super) fn new(
        sequence: u64,
        event_id: [u8; 16],
        event_bytes: u32,
        payload_bytes: u32,
        acknowledgement: Acknowledgement,
    ) -> Result<Self, CompanionFault> {
        if !(1..=MAX_EVENT_BYTES).contains(&event_bytes) || payload_bytes > MAX_PAYLOAD_BYTES {
            return Err(CompanionFault::Storage);
        }
        if let Acknowledgement::AcknowledgedAt {
            received_unix_seconds,
            ..
        } = acknowledgement
            && Acknowledgement::received_at(Some(received_unix_seconds)) != acknowledgement
        {
            return Err(CompanionFault::Storage);
        }
        Ok(Self {
            sequence,
            event_id,
            bytes: u64::from(event_bytes) + u64::from(payload_bytes),
            acknowledgement,
        })
    }

    pub(super) fn expired(self, now: Option<u64>) -> bool {
        match (self.acknowledgement, now) {
            (
                Acknowledgement::AcknowledgedAt {
                    retain_until_unix_seconds,
                    ..
                },
                Some(now),
            ) => now >= retain_until_unix_seconds,
            _ => false,
        }
    }
}
