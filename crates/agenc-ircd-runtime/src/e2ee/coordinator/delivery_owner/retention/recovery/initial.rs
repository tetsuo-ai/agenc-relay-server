//! Before the first ACK, every retained delivery row must be unacknowledged.
#![forbid(unsafe_code)]

use super::{CompanionFault, DeliveryOwner, Restored, ScopedOutbox};
use agenc_ircd_e2ee::limits::{
    MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE, MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{Acknowledgement, LastAcknowledged};

pub(super) struct Scan {
    current: DeliveryOwner,
    next: u64,
    bytes: u64,
}

impl Scan {
    pub(super) fn new(current: DeliveryOwner) -> Result<Self, CompanionFault> {
        if current.cursor().last_ack() != LastAcknowledged::BeforeFirst
            || current.cursor().next_sequence() > MAX_UNACKED_E2EE_EVENTS_PER_EDGE
        {
            return Err(CompanionFault::Storage);
        }
        Ok(Self {
            current,
            next: 0,
            bytes: 0,
        })
    }

    pub(super) fn observe(&mut self, row: ScopedOutbox) -> Result<ScopedOutbox, CompanionFault> {
        if row.scope() != self.current.scope()
            || row.generation() != self.current.cursor().generation()
            || row.sequence() != self.next
            || row.sequence() >= self.current.cursor().next_sequence()
            || row.acknowledgement() != Acknowledgement::Unacknowledged
        {
            return Err(CompanionFault::Storage);
        }
        self.next = self.next.checked_add(1).ok_or(CompanionFault::Storage)?;
        let bytes = u64::from(row.event_bytes()) + u64::from(row.payload_bytes());
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(CompanionFault::Storage)?;
        if self.next > MAX_UNACKED_E2EE_EVENTS_PER_EDGE
            || self.bytes > MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE
        {
            return Err(CompanionFault::Storage);
        }
        Ok(row)
    }

    pub(super) fn finish(self) -> Result<Restored, CompanionFault> {
        if self.next != self.current.cursor().next_sequence() {
            return Err(CompanionFault::Storage);
        }
        Ok(Restored {
            owner: None,
            head: None,
        })
    }
}
