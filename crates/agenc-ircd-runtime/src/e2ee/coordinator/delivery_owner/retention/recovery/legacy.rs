//! Legacy per-row ACKs are inventoried completely before adoption by version two.
#![forbid(unsafe_code)]

use super::super::{Acknowledgement, LastAcknowledged, LegacyInventory};
use super::{CompanionFault, DeliveryOwner, Restored, Row, ScopedOutbox};
use agenc_ircd_e2ee::limits::{
    MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE, MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
};

pub(super) struct Scan {
    current: DeliveryOwner,
    inventory: LegacyInventory,
    next: Option<u64>,
    head: Option<Row>,
    unacked_rows: u64,
    unacked_bytes: u64,
}

impl Scan {
    pub(super) fn new(current: DeliveryOwner) -> Self {
        Self {
            inventory: LegacyInventory::new(current.clone()),
            current,
            next: None,
            head: None,
            unacked_rows: 0,
            unacked_bytes: 0,
        }
    }

    pub(super) fn observe(&mut self, row: ScopedOutbox) -> Result<ScopedOutbox, CompanionFault> {
        if row.scope() != self.current.scope()
            || row.generation() != self.current.cursor().generation()
            || row.sequence() >= self.current.cursor().next_sequence()
            || self.next.is_some_and(|next| row.sequence() != next)
        {
            return Err(CompanionFault::Storage);
        }
        let metadata = Row::new(
            row.sequence(),
            row.event_id(),
            row.event_bytes(),
            row.payload_bytes(),
            row.acknowledgement(),
        )?;
        if self.is_acknowledged(row.sequence()) {
            self.inventory.observe(metadata)?;
            self.head.get_or_insert(metadata);
        } else {
            self.observe_unacknowledged(metadata)?;
        }
        self.next = row.sequence().checked_add(1);
        Ok(row)
    }

    fn is_acknowledged(&self, sequence: u64) -> bool {
        matches!(self.current.cursor().last_ack(), LastAcknowledged::At { sequence: end, .. } if sequence <= end)
    }

    fn first_unacknowledged(&self) -> Result<u64, CompanionFault> {
        match self.current.cursor().last_ack() {
            LastAcknowledged::BeforeFirst => Ok(0),
            LastAcknowledged::At { sequence, .. } => {
                sequence.checked_add(1).ok_or(CompanionFault::Storage)
            }
        }
    }

    fn observe_unacknowledged(&mut self, row: Row) -> Result<(), CompanionFault> {
        let expected = self
            .first_unacknowledged()?
            .checked_add(self.unacked_rows)
            .ok_or(CompanionFault::Storage)?;
        if row.sequence != expected || row.acknowledgement != Acknowledgement::Unacknowledged {
            return Err(CompanionFault::Storage);
        }
        self.unacked_rows = self
            .unacked_rows
            .checked_add(1)
            .ok_or(CompanionFault::Storage)?;
        self.unacked_bytes = self
            .unacked_bytes
            .checked_add(row.bytes)
            .ok_or(CompanionFault::Storage)?;
        if self.unacked_rows > MAX_UNACKED_E2EE_EVENTS_PER_EDGE
            || self.unacked_bytes > MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE
        {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Restored, CompanionFault> {
        let end = self.next.unwrap_or(self.first_unacknowledged()?);
        if end != self.current.cursor().next_sequence() {
            return Err(CompanionFault::Storage);
        }
        Ok(Restored {
            owner: self.inventory.finish()?,
            head: self.head,
            persisted: false,
        })
    }
}
