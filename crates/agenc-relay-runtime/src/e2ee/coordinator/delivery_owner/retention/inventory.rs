//! One range and one row suffice to validate a complete retained suffix.
#![forbid(unsafe_code)]

use super::{AckRange, Acknowledgement, CompanionFault, DeliveryOwner};
use super::{ReplayOwner, Row, validate_previous};
use agenc_relay_e2ee::limits::{
    MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE, MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
};
use agenc_relay_storage::e2ee_records::delivery_recovery::ScopedOutbox;

#[cfg(test)]
mod tests;

/// The read owner must validate keys, object bodies, and one pinned storage commit.
pub(super) struct Inventory {
    current: DeliveryOwner,
    replay: ReplayOwner,
    next: u64,
    range: Option<AckRange>,
    rows: u64,
    bytes: u64,
    unacked_rows: u64,
    unacked_bytes: u64,
    head: Option<Row>,
    failed: bool,
}

impl Inventory {
    pub(super) const fn owner(&self) -> ReplayOwner {
        self.replay
    }

    pub(super) fn new(current: DeliveryOwner, replay: ReplayOwner) -> Result<Self, CompanionFault> {
        validate_previous(&current, Some(replay))?;
        Ok(Self {
            current,
            next: replay.fields().first_retained,
            replay,
            range: None,
            rows: 0,
            bytes: 0,
            unacked_rows: 0,
            unacked_bytes: 0,
            head: None,
            failed: false,
        })
    }

    /// A lower-bound range read starts at this sequence's final-position key.
    pub(super) fn needs_range(&self) -> Option<u64> {
        (!self.failed
            && self.next <= self.replay.fields().through
            && self.range.is_none_or(|range| range.last() < self.next))
        .then_some(self.next)
    }

    pub(super) fn admit_range(&mut self, range: AckRange) -> Result<(), CompanionFault> {
        let Some(next) = self.needs_range() else {
            self.failed = true;
            return Err(CompanionFault::Storage);
        };
        let fields = range.fields();
        if range.scope() != self.current.scope()
            || range.generation() != self.current.cursor().generation()
            || fields.first > next
            || fields.last < next
            || fields.last > self.replay.fields().through
            || (next != self.replay.fields().first_retained && fields.first != next)
        {
            self.failed = true;
            return Err(CompanionFault::Storage);
        }
        self.range = Some(range);
        Ok(())
    }

    /// Returns effective ACK facts only after checking exact interval coverage.
    pub(super) fn observe(&mut self, row: ScopedOutbox) -> Result<ScopedOutbox, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.collect(row);
        self.failed = result.is_err();
        result
    }

    fn collect(&mut self, row: ScopedOutbox) -> Result<ScopedOutbox, CompanionFault> {
        if row.scope() != self.current.scope()
            || row.generation() != self.current.cursor().generation()
            || row.sequence() != self.next
            || self.next >= self.current.cursor().next_sequence()
        {
            return Err(CompanionFault::Storage);
        }
        let acknowledgement = self.acknowledgement(&row)?;
        let effective = row
            .with_acknowledgement(acknowledgement)
            .map_err(|_| CompanionFault::Storage)?;
        let metadata = Row::new(
            row.sequence(),
            row.event_id(),
            row.event_bytes(),
            row.payload_bytes(),
            acknowledgement,
        )?;
        self.count(metadata)?;
        self.next = self.next.checked_add(1).ok_or(CompanionFault::Storage)?;
        Ok(effective)
    }

    fn acknowledgement(&self, row: &ScopedOutbox) -> Result<Acknowledgement, CompanionFault> {
        let sequence = row.sequence();
        if sequence > self.replay.fields().through {
            return if row.acknowledgement() == Acknowledgement::Unacknowledged {
                Ok(Acknowledgement::Unacknowledged)
            } else {
                Err(CompanionFault::Storage)
            };
        }
        if sequence == self.replay.fields().through
            && row.event_id() != self.replay.fields().event_id
        {
            return Err(CompanionFault::Storage);
        }
        self.range_acknowledgement(row)
    }

    fn range_acknowledgement(&self, row: &ScopedOutbox) -> Result<Acknowledgement, CompanionFault> {
        let sequence = row.sequence();
        let range = self.range.ok_or(CompanionFault::Storage)?;
        let fields = range.fields();
        if row.acknowledgement() != Acknowledgement::Unacknowledged
            || sequence < fields.first
            || sequence > fields.last
            || (sequence == fields.last && row.event_id() != fields.event_id)
        {
            return Err(CompanionFault::Storage);
        }
        Ok(fields.acknowledgement)
    }

    fn count(&mut self, row: Row) -> Result<(), CompanionFault> {
        self.validate_time(row.acknowledgement)?;
        if row.acknowledgement.is_acknowledged() {
            self.rows = self.rows.checked_add(1).ok_or(CompanionFault::Storage)?;
            self.bytes = self
                .bytes
                .checked_add(row.bytes)
                .ok_or(CompanionFault::Storage)?;
            if self.rows > self.replay.fields().retained_rows
                || self.bytes > self.replay.fields().retained_bytes
            {
                return Err(CompanionFault::Storage);
            }
            self.head.get_or_insert(row);
        } else {
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
        }
        Ok(())
    }

    fn validate_time(&self, acknowledgement: Acknowledgement) -> Result<(), CompanionFault> {
        if let Acknowledgement::AcknowledgedAt {
            received_unix_seconds,
            ..
        } = acknowledgement
            && self
                .replay
                .fields()
                .trusted_unix_seconds
                .is_none_or(|time| received_unix_seconds > time)
        {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Option<Row>, CompanionFault> {
        if self.failed
            || self.next != self.current.cursor().next_sequence()
            || self.rows != self.replay.fields().retained_rows
            || self.bytes != self.replay.fields().retained_bytes
        {
            return Err(CompanionFault::Storage);
        }
        Ok(self.head)
    }
}
