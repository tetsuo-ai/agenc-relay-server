//! A legacy suffix is scanned once; no missing ACK history is synthesized.
#![forbid(unsafe_code)]

use super::{
    Acknowledgement, CompanionFault, DeliveryOwner, LastAcknowledged, ReplayOwner,
    ReplayOwnerFields, Row,
};

pub(in crate::e2ee::coordinator::delivery_owner) struct LegacyInventory {
    current: DeliveryOwner,
    first: Option<u64>,
    next: Option<u64>,
    rows: u64,
    bytes: u64,
    time: Option<u64>,
    failed: bool,
}

impl LegacyInventory {
    pub(super) fn new(current: DeliveryOwner) -> Self {
        Self {
            current,
            first: None,
            next: None,
            rows: 0,
            bytes: 0,
            time: None,
            failed: false,
        }
    }

    pub(super) fn observe(&mut self, row: Row) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.collect(row);
        self.failed = result.is_err();
        result
    }

    fn collect(&mut self, row: Row) -> Result<(), CompanionFault> {
        let LastAcknowledged::At { sequence, event_id } = self.current.cursor().last_ack() else {
            return Err(CompanionFault::Storage);
        };
        if !row.acknowledgement.is_acknowledged()
            || row.sequence > sequence
            || self.next.is_some_and(|next| next != row.sequence)
            || (row.sequence == sequence && row.event_id != event_id)
        {
            return Err(CompanionFault::Storage);
        }
        self.first.get_or_insert(row.sequence);
        self.next = row.sequence.checked_add(1);
        self.rows = self.rows.checked_add(1).ok_or(CompanionFault::Storage)?;
        self.bytes = self
            .bytes
            .checked_add(row.bytes)
            .ok_or(CompanionFault::Storage)?;
        if self.rows > super::MAX_ROWS || self.bytes > super::MAX_BYTES {
            return Err(CompanionFault::Storage);
        }
        if let Acknowledgement::AcknowledgedAt {
            received_unix_seconds,
            ..
        } = row.acknowledgement
        {
            self.time = Some(self.time.map_or(received_unix_seconds, |time| {
                time.max(received_unix_seconds)
            }));
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Option<ReplayOwner>, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let baseline = self.current.cursor().last_ack();
        let LastAcknowledged::At { sequence, event_id } = baseline else {
            return if self.rows == 0 {
                Ok(None)
            } else {
                Err(CompanionFault::Storage)
            };
        };
        let end = sequence.checked_add(1).ok_or(CompanionFault::Storage)?;
        if self.next.is_some_and(|next| next != end) {
            return Err(CompanionFault::Storage);
        }
        ReplayOwner::new(ReplayOwnerFields {
            scope: *self.current.scope(),
            generation: self.current.cursor().generation(),
            baseline,
            through: sequence,
            event_id,
            first_retained: self.first.unwrap_or(end),
            retained_rows: self.rows,
            retained_bytes: self.bytes,
            trusted_unix_seconds: self.time,
        })
        .map(Some)
        .map_err(|_| CompanionFault::Storage)
    }
}
