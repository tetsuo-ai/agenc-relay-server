//! A replay cutoff is calculated from streamed metadata before any durable write.
#![forbid(unsafe_code)]

mod append;
pub(crate) mod cleanup;
mod inventory;
pub(crate) mod maintenance;
pub(in crate::e2ee::coordinator) mod prefix;
pub(super) mod recovery;
mod row;
#[cfg(test)]
mod tests;
pub(super) mod update;

use agenc_ircd_e2ee::limits::{
    MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE as MAX_BYTES,
    MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE as MAX_ROWS,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::{
    AckRange, ReplayOwner, ReplayOwnerFields,
};
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, DeliveryOwner, LastAcknowledged,
};

use super::super::CompanionFault;
pub(super) use row::Row;

/// Unpublished totals may exceed a hard limit only while their prefix is scanned.
pub(super) struct Draft {
    fields: ReplayOwnerFields,
    range: Option<AckRange>,
    now: Option<u64>,
}

/// The caller must bind this proposal to the exact source owner and storage receipt.
pub(super) struct Proposal {
    pub(super) owner: ReplayOwner,
    pub(super) range: Option<AckRange>,
    pub(super) head: Option<Row>,
}

impl Draft {
    /// Folds exactly the newly acknowledged prefix without retaining its bodies.
    #[cfg(test)]
    pub(super) fn append(
        current: &DeliveryOwner,
        previous: Option<ReplayOwner>,
        through: u64,
        event_id: [u8; 16],
        rows: impl IntoIterator<Item = Row>,
        trusted_now: Option<u64>,
    ) -> Result<Self, CompanionFault> {
        append::begin(
            current,
            previous,
            through,
            event_id,
            rows.into_iter().map(Ok),
            trusted_now,
        )
    }

    pub(super) fn append_checked(
        current: &DeliveryOwner,
        previous: Option<ReplayOwner>,
        through: u64,
        event_id: [u8; 16],
        rows: impl IntoIterator<Item = Result<Row, CompanionFault>>,
        trusted_now: Option<u64>,
    ) -> Result<Self, CompanionFault> {
        append::begin(current, previous, through, event_id, rows, trusted_now)
    }

    /// Age-only maintenance preserves the last ACK and creates no new ACK range.
    pub(super) fn maintenance(
        current: &DeliveryOwner,
        previous: ReplayOwner,
        trusted_now: Option<u64>,
    ) -> Result<Self, CompanionFault> {
        validate_previous(current, Some(previous))?;
        Ok(Self {
            fields: *previous.fields(),
            range: None,
            now: accepted_time(trusted_now),
        })
    }

    /// Removes only the next acknowledged prefix row, when a bound requires it.
    /// A false result identifies the first retained head and stops the scan.
    pub(super) fn consider(&mut self, row: Row) -> Result<bool, CompanionFault> {
        self.validate_head(row)?;
        if !self.over_limit() && !row.expired(self.now) {
            return Ok(false);
        }
        self.fields.first_retained = self
            .fields
            .first_retained
            .checked_add(1)
            .ok_or(CompanionFault::Storage)?;
        self.fields.retained_rows = self
            .fields
            .retained_rows
            .checked_sub(1)
            .ok_or(CompanionFault::Storage)?;
        self.fields.retained_bytes = self
            .fields
            .retained_bytes
            .checked_sub(row.bytes)
            .ok_or(CompanionFault::Storage)?;
        Ok(true)
    }

    /// Finishing requires either a checked retained head or a completely empty suffix.
    pub(super) fn finish(self, head: Option<Row>) -> Result<Proposal, CompanionFault> {
        match head {
            Some(row) => {
                self.validate_head(row)?;
                if row.expired(self.now) {
                    return Err(CompanionFault::Storage);
                }
            }
            None if self.fields.retained_rows == 0 => {}
            None => return Err(CompanionFault::Storage),
        }
        if self.over_limit() {
            return Err(CompanionFault::Ceiling);
        }
        Ok(Proposal {
            owner: ReplayOwner::new(self.fields).map_err(|_| CompanionFault::Storage)?,
            range: self.range,
            head,
        })
    }

    fn validate_head(&self, row: Row) -> Result<(), CompanionFault> {
        if self.fields.retained_rows == 0
            || row.sequence != self.fields.first_retained
            || row.sequence > self.fields.through
            || row.bytes > self.fields.retained_bytes
            || !row.acknowledgement.is_acknowledged()
            || (row.sequence == self.fields.through && row.event_id != self.fields.event_id)
        {
            return Err(CompanionFault::Storage);
        }
        Ok(())
    }

    fn over_limit(&self) -> bool {
        self.fields.retained_rows > MAX_ROWS || self.fields.retained_bytes > MAX_BYTES
    }
}

pub(super) fn validate_previous(
    current: &DeliveryOwner,
    previous: Option<ReplayOwner>,
) -> Result<(), CompanionFault> {
    match (current.cursor().last_ack(), previous) {
        (LastAcknowledged::BeforeFirst, None) => Ok(()),
        (LastAcknowledged::At { sequence, event_id }, Some(previous))
            if previous.scope() == current.scope()
                && previous.generation() == current.cursor().generation()
                && previous.fields().through == sequence
                && previous.fields().event_id == event_id =>
        {
            Ok(())
        }
        _ => Err(CompanionFault::Storage),
    }
}

fn accepted_time(time: Option<u64>) -> Option<u64> {
    match Acknowledgement::received_at(time) {
        Acknowledgement::AcknowledgedAt {
            received_unix_seconds,
            ..
        } => Some(received_unix_seconds),
        _ => None,
    }
}
