//! A charged merge of bounded outbox and ACK-journal pages at one storage commit.
#![forbid(unsafe_code)]

mod initial;
mod page;
mod query;
#[cfg(test)]
mod tests;

use super::inventory::Inventory;
use super::{AckRange, CompanionFault, DeliveryOwner, ReplayOwner, Row};
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_relay_storage::e2ee_records::delivery_recovery::ScopedOutbox;
use agenc_relay_storage::{PersistentRecordValue, StoredKey};
use std::collections::VecDeque;

use query::Kind;
pub(in crate::e2ee::coordinator) use query::Query;

pub(super) const PAGE_ROWS: u16 = 128;
// Two bounded queues, their allocation overhead, and the reader's fixed metadata.
const METADATA_BYTES: usize = 2
    * PAGE_ROWS as usize
    * (std::mem::size_of::<ScopedOutbox>() + std::mem::size_of::<AckRange>())
    + 8_192;

pub(in crate::e2ee::coordinator::delivery_owner) enum Next {
    Read(Query),
    Row(ScopedOutbox),
    Done,
}

/// Object identity/body validation and stream installation remain the caller's job.
pub(in crate::e2ee::coordinator::delivery_owner) struct Restored {
    pub(in crate::e2ee::coordinator::delivery_owner) owner: Option<ReplayOwner>,
    pub(in crate::e2ee::coordinator::delivery_owner) head: Option<Row>,
}

enum Scan {
    Initial(Box<initial::Scan>),
    Ledger(Box<Inventory>),
}

pub(in crate::e2ee::coordinator::delivery_owner) struct Reader {
    current: DeliveryOwner,
    pinned_commit: Option<u64>,
    expected_owner: Option<Option<ReplayOwner>>,
    scan: Option<Scan>,
    pending: Option<Query>,
    rows: VecDeque<ScopedOutbox>,
    ranges: VecDeque<AckRange>,
    next_row: u64,
    next_range: u64,
    rows_done: bool,
    ranges_started: bool,
    ranges_done: bool,
    restored: Option<Restored>,
    failed: bool,
    _memory: MemoryPermit,
}

impl Reader {
    pub(in crate::e2ee::coordinator::delivery_owner) fn new(
        current: DeliveryOwner,
        pinned_commit: Option<u64>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let memory = backing
            .reserve(METADATA_BYTES)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut rows = VecDeque::new();
        let mut ranges = VecDeque::new();
        rows.try_reserve_exact(PAGE_ROWS as usize)
            .map_err(|_| CompanionFault::Ceiling)?;
        ranges
            .try_reserve_exact(PAGE_ROWS as usize)
            .map_err(|_| CompanionFault::Ceiling)?;
        Ok(Self {
            current,
            pinned_commit,
            expected_owner: None,
            scan: None,
            pending: None,
            rows,
            ranges,
            next_row: 0,
            next_range: 0,
            rows_done: false,
            ranges_started: false,
            ranges_done: false,
            restored: None,
            failed: false,
            _memory: memory,
        })
    }

    /// A live prefix scan is bound to an inventory already validated by its caller.
    pub(in crate::e2ee::coordinator::delivery_owner) fn new_bound(
        current: DeliveryOwner,
        pinned_commit: Option<u64>,
        expected_owner: Option<ReplayOwner>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let mut reader = Self::new(current, pinned_commit, backing)?;
        reader.expected_owner = Some(expected_owner);
        Ok(reader)
    }

    pub(in crate::e2ee::coordinator::delivery_owner) fn next(
        &mut self,
    ) -> Result<Next, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.advance();
        self.failed = result.is_err();
        result
    }

    fn advance(&mut self) -> Result<Next, CompanionFault> {
        if let Some(query) = &self.pending {
            return Ok(Next::Read(query.clone()));
        }
        if self.restored.is_some() {
            return Ok(Next::Done);
        }
        if self.scan.is_none() {
            return Ok(self.request(Kind::Owner));
        }
        if !self.ranges_started {
            return Ok(self.request(Kind::Ranges(self.next_range)));
        }
        if !self.rows.is_empty() {
            return self.next_row();
        }
        if !self.rows_done {
            return Ok(self.request(Kind::Rows(self.next_row)));
        }
        if !self.ranges_done {
            return Ok(self.request(Kind::Ranges(self.next_range)));
        }
        if !self.ranges.is_empty() {
            return Err(CompanionFault::Storage);
        }
        self.restored = Some(match self.scan.take().ok_or(CompanionFault::Storage)? {
            Scan::Initial(scan) => scan.finish()?,
            Scan::Ledger(inventory) => Restored {
                owner: Some(inventory.owner()),
                head: inventory.finish()?,
            },
        });
        Ok(Next::Done)
    }

    fn next_row(&mut self) -> Result<Next, CompanionFault> {
        if let Some(Scan::Ledger(inventory)) = &mut self.scan
            && inventory.needs_range().is_some()
        {
            if let Some(range) = self.ranges.pop_front() {
                inventory.admit_range(range)?;
            } else if !self.ranges_done {
                return Ok(self.request(Kind::Ranges(self.next_range)));
            } else {
                return Err(CompanionFault::Storage);
            }
        }
        let row = self.rows.pop_front().ok_or(CompanionFault::Storage)?;
        let effective = match self.scan.as_mut().ok_or(CompanionFault::Storage)? {
            Scan::Initial(scan) => scan.observe(row)?,
            Scan::Ledger(inventory) => inventory.observe(row)?,
        };
        Ok(Next::Row(effective))
    }

    fn request(&mut self, kind: Kind) -> Next {
        let query = Query::new(&self.current, kind);
        self.pending = Some(query.clone());
        Next::Read(query)
    }

    /// The adapter retains raw/decode leases until every supplied value is dropped.
    pub(in crate::e2ee::coordinator::delivery_owner) fn admit(
        &mut self,
        query: &Query,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = page::admit(self, query, commit, truncated, records);
        self.failed = result.is_err();
        result
    }

    pub(in crate::e2ee::coordinator::delivery_owner) fn finish(
        self,
    ) -> Result<Restored, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        self.restored.ok_or(CompanionFault::Storage)
    }
}
