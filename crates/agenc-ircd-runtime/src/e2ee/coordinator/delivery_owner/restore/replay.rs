//! A recovered stream stays private until every retained body has been checked.
#![forbid(unsafe_code)]

mod bodies;
mod request;

use super::super::retention::{Row, recovery};
use super::{
    CompanionFault, DeliveryBarrier, DeliveryOwner, DeliveryStream, LastAcknowledged,
    MAX_ACKED_REPLAY_ROWS, ScopedOutbox,
};
use crate::budget::BackingReservationPort;
use agenc_ircd_storage::e2ee_records::delivery_recovery::outbox::replay::ReplayOwner;
use agenc_ircd_storage::{PersistentRecordValue, StoredKey};

use request::Kind;
pub(crate) use request::Request;

const BODY_ROWS: usize = 32;
const BODY_BYTES: u64 = 8 * 1024 * 1024;
use crate::e2ee::coordinator::events::MAX_ACKED_CACHE_BYTES;

pub(in crate::e2ee::coordinator) struct Loaded {
    pub(in crate::e2ee::coordinator) stream: DeliveryStream,
    pub(in crate::e2ee::coordinator) owner: Option<ReplayOwner>,
    head: Option<Row>,
    persisted: bool,
}

/// Validated retention metadata remains attached to its exact delivery stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct State {
    pub(in crate::e2ee::coordinator::delivery_owner) owner: ReplayOwner,
    pub(in crate::e2ee::coordinator::delivery_owner) head: Option<Row>,
    pub(in crate::e2ee::coordinator::delivery_owner) persisted: bool,
}

#[cfg(test)]
impl State {
    pub(in crate::e2ee::coordinator) fn inspected(self) -> (ReplayOwner, bool) {
        (self.owner, self.persisted)
    }
}

impl Loaded {
    #[cfg(test)]
    pub(in crate::e2ee::coordinator) fn has_retained_head(&self) -> bool {
        self.head.is_some()
    }

    pub(super) fn into_stream(mut self) -> DeliveryStream {
        self.stream.replay = self.owner.map(|owner| State {
            owner,
            head: self.head,
            persisted: self.persisted,
        });
        self.stream
    }
}

pub(in crate::e2ee::coordinator) struct Job {
    owner: DeliveryOwner,
    gate: Option<DeliveryBarrier>,
    pinned_commit: Option<u64>,
    waiting: Option<Request>,
    buffered: Vec<ScopedOutbox>,
    deferred: Option<ScopedOutbox>,
    bytes: u64,
    verified: u64,
    hot_bytes: u64,
    stream: DeliveryStream,
    done: bool,
    failed: bool,
    backing: BackingReservationPort,
    // All metadata borrowed from the reader's reservation must drop before it.
    reader: recovery::Reader,
}

impl Job {
    pub(in crate::e2ee::coordinator) fn new(
        owner: DeliveryOwner,
        gate: Option<DeliveryBarrier>,
        pinned_commit: Option<u64>,
        backing: BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let cursor = owner.cursor();
        let (first_unacked, acked) = match cursor.last_ack() {
            LastAcknowledged::BeforeFirst => (0, None),
            LastAcknowledged::At { sequence, event_id } => (
                sequence.checked_add(1).ok_or(CompanionFault::Storage)?,
                Some((sequence, event_id)),
            ),
        };
        let capacity = cursor
            .next_sequence()
            .checked_sub(first_unacked)
            .and_then(|count| count.checked_add(first_unacked.min(MAX_ACKED_REPLAY_ROWS as u64)))
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(CompanionFault::Storage)?;
        let mut stream = DeliveryStream::with_row_capacity(capacity, &backing)?;
        stream.owner = Some(owner.clone());
        stream.generation = cursor.generation();
        stream.next_sequence = cursor.next_sequence();
        stream.acked = acked;
        let reader = recovery::Reader::new(owner.clone(), pinned_commit, &backing)?;
        Ok(Self {
            reader,
            owner,
            gate,
            pinned_commit,
            waiting: None,
            buffered: Vec::new(),
            deferred: None,
            bytes: 0,
            verified: 0,
            hot_bytes: 0,
            stream,
            done: false,
            failed: false,
            backing,
        })
    }

    pub(in crate::e2ee::coordinator) fn next(&mut self) -> Result<Option<Request>, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.advance();
        self.failed = result.is_err();
        result
    }

    fn advance(&mut self) -> Result<Option<Request>, CompanionFault> {
        while !self.done && self.waiting.is_none() {
            let next = self
                .deferred
                .take()
                .map_or_else(|| self.reader.next(), |row| Ok(recovery::Next::Row(row)))?;
            self.consume(next)?;
        }
        Ok(self.waiting.clone())
    }

    fn consume(&mut self, next: recovery::Next) -> Result<(), CompanionFault> {
        match next {
            recovery::Next::Read(query) if self.buffered.is_empty() => {
                self.wait(Kind::Metadata(query))?;
            }
            recovery::Next::Done if self.buffered.is_empty() => self.done = true,
            recovery::Next::Read(_) | recovery::Next::Done => {
                self.body_request()?;
            }
            recovery::Next::Row(row) => {
                if self.buffer_row(row)? {
                    self.body_request()?;
                }
            }
        }
        Ok(())
    }

    fn buffer_row(&mut self, row: ScopedOutbox) -> Result<bool, CompanionFault> {
        let bytes = u64::from(row.event_bytes()) + u64::from(row.payload_bytes());
        let total = self
            .bytes
            .checked_add(bytes)
            .ok_or(CompanionFault::Storage)?;
        if !self.buffered.is_empty() && (self.buffered.len() >= BODY_ROWS || total > BODY_BYTES) {
            self.deferred = Some(row);
            return Ok(true);
        }
        if total > BODY_BYTES {
            return Err(CompanionFault::Storage);
        }
        self.bytes = total;
        self.buffered.push(row);
        Ok(false)
    }

    fn body_request(&mut self) -> Result<Option<Request>, CompanionFault> {
        self.wait(Kind::Bodies(
            bodies::expected(&self.buffered)?.into_keys().collect(),
        ))
    }

    fn wait(&mut self, kind: Kind) -> Result<Option<Request>, CompanionFault> {
        let request = Request { kind };
        self.waiting = Some(request.clone());
        Ok(Some(request))
    }

    /// Caller-owned raw/decode leases must outlive all supplied values and this call.
    pub(in crate::e2ee::coordinator) fn admit(
        &mut self,
        request: &Request,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.complete(request, commit, truncated, records);
        self.failed = result.is_err();
        result
    }

    fn complete(
        &mut self,
        request: &Request,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.waiting.as_ref() != Some(request)
            || self.pinned_commit.is_some_and(|pinned| pinned != commit)
        {
            return Err(CompanionFault::Storage);
        }
        self.pinned_commit = Some(commit);
        match &request.kind {
            Kind::Metadata(query) => self.reader.admit(query, commit, truncated, records)?,
            Kind::Bodies(_) => bodies::admit(self, truncated, records)?,
        }
        self.waiting = None;
        Ok(())
    }

    pub(in crate::e2ee::coordinator) fn finish(self) -> Result<Loaded, CompanionFault> {
        if self.failed || !self.done || !self.buffered.is_empty() || self.deferred.is_some() {
            return Err(CompanionFault::Storage);
        }
        let restored = self.reader.finish()?;
        let first = restored
            .owner
            .map_or(0, |owner| owner.fields().first_retained);
        if self.owner.cursor().next_sequence().checked_sub(first) != Some(self.verified) {
            return Err(CompanionFault::Storage);
        }
        if let Some(gate) = &self.gate {
            gate.validate_for(&self.owner, gate.base().generation())
                .map_err(|_| CompanionFault::Storage)?;
            if first > gate.companion().first() {
                return Err(CompanionFault::Storage);
            }
        }
        super::validate_complete(&self.stream)?;
        Ok(Loaded {
            stream: self.stream,
            owner: restored.owner,
            head: restored.head,
            persisted: restored.persisted,
        })
    }
}
