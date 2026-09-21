//! A live retention scan extends a prior complete inventory only through the removed prefix.
#![forbid(unsafe_code)]

use super::super::restore::replay::State;
use super::{CompanionFault, DeliveryOwner, Draft, Proposal, Row, recovery, validate_previous};
use crate::budget::BackingReservationPort;
use agenc_relay_storage::e2ee_records::delivery_recovery::ScopedOutbox;
use agenc_relay_storage::{PersistentRecordValue, StoredKey};

#[cfg(test)]
mod tests;

pub(in crate::e2ee::coordinator) enum Next {
    Read(recovery::Query),
    Done,
}

pub(in crate::e2ee::coordinator) struct Prefix {
    draft: Option<Draft>,
    prior: State,
    protected_first: Option<u64>,
    started: bool,
    failed: bool,
    proposal: Option<Proposal>,
    // The reader reservation also covers this job's fixed metadata.
    reader: recovery::Reader,
}

impl Prefix {
    pub(in crate::e2ee::coordinator) fn for_ack(
        stream: &crate::e2ee::coordinator::events::DeliveryStream,
        position: agenc_relay_e2ee::federation::frames::DeliveryPosition,
        now: Option<u64>,
        protected_first: Option<u64>,
        pinned_commit: Option<u64>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
        let prior = stream.replay.ok_or(CompanionFault::Storage)?;
        if position.server_id != owner.scope().coordinator_server_id()
            || position.delivery_generation != owner.cursor().generation()
        {
            return Err(CompanionFault::Storage);
        }
        let rows = stream
            .rows
            .iter()
            .filter(|row| !row.acked() && row.sequence <= position.delivery_sequence)
            .map(|row| super::update::metadata(row, row.acknowledgement));
        let draft = Draft::append_checked(
            owner,
            Some(prior.owner),
            position.delivery_sequence,
            position.event_id,
            rows,
            now,
        )?;
        Self::new(
            owner.clone(),
            prior,
            draft,
            protected_first,
            pinned_commit,
            backing,
        )
    }

    pub(super) fn new(
        current: DeliveryOwner,
        prior: State,
        draft: Draft,
        protected_first: Option<u64>,
        pinned_commit: Option<u64>,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        validate_previous(&current, Some(prior.owner))?;
        if draft.fields.first_retained != prior.owner.fields().first_retained
            || draft.fields.retained_rows == 0
            || protected_first.is_some_and(|first| first < draft.fields.first_retained)
        {
            return Err(CompanionFault::Storage);
        }
        let expected = Some(prior.owner);
        let reader = recovery::Reader::new_bound(current, pinned_commit, expected, backing)?;
        Ok(Self {
            draft: Some(draft),
            prior,
            protected_first,
            started: false,
            failed: false,
            proposal: None,
            reader,
        })
    }

    pub(in crate::e2ee::coordinator) fn next(&mut self) -> Result<Next, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        let result = self.advance();
        self.failed = result.is_err();
        result
    }

    fn advance(&mut self) -> Result<Next, CompanionFault> {
        while self.proposal.is_none() {
            match self.reader.next()? {
                recovery::Next::Read(query) => return Ok(Next::Read(query)),
                recovery::Next::Row(row) => self.consider(row)?,
                recovery::Next::Done => return Err(CompanionFault::Storage),
            }
        }
        Ok(Next::Done)
    }

    fn consider(&mut self, row: ScopedOutbox) -> Result<(), CompanionFault> {
        let metadata = Row::new(
            row.sequence(),
            row.event_id(),
            row.event_bytes(),
            row.payload_bytes(),
            row.acknowledgement(),
        )?;
        if !self.started {
            if row.sequence() != self.prior.owner.fields().first_retained
                || self.prior.head.is_some_and(|head| head != metadata)
            {
                return Err(CompanionFault::Storage);
            }
            self.started = true;
        }
        let draft = self.draft.as_mut().ok_or(CompanionFault::Storage)?;
        let metadata = effective(draft, metadata)?;
        if !draft.consider(metadata)? {
            self.finish_with(Some(metadata))?;
            return Ok(());
        }
        if self
            .protected_first
            .is_some_and(|first| metadata.sequence >= first)
        {
            return Err(CompanionFault::Ceiling);
        }
        if draft.fields.retained_rows == 0 {
            self.finish_with(None)?;
        }
        Ok(())
    }

    fn finish_with(&mut self, head: Option<Row>) -> Result<(), CompanionFault> {
        self.proposal = Some(
            self.draft
                .take()
                .ok_or(CompanionFault::Storage)?
                .finish(head)?,
        );
        Ok(())
    }

    /// The adapter's raw and decoder leases outlive all supplied values and this call.
    pub(in crate::e2ee::coordinator) fn admit(
        &mut self,
        query: &recovery::Query,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.failed || self.proposal.is_some() {
            return Err(CompanionFault::Storage);
        }
        let result = self.reader.admit(query, commit, truncated, records);
        self.failed = result.is_err();
        result
    }

    pub(in crate::e2ee::coordinator::delivery_owner) fn finish(
        self,
    ) -> Result<Proposal, CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        self.proposal.ok_or(CompanionFault::Storage)
    }

    #[cfg(test)]
    pub(in crate::e2ee::coordinator) fn finish_ledger(
        self,
    ) -> Result<(super::ReplayOwner, Option<super::AckRange>), CompanionFault> {
        let proposal = self.finish()?;
        Ok((proposal.owner, proposal.range))
    }
}

fn effective(draft: &Draft, mut row: Row) -> Result<Row, CompanionFault> {
    if row.acknowledgement.is_acknowledged() {
        return Ok(row);
    }
    let range = draft.range.ok_or(CompanionFault::Storage)?;
    if row.sequence < range.fields().first
        || row.sequence > range.last()
        || row.sequence == range.last() && row.event_id != range.fields().event_id
    {
        return Err(CompanionFault::Storage);
    }
    row.acknowledgement = range.fields().acknowledgement;
    Ok(row)
}
