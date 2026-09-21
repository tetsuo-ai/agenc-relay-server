//! A complete ACK prefix proposes one ledger update without copying event bodies.
#![forbid(unsafe_code)]

use super::super::restore::replay::State;
use super::{Acknowledgement, CompanionFault, Draft, Proposal, Row};
use crate::e2ee::coordinator::events::{DeliveryStream, StreamRow};

pub(in crate::e2ee::coordinator::delivery_owner) struct Update {
    pub(in crate::e2ee::coordinator::delivery_owner) expected: Option<State>,
    pub(in crate::e2ee::coordinator::delivery_owner) proposed: State,
}

impl Update {
    pub(in crate::e2ee::coordinator::delivery_owner) fn new(
        stream: &DeliveryStream,
        proposal: &Proposal,
    ) -> Self {
        Self {
            expected: stream.replay,
            proposed: State {
                owner: proposal.owner,
                head: proposal.head,
            },
        }
    }

    pub(in crate::e2ee::coordinator::delivery_owner) fn apply(self, stream: &mut DeliveryStream) {
        let floor = self.proposed.owner.fields().first_retained;
        stream.replay = Some(self.proposed);
        while stream
            .rows
            .front()
            .is_some_and(|row| row.acked() && row.sequence < floor)
        {
            stream.rows.pop_front();
        }
    }
}

pub(in crate::e2ee::coordinator::delivery_owner) fn propose(
    stream: &DeliveryStream,
    through: u64,
    event_id: [u8; 16],
    trusted_now: Option<u64>,
) -> Result<Proposal, CompanionFault> {
    let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
    let prior = stream.replay;
    let rows = stream
        .rows
        .iter()
        .filter(|row| !row.acked() && row.sequence <= through);
    let mut draft = Draft::append_checked(
        owner,
        prior.map(|state| state.owner),
        through,
        event_id,
        rows.map(|row| metadata(row, row.acknowledgement)),
        trusted_now,
    )?;
    let acknowledgement = Acknowledgement::received_at(trusted_now);
    let head = match prior.and_then(|state| state.head) {
        Some(head) => head,
        None => {
            let row = stream
                .rows
                .iter()
                .find(|row| !row.acked())
                .ok_or(CompanionFault::Storage)?;
            metadata(row, acknowledgement)?
        }
    };
    if !draft.consider(head)? {
        return draft.finish(Some(head));
    }
    // An open combined barrier cannot lose its retained proof while the other profile waits.
    if stream.hold_after.is_some() {
        return Err(CompanionFault::Ceiling);
    }
    finish_cached(draft, stream, head.sequence, through, acknowledgement)
}

fn finish_cached(
    mut draft: Draft,
    stream: &DeliveryStream,
    removed: u64,
    through: u64,
    acknowledgement: Acknowledgement,
) -> Result<Proposal, CompanionFault> {
    let mut expected = removed.checked_add(1).ok_or(CompanionFault::Storage)?;
    for row in stream
        .rows
        .iter()
        .filter(|row| row.sequence > removed && row.sequence <= through)
    {
        if row.sequence != expected {
            // The missing prefix needs a charged disk scan before any ACK can be staged.
            return Err(CompanionFault::Ceiling);
        }
        let state = if row.acked() {
            row.acknowledgement
        } else {
            acknowledgement
        };
        let row = metadata(row, state)?;
        if !draft.consider(row)? {
            return draft.finish(Some(row));
        }
        expected = expected.checked_add(1).ok_or(CompanionFault::Storage)?;
    }
    if through.checked_add(1) != Some(expected) {
        return Err(CompanionFault::Ceiling);
    }
    draft.finish(None)
}

pub(super) fn metadata(
    row: &StreamRow,
    acknowledgement: Acknowledgement,
) -> Result<Row, CompanionFault> {
    Row::new(
        row.sequence,
        row.event_id,
        u32::try_from(row.event.len()).map_err(|_| CompanionFault::Storage)?,
        u32::try_from(row.payload.as_ref().map_or(0, |(_, bytes)| bytes.len()))
            .map_err(|_| CompanionFault::Storage)?,
        acknowledgement,
    )
}
