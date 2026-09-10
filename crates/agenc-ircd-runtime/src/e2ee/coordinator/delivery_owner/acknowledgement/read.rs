//! An asynchronous ACK retains its exact source and never publishes before a receipt.
#![forbid(unsafe_code)]

use super::super::restore::replay::State;
use super::super::retention::{Proposal, prefix, recovery, update};
use super::*;
use crate::budget::BackingReservationPort;
use agenc_ircd_storage::e2ee_records::delivery_recovery::DeliveryScope;
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Request {
    peer: ServerId,
    link: LinkId,
    position: DeliveryPosition,
    resume: bool,
    expected: DeliveryOwner,
    replay: Option<State>,
    barrier: Option<(u64, u64)>,
    hold_after: Option<u64>,
    trusted_now: Option<u64>,
}

pub(crate) struct Job {
    request: Request,
    query: Option<recovery::Query>,
    ready: bool,
    // The charged reader outlives the request and query metadata.
    prefix: prefix::Prefix,
}

impl Request {
    pub(super) fn new(
        stream: &DeliveryStream,
        peer: ServerId,
        link: LinkId,
        position: DeliveryPosition,
        resume: bool,
        trusted_now: Option<u64>,
    ) -> Result<Self, CompanionFault> {
        Ok(Self {
            peer,
            link,
            position,
            resume,
            trusted_now,
            expected: stream
                .owner
                .as_ref()
                .ok_or(CompanionFault::Storage)?
                .clone(),
            replay: stream.replay,
            barrier: stream.barrier,
            hold_after: stream.hold_after,
        })
    }

    pub(crate) fn peer(&self) -> ServerId {
        self.peer
    }
    pub(crate) fn link(&self) -> LinkId {
        self.link
    }
    pub(crate) fn scope(&self) -> &DeliveryScope {
        self.expected.scope()
    }

    pub(crate) fn generation(&self) -> u64 {
        self.expected.cursor().generation()
    }

    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        coordinator.validate_delivery_scope(self.expected.scope())?;
        let stream = coordinator
            .state
            .streams
            .get(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        let sync = coordinator
            .peers
            .get(&self.peer)
            .ok_or(CompanionFault::Protocol)?;
        if coordinator.pending.is_some()
            || stream.owner.as_ref() != Some(&self.expected)
            || super::super::cursor(stream)? != *self.expected.cursor()
            || stream.replay != self.replay
            || stream.barrier != self.barrier
            || stream.hold_after != self.hold_after
            || sync.link != Some(self.link)
            || sync.active == self.resume
        {
            return Err(CompanionFault::Protocol);
        }
        Ok(())
    }

    pub(super) fn plan(
        self,
        coordinator: &CompanionCoordinator,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.validate(coordinator)?;
        let stream = coordinator
            .state
            .streams
            .get(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        match update::propose(
            stream,
            self.position.delivery_sequence,
            self.position.event_id,
            self.trusted_now,
        ) {
            Ok(proposal) => self.stage(stream, proposal),
            Err(CompanionFault::Ceiling) if self.replay.is_some() => {
                Ok(vec![Action::ReadAcknowledgement(Box::new(self))])
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn begin(
        self,
        coordinator: &CompanionCoordinator,
        protected_first: Option<u64>,
        pinned_commit: u64,
        backing: &BackingReservationPort,
    ) -> Result<Job, CompanionFault> {
        self.validate(coordinator)?;
        if self.hold_after.is_some() && protected_first.is_none() {
            return Err(CompanionFault::Storage);
        }
        let stream = coordinator
            .state
            .streams
            .get(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        let prefix = prefix::Prefix::for_ack(
            stream,
            self.position,
            self.trusted_now,
            protected_first,
            Some(pinned_commit),
            backing,
        )?;
        Ok(Job {
            request: self,
            query: None,
            ready: false,
            prefix,
        })
    }

    fn stage(
        self,
        stream: &DeliveryStream,
        proposal: Proposal,
    ) -> Result<Vec<Action>, CompanionFault> {
        let proposed = DeliveryCursor::new(
            self.position.delivery_generation,
            self.expected.cursor().next_sequence(),
            LastAcknowledged::At {
                sequence: self.position.delivery_sequence,
                event_id: self.position.event_id,
            },
        )
        .map_err(|_| CompanionFault::Storage)?;
        let owner = DeliveryOwner::new(
            *self.expected.scope(),
            proposed,
            *self.expected.cut(),
            self.expected.phase(),
        )
        .map_err(|_| CompanionFault::Storage)?;
        let acknowledgement = Acknowledgement::received_at(self.trusted_now);
        let range = proposal.range.ok_or(CompanionFault::Storage)?;
        if range.fields().acknowledgement != acknowledgement
            || proposal.owner.scope() != owner.scope()
            || proposal.owner.generation() != proposed.generation()
            || proposal.owner.fields().through != self.position.delivery_sequence
            || proposal.owner.fields().event_id != self.position.event_id
        {
            return Err(CompanionFault::Storage);
        }
        let writes = super::write_proposal(&owner, &proposal)?;
        Ok(vec![Action::Stage {
            writes,
            work: PendingWork::Acknowledgement(PreparedAck {
                peer: self.peer,
                link: self.link,
                position: self.position,
                resume: self.resume,
                expected: self.expected,
                proposed,
                acknowledgement,
                replay: Box::new(Update::new(stream, &proposal)),
            }),
        }])
    }
}

impl Job {
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }

    pub(crate) fn next(&mut self) -> Result<Option<ReadPlan>, CompanionFault> {
        if self.query.is_some() {
            return Err(CompanionFault::Storage);
        }
        match self.prefix.next()? {
            prefix::Next::Read(query) => {
                let plan = query.plan()?;
                self.query = Some(query);
                Ok(Some(plan))
            }
            prefix::Next::Done => {
                self.ready = true;
                Ok(None)
            }
        }
    }

    /// The storage adapter owns all raw and decoding buffers throughout admission.
    pub(crate) fn admit(
        &mut self,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        let query = self.query.take().ok_or(CompanionFault::Storage)?;
        self.prefix.admit(&query, commit, truncated, records)
    }

    pub(crate) fn finish(
        self,
        coordinator: &CompanionCoordinator,
    ) -> Result<Vec<Action>, CompanionFault> {
        if !self.ready || self.query.is_some() {
            return Err(CompanionFault::Storage);
        }
        self.request.validate(coordinator)?;
        let stream = coordinator
            .state
            .streams
            .get(&self.request.peer)
            .ok_or(CompanionFault::Storage)?;
        self.request.stage(stream, self.prefix.finish()?)
    }
}
