//! A retained reply binds every required body before any response line is rendered.
#![forbid(unsafe_code)]

mod metadata;

use super::{CompanionCoordinator, CompanionFault, StoredResult};
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::federation::frames::Correlation;
use agenc_ircd_e2ee::object::IrcWireObject;
use agenc_ircd_e2ee::objects::federation::IrcFederationResponseDescriptor;
use agenc_ircd_federation_wire::FederationLineText;
use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow, ReplayKey, ReplayRow};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};
use agenc_ircd_types::ServerId;
use std::sync::Arc;

const MAX_RESPONSES: usize = 32;
const METADATA_BYTES: usize = 65_536;
const MAX_RESULT_BYTES: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The authenticated peer and original request tuple of one retained reply.
pub struct Identity {
    pub(crate) peer: ServerId,
    pub(crate) correlation: Correlation,
    pub(crate) request_object_id: [u8; 32],
}

impl Identity {
    pub(crate) fn missing(self, coordinator: &CompanionCoordinator) -> bool {
        coordinator
            .state
            .replays
            .get(&self.key())
            .is_some_and(|row| {
                row.request_object_id == self.request_object_id
                    && row.request_id == self.correlation.request_id
                    && coordinator
                        .state
                        .results
                        .get(&self.request_object_id)
                        .is_some_and(|stored| {
                            stored
                                .responses
                                .iter()
                                .any(|id| !coordinator.state.objects.contains_key(id))
                        })
            })
    }
    fn key(self) -> ReplayKey {
        ReplayKey {
            home_server_id: *self.peer.as_bytes(),
            server_incarnation: self.correlation.server_incarnation,
            origin_id: self.correlation.origin_id,
            origin_generation: self.correlation.origin_generation,
            operation_sequence: self.correlation.operation_sequence,
        }
    }
}

pub(crate) struct Candidate {
    identity: Identity,
    row: ReplayRow,
    stored: StoredResult,
    descriptors: Vec<IrcFederationResponseDescriptor>,
    _metadata: MemoryPermit,
}

impl Candidate {
    pub(crate) fn capture(
        coordinator: &CompanionCoordinator,
        identity: Identity,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let memory = backing
            .reserve(METADATA_BYTES)
            .map_err(|_| CompanionFault::Ceiling)?;
        let row = coordinator
            .state
            .replays
            .get(&identity.key())
            .ok_or(CompanionFault::Protocol)?;
        let stored = coordinator
            .state
            .results
            .get(&identity.request_object_id)
            .ok_or(CompanionFault::Protocol)?;
        if row.response_object_ids.len() > MAX_RESPONSES
            || stored.responses.len() > MAX_RESPONSES
            || stored.result.len() > MAX_RESULT_BYTES
        {
            return Err(CompanionFault::Storage);
        }
        let descriptors = metadata::validate(coordinator, identity, row, stored)?;
        Ok(Self {
            identity,
            row: row.clone(),
            stored: stored.clone(),
            descriptors,
            _metadata: memory,
        })
    }

    pub(crate) fn identity(&self) -> Identity {
        self.identity
    }

    pub(crate) fn validate(
        &self,
        coordinator: &CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        if coordinator.state.replays.get(&self.identity.key()) != Some(&self.row)
            || coordinator
                .state
                .results
                .get(&self.identity.request_object_id)
                != Some(&self.stored)
        {
            return Err(CompanionFault::Protocol);
        }
        Ok(())
    }

    pub(crate) fn begin(
        self,
        commit: u64,
        backing: &BackingReservationPort,
    ) -> Result<Job, CompanionFault> {
        let bytes =
            self.descriptors
                .iter()
                .try_fold(self.stored.result.len(), |sum, descriptor| {
                    sum.checked_add(
                        usize::try_from(descriptor.total_size)
                            .map_err(|_| CompanionFault::Ceiling)?,
                    )
                    .ok_or(CompanionFault::Ceiling)
                })?;
        // Retained input plus the same four-times rendering allowance used for snapshot pages.
        let capacity = bytes
            .checked_mul(5)
            .and_then(|n| n.checked_add(METADATA_BYTES))
            .ok_or(CompanionFault::Ceiling)?;
        let memory = backing
            .reserve(capacity)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut bodies = Vec::new();
        bodies
            .try_reserve_exact(self.descriptors.len())
            .map_err(|_| CompanionFault::Ceiling)?;
        Ok(Job {
            candidate: self,
            commit,
            waiting: false,
            failed: false,
            bodies,
            _memory: memory,
        })
    }
}

pub(crate) struct Job {
    candidate: Candidate,
    commit: u64,
    waiting: bool,
    failed: bool,
    bodies: Vec<Vec<u8>>,
    _memory: MemoryPermit,
}

impl Job {
    pub(crate) fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub(crate) fn next(&mut self) -> Result<Option<ReadPlan>, CompanionFault> {
        if self.failed || self.waiting {
            return Err(CompanionFault::Storage);
        }
        let Some(descriptor) = self.candidate.descriptors.get(self.bodies.len()) else {
            return Ok(None);
        };
        let key = agenc_ircd_storage::e2ee_records::object_key(&descriptor.object_id)
            .map_err(|_| CompanionFault::Storage)?;
        self.waiting = true;
        Ok(Some(ReadPlan::exact(TableId::E2eeObject, key)))
    }

    pub(crate) fn admit(
        &mut self,
        commit: u64,
        truncated: bool,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        if self.failed || !self.waiting || commit != self.commit || truncated || records.len() != 1
        {
            self.failed = true;
            return Err(CompanionFault::Storage);
        }
        self.waiting = false;
        let result = self.body(records);
        self.failed = result.is_err();
        result
    }

    fn body(
        &mut self,
        records: Vec<(StoredKey, PersistentRecordValue)>,
    ) -> Result<(), CompanionFault> {
        let (key, value) = records.into_iter().next().ok_or(CompanionFault::Storage)?;
        if value.record_kind() != OBJECT_RECORD_KIND {
            return Err(CompanionFault::Storage);
        }
        let row = ObjectRow::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
        let expected = self
            .candidate
            .descriptors
            .get(self.bodies.len())
            .ok_or(CompanionFault::Storage)?;
        let (kind, _) = IrcWireObject::peek(&row.bytes).map_err(|_| CompanionFault::Storage)?;
        if row.key().map_err(|_| CompanionFault::Storage)? != key
            || ObjectId::compute(&row.bytes).as_bytes() != &expected.object_id
            || kind != expected.wire_kind
            || row.bytes.len() != expected.total_size as usize
        {
            return Err(CompanionFault::Storage);
        }
        self.bodies.push(row.bytes);
        Ok(())
    }

    pub(crate) fn finish(
        self,
        coordinator: &CompanionCoordinator,
    ) -> Result<Output, CompanionFault> {
        if self.failed || self.waiting || self.bodies.len() != self.candidate.descriptors.len() {
            return Err(CompanionFault::Storage);
        }
        self.candidate.validate(coordinator)?;
        let identity = self.candidate.identity;
        let lines = super::execute::replay_lines(
            coordinator,
            &identity.correlation,
            *identity.peer.as_bytes(),
            &self.candidate.stored.result,
            &self.bodies,
        )
        .map_err(|_| CompanionFault::Storage)?;
        Ok(Output {
            lines,
            _memory: Arc::new(self._memory),
        })
    }
}

pub(crate) struct Output {
    lines: Vec<FederationLineText>,
    _memory: Arc<MemoryPermit>,
}

impl Output {
    pub(crate) fn backing(&self) -> Arc<MemoryPermit> {
        Arc::clone(&self._memory)
    }
    pub(crate) fn drain(&mut self) -> std::vec::Drain<'_, FederationLineText> {
        self.lines.drain(..)
    }
}
