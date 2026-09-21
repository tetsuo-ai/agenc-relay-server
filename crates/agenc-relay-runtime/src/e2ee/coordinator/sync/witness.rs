//! The coordinator's side of edge witness resolution (companion 12.5.1).
//!
//! A blocked edge names the position and head its durable `witness/v1` row
//! retained. The coordinator answers with the retained records that continue
//! from that position, or with an empty set when it holds none, and never
//! treats the request as a violation. One resolution is open per link at a
//! time, as the edge requires; later requests wait for `EWITNESS RESOLVED`.
//! The answer stops before the first chain event the edge has not yet
//! acknowledged, so the retransmitted event still extends the installed head.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use agenc_relay_domain::e2ee::sequencer_log::{Phase, SequencerLog};
use agenc_relay_e2ee::limits::{MAX_WITNESS_RESOLUTION_BYTES, MAX_WITNESS_RESOLUTION_RECORDS};
use agenc_relay_e2ee::objects::federation::{
    ArcFederationEventKind, ArcFederationWitnessResolution,
};
use agenc_relay_e2ee::objects::sequencing::ArcSequencerRecord;
use agenc_relay_e2ee::record_authentication::decode_record;
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};

use super::super::{CompanionState, ConversationState};
use super::*;

/// The requests one link may hold behind its open resolution; an edge
/// repeats a dropped request after `MAX_WITNESS_RESOLUTION_SECONDS`.
const MAX_QUEUED_WITNESS_REQUESTS: usize = 1_024;

/// The record bytes one answer renders into link lines at once: far below
/// `MAX_WITNESS_RESOLUTION_BYTES`, because the lines are built in memory. A
/// longer chain resolves through the requests that follow.
const WITNESS_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// One `EWITNESS REQUEST`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Request {
    /// The blocked conversation.
    pub(crate) conversation: [u8; 32],
    /// The route sequence the edge expects next.
    pub(crate) expected_sequence: u64,
    /// The head identifier the edge retained.
    pub(crate) expected_head_id: [u8; 32],
}

/// The resolution the edge has not settled yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Open {
    conversation: [u8; 32],
    token: [u8; 16],
    head: (u64, [u8; 32]),
    /// The first record forks the edge's head: the edge marks its row
    /// `conflict` and never answers `RESOLVED`.
    forked: bool,
}

/// The witness publication state of one link.
#[derive(Debug, Default)]
pub struct Publication {
    open: Option<Open>,
    resolved: Option<([u8; 32], [u8; 16])>,
    queued: VecDeque<Request>,
    served: bool,
}

impl Publication {
    /// Queues `request` and reports whether an answer may go out now. A
    /// repeated request, or any request after a forked answer, shows that
    /// the edge settled the open resolution without `RESOLVED`.
    fn admit(&mut self, request: Request) -> bool {
        let settled = self
            .open
            .is_some_and(|open| open.forked || open.conversation == request.conversation);
        if settled {
            self.open = None;
        }
        self.queued
            .retain(|queued| queued.conversation != request.conversation);
        if self.queued.len() < MAX_QUEUED_WITNESS_REQUESTS {
            self.queued.push_back(request);
        }
        self.open.is_none()
    }

    /// Whether this link answered a request since the last call: the edge
    /// dropped every delivery it received while blocked.
    pub(super) fn take_served(&mut self) -> bool {
        std::mem::take(&mut self.served)
    }
}

/// The records one answer delivers and the head they end at.
struct Answer {
    object_ids: Vec<[u8; 32]>,
    head: (u64, [u8; 32]),
    forked: bool,
}

impl Answer {
    fn empty(request: &Request) -> Self {
        Self {
            object_ids: Vec::new(),
            head: (request.expected_sequence, request.expected_head_id),
            forked: false,
        }
    }
}

/// The route sequence of the first chain event of `conversation` the edge
/// has not acknowledged, which the coordinator retransmits after the
/// resolution.
fn pending_chain_event(stream: Option<&DeliveryStream>, conversation: &[u8; 32]) -> Option<u64> {
    stream?
        .rows
        .iter()
        .filter(|row| !row.acked())
        .find_map(|row| {
            let event = super::super::delivery_owner::restore::decode_event(&row.event).ok()?;
            let extends = matches!(
                event.event_kind,
                ArcFederationEventKind::CandidateEvent
                    | ArcFederationEventKind::FinalizedEvent
                    | ArcFederationEventKind::AbortedEvent
                    | ArcFederationEventKind::ReinitStagedEvent
                    | ArcFederationEventKind::ReinitActivatedEvent
                    | ArcFederationEventKind::ReinitAbortedEvent
                    | ArcFederationEventKind::ClosedEvent
            );
            (extends && event.conversation_id.as_slice() == conversation)
                .then_some(event.route_sequence)
        })
}

/// The semantic identifier of the retained record at `sequence`: the head
/// when it is the head, the finalization a close followed, and otherwise
/// the predecessor its successor names.
fn semantic_id_at(
    state: &CompanionState,
    conversation: &ConversationState,
    log: &SequencerLog,
    sequence: u64,
) -> Option<[u8; 32]> {
    let head = log.head();
    if head.recorded && head.sequence == sequence {
        return Some(head.record_id);
    }
    let next = sequence.checked_add(1)?;
    if matches!(log.phase(), Phase::Closed { .. }) && head.sequence == next {
        return Some(*log.accepted_state_id());
    }
    let bytes = state.objects.get(conversation.records.get(&next)?)?;
    let mut budget = DecodeBudget::new(1 << 23, 4_096);
    let (_, declared) = decode_record(bytes, &mut budget).ok()?;
    Some(declared.predecessor_record_id)
}

/// Collects the retained records from the requested position up to `last`.
fn collect(
    state: &CompanionState,
    conversation: &ConversationState,
    request: &Request,
    last: u64,
) -> (Vec<[u8; 32]>, bool) {
    let mut ids = Vec::new();
    let mut bytes_total = 0_u64;
    let ceiling = MAX_WITNESS_RESOLUTION_BYTES.min(WITNESS_ANSWER_BYTES);
    for (sequence, object_id) in conversation.records.range(request.expected_sequence..=last) {
        let expected = u64::try_from(ids.len())
            .ok()
            .and_then(|count| request.expected_sequence.checked_add(count));
        let Some(bytes) = state.objects.get(object_id) else {
            break;
        };
        let mut budget = DecodeBudget::new(1 << 23, 4_096);
        let Ok((record, declared)) = decode_record(bytes, &mut budget) else {
            break;
        };
        bytes_total = bytes_total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        // An attempt receipt needs its attempt object, which this carrier
        // does not deliver; the chain before it still resolves.
        let deliverable = expected == Some(*sequence)
            && declared.route_sequence == *sequence
            && !matches!(record, ArcSequencerRecord::ReinitAttempt(_))
            && (ids.is_empty() || bytes_total <= ceiling)
            && u32::try_from(ids.len()).is_ok_and(|count| count < MAX_WITNESS_RESOLUTION_RECORDS);
        if !deliverable {
            break;
        }
        ids.push(*object_id);
        if ids.len() == 1 && declared.predecessor_record_id != request.expected_head_id {
            return (ids, true);
        }
    }
    (ids, false)
}

/// The answer to `request` from the retained chain of an entitled edge.
fn answer(state: &CompanionState, peer: ServerId, request: &Request) -> Answer {
    let retained = state
        .conversations
        .get(&request.conversation)
        .zip(state.logs.get(&request.conversation))
        .filter(|_| state.entitlements.entitled(peer, &request.conversation));
    let Some((conversation, log)) = retained else {
        return Answer::empty(request);
    };
    let last = pending_chain_event(state.streams.get(&peer), &request.conversation)
        .map_or(u64::MAX, |sequence| {
            sequence.saturating_sub(1).max(request.expected_sequence)
        });
    let (mut object_ids, forked) = collect(state, conversation, request, last);
    while let Some(count) = u64::try_from(object_ids.len())
        .ok()
        .filter(|count| *count > 0)
    {
        let sequence = request.expected_sequence.saturating_add(count - 1);
        if let Some(id) = semantic_id_at(state, conversation, log, sequence) {
            return Answer {
                object_ids,
                head: (sequence, id),
                forked,
            };
        }
        object_ids.pop();
    }
    Answer::empty(request)
}

impl CompanionCoordinator {
    /// `EWITNESS REQUEST`: answered now, or after the open resolution.
    pub(super) fn witness_request(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        request: Request,
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        let sync = self
            .peers
            .get_mut(&peer)
            .filter(|sync| sync.active)
            .ok_or(CompanionFault::Protocol)?;
        if !sync.witness.admit(request) {
            return Ok(Vec::new());
        }
        self.answer_queued(peer, entropy)
    }

    /// `EWITNESS RESOLVED`: the edge installed the open resolution's head;
    /// a repeat for the installed token is idempotent.
    pub(super) fn witness_resolved(
        &mut self,
        peer: ServerId,
        coordinator_server_id: [u8; 16],
        installed: ([u8; 32], [u8; 16], (u64, [u8; 32])),
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        self.require_self(coordinator_server_id)?;
        let (conversation, token, head) = installed;
        let publication = &mut self
            .peers
            .get_mut(&peer)
            .ok_or(CompanionFault::Protocol)?
            .witness;
        if publication.resolved == Some((conversation, token)) {
            return Ok(Vec::new());
        }
        let matches = publication.open.is_some_and(|open| {
            !open.forked
                && open.conversation == conversation
                && open.token == token
                && open.head == head
        });
        if !matches {
            return Err(CompanionFault::Protocol);
        }
        publication.open = None;
        publication.resolved = Some((conversation, token));
        self.answer_queued(peer, entropy)
    }

    /// Answers queued requests until one resolution stays open.
    fn answer_queued(
        &mut self,
        peer: ServerId,
        entropy: &mut dyn EntropySource,
    ) -> Result<Vec<Action>, CompanionFault> {
        let mut lines = Vec::new();
        loop {
            let publication = &mut self
                .peers
                .get_mut(&peer)
                .ok_or(CompanionFault::Protocol)?
                .witness;
            let Some(request) = publication.queued.pop_front() else {
                break;
            };
            publication.served = true;
            let mut token = [0; 16];
            entropy
                .fill_exact(&mut token)
                .map_err(|_| CompanionFault::Storage)?;
            let answer = answer(&self.state, peer, &request);
            lines.extend(self.render_answer(peer, &request, token, &answer)?);
            if answer.object_ids.is_empty() {
                continue;
            }
            self.peers
                .get_mut(&peer)
                .ok_or(CompanionFault::Protocol)?
                .witness
                .open = Some(Open {
                conversation: request.conversation,
                token,
                head: answer.head,
                forked: answer.forked,
            });
            break;
        }
        Ok(if lines.is_empty() {
            Vec::new()
        } else {
            vec![Action::Send(lines)]
        })
    }

    /// `EWITNESS BEGIN`, every `ENTRY` fragment in chain order, and `END`.
    fn render_answer(
        &self,
        peer: ServerId,
        request: &Request,
        token: [u8; 16],
        answer: &Answer,
    ) -> Result<Vec<FederationLineText>, CompanionFault> {
        let target = *peer.as_bytes();
        let count = u32::try_from(answer.object_ids.len()).map_err(|_| CompanionFault::Ceiling)?;
        let body = ArcFederationWitnessResolution {
            profile_version: 1,
            network_id: self.network_id,
            coordinator_server_id: *self.server_id.as_bytes(),
            target_server_id: target,
            conversation_id: request.conversation,
            resolution_token: token,
            expected_sequence: request.expected_sequence,
            expected_head_id: request.expected_head_id,
            record_count: count,
            new_head_sequence: answer.head.0,
            new_head_id: answer.head.1,
            record_object_ids: Opaque::new(answer.object_ids.concat())
                .map_err(|_| CompanionFault::Ceiling)?,
        };
        let object = body
            .encode()
            .and_then(|body| ArcWireObject::new(ArcWireObjectKind::WitnessResolution, body))
            .and_then(|object| object.encode())
            .map_err(|_| CompanionFault::Ceiling)?;
        let object_id = *agenc_relay_e2ee::ObjectId::compute(&object).as_bytes();
        let mut lines = Vec::new();
        for fragment in fragment_object(&object).map_err(|_| CompanionFault::Protocol)? {
            lines.push(line(
                &self.server_name,
                &CompanionFrame::WitnessBegin {
                    target_server_id: target,
                    conversation_id: request.conversation,
                    resolution_token: token,
                    object_id,
                    fragment,
                },
            )?);
        }
        for (index, record_id) in answer.object_ids.iter().enumerate() {
            let bytes = self
                .state
                .objects
                .get(record_id)
                .ok_or(CompanionFault::Storage)?;
            let entry_sequence = u32::try_from(index).map_err(|_| CompanionFault::Ceiling)?;
            for fragment in fragment_object(bytes).map_err(|_| CompanionFault::Protocol)? {
                lines.push(line(
                    &self.server_name,
                    &CompanionFrame::WitnessEntry {
                        target_server_id: target,
                        resolution_token: token,
                        entry_sequence,
                        object_id: *record_id,
                        fragment,
                    },
                )?);
            }
        }
        lines.push(line(
            &self.server_name,
            &CompanionFrame::WitnessEnd {
                target_server_id: target,
                resolution_token: token,
                record_count: count,
            },
        )?);
        Ok(lines)
    }
}
