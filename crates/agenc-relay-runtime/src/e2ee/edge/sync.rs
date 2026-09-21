//! Companion synchronization on the edge (12.5): after the profile is
//! active the edge resumes from its durable cursor or installs the ESTATE
//! snapshot the coordinator cuts, records READY durably before ACTIVE, and
//! then replays its origin set; `STATE_ACTIVE` follows EORIGIN READY.

use agenc_relay_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::DELIVERY_ROW_KIND;

use super::router::Refusal;
use super::{ClientOutput, E2eeEdge, Phase};
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;

/// Whether a frame is one the blocked witness phase reads: the resume the
/// requests follow, and the resolution family itself (companion 12.5.1).
fn witness_admitted(frame: &CompanionFrame) -> bool {
    matches!(
        frame,
        CompanionFrame::ResumeOk { .. }
            | CompanionFrame::WitnessBegin { .. }
            | CompanionFrame::WitnessEntry { .. }
            | CompanionFrame::WitnessEnd { .. }
    )
}

/// The edge's companion delivery position.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DeliveryState {
    /// The delivery generation in use.
    pub(crate) generation: u64,
    /// The last applied and acknowledged position.
    pub(crate) cursor: Option<(u64, [u8; 16])>,
}

impl DeliveryState {
    /// The next sequence the coordinator must deliver.
    pub(crate) fn next_sequence(&self) -> u64 {
        self.cursor
            .map_or(0, |(sequence, _)| sequence.saturating_add(1))
    }

    /// Advances to `position` after its apply.
    pub(crate) fn advance(&mut self, position: DeliveryPosition) {
        self.generation = position.delivery_generation;
        self.cursor = Some((position.delivery_sequence, position.event_id));
    }
}

impl E2eeEdge {
    /// The companion profile became active on the link: resume from the
    /// durable cursor, or announce a fresh scope.
    pub fn link_active(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> bool {
        // A durable witness row no longer refuses the resume itself: the
        // coordinator can only prove the chain over a resumed link, and the
        // blocked phase below admits nothing but EWITNESS (12.5.1).
        let blocked = self.witness_recovery_pending();
        if !blocked && !self.prepare_witness_retry(context, edge) {
            return false;
        }
        if self.witness_pending() {
            return false;
        }
        if self.phase != Phase::Down {
            return true;
        }
        // A durable READY generation is announced again exactly as before;
        // the coordinator answers with the identical ACTIVE.
        if self.snapshot_ready_pending() {
            return self.resend_ready(context, edge);
        }
        let delivery = self.resume_delivery();
        let frame = CompanionFrame::Resume {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            delivery_generation: delivery.generation,
            last: delivery.cursor,
        };
        let Ok(line) = self.line(&frame) else {
            return false;
        };
        self.phase = Phase::Resuming;
        self.send(context, edge, vec![line])
    }

    /// `ERESUME OK`: the retained cursor continues; the origin set replays.
    pub(super) fn resume_ok(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        delivery_generation: u64,
        next_delivery_sequence: u64,
    ) -> Result<(), Refusal> {
        if self.phase != Phase::Resuming
            || delivery_generation != self.delivery.generation
            || next_delivery_sequence != self.delivery.next_sequence()
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        if self.witness_recovery_pending() {
            return self.begin_witness_resolution(context, edge);
        }
        self.begin_origins(context, edge)
    }

    /// Sends EORIGIN RESET and re-declares every origin whose base
    /// declaration is acknowledged.
    pub(super) fn begin_origins(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        self.phase = Phase::Origins;
        let reset = self.line(&CompanionFrame::OriginReset {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
        })?;
        for origin in self.origins.values_mut() {
            origin.declared = None;
            origin.acked = None;
        }
        if !self.send(context, edge, vec![reset]) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.declare_origins(context, edge);
        Ok(())
    }

    /// `EORIGIN READY`: requests flow. Every request still waiting for its
    /// result is resent in origin and sequence order; the coordinator
    /// answers an executed one from its replay table and runs the rest.
    pub(super) fn origins_ready(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        if self.phase != Phase::Origins {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.phase = Phase::Active;
        self.resend_pending(context, edge);
        Ok(())
    }

    /// The unanswered requests of every acknowledged origin, in operation
    /// sequence order: what a resume sends again.
    pub(super) fn resend_order(&self) -> Vec<[u8; 16]> {
        let mut order: Vec<(u64, [u8; 16])> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.result.is_none())
            .filter(|(_, pending)| {
                self.origins
                    .get(&pending.generation)
                    .is_some_and(|origin| origin.acked.is_some() && origin.acked == origin.declared)
            })
            .map(|(request_id, pending)| (pending.sequence, *request_id))
            .collect();
        order.sort_unstable();
        order
            .into_iter()
            .map(|(_, request_id)| request_id)
            .collect()
    }

    /// Resends the unanswered requests of every acknowledged origin.
    fn resend_pending(&mut self, context: &mut StateCoreContext, edge: &mut EdgeFederation) {
        for request_id in self.resend_order() {
            let lines = self
                .pending
                .get(&request_id)
                .map(|pending| pending.frames.clone())
                .unwrap_or_default()
                .iter()
                .map(|frame| self.line(frame))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();
            if lines.is_empty() || !self.send(context, edge, lines) {
                return;
            }
        }
    }

    /// The durable rows a restart reads back: the delivery cursor row of
    /// this edge's coordinator.
    #[must_use]
    pub fn cursor_row_kind() -> u16 {
        DELIVERY_ROW_KIND
    }

    /// Frames from the coordinator once the profile is active.
    pub fn handle_frames(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        frames: Vec<CompanionFrame>,
    ) -> Vec<ClientOutput> {
        let blocked = self.witness_recovery_pending();
        if self.witness_pending()
            || (!blocked && !frames.is_empty() && !self.prepare_witness_retry(context, edge))
        {
            return Vec::new();
        }
        // While a row is unresolved only the resolution family is read; every
        // other companion frame is dropped exactly as before (12.5.1).
        let frames: Vec<CompanionFrame> = if blocked {
            frames.into_iter().filter(witness_admitted).collect()
        } else {
            frames
        };
        let mut outputs = Vec::new();
        self.adopt_barrier_cursor(edge);
        self.barrier_parts.retain(|mutation, _| {
            edge.collecting_barrier() == Some(*mutation) || edge.barrier_applied(mutation)
        });
        for frame in frames {
            match self.handle_frame(context, edge, frame) {
                Ok(more) => outputs.extend(more),
                Err(_) => {
                    self.fail_frame(context, edge);
                    break;
                }
            }
        }
        outputs
    }

    /// A frame violated the profile: the link closes, as a witness violation
    /// when the record chain did not extend (companion 12.5), and the router
    /// forgets the link.
    pub(crate) fn fail_frame(&mut self, context: &mut StateCoreContext, edge: &mut EdgeFederation) {
        if self.record_witness(context, edge) {
            self.link_down();
            return;
        }
        self.counters.violations = self.counters.violations.saturating_add(1);
        edge.fail_companion_link(context);
        self.link_down();
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match routes every coordinator frame to its handler with the exact fields the line carried
    fn handle_frame(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        frame: CompanionFrame,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        match frame {
            CompanionFrame::StateBegin { .. } if edge.collecting_barrier().is_some() => {
                Err(E2eeReplyCode::Syncing.into())
            }

            CompanionFrame::ResumeOk {
                delivery_generation,
                next_delivery_sequence,
                ..
            } => self
                .resume_ok(context, edge, delivery_generation, next_delivery_sequence)
                .map(|()| Vec::new()),
            CompanionFrame::StateBegin {
                snapshot_token,
                state_generation,
                delivery_generation,
                page_sequence,
                total_entry_count,
                page_entry_count,
                snapshot_digest,
                ..
            } => self
                .state_begin(
                    context,
                    edge,
                    snapshot_token,
                    state_generation,
                    delivery_generation,
                    page_sequence,
                    total_entry_count,
                    page_entry_count,
                    snapshot_digest,
                )
                .map(|()| Vec::new()),
            CompanionFrame::StateEntry {
                snapshot_token,
                page_sequence,
                conversation_id,
                object_id,
                fragment,
                ..
            } => self
                .state_entry(
                    context,
                    edge,
                    snapshot_token,
                    page_sequence,
                    conversation_id,
                    object_id,
                    fragment,
                )
                .map(|()| Vec::new()),
            CompanionFrame::StateEnd {
                snapshot_token,
                page_sequence,
                next_cursor,
                ..
            } => self
                .state_end(context, snapshot_token, page_sequence, next_cursor)
                .map(|()| Vec::new()),
            CompanionFrame::StateCut {
                active: true,
                snapshot_token,
                state_generation,
                delivery_generation,
                snapshot_digest,
                ..
            } => self
                .state_active(
                    context,
                    snapshot_token,
                    state_generation,
                    delivery_generation,
                    snapshot_digest,
                )
                .map(|()| Vec::new()),
            CompanionFrame::OriginReady { .. } => {
                self.origins_ready(context, edge).map(|()| Vec::new())
            }
            CompanionFrame::OriginAck {
                origin_id,
                origin_generation,
                object_id,
                ..
            } => self
                .origin_acked(
                    context,
                    edge,
                    origin_id,
                    origin_generation,
                    object_id.is_some(),
                )
                .map(|()| Vec::new()),
            CompanionFrame::WitnessBegin {
                target_server_id,
                conversation_id,
                resolution_token,
                object_id,
                ref fragment,
            } => self
                .witness_begin(
                    context,
                    target_server_id,
                    conversation_id,
                    resolution_token,
                    object_id,
                    fragment,
                )
                .map(|()| Vec::new()),
            CompanionFrame::WitnessEntry {
                target_server_id,
                resolution_token,
                entry_sequence,
                object_id,
                ref fragment,
            } => self
                .witness_entry(
                    context,
                    target_server_id,
                    resolution_token,
                    entry_sequence,
                    object_id,
                    fragment,
                )
                .map(|()| Vec::new()),
            CompanionFrame::WitnessEnd {
                target_server_id,
                resolution_token,
                record_count,
            } => self
                .witness_end(
                    context,
                    edge,
                    target_server_id,
                    resolution_token,
                    record_count,
                )
                .map(|()| Vec::new()),
            CompanionFrame::Result { .. } | CompanionFrame::Response { .. } => {
                self.on_result_frame(context, frame)
            }
            CompanionFrame::Event {
                position,
                object_id,
                fragment,
            } => self.on_event_frame(context, edge, position, object_id, fragment, false),
            CompanionFrame::Data {
                position,
                object_id,
                fragment,
            } => self.on_event_frame(context, edge, position, object_id, fragment, true),
            _ => Err(E2eeReplyCode::InvalidFragment.into()),
        }
    }
}
