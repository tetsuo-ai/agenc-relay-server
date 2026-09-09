//! Companion events on the edge (12.5): every `EEVENT` and its `EDATA`
//! reassembles at the exact next delivery position, applies in one
//! transaction that advances the cursor and the projected route state, and
//! is acknowledged after that commit. Application, candidate, and
//! acknowledgement copies fan out to the attached local sessions.

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_domain::e2ee::{
    ConversationId, DirectPair, RecoveryState, RouteEntry, RouteLifecycle, RouteTarget,
    SemanticLockId,
};
use agenc_ircd_e2ee::federation::frames::{CompanionFrame, DeliveryPosition};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::objects::federation::{
    IrcFederationEvent, IrcFederationEventKind, IrcFederationRouteState, IrcRouteStateKind,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode, TlsEncode};
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::{FragmentTag, ReceiptTag, fragment_object};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_e2ee::wire::response::{
    LiveLine, LiveTags, SuccessLine, render_ack_notice, render_broadcast, render_live,
};
use agenc_ircd_federation_wire::{DecodeBudget as WireBudget, SchemaObject};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::barrier::{BarrierIdentity, BarrierPart, CrossProfileStream};
use agenc_ircd_storage::e2ee_records::{
    DELIVERY_ROW_KIND, DeliveryRow, ROUTE_ROW_KIND, RouteLifecycle as RowLifecycle, RouteRow,
    WitnessRow,
};
use agenc_ircd_types::{AccountId, ChannelInstanceId, UserId};

use crate::connection::ConnectionGeneration;

use super::router::Refusal;
use super::{ClientOutput, E2eeEdge, PendingCommit};
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;

/// What the edge keeps of one projected conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Conversation {
    /// The channel, for a channel route.
    pub(crate) channel: Option<ChannelInstanceId>,
    /// The two accounts, for a direct route.
    pub(crate) direct: Option<([u8; 24], [u8; 24])>,
    /// The sequencer record-chain head this edge has witnessed.
    pub(crate) head: ChainHead,
}

/// The sequencer record-chain head an edge witnesses for one conversation
/// (companion 12.5): installed from the route-state cut, advanced by every
/// candidate, ReInit-staged, terminal, and close event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChainHead {
    /// Route sequence of the head record, or zero at the external anchor.
    pub(crate) sequence: u64,
    /// The head record's semantic identifier, or the anchor.
    pub(crate) record_id: [u8; 32],
    /// Whether a record occupies the head; false at the anchor, where the
    /// first candidate takes sequence zero itself.
    pub(crate) recorded: bool,
}

impl ChainHead {
    /// The head a route-state cut names; the anchor is the cut whose head is
    /// still its accepted state at sequence zero.
    fn from_state(state: &IrcFederationRouteState) -> Self {
        let sequence = state.sequencer_record_head_sequence;
        let record_id = state.sequencer_record_head_id;
        Self {
            sequence,
            record_id,
            recorded: !(sequence == 0 && record_id == state.accepted_state_id),
        }
    }

    /// The route sequence the next chain-extending event must carry.
    pub(super) const fn next_sequence(self) -> u64 {
        if self.recorded {
            self.sequence.saturating_add(1)
        } else {
            self.sequence
        }
    }

    /// Whether `cut` may replace this head: never an older or a forked one.
    pub(super) fn accepts_cut(self, cut: Self) -> bool {
        !self.recorded
            || cut.sequence > self.sequence
            || (cut.sequence == self.sequence && self.record_id == cut.record_id)
    }

    /// Whether an event at `sequence` naming `id` is this recorded head
    /// again, as after a route-state cut that already carried it.
    fn names(self, sequence: u64, id: [u8; 32]) -> bool {
        self.recorded && sequence == self.sequence && self.record_id == id
    }
}

/// What one chain-extending event contributes to the witness.
struct ChainStep {
    /// The identifier that becomes the head.
    id: [u8; 32],
    /// The predecessor the event asserts, when its receipt carries one.
    predecessor: Option<[u8; 32]>,
}

/// The chain step of a semantic event, or `None` for an event that never
/// moves the head.
fn chain_step(event: &IrcFederationEvent) -> Option<ChainStep> {
    use agenc_ircd_e2ee::objects::sequencing::IrcCandidateReceipt;
    let encoded = event.encoded_event_result.as_slice();
    let ids = encoded.as_chunks::<32>().0;
    let step = match event.event_kind {
        IrcFederationEventKind::CandidateEvent => {
            let mut budget = DecodeBudget::new(1 << 16, 1_024);
            let receipt = IrcCandidateReceipt::decode_exact(encoded, &mut budget).ok()?;
            ChainStep {
                id: candidate_id_of(encoded)?,
                predecessor: Some(receipt.tbs.predecessor_record_id),
            }
        }
        IrcFederationEventKind::ReinitStagedEvent | IrcFederationEventKind::ClosedEvent => {
            ChainStep {
                id: *ids.first()?,
                predecessor: None,
            }
        }
        IrcFederationEventKind::FinalizedEvent => ChainStep {
            id: encoded.get(8..40)?.try_into().ok()?,
            predecessor: None,
        },
        IrcFederationEventKind::AbortedEvent
        | IrcFederationEventKind::ReinitActivatedEvent
        | IrcFederationEventKind::ReinitAbortedEvent => ChainStep {
            id: *ids.get(1)?,
            predecessor: None,
        },
        _ => return None,
    };
    Some(step)
}

/// An event whose payload has not arrived.
#[derive(Clone)]
pub(crate) struct OpenEvent {
    pub(crate) position: DeliveryPosition,
    pub(crate) event: IrcFederationEvent,
    pub(crate) payload_object_id: Option<[u8; 32]>,
}

fn optional<const N: usize>(field: &[u8]) -> Option<[u8; N]> {
    field.try_into().ok()
}

impl E2eeEdge {
    /// `EEVENT` fragments: the event object assembles; its payload follows
    /// on `EDATA` when the event names one.
    pub(super) fn on_event_frame(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        position: DeliveryPosition,
        object_id: [u8; 32],
        fragment: FragmentTag,
        data: bool,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let kind = if data {
            IrcWireObjectKind::ApplicationMls
        } else {
            IrcWireObjectKind::FederationEvent
        };
        let Some(bytes) = self.assemble_event(&position, object_id, kind, &fragment, context)?
        else {
            return Ok(Vec::new());
        };
        if data {
            let Some(open) = self.events_in.remove(&position.event_id) else {
                return Err(E2eeReplyCode::InvalidFragment.into());
            };
            if open.payload_object_id != Some(object_id) {
                return Err(E2eeReplyCode::InvalidFragment.into());
            }
            return self.admit_event(context, edge, open, Some(bytes));
        }
        let mut budget = DecodeBudget::new(1 << 16, 4_096);
        let object = IrcWireObject::decode_kind(
            &bytes,
            Some(IrcWireObjectKind::FederationEvent),
            &mut budget,
        )
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let event = IrcFederationEvent::decode_exact(object.body(), &mut budget)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let payload_object_id = optional::<32>(event.payload_object_id.as_slice());
        let open = OpenEvent {
            position,
            event,
            payload_object_id,
        };
        if payload_object_id.is_some() {
            self.events_in.insert(position.event_id, open);
            return Ok(Vec::new());
        }
        self.admit_event(context, edge, open, None)
    }

    fn assemble_event(
        &mut self,
        position: &DeliveryPosition,
        object_id: [u8; 32],
        kind: IrcWireObjectKind,
        fragment: &FragmentTag,
        context: &StateCoreContext,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let command = CarrierCommand::Federation(kind);
        let mut route = [0; 32];
        if let Some(head) = route.get_mut(..16) {
            head.copy_from_slice(&position.event_id);
        }
        let key = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer(*self.config.coordinator_server_id.as_bytes()),
            command,
            route,
            scope: None,
            object_id: agenc_ircd_e2ee::ObjectId::from_bytes(object_id),
        };
        let scopes = QuotaScopes {
            peer: Some(*self.config.coordinator_server_id.as_bytes()),
            ..QuotaScopes::default()
        };
        let now = context.now().get() / 1_000;
        match self
            .assembler
            .ingest(key, scopes, command.limit(), fragment, now)
        {
            Ok(Ingest::Complete(bytes)) => Ok(Some(bytes)),
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(None),
            Err(error) => Err(error.reply_code().into()),
        }
    }

    /// A complete event: a cross-profile part goes to the barrier, an
    /// ordinary event must sit at the exact next position and applies.
    fn admit_event(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        open: OpenEvent,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let event = &open.event;
        let header_ok = event.network_id == self.config.network_id
            && event.target_server_id == *self.config.server_id.as_bytes()
            && event.delivery_generation == open.position.delivery_generation
            && event.delivery_sequence == open.position.delivery_sequence
            && event.event_id == open.position.event_id;
        if !header_ok {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        if let Some(mutation_id) = optional::<16>(event.cross_profile_mutation_id.as_slice()) {
            return self.barrier_part(context, edge, open, payload, mutation_id);
        }
        self.adopt_barrier_cursor(edge);
        if self.delivery.generation != open.position.delivery_generation
            || open.position.delivery_sequence != self.delivery.next_sequence()
        {
            return Err(E2eeReplyCode::Syncing.into());
        }
        if self.holds_events(context) {
            self.queued.push_back((
                CompanionFrame::Ack(open.position),
                payload.unwrap_or_default(),
            ));
            let _ = self.events_in.insert(open.position.event_id, open);
            return Ok(Vec::new());
        }
        self.apply_event(context, edge, open, payload)
    }

    /// Whether an event must wait: this profile's own slot is taken or a
    /// base batch is in flight; both profiles drain after every commit.
    fn holds_events(&self, context: &StateCoreContext) -> bool {
        self.commit.is_some() || context.in_flight()
    }

    /// Hands a cross-profile part to the base edge's barrier owner.
    fn barrier_part(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        open: OpenEvent,
        payload: Option<Vec<u8>>,
        mutation_id: [u8; 16],
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let event_bytes = IrcWireObject::new(
            IrcWireObjectKind::FederationEvent,
            open.event
                .encode()
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )
        .and_then(|object| object.encode())
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let (identity_epoch, identity_incarnation) = edge
            .coordinator_link_identity()
            .ok_or(E2eeReplyCode::Syncing)?;
        let part = BarrierPart {
            identity: BarrierIdentity {
                network_id: self.config.network_id,
                coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
                coordinator_server_incarnation: identity_incarnation,
                coordinator_recovery_epoch: identity_epoch,
                target_server_id: *self.config.server_id.as_bytes(),
                target_server_incarnation: self.config.incarnation,
                mutation_id,
                coordinator_state_generation: open.event.coordinator_state_generation,
                part_count: open.event.cross_profile_part_count,
            },
            stream: CrossProfileStream::Companion,
            part_index: open.event.cross_profile_part_index,
            delivery_generation: open.position.delivery_generation,
            delivery_sequence: open.position.delivery_sequence,
            event_id: open.position.event_id,
            event_object_id: *agenc_ircd_e2ee::ObjectId::compute(&event_bytes).as_bytes(),
            encoded_event_object: event_bytes,
            payload_object_id: open.payload_object_id,
            payload_object_bytes: payload
                .as_ref()
                .map_or(0, |bytes| u32::try_from(bytes.len()).unwrap_or(u32::MAX)),
        };
        edge.note_companion_delivery(self.delivery.generation, self.delivery.cursor);
        let part_index = part.part_index;
        if !edge.companion_barrier_part(context, part, payload.clone()) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.barrier_parts
            .entry(mutation_id)
            .or_default()
            .insert(part_index, (open, payload));
        Ok(Vec::new())
    }

    /// The rows and rendered lines of the companion parts of a complete
    /// barrier, applied to the route table now so the base edge can write
    /// them in the barrier's apply transaction (spec 20.8).
    pub(crate) fn prepare_barrier(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
        mutation_id: [u8; 16],
    ) -> Result<
        (
            Vec<crate::state_core::durable::AccountServiceDurableWrite>,
            Vec<ClientOutput>,
        ),
        E2eeReplyCode,
    > {
        self.begin_projection(Some(mutation_id))
            .map_err(|refusal| refusal.code)?;
        let prepared = self.prepare_barrier_parts(context, edge, mutation_id);
        if prepared.is_err() {
            self.rollback_projection();
        }
        prepared.map_err(|refusal| refusal.code)
    }

    fn prepare_barrier_parts(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
        mutation_id: [u8; 16],
    ) -> Result<
        (
            Vec<crate::state_core::durable::AccountServiceDurableWrite>,
            Vec<ClientOutput>,
        ),
        Refusal,
    > {
        self.barrier_completions.clear();
        let parts = self
            .barrier_parts
            .get(&mutation_id)
            .cloned()
            .unwrap_or_default();
        let position = parts
            .values()
            .map(|(open, _)| open.position)
            .max_by_key(|position| position.delivery_sequence)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let touched: std::collections::BTreeSet<_> = parts
            .values()
            .filter_map(|(open, _)| optional::<32>(open.event.conversation_id.as_slice()))
            .collect();
        let mut writes = Vec::new();
        let mut outputs = Vec::new();
        for (_, (open, payload)) in parts {
            let event = &open.event;
            match event.event_kind {
                IrcFederationEventKind::RouteStateChanged => {
                    let bytes = payload.as_deref().ok_or(E2eeReplyCode::InvalidFragment)?;
                    writes.push(self.route_changed(bytes)?);
                }
                IrcFederationEventKind::RouteStateHidden => {
                    let conversation = optional::<32>(event.conversation_id.as_slice())
                        .ok_or(E2eeReplyCode::InvalidFragment)?;
                    if let Some(write) = self.route_hidden(context, conversation) {
                        writes.push(write);
                    }
                }
                IrcFederationEventKind::RequestCompleted => {}
                _ => {
                    self.witness(event)?;
                    outputs.extend(self.fanout(context, edge, &open, payload.as_deref())?);
                }
            }
            let (completion, rendered) = self.prepare_completion(context, event)?;
            outputs.extend(rendered);
            self.barrier_completions.push(completion);
        }
        self.checkpoint_witnesses(touched, &mut writes)?;
        let mut delivery = self.delivery;
        delivery.advance(position);
        writes.push(cursor_write(&self.config, &delivery)?);
        Ok((writes, outputs))
    }

    /// Holds the rendered lines of a barrier the base edge staged.
    pub fn barrier_staged(&mut self, mutation_id: [u8; 16], outputs: Vec<ClientOutput>) {
        self.barrier_pending = Some((mutation_id, outputs));
    }

    /// Releases the lines of a barrier whose receipt now stands, and adopts
    /// the companion position it advanced.
    pub fn barrier_outputs(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
    ) -> Vec<ClientOutput> {
        self.commit_barrier_projection(edge);
        self.adopt_barrier_cursor(edge);
        let applied = self
            .barrier_pending
            .as_ref()
            .is_some_and(|(mutation_id, _)| edge.barrier_applied(mutation_id));
        if !applied {
            return Vec::new();
        }
        let mut late_outputs = Vec::new();
        for completion in std::mem::take(&mut self.barrier_completions) {
            late_outputs.extend(self.commit_completion(context, completion));
        }
        if let Some((mutation_id, _)) = &self.barrier_pending {
            self.barrier_parts.remove(mutation_id);
        }
        self.counters.events_applied = self.counters.events_applied.saturating_add(1);
        late_outputs.extend(
            self.barrier_pending
                .take()
                .map_or_else(Vec::new, |(_, outputs)| outputs),
        );
        late_outputs
    }

    /// Adopts the companion position a committed cross-profile barrier
    /// advanced on the base edge, which applied those parts itself.
    pub(super) fn adopt_barrier_cursor(&mut self, edge: &EdgeFederation) {
        let (generation, cursor) = edge.companion_cursor();
        if generation != self.delivery.generation {
            return;
        }
        if let Some((sequence, event_id)) = cursor
            && self
                .delivery
                .cursor
                .is_none_or(|(applied, _)| sequence > applied)
        {
            self.delivery.cursor = Some((sequence, event_id));
        }
    }

    /// Witnesses the sequencer record chain (companion 12.5): a candidate,
    /// ReInit-staged, terminal, or close event must extend the
    /// conversation's head, and then becomes it; an event that names the
    /// installed head again, as after a route-state cut that carried it,
    /// leaves it. A non-extending event is remembered for
    /// [`Self::record_witness`] and refused.
    pub(super) fn witness(&mut self, event: &IrcFederationEvent) -> Result<(), Refusal> {
        let Some(conversation) = optional::<32>(event.conversation_id.as_slice()) else {
            return Ok(());
        };
        let Some(step) = chain_step(event) else {
            return Ok(());
        };
        let Some(known) = self.conversations.get_mut(&conversation) else {
            return Ok(());
        };
        let head = known.head;
        if head.names(event.route_sequence, step.id) {
            return Ok(());
        }
        let expected = head.next_sequence();
        let extends = event.route_sequence == expected
            && step
                .predecessor
                .is_none_or(|predecessor| predecessor == head.record_id);
        if extends {
            known.head = ChainHead {
                sequence: event.route_sequence,
                record_id: step.id,
                recorded: true,
            };
            return Ok(());
        }
        self.witnessed = Some((
            conversation,
            WitnessRow {
                event_kind: event.event_kind.value(),
                expected_sequence: expected,
                expected_head_id: head.record_id,
                observed_sequence: event.route_sequence,
                observed_id: step.id,
                observed_predecessor_id: step.predecessor,
            },
        ));
        Err(E2eeReplyCode::RouteInvalid.into())
    }

    /// Applies one ordinary event: route projection, fanout, coverage, and
    /// the durable cursor batch whose commit sends the EACK.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one event applies its route change, renders its copies, records completion coverage, and stages its cursor batch as one atomic set
    fn apply_event(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        open: OpenEvent,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        self.begin_projection(None)?;
        let result = self.apply_event_projection(context, edge, open, payload);
        if result.is_err() {
            self.rollback_projection();
        }
        result
    }

    fn apply_event_projection(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        open: OpenEvent,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let event = &open.event;
        let conversation = optional::<32>(event.conversation_id.as_slice());
        let mut writes = Vec::new();
        let mut outputs = Vec::new();
        match event.event_kind {
            IrcFederationEventKind::RouteStateChanged => {
                let bytes = payload.as_deref().ok_or(E2eeReplyCode::InvalidFragment)?;
                writes.push(self.route_changed(bytes)?);
            }
            IrcFederationEventKind::RouteStateHidden => {
                let conversation = conversation.ok_or(E2eeReplyCode::InvalidFragment)?;
                if let Some(write) = self.route_hidden(context, conversation) {
                    writes.push(write);
                }
            }
            IrcFederationEventKind::RequestCompleted => {}
            _ => {
                self.witness(event)?;
                outputs.extend(self.fanout(context, edge, &open, payload.as_deref())?);
            }
        }
        // The home copy of a semantic event is its request's completion; a
        // generic completion is a `request_completed` of its own (12.5).
        let (completion, rendered) = self.prepare_completion(context, event)?;
        outputs.extend(rendered);
        self.checkpoint_witnesses(conversation, &mut writes)?;
        let position = open.position;
        let mut delivery = self.delivery;
        delivery.advance(position);
        writes.push(cursor_write(&self.config, &delivery).map_err(|_| E2eeReplyCode::RateLimited)?);
        self.stage(
            context,
            writes,
            PendingCommit::Event {
                position,
                outputs,
                completion,
            },
        )?;
        Ok(Vec::new())
    }

    /// Projects one `federation_state` object into the route table and its
    /// durable row.
    pub(super) fn route_changed(
        &mut self,
        bytes: &[u8],
    ) -> Result<crate::state_core::durable::AccountServiceDurableWrite, Refusal> {
        let mut budget = DecodeBudget::new(1 << 16, 4_096);
        let object = IrcWireObject::decode_kind(
            bytes,
            Some(IrcWireObjectKind::FederationState),
            &mut budget,
        )
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let state = IrcFederationRouteState::decode_exact(object.body(), &mut budget)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        if state.network_id != self.config.network_id {
            return Err(E2eeReplyCode::RouteInvalid.into());
        }
        let (entry, conversation) = route_entry(&state)?;
        if let Some(known) = self.conversations.get(&state.conversation_id)
            && !known.head.accepts_cut(conversation.head)
        {
            self.witnessed = Some((
                state.conversation_id,
                WitnessRow {
                    event_kind: IrcFederationEventKind::RouteStateChanged.value(),
                    expected_sequence: known.head.next_sequence(),
                    expected_head_id: known.head.record_id,
                    observed_sequence: conversation.head.sequence,
                    observed_id: conversation.head.record_id,
                    observed_predecessor_id: None,
                },
            ));
            return Err(E2eeReplyCode::RouteInvalid.into());
        }
        self.routes.restore_entry(entry);
        self.conversations
            .insert(state.conversation_id, conversation);
        self.route_objects
            .insert(state.conversation_id, bytes.to_vec());
        let tombstone = state.state == IrcRouteStateKind::EncryptedTombstone;
        let row = RouteRow {
            route_state: bytes.to_vec(),
            lifecycle: if tombstone {
                RowLifecycle::Tombstone
            } else {
                RowLifecycle::Active
            },
            binding_id: state.binding_id,
            lock_id: state.semantic_route_lock_id,
            accepted_state_id: state.accepted_state_id,
            sequencer_head_id: state.sequencer_record_head_id,
            route_sequence: state.sequencer_record_head_sequence,
            // A tombstone's head record is its close (companion 12.5).
            close_id: tombstone.then_some(state.sequencer_record_head_id),
            predecessor_close_id: None,
            recovery_gate: false,
            stored_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        };
        state_row(
            RouteRow::key(&state.conversation_id).map_err(|_| E2eeReplyCode::InvalidFragment)?,
            ROUTE_ROW_KIND,
            row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )
    }

    /// Drops one projected route and its row.
    pub(super) fn route_hidden(
        &mut self,
        context: &StateCoreContext,
        conversation: [u8; 32],
    ) -> Option<crate::state_core::durable::AccountServiceDurableWrite> {
        self.routes.remove_projection(&ConversationId(conversation));
        self.route_objects.remove(&conversation);
        self.conversations.remove(&conversation);
        let key = RouteRow::key(&conversation).ok()?;
        let exists = context
            .index()
            .existing(TableId::E2eeState, &key)
            .is_ok_and(|existing| existing.is_some());
        if !exists {
            return None;
        }
        crate::state_core::durable::AccountServiceDurableWrite::delete(TableId::E2eeState, key).ok()
    }

    /// The client lines one semantic event produces for the local
    /// sessions attached to its conversation.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match renders every event kind's copies for the recipients its conversation names
    fn fanout(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
        open: &OpenEvent,
        payload: Option<&[u8]>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let event = &open.event;
        let conversation = optional::<32>(event.conversation_id.as_slice())
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let recipients = self.recipients(context, edge, conversation);
        let source = self.source_prefix(event);
        let kind = event.event_kind;
        let requester = self.requester_of(event);
        // A channel copy names the channel; the replica projects the name
        // and the router remembers it for the conversation's later copies.
        let channel = self
            .conversations
            .get(&conversation)
            .and_then(|known| known.channel);
        let channel_name = channel.and_then(|channel| {
            self.channel_name(channel).or_else(|| {
                let name = edge
                    .replica()
                    .channel(channel)
                    .map(|record| record.name.presentation().to_owned())?;
                self.remember_channel(channel, &name);
                Some(name)
            })
        });
        let mut outputs = Vec::new();
        for (generation, _) in recipients {
            let label = requester
                .as_ref()
                .filter(|(request_generation, _)| *request_generation == generation)
                .and_then(|(_, label)| label.clone());
            let lines = match kind {
                IrcFederationEventKind::ChannelApplication
                | IrcFederationEventKind::DirectApplication
                | IrcFederationEventKind::CandidateEvent => self.live_lines(
                    &source,
                    label.as_deref(),
                    event,
                    (conversation, channel_name.as_deref()),
                    payload.ok_or(E2eeReplyCode::InvalidFragment)?,
                )?,
                IrcFederationEventKind::CommitAckEvent | IrcFederationEventKind::ReinitAckEvent => {
                    let selector = optional::<32>(event.encoded_event_result.as_slice())
                        .ok_or(E2eeReplyCode::InvalidFragment)?;
                    let object = optional::<32>(event.payload_object_id.as_slice())
                        .ok_or(E2eeReplyCode::InvalidFragment)?;
                    let reinit = kind == IrcFederationEventKind::ReinitAckEvent;
                    vec![
                        render_ack_notice(&source, reinit, &conversation, &selector, &object)
                            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                    ]
                }
                _ => terminal_lines(&self.config.server_name, conversation, event)?,
            };
            if requester
                .as_ref()
                .is_some_and(|(request_generation, _)| *request_generation == generation)
                && let Some(request_id) = optional::<16>(event.request_id.as_slice())
                && let Some(pending) = self.pending.get_mut(&request_id)
            {
                pending.echo_lines = lines.clone();
            }
            let frames = lines
                .iter()
                .map(|line| WireMessage::extension_line(line))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| E2eeReplyCode::InvalidFragment)?;
            if !frames.is_empty() {
                outputs.push(ClientOutput { generation, frames });
            }
        }
        Ok(outputs)
    }

    /// The requester of an event's request correlation, when local.
    fn requester_of(
        &self,
        event: &IrcFederationEvent,
    ) -> Option<(ConnectionGeneration, Option<String>)> {
        let request_id = optional::<16>(event.request_id.as_slice())?;
        let pending = self.pending.get(&request_id)?;
        Some((pending.generation, pending.label.clone()))
    }

    /// The local connections attached to a conversation: channel members
    /// holding the capability and an attachment, or the sessions of the two
    /// direct accounts.
    fn recipients(
        &self,
        context: &StateCoreContext,
        edge: &EdgeFederation,
        conversation: [u8; 32],
    ) -> Vec<(ConnectionGeneration, UserId)> {
        let Some(known) = self.conversations.get(&conversation) else {
            return Vec::new();
        };
        let mut recipients = Vec::new();
        if let Some(channel) = known.channel {
            for user in edge.replica().local_members(channel) {
                let Some(generation) = context.sessions().generation_for_user(user) else {
                    continue;
                };
                if self
                    .origins
                    .get(&generation)
                    .is_some_and(|origin| origin.device.is_some())
                {
                    recipients.push((generation, user));
                }
            }
        }
        if let Some((first, second)) = known.direct {
            for (generation, origin) in &self.origins {
                let member = origin
                    .account
                    .is_some_and(|account| account == first || account == second);
                if member
                    && origin.device.is_some()
                    && let Some(user) = origin.user_id
                {
                    recipients.push((*generation, user));
                }
            }
        }
        recipients
    }

    /// The `nick!user@host` prefix of an event's source view, or the
    /// server name when the event carries none.
    fn source_prefix(&self, event: &IrcFederationEvent) -> String {
        let mut budget = WireBudget::new(4_096, 256);
        SchemaObject::decode_exact(
            "FederationSourceView",
            event.source_view.as_slice(),
            &mut budget,
        )
        .ok()
        .and_then(|object| crate::federation::codec::source_view_of(&object).ok())
        .and_then(|view| crate::federation::edge::source_prefix(&view).ok())
        .unwrap_or_else(|| self.config.server_name.clone())
    }

    /// The live copies of one application or candidate object.
    fn live_lines(
        &self,
        source: &str,
        label: Option<&str>,
        event: &IrcFederationEvent,
        (conversation, channel_name): ([u8; 32], Option<&str>),
        payload: &[u8],
    ) -> Result<Vec<String>, Refusal> {
        let line = match event.event_kind {
            IrcFederationEventKind::ChannelApplication => {
                let name = channel_name.ok_or(E2eeReplyCode::RouteInvalid)?;
                LiveLine::Tagmsg(name.as_bytes().to_vec())
            }
            IrcFederationEventKind::DirectApplication => LiveLine::Edirect(conversation),
            _ => {
                let candidate_id = candidate_id_of(event.encoded_event_result.as_slice())
                    .ok_or(E2eeReplyCode::InvalidFragment)?;
                LiveLine::Candidate(
                    conversation,
                    *agenc_ircd_e2ee::ObjectId::compute(payload).as_bytes(),
                    candidate_id,
                )
            }
        };
        let receipt = matches!(line, LiveLine::Candidate(..)).then(|| ReceiptTag {
            candidate_id: match line {
                LiveLine::Candidate(_, _, id) => id,
                _ => [0; 32],
            },
            receipt: event.encoded_event_result.as_slice().to_vec(),
        });
        let mut lines = Vec::new();
        for fragment in fragment_object(payload).map_err(|_| E2eeReplyCode::ObjectTooLarge)? {
            let first = fragment.part == 0;
            let tags = LiveTags {
                label: label.filter(|_| first),
                account: None,
                receipt: receipt.as_ref().filter(|_| first),
            };
            lines.push(
                render_live(source, &tags, &fragment, &line)
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            );
        }
        Ok(lines)
    }

    /// The presentation name of a channel instance the replica knows.
    fn channel_name(&self, channel: ChannelInstanceId) -> Option<String> {
        self.channel_names.get(&channel).cloned()
    }

    /// Stages one event batch beside a checkpoint plan; a busy state core
    /// keeps the event queued.
    pub(super) fn stage(
        &mut self,
        context: &mut StateCoreContext,
        writes: Vec<crate::state_core::durable::AccountServiceDurableWrite>,
        pending: PendingCommit,
    ) -> Result<(), Refusal> {
        let plan = context
            .domain()
            .plan_account_service_checkpoint()
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let revision = plan.resulting_revision().get();
        let writes = writes
            .into_iter()
            .map(|write| write.at_revision(revision))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        context
            .stage_durable_with_account_service(plan, fanout, None, 0, writes)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        self.commit = Some(pending);
        Ok(())
    }

    /// The batch committed: the EACK goes out and the rendered copies are
    /// released to their connections.
    pub fn batch_applied(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Vec<ClientOutput> {
        if self.witness_batch_applied(context, edge) {
            return Vec::new();
        }
        let mut outputs = Vec::new();
        match self.commit.take() {
            Some(PendingCommit::Event {
                position,
                outputs: rendered,
                completion,
            }) => {
                self.commit_projection();
                self.delivery.advance(position);
                outputs.extend(self.commit_completion(context, completion));
                self.counters.events_applied = self.counters.events_applied.saturating_add(1);
                if let Ok(line) = self.line(&CompanionFrame::Ack(DeliveryPosition {
                    server_id: *self.config.coordinator_server_id.as_bytes(),
                    ..position
                })) {
                    self.send(context, edge, vec![line]);
                }
                outputs.extend(rendered);
            }
            Some(PendingCommit::Ready {
                delivery_generation,
            }) => {
                self.commit_projection();
                self.witness_snapshot_required = false;
                self.ready_recorded(context, edge, delivery_generation);
            }
            Some(PendingCommit::Witness) | None => {}
        }
        self.commit_barrier_projection(edge);
        outputs.extend(self.drain_queued(context, edge));
        outputs
    }

    /// The batch was rejected: the event must be resynchronized.
    pub fn batch_rejected(&mut self) {
        let projected = self.rollback_projection();
        if self.commit.take().is_some() || projected {
            self.counters.violations = self.counters.violations.saturating_add(1);
            self.link_down();
        }
    }

    fn drain_queued(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Vec<ClientOutput> {
        let mut outputs = Vec::new();
        while !self.holds_events(context) {
            let Some((frame, payload)) = self.queued.pop_front() else {
                break;
            };
            let CompanionFrame::Ack(position) = frame else {
                continue;
            };
            let Some(open) = self.events_in.remove(&position.event_id) else {
                continue;
            };
            let payload = (!payload.is_empty()).then_some(payload);
            match self.apply_event(context, edge, open, payload) {
                Ok(more) => outputs.extend(more),
                Err(_) => {
                    self.fail_frame(context, edge);
                    break;
                }
            }
        }
        outputs
    }
}

/// The projected route entry of one route state object.
fn route_entry(state: &IrcFederationRouteState) -> Result<(RouteEntry, Conversation), Refusal> {
    let lifecycle = match state.state {
        IrcRouteStateKind::ActiveRoute => RouteLifecycle::Active,
        IrcRouteStateKind::EncryptedTombstone => RouteLifecycle::Tombstone {
            close_id: state.sequencer_record_head_id,
        },
    };
    let (target, conversation) = match state.conversation_kind {
        IrcConversationKind::Channel => {
            let instance = optional::<16>(state.channel_instance_id.as_slice())
                .ok_or(E2eeReplyCode::RouteInvalid)?;
            let channel = ChannelInstanceId::from_bytes(instance);
            (
                RouteTarget::Channel(channel),
                Conversation {
                    channel: Some(channel),
                    direct: None,
                    head: ChainHead::from_state(state),
                },
            )
        }
        IrcConversationKind::Direct => {
            let a = optional::<24>(state.direct_account_a.as_slice())
                .ok_or(E2eeReplyCode::RouteInvalid)?;
            let b = optional::<24>(state.direct_account_b.as_slice())
                .ok_or(E2eeReplyCode::RouteInvalid)?;
            let first = AccountId::parse_wire_bytes(&a).map_err(|_| E2eeReplyCode::RouteInvalid)?;
            let second =
                AccountId::parse_wire_bytes(&b).map_err(|_| E2eeReplyCode::RouteInvalid)?;
            let pair = DirectPair::new(first, second).map_err(|_| E2eeReplyCode::RouteInvalid)?;
            (
                RouteTarget::Direct(pair),
                Conversation {
                    channel: None,
                    direct: Some((a, b)),
                    head: ChainHead::from_state(state),
                },
            )
        }
    };
    Ok((
        RouteEntry {
            conversation_id: ConversationId(state.conversation_id),
            target,
            lock: SemanticLockId(state.semantic_route_lock_id),
            incarnation: 0,
            binding_id: state.binding_id,
            binding_generation: 0,
            lifecycle,
            recovery: RecoveryState::Normal,
        },
        conversation,
    ))
}

/// The untagged terminal broadcasts (11.7).
fn terminal_lines(
    server: &str,
    conversation: [u8; 32],
    event: &IrcFederationEvent,
) -> Result<Vec<String>, Refusal> {
    let encoded = event.encoded_event_result.as_slice();
    let ids = |count: usize| -> Result<Vec<[u8; 32]>, Refusal> {
        if encoded.len() != count * 32 {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        Ok(encoded.as_chunks::<32>().0.to_vec())
    };
    let line = match event.event_kind {
        IrcFederationEventKind::FinalizedEvent => {
            let epoch = encoded
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u64::from_be_bytes)
                .ok_or(E2eeReplyCode::InvalidFragment)?;
            let rest: Vec<[u8; 32]> = encoded
                .get(8..)
                .unwrap_or_default()
                .as_chunks::<32>()
                .0
                .to_vec();
            match rest.as_slice() {
                [finalization, record] => {
                    SuccessLine::Finalized(conversation, epoch, *finalization, *record)
                }
                _ => return Err(E2eeReplyCode::InvalidFragment.into()),
            }
        }
        IrcFederationEventKind::AbortedEvent => match ids(3)?.as_slice() {
            [candidate, abort, record] => {
                SuccessLine::Aborted(conversation, *candidate, *abort, *record)
            }
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        },
        IrcFederationEventKind::ClosedEvent => match ids(1)?.as_slice() {
            [close] => SuccessLine::Closed(conversation, *close),
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        },
        IrcFederationEventKind::ReinitStagedEvent => match ids(2)?.as_slice() {
            [attempt, object] => SuccessLine::ReinitStaged(conversation, *attempt, *object),
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        },
        IrcFederationEventKind::ReinitActivatedEvent => match ids(3)?.as_slice() {
            [new, activation, record] => {
                SuccessLine::ReinitActivated(conversation, *new, *activation, *record)
            }
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        },
        IrcFederationEventKind::ReinitAbortedEvent => match ids(3)?.as_slice() {
            [attempt, abort, record] => {
                SuccessLine::ReinitAborted(conversation, *attempt, *abort, *record)
            }
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        },
        _ => return Ok(Vec::new()),
    };
    Ok(vec![
        render_broadcast(server, &line).map_err(|_| E2eeReplyCode::InvalidFragment)?,
    ])
}

/// The candidate identifier of a candidate event's receipt.
fn candidate_id_of(receipt: &[u8]) -> Option<[u8; 32]> {
    use agenc_ircd_e2ee::objects::sequencing::IrcCandidateReceipt;
    let mut budget = DecodeBudget::new(1 << 16, 1_024);
    let receipt = IrcCandidateReceipt::decode_exact(receipt, &mut budget).ok()?;
    agenc_ircd_e2ee::ids::semantic_id_of(
        agenc_ircd_crypto::SemanticHashDomain::CandidateId,
        &receipt.tbs,
    )
    .ok()
}

/// The durable companion cursor of the edge, keyed by its coordinator.
pub(super) fn cursor_write(
    config: &super::E2eeEdgeConfig,
    delivery: &super::sync::DeliveryState,
) -> Result<crate::state_core::durable::AccountServiceDurableWrite, E2eeReplyCode> {
    let row = DeliveryRow::WitnessedCursor {
        generation: delivery.generation,
        next_sequence: delivery.next_sequence(),
        acked_sequence: delivery.cursor.map_or(0, |(sequence, _)| sequence),
        acked_event_id: delivery.cursor.map_or([0; 16], |(_, event)| event),
        barrier_open: false,
    }
    .encode()
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let key = DeliveryRow::cursor_key(config.coordinator_server_id.as_bytes())
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    state_row(key, DELIVERY_ROW_KIND, row).map_err(|refusal| refusal.code)
}

pub(super) fn state_row(
    key: agenc_ircd_storage::StoredKey,
    kind: u16,
    body: Vec<u8>,
) -> Result<crate::state_core::durable::AccountServiceDurableWrite, Refusal> {
    let encoded = agenc_ircd_storage::PersistentRecordValue::new(
        TableId::E2eeState,
        kind,
        1,
        0,
        None,
        Vec::new(),
        body,
    )
    .and_then(|value| value.encode())
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    crate::state_core::durable::AccountServiceDurableWrite::put(TableId::E2eeState, key, encoded)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}
