//! Coordinator-side projection of every staged mutation into durable outbox
//! events and standing projection rows (spec 20.6, 20.8).
//!
//! The projector lives inside the state owner so that a mutation from a
//! local client, an administrator, or a federated request all produce their
//! edge events inside the same storage batch as the mutation. The router
//! that owns the links takes the encoded events after the commit.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_domain::federation::{
    CoordinatorProjection, MutationContext, MutationProjection, ProjectedEvent, ProjectionRecord,
};
use agenc_ircd_domain::{DomainState, MutationPlan};
use agenc_ircd_federation_wire::FederationHash32;
use agenc_ircd_federation_wire::{
    CanonicalEncode, CrossProfilePart, EventHeader, ProjectionEntryHeader, ProjectionPrimaryKey,
    RequestCorrelation, federation_object_id,
};
use agenc_ircd_storage::federation_records::{
    OUTBOX_EVENT_KIND, OutboxEventRecord, PROJECTION_ENTRY_KIND, ProjectionEntryRecord, outbox_key,
    projection_entry_key,
};
use agenc_ircd_storage::{PersistentRecordValue, StoredKey, TableId};
use agenc_ircd_types::{EntropySource, EventId, NetworkId, ServerId};

mod outbox;
pub(crate) use outbox::OutboxBudget;

use crate::RuntimeError;
use crate::federation::codec::events::event_arm_object;
use crate::federation::codec::projection::{projection_arm_object, projection_kind};
use crate::state_core::durable::{AccountServiceDurableWrite, DurableIndex};

/// One encoded event reserved in the outbox for a target edge.
pub struct OutboundEvent {
    /// The target edge.
    pub target: ServerId,
    /// The projection generation the event belongs to.
    pub projection_generation: u64,
    /// The delivery sequence within the generation.
    pub delivery_sequence: u64,
    /// The fresh event identity.
    pub event_id: EventId,
    /// The Section-20.4 object identity of the encoded event.
    pub object_id: FederationHash32,
    /// The complete canonical `FederationEvent` bytes.
    pub encoded: Vec<u8>,
}

/// The federated request one staged plan answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBinding {
    /// The requesting edge, which receives `request_completed`.
    pub home: ServerId,
    /// The correlation tuple the completion event carries.
    pub correlation: RequestCorrelation,
    /// The completion event identity the result names in advance.
    pub completion_event_id: EventId,
}

/// The per-edge delivery position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeDelivery {
    /// The active projection generation.
    pub projection_generation: u64,
    /// The next delivery sequence to reserve.
    pub next_delivery_sequence: u64,
}

/// The rows and events accumulated while projecting one plan.
struct ProjectedOutput {
    writes: Vec<AccountServiceDurableWrite>,
    events: Vec<OutboundEvent>,
    advances: BTreeMap<ServerId, u64>,
    revision: u64,
    state_generation: u64,
    fences: Vec<ServerId>,
}

/// The barrier tuple one target's base events carry (spec 20.8): every
/// base event of the plan for that edge takes the next index from zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossProfileAssignment {
    /// The per-target mutation identity.
    pub mutation_id: [u8; 16],
    /// Base plus companion parts.
    pub part_count: u16,
}

/// The delivery position one event is reserved at.
struct EventSlot {
    target: ServerId,
    projection_generation: u64,
    delivery_sequence: u64,
    state_generation: u64,
}

/// What one staged plan projected, held until its batch commits.
pub struct PendingProjection {
    fences: Vec<ServerId>,
    events: Vec<OutboundEvent>,
    projection: MutationProjection,
    advances: BTreeMap<ServerId, u64>,
}

/// The coordinator's standing projection plus outbox sequencing.
pub struct FederationProjector {
    network_id: NetworkId,
    server_id: ServerId,
    index: CoordinatorProjection,
    edges: BTreeMap<ServerId, EdgeDelivery>,
    snapshot_required: BTreeSet<ServerId>,
    outbox_budgets: BTreeMap<ServerId, OutboxBudget>,
    committed_fences: BTreeSet<ServerId>,
}

impl FederationProjector {
    /// Creates a projector for a coordinator with no known edges.
    #[must_use]
    pub fn new(network_id: NetworkId, server_id: ServerId) -> Self {
        Self {
            network_id,
            server_id,
            index: CoordinatorProjection::new(server_id),
            edges: BTreeMap::new(),
            snapshot_required: BTreeSet::new(),
            outbox_budgets: BTreeMap::new(),
            committed_fences: BTreeSet::new(),
        }
    }

    /// Declares or repositions one edge's delivery cursor.
    pub fn set_edge(&mut self, edge: ServerId, delivery: EdgeDelivery) {
        if self
            .edges
            .get(&edge)
            .is_none_or(|previous| previous.projection_generation != delivery.projection_generation)
        {
            self.snapshot_required.remove(&edge);
        }
        self.edges.insert(edge, delivery);
    }

    /// Fences ordinary delivery reservations until a successor snapshot opens.
    pub(crate) fn require_snapshot(&mut self, edge: ServerId) {
        self.snapshot_required.insert(edge);
    }

    /// Returns one edge's delivery position.
    #[must_use]
    pub fn edge(&self, edge: ServerId) -> Option<EdgeDelivery> {
        self.edges.get(&edge).copied()
    }

    /// Borrows the standing index.
    #[must_use]
    pub const fn index(&self) -> &CoordinatorProjection {
        &self.index
    }

    /// Returns the coordinator's own Server ID, which never receives events.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        self.server_id
    }

    /// Restores one standing entry read back from storage at startup.
    pub fn restore_key(&mut self, edge: ServerId, record: &ProjectionRecord) {
        self.index.restore_key(edge, record);
    }

    /// Replaces one edge's standing with a snapshot cut.
    pub fn install_edge(&mut self, edge: ServerId, records: &[ProjectionRecord]) {
        self.index.install_edge(edge, records);
    }

    /// Derives the events and rows one plan commits alongside its writes.
    /// Returns `None` when nothing projects, so callers can skip the batch.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=one projection pass takes the plan its mutation context binding entropy revision and the barrier assignments together
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn project(
        &self,
        domain: &DomainState,
        plan: &MutationPlan,
        mutation: &MutationContext,
        binding: Option<&RequestBinding>,
        entropy: &mut dyn EntropySource,
        row_revision: u64,
        cross_profile: &BTreeMap<ServerId, CrossProfileAssignment>,
        index: &DurableIndex,
    ) -> Result<Option<(Vec<AccountServiceDurableWrite>, PendingProjection)>, RuntimeError> {
        let mut projection = self
            .index
            .derive(domain, plan, mutation)
            .map_err(|_| RuntimeError::InvalidValue)?;
        crate::federation::codec::fill_projection_bindings(&self.network_id, &mut projection.edges);
        if let Some(binding) = binding {
            append_completion(
                &mut projection,
                binding.home,
                plan.resulting_revision().get(),
            );
        }
        if projection.edges.is_empty() {
            return Ok(None);
        }
        let mut output = ProjectedOutput {
            writes: Vec::new(),
            events: Vec::new(),
            advances: BTreeMap::new(),
            revision: row_revision,
            state_generation: plan.resulting_revision().get(),
            fences: Vec::new(),
        };
        for delta in &projection.edges {
            let Some(delivery) = self.edges.get(&delta.target) else {
                continue;
            };
            let assignment = cross_profile.get(&delta.target).copied();
            self.project_edge(
                delta,
                *delivery,
                binding,
                entropy,
                &mut output,
                assignment,
                index,
            )?;
        }
        Ok(Some((
            output.writes,
            PendingProjection {
                fences: output.fences,
                events: output.events,
                projection,
                advances: output.advances,
            },
        )))
    }

    /// The base event count and barrier-form encoded bytes per target the
    /// plan would project, without reserving anything (spec 20.8).
    pub(crate) fn preview(
        &self,
        domain: &DomainState,
        plan: &MutationPlan,
        mutation: &MutationContext,
    ) -> Result<BTreeMap<ServerId, (usize, u64)>, RuntimeError> {
        let mut projection = self
            .index
            .derive(domain, plan, mutation)
            .map_err(|_| RuntimeError::InvalidValue)?;
        crate::federation::codec::fill_projection_bindings(&self.network_id, &mut projection.edges);
        let mut counts = BTreeMap::new();
        let placeholder = CrossProfilePart {
            mutation_id: [0; 16],
            part_index: 0,
            part_count: 2,
        };
        for delta in &projection.edges {
            if delta.events.is_empty() || !self.edges.contains_key(&delta.target) {
                continue;
            }
            let mut bytes: u64 = 0;
            for event in &delta.events {
                let header = EventHeader {
                    network_id: self.network_id,
                    target_server_id: delta.target,
                    projection_generation: 0,
                    coordinator_state_generation: plan.resulting_revision().get(),
                    delivery_sequence: 0,
                    event_id: EventId::from_bytes([0; 16]),
                    event_kind: event.kind(),
                    correlation: None,
                    cross_profile: Some(placeholder),
                };
                let arm = event_arm_object(event).map_err(|_| RuntimeError::InvalidValue)?;
                let object = header.build(&arm).map_err(|_| RuntimeError::InvalidValue)?;
                let encoded = object
                    .encode_canonical()
                    .map_err(|_| RuntimeError::InvalidValue)?;
                bytes = bytes
                    .saturating_add(u64::try_from(encoded.as_slice().len()).unwrap_or(u64::MAX));
            }
            counts.insert(delta.target, (delta.events.len(), bytes));
        }
        Ok(counts)
    }

    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=one edge projection takes the delta its delivery binding entropy output and barrier assignment together
    #[allow(clippy::too_many_arguments)]
    fn project_edge(
        &self,
        delta: &agenc_ircd_domain::federation::EdgeDelta,
        delivery: EdgeDelivery,
        binding: Option<&RequestBinding>,
        entropy: &mut dyn EntropySource,
        output: &mut ProjectedOutput,
        assignment: Option<CrossProfileAssignment>,
        index: &DurableIndex,
    ) -> Result<(), RuntimeError> {
        let blocked = self.snapshot_required.contains(&delta.target);
        if blocked && assignment.is_some() {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut sequence = delivery.next_delivery_sequence;
        let mut reserved = Vec::new();
        for (index, event) in delta.events.iter().enumerate().filter(|_| !blocked) {
            let slot = EventSlot {
                target: delta.target,
                projection_generation: delivery.projection_generation,
                delivery_sequence: sequence,
                state_generation: output.state_generation,
            };
            let part = assignment
                .map(|assignment| {
                    u16::try_from(index)
                        .map(|part_index| CrossProfilePart {
                            mutation_id: assignment.mutation_id,
                            part_index,
                            part_count: assignment.part_count,
                        })
                        .map_err(|_| RuntimeError::Overflow)
                })
                .transpose()?;
            let outbound = self.encode_event(slot, event, binding, entropy, part)?;
            reserved.push(outbound);
            sequence = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
        }
        if !self.fit_outbox(delta.target, delivery, &reserved, assignment, output)? {
            reserved.clear();
            sequence = delivery.next_delivery_sequence;
        }
        for outbound in reserved {
            output.writes.push(outbox_write(
                &outbound,
                output.revision,
                output.state_generation,
                binding,
            )?);
            output.events.push(outbound);
        }
        output.advances.insert(delta.target, sequence);
        for record in &delta.upserts {
            output.writes.push(self.entry_write(
                delta.target,
                delivery.projection_generation,
                record,
                output.revision,
            )?);
        }
        for key in &delta.removals {
            let stored = projection_entry_key(
                delta.target,
                delivery.projection_generation,
                key.kind(),
                key.primary(),
            )?;
            // A snapshot cut installs the edge's standing under its new
            // generation before the cut rows are written (spec 20.9), and a
            // refused cut batch leaves keys standing with no row at all. A
            // key removed while its row does not exist needs no delete: the
            // standing drops it on commit and the cut skips it.
            if !index.holds(TableId::EdgeProjection, &stored) {
                continue;
            }
            output.writes.push(AccountServiceDurableWrite::delete(
                TableId::EdgeProjection,
                stored,
            )?);
        }
        Ok(())
    }

    fn encode_event(
        &self,
        slot: EventSlot,
        event: &ProjectedEvent,
        binding: Option<&RequestBinding>,
        entropy: &mut dyn EntropySource,
        cross_profile: Option<CrossProfilePart>,
    ) -> Result<OutboundEvent, RuntimeError> {
        let EventSlot {
            target,
            projection_generation,
            delivery_sequence: sequence,
            state_generation,
        } = slot;
        let completion = matches!(event, ProjectedEvent::RequestCompleted { .. });
        let bound = binding.filter(|binding| completion && binding.home == target);
        let event_id = match bound {
            Some(binding) => binding.completion_event_id,
            None => {
                let mut id = [0_u8; 16];
                entropy
                    .fill_exact(&mut id)
                    .map_err(|_| RuntimeError::InvalidValue)?;
                EventId::from_bytes(id)
            }
        };
        let header = EventHeader {
            network_id: self.network_id,
            target_server_id: target,
            projection_generation,
            coordinator_state_generation: state_generation,
            delivery_sequence: sequence,
            event_id,
            event_kind: event.kind(),
            correlation: bound.map(|binding| binding.correlation),
            cross_profile,
        };
        let arm = event_arm_object(event).map_err(|_| RuntimeError::InvalidValue)?;
        let object = header.build(&arm).map_err(|_| RuntimeError::InvalidValue)?;
        let encoded = object
            .encode_canonical()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let bytes = encoded.as_slice().to_vec();
        Ok(OutboundEvent {
            target,
            projection_generation,
            delivery_sequence: sequence,
            event_id,
            object_id: federation_object_id(&bytes),
            encoded: bytes,
        })
    }

    fn entry_write(
        &self,
        target: ServerId,
        projection_generation: u64,
        record: &ProjectionRecord,
        revision: u64,
    ) -> Result<AccountServiceDurableWrite, RuntimeError> {
        let kind = projection_kind(record);
        let arm = projection_arm_object(record).map_err(|_| RuntimeError::InvalidValue)?;
        let primary =
            ProjectionPrimaryKey::of(kind, &arm).map_err(|_| RuntimeError::InvalidValue)?;
        let entry = ProjectionEntryHeader {
            network_id: self.network_id,
            target_server_id: target,
            projection_generation,
            projection_kind: kind,
        }
        .build(&arm)
        .map_err(|_| RuntimeError::InvalidValue)?;
        let encoded = entry
            .encode_canonical()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let body = ProjectionEntryRecord {
            entry_object_id: *federation_object_id(encoded.as_slice()).as_bytes(),
            entry_object: encoded.as_slice().to_vec(),
        }
        .encode()?;
        let key = projection_entry_key(
            target,
            projection_generation,
            primary.kind(),
            primary.primary(),
        )?;
        row_write(
            TableId::EdgeProjection,
            PROJECTION_ENTRY_KIND,
            key,
            revision,
            projection_generation,
            body,
        )
    }

    /// Applies one committed projection and returns its events for delivery.
    pub fn committed(&mut self, pending: PendingProjection) -> Vec<OutboundEvent> {
        self.index.apply(&pending.projection);
        for peer in pending.fences {
            self.snapshot_required.insert(peer);
            self.committed_fences.insert(peer);
        }
        for (edge, next) in pending.advances {
            if let Some(delivery) = self.edges.get_mut(&edge) {
                delivery.next_delivery_sequence = next;
            }
        }
        pending.events
    }
}

impl PendingProjection {
    /// Returns the number of reserved events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

fn append_completion(projection: &mut MutationProjection, home: ServerId, generation: u64) {
    let event = ProjectedEvent::RequestCompleted {
        resulting_state_generation: generation,
    };
    if let Some(delta) = projection
        .edges
        .iter_mut()
        .find(|delta| delta.target == home)
    {
        delta.events.push(event);
        return;
    }
    projection
        .edges
        .push(agenc_ircd_domain::federation::EdgeDelta {
            target: home,
            events: vec![event],
            upserts: Vec::new(),
            removals: Vec::new(),
        });
    projection
        .edges
        .sort_by(|left, right| left.target.as_bytes().cmp(right.target.as_bytes()));
}

fn outbox_write(
    event: &OutboundEvent,
    revision: u64,
    state_generation: u64,
    binding: Option<&RequestBinding>,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let body = OutboxEventRecord {
        event_id: *event.event_id.as_bytes(),
        event_object_id: *event.object_id.as_bytes(),
        event_object: event.encoded.clone(),
        coordinator_state_generation: state_generation,
        acknowledged: false,
        completion_replay_key: binding
            .filter(|binding| {
                binding.home == event.target && binding.completion_event_id == event.event_id
            })
            .map(|binding| binding.correlation.replay_key.to_bytes()),
    }
    .encode()?;
    let key = outbox_key(
        event.target,
        event.projection_generation,
        event.delivery_sequence,
    )?;
    row_write(
        TableId::EdgeOutbox,
        OUTBOX_EVENT_KIND,
        key,
        revision,
        0,
        body,
    )
}

fn row_write(
    table: TableId,
    kind: u16,
    key: StoredKey,
    revision: u64,
    generation: u64,
    body: Vec<u8>,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let plaintext =
        PersistentRecordValue::new(table, kind, revision, generation, None, Vec::new(), body)?
            .encode()?;
    AccountServiceDurableWrite::put(table, key, plaintext)
}
