//! Rebuilds companion edge authority only from validated committed rows.

use agenc_relay_e2ee::federation::frames::DeliveryPosition;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationEvent, ArcFederationRouteState};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_storage::e2ee_records::barrier::{BarrierPart, CrossProfileStream};
use agenc_relay_storage::e2ee_records::{DeliveryRow, RouteRow, SnapshotMarkerRow};
use agenc_relay_storage::{StorageError, StoredKey};

use super::{E2eeEdge, events::OpenEvent};
use crate::RuntimeError;
use crate::federation::edge::EdgeFederation;

fn invalid() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

impl E2eeEdge {
    pub(crate) fn needs_witness_snapshot(&self) -> bool {
        self.witness_snapshot_required
    }

    pub(super) fn resume_delivery(&self) -> super::sync::DeliveryState {
        if self.witness_snapshot_required {
            super::sync::DeliveryState::default()
        } else {
            self.delivery
        }
    }

    pub(crate) fn retention_blocked(&self) -> bool {
        !self.pending.is_empty()
            || self.commit.is_some()
            || self.barrier_pending.is_some()
            || self.witness_pending()
            || self.witness_recovery_pending()
    }

    pub(crate) fn restore_delivery(&mut self, row: &DeliveryRow) -> Result<(), RuntimeError> {
        let DeliveryRow::WitnessedCursor {
            generation,
            next_sequence,
            acked_sequence,
            acked_event_id,
            ..
        } = row;
        if (*next_sequence == 0 && (*acked_sequence != 0 || *acked_event_id != [0; 16]))
            || (*next_sequence > 0 && acked_sequence.checked_add(1) != Some(*next_sequence))
        {
            return Err(invalid());
        }
        self.witness_snapshot_required = false;
        self.delivery = super::sync::DeliveryState {
            generation: *generation,
            cursor: (*next_sequence > 0).then_some((*acked_sequence, *acked_event_id)),
        };
        Ok(())
    }

    pub(crate) fn restore_base_cursor(&self, edge: &mut EdgeFederation) {
        edge.note_companion_delivery(self.delivery.generation, self.delivery.cursor);
    }

    pub(crate) fn restore_route(
        &mut self,
        key: &StoredKey,
        row: &RouteRow,
    ) -> Result<(), RuntimeError> {
        let mut budget = DecodeBudget::new(1 << 16, 4096);
        let object = ArcWireObject::decode_kind(
            &row.route_state,
            Some(ArcWireObjectKind::FederationState),
            &mut budget,
        )
        .map_err(|_| invalid())?;
        let state = ArcFederationRouteState::decode_exact(object.body(), &mut budget)
            .map_err(|_| invalid())?;
        if RouteRow::parse_key(key)? != state.conversation_id
            || row.binding_id != state.binding_id
            || row.lock_id != state.semantic_route_lock_id
            || row.accepted_state_id != state.accepted_state_id
        {
            return Err(invalid());
        }
        if !self.restore_route_admitted(&state.conversation_id) {
            return Ok(());
        }
        self.route_changed(&row.route_state)
            .map_err(|_| invalid())?;
        let known = self
            .conversations
            .get_mut(&state.conversation_id)
            .ok_or_else(invalid)?;
        let head = super::events::ChainHead {
            sequence: row.route_sequence,
            record_id: row.sequencer_head_id,
            recorded: !(row.route_sequence == 0
                && row.sequencer_head_id == state.accepted_state_id),
        };
        if !known.head.accepts_cut(head) {
            return Err(invalid());
        }
        known.head = head;
        Ok(())
    }

    pub(crate) fn restore_part(
        &mut self,
        part: &BarrierPart,
        payload: Option<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        let mut budget = DecodeBudget::new(1 << 16, 4096);
        let object = ArcWireObject::decode_kind(
            &part.encoded_event_object,
            Some(ArcWireObjectKind::FederationEvent),
            &mut budget,
        )
        .map_err(|_| invalid())?;
        let event =
            ArcFederationEvent::decode_exact(object.body(), &mut budget).map_err(|_| invalid())?;
        let payload_id: Option<[u8; 32]> = event.payload_object_id.as_slice().try_into().ok();
        if !valid_part_header(&self.config, part, &event)
            || !valid_part_tuple(part, &event)
            || payload_id != part.payload_object_id
            || payload
                .as_ref()
                .map(|bytes| *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes())
                != payload_id
        {
            return Err(invalid());
        }
        let open = OpenEvent {
            position: DeliveryPosition {
                server_id: *self.config.server_id.as_bytes(),
                delivery_generation: part.delivery_generation,
                delivery_sequence: part.delivery_sequence,
                event_id: part.event_id,
            },
            event,
            payload_object_id: payload_id,
        };
        self.barrier_parts
            .entry(part.identity.mutation_id)
            .or_default()
            .insert(part.part_index, (open, payload));
        Ok(())
    }
}

fn valid_part_header(
    config: &super::E2eeEdgeConfig,
    part: &BarrierPart,
    event: &ArcFederationEvent,
) -> bool {
    part.stream == CrossProfileStream::Companion
        && event.network_id == config.network_id
        && event.target_server_id == *config.server_id.as_bytes()
        && event.delivery_generation == part.delivery_generation
        && event.delivery_sequence == part.delivery_sequence
        && event.event_id == part.event_id
        && agenc_relay_e2ee::ObjectId::compute(&part.encoded_event_object).as_bytes()
            == &part.event_object_id
}

fn valid_part_tuple(part: &BarrierPart, event: &ArcFederationEvent) -> bool {
    event.coordinator_state_generation == part.identity.coordinator_state_generation
        && event.cross_profile_mutation_id.as_slice() == part.identity.mutation_id
        && event.cross_profile_part_index == part.part_index
        && event.cross_profile_part_count == part.identity.part_count
}

impl E2eeEdge {
    /// The durable snapshot marker of this edge's coordinator.
    pub(crate) fn restore_snapshot_marker(
        &mut self,
        key: &StoredKey,
        row: &SnapshotMarkerRow,
    ) -> Result<(), RuntimeError> {
        if SnapshotMarkerRow::parse_key(key)? != *self.config.coordinator_server_id.as_bytes()
            || self.snapshot.is_some()
        {
            return Err(invalid());
        }
        self.snapshot = Some(super::snapshot::SnapshotInstall::restored(row));
        Ok(())
    }

    /// One pending route row: part of the READY generation's projection,
    /// still to migrate for an ACTIVE generation, or an abandoned row.
    pub(crate) fn restore_pending_route(
        &mut self,
        key: &StoredKey,
        row: &RouteRow,
    ) -> Result<(), RuntimeError> {
        let (generation, conversation) =
            agenc_relay_storage::e2ee_records::PendingRouteRow::parse_key(key)?;
        let matches = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.delivery_generation == generation);
        if !matches {
            self.snapshot_stray_row(generation, conversation);
            return Ok(());
        }
        let (state, entry, conversation_facts) =
            super::events::decode_route_state(&row.route_state).map_err(|_| invalid())?;
        if state.conversation_id != conversation || state.network_id != self.config.network_id {
            return Err(invalid());
        }
        self.snapshot_restore_entry(conversation, entry, conversation_facts, &row.route_state)
    }

    /// Whether an active route row is authoritative beside the restored
    /// snapshot generation: a migrating generation owns every conversation
    /// beyond its migration cursor through its pending rows.
    fn restore_route_admitted(&mut self, conversation: &[u8; 32]) -> bool {
        self.snapshot_admits_active_row(conversation)
    }

    /// After the scan: a generation that was still being received is
    /// abandoned, and a READY generation must be complete.
    ///
    /// The only refusal is an incomplete READY generation, which is a fact
    /// about the restored rows and not about the storage layer, so it is
    /// recorded in `cause` instead of being discarded.
    pub(crate) fn finish_snapshot_restore(
        &mut self,
        cause: &mut crate::federation::edge::EdgeRestoreCause,
    ) -> Result<(), RuntimeError> {
        self.snapshot_finish_restore().map_err(|_| {
            *cause = crate::federation::edge::EdgeRestoreCause::CompanionSnapshotIncomplete;
            invalid()
        })
    }
}
