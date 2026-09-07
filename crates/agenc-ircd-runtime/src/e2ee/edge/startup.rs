//! Rebuilds companion edge authority only from validated committed rows.

use agenc_ircd_e2ee::federation::frames::DeliveryPosition;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{IrcFederationEvent, IrcFederationRouteState};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_storage::e2ee_records::barrier::{BarrierPart, CrossProfileStream};
use agenc_ircd_storage::e2ee_records::{DeliveryRow, RouteRow};
use agenc_ircd_storage::{StorageError, StoredKey};

use super::{E2eeEdge, events::OpenEvent};
use crate::RuntimeError;
use crate::federation::edge::EdgeFederation;

fn invalid() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

impl E2eeEdge {
    pub(crate) fn needs_witness_snapshot(&self) -> bool {
        self.legacy_cursor
    }

    pub(super) fn resume_delivery(&self) -> super::sync::DeliveryState {
        if self.legacy_cursor {
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
        let (DeliveryRow::Cursor {
            next_sequence,
            acked_sequence,
            acked_event_id,
            ..
        }
        | DeliveryRow::WitnessedCursor {
            next_sequence,
            acked_sequence,
            acked_event_id,
            ..
        }) = row
        else {
            return Err(invalid());
        };
        if (*next_sequence == 0 && (*acked_sequence != 0 || *acked_event_id != [0; 16]))
            || (*next_sequence > 0 && acked_sequence.checked_add(1) != Some(*next_sequence))
        {
            return Err(invalid());
        }
        self.legacy_cursor = matches!(row, DeliveryRow::Cursor { .. });
        self.restore_cursor(row);
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
        let object = IrcWireObject::decode_kind(
            &row.route_state,
            Some(IrcWireObjectKind::FederationState),
            &mut budget,
        )
        .map_err(|_| invalid())?;
        let state = IrcFederationRouteState::decode_exact(object.body(), &mut budget)
            .map_err(|_| invalid())?;
        if RouteRow::parse_key(key)? != state.conversation_id
            || row.binding_id != state.binding_id
            || row.lock_id != state.semantic_route_lock_id
            || row.accepted_state_id != state.accepted_state_id
        {
            return Err(invalid());
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
        let object = IrcWireObject::decode_kind(
            &part.encoded_event_object,
            Some(IrcWireObjectKind::FederationEvent),
            &mut budget,
        )
        .map_err(|_| invalid())?;
        let event =
            IrcFederationEvent::decode_exact(object.body(), &mut budget).map_err(|_| invalid())?;
        let payload_id: Option<[u8; 32]> = event.payload_object_id.as_slice().try_into().ok();
        if !valid_part_header(&self.config, part, &event)
            || !valid_part_tuple(part, &event)
            || payload_id != part.payload_object_id
            || payload
                .as_ref()
                .map(|bytes| *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes())
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
    event: &IrcFederationEvent,
) -> bool {
    part.stream == CrossProfileStream::Companion
        && event.network_id == config.network_id
        && event.target_server_id == *config.server_id.as_bytes()
        && event.delivery_generation == part.delivery_generation
        && event.delivery_sequence == part.delivery_sequence
        && event.event_id == part.event_id
        && agenc_ircd_e2ee::ObjectId::compute(&part.encoded_event_object).as_bytes()
            == &part.event_object_id
}

fn valid_part_tuple(part: &BarrierPart, event: &IrcFederationEvent) -> bool {
    event.coordinator_state_generation == part.identity.coordinator_state_generation
        && event.cross_profile_mutation_id.as_slice() == part.identity.mutation_id
        && event.cross_profile_part_index == part.part_index
        && event.cross_profile_part_count == part.identity.part_count
}
