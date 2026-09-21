//! Cross-check both durable stream owners before making a restored gate live.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, PersistentRecordValue, StoredKey, TableId, Violation};
use agenc_relay_federation_wire::{DecodeBudget, EventHeader, SchemaObject};
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    BARRIER_PREFIX, DeliveryBarrier, parse_barrier_key,
};
use agenc_relay_types::ServerId;

pub(super) fn admit(
    coordinator: &mut FederationCoordinator,
    key: &StoredKey,
    value: &PersistentRecordValue,
) -> Result<(), Violation> {
    if key.as_bytes().starts_with(BARRIER_PREFIX) {
        let peer = ServerId::from_bytes(parse_barrier_key(key).map_err(|_| Violation::Codec)?);
        if !coordinator.peers.contains_key(&peer) || coordinator.companion_exec.is_none() {
            return Err(Violation::Codec);
        }
    }
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        executor.admit_restored(TableId::E2eeState, key, value);
    }
    Ok(())
}

pub(super) fn validate_event(
    gate: &DeliveryBarrier,
    bytes: &[u8],
    covered: bool,
) -> Result<(), Violation> {
    let mut budget = DecodeBudget::new(1 << 20, 4_096);
    let object = SchemaObject::decode_exact("FederationEvent", bytes, &mut budget)
        .map_err(|_| Violation::Codec)?;
    let header = EventHeader::from_object(&object).map_err(|_| Violation::Codec)?;
    let endpoint = gate.base();
    let sequence = header.delivery_sequence;
    if header.network_id.as_bytes() != &gate.scope().network_id()
        || header.target_server_id.as_bytes() != &gate.scope().target_server_id()
        || header.projection_generation != endpoint.generation()
    {
        return Err(Violation::Codec);
    }
    if sequence < endpoint.first() || sequence > endpoint.last() {
        return if header.cross_profile.is_none()
            || covered
                && header
                    .cross_profile
                    .is_some_and(|part| part.mutation_id != gate.mutation_id())
        {
            Ok(())
        } else {
            Err(Violation::Codec)
        };
    }
    validate_part(gate, &header, covered)
}

fn validate_part(
    gate: &DeliveryBarrier,
    header: &EventHeader,
    covered: bool,
) -> Result<(), Violation> {
    let endpoint = gate.base();
    let sequence = header.delivery_sequence;
    let part = header.cross_profile.ok_or(Violation::Codec)?;
    if part.mutation_id != gate.mutation_id()
        || part.part_count != gate.part_count()
        || u64::from(part.part_index)
            != sequence
                .checked_sub(endpoint.first())
                .ok_or(Violation::Codec)?
        || header.coordinator_state_generation != gate.state_generation()
        || covered != gate.base_acked()
        || sequence == endpoint.last() && header.event_id.as_bytes() != &endpoint.final_event_id()
    {
        return Err(Violation::Codec);
    }
    Ok(())
}

pub(super) fn finish(coordinator: &mut FederationCoordinator) -> Result<(), Violation> {
    let Some(executor) = coordinator.companion_exec.as_ref() else {
        return Ok(());
    };
    for (peer, gate) in &executor.state.restored_barriers {
        let state = coordinator.peers.get(peer).ok_or(Violation::Codec)?;
        let stream = executor.state.streams.get(peer).ok_or(Violation::Codec)?;
        let owner = stream.owner.as_ref().ok_or(Violation::Codec)?;
        gate.validate_for(owner, state.projection_generation)
            .map_err(|_| Violation::Codec)?;
        if state.incarnation.map(|id| *id.as_bytes()) != Some(gate.scope().target_incarnation())
            || state.client_resync_epoch != gate.scope().covered_base_client_resync_epoch()
            || state.outbox.snapshot_required
            || state.fence_pending
            || state.quarantined
            || gate.base().last() >= state.outbox.reserved_next
            || !matches!(
                state.phase,
                agenc_relay_storage::federation_records::PeerPhase::Ready
                    | agenc_relay_storage::federation_records::PeerPhase::Suspended
            )
        {
            return Err(Violation::Codec);
        }
        validate_base(state, gate)?;
    }
    if let Some(executor) = coordinator.companion_exec.as_mut() {
        coordinator.barriers = std::mem::take(&mut executor.state.restored_barriers);
    }
    Ok(())
}

fn validate_base(state: &super::super::PeerState, gate: &DeliveryBarrier) -> Result<(), Violation> {
    let endpoint = gate.base();
    let covered = match state.outbox.cursor {
        Some((sequence, id)) if sequence >= endpoint.first() => {
            if sequence != endpoint.last() || id.as_bytes() != &endpoint.final_event_id() {
                return Err(Violation::Codec);
            }
            true
        }
        _ => false,
    };
    if covered != gate.base_acked() {
        return Err(Violation::Codec);
    }
    if covered {
        return Ok(());
    }
    validate_window(state, gate)
}

fn validate_window(
    state: &super::super::PeerState,
    gate: &DeliveryBarrier,
) -> Result<(), Violation> {
    let endpoint = gate.base();
    let mut next = endpoint.first();
    for (sequence, id, _) in state
        .outbox
        .unacked
        .iter()
        .filter(|(seq, _, _)| *seq >= endpoint.first() && *seq <= endpoint.last())
    {
        if *sequence != next
            || *sequence == endpoint.last() && id.as_bytes() != &endpoint.final_event_id()
        {
            return Err(Violation::Codec);
        }
        next = next.checked_add(1).ok_or(Violation::Codec)?;
    }
    if endpoint.last().checked_add(1) != Some(next) {
        return Err(Violation::Codec);
    }
    Ok(())
}
