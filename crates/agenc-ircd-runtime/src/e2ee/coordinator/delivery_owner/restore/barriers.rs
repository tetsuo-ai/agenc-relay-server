//! Rebuild a complete companion slice only under its exact durable gate.
#![forbid(unsafe_code)]

use super::{CompanionFault, DeliveryBarrier, DeliveryStream, IrcFederationEvent};

#[cfg(test)]
mod tests;

pub(super) fn validate_event(
    gate: Option<&DeliveryBarrier>,
    event: &IrcFederationEvent,
    acknowledged: bool,
) -> Result<(), CompanionFault> {
    let cross = super::cross_profile(event)?;
    let Some(gate) = gate else {
        return if cross.is_none() || acknowledged {
            Ok(())
        } else {
            Err(CompanionFault::Storage)
        };
    };
    let endpoint = gate.companion();
    let sequence = event.delivery_sequence;
    if sequence < endpoint.first() || sequence > endpoint.last() {
        return if cross.is_none()
            || acknowledged && cross.is_some_and(|part| part.mutation_id != gate.mutation_id())
        {
            Ok(())
        } else {
            Err(CompanionFault::Storage)
        };
    }
    let part = cross.ok_or(CompanionFault::Storage)?;
    validate_part(gate, event, part, acknowledged)
}

fn validate_part(
    gate: &DeliveryBarrier,
    event: &IrcFederationEvent,
    part: agenc_ircd_storage::e2ee_records::CrossProfileTuple,
    acknowledged: bool,
) -> Result<(), CompanionFault> {
    let endpoint = gate.companion();
    let sequence = event.delivery_sequence;
    let base_count = gate
        .base()
        .last()
        .checked_sub(gate.base().first())
        .and_then(|count| count.checked_add(1))
        .ok_or(CompanionFault::Storage)?;
    let index = sequence
        .checked_sub(endpoint.first())
        .and_then(|n| n.checked_add(base_count))
        .ok_or(CompanionFault::Storage)?;
    if event.delivery_generation != endpoint.generation()
        || event.coordinator_state_generation != gate.state_generation()
        || part.mutation_id != gate.mutation_id()
        || u64::from(part.part_index) != index
        || part.part_count != gate.part_count()
        || acknowledged != gate.companion_acked()
        || sequence == endpoint.last() && event.event_id != endpoint.final_event_id()
    {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

pub(super) fn validate_complete(
    stream: &DeliveryStream,
    gate: &DeliveryBarrier,
) -> Result<(), CompanionFault> {
    let endpoint = gate.companion();
    if gate.companion_acked() {
        return validate_acknowledged_inventory(stream, gate);
    }
    let mut next = endpoint.first();
    for row in stream
        .rows
        .iter()
        .filter(|row| row.sequence >= endpoint.first() && row.sequence <= endpoint.last())
    {
        if row.sequence != next {
            return Err(CompanionFault::Storage);
        }
        next = next.checked_add(1).ok_or(CompanionFault::Storage)?;
    }
    if endpoint.last().checked_add(1) != Some(next) {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}

fn validate_acknowledged_inventory(
    stream: &DeliveryStream,
    gate: &DeliveryBarrier,
) -> Result<(), CompanionFault> {
    let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
    let replay = stream.replay.ok_or(CompanionFault::Storage)?;
    gate.validate_for(owner, gate.base().generation())
        .map_err(|_| CompanionFault::Storage)?;
    super::super::retention::validate_previous(owner, Some(replay.owner))?;
    let endpoint = gate.companion();
    if stream.acked != Some((endpoint.last(), endpoint.final_event_id()))
        || replay.owner.fields().first_retained > endpoint.first()
    {
        return Err(CompanionFault::Storage);
    }
    // ReplayState is installed only after complete body validation or the exact ACK receipt.
    // A logical retention scan cannot cross an open barrier's first part.
    Ok(())
}

pub(super) fn validate_owners(
    gates: &std::collections::BTreeMap<agenc_ircd_types::ServerId, DeliveryBarrier>,
    owners: &std::collections::BTreeMap<agenc_ircd_types::ServerId, super::DeliveryOwner>,
) -> Result<(), CompanionFault> {
    for (peer, gate) in gates {
        let owner = owners.get(peer).ok_or(CompanionFault::Storage)?;
        gate.validate_for(owner, gate.base().generation())
            .map_err(|_| CompanionFault::Storage)?;
        if gate.base_acked() && gate.companion_acked() || owner.phase() != super::CutPhase::Ready {
            return Err(CompanionFault::Storage);
        }
    }
    Ok(())
}

pub(super) fn install(
    streams: &mut std::collections::BTreeMap<agenc_ircd_types::ServerId, DeliveryStream>,
    gates: &std::collections::BTreeMap<agenc_ircd_types::ServerId, DeliveryBarrier>,
) -> Result<(), CompanionFault> {
    for (peer, gate) in gates {
        let stream = streams.get_mut(peer).ok_or(CompanionFault::Storage)?;
        validate_complete(stream, gate)?;
        stream.hold_after = Some(gate.companion().last());
        stream.barrier = (!gate.companion_acked())
            .then_some((gate.companion().first(), gate.companion().last()));
    }
    Ok(())
}
