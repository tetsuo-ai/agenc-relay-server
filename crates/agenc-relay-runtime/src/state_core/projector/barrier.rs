//! The combined gate is prepared with both event endpoints in the mutation batch.
#![forbid(unsafe_code)]

use super::{CrossProfileAssignment, OutboundEvent};
use crate::RuntimeError;
use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_relay_storage::e2ee_records::DELIVERY_RECOVERY_ROW_KIND;
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields, DeliveryRecoveryRow,
};
use agenc_relay_storage::{PersistentRecordValue, TableId};
use agenc_relay_types::{NetworkId, ServerId};

pub(crate) fn attach(
    network: NetworkId,
    coordinator: ServerId,
    target: ServerId,
    assignment: &CrossProfileAssignment,
    state_generation: u64,
    events: &mut [OutboundEvent],
) -> Result<DeliveryBarrier, RuntimeError> {
    let scope = assignment.companion_scope;
    if scope.network_id() != *network.as_bytes()
        || scope.coordinator_server_id() != *coordinator.as_bytes()
        || scope.target_server_id() != *target.as_bytes()
    {
        return Err(RuntimeError::InvalidValue);
    }
    let mut first = None;
    let mut last: Option<(usize, u64, [u8; 16])> = None;
    for (index, event) in events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.target == target)
    {
        let (generation, start) =
            *first.get_or_insert((event.projection_generation, event.delivery_sequence));
        if event.projection_generation != generation || event.combined_barrier.is_some() {
            return Err(RuntimeError::InvalidValue);
        }
        if let Some((_, previous, _)) = last
            && previous.checked_add(1) != Some(event.delivery_sequence)
        {
            return Err(RuntimeError::InvalidValue);
        }
        if event.delivery_sequence < start {
            return Err(RuntimeError::InvalidValue);
        }
        last = Some((index, event.delivery_sequence, *event.event_id.as_bytes()));
    }
    let (generation, first) = first.ok_or(RuntimeError::InvalidValue)?;
    let (index, last, event_id) = last.ok_or(RuntimeError::InvalidValue)?;
    let record = DeliveryBarrier::new(DeliveryBarrierFields {
        scope,
        mutation_id: assignment.mutation_id,
        state_generation,
        part_count: assignment.part_count,
        base: BarrierEndpoint::new(generation, first, last, event_id)?,
        companion: assignment.companion,
        base_acked: false,
        companion_acked: false,
    })?;
    events
        .get_mut(index)
        .ok_or(RuntimeError::InvalidValue)?
        .combined_barrier = Some(Box::new(record.clone()));
    Ok(record)
}

pub(crate) fn write(
    record: &DeliveryBarrier,
    revision: u64,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let row = DeliveryRecoveryRow::Barrier(record.clone());
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        DELIVERY_RECOVERY_ROW_KIND,
        revision,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    AccountServiceDurableWrite::put(TableId::E2eeState, row.key()?, value.encode()?)
}

pub(crate) fn delete(record: &DeliveryBarrier) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let row = DeliveryRecoveryRow::Barrier(record.clone());
    AccountServiceDurableWrite::delete(TableId::E2eeState, row.key()?)
}
