//! Recovery declarations derive authority from the paired authenticated route source.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee_records::{
    RECOVERY_GATE_KIND, ROUTE_ROW_KIND, RouteLifecycle, RouteRow, recovery_gate_key,
};
use crate::{E2eeRecoveryGate, E2eeRecoveryKind};

struct Sources<'a> {
    route_key: &'a StoredKey,
    route: PersistentRecordValue,
    gate: PersistentRecordValue,
}

pub(super) fn transform(
    entry: &StorageConstructionPlanEntry,
    sources: &[ConstructionSourceRecord],
    target_epoch: RecoveryEpoch,
    source_guard: StorageDigest,
) -> Result<Vec<u8>, StorageError> {
    let Sources {
        route_key,
        route: route_value,
        gate: gate_value,
    } = paired_sources(entry, sources)?;
    let conversation = RouteRow::parse_key(route_key)?;
    if entry.target_key() != &recovery_gate_key(&conversation)? {
        return Err(StorageError::StaleState);
    }
    let route = RouteRow::decode(route_value.body())?;
    let gate = E2eeRecoveryGate::decode(gate_value.body())?;
    if gate.conversation_id().as_bytes() != &conversation {
        return Err(StorageError::StaleState);
    }
    let restored = restore_gate(gate, &route, conversation, target_epoch, source_guard)?;
    PersistentRecordValue::new(
        TableId::E2eeState,
        RECOVERY_GATE_KIND,
        gate_value.revision(),
        gate_value.generation(),
        gate_value.expires_at(),
        gate_value.references().to_vec(),
        restored.encode()?,
    )?
    .encode()
}

fn paired_sources<'a>(
    entry: &StorageConstructionPlanEntry,
    sources: &'a [ConstructionSourceRecord],
) -> Result<Sources<'a>, StorageError> {
    if entry.target_table() != TableId::E2eeState
        || sources.len() != 2
        || sources.len() != entry.sources().len()
    {
        return Err(StorageError::StaleState);
    }
    let mut route = None;
    let mut gate = None;
    for (source, reference) in sources.iter().zip(entry.sources()) {
        let value = source_value(entry, source, reference)?;
        match value.record_kind() {
            ROUTE_ROW_KIND if route.is_none() => route = Some((source.key(), value)),
            RECOVERY_GATE_KIND if gate.is_none() => gate = Some(value),
            _ => return Err(StorageError::StaleState),
        }
    }
    let (key, value) = route.ok_or(StorageError::StaleState)?;
    Ok(Sources {
        route_key: key,
        route: value,
        gate: gate.ok_or(StorageError::StaleState)?,
    })
}

fn source_value(
    entry: &StorageConstructionPlanEntry,
    source: &ConstructionSourceRecord,
    reference: &StorageConstructionSource,
) -> Result<PersistentRecordValue, StorageError> {
    if reference.kind() != StorageConstructionSourceKind::BackupRecord
        || source.table() != TableId::E2eeState
        || source.table() != reference.table()
        || source.key() != reference.key()
        || source.record_schema() != reference.record_schema()
        || source.record_schema() != entry.target_record_schema()
    {
        return Err(StorageError::StaleState);
    }
    recovery::decode_e2ee_restore(source.key(), source.plaintext())
}

fn restore_gate(
    gate: E2eeRecoveryGate,
    route: &RouteRow,
    conversation: [u8; 32],
    target_epoch: RecoveryEpoch,
    source_guard: StorageDigest,
) -> Result<E2eeRecoveryGate, StorageError> {
    if gate.state() != E2eeRecoveryKind::Normal {
        return restore_declared(gate, route, target_epoch, source_guard);
    }
    if route.recovery_gate {
        return Err(StorageError::StaleState);
    }
    let state = if route.lifecycle == RouteLifecycle::Tombstone {
        if route.close_id.is_none() {
            return Err(StorageError::StaleState);
        }
        E2eeRecoveryKind::Closed
    } else {
        E2eeRecoveryKind::Pending
    };
    Ok(E2eeRecoveryGate::new(
        StorageDigest::from_bytes(conversation),
        state,
        target_epoch,
        StorageDigest::from_bytes(route.binding_id),
        StorageDigest::from_bytes(route.accepted_state_id),
        StorageDigest::from_bytes(route.sequencer_head_id),
        source_guard,
    ))
}

fn restore_declared(
    gate: E2eeRecoveryGate,
    route: &RouteRow,
    target_epoch: RecoveryEpoch,
    source_guard: StorageDigest,
) -> Result<E2eeRecoveryGate, StorageError> {
    match gate.state() {
        E2eeRecoveryKind::Closed => {
            if route.lifecycle != RouteLifecycle::Tombstone || route.close_id.is_none() {
                return Err(StorageError::StaleState);
            }
            Ok(gate)
        }
        E2eeRecoveryKind::Conflict => {
            if !route.recovery_gate {
                return Err(StorageError::StaleState);
            }
            Ok(gate)
        }
        E2eeRecoveryKind::Pending => {
            if !matches_pending_heads(gate, route) {
                return Err(StorageError::StaleState);
            }
            Ok(gate.recover(target_epoch, source_guard))
        }
        E2eeRecoveryKind::Normal => Err(StorageError::StaleState),
    }
}

fn matches_pending_heads(gate: E2eeRecoveryGate, route: &RouteRow) -> bool {
    route.recovery_gate
        && gate.restored_binding_id().as_bytes() == &route.binding_id
        && gate.restored_accepted_state_id().as_bytes() == &route.accepted_state_id
        && gate.restored_sequencer_head_id().as_bytes() == &route.sequencer_head_id
}
