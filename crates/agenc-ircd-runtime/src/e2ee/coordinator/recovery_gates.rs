//! Declared recovery provenance is checked before route reconstruction and remains owned afterward.
#![forbid(unsafe_code)]
use super::{CompanionFault, CompanionState};
use crate::budget::{BackingReservationPort, MemoryPermit};
use agenc_ircd_domain::e2ee::lifecycle::{Lifecycle, RecoveryGate};
use agenc_ircd_domain::e2ee::{ConversationId, RecoveryState};
use agenc_ircd_storage::e2ee_records::{
    RECOVERY_GATE_KIND, RouteLifecycle, RouteRow, recovery_gate_key,
};
use agenc_ircd_storage::{E2eeRecoveryGate, E2eeRecoveryKind, PersistentRecordValue, StoredKey};
use agenc_ircd_types::RecoveryEpoch;
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "tests/recovery_gate_validation.rs"]
mod tests;

struct Owned {
    row: E2eeRecoveryGate,
    _backing: MemoryPermit,
}

#[derive(Default)]
pub(crate) struct Gates {
    rows: BTreeMap<[u8; 32], Owned>,
}

impl Gates {
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
        backing: &BackingReservationPort,
    ) -> Result<(), CompanionFault> {
        if value.record_kind() != RECOVERY_GATE_KIND {
            return Err(CompanionFault::Storage);
        }
        let row = E2eeRecoveryGate::decode(value.body()).map_err(|_| CompanionFault::Storage)?;
        let id = *row.conversation_id().as_bytes();
        if recovery_gate_key(&id).map_err(|_| CompanionFault::Storage)? != *key {
            return Err(CompanionFault::Storage);
        }
        // Covers a complete new BTree node before insertion, including replacement overlap.
        let permit = backing.reserve(4096).map_err(|_| CompanionFault::Ceiling)?;
        self.rows.insert(
            id,
            Owned {
                row,
                _backing: permit,
            },
        );
        Ok(())
    }

    pub(super) fn validate(
        &self,
        routes: &BTreeMap<[u8; 32], RouteRow>,
        epoch: Option<RecoveryEpoch>,
    ) -> Result<(), CompanionFault> {
        for (id, owned) in &self.rows {
            let route = routes.get(id).ok_or(CompanionFault::Storage)?;
            validate_row(owned.row, route, epoch)?;
        }
        Ok(())
    }

    pub(crate) fn get(&self, id: &[u8; 32]) -> Option<E2eeRecoveryGate> {
        self.rows.get(id).map(|owned| owned.row)
    }

    pub(super) fn install(self, state: &mut CompanionState) -> Result<(), CompanionFault> {
        if self.rows.is_empty() {
            return Ok(());
        }
        if !state.recovery_gates.rows.is_empty() {
            return Err(CompanionFault::Storage);
        }
        // Check every reconstructed owner before changing any of its guards.
        for id in self.rows.keys() {
            if state.routes.route(&ConversationId(*id)).is_none()
                || !state.lifecycles.contains_key(id)
                || !state.logs.contains_key(id)
                || !state.conversations.contains_key(id)
            {
                return Err(CompanionFault::Storage);
            }
            let row = self.get(id).ok_or(CompanionFault::Storage)?;
            let current = state.lifecycles.get(id).ok_or(CompanionFault::Storage)?;
            restored_lifecycle(current, states(row.state()).1)?;
        }
        for id in self.rows.keys() {
            let row = self.get(id).ok_or(CompanionFault::Storage)?;
            let (route_gate, lifecycle_gate) = states(row.state());
            let mut route = *state
                .routes
                .route(&ConversationId(*id))
                .ok_or(CompanionFault::Storage)?;
            route.recovery = route_gate;
            state.routes.restore_entry(route);
            let current = state.lifecycles.get(id).ok_or(CompanionFault::Storage)?;
            let lifecycle = restored_lifecycle(current, lifecycle_gate)?;
            state.lifecycles.insert(*id, lifecycle);
        }
        state.recovery_gates = self;
        Ok(())
    }
}

fn restored_lifecycle(
    current: &Lifecycle,
    gate: RecoveryGate,
) -> Result<Lifecycle, CompanionFault> {
    let mut next = current.clone();
    if next.gate() == gate {
        return Ok(next);
    }
    if next.gate() == RecoveryGate::Normal {
        next.restore_pending()
            .map_err(|_| CompanionFault::Storage)?;
    }
    if gate != RecoveryGate::Pending {
        next.resolve_recovery(gate)
            .map_err(|_| CompanionFault::Storage)?;
    }
    if next.gate() != gate {
        return Err(CompanionFault::Storage);
    }
    Ok(next)
}

fn validate_row(
    gate: E2eeRecoveryGate,
    route: &RouteRow,
    epoch: Option<RecoveryEpoch>,
) -> Result<(), CompanionFault> {
    match gate.state() {
        E2eeRecoveryKind::Normal => {
            if epoch != Some(gate.recovery_epoch()) || route.recovery_gate {
                return Err(CompanionFault::Storage);
            }
        }
        E2eeRecoveryKind::Pending => {
            if epoch != Some(gate.recovery_epoch())
                || !matches_restored_heads(gate, route)
                || !route.recovery_gate
            {
                return Err(CompanionFault::Storage);
            }
        }
        // Terminal declarations preserve their original source epoch and heads across restore.
        // They can only retain blocked state; this does not validate or ingest a new terminal chain.
        E2eeRecoveryKind::Closed => {
            if route.lifecycle != RouteLifecycle::Tombstone || route.close_id.is_none() {
                return Err(CompanionFault::Storage);
            }
        }
        E2eeRecoveryKind::Conflict => {}
    }
    Ok(())
}

fn matches_restored_heads(gate: E2eeRecoveryGate, route: &RouteRow) -> bool {
    gate.restored_binding_id().as_bytes() == &route.binding_id
        && gate.restored_accepted_state_id().as_bytes() == &route.accepted_state_id
        && gate.restored_sequencer_head_id().as_bytes() == &route.sequencer_head_id
}

fn states(kind: E2eeRecoveryKind) -> (RecoveryState, RecoveryGate) {
    match kind {
        E2eeRecoveryKind::Normal => (RecoveryState::Normal, RecoveryGate::Normal),
        E2eeRecoveryKind::Pending => (RecoveryState::Pending, RecoveryGate::Pending),
        E2eeRecoveryKind::Closed => (RecoveryState::Closed, RecoveryGate::Closed),
        E2eeRecoveryKind::Conflict => (RecoveryState::Conflict, RecoveryGate::Conflict),
    }
}
