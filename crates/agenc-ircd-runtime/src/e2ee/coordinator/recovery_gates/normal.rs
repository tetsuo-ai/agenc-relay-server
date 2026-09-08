//! Live declarations are prepared with the route and retained only after its receipt.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::ops::{Exec, Fail};
use crate::e2ee::coordinator::request::{Outcome, state_row};
use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode as Code;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{ROUTE_ROW_KIND, prefix};

pub(in crate::e2ee::coordinator) fn prepare(
    exec: &Exec<'_>,
    outcome: &mut Outcome,
) -> Result<(), Fail> {
    let mut pending = Gates::default();
    // The last write owns the resulting route when a handler revises it twice.
    for write in outcome.writes.iter().rev() {
        let Some((TableId::E2eeState, key, encoded)) = write.encoded_record() else {
            continue;
        };
        if !key.as_bytes().starts_with(prefix::ROUTE) {
            continue;
        }
        let id = RouteRow::parse_key(key).map_err(|_| Code::InvalidFragment)?;
        if pending.rows.contains_key(&id) {
            continue;
        }
        prepare_route(exec, id, encoded, &mut pending)?;
    }
    for (id, owned) in &pending.rows {
        outcome.writes.push(state_row(
            TableId::E2eeState,
            RECOVERY_GATE_KIND,
            recovery_gate_key(id).map_err(|_| Code::InvalidFragment)?,
            owned.row.encode().map_err(|_| Code::InvalidFragment)?,
        )?);
    }
    if !pending.rows.is_empty() {
        outcome.effects.push(Box::new(move |state| {
            state.recovery_gates.rows.extend(pending.rows);
        }));
    }
    Ok(())
}

fn prepare_route(
    exec: &Exec<'_>,
    id: [u8; 32],
    encoded: &[u8],
    pending: &mut Gates,
) -> Result<(), Fail> {
    // Wrapper decode and RouteRow decode both copy bounded body storage.
    let bytes = encoded
        .len()
        .checked_mul(4)
        .and_then(|size| size.checked_add(8192))
        .ok_or(Code::RateLimited)?;
    let _temporary = exec.backing.reserve(bytes).map_err(|_| Code::RateLimited)?;
    let value = PersistentRecordValue::decode(TableId::E2eeState, encoded)
        .map_err(|_| Code::InvalidFragment)?;
    if value.record_kind() != ROUTE_ROW_KIND {
        return Err(Code::InvalidFragment.into());
    }
    let route = RouteRow::decode(value.body()).map_err(|_| Code::InvalidFragment)?;
    let epoch = exec
        .coordinator
        .delivery_identity
        .as_ref()
        .map(|identity| identity.recovery_epoch())
        .ok_or(Code::RouteInvalid)?;
    if route.recovery_gate
        || exec
            .coordinator
            .state
            .routes
            .route(&ConversationId(id))
            .is_some_and(|entry| entry.recovery != RecoveryState::Normal)
    {
        return Err(Code::RouteInvalid.into());
    }
    if let Some(existing) = exec.coordinator.state.recovery_gates.get(&id) {
        if existing.state() != E2eeRecoveryKind::Normal || existing.recovery_epoch() != epoch {
            return Err(Code::RouteInvalid.into());
        }
        return Ok(());
    }
    let permit = exec.backing.reserve(4096).map_err(|_| Code::RateLimited)?;
    let row = E2eeRecoveryGate::new(
        StorageDigest::from_bytes(id),
        E2eeRecoveryKind::Normal,
        epoch,
        StorageDigest::from_bytes(route.binding_id),
        StorageDigest::from_bytes(route.accepted_state_id),
        StorageDigest::from_bytes(route.sequencer_head_id),
        StorageDigest::from_bytes([0; 32]),
    );
    pending.rows.insert(
        id,
        Owned {
            row,
            _backing: permit,
        },
    );
    Ok(())
}
