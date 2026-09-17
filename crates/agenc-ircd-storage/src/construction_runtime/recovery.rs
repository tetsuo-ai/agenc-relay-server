//! Typed companion selection and body transformation for declared recovery.
#![forbid(unsafe_code)]

use agenc_ircd_crypto::StorageDigest;
use agenc_ircd_e2ee::limits::MAX_FEDERATION_CONTROL_OBJECT;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationRouteState;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_types::RecoveryEpoch;

use crate::e2ee_records::barrier::{BarrierHead, BarrierPart};
use crate::e2ee_records::origin::OriginSequenceRow;
use crate::e2ee_records::{
    BARRIER_ROW_KIND, DELIVERY_RECOVERY_ROW_KIND, DELIVERY_ROW_KIND, DeliveryRow, OWNER_ROW_KIND,
    ObjectOwnerRow, RECOVERY_GATE_KIND, REPLAY_ROW_KIND, ROUTE_ROW_KIND, ReplayRow, RouteLifecycle,
    RouteRow, UNDATED_SECOND, check_state_key, prefix, record_kind_for_key,
};
use crate::{
    PersistentRecordValue, RecordReference, StorageConstructionAction, StorageError, StoredKey,
    TableId,
};

pub(super) fn select_e2ee_restore(
    key: &StoredKey,
    plaintext: &[u8],
) -> Result<Option<StorageConstructionAction>, StorageError> {
    let state = decode_e2ee_restore(key, plaintext)?;
    match state.record_kind() {
        REPLAY_ROW_KIND => validate_replay_key(key, state.body())?,
        DELIVERY_ROW_KIND => validate_delivery_key(key, state.body())?,
        BARRIER_ROW_KIND => validate_barrier_key(key, state.body())?,
        DELIVERY_RECOVERY_ROW_KIND => {
            crate::e2ee_records::delivery_recovery::validate_at(key, state.body())?;
        }
        _ => return Ok(Some(StorageConstructionAction::RestoreE2eeState)),
    }
    Ok(None)
}

pub(super) fn decode_e2ee_restore(
    key: &StoredKey,
    plaintext: &[u8],
) -> Result<PersistentRecordValue, StorageError> {
    let state = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
    check_state_key(key, state.record_kind())?;
    match state.record_kind() {
        ROUTE_ROW_KIND => validate_route_key(key, state.body())?,
        RECOVERY_GATE_KIND => {
            let gate = crate::E2eeRecoveryGate::decode(state.body())?;
            let expected =
                crate::e2ee_records::recovery_gate_key(gate.conversation_id().as_bytes())?;
            if expected != *key {
                return Err(StorageError::StaleState);
            }
        }
        crate::e2ee_records::MAILBOX_SEQUENCE_ROW_KIND => {
            crate::e2ee_records::MailboxSequenceRow::decode_keyed(key, state.body())?;
        }
        crate::e2ee_records::MAILBOX_ROW_KIND => validate_mailbox_key(key, state.body())?,
        _ => {}
    }
    Ok(state)
}

fn validate_mailbox_key(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    use crate::e2ee_records::MailboxRow;

    match MailboxRow::decode(body)? {
        MailboxRow::Item { .. } => MailboxRow::parse_item_key(key).map(|_| ()),
        MailboxRow::Token { .. } => MailboxRow::parse_token_key(key).map(|_| ()),
        MailboxRow::Ack { .. } => MailboxRow::parse_ack_key(key).map(|_| ()),
    }
}

fn validate_route_key(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    let conversation = RouteRow::parse_key(key)?;
    let route = RouteRow::decode(body)?;
    let mut budget = DecodeBudget::new(MAX_FEDERATION_CONTROL_OBJECT, 64);
    let object = IrcWireObject::decode_kind(
        &route.route_state,
        Some(IrcWireObjectKind::FederationState),
        &mut budget,
    )
    .map_err(|_| StorageError::InvalidEncoding)?;
    let state = IrcFederationRouteState::decode_exact(object.body(), &mut budget)
        .map_err(|_| StorageError::InvalidEncoding)?;
    if conversation != state.conversation_id {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

fn validate_replay_key(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    if key.as_bytes().starts_with(prefix::REPLAY) {
        ReplayRow::decode(body)?;
        ReplayRow::parse_key(key)?;
    } else {
        OriginSequenceRow::decode(body)?;
        OriginSequenceRow::parse_key(key)?;
    }
    Ok(())
}

fn validate_delivery_key(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    DeliveryRow::decode(body)?;
    DeliveryRow::parse_cursor_key(key)?;
    Ok(())
}

fn validate_barrier_key(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    let expected = if key.as_bytes().starts_with(prefix::BARRIER_HEAD) {
        BarrierHead::decode(body)?.identity().head_key()?
    } else {
        let part = BarrierPart::decode(body)?;
        part.identity.part_key(part.part_index)?
    };
    if expected == *key {
        Ok(())
    } else {
        Err(StorageError::StaleState)
    }
}

/// Whether a restore carries the row a reference names: replay, delivery,
/// barrier and delivery-recovery state is not restored, so references to
/// those rows are dropped with them.
fn restored_reference(reference: &RecordReference) -> bool {
    reference.table() != TableId::E2eeState
        || !matches!(
            record_kind_for_key(reference.key()),
            Ok(REPLAY_ROW_KIND | DELIVERY_ROW_KIND | BARRIER_ROW_KIND | DELIVERY_RECOVERY_ROW_KIND)
        )
}

/// The references of a restored state row: those naming rows the restore
/// carries.
pub(super) fn e2ee_restore_references(state: &PersistentRecordValue) -> Vec<RecordReference> {
    state
        .references()
        .iter()
        .filter(|reference| restored_reference(reference))
        .cloned()
        .collect()
}

pub(super) fn e2ee_recovery_body(
    state: &PersistentRecordValue,
    target_recovery_epoch: RecoveryEpoch,
    source_rollback_guard_hash: StorageDigest,
    references: &[RecordReference],
) -> Result<Vec<u8>, StorageError> {
    match state.record_kind() {
        // An ownership account whose every owner the restore dropped is
        // retired at an undated second: the retirement is a fact of the
        // restore, its time is not.
        OWNER_ROW_KIND => {
            let mut row = ObjectOwnerRow::decode(state.body())?;
            if references.is_empty() && row.retired_at.is_none() {
                row.retired_at = Some(UNDATED_SECOND);
            }
            row.encode()
        }
        RECOVERY_GATE_KIND => crate::E2eeRecoveryGate::decode(state.body())?
            .recover(target_recovery_epoch, source_rollback_guard_hash)
            .encode(),
        ROUTE_ROW_KIND => {
            let mut route = RouteRow::decode(state.body())?;
            if route.lifecycle != RouteLifecycle::Tombstone {
                route.recovery_gate = true;
            }
            route.encode()
        }
        REPLAY_ROW_KIND | DELIVERY_ROW_KIND | BARRIER_ROW_KIND | DELIVERY_RECOVERY_ROW_KIND => {
            Err(StorageError::StaleState)
        }
        _ => Ok(state.body().to_vec()),
    }
}

#[cfg(test)]
#[path = "tests/owner_restore.rs"]
mod owner_restore_tests;
