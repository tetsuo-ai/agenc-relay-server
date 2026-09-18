//! Pair recovery declarations with route sources in the bounded scratch plan.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee_records::{RECOVERY_GATE_KIND, ROUTE_ROW_KIND, RouteRow, recovery_gate_key};

const GATES: TableDefinition<'static, &'static [u8], &'static [u8]> =
    TableDefinition::new("restore_recovery_gate_sources");
// A source has 44 encoded bytes and a fixed 43-byte recovery key. Reserve
// 128 bytes per pending index entry against the plan's existing byte limit.
const INDEX_ENTRY_BYTES: u64 = 128;

pub(super) fn pending_bytes(transaction: &redb::WriteTransaction) -> Result<u64, StorageError> {
    transaction
        .open_table(GATES)
        .map_err(|_| StorageError::DatabaseRejected)?
        .len()
        .map_err(|_| StorageError::DatabaseRejected)?
        .checked_mul(INDEX_ENTRY_BYTES)
        .ok_or(StorageError::Overflow)
}

pub(super) fn reset(transaction: &redb::WriteTransaction) -> Result<(), StorageError> {
    transaction
        .open_table(GATES)
        .map_err(|_| StorageError::DatabaseRejected)?
        .retain(|_, _| false)
        .map_err(|_| StorageError::DatabaseRejected)
}

pub(super) fn require_consumed(transaction: &redb::ReadTransaction) -> Result<(), StorageError> {
    let table = transaction
        .open_table(GATES)
        .map_err(|_| StorageError::DatabaseRejected)?;
    if !table
        .is_empty()
        .map_err(|_| StorageError::DatabaseRejected)?
    {
        return Err(StorageError::StaleState);
    }
    Ok(())
}

pub(super) fn push(
    builder: &mut ConstructionPlanBuilder,
    source: &StorageConstructionSource,
    record: &ConstructionSourceRecord,
) -> Result<bool, StorageError> {
    if builder.kind != StorageConstructionKind::Restore
        || source.kind() != StorageConstructionSourceKind::BackupRecord
        || source.table() != TableId::E2eeState
        || record.table() != source.table()
        || record.key() != source.key()
        || record.record_schema() != source.record_schema()
    {
        return Err(StorageError::StaleState);
    }
    let state = recovery::decode_e2ee_restore(source.key(), record.plaintext())?;
    match state.record_kind() {
        RECOVERY_GATE_KIND => index_gate(builder, source).map(|()| true),
        ROUTE_ROW_KIND => {
            RouteRow::decode(state.body())?;
            push_route(builder, source)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn index_gate(
    builder: &mut ConstructionPlanBuilder,
    source: &StorageConstructionSource,
) -> Result<(), StorageError> {
    builder.rotate_if_full()?;
    {
        let mut table = builder
            .slice()?
            .open_table(GATES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let charge = table
            .len()
            .map_err(|_| StorageError::DatabaseRejected)?
            .checked_add(1)
            .and_then(|count| count.checked_mul(INDEX_ENTRY_BYTES))
            .and_then(|bytes| bytes.checked_add(builder.encoded_bytes))
            .ok_or(StorageError::Overflow)?;
        if charge > builder.maximum_bytes {
            return Err(StorageError::LimitExceeded);
        }
        let mut encoded = [0; 44];
        let (schema, rest) = encoded.split_at_mut(4);
        let (id, offset) = rest.split_at_mut(32);
        schema.copy_from_slice(&source.record_schema().to_be_bytes());
        id.copy_from_slice(source.sealed_record_id().as_bytes());
        offset.copy_from_slice(&source.backup_byte_offset().to_be_bytes());
        if table
            .insert(source.key().as_bytes(), encoded.as_slice())
            .map_err(|_| StorageError::DatabaseRejected)?
            .is_some()
        {
            return Err(StorageError::StaleState);
        }
    }
    builder.charge_write(source.key().as_bytes().len(), 44)
}

fn take_gate(
    builder: &mut ConstructionPlanBuilder,
    key: &StoredKey,
) -> Result<StorageConstructionSource, StorageError> {
    builder.rotate_if_full()?;
    let source = {
        let mut table = builder
            .slice()?
            .open_table(GATES)
            .map_err(|_| StorageError::DatabaseRejected)?;
        let encoded = table
            .remove(key.as_bytes())
            .map_err(|_| StorageError::DatabaseRejected)?
            .ok_or(StorageError::StaleState)?;
        let (schema, rest) = encoded
            .value()
            .split_first_chunk::<4>()
            .ok_or(StorageError::InvalidEncoding)?;
        let (id, offset) = rest
            .split_first_chunk::<32>()
            .ok_or(StorageError::InvalidEncoding)?;
        let offset: [u8; 8] = offset
            .try_into()
            .map_err(|_| StorageError::InvalidEncoding)?;
        StorageConstructionSource::new(
            StorageConstructionSourceKind::BackupRecord,
            TableId::E2eeState,
            StoredKey::new(key.as_bytes().to_vec())?,
            u32::from_be_bytes(*schema),
            StorageDigest::from_bytes(*id),
            u64::from_be_bytes(offset),
        )?
    };
    builder.charge_write(key.as_bytes().len(), 0)?;
    Ok(source)
}

fn push_route(
    builder: &mut ConstructionPlanBuilder,
    source: &StorageConstructionSource,
) -> Result<(), StorageError> {
    let id = RouteRow::parse_key(source.key())?;
    let key = recovery_gate_key(&id)?;
    let gate = take_gate(builder, &key)?;
    builder.push(StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![copy_source(source)?, gate],
        TableId::E2eeState,
        key,
        source.record_schema(),
        StorageConstructionAction::RestoreE2eeState,
        0,
    )?)?;
    builder.push(StorageConstructionPlanEntry::new(
        StorageConstructionKind::Restore,
        vec![copy_source(source)?],
        TableId::E2eeState,
        StoredKey::new(source.key().as_bytes().to_vec())?,
        source.record_schema(),
        StorageConstructionAction::RestoreE2eeState,
        0,
    )?)
}

fn copy_source(
    source: &StorageConstructionSource,
) -> Result<StorageConstructionSource, StorageError> {
    StorageConstructionSource::new(
        source.kind(),
        source.table(),
        StoredKey::new(source.key().as_bytes().to_vec())?,
        source.record_schema(),
        source.sealed_record_id(),
        source.backup_byte_offset(),
    )
}
