//! Table reads retain their byte owners through cancellation and release them before continuation.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::MemoryPermit;
use agenc_ircd_storage::{ReadRecord, StorageError};

const RAW_BYTES: usize = agenc_ircd_storage::MAX_SEALED_RECORD_BYTES
    + 256 * (MAX_STORED_KEY_BYTES + std::mem::size_of::<ReadRecord>())
    + 8192;
const DECODE_BYTES: usize = 3 * agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 8192;

pub(super) struct Pending {
    pub(super) id: StorageReadId,
    table: TableId,
    start: StoredKey,
    end: StoredKey,
    commit: u64,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}
struct Completed {
    message: StorageReadCompletionMessage,
    pending: Box<Pending>,
}
enum Next {
    Retry,
    Page(StoredKey),
    Table,
}

pub(super) fn prepare(
    context: &mut StateCoreContext,
    table: TableId,
    start: StoredKey,
) -> Result<Box<Pending>, StorageError> {
    if context.is_quiescing() {
        return Err(StorageError::Unavailable);
    }
    let end = StoredKey::new(vec![0xff; MAX_STORED_KEY_BYTES])?;
    let plan = ReadPlan::range(table, start.clone(), end.clone(), PAGE_ROWS)?;
    let raw = context
        .reserve_output_backing(RAW_BYTES)
        .map_err(|_| StorageError::AllocationFailed)?;
    let decode = context
        .reserve_output_backing(DECODE_BYTES)
        .map_err(|_| StorageError::AllocationFailed)?;
    let commit = context.head().storage_commit_sequence;
    let id = context.submit_storage_read(plan)?;
    Ok(Box::new(Pending {
        id,
        table,
        start,
        end,
        commit,
        _raw: raw,
        _decode: decode,
    }))
}

pub(super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !coordinator
        .loader
        .table_read
        .as_ref()
        .is_some_and(|pending| pending.id == message.read_id)
    {
        return;
    }
    let Some(pending) = coordinator.loader.table_read.take() else {
        return;
    };
    let completed = Completed { message, pending };
    coordinator.loader.pending = None;
    if coordinator.loader.failed || context.is_quiescing() {
        return;
    }
    let next = admit(coordinator, context, &completed);
    drop(completed);
    match next {
        Err(_) => fail_restore(coordinator),
        Ok(Next::Retry) => request_page(coordinator, context, coordinator.loader.retry.clone()),
        Ok(Next::Page(start)) => request_page(coordinator, context, Some(start)),
        Ok(Next::Table) => {
            coordinator.loader.position = coordinator.loader.position.saturating_add(1);
            request_page(coordinator, context, first_key());
        }
    }
}

fn admit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    completed: &Completed,
) -> Result<Next, Violation> {
    let pending = &completed.pending;
    if TABLES.get(coordinator.loader.position) != Some(&pending.table)
        || context.head().storage_commit_sequence != pending.commit
    {
        return Err(Violation::Codec);
    }
    let Ok(result) = &completed.message.result else {
        return Ok(Next::Retry);
    };
    if result.storage_commit_sequence != pending.commit
        || result.records.len() > usize::from(PAGE_ROWS)
    {
        return Err(Violation::Codec);
    }
    pin_result(coordinator, result.storage_commit_sequence)?;
    let mut last = None;
    let mut bytes = 0_usize;
    for record in &result.records {
        bytes = bytes
            .checked_add(record.sealed_record.len())
            .ok_or(Violation::Ceiling)?;
        validate_row(pending, record, last.as_ref(), bytes)?;
        let plain = context
            .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
            .map_err(|_| Violation::Codec)?;
        let value = PersistentRecordValue::decode(record.table, plain.expose_for_storage_codec())
            .map_err(|_| Violation::Codec)?;
        super::admit(coordinator, context, record.table, &record.key, &value)?;
        last = Some(record.key.clone());
    }
    if result.truncated {
        let next = last
            .and_then(|key| successor(&key))
            .ok_or(Violation::Codec)?;
        Ok(Next::Page(next))
    } else {
        Ok(Next::Table)
    }
}

fn validate_row(
    pending: &Pending,
    record: &ReadRecord,
    last: Option<&StoredKey>,
    bytes: usize,
) -> Result<(), Violation> {
    if record.table != pending.table
        || record.key < pending.start
        || record.key > pending.end
        || bytes > agenc_ircd_storage::MAX_SEALED_RECORD_BYTES
        || last.is_some_and(|previous| previous >= &record.key)
    {
        return Err(Violation::Codec);
    }
    Ok(())
}
