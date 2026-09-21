//! Scoped replay reads keep their raw and decoding reservations through cancellation.
#![forbid(unsafe_code)]

use super::super::{FederationCoordinator, Violation};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::ReplayRestoreRequest;
use crate::state_core::StateCoreContext;
use agenc_relay_storage::{PersistentRecordValue, ReadRecord, StorageError};

const RAW_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES
    + 128 * (agenc_relay_storage::MAX_STORED_KEY_BYTES + std::mem::size_of::<ReadRecord>())
    + 8_192;
// Opened plaintext, persistent values, object decoding, and retained body copies coexist.
const DECODE_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct Loader {
    complete: bool,
    read: Option<Box<ReadOwner>>,
}

struct ReadOwner {
    id: StorageReadId,
    request: ReplayRestoreRequest,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}

// A queued sealed result drops before its reservations on every exit.
struct Completed {
    message: StorageReadCompletionMessage,
    owner: Box<ReadOwner>,
}

impl Loader {
    pub(super) fn owns(&self, id: StorageReadId) -> bool {
        self.read.as_ref().is_some_and(|read| read.id == id)
    }
}

pub(super) fn advance(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.loader.replay.complete {
        super::finish(coordinator, context);
        return;
    }
    match next(coordinator, context) {
        Ok(Some(request)) => submit(coordinator, context, request),
        Ok(None) => {
            coordinator.loader.replay.complete = true;
            super::finish(coordinator, context);
        }
        Err(_) => super::fail_restore(coordinator),
    }
}

fn next(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
) -> Result<Option<ReplayRestoreRequest>, Violation> {
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Ok(None);
    };
    executor
        .next_restored_replay(
            &context.backing_reservations(),
            coordinator.loader.pinned_commit.ok_or(Violation::Codec)?,
        )
        .map_err(|_| Violation::Codec)
}

fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    request: ReplayRestoreRequest,
) {
    match prepare(context, request) {
        Ok(read) => {
            coordinator.loader.pending = Some(read.id);
            coordinator.loader.replay.read = Some(Box::new(read));
        }
        Err(StorageError::AllocationFailed | StorageError::QueueFull) => {}
        Err(_) => super::fail_restore(coordinator),
    }
}

fn prepare(
    context: &mut StateCoreContext,
    request: ReplayRestoreRequest,
) -> Result<ReadOwner, StorageError> {
    let backing = context.backing_reservations();
    let raw = backing
        .reserve(RAW_BYTES)
        .map_err(|_| StorageError::AllocationFailed)?;
    let decode = backing
        .reserve(DECODE_BYTES)
        .map_err(|_| StorageError::AllocationFailed)?;
    let plan = request.plan().map_err(|_| StorageError::InvalidEncoding)?;
    let id = context.submit_storage_read(plan)?;
    Ok(ReadOwner {
        id,
        request,
        _raw: raw,
        _decode: decode,
    })
}

pub(super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !coordinator.loader.replay.owns(message.read_id) {
        return;
    }
    let Some(owner) = coordinator.loader.replay.read.take() else {
        return;
    };
    let completed = Completed { message, owner };
    coordinator.loader.pending = None;
    if coordinator.loader.failed {
        drop(completed);
        return;
    }
    let outcome = validate(coordinator, context, &completed);
    drop(completed);
    match outcome {
        Ok(true) => advance(coordinator, context),
        Ok(false) => {}
        Err(_) => super::fail_restore(coordinator),
    }
}

fn validate(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
    completed: &Completed,
) -> Result<bool, Violation> {
    if completed.owner.id != completed.message.read_id {
        return Err(Violation::Codec);
    }
    let result = match &completed.message.result {
        Ok(result) => result,
        Err(StorageError::AllocationFailed | StorageError::QueueFull) => return Ok(false),
        Err(_) => return Err(Violation::Codec),
    };
    super::pin_result(coordinator, result.storage_commit_sequence)?;
    let request = &completed.owner.request;
    validate_shape(request, result)?;
    let mut values = Vec::new();
    for record in &result.records {
        let plaintext = context
            .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
            .map_err(|_| Violation::Codec)?;
        let value =
            PersistentRecordValue::decode(record.table, plaintext.expose_for_storage_codec())
                .map_err(|_| Violation::Codec)?;
        values.push((record.key.clone(), value));
    }
    coordinator
        .companion_exec
        .as_mut()
        .ok_or(Violation::Codec)?
        .admit_restored_replay(
            request,
            result.storage_commit_sequence,
            result.truncated,
            values,
        )
        .map_err(|_| Violation::Codec)?;
    Ok(true)
}

fn validate_shape(
    request: &ReplayRestoreRequest,
    result: &agenc_relay_storage::ReadResult,
) -> Result<(), Violation> {
    if result.records.len() > request.record_limit()
        || result.truncated && result.records.is_empty()
    {
        return Err(Violation::Codec);
    }
    let mut bytes = 0_usize;
    for record in &result.records {
        if record.table != request.table()
            || record.sealed_record.len() > request.sealed_record_limit()
        {
            return Err(Violation::Codec);
        }
        bytes = bytes
            .checked_add(record.sealed_record.len())
            .ok_or(Violation::Codec)?;
        if bytes > request.sealed_page_limit() {
            return Err(Violation::Codec);
        }
    }
    Ok(())
}
