//! Owner-first companion pages are read under exact result leases at one commit.
#![forbid(unsafe_code)]

use super::super::{FederationCoordinator, Violation};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::budget::MemoryPermit;
use crate::state_core::StateCoreContext;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{CUT_PAGE_PREFIX, MAX_PAGE_BODY_BYTES};
use agenc_ircd_storage::{PersistentRecordValue, ReadPlan, StorageError, StoredKey, TableId};

// Exact storage reads can return one full sealed record even when its expected
// semantic page is smaller. Result/key metadata and decoder coexistence are separate.
const RAW_READ_BYTES: usize = agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 8_192;
const DECODE_BUFFERS: usize = 8;
const DECODE_BYTES: usize = MAX_PAGE_BODY_BYTES + 8_192;

#[derive(Default)]
pub(super) struct Loader {
    inventory: Option<StoredKey>,
    inventory_started: bool,
    complete: bool,
    read: Option<ReadOwner>,
}

struct ReadOwner {
    id: StorageReadId,
    key: StoredKey,
    inventory: bool,
    _raw: MemoryPermit,
    _decode: [MemoryPermit; DECODE_BUFFERS],
}

// The queued raw result is destroyed before its reservations, including refusal.
struct Completed {
    message: StorageReadCompletionMessage,
    owner: ReadOwner,
}

impl Loader {
    pub(super) fn owns(&self, id: StorageReadId) -> bool {
        self.read.as_ref().is_some_and(|read| read.id == id)
    }
}

pub(super) fn advance(coordinator: &mut FederationCoordinator, context: &mut StateCoreContext) {
    if coordinator.loader.delivery.complete {
        super::replay::advance(coordinator, context);
        return;
    }
    match next(coordinator, context) {
        Ok(Some((key, inventory))) => submit(coordinator, context, key, inventory),
        Ok(None) => {
            coordinator.loader.delivery.complete = true;
            super::replay::advance(coordinator, context);
        }
        Err(Violation::Ceiling) => {}
        Err(_) => super::fail_restore(coordinator),
    }
}

fn next(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
) -> Result<Option<(StoredKey, bool)>, Violation> {
    if !coordinator.loader.delivery.inventory_started {
        if let Some(key) = next_authoritative(coordinator, context)? {
            return Ok(Some((key, false)));
        }
        coordinator.loader.delivery.inventory_started = true;
        coordinator.loader.delivery.inventory = Some(prefix_key()?);
    }
    Ok(coordinator
        .loader
        .delivery
        .inventory
        .clone()
        .map(|key| (key, true)))
}

fn next_authoritative(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
) -> Result<Option<StoredKey>, Violation> {
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Ok(None);
    };
    executor
        .next_restored_delivery_page(&context.backing_reservations())
        .map_err(|error| match error {
            crate::e2ee::coordinator::CompanionFault::Ceiling => Violation::Ceiling,
            _ => Violation::Codec,
        })
}

fn prefix_key() -> Result<StoredKey, Violation> {
    StoredKey::new(CUT_PAGE_PREFIX.to_vec()).map_err(|_| Violation::Codec)
}

fn end_key() -> Result<StoredKey, Violation> {
    let mut bytes = CUT_PAGE_PREFIX.to_vec();
    let last = bytes.last_mut().ok_or(Violation::Codec)?;
    *last = last.checked_add(1).ok_or(Violation::Codec)?;
    StoredKey::new(bytes).map_err(|_| Violation::Codec)
}

fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    key: StoredKey,
    inventory: bool,
) {
    let result = prepare_read(context, key, inventory);
    match result {
        Ok(read) => {
            coordinator.loader.pending = Some(read.id);
            coordinator.loader.delivery.read = Some(read);
        }
        Err(StorageError::AllocationFailed | StorageError::QueueFull) => {}
        Err(_) => super::fail_restore(coordinator),
    }
}

fn prepare_read(
    context: &mut StateCoreContext,
    key: StoredKey,
    inventory: bool,
) -> Result<ReadOwner, StorageError> {
    let backing = context.backing_reservations();
    let raw = backing
        .reserve(RAW_READ_BYTES)
        .map_err(|_| StorageError::AllocationFailed)?;
    let mut decode = Vec::new();
    for _ in 0..DECODE_BUFFERS {
        decode.push(
            backing
                .reserve(DECODE_BYTES)
                .map_err(|_| StorageError::AllocationFailed)?,
        );
    }
    let decode: [MemoryPermit; DECODE_BUFFERS] = decode
        .try_into()
        .map_err(|_| StorageError::AllocationFailed)?;
    let plan = if inventory {
        ReadPlan::range(
            TableId::E2eeState,
            key.clone(),
            end_key().map_err(|_| StorageError::InvalidEncoding)?,
            1,
        )?
    } else {
        ReadPlan::exact(TableId::E2eeState, key.clone())
    };
    let id = context.submit_storage_read(plan)?;
    Ok(ReadOwner {
        id,
        key,
        inventory,
        _raw: raw,
        _decode: decode,
    })
}

pub(super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !coordinator.loader.delivery.owns(message.read_id) {
        return;
    }
    let Some(owner) = coordinator.loader.delivery.read.take() else {
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
    validate_result_shape(result, completed.owner.inventory)?;
    for record in &result.records {
        admit(coordinator, context, &completed.owner, record)?;
    }
    if completed.owner.inventory {
        coordinator.loader.delivery.inventory = if result.truncated {
            Some(
                super::successor(&result.records.first().ok_or(Violation::Codec)?.key)
                    .ok_or(Violation::Codec)?,
            )
        } else {
            None
        };
    }
    Ok(true)
}

fn validate_result_shape(
    result: &agenc_ircd_storage::ReadResult,
    inventory: bool,
) -> Result<(), Violation> {
    if result.records.len() > 1 || result.truncated && result.records.is_empty() {
        return Err(Violation::Codec);
    }
    if !inventory && (result.records.len() != 1 || result.truncated) {
        return Err(Violation::Codec);
    }
    Ok(())
}

fn admit(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
    read: &ReadOwner,
    record: &agenc_ircd_storage::ReadRecord,
) -> Result<(), Violation> {
    if record.table != TableId::E2eeState
        || record.sealed_record.len() > DECODE_BYTES
        || (!read.inventory && record.key != read.key)
        || (read.inventory && (record.key < read.key || record.key >= end_key()?))
    {
        return Err(Violation::Codec);
    }
    let opened = context
        .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
        .map_err(|_| Violation::Codec)?;
    let value = PersistentRecordValue::decode(record.table, opened.expose_for_storage_codec())
        .map_err(|_| Violation::Codec)?;
    let Some(executor) = coordinator.companion_exec.as_mut() else {
        return Ok(());
    };
    if read.inventory {
        executor.inventory_restored_delivery_page(&record.key, &value)
    } else {
        executor.admit_restored_delivery_page(&record.key, &value)
    }
    .map_err(|_| Violation::Codec)
}

#[cfg(test)]
#[path = "delivery/tests/cancellation.rs"]
mod cancellation_tests;
