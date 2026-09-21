//! A submitted metadata page owns its raw and decoding buffers through exact completion.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use crate::budget::MemoryPermit;
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, ReadRecord, TableId};

const PAGE_ROWS: usize = 128;
const RAW_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES
    + PAGE_ROWS * (agenc_relay_storage::MAX_STORED_KEY_BYTES + std::mem::size_of::<ReadRecord>())
    + 8_192;
const DECODE_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct ReadOwner {
    pub(super) id: StorageReadId,
    commit: u64,
    job: task::Job,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}

struct Completed {
    message: StorageReadCompletionMessage,
    owner: Box<ReadOwner>,
}

pub(super) fn prepare(
    context: &mut StateCoreContext,
    job: task::Job,
    plan: ReadPlan,
    commit: u64,
) -> Result<Box<ReadOwner>, CompanionFault> {
    let raw = context
        .reserve_output_backing(RAW_BYTES)
        .map_err(|_| CompanionFault::Ceiling)?;
    let decode = context
        .reserve_output_backing(DECODE_BYTES)
        .map_err(|_| CompanionFault::Ceiling)?;
    let id = context
        .submit_storage_read(plan)
        .map_err(|_| CompanionFault::Ceiling)?;
    Ok(Box::new(ReadOwner {
        id,
        commit,
        job,
        _raw: raw,
        _decode: decode,
    }))
}

pub(in super::super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !coordinator.replay_maintenance.owns(message.read_id) {
        return;
    }
    let Some(owner) = coordinator.replay_maintenance.read.take() else {
        return;
    };
    let mut completed = Completed { message, owner };
    let result = admit(coordinator, context, &mut completed);
    let Completed { message, owner } = completed;
    drop(message);
    let ReadOwner {
        job,
        commit,
        _raw,
        _decode,
        ..
    } = *owner;
    drop((_raw, _decode));
    let result = result.and_then(|plan| advance(coordinator, context, job, plan, commit));
    if let Err(error) = result {
        super::refused(coordinator, context, error);
    }
    if !coordinator.replay_maintenance.busy() {
        super::super::companion::drain_queued(coordinator, context);
        coordinator.drain_backlog(context);
    }
}

fn admit(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    completed: &mut Completed,
) -> Result<Option<ReadPlan>, CompanionFault> {
    super::validate_source(coordinator, context, &completed.owner.job)?;
    let result = completed
        .message
        .result
        .as_ref()
        .map_err(|_| CompanionFault::Ceiling)?;
    if result.storage_commit_sequence != completed.owner.commit {
        return Err(CompanionFault::Protocol);
    }
    if result.records.len() > PAGE_ROWS || result.truncated && result.records.is_empty() {
        return Err(CompanionFault::Storage);
    }
    let mut records = Vec::new();
    for row in &result.records {
        if row.table != TableId::E2eeState || row.sealed_record.len() > 8_192 {
            return Err(CompanionFault::Storage);
        }
        let plaintext = context
            .open_storage_plaintext(row.table, &row.key, &row.sealed_record)
            .map_err(|_| CompanionFault::Storage)?;
        let value = PersistentRecordValue::decode(row.table, plaintext.expose_for_storage_codec())
            .map_err(|_| CompanionFault::Storage)?;
        records.push((row.key.clone(), value));
    }
    completed
        .owner
        .job
        .admit(result.storage_commit_sequence, result.truncated, records)?;
    completed.owner.job.next()
}

fn advance(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    job: task::Job,
    plan: Option<ReadPlan>,
    commit: u64,
) -> Result<(), CompanionFault> {
    if let Some(plan) = plan {
        coordinator.replay_maintenance.read = Some(prepare(context, job, plan, commit)?);
        return Ok(());
    }
    let prepared = job.finish(
        coordinator
            .companion_exec
            .as_ref()
            .ok_or(CompanionFault::Storage)?,
    )?;
    if let Some(stamp) = prepared.clean_stamp() {
        return super::mark_clean(coordinator, context, stamp, commit);
    }
    let receipt = super::receipt::stage(coordinator, context, prepared, commit)?;
    coordinator.pending = Some(PendingCommit::CompanionReplayMaintenance(Box::new(receipt)));
    Ok(())
}
