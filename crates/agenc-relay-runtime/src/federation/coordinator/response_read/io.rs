//! One raw result and its decoder lease belong to one submitted read identifier.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use agenc_relay_storage::{PersistentRecordValue, TableId};

const RAW_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES + 8_192;
const DECODE_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES * 3 + 8_192;

struct Completed {
    message: StorageReadCompletionMessage,
    pending: Box<Pending>,
}

pub(super) fn prepare(
    context: &mut StateCoreContext,
    job: Job,
    plan: ReadPlan,
    own_commits: u64,
    link: LinkId,
    base_epoch: u64,
) -> Result<Box<Pending>, Violation> {
    let raw = context
        .reserve_output_backing(RAW_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let decode = context
        .reserve_output_backing(DECODE_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let id = context
        .submit_storage_read(plan)
        .map_err(|_| Violation::Ceiling)?;
    Ok(Box::new(Pending {
        id,
        own_commits,
        link,
        base_epoch,
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
    if !owns(coordinator, message.read_id) {
        return;
    }
    let Some(pending) = coordinator.companion_response_read.take() else {
        return;
    };
    let mut completed = Completed { message, pending };
    let result = admit(coordinator, context, &mut completed);
    let Completed { message, pending } = completed;
    drop(message);
    let Pending {
        job,
        own_commits,
        link,
        base_epoch,
        _raw,
        _decode,
        ..
    } = *pending;
    let identity = job.candidate().identity();
    let peer = identity.peer;
    drop((_raw, _decode));
    let result = result.and_then(|step| match step {
        ReadStep::Next(plan) => super::advance(
            coordinator,
            context,
            job,
            plan,
            own_commits,
            link,
            base_epoch,
        ),
        ReadStep::Stale => {
            drop(job);
            super::submit(coordinator, context, link, peer, identity)
        }
    });
    if let Err(error) = result
        && coordinator.link_is_live(link, peer)
        && !context.is_quiescing()
    {
        coordinator.fail_link(context, link, peer, error);
    }
    coordinator.companion_read_settled(context);
}

fn admit(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    completed: &mut Completed,
) -> Result<ReadStep, Violation> {
    let pending = &mut completed.pending;
    super::validate_link(
        coordinator,
        context,
        pending.link,
        pending.job.candidate().identity(),
        pending.base_epoch,
    )?;
    pending
        .job
        .candidate()
        .validate(
            coordinator
                .companion_exec
                .as_ref()
                .ok_or(Violation::Codec)?,
        )
        .map_err(companion::fault_violation)?;
    // A commit another router made leaves the read current; one of the
    // coordinator's own may have changed the bodies it reads.
    if coordinator.own_commits != pending.own_commits {
        return Ok(ReadStep::Stale);
    }
    let result = completed
        .message
        .result
        .as_ref()
        .map_err(|_| Violation::Ceiling)?;
    if result.truncated || result.records.len() != 1 {
        return Err(Violation::Codec);
    }
    let mut records = Vec::new();
    for row in &result.records {
        if row.table != TableId::E2eeObject
            || row.sealed_record.len() > agenc_relay_storage::MAX_SEALED_RECORD_BYTES
        {
            return Err(Violation::Codec);
        }
        let plain = context
            .open_storage_plaintext(row.table, &row.key, &row.sealed_record)
            .map_err(|_| Violation::Codec)?;
        let value = PersistentRecordValue::decode(row.table, plain.expose_for_storage_codec())
            .map_err(|_| Violation::Codec)?;
        records.push((row.key.clone(), value));
    }
    pending
        .job
        .admit(pending.own_commits, result.truncated, records)
        .map_err(companion::fault_violation)?;
    pending
        .job
        .next()
        .map(ReadStep::Next)
        .map_err(companion::fault_violation)
}
