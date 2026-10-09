//! A cold ACK prefix read retains its storage buffers until the exact completion drops.
#![forbid(unsafe_code)]

use super::super::ReadStep;
use super::{FederationCoordinator, StateCoreContext, Violation};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::{AckReadJob, AckReadRequest};
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, ReadRecord, TableId};

const PAGE_ROWS: usize = 128;
const RECORD_BYTES: usize = 8_192;
const RAW_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES
    + PAGE_ROWS * (agenc_relay_storage::MAX_STORED_KEY_BYTES + std::mem::size_of::<ReadRecord>())
    + 8_192;
const DECODE_BYTES: usize = 8 * 1024 * 1024;

pub(in super::super) struct Pending {
    id: StorageReadId,
    job: AckReadJob,
    /// The coordinator's own commits when the read began; every page is
    /// read against them.
    own_commits: u64,
    _raw: MemoryPermit,
    _decode: MemoryPermit,
}

// Field order keeps raw records alive for less time than their reservations.
struct Completed {
    message: StorageReadCompletionMessage,
    pending: Box<Pending>,
}

pub(in super::super) fn owns(coordinator: &FederationCoordinator, id: StorageReadId) -> bool {
    coordinator
        .companion_ack_read
        .as_ref()
        .is_some_and(|pending| pending.id == id)
}

pub(in super::super) fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    request: AckReadRequest,
) -> Result<(), Violation> {
    if let Some(pending) = &coordinator.companion_ack_read {
        return if pending.job.request() == &request {
            Ok(())
        } else {
            Err(Violation::Ceiling)
        };
    }
    // Companion reads run one at a time, so one completion at most waits
    // for a free batch slot (`parked_read`).
    if coordinator.replay_io_busy() {
        return Err(Violation::Ceiling);
    }
    validate_source(coordinator, context, &request)?;
    let protected = protected_first(coordinator, &request)?;
    let executor = coordinator
        .companion_exec
        .as_ref()
        .ok_or(Violation::Codec)?;
    // No other router writes companion rows, so the pages are pinned to the
    // coordinator's own commits rather than to the storage commit.
    let own_commits = coordinator.own_commits;
    let mut job = request
        .begin(
            executor,
            protected,
            own_commits,
            &context.backing_reservations(),
        )
        .map_err(super::fault_violation)?;
    let plan = job
        .next()
        .map_err(super::fault_violation)?
        .ok_or(Violation::Codec)?;
    coordinator.companion_ack_read = Some(prepare(context, job, plan, own_commits)?);
    Ok(())
}

fn prepare(
    context: &mut StateCoreContext,
    job: AckReadJob,
    plan: ReadPlan,
    own_commits: u64,
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
        job,
        own_commits,
        _raw: raw,
        _decode: decode,
    }))
}

fn validate_source(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    request: &AckReadRequest,
) -> Result<(), Violation> {
    if context.is_quiescing()
        || coordinator.pending.is_some()
        || !coordinator.link_is_live(request.link(), request.peer())
    {
        return Err(Violation::Phase);
    }
    let peer = coordinator
        .peers
        .get(&request.peer())
        .ok_or(Violation::Phase)?;
    let live = peer.live.as_ref().ok_or(Violation::Phase)?;
    if *live.incarnation.as_bytes() != request.scope().target_incarnation()
        || peer.client_resync_epoch != request.scope().covered_base_client_resync_epoch()
    {
        return Err(Violation::Phase);
    }
    request
        .validate(
            coordinator
                .companion_exec
                .as_ref()
                .ok_or(Violation::Codec)?,
        )
        .map_err(super::fault_violation)
}

fn protected_first(
    coordinator: &FederationCoordinator,
    request: &AckReadRequest,
) -> Result<Option<u64>, Violation> {
    let Some(gate) = coordinator.barriers.get(&request.peer()) else {
        return Ok(None);
    };
    if gate.scope() != request.scope() || gate.companion().generation() != request.generation() {
        return Err(Violation::Codec);
    }
    Ok(Some(gate.companion().first()))
}

pub(in super::super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !owns(coordinator, message.read_id) {
        return;
    }
    let Some(pending) = coordinator.companion_ack_read.take() else {
        return;
    };
    let mut completed = Completed { message, pending };
    let peer = completed.pending.job.request().peer();
    let link = completed.pending.job.request().link();
    let outcome = admit(coordinator, context, &mut completed);
    // Release the sealed page and both I/O leases before reserving the next page.
    let Completed { message, pending } = completed;
    drop(message);
    let Pending {
        job,
        own_commits,
        _raw,
        _decode,
        ..
    } = *pending;
    drop((_raw, _decode));
    let result = outcome.and_then(|step| match step {
        ReadStep::Next(plan) => advance(coordinator, context, job, plan, own_commits),
        ReadStep::Stale => {
            let request = job.request().clone();
            drop(job);
            submit(coordinator, context, request)
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
    validate_source(coordinator, context, completed.pending.job.request())?;
    // A commit another router made leaves the read current; one of the
    // coordinator's own may have changed the rows it reads.
    if coordinator.own_commits != completed.pending.own_commits {
        return Ok(ReadStep::Stale);
    }
    let result = completed
        .message
        .result
        .as_ref()
        .map_err(|_| Violation::Ceiling)?;
    if result.records.len() > PAGE_ROWS || result.truncated && result.records.is_empty() {
        return Err(Violation::Codec);
    }
    let mut records = Vec::new();
    for record in &result.records {
        if record.table != TableId::E2eeState || record.sealed_record.len() > RECORD_BYTES {
            return Err(Violation::Codec);
        }
        let plaintext = context
            .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
            .map_err(|_| Violation::Codec)?;
        let value =
            PersistentRecordValue::decode(record.table, plaintext.expose_for_storage_codec())
                .map_err(|_| Violation::Codec)?;
        records.push((record.key.clone(), value));
    }
    let own_commits = completed.pending.own_commits;
    completed
        .pending
        .job
        .admit(own_commits, result.truncated, records)
        .map_err(super::fault_violation)?;
    completed
        .pending
        .job
        .next()
        .map(ReadStep::Next)
        .map_err(super::fault_violation)
}

fn advance(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    job: AckReadJob,
    plan: Option<ReadPlan>,
    own_commits: u64,
) -> Result<(), Violation> {
    if let Some(plan) = plan {
        coordinator.companion_ack_read = Some(prepare(context, job, plan, own_commits)?);
        return Ok(());
    }
    let peer = job.request().peer();
    let link = job.request().link();
    let actions = job
        .finish(
            coordinator
                .companion_exec
                .as_ref()
                .ok_or(Violation::Codec)?,
        )
        .map_err(super::fault_violation)?;
    for action in actions {
        super::apply(coordinator, context, link, peer, action)?;
    }
    Ok(())
}
