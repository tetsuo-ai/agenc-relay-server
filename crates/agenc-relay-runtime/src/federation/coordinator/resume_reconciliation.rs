//! Durable reconciliation of an ordinary retained FRESUME prefix.
//!
//! Every covered row is authenticated before bounded deletion batches begin.

#![forbid(unsafe_code)]

use agenc_relay_federation_wire::{DeliveryCursor, EventHeader, FederationFrame};
use agenc_relay_storage::federation_records::{outbox_key, outbox_range};
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, StorageError, TableId};
use agenc_relay_types::{EventId, NetworkId, ServerId, ServerIncarnation};

use super::{FederationCoordinator, PendingCommit, Violation, snapshot};
use crate::RuntimeError;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::budget::MemoryPermit;
use crate::federation::LinkId;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::{FanoutRefused, FanoutRequest};
use crate::state_core::timers::{TimedId, TimerEntry, TimerGeneration, TimerKind};
use crate::state_core::{StageAccepted, StageRefused, StateCoreContext};

const VALIDATION_ROWS: u16 = 64;
const CHUNK_ROWS: usize = 256;
const RETRY_MILLIS: u64 = 1_000;
const NEXT_CHUNK_MILLIS: u64 = 20;
// Two bounded key allocations per deletion, plus the vector and peer encoding.
const CHUNK_BACKING_BYTES: usize = CHUNK_ROWS * 2 * 4_096 + 131_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Target {
    network: NetworkId,
    peer: ServerId,
    link: LinkId,
    incarnation: ServerIncarnation,
    generation: u64,
    sequence: u64,
    event_id: EventId,
}

pub(super) struct Reconciliation {
    target: Target,
    validate_next: u64,
    validated: bool,
    read: Option<StorageReadId>,
    retry: Option<TimerGeneration>,
}

pub(super) struct ChunkReceipt {
    target: Target,
    pub(super) staged_after: u64,
    sequence: u64,
    event_id: EventId,
    // The StateCore batch releases its write allocations before this receipt.
    _permit: MemoryPermit,
}

struct PreparedChunk {
    plan: agenc_relay_domain::MutationPlan,
    writes: Vec<AccountServiceDurableWrite>,
    receipt: ChunkReceipt,
}

/// Returns false only when this is not a newer exact retained candidate.
pub(super) fn begin(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    link: LinkId,
    generation: u64,
    cursor: DeliveryCursor,
) -> Result<bool, Violation> {
    let DeliveryCursor::At {
        delivery_sequence,
        event_id,
    } = cursor
    else {
        return Ok(false);
    };
    let state = coordinator
        .peers
        .get(&peer)
        .ok_or(Violation::Misaddressed)?;
    let Some(live) = state.live.as_ref().filter(|live| live.link == link) else {
        return Err(Violation::Phase);
    };
    let first = state.outbox.cursor.map_or(Ok(0), |(sequence, _)| {
        sequence.checked_add(1).ok_or(Violation::Ceiling)
    })?;
    if delivery_sequence < first
        || !state
            .outbox
            .unacked
            .iter()
            .any(|(sequence, id, _)| *sequence == delivery_sequence && *id == event_id)
    {
        return Ok(false);
    }
    validate_window(state, first, delivery_sequence)?;
    if coordinator
        .barriers
        .get(&peer)
        .is_some_and(|barrier| delivery_sequence > barrier.base().last())
    {
        return Err(Violation::Acknowledgement);
    }
    let target = Target {
        network: coordinator.config.network_id,
        peer,
        link,
        incarnation: live.incarnation,
        generation,
        sequence: delivery_sequence,
        event_id,
    };
    coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?
        .reconciliation = Some(Reconciliation {
        target,
        validate_next: first,
        validated: false,
        read: None,
        retry: None,
    });
    continue_work(coordinator, context, peer);
    Ok(true)
}

fn validate_window(state: &super::PeerState, first: u64, through: u64) -> Result<(), Violation> {
    let mut expected = first;
    for (sequence, _, _) in &state.outbox.unacked {
        if *sequence != expected {
            return Err(Violation::Acknowledgement);
        }
        if *sequence == through {
            return Ok(());
        }
        expected = expected.checked_add(1).ok_or(Violation::Ceiling)?;
    }
    Err(Violation::Acknowledgement)
}

fn applicable(coordinator: &FederationCoordinator, target: Target) -> bool {
    coordinator.peers.get(&target.peer).is_some_and(|state| {
        state.projection_generation == target.generation
            && !state.fence_pending
            && !state.quarantined
            && !state.outbox.snapshot_required
            && state.snapshot.is_none()
            && state.live.as_ref().is_some_and(|live| {
                live.link == target.link && live.incarnation == target.incarnation
            })
    })
}

pub(super) fn cancel(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    if let Some(state) = coordinator.peers.get_mut(&peer) {
        state.reconciliation = None;
    }
    let _cancelled = context
        .timers_mut()
        .cancel(TimerKind::FederationResumeRetry, TimedId::Peer(peer));
}

fn cancel_target(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
) {
    if coordinator.peers.get(&target.peer).is_some_and(|state| {
        state
            .reconciliation
            .as_ref()
            .is_some_and(|pending| pending.target == target)
    }) {
        cancel(coordinator, context, target.peer);
    }
}

fn fail(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
    violation: Violation,
) {
    cancel_target(coordinator, context, target);
    if coordinator.link_is_live(target.link, target.peer) {
        coordinator.fail_link(context, target.link, target.peer, violation);
    }
}

fn arm_retry(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
) {
    arm_after(coordinator, context, target, RETRY_MILLIS);
}

fn arm_after(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
    delay: u64,
) {
    let Some(pending) = coordinator
        .peers
        .get_mut(&target.peer)
        .and_then(|state| state.reconciliation.as_mut())
        .filter(|pending| pending.target == target)
    else {
        return;
    };
    if pending.retry.is_some() {
        return;
    }
    let timer = context.now().checked_add(delay).ok().and_then(|deadline| {
        context
            .timers_mut()
            .schedule(
                deadline,
                TimerKind::FederationResumeRetry,
                TimedId::Peer(target.peer),
            )
            .ok()
    });
    match timer {
        Some(timer) => pending.retry = Some(timer),
        None => fail(coordinator, context, target, Violation::Ceiling),
    }
}

pub(super) fn timer_fired(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    let (TimerKind::FederationResumeRetry, TimedId::Peer(peer)) = (entry.kind, entry.id) else {
        return false;
    };
    let Some(pending) = coordinator
        .peers
        .get_mut(&peer)
        .and_then(|state| state.reconciliation.as_mut())
    else {
        return true;
    };
    if pending.retry != Some(entry.generation) {
        return true;
    }
    pending.retry = None;
    continue_work(coordinator, context, peer);
    true
}

fn continue_work(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
) {
    let Some(pending) = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.reconciliation.as_ref())
    else {
        return;
    };
    let target = pending.target;
    if context.is_quiescing() || !applicable(coordinator, target) {
        cancel(coordinator, context, peer);
        return;
    }
    if pending.retry.is_some() || pending.read.is_some() {
        return;
    }
    if coordinator.pending.is_some() || context.in_flight() || context.pending_len() != 0 {
        arm_retry(coordinator, context, target);
        return;
    }
    if pending.validated {
        stage_chunk(coordinator, context, target);
    } else {
        read_prefix(coordinator, context, target);
    }
}

fn read_prefix(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
) {
    let Some(pending) = coordinator
        .peers
        .get(&target.peer)
        .and_then(|state| state.reconciliation.as_ref())
    else {
        return;
    };
    let last = pending
        .validate_next
        .saturating_add(u64::from(VALIDATION_ROWS) - 1)
        .min(target.sequence);
    let plan = outbox_range(target.peer, target.generation, pending.validate_next, last).and_then(
        |(first, last)| ReadPlan::range(TableId::EdgeOutbox, first, last, VALIDATION_ROWS),
    );
    match plan.and_then(|plan| context.submit_storage_read(plan)) {
        Ok(read) => {
            if let Some(pending) = coordinator
                .peers
                .get_mut(&target.peer)
                .and_then(|state| state.reconciliation.as_mut())
            {
                pending.read = Some(read);
            }
        }
        Err(error) if retryable_storage(error) => arm_retry(coordinator, context, target),
        Err(_) => fail(coordinator, context, target, Violation::Ceiling),
    }
}

pub(super) fn owns_read(coordinator: &FederationCoordinator, id: StorageReadId) -> bool {
    coordinator.peers.values().any(|state| {
        state
            .reconciliation
            .as_ref()
            .is_some_and(|pending| pending.read == Some(id))
    })
}

pub(super) fn read_completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    let Some(target) = coordinator.peers.values().find_map(|state| {
        state
            .reconciliation
            .as_ref()
            .filter(|pending| pending.read == Some(message.read_id))
            .map(|pending| pending.target)
    }) else {
        return;
    };
    if !applicable(coordinator, target) {
        cancel(coordinator, context, target.peer);
        return;
    }
    if let Some(pending) = coordinator
        .peers
        .get_mut(&target.peer)
        .and_then(|state| state.reconciliation.as_mut())
    {
        pending.read = None;
    }
    let page = match message.result {
        Ok(page) => page,
        Err(error) if retryable_storage(error) => {
            arm_retry(coordinator, context, target);
            return;
        }
        Err(_) => {
            fail(coordinator, context, target, Violation::Codec);
            return;
        }
    };
    let next = coordinator
        .peers
        .get(&target.peer)
        .ok_or(Violation::Misaddressed)
        .and_then(|state| validate_page(context, state, page));
    match next {
        Ok(next) => {
            if let Some(pending) = coordinator
                .peers
                .get_mut(&target.peer)
                .and_then(|state| state.reconciliation.as_mut())
            {
                pending.validate_next = next;
                pending.validated = next > target.sequence;
            }
            continue_work(coordinator, context, target.peer);
        }
        Err(violation) => fail(coordinator, context, target, violation),
    }
}

fn validate_page(
    context: &StateCoreContext,
    state: &super::PeerState,
    page: agenc_relay_storage::ReadResult,
) -> Result<u64, Violation> {
    let pending = state.reconciliation.as_ref().ok_or(Violation::Phase)?;
    if page.records.is_empty() || page.records.len() > usize::from(VALIDATION_ROWS) {
        return Err(Violation::Acknowledgement);
    }
    let mut next = pending.validate_next;
    for record in page.records {
        let (sequence, event_id) = validate_ordinary_row(context, pending.target, &record)?;
        if sequence != next || sequence > pending.target.sequence {
            return Err(Violation::Acknowledgement);
        }
        if !retained_tuple(state, sequence, event_id) {
            return Err(Violation::Acknowledgement);
        }
        next = next.checked_add(1).ok_or(Violation::Ceiling)?;
    }
    Ok(next)
}

fn retained_tuple(state: &super::PeerState, sequence: u64, event_id: EventId) -> bool {
    let Some((first, _, _)) = state.outbox.unacked.front() else {
        return false;
    };
    sequence
        .checked_sub(*first)
        .and_then(|offset| usize::try_from(offset).ok())
        .and_then(|offset| state.outbox.unacked.get(offset))
        .is_some_and(|(retained, id, _)| *retained == sequence && *id == event_id)
}

fn validate_ordinary_row(
    context: &StateCoreContext,
    target: Target,
    record: &agenc_relay_storage::ReadRecord,
) -> Result<(u64, EventId), Violation> {
    if record.table != TableId::EdgeOutbox {
        return Err(Violation::Codec);
    }
    let opened = context
        .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
        .map_err(|_| Violation::Codec)?;
    let value = PersistentRecordValue::decode(record.table, opened.expose_for_storage_codec())
        .map_err(|_| Violation::Codec)?;
    if value.record_kind() != agenc_relay_storage::federation_records::OUTBOX_EVENT_KIND {
        return Err(Violation::Codec);
    }
    let (parts, event) = snapshot::decode_outbox_record(&record.key, &value)?;
    if parts.target != target.peer || parts.projection_generation != target.generation {
        return Err(Violation::Acknowledgement);
    }
    let mut budget = agenc_relay_federation_wire::DecodeBudget::new(1 << 20, 4_096);
    let object = agenc_relay_federation_wire::SchemaObject::decode_exact(
        "FederationEvent",
        &event.event_object,
        &mut budget,
    )
    .map_err(|_| Violation::Codec)?;
    let header = EventHeader::from_object(&object).map_err(|_| Violation::Codec)?;
    if header.network_id != target.network {
        return Err(Violation::Misaddressed);
    }
    if header.cross_profile.is_some() || event.acknowledged {
        // This path cannot substitute a snapshot for an unacknowledged barrier.
        return Err(Violation::Acknowledgement);
    }
    Ok((parts.delivery_sequence, header.event_id))
}

fn prepare_chunk(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    target: Target,
) -> Result<PreparedChunk, RuntimeError> {
    let permit = context.reserve_output_backing(CHUNK_BACKING_BYTES)?;
    let state = coordinator
        .peers
        .get(&target.peer)
        .ok_or(RuntimeError::InvalidValue)?;
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| RuntimeError::InvalidValue)?;
    let mut writes = Vec::new();
    writes
        .try_reserve_exact(CHUNK_ROWS + 1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    if writes.capacity() != CHUNK_ROWS + 1 {
        return Err(RuntimeError::MemoryExhausted);
    }
    let mut last = None;
    for (sequence, event_id, _) in state.outbox.unacked.iter().take(CHUNK_ROWS) {
        if *sequence > target.sequence {
            break;
        }
        writes.push(AccountServiceDurableWrite::delete(
            TableId::EdgeOutbox,
            outbox_key(target.peer, target.generation, *sequence)?,
        )?);
        last = Some((*sequence, *event_id));
    }
    let (sequence, event_id) = last.ok_or(RuntimeError::InvalidValue)?;
    writes.push(coordinator.peer_row_at(
        target.peer,
        plan.resulting_revision().get(),
        Some((sequence, event_id)),
    )?);
    Ok(PreparedChunk {
        plan,
        writes,
        receipt: ChunkReceipt {
            target,
            staged_after: context.head().storage_commit_sequence,
            sequence,
            event_id,
            _permit: permit,
        },
    })
}

fn stage_chunk(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    target: Target,
) {
    let prepared = match prepare_chunk(coordinator, context, target) {
        Ok(prepared) => prepared,
        Err(RuntimeError::MemoryExhausted) => {
            arm_retry(coordinator, context, target);
            return;
        }
        Err(_) => {
            fail(coordinator, context, target, Violation::Ceiling);
            return;
        }
    };
    let Ok(fanout) = FanoutRequest::new(Vec::new(), Vec::new()) else {
        fail(coordinator, context, target, Violation::Ceiling);
        return;
    };
    match context.stage_durable_with_account_service(
        prepared.plan,
        fanout,
        None,
        0,
        prepared.writes,
    ) {
        Ok(StageAccepted::Staged { .. }) => {
            coordinator.pending = Some(PendingCommit::ResumeAcknowledged(prepared.receipt));
        }
        Err(StageRefused::Busy | StageRefused::Fanout(FanoutRefused::MemoryExhausted)) => {
            arm_retry(coordinator, context, target);
        }
        Err(StageRefused::Quiescing) => cancel(coordinator, context, target.peer),
        _ => fail(coordinator, context, target, Violation::Ceiling),
    }
}

pub(super) fn committed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    receipt: ChunkReceipt,
) {
    let target = receipt.target;
    if coordinator
        .peers
        .get(&target.peer)
        .is_none_or(|state| state.projection_generation != target.generation)
    {
        fail(coordinator, context, target, Violation::Acknowledgement);
        return;
    }
    coordinator.acknowledgement_committed(
        context,
        target.peer,
        receipt.sequence,
        receipt.event_id,
        None,
    );
    if !applicable(coordinator, target) {
        cancel_target(coordinator, context, target);
        return;
    }
    if receipt.sequence < target.sequence {
        // Defers the next chunk until StateCore finishes receipt index refresh.
        arm_after(coordinator, context, target, NEXT_CHUNK_MILLIS);
        return;
    }
    cancel_target(coordinator, context, target);
    let Some(next) = target.sequence.checked_add(1) else {
        fail(coordinator, context, target, Violation::Ceiling);
        return;
    };
    let frame = FederationFrame::ResumeOk {
        edge_server_id: target.peer,
        projection_generation: target.generation,
        next_delivery_sequence: next,
    };
    if coordinator.send_frame(context, target.link, target.peer, &frame) {
        snapshot::start_resend(coordinator, context, target.peer, next);
    }
}

pub(super) fn rejected(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    receipt: ChunkReceipt,
    error: StorageError,
) {
    if retryable_storage(error) {
        arm_retry(coordinator, context, receipt.target);
    } else {
        fail(coordinator, context, receipt.target, Violation::Ceiling);
    }
}

fn retryable_storage(error: StorageError) -> bool {
    matches!(
        error,
        StorageError::QueueFull
            | StorageError::AllocationFailed
            | StorageError::FilesystemRejected(_)
    )
}
