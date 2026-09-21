//! A submitted page's raw result keeps its lease even after its link disappears.
#![forbid(unsafe_code)]

use super::{FederationCoordinator, HostView, StateCoreContext, Violation};
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::budget::MemoryPermit;
use crate::e2ee::coordinator::sync::{Action, SnapshotPageRequest};
use agenc_relay_storage::e2ee_records::delivery_recovery::MAX_PAGE_BODY_BYTES;
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, TableId};
use std::collections::BTreeSet;

const RAW_BYTES: usize = agenc_relay_storage::MAX_SEALED_RECORD_BYTES + 8_192;
const DECODE_BYTES: usize = MAX_PAGE_BODY_BYTES + 8_192;
const DECODE_BUFFERS: usize = 8;

pub(in super::super) struct Pending {
    id: StorageReadId,
    request: SnapshotPageRequest,
    _raw: MemoryPermit,
    _decode: [Option<MemoryPermit>; DECODE_BUFFERS],
}

// The actual completion message is always destroyed before the pending lease.
struct Completed {
    message: StorageReadCompletionMessage,
    pending: Pending,
}

pub(in super::super) fn owns(coordinator: &FederationCoordinator, id: StorageReadId) -> bool {
    coordinator
        .companion_page_read
        .as_ref()
        .is_some_and(|pending| pending.id == id)
}

pub(in super::super) fn submit(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    request: SnapshotPageRequest,
) -> Result<(), Violation> {
    if let Some(pending) = &coordinator.companion_page_read {
        return if pending.request == request {
            Ok(())
        } else {
            Err(Violation::Ceiling)
        };
    }
    if coordinator.pending.is_some() || context.is_quiescing() {
        return Err(Violation::Ceiling);
    }
    let raw = context
        .reserve_output_backing(RAW_BYTES)
        .map_err(|_| Violation::Ceiling)?;
    let mut decode = std::array::from_fn(|_| None);
    for slot in &mut decode {
        *slot = Some(
            context
                .reserve_output_backing(DECODE_BYTES)
                .map_err(|_| Violation::Ceiling)?,
        );
    }
    let key = request.key().map_err(super::fault_violation)?;
    let id = context
        .submit_storage_read(ReadPlan::exact(TableId::E2eeState, key))
        .map_err(|_| Violation::Ceiling)?;
    coordinator.companion_page_read = Some(Pending {
        id,
        request,
        _raw: raw,
        _decode: decode,
    });
    Ok(())
}

pub(in super::super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !owns(coordinator, message.read_id) {
        return;
    }
    let Some(pending) = coordinator.companion_page_read.take() else {
        return;
    };
    let completed = Completed { message, pending };
    let peer = completed.pending.request.peer();
    let link = completed.pending.request.link();
    let actions = validate(coordinator, context, &completed);
    drop(completed);
    let result = actions.and_then(|actions| {
        for action in actions {
            super::apply(coordinator, context, link, peer, action)?;
        }
        Ok(())
    });
    if let Err(error) = result
        && coordinator.link_is_live(link, peer)
    {
        coordinator.fail_link(context, link, peer, error);
    }
}

fn validate(
    coordinator: &mut FederationCoordinator,
    context: &StateCoreContext,
    completed: &Completed,
) -> Result<Vec<Action>, Violation> {
    let request = &completed.pending.request;
    let peer = request.peer();
    if context.is_quiescing() || !coordinator.link_is_live(request.link(), peer) {
        return Ok(Vec::new());
    }
    let result = completed
        .message
        .result
        .as_ref()
        .map_err(|_| Violation::Ceiling)?;
    if result.truncated || result.records.len() != 1 {
        return Err(Violation::Codec);
    }
    let record = result.records.first().ok_or(Violation::Codec)?;
    if record.table != TableId::E2eeState
        || record.key != request.key().map_err(super::fault_violation)?
        || record.sealed_record.len() > DECODE_BYTES
    {
        return Err(Violation::Codec);
    }
    let opened = context
        .open_storage_plaintext(record.table, &record.key, &record.sealed_record)
        .map_err(|_| Violation::Codec)?;
    let value = PersistentRecordValue::decode(record.table, opened.expose_for_storage_codec())
        .map_err(|_| Violation::Codec)?;
    let host = HostView {
        trusted_ack_unix_seconds: None,
        backing: context.backing_reservations(),
        origins: &coordinator.origins,
        peers: &coordinator.peers,
        revision: context.domain().revision().get(),
        peer,
        held_channels: BTreeSet::new(),
    };
    let executor = coordinator
        .companion_exec
        .as_mut()
        .ok_or(Violation::Codec)?;
    request
        .clone()
        .complete(
            executor,
            &record.key,
            &value,
            super::tick_millis(context.now()),
            &host,
        )
        .map_err(super::fault_violation)
}
