//! A confirmed empty read can become an empty fetch; failed storage can never do so.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::StorageReadCompletionMessage;
use agenc_ircd_storage::PersistentRecordValue;

pub(super) const RAW_BYTES: usize = agenc_ircd_storage::MAX_SEALED_RECORD_BYTES + 8_192;
pub(super) const DECODE_BYTES: usize = agenc_ircd_storage::MAX_SEALED_RECORD_BYTES * 3 + 8_192;

struct Completed {
    message: StorageReadCompletionMessage,
    pending: Box<Pending>,
}

pub(in super::super) fn completed(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    message: StorageReadCompletionMessage,
) {
    if !owns(coordinator, message.read_id) {
        return;
    }
    let Some(pending) = coordinator.companion_object_read.take() else {
        return;
    };
    let completed = Completed { message, pending };
    let result = admit(coordinator, context, &completed);
    let Completed { message, pending } = completed;
    drop(message);
    let Pending {
        operation,
        identity,
        link,
        _metadata,
        _raw,
        _decode,
        ..
    } = *pending;
    drop((_raw, _decode));
    let result = result.and_then(|resolved| {
        companion::run_with_object(
            coordinator,
            context,
            link,
            identity.peer,
            operation.complete,
            Some(&resolved),
        )
    });
    if let Err(error) = result
        && coordinator.link_is_live(link, identity.peer)
        && !context.is_quiescing()
    {
        coordinator.fail_link(context, link, identity.peer, error);
    }
    if !context.is_quiescing() {
        companion::drain_queued(coordinator, context);
        coordinator.drain_backlog(context);
    }
}

fn admit(
    coordinator: &FederationCoordinator,
    context: &StateCoreContext,
    completed: &Completed,
) -> Result<Resolved, Violation> {
    super::validate(coordinator, context, &completed.pending)?;
    let result = completed
        .message
        .result
        .as_ref()
        .map_err(|_| Violation::Ceiling)?;
    if result.storage_commit_sequence != completed.pending.commit {
        return Err(Violation::Phase);
    }
    if result.truncated || result.records.len() > 1 {
        return Err(Violation::Codec);
    }
    let mut records = Vec::new();
    for row in &result.records {
        if row.table != TableId::E2eeObject
            || row.sealed_record.len() > agenc_ircd_storage::MAX_SEALED_RECORD_BYTES
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
    Resolved::admit(
        completed.pending.operation.request,
        records,
        &context.backing_reservations(),
    )
    .map_err(companion::fault_violation)
}
