//! Conservative complete working-set admission before any aggregate allocation.

use super::super::{EdgeFederation, events::QueuedEvent};
use super::Refused;
use crate::RuntimeError;
use crate::budget::MemoryPermit;
use crate::state_core::StateCoreContext;
use agenc_relay_storage::TableId;

// One encoded field may become a typed value, tree node, owned map key and
// temporary encoder value in several simultaneous representations. This bound
// includes those representations, final rows, and the storage preflight copy.
const REPRESENTATION_FACTOR: usize = 256;
const ENTRY_OVERHEAD: usize = 2_048;
// The ordinary renderer emits at most one bounded wire message per recipient.
// Covers strings, tags, frame maps, sorted groups and their temporary clones.
const FRAME_BACKING: usize = 32_768;

pub(super) fn reserve(
    edge: &EdgeFederation,
    context: &StateCoreContext,
    count: usize,
) -> Result<MemoryPermit, Refused> {
    let (stored_bytes, stored_rows) = context.index().table_backing(TableId::EdgeProjection)?;
    let payload = input_bytes(edge, count)?;
    let entries = edge
        .replica
        .entry_count()
        .max(stored_rows)
        .checked_add(edge.nicknames.len())
        .ok_or(RuntimeError::Overflow)?;
    let structural = entries
        .checked_mul(ENTRY_OVERHEAD)
        .ok_or(RuntimeError::Overflow)?;
    let representations = stored_bytes
        .checked_add(payload)
        .and_then(|bytes| bytes.checked_mul(REPRESENTATION_FACTOR))
        .and_then(|bytes| bytes.checked_add(structural))
        .ok_or(RuntimeError::Overflow)?;
    let recipient_events = count
        .checked_mul(context.sessions().len())
        .ok_or(RuntimeError::Overflow)?;
    let frames = recipient_events
        .min(crate::state_core::fanout::MAX_FANOUT_FRAMES)
        .checked_mul(FRAME_BACKING)
        .ok_or(RuntimeError::Overflow)?;
    let recipients = recipient_events
        .checked_mul(64)
        .ok_or(RuntimeError::Overflow)?;
    let metadata = count
        .checked_mul(ENTRY_OVERHEAD)
        .ok_or(RuntimeError::Overflow)?;
    let bytes = representations
        .checked_add(frames)
        .and_then(|bytes| bytes.checked_add(recipients))
        .and_then(|bytes| bytes.checked_add(metadata))
        .ok_or(RuntimeError::Overflow)?;
    Ok(context.reserve_output_backing(bytes)?)
}

fn input_bytes(edge: &EdgeFederation, count: usize) -> Result<usize, Refused> {
    edge.queued_events
        .iter()
        .take(count)
        .try_fold(0_usize, |bytes, event| {
            let QueuedEvent::Base {
                header,
                encoded_bytes,
                ..
            } = event
            else {
                return Err(Refused::Protocol(super::super::Violation::Consistency));
            };
            let request = header
                .correlation
                .and_then(|correlation| edge.pending.get(&correlation.request_id));
            let request_bytes = request.map_or(Ok(0), |request| {
                request
                    .bytes
                    .len()
                    .checked_add(request.result_bytes.len())
                    .ok_or(RuntimeError::Overflow)
            })?;
            bytes
                .checked_add(*encoded_bytes)
                .and_then(|bytes| bytes.checked_add(request_bytes))
                .ok_or_else(|| RuntimeError::Overflow.into())
        })
}
