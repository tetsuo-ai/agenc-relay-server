//! Receipt-atomic ordinary prefixes, with complete resource admission.

mod backing;
mod prepare;

use super::{EdgeCompletion, EdgeFederation, PendingCommit, Violation, events, join_echo, journal};
use crate::RuntimeError;
use crate::budget::MemoryPermit;
use crate::federation::LinkId;
use crate::federation::link::ReservedFrames;
use crate::state_core::{StateCoreContext, edge_checkpoint::CheckpointRefused};
use agenc_ircd_federation_wire::EventHeader;
use agenc_ircd_types::RequestId;

pub(super) struct EventReceipt {
    pub(super) header: EventHeader,
    pub(super) completion: Option<RequestId>,
}

pub(super) struct Pending {
    pub(super) staged_after: u64,
    pub(super) link: LinkId,
    pub(super) receipts: Vec<EventReceipt>,
    pub(super) coverage: Vec<journal::Version>,
    pub(super) echoes: Vec<join_echo::JoinEcho>,
    pub(super) acknowledgements: Option<ReservedFrames>,
    // Covers new preparation containers and rows until their shared receipt.
    pub(super) _backing: MemoryPermit,
}

pub(super) enum Refused {
    Resource,
    Busy,
    Protocol(Violation),
}

impl From<RuntimeError> for Refused {
    fn from(error: RuntimeError) -> Self {
        match error {
            RuntimeError::MemoryExhausted | RuntimeError::LimitExceeded => Self::Resource,
            _ => Self::Protocol(Violation::Consistency),
        }
    }
}

impl From<Violation> for Refused {
    fn from(error: Violation) -> Self {
        Self::Protocol(error)
    }
}

impl From<CheckpointRefused> for Refused {
    fn from(error: CheckpointRefused) -> Self {
        match error {
            CheckpointRefused::Resource => Self::Resource,
            CheckpointRefused::Busy => Self::Busy,
            CheckpointRefused::Invalid => Self::Protocol(Violation::Consistency),
        }
    }
}

/// Tries only the contiguous ordinary prefix; one remaining event keeps its
/// original admission and slow-consumer policy. No prefix is consumed on refusal.
pub(super) fn try_stage(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> Result<bool, Violation> {
    let mut count = edge
        .queued_events
        .iter()
        .take_while(|event| matches!(event, events::QueuedEvent::Base { .. }))
        .count();
    while count > 1 {
        match prepare::stage(edge, context, count) {
            Ok(()) => return Ok(true),
            Err(Refused::Resource) => count /= 2,
            Err(Refused::Busy) => return Ok(true),
            Err(Refused::Protocol(violation)) => return Err(violation),
        }
    }
    Ok(false)
}

/// Receipt ownership precedes every client completion or acknowledgment.
pub(super) fn committed(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    mut pending: Pending,
) -> Vec<EdgeCompletion> {
    if pending.staged_after.checked_add(1) != Some(context.head().storage_commit_sequence) {
        pending.acknowledgements = None;
        edge.event_before = None;
        edge.fail_link(context, Violation::Consistency);
        return Vec::new();
    }
    edge.event_before = None;
    if let Err(violation) = commit_private(edge, &mut pending) {
        pending.acknowledgements = None;
        edge.fail_link(context, violation);
        return Vec::new();
    }
    let Some(last) = pending.receipts.last() else {
        return Vec::new();
    };
    edge.cursor = Some((last.header.delivery_sequence, last.header.event_id));
    edge.counters.events_applied = edge
        .counters
        .events_applied
        .saturating_add(u64::try_from(pending.receipts.len()).unwrap_or(u64::MAX));
    if edge.link_is(pending.link)
        && let Some(acknowledgements) = pending.acknowledgements.take()
        && acknowledgements.publish().is_err()
    {
        edge.link_closed(context, pending.link);
    }
    let mut completions = Vec::new();
    for receipt in &pending.receipts {
        if let Some(request) = receipt.completion {
            completions.extend(events::committed_completion(
                edge,
                context,
                receipt.header.event_id,
                request,
                receipt.header.coordinator_state_generation,
            ));
        }
    }
    // A replacement link deferred its resume while this receipt owned the replica.
    if !edge.link_is(pending.link) && edge.live.is_some() {
        edge.begin_link_sync(context);
    }
    completions
}

fn commit_private(edge: &mut EdgeFederation, pending: &mut Pending) -> Result<(), Violation> {
    for version in std::mem::take(&mut pending.coverage) {
        journal::completion_committed(edge, version)?;
    }
    for echo in std::mem::take(&mut pending.echoes) {
        join_echo::committed(edge, echo)?;
    }
    Ok(())
}

pub(super) fn release_acknowledgements(edge: &mut EdgeFederation) {
    if let Some(PendingCommit::OrdinaryBatch(pending)) = edge.commit.as_mut() {
        pending.acknowledgements = None;
    }
}
