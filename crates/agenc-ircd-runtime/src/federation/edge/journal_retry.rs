//! Paced retries of journal writes whose admission definitely failed.

use agenc_ircd_domain::DomainError;
use agenc_ircd_storage::StorageError;
use agenc_ircd_types::MonotonicTick;

use super::{EdgeFederation, Violation, journal};
use crate::connection::sink::QueueAllocationError;
use crate::federation::LinkId;
use crate::state_core::fanout::FanoutRefused;
use crate::state_core::timers::{TimedId, TimerEntry, TimerGeneration, TimerKind};
use crate::state_core::{StageRefused, StateCoreContext};

const RETRY_MILLIS: u64 = 1_000;

/// A refusal closes new admission until every retained change is durable.
#[derive(Default)]
pub(super) struct Retry {
    pub(super) recovering: bool,
    pub(super) waiting: Option<TimerGeneration>,
    scheduling_failed: bool,
    last_link: Option<LinkId>,
}

pub(super) const fn stage_retryable(error: &StageRefused) -> bool {
    matches!(
        error,
        StageRefused::Busy
            | StageRefused::Domain(DomainError::ServerBusy)
            | StageRefused::Fanout(FanoutRefused::MemoryExhausted)
            | StageRefused::Fanout(FanoutRefused::Prepare(
                QueueAllocationError::AllocationFailed
            ))
    )
}

pub(super) const fn storage_retryable(error: StorageError) -> bool {
    matches!(
        error,
        StorageError::QueueFull | StorageError::AllocationFailed | StorageError::FilesystemRejected
    )
}

/// Never called with an indeterminate receipt: StateCore stops before dispatch.
pub(super) fn rejected(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    error: StorageError,
) {
    if storage_retryable(error) {
        defer(edge, context);
    } else {
        edge.fail_link(context, Violation::Ceiling);
    }
}

pub(super) fn defer(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    edge.journal.retry.recovering = true;
    if context.is_quiescing() {
        cancel(edge, context);
        return;
    }
    if edge.journal.retry.waiting.is_some() || edge.journal.retry.scheduling_failed {
        return;
    }
    if schedule(edge, context).is_err() {
        edge.journal.retry.scheduling_failed = true;
        if let Some(live) = &edge.live {
            edge.journal.retry.last_link = Some(live.link);
        }
        edge.fail_link(context, Violation::Ceiling);
    }
}

/// A stale establishment cannot reset the retry owned by a newer attempt.
pub(super) fn observe_link(edge: &mut EdgeFederation, link: LinkId) -> bool {
    if edge
        .journal
        .retry
        .last_link
        .is_some_and(|previous| previous >= link)
    {
        return false;
    }
    edge.journal.retry.last_link = Some(link);
    true
}

/// Authentication is a later actor event, outside rejected-batch callbacks.
pub(super) fn link_reestablished(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
) -> bool {
    if !edge.journal.retry.scheduling_failed {
        return true;
    }
    edge.journal.retry.scheduling_failed = false;
    defer(edge, context);
    !edge.journal.retry.scheduling_failed
}

fn schedule(edge: &mut EdgeFederation, context: &mut StateCoreContext) -> Result<(), Violation> {
    let deadline = context
        .now()
        .get()
        .checked_add(RETRY_MILLIS)
        .ok_or(Violation::Ceiling)?;
    let generation = context.timers_mut().schedule(
        MonotonicTick::from_ticks(deadline),
        TimerKind::FederationJournalRetry,
        TimedId::Peer(edge.config.coordinator.server_id()),
    )?;
    edge.journal.retry.waiting = Some(generation);
    Ok(())
}

pub(super) fn cancel(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    context.timers_mut().cancel(
        TimerKind::FederationJournalRetry,
        TimedId::Peer(edge.config.coordinator.server_id()),
    );
    edge.journal.retry.waiting = None;
}

pub(super) fn recovered(edge: &mut EdgeFederation, context: &mut StateCoreContext) {
    cancel(edge, context);
    edge.journal.retry.recovering = false;
    edge.journal.retry.scheduling_failed = false;
}

pub(super) fn timer_fired(
    edge: &mut EdgeFederation,
    context: &mut StateCoreContext,
    entry: TimerEntry,
) -> bool {
    if entry.kind != TimerKind::FederationJournalRetry
        || entry.id != TimedId::Peer(edge.config.coordinator.server_id())
    {
        return false;
    }
    if edge.journal.retry.waiting != Some(entry.generation) {
        return true;
    }
    edge.journal.retry.waiting = None;
    journal::retry_write(edge, context);
    true
}
