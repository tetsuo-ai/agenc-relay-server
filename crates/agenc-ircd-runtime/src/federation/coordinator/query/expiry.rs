//! The existing idle and absolute cursor limits release quiet query owners.

#![forbid(unsafe_code)]

use super::*;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};

pub(super) fn deadline(
    created: MonotonicTick,
    now: MonotonicTick,
) -> Result<MonotonicTick, DomainError> {
    let idle = now
        .get()
        .checked_add(agenc_ircd_types::QUERY_CURSOR_SECONDS * 1_000);
    let absolute = created
        .get()
        .checked_add(agenc_ircd_types::QUERY_SNAPSHOT_ABSOLUTE_SECONDS * 1_000);
    Ok(MonotonicTick::from_ticks(
        idle.ok_or(DomainError::ServerBusy)?
            .min(absolute.ok_or(DomainError::ServerBusy)?),
    ))
}

impl Queries {
    pub(super) fn reserve_expiry(
        &mut self,
        context: &mut StateCoreContext,
        deadline: MonotonicTick,
    ) -> Result<(), DomainError> {
        if self
            .expiry_armed
            .is_some_and(|(armed, _)| armed <= deadline)
        {
            return Ok(());
        }
        let generation = context
            .timers_mut()
            .schedule(deadline, TimerKind::DirectoryQueryExpiry, TimedId::Global)
            .map_err(|_| DomainError::ServerBusy)?;
        self.expiry_armed = Some((deadline, generation));
        Ok(())
    }

    pub(in super::super) fn timer_fired(
        &mut self,
        context: &mut StateCoreContext,
        entry: TimerEntry,
    ) -> bool {
        if entry.kind != TimerKind::DirectoryQueryExpiry || entry.id != TimedId::Global {
            return false;
        }
        if self.expiry_armed != Some((entry.deadline, entry.generation)) {
            return true;
        }
        self.expiry_armed = None;
        self.expire(context.now().max(entry.deadline));
        let next = self.retained.values().map(|value| value.expires_at).min();
        if let Some(next) = next
            && self.reserve_expiry(context, next).is_err()
        {
            // No retained backing may survive without its expiry owner.
            self.cursors = QueryCursorTable::new();
            self.retained.clear();
        }
        true
    }
}
