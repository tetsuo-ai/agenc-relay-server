//! Purge cutoffs and bounded physical expiry use the same durable history delta.

use agenc_relay_domain::{DomainState, HistoryPolicy};
use agenc_relay_storage::{
    TableId,
    history_records::{
        HISTORY_CONTROL_KIND, HistoryPurgeState, history_control_key, history_message_key,
    },
};
use agenc_relay_types::ChannelInstanceId;

use crate::RuntimeError;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::FanoutRequest;
use crate::state_core::{DurableAdmission, StageRefused, Staging, StateCore, StateCoreContext};

use super::capture::encode_row;
use super::{HistoryMutation, HistoryState, INDEX_ENTRY_CHARGE, acquire, corrupt};

const MAX_DELETIONS: usize = 1_000;
const DELETE_WORKING_BYTES: u64 = 8_388_608;

impl HistoryState {
    pub(crate) fn prepare_purge(
        &self,
        channel_id: ChannelInstanceId,
        revision: u64,
        operation_id: [u8; 32],
        audit_intent_sequence: u64,
        generation: u64,
    ) -> Result<(Vec<AccountServiceDurableWrite>, HistoryMutation), RuntimeError> {
        if !self.coordinator || operation_id == [0; 32] {
            return Err(corrupt());
        }
        let mut pending = HistoryMutation::new();
        let change = self.change(&mut pending, channel_id, generation)?;
        if change.control.purge != HistoryPurgeState::Idle {
            return Err(RuntimeError::LimitExceeded);
        }
        change.control.history_authorization_generation = generation;
        change.control.purged_through = change.control.high_water_sequence;
        if change.control.retained_message_count != 0 {
            change.control.purge = HistoryPurgeState::Active {
                cutoff_sequence: change.control.high_water_sequence,
                last_scanned_sequence: 0,
                operation_id,
                audit_intent_sequence,
            };
        }
        let write = control_write(channel_id, revision, &change.control)?;
        Ok((vec![write], pending))
    }

    pub(crate) fn prepare_admin_authority_change(
        &self,
        channel_id: ChannelInstanceId,
        revision: u64,
        generation: u64,
    ) -> Result<Option<(Vec<AccountServiceDurableWrite>, HistoryMutation)>, RuntimeError> {
        if !self.coordinator || !self.channels.contains_key(&channel_id) {
            return Ok(None);
        }
        let mut pending = HistoryMutation::new();
        let change = self.change(&mut pending, channel_id, generation)?;
        change.control.history_authorization_generation = generation;
        let write = control_write(channel_id, revision, &change.control)?;
        Ok(Some((vec![write], pending)))
    }

    pub(crate) fn purge_complete(&self, channel_id: ChannelInstanceId) -> bool {
        self.channels
            .get(&channel_id)
            .is_none_or(|channel| channel.control.purge == HistoryPurgeState::Idle)
    }

    fn prepare_cleanup(
        &self,
        domain: &DomainState,
        now: u64,
        revision: u64,
    ) -> Result<Option<(Vec<AccountServiceDurableWrite>, HistoryMutation)>, RuntimeError> {
        if !self.coordinator {
            return Ok(None);
        }
        let selected = self
            .channels
            .iter()
            .find(|(id, channel)| self.needs_cleanup(domain, **id, channel, now));
        let Some((id, channel)) = selected else {
            return Ok(None);
        };
        let mut pending = HistoryMutation::new();
        pending
            ._working
            .push(acquire(&self.budget, DELETE_WORKING_BYTES)?);
        let change = self.change(&mut pending, *id, revision)?;
        let mut writes = Vec::new();
        if channel.rows.is_empty() && channel.control.purge == HistoryPurgeState::Idle {
            change.remove_control = true;
            pending.removed_index_bytes = INDEX_ENTRY_CHARGE;
            writes.push(AccountServiceDurableWrite::delete(
                TableId::History,
                history_control_key(*id)?,
            )?);
            return Ok(Some((writes, pending)));
        }
        let cutoff = match channel.control.purge {
            HistoryPurgeState::Idle => 0,
            HistoryPurgeState::Active {
                cutoff_sequence, ..
            } => cutoff_sequence,
        };
        let bytes = append_deletions(*id, channel, change, cutoff, now, &mut writes)?;
        let removed = u64::try_from(change.deleted.len()).map_err(|_| RuntimeError::Overflow)?;
        change.control.retained_message_count = change
            .control
            .retained_message_count
            .checked_sub(removed)
            .ok_or_else(corrupt)?;
        change.control.retained_logical_bytes = change
            .control
            .retained_logical_bytes
            .checked_sub(bytes)
            .ok_or_else(corrupt)?;
        advance_purge(channel, change, cutoff);
        writes.push(control_write(*id, revision, &change.control)?);
        pending.removed_rows = removed;
        pending.removed_bytes = bytes;
        pending.removed_index_bytes = removed
            .checked_mul(INDEX_ENTRY_CHARGE)
            .ok_or(RuntimeError::Overflow)?;
        Ok(Some((writes, pending)))
    }

    fn needs_cleanup(
        &self,
        domain: &DomainState,
        id: ChannelInstanceId,
        channel: &super::HistoryChannel,
        now: u64,
    ) -> bool {
        if channel.control.purge != HistoryPurgeState::Idle
            || channel
                .rows
                .values()
                .any(|row| row.reference.expires_unix_milliseconds <= now)
        {
            return true;
        }
        channel.rows.is_empty()
            && channel.available_results == 0
            && self.queries.load(std::sync::atomic::Ordering::Acquire) == 0
            && domain
                .channel(id)
                .is_none_or(|channel| channel.history_policy() == HistoryPolicy::Off)
    }
}

fn control_write(
    id: ChannelInstanceId,
    revision: u64,
    control: &agenc_relay_storage::history_records::HistoryControlRecord,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    AccountServiceDurableWrite::put(
        TableId::History,
        history_control_key(id)?,
        encode_row(id, HISTORY_CONTROL_KIND, revision, None, control.encode()?)?,
    )
}

impl StateCoreContext {
    pub(crate) fn history_result_retained(
        &mut self,
        channel_id: ChannelInstanceId,
        add: bool,
    ) -> Result<(), RuntimeError> {
        let Some(history) = self.history.as_mut() else {
            return Ok(());
        };
        let Some(channel) = history.channels.get_mut(&channel_id) else {
            return Ok(());
        };
        let updated = if add {
            channel.available_results.checked_add(1)
        } else {
            channel.available_results.checked_sub(1)
        };
        let Some(updated) = updated else {
            history.enabled = false;
            return Err(corrupt());
        };
        channel.available_results = updated;
        Ok(())
    }

    fn stage_history_cleanup(&mut self) -> Result<(), RuntimeError> {
        if self.quiescing || self.pending.is_some() || !self.drift.wall_trusted() {
            return Ok(());
        }
        let Some(history) = &self.history else {
            return Ok(());
        };
        let now = self.history_now()?;
        let plan = self
            .domain
            .plan_account_service_checkpoint()
            .map_err(|_| corrupt())?;
        let Some((writes, history)) =
            history.prepare_cleanup(&self.domain, now, plan.resulting_revision().get())?
        else {
            return Ok(());
        };
        self.stage_prepared(Staging {
            plan,
            request: FanoutRequest::new(Vec::new(), Vec::new())?,
            origin: None,
            response_count_increment: 0,
            account_service_writes: writes,
            admission: DurableAdmission::Ordinary,
            projection: None,
            history: Some(history),
        })
        .map_err(|error| match error {
            StageRefused::Busy | StageRefused::Quiescing => RuntimeError::LimitExceeded,
            _ => corrupt(),
        })?;
        Ok(())
    }
}

impl StateCore {
    pub(in crate::state_core) fn maintain_history(&mut self) {
        self.complete_history_purge();
        if self.storage_in_flight()
            || self.reload_pending.is_some()
            || self.reload_provisional.is_some()
        {
            return;
        }
        // Resource pressure postpones deletion; expiry and purge predicates still hide rows.
        let _deferred = self.context.stage_history_cleanup();
    }
}

fn advance_purge(
    channel: &super::HistoryChannel,
    change: &mut super::capture::ChannelChange,
    cutoff: u64,
) {
    if let HistoryPurgeState::Active {
        last_scanned_sequence,
        ..
    } = &mut change.control.purge
    {
        *last_scanned_sequence = change
            .deleted
            .iter()
            .copied()
            .filter(|sequence| *sequence <= cutoff)
            .max()
            .unwrap_or(*last_scanned_sequence);
        if channel
            .rows
            .range(..=cutoff)
            .all(|(sequence, _)| change.deleted.contains(sequence))
        {
            change.control.purge = HistoryPurgeState::Idle;
        }
    }
}

#[cfg(test)]
mod tests;

fn append_deletions(
    id: ChannelInstanceId,
    channel: &super::HistoryChannel,
    change: &mut super::capture::ChannelChange,
    cutoff: u64,
    now: u64,
    writes: &mut Vec<AccountServiceDurableWrite>,
) -> Result<u64, RuntimeError> {
    let mut bytes = 0_u64;
    for (sequence, row) in channel
        .rows
        .iter()
        .filter(|(sequence, row)| {
            **sequence <= cutoff || row.reference.expires_unix_milliseconds <= now
        })
        .take(MAX_DELETIONS)
    {
        change.deleted.push(*sequence);
        bytes = bytes
            .checked_add(row.logical_bytes)
            .ok_or(RuntimeError::Overflow)?;
        writes.push(AccountServiceDurableWrite::delete(
            TableId::History,
            history_message_key(id, *sequence)?,
        )?);
    }
    Ok(bytes)
}
