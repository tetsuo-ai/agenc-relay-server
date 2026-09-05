//! History rows are prepared with a domain mutation and published only after its commit.

#[cfg(all(test, feature = "history"))]
mod tests;

use std::collections::BTreeMap;

use agenc_ircd_domain::federation::{MutationContext, SourceView};
use agenc_ircd_domain::{
    ChannelScope, ContentPolicy, DomainState, DurableWrite, HistoryPolicy, MessageKind,
    MutationPlan, PersistencePolicy, ResolvedMessageTarget, Visibility,
};
use agenc_ircd_storage::history_records::{
    HISTORY_CONTROL_KIND, HISTORY_MESSAGE_KIND, HistoryControlRecord, HistoryMessageRecord,
    HistoryPurgeState, history_control_key, history_message_key,
};
use agenc_ircd_storage::{
    MIN_SEALED_RECORD_BYTES, PersistentRecordValue, RecordReference, StoredKey, TableId,
    logical_record_charge,
};
use agenc_ircd_types::ChannelInstanceId;

use crate::RuntimeError;
use crate::budget::MemoryPermit;
use crate::state_core::durable::AccountServiceDurableWrite;

use super::index::row_reference;
use super::{
    CONTROL_WORKING_CHARGE, DECODE_WORKING_CHARGE, HistoryChannel, HistoryRow, HistoryState,
    INDEX_ENTRY_CHARGE, MAX_CHANNEL_BYTES, MAX_CHANNEL_MESSAGES, MAX_CHANNELS, MAX_MESSAGES,
    acquire, corrupt, retention_seconds,
};

pub(crate) struct HistoryMutation {
    pub(super) changes: BTreeMap<ChannelInstanceId, ChannelChange>,
    pub(super) added_rows: u64,
    pub(super) added_bytes: u64,
    pub(super) added_index_bytes: u64,
    pub(super) removed_rows: u64,
    pub(super) removed_bytes: u64,
    pub(super) removed_index_bytes: u64,
    pub(super) _working: Vec<MemoryPermit>,
}

pub(super) struct ChannelChange {
    pub(super) control: HistoryControlRecord,
    pub(super) new_control_permit: Option<MemoryPermit>,
    pub(super) rows: Vec<HistoryRow>,
    pub(super) deleted: Vec<u64>,
    pub(super) remove_control: bool,
}

impl HistoryMutation {
    pub(super) fn new() -> Self {
        Self {
            changes: BTreeMap::new(),
            added_rows: 0,
            added_bytes: 0,
            added_index_bytes: 0,
            removed_rows: 0,
            removed_bytes: 0,
            removed_index_bytes: 0,
            _working: Vec::new(),
        }
    }
}

impl HistoryState {
    pub(crate) fn prepare(
        &self,
        domain: &DomainState,
        plan: &MutationPlan,
        intent: &MutationContext,
        wall_trusted: bool,
        accepting_generation: u64,
    ) -> Result<(Vec<AccountServiceDurableWrite>, Option<HistoryMutation>), RuntimeError> {
        let mut pending = HistoryMutation::new();
        let mut writes = Vec::new();
        if !self.coordinator {
            return Ok((writes, None));
        }
        for write in plan.durable_writes() {
            self.prepare_policy(domain, write, accepting_generation, &mut pending)?;
        }
        let input = CaptureInput {
            domain,
            plan,
            intent,
            wall_trusted,
            accepting_generation,
        };
        if self.enabled
            && let Some(batch) = plan.message_batch()
        {
            for route in batch.routes() {
                if let Some((message, permit)) = self.prepare_message(&input, route)? {
                    pending._working.push(permit);
                    self.admit_message(
                        &mut pending,
                        message,
                        &mut writes,
                        plan.resulting_revision().get(),
                    )?;
                }
            }
        }
        if self
            .message_count
            .checked_add(pending.added_rows)
            .ok_or(RuntimeError::Overflow)?
            > MAX_MESSAGES
            || self
                .logical_bytes
                .checked_add(pending.added_bytes)
                .ok_or(RuntimeError::Overflow)?
                > self.maximum_bytes
        {
            return Err(RuntimeError::LimitExceeded);
        }
        for (id, change) in &pending.changes {
            let plaintext = encode_row(
                *id,
                HISTORY_CONTROL_KIND,
                plan.resulting_revision().get(),
                None,
                change.control.encode()?,
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::History,
                history_control_key(*id)?,
                plaintext,
            )?);
        }
        Ok((writes, (!pending.changes.is_empty()).then_some(pending)))
    }

    fn prepare_policy(
        &self,
        domain: &DomainState,
        write: &DurableWrite,
        revision: u64,
        pending: &mut HistoryMutation,
    ) -> Result<(), RuntimeError> {
        let channel_id = match write {
            DurableWrite::PutChannel(channel) => {
                if !self.policy_needs_control(domain, channel)? {
                    return Ok(());
                }
                channel.channel_id
            }
            DurableWrite::TombstoneChannel { channel_id, .. }
                if self.channels.contains_key(channel_id) =>
            {
                *channel_id
            }
            _ => return Ok(()),
        };
        self.change(pending, channel_id, revision)?
            .control
            .history_authorization_generation = revision;
        Ok(())
    }

    fn policy_needs_control(
        &self,
        domain: &DomainState,
        channel: &agenc_ircd_domain::DurableChannel,
    ) -> Result<bool, RuntimeError> {
        if channel.content_policy != ContentPolicy::Plaintext
            && self.has_messages_or_purge(channel.channel_id)
        {
            return Err(corrupt());
        }
        let old = domain.channel(channel.channel_id);
        let enabling = channel.history != HistoryPolicy::Off
            && old.is_none_or(|old| old.history_policy() != channel.history);
        if enabling && !self.enabled {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(enabling
            || (self.channels.contains_key(&channel.channel_id) && policy_changed(domain, channel)))
    }

    fn prepare_message(
        &self,
        input: &CaptureInput<'_>,
        route: &agenc_ircd_domain::MessageRoute,
    ) -> Result<Option<(HistoryMessageRecord, MemoryPermit)>, RuntimeError> {
        let batch = input.plan.message_batch().ok_or_else(corrupt)?;
        if !matches!(batch.kind(), MessageKind::Privmsg | MessageKind::Notice) {
            return Ok(None);
        }
        let ResolvedMessageTarget::Channel(channel_id) = route.target() else {
            return Ok(None);
        };
        let channel = input.domain.channel(channel_id).ok_or_else(corrupt)?;
        let Some(seconds) = retention_seconds(channel.history_policy()) else {
            return Ok(None);
        };
        validate_message_channel(input, channel)?;
        let permit = acquire(&self.budget, DECODE_WORKING_CHARGE)?;
        let sender = input.domain.session(batch.sender()).ok_or_else(corrupt)?;
        let received = batch
            .accepted_at()
            .get()
            .checked_mul(1_000)
            .ok_or(RuntimeError::Overflow)?;
        if received == 0
            || (input.intent.received_unix_milliseconds != 0
                && input.intent.received_unix_milliseconds != received)
        {
            return Err(corrupt());
        }
        let expires = received
            .checked_add(u64::from(seconds) * 1_000)
            .ok_or(RuntimeError::Overflow)?;
        let message = HistoryMessageRecord {
            channel_id,
            channel_sequence: input.accepting_generation,
            message_id: route.message_id(),
            received_unix_milliseconds: received,
            expires_unix_milliseconds: expires,
            retention_seconds: seconds,
            channel_name: channel.name().clone(),
            sender: SourceView {
                user_id: batch.sender(),
                nickname: sender.nickname().clone(),
                public_cloak: sender.public_cloak(),
                account_label: sender
                    .account_id()
                    .and_then(|id| input.domain.account(id))
                    .and_then(|account| account.label())
                    .cloned(),
            },
            kind: batch.kind(),
            tags: input.intent.client_tags.clone(),
            body: batch.body().unwrap_or("").to_owned(),
        };
        Ok(Some((message, permit)))
    }

    fn admit_message(
        &self,
        pending: &mut HistoryMutation,
        message: HistoryMessageRecord,
        writes: &mut Vec<AccountServiceDurableWrite>,
        revision: u64,
    ) -> Result<(), RuntimeError> {
        let key = history_message_key(message.channel_id, message.channel_sequence)?;
        let plaintext = encode_row(
            message.channel_id,
            HISTORY_MESSAGE_KIND,
            revision,
            Some(message.expires_unix_milliseconds.div_ceil(1_000)),
            message.encode()?,
        )?;
        let logical_bytes = logical_record_charge(
            key.as_bytes().len(),
            plaintext
                .len()
                .checked_add(MIN_SEALED_RECORD_BYTES)
                .ok_or(RuntimeError::Overflow)?,
        )?;
        let permit = self.reserve_pending_entry(pending)?;
        let change = self.change(pending, message.channel_id, message.channel_sequence)?;
        if message.channel_sequence <= change.control.high_water_sequence {
            return Err(corrupt());
        }
        change.control.high_water_sequence = message.channel_sequence;
        change.control.retained_message_count = change
            .control
            .retained_message_count
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        change.control.retained_logical_bytes = change
            .control
            .retained_logical_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeError::Overflow)?;
        if change.control.retained_message_count > MAX_CHANNEL_MESSAGES
            || change.control.retained_logical_bytes > MAX_CHANNEL_BYTES
        {
            return Err(RuntimeError::LimitExceeded);
        }
        change.rows.push(HistoryRow {
            reference: row_reference(&message),
            logical_bytes,
            _permit: permit,
        });
        pending.added_rows = pending
            .added_rows
            .checked_add(1)
            .ok_or(RuntimeError::Overflow)?;
        pending.added_bytes = pending
            .added_bytes
            .checked_add(logical_bytes)
            .ok_or(RuntimeError::Overflow)?;
        writes.push(AccountServiceDurableWrite::put(
            TableId::History,
            key,
            plaintext,
        )?);
        Ok(())
    }

    pub(super) fn change<'a>(
        &self,
        pending: &'a mut HistoryMutation,
        channel_id: ChannelInstanceId,
        revision: u64,
    ) -> Result<&'a mut ChannelChange, RuntimeError> {
        if !pending.changes.contains_key(&channel_id) {
            pending
                ._working
                .push(acquire(&self.budget, CONTROL_WORKING_CHARGE)?);
            let (control, new_control_permit) =
                self.control_for_change(pending, channel_id, revision)?;
            pending.changes.insert(
                channel_id,
                ChannelChange {
                    control,
                    new_control_permit,
                    rows: Vec::new(),
                    deleted: Vec::new(),
                    remove_control: false,
                },
            );
        }
        pending.changes.get_mut(&channel_id).ok_or_else(corrupt)
    }

    fn control_for_change(
        &self,
        pending: &mut HistoryMutation,
        channel_id: ChannelInstanceId,
        revision: u64,
    ) -> Result<(HistoryControlRecord, Option<MemoryPermit>), RuntimeError> {
        if let Some(channel) = self.channels.get(&channel_id) {
            return Ok((channel.control.clone(), None));
        }
        let added = pending
            .changes
            .values()
            .filter(|change| change.new_control_permit.is_some())
            .count();
        if self
            .channels
            .len()
            .checked_add(added)
            .ok_or(RuntimeError::Overflow)?
            >= MAX_CHANNELS
        {
            return Err(RuntimeError::LimitExceeded);
        }
        Ok((
            HistoryControlRecord::empty(channel_id, revision)?,
            Some(self.reserve_pending_entry(pending)?),
        ))
    }

    fn reserve_pending_entry(
        &self,
        pending: &mut HistoryMutation,
    ) -> Result<MemoryPermit, RuntimeError> {
        let added = pending
            .added_index_bytes
            .checked_add(INDEX_ENTRY_CHARGE)
            .ok_or(RuntimeError::Overflow)?;
        if self
            .index_bytes
            .checked_add(added)
            .ok_or(RuntimeError::Overflow)?
            > self.maximum_index_bytes
        {
            return Err(RuntimeError::LimitExceeded);
        }
        let permit = acquire(&self.budget, INDEX_ENTRY_CHARGE)?;
        pending.added_index_bytes = added;
        Ok(permit)
    }

    pub(crate) fn committed(&mut self, pending: HistoryMutation) -> Result<(), RuntimeError> {
        for (id, change) in pending.changes {
            self.commit_channel(id, change)?;
        }
        self.message_count = self
            .message_count
            .checked_sub(pending.removed_rows)
            .and_then(|count| count.checked_add(pending.added_rows))
            .ok_or(RuntimeError::Overflow)?;
        self.logical_bytes = self
            .logical_bytes
            .checked_sub(pending.removed_bytes)
            .and_then(|bytes| bytes.checked_add(pending.added_bytes))
            .ok_or(RuntimeError::Overflow)?;
        self.index_bytes = self
            .index_bytes
            .checked_sub(pending.removed_index_bytes)
            .and_then(|bytes| bytes.checked_add(pending.added_index_bytes))
            .ok_or(RuntimeError::Overflow)?;
        Ok(())
    }

    fn commit_channel(
        &mut self,
        id: ChannelInstanceId,
        change: ChannelChange,
    ) -> Result<(), RuntimeError> {
        if change.remove_control {
            let channel = self.channels.remove(&id).ok_or_else(corrupt)?;
            if !channel.rows.is_empty() {
                return Err(corrupt());
            }
            return Ok(());
        }
        if let Some(channel) = self.channels.get_mut(&id) {
            channel.control = change.control;
            for sequence in change.deleted {
                if channel.rows.remove(&sequence).is_none() {
                    return Err(corrupt());
                }
            }
            for row in change.rows {
                if channel
                    .rows
                    .insert(row.reference.channel_sequence, row)
                    .is_some()
                {
                    return Err(corrupt());
                }
            }
            return Ok(());
        }
        let permit = change.new_control_permit.ok_or_else(corrupt)?;
        let rows = change
            .rows
            .into_iter()
            .map(|row| (row.reference.channel_sequence, row))
            .collect();
        self.channels.insert(
            id,
            HistoryChannel {
                control: change.control,
                rows,
                available_results: 0,
                _permit: permit,
            },
        );
        Ok(())
    }

    pub(crate) fn has_messages_or_purge(&self, channel_id: ChannelInstanceId) -> bool {
        self.channels.get(&channel_id).is_some_and(|channel| {
            channel.control.retained_message_count != 0
                || channel.control.purge != HistoryPurgeState::Idle
        })
    }
}

pub(super) fn encode_row(
    channel: ChannelInstanceId,
    kind: u16,
    revision: u64,
    expiry: Option<u64>,
    body: Vec<u8>,
) -> Result<Vec<u8>, RuntimeError> {
    Ok(PersistentRecordValue::new(
        TableId::History,
        kind,
        revision,
        1,
        expiry,
        vec![RecordReference::new(
            TableId::Channel,
            StoredKey::new(channel.as_bytes().to_vec())?,
        )?],
        body,
    )?
    .encode()?)
}

struct CaptureInput<'a> {
    domain: &'a DomainState,
    plan: &'a MutationPlan,
    intent: &'a MutationContext,
    wall_trusted: bool,
    accepting_generation: u64,
}

fn validate_message_channel(
    input: &CaptureInput<'_>,
    channel: &agenc_ircd_domain::ChannelState,
) -> Result<(), RuntimeError> {
    if !input.wall_trusted
        || channel.scope() != ChannelScope::Global
        || channel.visibility() != Visibility::Listed
        || channel.persistence_policy() != PersistencePolicy::Registered
        || channel.content_policy() != ContentPolicy::Plaintext
        || input.domain.channel_is_quarantined(channel.channel_id())
    {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(())
}

fn policy_changed(domain: &DomainState, channel: &agenc_ircd_domain::DurableChannel) -> bool {
    domain.channel(channel.channel_id).is_some_and(|old| {
        old.history_policy() != channel.history
            || old.content_policy() != channel.content_policy
            || old.visibility() != channel.visibility
            || old.persistence_policy() != channel.persistence
            || domain.channel_is_quarantined(channel.channel_id) != channel.admin_quarantined
    })
}
