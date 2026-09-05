//! Every history read remains bound to current authority and the original row identities.

use std::collections::btree_map;
use std::sync::atomic::{AtomicUsize, Ordering};

use agenc_ircd_domain::{
    AccountState, ChannelNameValue, ChannelScope, ChannelState, ContentPolicy, HistoryError,
    HistoryPolicy, HistoryPosition, HistoryQuery, HistorySelection, PersistencePolicy, Visibility,
    select_history_iter,
};
use agenc_ircd_storage::history_records::{
    HISTORY_MESSAGE_KIND, HistoryAuthorizationBinding, HistoryMessageRecord, HistoryRowReference,
    history_message_key,
};
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, ReadRecord, ReadResult, TableId, validate_record_plaintext,
};
use agenc_ircd_types::{ChannelInstanceId, SessionId, UserId};

use crate::RuntimeError;
use crate::bridge::StorageReadId;
use crate::budget::MemoryPermit;
use crate::state_core::session::BoundSession;
use crate::state_core::{StateCore, StateCoreContext};
use crate::sync::Arc;

use super::{HistoryRow, HistoryState, acquire, corrupt};

/// Seven maximum-sized IRC lines leave room for both batch boundaries within 64 KiB.
pub(crate) const HISTORY_PAGE_MESSAGES: usize = 7;
const SNAPSHOT_CHARGE: u64 = 16_384;
const PAGE_WORKING_CHARGE: u64 = 2_097_152;
const MAX_QUERIES: usize = 256;

pub(crate) struct HistorySnapshot {
    pub(crate) authorization: HistoryAuthorizationBinding,
    pub(crate) selection: HistorySelection,
    pub(crate) channel_id: ChannelInstanceId,
    pub(crate) channel_name: ChannelNameValue,
    pub(crate) snapshot_state_generation: u64,
    references: Vec<HistoryRowReference>,
    _permit: MemoryPermit,
    _query: QueryLease,
}

impl HistorySnapshot {
    pub(crate) fn references(&self) -> &[HistoryRowReference] {
        &self.references
    }
}

pub(crate) struct HistoryMaterialized {
    messages: Vec<HistoryMessageRecord>,
    _permit: MemoryPermit,
}

impl HistoryMaterialized {
    pub(crate) fn messages(&self) -> &[HistoryMessageRecord] {
        &self.messages
    }

    pub(crate) fn into_permit(self) -> MemoryPermit {
        let Self {
            messages,
            _permit: permit,
        } = self;
        drop(messages);
        permit
    }
}

struct SnapshotRequest {
    bound: BoundSession,
    channel_id: ChannelInstanceId,
    authorization: HistoryAuthorizationBinding,
    selection: HistorySelection,
    channel_name: ChannelNameValue,
    snapshot_state_generation: u64,
}

struct QueryLease(Arc<AtomicUsize>);

impl QueryLease {
    fn acquire(counter: &Arc<AtomicUsize>) -> Result<Self, RuntimeError> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1).filter(|count| *count <= MAX_QUERIES)
            })
            .map_err(|_| RuntimeError::LimitExceeded)?;
        Ok(Self(Arc::clone(counter)))
    }
}

impl Drop for QueryLease {
    fn drop(&mut self) {
        let _released = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            });
    }
}

#[derive(Clone)]
struct EligiblePositions<'a> {
    rows: btree_map::Values<'a, u64, HistoryRow>,
    now: u64,
    cutoff: u64,
    remaining: usize,
}

impl Iterator for EligiblePositions<'_> {
    type Item = HistoryPosition;
    fn next(&mut self) -> Option<Self::Item> {
        for row in self.rows.by_ref() {
            if row.reference.expires_unix_milliseconds > self.now
                && row.reference.channel_sequence > self.cutoff
            {
                self.remaining = self.remaining.saturating_sub(1);
                // Metadata positions were validated before index insertion.
                return row.position().ok();
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for EligiblePositions<'_> {}

impl StateCore {
    pub(crate) fn install_history(&mut self, history: HistoryState) {
        self.context.history = Some(history);
    }
}

impl StateCoreContext {
    pub(crate) fn history_clock_safe(&self) -> bool {
        self.utc_now()
            .is_ok_and(|wall| self.drift.accepts_wall(self.now(), wall))
    }

    pub(crate) fn history_enabled(&self) -> bool {
        self.history.as_ref().is_some_and(|history| history.enabled)
    }

    pub(crate) fn history_default(&self) -> HistoryPolicy {
        self.history
            .as_ref()
            .map_or(HistoryPolicy::TwentyFourHours, |history| history.default)
    }

    pub(crate) fn history_select(
        &self,
        bound: BoundSession,
        channel_id: ChannelInstanceId,
        query: HistoryQuery,
    ) -> Result<HistorySnapshot, RuntimeError> {
        let authorization = self.history_authorize(bound, channel_id)?;
        let history = self.history.as_ref().ok_or_else(corrupt)?;
        let channel = history.channels.get(&channel_id).ok_or_else(corrupt)?;
        let now = self.history_now()?;
        let remaining = channel
            .rows
            .values()
            .filter(|row| {
                row.reference.expires_unix_milliseconds > now
                    && row.reference.channel_sequence > channel.control.purged_through
            })
            .count();
        let lease = QueryLease::acquire(&history.queries)?;
        let permit = acquire(&self.budget, SNAPSHOT_CHARGE)?;
        let positions = EligiblePositions {
            rows: channel.rows.values(),
            now,
            cutoff: channel.control.purged_through,
            remaining,
        };
        let selection = match select_history_iter(&query, positions) {
            Ok(selection) => selection,
            Err(HistoryError::UnknownReference) => HistorySelection::empty(),
            Err(_) => return Err(corrupt()),
        };
        self.history_snapshot(
            SnapshotRequest {
                bound,
                channel_id,
                authorization,
                selection,
                channel_name: self
                    .domain
                    .channel(channel_id)
                    .ok_or_else(corrupt)?
                    .name()
                    .clone(),
                snapshot_state_generation: self.head.state_generation,
            },
            lease,
            permit,
        )
    }

    pub(crate) fn history_restore_selection(
        &self,
        bound: BoundSession,
        channel_id: ChannelInstanceId,
        authorization: HistoryAuthorizationBinding,
        selection: HistorySelection,
        channel_name: ChannelNameValue,
        snapshot_state_generation: u64,
    ) -> Result<HistorySnapshot, RuntimeError> {
        let history = self.history.as_ref().ok_or_else(corrupt)?;
        let lease = QueryLease::acquire(&history.queries)?;
        let permit = acquire(&self.budget, SNAPSHOT_CHARGE)?;
        self.history_snapshot(
            SnapshotRequest {
                bound,
                channel_id,
                authorization,
                selection,
                channel_name,
                snapshot_state_generation,
            },
            lease,
            permit,
        )
    }

    fn history_snapshot(
        &self,
        request: SnapshotRequest,
        lease: QueryLease,
        permit: MemoryPermit,
    ) -> Result<HistorySnapshot, RuntimeError> {
        let SnapshotRequest {
            bound,
            channel_id,
            authorization,
            selection,
            channel_name,
            snapshot_state_generation,
        } = request;
        if self.history_authorize(bound, channel_id)? != authorization
            || snapshot_state_generation == 0
            || snapshot_state_generation > self.head.state_generation
            || self.domain.channel(channel_id).ok_or_else(corrupt)?.name() != &channel_name
        {
            return Err(corrupt());
        }
        let channel = self
            .history
            .as_ref()
            .and_then(|history| history.channels.get(&channel_id))
            .ok_or_else(corrupt)?;
        let now = self.history_now()?;
        let mut references = Vec::new();
        references
            .try_reserve_exact(selection.positions().len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for position in selection.positions() {
            let row = channel
                .rows
                .get(&position.channel_sequence())
                .ok_or_else(corrupt)?;
            if row.position()? != *position
                || row.reference.expires_unix_milliseconds <= now
                || row.reference.channel_sequence <= channel.control.purged_through
            {
                return Err(corrupt());
            }
            references.push(row.reference);
        }
        Ok(HistorySnapshot {
            authorization,
            selection,
            channel_id,
            channel_name,
            snapshot_state_generation,
            references,
            _permit: permit,
            _query: lease,
        })
    }

    pub(crate) fn history_read(
        &mut self,
        snapshot: &HistorySnapshot,
        positions: &[HistoryPosition],
    ) -> Result<StorageReadId, RuntimeError> {
        self.history_recheck(snapshot)?;
        if positions.is_empty() || positions.len() > HISTORY_PAGE_MESSAGES {
            return Err(RuntimeError::LimitExceeded);
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(positions.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for position in positions {
            if !snapshot.selection.positions().contains(position) {
                return Err(corrupt());
            }
            keys.push(history_message_key(
                snapshot.channel_id,
                position.channel_sequence(),
            )?);
        }
        self.submit_storage_read(ReadPlan::exact_keys(TableId::History, keys)?)
            .map_err(Into::into)
    }

    pub(crate) fn history_materialize(
        &self,
        snapshot: &HistorySnapshot,
        expected: &[HistoryPosition],
        result: &ReadResult,
    ) -> Result<HistoryMaterialized, RuntimeError> {
        self.history_recheck(snapshot)?;
        if result.truncated
            || expected.is_empty()
            || expected.len() > HISTORY_PAGE_MESSAGES
            || result.records.len() != expected.len()
        {
            return Err(corrupt());
        }
        let permit = acquire(&self.budget, PAGE_WORKING_CHARGE)?;
        let mut messages = Vec::new();
        messages
            .try_reserve_exact(result.records.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        let mut previous = None;
        for (row, position) in result.records.iter().zip(expected) {
            let message = self.history_message(snapshot, position, row)?;
            if previous.is_some_and(|sequence| sequence >= message.channel_sequence) {
                return Err(corrupt());
            }
            previous = Some(message.channel_sequence);
            messages.push(message);
        }
        self.history_recheck(snapshot)?;
        Ok(HistoryMaterialized {
            messages,
            _permit: permit,
        })
    }

    fn history_message(
        &self,
        snapshot: &HistorySnapshot,
        position: &HistoryPosition,
        row: &ReadRecord,
    ) -> Result<HistoryMessageRecord, RuntimeError> {
        if row.table != TableId::History {
            return Err(corrupt());
        }
        if !snapshot.selection.positions().contains(position)
            || row.key != history_message_key(snapshot.channel_id, position.channel_sequence())?
        {
            return Err(corrupt());
        }
        let opened = self.open_storage_plaintext(row.table, &row.key, &row.sealed_record)?;
        validate_record_plaintext(row.table, &row.key, 1, opened.expose_for_storage_codec())?;
        let value = PersistentRecordValue::decode(row.table, opened.expose_for_storage_codec())?;
        if value.record_kind() != HISTORY_MESSAGE_KIND {
            return Err(corrupt());
        }
        let message = HistoryMessageRecord::decode(value.body())?;
        let reference = super::index::row_reference(&message);
        let actual = HistoryPosition::new(
            message.channel_sequence,
            message.message_id,
            message.received_unix_milliseconds,
        )
        .map_err(|_| corrupt())?;
        if message.channel_id != snapshot.channel_id
            || actual != *position
            || !snapshot.references.contains(&reference)
        {
            return Err(corrupt());
        }
        Ok(message)
    }

    pub(crate) fn history_recheck(&self, snapshot: &HistorySnapshot) -> Result<(), RuntimeError> {
        let bound = BoundSession {
            session_id: SessionId::from_bytes(snapshot.authorization.session_id),
            user_id: UserId::from_bytes(snapshot.authorization.user_id),
            capability_hash: [0; 32],
        };
        if self.history_authorize(bound, snapshot.channel_id)? != snapshot.authorization {
            return Err(corrupt());
        }
        let now = self.history_now()?;
        let channel = self
            .history
            .as_ref()
            .and_then(|history| history.channels.get(&snapshot.channel_id))
            .ok_or_else(corrupt)?;
        for reference in &snapshot.references {
            if reference.expires_unix_milliseconds <= now
                || reference.channel_sequence <= channel.control.purged_through
                || channel
                    .rows
                    .get(&reference.channel_sequence)
                    .is_none_or(|row| row.reference != *reference)
            {
                return Err(corrupt());
            }
        }
        Ok(())
    }

    fn history_authorize(
        &self,
        bound: BoundSession,
        channel_id: ChannelInstanceId,
    ) -> Result<HistoryAuthorizationBinding, RuntimeError> {
        let history = self.history.as_ref().ok_or(RuntimeError::InvalidValue)?;
        if !history.enabled || !history.coordinator || !self.history_clock_safe() || self.quiescing
        {
            return Err(RuntimeError::InvalidValue);
        }
        let session = self.domain.session(bound.user_id).ok_or_else(corrupt)?;
        if session.session_id() != bound.session_id
            || self.domain.channel_is_quarantined(channel_id)
        {
            return Err(corrupt());
        }
        let channel = self.domain.channel(channel_id).ok_or_else(corrupt)?;
        authorize_channel(channel)?;
        let membership = channel.membership(bound.user_id).ok_or_else(corrupt)?;
        let control = &history
            .channels
            .get(&channel_id)
            .ok_or_else(corrupt)?
            .control;
        let account = self.history_account(session)?;
        let authorization = HistoryAuthorizationBinding {
            session_id: *bound.session_id.as_bytes(),
            user_id: *bound.user_id.as_bytes(),
            session_generation: session.generation().get(),
            account_id: session
                .account_id()
                .map(|id| id.to_text().as_bytes().try_into().map_err(|_| corrupt()))
                .transpose()?,
            account_session_generation: account
                .map_or(0, |_| session.account_session_generation().get()),
            membership_revision: membership.revision().get(),
            history_authorization_generation: control.history_authorization_generation,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    fn history_account(
        &self,
        session: &agenc_ircd_domain::SessionState,
    ) -> Result<Option<&AccountState>, RuntimeError> {
        let Some(id) = session.account_id() else {
            if session.account_session_generation().get() != 0 {
                return Err(corrupt());
            }
            return Ok(None);
        };
        let account = self.domain.account(id).ok_or_else(corrupt)?;
        if account.session_generation() != session.account_session_generation()
            || self
                .domain
                .account_is_suspended(id, self.utc_now().map_err(|_| corrupt())?)
        {
            return Err(corrupt());
        }
        Ok(Some(account))
    }

    pub(super) fn history_now(&self) -> Result<u64, RuntimeError> {
        let wall = self.utc_now().map_err(|_| RuntimeError::InvalidValue)?;
        if !self.drift.accepts_wall(self.now(), wall) {
            return Err(RuntimeError::InvalidValue);
        }
        wall.get().checked_mul(1_000).ok_or(RuntimeError::Overflow)
    }
}

fn authorize_channel(channel: &ChannelState) -> Result<(), RuntimeError> {
    if channel.scope() != ChannelScope::Global
        || channel.visibility() != Visibility::Listed
        || channel.persistence_policy() != PersistencePolicy::Registered
        || channel.content_policy() != ContentPolicy::Plaintext
        || channel.history_policy() == HistoryPolicy::Off
    {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
