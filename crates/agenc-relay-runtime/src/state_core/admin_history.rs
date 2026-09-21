//! Atomic history authority changes and delayed administrative purge replies.

use agenc_relay_admin::AdminAuditEvent;
use agenc_relay_domain::{ChannelScope, ContentPolicy};
use agenc_relay_types::ChannelInstanceId;

use super::durable::AccountServiceDurableWrite;
use super::history::HistoryMutation;
use super::{
    AdminCoreFailure, AdminCoreResult, AdminMutation, CorruptionCause, PendingAdminReply,
    StateCore, StateCoreExit,
};

impl StateCore {
    pub(super) fn validate_history_purge(&self, channel_id: ChannelInstanceId) -> AdminCoreResult {
        if self.history_purge_reply.is_some() {
            return Err(AdminCoreFailure::Busy);
        }
        let channel = self
            .context
            .domain
            .channel(channel_id)
            .ok_or(AdminCoreFailure::InvalidTarget)?;
        if channel.scope() != ChannelScope::Global
            || channel.content_policy() != ContentPolicy::Plaintext
        {
            return Err(AdminCoreFailure::InvalidTarget);
        }
        if self.context.history.is_none() {
            return Err(AdminCoreFailure::InvalidTarget);
        }
        Ok(())
    }

    pub(super) fn prepare_admin_history(
        &self,
        mutation: Option<AdminMutation>,
        event: &AdminAuditEvent,
    ) -> Result<(Vec<AccountServiceDurableWrite>, Option<HistoryMutation>), AdminCoreFailure> {
        let Some(history) = &self.context.history else {
            return Ok((Vec::new(), None));
        };
        let revision = self
            .context
            .domain
            .revision()
            .checked_add(1)
            .map_err(|_| AdminCoreFailure::StorageUnavailable)?
            .get();
        let generation = self
            .context
            .head
            .state_generation
            .checked_add(1)
            .ok_or(AdminCoreFailure::StorageUnavailable)?;
        let prepared = match mutation {
            Some(AdminMutation::PurgeChannelHistory(id)) => Some(
                history
                    .prepare_purge(
                        id,
                        revision,
                        event.event_hash(),
                        event.tbs().audit_sequence,
                        generation,
                    )
                    .map_err(|_| AdminCoreFailure::Busy)?,
            ),
            Some(AdminMutation::QuarantineChannel(id)) => history
                .prepare_admin_authority_change(id, revision, generation)
                .map_err(|_| AdminCoreFailure::StorageUnavailable)?,
            _ => None,
        };
        Ok(prepared.map_or_else(
            || (Vec::new(), None),
            |(writes, mutation)| (writes, Some(mutation)),
        ))
    }

    pub(super) fn defer_history_purge_reply(
        &mut self,
        mutation: Option<AdminMutation>,
        reply: PendingAdminReply,
    ) -> Result<PendingAdminReply, StateCoreExit> {
        let Some(AdminMutation::PurgeChannelHistory(channel_id)) = mutation else {
            return Ok(reply);
        };
        let PendingAdminReply::Admin(reply) = reply else {
            return Err(corrupt());
        };
        if self.history_purge_reply.is_some() {
            return Err(corrupt());
        }
        self.history_purge_reply = Some((channel_id, reply));
        Ok(PendingAdminReply::DeferredHistoryPurge)
    }

    pub(in crate::state_core) fn complete_history_purge(&mut self) {
        let Some((channel_id, _)) = &self.history_purge_reply else {
            return;
        };
        if !self
            .context
            .history
            .as_ref()
            .is_some_and(|history| history.purge_complete(*channel_id))
        {
            return;
        }
        if let Some((_, reply)) = self.history_purge_reply.take() {
            let _sent = reply.send(Ok(()));
        }
    }
}

fn corrupt() -> StateCoreExit {
    StateCoreExit::Corrupt(CorruptionCause::ApplyFailed)
}
