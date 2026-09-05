//! Commit the latest witnessed record head beside the exact retained coordinator cut.

use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{IrcFederationRouteState, IrcRouteStateKind};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::e2ee_records::{ROUTE_ROW_KIND, RouteLifecycle, RouteRow};
use agenc_ircd_storage::{PersistentRecordValue, TableId};
use std::collections::BTreeSet;

use super::{E2eeEdge, router::Refusal};
use crate::state_core::durable::AccountServiceDurableWrite;

impl E2eeEdge {
    /// Replaces each touched route's final after-image once in this transaction.
    pub(super) fn checkpoint_witnesses(
        &self,
        conversations: impl IntoIterator<Item = [u8; 32]>,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<(), Refusal> {
        let conversations: BTreeSet<_> = conversations.into_iter().collect();
        for conversation in conversations {
            let Some(write) = self.witness_checkpoint(conversation)? else {
                continue;
            };
            let key = RouteRow::key(&conversation).map_err(|_| E2eeReplyCode::InvalidFragment)?;
            writes.retain(|previous| {
                !matches!(previous,
                AccountServiceDurableWrite::Put { table: TableId::E2eeState, key: previous, .. }
                    if previous == &key)
            });
            writes.push(write);
        }
        Ok(())
    }

    fn witness_checkpoint(
        &self,
        conversation: [u8; 32],
    ) -> Result<Option<AccountServiceDurableWrite>, Refusal> {
        let Some(known) = self.conversations.get(&conversation) else {
            return Ok(None);
        };
        let bytes = self
            .route_objects
            .get(&conversation)
            .ok_or(E2eeReplyCode::RouteInvalid)?;
        let mut budget = DecodeBudget::new(1 << 16, 4096);
        let object = IrcWireObject::decode_kind(
            bytes,
            Some(IrcWireObjectKind::FederationState),
            &mut budget,
        )
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let cut = IrcFederationRouteState::decode_exact(object.body(), &mut budget)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let tombstone = cut.state == IrcRouteStateKind::EncryptedTombstone;
        let row = RouteRow {
            route_state: bytes.clone(),
            lifecycle: if tombstone {
                RouteLifecycle::Tombstone
            } else {
                RouteLifecycle::Active
            },
            binding_id: cut.binding_id,
            lock_id: cut.semantic_route_lock_id,
            accepted_state_id: cut.accepted_state_id,
            sequencer_head_id: known.head.record_id,
            route_sequence: known.head.sequence,
            close_id: tombstone.then_some(cut.sequencer_record_head_id),
            predecessor_close_id: None,
            recovery_gate: false,
            stored_bytes: u64::try_from(bytes.len()).map_err(|_| E2eeReplyCode::ObjectTooLarge)?,
        };
        let key = RouteRow::key(&conversation).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let encoded = PersistentRecordValue::new(
            TableId::E2eeState,
            ROUTE_ROW_KIND,
            1,
            0,
            None,
            Vec::new(),
            row.encode().map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )
        .and_then(|value| value.encode())
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        AccountServiceDurableWrite::put(TableId::E2eeState, key, encoded)
            .map(Some)
            .map_err(|_| E2eeReplyCode::InvalidFragment.into())
    }
}
