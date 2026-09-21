//! Commit the latest witnessed record head beside the exact retained coordinator cut.

use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::{ROUTE_ROW_KIND, RouteLifecycle, RouteRow};
use agenc_relay_storage::{PersistentRecordValue, TableId};
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
        self.route_checkpoint(conversation, known.head)
    }

    /// The route row of `conversation` with `head` as its witnessed record
    /// head, without touching the live projection: an authenticated witness
    /// resolution installs its proven head this way (companion 12.5.1).
    pub(super) fn route_checkpoint(
        &self,
        conversation: [u8; 32],
        head: super::events::ChainHead,
    ) -> Result<Option<AccountServiceDurableWrite>, Refusal> {
        if !self.conversations.contains_key(&conversation) {
            return Ok(None);
        }
        let bytes = self
            .route_objects
            .get(&conversation)
            .ok_or(E2eeReplyCode::RouteInvalid)?;
        let mut budget = DecodeBudget::new(1 << 16, 4096);
        let object = ArcWireObject::decode_kind(
            bytes,
            Some(ArcWireObjectKind::FederationState),
            &mut budget,
        )
        .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let cut = ArcFederationRouteState::decode_exact(object.body(), &mut budget)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let tombstone = cut.state == ArcRouteStateKind::EncryptedTombstone;
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
            sequencer_head_id: head.record_id,
            route_sequence: head.sequence,
            close_id: tombstone.then_some(cut.sequencer_record_head_id),
            predecessor_close_id: None,
            recovery_gate: false,
            stored_bytes: u64::try_from(bytes.len()).map_err(|_| E2eeReplyCode::ObjectTooLarge)?,
            sequencer_credential_id: None,
            blocked_credential_id: None,
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
