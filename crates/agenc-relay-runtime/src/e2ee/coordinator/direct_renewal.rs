//! Keep one renewable public target for the current Direct binding. Actual
//! grants retain their own owner, deadline and one-use admission semantics.
use std::collections::BTreeMap;

use agenc_relay_domain::e2ee::{ConversationId, DirectPair};
use agenc_relay_e2ee::route::direct_route_binding;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::direct_renewal::{DirectRenewal, KIND};
use agenc_relay_storage::{StoredKey, TableId};

use super::ops::{Exec, Fail};
use super::request::{Outcome, state_row};
use super::{CompanionFault, CompanionState};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite;

type Id = [u8; 32];
const ENTRY_BACKING: usize = 384;

#[derive(Default)]
pub(super) struct Nonces(BTreeMap<Id, (DirectRenewal, Option<MemoryPermit>)>);

impl Nonces {
    pub(super) fn admit(
        &mut self,
        key: &StoredKey,
        bytes: &[u8],
        backing: Option<&BackingReservationPort>,
    ) -> Result<(), CompanionFault> {
        let row = DirectRenewal::decode_keyed(key, bytes).map_err(|_| CompanionFault::Storage)?;
        if self.0.contains_key(&row.conversation) {
            return Err(CompanionFault::Storage);
        }
        let memory = backing
            .map(|port| port.reserve(ENTRY_BACKING))
            .transpose()
            .map_err(|_| CompanionFault::Ceiling)?;
        self.0.insert(row.conversation, (row, memory));
        Ok(())
    }

    pub(super) fn validate(
        &self,
        state: &CompanionState,
        network: &Id,
    ) -> Result<(), CompanionFault> {
        for (id, (row, _)) in &self.0 {
            let group = state.conversations.get(id).ok_or(CompanionFault::Storage)?;
            let (a, b) = group.direct_accounts.ok_or(CompanionFault::Storage)?;
            if group.binding != row.previous
                || direct_route_binding(network, &row.nonce, &a, &b).ok() != Some(row.route)
                || !state.routes.is_current(&ConversationId(*id))
                || !state
                    .routes
                    .route(&ConversationId(*id))
                    .is_some_and(|entry| entry.authorized_close().is_none())
            {
                return Err(CompanionFault::Storage);
            }
        }
        Ok(())
    }
}

pub(super) fn selected(state: &CompanionState, pair: &DirectPair) -> Option<Id> {
    let entry = state.routes.direct_route(pair)?;
    let group = state.conversations.get(&entry.conversation_id.0)?;
    if let Some((hint, _)) = state.renewals.0.get(&entry.conversation_id.0) {
        return (hint.previous == group.binding).then_some(hint.nonce);
    }
    group
        .pending_binding
        .and_then(|_| group.reinit_facts?.conversation_nonce())
}

pub(super) fn remember(
    exec: &Exec<'_>,
    outcome: &mut Outcome,
    row: DirectRenewal,
) -> Result<(), Fail> {
    let invalid = || Fail::with(E2eeReplyCode::BindingAuthInvalid, &row.conversation);
    if let Some((old, _)) = exec.coordinator.state.renewals.0.get(&row.conversation) {
        return (*old == row).then_some(()).ok_or_else(invalid);
    }
    let permit = exec
        .backing
        .reserve(ENTRY_BACKING)
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    outcome.writes.push(state_row(
        TableId::E2eeState,
        KIND,
        DirectRenewal::key(&row.conversation).map_err(|_| invalid())?,
        row.encode().map_err(|_| invalid())?,
    )?);
    outcome.effects.push(Box::new(move |state| {
        state
            .renewals
            .0
            .insert(row.conversation, (row, Some(permit)));
    }));
    Ok(())
}

pub(super) fn forget(exec: &Exec<'_>, outcome: &mut Outcome, id: Id) -> Result<(), Fail> {
    if !exec.coordinator.state.renewals.0.contains_key(&id) {
        return Ok(());
    }
    let key = DirectRenewal::key(&id).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    outcome.writes.push(
        AccountServiceDurableWrite::delete(TableId::E2eeState, key)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    );
    outcome.effects.push(Box::new(move |state| {
        state.renewals.0.remove(&id);
    }));
    Ok(())
}
