//! The offline complement of direct live fanout (companion 11.4, 12.5 and 15).
use super::super::CompanionState;
use super::super::request::Outcome;
use super::{Exec, Fail, mailbox};
use agenc_relay_domain::e2ee::mailbox::{MailboxKind, Target};
use agenc_relay_e2ee::{ObjectId, ids::account_id_digest, wire::reply::E2eeReplyCode};
use agenc_relay_types::ServerId;
use std::collections::BTreeSet;

#[cfg(test)]
#[path = "offline_application/tests/recipients.rs"]
mod tests;

pub(super) fn prepare(
    exec: &Exec<'_>,
    outcome: &mut Outcome,
    conversation: [u8; 32],
    ciphertext: &[u8],
) -> Result<Vec<ServerId>, Fail> {
    let coordinator = exec.coordinator;
    let state = &coordinator.state;
    let (first, second) = state
        .conversations
        .get(&conversation)
        .and_then(|route| route.direct_accounts)
        .ok_or_else(|| Fail::with(E2eeReplyCode::RouteInvalid, &conversation))?;
    let digest = |account| {
        account_id_digest(&coordinator.network_id, account)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
    };
    let accounts = [digest(&first)?, digest(&second)?];
    let id = *ObjectId::compute(ciphertext).as_bytes();
    let (edges, offline) = recipients(state, accounts);
    for target in offline {
        mailbox::stage_item(
            exec,
            outcome,
            target,
            MailboxKind::Application,
            id,
            conversation,
        )?;
    }
    Ok(edges.into_iter().collect())
}

/// Both the edge event set and the device mailboxes come from this one committed cut.
fn recipients(
    state: &CompanionState,
    accounts: [[u8; 32]; 2],
) -> (BTreeSet<ServerId>, BTreeSet<Target>) {
    let mut offline = BTreeSet::new();
    for account_digest in accounts {
        if let Some(roster) = state
            .directory
            .account(&account_digest)
            .and_then(|entry| entry.roster.as_ref())
        {
            offline.extend(roster.active_devices.iter().map(|device_id| Target {
                account_digest,
                device_id: *device_id,
            }));
        }
    }
    let mut edges = BTreeSet::new();
    for origin in state
        .origins
        .values()
        .filter(|origin| !origin.fenced && !origin.suspended)
    {
        if let Some(account_digest) = origin.account_digest
            && accounts.contains(&account_digest)
            && let Some((device_id, _)) = state.current_attachment(origin)
        {
            edges.insert(ServerId::from_bytes(origin.home_server_id));
            offline.remove(&Target {
                account_digest,
                device_id,
            });
        }
    }
    (edges, offline)
}
