//! One exact current mailbox grant is persisted beside its token index.

#![forbid(unsafe_code)]

use agenc_relay_domain::e2ee::mailbox::{Delivery, Item, Mailboxes};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::{DeliveryGrant, MAILBOX_ROW_KIND, MailboxRow};

use super::super::request::state_row;
use super::mailbox_snapshot::Scope;
use super::{Exec, Fail};
use crate::state_core::durable::AccountServiceDurableWrite as Write;

pub(super) fn writes(
    exec: &Exec<'_>,
    scope: Scope,
    delivery: &Delivery,
    mailboxes: &Mailboxes,
) -> Result<Vec<Write>, Fail> {
    let item = mailboxes
        .retained_item(scope.target, scope.kind, delivery.sequence)
        .ok_or_else(invalid)?;
    let grant = item.grant.ok_or_else(invalid)?;
    if grant.token != delivery.token
        || grant.session_generation != scope.session_generation
        || item.object_id != delivery.object_id
    {
        return Err(invalid());
    }
    let mut rows = vec![
        item_write(scope, delivery.sequence, item)?,
        token_write(scope, delivery, grant.expires_at)?,
    ];
    let prior = exec
        .coordinator
        .state
        .mailboxes
        .retained_item(scope.target, scope.kind, delivery.sequence)
        .ok_or_else(invalid)?;
    if let Some(old) = prior.grant.filter(|old| old.token != grant.token) {
        let key = MailboxRow::token_key(&old.token).map_err(|_| invalid())?;
        rows.push(Write::delete(TableId::E2eeState, key).map_err(|_| invalid())?);
    }
    Ok(rows)
}

fn item_write(scope: Scope, sequence: u64, item: &Item) -> Result<Write, Fail> {
    let grant = item.grant.ok_or_else(invalid)?;
    let key = MailboxRow::item_key(
        &scope.target.account_digest,
        &scope.target.device_id,
        super::mailbox::row_kind(scope.kind),
        sequence,
    )
    .map_err(|_| invalid())?;
    let body = MailboxRow::Item {
        object_id: item.object_id,
        conversation_id: item.conversation_id,
        inserted_at: item.inserted_at,
        expires_at: item.expires_at,
        grant: Some(DeliveryGrant {
            token: grant.token,
            session_generation: grant.session_generation,
            expires_at: grant.expires_at,
        }),
    }
    .encode()
    .map_err(|_| invalid())?;
    state_row(TableId::E2eeState, MAILBOX_ROW_KIND, key, body).map_err(Fail::from)
}

fn token_write(scope: Scope, delivery: &Delivery, expires_at: u64) -> Result<Write, Fail> {
    let key = MailboxRow::token_key(&delivery.token).map_err(|_| invalid())?;
    let body = MailboxRow::Token {
        account_digest: scope.target.account_digest,
        device_id: scope.target.device_id,
        kind: super::mailbox::row_kind(scope.kind),
        sequence: delivery.sequence,
        object_id: delivery.object_id,
        session_generation: scope.session_generation,
        expires_at,
    }
    .encode()
    .map_err(|_| invalid())?;
    state_row(TableId::E2eeState, MAILBOX_ROW_KIND, key, body).map_err(Fail::from)
}

fn invalid() -> Fail {
    E2eeReplyCode::InvalidFragment.into()
}
