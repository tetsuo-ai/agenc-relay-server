//! Mailbox operations: binding and Welcome delivery, fetch pages with fresh
//! tokens, and idempotent acknowledgement (companion Section 11.6).

use crate::state_core::durable::AccountServiceDurableWrite;
use agenc_ircd_domain::e2ee::limits::WELCOME_RETENTION_SECONDS;
use agenc_ircd_domain::e2ee::mailbox::{
    AckOutcome, FetchSelector, MailboxError, MailboxKind, Target,
};
use agenc_ircd_domain::e2ee::projection::{EmptyKind, StoreKind};
use agenc_ircd_e2ee::limits::MAX_WELCOME_MAILBOX_OBJECT;
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::federation::IrcFederationMailboxKind;
use agenc_ircd_e2ee::objects::reinit::IrcStagedReInit;
use agenc_ircd_e2ee::objects::sequencing::IrcDeliveredWelcome;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::welcome::{WelcomeTarget, verify_delivered_welcome, verify_staged_reinit};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxKind as RowKind, MailboxRow,
    MailboxSequenceRow,
};

use super::super::CompanionCoordinator;
use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::{Exec, Fail, account, cursor};

fn digest(exec: &Exec<'_>, account: &[u8; 24]) -> Result<[u8; 32], Fail> {
    agenc_ircd_e2ee::ids::account_id_digest(&exec.coordinator.network_id, account)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}

pub(super) fn row_kind(kind: MailboxKind) -> RowKind {
    match kind {
        MailboxKind::Application => RowKind::Application,
        MailboxKind::Binding => RowKind::Binding,
        MailboxKind::Welcome => RowKind::Welcome,
        MailboxKind::StagedReinit => RowKind::StagedReinit,
    }
}

fn target_device(exec: &Exec<'_>, target: &[u8; 24], device_id: [u8; 16]) -> Result<Target, Fail> {
    let account_digest = digest(exec, target)?;
    let active = exec
        .coordinator
        .state
        .directory
        .account(&account_digest)
        .is_some_and(|entry| entry.device_active(&device_id));
    if !active {
        return Err(Fail::with(E2eeReplyCode::DeviceRequired, &device_id));
    }
    Ok(Target {
        account_digest,
        device_id,
    })
}

fn deliver(
    exec: &mut Exec<'_>,
    target: Target,
    kind: MailboxKind,
    bytes: &[u8],
    conversation_id: [u8; 32],
    store: StoreKind,
) -> Result<Outcome, Fail> {
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let mut mailboxes = exec.coordinator.state.mailboxes.clone();
    let sequence = mailboxes
        .deliver(
            target,
            kind,
            object_id,
            conversation_id,
            exec.now,
            WELCOME_RETENTION_SECONDS,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?;
    let mut outcome = Outcome::scalar(ResultBody::Stored(store, object_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(sequence_write(target, kind, sequence)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        MAILBOX_ROW_KIND,
        MailboxRow::item_key(
            &target.account_digest,
            &target.device_id,
            row_kind(kind),
            sequence,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        MailboxRow::Item {
            object_id,
            conversation_id,
            inserted_at: exec.now,
            expires_at: exec.now.saturating_add(WELCOME_RETENTION_SECONDS),
            grant: None,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
    }));
    Ok(outcome)
}

fn sequence_write(
    target: Target,
    kind: MailboxKind,
    sequence: u64,
) -> Result<AccountServiceDurableWrite, Fail> {
    let next = sequence
        .checked_add(1)
        .ok_or_else(|| Fail::from(E2eeReplyCode::RateLimited))?;
    let row = MailboxSequenceRow::new(
        target.account_digest,
        target.device_id,
        row_kind(kind),
        next,
    )
    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    state_row(
        TableId::E2eeState,
        MAILBOX_SEQUENCE_ROW_KIND,
        row.key()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )
    .map_err(Fail::from)
}

/// `deliver_binding`.
pub fn deliver_binding(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (account_bytes, device_id) = exec
        .params()
        .read(|reader| Ok((account(reader)?, reader.fixed::<16>()?)))?;
    exec.attached_device()?;
    let (object, bytes) = exec.payload()?;
    if object.kind() != IrcWireObjectKind::ConversationBinding {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    let conversation = super::mailbox_recovery::binding_conversation(exec.coordinator, object)?;
    super::recovery::mutation(exec, &conversation)?;
    super::binding_delivery::admit(exec, &conversation, object, bytes)?;
    let bytes = bytes.to_vec();
    let target = target_device(exec, &account_bytes, device_id)?;
    deliver(
        exec,
        target,
        MailboxKind::Binding,
        &bytes,
        [0; 32],
        StoreKind::Binding,
    )
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler validates the delivered Welcome wrapper, admits the mailbox item, and stages the object, item, and event as one atomic set
/// `deliver_welcome`: a normal Welcome or a staged ReInit, matched to the
/// command's account, device, conversation, and authorization identifier.
pub fn deliver_welcome(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (account_bytes, device_id, conversation_id, authorization_id) =
        exec.params().read(|reader| {
            Ok((
                account(reader)?,
                reader.fixed::<16>()?,
                reader.fixed::<32>()?,
                reader.fixed::<32>()?,
            ))
        })?;
    exec.attached_device()?;
    super::recovery::mutation(exec, &conversation_id)?;
    let (object, bytes) = exec.payload()?;
    let bytes = bytes.to_vec();
    let target = target_device(exec, &account_bytes, device_id)?;
    let welcome_target = WelcomeTarget {
        account_id_digest: target.account_digest,
        device_id,
    };
    let mut budget = DecodeBudget::new(MAX_WELCOME_MAILBOX_OBJECT, 1 << 20);
    let (kind, store) = match object.kind() {
        IrcWireObjectKind::WelcomeMls => {
            let welcome = IrcDeliveredWelcome::decode_exact(object.body(), &mut budget)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
            let verified = verify_delivered_welcome(
                &exec.coordinator.network_id,
                &welcome,
                &conversation_id,
                &welcome_target,
                &mut budget,
            )
            .map_err(|_| Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
            let known = exec
                .coordinator
                .state
                .conversations
                .get(&conversation_id)
                .is_some_and(|state| state.proofs.contains_key(&verified.finalization_id));
            if verified.finalization_id != authorization_id || !known {
                return Err(Fail::with(
                    E2eeReplyCode::FinalityRequired,
                    &conversation_id,
                ));
            }
            (MailboxKind::Welcome, StoreKind::Welcome)
        }
        IrcWireObjectKind::StagedReinit => {
            let staged = IrcStagedReInit::decode_exact(object.body(), &mut budget)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
            let verified = verify_staged_reinit(
                &exec.coordinator.network_id,
                &staged,
                &welcome_target,
                &mut budget,
            )
            .map_err(|_| Fail::with(E2eeReplyCode::BindingAuthInvalid, &conversation_id))?;
            if verified.new_conversation_id != conversation_id
                || verified.reinit_attempt_id != authorization_id
            {
                return Err(Fail::with(
                    E2eeReplyCode::FinalityRequired,
                    &conversation_id,
                ));
            }
            super::recovery::mutation(exec, &verified.old_conversation_id)?;
            (MailboxKind::StagedReinit, StoreKind::StagedReinit)
        }
        _ => return Err(E2eeReplyCode::InvalidFragment.into()),
    };
    deliver(exec, target, kind, &bytes, conversation_id, store)
}

fn mailbox_kind(selector: IrcFederationMailboxKind) -> MailboxKind {
    match selector {
        IrcFederationMailboxKind::MailboxApplication => MailboxKind::Application,
        IrcFederationMailboxKind::MailboxBinding => MailboxKind::Binding,
        IrcFederationMailboxKind::MailboxWelcome => MailboxKind::Welcome,
        IrcFederationMailboxKind::MailboxStagedReinit => MailboxKind::StagedReinit,
    }
}

const fn empty_for(kind: MailboxKind) -> EmptyKind {
    match kind {
        MailboxKind::Application => EmptyKind::Application,
        MailboxKind::Binding => EmptyKind::Binding,
        MailboxKind::Welcome => EmptyKind::Welcome,
        MailboxKind::StagedReinit => EmptyKind::StagedReinit,
    }
}

/// `fetch_mailbox`: every continuation reads its original committed cut.
pub fn fetch_mailbox(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (selector, cursor) = exec.params().read(|reader| {
        let selector = IrcFederationMailboxKind::from_value(reader.u8()?)?;
        Ok((selector, cursor(reader)?))
    })?;
    let account_digest = exec.account_digest()?;
    let (device_id, session_generation) = exec.attached_device()?;
    let kind = mailbox_kind(selector);
    let target = Target {
        account_digest,
        device_id,
    };
    let scope = super::mailbox_snapshot::Scope {
        user: exec
            .queries
            .as_ref()
            .ok_or(E2eeReplyCode::ObjectNotFound)?
            .user(),
        origin: super::super::CompanionOriginKey {
            home_server_id: exec.origin.home_server_id,
            server_incarnation: exec.origin.server_incarnation,
            origin_id: exec.origin.origin_id,
        },
        origin_generation: exec.origin.generation,
        target,
        kind,
        session_generation,
    };
    let Some(mut prepared) = super::mailbox_snapshot::prepare(exec, scope, cursor)? else {
        return Ok(Outcome::scalar(ResultBody::Empty(empty_for(kind))));
    };
    let mut mailboxes = exec.coordinator.state.mailboxes.clone();
    let deliveries = grant_page(exec, &mut mailboxes, scope, &prepared.items()?)?;
    let mut outcome = Outcome::scalar(ResultBody::MailboxPage);
    outcome.snapshot_token = Some(prepared.snapshot_token());
    outcome.next_cursor = prepared.next_cursor;
    outcome.mailbox_expiry = prepared
        .replacement
        .as_ref()
        .and_then(|store| store.next_expiry());
    for (index, delivery) in deliveries.iter().enumerate() {
        outcome.responses.push(ResponseObject {
            bytes: prepared.object(index)?.to_vec(),
            delivery_token: Some(delivery.token),
            target_device_id: Some(device_id),
        });
        outcome.writes.extend(super::mailbox_grant::writes(
            exec, scope, delivery, &mailboxes,
        )?);
    }
    let replacement = prepared.replacement.take();
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
        if let Some(replacement) = replacement {
            replacement.publish(companion);
        }
    }));
    Ok(outcome)
}

fn grant_page(
    exec: &mut Exec<'_>,
    mailboxes: &mut agenc_ircd_domain::e2ee::mailbox::Mailboxes,
    scope: super::mailbox_snapshot::Scope,
    items: &[(u64, agenc_ircd_domain::e2ee::mailbox::Item)],
) -> Result<Vec<agenc_ircd_domain::e2ee::mailbox::Delivery>, Fail> {
    let mut failed = false;
    let mut fresh = || {
        let mut token = [0; 32];
        if exec.entropy.fill_exact(&mut token).is_err() {
            failed = true;
        }
        token
    };
    let deliveries = mailboxes
        .grant_snapshot(
            FetchSelector {
                target: scope.target,
                kind: scope.kind,
                cursor: None,
            },
            items,
            scope.session_generation,
            exec.now,
            &mut fresh,
        )
        .map_err(|error| acknowledgement_failure(error, &[0; 32]))?;
    if failed {
        return Err(E2eeReplyCode::RateLimited.into());
    }
    Ok(deliveries)
}

/// `acknowledge_mailbox`.
pub fn acknowledge_mailbox(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (token, object_id) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<32>()?, reader.fixed::<32>()?)))?;
    let account_digest = exec.account_digest()?;
    let (device_id, session_generation) = exec.attached_device()?;
    let target = Target {
        account_digest,
        device_id,
    };
    let live = exec
        .coordinator
        .state
        .mailboxes
        .acknowledgement_item(target, token, object_id, session_generation, exec.now)
        .map_err(|error| acknowledgement_failure(error, &token))?;
    if let Some((kind, _, item)) = live
        && !super::mailbox_recovery::admitted(exec.coordinator, target, kind, item)?
    {
        return Err(E2eeReplyCode::RouteInvalid.into());
    }
    let mut mailboxes = exec.coordinator.state.mailboxes.clone();
    let acked = mailboxes
        .acknowledge(target, token, object_id, session_generation, exec.now)
        .map_err(|error| acknowledgement_failure(error, &token))?;
    let mut outcome = Outcome::scalar(ResultBody::MailboxAcked(token, object_id));
    if acked == AckOutcome::Acked {
        let (kind, sequence, _) = live.ok_or_else(|| Fail::from(E2eeReplyCode::InvalidFragment))?;
        outcome.writes =
            acknowledgement_writes(target, token, object_id, (kind, sequence), exec.now)?;
    }
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
        super::super::resident::retire_payload(companion, &object_id);
    }));
    Ok(outcome)
}

fn acknowledgement_writes(
    target: Target,
    token: [u8; 32],
    object_id: [u8; 32],
    position: (MailboxKind, u64),
    now: u64,
) -> Result<Vec<AccountServiceDurableWrite>, Fail> {
    let (kind, sequence) = position;
    let item = MailboxRow::item_key(
        &target.account_digest,
        &target.device_id,
        row_kind(kind),
        sequence,
    )
    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let token_key =
        MailboxRow::token_key(&token).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let ack_key = MailboxRow::ack_key(&target.account_digest, &target.device_id, &token)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let row = MailboxRow::Ack {
        object_id,
        acknowledged_at: now,
        retain_until: now
            .saturating_add(agenc_ircd_domain::e2ee::limits::MAILBOX_ACK_RETENTION_SECONDS),
    }
    .encode()
    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    Ok(vec![
        state_row(TableId::E2eeState, MAILBOX_ROW_KIND, ack_key, row)?,
        AccountServiceDurableWrite::delete(TableId::E2eeState, item)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        AccountServiceDurableWrite::delete(TableId::E2eeState, token_key)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    ])
}

fn acknowledgement_failure(error: MailboxError, token: &[u8; 32]) -> Fail {
    match error {
        MailboxError::ObjectMismatch => Fail::with(E2eeReplyCode::OperationConflict, token),
        _ => Fail::with(E2eeReplyCode::ObjectNotFound, token),
    }
}
