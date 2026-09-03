//! Mailbox operations: binding and Welcome delivery, fetch pages with fresh
//! tokens, and idempotent acknowledgement (companion Section 11.6).

use agenc_ircd_domain::e2ee::limits::WELCOME_RETENTION_SECONDS;
use agenc_ircd_domain::e2ee::mailbox::{AckOutcome, MailboxKind, Target};
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
    DeliveryGrant, MAILBOX_ROW_KIND, MailboxKind as RowKind, MailboxRow,
};

use super::super::CompanionCoordinator;
use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::{Exec, Fail, account, cursor};

fn digest(exec: &Exec<'_>, account: &[u8; 24]) -> Result<[u8; 32], Fail> {
    agenc_ircd_e2ee::ids::account_id_digest(&exec.coordinator.network_id, account)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}

fn row_kind(kind: MailboxKind) -> RowKind {
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
    let retained = bytes.to_vec();
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
        CompanionCoordinator::retain_object(companion, retained).ok();
    }));
    Ok(outcome)
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

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler pages the mailbox, mints one token per item, and stages the token rows as one atomic set
/// `fetch_mailbox`.
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
    let start = cursor.map(|cursor| {
        u64::from_be_bytes(
            cursor
                .get(24..)
                .and_then(|tail| tail.try_into().ok())
                .unwrap_or([0; 8]),
        )
    });
    let mut mailboxes = exec.coordinator.state.mailboxes.clone();
    let mut tokens = Vec::new();
    let mut failure = false;
    let page = {
        let entropy = &mut *exec.entropy;
        let mut fresh = || {
            let mut token = [0; 32];
            if entropy.fill_exact(&mut token).is_err() {
                failure = true;
            }
            tokens.push(token);
            token
        };
        mailboxes
            .fetch(
                target,
                kind,
                start,
                session_generation,
                exec.now,
                &mut fresh,
            )
            .map_err(|_| Fail::from(E2eeReplyCode::RateLimited))?
    };
    if failure {
        return Err(E2eeReplyCode::RateLimited.into());
    }
    if page.deliveries.is_empty() {
        return Ok(Outcome::scalar(ResultBody::Empty(empty_for(kind))));
    }
    let mut outcome = Outcome::scalar(ResultBody::MailboxPage);
    outcome.snapshot_token = Some(exec.random()?);
    outcome.next_cursor = page.next.map(|sequence| {
        let mut cursor = [0; 32];
        if let Some(tail) = cursor.get_mut(24..) {
            tail.copy_from_slice(&sequence.to_be_bytes());
        }
        cursor
    });
    for delivery in &page.deliveries {
        let bytes = exec
            .coordinator
            .state
            .objects
            .get(&delivery.object_id)
            .cloned()
            .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
        outcome.responses.push(ResponseObject {
            bytes,
            delivery_token: Some(delivery.token),
            target_device_id: Some(device_id),
        });
        outcome.writes.push(state_row(
            TableId::E2eeState,
            MAILBOX_ROW_KIND,
            MailboxRow::token_key(&delivery.token)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
            MailboxRow::Token {
                account_digest,
                device_id,
                kind: row_kind(kind),
                sequence: delivery.sequence,
                object_id: delivery.object_id,
                session_generation,
                expires_at: exec.now.saturating_add(
                    agenc_ircd_domain::e2ee::limits::MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS,
                ),
            }
            .encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        )?);
        let _ = DeliveryGrant {
            token: delivery.token,
            session_generation,
            expires_at: 0,
        };
    }
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
    }));
    Ok(outcome)
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
    let mut mailboxes = exec.coordinator.state.mailboxes.clone();
    let acked = mailboxes
        .acknowledge(target, token, object_id, session_generation, exec.now)
        .map_err(|error| match error {
            agenc_ircd_domain::e2ee::mailbox::MailboxError::ObjectMismatch => {
                Fail::with(E2eeReplyCode::OperationConflict, &token)
            }
            _ => Fail::with(E2eeReplyCode::ObjectNotFound, &token),
        })?;
    let mut outcome = Outcome::scalar(ResultBody::MailboxAcked(token, object_id));
    if acked == AckOutcome::Acked {
        outcome.writes.push(state_row(
            TableId::E2eeState,
            MAILBOX_ROW_KIND,
            MailboxRow::ack_key(&account_digest, &device_id, &token)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
            MailboxRow::Ack {
                object_id,
                acknowledged_at: exec.now,
                retain_until: exec
                    .now
                    .saturating_add(agenc_ircd_domain::e2ee::limits::MAILBOX_ACK_RETENTION_SECONDS),
            }
            .encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        )?);
        outcome.writes.push(
            crate::state_core::durable::AccountServiceDurableWrite::delete(
                TableId::E2eeState,
                MailboxRow::token_key(&token)
                    .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
            )
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        );
    }
    outcome.effects.push(Box::new(move |companion| {
        companion.mailboxes = mailboxes;
    }));
    Ok(outcome)
}
