//! Recovery checks use each retained mailbox object's exact lineage.

#![forbid(unsafe_code)]

use agenc_relay_domain::e2ee::mailbox::{Item, MailboxKind, Target};
use agenc_relay_e2ee::envelope::{RouteExpectation, verify_application_object};
use agenc_relay_e2ee::ids::conversation_id;
use agenc_relay_e2ee::limits::{
    MAX_BINDING_OBJECT, MAX_MAILBOX_BYTES_PER_ACCOUNT, MAX_WELCOME_MAILBOX_OBJECT,
};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage;
use agenc_relay_e2ee::objects::reinit::ArcStagedReInit;
use agenc_relay_e2ee::objects::sequencing::ArcDeliveredWelcome;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::welcome::{WelcomeTarget, verify_delivered_welcome, verify_staged_reinit};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::super::CompanionCoordinator;
use super::{Fail, recovery};

#[derive(Default)]
pub(super) struct FetchAdmission {
    scanned_bytes: u64,
}

impl FetchAdmission {
    pub(super) fn admitted(
        &mut self,
        coordinator: &CompanionCoordinator,
        target: Target,
        kind: MailboxKind,
        item: &Item,
    ) -> Result<bool, Fail> {
        let bytes = coordinator
            .state
            .objects
            .get(&item.object_id)
            .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
        self.charge(bytes.len())?;
        admitted(coordinator, target, kind, item)
    }

    fn charge(&mut self, bytes: usize) -> Result<(), Fail> {
        let total = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| self.scanned_bytes.checked_add(bytes))
            .filter(|total| *total <= MAX_MAILBOX_BYTES_PER_ACCOUNT)
            .ok_or_else(|| Fail::from(E2eeReplyCode::RateLimited))?;
        self.scanned_bytes = total;
        Ok(())
    }
}

pub(super) fn admitted(
    coordinator: &CompanionCoordinator,
    target: Target,
    kind: MailboxKind,
    item: &Item,
) -> Result<bool, Fail> {
    let bytes = coordinator
        .state
        .objects
        .get(&item.object_id)
        .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
    let expected = match kind {
        MailboxKind::Application => ArcWireObjectKind::ApplicationMls,
        MailboxKind::Binding => ArcWireObjectKind::ConversationBinding,
        MailboxKind::Welcome => ArcWireObjectKind::WelcomeMls,
        MailboxKind::StagedReinit => ArcWireObjectKind::StagedReinit,
    };
    let mut budget = DecodeBudget::new(expected.maximum_object_bytes(), 1 << 20);
    let object = ArcWireObject::decode_kind(bytes, Some(expected), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let (conversation, predecessor) = match kind {
        MailboxKind::Binding => (binding_conversation(coordinator, &object)?, None),
        MailboxKind::Application => (application_conversation(coordinator, item, &object)?, None),
        MailboxKind::Welcome | MailboxKind::StagedReinit => {
            welcome_conversations(coordinator, target, item, &object)?
        }
    };
    if item.conversation_id != conversation
        && !(kind == MailboxKind::Binding && item.conversation_id == [0; 32])
    {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    Ok(recovery::permitted(&coordinator.state, &conversation)
        && predecessor.is_none_or(|id| recovery::permitted(&coordinator.state, &id)))
}

pub(super) fn binding_conversation(
    coordinator: &CompanionCoordinator,
    object: &ArcWireObject,
) -> Result<[u8; 32], Fail> {
    let mut budget = DecodeBudget::new(MAX_BINDING_OBJECT, 1 << 20);
    let package = ArcConversationBindingPackage::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let tbs = &package.binding.tbs;
    let id = conversation_id(&coordinator.network_id, tbs.group_id.as_slice())
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    if tbs.network_id != coordinator.network_id || tbs.conversation_id != id {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    Ok(id)
}

fn application_conversation(
    coordinator: &CompanionCoordinator,
    item: &Item,
    object: &ArcWireObject,
) -> Result<[u8; 32], Fail> {
    let conversation = coordinator
        .state
        .conversations
        .get(&item.conversation_id)
        .ok_or_else(|| Fail::from(E2eeReplyCode::RouteInvalid))?;
    let expected = RouteExpectation {
        network_id: coordinator.network_id,
        conversation_id: item.conversation_id,
        route_binding: conversation.route_binding,
        group_id: conversation
            .group_id
            .as_slice()
            .try_into()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    };
    let mut budget = DecodeBudget::new(object.kind().maximum_object_bytes(), 1 << 20);
    verify_application_object(object, &expected, &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    Ok(item.conversation_id)
}

fn welcome_conversations(
    coordinator: &CompanionCoordinator,
    target: Target,
    item: &Item,
    object: &ArcWireObject,
) -> Result<([u8; 32], Option<[u8; 32]>), Fail> {
    let target = WelcomeTarget {
        account_id_digest: target.account_digest,
        device_id: target.device_id,
    };
    let mut budget = DecodeBudget::new(MAX_WELCOME_MAILBOX_OBJECT, 1 << 20);
    if object.kind() == ArcWireObjectKind::WelcomeMls {
        let welcome = ArcDeliveredWelcome::decode_exact(object.body(), &mut budget)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        verify_delivered_welcome(
            &coordinator.network_id,
            &welcome,
            &item.conversation_id,
            &target,
            &mut budget,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        return Ok((welcome.conversation_id, None));
    }
    let staged = ArcStagedReInit::decode_exact(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let verified = verify_staged_reinit(&coordinator.network_id, &staged, &target, &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    Ok((
        verified.new_conversation_id,
        Some(verified.old_conversation_id),
    ))
}

#[cfg(test)]
#[path = "mailbox_recovery/tests/scan.rs"]
mod tests;
