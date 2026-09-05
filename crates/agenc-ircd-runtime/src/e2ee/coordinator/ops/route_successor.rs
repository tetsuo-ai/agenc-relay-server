//! ReInit binding authorization from the retained activation and attempt.

#![forbid(unsafe_code)]

use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_domain::e2ee::sequencer_log::Phase;
use agenc_ircd_domain::e2ee::{DirectPair, RouteReservation, RouteTable, RouteTarget};
use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::limits::{MAX_BINDING_OBJECT, MAX_SEQUENCER_RECORD_OBJECT};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage;
use agenc_ircd_e2ee::objects::reinit::IrcReInitActivationCertificate;
use agenc_ircd_e2ee::objects::sequencing::IrcSequencerRecord;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::super::CompanionState;
use super::{Exec, Fail};

pub(in crate::e2ee::coordinator) fn binding(
    state: &CompanionState,
    conversation: &[u8; 32],
) -> Result<IrcConversationBindingPackage, E2eeError> {
    let id = state
        .conversations
        .get(conversation)
        .ok_or(E2eeError::InvalidValue)?
        .binding_object_id;
    let bytes = state.objects.get(&id).ok_or(E2eeError::InvalidValue)?;
    decode(
        bytes,
        IrcWireObjectKind::ConversationBinding,
        MAX_BINDING_OBJECT,
    )
}

fn decode<T: TlsDecode>(
    bytes: &[u8],
    kind: IrcWireObjectKind,
    limit: usize,
) -> Result<T, E2eeError> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = IrcWireObject::decode_kind(bytes, Some(kind), &mut budget)?;
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    T::decode_exact(object.body(), &mut budget)
}

/// Renewal keeps the same verified concrete direct route, including its nonce.
pub(super) fn direct_nonce(exec: &Exec<'_>, pair: &DirectPair) -> Result<Option<[u8; 32]>, Fail> {
    let Some(route) = exec.coordinator.state.routes.direct_route(pair) else {
        return Ok(None);
    };
    binding(&exec.coordinator.state, &route.conversation_id.0)
        .and_then(|package| package.binding.tbs.conversation_nonce.exactly::<32>())
        .map(Some)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))
}

/// A reservation has no security effect. Only a current principal can reserve
/// an existing route, and ordinary BIND cannot consume this reservation.
pub(super) fn reserve(
    exec: &Exec<'_>,
    routes: &mut RouteTable,
    reservation: RouteReservation,
) -> Result<bool, Fail> {
    let predecessor = match reservation.target {
        RouteTarget::Channel(channel) => routes.channel_route(&channel),
        RouteTarget::Direct(pair) => routes.direct_route(&pair),
    }
    .map(|entry| entry.conversation_id);
    let Some(predecessor) = predecessor else {
        return Ok(false);
    };
    owner(exec, &predecessor.0)?;
    if let RouteTarget::Channel(channel) = reservation.target {
        let principals = &exec
            .coordinator
            .state
            .conversations
            .get(&predecessor.0)
            .ok_or_else(|| Fail::from(E2eeReplyCode::RouteInvalid))?
            .principal_accounts;
        if (exec.plan_binding)(channel, principals)?.is_some() {
            return Err(E2eeReplyCode::BindingAuthInvalid.into());
        }
    }
    routes
        .reserve_successor(
            reservation.reservation_id,
            predecessor,
            reservation.owner,
            reservation.conversation_nonce,
            reservation.expires_at,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::GroupConflict))?;
    Ok(true)
}

pub(super) fn owner(exec: &Exec<'_>, conversation: &[u8; 32]) -> Result<(), Fail> {
    let account = exec.account_id()?;
    if !exec
        .coordinator
        .state
        .conversations
        .get(conversation)
        .is_some_and(|state| state.principal_accounts.contains(&account))
    {
        return Err(Fail::with(E2eeReplyCode::BindingAuthInvalid, conversation));
    }
    Ok(())
}

/// Loads the exact terminal record referenced by the predecessor's migrated log.
pub(in crate::e2ee::coordinator) fn activation(
    state: &CompanionState,
    old: &[u8; 32],
) -> Result<IrcReInitActivationCertificate, E2eeError> {
    let log = state.logs.get(old).ok_or(E2eeError::InvalidValue)?;
    let Phase::Migrated {
        activation_id,
        new_conversation_id,
    } = log.phase()
    else {
        return Err(E2eeError::InvalidValue);
    };
    let id = state
        .conversations
        .get(old)
        .and_then(|value| value.records.get(&log.head().sequence))
        .ok_or(E2eeError::InvalidValue)?;
    let bytes = state.objects.get(id).ok_or(E2eeError::InvalidValue)?;
    let record: IrcSequencerRecord = decode(
        bytes,
        IrcWireObjectKind::SequencerRecord,
        MAX_SEQUENCER_RECORD_OBJECT,
    )?;
    let IrcSequencerRecord::ReinitActivation(certificate) = record else {
        return Err(E2eeError::InvalidValue);
    };
    let tbs = &certificate.tbs;
    let core = &tbs.request.core;
    if tbs.old_conversation_id != *old
        || tbs.route_sequence != log.head().sequence
        || tbs.reinit_activation_id != activation_id
        || core.old_conversation_id != *old
        || core.new_conversation_id != new_conversation_id
        || semantic_id_of(SemanticHashDomain::ReinitActivationId, core)? != activation_id
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(certificate)
}

/// Checks all BIND-visible target fields against the quorum-activated attempt.
pub(in crate::e2ee::coordinator) fn verify(
    state: &CompanionState,
    network: &[u8; 32],
    old: &[u8; 32],
    package: &IrcConversationBindingPackage,
    context_digest: &[u8; 32],
) -> Result<[u8; 32], E2eeError> {
    let certificate = activation(state, old)?;
    let attempt = &certificate.tbs.request.attempt.tbs;
    let target = &package.binding.tbs;
    let predecessor = binding(state, old)?;
    let previous = &predecessor.binding.tbs;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, target)?;
    let group = (
        &target.group_id,
        target.mls_version,
        target.cipher_suite,
        target.initial_member_plan_id,
    );
    let authorized = (
        &attempt.target_group_id,
        attempt.target_version,
        attempt.target_suite,
        attempt.initial_member_plan_id,
    );
    if certificate.tbs.network_id != *network
        || attempt.network_id != *network
        || target.network_id != *network
        || target.conversation_id != attempt.new_conversation_id
        || certificate.tbs.request.core.new_conversation_id != target.conversation_id
        || binding_id != attempt.target_binding_id
        || context_digest != &attempt.target_context_digest
        || group != authorized
    {
        return Err(E2eeError::InvalidValue);
    }
    if previous.binding_generation.checked_add(1) != Some(target.binding_generation)
        || target.previous_binding_id != semantic_id_of(SemanticHashDomain::BindingId, previous)?
        || target.semantic_route != previous.semantic_route
        || target.route_binding != previous.route_binding
        || target.channel_instance_id != previous.channel_instance_id
        || target.conversation_nonce != previous.conversation_nonce
        || target.conversation_id == previous.conversation_id
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(certificate.tbs.reinit_activation_id)
}
