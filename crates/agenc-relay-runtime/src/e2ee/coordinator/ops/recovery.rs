//! Route-specific recovery admission before ordinary handlers create authority.

#![forbid(unsafe_code)]

use agenc_relay_domain::e2ee::lifecycle::RecoveryGate;
use agenc_relay_domain::e2ee::{ConversationId, DirectPair, RecoveryState, ReservationId};
use agenc_relay_e2ee::limits::MAX_REINIT_OBJECT;
use agenc_relay_e2ee::objects::federation::ArcFederationOpcode as Op;
use agenc_relay_e2ee::objects::reinit::{ArcReInitActivationRequest, ArcReInitAttempt};
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_types::{AccountId, ChannelInstanceId};

use super::super::CompanionState;
use super::{Exec, Fail, account};

/// Ordinary requests cannot manufacture the signed evidence required by
/// architecture Section 18.4 and companion Section 13.7.1 after restoration.
pub(super) fn admit(exec: &Exec<'_>) -> Result<(), Fail> {
    match exec.opcode() {
        Op::ApplicationChannel
        | Op::ApplicationDirect
        | Op::CloseGroup
        | Op::SubmitCandidate
        | Op::SubmitAuthorization
        | Op::SubmitCommitAck
        | Op::SubmitFinalization
        | Op::SubmitAbort
        | Op::SubmitReinitAck
        | Op::SubmitReinitAbort
        | Op::SubmitPolicy
        | Op::SubmitMembership => direct_mutation(exec),
        Op::SubmitReinitAttempt | Op::SubmitReinitActivate => reinit(exec),
        Op::ReserveChannel => reserve_channel(exec),
        Op::ReserveDirect => reserve_direct(exec),
        Op::BindGroup => bind(exec),
        Op::QueryChannel
        | Op::QueryDirect
        | Op::FetchObject
        | Op::FetchAuthorizations
        | Op::FetchAcks
        | Op::FetchReceipts
        | Op::FetchIdentity
        | Op::FetchRootChain
        | Op::FetchRoster
        | Op::FetchCapabilities
        | Op::FetchBindingLocks
        | Op::Whoami
        | Op::PublishIdentity
        | Op::PublishRoster
        | Op::PublishCapabilities
        | Op::AttachBegin
        | Op::AttachFinish
        | Op::ClaimPackage
        | Op::ClaimStatus
        | Op::PublishPackage
        | Op::RevokePackage
        | Op::DeliverBinding
        | Op::DeliverWelcome
        | Op::FetchMailbox
        | Op::AcknowledgeMailbox => Ok(()),
        // The recovery carrier is the one mutation a pending route accepts;
        // its handler checks the gate itself.
        Op::SubmitRecovery | Op::SubmitRecoveryElement => Ok(()),
    }
}

fn reinit(exec: &Exec<'_>) -> Result<(), Fail> {
    direct_mutation(exec)?;
    let (object, _) = exec.payload()?;
    let mut budget = DecodeBudget::new(MAX_REINIT_OBJECT, 1 << 18);
    let successor = if exec.opcode() == Op::SubmitReinitAttempt {
        let attempt = ArcReInitAttempt::decode_exact(object.body(), &mut budget)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        attempt.tbs.new_conversation_id
    } else {
        let request = ArcReInitActivationRequest::decode_exact(object.body(), &mut budget)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        request.core.new_conversation_id
    };
    // A new successor must be absent in every representation, including
    // recovery tombstones. This also excludes Pending, Conflict and Closed.
    vacant_successor(&exec.coordinator.state, &successor)
}

fn vacant_successor(state: &CompanionState, successor: &[u8; 32]) -> Result<(), Fail> {
    if state.routes.route(&ConversationId(*successor)).is_some()
        || state.conversations.contains_key(successor)
        || state.logs.contains_key(successor)
        || state.lifecycles.contains_key(successor)
    {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, successor));
    }
    Ok(())
}

fn direct_mutation(exec: &Exec<'_>) -> Result<(), Fail> {
    exec.attached_device()?;
    let conversation = exec.params().read(|reader| {
        let conversation = reader.fixed::<32>()?;
        match exec.opcode() {
            Op::ApplicationChannel => {
                reader.fixed::<16>()?;
            }
            Op::CloseGroup => {
                reader.u16()?;
            }
            _ => {}
        }
        Ok(conversation)
    })?;
    mutation(exec, &conversation)
}

/// A new conversation can be absent while BIND or a ReInit successor is
/// prepared. Every existing recovery representation must allow mutation.
pub(super) fn mutation(exec: &Exec<'_>, conversation: &[u8; 32]) -> Result<(), Fail> {
    if !permitted(&exec.coordinator.state, conversation) {
        return Err(Fail::with(E2eeReplyCode::RouteInvalid, conversation));
    }
    Ok(())
}

pub(super) fn permitted(state: &CompanionState, conversation: &[u8; 32]) -> bool {
    let route = state.routes.route(&ConversationId(*conversation));
    let lifecycle = state.lifecycles.get(conversation);
    if state.conversations.contains_key(conversation) && (route.is_none() || lifecycle.is_none()) {
        return false;
    }
    route.is_none_or(|entry| entry.recovery == RecoveryState::Normal)
        && lifecycle.is_none_or(|entry| entry.gate() == RecoveryGate::Normal)
}

fn reserve_channel(exec: &Exec<'_>) -> Result<(), Fail> {
    exec.attached_device()?;
    let instance = exec.params().read(|reader| {
        let instance = reader.fixed::<16>()?;
        reader.opaque(1, 255)?;
        Ok(instance)
    })?;
    let route = exec
        .coordinator
        .state
        .routes
        .channel_route(&ChannelInstanceId::from_bytes(instance));
    match route {
        Some(route) => mutation(exec, &route.conversation_id.0),
        None => Ok(()),
    }
}

fn reserve_direct(exec: &Exec<'_>) -> Result<(), Fail> {
    let requester = exec.account_id()?;
    exec.attached_device()?;
    let peer = exec.params().read(account)?;
    let requester = AccountId::parse_wire_bytes(&requester)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let peer = AccountId::parse_wire_bytes(&peer)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let pair =
        DirectPair::new(requester, peer).map_err(|_| Fail::from(E2eeReplyCode::RouteInvalid))?;
    match exec.coordinator.state.routes.direct_route(&pair) {
        Some(route) => mutation(exec, &route.conversation_id.0),
        None => Ok(()),
    }
}

fn bind(exec: &Exec<'_>) -> Result<(), Fail> {
    exec.attached_device()?;
    let (reservation, conversation) = exec.params().read(|reader| {
        let reservation = reader.fixed::<16>()?;
        let conversation = reader.fixed::<32>()?;
        reader.fixed::<32>()?;
        Ok((reservation, conversation))
    })?;
    mutation(exec, &conversation)?;
    let predecessor = exec
        .coordinator
        .state
        .routes
        .reservation_predecessor(&ReservationId(reservation));
    match predecessor {
        Some(predecessor) => mutation(exec, &predecessor.0),
        None => Ok(()),
    }
}
