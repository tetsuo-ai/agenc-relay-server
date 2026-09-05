//! FORIGIN RESET, ADD, UPDATE, DEL, and READY on the coordinator (spec 20.5).

use agenc_ircd_domain::federation::{
    OriginBinding, OriginDeclaration, OriginKey, OriginPrincipal, OriginStatus,
};
use agenc_ircd_federation_wire::{
    AssembledObject, DecodeBudget, FederationFrame, OriginDescriptor, OriginRecord, SchemaObject,
};
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::federation_records::{
    FederationOriginRecord, ORIGIN_RECORD_KIND, OriginRowStatus, origin_key,
};
use agenc_ircd_types::{Generation, ServerId, ServerIncarnation};

use super::{FederationCoordinator, PendingCommit, Violation, grace, request};
use crate::federation::{IngressCharge, LinkId};
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;

const ORIGIN_DECODE_BYTES: usize = 4_096;
const ORIGIN_DECODE_VALUES: usize = 64;

/// Accepts FORIGIN RESET for the live incarnation.
pub(super) fn reset(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    incarnation: ServerIncarnation,
) -> Result<(), Violation> {
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    let live = state.live.as_ref().ok_or(Violation::Phase)?;
    if live.incarnation != incarnation {
        return Err(Violation::Misaddressed);
    }
    coordinator.origins.reset(peer, incarnation);
    let previous = state.incarnation.replace(incarnation);
    state.phase = agenc_ircd_storage::federation_records::PeerPhase::Suspended;
    if previous.is_some_and(|previous| previous != incarnation) {
        // A new incarnation permanently fences the previous one (FED-04), so
        // the sessions it hosted can never be closed by their owners again;
        // they are hidden now instead of waiting for a grace interval.
        grace::queue_hosted_cleanup(coordinator, context, peer);
    }
    Ok(())
}

/// Accepts one FORIGIN ADD or UPDATE object.
// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=an origin declaration carries its link peer descriptor object charge and update flag through one validation path
#[allow(clippy::too_many_arguments)]
pub(super) fn declare(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    descriptor: OriginDescriptor,
    object: &AssembledObject,
    charge: Option<IngressCharge>,
    update: bool,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    let mut budget = DecodeBudget::new(ORIGIN_DECODE_BYTES, ORIGIN_DECODE_VALUES);
    let record = SchemaObject::decode_exact("FederationOrigin", object.as_slice(), &mut budget)
        .and_then(|object| OriginRecord::from_object(&object))
        .map_err(|_| Violation::Codec)?;
    let key = OriginKey {
        home_server_id: peer,
        server_incarnation: record.server_incarnation,
        origin_id: record.origin_id,
    };
    check_descriptor(coordinator, peer, &descriptor, &record, object)?;
    let declaration = OriginDeclaration {
        origin: key,
        generation: record.generation,
        previous_object_id: record.previous_origin_object_id,
        binding: OriginBinding {
            connection_id: record.connection_id,
            connection_nonce: record.connection_nonce,
        },
        principal: principal_of(context, peer, &record)?,
        object_id: *object.object_id().as_bytes(),
    };
    let accepted = if update {
        coordinator.origins.update(declaration)
    } else {
        coordinator.origins.add(declaration)
    };
    accepted.map_err(|_| Violation::Origin)?;
    coordinator
        .origin_objects
        .insert(key, object.as_slice().to_vec());
    let frame = FederationFrame::OriginAck {
        edge_server_id: peer,
        server_incarnation: record.server_incarnation,
        origin_id: record.origin_id,
        generation: record.generation,
        object_id: Some(object.object_id()),
    };
    stage_origin(coordinator, context, link, peer, key, frame, charge)
}

fn check_descriptor(
    coordinator: &FederationCoordinator,
    peer: ServerId,
    descriptor: &OriginDescriptor,
    record: &OriginRecord,
    object: &AssembledObject,
) -> Result<(), Violation> {
    let live_incarnation = coordinator
        .peers
        .get(&peer)
        .and_then(|state| state.live.as_ref())
        .map(|live| live.incarnation)
        .ok_or(Violation::Phase)?;
    let matches = record.network_id == coordinator.config.network_id
        && record.home_server_id == peer
        && record.server_incarnation == live_incarnation
        && descriptor.coordinator_server_id == coordinator.config.server_id
        && descriptor.server_incarnation == record.server_incarnation
        && descriptor.origin_id == record.origin_id
        && descriptor.generation == record.generation
        && descriptor.object_id == object.object_id();
    if matches {
        Ok(())
    } else {
        Err(Violation::Misaddressed)
    }
}

/// Validates the declared principal against live sessions hosted by the edge.
fn principal_of(
    context: &StateCoreContext,
    peer: ServerId,
    record: &OriginRecord,
) -> Result<OriginPrincipal, Violation> {
    let session = match record.session {
        None => None,
        Some(session) => {
            let live = context
                .domain()
                .user_for_session(session.session_id)
                .and_then(|user_id| context.domain().session(user_id))
                .ok_or(Violation::Origin)?;
            if live.user_id() != session.user_id || live.home_server_id() != peer {
                return Err(Violation::Origin);
            }
            Some((session.session_id, session.user_id))
        }
    };
    let account = record
        .account
        .map(|account| {
            Generation::new(account.account_session_generation)
                .map(|generation| (account.account_id, generation))
        })
        .transpose()
        .map_err(|_| Violation::Codec)?;
    // A declared account must be the one the live session authenticated;
    // an unauthenticated declaration may omit it.
    if let Some((account_id, _)) = account {
        let live_account = session
            .and_then(|(_, user_id)| context.domain().session(user_id))
            .and_then(|live| live.account_id());
        if live_account != Some(account_id) {
            return Err(Violation::Origin);
        }
    }
    Ok(OriginPrincipal { session, account })
}

/// Accepts FORIGIN DEL.
// agenc-review: allow owner=runtime reviewed=2026-09-02 reason=an origin declaration carries its link peer descriptor object charge and update flag through one validation path
#[allow(clippy::too_many_arguments)]
pub(super) fn delete(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    key: OriginKey,
    generation: u64,
    next_sequence: u64,
) -> Result<(), Violation> {
    if coordinator.pending.is_some() {
        return Err(Violation::Ceiling);
    }
    coordinator
        .origins
        .delete(key, generation, next_sequence)
        .map_err(|_| Violation::Origin)?;
    let frame = FederationFrame::OriginAck {
        edge_server_id: peer,
        server_incarnation: key.server_incarnation,
        origin_id: key.origin_id,
        generation,
        object_id: None,
    };
    stage_origin(coordinator, context, link, peer, key, frame, None)
}

fn stage_origin(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    link: LinkId,
    peer: ServerId,
    key: OriginKey,
    frame: FederationFrame,
    charge: Option<IngressCharge>,
) -> Result<(), Violation> {
    let plan = context
        .domain()
        .plan_account_service_checkpoint()
        .map_err(|_| Violation::Ceiling)?;
    let revision = plan.resulting_revision().get();
    let entry = coordinator.origins.origin(&key).ok_or(Violation::Origin)?;
    let writes = vec![origin_row(coordinator, key, entry.next_sequence, revision)?];
    let fanout = crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())
        .map_err(|_| Violation::Ceiling)?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|_| Violation::Ceiling)?;
    coordinator.pending = Some(PendingCommit::OriginAck {
        peer,
        link,
        frame,
        _charge: charge,
    });
    Ok(())
}

/// Accepts FORIGIN READY: execution resumes and orphaned sessions of the
/// edge are scheduled for cleanup.
pub(super) fn ready(
    coordinator: &mut FederationCoordinator,
    context: &mut StateCoreContext,
    peer: ServerId,
    incarnation: ServerIncarnation,
) -> Result<(), Violation> {
    coordinator
        .origins
        .ready(peer, incarnation)
        .map_err(|_| Violation::Origin)?;
    let bound: std::collections::BTreeSet<agenc_ircd_types::UserId> = coordinator
        .origins
        .origins_of(peer, incarnation)
        .filter(|(_, entry)| entry.status == OriginStatus::Live)
        .filter_map(|(_, entry)| entry.principal.session.map(|(_, user_id)| user_id))
        .collect();
    let orphans: Vec<agenc_ircd_types::UserId> = context
        .domain()
        .session_user_ids()
        .filter(|user_id| {
            !bound.contains(user_id)
                && context
                    .domain()
                    .session(*user_id)
                    .is_some_and(|session| session.home_server_id() == peer)
        })
        .collect();
    let state = coordinator
        .peers
        .get_mut(&peer)
        .ok_or(Violation::Misaddressed)?;
    state.phase = agenc_ircd_storage::federation_records::PeerPhase::Ready;
    state.cleanup.extend(orphans);
    grace::continue_cleanup(coordinator, context, peer);
    if coordinator.pending.is_none() {
        request::drain_queued(coordinator, context);
    }
    Ok(())
}

/// Encodes the durable row of one origin at its current entry.
pub(super) fn origin_row(
    coordinator: &FederationCoordinator,
    key: OriginKey,
    next_sequence: u64,
    revision: u64,
) -> Result<AccountServiceDurableWrite, Violation> {
    let entry = coordinator.origins.origin(&key).ok_or(Violation::Origin)?;
    let object = coordinator
        .origin_objects
        .get(&key)
        .ok_or(Violation::Origin)?;
    let status = match entry.status {
        OriginStatus::Live => OriginRowStatus::Live,
        OriginStatus::Suspended => OriginRowStatus::Suspended,
        OriginStatus::Blocked => OriginRowStatus::Blocked,
        OriginStatus::Deleted => OriginRowStatus::Deleted,
        OriginStatus::Fenced => OriginRowStatus::Fenced,
    };
    let body = FederationOriginRecord {
        origin_object: object.clone(),
        origin_object_id: entry.object_id,
        // A deleted origin is recorded at the sequence its edge deleted it,
        // so a restart fences everything that would follow.
        next_sequence: entry.deleted_after.unwrap_or(next_sequence),
        status,
        flags: 0,
    }
    .encode()
    .map_err(|_| Violation::Codec)?;
    let stored = origin_key(
        key.home_server_id,
        key.server_incarnation,
        *key.origin_id.as_bytes(),
        entry.generation,
    )
    .map_err(|_| Violation::Codec)?;
    request::row(
        TableId::FederationOrigin,
        ORIGIN_RECORD_KIND,
        stored,
        revision,
        body,
    )
}
