//! The original result descriptors bind complete replay identity and every response position.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_e2ee::limits::PROFILE_VERSION;
use agenc_ircd_e2ee::object::IrcWireObjectKind;
use agenc_ircd_e2ee::objects::federation::IrcFederationResult;
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};

pub(super) fn validate(
    coordinator: &CompanionCoordinator,
    identity: Identity,
    row: &ReplayRow,
    stored: &StoredResult,
) -> Result<Vec<IrcFederationResponseDescriptor>, CompanionFault> {
    validate_row(identity, row, stored)?;
    let object = IrcWireObject::decode_kind(
        &stored.result,
        Some(IrcWireObjectKind::FederationResult),
        &mut DecodeBudget::new(MAX_RESULT_BYTES, 512),
    )
    .map_err(|_| CompanionFault::Storage)?;
    let result = IrcFederationResult::decode_exact(
        object.body(),
        &mut DecodeBudget::new(MAX_RESULT_BYTES, 512),
    )
    .map_err(|_| CompanionFault::Storage)?;
    validate_identity(coordinator, identity, &result)?;
    validate_descriptors(&result, stored)?;
    Ok(result.responses.into_items())
}

fn validate_row(
    identity: Identity,
    row: &ReplayRow,
    stored: &StoredResult,
) -> Result<(), CompanionFault> {
    if row.request_object_id != identity.request_object_id
        || row.request_id != identity.correlation.request_id
        || row.response_object_ids != stored.responses
        || row.result_object_id != Some(*ObjectId::compute(&stored.result).as_bytes())
    {
        return Err(CompanionFault::Protocol);
    }
    Ok(())
}

fn validate_descriptors(
    result: &IrcFederationResult,
    stored: &StoredResult,
) -> Result<(), CompanionFault> {
    if result.responses.as_slice().len() != stored.responses.len() {
        return Err(CompanionFault::Storage);
    }
    for (index, (descriptor, id)) in result
        .responses
        .as_slice()
        .iter()
        .zip(&stored.responses)
        .enumerate()
    {
        if usize::from(descriptor.response_index) != index
            || descriptor.object_id != *id
            || descriptor.total_size < 6
            || descriptor.total_size as usize > descriptor.wire_kind.maximum_object_bytes()
        {
            return Err(CompanionFault::Storage);
        }
    }
    Ok(())
}

fn validate_identity(
    coordinator: &CompanionCoordinator,
    identity: Identity,
    result: &IrcFederationResult,
) -> Result<(), CompanionFault> {
    let correlation = identity.correlation;
    if correlation.peer_server_id != *identity.peer.as_bytes()
        && correlation.peer_server_id != *coordinator.server_id.as_bytes()
    {
        return Err(CompanionFault::Protocol);
    }
    if result.profile_version != PROFILE_VERSION || result.network_id != coordinator.network_id {
        return Err(CompanionFault::Storage);
    }
    validate_origin(identity, result)
}

fn validate_origin(identity: Identity, result: &IrcFederationResult) -> Result<(), CompanionFault> {
    let correlation = identity.correlation;
    if result.home_server_id != *identity.peer.as_bytes()
        || result.server_incarnation != correlation.server_incarnation
        || result.origin_id != correlation.origin_id
        || result.origin_generation != correlation.origin_generation
        || result.operation_sequence != correlation.operation_sequence
        || result.request_id != correlation.request_id
        || result.request_object_id != identity.request_object_id
    {
        return Err(CompanionFault::Storage);
    }
    Ok(())
}
