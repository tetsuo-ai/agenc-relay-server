//! Bound retained response objects and reconcile them with their result descriptors.

use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::limits::{
    MAX_BATCH_DECODED_BYTES, MAX_BATCH_OBJECTS, WIRE_OBJECT_ENVELOPE_BYTES,
};
use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_e2ee::objects::federation::ArcFederationResponseDescriptor;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::router::Refusal;
use super::{DecodedResult, PendingRequest};

/// Validate the complete descriptor set before publishing any completion mapping.
pub(super) fn result(
    pending: &PendingRequest,
    result: &DecodedResult,
    object_id: [u8; 32],
) -> Result<(), Refusal> {
    if pending
        .result_object_id
        .is_some_and(|previous| previous != object_id)
        || pending
            .result
            .as_ref()
            .is_some_and(|previous| previous != result)
    {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    if result.descriptors.len() > MAX_BATCH_OBJECTS {
        return Err(E2eeReplyCode::ObjectTooLarge.into());
    }
    let mut total = 0usize;
    for (index, descriptor) in result.descriptors.iter().enumerate() {
        let size =
            usize::try_from(descriptor.total_size).map_err(|_| E2eeReplyCode::ObjectTooLarge)?;
        if usize::from(descriptor.response_index) != index
            || size <= WIRE_OBJECT_ENVELOPE_BYTES
            || size > descriptor.wire_kind.maximum_object_bytes()
        {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        total = add_bytes(total, size)?;
    }
    for (index, bytes) in &pending.responses {
        matches_descriptor(&result.descriptors, *index, bytes)?;
    }
    Ok(())
}

/// Returns whether these bytes add a new response. Exact duplicates consume
/// no extra quota; conflicting replacements are refused without mutation.
pub(super) fn response(
    pending: &PendingRequest,
    index: u16,
    bytes: &[u8],
) -> Result<bool, Refusal> {
    if usize::from(index) >= MAX_BATCH_OBJECTS {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    ArcWireObject::peek(bytes).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    if let Some(previous) = pending.responses.get(&index) {
        return if previous == bytes {
            Ok(false)
        } else {
            Err(E2eeReplyCode::InvalidFragment.into())
        };
    }
    if pending.responses.len() >= MAX_BATCH_OBJECTS {
        return Err(E2eeReplyCode::ObjectTooLarge.into());
    }
    let mut total = bytes.len();
    for previous in pending.responses.values() {
        total = add_bytes(total, previous.len())?;
    }
    if total > MAX_BATCH_DECODED_BYTES {
        return Err(E2eeReplyCode::ObjectTooLarge.into());
    }
    if let Some(result) = &pending.result {
        matches_descriptor(&result.descriptors, index, bytes)?;
    }
    Ok(true)
}

fn add_bytes(total: usize, size: usize) -> Result<usize, Refusal> {
    total
        .checked_add(size)
        .filter(|total| *total <= MAX_BATCH_DECODED_BYTES)
        .ok_or_else(|| E2eeReplyCode::ObjectTooLarge.into())
}

fn matches_descriptor(
    descriptors: &[ArcFederationResponseDescriptor],
    index: u16,
    bytes: &[u8],
) -> Result<(), Refusal> {
    let descriptor = descriptors
        .get(usize::from(index))
        .filter(|descriptor| descriptor.response_index == index)
        .ok_or(E2eeReplyCode::InvalidFragment)?;
    let (kind, _) = ArcWireObject::peek(bytes).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    if kind != descriptor.wire_kind
        || u32::try_from(bytes.len()).ok() != Some(descriptor.total_size)
        || ObjectId::compute(bytes).as_bytes() != &descriptor.object_id
    {
        return Err(E2eeReplyCode::InvalidFragment.into());
    }
    Ok(())
}
