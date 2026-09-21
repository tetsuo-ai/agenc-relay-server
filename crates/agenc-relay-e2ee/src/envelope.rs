//! Application and Commit object checks (companion Sections 7.5, 10, 11.4)
//! and the deterministic padding arithmetic.
//!
//! The daemon reads the outer `PrivateMessage` and its authenticated data,
//! compares them with the route it is about to fan out on, and enforces the
//! outer object limit. Endpoint-only: the application-content padding of
//! Section 7.5 (applied by [`crate::objects::content::ArcEncryptedContent`]
//! before encryption), message IDs, sender sequences, and every decrypted
//! field.

use crate::error::E2eeError;
use crate::ids::SemanticId;
use crate::limits::PROFILE_VERSION;
use crate::mls_outer::{MlsContentType, MlsOuterMessage, PrivateMessageHeader, parse_mls_message};
use crate::object::{ArcWireObject, ArcWireObjectKind};
use crate::objects::aad::{ArcApplicationAad, ArcCommitAad};
use crate::tls::{DecodeBudget, TlsDecode};

/// The padding bucket for an unpadded application content length `L`
/// (Section 7.5): the least multiple of 256 at or above `L` when
/// `L <= 4096`, otherwise the least multiple of 1024.
pub fn padding_target(content_length: usize) -> Result<usize, E2eeError> {
    let bucket = if content_length <= 4_096 { 256 } else { 1_024 };
    let rounded = content_length
        .checked_add(bucket - 1)
        .ok_or(E2eeError::Overflow)?;
    Ok(rounded / bucket * bucket)
}

/// The exact number of zero padding octets a sender places in
/// `zero_padding`.
pub fn padding_bytes(content_length: usize) -> Result<usize, E2eeError> {
    padding_target(content_length)?
        .checked_sub(content_length)
        .ok_or(E2eeError::Overflow)
}

/// Checks a receiver's view: the padding vector of a content whose
/// unpadded length is `content_length` must be exactly the bucket
/// difference, and every padding octet zero.
pub fn check_padding(content_length: usize, padding: &[u8]) -> Result<(), E2eeError> {
    if padding.len() != padding_bytes(content_length)? || padding.iter().any(|byte| *byte != 0) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(())
}

/// What the route expects every object on it to name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteExpectation {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Conversation identifier.
    pub conversation_id: SemanticId,
    /// Concrete route binding.
    pub route_binding: SemanticId,
    /// MLS group identifier.
    pub group_id: [u8; 32],
}

/// A validated application object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationEnvelope {
    /// The outer header.
    pub header: PrivateMessageHeader,
    /// The authenticated data.
    pub aad: ArcApplicationAad,
}

/// A validated Commit object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitEnvelope {
    /// The outer header.
    pub header: PrivateMessageHeader,
    /// The authenticated data.
    pub aad: ArcCommitAad,
}

fn private_message(
    object: &ArcWireObject,
    kind: ArcWireObjectKind,
    content_type: MlsContentType,
    expected: &RouteExpectation,
    budget: &mut DecodeBudget,
) -> Result<PrivateMessageHeader, E2eeError> {
    if object.kind() != kind {
        return Err(E2eeError::WrongKind);
    }
    let MlsOuterMessage::Private(header) = parse_mls_message(object.body(), budget)? else {
        return Err(E2eeError::WrongKind);
    };
    if header.content_type != content_type || header.group_id != expected.group_id {
        return Err(E2eeError::InvalidValue);
    }
    Ok(header)
}

/// Validates an `application_mls` object against its route.
pub fn verify_application_object(
    object: &ArcWireObject,
    expected: &RouteExpectation,
    budget: &mut DecodeBudget,
) -> Result<ApplicationEnvelope, E2eeError> {
    let header = private_message(
        object,
        ArcWireObjectKind::ApplicationMls,
        MlsContentType::Application,
        expected,
        budget,
    )?;
    let aad = ArcApplicationAad::decode_exact(&header.authenticated_data, budget)?;
    let agrees = aad.profile_version == PROFILE_VERSION
        && aad.network_id == expected.network_id
        && aad.conversation_id == expected.conversation_id
        && aad.route_binding == expected.route_binding;
    if !agrees {
        return Err(E2eeError::InvalidValue);
    }
    Ok(ApplicationEnvelope { header, aad })
}

/// Validates a `commit_mls` object against its route and the accepted
/// state: the AAD must name the current accepted state as prior and may
/// not step the validation time backwards.
pub fn verify_commit_object(
    object: &ArcWireObject,
    expected: &RouteExpectation,
    accepted_state_id: &SemanticId,
    last_validation_time: u64,
    budget: &mut DecodeBudget,
) -> Result<CommitEnvelope, E2eeError> {
    let header = private_message(
        object,
        ArcWireObjectKind::CommitMls,
        MlsContentType::Commit,
        expected,
        budget,
    )?;
    let aad = ArcCommitAad::decode_exact(&header.authenticated_data, budget)?;
    let agrees = aad.profile_version == PROFILE_VERSION
        && aad.network_id == expected.network_id
        && aad.conversation_id == expected.conversation_id
        && aad.route_binding == expected.route_binding
        && aad.prior_state_id == *accepted_state_id
        && aad.validation_time >= last_validation_time;
    if !agrees {
        return Err(E2eeError::InvalidValue);
    }
    Ok(CommitEnvelope { header, aad })
}

#[cfg(test)]
#[path = "tests/envelope.rs"]
mod tests;
