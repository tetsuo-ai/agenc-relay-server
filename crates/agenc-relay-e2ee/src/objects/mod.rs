//! Typed declarations of every companion public object, mirroring the
//! specification structures field for field.
//!
//! The declarations encode and decode only. Semantic rules that need more
//! than one object (chains, quorums, route state) live in the validation
//! modules. Field shapes the specification fixes independently of context
//! (an Account ID is exactly 24 bytes, an optional 16-byte ID is empty or 16
//! bytes) are checked by the `shape` methods and by `decode_body`.
//!
//! `ArcEncryptedContent` (Section 10) lives in [`content`] for clients and
//! test harnesses only: it exists inside MLS application data, which no
//! daemon code path receives or decodes.

pub mod aad;
pub mod attach;
pub mod content;
pub mod conversation;
pub mod federation;
pub mod identity;
pub mod membership;
pub mod recovery;
pub mod reinit;
pub mod sequencing;

use crate::error::E2eeError;
use crate::mls_outer::{
    MlsContentType, MlsOuterMessage, PrivateMessageHeader, PublicKeyPackage, parse_mls_message,
};
use crate::object::{ArcWireObject, ArcWireObjectKind};
use crate::tls::{DecodeBudget, Opaque, TlsDecode};

/// The `opaque account_id<1..255>` envelope; semantically exactly 24 bytes.
pub type AccountIdField = Opaque<1, 255>;
/// The `opaque group_id<1..255>` envelope; semantically exactly 32 bytes.
pub type GroupIdField = Opaque<1, 255>;
/// A `KeyPackageRef` field whose decoded length is the suite hash length.
pub type KeyPackageRefField = Opaque<1, 255>;
/// An optional 16-byte identifier: empty or exactly sixteen bytes.
pub type OptionalId16 = Opaque<0, 16>;
/// An optional 32-byte identifier: empty or exactly thirty-two bytes.
pub type OptionalId32 = Opaque<0, 32>;
/// An optional 24-byte Account ID.
pub type OptionalAccountId = Opaque<0, 24>;

/// Bytes of a canonical Account ID.
pub const ACCOUNT_ID_BYTES: usize = 24;
/// Bytes of a `group_id`.
pub const GROUP_ID_BYTES: usize = 32;

/// Requires an `opaque<1..255>` Account ID field to hold exactly 24 bytes.
pub fn account_id_bytes(field: &AccountIdField) -> Result<[u8; ACCOUNT_ID_BYTES], E2eeError> {
    field.exactly::<ACCOUNT_ID_BYTES>()
}

/// Requires a `group_id` field to hold exactly 32 bytes.
pub fn group_id_bytes(field: &GroupIdField) -> Result<[u8; GROUP_ID_BYTES], E2eeError> {
    field.exactly::<GROUP_ID_BYTES>()
}

/// Requires a Boolean byte to be 0 or 1.
pub const fn boolean(value: u8) -> Result<bool, E2eeError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(E2eeError::InvalidValue),
    }
}

/// One decoded body, typed by the envelope kind (the Section 11.4 matrix).
///
/// Large bodies are boxed so the enum stays small on the dispatch path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedBody {
    /// An MLS `PrivateMessage` with `application` content.
    ApplicationMls(PrivateMessageHeader),
    /// An MLS `PrivateMessage` with `commit` content.
    CommitMls(PrivateMessageHeader),
    /// `ArcCommitApprovalEnvelope`.
    CommitApproval(Box<conversation::ArcCommitApprovalEnvelope>),
    /// `ArcCommitAck`.
    CommitAck(Box<sequencing::ArcCommitAck>),
    /// `ArcFinalizationRequest`.
    FinalizationRequest(Box<sequencing::ArcFinalizationRequest>),
    /// `ArcCommitFinalizationCertificate`.
    FinalizationCertificate(Box<sequencing::ArcCommitFinalizationCertificate>),
    /// `ArcAbortRequest`.
    AbortRequest(Box<sequencing::ArcAbortRequest>),
    /// `ArcCommitAbortCertificate`.
    AbortCertificate(Box<sequencing::ArcCommitAbortCertificate>),
    /// `ArcDeliveredWelcome`.
    WelcomeMls(Box<sequencing::ArcDeliveredWelcome>),
    /// `ArcRootIdentity`.
    RootIdentity(Box<identity::ArcRootIdentity>),
    /// `ArcAccountRootChain`.
    RootIdentityChain(Box<identity::ArcAccountRootChain>),
    /// `ArcDeviceRoster`.
    DeviceRoster(Box<identity::ArcDeviceRoster>),
    /// `ArcDeviceCapabilities`.
    DeviceCapabilities(Box<identity::ArcDeviceCapabilities>),
    /// A public MLS `KeyPackage`.
    KeyPackageMls(Box<PublicKeyPackage>),
    /// `ArcConversationBindingPackage`.
    ConversationBinding(Box<conversation::ArcConversationBindingPackage>),
    /// `ArcCloseAuthorization`.
    CloseAuthorization(Box<conversation::ArcCloseAuthorization>),
    /// `ArcReservation`.
    Reservation(Box<conversation::ArcReservation>),
    /// `ArcReInitAttempt`.
    ReinitAttempt(Box<reinit::ArcReInitAttempt>),
    /// `ArcStagedReInit`.
    StagedReinit(Box<reinit::ArcStagedReInit>),
    /// `ArcReInitAck`.
    ReinitAck(Box<reinit::ArcReInitAck>),
    /// `ArcReInitActivationRequest`.
    ReinitActivationRequest(Box<reinit::ArcReInitActivationRequest>),
    /// `ArcReInitActivationCertificate`.
    ReinitActivationCertificate(Box<reinit::ArcReInitActivationCertificate>),
    /// `ArcReInitAbortRequest`.
    ReinitAbortRequest(Box<reinit::ArcReInitAbortRequest>),
    /// `ArcReInitAbortCertificate`.
    ReinitAbortCertificate(Box<reinit::ArcReInitAbortCertificate>),
    /// `ArcSequencerRecord`.
    SequencerRecord(Box<sequencing::ArcSequencerRecord>),
    /// `ArcDeviceAttachChallenge`.
    DeviceAttachChallenge(Box<attach::ArcDeviceAttachChallenge>),
    /// `ArcDeviceAttach`.
    DeviceAttach(Box<attach::ArcDeviceAttach>),
    /// `ArcRootBindingLock`.
    RootBindingLock(Box<conversation::ArcRootBindingLock>),
    /// `ArcFederationRouteState`.
    FederationState(Box<federation::ArcFederationRouteState>),
    /// `ArcFederationOrigin`.
    FederationOrigin(Box<federation::ArcFederationOrigin>),
    /// `ArcFederationRequest`.
    FederationRequest(Box<federation::ArcFederationRequest>),
    /// `ArcFederationResult`.
    FederationResult(Box<federation::ArcFederationResult>),
    /// `ArcFederationEvent`.
    FederationEvent(Box<federation::ArcFederationEvent>),
    /// `ArcPolicy`.
    Policy(Box<conversation::ArcPolicy>),
    /// `ArcLeafMembershipProof`.
    LeafMembershipProof(Box<membership::ArcLeafMembershipProof>),
    /// `ArcRecoverySubmission`.
    RecoverySubmission(Box<recovery::ArcRecoverySubmission>),
    /// `ArcFederationWitnessResolution`.
    WitnessResolution(Box<federation::ArcFederationWitnessResolution>),
}

fn typed<T: TlsDecode>(body: &[u8], budget: &mut DecodeBudget) -> Result<Box<T>, E2eeError> {
    Ok(Box::new(T::decode_exact(body, budget)?))
}

fn private_message(
    body: &[u8],
    expected: MlsContentType,
    budget: &mut DecodeBudget,
) -> Result<PrivateMessageHeader, E2eeError> {
    match parse_mls_message(body, budget)? {
        MlsOuterMessage::Private(header) if header.content_type == expected => Ok(header),
        _ => Err(E2eeError::WrongKind),
    }
}

/// Decodes the body of `object` as exactly the type its kind names.
// agenc-review: focus owner=e2ee reviewed=2026-09-03 reason=one closed thirty-five-arm dispatch table mirrors the Section 11.4 kind matrix in place
pub fn decode_body(
    object: &ArcWireObject,
    budget: &mut DecodeBudget,
) -> Result<TypedBody, E2eeError> {
    let body = object.body();
    Ok(match object.kind() {
        ArcWireObjectKind::ApplicationMls => {
            TypedBody::ApplicationMls(private_message(body, MlsContentType::Application, budget)?)
        }
        ArcWireObjectKind::CommitMls => {
            TypedBody::CommitMls(private_message(body, MlsContentType::Commit, budget)?)
        }
        ArcWireObjectKind::CommitApproval => TypedBody::CommitApproval(typed(body, budget)?),
        ArcWireObjectKind::CommitAck => TypedBody::CommitAck(typed(body, budget)?),
        ArcWireObjectKind::FinalizationRequest => {
            TypedBody::FinalizationRequest(typed(body, budget)?)
        }
        ArcWireObjectKind::FinalizationCertificate => {
            TypedBody::FinalizationCertificate(typed(body, budget)?)
        }
        ArcWireObjectKind::AbortRequest => TypedBody::AbortRequest(typed(body, budget)?),
        ArcWireObjectKind::AbortCertificate => TypedBody::AbortCertificate(typed(body, budget)?),
        ArcWireObjectKind::WelcomeMls => TypedBody::WelcomeMls(typed(body, budget)?),
        ArcWireObjectKind::RootIdentity => TypedBody::RootIdentity(typed(body, budget)?),
        ArcWireObjectKind::RootIdentityChain => TypedBody::RootIdentityChain(typed(body, budget)?),
        ArcWireObjectKind::DeviceRoster => TypedBody::DeviceRoster(typed(body, budget)?),
        ArcWireObjectKind::DeviceCapabilities => {
            TypedBody::DeviceCapabilities(typed(body, budget)?)
        }
        ArcWireObjectKind::KeyPackageMls => match parse_mls_message(body, budget)? {
            MlsOuterMessage::KeyPackage(package) => TypedBody::KeyPackageMls(package),
            _ => return Err(E2eeError::WrongKind),
        },
        ArcWireObjectKind::ConversationBinding => {
            TypedBody::ConversationBinding(typed(body, budget)?)
        }
        ArcWireObjectKind::CloseAuthorization => {
            TypedBody::CloseAuthorization(typed(body, budget)?)
        }
        ArcWireObjectKind::Reservation => TypedBody::Reservation(typed(body, budget)?),
        ArcWireObjectKind::ReinitAttempt => TypedBody::ReinitAttempt(typed(body, budget)?),
        ArcWireObjectKind::StagedReinit => TypedBody::StagedReinit(typed(body, budget)?),
        ArcWireObjectKind::ReinitAck => TypedBody::ReinitAck(typed(body, budget)?),
        ArcWireObjectKind::ReinitActivationRequest => {
            TypedBody::ReinitActivationRequest(typed(body, budget)?)
        }
        ArcWireObjectKind::ReinitActivationCertificate => {
            TypedBody::ReinitActivationCertificate(typed(body, budget)?)
        }
        ArcWireObjectKind::ReinitAbortRequest => {
            TypedBody::ReinitAbortRequest(typed(body, budget)?)
        }
        ArcWireObjectKind::ReinitAbortCertificate => {
            TypedBody::ReinitAbortCertificate(typed(body, budget)?)
        }
        ArcWireObjectKind::SequencerRecord => TypedBody::SequencerRecord(typed(body, budget)?),
        ArcWireObjectKind::DeviceAttachChallenge => {
            TypedBody::DeviceAttachChallenge(typed(body, budget)?)
        }
        ArcWireObjectKind::DeviceAttach => TypedBody::DeviceAttach(typed(body, budget)?),
        ArcWireObjectKind::RootBindingLock => TypedBody::RootBindingLock(typed(body, budget)?),
        ArcWireObjectKind::FederationState => TypedBody::FederationState(typed(body, budget)?),
        ArcWireObjectKind::FederationOrigin => TypedBody::FederationOrigin(typed(body, budget)?),
        ArcWireObjectKind::FederationRequest => TypedBody::FederationRequest(typed(body, budget)?),
        ArcWireObjectKind::FederationResult => TypedBody::FederationResult(typed(body, budget)?),
        ArcWireObjectKind::FederationEvent => TypedBody::FederationEvent(typed(body, budget)?),
        ArcWireObjectKind::Policy => TypedBody::Policy(typed(body, budget)?),
        ArcWireObjectKind::RecoverySubmission => {
            TypedBody::RecoverySubmission(typed(body, budget)?)
        }
        ArcWireObjectKind::LeafMembershipProof => {
            TypedBody::LeafMembershipProof(typed(body, budget)?)
        }
        ArcWireObjectKind::WitnessResolution => TypedBody::WitnessResolution(typed(body, budget)?),
    })
}

impl TypedBody {
    /// The envelope kind this body belongs to.
    #[must_use]
    pub const fn kind(&self) -> ArcWireObjectKind {
        match self {
            Self::ApplicationMls(_) => ArcWireObjectKind::ApplicationMls,
            Self::CommitMls(_) => ArcWireObjectKind::CommitMls,
            Self::CommitApproval(_) => ArcWireObjectKind::CommitApproval,
            Self::CommitAck(_) => ArcWireObjectKind::CommitAck,
            Self::FinalizationRequest(_) => ArcWireObjectKind::FinalizationRequest,
            Self::FinalizationCertificate(_) => ArcWireObjectKind::FinalizationCertificate,
            Self::AbortRequest(_) => ArcWireObjectKind::AbortRequest,
            Self::AbortCertificate(_) => ArcWireObjectKind::AbortCertificate,
            Self::WelcomeMls(_) => ArcWireObjectKind::WelcomeMls,
            Self::RootIdentity(_) => ArcWireObjectKind::RootIdentity,
            Self::RootIdentityChain(_) => ArcWireObjectKind::RootIdentityChain,
            Self::DeviceRoster(_) => ArcWireObjectKind::DeviceRoster,
            Self::DeviceCapabilities(_) => ArcWireObjectKind::DeviceCapabilities,
            Self::KeyPackageMls(_) => ArcWireObjectKind::KeyPackageMls,
            Self::ConversationBinding(_) => ArcWireObjectKind::ConversationBinding,
            Self::CloseAuthorization(_) => ArcWireObjectKind::CloseAuthorization,
            Self::Reservation(_) => ArcWireObjectKind::Reservation,
            Self::ReinitAttempt(_) => ArcWireObjectKind::ReinitAttempt,
            Self::StagedReinit(_) => ArcWireObjectKind::StagedReinit,
            Self::ReinitAck(_) => ArcWireObjectKind::ReinitAck,
            Self::ReinitActivationRequest(_) => ArcWireObjectKind::ReinitActivationRequest,
            Self::ReinitActivationCertificate(_) => ArcWireObjectKind::ReinitActivationCertificate,
            Self::ReinitAbortRequest(_) => ArcWireObjectKind::ReinitAbortRequest,
            Self::ReinitAbortCertificate(_) => ArcWireObjectKind::ReinitAbortCertificate,
            Self::SequencerRecord(_) => ArcWireObjectKind::SequencerRecord,
            Self::DeviceAttachChallenge(_) => ArcWireObjectKind::DeviceAttachChallenge,
            Self::DeviceAttach(_) => ArcWireObjectKind::DeviceAttach,
            Self::RootBindingLock(_) => ArcWireObjectKind::RootBindingLock,
            Self::FederationState(_) => ArcWireObjectKind::FederationState,
            Self::FederationOrigin(_) => ArcWireObjectKind::FederationOrigin,
            Self::FederationRequest(_) => ArcWireObjectKind::FederationRequest,
            Self::FederationResult(_) => ArcWireObjectKind::FederationResult,
            Self::FederationEvent(_) => ArcWireObjectKind::FederationEvent,
            Self::Policy(_) => ArcWireObjectKind::Policy,
            Self::LeafMembershipProof(_) => ArcWireObjectKind::LeafMembershipProof,
            Self::RecoverySubmission(_) => ArcWireObjectKind::RecoverySubmission,
            Self::WitnessResolution(_) => ArcWireObjectKind::WitnessResolution,
        }
    }
}

#[cfg(test)]
#[path = "../tests/objects.rs"]
mod tests;
