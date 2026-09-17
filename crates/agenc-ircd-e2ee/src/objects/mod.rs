//! Typed declarations of every companion public object, mirroring the
//! specification structures field for field.
//!
//! The declarations encode and decode only. Semantic rules that need more
//! than one object (chains, quorums, route state) live in the validation
//! modules. Field shapes the specification fixes independently of context
//! (an Account ID is exactly 24 bytes, an optional 16-byte ID is empty or 16
//! bytes) are checked by the `shape` methods and by `decode_body`.
//!
//! `IrcEncryptedContent` (Section 10) lives in [`content`] for clients and
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
use crate::object::{IrcWireObject, IrcWireObjectKind};
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
    /// `IrcCommitApprovalEnvelope`.
    CommitApproval(Box<conversation::IrcCommitApprovalEnvelope>),
    /// `IrcCommitAck`.
    CommitAck(Box<sequencing::IrcCommitAck>),
    /// `IrcFinalizationRequest`.
    FinalizationRequest(Box<sequencing::IrcFinalizationRequest>),
    /// `IrcCommitFinalizationCertificate`.
    FinalizationCertificate(Box<sequencing::IrcCommitFinalizationCertificate>),
    /// `IrcAbortRequest`.
    AbortRequest(Box<sequencing::IrcAbortRequest>),
    /// `IrcCommitAbortCertificate`.
    AbortCertificate(Box<sequencing::IrcCommitAbortCertificate>),
    /// `IrcDeliveredWelcome`.
    WelcomeMls(Box<sequencing::IrcDeliveredWelcome>),
    /// `IrcRootIdentity`.
    RootIdentity(Box<identity::IrcRootIdentity>),
    /// `IrcAccountRootChain`.
    RootIdentityChain(Box<identity::IrcAccountRootChain>),
    /// `IrcDeviceRoster`.
    DeviceRoster(Box<identity::IrcDeviceRoster>),
    /// `IrcDeviceCapabilities`.
    DeviceCapabilities(Box<identity::IrcDeviceCapabilities>),
    /// A public MLS `KeyPackage`.
    KeyPackageMls(Box<PublicKeyPackage>),
    /// `IrcConversationBindingPackage`.
    ConversationBinding(Box<conversation::IrcConversationBindingPackage>),
    /// `IrcCloseAuthorization`.
    CloseAuthorization(Box<conversation::IrcCloseAuthorization>),
    /// `IrcReservation`.
    Reservation(Box<conversation::IrcReservation>),
    /// `IrcReInitAttempt`.
    ReinitAttempt(Box<reinit::IrcReInitAttempt>),
    /// `IrcStagedReInit`.
    StagedReinit(Box<reinit::IrcStagedReInit>),
    /// `IrcReInitAck`.
    ReinitAck(Box<reinit::IrcReInitAck>),
    /// `IrcReInitActivationRequest`.
    ReinitActivationRequest(Box<reinit::IrcReInitActivationRequest>),
    /// `IrcReInitActivationCertificate`.
    ReinitActivationCertificate(Box<reinit::IrcReInitActivationCertificate>),
    /// `IrcReInitAbortRequest`.
    ReinitAbortRequest(Box<reinit::IrcReInitAbortRequest>),
    /// `IrcReInitAbortCertificate`.
    ReinitAbortCertificate(Box<reinit::IrcReInitAbortCertificate>),
    /// `IrcSequencerRecord`.
    SequencerRecord(Box<sequencing::IrcSequencerRecord>),
    /// `IrcDeviceAttachChallenge`.
    DeviceAttachChallenge(Box<attach::IrcDeviceAttachChallenge>),
    /// `IrcDeviceAttach`.
    DeviceAttach(Box<attach::IrcDeviceAttach>),
    /// `IrcRootBindingLock`.
    RootBindingLock(Box<conversation::IrcRootBindingLock>),
    /// `IrcFederationRouteState`.
    FederationState(Box<federation::IrcFederationRouteState>),
    /// `IrcFederationOrigin`.
    FederationOrigin(Box<federation::IrcFederationOrigin>),
    /// `IrcFederationRequest`.
    FederationRequest(Box<federation::IrcFederationRequest>),
    /// `IrcFederationResult`.
    FederationResult(Box<federation::IrcFederationResult>),
    /// `IrcFederationEvent`.
    FederationEvent(Box<federation::IrcFederationEvent>),
    /// `IrcPolicy`.
    Policy(Box<conversation::IrcPolicy>),
    /// `IrcLeafMembershipProof`.
    LeafMembershipProof(Box<membership::IrcLeafMembershipProof>),
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
    object: &IrcWireObject,
    budget: &mut DecodeBudget,
) -> Result<TypedBody, E2eeError> {
    let body = object.body();
    Ok(match object.kind() {
        IrcWireObjectKind::ApplicationMls => {
            TypedBody::ApplicationMls(private_message(body, MlsContentType::Application, budget)?)
        }
        IrcWireObjectKind::CommitMls => {
            TypedBody::CommitMls(private_message(body, MlsContentType::Commit, budget)?)
        }
        IrcWireObjectKind::CommitApproval => TypedBody::CommitApproval(typed(body, budget)?),
        IrcWireObjectKind::CommitAck => TypedBody::CommitAck(typed(body, budget)?),
        IrcWireObjectKind::FinalizationRequest => {
            TypedBody::FinalizationRequest(typed(body, budget)?)
        }
        IrcWireObjectKind::FinalizationCertificate => {
            TypedBody::FinalizationCertificate(typed(body, budget)?)
        }
        IrcWireObjectKind::AbortRequest => TypedBody::AbortRequest(typed(body, budget)?),
        IrcWireObjectKind::AbortCertificate => TypedBody::AbortCertificate(typed(body, budget)?),
        IrcWireObjectKind::WelcomeMls => TypedBody::WelcomeMls(typed(body, budget)?),
        IrcWireObjectKind::RootIdentity => TypedBody::RootIdentity(typed(body, budget)?),
        IrcWireObjectKind::RootIdentityChain => TypedBody::RootIdentityChain(typed(body, budget)?),
        IrcWireObjectKind::DeviceRoster => TypedBody::DeviceRoster(typed(body, budget)?),
        IrcWireObjectKind::DeviceCapabilities => {
            TypedBody::DeviceCapabilities(typed(body, budget)?)
        }
        IrcWireObjectKind::KeyPackageMls => match parse_mls_message(body, budget)? {
            MlsOuterMessage::KeyPackage(package) => TypedBody::KeyPackageMls(package),
            _ => return Err(E2eeError::WrongKind),
        },
        IrcWireObjectKind::ConversationBinding => {
            TypedBody::ConversationBinding(typed(body, budget)?)
        }
        IrcWireObjectKind::CloseAuthorization => {
            TypedBody::CloseAuthorization(typed(body, budget)?)
        }
        IrcWireObjectKind::Reservation => TypedBody::Reservation(typed(body, budget)?),
        IrcWireObjectKind::ReinitAttempt => TypedBody::ReinitAttempt(typed(body, budget)?),
        IrcWireObjectKind::StagedReinit => TypedBody::StagedReinit(typed(body, budget)?),
        IrcWireObjectKind::ReinitAck => TypedBody::ReinitAck(typed(body, budget)?),
        IrcWireObjectKind::ReinitActivationRequest => {
            TypedBody::ReinitActivationRequest(typed(body, budget)?)
        }
        IrcWireObjectKind::ReinitActivationCertificate => {
            TypedBody::ReinitActivationCertificate(typed(body, budget)?)
        }
        IrcWireObjectKind::ReinitAbortRequest => {
            TypedBody::ReinitAbortRequest(typed(body, budget)?)
        }
        IrcWireObjectKind::ReinitAbortCertificate => {
            TypedBody::ReinitAbortCertificate(typed(body, budget)?)
        }
        IrcWireObjectKind::SequencerRecord => TypedBody::SequencerRecord(typed(body, budget)?),
        IrcWireObjectKind::DeviceAttachChallenge => {
            TypedBody::DeviceAttachChallenge(typed(body, budget)?)
        }
        IrcWireObjectKind::DeviceAttach => TypedBody::DeviceAttach(typed(body, budget)?),
        IrcWireObjectKind::RootBindingLock => TypedBody::RootBindingLock(typed(body, budget)?),
        IrcWireObjectKind::FederationState => TypedBody::FederationState(typed(body, budget)?),
        IrcWireObjectKind::FederationOrigin => TypedBody::FederationOrigin(typed(body, budget)?),
        IrcWireObjectKind::FederationRequest => TypedBody::FederationRequest(typed(body, budget)?),
        IrcWireObjectKind::FederationResult => TypedBody::FederationResult(typed(body, budget)?),
        IrcWireObjectKind::FederationEvent => TypedBody::FederationEvent(typed(body, budget)?),
        IrcWireObjectKind::Policy => TypedBody::Policy(typed(body, budget)?),
        IrcWireObjectKind::LeafMembershipProof => {
            TypedBody::LeafMembershipProof(typed(body, budget)?)
        }
    })
}

impl TypedBody {
    /// The envelope kind this body belongs to.
    #[must_use]
    pub const fn kind(&self) -> IrcWireObjectKind {
        match self {
            Self::ApplicationMls(_) => IrcWireObjectKind::ApplicationMls,
            Self::CommitMls(_) => IrcWireObjectKind::CommitMls,
            Self::CommitApproval(_) => IrcWireObjectKind::CommitApproval,
            Self::CommitAck(_) => IrcWireObjectKind::CommitAck,
            Self::FinalizationRequest(_) => IrcWireObjectKind::FinalizationRequest,
            Self::FinalizationCertificate(_) => IrcWireObjectKind::FinalizationCertificate,
            Self::AbortRequest(_) => IrcWireObjectKind::AbortRequest,
            Self::AbortCertificate(_) => IrcWireObjectKind::AbortCertificate,
            Self::WelcomeMls(_) => IrcWireObjectKind::WelcomeMls,
            Self::RootIdentity(_) => IrcWireObjectKind::RootIdentity,
            Self::RootIdentityChain(_) => IrcWireObjectKind::RootIdentityChain,
            Self::DeviceRoster(_) => IrcWireObjectKind::DeviceRoster,
            Self::DeviceCapabilities(_) => IrcWireObjectKind::DeviceCapabilities,
            Self::KeyPackageMls(_) => IrcWireObjectKind::KeyPackageMls,
            Self::ConversationBinding(_) => IrcWireObjectKind::ConversationBinding,
            Self::CloseAuthorization(_) => IrcWireObjectKind::CloseAuthorization,
            Self::Reservation(_) => IrcWireObjectKind::Reservation,
            Self::ReinitAttempt(_) => IrcWireObjectKind::ReinitAttempt,
            Self::StagedReinit(_) => IrcWireObjectKind::StagedReinit,
            Self::ReinitAck(_) => IrcWireObjectKind::ReinitAck,
            Self::ReinitActivationRequest(_) => IrcWireObjectKind::ReinitActivationRequest,
            Self::ReinitActivationCertificate(_) => IrcWireObjectKind::ReinitActivationCertificate,
            Self::ReinitAbortRequest(_) => IrcWireObjectKind::ReinitAbortRequest,
            Self::ReinitAbortCertificate(_) => IrcWireObjectKind::ReinitAbortCertificate,
            Self::SequencerRecord(_) => IrcWireObjectKind::SequencerRecord,
            Self::DeviceAttachChallenge(_) => IrcWireObjectKind::DeviceAttachChallenge,
            Self::DeviceAttach(_) => IrcWireObjectKind::DeviceAttach,
            Self::RootBindingLock(_) => IrcWireObjectKind::RootBindingLock,
            Self::FederationState(_) => IrcWireObjectKind::FederationState,
            Self::FederationOrigin(_) => IrcWireObjectKind::FederationOrigin,
            Self::FederationRequest(_) => IrcWireObjectKind::FederationRequest,
            Self::FederationResult(_) => IrcWireObjectKind::FederationResult,
            Self::FederationEvent(_) => IrcWireObjectKind::FederationEvent,
            Self::Policy(_) => IrcWireObjectKind::Policy,
            Self::LeafMembershipProof(_) => IrcWireObjectKind::LeafMembershipProof,
        }
    }
}

#[cfg(test)]
#[path = "../tests/objects.rs"]
mod tests;
