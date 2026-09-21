//! The `ArcWireObject` envelope and transport object identifier
//! (companion Section 11.4).

use sha2::{Digest as _, Sha256};

use crate::error::E2eeError;
use crate::limits::{
    self, MAX_WIRE_OBJECT_BODY_BYTES, PROFILE_VERSION, WIRE_OBJECT_ENVELOPE_BYTES,
};
use crate::tls::{DecodeBudget, Opaque, Reader, TlsDecode, TlsEncode, Writer, tls_enum};

/// The SHA-256 content address of one complete encoded `ArcWireObject`.
///
/// It is a transport identifier only and is never a protocol-state head.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectId([u8; 32]);

impl ObjectId {
    /// Wraps an asserted identifier.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the identifier of complete object bytes.
    #[must_use]
    pub fn compute(complete_object_bytes: &[u8]) -> Self {
        Self(Sha256::digest(complete_object_bytes).into())
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

tls_enum! {
    /// Every typed envelope kind of profile version 1.
    pub enum ArcWireObjectKind: u8 {
        /// One MLS `PrivateMessage` with `application` content.
        ApplicationMls = 1,
        /// One MLS `PrivateMessage` with `commit` content.
        CommitMls = 2,
        /// `ArcCommitApprovalEnvelope`.
        CommitApproval = 3,
        /// `ArcCommitAck`.
        CommitAck = 4,
        /// `ArcFinalizationRequest`.
        FinalizationRequest = 5,
        /// `ArcCommitFinalizationCertificate`.
        FinalizationCertificate = 6,
        /// `ArcAbortRequest`.
        AbortRequest = 7,
        /// `ArcCommitAbortCertificate`.
        AbortCertificate = 8,
        /// `ArcDeliveredWelcome`.
        WelcomeMls = 9,
        /// `ArcRootIdentity`.
        RootIdentity = 10,
        /// `ArcAccountRootChain`.
        RootIdentityChain = 11,
        /// `ArcDeviceRoster`.
        DeviceRoster = 12,
        /// `ArcDeviceCapabilities`.
        DeviceCapabilities = 13,
        /// One MLS `KeyPackage`.
        KeyPackageMls = 14,
        /// `ArcConversationBindingPackage`.
        ConversationBinding = 15,
        /// `ArcCloseAuthorization`.
        CloseAuthorization = 16,
        /// `ArcReservation`.
        Reservation = 17,
        /// `ArcReInitAttempt`.
        ReinitAttempt = 18,
        /// `ArcStagedReInit`.
        StagedReinit = 19,
        /// `ArcReInitAck`.
        ReinitAck = 20,
        /// `ArcReInitActivationRequest`.
        ReinitActivationRequest = 21,
        /// `ArcReInitActivationCertificate`.
        ReinitActivationCertificate = 22,
        /// `ArcReInitAbortRequest`.
        ReinitAbortRequest = 23,
        /// `ArcReInitAbortCertificate`.
        ReinitAbortCertificate = 24,
        /// `ArcSequencerRecord`.
        SequencerRecord = 25,
        /// `ArcDeviceAttachChallenge`.
        DeviceAttachChallenge = 26,
        /// `ArcDeviceAttach`.
        DeviceAttach = 27,
        /// `ArcRootBindingLock`.
        RootBindingLock = 28,
        /// `ArcFederationRouteState`.
        FederationState = 29,
        /// `ArcFederationOrigin`.
        FederationOrigin = 30,
        /// `ArcFederationRequest`.
        FederationRequest = 31,
        /// `ArcFederationResult`.
        FederationResult = 32,
        /// `ArcFederationEvent`.
        FederationEvent = 33,
        /// `ArcPolicy`, published to the server (9.3).
        Policy = 34,
        /// `ArcRecoverySubmission`, published to the server (13.7.4).
        RecoverySubmission = 35,
        /// `ArcFederationWitnessResolution` (12.5.1).
        WitnessResolution = 36,
        /// `ArcLeafMembershipProof`, published to the server (13.7.3).
        LeafMembershipProof = 37,
    }
}

impl ArcWireObjectKind {
    /// The hard complete-object maximum for this kind, including the
    /// six-byte envelope (Sections 11.4 and 16).
    #[must_use]
    pub const fn maximum_object_bytes(self) -> usize {
        match self {
            Self::ApplicationMls => limits::MAX_APPLICATION_MLS_OBJECT,
            Self::CommitMls => limits::MAX_LIVE_OBJECT,
            Self::CommitApproval => limits::MAX_COMMIT_APPROVAL_OBJECT,
            Self::CommitAck => limits::MAX_COMMIT_ACK_OBJECT,
            Self::FinalizationRequest | Self::FinalizationCertificate => {
                limits::MAX_FINALIZATION_OBJECT
            }
            Self::AbortRequest | Self::AbortCertificate => limits::MAX_ABORT_OBJECT,
            Self::WelcomeMls | Self::StagedReinit => limits::MAX_WELCOME_MAILBOX_OBJECT,
            Self::RootIdentity | Self::RootBindingLock => limits::MAX_IDENTITY_OBJECT,
            Self::RootIdentityChain => limits::MAX_ROOT_CHAIN_OBJECT,
            Self::DeviceRoster => limits::MAX_ROSTER_OBJECT,
            Self::DeviceCapabilities => limits::MAX_CAPABILITY_OBJECT,
            Self::KeyPackageMls => limits::MAX_KEY_PACKAGE_OBJECT,
            Self::ConversationBinding => limits::MAX_BINDING_OBJECT,
            Self::CloseAuthorization => limits::MAX_CLOSE_OBJECT,
            Self::Reservation => limits::MAX_RESERVATION_OBJECT,
            Self::ReinitAttempt
            | Self::ReinitActivationRequest
            | Self::ReinitActivationCertificate
            | Self::ReinitAbortRequest
            | Self::ReinitAbortCertificate => limits::MAX_REINIT_OBJECT,
            Self::ReinitAck => limits::MAX_REINIT_ACK_OBJECT,
            Self::SequencerRecord => limits::MAX_SEQUENCER_RECORD_OBJECT,
            Self::DeviceAttachChallenge | Self::DeviceAttach => limits::MAX_DEVICE_ATTACH_OBJECT,
            Self::FederationState
            | Self::FederationOrigin
            | Self::FederationRequest
            | Self::FederationResult
            | Self::FederationEvent
            | Self::WitnessResolution => limits::MAX_FEDERATION_CONTROL_OBJECT,
            Self::Policy => limits::MAX_POLICY_OBJECT,
            Self::LeafMembershipProof => limits::MAX_LEAF_MEMBERSHIP_OBJECT,
            Self::RecoverySubmission => limits::MAX_RECOVERY_SUBMISSION_OBJECT,
        }
    }

    /// Whether the kind travels only between servers.
    #[must_use]
    pub const fn is_server_only(self) -> bool {
        matches!(
            self,
            Self::FederationState
                | Self::FederationOrigin
                | Self::FederationRequest
                | Self::FederationResult
                | Self::FederationEvent
                | Self::WitnessResolution
        )
    }

    /// The Section 11.7 `object-kind` token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ApplicationMls => "APPLICATION",
            Self::CommitMls => "COMMIT",
            Self::CommitApproval => "AUTHORIZATION",
            Self::CommitAck => "ACK",
            Self::FinalizationRequest => "FINALIZATION-REQUEST",
            Self::FinalizationCertificate => "FINALIZATION-CERTIFICATE",
            Self::AbortRequest => "ABORT-REQUEST",
            Self::AbortCertificate => "ABORT-CERTIFICATE",
            Self::WelcomeMls => "WELCOME",
            Self::RootIdentity => "IDENTITY",
            Self::RootIdentityChain => "ROOT-CHAIN",
            Self::DeviceRoster => "ROSTER",
            Self::DeviceCapabilities => "CAPABILITIES",
            Self::KeyPackageMls => "PACKAGE",
            Self::ConversationBinding => "BINDING",
            Self::CloseAuthorization => "CLOSE",
            Self::Reservation => "RESERVATION",
            Self::ReinitAttempt => "REINIT-ATTEMPT",
            Self::StagedReinit => "STAGED-REINIT",
            Self::ReinitAck => "REINIT-ACK",
            Self::ReinitActivationRequest => "REINIT-ACTIVATION-REQUEST",
            Self::ReinitActivationCertificate => "REINIT-ACTIVATION-CERTIFICATE",
            Self::ReinitAbortRequest => "REINIT-ABORT-REQUEST",
            Self::ReinitAbortCertificate => "REINIT-ABORT-CERTIFICATE",
            Self::SequencerRecord => "SEQUENCER-RECORD",
            Self::DeviceAttachChallenge => "DEVICE-ATTACH-CHALLENGE",
            Self::DeviceAttach => "DEVICE-ATTACH",
            Self::RootBindingLock => "BINDING-LOCK",
            Self::FederationState => "FEDERATION-STATE",
            Self::FederationOrigin => "FEDERATION-ORIGIN",
            Self::FederationRequest => "FEDERATION-REQUEST",
            Self::FederationResult => "FEDERATION-RESULT",
            Self::FederationEvent => "FEDERATION-EVENT",
            Self::WitnessResolution => "WITNESS-RESOLUTION",
            Self::Policy => "POLICY",
            Self::LeafMembershipProof => "LEAF-MEMBERSHIP-PROOF",
            Self::RecoverySubmission => "RECOVERY-SUBMISSION",
        }
    }

    /// Maps a Section 11.7 token back to its kind.
    pub fn from_token(token: &str) -> Result<Self, E2eeError> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.token() == token)
            .ok_or(E2eeError::UnknownDiscriminant)
    }
}

/// One typed transport envelope: `profile_version`, `kind`, and exactly one
/// TLS encoding of the kind's body with no trailing byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArcWireObject {
    kind: ArcWireObjectKind,
    body: Opaque<1, MAX_WIRE_OBJECT_BODY_BYTES>,
}

impl ArcWireObject {
    /// Wraps an encoded body under `kind`, enforcing the kind's complete
    /// object maximum.
    pub fn new(kind: ArcWireObjectKind, body: Vec<u8>) -> Result<Self, E2eeError> {
        let total = body
            .len()
            .checked_add(WIRE_OBJECT_ENVELOPE_BYTES)
            .ok_or(E2eeError::Overflow)?;
        if total > kind.maximum_object_bytes() {
            return Err(E2eeError::LimitExceeded);
        }
        Ok(Self {
            kind,
            body: Opaque::new(body)?,
        })
    }

    /// The envelope kind.
    #[must_use]
    pub const fn kind(&self) -> ArcWireObjectKind {
        self.kind
    }

    /// The exact body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// The complete encoded length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.body.len().saturating_add(WIRE_OBJECT_ENVELOPE_BYTES)
    }

    /// Computes the transport object identifier.
    pub fn object_id(&self) -> Result<ObjectId, E2eeError> {
        Ok(ObjectId::compute(&self.encode()?))
    }

    /// Reads the kind and declared body length of a complete encoding
    /// without copying the body, so a carrier can check the kind's limit
    /// before allocating.
    pub fn peek(bytes: &[u8]) -> Result<(ArcWireObjectKind, usize), E2eeError> {
        let mut budget = DecodeBudget::new(0, 0);
        let mut reader = Reader::new(bytes, &mut budget);
        if reader.u16()? != PROFILE_VERSION {
            return Err(E2eeError::ProfileMismatch);
        }
        let kind = ArcWireObjectKind::from_value(reader.u8()?)?;
        let declared = usize::from(reader.u8()?) << 16 | usize::from(reader.u16()?);
        if declared == 0 {
            return Err(E2eeError::LengthOutOfRange);
        }
        let total = declared
            .checked_add(WIRE_OBJECT_ENVELOPE_BYTES)
            .ok_or(E2eeError::Overflow)?;
        if total != bytes.len() || total > kind.maximum_object_bytes() {
            return Err(E2eeError::LimitExceeded);
        }
        Ok((kind, declared))
    }

    /// Decodes a complete envelope and checks it against `expected` when
    /// the carrier fixes the kind.
    pub fn decode_kind(
        bytes: &[u8],
        expected: Option<ArcWireObjectKind>,
        budget: &mut DecodeBudget,
    ) -> Result<Self, E2eeError> {
        let (kind, _) = Self::peek(bytes)?;
        if expected.is_some_and(|wanted| wanted != kind) {
            return Err(E2eeError::WrongKind);
        }
        Self::decode_exact(bytes, budget)
    }
}

impl TlsEncode for ArcWireObject {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.u16(PROFILE_VERSION)?;
        self.kind.encode_into(writer)?;
        self.body.encode_into(writer)
    }
}

impl TlsDecode for ArcWireObject {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        if reader.u16()? != PROFILE_VERSION {
            return Err(E2eeError::ProfileMismatch);
        }
        let kind = ArcWireObjectKind::decode_from(reader)?;
        let body: Opaque<1, MAX_WIRE_OBJECT_BODY_BYTES> = Opaque::decode_from(reader)?;
        Self::new(kind, body.as_slice().to_vec())
    }
}

#[cfg(test)]
#[path = "tests/object.rs"]
mod tests;
