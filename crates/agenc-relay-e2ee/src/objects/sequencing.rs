//! Candidate receipts, records, acknowledgements, finalization, abort, and
//! Welcome delivery objects (companion Sections 12.2 to 12.4).

use crate::error::E2eeError;
use crate::tls::{Opaque, Reader, TlsDecode, TlsEncode, TlsVec, Writer, tls_enum, tls_struct};

use super::conversation::{ArcCommitAuthorization, ArcJoinTransitionProofBundle};
use super::reinit::{
    ArcReInitAbortCertificate, ArcReInitActivationCertificate, ArcReInitAttemptReceipt,
};
use super::{GroupIdField, KeyPackageRefField};

tls_struct! {
    /// `ArcGroupGenesisTBS` (12.2).
    pub struct ArcGroupGenesisTbs {
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Group identifier.
        pub group_id: GroupIdField,
        /// Binding identifier.
        pub binding_id: [u8; 32],
        /// Context core identifier.
        pub context_core_id: [u8; 32],
    }
}

tls_struct! {
    /// `ArcCandidateReceiptTBS` (12.2).
    pub struct ArcCandidateReceiptTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Prior epoch.
        pub prior_epoch: u64,
        /// Resulting epoch.
        pub resulting_epoch: u64,
        /// Candidate sequence within the prior epoch.
        pub candidate_sequence: u32,
        /// Commit object identifier.
        pub commit_object_id: [u8; 32],
        /// Prior accepted state identifier.
        pub prior_state_id: [u8; 32],
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Informational sequencing second.
        pub sequenced_at: u64,
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
    }
}

tls_struct! {
    /// `ArcCandidateReceipt` (12.2).
    pub struct ArcCandidateReceipt {
        /// Signed fields.
        pub tbs: ArcCandidateReceiptTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_enum! {
    /// `ArcSequencerRecordKind` (12.2).
    pub enum ArcSequencerRecordKind: u8 {
        /// A candidate receipt.
        CandidateRecord = 1,
        /// A finalization certificate.
        FinalizationRecord = 2,
        /// An abort certificate.
        AbortRecord = 3,
        /// A ReInit attempt receipt.
        ReinitAttemptRecord = 4,
        /// A ReInit activation certificate.
        ReinitActivationRecord = 5,
        /// A ReInit abort certificate.
        ReinitAbortRecord = 6,
    }
}

/// `ArcSequencerRecord` (12.2), the tagged union of record history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArcSequencerRecord {
    /// A candidate receipt.
    Candidate(ArcCandidateReceipt),
    /// A finalization certificate.
    Finalization(ArcCommitFinalizationCertificate),
    /// An abort certificate.
    Abort(ArcCommitAbortCertificate),
    /// A ReInit attempt receipt.
    ReinitAttempt(ArcReInitAttemptReceipt),
    /// A ReInit activation certificate.
    ReinitActivation(ArcReInitActivationCertificate),
    /// A ReInit abort certificate.
    ReinitAbort(ArcReInitAbortCertificate),
}

impl ArcSequencerRecord {
    /// The union discriminant.
    #[must_use]
    pub const fn kind(&self) -> ArcSequencerRecordKind {
        match self {
            Self::Candidate(_) => ArcSequencerRecordKind::CandidateRecord,
            Self::Finalization(_) => ArcSequencerRecordKind::FinalizationRecord,
            Self::Abort(_) => ArcSequencerRecordKind::AbortRecord,
            Self::ReinitAttempt(_) => ArcSequencerRecordKind::ReinitAttemptRecord,
            Self::ReinitActivation(_) => ArcSequencerRecordKind::ReinitActivationRecord,
            Self::ReinitAbort(_) => ArcSequencerRecordKind::ReinitAbortRecord,
        }
    }
}

impl TlsEncode for ArcSequencerRecord {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        self.kind().encode_into(writer)?;
        match self {
            Self::Candidate(record) => record.encode_into(writer),
            Self::Finalization(record) => record.encode_into(writer),
            Self::Abort(record) => record.encode_into(writer),
            Self::ReinitAttempt(record) => record.encode_into(writer),
            Self::ReinitActivation(record) => record.encode_into(writer),
            Self::ReinitAbort(record) => record.encode_into(writer),
        }
    }
}

impl TlsDecode for ArcSequencerRecord {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        Ok(match ArcSequencerRecordKind::decode_from(reader)? {
            ArcSequencerRecordKind::CandidateRecord => {
                Self::Candidate(TlsDecode::decode_from(reader)?)
            }
            ArcSequencerRecordKind::FinalizationRecord => {
                Self::Finalization(TlsDecode::decode_from(reader)?)
            }
            ArcSequencerRecordKind::AbortRecord => Self::Abort(TlsDecode::decode_from(reader)?),
            ArcSequencerRecordKind::ReinitAttemptRecord => {
                Self::ReinitAttempt(TlsDecode::decode_from(reader)?)
            }
            ArcSequencerRecordKind::ReinitActivationRecord => {
                Self::ReinitActivation(TlsDecode::decode_from(reader)?)
            }
            ArcSequencerRecordKind::ReinitAbortRecord => {
                Self::ReinitAbort(TlsDecode::decode_from(reader)?)
            }
        })
    }
}

tls_struct! {
    /// `ArcGroupContextDigestTBS` (12.3).
    pub struct ArcGroupContextDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded GroupContext.
        pub encoded_group_context: Opaque<1, 1_048_576>,
    }
}

tls_struct! {
    /// `ArcRatchetTreeDigestTBS` (12.3).
    pub struct ArcRatchetTreeDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded ratchet tree.
        pub encoded_ratchet_tree: Opaque<1, 4_194_304>,
    }
}

tls_struct! {
    /// `ArcGroupInfoDigestTBS` (12.3).
    pub struct ArcGroupInfoDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded GroupInfo.
        pub encoded_group_info: Opaque<1, 4_194_304>,
    }
}

tls_struct! {
    /// `ArcCommitAckTBS` (12.3).
    pub struct ArcCommitAckTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Prior epoch.
        pub prior_epoch: u64,
        /// Candidate identifier.
        pub candidate_id: [u8; 32],
        /// Commit object identifier.
        pub commit_object_id: [u8; 32],
        /// Signer's old leaf index.
        pub old_leaf_index: u32,
        /// Signer's old credential hash.
        pub old_credential_hash: [u8; 32],
        /// Resulting epoch.
        pub resulting_epoch: u64,
        /// Resulting group context digest.
        pub resulting_group_context_digest: [u8; 32],
        /// Resulting ratchet tree digest.
        pub resulting_ratchet_tree_digest: [u8; 32],
        /// Exported finalization authenticator.
        pub finalization_authenticator: [u8; 32],
    }
}

tls_struct! {
    /// `ArcCommitAck` (12.3).
    pub struct ArcCommitAck {
        /// Signed fields.
        pub tbs: ArcCommitAckTbs,
        /// Old-leaf signature.
        pub old_leaf_signature: Opaque<1, 255>,
    }
}

tls_struct! {
    /// `ArcFinalizationCoreTBS` (12.4).
    pub struct ArcFinalizationCoreTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Prior epoch.
        pub prior_epoch: u64,
        /// Prior accepted state identifier.
        pub prior_state_id: [u8; 32],
        /// Candidate identifier.
        pub candidate_id: [u8; 32],
        /// Commit object identifier.
        pub commit_object_id: [u8; 32],
        /// Resulting epoch.
        pub resulting_epoch: u64,
        /// Old policy identifier.
        pub old_policy_id: [u8; 32],
        /// Commit authorization identifier.
        pub commit_authorization_id: [u8; 32],
        /// Acknowledgement set digest.
        pub acknowledgement_set_digest: [u8; 32],
        /// Resulting group context digest.
        pub resulting_group_context_digest: [u8; 32],
        /// Resulting ratchet tree digest.
        pub resulting_ratchet_tree_digest: [u8; 32],
        /// Exported finalization authenticator.
        pub finalization_authenticator: [u8; 32],
    }
}

tls_struct! {
    /// `ArcFinalizationProof` (12.4).
    pub struct ArcFinalizationProof {
        /// Core fields.
        pub core: ArcFinalizationCoreTbs,
        /// The candidate receipt.
        pub receipt: ArcCandidateReceipt,
        /// The commit authorization.
        pub authorization: ArcCommitAuthorization,
        /// Acknowledgements, canonical by old leaf index.
        pub acknowledgements: TlsVec<ArcCommitAck, 1, 262_144>,
    }
}

tls_enum! {
    /// `ArcDisposition` (12.4).
    pub enum ArcDisposition: u8 {
        /// Finalize.
        Finalize = 1,
        /// Abort.
        Abort = 2,
    }
}

tls_struct! {
    /// `ArcDispositionVoteTBS` (12.4).
    pub struct ArcDispositionVoteTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Prior epoch.
        pub prior_epoch: u64,
        /// Prior accepted state identifier.
        pub prior_state_id: [u8; 32],
        /// Candidate sequence.
        pub candidate_sequence: u32,
        /// Slot predecessor record identifier.
        pub slot_predecessor_record_id: [u8; 32],
        /// Candidate identifier.
        pub candidate_id: [u8; 32],
        /// Disposition.
        pub disposition: ArcDisposition,
        /// Terminal identifier.
        pub terminal_id: [u8; 32],
        /// Reason code, zero for finalize.
        pub reason_code: u16,
    }
}

tls_struct! {
    /// `ArcFinalityVote` (12.4).
    pub struct ArcFinalityVote {
        /// Signer root fingerprint.
        pub signer_root_fingerprint: [u8; 32],
        /// Signer device identity.
        pub signer_device_id: [u8; 16],
        /// Signer certificate identifier.
        pub signer_device_certificate_id: [u8; 32],
        /// Device signature.
        pub device_signature: [u8; 64],
    }
}

tls_struct! {
    /// `ArcFinalizationRequest` (12.4), the `finalization_request` body.
    pub struct ArcFinalizationRequest {
        /// The proof.
        pub proof: ArcFinalizationProof,
        /// Votes, canonical by principal.
        pub votes: TlsVec<ArcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `ArcCommitFinalizationTBS` (12.4).
    pub struct ArcCommitFinalizationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Finalization identifier.
        pub finalization_id: [u8; 32],
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
        /// The request.
        pub request: ArcFinalizationRequest,
    }
}

tls_struct! {
    /// `ArcCommitFinalizationCertificate` (12.4).
    pub struct ArcCommitFinalizationCertificate {
        /// Signed fields.
        pub tbs: ArcCommitFinalizationTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `ArcNormalJoinAuthorizationProof` (12.4).
    pub struct ArcNormalJoinAuthorizationProof {
        /// Finalization identifier.
        pub finalization_id: [u8; 32],
        /// Finalization object identifier.
        pub finalization_object_id: [u8; 32],
        /// KeyPackageRef added.
        pub added_key_package_ref: KeyPackageRefField,
        /// Resulting leaf index.
        pub resulting_leaf_index: u32,
        /// Resulting leaf credential hash.
        pub resulting_leaf_credential_hash: [u8; 32],
    }
}

tls_struct! {
    /// `ArcDeliveredWelcome` (12.4), the `welcome_mls` body.
    pub struct ArcDeliveredWelcome {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Target account digest.
        pub target_account_id_digest: [u8; 32],
        /// Target device identity.
        pub target_device_id: [u8; 16],
        /// Join authorization proof.
        pub authorization: ArcNormalJoinAuthorizationProof,
        /// Transition proof references.
        pub transition_proofs: ArcJoinTransitionProofBundle,
        /// Immutable MLS Welcome bytes.
        pub welcome_bytes: Opaque<1, 4_190_000>,
    }
}

tls_enum! {
    /// `ArcCommitAbortReason` (12.4).
    pub enum ArcCommitAbortReason: u8 {
        /// The sender withdrew.
        SenderWithdrawn = 1,
        /// Policy recovery.
        PolicyRecovery = 2,
        /// Definitively invalid.
        DefinitivelyInvalid = 3,
        /// Local state unavailable.
        LocalStateUnavailable = 4,
        /// Staging timed out.
        StagingTimeout = 5,
    }
}

tls_struct! {
    /// `ArcAbortCoreTBS` (12.4).
    pub struct ArcAbortCoreTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Prior accepted state identifier.
        pub prior_state_id: [u8; 32],
        /// Candidate identifier.
        pub candidate_id: [u8; 32],
        /// Prior epoch.
        pub prior_epoch: u64,
        /// Reason.
        pub reason: ArcCommitAbortReason,
        /// Evidence digest.
        pub evidence_digest: [u8; 32],
    }
}

tls_struct! {
    /// `ArcAbortRequest` (12.4), the `abort_request` body.
    pub struct ArcAbortRequest {
        /// Core fields.
        pub core: ArcAbortCoreTbs,
        /// The candidate receipt.
        pub receipt: ArcCandidateReceipt,
        /// Votes, canonical.
        pub votes: TlsVec<ArcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `ArcCommitAbortTBS` (12.4).
    pub struct ArcCommitAbortTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Abort identifier.
        pub abort_id: [u8; 32],
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
        /// The request.
        pub request: ArcAbortRequest,
    }
}

tls_struct! {
    /// `ArcCommitAbortCertificate` (12.4).
    pub struct ArcCommitAbortCertificate {
        /// Signed fields.
        pub tbs: ArcCommitAbortTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}
