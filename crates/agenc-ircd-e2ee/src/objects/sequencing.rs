//! Candidate receipts, records, acknowledgements, finalization, abort, and
//! Welcome delivery objects (companion Sections 12.2 to 12.4).

use crate::error::E2eeError;
use crate::tls::{Opaque, Reader, TlsDecode, TlsEncode, TlsVec, Writer, tls_enum, tls_struct};

use super::conversation::{IrcCommitAuthorization, IrcJoinTransitionProofBundle};
use super::reinit::{
    IrcReInitAbortCertificate, IrcReInitActivationCertificate, IrcReInitAttemptReceipt,
};
use super::{GroupIdField, KeyPackageRefField};

tls_struct! {
    /// `IrcGroupGenesisTBS` (12.2).
    pub struct IrcGroupGenesisTbs {
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
    /// `IrcCandidateReceiptTBS` (12.2).
    pub struct IrcCandidateReceiptTbs {
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
    /// `IrcCandidateReceipt` (12.2).
    pub struct IrcCandidateReceipt {
        /// Signed fields.
        pub tbs: IrcCandidateReceiptTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_enum! {
    /// `IrcSequencerRecordKind` (12.2).
    pub enum IrcSequencerRecordKind: u8 {
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

/// `IrcSequencerRecord` (12.2), the tagged union of record history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrcSequencerRecord {
    /// A candidate receipt.
    Candidate(IrcCandidateReceipt),
    /// A finalization certificate.
    Finalization(IrcCommitFinalizationCertificate),
    /// An abort certificate.
    Abort(IrcCommitAbortCertificate),
    /// A ReInit attempt receipt.
    ReinitAttempt(IrcReInitAttemptReceipt),
    /// A ReInit activation certificate.
    ReinitActivation(IrcReInitActivationCertificate),
    /// A ReInit abort certificate.
    ReinitAbort(IrcReInitAbortCertificate),
}

impl IrcSequencerRecord {
    /// The union discriminant.
    #[must_use]
    pub const fn kind(&self) -> IrcSequencerRecordKind {
        match self {
            Self::Candidate(_) => IrcSequencerRecordKind::CandidateRecord,
            Self::Finalization(_) => IrcSequencerRecordKind::FinalizationRecord,
            Self::Abort(_) => IrcSequencerRecordKind::AbortRecord,
            Self::ReinitAttempt(_) => IrcSequencerRecordKind::ReinitAttemptRecord,
            Self::ReinitActivation(_) => IrcSequencerRecordKind::ReinitActivationRecord,
            Self::ReinitAbort(_) => IrcSequencerRecordKind::ReinitAbortRecord,
        }
    }
}

impl TlsEncode for IrcSequencerRecord {
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

impl TlsDecode for IrcSequencerRecord {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        Ok(match IrcSequencerRecordKind::decode_from(reader)? {
            IrcSequencerRecordKind::CandidateRecord => {
                Self::Candidate(TlsDecode::decode_from(reader)?)
            }
            IrcSequencerRecordKind::FinalizationRecord => {
                Self::Finalization(TlsDecode::decode_from(reader)?)
            }
            IrcSequencerRecordKind::AbortRecord => Self::Abort(TlsDecode::decode_from(reader)?),
            IrcSequencerRecordKind::ReinitAttemptRecord => {
                Self::ReinitAttempt(TlsDecode::decode_from(reader)?)
            }
            IrcSequencerRecordKind::ReinitActivationRecord => {
                Self::ReinitActivation(TlsDecode::decode_from(reader)?)
            }
            IrcSequencerRecordKind::ReinitAbortRecord => {
                Self::ReinitAbort(TlsDecode::decode_from(reader)?)
            }
        })
    }
}

tls_struct! {
    /// `IrcGroupContextDigestTBS` (12.3).
    pub struct IrcGroupContextDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded GroupContext.
        pub encoded_group_context: Opaque<1, 1_048_576>,
    }
}

tls_struct! {
    /// `IrcRatchetTreeDigestTBS` (12.3).
    pub struct IrcRatchetTreeDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded ratchet tree.
        pub encoded_ratchet_tree: Opaque<1, 4_194_304>,
    }
}

tls_struct! {
    /// `IrcGroupInfoDigestTBS` (12.3).
    pub struct IrcGroupInfoDigestTbs {
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Encoded GroupInfo.
        pub encoded_group_info: Opaque<1, 4_194_304>,
    }
}

tls_struct! {
    /// `IrcCommitAckTBS` (12.3).
    pub struct IrcCommitAckTbs {
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
    /// `IrcCommitAck` (12.3).
    pub struct IrcCommitAck {
        /// Signed fields.
        pub tbs: IrcCommitAckTbs,
        /// Old-leaf signature.
        pub old_leaf_signature: Opaque<1, 255>,
    }
}

tls_struct! {
    /// `IrcFinalizationCoreTBS` (12.4).
    pub struct IrcFinalizationCoreTbs {
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
    /// `IrcFinalizationProof` (12.4).
    pub struct IrcFinalizationProof {
        /// Core fields.
        pub core: IrcFinalizationCoreTbs,
        /// The candidate receipt.
        pub receipt: IrcCandidateReceipt,
        /// The commit authorization.
        pub authorization: IrcCommitAuthorization,
        /// Acknowledgements, canonical by old leaf index.
        pub acknowledgements: TlsVec<IrcCommitAck, 1, 262_144>,
    }
}

tls_enum! {
    /// `IrcDisposition` (12.4).
    pub enum IrcDisposition: u8 {
        /// Finalize.
        Finalize = 1,
        /// Abort.
        Abort = 2,
    }
}

tls_struct! {
    /// `IrcDispositionVoteTBS` (12.4).
    pub struct IrcDispositionVoteTbs {
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
        pub disposition: IrcDisposition,
        /// Terminal identifier.
        pub terminal_id: [u8; 32],
        /// Reason code, zero for finalize.
        pub reason_code: u16,
    }
}

tls_struct! {
    /// `IrcFinalityVote` (12.4).
    pub struct IrcFinalityVote {
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
    /// `IrcFinalizationRequest` (12.4), the `finalization_request` body.
    pub struct IrcFinalizationRequest {
        /// The proof.
        pub proof: IrcFinalizationProof,
        /// Votes, canonical by principal.
        pub votes: TlsVec<IrcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `IrcCommitFinalizationTBS` (12.4).
    pub struct IrcCommitFinalizationTbs {
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
        pub request: IrcFinalizationRequest,
    }
}

tls_struct! {
    /// `IrcCommitFinalizationCertificate` (12.4).
    pub struct IrcCommitFinalizationCertificate {
        /// Signed fields.
        pub tbs: IrcCommitFinalizationTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcNormalJoinAuthorizationProof` (12.4).
    pub struct IrcNormalJoinAuthorizationProof {
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
    /// `IrcDeliveredWelcome` (12.4), the `welcome_mls` body.
    pub struct IrcDeliveredWelcome {
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
        pub authorization: IrcNormalJoinAuthorizationProof,
        /// Transition proof references.
        pub transition_proofs: IrcJoinTransitionProofBundle,
        /// Immutable MLS Welcome bytes.
        pub welcome_bytes: Opaque<1, 4_190_000>,
    }
}

tls_enum! {
    /// `IrcCommitAbortReason` (12.4).
    pub enum IrcCommitAbortReason: u8 {
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
    /// `IrcAbortCoreTBS` (12.4).
    pub struct IrcAbortCoreTbs {
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
        pub reason: IrcCommitAbortReason,
        /// Evidence digest.
        pub evidence_digest: [u8; 32],
    }
}

tls_struct! {
    /// `IrcAbortRequest` (12.4), the `abort_request` body.
    pub struct IrcAbortRequest {
        /// Core fields.
        pub core: IrcAbortCoreTbs,
        /// The candidate receipt.
        pub receipt: IrcCandidateReceipt,
        /// Votes, canonical.
        pub votes: TlsVec<IrcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `IrcCommitAbortTBS` (12.4).
    pub struct IrcCommitAbortTbs {
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
        pub request: IrcAbortRequest,
    }
}

tls_struct! {
    /// `IrcCommitAbortCertificate` (12.4).
    pub struct IrcCommitAbortCertificate {
        /// Signed fields.
        pub tbs: IrcCommitAbortTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}
