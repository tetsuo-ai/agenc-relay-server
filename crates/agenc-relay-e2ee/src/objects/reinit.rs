//! Full ReInit and route migration objects (companion Section 13.8).

use crate::tls::{Opaque, TlsVec, tls_enum, tls_struct};

use super::GroupIdField;
use super::conversation::{ArcCommitApproval, ArcJoinTransitionProofBundle, ArcKeyPackagePlan};
use super::sequencing::ArcFinalityVote;

tls_enum! {
    /// `ArcReInitAckKind` (13.8).
    pub enum ArcReInitAckKind: u8 {
        /// The creator's locally constructed state.
        CreatorState = 1,
        /// A consumed Welcome.
        WelcomeJoin = 2,
    }
}

tls_struct! {
    /// `ArcReInitTargetTBS` (13.8). It covers no accepted-state or record ID
    /// of the old group: every field is fixed by the old conversation and the
    /// ReInit Proposal, so the target exists before the old ReInit Commit
    /// whose authorization commits its digest ([`crate::reinit_target`]).
    pub struct ArcReInitTargetTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Target group identifier.
        pub target_group_id: GroupIdField,
        /// Target version.
        pub target_version: u16,
        /// Target suite.
        pub target_suite: u16,
        /// Target context core identifier.
        pub target_context_core_id: [u8; 32],
        /// Target binding identifier.
        pub target_binding_id: [u8; 32],
        /// Initial member plan identifier.
        pub initial_member_plan_id: [u8; 32],
        /// Encoded target extensions.
        pub encoded_target_extensions: Opaque<1, 1_048_576>,
    }
}

tls_struct! {
    /// `ArcReInitAttemptTBS` (13.8).
    pub struct ArcReInitAttemptTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Creator's old leaf index.
        pub creator_old_leaf_index: u32,
        /// Creator's old credential hash.
        pub creator_old_credential_hash: [u8; 32],
        /// Target group identifier.
        pub target_group_id: GroupIdField,
        /// Target version.
        pub target_version: u16,
        /// Target suite.
        pub target_suite: u16,
        /// Target context digest.
        pub target_context_digest: [u8; 32],
        /// Target binding identifier.
        pub target_binding_id: [u8; 32],
        /// Initial member plan identifier.
        pub initial_member_plan_id: [u8; 32],
        /// KeyPackage plan identifier.
        pub key_package_plan_id: [u8; 32],
        /// Initial commit digest.
        pub initial_commit_digest: [u8; 32],
        /// Attempt authorization identifier.
        pub attempt_authorization_id: [u8; 32],
        /// New group info digest.
        pub new_group_info_digest: [u8; 32],
        /// New group context digest.
        pub new_group_context_digest: [u8; 32],
        /// New ratchet tree digest.
        pub new_ratchet_tree_digest: [u8; 32],
        /// New exporter authenticator.
        pub new_exporter_authenticator: [u8; 32],
    }
}

tls_struct! {
    /// `ArcReInitAttemptAuthorizationTBS` (13.8).
    pub struct ArcReInitAttemptAuthorizationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Creator's old leaf index.
        pub creator_old_leaf_index: u32,
        /// Creator's old credential hash.
        pub creator_old_credential_hash: [u8; 32],
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Target context digest.
        pub target_context_digest: [u8; 32],
        /// Target binding identifier.
        pub target_binding_id: [u8; 32],
        /// Initial member plan identifier.
        pub initial_member_plan_id: [u8; 32],
        /// KeyPackage plan identifier.
        pub key_package_plan_id: [u8; 32],
        /// Initial commit digest.
        pub initial_commit_digest: [u8; 32],
        /// New group info digest.
        pub new_group_info_digest: [u8; 32],
        /// New group context digest.
        pub new_group_context_digest: [u8; 32],
        /// New ratchet tree digest.
        pub new_ratchet_tree_digest: [u8; 32],
        /// New exporter authenticator.
        pub new_exporter_authenticator: [u8; 32],
    }
}

tls_struct! {
    /// `ArcReInitAttemptAuthorization` (13.8).
    pub struct ArcReInitAttemptAuthorization {
        /// Signed fields.
        pub tbs: ArcReInitAttemptAuthorizationTbs,
        /// Controller approvals.
        pub approvals: TlsVec<ArcCommitApproval, 144, 16_384>,
    }
}

tls_struct! {
    /// `ArcReInitAttempt` (13.8), the `reinit_attempt` body.
    pub struct ArcReInitAttempt {
        /// Signed fields.
        pub tbs: ArcReInitAttemptTbs,
        /// The exact target whose digest is `tbs.target_context_digest`,
        /// copied byte for byte from the one the old candidate authorization
        /// committed.
        pub target: ArcReInitTargetTbs,
        /// KeyPackage plan.
        pub key_package_plan: ArcKeyPackagePlan,
        /// Complete initial commit message bytes.
        pub initial_commit_bytes: Opaque<1, 3_145_728>,
        /// Attempt authorization.
        pub authorization: ArcReInitAttemptAuthorization,
        /// Creator's old-leaf signature.
        pub creator_old_leaf_signature: Opaque<1, 255>,
    }
}

tls_struct! {
    /// `ArcReInitAttemptReceiptTBS` (13.8).
    pub struct ArcReInitAttemptReceiptTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Attempt identifier.
        pub reinit_attempt_id: [u8; 32],
        /// Attempt object identifier.
        pub attempt_object_id: [u8; 32],
        /// Informational sequencing second.
        pub sequenced_at: u64,
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
    }
}

tls_struct! {
    /// `ArcReInitAttemptReceipt` (13.8).
    pub struct ArcReInitAttemptReceipt {
        /// Signed fields.
        pub tbs: ArcReInitAttemptReceiptTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `ArcStagedReInit` (13.8), the `staged_reinit` body.
    pub struct ArcStagedReInit {
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Old ReInit finalization object identifier.
        pub old_reinit_finalization_object_id: [u8; 32],
        /// The attempt receipt.
        pub receipt: ArcReInitAttemptReceipt,
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Target account digest.
        pub target_account_id_digest: [u8; 32],
        /// Target device identity.
        pub target_device_id: [u8; 16],
        /// Transition proof references.
        pub transition_proofs: ArcJoinTransitionProofBundle,
        /// Immutable MLS Welcome bytes.
        pub welcome_bytes: Opaque<1, 4_190_000>,
    }
}

tls_struct! {
    /// `ArcReInitAckTBS` (13.8).
    pub struct ArcReInitAckTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt identifier.
        pub reinit_attempt_id: [u8; 32],
        /// Acknowledgement kind.
        pub ack_kind: ArcReInitAckKind,
        /// New group info digest.
        pub new_group_info_digest: [u8; 32],
        /// New group context digest.
        pub new_group_context_digest: [u8; 32],
        /// New ratchet tree digest.
        pub new_ratchet_tree_digest: [u8; 32],
        /// New exporter authenticator.
        pub new_exporter_authenticator: [u8; 32],
        /// Old leaf index.
        pub old_leaf_index: u32,
        /// Old credential hash.
        pub old_credential_hash: [u8; 32],
        /// New leaf index.
        pub new_leaf_index: u32,
        /// KeyPackageRef, empty only for the creator.
        pub key_package_ref: Opaque<0, 255>,
    }
}

tls_struct! {
    /// `ArcReInitAck` (13.8), the `reinit_ack` body.
    pub struct ArcReInitAck {
        /// Signed fields.
        pub tbs: ArcReInitAckTbs,
        /// Old-leaf signature.
        pub old_leaf_signature: Opaque<1, 255>,
    }
}

tls_enum! {
    /// `ArcReInitDisposition` (13.8).
    pub enum ArcReInitDisposition: u8 {
        /// Activate the successor.
        ActivateReinit = 1,
        /// Abort the attempt.
        AbortReinitAttempt = 2,
    }
}

tls_struct! {
    /// `ArcReInitDispositionVoteTBS` (13.8).
    pub struct ArcReInitDispositionVoteTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Slot predecessor record identifier.
        pub slot_predecessor_record_id: [u8; 32],
        /// Attempt identifier.
        pub reinit_attempt_id: [u8; 32],
        /// Disposition.
        pub disposition: ArcReInitDisposition,
        /// Terminal identifier.
        pub terminal_id: [u8; 32],
        /// Reason code.
        pub reason_code: u16,
    }
}

tls_struct! {
    /// `ArcReInitActivationCoreTBS` (13.8).
    pub struct ArcReInitActivationCoreTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Attempt identifier.
        pub reinit_attempt_id: [u8; 32],
        /// New group info digest.
        pub new_group_info_digest: [u8; 32],
        /// New group context digest.
        pub new_group_context_digest: [u8; 32],
        /// New ratchet tree digest.
        pub new_ratchet_tree_digest: [u8; 32],
        /// New exporter authenticator.
        pub new_exporter_authenticator: [u8; 32],
        /// Acknowledgement set digest.
        pub acknowledgement_set_digest: [u8; 32],
    }
}

tls_struct! {
    /// `ArcReInitActivationRequest` (13.8), the `reinit_activation_request` body.
    pub struct ArcReInitActivationRequest {
        /// Core fields.
        pub core: ArcReInitActivationCoreTbs,
        /// The attempt receipt.
        pub receipt: ArcReInitAttemptReceipt,
        /// The attempt.
        pub attempt: ArcReInitAttempt,
        /// Acknowledgements, canonical by old leaf index.
        pub acknowledgements: TlsVec<ArcReInitAck, 1, 1_048_576>,
        /// Votes, canonical.
        pub votes: TlsVec<ArcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `ArcReInitActivationTBS` (13.8).
    pub struct ArcReInitActivationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Activation identifier.
        pub reinit_activation_id: [u8; 32],
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
        /// The request.
        pub request: ArcReInitActivationRequest,
    }
}

tls_struct! {
    /// `ArcReInitActivationCertificate` (13.8).
    pub struct ArcReInitActivationCertificate {
        /// Signed fields.
        pub tbs: ArcReInitActivationTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `ArcReInitAbortCoreTBS` (13.8).
    pub struct ArcReInitAbortCoreTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Attempt sequence.
        pub attempt_sequence: u32,
        /// Slot predecessor record identifier.
        pub slot_predecessor_record_id: [u8; 32],
        /// Attempt identifier.
        pub reinit_attempt_id: [u8; 32],
        /// Reason code.
        pub reason_code: u16,
        /// Evidence digest.
        pub evidence_digest: [u8; 32],
    }
}

tls_struct! {
    /// `ArcReInitAbortRequest` (13.8), the `reinit_abort_request` body.
    pub struct ArcReInitAbortRequest {
        /// Core fields.
        pub core: ArcReInitAbortCoreTbs,
        /// The attempt receipt.
        pub receipt: ArcReInitAttemptReceipt,
        /// The attempt.
        pub attempt: ArcReInitAttempt,
        /// Votes, canonical.
        pub votes: TlsVec<ArcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `ArcReInitAbortTBS` (13.8).
    pub struct ArcReInitAbortTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Route sequence.
        pub route_sequence: u64,
        /// Predecessor record identifier.
        pub predecessor_record_id: [u8; 32],
        /// Abort identifier.
        pub reinit_abort_id: [u8; 32],
        /// Sequencer key identifier.
        pub sequencer_key_id: [u8; 32],
        /// The request.
        pub request: ArcReInitAbortRequest,
    }
}

tls_struct! {
    /// `ArcReInitAbortCertificate` (13.8).
    pub struct ArcReInitAbortCertificate {
        /// Signed fields.
        pub tbs: ArcReInitAbortTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}
