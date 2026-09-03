//! Full ReInit and route migration objects (companion Section 13.8).

use crate::tls::{Opaque, TlsVec, tls_enum, tls_struct};

use super::GroupIdField;
use super::conversation::{IrcCommitApproval, IrcJoinTransitionProofBundle, IrcKeyPackagePlan};
use super::sequencing::IrcFinalityVote;

tls_enum! {
    /// `IrcReInitAckKind` (13.8).
    pub enum IrcReInitAckKind: u8 {
        /// The creator's locally constructed state.
        CreatorState = 1,
        /// A consumed Welcome.
        WelcomeJoin = 2,
    }
}

tls_struct! {
    /// `IrcReInitTargetTBS` (13.8).
    pub struct IrcReInitTargetTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Old conversation identifier.
        pub old_conversation_id: [u8; 32],
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
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
    /// `IrcReInitAttemptTBS` (13.8).
    pub struct IrcReInitAttemptTbs {
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
    /// `IrcReInitAttemptAuthorizationTBS` (13.8).
    pub struct IrcReInitAttemptAuthorizationTbs {
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
    /// `IrcReInitAttemptAuthorization` (13.8).
    pub struct IrcReInitAttemptAuthorization {
        /// Signed fields.
        pub tbs: IrcReInitAttemptAuthorizationTbs,
        /// Controller approvals.
        pub approvals: TlsVec<IrcCommitApproval, 144, 16_384>,
    }
}

tls_struct! {
    /// `IrcReInitAttempt` (13.8), the `reinit_attempt` body.
    pub struct IrcReInitAttempt {
        /// Signed fields.
        pub tbs: IrcReInitAttemptTbs,
        /// KeyPackage plan.
        pub key_package_plan: IrcKeyPackagePlan,
        /// Complete initial commit message bytes.
        pub initial_commit_bytes: Opaque<1, 3_145_728>,
        /// Attempt authorization.
        pub authorization: IrcReInitAttemptAuthorization,
        /// Creator's old-leaf signature.
        pub creator_old_leaf_signature: Opaque<1, 255>,
    }
}

tls_struct! {
    /// `IrcReInitAttemptReceiptTBS` (13.8).
    pub struct IrcReInitAttemptReceiptTbs {
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
    /// `IrcReInitAttemptReceipt` (13.8).
    pub struct IrcReInitAttemptReceipt {
        /// Signed fields.
        pub tbs: IrcReInitAttemptReceiptTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcStagedReInit` (13.8), the `staged_reinit` body.
    pub struct IrcStagedReInit {
        /// Old ReInit finalization identifier.
        pub old_reinit_state_id: [u8; 32],
        /// Old ReInit finalization object identifier.
        pub old_reinit_finalization_object_id: [u8; 32],
        /// The attempt receipt.
        pub receipt: IrcReInitAttemptReceipt,
        /// New conversation identifier.
        pub new_conversation_id: [u8; 32],
        /// Target account digest.
        pub target_account_id_digest: [u8; 32],
        /// Target device identity.
        pub target_device_id: [u8; 16],
        /// Transition proof references.
        pub transition_proofs: IrcJoinTransitionProofBundle,
        /// Immutable MLS Welcome bytes.
        pub welcome_bytes: Opaque<1, 4_190_000>,
    }
}

tls_struct! {
    /// `IrcReInitAckTBS` (13.8).
    pub struct IrcReInitAckTbs {
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
        pub ack_kind: IrcReInitAckKind,
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
    /// `IrcReInitAck` (13.8), the `reinit_ack` body.
    pub struct IrcReInitAck {
        /// Signed fields.
        pub tbs: IrcReInitAckTbs,
        /// Old-leaf signature.
        pub old_leaf_signature: Opaque<1, 255>,
    }
}

tls_enum! {
    /// `IrcReInitDisposition` (13.8).
    pub enum IrcReInitDisposition: u8 {
        /// Activate the successor.
        ActivateReinit = 1,
        /// Abort the attempt.
        AbortReinitAttempt = 2,
    }
}

tls_struct! {
    /// `IrcReInitDispositionVoteTBS` (13.8).
    pub struct IrcReInitDispositionVoteTbs {
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
        pub disposition: IrcReInitDisposition,
        /// Terminal identifier.
        pub terminal_id: [u8; 32],
        /// Reason code.
        pub reason_code: u16,
    }
}

tls_struct! {
    /// `IrcReInitActivationCoreTBS` (13.8).
    pub struct IrcReInitActivationCoreTbs {
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
    /// `IrcReInitActivationRequest` (13.8), the `reinit_activation_request` body.
    pub struct IrcReInitActivationRequest {
        /// Core fields.
        pub core: IrcReInitActivationCoreTbs,
        /// The attempt receipt.
        pub receipt: IrcReInitAttemptReceipt,
        /// The attempt.
        pub attempt: IrcReInitAttempt,
        /// Acknowledgements, canonical by old leaf index.
        pub acknowledgements: TlsVec<IrcReInitAck, 1, 1_048_576>,
        /// Votes, canonical.
        pub votes: TlsVec<IrcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `IrcReInitActivationTBS` (13.8).
    pub struct IrcReInitActivationTbs {
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
        pub request: IrcReInitActivationRequest,
    }
}

tls_struct! {
    /// `IrcReInitActivationCertificate` (13.8).
    pub struct IrcReInitActivationCertificate {
        /// Signed fields.
        pub tbs: IrcReInitActivationTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcReInitAbortCoreTBS` (13.8).
    pub struct IrcReInitAbortCoreTbs {
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
    /// `IrcReInitAbortRequest` (13.8), the `reinit_abort_request` body.
    pub struct IrcReInitAbortRequest {
        /// Core fields.
        pub core: IrcReInitAbortCoreTbs,
        /// The attempt receipt.
        pub receipt: IrcReInitAttemptReceipt,
        /// The attempt.
        pub attempt: IrcReInitAttempt,
        /// Votes, canonical.
        pub votes: TlsVec<IrcFinalityVote, 0, 16_384>,
    }
}

tls_struct! {
    /// `IrcReInitAbortTBS` (13.8).
    pub struct IrcReInitAbortTbs {
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
        pub request: IrcReInitAbortRequest,
    }
}

tls_struct! {
    /// `IrcReInitAbortCertificate` (13.8).
    pub struct IrcReInitAbortCertificate {
        /// Signed fields.
        pub tbs: IrcReInitAbortTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}
