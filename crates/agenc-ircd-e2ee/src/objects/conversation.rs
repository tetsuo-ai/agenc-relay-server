//! Conversation identity, sequencer credential, policy, binding, context,
//! reservation, and close objects (companion Sections 9 and 11.5).

use crate::tls::{Opaque, TlsVec, tls_enum, tls_struct};

use super::identity::{IrcDeviceRoster, IrcRootIdentity};
use super::{
    AccountIdField, GroupIdField, KeyPackageRefField, OptionalAccountId, OptionalId16, OptionalId32,
};

tls_struct! {
    /// `IrcChannelRouteTBS` (9.1).
    pub struct IrcChannelRouteTbs {
        /// Network identity.
        pub network_id: [u8; 32],
        /// Channel instance.
        pub channel_instance_id: [u8; 16],
    }
}

tls_struct! {
    /// `IrcDirectRouteTBS` (9.1).
    pub struct IrcDirectRouteTbs {
        /// Network identity.
        pub network_id: [u8; 32],
        /// Coordinator-chosen nonce.
        pub conversation_nonce: [u8; 32],
        /// Smaller Account ID.
        pub account_id_a: AccountIdField,
        /// Larger Account ID.
        pub account_id_b: AccountIdField,
    }
}

tls_struct! {
    /// `IrcSequencerCredentialTBS` (9.2).
    pub struct IrcSequencerCredentialTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Key generation.
        pub key_generation: u64,
        /// Sequencer public key.
        pub sequencer_public_key: [u8; 32],
        /// Earliest valid second.
        pub not_before: u64,
        /// Latest valid second.
        pub not_after: u64,
        /// Previous key identifier, all zero at generation zero.
        pub previous_key_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcSequencerCredential` (9.2).
    pub struct IrcSequencerCredential {
        /// Signed fields.
        pub tbs: IrcSequencerCredentialTbs,
        /// Previous-key continuity signature, empty at generation zero.
        pub continuity_signature: Opaque<0, 64>,
    }
}

tls_enum! {
    /// `IrcConversationKind` (9.3).
    pub enum IrcConversationKind: u8 {
        /// A channel conversation.
        Channel = 1,
        /// A direct conversation.
        Direct = 2,
    }
}

tls_enum! {
    /// `IrcMembershipPolicy` (9.3).
    pub enum IrcMembershipPolicy: u8 {
        /// Members may propose visible Adds.
        OpenVisible = 1,
        /// The controller threshold governs every change.
        Moderated = 2,
        /// Exactly two bound roots.
        FixedDirect = 3,
    }
}

tls_struct! {
    /// `IrcFinalityPrincipal` (9.3).
    pub struct IrcFinalityPrincipal {
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Device certificate identifier.
        pub device_certificate_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcPolicyTBS` (9.3).
    pub struct IrcPolicyTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Policy generation.
        pub policy_generation: u64,
        /// Previous policy identifier.
        pub previous_policy_id: [u8; 32],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Membership policy.
        pub membership_policy: IrcMembershipPolicy,
        /// MLS version.
        pub mls_version: u16,
        /// Selected suite.
        pub selected_suite: u16,
        /// Ordered allowed suites.
        pub allowed_suites: TlsVec<u16, 2, 32>,
        /// Concatenated controller root fingerprints in canonical order.
        pub controller_root_fingerprints: Opaque<0, 2_048>,
        /// Distinct controller roots required.
        pub controller_threshold: u16,
        /// Finality council, canonical.
        pub finality_principals: TlsVec<IrcFinalityPrincipal, 80, 5_120>,
        /// Byzantine fault bound.
        pub finality_fault_bound: u16,
        /// Whether out-of-band verified roots are required.
        pub require_oob_verified_roots: u8,
        /// Device cap per account.
        pub max_devices_per_account: u16,
        /// Leaf cap for the group.
        pub max_group_leaves: u32,
    }
}

tls_struct! {
    /// `IrcPolicyApproval` (9.3).
    pub struct IrcPolicyApproval {
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
    /// `IrcPolicy` (9.3).
    pub struct IrcPolicy {
        /// Signed fields.
        pub tbs: IrcPolicyTbs,
        /// Approvals, canonical.
        pub approvals: TlsVec<IrcPolicyApproval, 144, 16_384>,
    }
}

tls_enum! {
    /// `IrcCommitAuthorizationRule` (9.3).
    pub enum IrcCommitAuthorizationRule: u8 {
        /// Self update with no action bits.
        RoutineSelfUpdate = 1,
        /// One visible Add under `open_visible`.
        OpenVisibleAdd = 2,
        /// Any other permitted combination.
        ControlledTransition = 3,
        /// Narrow expired-roster recovery.
        RosterRecovery = 4,
        /// Clears a pending join.
        JoinConfirmation = 5,
        /// Installs the operational policy.
        BootstrapActivation = 6,
    }
}

/// `action_bits` values (9.3).
pub mod action_bits {
    /// Add leaf.
    pub const ADD_LEAF: u32 = 0x0000_0001;
    /// Remove leaf.
    pub const REMOVE_LEAF: u32 = 0x0000_0002;
    /// Roster proposal or reaffirmation.
    pub const ROSTER: u32 = 0x0000_0004;
    /// Policy change.
    pub const POLICY: u32 = 0x0000_0008;
    /// Sequencer change.
    pub const SEQUENCER: u32 = 0x0000_0010;
    /// Binding or route change.
    pub const BINDING: u32 = 0x0000_0020;
    /// Leaf credential change.
    pub const LEAF_CREDENTIAL: u32 = 0x0000_0040;
    /// ReInit proposal.
    pub const REINIT: u32 = 0x0000_0080;
    /// Pending-join change.
    pub const PENDING_JOIN: u32 = 0x0000_0100;
    /// Bootstrap-state change.
    pub const BOOTSTRAP: u32 = 0x0000_0200;
    /// Close-intent change.
    pub const CLOSE_INTENT: u32 = 0x0000_0400;
    /// Private-topic change.
    pub const PRIVATE_TOPIC: u32 = 0x0000_0800;
    /// Every bit defined in version 1.
    pub const KNOWN: u32 = 0x0000_0fff;
}

tls_struct! {
    /// `IrcCommitAuthorizationTBS` (9.3).
    pub struct IrcCommitAuthorizationTbs {
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
        /// Canonical validation time.
        pub canonical_validation_time: u64,
        /// Old policy identifier.
        pub old_policy_id: [u8; 32],
        /// Authorization rule.
        pub authorization_rule: IrcCommitAuthorizationRule,
        /// Derived action bits.
        pub action_bits: u32,
        /// Resulting policy identifier.
        pub resulting_policy_id: [u8; 32],
        /// Resulting group context digest.
        pub resulting_group_context_digest: [u8; 32],
        /// Resulting ratchet tree digest.
        pub resulting_ratchet_tree_digest: [u8; 32],
        /// Transition target digest, zero unless a transition class applies.
        pub transition_target_digest: [u8; 32],
    }
}

tls_struct! {
    /// `IrcCommitApproval` (9.3).
    pub struct IrcCommitApproval {
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
    /// `IrcCommitAuthorization` (9.3).
    pub struct IrcCommitAuthorization {
        /// Signed fields.
        pub tbs: IrcCommitAuthorizationTbs,
        /// Approvals, canonical, possibly empty.
        pub approvals: TlsVec<IrcCommitApproval, 0, 16_384>,
    }
}

tls_struct! {
    /// `IrcCommitApprovalEnvelope` (9.3), the `commit_approval` body.
    pub struct IrcCommitApprovalEnvelope {
        /// Signed fields.
        pub tbs: IrcCommitAuthorizationTbs,
        /// One approval.
        pub approval: IrcCommitApproval,
    }
}

tls_struct! {
    /// `IrcDeviceRosterUpdate` (9.3), the roster proposal body.
    pub struct IrcDeviceRosterUpdate {
        /// The complete roster.
        pub roster: IrcDeviceRoster,
    }
}

tls_struct! {
    /// `IrcInitialMemberPlanEntry` (9.4).
    pub struct IrcInitialMemberPlanEntry {
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Capability identifier.
        pub capability_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcInitialMemberPlan` (9.4).
    pub struct IrcInitialMemberPlan {
        /// Entries, canonical.
        pub entries: TlsVec<IrcInitialMemberPlanEntry, 1, 1_048_576>,
    }
}

tls_struct! {
    /// `IrcKeyPackagePlanEntry` (9.4).
    pub struct IrcKeyPackagePlanEntry {
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Device identity.
        pub device_id: [u8; 16],
        /// Capability identifier.
        pub capability_id: [u8; 32],
        /// Reserved KeyPackageRef, empty only for the creator.
        pub key_package_ref: Opaque<0, 255>,
        /// Leaf signature scheme.
        pub leaf_signature_scheme: u16,
        /// Leaf signature key digest.
        pub leaf_signature_key_digest: [u8; 32],
        /// Whether this entry is the creator.
        pub creator: u8,
    }
}

tls_struct! {
    /// `IrcKeyPackagePlan` (9.4).
    pub struct IrcKeyPackagePlan {
        /// Entries, canonical.
        pub entries: TlsVec<IrcKeyPackagePlanEntry, 1, 1_048_576>,
    }
}

tls_struct! {
    /// `IrcSemanticRouteTBS` (9.4).
    pub struct IrcSemanticRouteTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Smaller direct Account ID, empty for a channel.
        pub direct_account_a: OptionalAccountId,
        /// Larger direct Account ID, empty for a channel.
        pub direct_account_b: OptionalAccountId,
        /// Canonical channel name, empty for a direct conversation.
        pub canonical_channel_name: Opaque<0, 255>,
        /// Channel authority root, all zero for a direct conversation.
        pub channel_authority_root_fingerprint: [u8; 32],
        /// Semantic incarnation.
        pub semantic_incarnation: u64,
        /// Predecessor close identifier, all zero at incarnation zero.
        pub predecessor_close_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcContextCoreTBS` (9.4).
    pub struct IrcContextCoreTbs {
        /// Profile version.
        pub profile_version: u16,
        /// MLS version.
        pub mls_version: u16,
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Group identifier.
        pub group_id: GroupIdField,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Semantic route lock identifier.
        pub semantic_route_lock_id: [u8; 32],
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// Initial validation time.
        pub initial_validation_time: u64,
        /// Initial policy identifier.
        pub initial_policy_id: [u8; 32],
        /// Required operational policy identifier.
        pub required_operational_policy_id: [u8; 32],
        /// One while a generation-zero group bootstraps.
        pub initial_bootstrap_pending: u8,
        /// Initial member plan identifier.
        pub initial_member_plan_id: [u8; 32],
        /// Sequencer credential identifier.
        pub sequencer_credential_id: [u8; 32],
        /// Encoded `required_capabilities`.
        pub encoded_required_capabilities: Opaque<1, 65_535>,
    }
}

tls_struct! {
    /// `IrcBindingPrincipal` (9.4).
    pub struct IrcBindingPrincipal {
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation.
        pub roster_generation: u64,
        /// Roster identifier.
        pub roster_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcConversationBindingTBS` (9.4).
    pub struct IrcConversationBindingTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Binding generation.
        pub binding_generation: u64,
        /// Previous binding identifier.
        pub previous_binding_id: [u8; 32],
        /// Semantic route.
        pub semantic_route: IrcSemanticRouteTbs,
        /// Semantic route lock identifier.
        pub semantic_route_lock_id: [u8; 32],
        /// Channel instance, 16 bytes for a channel.
        pub channel_instance_id: OptionalId16,
        /// Conversation nonce, 32 bytes for a direct conversation.
        pub conversation_nonce: OptionalId32,
        /// Group identifier.
        pub group_id: GroupIdField,
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// MLS version.
        pub mls_version: u16,
        /// Cipher suite.
        pub cipher_suite: u16,
        /// Initial policy identifier.
        pub initial_policy_id: [u8; 32],
        /// Required operational policy identifier.
        pub required_operational_policy_id: [u8; 32],
        /// Initial member plan identifier.
        pub initial_member_plan_id: [u8; 32],
        /// Context core identifier.
        pub context_core_id: [u8; 32],
        /// Sequencer credential identifier.
        pub sequencer_credential_id: [u8; 32],
        /// Principals, canonical by Account ID.
        pub principals: TlsVec<IrcBindingPrincipal, 1, 65_535>,
    }
}

tls_struct! {
    /// `IrcBindingApproval` (9.4).
    pub struct IrcBindingApproval {
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
    /// `IrcConversationBinding` (9.4).
    pub struct IrcConversationBinding {
        /// Signed fields.
        pub tbs: IrcConversationBindingTbs,
        /// Approvals, canonical.
        pub approvals: TlsVec<IrcBindingApproval, 0, 65_535>,
    }
}

tls_struct! {
    /// `IrcRootBindingLockTBS` (9.4).
    pub struct IrcRootBindingLockTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Account ID envelope.
        pub account_id: AccountIdField,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Global lock sequence for this root.
        pub root_binding_sequence: u64,
        /// Previous lock identifier.
        pub previous_root_binding_lock_id: [u8; 32],
        /// Semantic route lock identifier.
        pub semantic_route_lock_id: [u8; 32],
        /// Binding identifier.
        pub binding_id: [u8; 32],
        /// Roster generation.
        pub roster_generation: u64,
        /// Roster identifier.
        pub roster_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcRootBindingLock` (9.4).
    pub struct IrcRootBindingLock {
        /// Signed fields.
        pub tbs: IrcRootBindingLockTbs,
        /// Root signature.
        pub root_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcConversationBindingPackage` (9.4), the `conversation_binding` body.
    pub struct IrcConversationBindingPackage {
        /// The binding.
        pub binding: IrcConversationBinding,
        /// The semantic initial member plan.
        pub initial_member_plan: IrcInitialMemberPlan,
        /// Root locks, one per principal at generation zero.
        pub root_binding_locks: TlsVec<IrcRootBindingLock, 0, 65_535>,
    }
}

tls_enum! {
    /// `IrcBindingProofKind` (9.4).
    pub enum IrcBindingProofKind: u8 {
        /// Genesis binding authorized by root locks.
        RootLockedGenesis = 1,
        /// Same-group transition authorized by a finalization.
        CommitFinalizedTransition = 2,
        /// ReInit target transition.
        ReinitTargetTransition = 3,
    }
}

tls_struct! {
    /// `IrcBindingChainEntry` (9.4).
    pub struct IrcBindingChainEntry {
        /// The package.
        pub package: IrcConversationBindingPackage,
        /// How the entry was authorized.
        pub proof_kind: IrcBindingProofKind,
    }
}

tls_struct! {
    /// `IrcRosterHead` (9.5).
    pub struct IrcRosterHead {
        /// Account ID digest.
        pub account_id_digest: [u8; 32],
        /// Root generation.
        pub root_generation: u64,
        /// Root fingerprint.
        pub root_fingerprint: [u8; 32],
        /// Roster generation.
        pub roster_generation: u64,
        /// Roster identifier.
        pub roster_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcPendingJoin` (9.5).
    pub struct IrcPendingJoin {
        /// Leaf index.
        pub leaf_index: u32,
        /// KeyPackageRef of the added leaf.
        pub key_package_ref: KeyPackageRefField,
    }
}

tls_struct! {
    /// `IrcCloseIntent` (9.5).
    pub struct IrcCloseIntent {
        /// Reason code.
        pub reason_code: u16,
        /// Validation time.
        pub validation_time: u64,
    }
}

tls_enum! {
    /// `IrcConversationLifecycleKind` (9.5).
    pub enum IrcConversationLifecycleKind: u8 {
        /// Active.
        ActiveConversation = 1,
        /// Closing.
        ClosingConversation = 2,
    }
}

tls_struct! {
    /// `IrcConversationLifecycle` (9.5).
    pub struct IrcConversationLifecycle {
        /// Lifecycle kind.
        pub kind: IrcConversationLifecycleKind,
        /// Close intent identifier, zero while active.
        pub close_intent_id: [u8; 32],
    }
}

tls_enum! {
    /// `IrcPolicyProofKind` (9.5).
    pub enum IrcPolicyProofKind: u8 {
        /// Genesis policy.
        PolicyRootLockedGenesis = 1,
        /// In-group finalized transition.
        PolicyCommitFinalizedTransition = 2,
        /// ReInit target policy.
        PolicyReinitTargetTransition = 3,
    }
}

tls_struct! {
    /// `IrcPolicyChainEntry` (9.5).
    pub struct IrcPolicyChainEntry {
        /// The policy.
        pub policy: IrcPolicy,
        /// How the entry was authorized.
        pub proof_kind: IrcPolicyProofKind,
    }
}

tls_enum! {
    /// `IrcJoinTransitionSubject` (9.5).
    pub enum IrcJoinTransitionSubject: u8 {
        /// A binding subject.
        BindingSubject = 1,
        /// A policy subject.
        PolicySubject = 2,
    }
}

tls_enum! {
    /// `IrcJoinTransitionProofRole` (9.5).
    pub enum IrcJoinTransitionProofRole: u8 {
        /// A finalized same-group transition.
        FinalizedGroupTransition = 1,
        /// The old ReInit Commit's finalization.
        ReinitTargetAuthorization = 2,
        /// The matching ReInit activation.
        ReinitActivation = 3,
    }
}

tls_struct! {
    /// `IrcJoinTransitionProofReference` (9.5).
    pub struct IrcJoinTransitionProofReference {
        /// Subject kind.
        pub subject_kind: IrcJoinTransitionSubject,
        /// Subject identifier.
        pub subject_id: [u8; 32],
        /// Proof role.
        pub proof_role: IrcJoinTransitionProofRole,
        /// Conversation whose log holds the record.
        pub record_conversation_id: [u8; 32],
        /// Semantic record identifier.
        pub authorizing_record_id: [u8; 32],
        /// Transport object identifier.
        pub authorizing_object_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcJoinTransitionProofBundle` (9.5).
    pub struct IrcJoinTransitionProofBundle {
        /// References, canonical.
        pub references: TlsVec<IrcJoinTransitionProofReference, 0, 262_144>,
    }
}

tls_struct! {
    /// `IrcMlsContext` (9.5), extension `0xF1C1`.
    pub struct IrcMlsContext {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// Initial validation time.
        pub initial_validation_time: u64,
        /// Current policy.
        pub policy: IrcPolicy,
        /// Pinned sequencer credential.
        pub sequencer: IrcSequencerCredential,
        /// Current binding.
        pub current_binding: IrcConversationBinding,
        /// Lifecycle.
        pub lifecycle: IrcConversationLifecycle,
        /// Private topic.
        pub private_topic: Opaque<0, 4_096>,
        /// One while bootstrapping.
        pub bootstrap_pending: u8,
        /// Roster heads, canonical.
        pub roster_heads: TlsVec<IrcRosterHead, 1, 65_535>,
        /// Pending joins, at most one.
        pub pending_joins: TlsVec<IrcPendingJoin, 0, 65_535>,
    }
}

tls_struct! {
    /// `IrcJoinAuthBundle` (9.5), extension `0xF1C3`.
    pub struct IrcJoinAuthBundle {
        /// Root chains, canonical by Account ID.
        pub root_chains: TlsVec<super::identity::IrcAccountRootChain, 1, 1_048_576>,
        /// Binding chain, oldest first.
        pub binding_chain: TlsVec<IrcBindingChainEntry, 1, 1_048_576>,
        /// Policy chain, oldest first.
        pub policy_chain: TlsVec<IrcPolicyChainEntry, 1, 1_048_576>,
        /// Roster chain, canonical.
        pub roster_chain: TlsVec<IrcDeviceRoster, 1, 3_145_728>,
    }
}

tls_struct! {
    /// `IrcReservationTBS` (11.5).
    pub struct IrcReservationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Reservation identifier.
        pub reservation_id: [u8; 16],
        /// Conversation kind.
        pub kind: IrcConversationKind,
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// Channel instance, 16 bytes for a channel.
        pub channel_instance_id: OptionalId16,
        /// Conversation nonce, 32 bytes for a direct conversation.
        pub conversation_nonce: OptionalId32,
        /// Full sequencer credential.
        pub sequencer: IrcSequencerCredential,
        /// Advertised application object limit.
        pub application_object_limit: u32,
        /// Advertised live object limit.
        pub live_object_limit: u32,
        /// Advertised KeyPackage object limit.
        pub key_package_object_limit: u32,
        /// Advertised identity object limit.
        pub identity_object_limit: u32,
        /// Advertised root chain object limit.
        pub root_chain_object_limit: u32,
        /// Advertised roster object limit.
        pub roster_object_limit: u32,
        /// Advertised capability object limit.
        pub capability_object_limit: u32,
        /// Advertised binding object limit.
        pub binding_object_limit: u32,
        /// Advertised commit approval object limit.
        pub commit_approval_object_limit: u32,
        /// Advertised commit ACK object limit.
        pub commit_ack_object_limit: u32,
        /// Advertised finalization object limit.
        pub finalization_object_limit: u32,
        /// Advertised abort object limit.
        pub abort_object_limit: u32,
        /// Advertised ReInit object limit.
        pub reinit_object_limit: u32,
        /// Advertised close object limit.
        pub close_object_limit: u32,
        /// Advertised Welcome object limit.
        pub welcome_object_limit: u32,
        /// Advertised live part limit.
        pub live_part_limit: u16,
        /// Advertised mailbox part limit.
        pub mailbox_part_limit: u16,
        /// Expiry second.
        pub expires_at: u64,
    }
}

tls_struct! {
    /// `IrcReservation` (11.5).
    pub struct IrcReservation {
        /// Signed fields.
        pub tbs: IrcReservationTbs,
        /// Sequencer signature.
        pub sequencer_signature: [u8; 64],
    }
}

tls_struct! {
    /// `IrcCloseAuthorizationTBS` (11.5).
    pub struct IrcCloseAuthorizationTbs {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Binding identifier.
        pub binding_id: [u8; 32],
        /// Finalization of the active-to-closing transition.
        pub authorizing_terminal_id: [u8; 32],
        /// Close intent.
        pub close_intent: IrcCloseIntent,
        /// Close intent identifier.
        pub close_intent_id: [u8; 32],
    }
}

tls_struct! {
    /// `IrcCloseAuthorization` (11.5).
    pub struct IrcCloseAuthorization {
        /// Signed fields.
        pub tbs: IrcCloseAuthorizationTbs,
        /// Controller approvals.
        pub approvals: TlsVec<IrcCommitApproval, 144, 16_384>,
    }
}

/// Re-export so chain entries and bundles can name the root type.
pub use super::identity::IrcAccountRootChain as RootChain;

/// Marker for callers that need the root identity type beside the chain.
pub type RootIdentity = IrcRootIdentity;
