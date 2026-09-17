//! Federation objects (companion Section 12.5): requests, results, response
//! descriptors, events, origins, and route state, with every closed
//! enumeration of the closed tables.
//!
//! Interpretation recorded for the completion notes: the specification
//! writes `IrcFederationResponseDescriptor responses<0..32>`, a bound no
//! descriptor fits under the TLS byte-length reading. The bound is read as
//! `MAX_BATCH_OBJECTS` descriptors; the vector carries the two-byte prefix
//! implied by its maximum encoded size (32 descriptors of at most 89 bytes).

use crate::tls::{Opaque, TlsVec, tls_enum, tls_struct};

use super::conversation::IrcConversationKind;
use super::{AccountIdField, OptionalAccountId, OptionalId16, OptionalId32};

tls_enum! {
    /// `IrcFederationOpcode`.
    pub enum IrcFederationOpcode: u8 {
        /// Channel application object.
        ApplicationChannel = 1,
        /// Direct application object.
        ApplicationDirect = 2,
        /// Reserve a channel route.
        ReserveChannel = 3,
        /// Reserve a direct route.
        ReserveDirect = 4,
        /// Bind a group.
        BindGroup = 5,
        /// Query a channel binding.
        QueryChannel = 6,
        /// Query a direct binding.
        QueryDirect = 7,
        /// Close a group.
        CloseGroup = 8,
        /// Submit a candidate.
        SubmitCandidate = 9,
        /// Submit an authorization.
        SubmitAuthorization = 10,
        /// Submit a Commit ACK.
        SubmitCommitAck = 11,
        /// Submit a finalization.
        SubmitFinalization = 12,
        /// Submit an abort.
        SubmitAbort = 13,
        /// Submit a ReInit attempt.
        SubmitReinitAttempt = 14,
        /// Submit a ReInit ACK.
        SubmitReinitAck = 15,
        /// Submit a ReInit activation.
        SubmitReinitActivate = 16,
        /// Submit a ReInit abort.
        SubmitReinitAbort = 17,
        /// Fetch an object.
        FetchObject = 18,
        /// Fetch authorizations.
        FetchAuthorizations = 19,
        /// Fetch ACKs.
        FetchAcks = 20,
        /// Fetch receipts.
        FetchReceipts = 21,
        /// Fetch an identity.
        FetchIdentity = 22,
        /// Fetch a root chain.
        FetchRootChain = 23,
        /// Publish an identity.
        PublishIdentity = 24,
        /// Fetch a roster.
        FetchRoster = 25,
        /// Publish a roster.
        PublishRoster = 26,
        /// Fetch capabilities.
        FetchCapabilities = 27,
        /// Publish capabilities.
        PublishCapabilities = 28,
        /// Fetch binding locks.
        FetchBindingLocks = 29,
        /// WHOAMI.
        Whoami = 30,
        /// Begin device attachment.
        AttachBegin = 31,
        /// Finish device attachment.
        AttachFinish = 32,
        /// Claim a KeyPackage.
        ClaimPackage = 33,
        /// Query a claim.
        ClaimStatus = 34,
        /// Publish a KeyPackage.
        PublishPackage = 35,
        /// Revoke a KeyPackage.
        RevokePackage = 36,
        /// Deliver a binding.
        DeliverBinding = 37,
        /// Deliver a Welcome.
        DeliverWelcome = 38,
        /// Fetch a mailbox page.
        FetchMailbox = 39,
        /// Acknowledge a mailbox item.
        AcknowledgeMailbox = 40,
        /// Publish a conversation policy.
        SubmitPolicy = 41,
        /// Accept a recovery submission (companion 13.7.4).
        SubmitRecovery = 42,
        /// Deliver the element an accepted recovery submission names.
        SubmitRecoveryElement = 43,
        /// Store a leaf-membership proof (companion 13.7.3).
        SubmitMembership = 44,
    }
}

tls_struct! {
    /// `IrcFederationRequest`, the `federation_request` body.
    pub struct IrcFederationRequest {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Home server identity.
        pub home_server_id: [u8; 16],
        /// Home server incarnation.
        pub server_incarnation: [u8; 16],
        /// Origin identity.
        pub origin_id: [u8; 16],
        /// Origin generation.
        pub origin_generation: u64,
        /// Companion operation sequence.
        pub operation_sequence: u64,
        /// Request identity.
        pub request_id: [u8; 16],
        /// Opcode.
        pub opcode: IrcFederationOpcode,
        /// Exactly one canonical parameter tuple.
        pub encoded_parameters: Opaque<0, 1_024>,
        /// Payload object identifier, empty only for a `none` row.
        pub payload_object_id: OptionalId32,
    }
}

tls_enum! {
    /// `IrcFederationStoreKind`.
    pub enum IrcFederationStoreKind: u8 {
        /// Authorization stored.
        StoreAuthorization = 1,
        /// Identity stored.
        StoreIdentity = 2,
        /// Roster stored.
        StoreRoster = 3,
        /// Capabilities stored.
        StoreCapabilities = 4,
        /// Package stored.
        StorePackage = 5,
        /// Application object stored.
        StoreApplication = 6,
        /// Binding stored.
        StoreBinding = 7,
        /// Welcome stored.
        StoreWelcome = 8,
        /// Staged ReInit stored.
        StoreStagedReinit = 9,
        /// Policy stored.
        StorePolicy = 10,
        /// Leaf-membership proof stored.
        StoreMembership = 11,
    }
}

tls_enum! {
    /// `IrcFederationPendingKind`.
    pub enum IrcFederationPendingKind: u8 {
        /// Finalization pending.
        PendingFinalization = 1,
        /// Abort pending.
        PendingAbort = 2,
        /// ReInit attempt pending.
        PendingReinitAttempt = 3,
        /// ReInit activation pending.
        PendingReinitActivate = 4,
        /// ReInit abort pending.
        PendingReinitAbort = 5,
    }
}

tls_enum! {
    /// `IrcFederationEmptyKind`.
    pub enum IrcFederationEmptyKind: u8 {
        /// No authorizations.
        EmptyAuthorizations = 1,
        /// No ACKs.
        EmptyAcks = 2,
        /// No receipts.
        EmptyReceipts = 3,
        /// No objects.
        EmptyObjects = 4,
        /// No identity.
        EmptyIdentity = 5,
        /// No root chain.
        EmptyRootChain = 6,
        /// No roster.
        EmptyRoster = 7,
        /// No capabilities.
        EmptyCapabilities = 8,
        /// No package.
        EmptyPackage = 9,
        /// No application mailbox item.
        EmptyApplication = 10,
        /// No binding.
        EmptyBinding = 11,
        /// No binding lock.
        EmptyBindingLock = 12,
        /// No Welcome.
        EmptyWelcome = 13,
        /// No staged ReInit.
        EmptyStagedReinit = 14,
    }
}

tls_enum! {
    /// `IrcFederationPackageKind`.
    pub enum IrcFederationPackageKind: u8 {
        /// A normal one-use package.
        NormalPackage = 1,
    }
}

tls_enum! {
    /// `IrcFederationMailboxKind`.
    pub enum IrcFederationMailboxKind: u8 {
        /// Application mailbox.
        MailboxApplication = 1,
        /// Binding mailbox.
        MailboxBinding = 2,
        /// Welcome mailbox.
        MailboxWelcome = 3,
        /// Staged ReInit mailbox.
        MailboxStagedReinit = 4,
    }
}

tls_enum! {
    /// `IrcFederationResultKind`.
    pub enum IrcFederationResultKind: u8 {
        /// Failed.
        Failed = 1,
        /// Accepted with a semantic event.
        AcceptedEvent = 2,
        /// Bound.
        Bound = 3,
        /// Closed.
        Closed = 4,
        /// Stored.
        Stored = 5,
        /// Commit ACK accepted.
        CommitAcked = 6,
        /// Pending.
        Pending = 7,
        /// Empty.
        Empty = 8,
        /// Account.
        Account = 9,
        /// Attached.
        Attached = 10,
        /// Attach challenge.
        AttachChallenge = 11,
        /// Revoked.
        Revoked = 12,
        /// Reserved.
        Reserved = 13,
        /// Finalized.
        Finalized = 14,
        /// Aborted.
        Aborted = 15,
        /// Claimed.
        Claimed = 16,
        /// Object page.
        ObjectPage = 17,
        /// Mailbox page.
        MailboxPage = 18,
        /// ReInit staged.
        ReinitStaged = 19,
        /// ReInit ACK accepted.
        ReinitAcked = 20,
        /// ReInit activated.
        ReinitActivated = 21,
        /// ReInit aborted.
        ReinitAborted = 22,
        /// Mailbox ACK accepted.
        MailboxAcked = 23,
        /// A recovery submission was accepted (companion 13.7.4).
        RecoveryAccepted = 24,
        /// A recovery element extended the restored head.
        RecoveryExtended = 25,
        /// A recovery element installed the permanent `closed` gate.
        RecoveryClosed = 26,
        /// A recovery element installed the permanent `conflict` gate.
        RecoveryConflict = 27,
    }
}

tls_struct! {
    /// `IrcFederationResponseDescriptor`.
    pub struct IrcFederationResponseDescriptor {
        /// Contiguous index from zero.
        pub response_index: u16,
        /// Wire kind of the response object.
        pub wire_kind: crate::object::IrcWireObjectKind,
        /// Object identifier.
        pub object_id: [u8; 32],
        /// Complete object size.
        pub total_size: u32,
        /// Delivery token, 32 bytes only for a mailbox page.
        pub delivery_token: OptionalId32,
        /// Target device, 16 bytes only for a mailbox page.
        pub target_device_id: OptionalId16,
    }
}

/// Maximum encoded bytes of `MAX_BATCH_OBJECTS` descriptors.
pub const MAX_RESPONSE_DESCRIPTOR_BYTES: usize = 32 * 89;

tls_struct! {
    /// `IrcFederationResult`, the `federation_result` body.
    pub struct IrcFederationResult {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Home server identity.
        pub home_server_id: [u8; 16],
        /// Home server incarnation.
        pub server_incarnation: [u8; 16],
        /// Origin identity.
        pub origin_id: [u8; 16],
        /// Origin generation.
        pub origin_generation: u64,
        /// Companion operation sequence.
        pub operation_sequence: u64,
        /// Request identity.
        pub request_id: [u8; 16],
        /// Request object identifier.
        pub request_object_id: [u8; 32],
        /// Coordinator state generation, zero for failed and `none`.
        pub coordinator_state_generation: u64,
        /// Completion event identity, empty for failed and `none`.
        pub completion_event_id: OptionalId16,
        /// Result kind.
        pub result_kind: IrcFederationResultKind,
        /// Exactly one canonical result tuple.
        pub encoded_result: Opaque<0, 1_024>,
        /// Snapshot token for pages and singleton responses.
        pub snapshot_token: OptionalId32,
        /// Next cursor, empty when exhausted.
        pub next_cursor: OptionalId32,
        /// Response descriptors, contiguous from zero.
        pub responses: TlsVec<IrcFederationResponseDescriptor, 0, MAX_RESPONSE_DESCRIPTOR_BYTES>,
    }
}

tls_enum! {
    /// `IrcFederationEventKind`.
    pub enum IrcFederationEventKind: u8 {
        /// Channel application.
        ChannelApplication = 1,
        /// Direct application.
        DirectApplication = 2,
        /// Candidate event.
        CandidateEvent = 3,
        /// Commit ACK event.
        CommitAckEvent = 4,
        /// Finalized event.
        FinalizedEvent = 5,
        /// Aborted event.
        AbortedEvent = 6,
        /// ReInit activated event.
        ReinitActivatedEvent = 7,
        /// ReInit aborted event.
        ReinitAbortedEvent = 8,
        /// Closed event.
        ClosedEvent = 9,
        /// Route state changed.
        RouteStateChanged = 10,
        /// Generic request completion.
        RequestCompleted = 11,
        /// Route state hidden.
        RouteStateHidden = 12,
        /// ReInit staged event.
        ReinitStagedEvent = 13,
        /// ReInit ACK event.
        ReinitAckEvent = 14,
    }
}

tls_struct! {
    /// `IrcFederationSourceView`, byte-identical to the base
    /// `FederationSourceView`.
    pub struct IrcFederationSourceView {
        /// User identity.
        pub user_id: [u8; 16],
        /// Current nickname.
        pub nickname: Opaque<1, 32>,
        /// Public user component.
        pub public_user_component: [u8; 10],
        /// Public host component.
        pub public_host_component: [u8; 16],
        /// Account label, possibly empty.
        pub account_label: Opaque<0, 32>,
    }
}

tls_struct! {
    /// `IrcFederationEvent`, the `federation_event` body.
    pub struct IrcFederationEvent {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Target server identity.
        pub target_server_id: [u8; 16],
        /// Delivery generation.
        pub delivery_generation: u64,
        /// Coordinator state generation.
        pub coordinator_state_generation: u64,
        /// Delivery sequence.
        pub delivery_sequence: u64,
        /// Event identity.
        pub event_id: [u8; 16],
        /// Event kind.
        pub event_kind: IrcFederationEventKind,
        /// Cross-profile mutation identity.
        pub cross_profile_mutation_id: OptionalId16,
        /// Cross-profile part index.
        pub cross_profile_part_index: u16,
        /// Cross-profile part count.
        pub cross_profile_part_count: u16,
        /// Conversation identifier.
        pub conversation_id: OptionalId32,
        /// Route sequence.
        pub route_sequence: u64,
        /// Origin identity.
        pub origin_id: OptionalId16,
        /// Origin generation.
        pub origin_generation: u64,
        /// Encoded source view.
        pub source_view: Opaque<0, 108>,
        /// Request home server identity.
        pub request_home_server_id: OptionalId16,
        /// Request server incarnation.
        pub request_server_incarnation: OptionalId16,
        /// Request origin identity.
        pub request_origin_id: OptionalId16,
        /// Request origin generation.
        pub request_origin_generation: u64,
        /// Request operation sequence.
        pub request_operation_sequence: u64,
        /// Request identity.
        pub request_id: OptionalId16,
        /// Payload object identifier.
        pub payload_object_id: OptionalId32,
        /// Exactly one canonical event result tuple.
        pub encoded_event_result: Opaque<0, 1_024>,
    }
}

tls_struct! {
    /// `IrcFederationOrigin`, the `federation_origin` body.
    pub struct IrcFederationOrigin {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// Home server identity.
        pub home_server_id: [u8; 16],
        /// Home server incarnation.
        pub server_incarnation: [u8; 16],
        /// Origin identity.
        pub origin_id: [u8; 16],
        /// Origin generation.
        pub origin_generation: u64,
        /// Previous origin state identifier.
        pub previous_origin_state_id: [u8; 32],
        /// Connection identity.
        pub connection_id: [u8; 16],
        /// Session identity, empty or 16 bytes.
        pub session_id: OptionalId16,
        /// User identity, empty or 16 bytes.
        pub user_id: OptionalId16,
        /// Account ID, empty or 24 bytes.
        pub account_id: OptionalAccountId,
        /// Account session generation.
        pub account_session_generation: u64,
        /// Connection nonce.
        pub connection_nonce: [u8; 32],
        /// Attached device, empty or 16 bytes.
        pub attached_device_id: OptionalId16,
        /// Device session generation.
        pub device_session_generation: u64,
    }
}

tls_enum! {
    /// `IrcRouteStateKind`.
    pub enum IrcRouteStateKind: u8 {
        /// An active route.
        ActiveRoute = 1,
        /// An encrypted tombstone.
        EncryptedTombstone = 2,
    }
}

tls_struct! {
    /// `IrcFederationRouteState`, the `federation_state` body.
    pub struct IrcFederationRouteState {
        /// Profile version.
        pub profile_version: u16,
        /// Network identity.
        pub network_id: [u8; 32],
        /// State generation.
        pub state_generation: u64,
        /// Conversation identifier.
        pub conversation_id: [u8; 32],
        /// Conversation kind.
        pub conversation_kind: IrcConversationKind,
        /// Concrete route binding.
        pub route_binding: [u8; 32],
        /// Semantic route lock identifier.
        pub semantic_route_lock_id: [u8; 32],
        /// Channel instance, 16 bytes for a channel.
        pub channel_instance_id: OptionalId16,
        /// Canonical channel name hash, zero for a direct route.
        pub canonical_channel_name_hash: [u8; 32],
        /// Smaller direct Account ID.
        pub direct_account_a: OptionalAccountId,
        /// Larger direct Account ID.
        pub direct_account_b: OptionalAccountId,
        /// Binding identifier.
        pub binding_id: [u8; 32],
        /// Finalized epoch.
        pub finalized_epoch: u64,
        /// Accepted state identifier.
        pub accepted_state_id: [u8; 32],
        /// Sequencer record head sequence.
        pub sequencer_record_head_sequence: u64,
        /// Sequencer record head identifier.
        pub sequencer_record_head_id: [u8; 32],
        /// Route state kind.
        pub state: IrcRouteStateKind,
    }
}

/// The Account ID envelope shared with request parameters.
pub type FederationAccountId = AccountIdField;
