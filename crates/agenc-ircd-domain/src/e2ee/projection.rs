//! Companion event projection (companion 12.5): the opcode, result, and
//! completion tables, the closed descriptor registry, route-state
//! entitlement with reference counting, recipient derivation, the
//! five-phase copy ordering, and cross-profile barrier planning.
//!
//! Event identifiers are sampled by the caller only after
//! [`EventPlan::order`] fixed the sequence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use agenc_ircd_types::ServerId;

use super::limits::{MAX_CROSS_PROFILE_AGGREGATE_BYTES, MAX_CROSS_PROFILE_PARTS};

/// A 32-byte identifier.
pub type Id = [u8; 32];

/// The forty federation opcodes, by companion discriminant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    /// `application_channel`.
    pub const APPLICATION_CHANNEL: Self = Self(1);
    /// `application_direct`.
    pub const APPLICATION_DIRECT: Self = Self(2);
    /// `reserve_channel`.
    pub const RESERVE_CHANNEL: Self = Self(3);
    /// `reserve_direct`.
    pub const RESERVE_DIRECT: Self = Self(4);
    /// `bind_group`.
    pub const BIND_GROUP: Self = Self(5);
    /// `query_channel`.
    pub const QUERY_CHANNEL: Self = Self(6);
    /// `query_direct`.
    pub const QUERY_DIRECT: Self = Self(7);
    /// `close_group`.
    pub const CLOSE_GROUP: Self = Self(8);
    /// `submit_candidate`.
    pub const SUBMIT_CANDIDATE: Self = Self(9);
    /// `submit_authorization`.
    pub const SUBMIT_AUTHORIZATION: Self = Self(10);
    /// `submit_commit_ack`.
    pub const SUBMIT_COMMIT_ACK: Self = Self(11);
    /// `submit_finalization`.
    pub const SUBMIT_FINALIZATION: Self = Self(12);
    /// `submit_abort`.
    pub const SUBMIT_ABORT: Self = Self(13);
    /// `submit_reinit_attempt`.
    pub const SUBMIT_REINIT_ATTEMPT: Self = Self(14);
    /// `submit_reinit_ack`.
    pub const SUBMIT_REINIT_ACK: Self = Self(15);
    /// `submit_reinit_activate`.
    pub const SUBMIT_REINIT_ACTIVATE: Self = Self(16);
    /// `submit_reinit_abort`.
    pub const SUBMIT_REINIT_ABORT: Self = Self(17);
    /// `fetch_object`.
    pub const FETCH_OBJECT: Self = Self(18);
    /// `fetch_authorizations`.
    pub const FETCH_AUTHORIZATIONS: Self = Self(19);
    /// `fetch_acks`.
    pub const FETCH_ACKS: Self = Self(20);
    /// `fetch_receipts`.
    pub const FETCH_RECEIPTS: Self = Self(21);
    /// `fetch_identity`.
    pub const FETCH_IDENTITY: Self = Self(22);
    /// `fetch_root_chain`.
    pub const FETCH_ROOT_CHAIN: Self = Self(23);
    /// `publish_identity`.
    pub const PUBLISH_IDENTITY: Self = Self(24);
    /// `fetch_roster`.
    pub const FETCH_ROSTER: Self = Self(25);
    /// `publish_roster`.
    pub const PUBLISH_ROSTER: Self = Self(26);
    /// `fetch_capabilities`.
    pub const FETCH_CAPABILITIES: Self = Self(27);
    /// `publish_capabilities`.
    pub const PUBLISH_CAPABILITIES: Self = Self(28);
    /// `fetch_binding_locks`.
    pub const FETCH_BINDING_LOCKS: Self = Self(29);
    /// `whoami`.
    pub const WHOAMI: Self = Self(30);
    /// `attach_begin`.
    pub const ATTACH_BEGIN: Self = Self(31);
    /// `attach_finish`.
    pub const ATTACH_FINISH: Self = Self(32);
    /// `claim_package`.
    pub const CLAIM_PACKAGE: Self = Self(33);
    /// `claim_status`.
    pub const CLAIM_STATUS: Self = Self(34);
    /// `publish_package`.
    pub const PUBLISH_PACKAGE: Self = Self(35);
    /// `revoke_package`.
    pub const REVOKE_PACKAGE: Self = Self(36);
    /// `deliver_binding`.
    pub const DELIVER_BINDING: Self = Self(37);
    /// `deliver_welcome`.
    pub const DELIVER_WELCOME: Self = Self(38);
    /// `fetch_mailbox`.
    pub const FETCH_MAILBOX: Self = Self(39);
    /// `acknowledge_mailbox`.
    pub const ACKNOWLEDGE_MAILBOX: Self = Self(40);
    /// `submit_policy`.
    pub const SUBMIT_POLICY: Self = Self(41);
    /// `submit_recovery` (companion 13.7.4).
    pub const SUBMIT_RECOVERY: Self = Self(42);
    /// `submit_recovery_element` (companion 13.7.4).
    pub const SUBMIT_RECOVERY_ELEMENT: Self = Self(43);
    /// `submit_membership` (companion 13.7.3).
    pub const SUBMIT_MEMBERSHIP: Self = Self(44);

    /// Every registered opcode.
    pub fn all() -> impl Iterator<Item = Self> {
        (1..=44).map(Self)
    }

    /// Whether the value is a registered opcode.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 >= 1 && self.0 <= 44
    }
}

/// The result kinds, by companion discriminant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ResultKind {
    /// `failed`.
    Failed,
    /// `accepted_event`.
    AcceptedEvent,
    /// `bound`.
    Bound,
    /// `closed`.
    Closed,
    /// `stored` with a store selector.
    Stored(StoreKind),
    /// `commit_acked`.
    CommitAcked,
    /// `pending` with a pending selector.
    Pending(PendingKind),
    /// `empty` with an empty selector.
    Empty(EmptyKind),
    /// `account`.
    Account,
    /// `attached`.
    Attached,
    /// `attach_challenge`.
    AttachChallenge,
    /// `revoked`.
    Revoked,
    /// `reserved`.
    Reserved,
    /// `finalized`.
    Finalized,
    /// `aborted`.
    Aborted,
    /// `claimed`.
    Claimed,
    /// `object_page`.
    ObjectPage,
    /// `mailbox_page`.
    MailboxPage,
    /// `reinit_staged`.
    ReinitStaged,
    /// `reinit_acked`.
    ReinitAcked,
    /// `reinit_activated`.
    ReinitActivated,
    /// `reinit_aborted`.
    ReinitAborted,
    /// `mailbox_acked`.
    MailboxAcked,
    /// `recovery_accepted` (companion 13.7.4).
    RecoveryAccepted,
    /// `recovery_extended`.
    RecoveryExtended,
    /// `recovery_closed`.
    RecoveryClosed,
    /// `recovery_conflict`.
    RecoveryConflict,
}

/// `IrcFederationStoreKind`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum StoreKind {
    /// `store_authorization`.
    Authorization,
    /// `store_identity`.
    Identity,
    /// `store_roster`.
    Roster,
    /// `store_capabilities`.
    Capabilities,
    /// `store_package`.
    Package,
    /// `store_application`.
    Application,
    /// `store_binding`.
    Binding,
    /// `store_welcome`.
    Welcome,
    /// `store_staged_reinit`.
    StagedReinit,
    /// `store_policy`.
    Policy,
    /// `store_membership`.
    Membership,
}

/// `IrcFederationPendingKind`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PendingKind {
    /// `pending_finalization`.
    Finalization,
    /// `pending_abort`.
    Abort,
    /// `pending_reinit_attempt`.
    ReinitAttempt,
    /// `pending_reinit_activate`.
    ReinitActivate,
    /// `pending_reinit_abort`.
    ReinitAbort,
}

/// `IrcFederationEmptyKind`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EmptyKind {
    /// `empty_authorizations`.
    Authorizations,
    /// `empty_acks`.
    Acks,
    /// `empty_receipts`.
    Receipts,
    /// `empty_objects`.
    Objects,
    /// `empty_identity`.
    Identity,
    /// `empty_root_chain`.
    RootChain,
    /// `empty_roster`.
    Roster,
    /// `empty_capabilities`.
    Capabilities,
    /// `empty_package`.
    Package,
    /// `empty_application`.
    Application,
    /// `empty_binding`.
    Binding,
    /// `empty_binding_lock`.
    BindingLock,
    /// `empty_welcome`.
    Welcome,
    /// `empty_staged_reinit`.
    StagedReinit,
}

/// The fourteen event kinds, by companion discriminant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EventKind {
    /// `channel_application`.
    ChannelApplication,
    /// `direct_application`.
    DirectApplication,
    /// `candidate_event`.
    Candidate,
    /// `commit_ack_event`.
    CommitAck,
    /// `finalized_event`.
    Finalized,
    /// `aborted_event`.
    Aborted,
    /// `reinit_activated_event`.
    ReinitActivated,
    /// `reinit_aborted_event`.
    ReinitAborted,
    /// `closed_event`.
    Closed,
    /// `route_state_changed`.
    RouteStateChanged,
    /// `request_completed`.
    RequestCompleted,
    /// `route_state_hidden`.
    RouteStateHidden,
    /// `reinit_staged_event`.
    ReinitStaged,
    /// `reinit_ack_event`.
    ReinitAck,
}

impl EventKind {
    /// The companion discriminant.
    #[must_use]
    pub const fn discriminant(self) -> u8 {
        match self {
            Self::ChannelApplication => 1,
            Self::DirectApplication => 2,
            Self::Candidate => 3,
            Self::CommitAck => 4,
            Self::Finalized => 5,
            Self::Aborted => 6,
            Self::ReinitActivated => 7,
            Self::ReinitAborted => 8,
            Self::Closed => 9,
            Self::RouteStateChanged => 10,
            Self::RequestCompleted => 11,
            Self::RouteStateHidden => 12,
            Self::ReinitStaged => 13,
            Self::ReinitAck => 14,
        }
    }

    /// The construction phase (1 to 5).
    #[must_use]
    pub const fn phase(self) -> u8 {
        match self {
            Self::RouteStateChanged => 1,
            Self::ChannelApplication
            | Self::DirectApplication
            | Self::Candidate
            | Self::CommitAck
            | Self::ReinitAck => 2,
            Self::ReinitStaged
            | Self::Finalized
            | Self::Aborted
            | Self::ReinitActivated
            | Self::ReinitAborted
            | Self::Closed => 3,
            Self::RouteStateHidden => 4,
            Self::RequestCompleted => 5,
        }
    }

    /// Whether the event carries an origin and source view.
    #[must_use]
    pub const fn has_source(self) -> bool {
        matches!(
            self,
            Self::ChannelApplication
                | Self::DirectApplication
                | Self::Candidate
                | Self::CommitAck
                | Self::ReinitAck
        )
    }

    /// Whether the event requires a data object.
    #[must_use]
    pub const fn has_payload(self) -> bool {
        matches!(
            self,
            Self::ChannelApplication
                | Self::DirectApplication
                | Self::Candidate
                | Self::CommitAck
                | Self::RouteStateChanged
                | Self::ReinitAck
        )
    }

    /// Whether the event always names a conversation.
    #[must_use]
    pub const fn has_conversation(self) -> bool {
        !matches!(self, Self::RequestCompleted)
    }
}

/// How a request completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// The named semantic event's home copy is the completion.
    Semantic(EventKind),
    /// A separate home-only `request_completed`.
    Generic,
    /// No completion; generation zero and empty identifier.
    None,
}

/// Why a result or completion combination was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The opcode is unknown.
    UnknownOpcode,
    /// The result kind is not permitted for the opcode.
    ResultNotPermitted,
    /// The plan violates ordering or capacity rules.
    InvalidPlan,
    /// A reference count would underflow or an entry is orphaned.
    ReferenceUnderflow,
    /// Arithmetic overflow.
    Overflow,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::UnknownOpcode => "unknown opcode",
            Self::ResultNotPermitted => "the result kind is not permitted for the opcode",
            Self::InvalidPlan => "the event plan is invalid",
            Self::ReferenceUnderflow => "a projection reference would underflow",
            Self::Overflow => "counter overflow",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for PlanError {}

/// The completion of a successful `(opcode, result)` per the 12.5 table;
/// `failed` is permitted for every opcode and completes with `None`.
pub fn completion_for(opcode: Opcode, result: ResultKind) -> Result<Completion, PlanError> {
    use Completion::{Generic, None as NoCompletion, Semantic};
    use ResultKind as R;
    if !opcode.is_valid() {
        return Err(PlanError::UnknownOpcode);
    }
    if result == R::Failed {
        return Ok(NoCompletion);
    }
    let completion = match (opcode, result) {
        (Opcode::APPLICATION_CHANNEL, R::AcceptedEvent) => Semantic(EventKind::ChannelApplication),
        (Opcode::APPLICATION_DIRECT, R::AcceptedEvent) => Semantic(EventKind::DirectApplication),
        (Opcode::RESERVE_CHANNEL | Opcode::RESERVE_DIRECT, R::Reserved) => Generic,
        (Opcode::BIND_GROUP, R::Bound) => Semantic(EventKind::RouteStateChanged),
        (Opcode::QUERY_CHANNEL | Opcode::QUERY_DIRECT, R::Bound | R::Empty(EmptyKind::Binding)) => {
            NoCompletion
        }
        (Opcode::CLOSE_GROUP, R::Closed) => Semantic(EventKind::Closed),
        (Opcode::SUBMIT_CANDIDATE, R::AcceptedEvent) => Semantic(EventKind::Candidate),
        (Opcode::SUBMIT_AUTHORIZATION, R::Stored(StoreKind::Authorization)) => Generic,
        (Opcode::SUBMIT_POLICY, R::Stored(StoreKind::Policy)) => Generic,
        (Opcode::SUBMIT_MEMBERSHIP, R::Stored(StoreKind::Membership)) => Generic,
        (Opcode::SUBMIT_RECOVERY, R::RecoveryAccepted) => Generic,
        // The closing submitter's edge need not host the route it closes:
        // the closed route's own event goes to the hosting edges, and the
        // submitter's completion is generic like every other recovery reply.
        (
            Opcode::SUBMIT_RECOVERY_ELEMENT,
            R::RecoveryExtended | R::RecoveryConflict | R::RecoveryClosed,
        ) => Generic,
        (Opcode::SUBMIT_COMMIT_ACK, R::CommitAcked) => Semantic(EventKind::CommitAck),
        (Opcode::SUBMIT_FINALIZATION, R::Pending(PendingKind::Finalization)) => Generic,
        (Opcode::SUBMIT_FINALIZATION, R::Finalized) => Semantic(EventKind::Finalized),
        (Opcode::SUBMIT_ABORT, R::Pending(PendingKind::Abort)) => Generic,
        (Opcode::SUBMIT_ABORT, R::Aborted) => Semantic(EventKind::Aborted),
        (Opcode::SUBMIT_REINIT_ATTEMPT, R::Pending(PendingKind::ReinitAttempt)) => Generic,
        (Opcode::SUBMIT_REINIT_ATTEMPT, R::ReinitStaged) => Semantic(EventKind::ReinitStaged),
        (Opcode::SUBMIT_REINIT_ACK, R::ReinitAcked) => Semantic(EventKind::ReinitAck),
        (Opcode::SUBMIT_REINIT_ACTIVATE, R::Pending(PendingKind::ReinitActivate)) => Generic,
        (Opcode::SUBMIT_REINIT_ACTIVATE, R::ReinitActivated) => {
            Semantic(EventKind::ReinitActivated)
        }
        (Opcode::SUBMIT_REINIT_ABORT, R::Pending(PendingKind::ReinitAbort)) => Generic,
        (Opcode::SUBMIT_REINIT_ABORT, R::ReinitAborted) => Semantic(EventKind::ReinitAborted),
        _ => return fetch_and_directory_completion(opcode, result),
    };
    Ok(completion)
}

fn fetch_and_directory_completion(
    opcode: Opcode,
    result: ResultKind,
) -> Result<Completion, PlanError> {
    use Completion::{Generic, None as NoCompletion};
    use ResultKind as R;
    let completion = match (opcode, result) {
        (Opcode::FETCH_OBJECT, R::ObjectPage | R::Empty(EmptyKind::Objects))
        | (Opcode::FETCH_AUTHORIZATIONS, R::ObjectPage | R::Empty(EmptyKind::Authorizations))
        | (Opcode::FETCH_ACKS, R::ObjectPage | R::Empty(EmptyKind::Acks))
        | (Opcode::FETCH_RECEIPTS, R::ObjectPage | R::Empty(EmptyKind::Receipts))
        | (Opcode::FETCH_IDENTITY, R::ObjectPage | R::Empty(EmptyKind::Identity))
        | (Opcode::FETCH_ROOT_CHAIN, R::ObjectPage | R::Empty(EmptyKind::RootChain))
        | (Opcode::FETCH_ROSTER, R::ObjectPage | R::Empty(EmptyKind::Roster))
        | (Opcode::FETCH_CAPABILITIES, R::ObjectPage | R::Empty(EmptyKind::Capabilities))
        | (Opcode::FETCH_BINDING_LOCKS, R::ObjectPage | R::Empty(EmptyKind::BindingLock))
        | (Opcode::WHOAMI, R::Account)
        | (Opcode::ATTACH_BEGIN, R::AttachChallenge)
        | (Opcode::CLAIM_STATUS, R::Claimed | R::Empty(EmptyKind::Package))
        | (Opcode::CLAIM_PACKAGE, R::Empty(EmptyKind::Package)) => NoCompletion,
        (Opcode::PUBLISH_IDENTITY, R::Stored(StoreKind::Identity))
        | (Opcode::PUBLISH_ROSTER, R::Stored(StoreKind::Roster))
        | (Opcode::PUBLISH_CAPABILITIES, R::Stored(StoreKind::Capabilities))
        | (Opcode::ATTACH_FINISH, R::Attached)
        | (Opcode::CLAIM_PACKAGE, R::Claimed)
        | (Opcode::PUBLISH_PACKAGE, R::Stored(StoreKind::Package))
        | (Opcode::REVOKE_PACKAGE, R::Revoked)
        | (Opcode::DELIVER_BINDING, R::Stored(StoreKind::Binding))
        | (Opcode::DELIVER_WELCOME, R::Stored(StoreKind::Welcome | StoreKind::StagedReinit))
        | (Opcode::FETCH_MAILBOX, R::MailboxPage)
        | (Opcode::ACKNOWLEDGE_MAILBOX, R::MailboxAcked) => Generic,
        (
            Opcode::FETCH_MAILBOX,
            R::Empty(
                EmptyKind::Application
                | EmptyKind::Binding
                | EmptyKind::Welcome
                | EmptyKind::StagedReinit,
            ),
        ) => NoCompletion,
        _ => return Err(PlanError::ResultNotPermitted),
    };
    Ok(completion)
}

/// The closed response descriptor registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorRule {
    /// Zero descriptors, empty snapshot and cursor.
    None,
    /// Exactly one object of the named wire kind (companion discriminant)
    /// with a fresh response snapshot token and an empty cursor.
    ExactlyOne(u8),
    /// One to `MAX_BATCH_OBJECTS` objects of the named wire kinds.
    Page(&'static [u8]),
    /// One to `MAX_BATCH_OBJECTS` mailbox objects, each with a token.
    MailboxPage,
}

const KIND_APPLICATION_MLS: u8 = 1;
const KIND_COMMIT_APPROVAL: u8 = 3;
const KIND_COMMIT_ACK: u8 = 4;
const KIND_ROOT_IDENTITY: u8 = 10;
const KIND_ROOT_IDENTITY_CHAIN: u8 = 11;
const KIND_DEVICE_ROSTER: u8 = 12;
const KIND_DEVICE_CAPABILITIES: u8 = 13;
const KIND_KEY_PACKAGE: u8 = 14;
const KIND_CONVERSATION_BINDING: u8 = 15;
const KIND_RESERVATION: u8 = 17;
const KIND_REINIT_ACK: u8 = 20;
const KIND_SEQUENCER_RECORD: u8 = 25;
const KIND_DEVICE_ATTACH_CHALLENGE: u8 = 26;
const KIND_ROOT_BINDING_LOCK: u8 = 28;

/// Every non-S2S kind, for the `fetch_object` page rule; the retained
/// leaf-membership proof (37) is fetched only through `fetch_object`.
const CLIENT_KINDS: [u8; 29] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 37,
];

/// The descriptor rule for a successful `(opcode, result)`.
pub fn descriptor_rule(opcode: Opcode, result: ResultKind) -> Result<DescriptorRule, PlanError> {
    completion_for(opcode, result)?;
    let rule = match (opcode, result) {
        (Opcode::RESERVE_CHANNEL | Opcode::RESERVE_DIRECT, ResultKind::Reserved) => {
            DescriptorRule::ExactlyOne(KIND_RESERVATION)
        }
        (Opcode::QUERY_CHANNEL | Opcode::QUERY_DIRECT, ResultKind::Bound) => {
            DescriptorRule::ExactlyOne(KIND_CONVERSATION_BINDING)
        }
        (Opcode::ATTACH_BEGIN, ResultKind::AttachChallenge) => {
            DescriptorRule::ExactlyOne(KIND_DEVICE_ATTACH_CHALLENGE)
        }
        (Opcode::CLAIM_PACKAGE | Opcode::CLAIM_STATUS, ResultKind::Claimed) => {
            DescriptorRule::ExactlyOne(KIND_KEY_PACKAGE)
        }
        (Opcode::FETCH_OBJECT, ResultKind::ObjectPage) => DescriptorRule::Page(&CLIENT_KINDS),
        (Opcode::FETCH_AUTHORIZATIONS, ResultKind::ObjectPage) => {
            DescriptorRule::Page(&[KIND_COMMIT_APPROVAL])
        }
        (Opcode::FETCH_ACKS, ResultKind::ObjectPage) => {
            DescriptorRule::Page(&[KIND_COMMIT_ACK, KIND_REINIT_ACK])
        }
        (Opcode::FETCH_RECEIPTS, ResultKind::ObjectPage) => {
            DescriptorRule::Page(&[KIND_SEQUENCER_RECORD])
        }
        (Opcode::FETCH_IDENTITY, ResultKind::ObjectPage) => {
            DescriptorRule::ExactlyOne(KIND_ROOT_IDENTITY)
        }
        (Opcode::FETCH_ROOT_CHAIN, ResultKind::ObjectPage) => {
            DescriptorRule::ExactlyOne(KIND_ROOT_IDENTITY_CHAIN)
        }
        (Opcode::FETCH_ROSTER, ResultKind::ObjectPage) => {
            DescriptorRule::ExactlyOne(KIND_DEVICE_ROSTER)
        }
        (Opcode::FETCH_CAPABILITIES, ResultKind::ObjectPage) => {
            DescriptorRule::Page(&[KIND_DEVICE_CAPABILITIES])
        }
        (Opcode::FETCH_BINDING_LOCKS, ResultKind::ObjectPage) => {
            DescriptorRule::Page(&[KIND_ROOT_BINDING_LOCK])
        }
        (Opcode::FETCH_MAILBOX, ResultKind::MailboxPage) => DescriptorRule::MailboxPage,
        _ => DescriptorRule::None,
    };
    Ok(rule)
}

/// The wire kind a mailbox page of `kind` carries.
#[must_use]
pub const fn mailbox_wire_kind(kind: super::mailbox::MailboxKind) -> u8 {
    match kind {
        super::mailbox::MailboxKind::Application => KIND_APPLICATION_MLS,
        super::mailbox::MailboxKind::Binding => KIND_CONVERSATION_BINDING,
        super::mailbox::MailboxKind::Welcome => 9,
        super::mailbox::MailboxKind::StagedReinit => 19,
    }
}

/// Why an edge needs a direct route view.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EntitlementReason {
    /// An unacknowledged event for a local attached origin.
    Event,
    /// An unfinished operation for a local attached origin.
    Operation,
    /// A live mailbox item for a local target device.
    Mailbox,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct References {
    events: u64,
    operations: u64,
    mailbox: u64,
}

impl References {
    const fn total(self) -> u64 {
        self.events + self.operations + self.mailbox
    }

    fn slot(&mut self, reason: EntitlementReason) -> &mut u64 {
        match reason {
            EntitlementReason::Event => &mut self.events,
            EntitlementReason::Operation => &mut self.operations,
            EntitlementReason::Mailbox => &mut self.mailbox,
        }
    }
}

/// Standing route projection per edge: channel routes follow the base
/// channel-detail entitlement; direct routes are reference counted.
#[derive(Clone, Debug, Default)]
pub struct RouteEntitlements {
    channel: BTreeMap<(ServerId, Id), bool>,
    direct: BTreeMap<(ServerId, Id), References>,
}

impl RouteEntitlements {
    /// Retires standing route views when a verified successor takes the route.
    /// Historical proof objects remain available through their old log.
    pub fn retire_conversation(&mut self, conversation: Id) {
        self.channel.retain(|(_, id), _| *id != conversation);
        self.direct.retain(|(_, id), _| *id != conversation);
    }

    /// Empty entitlements.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `edge` currently holds the route view of `conversation`.
    #[must_use]
    pub fn entitled(&self, edge: ServerId, conversation: &Id) -> bool {
        self.channel
            .get(&(edge, *conversation))
            .copied()
            .unwrap_or(false)
            || self
                .direct
                .get(&(edge, *conversation))
                .is_some_and(|references| references.total() > 0)
    }

    /// Follows the base channel-detail entitlement; returns whether the
    /// standing changed (newly entitled, or lost).
    pub fn set_channel(&mut self, edge: ServerId, conversation: Id, entitled: bool) -> bool {
        let previous = self.entitled(edge, &conversation);
        if entitled {
            self.channel.insert((edge, conversation), true);
        } else {
            self.channel.remove(&(edge, conversation));
        }
        previous != self.entitled(edge, &conversation)
    }

    /// Adds one direct reference; returns whether the edge became entitled.
    pub fn require_direct(
        &mut self,
        edge: ServerId,
        conversation: Id,
        reason: EntitlementReason,
    ) -> Result<bool, PlanError> {
        let previous = self.entitled(edge, &conversation);
        let references = self.direct.entry((edge, conversation)).or_default();
        let slot = references.slot(reason);
        *slot = slot.checked_add(1).ok_or(PlanError::Overflow)?;
        Ok(!previous)
    }

    /// Releases one direct reference; returns whether the edge lost its
    /// last standing.
    pub fn release_direct(
        &mut self,
        edge: ServerId,
        conversation: Id,
        reason: EntitlementReason,
    ) -> Result<bool, PlanError> {
        let references = self
            .direct
            .get_mut(&(edge, conversation))
            .ok_or(PlanError::ReferenceUnderflow)?;
        let slot = references.slot(reason);
        *slot = slot.checked_sub(1).ok_or(PlanError::ReferenceUnderflow)?;
        let hidden = references.total() == 0;
        if hidden {
            self.direct.remove(&(edge, conversation));
        }
        Ok(hidden && !self.entitled(edge, &conversation))
    }

    /// Every conversation `edge` is entitled to, in canonical order: the
    /// ESTATE entry set.
    #[must_use]
    pub fn snapshot(&self, edge: ServerId) -> BTreeSet<Id> {
        self.channel
            .iter()
            .filter(|((server, _), entitled)| *server == edge && **entitled)
            .map(|((_, conversation), _)| *conversation)
            .chain(
                self.direct
                    .iter()
                    .filter(|((server, _), references)| *server == edge && references.total() > 0)
                    .map(|((_, conversation), _)| *conversation),
            )
            .collect()
    }

    /// Visits the exact canonical snapshot set without allocating a copy.
    pub fn snapshot_iter(&self, edge: ServerId) -> impl Iterator<Item = Id> + '_ {
        let mut channel = self
            .channel
            .range((edge, [0; 32])..=(edge, [0xff; 32]))
            .filter(|(_, entitled)| **entitled)
            .map(|((_, conversation), _)| *conversation)
            .peekable();
        let mut direct = self
            .direct
            .range((edge, [0; 32])..=(edge, [0xff; 32]))
            .filter(|(_, references)| references.total() > 0)
            .map(|((_, conversation), _)| *conversation)
            .peekable();
        std::iter::from_fn(move || match (channel.peek(), direct.peek()) {
            (Some(left), Some(right)) if left < right => channel.next(),
            (Some(left), Some(right)) if left == right => {
                let _same = direct.next();
                channel.next()
            }
            (Some(_), Some(_)) | (None, Some(_)) => direct.next(),
            (Some(_), None) => channel.next(),
            (None, None) => None,
        })
    }

    /// Drops every entry of `edge` (peer fence).
    pub fn fence(&mut self, edge: ServerId) {
        self.channel.retain(|(server, _), _| *server != edge);
        self.direct.retain(|(server, _), _| *server != edge);
    }
}

/// One planned event copy before identifiers are assigned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedEvent {
    /// Event kind.
    pub kind: EventKind,
    /// Conversation identifier, absent only for a non-conversation
    /// generic completion.
    pub conversation_id: Option<Id>,
    /// Target edge.
    pub target: ServerId,
    /// Referenced payload object.
    pub payload_object_id: Option<Id>,
    /// Whether this copy is the home completion copy.
    pub completion: bool,
    /// Route sequence.
    pub route_sequence: u64,
    /// Encoded event plus required payload bytes, for capacity planning.
    pub bytes: u64,
}

impl PlannedEvent {
    fn sort_key(&self) -> (u8, Option<Id>, u8, [u8; 16], Option<Id>) {
        (
            self.kind.phase(),
            self.conversation_id,
            self.kind.discriminant(),
            *self.target.as_bytes(),
            self.payload_object_id,
        )
    }

    fn check(&self) -> Result<(), PlanError> {
        let conversation_ok =
            self.conversation_id.is_some() || self.kind == EventKind::RequestCompleted;
        let payload_ok = self.kind.has_payload() == self.payload_object_id.is_some();
        let completion_ok = !self.completion || self.kind != EventKind::RouteStateHidden;
        if conversation_ok && payload_ok && completion_ok {
            Ok(())
        } else {
            Err(PlanError::InvalidPlan)
        }
    }
}

/// The ordered companion copies of one mutation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventPlan {
    events: Vec<PlannedEvent>,
}

impl EventPlan {
    /// Orders `events` by the five phases and the in-phase key, refusing
    /// duplicate logical copies and more than one completion.
    pub fn order(mut events: Vec<PlannedEvent>) -> Result<Self, PlanError> {
        for event in &events {
            event.check()?;
        }
        events.sort_by_key(PlannedEvent::sort_key);
        let mut seen = BTreeSet::new();
        for event in &events {
            if !seen.insert(event.sort_key()) {
                return Err(PlanError::InvalidPlan);
            }
        }
        if events.iter().filter(|event| event.completion).count() > 1 {
            return Err(PlanError::InvalidPlan);
        }
        Ok(Self { events })
    }

    /// The events in delivery order.
    #[must_use]
    pub fn events(&self) -> &[PlannedEvent] {
        &self.events
    }

    /// The target-specific subsequence, in order.
    #[must_use]
    pub fn for_target(&self, target: ServerId) -> Vec<&PlannedEvent> {
        self.events
            .iter()
            .filter(|event| event.target == target)
            .collect()
    }

    /// Every distinct target.
    #[must_use]
    pub fn targets(&self) -> BTreeSet<ServerId> {
        self.events.iter().map(|event| event.target).collect()
    }
}

/// The cross-profile barrier decision for one target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierPlan {
    /// Target edge.
    pub target: ServerId,
    /// Base part count, indices `0..base`.
    pub base_parts: usize,
    /// Companion part count, indices `base..base + companion`.
    pub companion_parts: usize,
    /// Aggregate event plus payload bytes.
    pub aggregate_bytes: u64,
}

impl BarrierPlan {
    /// Total parts.
    #[must_use]
    pub const fn part_count(&self) -> usize {
        self.base_parts + self.companion_parts
    }
}

/// Plans barriers for every target that receives both a base and a
/// companion slice; a one-profile target gets none.
pub fn plan_barriers(
    base: &BTreeMap<ServerId, (usize, u64)>,
    companion: &EventPlan,
) -> Result<Vec<BarrierPlan>, PlanError> {
    let mut plans = Vec::new();
    for target in companion.targets() {
        let Some((base_parts, base_bytes)) = base.get(&target).copied() else {
            continue;
        };
        if base_parts == 0 {
            continue;
        }
        let companion_events = companion.for_target(target);
        let companion_bytes = companion_events
            .iter()
            .try_fold(0_u64, |sum, event| sum.checked_add(event.bytes))
            .ok_or(PlanError::Overflow)?;
        let aggregate_bytes = base_bytes
            .checked_add(companion_bytes)
            .ok_or(PlanError::Overflow)?;
        let part_count = base_parts
            .checked_add(companion_events.len())
            .ok_or(PlanError::Overflow)?;
        if !(2..=MAX_CROSS_PROFILE_PARTS).contains(&part_count)
            || aggregate_bytes > MAX_CROSS_PROFILE_AGGREGATE_BYTES
        {
            return Err(PlanError::InvalidPlan);
        }
        plans.push(BarrierPlan {
            target,
            base_parts,
            companion_parts: companion_events.len(),
            aggregate_bytes,
        });
    }
    Ok(plans)
}

/// The recipient set of one semantic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Audience<'a> {
    /// A channel conversation: edges hosting a base membership.
    Channel {
        /// Edges hosting at least one current member.
        hosting: &'a BTreeSet<ServerId>,
    },
    /// A direct conversation: edges hosting an attached bound device.
    Direct {
        /// Edges hosting an ACKed origin whose device is attached and active.
        attached: &'a BTreeSet<ServerId>,
    },
}

/// Derives the target set: the audience, unioned with the home edge when
/// it must receive the completion copy.
#[must_use]
pub fn recipients(audience: &Audience<'_>, home: Option<ServerId>) -> BTreeSet<ServerId> {
    let mut targets = match audience {
        Audience::Channel { hosting } => (*hosting).clone(),
        Audience::Direct { attached } => (*attached).clone(),
    };
    if let Some(home) = home {
        targets.insert(home);
    }
    targets
}

#[cfg(test)]
#[path = "tests/projection.rs"]
mod tests;
