#![forbid(unsafe_code)]

//! Pure protocol state, authorization, plans, projections, and events.
//!
//! This crate owns no sockets, executors, storage handles, clocks, or random
//! generators. Callers provide validated commands and explicit external
//! values, then apply the resulting revision-bound plans.

mod command;
mod decision;
pub mod e2ee;
mod error;
pub mod federation;
mod history;
mod model;
mod persist;
mod projection;

pub use command::{
    AccountCommand, CanonicalCommand, CanonicalCommandView, ChannelCommand, ChannelTarget,
    CommandEnvelope, DepartureReason, DomainCommandKind, E2eeApplicationProof, InformationQuery,
    MaskList, MessageCommand, MessageKind, MessageTarget, MessageText, ModeChange, ModeCommand,
    ModeOperation, PresenceCommand, TagmsgClassification, UserQuery, VisibilityMode, WhoTarget,
};
pub use decision::{
    AdmissionSnapshot, ApplyReceipt, AuthorizationFailure, AuthorizedCommand, DomainEvent,
    E2eeBindingProof, E2eeRemovalFinality, EntropyPurpose, ExternalInputRequest, ExternalInputs,
    FailedTarget, MAX_INVITE_EXPIRATIONS_PER_PLAN, MessageBatch, MessageRoute, MutationPlan,
    PlanDecision, PreparedMutation, QueryPlan, RateBucket, RateCharge, RecipientSet, RejectedPlan,
    ResolvedMessageTarget, SanctionRequest, StorageClass, TargetFailure, is_expensive_query,
};
pub use error::DomainError;
pub use history::{
    HistoryError, HistoryPosition, HistoryQuery, HistoryReference, HistorySelection,
    HistorySelector, HistoryTimestamp, MAX_HISTORY_RESULTS, select_history, select_history_iter,
};
pub use model::{
    AccountLabelValue, AccountState, AwayText, ChannelKeyVerifier, ChannelModes, ChannelNameValue,
    ChannelScope, ChannelState, ContentPolicy, DirectMessagePolicy, DisplayNameValue, DomainState,
    GuestDirectMessagePolicy, HistoryPolicy, ListEntry, MAX_CHANNELS_PER_SESSION,
    MAX_CONTACTS_PER_ACCOUNT, MAX_GLOBAL_CHANNELS, MAX_INVITES_PER_CHANNEL, MAX_LOCAL_CHANNELS,
    MAX_MASK_ENTRIES_PER_LIST, MAX_MEMBERS_PER_CHANNEL, MAX_MONITORED_NICKNAMES,
    MAX_RESERVED_NICKNAMES, MAX_ROLE_GRANTS_PER_CHANNEL, MAX_SESSIONS_PER_ACCOUNT, Membership,
    ModerationAction, ModerationReason, ModerationReasonCode, NicknameValue,
    OperationalLimitValues, OperationalLimits, OperationalUsage, PersistencePolicy, PlaintextTopic,
    PresencePolicy, Principal, Role, Sanction, SessionSeed, SessionState, TopicText, Visibility,
};
pub use persist::{
    DurableAccount, DurableChannel, DurableInvite, DurableListEntry, DurableMembership,
    DurableSanction, DurableSession, DurableTopic, DurableWrite,
};
pub use projection::{
    AccountProjection, ChannelListProjection, ChannelListScan, ChannelProjection,
    LIST_RECORDS_PER_QUERY_TOKEN, MAX_LIST_SCAN_RECORDS, MemberProjection, PresenceProjection,
    ProjectionDecision, SessionProjection, TopicProjection,
};
