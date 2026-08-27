#![forbid(unsafe_code)]

//! Pure protocol state, authorization, plans, projections, and events.
//!
//! This crate owns no sockets, executors, storage handles, clocks, or random
//! generators. Callers provide validated commands and explicit external
//! values, then apply the resulting revision-bound plans.

mod command;
mod decision;
mod error;
mod model;
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
    ResolvedMessageTarget, SanctionRequest, StorageClass, TargetFailure,
};
pub use error::DomainError;
pub use model::{
    AccountLabelValue, AccountState, AwayText, ChannelModes, ChannelNameValue, ChannelScope,
    ChannelState, ContentPolicy, DirectMessagePolicy, DisplayNameValue, DomainState,
    GuestDirectMessagePolicy, HistoryPolicy, ListEntry, MAX_CHANNELS_PER_SESSION,
    MAX_CONTACTS_PER_ACCOUNT, MAX_INVITES_PER_CHANNEL, MAX_MASK_ENTRIES_PER_LIST,
    MAX_MEMBERS_PER_CHANNEL, MAX_MONITORED_NICKNAMES, MAX_RESERVED_NICKNAMES,
    MAX_ROLE_GRANTS_PER_CHANNEL, MAX_SESSIONS_PER_ACCOUNT, Membership, ModerationAction,
    ModerationReason, ModerationReasonCode, NicknameValue, PersistencePolicy, PlaintextTopic,
    PresencePolicy, Principal, Role, Sanction, SessionSeed, SessionState, TopicText, Visibility,
};
pub use projection::{
    AccountProjection, ChannelListProjection, ChannelProjection, MemberProjection,
    PresenceProjection, ProjectionDecision, SessionProjection, TopicProjection,
};
