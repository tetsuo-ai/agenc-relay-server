//! Revision-fenced authorization, external requests, and pure plans.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_types::{
    AccountDeletionToken, AccountId, ChannelInstanceId, ControlPolicy, EntryId, InviteId,
    MaskSubject, MessageId, MonotonicTick, Revision, SessionId, TypedMask, UserId, UtcSecond,
};

use crate::command::{CanonicalCommandData, MaskList, MessageTarget};
use crate::model::{AccountDeletionChallengeState, Invite, MAX_MEMBERS_PER_CHANNEL};
use crate::persist::{
    DurableAccount, DurableChannel, DurableSanction, DurableSession, DurableWrite,
    duplicate_typed_mask,
};
use crate::{
    AccountCommand, AccountState, CanonicalCommand, ChannelCommand, ChannelNameValue,
    CommandEnvelope, ContentPolicy, DirectMessagePolicy, DisplayNameValue, DomainCommandKind,
    DomainError, DomainState, GuestDirectMessagePolicy, HistoryPolicy, Membership, MessageKind,
    ModeChange, ModeCommand, ModeOperation, ModerationAction, ModerationReasonCode, NicknameValue,
    PersistencePolicy, PlaintextTopic, PresenceCommand, PresencePolicy, Principal, Role, Sanction,
    SessionSeed, SessionState, TagmsgClassification, TopicText, Visibility, VisibilityMode,
};

/// Maximum number of expired invitations removed by one timer plan.
pub const MAX_INVITE_EXPIRATIONS_PER_PLAN: usize = 256;
/// How long a same-account OPAQUE authentication stays fresh for destructive
/// account controls, in monotonic milliseconds (spec 1485-1486: 300 seconds).
const FRESH_AUTH_WINDOW_MILLIS: u64 = 300_000;
/// Lifetime of one account-deletion challenge token in monotonic milliseconds
/// (spec 2113: 60-second monotonic expiry).
const DELETION_CHALLENGE_LIFETIME_MILLIS: u64 = 60_000;
/// Lifetime of one channel invite in wall-clock seconds (spec 2049: 10 minutes).
const INVITE_LIFETIME_SECONDS: u64 = 600;
/// The invite lifetime in monotonic milliseconds.
const INVITE_LIFETIME_MILLIS: u64 = INVITE_LIFETIME_SECONDS * 1_000;

/// One hierarchical admission bucket selected without peer-controlled text.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RateBucket {
    /// Per-session registered command bucket.
    RegisteredCommand(UserId),
    /// Stricter per-session guest message bucket.
    GuestMessage(UserId),
    /// Per-account message bucket.
    AccountMessage(AccountId),
    /// Per-channel message bucket.
    ChannelMessage(ChannelInstanceId),
    /// Per-session expensive query bucket.
    ExpensiveQuery(UserId),
    /// Per-principal channel-key attempt bucket.
    ChannelKeyAttempt(Principal),
}

/// One exact token charge assessed before semantic planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateCharge {
    bucket: RateBucket,
    tokens: u64,
}

impl RateCharge {
    /// Creates a nonzero token charge.
    pub const fn new(bucket: RateBucket, tokens: u64) -> Result<Self, DomainError> {
        if tokens == 0 {
            return Err(DomainError::InvalidArgument);
        }
        Ok(Self { bucket, tokens })
    }

    /// Returns the selected hierarchical bucket.
    #[must_use]
    pub const fn bucket(self) -> RateBucket {
        self.bucket
    }

    /// Returns the token count.
    #[must_use]
    pub const fn tokens(self) -> u64 {
        self.tokens
    }
}

/// Available token credit supplied by the runtime-owned monotonic buckets.
pub struct AdmissionSnapshot {
    available: BTreeMap<RateBucket, u64>,
}

impl AdmissionSnapshot {
    /// Builds a finite snapshot, rejecting duplicate bucket entries.
    pub fn new(entries: Vec<(RateBucket, u64)>) -> Result<Self, DomainError> {
        let mut available = BTreeMap::new();
        for (bucket, tokens) in entries {
            if available.insert(bucket, tokens).is_some() {
                return Err(DomainError::InvalidArgument);
            }
        }
        Ok(Self { available })
    }

    fn admits(&self, charges: &[RateCharge]) -> Result<bool, DomainError> {
        let mut required = BTreeMap::new();
        for charge in charges {
            let total = required
                .get(&charge.bucket)
                .copied()
                .unwrap_or(0_u64)
                .checked_add(charge.tokens)
                .ok_or(DomainError::Overflow)?;
            required.insert(charge.bucket, total);
        }
        Ok(required.into_iter().all(|(bucket, tokens)| {
            self.available
                .get(&bucket)
                .is_some_and(|available| *available >= tokens)
        }))
    }
}

/// Authorization rejection with the charges that still apply.
pub struct AuthorizationFailure {
    error: DomainError,
    charges: Vec<RateCharge>,
    silent: bool,
}

impl AuthorizationFailure {
    /// Returns the closed public-safe failure.
    #[must_use]
    pub const fn error(&self) -> DomainError {
        self.error
    }

    /// Borrows charges assessed before the rejection.
    #[must_use]
    pub fn charges(&self) -> &[RateCharge] {
        &self.charges
    }

    /// Reports whether NOTICE semantics suppress an automatic reply.
    #[must_use]
    pub const fn is_silent(&self) -> bool {
        self.silent
    }
}

/// A canonical command proven against the current session fence and admission.
pub struct AuthorizedCommand {
    user_id: UserId,
    principal: Principal,
    expected_state_revision: Revision,
    command: CanonicalCommand,
    charges: Vec<RateCharge>,
}

/// Complete typed input for one content-free moderation decision.
pub struct SanctionRequest {
    /// Live user exercising moderation authority.
    pub actor_user_id: UserId,
    /// Account or guest authority being sanctioned.
    pub target: Principal,
    /// Optional channel scope; absence selects network scope.
    pub channel_id: Option<ChannelInstanceId>,
    /// Server-enforceable action.
    pub action: ModerationAction,
    /// Closed audit-safe reason classification.
    pub reason_code: ModerationReasonCode,
    /// Optional bounded free-form reason for encrypted storage.
    pub reason: Option<crate::ModerationReason>,
    /// Explicit authoritative creation second.
    pub created_at: UtcSecond,
    /// Optional explicit expiry second.
    pub expires_at: Option<UtcSecond>,
}

/// Companion-approved roster proof for the one-way plaintext-to-E2EE transition.
pub struct E2eeBindingProof {
    channel_id: ChannelInstanceId,
    channel_revision: Revision,
    approved_roster: Vec<(UserId, AccountId)>,
}

impl E2eeBindingProof {
    /// Creates a bounded, canonical proof from a companion-approved roster.
    pub fn new(
        channel_id: ChannelInstanceId,
        channel_revision: Revision,
        mut approved_roster: Vec<(UserId, AccountId)>,
    ) -> Result<Self, DomainError> {
        if approved_roster.is_empty() || approved_roster.len() > MAX_MEMBERS_PER_CHANNEL {
            return Err(DomainError::LimitExceeded);
        }
        approved_roster.sort_unstable_by_key(|(user_id, _)| *user_id);
        if approved_roster
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.0 == right.0))
        {
            return Err(DomainError::InvalidArgument);
        }
        Ok(Self {
            channel_id,
            channel_revision,
            approved_roster,
        })
    }

    /// Returns the immutable channel instance approved by the companion.
    #[must_use]
    pub const fn channel_id(&self) -> ChannelInstanceId {
        self.channel_id
    }

    /// Returns the exact channel revision approved by the companion.
    #[must_use]
    pub const fn channel_revision(&self) -> Revision {
        self.channel_revision
    }

    /// Borrows the canonical user-to-account roster approved by every member.
    #[must_use]
    pub fn approved_roster(&self) -> &[(UserId, AccountId)] {
        &self.approved_roster
    }
}

/// Companion finality proof for one pending E2EE membership removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eeRemovalFinality {
    channel_id: ChannelInstanceId,
    user_id: UserId,
    channel_revision: Revision,
}

impl E2eeRemovalFinality {
    /// Records the pending removal and exact channel revision finalized by the companion.
    #[must_use]
    pub const fn new(
        channel_id: ChannelInstanceId,
        user_id: UserId,
        channel_revision: Revision,
    ) -> Self {
        Self {
            channel_id,
            user_id,
            channel_revision,
        }
    }
}

impl AuthorizedCommand {
    /// Discards the authorization proof and returns the canonical command.
    /// The caller must authorize it again before planning at another revision.
    #[must_use]
    pub fn into_command(self) -> CanonicalCommand {
        self.command
    }

    /// Returns the exact live user authority.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Returns account or guest authority without conversion.
    #[must_use]
    pub const fn principal(&self) -> Principal {
        self.principal
    }

    /// Borrows the assessed hierarchical charges.
    #[must_use]
    pub fn charges(&self) -> &[RateCharge] {
        &self.charges
    }
}

/// Purpose bound to one fresh random identifier request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyPurpose {
    /// A new channel creation at this target index.
    ChannelInstance(u8),
    /// An accepted message at this target index.
    Message(u8),
    /// One single-use channel invitation.
    Invite,
    /// One new typed mask-list entry.
    MaskEntry(u8),
    /// One account-deletion challenge owned by the later auth flow.
    AccountDeletionChallenge,
}

/// One explicit clock, entropy, or expensive verification request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalInputRequest {
    /// Obtain one trusted UTC second for display or retention state.
    UtcNow {
        /// Stable position in this plan's external request vector.
        request_sequence: u16,
    },
    /// Obtain one process-local monotonic tick for expiry policy.
    MonotonicNow {
        /// Stable position in this plan's external request vector.
        request_sequence: u16,
    },
    /// Fill one purpose-bound identifier from operating-system entropy.
    Entropy {
        /// Stable position in this plan's external request vector.
        request_sequence: u16,
        /// Domain purpose that prevents substitution.
        purpose: EntropyPurpose,
        /// Exact number of requested bytes.
        bytes: u8,
    },
    /// Run the real-or-dummy channel-key verification class.
    ChannelKeyVerification {
        /// Stable position in this plan's external request vector.
        request_sequence: u16,
        /// Canonical JOIN target position.
        target_index: u8,
    },
    /// Derive and return one verifier for a `MODE +k` change.
    ChannelKeyConstruction {
        /// Stable position in this plan's external request vector.
        request_sequence: u16,
        /// Canonical MODE change position.
        change_index: u8,
    },
}

impl ExternalInputRequest {
    /// Returns this request's stable identity inside the plan.
    #[must_use]
    pub const fn request_sequence(self) -> u16 {
        match self {
            Self::UtcNow { request_sequence }
            | Self::MonotonicNow { request_sequence }
            | Self::Entropy {
                request_sequence, ..
            }
            | Self::ChannelKeyVerification {
                request_sequence, ..
            }
            | Self::ChannelKeyConstruction {
                request_sequence, ..
            } => request_sequence,
        }
    }
}

/// Complete caller-supplied results for one external request vector.
#[derive(Default)]
pub struct ExternalInputs {
    /// Trusted UTC value, when requested.
    pub utc_now: Option<UtcSecond>,
    /// Reports that a requested wall-clock read failed.
    pub wall_clock_unavailable: bool,
    /// Monotonic policy time, when requested.
    pub monotonic_now: Option<MonotonicTick>,
    /// Fresh channel identities in request order.
    pub channel_ids: Vec<ChannelInstanceId>,
    /// Fresh message identities in request order.
    pub message_ids: Vec<MessageId>,
    /// Fresh invitation identities in request order.
    pub invite_ids: Vec<InviteId>,
    /// Fresh list-entry identities in request order.
    pub entry_ids: Vec<EntryId>,
    /// Fresh deletion tokens in request order.
    pub deletion_tokens: Vec<AccountDeletionToken>,
    /// Real-or-dummy key-verification outcomes in target order.
    pub key_verdicts: Vec<bool>,
    /// Derived channel-key verifiers in mode-change order.
    pub key_verifiers: Vec<crate::ChannelKeyVerifier>,
}

/// Persistence class selected without introducing a storage handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageClass {
    /// Live-only state or local delivery.
    Ephemeral,
    /// A later storage owner must commit before apply and fanout.
    Durable,
}

/// Logical recipients in deterministic User-ID order.
pub struct RecipientSet(BTreeSet<UserId>);

impl RecipientSet {
    fn new() -> Self {
        Self(BTreeSet::new())
    }

    fn insert(&mut self, user_id: UserId) {
        self.0.insert(user_id);
    }

    /// Iterates recipients in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = UserId> + '_ {
        self.0.iter().copied()
    }

    /// Returns the exact recipient count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether no protocol sink receives this result.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One immutable message route resolved at the command revision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResolvedMessageTarget {
    /// One immutable channel creation.
    Channel(ChannelInstanceId),
    /// One live user identity, unaffected by later nickname reuse.
    User(UserId),
}

/// One accepted target and its independently derived recipient set.
pub struct MessageRoute {
    message_id: MessageId,
    target: ResolvedMessageTarget,
    recipients: RecipientSet,
}

impl MessageRoute {
    /// Returns the immutable message identity allocated after policy acceptance.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the target identity resolved at the command revision.
    #[must_use]
    pub const fn target(&self) -> ResolvedMessageTarget {
        self.target
    }

    /// Borrows the exact logical recipients for this target.
    #[must_use]
    pub const fn recipients(&self) -> &RecipientSet {
        &self.recipients
    }
}

/// Complete content and routing data for one accepted message command.
pub struct MessageBatch {
    kind: MessageKind,
    sender: UserId,
    body: Option<crate::MessageText>,
    tagmsg_classification: Option<TagmsgClassification>,
    accepted_at: UtcSecond,
    routes: Vec<MessageRoute>,
}

impl MessageBatch {
    /// Returns ordinary, silent, or tag-only routing behavior.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Returns the immutable sending user.
    #[must_use]
    pub const fn sender(&self) -> UserId {
        self.sender
    }

    /// Borrows validated plaintext when the command carries it.
    #[must_use]
    pub fn body(&self) -> Option<&str> {
        self.body.as_ref().map(crate::MessageText::as_str)
    }

    /// Returns the validated semantic classification of a tag-only message.
    #[must_use]
    pub const fn tagmsg_classification(&self) -> Option<TagmsgClassification> {
        self.tagmsg_classification
    }

    /// Returns the explicitly supplied authoritative acceptance second.
    #[must_use]
    pub const fn accepted_at(&self) -> UtcSecond {
        self.accepted_at
    }

    /// Borrows accepted routes in canonical target order.
    #[must_use]
    pub fn routes(&self) -> &[MessageRoute] {
        &self.routes
    }
}

struct ResolvedMessageRoute {
    target: ResolvedMessageTarget,
    recipients: RecipientSet,
}

/// One canonical target whose target-local policy check failed.
pub enum FailedTarget {
    /// A canonical channel name.
    Channel(ChannelNameValue),
    /// A canonical nickname.
    User(NicknameValue),
}

impl FailedTarget {
    /// Borrows a failed channel target when this is a channel operation.
    #[must_use]
    pub const fn channel(&self) -> Option<&ChannelNameValue> {
        match self {
            Self::Channel(name) => Some(name),
            Self::User(_) => None,
        }
    }

    /// Borrows a failed nickname target when this is a user operation.
    #[must_use]
    pub const fn user(&self) -> Option<&NicknameValue> {
        match self {
            Self::Channel(_) => None,
            Self::User(nickname) => Some(nickname),
        }
    }
}

/// One bounded per-target policy failure in canonical command order.
pub struct TargetFailure {
    target_index: u8,
    target: FailedTarget,
    error: DomainError,
}

impl TargetFailure {
    fn channel(
        target_index: usize,
        name: ChannelNameValue,
        error: DomainError,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            target_index: u8::try_from(target_index).map_err(|_| DomainError::Overflow)?,
            target: FailedTarget::Channel(name),
            error,
        })
    }

    fn message(
        target_index: usize,
        target: &MessageTarget,
        error: DomainError,
    ) -> Result<Self, DomainError> {
        let target = match target {
            MessageTarget::Channel(name) => FailedTarget::Channel(name.clone()),
            MessageTarget::User(nickname) => FailedTarget::User(nickname.clone()),
        };
        Ok(Self {
            target_index: u8::try_from(target_index).map_err(|_| DomainError::Overflow)?,
            target,
            error,
        })
    }

    fn user(
        target_index: usize,
        nickname: NicknameValue,
        error: DomainError,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            target_index: u8::try_from(target_index).map_err(|_| DomainError::Overflow)?,
            target: FailedTarget::User(nickname),
            error,
        })
    }

    /// Returns the target's stable position in the canonical command vector.
    #[must_use]
    pub const fn target_index(&self) -> u8 {
        self.target_index
    }

    /// Borrows the canonical target without exposing private lookup state.
    #[must_use]
    pub const fn target(&self) -> &FailedTarget {
        &self.target
    }

    /// Returns the closed target-local rejection class.
    #[must_use]
    pub const fn error(&self) -> DomainError {
        self.error
    }
}

/// A semantic event emitted only after a plan is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainEvent {
    /// One immutable account authority entered the domain state.
    AccountCreated(AccountId),
    /// One independently identified session entered the state.
    SessionOpened(UserId),
    /// One live session changed guest or account authority at a new generation.
    SessionAuthorityChanged(UserId),
    /// One immutable account and its live sessions left domain state.
    AccountDeleted(AccountId),
    /// One process-local account-deletion confirmation challenge was installed.
    AccountDeletionChallengeStarted(UserId),
    /// One account-deletion confirmation was rejected and its challenge consumed.
    AccountDeletionConfirmationRejected(UserId),
    /// One account advanced its credential generation and fenced every old session.
    AccountCredentialReplaced(AccountId),
    /// One session and all live memberships were removed.
    SessionHidden(UserId),
    /// One nickname mapping changed without changing User ID.
    NicknameChanged(UserId),
    /// One prepared per-session display name changed without changing routing identity.
    DisplayNameChanged(UserId),
    /// One per-session away value changed.
    AwayChanged(UserId),
    /// One session's user modes changed for its home edge.
    UserModesChanged(UserId),
    /// One channel instance was created.
    ChannelCreated(ChannelInstanceId),
    /// One channel instance was destroyed and cannot be reused.
    ChannelDestroyed(ChannelInstanceId),
    /// One live membership was added.
    Joined(ChannelInstanceId, UserId),
    /// One live membership was removed.
    Parted(ChannelInstanceId, UserId),
    /// One plaintext topic assignment changed.
    TopicChanged(ChannelInstanceId, MessageId),
    /// One atomic channel-mode vector changed policy.
    ChannelModesChanged(ChannelInstanceId),
    /// Every live session of one account was recomputed at one revision.
    ChannelMembershipsRecomputed(ChannelInstanceId, AccountId),
    /// One accepted message received an immutable identity.
    MessageAccepted(MessageId, UserId),
    /// One single-use invitation was created.
    InviteCreated(ChannelInstanceId, InviteId),
    /// One expired invitation was removed by bounded timer maintenance.
    InviteExpired(ChannelInstanceId, InviteId),
    /// One authenticated account setting changed.
    AccountUpdated(AccountId),
    /// One owner-controlled channel setting changed.
    ChannelPolicyChanged(ChannelInstanceId),
    /// One server-side removal awaits companion cryptographic removal.
    E2eeRemovalPending(ChannelInstanceId, UserId),
    /// One typed, content-free sanction entered audit state.
    SanctionRecorded(Principal),
}

enum Mutation {
    InsertAccount(AccountState),
    InsertSession(SessionState),
    SwitchSessionAccount {
        user_id: UserId,
        account_id: Option<AccountId>,
        account_session_generation: agenc_ircd_types::Generation,
        session_generation: agenc_ircd_types::Generation,
        channel_ids: Vec<ChannelInstanceId>,
    },
    DeleteAccount {
        account_id: AccountId,
        user_ids: Vec<UserId>,
    },
    ReplaceAccountCredential {
        account_id: AccountId,
        account_session_generation: agenc_ircd_types::Generation,
        user_ids: Vec<UserId>,
    },
    Rename {
        user_id: UserId,
        nickname: NicknameValue,
    },
    SetAway {
        user_id: UserId,
        away: Option<crate::AwayText>,
    },
    SetOperatorNotices {
        user_id: UserId,
        enabled: bool,
    },
    SetMonitor {
        user_id: UserId,
        change: MonitorChange,
    },
    SetDisplayName {
        user_id: UserId,
        display_name: DisplayNameValue,
    },
    SetFreshAuthDeadline {
        user_id: UserId,
        deadline: MonotonicTick,
    },
    StartAccountDeletion(AccountDeletionChallengeState),
    ConsumeAccountDeletionChallenge(SessionId),
    JoinNew(crate::ChannelState),
    JoinExisting {
        channel_id: ChannelInstanceId,
        membership: Membership,
        consumed_invite: Option<InviteId>,
    },
    Part {
        channel_id: ChannelInstanceId,
        user_id: UserId,
    },
    CloseSession(UserId),
    SetTopic {
        channel_id: ChannelInstanceId,
        topic: PlaintextTopic,
    },
    ApplyModes {
        channel_id: ChannelInstanceId,
        setter: Principal,
        changes: Vec<ModeChange>,
        entry_ids: Vec<EntryId>,
        key_verifiers: Vec<crate::ChannelKeyVerifier>,
        created_at: Option<UtcSecond>,
    },
    AccountSetting {
        account_id: AccountId,
        setting: AccountSetting,
    },
    ChannelSetting(ChannelCommand),
    BindE2ee {
        channel_id: ChannelInstanceId,
    },
    CreateInvite {
        channel_id: ChannelInstanceId,
        invite: Invite,
        expired_invites: Vec<InviteId>,
    },
    MarkRemovalPending {
        channel_id: ChannelInstanceId,
        user_id: UserId,
    },
    FinalizeE2eeRemoval {
        channel_id: ChannelInstanceId,
        user_id: UserId,
    },
    ExpireInvites(Vec<(ChannelInstanceId, InviteId)>),
    AddSanction(Sanction),
    EventOnly,
}

/// The persisted entities a mutation list can change.
struct TouchedEntities {
    accounts: BTreeSet<AccountId>,
    sessions: BTreeSet<UserId>,
    channels: BTreeSet<ChannelInstanceId>,
    role_targets: Vec<NicknameValue>,
    sanctions: bool,
}

impl TouchedEntities {
    fn collect(state: &DomainState, mutations: &[Mutation]) -> Self {
        let mut touched = Self {
            accounts: BTreeSet::new(),
            sessions: BTreeSet::new(),
            channels: BTreeSet::new(),
            role_targets: Vec::new(),
            sanctions: false,
        };
        for mutation in mutations {
            touched.note(state, mutation);
        }
        touched
    }

    // agenc-review: focus owner=domain reviewed=2026-09-01 reason=closed mutation inventory records every durable account session channel and sanction dependency before projection
    fn note(&mut self, state: &DomainState, mutation: &Mutation) {
        match mutation {
            Mutation::InsertAccount(account) => {
                self.accounts.insert(account.account_id);
            }
            Mutation::InsertSession(session) => {
                self.sessions.insert(session.user_id);
            }
            Mutation::SwitchSessionAccount {
                user_id,
                channel_ids,
                ..
            } => {
                self.sessions.insert(*user_id);
                self.channels.extend(channel_ids.iter().copied());
                self.note_guest_invite_channels(state, *user_id);
            }
            Mutation::DeleteAccount {
                account_id,
                user_ids,
            } => {
                self.accounts.insert(*account_id);
                for user_id in user_ids {
                    self.note_closed_session(state, *user_id);
                }
                self.channels
                    .extend(state.channels.values().filter_map(|channel| {
                        (channel.role_grants.contains_key(account_id)
                            || channel
                                .invites
                                .values()
                                .any(|invite| invite.target == Principal::Account(*account_id)))
                        .then_some(channel.channel_id)
                    }));
            }
            Mutation::ReplaceAccountCredential {
                account_id,
                user_ids,
                ..
            } => {
                self.accounts.insert(*account_id);
                for user_id in user_ids {
                    self.note_closed_session(state, *user_id);
                }
            }
            Mutation::AccountSetting { account_id, .. } => {
                self.accounts.insert(*account_id);
            }
            Mutation::Rename { user_id, .. }
            | Mutation::SetAway { user_id, .. }
            | Mutation::SetOperatorNotices { user_id, .. }
            | Mutation::SetDisplayName { user_id, .. } => {
                self.sessions.insert(*user_id);
            }
            Mutation::JoinNew(channel) => {
                self.channels.insert(channel.channel_id);
                self.sessions.extend(channel.memberships.keys().copied());
            }
            Mutation::JoinExisting {
                channel_id,
                membership,
                ..
            } => {
                self.channels.insert(*channel_id);
                self.sessions.insert(membership.user_id);
            }
            Mutation::Part {
                channel_id,
                user_id,
            }
            | Mutation::FinalizeE2eeRemoval {
                channel_id,
                user_id,
            } => {
                self.channels.insert(*channel_id);
                self.sessions.insert(*user_id);
            }
            Mutation::CloseSession(user_id) => self.note_closed_session(state, *user_id),
            Mutation::SetTopic { channel_id, .. }
            | Mutation::BindE2ee { channel_id }
            | Mutation::CreateInvite { channel_id, .. }
            | Mutation::MarkRemovalPending { channel_id, .. } => {
                self.channels.insert(*channel_id);
            }
            Mutation::ApplyModes {
                channel_id,
                changes,
                ..
            } => self.note_mode_changes(*channel_id, changes),
            Mutation::ChannelSetting(command) => {
                let channel_id = channel_command_id(*command);
                self.channels.insert(channel_id);
                if matches!(
                    *command,
                    ChannelCommand::Register(_) | ChannelCommand::Unregister(_)
                ) && let Some(channel) = state.channels.get(&channel_id)
                    && channel.scope == crate::ChannelScope::Local
                {
                    self.sessions.extend(channel.memberships.keys().copied());
                }
            }
            Mutation::ExpireInvites(expired) => self
                .channels
                .extend(expired.iter().map(|(channel_id, _)| *channel_id)),
            Mutation::AddSanction(_) => self.sanctions = true,
            _ => {}
        }
    }

    fn note_closed_session(&mut self, state: &DomainState, user_id: UserId) {
        self.sessions.insert(user_id);
        if let Some(session) = state.sessions.get(&user_id) {
            self.channels
                .extend(session.joined_channels.iter().copied());
        }
        self.note_guest_invite_channels(state, user_id);
    }

    fn note_guest_invite_channels(&mut self, state: &DomainState, user_id: UserId) {
        self.channels
            .extend(state.channels.values().filter_map(|channel| {
                channel
                    .invites
                    .values()
                    .any(|invite| invite.target == Principal::Guest(user_id))
                    .then_some(channel.channel_id)
            }));
    }

    fn note_mode_changes(&mut self, channel_id: ChannelInstanceId, changes: &[ModeChange]) {
        self.channels.insert(channel_id);
        for change in changes {
            if let ModeChange::Role { target, .. } = change {
                self.role_targets.push(target.clone());
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.accounts.is_empty()
            && self.sessions.is_empty()
            && self.channels.is_empty()
            && !self.sanctions
    }

    /// Builds a state holding only duplicates of the touched entities and the
    /// nickname index entries the mode arms resolve.
    fn scratch(&self, state: &DomainState) -> Result<DomainState, DomainError> {
        let mut scratch = DomainState::at_revision(state.revision);
        for account_id in &self.accounts {
            if let Some(account) = state.accounts.get(account_id) {
                scratch.accounts.insert(*account_id, account.clone());
            }
        }
        for user_id in &self.sessions {
            if let Some(session) = state.sessions.get(user_id) {
                let session = DurableSession::from_state(session).into_state()?;
                scratch
                    .session_ids
                    .insert(session.session_id, session.user_id);
                scratch
                    .nicknames
                    .insert(session.nickname.clone(), session.user_id);
                scratch
                    .public_cloaks
                    .insert(session.public_cloak, session.user_id);
                scratch.sessions.insert(*user_id, session);
            }
        }
        for channel_id in &self.channels {
            if let Some(channel) = state.channels.get(channel_id) {
                scratch.channels.insert(*channel_id, channel.duplicate()?);
            }
        }
        for target in &self.role_targets {
            if let Some(user_id) = state.nicknames.get(target) {
                scratch.nicknames.insert(target.clone(), *user_id);
            }
        }
        Ok(scratch)
    }

    fn writes(&self, before: &DomainState, after: &DomainState) -> Vec<DurableWrite> {
        let mut writes = Vec::new();
        for account_id in &self.accounts {
            let previous = before.durable_account(*account_id);
            let next = after.durable_account(*account_id);
            match (previous, next) {
                (previous, Some(next)) if account_differs(previous.as_ref(), &next) => {
                    writes.push(DurableWrite::PutAccount(next));
                }
                (Some(_), None) => writes.push(DurableWrite::TombstoneAccount(*account_id)),
                _ => {}
            }
        }
        for user_id in &self.sessions {
            let previous = before.durable_session(*user_id);
            let next = durable_session_after(*user_id, before, after, &self.channels);
            match (previous, next) {
                (previous, Some(next)) if session_differs(previous.as_ref(), &next) => {
                    writes.push(DurableWrite::PutSession(next));
                }
                (Some(previous), None) => {
                    writes.push(DurableWrite::TombstoneSession(previous.session_id));
                }
                _ => {}
            }
        }
        for channel_id in &self.channels {
            let previous = before.durable_channel(*channel_id);
            let next = after.durable_channel(*channel_id);
            match (previous, next) {
                (previous, Some(next)) if channel_differs(previous.as_ref(), &next) => {
                    writes.push(DurableWrite::PutChannel(next));
                }
                (Some(previous), None) => writes.push(DurableWrite::TombstoneChannel {
                    channel_id: *channel_id,
                    name: previous.name,
                }),
                _ => {}
            }
        }
        writes.extend(
            after.sanctions.iter().map(|sanction| {
                DurableWrite::AppendSanction(DurableSanction::from_state(sanction))
            }),
        );
        writes
    }
}

fn durable_session_after(
    user_id: UserId,
    before: &DomainState,
    after: &DomainState,
    touched_channels: &BTreeSet<ChannelInstanceId>,
) -> Option<DurableSession> {
    after.sessions.get(&user_id).map(|session| {
        let mut durable = DurableSession::from_state(session);
        durable.joined_channels.retain(|channel_id| {
            let channel = if touched_channels.contains(channel_id) {
                after.channels.get(channel_id)
            } else {
                before.channels.get(channel_id)
            };
            channel.is_some_and(|channel| {
                channel.scope == crate::ChannelScope::Global
                    || channel.persistence == PersistencePolicy::Registered
            })
        });
        durable
    })
}

fn account_differs(previous: Option<&DurableAccount>, next: &DurableAccount) -> bool {
    previous.is_none_or(|previous| !previous.same_content(next))
}

fn session_differs(previous: Option<&DurableSession>, next: &DurableSession) -> bool {
    previous.is_none_or(|previous| !previous.same_content(next))
}

fn channel_differs(previous: Option<&DurableChannel>, next: &DurableChannel) -> bool {
    previous.is_none_or(|previous| !previous.same_content(next))
}

impl Mutation {
    /// Copies every arm that can change persisted state; process-local arms
    /// become no-ops in the projection scratch state.
    // agenc-review: focus owner=domain reviewed=2026-09-01 reason=closed mutation copier retains every persisted field while explicitly erasing process-local state from projection
    fn duplicate_for_projection(&self) -> Result<Self, DomainError> {
        Ok(match self {
            Self::InsertAccount(account) => Self::InsertAccount(account.clone()),
            Self::InsertSession(session) => {
                Self::InsertSession(DurableSession::from_state(session).into_state()?)
            }
            Self::SwitchSessionAccount {
                user_id,
                account_id,
                account_session_generation,
                session_generation,
                channel_ids,
            } => Self::SwitchSessionAccount {
                user_id: *user_id,
                account_id: *account_id,
                account_session_generation: *account_session_generation,
                session_generation: *session_generation,
                channel_ids: channel_ids.clone(),
            },
            Self::DeleteAccount {
                account_id,
                user_ids,
            } => Self::DeleteAccount {
                account_id: *account_id,
                user_ids: user_ids.clone(),
            },
            Self::ReplaceAccountCredential {
                account_id,
                account_session_generation,
                user_ids,
            } => Self::ReplaceAccountCredential {
                account_id: *account_id,
                account_session_generation: *account_session_generation,
                user_ids: user_ids.clone(),
            },
            Self::Rename { user_id, nickname } => Self::Rename {
                user_id: *user_id,
                nickname: nickname.clone(),
            },
            Self::SetAway { user_id, away } => Self::SetAway {
                user_id: *user_id,
                away: away
                    .as_ref()
                    .map(|away| {
                        crate::AwayText::try_from_str(
                            away.as_str(),
                            ControlPolicy::PermitHorizontalTab,
                        )
                    })
                    .transpose()?,
            },
            Self::SetOperatorNotices { user_id, enabled } => Self::SetOperatorNotices {
                user_id: *user_id,
                enabled: *enabled,
            },
            Self::SetDisplayName {
                user_id,
                display_name,
            } => Self::SetDisplayName {
                user_id: *user_id,
                display_name: display_name.clone(),
            },
            Self::JoinNew(channel) => Self::JoinNew(channel.duplicate()?),
            Self::JoinExisting {
                channel_id,
                membership,
                consumed_invite,
            } => Self::JoinExisting {
                channel_id: *channel_id,
                membership: *membership,
                consumed_invite: *consumed_invite,
            },
            Self::Part {
                channel_id,
                user_id,
            } => Self::Part {
                channel_id: *channel_id,
                user_id: *user_id,
            },
            Self::CloseSession(user_id) => Self::CloseSession(*user_id),
            Self::CreateInvite {
                channel_id,
                invite,
                expired_invites,
            } => Self::CreateInvite {
                channel_id: *channel_id,
                invite: invite.clone(),
                expired_invites: expired_invites.clone(),
            },
            Self::MarkRemovalPending {
                channel_id,
                user_id,
            } => Self::MarkRemovalPending {
                channel_id: *channel_id,
                user_id: *user_id,
            },
            Self::FinalizeE2eeRemoval {
                channel_id,
                user_id,
            } => Self::FinalizeE2eeRemoval {
                channel_id: *channel_id,
                user_id: *user_id,
            },
            Self::AccountSetting {
                account_id,
                setting,
            } => Self::AccountSetting {
                account_id: *account_id,
                setting: setting.clone(),
            },
            Self::SetTopic { channel_id, topic } => Self::SetTopic {
                channel_id: *channel_id,
                topic: topic.duplicate()?,
            },
            Self::ApplyModes {
                channel_id,
                setter,
                changes,
                entry_ids,
                key_verifiers,
                created_at,
            } => Self::ApplyModes {
                channel_id: *channel_id,
                setter: *setter,
                changes: changes
                    .iter()
                    .map(duplicate_mode_change)
                    .collect::<Result<Vec<_>, _>>()?,
                entry_ids: entry_ids.clone(),
                key_verifiers: key_verifiers.clone(),
                created_at: *created_at,
            },
            Self::ChannelSetting(command) => Self::ChannelSetting(*command),
            Self::BindE2ee { channel_id } => Self::BindE2ee {
                channel_id: *channel_id,
            },
            Self::ExpireInvites(expired) => Self::ExpireInvites(expired.clone()),
            Self::AddSanction(sanction) => Self::AddSanction(sanction.duplicate()?),
            _ => Self::EventOnly,
        })
    }
}

fn duplicate_mode_change(change: &ModeChange) -> Result<ModeChange, DomainError> {
    Ok(match change {
        ModeChange::Visibility { operation, mode } => ModeChange::Visibility {
            operation: *operation,
            mode: *mode,
        },
        ModeChange::InviteOnly(value) => ModeChange::InviteOnly(*value),
        ModeChange::Moderated(value) => ModeChange::Moderated(*value),
        ModeChange::TopicProtected(value) => ModeChange::TopicProtected(*value),
        ModeChange::JoinKey(value) => ModeChange::JoinKey(*value),
        ModeChange::MemberLimit(value) => ModeChange::MemberLimit(*value),
        ModeChange::Role {
            operation,
            target,
            role,
        } => ModeChange::Role {
            operation: *operation,
            target: target.clone(),
            role: *role,
        },
        ModeChange::AddMask { list, mask } => ModeChange::AddMask {
            list: *list,
            mask: duplicate_typed_mask(mask)?,
        },
        ModeChange::RemoveMask { list, entry_id } => ModeChange::RemoveMask {
            list: *list,
            entry_id: *entry_id,
        },
        ModeChange::RemoveMaskValue { list, mask } => ModeChange::RemoveMaskValue {
            list: *list,
            mask: duplicate_typed_mask(mask)?,
        },
    })
}

/// One atomic mode vector with the external inputs its mask and key arms consume.
struct ModeBatch {
    setter: Principal,
    changes: Vec<ModeChange>,
    entry_ids: Vec<EntryId>,
    key_verifiers: Vec<crate::ChannelKeyVerifier>,
    created_at: Option<UtcSecond>,
}
struct JoinPlanAccumulator {
    user_id: UserId,
    principal: Principal,
    utc: Option<UtcSecond>,
    monotonic: Option<MonotonicTick>,
    channel_ids: std::vec::IntoIter<ChannelInstanceId>,
    new_channel_ids: BTreeSet<ChannelInstanceId>,
    accepted_joins: usize,
    mutations: Vec<Mutation>,
    events: Vec<DomainEvent>,
    recipients: RecipientSet,
}

struct ExpiredInviteSweep {
    expired: Vec<(ChannelInstanceId, InviteId)>,
    events: Vec<DomainEvent>,
    recipients: RecipientSet,
}

#[derive(Clone)]
enum AccountSetting {
    Label(Option<crate::AccountLabelValue>),
    Presence(PresencePolicy),
    GuestDirectMessages(GuestDirectMessagePolicy),
    DirectMessages(DirectMessagePolicy),
    ContactAdd(AccountId),
    ContactRemove(AccountId),
    NickReserve(NicknameValue),
    NickRelease(NicknameValue),
}

enum MonitorChange {
    Add(Vec<NicknameValue>),
    Remove(Vec<NicknameValue>),
    Clear,
}

/// A complete state transition with no runtime or storage handles.
pub struct MutationPlan {
    expected_revision: Revision,
    resulting_revision: Revision,
    mutations: Vec<Mutation>,
    events: Vec<DomainEvent>,
    recipients: RecipientSet,
    failures: Vec<TargetFailure>,
    message_batch: Option<MessageBatch>,
    charges: Vec<RateCharge>,
    storage: StorageClass,
    durable_writes: Vec<DurableWrite>,
}

/// Every field of a plan except the revisions and the derived durable writes.
struct PlanParts {
    mutations: Vec<Mutation>,
    events: Vec<DomainEvent>,
    recipients: RecipientSet,
    failures: Vec<TargetFailure>,
    message_batch: Option<MessageBatch>,
    charges: Vec<RateCharge>,
    storage: StorageClass,
}

impl MutationPlan {
    /// Borrows the logical persisted writes this plan produces, in canonical order.
    ///
    /// The set is derived from the same apply logic that later executes the plan,
    /// so a durable plan whose entities keep their persisted content yields nothing.
    #[must_use]
    pub fn durable_writes(&self) -> &[DurableWrite] {
        &self.durable_writes
    }

    /// Returns the state revision this plan was validated against.
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }

    /// Returns the exact successor revision.
    #[must_use]
    pub const fn resulting_revision(&self) -> Revision {
        self.resulting_revision
    }

    /// Borrows semantic events in final output order.
    #[must_use]
    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    /// Borrows deterministic logical recipients.
    #[must_use]
    pub const fn recipients(&self) -> &RecipientSet {
        &self.recipients
    }

    /// Borrows target-local policy failures in canonical command order.
    #[must_use]
    pub fn failures(&self) -> &[TargetFailure] {
        &self.failures
    }

    /// Borrows complete accepted message data when this is a message plan.
    #[must_use]
    pub const fn message_batch(&self) -> Option<&MessageBatch> {
        self.message_batch.as_ref()
    }

    /// Returns whether a later storage owner must commit first.
    #[must_use]
    pub const fn storage_class(&self) -> StorageClass {
        self.storage
    }

    /// Borrows a new deletion token only for the private challenge reply boundary.
    #[must_use]
    pub fn account_deletion_token(&self) -> Option<&[u8; 16]> {
        self.mutations.iter().find_map(|mutation| match mutation {
            Mutation::StartAccountDeletion(challenge) => {
                Some(challenge.token.expose_for_deletion())
            }
            _ => None,
        })
    }

    /// Returns the original exclusive deadline for a new deletion challenge.
    #[must_use]
    pub fn account_deletion_expires_at(&self) -> Option<MonotonicTick> {
        self.mutations.iter().find_map(|mutation| match mutation {
            Mutation::StartAccountDeletion(challenge) => Some(challenge.expires_at),
            _ => None,
        })
    }
}

/// A read-only decision pinned to one immutable state revision.
pub struct QueryPlan {
    expected_revision: Revision,
    kind: DomainCommandKind,
    requester: UserId,
    command: CanonicalCommand,
    charges: Vec<RateCharge>,
}

/// A command with no authorized target and therefore no state transition.
pub struct RejectedPlan {
    expected_revision: Revision,
    kind: DomainCommandKind,
    failures: Vec<TargetFailure>,
    charges: Vec<RateCharge>,
    silent: bool,
}

impl RejectedPlan {
    /// Returns the immutable revision used for every target-local check.
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }

    /// Returns the closed command family.
    #[must_use]
    pub const fn kind(&self) -> DomainCommandKind {
        self.kind
    }

    /// Borrows the complete nonempty canonical target-failure vector.
    #[must_use]
    pub fn failures(&self) -> &[TargetFailure] {
        &self.failures
    }

    /// Borrows charges assessed before target policy evaluation.
    #[must_use]
    pub fn charges(&self) -> &[RateCharge] {
        &self.charges
    }

    /// Reports whether NOTICE suppresses automatic failure replies.
    #[must_use]
    pub const fn is_silent(&self) -> bool {
        self.silent
    }
}

impl QueryPlan {
    /// Returns the immutable revision read by this query.
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }

    /// Returns the closed command family.
    #[must_use]
    pub const fn kind(&self) -> DomainCommandKind {
        self.kind
    }

    /// Returns the requesting live User ID.
    #[must_use]
    pub const fn requester(&self) -> UserId {
        self.requester
    }

    /// Borrows the complete canonical query, including its bounded selector.
    #[must_use]
    pub const fn command(&self) -> &CanonicalCommand {
        &self.command
    }

    /// Borrows charges already assessed for the query.
    #[must_use]
    pub fn charges(&self) -> &[RateCharge] {
        &self.charges
    }
}

/// Planning result before any side effect occurs.
pub enum PlanDecision {
    /// The caller must satisfy this exact external request vector and retry.
    NeedsExternal(Vec<ExternalInputRequest>),
    /// A revision-bound state mutation is ready for runtime reservation.
    Mutation(MutationPlan),
    /// A revision-bound privacy-filtered query is ready.
    Query(QueryPlan),
    /// Every syntactically valid target failed target-local policy checks.
    Rejected(RejectedPlan),
}

/// A plan checked against the current state and ready for one apply.
pub struct PreparedMutation(MutationPlan);

/// Result of applying one prepared plan.
pub struct ApplyReceipt {
    revision: Revision,
    events: Vec<DomainEvent>,
    recipients: RecipientSet,
    failures: Vec<TargetFailure>,
    message_batch: Option<MessageBatch>,
    charges: Vec<RateCharge>,
    storage: StorageClass,
}

impl ApplyReceipt {
    /// Returns the resulting authoritative revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Borrows emitted events in deterministic order.
    #[must_use]
    pub fn events(&self) -> &[DomainEvent] {
        &self.events
    }

    /// Borrows logical recipients in deterministic order.
    #[must_use]
    pub const fn recipients(&self) -> &RecipientSet {
        &self.recipients
    }

    /// Borrows target-local failures committed alongside the successful subset.
    #[must_use]
    pub fn failures(&self) -> &[TargetFailure] {
        &self.failures
    }

    /// Borrows the committed message batch for renderer/storage handoff.
    #[must_use]
    pub const fn message_batch(&self) -> Option<&MessageBatch> {
        self.message_batch.as_ref()
    }

    /// Borrows charges inherited from authorization.
    #[must_use]
    pub fn charges(&self) -> &[RateCharge] {
        &self.charges
    }

    /// Returns the persistence class proved before apply.
    #[must_use]
    pub const fn storage_class(&self) -> StorageClass {
        self.storage
    }
}

impl DomainState {
    /// Plans one revision-fenced account-service persistence checkpoint.
    ///
    /// The runtime must attach at least one validated account-service row to
    /// this plan before staging it. The marker keeps the domain revision and
    /// storage generation advancing together without inventing a domain
    /// entity for an authentication transaction or sealed response.
    pub fn plan_account_service_checkpoint(&self) -> Result<MutationPlan, DomainError> {
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::EventOnly],
            events: Vec::new(),
            recipients: RecipientSet::new(),
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }

    /// Plans insertion of one account created by the later authentication stage.
    pub fn plan_account_created(&self, account: AccountState) -> Result<MutationPlan, DomainError> {
        if self.accounts.contains_key(&account.account_id) {
            return Err(DomainError::BadState);
        }
        let account_id = account.account_id;
        self.single_mutation(
            Mutation::InsertAccount(account),
            DomainEvent::AccountCreated(account_id),
            RecipientSet::new(),
            Vec::new(),
            StorageClass::Durable,
        )
    }

    /// Plans insertion of one session after Stage 02 and later auth acceptance.
    pub fn plan_session_opened(&self, seed: SessionSeed) -> Result<MutationPlan, DomainError> {
        self.plan_session_opened_at_authentication(seed, None)
    }

    /// Plans an authenticated session with its original, process-local OPAQUE
    /// instant in the same insertion revision. The deadline is never persisted.
    pub fn plan_authenticated_session_opened(
        &self,
        seed: SessionSeed,
        authenticated_at: MonotonicTick,
    ) -> Result<MutationPlan, DomainError> {
        if seed.account_id.is_none() {
            return Err(DomainError::BadState);
        }
        self.plan_session_opened_at_authentication(seed, Some(authenticated_at))
    }

    fn plan_session_opened_at_authentication(
        &self,
        seed: SessionSeed,
        authenticated_at: Option<MonotonicTick>,
    ) -> Result<MutationPlan, DomainError> {
        self.validate_session_seed(&seed)?;
        let user_id = seed.user_id;
        let mut session = SessionState::from_seed(seed);
        session.fresh_auth_deadline = authenticated_at
            .map(|instant| instant.checked_add(FRESH_AUTH_WINDOW_MILLIS))
            .transpose()?;
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.single_mutation(
            Mutation::InsertSession(session),
            DomainEvent::SessionOpened(user_id),
            recipients,
            Vec::new(),
            StorageClass::Durable,
        )
    }

    /// Plans durable removal of one connection-bound session recovered after
    /// its owning process has restarted.
    pub fn plan_session_disconnected(&self, user_id: UserId) -> Result<MutationPlan, DomainError> {
        let mut events = self.part_events(user_id)?;
        events.push(DomainEvent::SessionHidden(user_id));
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::CloseSession(user_id)],
            events,
            recipients: RecipientSet::new(),
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }

    /// Plans a generation-fenced guest login or authenticated logout.
    pub fn plan_session_account_switch(
        &self,
        user_id: UserId,
        expected_session_generation: agenc_ircd_types::Generation,
        account: Option<(AccountId, agenc_ircd_types::Generation)>,
    ) -> Result<MutationPlan, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        if session.generation != expected_session_generation {
            return Err(DomainError::StaleGeneration);
        }
        let replaces_account = match account {
            Some((requested_account, _)) => session.account_id != Some(requested_account),
            None => session.account_id.is_some(),
        };
        if replaces_account
            && session.joined_channels.iter().any(|channel_id| {
                self.channels
                    .get(channel_id)
                    .is_some_and(|channel| channel.content_policy == ContentPolicy::E2eeBound)
            })
        {
            return Err(DomainError::BadState);
        }
        let (account_id, account_session_generation) =
            self.resolve_switch_account(session.account_id, account)?;
        if session.account_id == account_id
            || (session.account_id.is_some() && account_id.is_some())
        {
            return Err(DomainError::BadState);
        }
        if self
            .reserved_nickname_owner(&session.nickname)
            .is_some_and(|owner| Some(owner) != account_id)
        {
            return Err(DomainError::Forbidden);
        }
        let session_generation = session.generation.checked_add(1)?;
        let channel_ids = session.joined_channels.iter().copied().collect();
        let mut recipients = self.session_recipients(user_id)?;
        recipients.insert(user_id);
        self.single_mutation(
            Mutation::SwitchSessionAccount {
                user_id,
                account_id,
                account_session_generation,
                session_generation,
                channel_ids,
            },
            DomainEvent::SessionAuthorityChanged(user_id),
            recipients,
            Vec::new(),
            StorageClass::Durable,
        )
    }

    fn resolve_switch_account(
        &self,
        current_account: Option<AccountId>,
        requested: Option<(AccountId, agenc_ircd_types::Generation)>,
    ) -> Result<(Option<AccountId>, agenc_ircd_types::Generation), DomainError> {
        let Some((account_id, generation)) = requested else {
            return Ok((None, agenc_ircd_types::Generation::new(0)?));
        };
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(DomainError::NotFound)?;
        if account.session_generation != generation {
            return Err(DomainError::StaleGeneration);
        }
        if current_account != Some(account_id) {
            let live = self
                .sessions
                .values()
                .filter(|session| session.account_id == Some(account_id))
                .count();
            if live >= self.operational_limits.sessions_per_account() {
                return Err(DomainError::LimitExceeded);
            }
        }
        Ok((Some(account_id), generation))
    }

    /// Plans deletion after a later authentication owner proves fresh authority.
    pub fn plan_account_deleted(
        &self,
        account_id: AccountId,
        expected_generation: agenc_ircd_types::Generation,
    ) -> Result<MutationPlan, DomainError> {
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(DomainError::NotFound)?;
        if account.session_generation != expected_generation {
            return Err(DomainError::StaleGeneration);
        }
        self.validate_account_deletion_roles(account_id)?;
        let user_ids: Vec<UserId> = self
            .sessions
            .iter()
            .filter_map(|(user_id, session)| {
                (session.account_id == Some(account_id)).then_some(*user_id)
            })
            .collect();
        if user_ids.len() != 1 {
            return Err(DomainError::BadState);
        }
        let confirming_user = user_ids
            .first()
            .copied()
            .ok_or(DomainError::InvariantViolation)?;
        let confirming_session = self
            .sessions
            .get(&confirming_user)
            .ok_or(DomainError::InvariantViolation)?;
        if !confirming_session.joined_channels.is_empty() {
            return Err(DomainError::BadState);
        }
        let mut recipients = RecipientSet::new();
        for user_id in &user_ids {
            for recipient in self.session_recipients(*user_id)?.iter() {
                recipients.insert(recipient);
            }
            recipients.insert(*user_id);
        }
        self.single_mutation(
            Mutation::DeleteAccount {
                account_id,
                user_ids,
            },
            DomainEvent::AccountDeleted(account_id),
            recipients,
            Vec::new(),
            StorageClass::Durable,
        )
    }

    /// Plans deletion only at the account revision authenticated by a one-use confirmation.
    pub fn plan_account_deleted_at_revision(
        &self,
        account_id: AccountId,
        expected_generation: agenc_ircd_types::Generation,
        expected_account_revision: Revision,
    ) -> Result<MutationPlan, DomainError> {
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(DomainError::NotFound)?;
        if account.revision != expected_account_revision {
            return Err(DomainError::StaleRevision);
        }
        self.plan_account_deleted(account_id, expected_generation)
    }

    /// Installs one coordinator-local fresh-auth deadline from a trusted auth completion.
    pub fn plan_session_fresh_authentication(
        &self,
        user_id: UserId,
        account_id: AccountId,
        expected_session_generation: agenc_ircd_types::Generation,
        authenticated_at: MonotonicTick,
    ) -> Result<MutationPlan, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        if session.account_id != Some(account_id) {
            return Err(DomainError::Forbidden);
        }
        if session.generation != expected_session_generation {
            return Err(DomainError::StaleGeneration);
        }
        if self
            .account_deletion_challenges
            .get(&session.session_id)
            .is_some_and(|challenge| authenticated_at < challenge.expires_at)
        {
            return Err(DomainError::BadState);
        }
        let deadline = authenticated_at.checked_add(FRESH_AUTH_WINDOW_MILLIS)?;
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::SetFreshAuthDeadline { user_id, deadline }],
            events: Vec::new(),
            recipients,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Ephemeral,
        })
    }

    /// Plans one atomic credential-generation advance and removal of every old session.
    pub fn plan_account_credential_replaced(
        &self,
        account_id: AccountId,
        expected_generation: agenc_ircd_types::Generation,
        expected_account_revision: Revision,
    ) -> Result<(MutationPlan, agenc_ircd_types::Generation), DomainError> {
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(DomainError::NotFound)?;
        if account.session_generation != expected_generation {
            return Err(DomainError::StaleGeneration);
        }
        if account.revision != expected_account_revision {
            return Err(DomainError::StaleRevision);
        }
        let account_session_generation = account.session_generation.checked_add(1)?;
        let user_ids: Vec<UserId> = self
            .sessions
            .iter()
            .filter_map(|(user_id, session)| {
                (session.account_id == Some(account_id)).then_some(*user_id)
            })
            .collect();
        if user_ids.is_empty() {
            return Err(DomainError::BadState);
        }
        let mut recipients = RecipientSet::new();
        let mut events = vec![DomainEvent::AccountCredentialReplaced(account_id)];
        for user_id in &user_ids {
            for recipient in self.session_recipients(*user_id)?.iter() {
                recipients.insert(recipient);
            }
            recipients.insert(*user_id);
            events.push(DomainEvent::SessionHidden(*user_id));
        }
        let plan = self.assemble_plan(PlanParts {
            mutations: vec![Mutation::ReplaceAccountCredential {
                account_id,
                account_session_generation,
                user_ids,
            }],
            events,
            recipients,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })?;
        Ok((plan, account_session_generation))
    }

    /// Returns the exact pre-mutation audience for one session departure.
    /// Runtime uses this only while rendering a plan that already contains
    /// the matching `SessionHidden` event.
    pub fn session_fanout_recipients(&self, user_id: UserId) -> Result<RecipientSet, DomainError> {
        self.session_recipients(user_id)
    }

    /// Plans the one-way joint transition from plaintext to companion-bound E2EE.
    pub fn plan_e2ee_binding(
        &self,
        actor_user_id: UserId,
        proof: E2eeBindingProof,
    ) -> Result<MutationPlan, DomainError> {
        let channel = self
            .channels
            .get(&proof.channel_id)
            .ok_or(DomainError::NotFound)?;
        if channel.revision != proof.channel_revision {
            return Err(DomainError::StaleRevision);
        }
        self.validate_e2ee_binding_actor(actor_user_id, channel)?;
        if !channel_accepts_e2ee_binding(channel) {
            return Err(DomainError::BadState);
        }
        if canonical_account_roster(channel)? != proof.approved_roster {
            return Err(DomainError::StaleRevision);
        }
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::BindE2ee {
                channel_id: proof.channel_id,
            }],
            events: vec![DomainEvent::ChannelPolicyChanged(proof.channel_id)],
            recipients: self.channel_recipients(proof.channel_id)?,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }

    fn validate_e2ee_binding_actor(
        &self,
        actor_user_id: UserId,
        channel: &crate::ChannelState,
    ) -> Result<(), DomainError> {
        let actor = self
            .sessions
            .get(&actor_user_id)
            .ok_or(DomainError::NotFound)?;
        if actor.account_id.is_none() || channel.role_of(actor_user_id) != Some(Role::Owner) {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    /// Plans membership removal only after companion cryptographic finality.
    pub fn plan_e2ee_removal_finalized(
        &self,
        finality: E2eeRemovalFinality,
    ) -> Result<MutationPlan, DomainError> {
        let channel = self
            .channels
            .get(&finality.channel_id)
            .ok_or(DomainError::NotFound)?;
        if channel.revision != finality.channel_revision {
            return Err(DomainError::StaleRevision);
        }
        if channel.content_policy != ContentPolicy::E2eeBound
            || !channel.e2ee_removal_pending.contains(&finality.user_id)
            || !channel.memberships.contains_key(&finality.user_id)
        {
            return Err(DomainError::BadState);
        }
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::FinalizeE2eeRemoval {
                channel_id: finality.channel_id,
                user_id: finality.user_id,
            }],
            events: vec![DomainEvent::Parted(finality.channel_id, finality.user_id)],
            recipients: self.channel_recipients(finality.channel_id)?,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }

    /// Plans one deterministic, bounded network-wide expired-invitation sweep.
    pub fn plan_expired_invites(
        &self,
        now: MonotonicTick,
    ) -> Result<Option<MutationPlan>, DomainError> {
        let sweep = self.collect_expired_invites(now)?;
        if sweep.expired.is_empty() {
            return Ok(None);
        }
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::ExpireInvites(sweep.expired)],
            events: sweep.events,
            recipients: sweep.recipients,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
        .map(Some)
    }

    fn collect_expired_invites(
        &self,
        now: MonotonicTick,
    ) -> Result<ExpiredInviteSweep, DomainError> {
        let mut expired = Vec::new();
        expired
            .try_reserve_exact(MAX_INVITE_EXPIRATIONS_PER_PLAN)
            .map_err(|_| DomainError::AllocationFailed)?;
        let mut events = Vec::new();
        events
            .try_reserve_exact(MAX_INVITE_EXPIRATIONS_PER_PLAN)
            .map_err(|_| DomainError::AllocationFailed)?;
        let mut recipients = RecipientSet::new();
        let candidates = self.channels.iter().flat_map(|(channel_id, channel)| {
            channel
                .invites
                .iter()
                .map(move |(invite_id, invite)| (*channel_id, *invite_id, invite))
        });
        for (channel_id, invite_id, invite) in candidates
            .filter(|(_, _, invite)| now >= invite.expires_at)
            .take(MAX_INVITE_EXPIRATIONS_PER_PLAN)
        {
            expired.push((channel_id, invite_id));
            events.push(DomainEvent::InviteExpired(channel_id, invite_id));
            self.add_invite_recipients(invite, &mut recipients);
        }
        Ok(ExpiredInviteSweep {
            expired,
            events,
            recipients,
        })
    }

    fn add_invite_recipients(&self, invite: &Invite, recipients: &mut RecipientSet) {
        recipients.insert(invite.inviter);
        match invite.target {
            Principal::Guest(user_id) => recipients.insert(user_id),
            Principal::Account(account_id) => {
                self.add_account_session_recipients(account_id, recipients);
            }
        }
    }

    fn add_account_session_recipients(&self, account_id: AccountId, recipients: &mut RecipientSet) {
        for user_id in self.sessions.iter().filter_map(|(user_id, session)| {
            (session.account_id == Some(account_id)).then_some(*user_id)
        }) {
            recipients.insert(user_id);
        }
    }

    /// Validates session fences, authorization, and all hierarchical charges.
    pub fn authorize(
        &self,
        envelope: CommandEnvelope,
        admission: &AdmissionSnapshot,
    ) -> Result<AuthorizedCommand, AuthorizationFailure> {
        let charges = self.assess_charges(envelope.user_id(), envelope.command());
        let silent = command_is_silent(envelope.command());
        let result = self.authorize_inner(&envelope, admission, &charges);
        match result {
            Ok(principal) => Ok(AuthorizedCommand {
                user_id: envelope.user_id(),
                principal,
                expected_state_revision: envelope.expected_state_revision(),
                command: envelope.into_command(),
                charges,
            }),
            Err(error) => Err(AuthorizationFailure {
                error,
                charges,
                silent,
            }),
        }
    }

    /// Returns the exact hierarchical charges runtime admission must
    /// snapshot before authorizing this command.
    #[must_use]
    pub fn command_charges(&self, user_id: UserId, command: &CanonicalCommand) -> Vec<RateCharge> {
        self.assess_charges(user_id, command)
    }

    /// Computes or completes a pure command plan from explicit external inputs.
    pub fn plan_authorized(
        &self,
        authorized: AuthorizedCommand,
        external: Option<ExternalInputs>,
    ) -> Result<PlanDecision, DomainError> {
        if authorized.expected_state_revision != self.revision {
            return Err(DomainError::StaleRevision);
        }
        if !self.session_authority_available(authorized.user_id) {
            return Err(DomainError::ServerBusy);
        }
        let requests = self.external_requests(authorized.user_id, &authorized.command)?;
        let Some(inputs) = external else {
            if requests.is_empty() {
                return self.plan_with_inputs(authorized, ExternalInputs::default());
            }
            return Ok(PlanDecision::NeedsExternal(requests));
        };
        validate_external_inputs(&requests, &inputs)?;
        self.plan_with_inputs(authorized, inputs)
    }

    /// Checks a private plan against the current revision before runtime commit.
    pub fn prepare_mutation(&self, plan: MutationPlan) -> Result<PreparedMutation, DomainError> {
        if plan.expected_revision != self.revision {
            return Err(DomainError::StaleRevision);
        }
        Ok(PreparedMutation(plan))
    }

    /// Applies one already prepared plan without performing I/O or allocation admission.
    pub fn apply_prepared(
        &mut self,
        prepared: PreparedMutation,
    ) -> Result<ApplyReceipt, DomainError> {
        let plan = prepared.0;
        if plan.expected_revision != self.revision {
            return Err(DomainError::StaleRevision);
        }
        for mutation in plan.mutations {
            self.apply_mutation(mutation, plan.resulting_revision);
        }
        self.revision = plan.resulting_revision;
        Ok(ApplyReceipt {
            revision: plan.resulting_revision,
            events: plan.events,
            recipients: plan.recipients,
            failures: plan.failures,
            message_batch: plan.message_batch,
            charges: plan.charges,
            storage: plan.storage,
        })
    }

    /// Creates one auditable typed sanction plan without inspecting message content.
    pub fn plan_sanction(&self, request: SanctionRequest) -> Result<MutationPlan, DomainError> {
        let Some(actor_session) = self.sessions.get(&request.actor_user_id) else {
            return Err(DomainError::NotFound);
        };
        if request
            .expires_at
            .is_some_and(|expires_at| expires_at <= request.created_at)
        {
            return Err(DomainError::InvalidArgument);
        }
        authorize_sanction(
            self,
            actor_session,
            request.target,
            request.channel_id,
            request.action,
            request.expires_at.is_none(),
        )?;
        let next = crate::model::next_revision(self.revision)?;
        let sanction = Sanction {
            actor: actor_session.principal(),
            target: request.target,
            channel_id: request.channel_id,
            action: request.action,
            reason_code: request.reason_code,
            reason: request.reason,
            created_at: request.created_at,
            expires_at: request.expires_at,
            revision: next,
        };
        let mut recipients = RecipientSet::new();
        recipients.insert(request.actor_user_id);
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::AddSanction(sanction)],
            events: vec![DomainEvent::SanctionRecorded(request.target)],
            recipients,
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }

    fn validate_session_seed(&self, seed: &SessionSeed) -> Result<(), DomainError> {
        if self.sessions.contains_key(&seed.user_id)
            || self.session_ids.contains_key(&seed.session_id)
            || self.nicknames.contains_key(&seed.nickname)
            || self.public_cloaks.contains_key(&seed.public_cloak)
        {
            return Err(DomainError::BadState);
        }
        if self
            .reserved_nickname_owner(&seed.nickname)
            .is_some_and(|owner| Some(owner) != seed.account_id)
        {
            return Err(DomainError::Forbidden);
        }
        let Some(account_id) = seed.account_id else {
            if seed.account_session_generation.get() != 0 {
                return Err(DomainError::InvalidArgument);
            }
            return Ok(());
        };
        let Some(account) = self.accounts.get(&account_id) else {
            return Err(DomainError::NotFound);
        };
        if account.session_generation != seed.account_session_generation {
            return Err(DomainError::StaleGeneration);
        }
        let live = self
            .sessions
            .values()
            .filter(|session| session.account_id == Some(account_id))
            .count();
        if live >= self.operational_limits.sessions_per_account() {
            return Err(DomainError::LimitExceeded);
        }
        Ok(())
    }

    fn validate_account_deletion_roles(&self, account_id: AccountId) -> Result<(), DomainError> {
        for channel in self.channels.values() {
            if channel.persistence != PersistencePolicy::Registered
                || channel.role_grants.get(&account_id) != Some(&Role::Owner)
            {
                continue;
            }
            let another_owner = channel
                .role_grants
                .iter()
                .any(|(owner, role)| *owner != account_id && *role == Role::Owner);
            if !another_owner {
                return Err(DomainError::BadState);
            }
        }
        Ok(())
    }

    fn authorize_inner(
        &self,
        envelope: &CommandEnvelope,
        admission: &AdmissionSnapshot,
        charges: &[RateCharge],
    ) -> Result<Principal, DomainError> {
        if envelope.expected_state_revision() != self.revision {
            return Err(DomainError::StaleRevision);
        }
        let Some(session) = self.sessions.get(&envelope.user_id()) else {
            return Err(DomainError::NotFound);
        };
        if !self.session_authority_available(envelope.user_id()) {
            return Err(DomainError::ServerBusy);
        }
        if session.session_id != envelope.session_id()
            || session.generation != envelope.session_generation()
        {
            return Err(DomainError::StaleGeneration);
        }
        if !admission.admits(charges)? {
            return Err(DomainError::ServerBusy);
        }
        self.authorize_command(session, envelope.command())?;
        Ok(session.principal())
    }

    fn authorize_command(
        &self,
        session: &SessionState,
        command: &CanonicalCommand,
    ) -> Result<(), DomainError> {
        match command.data() {
            CanonicalCommandData::Account(_) | CanonicalCommandData::Channel(_) => {
                require_account(session).map(|_| ())
            }
            CanonicalCommandData::Mode(ModeCommand::ChannelChange(channel, _)) => {
                self.require_channel_role(session, channel, Role::HalfOperator)
            }
            CanonicalCommandData::Mode(
                ModeCommand::ChannelQuery(channel) | ModeCommand::ChannelList(channel, _),
            )
            | CanonicalCommandData::TopicQuery(channel) => {
                self.privacy_safe_channel(session, channel).map(|_| ())
            }
            CanonicalCommandData::Mode(
                ModeCommand::UserQuery(nickname) | ModeCommand::UserOperatorNotices(nickname, _),
            ) if nickname != &session.nickname => Err(DomainError::Forbidden),
            CanonicalCommandData::Mode(
                ModeCommand::UserQuery(_) | ModeCommand::UserOperatorNotices(_, _),
            ) => Ok(()),
            CanonicalCommandData::TopicSet(channel, _) => {
                self.authorize_topic_change(session, channel)
            }
            CanonicalCommandData::Names(channels) => {
                for channel in channels {
                    self.privacy_safe_channel(session, channel)?;
                }
                Ok(())
            }
            CanonicalCommandData::Invite(_, channel) => {
                self.require_channel_role(session, channel, Role::Operator)
            }
            CanonicalCommandData::Kick(channel, _, _) => self.authorize_kick(session, channel),
            CanonicalCommandData::Message(_) => Ok(()),
            CanonicalCommandData::Chathistory(channel_id, _) => {
                self.authorize_history(session, *channel_id)
            }
            _ => Ok(()),
        }
    }

    fn privacy_safe_channel<'a>(
        &'a self,
        session: &SessionState,
        name: &ChannelNameValue,
    ) -> Result<&'a crate::ChannelState, DomainError> {
        let Some(channel_id) = self.channel_names.get(name) else {
            return Err(DomainError::SecretUnavailable);
        };
        let Some(channel) = self.channels.get(channel_id) else {
            return Err(DomainError::InvariantViolation);
        };
        if channel.visibility != Visibility::Listed
            && !channel.memberships.contains_key(&session.user_id)
        {
            return Err(DomainError::SecretUnavailable);
        }
        Ok(channel)
    }

    fn require_channel_role(
        &self,
        session: &SessionState,
        name: &ChannelNameValue,
        required: Role,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(session, name)?;
        let Some(role) = channel.role_of(session.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if role < required {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    fn authorize_topic_change(
        &self,
        session: &SessionState,
        name: &ChannelNameValue,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(session, name)?;
        if channel.content_policy == ContentPolicy::E2eeBound {
            return Err(DomainError::EncryptedRoute);
        }
        let Some(role) = channel.role_of(session.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if effective_mask(channel, session, true) {
            return Err(DomainError::Forbidden);
        }
        if channel.modes.topic_protected && role < Role::HalfOperator {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    fn authorize_kick(
        &self,
        session: &SessionState,
        name: &ChannelNameValue,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(session, name)?;
        let Some(actor_role) = channel.role_of(session.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if actor_role < Role::HalfOperator {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    fn authorize_channel_message(
        &self,
        sender: &SessionState,
        name: &ChannelNameValue,
        _kind: MessageKind,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(sender, name)?;
        let Some(role) = channel.role_of(sender.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if effective_mask(channel, sender, true) {
            return Err(DomainError::Forbidden);
        }
        if channel.content_policy == ContentPolicy::E2eeBound {
            return Err(DomainError::EncryptedRoute);
        }
        if channel.modes.moderated && role < Role::Voice {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    fn authorize_e2ee_channel_message(
        &self,
        sender: &SessionState,
        name: &ChannelNameValue,
        proof: crate::E2eeApplicationProof,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(sender, name)?;
        if channel.content_policy != ContentPolicy::E2eeBound {
            return Err(DomainError::PlaintextRoute);
        }
        if proof.channel_id() != channel.channel_id || proof.sender() != sender.user_id {
            return Err(DomainError::Forbidden);
        }
        if proof.channel_revision() != channel.revision {
            return Err(DomainError::StaleRevision);
        }
        if !channel.e2ee_removal_pending.is_empty() {
            return Err(DomainError::BadState);
        }
        let Some(role) = channel.role_of(sender.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if effective_mask(channel, sender, true) {
            return Err(DomainError::Forbidden);
        }
        if channel.modes.moderated && role < Role::Voice {
            return Err(DomainError::Forbidden);
        }
        Ok(())
    }

    fn authorize_direct_message(
        &self,
        sender: &SessionState,
        nickname: &NicknameValue,
    ) -> Result<(), DomainError> {
        let Some(target_user) = self.nicknames.get(nickname) else {
            return Err(DomainError::NotFound);
        };
        let Some(target) = self.sessions.get(target_user) else {
            return Err(DomainError::InvariantViolation);
        };
        if !self.session_authority_available(*target_user) {
            return Err(DomainError::NotFound);
        }
        let Some(target_account_id) = target.account_id else {
            return Ok(());
        };
        let Some(target_account) = self.accounts.get(&target_account_id) else {
            return Err(DomainError::InvariantViolation);
        };
        authorize_direct_policy(sender, target_account)
    }

    fn authorize_history(
        &self,
        session: &SessionState,
        channel_id: ChannelInstanceId,
    ) -> Result<(), DomainError> {
        let Some(channel) = self.channels.get(&channel_id) else {
            return Err(DomainError::NotFound);
        };
        if !channel.memberships.contains_key(&session.user_id) {
            return Err(DomainError::Forbidden);
        }
        if channel.content_policy != ContentPolicy::Plaintext {
            return Err(DomainError::EncryptedRoute);
        }
        if channel.history == HistoryPolicy::Off {
            return Err(DomainError::BadState);
        }
        if !history_setting_is_allowed(channel, channel.history) {
            return Err(DomainError::BadState);
        }
        Ok(())
    }

    fn assess_charges(&self, user_id: UserId, command: &CanonicalCommand) -> Vec<RateCharge> {
        let mut charges = Vec::new();
        charges.push(rate_charge(RateBucket::RegisteredCommand(user_id)));
        if let CanonicalCommandData::List(selected) = command.data() {
            // A LIST owes one query token per 20 records its bounded scan
            // will examine (spec 14.3), assessed before the scan runs.
            charges.push(RateCharge {
                bucket: RateBucket::ExpensiveQuery(user_id),
                tokens: self.list_query_tokens(selected),
            });
        } else if is_expensive_query(command.kind()) {
            charges.push(rate_charge(RateBucket::ExpensiveQuery(user_id)));
        }
        if let CanonicalCommandData::Message(message) = command.data() {
            self.add_message_charges(user_id, message, &mut charges);
        }
        if let CanonicalCommandData::Join(targets) = command.data() {
            self.add_key_charges(user_id, targets, &mut charges);
        }
        charges
    }

    fn add_message_charges(
        &self,
        user_id: UserId,
        message: &crate::MessageCommand,
        charges: &mut Vec<RateCharge>,
    ) {
        match self
            .sessions
            .get(&user_id)
            .and_then(|session| session.account_id)
        {
            Some(account_id) => charges.push(rate_charge(RateBucket::AccountMessage(account_id))),
            None => charges.push(rate_charge(RateBucket::GuestMessage(user_id))),
        }
        for target in message.targets() {
            let MessageTarget::Channel(name) = target else {
                continue;
            };
            if let Some(channel_id) = self.channel_names.get(name) {
                charges.push(rate_charge(RateBucket::ChannelMessage(*channel_id)));
            }
        }
    }

    fn add_key_charges(
        &self,
        user_id: UserId,
        targets: &[crate::ChannelTarget],
        charges: &mut Vec<RateCharge>,
    ) {
        let principal = self
            .sessions
            .get(&user_id)
            .map(SessionState::principal)
            .unwrap_or(Principal::Guest(user_id));
        for target in targets {
            if target.key_supplied() {
                charges.push(rate_charge(RateBucket::ChannelKeyAttempt(principal)));
            }
        }
    }

    fn external_requests(
        &self,
        user_id: UserId,
        command: &CanonicalCommand,
    ) -> Result<Vec<ExternalInputRequest>, DomainError> {
        let mut requests = Vec::new();
        match command.data() {
            CanonicalCommandData::Join(targets) => self.join_requests(targets, &mut requests)?,
            CanonicalCommandData::TopicSet(_, _) => topic_requests(&mut requests)?,
            CanonicalCommandData::Invite(_, _) => invite_requests(&mut requests)?,
            CanonicalCommandData::Mode(ModeCommand::ChannelChange(_, changes)) => {
                mode_requests(changes, &mut requests)?;
            }
            CanonicalCommandData::Message(message) => {
                let sender = self
                    .sessions
                    .get(&user_id)
                    .ok_or(DomainError::InvariantViolation)?;
                let (accepted, _) = self.resolve_message_targets(sender, message)?;
                let accepted_indices: Vec<u8> = (0..accepted.len())
                    .map(|index| u8::try_from(index).map_err(|_| DomainError::Overflow))
                    .collect::<Result<_, _>>()?;
                message_requests(&accepted_indices, &mut requests)?;
            }
            CanonicalCommandData::Account(AccountCommand::DeleteStart) => {
                push_request(
                    &mut requests,
                    RequestShape::Entropy(EntropyPurpose::AccountDeletionChallenge, 16),
                )?;
                push_request(&mut requests, RequestShape::Monotonic)?;
            }
            CanonicalCommandData::Account(AccountCommand::DeleteConfirm(_)) => {
                push_request(&mut requests, RequestShape::Monotonic)?;
            }
            _ => {}
        }
        Ok(requests)
    }

    fn resolve_message_targets(
        &self,
        sender: &SessionState,
        message: &crate::MessageCommand,
    ) -> Result<(Vec<ResolvedMessageRoute>, Vec<TargetFailure>), DomainError> {
        let mut accepted = Vec::new();
        let mut failures = Vec::new();
        for (index, target) in message.targets().iter().enumerate() {
            match self.authorize_message_target(sender, target, message) {
                Ok(()) => accepted.push(self.resolve_message_target(target)?),
                Err(error) if is_target_policy_failure(error) => {
                    failures.push(TargetFailure::message(index, target, error)?);
                }
                Err(error) => return Err(error),
            }
        }
        accepted.sort_by_key(|route| route.target);
        Ok((accepted, failures))
    }

    fn authorize_message_target(
        &self,
        sender: &SessionState,
        target: &MessageTarget,
        message: &crate::MessageCommand,
    ) -> Result<(), DomainError> {
        if let MessageTarget::Channel(name) = target
            && self
                .channel_names
                .get(name)
                .is_some_and(|channel_id| self.channel_is_quarantined(*channel_id))
        {
            return Err(DomainError::Forbidden);
        }
        match (target, message.tagmsg_classification()) {
            (MessageTarget::Channel(name), Some(TagmsgClassification::E2eeApplication(proof))) => {
                self.authorize_e2ee_channel_message(sender, name, proof)
            }
            (MessageTarget::Channel(name), _) => {
                self.authorize_channel_message(sender, name, message.kind())
            }
            (MessageTarget::User(_), Some(TagmsgClassification::E2eeApplication(_))) => {
                Err(DomainError::EncryptedRoute)
            }
            (MessageTarget::User(nickname), _) => self.authorize_direct_message(sender, nickname),
        }
    }

    fn join_requests(
        &self,
        targets: &[crate::ChannelTarget],
        requests: &mut Vec<ExternalInputRequest>,
    ) -> Result<(), DomainError> {
        if !targets.is_empty() {
            push_request(requests, RequestShape::Utc)?;
        }
        if targets.iter().any(|target| {
            self.channel_names
                .get(target.name())
                .and_then(|channel_id| self.channels.get(channel_id))
                .is_some_and(|channel| channel.modes.invite_only || !channel.invites.is_empty())
        }) {
            push_request(requests, RequestShape::Monotonic)?;
        }
        for (index, target) in targets.iter().enumerate() {
            let index = u8::try_from(index).map_err(|_| DomainError::Overflow)?;
            if !self.channel_names.contains_key(target.name()) {
                push_request(
                    requests,
                    RequestShape::Entropy(EntropyPurpose::ChannelInstance(index), 16),
                )?;
            }
            if target.key_supplied() {
                push_request(requests, RequestShape::Key(index))?;
            }
        }
        Ok(())
    }

    fn plan_with_inputs(
        &self,
        authorized: AuthorizedCommand,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let AuthorizedCommand {
            user_id,
            principal,
            command,
            charges,
            ..
        } = authorized;
        let kind = command.kind();
        match command.into_data() {
            CanonicalCommandData::Nick(nickname) => self.plan_nick(user_id, nickname, charges),
            CanonicalCommandData::Quit(_) => self.plan_quit(user_id, charges),
            CanonicalCommandData::Join(targets) => {
                self.plan_join(user_id, principal, targets, charges, inputs)
            }
            CanonicalCommandData::Part(channels, _) => self.plan_part(user_id, channels, charges),
            CanonicalCommandData::PartAll => self.plan_part_all(user_id, charges),
            CanonicalCommandData::TopicSet(name, topic) => {
                self.plan_topic(user_id, name, topic, charges, inputs)
            }
            CanonicalCommandData::Mode(ModeCommand::ChannelChange(name, changes)) => {
                self.plan_modes(user_id, principal, name, changes, charges, inputs)
            }
            CanonicalCommandData::Mode(ModeCommand::UserOperatorNotices(_, enabled)) => {
                self.plan_operator_notices(user_id, enabled, charges)
            }
            CanonicalCommandData::Invite(target, channel) => {
                self.plan_invite(user_id, target, channel, charges, inputs)
            }
            CanonicalCommandData::Kick(channel, targets, _) => {
                self.plan_kick(user_id, channel, targets, charges)
            }
            CanonicalCommandData::Message(message) => {
                self.plan_message(user_id, message, charges, inputs)
            }
            CanonicalCommandData::Presence(PresenceCommand::Away(away)) => {
                self.plan_away(user_id, away, charges)
            }
            CanonicalCommandData::Presence(PresenceCommand::MonitorAdd(targets)) => {
                self.plan_monitor(user_id, MonitorChange::Add(targets), charges)
            }
            CanonicalCommandData::Presence(PresenceCommand::MonitorRemove(targets)) => {
                self.plan_monitor(user_id, MonitorChange::Remove(targets), charges)
            }
            CanonicalCommandData::Presence(PresenceCommand::MonitorClear) => {
                self.plan_monitor(user_id, MonitorChange::Clear, charges)
            }
            CanonicalCommandData::Setname(display_name) => {
                self.plan_setname(user_id, display_name, charges)
            }
            CanonicalCommandData::Account(account) => {
                self.plan_account(user_id, principal, account, charges, inputs)
            }
            CanonicalCommandData::Channel(channel) => {
                self.plan_channel(user_id, principal, channel, charges)
            }
            other => Ok(PlanDecision::Query(QueryPlan {
                expected_revision: self.revision,
                kind,
                requester: user_id,
                command: CanonicalCommand::from_data(other),
                charges,
            })),
        }
    }

    fn plan_nick(
        &self,
        user_id: UserId,
        nickname: NicknameValue,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        if self.nicknames.contains_key(&nickname) {
            return Err(DomainError::BadState);
        }
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        if self
            .reserved_nickname_owner(&nickname)
            .is_some_and(|owner| Some(owner) != session.account_id)
        {
            return Err(DomainError::Forbidden);
        }
        let mut recipients = self.session_recipients(user_id)?;
        recipients.insert(user_id);
        self.command_plan(
            vec![Mutation::Rename { user_id, nickname }],
            vec![DomainEvent::NicknameChanged(user_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn reserved_nickname_owner(&self, nickname: &NicknameValue) -> Option<AccountId> {
        self.accounts.iter().find_map(|(account_id, account)| {
            account
                .reserved_nicknames
                .contains(nickname)
                .then_some(*account_id)
        })
    }

    fn plan_quit(
        &self,
        user_id: UserId,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let recipients = self.session_recipients(user_id)?;
        let mut events = self.part_events(user_id)?;
        events.push(DomainEvent::SessionHidden(user_id));
        self.command_plan(
            vec![Mutation::CloseSession(user_id)],
            events,
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_join(
        &self,
        user_id: UserId,
        principal: Principal,
        targets: Vec<crate::ChannelTarget>,
        charges: Vec<RateCharge>,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let utc = inputs.utc_now;
        let mut key_verdicts = inputs.key_verdicts.into_iter();
        let mut plan = JoinPlanAccumulator {
            user_id,
            principal,
            utc,
            monotonic: inputs.monotonic_now,
            channel_ids: inputs.channel_ids.into_iter(),
            new_channel_ids: BTreeSet::new(),
            accepted_joins: 0,
            mutations: Vec::new(),
            events: Vec::new(),
            recipients: RecipientSet::new(),
        };
        let mut failures = Vec::new();
        for (index, target) in targets.into_iter().enumerate() {
            let key_ok = if target.key_supplied() {
                key_verdicts
                    .next()
                    .ok_or(DomainError::ExternalInputMismatch)?
            } else {
                true
            };
            let failed_name = target.name().clone();
            match self.plan_join_target(target, key_ok, &mut plan) {
                Ok(()) => {}
                Err(error) if is_target_policy_failure(error) => {
                    failures.push(TargetFailure::channel(index, failed_name, error)?);
                }
                Err(error) => return Err(error),
            }
        }
        if plan.mutations.is_empty() {
            return self.rejected_plan(DomainCommandKind::Join, failures, charges, false);
        }
        self.command_plan_with_failures(
            plan.mutations,
            plan.events,
            plan.recipients,
            failures,
            charges,
            StorageClass::Durable,
        )
    }

    // agenc-review: focus owner=core reviewed=2026-08-26 reason=join-plan-keeps-partial-policy-results-atomic
    fn plan_join_target(
        &self,
        target: crate::ChannelTarget,
        key_ok: bool,
        plan: &mut JoinPlanAccumulator,
    ) -> Result<(), DomainError> {
        let existing_channel_id = self.channel_names.get(target.name()).copied();
        let new_channel_id = if existing_channel_id.is_none() {
            Some(
                plan.channel_ids
                    .next()
                    .ok_or(DomainError::ExternalInputMismatch)?,
            )
        } else {
            None
        };
        let session = self
            .sessions
            .get(&plan.user_id)
            .ok_or(DomainError::InvariantViolation)?;
        let resulting_memberships = session
            .joined_channels
            .len()
            .checked_add(plan.accepted_joins)
            .ok_or(DomainError::Overflow)?;
        if resulting_memberships >= self.operational_limits.channels_per_session() {
            return Err(DomainError::LimitExceeded);
        }
        if let Some(channel_id) = existing_channel_id {
            let channel = self
                .channels
                .get(&channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            let consumed_invite = self.check_join_existing(
                plan.user_id,
                plan.principal,
                channel,
                target.key_supplied(),
                key_ok,
                plan.monotonic,
            )?;
            let joined_at = plan.utc.ok_or(DomainError::ExternalInputMismatch)?;
            let membership = Membership::joined(
                plan.user_id,
                plan.principal.account_id(),
                Role::Member,
                crate::model::next_revision(self.revision)?,
                joined_at,
            );
            let mut membership = membership;
            membership.effective_role = channel.effective_role(membership);
            plan.mutations.push(Mutation::JoinExisting {
                channel_id,
                membership,
                consumed_invite,
            });
            plan.events
                .push(DomainEvent::Joined(channel_id, plan.user_id));
            for member in channel.memberships.keys().copied() {
                plan.recipients.insert(member);
            }
            plan.recipients.insert(plan.user_id);
            plan.accepted_joins = plan
                .accepted_joins
                .checked_add(1)
                .ok_or(DomainError::Overflow)?;
            return Ok(());
        }
        let channel_id = new_channel_id.ok_or(DomainError::InvariantViolation)?;
        if self.channels.contains_key(&channel_id) || !plan.new_channel_ids.insert(channel_id) {
            return Err(DomainError::ExternalInputMismatch);
        }
        let scope = target.name().scope();
        let existing = self
            .channels
            .values()
            .filter(|channel| channel.name.scope() == scope)
            .count();
        let planned = plan
            .mutations
            .iter()
            .filter(|mutation| {
                matches!(mutation, Mutation::JoinNew(channel) if channel.name.scope() == scope)
            })
            .count();
        let ceiling = match scope {
            crate::ChannelScope::Global => self.operational_limits.global_channels(),
            crate::ChannelScope::Local => self.operational_limits.local_channels(),
        };
        if existing.checked_add(planned).ok_or(DomainError::Overflow)? >= ceiling {
            return Err(DomainError::LimitExceeded);
        }
        let created_at = plan.utc.ok_or(DomainError::ExternalInputMismatch)?;
        let revision = crate::model::next_revision(self.revision)?;
        let membership = Membership::joined(
            plan.user_id,
            plan.principal.account_id(),
            Role::Owner,
            revision,
            created_at,
        );
        let channel = crate::ChannelState::new_ephemeral(
            channel_id,
            target.into_name(),
            plan.principal,
            membership,
            created_at,
            revision,
        );
        plan.mutations.push(Mutation::JoinNew(channel));
        plan.events.push(DomainEvent::ChannelCreated(channel_id));
        plan.events
            .push(DomainEvent::Joined(channel_id, plan.user_id));
        plan.recipients.insert(plan.user_id);
        plan.accepted_joins = plan
            .accepted_joins
            .checked_add(1)
            .ok_or(DomainError::Overflow)?;
        Ok(())
    }

    fn check_join_existing(
        &self,
        user_id: UserId,
        principal: Principal,
        channel: &crate::ChannelState,
        key_supplied: bool,
        key_ok: bool,
        now: Option<MonotonicTick>,
    ) -> Result<Option<InviteId>, DomainError> {
        if channel.memberships.contains_key(&user_id) {
            return Err(DomainError::BadState);
        }
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        validate_guest_join(channel, principal)?;
        let matching_invite = matching_join_invite(channel, principal, now)?;
        validate_hidden_channel_join(channel, session, matching_invite, key_supplied, key_ok)?;
        if effective_mask(channel, session, false) {
            return Err(DomainError::Forbidden);
        }
        // The operational member ceiling is a channel-specific capacity
        // outcome in the spec 14.2 order (limit after visibility-safe lookup,
        // account, ban, invite and key), so it is checked only after hidden
        // authorization confirmed the requester may learn the channel exists
        // (PRV-01); it never precedes that decision.
        validate_join_admission(
            channel,
            session,
            matching_invite,
            key_supplied,
            key_ok,
            self.operational_limits.members_per_channel(),
        )?;
        Ok(matching_invite)
    }

    fn plan_part(
        &self,
        user_id: UserId,
        channels: Vec<ChannelNameValue>,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let mut channel_ids = Vec::new();
        let mut failures = Vec::new();
        channel_ids
            .try_reserve_exact(channels.len())
            .map_err(|_| DomainError::AllocationFailed)?;
        for (index, name) in channels.into_iter().enumerate() {
            let Some(channel_id) = self.channel_names.get(&name).copied() else {
                failures.push(TargetFailure::channel(index, name, DomainError::NotFound)?);
                continue;
            };
            let channel = self
                .channels
                .get(&channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            if !channel.memberships.contains_key(&user_id) {
                failures.push(TargetFailure::channel(index, name, DomainError::Forbidden)?);
                continue;
            }
            channel_ids.push(channel_id);
        }
        if channel_ids.is_empty() {
            return self.rejected_plan(DomainCommandKind::Part, failures, charges, false);
        }
        self.plan_part_ids(user_id, channel_ids, failures, charges)
    }

    fn plan_part_all(
        &self,
        user_id: UserId,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        let mut scope = None;
        for channel_id in &session.joined_channels {
            let channel = self
                .channels
                .get(channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            if scope.is_some_and(|current| current != channel.scope) {
                return Err(DomainError::MixedAuthority);
            }
            scope = Some(channel.scope);
        }
        self.plan_part_ids(
            user_id,
            session.joined_channels.iter().copied().collect(),
            Vec::new(),
            charges,
        )
    }

    fn plan_part_ids(
        &self,
        user_id: UserId,
        mut channel_ids: Vec<ChannelInstanceId>,
        failures: Vec<TargetFailure>,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        channel_ids.sort_unstable();
        let mut mutations = Vec::new();
        let mut events = Vec::new();
        let mut recipients = RecipientSet::new();
        for channel_id in channel_ids {
            let channel = self
                .channels
                .get(&channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            for member in channel.memberships.keys().copied() {
                recipients.insert(member);
            }
            if channel.content_policy == ContentPolicy::E2eeBound {
                if channel.e2ee_removal_pending.contains(&user_id) {
                    return Err(DomainError::BadState);
                }
                mutations.push(Mutation::MarkRemovalPending {
                    channel_id,
                    user_id,
                });
                events.push(DomainEvent::E2eeRemovalPending(channel_id, user_id));
            } else {
                mutations.push(Mutation::Part {
                    channel_id,
                    user_id,
                });
                events.push(DomainEvent::Parted(channel_id, user_id));
                if channel.memberships.len() == 1
                    && channel.persistence == PersistencePolicy::Ephemeral
                {
                    events.push(DomainEvent::ChannelDestroyed(channel_id));
                }
            }
        }
        self.command_plan_with_failures(
            mutations,
            events,
            recipients,
            failures,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_topic(
        &self,
        user_id: UserId,
        name: ChannelNameValue,
        text: TopicText,
        charges: Vec<RateCharge>,
        mut inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let channel_id = self
            .channel_names
            .get(&name)
            .copied()
            .ok_or(DomainError::NotFound)?;
        let message_id = take_one(&mut inputs.message_ids)?;
        let set_at = inputs.utc_now.ok_or(DomainError::ExternalInputMismatch)?;
        let topic = PlaintextTopic {
            text,
            message_id,
            setter: user_id,
            set_at,
        };
        let recipients = self.channel_recipients(channel_id)?;
        self.command_plan(
            vec![Mutation::SetTopic { channel_id, topic }],
            vec![DomainEvent::TopicChanged(channel_id, message_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_modes(
        &self,
        user_id: UserId,
        principal: Principal,
        name: ChannelNameValue,
        changes: Vec<ModeChange>,
        charges: Vec<RateCharge>,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let channel_id = self
            .channel_names
            .get(&name)
            .copied()
            .ok_or(DomainError::NotFound)?;
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        validate_mode_vector(self, channel, user_id, &changes, &inputs.entry_ids)?;
        let recipients = self.channel_recipients(channel_id)?;
        let events = mode_events(self, channel, &changes)?;
        self.command_plan(
            vec![Mutation::ApplyModes {
                channel_id,
                setter: principal,
                changes,
                entry_ids: inputs.entry_ids,
                key_verifiers: inputs.key_verifiers,
                created_at: inputs.utc_now,
            }],
            events,
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_invite(
        &self,
        user_id: UserId,
        target: NicknameValue,
        name: ChannelNameValue,
        charges: Vec<RateCharge>,
        mut inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let channel_id = self
            .channel_names
            .get(&name)
            .copied()
            .ok_or(DomainError::NotFound)?;
        let target_user = self
            .nicknames
            .get(&target)
            .copied()
            .ok_or(DomainError::NotFound)?;
        let target_session = self
            .sessions
            .get(&target_user)
            .ok_or(DomainError::InvariantViolation)?;
        let invite_id = take_one(&mut inputs.invite_ids)?;
        self.validate_new_invite_id(invite_id)?;
        let now = inputs
            .monotonic_now
            .ok_or(DomainError::ExternalInputMismatch)?;
        let expires_at = invite_expiry(now)?;
        let created_at_utc = inputs.utc_now.ok_or(DomainError::ExternalInputMismatch)?;
        let expires_at_utc = created_at_utc.checked_add(INVITE_LIFETIME_SECONDS)?;
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        let target_principal = target_session.principal();
        let expired_invites = self.validate_invite_capacity(channel, target_principal, now)?;
        let actor = self
            .sessions
            .get(&user_id)
            .ok_or(DomainError::InvariantViolation)?;
        if effective_mask(channel, actor, true) {
            return Err(DomainError::Forbidden);
        }
        let invite = Invite {
            invite_id,
            target: target_principal,
            inviter: user_id,
            creation_revision: crate::model::next_revision(self.revision)?,
            expires_at,
            expires_at_utc,
        };
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        recipients.insert(target_user);
        self.command_plan(
            vec![Mutation::CreateInvite {
                channel_id,
                invite,
                expired_invites,
            }],
            vec![DomainEvent::InviteCreated(channel_id, invite_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn validate_new_invite_id(&self, invite_id: InviteId) -> Result<(), DomainError> {
        if self
            .channels
            .values()
            .any(|channel| channel.invites.contains_key(&invite_id))
        {
            return Err(DomainError::ExternalInputMismatch);
        }
        Ok(())
    }

    fn validate_invite_capacity(
        &self,
        channel: &crate::ChannelState,
        target: Principal,
        now: MonotonicTick,
    ) -> Result<Vec<InviteId>, DomainError> {
        let expired: Vec<InviteId> = channel
            .invites
            .values()
            .filter(|invite| invite.expires_at <= now)
            .map(|invite| invite.invite_id)
            .collect();
        let active = channel
            .invites
            .len()
            .checked_sub(expired.len())
            .ok_or(DomainError::InvariantViolation)?;
        if active >= self.operational_limits.invites_per_channel() {
            return Err(DomainError::LimitExceeded);
        }
        let network_total = self.channels.values().try_fold(0_usize, |total, current| {
            total.checked_add(current.invites.len())
        });
        validate_network_invite_capacity(
            network_total.ok_or(DomainError::Overflow)?,
            expired.len(),
            self.operational_limits.invites_global(),
        )?;
        let target_count = self
            .channels
            .values()
            .flat_map(|current| current.invites.values())
            .filter(|invite| invite.target == target && now < invite.expires_at)
            .count();
        if target_count >= self.operational_limits.invites_per_principal() {
            return Err(DomainError::LimitExceeded);
        }
        Ok(expired)
    }

    fn plan_kick(
        &self,
        user_id: UserId,
        name: ChannelNameValue,
        targets: Vec<NicknameValue>,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let channel_id = self
            .channel_names
            .get(&name)
            .copied()
            .ok_or(DomainError::NotFound)?;
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        let actor_role = channel.role_of(user_id).ok_or(DomainError::Forbidden)?;
        let mut accepted = Vec::new();
        let mut failures = Vec::new();
        for (index, target) in targets.into_iter().enumerate() {
            let Some(target_user) = self.nicknames.get(&target).copied() else {
                failures.push(TargetFailure::user(index, target, DomainError::NotFound)?);
                continue;
            };
            let Some(target_role) = channel.role_of(target_user) else {
                failures.push(TargetFailure::user(index, target, DomainError::NotFound)?);
                continue;
            };
            if target_role >= actor_role {
                failures.push(TargetFailure::user(index, target, DomainError::Forbidden)?);
                continue;
            }
            if channel.content_policy == ContentPolicy::E2eeBound
                && channel.e2ee_removal_pending.contains(&target_user)
            {
                failures.push(TargetFailure::user(index, target, DomainError::BadState)?);
                continue;
            }
            accepted.push(target_user);
        }
        accepted.sort_unstable();
        if accepted.is_empty() {
            return self.rejected_plan(DomainCommandKind::Kick, failures, charges, false);
        }
        let mut mutations = Vec::new();
        let mut events = Vec::new();
        for target_user in accepted {
            if channel.content_policy == ContentPolicy::E2eeBound {
                mutations.push(Mutation::MarkRemovalPending {
                    channel_id,
                    user_id: target_user,
                });
                events.push(DomainEvent::E2eeRemovalPending(channel_id, target_user));
            } else {
                mutations.push(Mutation::Part {
                    channel_id,
                    user_id: target_user,
                });
                events.push(DomainEvent::Parted(channel_id, target_user));
            }
        }
        let recipients = self.channel_recipients(channel_id)?;
        self.command_plan_with_failures(
            mutations,
            events,
            recipients,
            failures,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_message(
        &self,
        user_id: UserId,
        message: crate::MessageCommand,
        charges: Vec<RateCharge>,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let sender = self
            .sessions
            .get(&user_id)
            .ok_or(DomainError::InvariantViolation)?;
        let (resolved_routes, failures) = self.resolve_message_targets(sender, &message)?;
        if resolved_routes.len() != inputs.message_ids.len()
            || contains_duplicate(&inputs.message_ids)
        {
            return Err(DomainError::ExternalInputMismatch);
        }
        let kind = match message.kind() {
            MessageKind::Privmsg => DomainCommandKind::Privmsg,
            MessageKind::Notice => DomainCommandKind::Notice,
            MessageKind::Tagmsg => DomainCommandKind::Tagmsg,
        };
        if resolved_routes.is_empty() {
            return self.rejected_plan(
                kind,
                failures,
                charges,
                message.kind() == MessageKind::Notice,
            );
        }
        let mut events = Vec::new();
        let mut recipients = RecipientSet::new();
        let mut routes = Vec::new();
        for (resolved, message_id) in resolved_routes.into_iter().zip(inputs.message_ids) {
            events.push(DomainEvent::MessageAccepted(message_id, user_id));
            for recipient in resolved.recipients.iter() {
                recipients.insert(recipient);
            }
            routes.push(MessageRoute {
                message_id,
                target: resolved.target,
                recipients: resolved.recipients,
            });
        }
        recipients.insert(user_id);
        let accepted_at = inputs.utc_now.ok_or(DomainError::ExternalInputMismatch)?;
        let (message_kind, _targets, body, tagmsg_classification) = message.into_parts();
        self.message_plan(
            events,
            recipients,
            failures,
            MessageBatch {
                kind: message_kind,
                sender: user_id,
                body,
                tagmsg_classification,
                accepted_at,
                routes,
            },
            charges,
        )
    }

    fn resolve_message_target(
        &self,
        target: &MessageTarget,
    ) -> Result<ResolvedMessageRoute, DomainError> {
        let mut recipients = RecipientSet::new();
        let resolved = match target {
            MessageTarget::Channel(name) => {
                let channel_id = self.channel_names.get(name).ok_or(DomainError::NotFound)?;
                let channel = self
                    .channels
                    .get(channel_id)
                    .ok_or(DomainError::InvariantViolation)?;
                for user_id in channel.memberships.keys().copied() {
                    recipients.insert(user_id);
                }
                ResolvedMessageTarget::Channel(*channel_id)
            }
            MessageTarget::User(nickname) => {
                let user_id = *self.nicknames.get(nickname).ok_or(DomainError::NotFound)?;
                recipients.insert(user_id);
                ResolvedMessageTarget::User(user_id)
            }
        };
        Ok(ResolvedMessageRoute {
            target: resolved,
            recipients,
        })
    }

    fn plan_away(
        &self,
        user_id: UserId,
        away: Option<crate::AwayText>,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let recipients = self.session_recipients(user_id)?;
        self.command_plan(
            vec![Mutation::SetAway { user_id, away }],
            vec![DomainEvent::AwayChanged(user_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_operator_notices(
        &self,
        user_id: UserId,
        enabled: bool,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.command_plan(
            vec![Mutation::SetOperatorNotices { user_id, enabled }],
            vec![DomainEvent::UserModesChanged(user_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_monitor(
        &self,
        user_id: UserId,
        change: MonitorChange,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        if let MonitorChange::Add(targets) = &change {
            let added = targets
                .iter()
                .filter(|target| !session.monitored_nicknames.contains(*target))
                .count();
            let resulting = session
                .monitored_nicknames
                .len()
                .checked_add(added)
                .ok_or(DomainError::Overflow)?;
            if resulting > crate::model::MAX_MONITORED_NICKNAMES {
                return Err(DomainError::LimitExceeded);
            }
        }
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.command_plan(
            vec![Mutation::SetMonitor { user_id, change }],
            Vec::new(),
            recipients,
            charges,
            StorageClass::Ephemeral,
        )
    }

    fn plan_setname(
        &self,
        user_id: UserId,
        display_name: DisplayNameValue,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let recipients = self.session_recipients(user_id)?;
        self.command_plan(
            vec![Mutation::SetDisplayName {
                user_id,
                display_name,
            }],
            vec![DomainEvent::DisplayNameChanged(user_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_account(
        &self,
        user_id: UserId,
        principal: Principal,
        command: AccountCommand,
        charges: Vec<RateCharge>,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let account_id = principal
            .account_id()
            .ok_or(DomainError::RegistrationRequired)?;
        match command {
            AccountCommand::DeleteStart => {
                return self.plan_account_deletion_start(user_id, account_id, charges, inputs);
            }
            AccountCommand::DeleteConfirm(candidate) => {
                return self.plan_account_deletion_confirm(
                    user_id, account_id, candidate, charges, inputs,
                );
            }
            _ => {}
        }
        let setting = account_setting(self, account_id, command)?;
        let mut recipients = RecipientSet::new();
        for session in self.sessions.values() {
            if session.account_id == Some(account_id) {
                recipients.insert(session.user_id);
            }
        }
        self.command_plan(
            vec![Mutation::AccountSetting {
                account_id,
                setting,
            }],
            vec![DomainEvent::AccountUpdated(account_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn plan_account_deletion_start(
        &self,
        user_id: UserId,
        account_id: AccountId,
        charges: Vec<RateCharge>,
        mut inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        let account = self
            .accounts
            .get(&account_id)
            .ok_or(DomainError::NotFound)?;
        let now = inputs
            .monotonic_now
            .ok_or(DomainError::ExternalInputMismatch)?;
        if session
            .fresh_auth_deadline
            .is_none_or(|deadline| now > deadline)
        {
            return Err(DomainError::BadState);
        }
        let token = take_one(&mut inputs.deletion_tokens)?;
        let expires_at = now.checked_add(DELETION_CHALLENGE_LIFETIME_MILLIS)?;
        let challenge = AccountDeletionChallengeState {
            token,
            account_id,
            account_revision: account.revision,
            account_session_generation: account.session_generation,
            session_id: session.session_id,
            user_id,
            session_generation: session.generation,
            expires_at,
        };
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.command_plan(
            vec![Mutation::StartAccountDeletion(challenge)],
            vec![DomainEvent::AccountDeletionChallengeStarted(user_id)],
            recipients,
            charges,
            StorageClass::Ephemeral,
        )
    }

    fn plan_account_deletion_confirm(
        &self,
        user_id: UserId,
        account_id: AccountId,
        candidate: AccountDeletionToken,
        charges: Vec<RateCharge>,
        inputs: ExternalInputs,
    ) -> Result<PlanDecision, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        let now = inputs
            .monotonic_now
            .ok_or(DomainError::ExternalInputMismatch)?;
        let challenge = self
            .account_deletion_challenges
            .get(&session.session_id)
            .ok_or(DomainError::BadState)?;
        let token_matches = challenge.token.matches(candidate.expose_for_deletion());
        let binding_matches = challenge.account_id == account_id
            && challenge.account_session_generation == session.account_session_generation
            && challenge.session_id == session.session_id
            && challenge.user_id == user_id
            && challenge.session_generation == session.generation
            && now < challenge.expires_at;
        if token_matches
            && binding_matches
            && let Ok(mut plan) = self.plan_account_deleted_at_revision(
                account_id,
                challenge.account_session_generation,
                challenge.account_revision,
            )
        {
            plan.charges = charges;
            return Ok(PlanDecision::Mutation(plan));
        }
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.command_plan(
            vec![Mutation::ConsumeAccountDeletionChallenge(
                session.session_id,
            )],
            vec![DomainEvent::AccountDeletionConfirmationRejected(user_id)],
            recipients,
            charges,
            StorageClass::Ephemeral,
        )
    }

    fn plan_channel(
        &self,
        user_id: UserId,
        principal: Principal,
        command: ChannelCommand,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let account_id = principal
            .account_id()
            .ok_or(DomainError::RegistrationRequired)?;
        let channel_id = channel_command_id(command);
        validate_channel_setting(self, user_id, account_id, command)?;
        let recipients = self.channel_recipients(channel_id)?;
        self.command_plan(
            vec![Mutation::ChannelSetting(command)],
            vec![DomainEvent::ChannelPolicyChanged(channel_id)],
            recipients,
            charges,
            StorageClass::Durable,
        )
    }

    fn single_mutation(
        &self,
        mutation: Mutation,
        event: DomainEvent,
        recipients: RecipientSet,
        charges: Vec<RateCharge>,
        storage: StorageClass,
    ) -> Result<MutationPlan, DomainError> {
        self.assemble_plan(PlanParts {
            mutations: vec![mutation],
            events: vec![event],
            recipients,
            failures: Vec::new(),
            message_batch: None,
            charges,
            storage,
        })
    }

    /// Fixes the revisions of one plan and derives its persisted write set.
    fn assemble_plan(&self, parts: PlanParts) -> Result<MutationPlan, DomainError> {
        let resulting_revision = crate::model::next_revision(self.revision)?;
        let durable_writes =
            self.durable_writes_for(&parts.mutations, resulting_revision, parts.storage)?;
        Ok(MutationPlan {
            expected_revision: self.revision,
            resulting_revision,
            mutations: parts.mutations,
            events: parts.events,
            recipients: parts.recipients,
            failures: parts.failures,
            message_batch: parts.message_batch,
            charges: parts.charges,
            storage: parts.storage,
            durable_writes,
        })
    }

    /// Runs the persisted-entity arms of a plan against duplicated entities and
    /// reports every projection that changed.
    fn durable_writes_for(
        &self,
        mutations: &[Mutation],
        revision: Revision,
        storage: StorageClass,
    ) -> Result<Vec<DurableWrite>, DomainError> {
        let touched = TouchedEntities::collect(self, mutations);
        if touched.is_empty() {
            return Ok(Vec::new());
        }
        let mut scratch = touched.scratch(self)?;
        for mutation in mutations {
            scratch.apply_mutation(mutation.duplicate_for_projection()?, revision);
        }
        let writes = touched.writes(self, &scratch);
        if storage == StorageClass::Ephemeral && !writes.is_empty() {
            return Err(DomainError::InvariantViolation);
        }
        Ok(writes)
    }

    fn command_plan(
        &self,
        mutations: Vec<Mutation>,
        events: Vec<DomainEvent>,
        recipients: RecipientSet,
        charges: Vec<RateCharge>,
        storage: StorageClass,
    ) -> Result<PlanDecision, DomainError> {
        self.command_plan_with_failures(mutations, events, recipients, Vec::new(), charges, storage)
    }

    fn command_plan_with_failures(
        &self,
        mutations: Vec<Mutation>,
        events: Vec<DomainEvent>,
        recipients: RecipientSet,
        failures: Vec<TargetFailure>,
        charges: Vec<RateCharge>,
        storage: StorageClass,
    ) -> Result<PlanDecision, DomainError> {
        Ok(PlanDecision::Mutation(self.assemble_plan(PlanParts {
            mutations,
            events,
            recipients,
            failures,
            message_batch: None,
            charges,
            storage,
        })?))
    }

    fn rejected_plan(
        &self,
        kind: DomainCommandKind,
        failures: Vec<TargetFailure>,
        charges: Vec<RateCharge>,
        silent: bool,
    ) -> Result<PlanDecision, DomainError> {
        if failures.is_empty() {
            return Err(DomainError::InvariantViolation);
        }
        Ok(PlanDecision::Rejected(RejectedPlan {
            expected_revision: self.revision,
            kind,
            failures,
            charges,
            silent,
        }))
    }

    fn message_plan(
        &self,
        events: Vec<DomainEvent>,
        recipients: RecipientSet,
        failures: Vec<TargetFailure>,
        message_batch: MessageBatch,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        Ok(PlanDecision::Mutation(self.assemble_plan(PlanParts {
            mutations: vec![Mutation::EventOnly],
            events,
            recipients,
            failures,
            message_batch: Some(message_batch),
            charges,
            storage: StorageClass::Durable,
        })?))
    }

    fn channel_recipients(
        &self,
        channel_id: ChannelInstanceId,
    ) -> Result<RecipientSet, DomainError> {
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or(DomainError::NotFound)?;
        let mut recipients = RecipientSet::new();
        for user_id in channel.memberships.keys().copied() {
            recipients.insert(user_id);
        }
        Ok(recipients)
    }

    fn session_recipients(&self, user_id: UserId) -> Result<RecipientSet, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        let mut recipients = RecipientSet::new();
        for channel_id in &session.joined_channels {
            let channel = self
                .channels
                .get(channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            for member in channel.memberships.keys().copied() {
                recipients.insert(member);
            }
        }
        Ok(recipients)
    }

    fn part_events(&self, user_id: UserId) -> Result<Vec<DomainEvent>, DomainError> {
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        let mut events = Vec::new();
        events
            .try_reserve_exact(session.joined_channels.len())
            .map_err(|_| DomainError::AllocationFailed)?;
        for channel_id in &session.joined_channels {
            events.push(DomainEvent::Parted(*channel_id, user_id));
        }
        Ok(events)
    }

    // agenc-review: focus owner=core reviewed=2026-08-26 reason=closed-domain-mutation-dispatcher
    fn apply_mutation(&mut self, mutation: Mutation, revision: Revision) {
        match mutation {
            Mutation::InsertAccount(account) => self.apply_account(account, revision),
            Mutation::InsertSession(session) => self.apply_session(session, revision),
            Mutation::SwitchSessionAccount {
                user_id,
                account_id,
                account_session_generation,
                session_generation,
                channel_ids,
            } => self.apply_session_account_switch(
                user_id,
                account_id,
                account_session_generation,
                session_generation,
                &channel_ids,
                revision,
            ),
            Mutation::DeleteAccount {
                account_id,
                user_ids,
            } => self.apply_account_deletion(account_id, user_ids, revision),
            Mutation::ReplaceAccountCredential {
                account_id,
                account_session_generation,
                user_ids,
            } => self.apply_account_credential_replacement(
                account_id,
                account_session_generation,
                user_ids,
                revision,
            ),
            Mutation::Rename { user_id, nickname } => self.apply_nick(user_id, nickname, revision),
            Mutation::SetAway { user_id, away } => self.apply_away(user_id, away, revision),
            Mutation::SetOperatorNotices { user_id, enabled } => {
                self.apply_operator_notices(user_id, enabled, revision);
            }
            Mutation::SetMonitor { user_id, change } => {
                self.apply_monitor(user_id, change, revision);
            }
            Mutation::SetDisplayName {
                user_id,
                display_name,
            } => {
                self.apply_display_name(user_id, display_name, revision);
            }
            Mutation::SetFreshAuthDeadline { user_id, deadline } => {
                // Process-local authentication state has no session projection.
                if let Some(session) = self.sessions.get_mut(&user_id) {
                    self.account_deletion_challenges.remove(&session.session_id);
                    session.fresh_auth_deadline = Some(deadline);
                }
            }
            Mutation::StartAccountDeletion(challenge) => {
                // Consuming freshness leaves the published session revision intact.
                if let Some(session) = self.sessions.get_mut(&challenge.user_id) {
                    session.fresh_auth_deadline = None;
                }
                self.account_deletion_challenges
                    .insert(challenge.session_id, challenge);
            }
            Mutation::ConsumeAccountDeletionChallenge(session_id) => {
                self.account_deletion_challenges.remove(&session_id);
            }
            Mutation::JoinNew(channel) => self.apply_join_new(channel, revision),
            Mutation::JoinExisting {
                channel_id,
                membership,
                consumed_invite,
            } => {
                self.apply_join_existing(channel_id, membership, consumed_invite, revision);
            }
            Mutation::Part {
                channel_id,
                user_id,
            } => self.apply_part(channel_id, user_id, revision),
            Mutation::CloseSession(user_id) => self.apply_close_session(user_id, revision),
            Mutation::SetTopic { channel_id, topic } => {
                self.apply_topic(channel_id, topic, revision);
            }
            Mutation::ApplyModes {
                channel_id,
                setter,
                changes,
                entry_ids,
                key_verifiers,
                created_at,
            } => {
                self.apply_modes(
                    channel_id,
                    ModeBatch {
                        setter,
                        changes,
                        entry_ids,
                        key_verifiers,
                        created_at,
                    },
                    revision,
                );
            }
            Mutation::AccountSetting {
                account_id,
                setting,
            } => {
                self.apply_account_setting(account_id, setting, revision);
            }
            Mutation::ChannelSetting(command) => self.apply_channel_setting(command, revision),
            Mutation::BindE2ee { channel_id } => {
                if let Some(channel) = self.channels.get_mut(&channel_id) {
                    channel.content_policy = ContentPolicy::E2eeBound;
                    channel.revision = revision;
                }
            }
            Mutation::CreateInvite {
                channel_id,
                invite,
                expired_invites,
            } => {
                if let Some(channel) = self.channels.get_mut(&channel_id) {
                    for invite_id in expired_invites {
                        channel.invites.remove(&invite_id);
                    }
                    channel.invites.insert(invite.invite_id, invite);
                    channel.revision = revision;
                }
            }
            Mutation::MarkRemovalPending {
                channel_id,
                user_id,
            } => {
                if let Some(channel) = self.channels.get_mut(&channel_id) {
                    channel.e2ee_removal_pending.insert(user_id);
                    channel.revision = revision;
                }
            }
            Mutation::FinalizeE2eeRemoval {
                channel_id,
                user_id,
            } => self.apply_part(channel_id, user_id, revision),
            Mutation::ExpireInvites(expired) => {
                for (channel_id, invite_id) in expired {
                    if let Some(channel) = self.channels.get_mut(&channel_id)
                        && channel.invites.remove(&invite_id).is_some()
                    {
                        channel.revision = revision;
                    }
                }
            }
            Mutation::AddSanction(sanction) => self.sanctions.push(sanction),
            Mutation::EventOnly => {}
        }
    }

    fn apply_account(&mut self, mut account: AccountState, revision: Revision) {
        account.revision = revision;
        self.accounts.insert(account.account_id, account);
    }

    fn apply_session(&mut self, mut session: SessionState, revision: Revision) {
        session.revision = revision;
        self.session_ids.insert(session.session_id, session.user_id);
        self.nicknames
            .insert(session.nickname.clone(), session.user_id);
        self.public_cloaks
            .insert(session.public_cloak, session.user_id);
        self.sessions.insert(session.user_id, session);
    }

    fn apply_session_account_switch(
        &mut self,
        user_id: UserId,
        account_id: Option<AccountId>,
        account_session_generation: agenc_ircd_types::Generation,
        session_generation: agenc_ircd_types::Generation,
        channel_ids: &[ChannelInstanceId],
        revision: Revision,
    ) {
        let was_guest = self
            .sessions
            .get(&user_id)
            .is_some_and(|session| session.account_id.is_none());
        let session_id = self
            .sessions
            .get(&user_id)
            .map(|session| session.session_id);
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.account_id = account_id;
            session.account_session_generation = account_session_generation;
            session.generation = session_generation;
            session.fresh_auth_deadline = None;
            session.revision = revision;
        }
        if let Some(session_id) = session_id {
            self.account_deletion_challenges.remove(&session_id);
        }
        for channel_id in channel_ids {
            let Some(channel) = self.channels.get_mut(channel_id) else {
                continue;
            };
            let Some(membership) = channel.memberships.get_mut(&user_id) else {
                continue;
            };
            membership.account_id = account_id;
            let grant = account_id
                .and_then(|current| channel.role_grants.get(&current).copied())
                .unwrap_or(Role::Member);
            membership.effective_role = std::cmp::max(membership.session_role, grant);
            channel.revision = revision;
        }
        if was_guest && account_id.is_some() {
            for channel in self.channels.values_mut() {
                let invite_count = channel.invites.len();
                channel
                    .invites
                    .retain(|_, invite| invite.target != Principal::Guest(user_id));
                if channel.invites.len() != invite_count {
                    channel.revision = revision;
                }
            }
        }
    }

    fn apply_account_deletion(
        &mut self,
        account_id: AccountId,
        user_ids: Vec<UserId>,
        revision: Revision,
    ) {
        for user_id in user_ids {
            self.apply_close_session(user_id, revision);
        }
        self.accounts.remove(&account_id);
        for channel in self.channels.values_mut() {
            let grant_removed = channel.role_grants.remove(&account_id).is_some();
            let invite_count = channel.invites.len();
            channel
                .invites
                .retain(|_, invite| invite.target != Principal::Account(account_id));
            if grant_removed || channel.invites.len() != invite_count {
                channel.revision = revision;
            }
        }
    }

    fn apply_account_credential_replacement(
        &mut self,
        account_id: AccountId,
        account_session_generation: agenc_ircd_types::Generation,
        user_ids: Vec<UserId>,
        revision: Revision,
    ) {
        for user_id in user_ids {
            self.apply_close_session(user_id, revision);
        }
        if let Some(account) = self.accounts.get_mut(&account_id) {
            account.session_generation = account_session_generation;
            account.revision = revision;
        }
    }

    fn apply_nick(&mut self, user_id: UserId, nickname: NicknameValue, revision: Revision) {
        let Some(session) = self.sessions.get_mut(&user_id) else {
            return;
        };
        self.nicknames.remove(&session.nickname);
        self.nicknames.insert(nickname.clone(), user_id);
        session.nickname = nickname;
        session.revision = revision;
    }

    fn apply_away(&mut self, user_id: UserId, away: Option<crate::AwayText>, revision: Revision) {
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.away = away;
            session.revision = revision;
        }
    }

    fn apply_operator_notices(&mut self, user_id: UserId, enabled: bool, revision: Revision) {
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.operator_notices = enabled;
            session.revision = revision;
        }
    }

    fn apply_monitor(&mut self, user_id: UserId, change: MonitorChange, _revision: Revision) {
        let Some(session) = self.sessions.get_mut(&user_id) else {
            return;
        };
        match change {
            MonitorChange::Add(targets) => session.monitored_nicknames.extend(targets),
            MonitorChange::Remove(targets) => {
                for target in targets {
                    session.monitored_nicknames.remove(&target);
                }
            }
            MonitorChange::Clear => session.monitored_nicknames.clear(),
        }
    }

    fn apply_display_name(
        &mut self,
        user_id: UserId,
        display_name: DisplayNameValue,
        revision: Revision,
    ) {
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.display_name = display_name;
            session.revision = revision;
        }
    }

    fn apply_join_new(&mut self, mut channel: crate::ChannelState, revision: Revision) {
        channel.revision = revision;
        let channel_id = channel.channel_id;
        let name = channel.name.clone();
        for user_id in channel.memberships.keys() {
            if let Some(session) = self.sessions.get_mut(user_id) {
                session.joined_channels.insert(channel_id);
                session.revision = revision;
            }
        }
        self.channel_names.insert(name, channel_id);
        self.channels.insert(channel_id, channel);
    }

    fn apply_join_existing(
        &mut self,
        channel_id: ChannelInstanceId,
        membership: Membership,
        consumed_invite: Option<InviteId>,
        revision: Revision,
    ) {
        if let Some(session) = self.sessions.get_mut(&membership.user_id) {
            session.joined_channels.insert(channel_id);
            session.revision = revision;
        }
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.memberships.insert(membership.user_id, membership);
            if let Some(invite_id) = consumed_invite {
                channel.invites.remove(&invite_id);
            }
            channel.revision = revision;
        }
    }

    fn apply_part(&mut self, channel_id: ChannelInstanceId, user_id: UserId, revision: Revision) {
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.joined_channels.remove(&channel_id);
            session.revision = revision;
        }
        let destroy = self.channels.get_mut(&channel_id).is_some_and(|channel| {
            channel.e2ee_removal_pending.remove(&user_id);
            channel.memberships.remove(&user_id);
            channel.revision = revision;
            channel.memberships.is_empty() && channel.persistence == PersistencePolicy::Ephemeral
        });
        if destroy {
            self.destroy_channel(channel_id);
        }
    }

    fn destroy_channel(&mut self, channel_id: ChannelInstanceId) {
        if let Some(channel) = self.channels.remove(&channel_id) {
            self.channel_names.remove(&channel.name);
        }
    }

    fn apply_close_session(&mut self, user_id: UserId, revision: Revision) {
        let Some(session) = self.sessions.remove(&user_id) else {
            return;
        };
        self.account_deletion_challenges.remove(&session.session_id);
        self.session_ids.remove(&session.session_id);
        self.nicknames.remove(&session.nickname);
        self.public_cloaks.remove(&session.public_cloak);
        for channel in self.channels.values_mut() {
            let invite_count = channel.invites.len();
            channel
                .invites
                .retain(|_, invite| invite.target != Principal::Guest(user_id));
            if channel.invites.len() != invite_count {
                channel.revision = revision;
            }
        }
        for channel_id in session.joined_channels {
            self.apply_part(channel_id, user_id, revision);
        }
    }

    fn apply_topic(
        &mut self,
        channel_id: ChannelInstanceId,
        topic: PlaintextTopic,
        revision: Revision,
    ) {
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.topic = Some(topic);
            channel.revision = revision;
        }
    }

    fn apply_modes(&mut self, channel_id: ChannelInstanceId, batch: ModeBatch, revision: Revision) {
        let ModeBatch {
            setter,
            changes,
            entry_ids,
            key_verifiers,
            created_at,
        } = batch;
        let mut entry_ids = entry_ids.into_iter();
        let mut key_verifiers = key_verifiers.into_iter();
        for change in changes {
            self.apply_mode_change(
                channel_id,
                setter,
                change,
                &mut entry_ids,
                &mut key_verifiers,
                created_at,
            );
        }
        self.recompute_channel_roles(channel_id, revision);
    }

    fn apply_mode_change(
        &mut self,
        channel_id: ChannelInstanceId,
        setter: Principal,
        change: ModeChange,
        entry_ids: &mut impl Iterator<Item = EntryId>,
        key_verifiers: &mut impl Iterator<Item = crate::ChannelKeyVerifier>,
        created_at: Option<UtcSecond>,
    ) {
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return;
        };
        match change {
            ModeChange::Visibility { operation, mode } => {
                channel.visibility = resulting_visibility(channel.visibility, operation, mode);
            }
            ModeChange::InviteOnly(value) => channel.modes.invite_only = value,
            ModeChange::Moderated(value) => channel.modes.moderated = value,
            ModeChange::TopicProtected(value) => channel.modes.topic_protected = value,
            ModeChange::JoinKey(value) => {
                channel.key_verifier = if value { key_verifiers.next() } else { None };
                channel.modes.join_key = channel.key_verifier.is_some();
            }
            ModeChange::MemberLimit(value) => channel.member_limit = value,
            ModeChange::Role {
                operation,
                target,
                role,
            } => {
                apply_role_change(&self.nicknames, channel, operation, &target, role);
            }
            ModeChange::AddMask { list, mask } => {
                if let Some(entry_id) = entry_ids.next() {
                    // Spec 21.4 records the principal that created the entry,
                    // which is the acting operator, not the channel creator.
                    let entry = crate::ListEntry::new(
                        entry_id,
                        mask,
                        setter,
                        created_at.unwrap_or(channel.created_at),
                    );
                    mask_list_mut(channel, list).push(entry);
                }
            }
            ModeChange::RemoveMask { list, entry_id } => {
                mask_list_mut(channel, list).retain(|entry| entry.entry_id != entry_id);
            }
            ModeChange::RemoveMaskValue { list, mask } => {
                mask_list_mut(channel, list).retain(|entry| entry.mask != mask);
            }
        }
    }

    fn recompute_channel_roles(&mut self, channel_id: ChannelInstanceId, revision: Revision) {
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return;
        };
        for membership in channel.memberships.values_mut() {
            let grant = membership
                .account_id
                .and_then(|account_id| channel.role_grants.get(&account_id).copied())
                .unwrap_or(Role::Member);
            membership.effective_role = std::cmp::max(membership.session_role, grant);
        }
        channel.revision = revision;
    }

    fn apply_account_setting(
        &mut self,
        account_id: AccountId,
        setting: AccountSetting,
        revision: Revision,
    ) {
        let Some(account) = self.accounts.get_mut(&account_id) else {
            return;
        };
        match setting {
            AccountSetting::Label(label) => account.label = label,
            AccountSetting::Presence(policy) => account.presence = policy,
            AccountSetting::GuestDirectMessages(policy) => account.guest_direct_messages = policy,
            AccountSetting::DirectMessages(policy) => account.direct_messages = policy,
            AccountSetting::ContactAdd(contact) => {
                account.contacts.insert(contact);
            }
            AccountSetting::ContactRemove(contact) => {
                account.contacts.remove(&contact);
            }
            AccountSetting::NickReserve(nickname) => {
                account.reserved_nicknames.insert(nickname);
            }
            AccountSetting::NickRelease(nickname) => {
                account.reserved_nicknames.remove(&nickname);
            }
        }
        account.revision = revision;
    }

    fn apply_channel_setting(&mut self, command: ChannelCommand, revision: Revision) {
        let channel_id = channel_command_id(command);
        let (channels, sessions) = (&mut self.channels, &mut self.sessions);
        let Some(channel) = channels.get_mut(&channel_id) else {
            return;
        };
        let session_projection_changes = channel.scope == crate::ChannelScope::Local
            && matches!(
                command,
                ChannelCommand::Register(_) | ChannelCommand::Unregister(_)
            );
        match command {
            ChannelCommand::Register(_) => register_channel_roles(channel),
            ChannelCommand::Unregister(_) => unregister_channel_roles(channel),
            ChannelCommand::History(_, history) => channel.history = history,
            ChannelCommand::HistoryDefault(_) => return,
        }
        channel.revision = revision;
        if session_projection_changes {
            for user_id in channel.memberships.keys() {
                if let Some(session) = sessions.get_mut(user_id) {
                    session.revision = revision;
                }
            }
        }
    }
}

fn register_channel_roles(channel: &mut crate::ChannelState) {
    for membership in channel.memberships.values() {
        let Some(account_id) = membership.account_id else {
            continue;
        };
        channel
            .role_grants
            .entry(account_id)
            .and_modify(|role| *role = std::cmp::max(*role, membership.effective_role))
            .or_insert(membership.effective_role);
    }
    for membership in channel.memberships.values_mut() {
        let grant = membership
            .account_id
            .and_then(|account_id| channel.role_grants.get(&account_id).copied())
            .unwrap_or(Role::Member);
        if membership.account_id.is_some() {
            membership.session_role = Role::Member;
            membership.effective_role = grant;
        }
    }
    channel.persistence = PersistencePolicy::Registered;
}

fn unregister_channel_roles(channel: &mut crate::ChannelState) {
    for membership in channel.memberships.values_mut() {
        membership.session_role = membership.effective_role;
    }
    channel.role_grants.clear();
    channel.persistence = PersistencePolicy::Ephemeral;
    // Plaintext history is retained only for registered channels, so an ephemeral
    // channel must not keep a retention policy the invariants forbid.
    channel.history = HistoryPolicy::Off;
}

fn require_account(session: &SessionState) -> Result<AccountId, DomainError> {
    session.account_id.ok_or(DomainError::RegistrationRequired)
}

fn command_is_silent(command: &CanonicalCommand) -> bool {
    matches!(command.data(), CanonicalCommandData::Message(message) if message.kind() == MessageKind::Notice)
}

fn rate_charge(bucket: RateBucket) -> RateCharge {
    RateCharge { bucket, tokens: 1 }
}

/// Returns whether one command kind belongs to the expensive query class.
///
/// These are exactly the kinds that owe a token from the session-keyed
/// expensive-query bucket of spec 19.1, and therefore exactly the queries the
/// 80-percent overload class of spec 19.3 stops accepting. The predicate is
/// public so an overload owner refuses the same closed set the rate limiter
/// charges, rather than restating it.
#[must_use]
pub const fn is_expensive_query(kind: DomainCommandKind) -> bool {
    matches!(
        kind,
        DomainCommandKind::Names
            | DomainCommandKind::List
            | DomainCommandKind::Who
            | DomainCommandKind::Whois
            | DomainCommandKind::Whowas
            | DomainCommandKind::Chathistory
    )
}

fn authorize_direct_policy(
    sender: &SessionState,
    target: &AccountState,
) -> Result<(), DomainError> {
    match sender.account_id {
        None if target.guest_direct_messages == GuestDirectMessagePolicy::Deny => {
            Err(DomainError::Forbidden)
        }
        None => Ok(()),
        Some(sender_account) if sender_account == target.account_id => Ok(()),
        Some(_) if target.direct_messages == DirectMessagePolicy::Allow => Ok(()),
        Some(sender_account)
            if target.direct_messages == DirectMessagePolicy::Contacts
                && target.contacts.contains(&sender_account) =>
        {
            Ok(())
        }
        Some(_) => Err(DomainError::Forbidden),
    }
}

enum RequestShape {
    Utc,
    Monotonic,
    Entropy(EntropyPurpose, u8),
    Key(u8),
    KeyConstruction(u8),
}

fn push_request(
    requests: &mut Vec<ExternalInputRequest>,
    shape: RequestShape,
) -> Result<(), DomainError> {
    let request_sequence = u16::try_from(requests.len()).map_err(|_| DomainError::Overflow)?;
    let request = match shape {
        RequestShape::Utc => ExternalInputRequest::UtcNow { request_sequence },
        RequestShape::Monotonic => ExternalInputRequest::MonotonicNow { request_sequence },
        RequestShape::Entropy(purpose, bytes) => ExternalInputRequest::Entropy {
            request_sequence,
            purpose,
            bytes,
        },
        RequestShape::Key(target_index) => ExternalInputRequest::ChannelKeyVerification {
            request_sequence,
            target_index,
        },
        RequestShape::KeyConstruction(change_index) => {
            ExternalInputRequest::ChannelKeyConstruction {
                request_sequence,
                change_index,
            }
        }
    };
    requests
        .try_reserve(1)
        .map_err(|_| DomainError::AllocationFailed)?;
    requests.push(request);
    Ok(())
}

fn topic_requests(requests: &mut Vec<ExternalInputRequest>) -> Result<(), DomainError> {
    push_request(requests, RequestShape::Utc)?;
    push_request(
        requests,
        RequestShape::Entropy(EntropyPurpose::Message(0), 16),
    )
}

fn invite_requests(requests: &mut Vec<ExternalInputRequest>) -> Result<(), DomainError> {
    push_request(requests, RequestShape::Monotonic)?;
    push_request(requests, RequestShape::Utc)?;
    push_request(requests, RequestShape::Entropy(EntropyPurpose::Invite, 16))
}

fn mode_requests(
    changes: &[ModeChange],
    requests: &mut Vec<ExternalInputRequest>,
) -> Result<(), DomainError> {
    let mut needs_utc = false;
    for (index, change) in changes.iter().enumerate() {
        if matches!(change, ModeChange::JoinKey(true)) {
            let index = u8::try_from(index).map_err(|_| DomainError::Overflow)?;
            push_request(requests, RequestShape::KeyConstruction(index))?;
        }
        if matches!(change, ModeChange::AddMask { .. }) {
            let index = u8::try_from(index).map_err(|_| DomainError::Overflow)?;
            push_request(
                requests,
                RequestShape::Entropy(EntropyPurpose::MaskEntry(index), 16),
            )?;
            needs_utc = true;
        }
    }
    if needs_utc {
        push_request(requests, RequestShape::Utc)?;
    }
    Ok(())
}

fn message_requests(
    accepted_target_indices: &[u8],
    requests: &mut Vec<ExternalInputRequest>,
) -> Result<(), DomainError> {
    if accepted_target_indices.is_empty() {
        return Ok(());
    }
    push_request(requests, RequestShape::Utc)?;
    for index in accepted_target_indices {
        push_request(
            requests,
            RequestShape::Entropy(EntropyPurpose::Message(*index), 16),
        )?;
    }
    Ok(())
}

fn is_target_policy_failure(error: DomainError) -> bool {
    matches!(
        error,
        DomainError::NotFound
            | DomainError::SecretUnavailable
            | DomainError::Forbidden
            | DomainError::RegistrationRequired
            | DomainError::LimitExceeded
            | DomainError::BadState
            | DomainError::EncryptedRoute
            | DomainError::PlaintextRoute
    )
}

fn validate_external_inputs(
    requests: &[ExternalInputRequest],
    inputs: &ExternalInputs,
) -> Result<(), DomainError> {
    let expected_utc = requests
        .iter()
        .any(|request| matches!(request, ExternalInputRequest::UtcNow { .. }));
    let expected_monotonic = requests
        .iter()
        .any(|request| matches!(request, ExternalInputRequest::MonotonicNow { .. }));
    validate_requested_clocks(expected_utc, expected_monotonic, inputs)?;
    let counts = request_counts(requests);
    if inputs.channel_ids.len() != counts.channel_ids
        || inputs.message_ids.len() != counts.message_ids
        || inputs.invite_ids.len() != counts.invite_ids
        || inputs.entry_ids.len() != counts.entry_ids
        || inputs.deletion_tokens.len() != counts.deletion_tokens
        || inputs.key_verdicts.len() != counts.key_verdicts
        || inputs.key_verifiers.len() != counts.key_verifiers
    {
        return Err(DomainError::ExternalInputMismatch);
    }
    Ok(())
}

fn validate_requested_clocks(
    expected_utc: bool,
    expected_monotonic: bool,
    inputs: &ExternalInputs,
) -> Result<(), DomainError> {
    if inputs.wall_clock_unavailable {
        if !expected_utc || inputs.utc_now.is_some() {
            return Err(DomainError::ExternalInputMismatch);
        }
        return Err(DomainError::WallClockUnavailable);
    }
    if expected_utc != inputs.utc_now.is_some()
        || expected_monotonic != inputs.monotonic_now.is_some()
    {
        return Err(DomainError::ExternalInputMismatch);
    }
    Ok(())
}

#[derive(Default)]
struct RequestCounts {
    channel_ids: usize,
    message_ids: usize,
    invite_ids: usize,
    entry_ids: usize,
    deletion_tokens: usize,
    key_verdicts: usize,
    key_verifiers: usize,
}

fn request_counts(requests: &[ExternalInputRequest]) -> RequestCounts {
    let mut counts = RequestCounts::default();
    for request in requests {
        match request {
            ExternalInputRequest::Entropy { purpose, .. } => match purpose {
                EntropyPurpose::ChannelInstance(_) => counts.channel_ids += 1,
                EntropyPurpose::Message(_) => counts.message_ids += 1,
                EntropyPurpose::Invite => counts.invite_ids += 1,
                EntropyPurpose::MaskEntry(_) => counts.entry_ids += 1,
                EntropyPurpose::AccountDeletionChallenge => counts.deletion_tokens += 1,
            },
            ExternalInputRequest::ChannelKeyVerification { .. } => counts.key_verdicts += 1,
            ExternalInputRequest::ChannelKeyConstruction { .. } => counts.key_verifiers += 1,
            ExternalInputRequest::UtcNow { .. } | ExternalInputRequest::MonotonicNow { .. } => {}
        }
    }
    counts
}

fn take_one<Value>(values: &mut Vec<Value>) -> Result<Value, DomainError> {
    if values.len() != 1 {
        return Err(DomainError::ExternalInputMismatch);
    }
    values.pop().ok_or(DomainError::ExternalInputMismatch)
}

fn contains_duplicate<Value: Eq>(values: &[Value]) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        values
            .get(index + 1..)
            .is_some_and(|remaining| remaining.contains(value))
    })
}

fn invite_expiry(now: MonotonicTick) -> Result<MonotonicTick, DomainError> {
    let ticks = now
        .get()
        .checked_add(INVITE_LIFETIME_MILLIS)
        .ok_or(DomainError::Overflow)?;
    Ok(MonotonicTick::from_ticks(ticks))
}

fn validate_network_invite_capacity(
    total: usize,
    expired_in_target_channel: usize,
    limit: usize,
) -> Result<(), DomainError> {
    let active = total
        .checked_sub(expired_in_target_channel)
        .ok_or(DomainError::InvariantViolation)?;
    if active >= limit {
        return Err(DomainError::LimitExceeded);
    }
    Ok(())
}

fn validate_guest_join(
    channel: &crate::ChannelState,
    principal: Principal,
) -> Result<(), DomainError> {
    if principal.account_id().is_none()
        && (channel.visibility != Visibility::Listed
            || channel.content_policy == ContentPolicy::E2eeBound)
    {
        return Err(DomainError::SecretUnavailable);
    }
    Ok(())
}

fn matching_join_invite(
    channel: &crate::ChannelState,
    principal: Principal,
    now: Option<MonotonicTick>,
) -> Result<Option<InviteId>, DomainError> {
    if !channel.modes.invite_only && channel.invites.is_empty() {
        return Ok(None);
    }
    let now = now.ok_or(DomainError::ExternalInputMismatch)?;
    Ok(channel.matching_invite(principal, now))
}

// A non-member joins an unlisted or secret channel only through a matching
// invite, a matching invite exception, or the channel's own verified key.
// Every other non-member gets the nonexistent-channel failure, so this runs
// before the ban and limit checks that would otherwise confirm existence.
fn validate_hidden_channel_join(
    channel: &crate::ChannelState,
    session: &SessionState,
    matching_invite: Option<InviteId>,
    key_supplied: bool,
    key_ok: bool,
) -> Result<(), DomainError> {
    if channel.visibility == Visibility::Listed {
        return Ok(());
    }
    let invited =
        matching_invite.is_some() || matches_mask_list(&channel.invite_exceptions, session);
    let keyed = channel.modes.join_key && key_supplied && key_ok;
    if invited || keyed {
        return Ok(());
    }
    Err(DomainError::SecretUnavailable)
}

fn validate_join_admission(
    channel: &crate::ChannelState,
    session: &SessionState,
    matching_invite: Option<InviteId>,
    key_supplied: bool,
    key_ok: bool,
    member_ceiling: usize,
) -> Result<(), DomainError> {
    if channel.modes.invite_only
        && matching_invite.is_none()
        && !matches_mask_list(&channel.invite_exceptions, session)
    {
        return Err(DomainError::Forbidden);
    }
    if channel.modes.join_key && (!key_supplied || !key_ok) {
        return Err(DomainError::SecretUnavailable);
    }
    if channel_is_full(channel, member_ceiling) {
        return Err(DomainError::LimitExceeded);
    }
    if channel.content_policy == ContentPolicy::E2eeBound && session.account_id.is_none() {
        return Err(DomainError::RegistrationRequired);
    }
    Ok(())
}

/// Whether the channel's own `+l` limit or the configured member ceiling is
/// reached. Only a requester already admitted to learn the channel exists
/// reaches this check (architecture Section 14.2).
fn channel_is_full(channel: &crate::ChannelState, member_ceiling: usize) -> bool {
    let members = channel.memberships.len();
    channel
        .member_limit
        .is_some_and(|limit| members >= usize::from(limit))
        || members >= member_ceiling
}

fn validate_mode_vector(
    state: &DomainState,
    channel: &crate::ChannelState,
    actor: UserId,
    changes: &[ModeChange],
    entry_ids: &[EntryId],
) -> Result<(), DomainError> {
    let actor_role = channel.role_of(actor).ok_or(DomainError::Forbidden)?;
    let actor_account = state
        .sessions
        .get(&actor)
        .ok_or(DomainError::InvariantViolation)?
        .account_id;
    let expected_entries = changes
        .iter()
        .filter(|change| matches!(change, ModeChange::AddMask { .. }))
        .count();
    if expected_entries != entry_ids.len() {
        return Err(DomainError::ExternalInputMismatch);
    }
    for (index, entry_id) in entry_ids.iter().enumerate() {
        if entry_ids
            .iter()
            .take(index)
            .any(|previous| previous == entry_id)
            || channel
                .bans
                .iter()
                .chain(&channel.exceptions)
                .chain(&channel.invite_exceptions)
                .any(|entry| entry.entry_id == *entry_id)
        {
            return Err(DomainError::ExternalInputMismatch);
        }
    }
    let mut validation = ModeValidationState::new(channel, changes.len())?;
    let mut supplied_entry_ids = entry_ids.iter().copied();
    for change in changes {
        let entry_id = if matches!(change, ModeChange::AddMask { .. }) {
            Some(
                supplied_entry_ids
                    .next()
                    .ok_or(DomainError::ExternalInputMismatch)?,
            )
        } else {
            None
        };
        validation.validate_and_apply(
            state,
            channel,
            actor_role,
            actor_account,
            change,
            entry_id,
        )?;
    }
    if supplied_entry_ids.next().is_some() {
        return Err(DomainError::ExternalInputMismatch);
    }
    validation.validate_final(channel)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ModeRoleSubject {
    Account(AccountId),
    Session(UserId),
}

struct ModeRoleState {
    subject: ModeRoleSubject,
    role: Role,
    grant_present: bool,
}

#[derive(Clone, Copy)]
enum ModeMaskDelta<'a> {
    Added {
        list: MaskList,
        entry_id: EntryId,
        mask: &'a TypedMask,
    },
    Removed {
        list: MaskList,
        entry_id: EntryId,
    },
}

struct ModeValidationState<'a> {
    visibility: Visibility,
    roles: Vec<ModeRoleState>,
    mask_deltas: Vec<ModeMaskDelta<'a>>,
    mask_lengths: [usize; 3],
}

impl<'a> ModeValidationState<'a> {
    fn new(channel: &crate::ChannelState, change_count: usize) -> Result<Self, DomainError> {
        let mut roles = Vec::new();
        roles
            .try_reserve_exact(change_count)
            .map_err(|_| DomainError::AllocationFailed)?;
        let mut mask_deltas = Vec::new();
        mask_deltas
            .try_reserve_exact(change_count)
            .map_err(|_| DomainError::AllocationFailed)?;
        Ok(Self {
            visibility: channel.visibility,
            roles,
            mask_deltas,
            mask_lengths: [
                channel.bans.len(),
                channel.exceptions.len(),
                channel.invite_exceptions.len(),
            ],
        })
    }

    fn validate_and_apply(
        &mut self,
        state: &DomainState,
        channel: &'a crate::ChannelState,
        actor_role: Role,
        actor_account: Option<AccountId>,
        change: &'a ModeChange,
        entry_id: Option<EntryId>,
    ) -> Result<(), DomainError> {
        validate_mode_authority(actor_role, actor_account, change)?;
        match change {
            ModeChange::Visibility { operation, mode } => {
                self.visibility = resulting_visibility(self.visibility, *operation, *mode);
            }
            ModeChange::Role {
                operation,
                target,
                role,
            } => self.apply_role_change(state, channel, *operation, target, *role)?,
            ModeChange::AddMask { list, mask } => {
                let entry_id = entry_id.ok_or(DomainError::ExternalInputMismatch)?;
                self.apply_mask_add(channel, *list, entry_id, mask)?;
            }
            ModeChange::RemoveMask { list, entry_id } => {
                self.apply_mask_remove(channel, actor_role, *list, *entry_id)?;
            }
            ModeChange::RemoveMaskValue { list, mask } => {
                let entry_id = self
                    .entry_for_mask(channel, *list, mask)
                    .ok_or(DomainError::InvalidArgument)?;
                self.apply_mask_remove(channel, actor_role, *list, entry_id)?;
            }
            ModeChange::InviteOnly(_)
            | ModeChange::Moderated(_)
            | ModeChange::TopicProtected(_)
            | ModeChange::JoinKey(_)
            | ModeChange::MemberLimit(_) => {}
        }
        Ok(())
    }

    fn apply_role_change(
        &mut self,
        state: &DomainState,
        channel: &crate::ChannelState,
        operation: ModeOperation,
        target: &NicknameValue,
        role: Role,
    ) -> Result<(), DomainError> {
        let (subject, initial_role, grant_present) =
            resolve_mode_role_subject(state, channel, target)?;
        let role_state = if let Some(index) = self
            .roles
            .iter()
            .position(|current| current.subject == subject)
        {
            self.roles
                .get_mut(index)
                .ok_or(DomainError::InvariantViolation)?
        } else {
            self.roles.push(ModeRoleState {
                subject,
                role: initial_role,
                grant_present,
            });
            self.roles
                .last_mut()
                .ok_or(DomainError::InvariantViolation)?
        };
        role_state.role = resulting_role(role_state.role, operation, role)?;
        if matches!(subject, ModeRoleSubject::Account(_)) {
            role_state.grant_present = role_state.role != Role::Member;
        }
        Ok(())
    }

    fn apply_mask_add(
        &mut self,
        channel: &'a crate::ChannelState,
        list: MaskList,
        entry_id: EntryId,
        mask: &'a TypedMask,
    ) -> Result<(), DomainError> {
        if self.mask_is_present(channel, list, mask) {
            return Err(DomainError::InvalidArgument);
        }
        let index = mask_list_index(list);
        let length = self
            .mask_lengths
            .get_mut(index)
            .ok_or(DomainError::InvariantViolation)?;
        *length = length.checked_add(1).ok_or(DomainError::Overflow)?;
        self.mask_deltas.push(ModeMaskDelta::Added {
            list,
            entry_id,
            mask,
        });
        Ok(())
    }

    fn apply_mask_remove(
        &mut self,
        channel: &'a crate::ChannelState,
        actor_role: Role,
        list: MaskList,
        entry_id: EntryId,
    ) -> Result<(), DomainError> {
        let quiet = self
            .mask_for_entry(channel, list, entry_id)
            .ok_or(DomainError::InvalidArgument)?
            .is_quiet();
        if quiet {
            require_role(actor_role, Role::Operator)?;
        }
        let index = mask_list_index(list);
        let length = self
            .mask_lengths
            .get_mut(index)
            .ok_or(DomainError::InvariantViolation)?;
        *length = length
            .checked_sub(1)
            .ok_or(DomainError::InvariantViolation)?;
        self.mask_deltas
            .push(ModeMaskDelta::Removed { list, entry_id });
        Ok(())
    }

    fn mask_for_entry(
        &self,
        channel: &'a crate::ChannelState,
        list: MaskList,
        entry_id: EntryId,
    ) -> Option<&'a TypedMask> {
        let mut found = mask_list(channel, list)
            .iter()
            .find(|entry| entry.entry_id == entry_id)
            .map(|entry| &entry.mask);
        for delta in &self.mask_deltas {
            match delta {
                ModeMaskDelta::Added {
                    list: added_list,
                    entry_id: added_id,
                    mask,
                } if *added_list == list && *added_id == entry_id => found = Some(mask),
                ModeMaskDelta::Removed {
                    list: removed_list,
                    entry_id: removed_id,
                } if *removed_list == list && *removed_id == entry_id => found = None,
                ModeMaskDelta::Added { .. } | ModeMaskDelta::Removed { .. } => {}
            }
        }
        found
    }

    fn entry_for_mask(
        &self,
        channel: &'a crate::ChannelState,
        list: MaskList,
        mask: &TypedMask,
    ) -> Option<EntryId> {
        let original = mask_list(channel, list)
            .iter()
            .filter_map(|entry| (entry.mask == *mask).then_some(entry.entry_id));
        let added = self.mask_deltas.iter().filter_map(|delta| match delta {
            ModeMaskDelta::Added {
                list: added_list,
                entry_id,
                mask: added_mask,
            } if *added_list == list && **added_mask == *mask => Some(*entry_id),
            _ => None,
        });
        original
            .chain(added)
            .find(|entry_id| self.mask_for_entry(channel, list, *entry_id).is_some())
    }

    fn mask_is_present(
        &self,
        channel: &'a crate::ChannelState,
        list: MaskList,
        mask: &TypedMask,
    ) -> bool {
        let original_match = mask_list(channel, list).iter().any(|entry| {
            entry.mask == *mask && self.mask_for_entry(channel, list, entry.entry_id).is_some()
        });
        original_match
            || self.mask_deltas.iter().any(|delta| {
                let ModeMaskDelta::Added {
                    list: added_list,
                    entry_id,
                    mask: added_mask,
                } = delta
                else {
                    return false;
                };
                *added_list == list
                    && **added_mask == *mask
                    && self.mask_for_entry(channel, list, *entry_id).is_some()
            })
    }

    fn validate_final(&self, channel: &crate::ChannelState) -> Result<(), DomainError> {
        if self
            .mask_lengths
            .iter()
            .any(|length| *length > crate::model::MAX_MASK_ENTRIES_PER_LIST)
        {
            return Err(DomainError::LimitExceeded);
        }
        if channel.history != HistoryPolicy::Off && self.visibility != Visibility::Listed {
            return Err(DomainError::BadState);
        }
        self.validate_registered_roles(channel)
    }

    fn validate_registered_roles(&self, channel: &crate::ChannelState) -> Result<(), DomainError> {
        if channel.persistence != PersistencePolicy::Registered {
            return Ok(());
        }
        let mut grants = channel.role_grants.len();
        let mut owners = channel
            .role_grants
            .values()
            .filter(|role| **role == Role::Owner)
            .count();
        for role_state in &self.roles {
            let ModeRoleSubject::Account(account_id) = role_state.subject else {
                continue;
            };
            let initial = channel.role_grants.get(&account_id).copied();
            match (initial.is_some(), role_state.grant_present) {
                (true, false) => {
                    grants = grants
                        .checked_sub(1)
                        .ok_or(DomainError::InvariantViolation)?;
                }
                (false, true) => {
                    grants = grants.checked_add(1).ok_or(DomainError::Overflow)?;
                }
                (true, true) | (false, false) => {}
            }
            if initial == Some(Role::Owner) {
                owners = owners
                    .checked_sub(1)
                    .ok_or(DomainError::InvariantViolation)?;
            }
            if role_state.grant_present && role_state.role == Role::Owner {
                owners = owners.checked_add(1).ok_or(DomainError::Overflow)?;
            }
        }
        if grants > crate::model::MAX_ROLE_GRANTS_PER_CHANNEL {
            return Err(DomainError::LimitExceeded);
        }
        if owners == 0 {
            return Err(DomainError::BadState);
        }
        Ok(())
    }
}

fn validate_mode_authority(
    actor_role: Role,
    actor_account: Option<AccountId>,
    change: &ModeChange,
) -> Result<(), DomainError> {
    match change {
        ModeChange::Visibility {
            operation: ModeOperation::Add,
            mode: VisibilityMode::Secret,
        } => validate_secret_visibility(actor_role, actor_account),
        ModeChange::MemberLimit(Some(0)) => Err(DomainError::InvalidArgument),
        ModeChange::Visibility { .. }
        | ModeChange::InviteOnly(_)
        | ModeChange::Moderated(_)
        | ModeChange::JoinKey(_)
        | ModeChange::MemberLimit(_) => require_role(actor_role, Role::Operator),
        ModeChange::TopicProtected(_) => require_role(actor_role, Role::HalfOperator),
        ModeChange::Role { role, .. } => {
            if *role == Role::Member {
                return Err(DomainError::InvalidArgument);
            }
            if !actor_role.can_grant(*role) {
                return Err(DomainError::Forbidden);
            }
            Ok(())
        }
        ModeChange::AddMask { list, mask } | ModeChange::RemoveMaskValue { list, mask } => {
            if mask.is_quiet() && *list != MaskList::Ban {
                return Err(DomainError::InvalidArgument);
            }
            let required = if mask.is_quiet() {
                Role::Operator
            } else {
                Role::HalfOperator
            };
            require_role(actor_role, required)
        }
        ModeChange::RemoveMask { .. } => require_role(actor_role, Role::HalfOperator),
    }
}

fn resolve_mode_role_subject(
    state: &DomainState,
    channel: &crate::ChannelState,
    target: &NicknameValue,
) -> Result<(ModeRoleSubject, Role, bool), DomainError> {
    let user_id = state
        .nicknames
        .get(target)
        .copied()
        .ok_or(DomainError::NotFound)?;
    let membership = channel
        .memberships
        .get(&user_id)
        .ok_or(DomainError::NotFound)?;
    let session = state
        .sessions
        .get(&user_id)
        .ok_or(DomainError::InvariantViolation)?;
    if membership.account_id != session.account_id {
        return Err(DomainError::InvariantViolation);
    }
    if channel.persistence == PersistencePolicy::Registered
        && let Some(account_id) = session.account_id
    {
        let grant = channel.role_grants.get(&account_id).copied();
        let role = grant.unwrap_or(Role::Member);
        if membership.session_role != Role::Member || membership.effective_role != role {
            return Err(DomainError::InvariantViolation);
        }
        return Ok((ModeRoleSubject::Account(account_id), role, grant.is_some()));
    }
    Ok((
        ModeRoleSubject::Session(user_id),
        membership.effective_role,
        false,
    ))
}

fn resulting_role(
    current: Role,
    operation: ModeOperation,
    requested: Role,
) -> Result<Role, DomainError> {
    match operation {
        ModeOperation::Add => Ok(std::cmp::max(current, requested)),
        ModeOperation::Remove if requested == current => {
            current.next_lower().ok_or(DomainError::InvalidArgument)
        }
        ModeOperation::Remove => Err(DomainError::InvalidArgument),
    }
}

fn resulting_visibility(
    current: Visibility,
    operation: ModeOperation,
    mode: VisibilityMode,
) -> Visibility {
    match (operation, mode) {
        (ModeOperation::Add, VisibilityMode::Unlisted) => Visibility::Unlisted,
        (ModeOperation::Add, VisibilityMode::Secret) => Visibility::Secret,
        (ModeOperation::Remove, VisibilityMode::Unlisted) if current == Visibility::Unlisted => {
            Visibility::Listed
        }
        (ModeOperation::Remove, VisibilityMode::Secret) if current == Visibility::Secret => {
            Visibility::Listed
        }
        (ModeOperation::Remove, VisibilityMode::Unlisted | VisibilityMode::Secret) => current,
    }
}

const fn mask_list_index(list: MaskList) -> usize {
    match list {
        MaskList::Ban => 0,
        MaskList::Exception => 1,
        MaskList::InviteException => 2,
    }
}

fn require_role(actual: Role, required: Role) -> Result<(), DomainError> {
    if actual < required {
        return Err(DomainError::Forbidden);
    }
    Ok(())
}

fn validate_secret_visibility(
    actor_role: Role,
    actor_account: Option<AccountId>,
) -> Result<(), DomainError> {
    if actor_account.is_none() {
        return Err(DomainError::RegistrationRequired);
    }
    require_role(actor_role, Role::Owner)
}

#[cfg(test)]
fn validate_mode_change(
    state: &DomainState,
    channel: &crate::ChannelState,
    actor_role: Role,
    actor_account: Option<AccountId>,
    change: &ModeChange,
) -> Result<(), DomainError> {
    let mut validation = ModeValidationState::new(channel, 1)?;
    let entry_id =
        matches!(change, ModeChange::AddMask { .. }).then_some(EntryId::from_bytes([0_u8; 16]));
    validation.validate_and_apply(state, channel, actor_role, actor_account, change, entry_id)?;
    validation.validate_final(channel)
}

#[cfg(test)]
fn validate_role_change(
    state: &DomainState,
    channel: &crate::ChannelState,
    actor_role: Role,
    operation: ModeOperation,
    target: &NicknameValue,
    role: Role,
) -> Result<(), DomainError> {
    validate_mode_authority(
        actor_role,
        None,
        &ModeChange::Role {
            operation,
            target: target.clone(),
            role,
        },
    )?;
    let (_, current, _) = resolve_mode_role_subject(state, channel, target)?;
    resulting_role(current, operation, role).map(|_| ())
}

#[cfg(test)]
fn validate_role_vector_final(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<(), DomainError> {
    let mut validation = ModeValidationState::new(channel, changes.len())?;
    for change in changes {
        let ModeChange::Role {
            operation,
            target,
            role,
        } = change
        else {
            continue;
        };
        validation.apply_role_change(state, channel, *operation, target, *role)?;
    }
    validation.validate_final(channel)
}

#[cfg(test)]
fn validate_role_grant_capacity(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<(), DomainError> {
    validate_role_vector_final(state, channel, changes)
}

#[cfg(test)]
fn validate_owner_continuity(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<(), DomainError> {
    validate_role_vector_final(state, channel, changes)
}

fn mode_events(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<Vec<DomainEvent>, DomainError> {
    let mut events = vec![DomainEvent::ChannelModesChanged(channel.channel_id)];
    for change in changes {
        let ModeChange::Role { target, .. } = change else {
            continue;
        };
        let Some(user_id) = state.nicknames.get(target) else {
            return Err(DomainError::NotFound);
        };
        let Some(account_id) = state
            .sessions
            .get(user_id)
            .and_then(|session| session.account_id)
        else {
            continue;
        };
        if channel.persistence == PersistencePolicy::Registered
            && !events.iter().any(|event| {
                *event == DomainEvent::ChannelMembershipsRecomputed(channel.channel_id, account_id)
            })
        {
            events.push(DomainEvent::ChannelMembershipsRecomputed(
                channel.channel_id,
                account_id,
            ));
        }
    }
    Ok(events)
}

fn apply_role_change(
    nicknames: &BTreeMap<NicknameValue, UserId>,
    channel: &mut crate::ChannelState,
    operation: ModeOperation,
    target: &NicknameValue,
    role: Role,
) {
    let Some(user_id) = nicknames.get(target).copied() else {
        return;
    };
    let Some(membership) = channel.memberships.get(&user_id) else {
        return;
    };
    let account_id = membership.account_id;
    if channel.persistence != PersistencePolicy::Registered || account_id.is_none() {
        let current = membership.effective_role;
        let Ok(next) = resulting_role(current, operation, role) else {
            return;
        };
        let Some(membership) = channel.memberships.get_mut(&user_id) else {
            return;
        };
        membership.session_role = next;
        membership.effective_role = next;
        return;
    }
    let Some(account_id) = account_id else {
        return;
    };
    let current = channel
        .role_grants
        .get(&account_id)
        .copied()
        .unwrap_or(Role::Member);
    let Ok(next) = resulting_role(current, operation, role) else {
        return;
    };
    if next == Role::Member {
        channel.role_grants.remove(&account_id);
    } else {
        channel.role_grants.insert(account_id, next);
    }
    for current in channel.memberships.values_mut() {
        if current.account_id == Some(account_id) {
            current.session_role = Role::Member;
            current.effective_role = next;
        }
    }
}

fn effective_mask(channel: &crate::ChannelState, session: &SessionState, quiet: bool) -> bool {
    let strongest_ban = channel
        .bans
        .iter()
        .filter(|entry| entry.mask.is_quiet() == quiet)
        .filter_map(|entry| mask_strength(&entry.mask, session))
        .max();
    let strongest_exception = channel
        .exceptions
        .iter()
        .filter_map(|entry| mask_strength(&entry.mask, session))
        .max();
    strongest_ban.is_some_and(|ban| strongest_exception.is_none_or(|exception| exception < ban))
}

fn matches_mask_list(entries: &[crate::ListEntry], session: &SessionState) -> bool {
    entries
        .iter()
        .any(|entry| mask_strength(&entry.mask, session).is_some())
}

fn mask_strength(mask: &TypedMask, session: &SessionState) -> Option<u8> {
    match mask.subject() {
        MaskSubject::Account(account) => {
            (session.account_id.map(AccountId::random) == Some(*account)).then_some(4)
        }
        MaskSubject::User(user_id) => (session.user_id == *user_id).then_some(3),
        MaskSubject::Nickname(glob) => glob.is_match(session.nickname.canonical()).then_some(2),
        MaskSubject::Cloak(glob) => {
            let mut rendered = [0_u8; 26];
            rendered[..2].copy_from_slice(b"h-");
            rendered[2..18].copy_from_slice(session.public_cloak.host_component());
            rendered[18..].copy_from_slice(b".invalid");
            std::str::from_utf8(&rendered)
                .is_ok_and(|cloak| glob.is_match(cloak))
                .then_some(1)
        }
    }
}

fn mask_list(channel: &crate::ChannelState, list: MaskList) -> &[crate::ListEntry] {
    match list {
        MaskList::Ban => &channel.bans,
        MaskList::Exception => &channel.exceptions,
        MaskList::InviteException => &channel.invite_exceptions,
    }
}

fn mask_list_mut(channel: &mut crate::ChannelState, list: MaskList) -> &mut Vec<crate::ListEntry> {
    match list {
        MaskList::Ban => &mut channel.bans,
        MaskList::Exception => &mut channel.exceptions,
        MaskList::InviteException => &mut channel.invite_exceptions,
    }
}

fn account_setting(
    state: &DomainState,
    account_id: AccountId,
    command: AccountCommand,
) -> Result<AccountSetting, DomainError> {
    let account = state
        .accounts
        .get(&account_id)
        .ok_or(DomainError::NotFound)?;
    match command {
        AccountCommand::Label(label) => Ok(AccountSetting::Label(label)),
        AccountCommand::Presence(policy) => Ok(AccountSetting::Presence(policy)),
        AccountCommand::GuestDirectMessages(policy) => {
            Ok(AccountSetting::GuestDirectMessages(policy))
        }
        AccountCommand::DirectMessages(policy) => Ok(AccountSetting::DirectMessages(policy)),
        AccountCommand::ContactAdd(contact) => {
            if account.contacts.len() >= state.operational_limits.contacts_per_account()
                || contact == account_id
            {
                return Err(DomainError::LimitExceeded);
            }
            Ok(AccountSetting::ContactAdd(contact))
        }
        AccountCommand::ContactRemove(contact) => Ok(AccountSetting::ContactRemove(contact)),
        AccountCommand::NickReserve(nickname) => {
            if account.reserved_nicknames.contains(&nickname) {
                return Err(DomainError::BadState);
            }
            if account.reserved_nicknames.len() >= crate::model::MAX_RESERVED_NICKNAMES {
                return Err(DomainError::LimitExceeded);
            }
            if state.accounts.iter().any(|(other_id, other)| {
                *other_id != account_id && other.reserved_nicknames.contains(&nickname)
            }) {
                return Err(DomainError::BadState);
            }
            if state.nicknames.get(&nickname).is_some_and(|user_id| {
                state
                    .sessions
                    .get(user_id)
                    .is_none_or(|session| session.account_id != Some(account_id))
            }) {
                return Err(DomainError::BadState);
            }
            Ok(AccountSetting::NickReserve(nickname))
        }
        AccountCommand::NickRelease(nickname) => Ok(AccountSetting::NickRelease(nickname)),
        AccountCommand::DeleteStart | AccountCommand::DeleteConfirm(_) => {
            Err(DomainError::BadState)
        }
    }
}

fn channel_command_id(command: ChannelCommand) -> ChannelInstanceId {
    match command {
        ChannelCommand::Register(channel_id)
        | ChannelCommand::Unregister(channel_id)
        | ChannelCommand::History(channel_id, _)
        | ChannelCommand::HistoryDefault(channel_id) => channel_id,
    }
}

fn validate_channel_setting(
    state: &DomainState,
    user_id: UserId,
    account_id: AccountId,
    command: ChannelCommand,
) -> Result<(), DomainError> {
    let channel_id = channel_command_id(command);
    let channel = state
        .channels
        .get(&channel_id)
        .ok_or(DomainError::NotFound)?;
    if channel.role_of(user_id) != Some(Role::Owner) {
        return Err(DomainError::Forbidden);
    }
    match command {
        ChannelCommand::Register(_) => {
            if channel.persistence != PersistencePolicy::Ephemeral
                || channel.creator != Principal::Account(account_id)
            {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::Unregister(_) => {
            if channel.persistence != PersistencePolicy::Registered
                || channel.content_policy == ContentPolicy::E2eeBound
            {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::History(_, history) => {
            if !history_setting_is_allowed(channel, history) {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::HistoryDefault(_) => return Err(DomainError::BadState),
    }
    Ok(())
}

fn history_setting_is_allowed(channel: &crate::ChannelState, history: HistoryPolicy) -> bool {
    history == HistoryPolicy::Off
        || (channel.visibility == Visibility::Listed
            && channel.persistence == PersistencePolicy::Registered
            && channel.content_policy == ContentPolicy::Plaintext
            && channel.scope == crate::ChannelScope::Global)
}

fn channel_accepts_e2ee_binding(channel: &crate::ChannelState) -> bool {
    channel.scope == crate::ChannelScope::Global
        && channel.persistence == PersistencePolicy::Registered
        && channel.content_policy == ContentPolicy::Plaintext
        && channel.history == HistoryPolicy::Off
        && channel.topic.is_none()
        && channel.e2ee_removal_pending.is_empty()
}

fn canonical_account_roster(
    channel: &crate::ChannelState,
) -> Result<Vec<(UserId, AccountId)>, DomainError> {
    let mut roster = Vec::new();
    roster
        .try_reserve_exact(channel.memberships.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    for membership in channel.memberships.values() {
        let account_id = membership.account_id.ok_or(DomainError::BadState)?;
        roster.push((membership.user_id, account_id));
    }
    roster.sort_unstable_by_key(|(user_id, _)| *user_id);
    Ok(roster)
}

fn authorize_sanction(
    state: &DomainState,
    actor: &SessionState,
    target: Principal,
    channel_id: Option<ChannelInstanceId>,
    action: ModerationAction,
    permanent: bool,
) -> Result<(), DomainError> {
    let Some(channel_id) = channel_id else {
        return Err(DomainError::Forbidden);
    };
    if action == ModerationAction::Suspend {
        return Err(DomainError::Forbidden);
    }
    let channel = state
        .channels
        .get(&channel_id)
        .ok_or(DomainError::NotFound)?;
    let role = channel
        .role_of(actor.user_id)
        .ok_or(DomainError::Forbidden)?;
    let required = match action {
        ModerationAction::Mute | ModerationAction::Ban => Role::Operator,
        ModerationAction::Kick => Role::HalfOperator,
        ModerationAction::Suspend => Role::Owner,
    };
    if role < required {
        return Err(DomainError::Forbidden);
    }
    if permanent && role < Role::Owner {
        return Err(DomainError::Forbidden);
    }
    if action == ModerationAction::Kick {
        let target_role = channel
            .memberships
            .values()
            .filter(|membership| match target {
                Principal::Guest(user_id) => membership.user_id == user_id,
                Principal::Account(account_id) => membership.account_id == Some(account_id),
            })
            .map(|membership| membership.effective_role)
            .max()
            .ok_or(DomainError::NotFound)?;
        if target_role >= role {
            return Err(DomainError::Forbidden);
        }
    }
    Ok(())
}

#[cfg(test)]
mod projection_tests {
    use agenc_ircd_types::{MonotonicTick, Revision, UserId};

    use super::{MonitorChange, Mutation, StorageClass};
    use crate::{AccountState, DomainError, DomainState};

    fn revision(value: u64) -> Result<Revision, DomainError> {
        Ok(Revision::new(value)?)
    }

    #[test]
    fn process_local_arms_project_to_no_write() -> Result<(), DomainError> {
        let state = DomainState::new()?;
        let user_id = UserId::from_bytes([1; 16]);
        let mutations = [
            Mutation::SetMonitor {
                user_id,
                change: MonitorChange::Clear,
            },
            Mutation::SetFreshAuthDeadline {
                user_id,
                deadline: MonotonicTick::from_ticks(1),
            },
            Mutation::ConsumeAccountDeletionChallenge(agenc_ircd_types::SessionId::from_bytes(
                [2; 16],
            )),
            Mutation::EventOnly,
        ];
        for mutation in &mutations {
            assert!(matches!(
                mutation.duplicate_for_projection()?,
                Mutation::EventOnly
            ));
        }
        assert!(
            state
                .durable_writes_for(&mutations, revision(1)?, StorageClass::Ephemeral)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn a_persisted_change_under_an_ephemeral_label_is_an_invariant_violation()
    -> Result<(), DomainError> {
        let state = DomainState::new()?;
        let account = AccountState::new(
            crate::model::tests_support_account_id(3),
            agenc_ircd_types::Generation::new(1)?,
            revision(0)?,
        );
        let mutations = [Mutation::InsertAccount(account)];
        assert_eq!(
            state.durable_writes_for(&mutations, revision(1)?, StorageClass::Ephemeral),
            Err(DomainError::InvariantViolation)
        );
        assert_eq!(
            state
                .durable_writes_for(&mutations, revision(1)?, StorageClass::Durable)?
                .len(),
            1
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        MAX_CONTACTS_PER_ACCOUNT, MAX_INVITES_PER_CHANNEL, MAX_INVITES_PER_PRINCIPAL, next_revision,
    };
    use crate::{MessageCommand, MessageText};
    use agenc_ircd_types::{AccountRandomId, ControlPolicy, ServerId, SessionId};

    struct Fixture {
        state: DomainState,
        owner: SessionState,
        member: SessionState,
        outsider: SessionState,
        owner_account: AccountId,
        member_account: AccountId,
        channel_id: ChannelInstanceId,
        name: ChannelNameValue,
    }

    fn bytes(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn account_id(seed: u8) -> AccountId {
        AccountId::from_random(AccountRandomId::from_bytes(bytes(seed)))
    }

    fn session(seed: u8, account_id: Option<AccountId>) -> Result<SessionState, DomainError> {
        Ok(SessionState::from_seed(session_seed(
            seed,
            account_id,
            u64::from(account_id.is_some()),
        )?))
    }

    fn session_seed(
        seed: u8,
        account_id: Option<AccountId>,
        account_generation: u64,
    ) -> Result<SessionSeed, DomainError> {
        Ok(SessionSeed {
            session_id: SessionId::from_bytes(bytes(seed)),
            user_id: UserId::from_bytes(bytes(seed.wrapping_add(64))),
            home_server_id: ServerId::from_bytes(bytes(240)),
            account_id,
            account_session_generation: agenc_ircd_types::Generation::new(account_generation)?,
            generation: agenc_ircd_types::Generation::new(1)?,
            nickname: NicknameValue::parse(&format!("test{seed}"))?,
            display_name: DisplayNameValue::prepare(&format!("Test {seed}"))?,
            public_cloak: crate::model::test_public_cloak(seed)?,
            connection_nonce: [seed; 32],
            negotiated_capability_hash: [seed.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: Revision::new(1)?,
        })
    }

    /// Replaces the fixture's channels with `count` listed channels, each
    /// created by its own guest, and returns their names in creation order.
    fn listed_channels(f: &mut Fixture, count: u32) -> Result<Vec<ChannelNameValue>, DomainError> {
        f.state.channels.clear();
        f.state.channel_names.clear();
        let mut names = Vec::new();
        for n in 1..=count {
            let mut raw = [0_u8; 16];
            raw.get_mut(12..)
                .ok_or(DomainError::InvariantViolation)?
                .copy_from_slice(&n.to_be_bytes());
            let id = ChannelInstanceId::from_bytes(raw);
            let name = ChannelNameValue::parse(&format!("#list-{n}"))?;
            // Seeds wrap past 240 creators; a repeated creator only replaces
            // its earlier session, which these scans never depend on.
            let seed = u8::try_from(
                n.checked_rem(240)
                    .ok_or(DomainError::Overflow)?
                    .saturating_add(10),
            )
            .map_err(|_| DomainError::Overflow)?;
            let mut creator = session(seed, None)?;
            creator.joined_channels.insert(id);
            let channel = crate::ChannelState::new_ephemeral(
                id,
                name.clone(),
                creator.principal(),
                Membership::new(creator.user_id, None, Role::Owner),
                UtcSecond::from_unix_seconds(10),
                Revision::new(1)?,
            );
            f.state.apply_session(creator, Revision::new(1)?);
            f.state.channel_names.insert(name.clone(), id);
            f.state.channels.insert(id, channel);
            names.push(name);
        }
        Ok(names)
    }

    fn expensive_query_tokens(f: &Fixture, command: &CanonicalCommand) -> u64 {
        f.state
            .assess_charges(f.owner.user_id, command)
            .iter()
            .filter(|charge| charge.bucket() == RateBucket::ExpensiveQuery(f.owner.user_id))
            .map(|charge| charge.tokens())
            .sum()
    }

    #[test]
    fn list_selection_resolves_a_late_listed_channel_before_the_result_ceiling()
    -> Result<(), DomainError> {
        let mut f = fixture()?;
        let names = listed_channels(&mut f, 201)?;
        let first = names
            .first()
            .cloned()
            .ok_or(DomainError::InvariantViolation)?;
        let last = names
            .last()
            .cloned()
            .ok_or(DomainError::InvariantViolation)?;
        // The unselected page holds the first 200 channels and not the last.
        let page = f.state.select_channel_list(&[])?;
        assert_eq!(page.rows().len(), 200);
        assert_eq!(page.scanned_records(), 200);
        assert_eq!(
            page.rows().iter().filter(|row| row.name() == &last).count(),
            0
        );
        assert_eq!(f.state.project_channel_list()?.len(), 200);
        // An explicit name resolves wherever the channel sorts.
        let selected = f.state.select_channel_list(std::slice::from_ref(&last))?;
        assert_eq!(selected.rows().len(), 1);
        assert!(selected.rows().first().map(|row| row.name()) == Some(&last));
        assert_eq!(selected.scanned_records(), 1);
        let both = f
            .state
            .select_channel_list(&[first.clone(), last.clone()])?;
        assert_eq!(both.rows().len(), 2);
        assert_eq!(both.scanned_records(), 2);
        // Exactly 199 and 200 channels fill the page without truncation.
        for count in [199_u32, 200] {
            let names = listed_channels(&mut f, count)?;
            let page = f.state.select_channel_list(&[])?;
            assert_eq!(
                page.rows().len(),
                usize::try_from(count).map_err(|_| DomainError::Overflow)?
            );
            let last = names.last().ok_or(DomainError::InvariantViolation)?;
            assert!(page.rows().iter().any(|row| row.name() == last));
        }
        Ok(())
    }

    #[test]
    fn list_selection_hides_secret_unlisted_and_absent_names_identically() -> Result<(), DomainError>
    {
        let mut f = fixture()?;
        let names = listed_channels(&mut f, 3)?;
        let [listed, unlisted, secret] = names.as_slice() else {
            return Err(DomainError::InvariantViolation);
        };
        for (name, visibility) in [
            (unlisted, Visibility::Unlisted),
            (secret, Visibility::Secret),
        ] {
            let id = *f
                .state
                .channel_names
                .get(name)
                .ok_or(DomainError::InvariantViolation)?;
            f.state
                .channels
                .get_mut(&id)
                .ok_or(DomainError::InvariantViolation)?
                .visibility = visibility;
        }
        let absent = ChannelNameValue::parse("#list-absent")?;
        let mixed = f.state.select_channel_list(&[
            absent.clone(),
            secret.clone(),
            unlisted.clone(),
            listed.clone(),
        ])?;
        assert_eq!(mixed.rows().len(), 1);
        assert!(mixed.rows().first().map(|row| row.name()) == Some(listed));
        assert_eq!(mixed.scanned_records(), 4);
        // Hidden and absent selections are indistinguishable: empty results
        // with the same scan count and no row shape.
        let hidden = f.state.select_channel_list(std::slice::from_ref(secret))?;
        let missing = f.state.select_channel_list(std::slice::from_ref(&absent))?;
        assert!(hidden.rows().is_empty() && missing.rows().is_empty());
        assert_eq!(hidden.scanned_records(), missing.scanned_records());
        // The unselected scan examines hidden records but never returns them.
        let page = f.state.select_channel_list(&[])?;
        assert_eq!(page.rows().len(), 1);
        assert_eq!(page.scanned_records(), 3);
        // Duplicate names never reach selection and a canonical form is one name.
        assert_eq!(
            CanonicalCommand::list(vec![listed.clone(), listed.clone()]).err(),
            Some(DomainError::DuplicateTarget)
        );
        let upper = ChannelNameValue::parse("#LIST-1")?;
        assert_eq!(
            CanonicalCommand::list(vec![listed.clone(), upper]).err(),
            Some(DomainError::DuplicateTarget)
        );
        Ok(())
    }

    #[test]
    fn list_scan_tokens_charge_one_per_twenty_examined_records_before_the_scan()
    -> Result<(), DomainError> {
        let mut f = fixture()?;
        for (count, expected) in [
            (0_u32, 1_u64),
            (1, 1),
            (19, 1),
            (20, 1),
            (21, 2),
            (40, 2),
            (41, 3),
            (200, 10),
            (201, 10),
            (250, 10),
        ] {
            let names = listed_channels(&mut f, count)?;
            let unselected = CanonicalCommand::list(Vec::new())?;
            assert_eq!(
                f.state.list_scan_bound(&[]),
                usize::try_from(count.min(200)).map_err(|_| DomainError::Overflow)?
            );
            assert_eq!(
                expensive_query_tokens(&f, &unselected),
                expected,
                "{count} channels"
            );
            // The scan never examines more records than it was charged for.
            let scanned = f.state.select_channel_list(&[])?.scanned_records();
            assert!(scanned <= f.state.list_scan_bound(&[]));
            assert!(
                u64::try_from(scanned.div_ceil(20).max(1)).map_err(|_| DomainError::Overflow)?
                    <= expected
            );
            if let Some(last) = names.last() {
                let named = CanonicalCommand::list(vec![last.clone()])?;
                assert_eq!(
                    expensive_query_tokens(&f, &named),
                    1,
                    "{count} channels, one name"
                );
            }
        }
        // Twenty explicit names are one token; every other expensive query
        // keeps its single token.
        let names = listed_channels(&mut f, 20)?;
        assert_eq!(
            expensive_query_tokens(&f, &CanonicalCommand::list(names)?),
            1
        );
        assert_eq!(
            expensive_query_tokens(&f, &CanonicalCommand::names(Vec::new())?),
            1
        );
        Ok(())
    }

    fn fixture() -> Result<Fixture, DomainError> {
        let owner_account = account_id(1);
        let member_account = account_id(2);
        let owner = session(1, Some(owner_account))?;
        let member = session(2, Some(member_account))?;
        let outsider = session(3, None)?;
        let channel_id = ChannelInstanceId::from_bytes(bytes(20));
        let name = ChannelNameValue::parse("#test")?;
        let mut state = DomainState::at_revision(Revision::new(1)?);
        state.apply_account(
            AccountState::new(
                owner_account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(1)?,
            ),
            Revision::new(1)?,
        );
        state.apply_account(
            AccountState::new(
                member_account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(1)?,
            ),
            Revision::new(1)?,
        );
        state.apply_session(session(1, Some(owner_account))?, Revision::new(1)?);
        state.apply_session(session(2, Some(member_account))?, Revision::new(1)?);
        state.apply_session(session(3, None)?, Revision::new(1)?);
        let channel = crate::ChannelState::new_ephemeral(
            channel_id,
            name.clone(),
            Principal::Account(owner_account),
            Membership::new(owner.user_id, Some(owner_account), Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        );
        state.apply_join_new(channel, Revision::new(1)?);
        state.apply_join_existing(
            channel_id,
            Membership::new(member.user_id, Some(member_account), Role::Member),
            None,
            Revision::new(1)?,
        );
        Ok(Fixture {
            state,
            owner,
            member,
            outsider,
            owner_account,
            member_account,
            channel_id,
            name,
        })
    }

    fn admission(user_id: UserId) -> Result<AdmissionSnapshot, DomainError> {
        AdmissionSnapshot::new(vec![(RateBucket::RegisteredCommand(user_id), 10)])
    }

    /// RUN-01 (#44): a full hidden channel still hides its existence from a
    /// guest and from an authenticated non-member at, below and above a
    /// lowered operational member ceiling, while a listed channel keeps its
    /// capacity outcome for the same requester.
    #[test]
    fn hidden_full_channel_still_hides_existence() -> Result<(), DomainError> {
        for visibility in [Visibility::Secret, Visibility::Unlisted] {
            for ceiling in [1_usize, 2, 3] {
                let mut f = fixture()?;
                let stranger_account = account_id(3);
                f.state.apply_account(
                    AccountState::new(
                        stranger_account,
                        agenc_ircd_types::Generation::new(1)?,
                        Revision::new(1)?,
                    ),
                    Revision::new(1)?,
                );
                let stranger = session(4, Some(stranger_account))?;
                f.state
                    .apply_session(session(4, Some(stranger_account))?, Revision::new(1)?);
                let mut limits = crate::OperationalLimits::HARD_MAX.values();
                limits.members_per_channel = ceiling;
                f.state
                    .set_operational_limits(crate::OperationalLimits::new(limits)?);
                f.state
                    .channels
                    .get_mut(&f.channel_id)
                    .ok_or(DomainError::InvariantViolation)?
                    .visibility = visibility;
                for (user_id, principal) in [
                    (f.outsider.user_id, f.outsider.principal()),
                    (stranger.user_id, stranger.principal()),
                ] {
                    let result = f.state.check_join_existing(
                        user_id,
                        principal,
                        f.state
                            .channel(f.channel_id)
                            .ok_or(DomainError::InvariantViolation)?,
                        false,
                        false,
                        None,
                    );
                    assert_eq!(
                        result,
                        Err(DomainError::SecretUnavailable),
                        "{visibility:?} at ceiling {ceiling}"
                    );
                }
                // The same population on a listed channel reports capacity to
                // the authenticated non-member exactly when it is full.
                f.state
                    .channels
                    .get_mut(&f.channel_id)
                    .ok_or(DomainError::InvariantViolation)?
                    .visibility = Visibility::Listed;
                let listed = f.state.check_join_existing(
                    stranger.user_id,
                    stranger.principal(),
                    f.state
                        .channel(f.channel_id)
                        .ok_or(DomainError::InvariantViolation)?,
                    false,
                    false,
                    None,
                );
                if ceiling <= 2 {
                    assert_eq!(listed, Err(DomainError::LimitExceeded), "ceiling {ceiling}");
                } else {
                    assert_eq!(listed, Ok(None), "ceiling {ceiling}");
                }
            }
        }
        Ok(())
    }

    fn complete_external_inputs() -> ExternalInputs {
        ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(1)),
            monotonic_now: Some(MonotonicTick::from_ticks(1)),
            channel_ids: vec![ChannelInstanceId::from_bytes(bytes(1))],
            message_ids: vec![MessageId::from_bytes(bytes(2))],
            invite_ids: vec![InviteId::from_bytes(bytes(3))],
            entry_ids: vec![EntryId::from_bytes(bytes(4))],
            deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(5))],
            key_verdicts: vec![true],
            key_verifiers: vec![crate::ChannelKeyVerifier::new(bytes(6), [7; 32])],
            wall_clock_unavailable: false,
        }
    }

    fn envelope(
        session: &SessionState,
        revision: Revision,
        command: CanonicalCommand,
    ) -> CommandEnvelope {
        CommandEnvelope::new(
            session.session_id,
            session.user_id,
            session.generation,
            revision,
            command,
        )
    }

    fn rejected_message_error(
        state: &DomainState,
        session: &SessionState,
        command: CanonicalCommand,
        credit: &AdmissionSnapshot,
    ) -> Result<DomainError, DomainError> {
        let authorized = state
            .authorize(envelope(session, state.revision, command), credit)
            .map_err(|failure| failure.error())?;
        let PlanDecision::Rejected(rejected) = state.plan_authorized(authorized, None)? else {
            return Err(DomainError::InvariantViolation);
        };
        rejected
            .failures()
            .first()
            .map(TargetFailure::error)
            .ok_or(DomainError::InvariantViolation)
    }

    fn account_command_plan(
        state: &DomainState,
        session: &SessionState,
        command: AccountCommand,
        external: Option<ExternalInputs>,
    ) -> Result<PlanDecision, DomainError> {
        let authorized = state
            .authorize(
                envelope(session, state.revision, CanonicalCommand::account(command)),
                &admission(session.user_id)?,
            )
            .map_err(|failure| failure.error())?;
        state.plan_authorized(authorized, external)
    }

    #[test]
    fn admission_and_authorization_reject_each_fence_and_role_failure() -> Result<(), DomainError> {
        assert_eq!(
            RateCharge::new(
                RateBucket::RegisteredCommand(UserId::from_bytes(bytes(1))),
                0
            ),
            Err(DomainError::InvalidArgument)
        );
        assert!(
            RateCharge::new(
                RateBucket::RegisteredCommand(UserId::from_bytes(bytes(1))),
                1,
            )
            .is_ok()
        );
        assert_eq!(
            AdmissionSnapshot::new(vec![
                (
                    RateBucket::RegisteredCommand(UserId::from_bytes(bytes(1))),
                    1
                ),
                (
                    RateBucket::RegisteredCommand(UserId::from_bytes(bytes(1))),
                    2
                ),
            ])
            .err(),
            Some(DomainError::InvalidArgument)
        );

        let mut fixture = fixture()?;
        let state = &mut fixture.state;
        let stale = CommandEnvelope::new(
            fixture.owner.session_id,
            fixture.owner.user_id,
            fixture.owner.generation,
            Revision::new(0)?,
            CanonicalCommand::list(Vec::new())?,
        );
        assert_eq!(
            state
                .authorize(stale, &admission(fixture.owner.user_id)?)
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::StaleRevision)
        );
        let unknown = session(9, None)?;
        assert_eq!(
            state
                .authorize(
                    envelope(
                        &unknown,
                        state.revision,
                        CanonicalCommand::list(Vec::new())?,
                    ),
                    &admission(unknown.user_id)?,
                )
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::NotFound)
        );
        let wrong_session = CommandEnvelope::new(
            SessionId::from_bytes(bytes(99)),
            fixture.owner.user_id,
            fixture.owner.generation,
            state.revision,
            CanonicalCommand::list(Vec::new())?,
        );
        assert_eq!(
            state
                .authorize(wrong_session, &admission(fixture.owner.user_id)?)
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::StaleGeneration)
        );
        let no_credit = AdmissionSnapshot::new(Vec::new())?;
        assert_eq!(
            state
                .authorize(
                    envelope(
                        &fixture.owner,
                        state.revision,
                        CanonicalCommand::list(Vec::new())?,
                    ),
                    &no_credit,
                )
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::ServerBusy)
        );

        let missing = ChannelNameValue::parse("#missing")?;
        for command in [
            CanonicalCommand::mode(missing.clone(), vec![ModeChange::Moderated(true)])?,
            CanonicalCommand::topic_set(
                missing.clone(),
                TopicText::try_from_str("topic", ControlPolicy::RejectAll)?,
            ),
            CanonicalCommand::invite(fixture.member.nickname.clone(), missing.clone()),
            CanonicalCommand::kick(missing, vec![fixture.member.nickname.clone()], None)?,
        ] {
            assert_eq!(
                state
                    .authorize(
                        envelope(&fixture.owner, state.revision, command),
                        &admission(fixture.owner.user_id)?,
                    )
                    .err()
                    .map(|failure| failure.error()),
                Some(DomainError::SecretUnavailable)
            );
        }
        assert_eq!(
            state
                .authorize(
                    envelope(
                        &fixture.member,
                        state.revision,
                        CanonicalCommand::mode(
                            fixture.name.clone(),
                            vec![ModeChange::Moderated(true)],
                        )?,
                    ),
                    &admission(fixture.member.user_id)?,
                )
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::Forbidden)
        );
        assert_eq!(
            state
                .authorize(
                    envelope(
                        &fixture.outsider,
                        state.revision,
                        CanonicalCommand::topic_set(
                            fixture.name.clone(),
                            TopicText::try_from_str("topic", ControlPolicy::RejectAll)?,
                        ),
                    ),
                    &admission(fixture.outsider.user_id)?,
                )
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::Forbidden)
        );
        Ok(())
    }

    #[test]
    fn message_kick_history_and_join_policy_errors_are_closed() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let state = &mut fixture.state;
        let missing_name = ChannelNameValue::parse("#missing")?;
        let missing_message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(missing_name)],
            Some(MessageText::parse("x")?),
        )?;
        let message_credit = AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(fixture.owner.user_id), 10),
            (RateBucket::AccountMessage(fixture.owner_account), 10),
            (RateBucket::ChannelMessage(fixture.channel_id), 10),
        ])?;
        assert_eq!(
            rejected_message_error(
                state,
                &fixture.owner,
                CanonicalCommand::message(missing_message),
                &message_credit,
            )?,
            DomainError::SecretUnavailable
        );
        let outsider_message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(fixture.name.clone())],
            Some(MessageText::parse("x")?),
        )?;
        let outsider_credit = AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(fixture.outsider.user_id), 10),
            (RateBucket::GuestMessage(fixture.outsider.user_id), 10),
            (RateBucket::ChannelMessage(fixture.channel_id), 10),
        ])?;
        assert_eq!(
            rejected_message_error(
                state,
                &fixture.outsider,
                CanonicalCommand::message(outsider_message),
                &outsider_credit,
            )?,
            DomainError::Forbidden
        );

        let channel = state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.modes.moderated = true;
        let member_message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(fixture.name.clone())],
            Some(MessageText::parse("x")?),
        )?;
        let member_credit = AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(fixture.member.user_id), 10),
            (RateBucket::AccountMessage(fixture.member_account), 10),
            (RateBucket::ChannelMessage(fixture.channel_id), 10),
        ])?;
        assert_eq!(
            rejected_message_error(
                state,
                &fixture.member,
                CanonicalCommand::message(member_message),
                &member_credit,
            )?,
            DomainError::Forbidden
        );
        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .content_policy = ContentPolicy::E2eeBound;
        for kind in [MessageKind::Privmsg, MessageKind::Notice] {
            let body = (kind == MessageKind::Privmsg)
                .then(|| MessageText::parse("x"))
                .transpose()?;
            let command = CanonicalCommand::message(MessageCommand::new(
                kind,
                vec![MessageTarget::Channel(fixture.name.clone())],
                body,
            )?);
            assert_eq!(
                rejected_message_error(state, &fixture.owner, command, &message_credit)?,
                DomainError::EncryptedRoute
            );
        }

        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .content_policy = ContentPolicy::Plaintext;
        assert_eq!(state.authorize_kick(&fixture.owner, &fixture.name), Ok(()));
        assert_eq!(
            state.authorize_kick(&fixture.outsider, &fixture.name),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            state.authorize_kick(&fixture.member, &fixture.name),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            state.authorize_history(&fixture.member, ChannelInstanceId::from_bytes(bytes(99))),
            Err(DomainError::NotFound)
        );
        assert_eq!(
            state.authorize_history(&fixture.outsider, fixture.channel_id),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            state.authorize_history(&fixture.member, fixture.channel_id),
            Err(DomainError::BadState)
        );

        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .modes
            .join_key = true;
        let channel = state
            .channels
            .get(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(
            state.check_join_existing(
                fixture.member.user_id,
                Principal::Account(fixture.member_account),
                channel,
                true,
                true,
                None,
            ),
            Err(DomainError::BadState)
        );
        assert_eq!(
            state.check_join_existing(
                fixture.outsider.user_id,
                Principal::Guest(fixture.outsider.user_id),
                channel,
                false,
                false,
                None,
            ),
            Err(DomainError::SecretUnavailable)
        );
        let channel = state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.modes.join_key = false;
        channel.member_limit = Some(2);
        assert_eq!(
            state.check_join_existing(
                fixture.outsider.user_id,
                Principal::Guest(fixture.outsider.user_id),
                state
                    .channels
                    .get(&fixture.channel_id)
                    .ok_or(DomainError::InvariantViolation)?,
                false,
                true,
                None,
            ),
            Err(DomainError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn committed_admin_policy_suspends_accounts_and_quarantines_delivery() -> Result<(), DomainError>
    {
        let mut fixture = fixture()?;
        let initial_state_revision = fixture.state.revision();
        let expires_at = UtcSecond::from_unix_seconds(100);
        fixture
            .state
            .admin_suspend_account(fixture.owner_account, expires_at)?;
        assert_eq!(
            fixture.state.revision(),
            next_revision(initial_state_revision)?
        );
        assert_eq!(
            fixture
                .state
                .account(fixture.owner_account)
                .ok_or(DomainError::NotFound)?
                .revision(),
            next_revision(initial_state_revision)?
        );
        assert!(
            fixture
                .state
                .account_is_suspended(fixture.owner_account, UtcSecond::from_unix_seconds(99))
        );
        assert!(
            !fixture
                .state
                .account_is_suspended(fixture.owner_account, expires_at)
        );
        assert_eq!(
            fixture.state.users_for_account(fixture.owner_account),
            vec![fixture.owner.user_id]
        );
        fixture.state.admin_restore_account(fixture.owner_account)?;
        assert_eq!(
            fixture.state.revision(),
            next_revision(next_revision(initial_state_revision)?)?
        );
        assert_eq!(
            fixture
                .state
                .account(fixture.owner_account)
                .ok_or(DomainError::NotFound)?
                .revision(),
            next_revision(next_revision(initial_state_revision)?)?
        );
        assert!(
            !fixture
                .state
                .account_has_admin_suspension(fixture.owner_account)
        );

        assert_eq!(
            fixture.state.admin_quarantine_channel(fixture.channel_id),
            Err(DomainError::NotFound)
        );
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::NotFound)?;
        register_channel_roles(channel);
        fixture.state.admin_quarantine_channel(fixture.channel_id)?;
        let message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::Channel(fixture.name.clone())],
            Some(MessageText::parse("x")?),
        )?;
        let credit = AdmissionSnapshot::new(vec![
            (RateBucket::RegisteredCommand(fixture.owner.user_id), 10),
            (RateBucket::AccountMessage(fixture.owner_account), 10),
            (RateBucket::ChannelMessage(fixture.channel_id), 10),
        ])?;
        assert_eq!(
            rejected_message_error(
                &fixture.state,
                &fixture.owner,
                CanonicalCommand::message(message),
                &credit,
            )?,
            DomainError::Forbidden
        );
        Ok(())
    }

    #[test]
    fn external_input_validation_covers_every_shape_and_clock_combination()
    -> Result<(), DomainError> {
        let requests = vec![
            ExternalInputRequest::UtcNow {
                request_sequence: 0,
            },
            ExternalInputRequest::MonotonicNow {
                request_sequence: 1,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 2,
                purpose: EntropyPurpose::ChannelInstance(0),
                bytes: 16,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 3,
                purpose: EntropyPurpose::Message(0),
                bytes: 16,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 4,
                purpose: EntropyPurpose::Invite,
                bytes: 16,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 5,
                purpose: EntropyPurpose::MaskEntry(0),
                bytes: 16,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 6,
                purpose: EntropyPurpose::AccountDeletionChallenge,
                bytes: 16,
            },
            ExternalInputRequest::ChannelKeyVerification {
                request_sequence: 7,
                target_index: 0,
            },
            ExternalInputRequest::ChannelKeyConstruction {
                request_sequence: 8,
                change_index: 0,
            },
        ];
        let valid = complete_external_inputs();
        assert_eq!(validate_external_inputs(&requests, &valid), Ok(()));
        let mut invalid = complete_external_inputs();
        invalid.channel_ids.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.key_verifiers.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.message_ids.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.invite_ids.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.entry_ids.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.deletion_tokens.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        let mut invalid = complete_external_inputs();
        invalid.key_verdicts.clear();
        assert_eq!(
            validate_external_inputs(&requests, &invalid),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_requested_clocks(false, false, &ExternalInputs::default()),
            Ok(())
        );
        assert_eq!(
            validate_requested_clocks(
                true,
                false,
                &ExternalInputs {
                    wall_clock_unavailable: true,
                    ..ExternalInputs::default()
                },
            ),
            Err(DomainError::WallClockUnavailable)
        );
        assert_eq!(
            validate_requested_clocks(
                false,
                false,
                &ExternalInputs {
                    wall_clock_unavailable: true,
                    ..ExternalInputs::default()
                },
            ),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_requested_clocks(
                true,
                false,
                &ExternalInputs {
                    wall_clock_unavailable: true,
                    utc_now: Some(UtcSecond::from_unix_seconds(1)),
                    ..ExternalInputs::default()
                },
            ),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_requested_clocks(true, false, &ExternalInputs::default()),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_requested_clocks(false, true, &ExternalInputs::default()),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_requested_clocks(
                true,
                true,
                &ExternalInputs {
                    utc_now: Some(UtcSecond::from_unix_seconds(1)),
                    ..ExternalInputs::default()
                },
            ),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            take_one::<u8>(&mut Vec::new()),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            take_one(&mut vec![1_u8, 2]),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(take_one(&mut vec![7_u8]), Ok(7));
        Ok(())
    }

    #[test]
    fn mode_account_channel_and_sanction_validators_cover_rejections() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let state = &mut fixture.state;
        let channel = state
            .channels
            .get(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(
            validate_mode_change(
                state,
                channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                },
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                state,
                channel,
                Role::Member,
                Some(fixture.owner_account),
                &ModeChange::TopicProtected(false),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                state,
                channel,
                Role::Owner,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Exception,
                    mask: TypedMask::parse("$q:$n:test")?,
                },
            ),
            Err(DomainError::InvalidArgument)
        );
        assert_eq!(
            validate_mode_change(
                state,
                channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$q:$n:test")?,
                },
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_role_change(
                state,
                channel,
                Role::Member,
                ModeOperation::Add,
                &fixture.member.nickname,
                Role::Voice,
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_role_change(
                state,
                channel,
                Role::Owner,
                ModeOperation::Add,
                &NicknameValue::parse("missing")?,
                Role::Voice,
            ),
            Err(DomainError::NotFound)
        );
        assert_eq!(
            validate_role_change(
                state,
                channel,
                Role::Owner,
                ModeOperation::Add,
                &fixture.outsider.nickname,
                Role::Voice,
            ),
            Err(DomainError::NotFound)
        );
        assert_eq!(
            validate_role_change(
                state,
                channel,
                Role::Owner,
                ModeOperation::Add,
                &fixture.owner.nickname,
                Role::Owner,
            ),
            Ok(())
        );
        assert_eq!(
            validate_role_change(
                state,
                channel,
                Role::Owner,
                ModeOperation::Remove,
                &fixture.member.nickname,
                Role::Member,
            ),
            Err(DomainError::InvalidArgument)
        );

        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::ContactAdd(fixture.owner_account)
            )
            .err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            account_setting(
                state,
                account_id(99),
                AccountCommand::Presence(PresencePolicy::Public)
            )
            .err(),
            Some(DomainError::NotFound)
        );
        assert_eq!(
            account_setting(state, fixture.owner_account, AccountCommand::DeleteStart).err(),
            Some(DomainError::BadState)
        );
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.outsider.user_id,
                fixture.owner_account,
                ChannelCommand::Register(fixture.channel_id),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Unregister(fixture.channel_id),
            ),
            Err(DomainError::BadState)
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.member,
                Principal::Guest(fixture.outsider.user_id),
                Some(fixture.channel_id),
                ModerationAction::Ban,
                false,
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.owner,
                Principal::Guest(fixture.outsider.user_id),
                Some(fixture.channel_id),
                ModerationAction::Kick,
                false,
            ),
            Err(DomainError::NotFound)
        );
        Ok(())
    }

    #[test]
    fn mutation_helpers_ignore_missing_targets_without_corrupting_indexes()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let missing_user = UserId::from_bytes(bytes(99));
        let missing_channel = ChannelInstanceId::from_bytes(bytes(99));
        fixture.state.apply_nick(
            missing_user,
            NicknameValue::parse("new")?,
            Revision::new(2)?,
        );
        fixture
            .state
            .apply_away(missing_user, None, Revision::new(2)?);
        fixture.state.apply_display_name(
            missing_user,
            DisplayNameValue::prepare("new")?,
            Revision::new(2)?,
        );
        fixture.state.apply_join_existing(
            missing_channel,
            Membership::new(missing_user, None, Role::Member),
            None,
            Revision::new(2)?,
        );
        fixture
            .state
            .apply_part(missing_channel, missing_user, Revision::new(2)?);
        fixture
            .state
            .apply_close_session(missing_user, Revision::new(2)?);
        fixture.state.apply_topic(
            missing_channel,
            PlaintextTopic {
                text: TopicText::try_from_str("x", ControlPolicy::RejectAll)?,
                message_id: MessageId::from_bytes(bytes(1)),
                setter: missing_user,
                set_at: UtcSecond::from_unix_seconds(1),
            },
            Revision::new(2)?,
        );
        fixture
            .state
            .recompute_channel_roles(missing_channel, Revision::new(2)?);
        fixture.state.apply_account_setting(
            account_id(99),
            AccountSetting::Presence(PresencePolicy::Public),
            Revision::new(2)?,
        );
        fixture.state.apply_channel_setting(
            ChannelCommand::History(missing_channel, HistoryPolicy::Off),
            Revision::new(2)?,
        );
        assert_eq!(fixture.state.validate(), Ok(()));
        Ok(())
    }

    #[test]
    fn direct_message_policy_and_public_plan_helpers_cover_closed_variants()
    -> Result<(), DomainError> {
        let guest = session(11, None)?;
        let sender_account_id = account_id(12);
        let sender = session(12, Some(sender_account_id))?;
        let target_account_id = account_id(13);
        let mut target = AccountState::new(
            target_account_id,
            agenc_ircd_types::Generation::new(1)?,
            Revision::new(1)?,
        );

        target.guest_direct_messages = GuestDirectMessagePolicy::Deny;
        assert_eq!(
            authorize_direct_policy(&guest, &target),
            Err(DomainError::Forbidden)
        );
        target.guest_direct_messages = GuestDirectMessagePolicy::Allow;
        assert_eq!(authorize_direct_policy(&guest, &target), Ok(()));

        let same_account = session(13, Some(target_account_id))?;
        assert_eq!(authorize_direct_policy(&same_account, &target), Ok(()));
        target.direct_messages = DirectMessagePolicy::Allow;
        assert_eq!(authorize_direct_policy(&sender, &target), Ok(()));
        target.direct_messages = DirectMessagePolicy::Contacts;
        assert_eq!(
            authorize_direct_policy(&sender, &target),
            Err(DomainError::Forbidden)
        );
        target.contacts.insert(sender_account_id);
        assert_eq!(authorize_direct_policy(&sender, &target), Ok(()));

        let charge = RateCharge::new(RateBucket::AccountMessage(sender_account_id), 2)?;
        assert_eq!(
            charge.bucket(),
            RateBucket::AccountMessage(sender_account_id)
        );
        assert_eq!(charge.tokens(), 2);
        let admission = AdmissionSnapshot::new(vec![(charge.bucket(), 2)])?;
        assert_eq!(admission.admits(&[charge]), Ok(true));
        assert_eq!(
            admission.admits(&[
                RateCharge::new(charge.bucket(), 1)?,
                RateCharge::new(charge.bucket(), 2)?,
            ]),
            Ok(false)
        );
        assert_eq!(
            admission.admits(&[
                RateCharge::new(charge.bucket(), u64::MAX)?,
                RateCharge::new(charge.bucket(), 1)?,
            ]),
            Err(DomainError::Overflow)
        );

        for (index, request) in [
            ExternalInputRequest::UtcNow {
                request_sequence: 1,
            },
            ExternalInputRequest::MonotonicNow {
                request_sequence: 2,
            },
            ExternalInputRequest::Entropy {
                request_sequence: 3,
                purpose: EntropyPurpose::Invite,
                bytes: 16,
            },
            ExternalInputRequest::ChannelKeyVerification {
                request_sequence: 4,
                target_index: 0,
            },
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                request.request_sequence(),
                u16::try_from(index + 1).map_err(|_| DomainError::Overflow)?
            );
        }

        let mut recipients = RecipientSet::new();
        recipients.insert(guest.user_id);
        recipients.insert(guest.user_id);
        assert_eq!(recipients.len(), 1);
        assert!(!recipients.is_empty());
        assert_eq!(recipients.iter().collect::<Vec<_>>(), vec![guest.user_id]);

        let channel_failure = TargetFailure::channel(
            0,
            ChannelNameValue::parse("#failed")?,
            DomainError::Forbidden,
        )?;
        assert_eq!(channel_failure.target_index(), 0);
        assert_eq!(channel_failure.error(), DomainError::Forbidden);
        assert!(channel_failure.target().channel().is_some());
        assert!(channel_failure.target().user().is_none());
        let user_target = MessageTarget::User(NicknameValue::parse("failed")?);
        let user_failure = TargetFailure::message(1, &user_target, DomainError::NotFound)?;
        assert!(user_failure.target().channel().is_none());
        assert!(user_failure.target().user().is_some());

        assert_eq!(
            require_account(&guest),
            Err(DomainError::RegistrationRequired)
        );
        assert_eq!(require_account(&sender), Ok(sender_account_id));
        assert!(is_expensive_query(DomainCommandKind::Whois));
        assert!(!is_expensive_query(DomainCommandKind::Privmsg));
        Ok(())
    }

    #[test]
    fn mode_validation_and_role_application_cover_every_authority_class() -> Result<(), DomainError>
    {
        let mut fixture = fixture()?;
        let mut channel = fixture
            .state
            .channels
            .remove(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        let state = &fixture.state;

        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Owner,
                None,
                &ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                },
            ),
            Err(DomainError::RegistrationRequired)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Member,
                Some(fixture.owner_account),
                &ModeChange::Visibility {
                    operation: ModeOperation::Remove,
                    mode: VisibilityMode::Secret,
                },
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::MemberLimit(Some(0)),
            ),
            Err(DomainError::InvalidArgument)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Member,
                Some(fixture.owner_account),
                &ModeChange::MemberLimit(Some(10)),
            ),
            Err(DomainError::Forbidden)
        );

        let plain_mask = TypedMask::parse("$n:blocked*")?;
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: plain_mask,
                },
            ),
            Ok(())
        );
        let quiet_mask = || TypedMask::parse("$q:$n:quiet*");
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Operator,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Exception,
                    mask: quiet_mask()?,
                },
            ),
            Err(DomainError::InvalidArgument)
        );
        let quiet_id = EntryId::from_bytes(bytes(80));
        channel.bans.push(crate::ListEntry::new(
            quiet_id,
            quiet_mask()?,
            Principal::Account(fixture.owner_account),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::RemoveMask {
                    list: MaskList::Ban,
                    entry_id: quiet_id,
                },
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Operator,
                Some(fixture.owner_account),
                &ModeChange::RemoveMask {
                    list: MaskList::Ban,
                    entry_id: quiet_id,
                },
            ),
            Ok(())
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Member,
                Some(fixture.owner_account),
                &ModeChange::RemoveMask {
                    list: MaskList::Ban,
                    entry_id: EntryId::from_bytes(bytes(81)),
                },
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Owner,
                Some(fixture.owner_account),
                &ModeChange::RemoveMask {
                    list: MaskList::Ban,
                    entry_id: EntryId::from_bytes(bytes(81)),
                },
            ),
            Err(DomainError::InvalidArgument)
        );

        assert_eq!(
            validate_mode_vector(
                state,
                &channel,
                fixture.owner.user_id,
                &[ModeChange::AddMask {
                    list: MaskList::Exception,
                    mask: TypedMask::parse("$n:one")?,
                }],
                &[],
            ),
            Err(DomainError::ExternalInputMismatch)
        );
        let repeated_id = EntryId::from_bytes(bytes(82));
        assert_eq!(
            validate_mode_vector(
                state,
                &channel,
                fixture.owner.user_id,
                &[
                    ModeChange::AddMask {
                        list: MaskList::Exception,
                        mask: TypedMask::parse("$n:one")?,
                    },
                    ModeChange::AddMask {
                        list: MaskList::InviteException,
                        mask: TypedMask::parse("$n:two")?,
                    },
                ],
                &[repeated_id, repeated_id],
            ),
            Err(DomainError::ExternalInputMismatch)
        );
        assert_eq!(
            validate_mode_vector(
                state,
                &channel,
                fixture.owner.user_id,
                &[ModeChange::AddMask {
                    list: MaskList::Exception,
                    mask: TypedMask::parse("$n:three")?,
                }],
                &[quiet_id],
            ),
            Err(DomainError::ExternalInputMismatch)
        );

        channel.persistence = PersistencePolicy::Registered;
        channel
            .role_grants
            .insert(fixture.owner_account, Role::Owner);
        channel
            .role_grants
            .insert(fixture.member_account, Role::Member);
        for membership in channel.memberships.values_mut() {
            let Some(account_id) = membership.account_id else {
                continue;
            };
            membership.session_role = Role::Member;
            membership.effective_role = channel
                .role_grants
                .get(&account_id)
                .copied()
                .unwrap_or(Role::Member);
        }
        let remove_owner = ModeChange::Role {
            operation: ModeOperation::Remove,
            target: fixture.owner.nickname.clone(),
            role: Role::Owner,
        };
        assert_eq!(
            validate_owner_continuity(state, &channel, &[remove_owner]),
            Err(DomainError::BadState)
        );
        let add_owner = ModeChange::Role {
            operation: ModeOperation::Add,
            target: fixture.member.nickname.clone(),
            role: Role::Owner,
        };
        assert_eq!(
            validate_owner_continuity(state, &channel, &[add_owner]),
            Ok(())
        );

        let changes = [
            ModeChange::Role {
                operation: ModeOperation::Add,
                target: fixture.member.nickname.clone(),
                role: Role::Operator,
            },
            ModeChange::Role {
                operation: ModeOperation::Add,
                target: fixture.member.nickname.clone(),
                role: Role::Administrator,
            },
            ModeChange::Role {
                operation: ModeOperation::Add,
                target: fixture.outsider.nickname.clone(),
                role: Role::Voice,
            },
        ];
        let events = mode_events(state, &channel, &changes)?;
        assert_eq!(events.len(), 2);

        apply_role_change(
            &state.nicknames,
            &mut channel,
            ModeOperation::Add,
            &NicknameValue::parse("missing")?,
            Role::Voice,
        );
        channel.memberships.insert(
            fixture.outsider.user_id,
            Membership::new(fixture.outsider.user_id, None, Role::Member),
        );
        apply_role_change(
            &state.nicknames,
            &mut channel,
            ModeOperation::Add,
            &fixture.outsider.nickname,
            Role::Voice,
        );
        assert_eq!(channel.role_of(fixture.outsider.user_id), Some(Role::Voice));
        apply_role_change(
            &state.nicknames,
            &mut channel,
            ModeOperation::Add,
            &fixture.member.nickname,
            Role::Operator,
        );
        assert_eq!(
            channel.role_of(fixture.member.user_id),
            Some(Role::Operator)
        );

        channel.bans.clear();
        for index in 0..crate::model::MAX_MASK_ENTRIES_PER_LIST {
            let mut raw = [0_u8; 16];
            raw[..8].copy_from_slice(
                &u64::try_from(index)
                    .map_err(|_| DomainError::Overflow)?
                    .to_be_bytes(),
            );
            channel.bans.push(crate::ListEntry::new(
                EntryId::from_bytes(raw),
                TypedMask::parse("$n:full")?,
                Principal::Account(fixture.owner_account),
                UtcSecond::from_unix_seconds(10),
            ));
        }
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Owner,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$n:overflow")?,
                },
            ),
            Err(DomainError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn mode_vectors_simulate_client_order_and_check_only_the_final_state() -> Result<(), DomainError>
    {
        {
            let fixture = fixture()?;
            let channel = fixture
                .state
                .channels
                .get(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            let private_then_secret = [
                ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Unlisted,
                },
                ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                },
            ];
            validate_mode_vector(
                &fixture.state,
                channel,
                fixture.owner.user_id,
                &private_then_secret,
                &[],
            )?;
            let final_visibility = private_then_secret.iter().fold(
                channel.visibility,
                |current, change| match change {
                    ModeChange::Visibility { operation, mode } => {
                        resulting_visibility(current, *operation, *mode)
                    }
                    _ => current,
                },
            );
            assert_eq!(final_visibility, Visibility::Secret);
        }

        {
            let mut fixture = fixture()?;
            let mut channel = fixture
                .state
                .channels
                .remove(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            let raise_without_demotion = [
                ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: fixture.member.nickname.clone(),
                    role: Role::Operator,
                },
                ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: fixture.member.nickname.clone(),
                    role: Role::Voice,
                },
            ];
            validate_mode_vector(
                &fixture.state,
                &channel,
                fixture.owner.user_id,
                &raise_without_demotion,
                &[],
            )?;
            for change in raise_without_demotion {
                let ModeChange::Role {
                    operation,
                    target,
                    role,
                } = change
                else {
                    return Err(DomainError::InvariantViolation);
                };
                apply_role_change(
                    &fixture.state.nicknames,
                    &mut channel,
                    operation,
                    &target,
                    role,
                );
            }
            assert_eq!(
                channel.role_of(fixture.member.user_id),
                Some(Role::Operator)
            );
        }

        {
            let mut fixture = fixture()?;
            let mut channel = fixture
                .state
                .channels
                .remove(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            register_channel_roles(&mut channel);
            let transfer = [
                ModeChange::Role {
                    operation: ModeOperation::Remove,
                    target: fixture.owner.nickname.clone(),
                    role: Role::Owner,
                },
                ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: fixture.member.nickname.clone(),
                    role: Role::Owner,
                },
            ];
            validate_mode_vector(
                &fixture.state,
                &channel,
                fixture.owner.user_id,
                &transfer,
                &[],
            )?;
            for change in transfer {
                let ModeChange::Role {
                    operation,
                    target,
                    role,
                } = change
                else {
                    return Err(DomainError::InvariantViolation);
                };
                apply_role_change(
                    &fixture.state.nicknames,
                    &mut channel,
                    operation,
                    &target,
                    role,
                );
            }
            assert_eq!(
                channel.role_grants.get(&fixture.owner_account),
                Some(&Role::Administrator)
            );
            assert_eq!(
                channel.role_grants.get(&fixture.member_account),
                Some(&Role::Owner)
            );
            channel.validate()?;

            channel.memberships.insert(
                fixture.outsider.user_id,
                Membership::new(fixture.outsider.user_id, None, Role::Member),
            );
            validate_mode_vector(
                &fixture.state,
                &channel,
                fixture.member.user_id,
                &[ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: fixture.outsider.nickname.clone(),
                    role: Role::Voice,
                }],
                &[],
            )?;

            channel.history = HistoryPolicy::OneHour;
            assert_eq!(
                validate_mode_vector(
                    &fixture.state,
                    &channel,
                    fixture.member.user_id,
                    &[ModeChange::Visibility {
                        operation: ModeOperation::Add,
                        mode: VisibilityMode::Unlisted,
                    }],
                    &[],
                ),
                Err(DomainError::BadState)
            );
        }

        {
            let mut fixture = fixture()?;
            let channel = fixture
                .state
                .channels
                .get_mut(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            let mut first_entry_id = None;
            for index in 0..crate::model::MAX_MASK_ENTRIES_PER_LIST {
                let index = u64::try_from(index).map_err(|_| DomainError::Overflow)?;
                let mut raw = [0_u8; 16];
                raw[..8].copy_from_slice(&index.to_be_bytes());
                let entry_id = EntryId::from_bytes(raw);
                first_entry_id.get_or_insert(entry_id);
                channel.bans.push(crate::ListEntry::new(
                    entry_id,
                    TypedMask::parse(&format!("$n:bounded{index}"))?,
                    fixture.owner.principal(),
                    UtcSecond::from_unix_seconds(10),
                ));
            }
            let first_entry_id = first_entry_id.ok_or(DomainError::InvariantViolation)?;
            let channel = fixture
                .state
                .channels
                .get(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            validate_mode_vector(
                &fixture.state,
                channel,
                fixture.owner.user_id,
                &[
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$n:temporary")?,
                    },
                    ModeChange::RemoveMask {
                        list: MaskList::Ban,
                        entry_id: first_entry_id,
                    },
                ],
                &[EntryId::from_bytes([0xff_u8; 16])],
            )?;
            validate_mode_vector(
                &fixture.state,
                channel,
                fixture.owner.user_id,
                &[
                    ModeChange::RemoveMask {
                        list: MaskList::Ban,
                        entry_id: first_entry_id,
                    },
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$n:bounded0")?,
                    },
                ],
                &[EntryId::from_bytes([0xfe_u8; 16])],
            )?;
        }
        Ok(())
    }

    #[test]
    fn lowered_session_ceiling_retains_live_state_and_blocks_new_work() -> Result<(), DomainError> {
        let account = account_id(29);
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account,
            AccountState::new(
                account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(0)?,
            ),
        );
        state.apply_session(session(29, Some(account))?, Revision::new(0)?);
        state.apply_session(session(30, Some(account))?, Revision::new(0)?);

        let mut values = crate::OperationalLimits::HARD_MAX.values();
        values.sessions_per_account = 1;
        state.set_operational_limits(crate::OperationalLimits::new(values)?);

        assert_eq!(state.sessions.len(), 2);
        assert_eq!(
            state
                .plan_session_opened(session_seed(31, Some(account), 1)?)
                .err(),
            Some(DomainError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn lifecycle_planning_rejects_stale_duplicate_and_invalid_authority_state()
    -> Result<(), DomainError> {
        let account = account_id(30);
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account,
            AccountState::new(
                account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(0)?,
            ),
        );
        assert_eq!(
            state
                .plan_account_created(AccountState::new(
                    account,
                    agenc_ircd_types::Generation::new(1)?,
                    Revision::new(0)?,
                ))
                .err(),
            Some(DomainError::BadState)
        );
        assert_eq!(
            state.plan_session_opened(session_seed(31, None, 1)?).err(),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(
            state
                .plan_session_opened(session_seed(31, Some(account_id(99)), 1)?)
                .err(),
            Some(DomainError::NotFound)
        );
        assert_eq!(
            state
                .plan_session_opened(session_seed(31, Some(account), 2)?)
                .err(),
            Some(DomainError::StaleGeneration)
        );

        state.apply_session(session(31, Some(account))?, Revision::new(0)?);
        assert_eq!(
            state
                .plan_session_opened(session_seed(31, Some(account), 1)?)
                .err(),
            Some(DomainError::BadState)
        );
        let mut duplicate_session = session_seed(32, Some(account), 1)?;
        duplicate_session.session_id = SessionId::from_bytes(bytes(31));
        assert_eq!(
            state.plan_session_opened(duplicate_session).err(),
            Some(DomainError::BadState)
        );
        let mut duplicate_nickname = session_seed(32, Some(account), 1)?;
        duplicate_nickname.nickname = NicknameValue::parse("test31")?;
        assert_eq!(
            state.plan_session_opened(duplicate_nickname).err(),
            Some(DomainError::BadState)
        );

        let reserved = NicknameValue::parse("reserved")?;
        state
            .accounts
            .get_mut(&account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .insert(reserved.clone());
        let mut forbidden_seed = session_seed(32, None, 0)?;
        forbidden_seed.nickname = reserved;
        assert_eq!(
            state.plan_session_opened(forbidden_seed).err(),
            Some(DomainError::Forbidden)
        );

        let mut saturated = DomainState::new()?;
        saturated.accounts.insert(
            account,
            AccountState::new(
                account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(0)?,
            ),
        );
        for index in 0..crate::model::MAX_SESSIONS_PER_ACCOUNT {
            let seed = u8::try_from(index + 40).map_err(|_| DomainError::Overflow)?;
            saturated.apply_session(session(seed, Some(account))?, Revision::new(0)?);
        }
        assert_eq!(
            saturated
                .plan_session_opened(session_seed(90, Some(account), 1)?)
                .err(),
            Some(DomainError::LimitExceeded)
        );

        let mut deletion = DomainState::new()?;
        deletion.accounts.insert(
            account,
            AccountState::new(
                account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(0)?,
            ),
        );
        assert_eq!(
            deletion
                .plan_account_deleted(account, agenc_ircd_types::Generation::new(1)?)
                .err(),
            Some(DomainError::BadState)
        );
        deletion.apply_session(session(91, Some(account))?, Revision::new(0)?);
        let plan = deletion.plan_account_deleted(account, agenc_ircd_types::Generation::new(1)?)?;
        assert_eq!(plan.storage_class(), StorageClass::Durable);
        deletion.apply_session(session(92, Some(account))?, Revision::new(0)?);
        assert_eq!(
            deletion
                .plan_account_deleted(account, agenc_ircd_types::Generation::new(1)?)
                .err(),
            Some(DomainError::BadState)
        );
        let second_user = session(92, Some(account))?.user_id;
        deletion.sessions.remove(&second_user);
        let confirming_user = session(91, Some(account))?.user_id;
        deletion
            .sessions
            .get_mut(&confirming_user)
            .ok_or(DomainError::InvariantViolation)?
            .joined_channels
            .insert(ChannelInstanceId::from_bytes(bytes(90)));
        assert_eq!(
            deletion
                .plan_account_deleted(account, agenc_ircd_types::Generation::new(1)?)
                .err(),
            Some(DomainError::BadState)
        );

        let mut stale_fixture = fixture()?;
        let authorized = stale_fixture
            .state
            .authorize(
                envelope(
                    &stale_fixture.owner,
                    stale_fixture.state.revision,
                    CanonicalCommand::information(crate::InformationQuery::Motd),
                ),
                &admission(stale_fixture.owner.user_id)?,
            )
            .map_err(|failure| failure.error())?;
        stale_fixture.state.revision = Revision::new(2)?;
        assert_eq!(
            stale_fixture.state.plan_authorized(authorized, None).err(),
            Some(DomainError::StaleRevision)
        );

        let new_account = account_id(93);
        let mut stale_prepare = DomainState::new()?;
        let plan = stale_prepare.plan_account_created(AccountState::new(
            new_account,
            agenc_ircd_types::Generation::new(1)?,
            Revision::new(0)?,
        ))?;
        stale_prepare.revision = Revision::new(1)?;
        assert_eq!(
            stale_prepare.prepare_mutation(plan).err(),
            Some(DomainError::StaleRevision)
        );
        let mut stale_apply = DomainState::new()?;
        let plan = stale_apply.plan_account_created(AccountState::new(
            new_account,
            agenc_ircd_types::Generation::new(1)?,
            Revision::new(0)?,
        ))?;
        let prepared = stale_apply.prepare_mutation(plan)?;
        stale_apply.revision = Revision::new(1)?;
        assert_eq!(
            stale_apply.apply_prepared(prepared).err(),
            Some(DomainError::StaleRevision)
        );

        let fixture = fixture()?;
        assert_eq!(
            fixture
                .state
                .plan_sanction(SanctionRequest {
                    actor_user_id: UserId::from_bytes(bytes(250)),
                    target: Principal::Guest(fixture.outsider.user_id),
                    channel_id: Some(fixture.channel_id),
                    action: ModerationAction::Ban,
                    reason_code: ModerationReasonCode::Spam,
                    reason: None,
                    created_at: UtcSecond::from_unix_seconds(10),
                    expires_at: Some(UtcSecond::from_unix_seconds(20)),
                })
                .err(),
            Some(DomainError::NotFound)
        );
        assert_eq!(
            fixture
                .state
                .plan_sanction(SanctionRequest {
                    actor_user_id: fixture.owner.user_id,
                    target: Principal::Guest(fixture.outsider.user_id),
                    channel_id: Some(fixture.channel_id),
                    action: ModerationAction::Ban,
                    reason_code: ModerationReasonCode::Spam,
                    reason: None,
                    created_at: UtcSecond::from_unix_seconds(10),
                    expires_at: Some(UtcSecond::from_unix_seconds(10)),
                })
                .err(),
            Some(DomainError::InvalidArgument)
        );
        Ok(())
    }

    #[test]
    fn session_open_and_restart_disconnect_project_put_then_tombstone() -> Result<(), DomainError> {
        let mut state = DomainState::new()?;
        let seed = session_seed(33, None, 0)?;
        let user_id = seed.user_id;
        let session_id = seed.session_id;
        let opened = state.plan_session_opened(seed)?;
        assert_eq!(opened.storage_class(), StorageClass::Durable);
        assert!(matches!(
            opened.durable_writes(),
            [DurableWrite::PutSession(session)] if session.session_id == session_id
        ));
        let prepared = state.prepare_mutation(opened)?;
        state.apply_prepared(prepared)?;

        let disconnected = state.plan_session_disconnected(user_id)?;
        assert!(matches!(
            disconnected.durable_writes(),
            [DurableWrite::TombstoneSession(tombstoned)] if *tombstoned == session_id
        ));
        let prepared = state.prepare_mutation(disconnected)?;
        state.apply_prepared(prepared)?;
        assert_eq!(state.session_count(), 0);
        Ok(())
    }

    #[test]
    fn durable_session_omits_ephemeral_local_join_and_keeps_global_join() -> Result<(), DomainError>
    {
        let mut state = DomainState::at_revision(Revision::new(1)?);
        let live = session(34, None)?;
        let user_id = live.user_id;
        state.apply_session(live, Revision::new(1)?);
        let local_id = ChannelInstanceId::from_bytes(bytes(50));
        let global_id = ChannelInstanceId::from_bytes(bytes(51));
        for (channel_id, name, revision) in [
            (local_id, ChannelNameValue::parse("&local")?, 2_u64),
            (global_id, ChannelNameValue::parse("#global")?, 3_u64),
        ] {
            let membership = Membership::joined(
                user_id,
                None,
                Role::Owner,
                Revision::new(revision)?,
                UtcSecond::from_unix_seconds(20),
            );
            let channel = crate::ChannelState::new_ephemeral(
                channel_id,
                name,
                Principal::Guest(user_id),
                membership,
                UtcSecond::from_unix_seconds(20),
                Revision::new(revision)?,
            );
            state.apply_join_new(channel, Revision::new(revision)?);
        }
        let durable = state
            .durable_session(user_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(durable.joined_channels, vec![global_id]);
        assert!(state.durable_channel(local_id).is_none());
        assert!(state.durable_channel(global_id).is_some());
        Ok(())
    }

    #[test]
    fn authorization_helpers_cover_invariant_quiet_and_success_paths() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let missing_channel_id = ChannelInstanceId::from_bytes(bytes(200));
        let broken_name = ChannelNameValue::parse("#broken")?;
        fixture
            .state
            .channel_names
            .insert(broken_name.clone(), missing_channel_id);
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.owner, &broken_name),
            Err(DomainError::InvariantViolation)
        );
        assert_eq!(
            fixture.state.authorize_kick(&fixture.owner, &broken_name),
            Err(DomainError::InvariantViolation)
        );
        assert_eq!(
            fixture.state.authorize_channel_message(
                &fixture.owner,
                &broken_name,
                MessageKind::Privmsg,
            ),
            Err(DomainError::InvariantViolation)
        );

        assert_eq!(
            fixture
                .state
                .require_channel_role(&fixture.owner, &fixture.name, Role::Owner),
            Ok(())
        );
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.owner, &fixture.name),
            Ok(())
        );
        assert_eq!(
            fixture.state.authorize_kick(&fixture.owner, &fixture.name),
            Ok(())
        );
        assert_eq!(
            fixture.state.authorize_channel_message(
                &fixture.owner,
                &fixture.name,
                MessageKind::Privmsg,
            ),
            Ok(())
        );

        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .bans
            .push(crate::ListEntry::new(
                EntryId::from_bytes(bytes(201)),
                TypedMask::parse("$q:$n:test2")?,
                Principal::Account(fixture.owner_account),
                UtcSecond::from_unix_seconds(10),
            ));
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.member, &fixture.name),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            fixture.state.authorize_channel_message(
                &fixture.member,
                &fixture.name,
                MessageKind::Privmsg,
            ),
            Err(DomainError::Forbidden)
        );
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.bans.clear();
        channel.modes.topic_protected = true;
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.member, &fixture.name),
            Err(DomainError::Forbidden)
        );

        let missing_target = NicknameValue::parse("missing-direct")?;
        assert_eq!(
            fixture
                .state
                .authorize_direct_message(&fixture.owner, &missing_target),
            Err(DomainError::NotFound)
        );
        fixture
            .state
            .nicknames
            .insert(missing_target.clone(), UserId::from_bytes(bytes(202)));
        assert_eq!(
            fixture
                .state
                .authorize_direct_message(&fixture.owner, &missing_target),
            Err(DomainError::InvariantViolation)
        );
        assert_eq!(
            fixture
                .state
                .authorize_direct_message(&fixture.owner, &fixture.outsider.nickname),
            Ok(())
        );
        fixture.state.accounts.remove(&fixture.member_account);
        assert_eq!(
            fixture
                .state
                .authorize_direct_message(&fixture.owner, &fixture.member.nickname),
            Err(DomainError::InvariantViolation)
        );

        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.history = HistoryPolicy::OneHour;
        channel.persistence = PersistencePolicy::Registered;
        assert_eq!(
            fixture
                .state
                .authorize_history(&fixture.member, fixture.channel_id),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn account_channel_and_sanction_policy_matrix_covers_success_and_limits()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let state = &mut fixture.state;

        assert!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::ContactAdd(fixture.member_account),
            )
            .is_ok()
        );
        let reserved = NicknameValue::parse("reserved-owner")?;
        state
            .accounts
            .get_mut(&fixture.owner_account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .insert(reserved.clone());
        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::NickReserve(reserved),
            )
            .err(),
            Some(DomainError::BadState)
        );
        let account = state
            .accounts
            .get_mut(&fixture.owner_account)
            .ok_or(DomainError::InvariantViolation)?;
        account.reserved_nicknames.clear();
        for index in 0..crate::model::MAX_RESERVED_NICKNAMES {
            account
                .reserved_nicknames
                .insert(NicknameValue::parse(&format!("held{index}"))?);
        }
        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::NickReserve(NicknameValue::parse("overflow-reservation")?),
            )
            .err(),
            Some(DomainError::LimitExceeded)
        );
        state
            .accounts
            .get_mut(&fixture.owner_account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .clear();
        let cross_reserved = NicknameValue::parse("cross-reserved")?;
        state
            .accounts
            .get_mut(&fixture.member_account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .insert(cross_reserved.clone());
        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::NickReserve(cross_reserved),
            )
            .err(),
            Some(DomainError::BadState)
        );
        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::NickReserve(fixture.member.nickname.clone()),
            )
            .err(),
            Some(DomainError::BadState)
        );
        assert!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::NickReserve(fixture.owner.nickname.clone()),
            )
            .is_ok()
        );
        let account = state
            .accounts
            .get_mut(&fixture.owner_account)
            .ok_or(DomainError::InvariantViolation)?;
        account.contacts.clear();
        for index in 0..MAX_CONTACTS_PER_ACCOUNT {
            let mut raw = [0_u8; 16];
            raw[..8].copy_from_slice(
                &u64::try_from(index)
                    .map_err(|_| DomainError::Overflow)?
                    .to_be_bytes(),
            );
            account
                .contacts
                .insert(AccountId::from_random(AccountRandomId::from_bytes(raw)));
        }
        assert_eq!(
            account_setting(
                state,
                fixture.owner_account,
                AccountCommand::ContactAdd(account_id(200)),
            )
            .err(),
            Some(DomainError::LimitExceeded)
        );

        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Register(ChannelInstanceId::from_bytes(bytes(199))),
            ),
            Err(DomainError::NotFound)
        );
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Register(fixture.channel_id),
            ),
            Ok(())
        );
        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .creator = Principal::Guest(fixture.owner.user_id);
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Register(fixture.channel_id),
            ),
            Err(DomainError::BadState)
        );
        let channel = state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.creator = Principal::Account(fixture.owner_account);
        channel.persistence = PersistencePolicy::Registered;
        channel
            .role_grants
            .insert(fixture.owner_account, Role::Owner);
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Unregister(fixture.channel_id),
            ),
            Ok(())
        );
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::History(fixture.channel_id, HistoryPolicy::OneHour),
            ),
            Ok(())
        );
        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .visibility = Visibility::Unlisted;
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::History(fixture.channel_id, HistoryPolicy::OneHour),
            ),
            Err(DomainError::BadState)
        );
        let channel = state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.visibility = Visibility::Listed;
        channel.persistence = PersistencePolicy::Ephemeral;
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::History(fixture.channel_id, HistoryPolicy::Off),
            ),
            Ok(())
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.owner,
                Principal::Guest(fixture.outsider.user_id),
                None,
                ModerationAction::Ban,
                false,
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.owner,
                Principal::Guest(fixture.outsider.user_id),
                Some(fixture.channel_id),
                ModerationAction::Suspend,
                false,
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.owner,
                Principal::Account(fixture.member_account),
                Some(fixture.channel_id),
                ModerationAction::Kick,
                false,
            ),
            Ok(())
        );
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.owner,
                Principal::Account(fixture.owner_account),
                Some(fixture.channel_id),
                ModerationAction::Kick,
                false,
            ),
            Err(DomainError::Forbidden)
        );
        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::InvariantViolation)?
            .effective_role = Role::Operator;
        assert_eq!(
            authorize_sanction(
                state,
                &fixture.member,
                Principal::Guest(fixture.outsider.user_id),
                Some(fixture.channel_id),
                ModerationAction::Ban,
                true,
            ),
            Err(DomainError::Forbidden)
        );
        Ok(())
    }

    #[test]
    fn mutation_application_covers_optional_cleanup_and_destroy_paths() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let revision = Revision::new(2)?;
        let invite_id = InviteId::from_bytes(bytes(210));
        let expired_id = InviteId::from_bytes(bytes(211));
        let invite = Invite {
            invite_id,
            target: fixture.outsider.principal(),
            inviter: fixture.owner.user_id,
            creation_revision: revision,
            expires_at: MonotonicTick::from_ticks(100),
            expires_at_utc: UtcSecond::from_unix_seconds(610),
        };
        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                expired_id,
                Invite {
                    invite_id: expired_id,
                    ..invite
                },
            );
        fixture.state.apply_mutation(
            Mutation::CreateInvite {
                channel_id: fixture.channel_id,
                invite,
                expired_invites: vec![expired_id],
            },
            revision,
        );
        assert!(
            fixture
                .state
                .channels
                .get(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?
                .invites
                .contains_key(&invite_id)
        );
        fixture.state.apply_mutation(
            Mutation::CreateInvite {
                channel_id: ChannelInstanceId::from_bytes(bytes(212)),
                invite: Invite {
                    invite_id: InviteId::from_bytes(bytes(212)),
                    target: fixture.outsider.principal(),
                    inviter: fixture.owner.user_id,
                    creation_revision: revision,
                    expires_at: MonotonicTick::from_ticks(100),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
                expired_invites: Vec::new(),
            },
            revision,
        );
        fixture.state.apply_mutation(
            Mutation::MarkRemovalPending {
                channel_id: fixture.channel_id,
                user_id: fixture.member.user_id,
            },
            revision,
        );
        fixture.state.apply_mutation(
            Mutation::MarkRemovalPending {
                channel_id: ChannelInstanceId::from_bytes(bytes(213)),
                user_id: fixture.member.user_id,
            },
            revision,
        );

        let missing_channel = ChannelInstanceId::from_bytes(bytes(214));
        fixture.state.apply_session_account_switch(
            fixture.member.user_id,
            None,
            agenc_ircd_types::Generation::new(0)?,
            agenc_ircd_types::Generation::new(2)?,
            &[missing_channel, fixture.channel_id],
            revision,
        );
        assert_eq!(
            fixture
                .state
                .sessions
                .get(&fixture.member.user_id)
                .ok_or(DomainError::InvariantViolation)?
                .account_id,
            None
        );

        fixture.state.apply_join_existing(
            fixture.channel_id,
            Membership::new(fixture.outsider.user_id, None, Role::Member),
            Some(invite_id),
            revision,
        );
        fixture
            .state
            .apply_part(fixture.channel_id, fixture.outsider.user_id, revision);
        assert!(fixture.state.channels.contains_key(&fixture.channel_id));

        let temporary_id = ChannelInstanceId::from_bytes(bytes(215));
        let temporary = crate::ChannelState::new_ephemeral(
            temporary_id,
            ChannelNameValue::parse("#temporary")?,
            fixture.outsider.principal(),
            Membership::new(fixture.outsider.user_id, None, Role::Owner),
            UtcSecond::from_unix_seconds(10),
            revision,
        );
        fixture.state.apply_join_new(temporary, revision);
        fixture
            .state
            .apply_part(temporary_id, fixture.outsider.user_id, revision);
        assert!(!fixture.state.channels.contains_key(&temporary_id));

        fixture.state.apply_mode_change(
            missing_channel,
            Principal::Account(fixture.owner_account),
            ModeChange::Moderated(true),
            &mut Vec::<EntryId>::new().into_iter(),
            &mut Vec::<crate::ChannelKeyVerifier>::new().into_iter(),
            None,
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            Principal::Account(fixture.owner_account),
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:no-id")?,
            },
            &mut Vec::<EntryId>::new().into_iter(),
            &mut Vec::<crate::ChannelKeyVerifier>::new().into_iter(),
            None,
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            Principal::Account(fixture.owner_account),
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:with-id")?,
            },
            &mut vec![EntryId::from_bytes(bytes(216))].into_iter(),
            &mut Vec::<crate::ChannelKeyVerifier>::new().into_iter(),
            Some(UtcSecond::from_unix_seconds(20)),
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            Principal::Account(fixture.owner_account),
            ModeChange::RemoveMask {
                list: MaskList::Exception,
                entry_id: EntryId::from_bytes(bytes(216)),
            },
            &mut Vec::<EntryId>::new().into_iter(),
            &mut Vec::<crate::ChannelKeyVerifier>::new().into_iter(),
            None,
        );

        let removed_account = account_id(217);
        fixture.state.accounts.insert(
            removed_account,
            AccountState::new(
                removed_account,
                agenc_ircd_types::Generation::new(1)?,
                revision,
            ),
        );
        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .role_grants
            .insert(removed_account, Role::Voice);
        fixture
            .state
            .apply_account_deletion(removed_account, Vec::new(), revision);
        assert!(!fixture.state.accounts.contains_key(&removed_account));

        fixture.state.apply_account_setting(
            fixture.owner_account,
            AccountSetting::ContactAdd(fixture.member_account),
            revision,
        );
        fixture.state.apply_account_setting(
            fixture.owner_account,
            AccountSetting::ContactRemove(fixture.member_account),
            revision,
        );
        fixture.state.apply_account_setting(
            fixture.owner_account,
            AccountSetting::NickReserve(NicknameValue::parse("applied-reservation")?),
            revision,
        );
        fixture.state.apply_account_setting(
            fixture.owner_account,
            AccountSetting::NickRelease(NicknameValue::parse("applied-reservation")?),
            revision,
        );

        fixture
            .state
            .apply_close_session(fixture.member.user_id, revision);
        assert!(!fixture.state.sessions.contains_key(&fixture.member.user_id));
        fixture.state.apply_mutation(Mutation::EventOnly, revision);
        Ok(())
    }

    #[test]
    fn hidden_channel_join_admits_non_members_only_by_invite_exception_or_key()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let visitor_account = account_id(4);
        fixture.state.apply_account(
            AccountState::new(
                visitor_account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(1)?,
            ),
            Revision::new(1)?,
        );
        fixture
            .state
            .apply_session(session(4, Some(visitor_account))?, Revision::new(1)?);
        let visitor = session(4, Some(visitor_account))?;
        let owner_principal = fixture.owner.principal();
        let mut channel = fixture
            .state
            .channels
            .remove(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        let visitor_entry = |seed: u8| -> Result<crate::ListEntry, DomainError> {
            Ok(crate::ListEntry::new(
                EntryId::from_bytes(bytes(seed)),
                TypedMask::parse("$n:test4")?,
                owner_principal,
                UtcSecond::from_unix_seconds(10),
            ))
        };
        let join = |state: &DomainState,
                    target: &crate::ChannelState,
                    key_supplied: bool,
                    key_ok: bool,
                    now: Option<MonotonicTick>| {
            state.check_join_existing(
                visitor.user_id,
                visitor.principal(),
                target,
                key_supplied,
                key_ok,
                now,
            )
        };

        assert_eq!(join(&fixture.state, &channel, false, true, None), Ok(None));
        for visibility in [Visibility::Unlisted, Visibility::Secret] {
            channel.visibility = visibility;
            assert_eq!(
                join(&fixture.state, &channel, false, true, None),
                Err(DomainError::SecretUnavailable)
            );
        }

        channel.bans.push(visitor_entry(230)?);
        assert_eq!(
            join(&fixture.state, &channel, false, true, None),
            Err(DomainError::SecretUnavailable)
        );
        channel.invite_exceptions.push(visitor_entry(231)?);
        assert_eq!(
            join(&fixture.state, &channel, false, true, None),
            Err(DomainError::Forbidden)
        );
        channel.bans.clear();
        assert_eq!(join(&fixture.state, &channel, false, true, None), Ok(None));
        channel.invite_exceptions.clear();

        let invite_id = InviteId::from_bytes(bytes(232));
        channel.invites.insert(
            invite_id,
            Invite {
                invite_id,
                target: visitor.principal(),
                inviter: fixture.owner.user_id,
                creation_revision: Revision::new(1)?,
                expires_at: MonotonicTick::from_ticks(100),
                expires_at_utc: UtcSecond::from_unix_seconds(610),
            },
        );
        assert_eq!(
            join(
                &fixture.state,
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(50)),
            ),
            Ok(Some(invite_id))
        );
        assert_eq!(
            join(
                &fixture.state,
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(100)),
            ),
            Err(DomainError::SecretUnavailable)
        );
        channel.invites.clear();

        assert_eq!(
            join(&fixture.state, &channel, true, true, None),
            Err(DomainError::SecretUnavailable)
        );
        channel.modes.join_key = true;
        assert_eq!(
            join(&fixture.state, &channel, false, true, None),
            Err(DomainError::SecretUnavailable)
        );
        assert_eq!(
            join(&fixture.state, &channel, true, false, None),
            Err(DomainError::SecretUnavailable)
        );
        assert_eq!(join(&fixture.state, &channel, true, true, None), Ok(None));
        channel.modes.join_key = false;
        channel.visibility = Visibility::Listed;
        fixture.state.channels.insert(fixture.channel_id, channel);
        Ok(())
    }

    #[test]
    fn join_and_part_planners_cover_masks_invites_keys_and_identity_collisions()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let mut channel = fixture
            .state
            .channels
            .remove(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.member.user_id,
                fixture.member.principal(),
                &channel,
                false,
                true,
                None,
            ),
            Err(DomainError::BadState)
        );

        channel.visibility = Visibility::Unlisted;
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                None,
            ),
            Err(DomainError::SecretUnavailable)
        );
        channel.visibility = Visibility::Listed;
        channel.bans.push(crate::ListEntry::new(
            EntryId::from_bytes(bytes(220)),
            TypedMask::parse("$n:test3")?,
            fixture.owner.principal(),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                None,
            ),
            Err(DomainError::Forbidden)
        );
        channel.exceptions.push(crate::ListEntry::new(
            EntryId::from_bytes(bytes(221)),
            TypedMask::parse("$n:test3")?,
            fixture.owner.principal(),
            UtcSecond::from_unix_seconds(10),
        ));
        assert!(!effective_mask(&channel, &fixture.outsider, false));
        channel.bans.clear();
        channel.exceptions.clear();

        channel.modes.invite_only = true;
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(10)),
            ),
            Err(DomainError::Forbidden)
        );
        channel.invite_exceptions.push(crate::ListEntry::new(
            EntryId::from_bytes(bytes(222)),
            TypedMask::parse("$n:test3")?,
            fixture.owner.principal(),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(10)),
            ),
            Ok(None)
        );
        channel.invite_exceptions.clear();
        let invite_id = InviteId::from_bytes(bytes(223));
        channel.invites.insert(
            invite_id,
            Invite {
                invite_id,
                target: fixture.outsider.principal(),
                inviter: fixture.owner.user_id,
                creation_revision: Revision::new(1)?,
                expires_at: MonotonicTick::from_ticks(100),
                expires_at_utc: UtcSecond::from_unix_seconds(610),
            },
        );
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(50)),
            ),
            Ok(Some(invite_id))
        );
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                Some(MonotonicTick::from_ticks(100)),
            ),
            Err(DomainError::Forbidden)
        );
        channel.modes.invite_only = false;
        channel.invites.clear();

        channel.modes.join_key = true;
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                None,
            ),
            Err(DomainError::SecretUnavailable)
        );
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                true,
                false,
                None,
            ),
            Err(DomainError::SecretUnavailable)
        );
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                true,
                true,
                None,
            ),
            Ok(None)
        );
        channel.modes.join_key = false;
        channel.member_limit = Some(2);
        assert_eq!(
            fixture.state.check_join_existing(
                fixture.outsider.user_id,
                fixture.outsider.principal(),
                &channel,
                false,
                true,
                None,
            ),
            Err(DomainError::LimitExceeded)
        );
        channel.member_limit = None;
        fixture.state.channels.insert(fixture.channel_id, channel);

        let mut requests = Vec::new();
        fixture.state.join_requests(
            &[
                crate::ChannelTarget::new(ChannelNameValue::parse("#new-request")?, true),
                crate::ChannelTarget::new(fixture.name.clone(), false),
            ],
            &mut requests,
        )?;
        assert!(requests.iter().any(|request| matches!(
            request,
            ExternalInputRequest::Entropy {
                purpose: EntropyPurpose::ChannelInstance(0),
                ..
            }
        )));
        assert!(requests.iter().any(|request| matches!(
            request,
            ExternalInputRequest::ChannelKeyVerification {
                target_index: 0,
                ..
            }
        )));

        let colliding = fixture.state.plan_join(
            fixture.outsider.user_id,
            fixture.outsider.principal(),
            vec![crate::ChannelTarget::new(
                ChannelNameValue::parse("#collision")?,
                false,
            )],
            Vec::new(),
            ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(20)),
                channel_ids: vec![fixture.channel_id],
                ..ExternalInputs::default()
            },
        );
        assert_eq!(colliding.err(), Some(DomainError::ExternalInputMismatch));

        let repeated_id = ChannelInstanceId::from_bytes(bytes(224));
        let repeated = fixture.state.plan_join(
            fixture.outsider.user_id,
            fixture.outsider.principal(),
            vec![
                crate::ChannelTarget::new(ChannelNameValue::parse("#new-one")?, false),
                crate::ChannelTarget::new(ChannelNameValue::parse("#new-two")?, false),
            ],
            Vec::new(),
            ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(20)),
                channel_ids: vec![repeated_id, repeated_id],
                ..ExternalInputs::default()
            },
        );
        assert_eq!(repeated.err(), Some(DomainError::ExternalInputMismatch));

        let missing_part = fixture.state.plan_part(
            fixture.outsider.user_id,
            vec![ChannelNameValue::parse("#missing-part")?],
            Vec::new(),
        )?;
        assert!(matches!(missing_part, PlanDecision::Rejected(_)));
        let forbidden_part = fixture.state.plan_part(
            fixture.outsider.user_id,
            vec![fixture.name.clone()],
            Vec::new(),
        )?;
        assert!(matches!(forbidden_part, PlanDecision::Rejected(_)));
        Ok(())
    }

    #[test]
    fn remaining_plan_guards_cover_owner_continuity_part_scope_and_extra_entropy()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        assert_eq!(
            fixture
                .state
                .validate_account_deletion_roles(fixture.owner_account),
            Ok(())
        );
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.persistence = PersistencePolicy::Registered;
        channel
            .role_grants
            .insert(fixture.owner_account, Role::Owner);
        assert_eq!(
            fixture
                .state
                .validate_account_deletion_roles(fixture.owner_account),
            Err(DomainError::BadState)
        );
        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .role_grants
            .insert(fixture.member_account, Role::Owner);
        assert_eq!(
            fixture
                .state
                .validate_account_deletion_roles(fixture.owner_account),
            Ok(())
        );

        assert_eq!(
            fixture
                .state
                .plan_nick(
                    fixture.owner.user_id,
                    fixture.member.nickname.clone(),
                    Vec::new(),
                )
                .err(),
            Some(DomainError::BadState)
        );
        let reserved = NicknameValue::parse("member-reserved")?;
        fixture
            .state
            .accounts
            .get_mut(&fixture.member_account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .insert(reserved.clone());
        assert_eq!(
            fixture
                .state
                .plan_nick(fixture.owner.user_id, reserved, Vec::new())
                .err(),
            Some(DomainError::Forbidden)
        );
        assert!(matches!(
            fixture.state.plan_nick(
                fixture.owner.user_id,
                NicknameValue::parse("available-nick")?,
                Vec::new(),
            )?,
            PlanDecision::Mutation(_)
        ));

        assert_eq!(
            fixture
                .state
                .rejected_plan(DomainCommandKind::Part, Vec::new(), Vec::new(), false)
                .err(),
            Some(DomainError::InvariantViolation)
        );

        let local_id = ChannelInstanceId::from_bytes(bytes(230));
        let local = crate::ChannelState::new_ephemeral(
            local_id,
            ChannelNameValue::parse("&local-part")?,
            fixture.outsider.principal(),
            Membership::new(fixture.outsider.user_id, None, Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        );
        fixture.state.apply_join_new(local, Revision::new(1)?);
        let global_id = ChannelInstanceId::from_bytes(bytes(231));
        let global = crate::ChannelState::new_ephemeral(
            global_id,
            ChannelNameValue::parse("#global-part")?,
            fixture.outsider.principal(),
            Membership::new(fixture.outsider.user_id, None, Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        );
        fixture.state.apply_join_new(global, Revision::new(1)?);
        assert_eq!(
            fixture
                .state
                .plan_part_all(fixture.outsider.user_id, Vec::new())
                .err(),
            Some(DomainError::MixedAuthority)
        );
        fixture
            .state
            .apply_part(local_id, fixture.outsider.user_id, Revision::new(1)?);
        let PlanDecision::Mutation(part_plan) = fixture.state.plan_part_ids(
            fixture.outsider.user_id,
            vec![global_id],
            Vec::new(),
            Vec::new(),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert!(
            part_plan
                .events()
                .contains(&DomainEvent::ChannelDestroyed(global_id))
        );

        let message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(fixture.member.nickname.clone())],
            Some(MessageText::parse("extra")?),
        )?;
        assert_eq!(
            fixture
                .state
                .plan_message(
                    fixture.owner.user_id,
                    message,
                    Vec::new(),
                    ExternalInputs {
                        utc_now: Some(UtcSecond::from_unix_seconds(20)),
                        message_ids: vec![
                            MessageId::from_bytes(bytes(232)),
                            MessageId::from_bytes(bytes(233)),
                        ],
                        ..ExternalInputs::default()
                    },
                )
                .err(),
            Some(DomainError::ExternalInputMismatch)
        );
        Ok(())
    }

    #[test]
    fn message_planning_rejects_duplicate_external_ids_without_state_change()
    -> Result<(), DomainError> {
        let fixture = fixture()?;
        let message = MessageCommand::new(
            MessageKind::Privmsg,
            vec![
                MessageTarget::User(fixture.member.nickname.clone()),
                MessageTarget::User(fixture.outsider.nickname.clone()),
            ],
            Some(MessageText::parse("duplicate ID")?),
        )?;
        let duplicate = MessageId::from_bytes(bytes(239));
        let before_revision = fixture.state.revision;
        let before_sessions = fixture.state.session_count();

        assert_eq!(
            fixture
                .state
                .plan_message(
                    fixture.owner.user_id,
                    message,
                    Vec::new(),
                    ExternalInputs {
                        utc_now: Some(UtcSecond::from_unix_seconds(20)),
                        message_ids: vec![duplicate, duplicate],
                        ..ExternalInputs::default()
                    },
                )
                .err(),
            Some(DomainError::ExternalInputMismatch)
        );
        assert_eq!(fixture.state.revision, before_revision);
        assert_eq!(fixture.state.session_count(), before_sessions);
        fixture.state.validate()
    }

    #[test]
    fn invitation_planning_covers_collision_expiry_limits_and_quiet_actor()
    -> Result<(), DomainError> {
        let make_inputs = |invite_id, now| ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(now)),
            utc_now: Some(UtcSecond::from_unix_seconds(10)),
            invite_ids: vec![invite_id],
            ..ExternalInputs::default()
        };

        let mut collision = fixture()?;
        let collision_id = InviteId::from_bytes(bytes(240));
        collision
            .state
            .channels
            .get_mut(&collision.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                collision_id,
                Invite {
                    invite_id: collision_id,
                    target: collision.outsider.principal(),
                    inviter: collision.owner.user_id,
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(100),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );
        assert_eq!(
            collision
                .state
                .plan_invite(
                    collision.owner.user_id,
                    collision.outsider.nickname.clone(),
                    collision.name.clone(),
                    Vec::new(),
                    make_inputs(collision_id, 10),
                )
                .err(),
            Some(DomainError::ExternalInputMismatch)
        );

        let mut expired = fixture()?;
        let expired_id = InviteId::from_bytes(bytes(241));
        expired
            .state
            .channels
            .get_mut(&expired.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                expired_id,
                Invite {
                    invite_id: expired_id,
                    target: expired.outsider.principal(),
                    inviter: expired.owner.user_id,
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(10),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );
        assert!(matches!(
            expired.state.plan_invite(
                expired.owner.user_id,
                expired.outsider.nickname.clone(),
                expired.name.clone(),
                Vec::new(),
                make_inputs(InviteId::from_bytes(bytes(242)), 10),
            )?,
            PlanDecision::Mutation(_)
        ));

        let mut channel_limited = fixture()?;
        let target = channel_limited.outsider.principal();
        let channel = channel_limited
            .state
            .channels
            .get_mut(&channel_limited.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        for index in 0..MAX_INVITES_PER_CHANNEL {
            let mut raw = [0_u8; 16];
            raw[..8].copy_from_slice(
                &u64::try_from(index)
                    .map_err(|_| DomainError::Overflow)?
                    .to_be_bytes(),
            );
            let invite_id = InviteId::from_bytes(raw);
            channel.invites.insert(
                invite_id,
                Invite {
                    invite_id,
                    target,
                    inviter: channel_limited.owner.user_id,
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(1_000),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );
        }
        assert_eq!(
            channel_limited
                .state
                .plan_invite(
                    channel_limited.owner.user_id,
                    channel_limited.outsider.nickname.clone(),
                    channel_limited.name.clone(),
                    Vec::new(),
                    make_inputs(InviteId::from_bytes(bytes(243)), 10),
                )
                .err(),
            Some(DomainError::LimitExceeded)
        );

        let mut principal_limited = fixture()?;
        let target = principal_limited.outsider.principal();
        let channel = principal_limited
            .state
            .channels
            .get_mut(&principal_limited.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        for index in 0..MAX_INVITES_PER_PRINCIPAL {
            let mut raw = [0_u8; 16];
            raw[..8].copy_from_slice(
                &u64::try_from(index)
                    .map_err(|_| DomainError::Overflow)?
                    .to_be_bytes(),
            );
            raw[15] = 1;
            let invite_id = InviteId::from_bytes(raw);
            channel.invites.insert(
                invite_id,
                Invite {
                    invite_id,
                    target,
                    inviter: principal_limited.owner.user_id,
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(1_000),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );
        }
        assert_eq!(
            principal_limited
                .state
                .plan_invite(
                    principal_limited.owner.user_id,
                    principal_limited.outsider.nickname.clone(),
                    principal_limited.name.clone(),
                    Vec::new(),
                    make_inputs(InviteId::from_bytes(bytes(244)), 10),
                )
                .err(),
            Some(DomainError::LimitExceeded)
        );

        let mut quiet = fixture()?;
        quiet
            .state
            .channels
            .get_mut(&quiet.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .bans
            .push(crate::ListEntry::new(
                EntryId::from_bytes(bytes(245)),
                TypedMask::parse("$q:$n:test1")?,
                quiet.owner.principal(),
                UtcSecond::from_unix_seconds(10),
            ));
        assert_eq!(
            quiet
                .state
                .plan_invite(
                    quiet.owner.user_id,
                    quiet.outsider.nickname.clone(),
                    quiet.name.clone(),
                    Vec::new(),
                    make_inputs(InviteId::from_bytes(bytes(246)), 10),
                )
                .err(),
            Some(DomainError::Forbidden)
        );
        Ok(())
    }

    #[test]
    fn network_session_membership_and_role_caps_reject_the_next_entry() -> Result<(), DomainError> {
        assert_eq!(validate_network_invite_capacity(3, 0, 4), Ok(()));
        assert_eq!(
            validate_network_invite_capacity(4, 0, 4),
            Err(DomainError::LimitExceeded)
        );
        assert_eq!(validate_network_invite_capacity(4, 1, 4), Ok(()));
        assert_eq!(
            validate_network_invite_capacity(0, 1, 4),
            Err(DomainError::InvariantViolation)
        );

        let account = account_id(70);
        let mut saturated_account = DomainState::new()?;
        saturated_account.accounts.insert(
            account,
            AccountState::new(
                account,
                agenc_ircd_types::Generation::new(1)?,
                Revision::new(0)?,
            ),
        );
        for index in 0..crate::model::MAX_SESSIONS_PER_ACCOUNT {
            let seed = u8::try_from(index + 40).map_err(|_| DomainError::Overflow)?;
            saturated_account.apply_session(session(seed, Some(account))?, Revision::new(0)?);
        }
        let guest = session(90, None)?;
        let guest_user_id = guest.user_id;
        let guest_generation = guest.generation;
        saturated_account.apply_session(guest, Revision::new(0)?);
        assert_eq!(
            saturated_account
                .plan_session_account_switch(
                    guest_user_id,
                    guest_generation,
                    Some((account, agenc_ircd_types::Generation::new(1)?)),
                )
                .err(),
            Some(DomainError::LimitExceeded)
        );

        {
            let mut fixture = fixture()?;
            let channel = fixture
                .state
                .channels
                .get_mut(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            channel.memberships.clear();
            for index in 0..crate::model::MAX_MEMBERS_PER_CHANNEL {
                let mut raw = [0_u8; 16];
                raw[..8].copy_from_slice(
                    &u64::try_from(index)
                        .map_err(|_| DomainError::Overflow)?
                        .to_be_bytes(),
                );
                raw[15] = 77;
                let user_id = UserId::from_bytes(raw);
                channel
                    .memberships
                    .insert(user_id, Membership::new(user_id, None, Role::Member));
            }
            assert_eq!(
                fixture.state.check_join_existing(
                    fixture.outsider.user_id,
                    fixture.outsider.principal(),
                    fixture
                        .state
                        .channels
                        .get(&fixture.channel_id)
                        .ok_or(DomainError::InvariantViolation)?,
                    false,
                    true,
                    None,
                ),
                Err(DomainError::LimitExceeded)
            );
        }

        {
            let mut fixture = fixture()?;
            let channel = fixture
                .state
                .channels
                .get_mut(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            channel.persistence = PersistencePolicy::Registered;
            channel.role_grants.clear();
            for index in 0..crate::model::MAX_ROLE_GRANTS_PER_CHANNEL {
                let mut raw = [0_u8; 16];
                raw[..8].copy_from_slice(
                    &u64::try_from(index)
                        .map_err(|_| DomainError::Overflow)?
                        .to_be_bytes(),
                );
                raw[15] = 88;
                channel.role_grants.insert(
                    AccountId::from_random(AccountRandomId::from_bytes(raw)),
                    Role::Voice,
                );
            }
            let channel = fixture
                .state
                .channels
                .get(&fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?;
            assert_eq!(
                validate_role_grant_capacity(
                    &fixture.state,
                    channel,
                    &[ModeChange::Role {
                        operation: ModeOperation::Add,
                        target: fixture.member.nickname.clone(),
                        role: Role::Voice,
                    }],
                ),
                Err(DomainError::LimitExceeded)
            );
        }
        Ok(())
    }

    #[test]
    fn remaining_mode_and_request_helpers_cover_successful_fallthroughs() -> Result<(), DomainError>
    {
        let mut fixture = fixture()?;
        let mut channel = fixture
            .state
            .channels
            .remove(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        let duplicate_mask = TypedMask::parse("$n:duplicate-mask")?;
        channel.bans.push(crate::ListEntry::new(
            EntryId::from_bytes(bytes(250)),
            duplicate_mask,
            fixture.owner.principal(),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::Owner,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$n:duplicate-mask")?,
                },
            ),
            Err(DomainError::InvalidArgument)
        );
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::Owner,
                Some(fixture.owner_account),
                &ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                },
            ),
            Ok(())
        );
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::Operator,
                Some(fixture.owner_account),
                &ModeChange::Moderated(true),
            ),
            Ok(())
        );
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::MemberLimit(Some(10)),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::Operator,
                Some(fixture.owner_account),
                &ModeChange::MemberLimit(Some(10)),
            ),
            Ok(())
        );
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::Operator,
                Some(fixture.owner_account),
                &ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$q:$n:quiet-success")?,
                },
            ),
            Ok(())
        );
        let removable_id = EntryId::from_bytes(bytes(251));
        channel.exceptions.push(crate::ListEntry::new(
            removable_id,
            TypedMask::parse("$n:removable")?,
            fixture.owner.principal(),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            validate_mode_change(
                &fixture.state,
                &channel,
                Role::HalfOperator,
                Some(fixture.owner_account),
                &ModeChange::RemoveMask {
                    list: MaskList::Exception,
                    entry_id: removable_id,
                },
            ),
            Ok(())
        );
        assert_eq!(
            validate_role_change(
                &fixture.state,
                &channel,
                Role::Owner,
                ModeOperation::Add,
                &fixture.member.nickname,
                Role::Voice,
            ),
            Ok(())
        );
        channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::InvariantViolation)?
            .effective_role = Role::Voice;
        assert_eq!(
            validate_role_change(
                &fixture.state,
                &channel,
                Role::Owner,
                ModeOperation::Remove,
                &fixture.member.nickname,
                Role::Voice,
            ),
            Ok(())
        );
        assert_eq!(
            validate_role_change(
                &fixture.state,
                &channel,
                Role::Owner,
                ModeOperation::Remove,
                &fixture.member.nickname,
                Role::Operator,
            ),
            Err(DomainError::InvalidArgument)
        );
        channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::InvariantViolation)?
            .effective_role = Role::Member;
        assert_eq!(
            validate_role_change(
                &fixture.state,
                &channel,
                Role::Owner,
                ModeOperation::Remove,
                &fixture.member.nickname,
                Role::Member,
            ),
            Err(DomainError::InvalidArgument)
        );
        assert_eq!(
            validate_owner_continuity(&fixture.state, &channel, &[ModeChange::Moderated(true)],),
            Ok(())
        );
        assert_eq!(
            mode_events(
                &fixture.state,
                &channel,
                &[ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: NicknameValue::parse("missing-mode-target")?,
                    role: Role::Voice,
                }],
            )
            .err(),
            Some(DomainError::NotFound)
        );
        apply_role_change(
            &fixture.state.nicknames,
            &mut channel,
            ModeOperation::Add,
            &fixture.member.nickname,
            Role::Voice,
        );
        assert_eq!(channel.role_of(fixture.member.user_id), Some(Role::Voice));

        let mut requests = Vec::new();
        mode_requests(&[ModeChange::Moderated(true)], &mut requests)?;
        assert!(requests.is_empty());
        mode_requests(
            &[ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:request")?,
            }],
            &mut requests,
        )?;
        assert_eq!(requests.len(), 2);
        let mut message_inputs = Vec::new();
        message_requests(&[], &mut message_inputs)?;
        assert!(message_inputs.is_empty());
        message_requests(&[0, 2], &mut message_inputs)?;
        assert_eq!(message_inputs.len(), 3);
        Ok(())
    }

    #[test]
    fn closed_guards_and_missing_mutation_targets_are_observable() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        assert_eq!(
            fixture.state.require_channel_role(
                &fixture.outsider,
                &fixture.name,
                Role::HalfOperator,
            ),
            Err(DomainError::Forbidden)
        );

        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .content_policy = ContentPolicy::E2eeBound;
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.owner, &fixture.name),
            Err(DomainError::EncryptedRoute)
        );
        assert_eq!(
            validate_guest_join(
                fixture
                    .state
                    .channels
                    .get(&fixture.channel_id)
                    .ok_or(DomainError::InvariantViolation)?,
                fixture.outsider.principal(),
            ),
            Err(DomainError::SecretUnavailable)
        );

        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.content_policy = ContentPolicy::Plaintext;
        channel.modes.moderated = true;
        let member = channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::InvariantViolation)?;
        member.session_role = Role::Member;
        member.effective_role = Role::Voice;
        assert_eq!(
            fixture.state.authorize_channel_message(
                &fixture.member,
                &fixture.name,
                MessageKind::Privmsg,
            ),
            Ok(())
        );

        assert!(matches!(
            fixture.state.plan_kick(
                fixture.owner.user_id,
                fixture.name.clone(),
                vec![fixture.outsider.nickname.clone()],
                Vec::new(),
            ),
            Ok(PlanDecision::Rejected(_))
        ));

        let missing_user = UserId::from_bytes(bytes(99));
        let missing_channel = ChannelInstanceId::from_bytes(bytes(98));
        let revision = Revision::new(2)?;
        fixture.state.apply_session_account_switch(
            missing_user,
            None,
            fixture.outsider.account_session_generation,
            fixture.outsider.generation,
            &[],
            revision,
        );
        fixture
            .state
            .apply_operator_notices(missing_user, true, revision);
        fixture
            .state
            .apply_monitor(missing_user, MonitorChange::Clear, revision);
        fixture.state.destroy_channel(missing_channel);
        fixture.state.apply_session_account_switch(
            fixture.owner.user_id,
            Some(fixture.owner_account),
            fixture.owner.account_session_generation,
            agenc_ircd_types::Generation::new(2)?,
            &[],
            revision,
        );
        fixture
            .state
            .apply_close_session(fixture.outsider.user_id, revision);
        fixture
            .state
            .apply_account_deletion(fixture.member_account, Vec::new(), revision);
        Ok(())
    }

    #[test]
    fn account_switch_contact_and_invite_short_circuits_are_observable() -> Result<(), DomainError>
    {
        let mut fixture = fixture()?;
        assert_eq!(
            fixture
                .state
                .plan_session_account_switch(
                    fixture.owner.user_id,
                    fixture.owner.generation,
                    Some((
                        fixture.owner_account,
                        fixture.owner.account_session_generation,
                    )),
                )
                .err(),
            Some(DomainError::BadState)
        );

        fixture
            .state
            .accounts
            .get_mut(&fixture.member_account)
            .ok_or(DomainError::InvariantViolation)?
            .reserved_nicknames
            .insert(fixture.owner.nickname.clone());
        assert_eq!(
            fixture
                .state
                .plan_session_account_switch(fixture.owner.user_id, fixture.owner.generation, None,)
                .err(),
            Some(DomainError::Forbidden)
        );

        fixture
            .state
            .accounts
            .get_mut(&fixture.owner_account)
            .ok_or(DomainError::InvariantViolation)?
            .direct_messages = DirectMessagePolicy::Contacts;
        assert_eq!(
            authorize_direct_policy(
                &fixture.member,
                fixture
                    .state
                    .accounts
                    .get(&fixture.owner_account)
                    .ok_or(DomainError::InvariantViolation)?,
            ),
            Err(DomainError::Forbidden)
        );

        let invite_id = InviteId::from_bytes(bytes(77));
        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                invite_id,
                Invite {
                    invite_id,
                    target: fixture.outsider.principal(),
                    inviter: fixture.owner.user_id,
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(10),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );
        assert_eq!(
            matching_join_invite(
                fixture
                    .state
                    .channels
                    .get(&fixture.channel_id)
                    .ok_or(DomainError::InvariantViolation)?,
                fixture.outsider.principal(),
                Some(MonotonicTick::from_ticks(1)),
            ),
            Ok(Some(invite_id))
        );
        fixture
            .state
            .apply_close_session(fixture.outsider.user_id, Revision::new(2)?);
        Ok(())
    }

    #[test]
    fn registered_role_removal_updates_grants_and_ignores_nonmembers() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let nicknames = fixture.state.nicknames.clone();
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.persistence = PersistencePolicy::Registered;
        channel
            .role_grants
            .insert(fixture.owner_account, Role::Owner);
        channel
            .role_grants
            .insert(fixture.member_account, Role::Voice);
        for membership in channel.memberships.values_mut() {
            let Some(account_id) = membership.account_id else {
                continue;
            };
            membership.session_role = Role::Member;
            membership.effective_role = channel
                .role_grants
                .get(&account_id)
                .copied()
                .unwrap_or(Role::Member);
        }

        let removal = ModeChange::Role {
            operation: ModeOperation::Remove,
            target: fixture.member.nickname.clone(),
            role: Role::Voice,
        };
        assert_eq!(
            validate_role_grant_capacity(
                &fixture.state,
                fixture
                    .state
                    .channels
                    .get(&fixture.channel_id)
                    .ok_or(DomainError::InvariantViolation)?,
                std::slice::from_ref(&removal),
            ),
            Ok(())
        );

        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        apply_role_change(
            &nicknames,
            channel,
            ModeOperation::Remove,
            &fixture.member.nickname,
            Role::Voice,
        );
        apply_role_change(
            &nicknames,
            channel,
            ModeOperation::Add,
            &fixture.outsider.nickname,
            Role::Voice,
        );
        assert!(!channel.role_grants.contains_key(&fixture.member_account));
        Ok(())
    }

    #[test]
    fn credential_replacement_advances_generation_and_fences_every_session()
    -> Result<(), DomainError> {
        let account_id = account_id(220);
        let generation = agenc_ircd_types::Generation::new(1)?;
        let account_revision = Revision::new(0)?;
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, generation, account_revision),
        );
        let first = session(221, Some(account_id))?;
        let first_user = first.user_id;
        let second = session(222, Some(account_id))?;
        let second_user = second.user_id;
        state.apply_session(first, account_revision);
        state.apply_session(second, account_revision);

        assert_eq!(
            state
                .plan_account_credential_replaced(account_id, generation, Revision::new(9)?,)
                .err(),
            Some(DomainError::StaleRevision)
        );
        let (plan, next_generation) =
            state.plan_account_credential_replaced(account_id, generation, account_revision)?;
        assert_eq!(next_generation, agenc_ircd_types::Generation::new(2)?);
        assert_eq!(plan.events().len(), 3);
        let prepared = state.prepare_mutation(plan)?;
        let receipt = state.apply_prepared(prepared)?;
        assert_eq!(receipt.storage_class(), StorageClass::Durable);
        assert!(!state.sessions.contains_key(&first_user));
        assert!(!state.sessions.contains_key(&second_user));
        let account = state
            .accounts
            .get(&account_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(account.session_generation, next_generation);
        assert_eq!(account.revision, receipt.revision());
        Ok(())
    }

    #[test]
    fn deletion_confirmation_revision_is_rechecked_before_planning() -> Result<(), DomainError> {
        let account_id = account_id(223);
        let generation = agenc_ircd_types::Generation::new(1)?;
        let account_revision = Revision::new(0)?;
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, generation, account_revision),
        );
        state.apply_session(session(224, Some(account_id))?, account_revision);
        assert_eq!(
            state
                .plan_account_deleted_at_revision(account_id, generation, Revision::new(1)?,)
                .err(),
            Some(DomainError::StaleRevision)
        );
        let plan =
            state.plan_account_deleted_at_revision(account_id, generation, account_revision)?;
        assert_eq!(plan.storage_class(), StorageClass::Durable);
        Ok(())
    }

    #[test]
    fn expired_invite_sweep_is_network_wide_bounded_and_preserves_live_invites()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let second_channel_id = ChannelInstanceId::from_bytes(bytes(225));
        let second_channel = crate::ChannelState::new_ephemeral(
            second_channel_id,
            ChannelNameValue::parse("#second")?,
            Principal::Account(fixture.owner_account),
            Membership::new(
                fixture.owner.user_id,
                Some(fixture.owner_account),
                Role::Owner,
            ),
            UtcSecond::from_unix_seconds(10),
            fixture.state.revision,
        );
        fixture
            .state
            .apply_join_new(second_channel, fixture.state.revision);

        let first_expired = InviteId::from_bytes(bytes(226));
        let second_expired = InviteId::from_bytes(bytes(227));
        let live = InviteId::from_bytes(bytes(228));
        let creation_revision = fixture.state.revision;
        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .extend([
                (
                    first_expired,
                    Invite {
                        invite_id: first_expired,
                        target: Principal::Account(fixture.member_account),
                        inviter: fixture.owner.user_id,
                        creation_revision,
                        expires_at: MonotonicTick::from_ticks(5),
                        expires_at_utc: UtcSecond::from_unix_seconds(610),
                    },
                ),
                (
                    live,
                    Invite {
                        invite_id: live,
                        target: Principal::Account(fixture.member_account),
                        inviter: fixture.owner.user_id,
                        creation_revision,
                        expires_at: MonotonicTick::from_ticks(6),
                        expires_at_utc: UtcSecond::from_unix_seconds(610),
                    },
                ),
            ]);
        fixture
            .state
            .channels
            .get_mut(&second_channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                second_expired,
                Invite {
                    invite_id: second_expired,
                    target: Principal::Guest(fixture.outsider.user_id),
                    inviter: fixture.owner.user_id,
                    creation_revision,
                    expires_at: MonotonicTick::from_ticks(4),
                    expires_at_utc: UtcSecond::from_unix_seconds(610),
                },
            );

        let plan = fixture
            .state
            .plan_expired_invites(MonotonicTick::from_ticks(5))?
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(plan.events().len(), 2);
        assert!(
            plan.recipients()
                .iter()
                .any(|user_id| user_id == fixture.owner.user_id)
        );
        assert!(
            plan.recipients()
                .iter()
                .any(|user_id| user_id == fixture.member.user_id)
        );
        assert!(
            plan.recipients()
                .iter()
                .any(|user_id| user_id == fixture.outsider.user_id)
        );
        let prepared = fixture.state.prepare_mutation(plan)?;
        fixture.state.apply_prepared(prepared)?;
        assert_eq!(
            fixture
                .state
                .channel(fixture.channel_id)
                .ok_or(DomainError::InvariantViolation)?
                .pending_invites()
                .map(|(invite_id, ..)| invite_id)
                .collect::<Vec<_>>(),
            vec![live]
        );
        assert_eq!(
            fixture
                .state
                .channel(second_channel_id)
                .ok_or(DomainError::InvariantViolation)?
                .pending_invites()
                .count(),
            0
        );
        assert!(
            fixture
                .state
                .plan_expired_invites(MonotonicTick::from_ticks(5))?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn nickname_and_display_name_changes_emit_distinct_events() -> Result<(), DomainError> {
        let fixture = fixture()?;
        let PlanDecision::Mutation(nickname) = fixture.state.plan_nick(
            fixture.owner.user_id,
            NicknameValue::parse("renamed")?,
            Vec::new(),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            nickname.events(),
            &[DomainEvent::NicknameChanged(fixture.owner.user_id)]
        );
        let PlanDecision::Mutation(display_name) = fixture.state.plan_setname(
            fixture.owner.user_id,
            DisplayNameValue::prepare("Renamed Display")?,
            Vec::new(),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            display_name.events(),
            &[DomainEvent::DisplayNameChanged(fixture.owner.user_id)]
        );
        Ok(())
    }

    #[test]
    fn authenticated_session_open_retains_original_freshness_without_persisting_it()
    -> Result<(), DomainError> {
        let account_id = account_id(227);
        let mut state = DomainState::new()?;
        state.apply_account(
            AccountState::new(
                account_id,
                agenc_ircd_types::Generation::new(1)?,
                state.revision,
            ),
            state.revision,
        );
        let seed = session_seed(228, Some(account_id), 1)?;
        let user_id = seed.user_id;
        let previous_revision = state.revision;
        let plan = state.plan_authenticated_session_opened(seed, MonotonicTick::from_ticks(100))?;
        let prepared = state.prepare_mutation(plan)?;
        state.apply_prepared(prepared)?;
        let session = state
            .session(user_id)
            .ok_or(DomainError::InvariantViolation)?;
        assert_eq!(session.revision(), previous_revision.checked_add(1)?);
        assert_eq!(
            session.fresh_auth_deadline(),
            Some(MonotonicTick::from_ticks(300_100))
        );
        let restored = DurableSession::from_state(session).into_state()?;
        assert_eq!(restored.fresh_auth_deadline(), None);
        assert!(matches!(
            state.plan_account_deletion_start(
                user_id,
                account_id,
                Vec::new(),
                ExternalInputs {
                    monotonic_now: Some(MonotonicTick::from_ticks(300_100)),
                    deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(229))],
                    ..ExternalInputs::default()
                }
            )?,
            PlanDecision::Mutation(_)
        ));
        assert_eq!(
            state
                .plan_account_deletion_start(
                    user_id,
                    account_id,
                    Vec::new(),
                    ExternalInputs {
                        monotonic_now: Some(MonotonicTick::from_ticks(300_101)),
                        deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(229))],
                        ..ExternalInputs::default()
                    }
                )
                .err(),
            Some(DomainError::BadState)
        );
        assert_eq!(
            state
                .plan_authenticated_session_opened(
                    session_seed(226, None, 0)?,
                    MonotonicTick::from_ticks(100)
                )
                .err(),
            Some(DomainError::BadState)
        );
        Ok(())
    }

    #[test]
    fn fresh_authentication_keeps_the_published_session_revision() -> Result<(), DomainError> {
        let (mut state, user_id, account_id) = private_auth_session()?;
        let before = public_session_record(&state, user_id)?;
        let session_generation = state
            .session(user_id)
            .ok_or(DomainError::NotFound)?
            .generation();
        let revision = state.revision();
        let plan = state.plan_session_fresh_authentication(
            user_id,
            account_id,
            session_generation,
            MonotonicTick::from_ticks(200),
        )?;
        assert!(plan.events().is_empty());
        let prepared = state.prepare_mutation(plan)?;
        state.apply_prepared(prepared)?;
        assert_eq!(state.revision(), revision.checked_add(1)?);
        assert!(
            public_session_record(&state, user_id)? == before,
            "private authentication changed the published session record"
        );
        assert_eq!(
            state
                .session(user_id)
                .ok_or(DomainError::NotFound)?
                .fresh_auth_deadline(),
            Some(MonotonicTick::from_ticks(300_200))
        );
        state.validate()?;
        Ok(())
    }

    #[test]
    fn deletion_challenge_keeps_the_published_session_revision_until_confirmation()
    -> Result<(), DomainError> {
        let (mut state, user_id, account_id) = private_auth_session()?;
        let before = public_session_record(&state, user_id)?;
        let revision = state.revision();
        let PlanDecision::Mutation(start) = state.plan_account_deletion_start(
            user_id,
            account_id,
            Vec::new(),
            ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(101)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(231))],
                ..ExternalInputs::default()
            },
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            start.events(),
            &[DomainEvent::AccountDeletionChallengeStarted(user_id)]
        );
        let prepared = state.prepare_mutation(start)?;
        state.apply_prepared(prepared)?;
        assert_eq!(state.revision(), revision.checked_add(1)?);
        assert!(
            public_session_record(&state, user_id)? == before,
            "private authentication changed the published session record"
        );
        assert_eq!(
            state
                .session(user_id)
                .ok_or(DomainError::NotFound)?
                .fresh_auth_deadline(),
            None
        );
        state.validate()?;
        let PlanDecision::Mutation(confirmed) = state.plan_account_deletion_confirm(
            user_id,
            account_id,
            AccountDeletionToken::from_bytes(bytes(231)),
            Vec::new(),
            ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(102)),
                ..ExternalInputs::default()
            },
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            confirmed.events(),
            &[DomainEvent::AccountDeleted(account_id)]
        );
        let prepared = state.prepare_mutation(confirmed)?;
        state.apply_prepared(prepared)?;
        assert!(state.account(account_id).is_none());
        assert!(state.session(user_id).is_none());
        assert!(state.account_deletion_challenges.is_empty());
        state.validate()?;
        Ok(())
    }

    fn private_auth_session() -> Result<(DomainState, UserId, AccountId), DomainError> {
        let account_id = account_id(229);
        let mut state = DomainState::new()?;
        state.apply_account(
            AccountState::new(
                account_id,
                agenc_ircd_types::Generation::new(1)?,
                state.revision,
            ),
            state.revision,
        );
        let seed = session_seed(230, Some(account_id), 1)?;
        let user_id = seed.user_id;
        let plan = state.plan_authenticated_session_opened(seed, MonotonicTick::from_ticks(100))?;
        let prepared = state.prepare_mutation(plan)?;
        state.apply_prepared(prepared)?;
        Ok((state, user_id, account_id))
    }

    fn public_session_record(
        state: &DomainState,
        user_id: UserId,
    ) -> Result<crate::federation::record::SessionRecord, DomainError> {
        let durable = state
            .durable_session(user_id)
            .ok_or(DomainError::NotFound)?;
        Ok(crate::federation::projection::session_record_from(
            &durable, None,
        ))
    }

    #[test]
    fn account_delete_commands_consume_fresh_auth_and_every_confirmation_challenge()
    -> Result<(), DomainError> {
        let account_id = account_id(229);
        let account_generation = agenc_ircd_types::Generation::new(1)?;
        let mut state = DomainState::new()?;
        state.apply_account(
            AccountState::new(account_id, account_generation, state.revision),
            state.revision,
        );
        let live_session = session(230, Some(account_id))?;
        let live_user_id = live_session.user_id;
        state.apply_session(session(230, Some(account_id))?, state.revision);

        let fresh = state.plan_session_fresh_authentication(
            live_user_id,
            account_id,
            live_session.generation,
            MonotonicTick::from_ticks(100),
        )?;
        let prepared = state.prepare_mutation(fresh)?;
        state.apply_prepared(prepared)?;
        let PlanDecision::NeedsExternal(requests) =
            account_command_plan(&state, &live_session, AccountCommand::DeleteStart, None)?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(requests.len(), 2);
        let start = account_command_plan(
            &state,
            &live_session,
            AccountCommand::DeleteStart,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(101)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(231))],
                ..ExternalInputs::default()
            }),
        )?;
        let PlanDecision::Mutation(start) = start else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(start.account_deletion_token(), Some(&bytes(231)));
        assert_eq!(
            start.account_deletion_expires_at(),
            Some(MonotonicTick::from_ticks(60_101))
        );
        let prepared = state.prepare_mutation(start)?;
        state.apply_prepared(prepared)?;
        assert_eq!(
            state
                .session(live_user_id)
                .ok_or(DomainError::InvariantViolation)?
                .fresh_auth_deadline(),
            None
        );
        state.validate()?;
        assert_eq!(
            state
                .plan_session_fresh_authentication(
                    live_user_id,
                    account_id,
                    live_session.generation,
                    MonotonicTick::from_ticks(102),
                )
                .err(),
            Some(DomainError::BadState)
        );

        let rejected = account_command_plan(
            &state,
            &live_session,
            AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(bytes(232))),
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(102)),
                ..ExternalInputs::default()
            }),
        )?;
        let PlanDecision::Mutation(rejected) = rejected else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            rejected.events(),
            &[DomainEvent::AccountDeletionConfirmationRejected(
                live_user_id
            )]
        );
        let prepared = state.prepare_mutation(rejected)?;
        state.apply_prepared(prepared)?;
        assert!(state.account_deletion_challenges.is_empty());
        state.validate()?;

        let fresh = state.plan_session_fresh_authentication(
            live_user_id,
            account_id,
            live_session.generation,
            MonotonicTick::from_ticks(200),
        )?;
        let prepared = state.prepare_mutation(fresh)?;
        state.apply_prepared(prepared)?;
        let PlanDecision::Mutation(start) = account_command_plan(
            &state,
            &live_session,
            AccountCommand::DeleteStart,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(201)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(233))],
                ..ExternalInputs::default()
            }),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        let prepared = state.prepare_mutation(start)?;
        state.apply_prepared(prepared)?;
        let fresh = state.plan_session_fresh_authentication(
            live_user_id,
            account_id,
            live_session.generation,
            MonotonicTick::from_ticks(60_201),
        )?;
        let prepared = state.prepare_mutation(fresh)?;
        state.apply_prepared(prepared)?;
        assert!(state.account_deletion_challenges.is_empty());
        let PlanDecision::Mutation(start) = account_command_plan(
            &state,
            &live_session,
            AccountCommand::DeleteStart,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(60_202)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(234))],
                ..ExternalInputs::default()
            }),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        let prepared = state.prepare_mutation(start)?;
        state.apply_prepared(prepared)?;
        let PlanDecision::Mutation(confirmed) = account_command_plan(
            &state,
            &live_session,
            AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(bytes(234))),
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(60_203)),
                ..ExternalInputs::default()
            }),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            confirmed.events(),
            &[DomainEvent::AccountDeleted(account_id)]
        );
        let prepared = state.prepare_mutation(confirmed)?;
        state.apply_prepared(prepared)?;
        assert!(state.account(account_id).is_none());
        assert!(state.session(live_user_id).is_none());
        assert!(state.account_deletion_challenges.is_empty());
        state.validate()?;
        Ok(())
    }

    #[test]
    fn account_delete_start_defers_state_preconditions_until_confirmation()
    -> Result<(), DomainError> {
        let account_id = account_id(235);
        let account_generation = agenc_ircd_types::Generation::new(1)?;
        let mut state = DomainState::new()?;
        state.apply_account(
            AccountState::new(account_id, account_generation, state.revision),
            state.revision,
        );
        let confirming_session = session(236, Some(account_id))?;
        let confirming_user_id = confirming_session.user_id;
        state.apply_session(session(236, Some(account_id))?, state.revision);
        state.apply_session(session(237, Some(account_id))?, state.revision);

        let fresh = state.plan_session_fresh_authentication(
            confirming_user_id,
            account_id,
            confirming_session.generation,
            MonotonicTick::from_ticks(100),
        )?;
        let prepared = state.prepare_mutation(fresh)?;
        state.apply_prepared(prepared)?;

        let PlanDecision::Mutation(start) = account_command_plan(
            &state,
            &confirming_session,
            AccountCommand::DeleteStart,
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(101)),
                deletion_tokens: vec![AccountDeletionToken::from_bytes(bytes(238))],
                ..ExternalInputs::default()
            }),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        let prepared = state.prepare_mutation(start)?;
        state.apply_prepared(prepared)?;
        assert_eq!(state.account_deletion_challenges.len(), 1);

        let PlanDecision::Mutation(rejected) = account_command_plan(
            &state,
            &confirming_session,
            AccountCommand::DeleteConfirm(AccountDeletionToken::from_bytes(bytes(238))),
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(102)),
                ..ExternalInputs::default()
            }),
        )?
        else {
            return Err(DomainError::InvariantViolation);
        };
        assert_eq!(
            rejected.events(),
            &[DomainEvent::AccountDeletionConfirmationRejected(
                confirming_user_id
            )]
        );
        let prepared = state.prepare_mutation(rejected)?;
        state.apply_prepared(prepared)?;

        assert!(state.account_deletion_challenges.is_empty());
        assert!(state.account(account_id).is_some());
        state.validate()?;
        Ok(())
    }

    #[test]
    fn authorization_fences_user_modes_and_channel_privacy_cover_each_outcome()
    -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let wrong_generation = CommandEnvelope::new(
            fixture.owner.session_id,
            fixture.owner.user_id,
            agenc_ircd_types::Generation::new(2)?,
            fixture.state.revision,
            CanonicalCommand::list(Vec::new())?,
        );
        assert_eq!(
            fixture
                .state
                .authorize(wrong_generation, &admission(fixture.owner.user_id)?,)
                .err()
                .map(|failure| failure.error()),
            Some(DomainError::StaleGeneration)
        );

        for command in [
            CanonicalCommand::user_mode_query(fixture.owner.nickname.clone()),
            CanonicalCommand::user_operator_notices(fixture.owner.nickname.clone(), true),
        ] {
            assert!(
                fixture
                    .state
                    .authorize(
                        envelope(&fixture.owner, fixture.state.revision, command),
                        &admission(fixture.owner.user_id)?,
                    )
                    .is_ok()
            );
        }
        for command in [
            CanonicalCommand::user_mode_query(fixture.member.nickname.clone()),
            CanonicalCommand::user_operator_notices(fixture.member.nickname.clone(), true),
        ] {
            assert_eq!(
                fixture
                    .state
                    .authorize(
                        envelope(&fixture.owner, fixture.state.revision, command),
                        &admission(fixture.owner.user_id)?,
                    )
                    .err()
                    .map(|failure| failure.error()),
                Some(DomainError::Forbidden)
            );
        }

        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .visibility = Visibility::Unlisted;
        assert_eq!(
            fixture
                .state
                .privacy_safe_channel(&fixture.outsider, &fixture.name)
                .err(),
            Some(DomainError::SecretUnavailable)
        );
        assert!(
            fixture
                .state
                .privacy_safe_channel(&fixture.owner, &fixture.name)
                .is_ok()
        );

        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.visibility = Visibility::Listed;
        channel.modes.topic_protected = false;
        assert_eq!(
            fixture
                .state
                .require_channel_role(&fixture.outsider, &fixture.name, Role::Member),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            fixture
                .state
                .authorize_topic_change(&fixture.member, &fixture.name),
            Ok(())
        );

        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .persistence = PersistencePolicy::Registered;
        assert_eq!(
            fixture
                .state
                .validate_account_deletion_roles(fixture.owner_account),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn e2ee_message_authorization_rejects_each_binding_and_policy_failure()
    -> Result<(), DomainError> {
        let plaintext_fixture = fixture()?;
        let revision = plaintext_fixture
            .state
            .channel(plaintext_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .revision();
        let proof = crate::E2eeApplicationProof::new(
            plaintext_fixture.channel_id,
            plaintext_fixture.owner.user_id,
            revision,
        );
        assert_eq!(
            plaintext_fixture.state.authorize_e2ee_channel_message(
                &plaintext_fixture.owner,
                &plaintext_fixture.name,
                proof,
            ),
            Err(DomainError::PlaintextRoute)
        );

        let mut e2ee_fixture = fixture()?;
        e2ee_fixture
            .state
            .channels
            .get_mut(&e2ee_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .content_policy = ContentPolicy::E2eeBound;
        let revision = e2ee_fixture
            .state
            .channel(e2ee_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .revision();
        assert_eq!(
            e2ee_fixture.state.authorize_e2ee_channel_message(
                &e2ee_fixture.owner,
                &e2ee_fixture.name,
                crate::E2eeApplicationProof::new(
                    ChannelInstanceId::from_bytes(bytes(250)),
                    e2ee_fixture.owner.user_id,
                    revision,
                ),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            e2ee_fixture.state.authorize_e2ee_channel_message(
                &e2ee_fixture.owner,
                &e2ee_fixture.name,
                crate::E2eeApplicationProof::new(
                    e2ee_fixture.channel_id,
                    e2ee_fixture.member.user_id,
                    revision,
                ),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            e2ee_fixture.state.authorize_e2ee_channel_message(
                &e2ee_fixture.owner,
                &e2ee_fixture.name,
                crate::E2eeApplicationProof::new(
                    e2ee_fixture.channel_id,
                    e2ee_fixture.owner.user_id,
                    revision.checked_add(1)?,
                ),
            ),
            Err(DomainError::StaleRevision)
        );

        e2ee_fixture
            .state
            .channels
            .get_mut(&e2ee_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .e2ee_removal_pending
            .insert(e2ee_fixture.member.user_id);
        assert_eq!(
            e2ee_fixture.state.authorize_e2ee_channel_message(
                &e2ee_fixture.owner,
                &e2ee_fixture.name,
                proof,
            ),
            Err(DomainError::BadState)
        );

        let channel = e2ee_fixture
            .state
            .channels
            .get_mut(&e2ee_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.e2ee_removal_pending.clear();
        channel.bans.push(crate::ListEntry::new(
            EntryId::from_bytes(bytes(251)),
            TypedMask::parse("$q:$n:test1")?,
            Principal::Account(e2ee_fixture.owner_account),
            UtcSecond::from_unix_seconds(10),
        ));
        assert_eq!(
            e2ee_fixture.state.authorize_e2ee_channel_message(
                &e2ee_fixture.owner,
                &e2ee_fixture.name,
                proof,
            ),
            Err(DomainError::Forbidden)
        );

        let mut moderated_fixture = fixture()?;
        let channel = moderated_fixture
            .state
            .channels
            .get_mut(&moderated_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.content_policy = ContentPolicy::E2eeBound;
        channel.modes.moderated = true;
        let revision = channel.revision;
        assert_eq!(
            moderated_fixture.state.authorize_e2ee_channel_message(
                &moderated_fixture.member,
                &moderated_fixture.name,
                crate::E2eeApplicationProof::new(
                    moderated_fixture.channel_id,
                    moderated_fixture.member.user_id,
                    revision,
                ),
            ),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            moderated_fixture.state.authorize_e2ee_channel_message(
                &moderated_fixture.outsider,
                &moderated_fixture.name,
                crate::E2eeApplicationProof::new(
                    moderated_fixture.channel_id,
                    moderated_fixture.outsider.user_id,
                    revision,
                ),
            ),
            Err(DomainError::Forbidden)
        );

        moderated_fixture
            .state
            .channels
            .get_mut(&moderated_fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .modes
            .moderated = false;
        assert_eq!(
            moderated_fixture.state.authorize_e2ee_channel_message(
                &moderated_fixture.owner,
                &moderated_fixture.name,
                crate::E2eeApplicationProof::new(
                    moderated_fixture.channel_id,
                    moderated_fixture.owner.user_id,
                    revision,
                ),
            ),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn e2ee_moderation_allows_voice_or_higher() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let channel = fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?;
        channel.content_policy = ContentPolicy::E2eeBound;
        channel.modes.moderated = true;
        let revision = channel.revision;
        assert_eq!(
            fixture.state.authorize_e2ee_channel_message(
                &fixture.owner,
                &fixture.name,
                crate::E2eeApplicationProof::new(
                    fixture.channel_id,
                    fixture.owner.user_id,
                    revision,
                ),
            ),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn mask_list_entries_record_the_operator_that_added_them() -> Result<(), DomainError> {
        let mut fixture = fixture()?;
        let state = &mut fixture.state;
        let channel = state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::NotFound)?;
        let membership = channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::NotFound)?;
        membership.session_role = Role::Operator;
        membership.effective_role = Role::Operator;
        let command = CanonicalCommand::mode(
            fixture.name.clone(),
            vec![ModeChange::AddMask {
                list: MaskList::Ban,
                mask: TypedMask::parse("$n:troll")?,
            }],
        )?;
        let authorized = state
            .authorize(
                envelope(&fixture.member, state.revision, command),
                &admission(fixture.member.user_id)?,
            )
            .map_err(|failure| failure.error())?;
        let inputs = ExternalInputs {
            utc_now: Some(UtcSecond::from_unix_seconds(20)),
            entry_ids: vec![EntryId::from_bytes(bytes(90))],
            ..ExternalInputs::default()
        };
        let PlanDecision::Mutation(plan) = state.plan_authorized(authorized, Some(inputs))? else {
            return Err(DomainError::InvariantViolation);
        };
        let prepared = state.prepare_mutation(plan)?;
        state.apply_prepared(prepared)?;
        let entry = state
            .channel(fixture.channel_id)
            .and_then(|channel| channel.mask_list(MaskList::Ban).first())
            .ok_or(DomainError::NotFound)?;
        assert_eq!(entry.setter(), Principal::Account(fixture.member_account));
        assert_ne!(entry.setter(), Principal::Account(fixture.owner_account));
        assert_eq!(entry.created_at(), UtcSecond::from_unix_seconds(20));
        Ok(())
    }
    #[test]
    fn history_authorization_rechecks_membership_and_every_channel_guard() -> Result<(), DomainError>
    {
        let mut fixture = fixture()?;
        let id = fixture.channel_id;
        assert_eq!(
            fixture
                .state
                .authorize_history(&fixture.member, ChannelInstanceId::from_bytes([255; 16])),
            Err(DomainError::NotFound)
        );
        assert_eq!(
            fixture.state.authorize_history(&fixture.outsider, id),
            Err(DomainError::Forbidden)
        );
        assert_eq!(
            fixture.state.authorize_history(&fixture.member, id),
            Err(DomainError::BadState)
        );
        for variant in 0..5 {
            let channel = fixture
                .state
                .channels
                .get_mut(&id)
                .ok_or(DomainError::NotFound)?;
            channel.history = HistoryPolicy::OneHour;
            channel.content_policy = if variant == 0 {
                ContentPolicy::E2eeBound
            } else {
                ContentPolicy::Plaintext
            };
            channel.visibility = if variant == 1 {
                Visibility::Secret
            } else {
                Visibility::Listed
            };
            channel.persistence = if variant == 2 {
                PersistencePolicy::Ephemeral
            } else {
                PersistencePolicy::Registered
            };
            channel.scope = if variant == 3 {
                crate::ChannelScope::Local
            } else {
                crate::ChannelScope::Global
            };
            let expected = match variant {
                0 => Err(DomainError::EncryptedRoute),
                1..=3 => Err(DomainError::BadState),
                _ => Ok(()),
            };
            assert_eq!(
                fixture.state.authorize_history(&fixture.member, id),
                expected
            );
        }
        Ok(())
    }

    #[path = "authority_fences.rs"]
    mod authority_fences;
}

#[cfg(test)]
#[path = "decision/tests/advertised_scans.rs"]
mod advertised_scans;
