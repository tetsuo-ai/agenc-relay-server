//! Revision-fenced authorization, external requests, and pure plans.

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_types::{
    AccountDeletionToken, AccountId, ChannelInstanceId, EntryId, InviteId, MaskSubject, MessageId,
    MonotonicTick, Revision, TypedMask, UserId, UtcSecond,
};

use crate::command::{CanonicalCommandData, MaskList, MessageTarget};
use crate::model::{
    Invite, MAX_CHANNELS_PER_SESSION, MAX_CONTACTS_PER_ACCOUNT, MAX_INVITES_PER_CHANNEL,
    MAX_INVITES_PER_PRINCIPAL,
};
use crate::{
    AccountCommand, AccountState, CanonicalCommand, ChannelCommand, ChannelNameValue,
    CommandEnvelope, ContentPolicy, DirectMessagePolicy, DisplayNameValue, DomainCommandKind,
    DomainError, DomainState, GuestDirectMessagePolicy, HistoryPolicy, Membership, MessageKind,
    ModeChange, ModeCommand, ModeOperation, ModerationAction, ModerationReasonCode, NicknameValue,
    PersistencePolicy, PlaintextTopic, PresenceCommand, PresencePolicy, Principal, Role, Sanction,
    SessionSeed, SessionState, TopicText, Visibility,
};

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

    fn admits(&self, charges: &[RateCharge]) -> bool {
        charges.iter().all(|charge| {
            self.available
                .get(&charge.bucket)
                .is_some_and(|available| *available >= charge.tokens)
        })
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

impl AuthorizedCommand {
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
    /// One session and all live memberships were removed.
    SessionHidden(UserId),
    /// One nickname mapping changed without changing User ID.
    NicknameChanged(UserId),
    /// One per-session away value changed.
    AwayChanged(UserId),
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
        changes: Vec<ModeChange>,
        entry_ids: Vec<EntryId>,
        created_at: Option<UtcSecond>,
    },
    AccountSetting {
        account_id: AccountId,
        setting: AccountSetting,
    },
    ChannelSetting(ChannelCommand),
    CreateInvite {
        channel_id: ChannelInstanceId,
        invite: Invite,
        expired_invites: Vec<InviteId>,
    },
    MarkRemovalPending {
        channel_id: ChannelInstanceId,
        user_id: UserId,
    },
    AddSanction(Sanction),
    EventOnly,
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
}

impl MutationPlan {
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
        self.validate_session_seed(&seed)?;
        let user_id = seed.user_id;
        let mut recipients = RecipientSet::new();
        recipients.insert(user_id);
        self.single_mutation(
            Mutation::InsertSession(SessionState::from_seed(seed)),
            DomainEvent::SessionOpened(user_id),
            recipients,
            Vec::new(),
            StorageClass::Ephemeral,
        )
    }

    /// Plans an authentication-proved guest/account authority replacement.
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
        let (account_id, account_session_generation) =
            self.resolve_switch_account(session.account_id, account)?;
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
            if live >= crate::model::MAX_SESSIONS_PER_ACCOUNT {
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

    /// Computes or completes a pure command plan from explicit external inputs.
    pub fn plan_authorized(
        &self,
        authorized: AuthorizedCommand,
        external: Option<ExternalInputs>,
    ) -> Result<PlanDecision, DomainError> {
        if authorized.expected_state_revision != self.revision {
            return Err(DomainError::StaleRevision);
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
        Ok(MutationPlan {
            expected_revision: self.revision,
            resulting_revision: next,
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
        if live >= crate::model::MAX_SESSIONS_PER_ACCOUNT {
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
        if session.session_id != envelope.session_id()
            || session.generation != envelope.session_generation()
        {
            return Err(DomainError::StaleGeneration);
        }
        if !admission.admits(charges) {
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
        kind: MessageKind,
    ) -> Result<(), DomainError> {
        let channel = self.privacy_safe_channel(sender, name)?;
        let Some(role) = channel.role_of(sender.user_id) else {
            return Err(DomainError::Forbidden);
        };
        if effective_mask(channel, sender, true) {
            return Err(DomainError::Forbidden);
        }
        match (channel.content_policy, kind) {
            (ContentPolicy::E2eeBound, MessageKind::Privmsg | MessageKind::Notice) => {
                return Err(DomainError::EncryptedRoute);
            }
            (ContentPolicy::Plaintext, MessageKind::Tagmsg) => {
                return Err(DomainError::PlaintextRoute);
            }
            _ => {}
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
        if channel.history == HistoryPolicy::Off {
            return Err(DomainError::BadState);
        }
        Ok(())
    }

    fn assess_charges(&self, user_id: UserId, command: &CanonicalCommand) -> Vec<RateCharge> {
        let mut charges = Vec::new();
        charges.push(rate_charge(RateBucket::RegisteredCommand(user_id)));
        if is_expensive_query(command.kind()) {
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
            match self.authorize_message_target(sender, target, message.kind()) {
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
        kind: MessageKind,
    ) -> Result<(), DomainError> {
        match target {
            MessageTarget::Channel(name) => self.authorize_channel_message(sender, name, kind),
            MessageTarget::User(nickname) => self.authorize_direct_message(sender, nickname),
        }
    }

    fn join_requests(
        &self,
        targets: &[crate::ChannelTarget],
        requests: &mut Vec<ExternalInputRequest>,
    ) -> Result<(), DomainError> {
        if targets
            .iter()
            .any(|target| !self.channel_names.contains_key(target.name()))
        {
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
                self.plan_modes(user_id, name, changes, charges, inputs)
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
                self.plan_account(user_id, principal, account, charges)
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
            StorageClass::Ephemeral,
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
        if resulting_memberships >= MAX_CHANNELS_PER_SESSION {
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
            let membership =
                Membership::new(plan.user_id, plan.principal.account_id(), Role::Member);
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
        let created_at = plan.utc.ok_or(DomainError::ExternalInputMismatch)?;
        let revision = crate::model::next_revision(self.revision)?;
        let membership = Membership::new(plan.user_id, plan.principal.account_id(), Role::Owner);
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
        if channel.memberships.len() >= crate::model::MAX_MEMBERS_PER_CHANNEL {
            return Err(DomainError::LimitExceeded);
        }
        let session = self.sessions.get(&user_id).ok_or(DomainError::NotFound)?;
        validate_guest_join(channel, principal)?;
        if effective_mask(channel, session, false) {
            return Err(DomainError::Forbidden);
        }
        let matching_invite = matching_join_invite(channel, principal, now)?;
        validate_join_admission(channel, session, matching_invite, key_supplied, key_ok)?;
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
            mutations.push(Mutation::Part {
                channel_id,
                user_id,
            });
            events.push(DomainEvent::Parted(channel_id, user_id));
            if channel.memberships.len() == 1 && channel.persistence == PersistencePolicy::Ephemeral
            {
                events.push(DomainEvent::ChannelDestroyed(channel_id));
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
                changes,
                entry_ids: inputs.entry_ids,
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
        if active >= MAX_INVITES_PER_CHANNEL {
            return Err(DomainError::LimitExceeded);
        }
        let network_total = self.channels.values().try_fold(0_usize, |total, current| {
            total.checked_add(current.invites.len())
        });
        validate_network_invite_capacity(
            network_total.ok_or(DomainError::Overflow)?,
            expired.len(),
            crate::model::MAX_INVITES_NETWORK_WIDE,
        )?;
        let target_count = self
            .channels
            .values()
            .flat_map(|current| current.invites.values())
            .filter(|invite| invite.target == target && now < invite.expires_at)
            .count();
        if target_count >= MAX_INVITES_PER_PRINCIPAL {
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
        if resolved_routes.len() != inputs.message_ids.len() {
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
        let (message_kind, _targets, body) = message.into_parts();
        self.message_plan(
            events,
            recipients,
            failures,
            MessageBatch {
                kind: message_kind,
                sender: user_id,
                body,
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
            StorageClass::Ephemeral,
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
            Vec::new(),
            recipients,
            charges,
            StorageClass::Ephemeral,
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
            vec![DomainEvent::NicknameChanged(user_id)],
            recipients,
            charges,
            StorageClass::Ephemeral,
        )
    }

    fn plan_account(
        &self,
        _user_id: UserId,
        principal: Principal,
        command: AccountCommand,
        charges: Vec<RateCharge>,
    ) -> Result<PlanDecision, DomainError> {
        let account_id = principal
            .account_id()
            .ok_or(DomainError::RegistrationRequired)?;
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
        Ok(MutationPlan {
            expected_revision: self.revision,
            resulting_revision: crate::model::next_revision(self.revision)?,
            mutations: vec![mutation],
            events: vec![event],
            recipients,
            failures: Vec::new(),
            message_batch: None,
            charges,
            storage,
        })
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
        Ok(PlanDecision::Mutation(MutationPlan {
            expected_revision: self.revision,
            resulting_revision: crate::model::next_revision(self.revision)?,
            mutations,
            events,
            recipients,
            failures,
            message_batch: None,
            charges,
            storage,
        }))
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
        Ok(PlanDecision::Mutation(MutationPlan {
            expected_revision: self.revision,
            resulting_revision: crate::model::next_revision(self.revision)?,
            mutations: vec![Mutation::EventOnly],
            events,
            recipients,
            failures,
            message_batch: Some(message_batch),
            charges,
            storage: StorageClass::Durable,
        }))
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
                changes,
                entry_ids,
                created_at,
            } => {
                self.apply_modes(channel_id, changes, entry_ids, created_at, revision);
            }
            Mutation::AccountSetting {
                account_id,
                setting,
            } => {
                self.apply_account_setting(account_id, setting, revision);
            }
            Mutation::ChannelSetting(command) => self.apply_channel_setting(command, revision),
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
        if let Some(session) = self.sessions.get_mut(&user_id) {
            session.account_id = account_id;
            session.account_session_generation = account_session_generation;
            session.generation = session_generation;
            session.revision = revision;
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

    fn apply_monitor(&mut self, user_id: UserId, change: MonitorChange, revision: Revision) {
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
        session.revision = revision;
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
        self.session_ids.remove(&session.session_id);
        self.nicknames.remove(&session.nickname);
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

    fn apply_modes(
        &mut self,
        channel_id: ChannelInstanceId,
        changes: Vec<ModeChange>,
        entry_ids: Vec<EntryId>,
        created_at: Option<UtcSecond>,
        revision: Revision,
    ) {
        let mut entry_ids = entry_ids.into_iter();
        for change in changes {
            self.apply_mode_change(channel_id, change, &mut entry_ids, created_at);
        }
        self.recompute_channel_roles(channel_id, revision);
    }

    fn apply_mode_change(
        &mut self,
        channel_id: ChannelInstanceId,
        change: ModeChange,
        entry_ids: &mut impl Iterator<Item = EntryId>,
        created_at: Option<UtcSecond>,
    ) {
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return;
        };
        match change {
            ModeChange::Visibility(visibility) => channel.visibility = visibility,
            ModeChange::InviteOnly(value) => channel.modes.invite_only = value,
            ModeChange::Moderated(value) => channel.modes.moderated = value,
            ModeChange::TopicProtected(value) => channel.modes.topic_protected = value,
            ModeChange::JoinKey(value) => channel.modes.join_key = value,
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
                    let entry = crate::ListEntry::new(
                        entry_id,
                        mask,
                        channel.creator,
                        created_at.unwrap_or(channel.created_at),
                    );
                    mask_list_mut(channel, list).push(entry);
                }
            }
            ModeChange::RemoveMask { list, entry_id } => {
                mask_list_mut(channel, list).retain(|entry| entry.entry_id != entry_id);
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
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return;
        };
        match command {
            ChannelCommand::Register(_) => register_channel_roles(channel),
            ChannelCommand::Unregister(_) => unregister_channel_roles(channel),
            ChannelCommand::History(_, history) => channel.history = history,
            ChannelCommand::Content(_, content) => channel.content_policy = content,
        }
        channel.revision = revision;
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
        membership.effective_role = std::cmp::max(membership.session_role, grant);
    }
    channel.persistence = PersistencePolicy::Registered;
}

fn unregister_channel_roles(channel: &mut crate::ChannelState) {
    for membership in channel.memberships.values_mut() {
        membership.session_role = membership.effective_role;
    }
    channel.role_grants.clear();
    channel.persistence = PersistencePolicy::Ephemeral;
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

fn is_expensive_query(kind: DomainCommandKind) -> bool {
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
    push_request(requests, RequestShape::Entropy(EntropyPurpose::Invite, 16))
}

fn mode_requests(
    changes: &[ModeChange],
    requests: &mut Vec<ExternalInputRequest>,
) -> Result<(), DomainError> {
    let mut needs_utc = false;
    for (index, change) in changes.iter().enumerate() {
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

fn invite_expiry(now: MonotonicTick) -> Result<MonotonicTick, DomainError> {
    let ticks = now
        .get()
        .checked_add(600_000)
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

fn validate_join_admission(
    channel: &crate::ChannelState,
    session: &SessionState,
    matching_invite: Option<InviteId>,
    key_supplied: bool,
    key_ok: bool,
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
    if channel
        .member_limit
        .is_some_and(|limit| channel.memberships.len() >= usize::from(limit))
    {
        return Err(DomainError::LimitExceeded);
    }
    if channel.content_policy == ContentPolicy::E2eeBound && session.account_id.is_none() {
        return Err(DomainError::RegistrationRequired);
    }
    Ok(())
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
    let mut unique_entry_ids = BTreeSet::new();
    for entry_id in entry_ids {
        if !unique_entry_ids.insert(*entry_id)
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
    for change in changes {
        validate_mode_change(state, channel, actor_role, actor_account, change)?;
    }
    validate_role_grant_capacity(state, channel, changes)?;
    validate_owner_continuity(state, channel, changes)
}

fn validate_role_grant_capacity(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<(), DomainError> {
    if channel.persistence != PersistencePolicy::Registered {
        return Ok(());
    }
    let mut grants: BTreeSet<AccountId> = channel.role_grants.keys().copied().collect();
    for change in changes {
        let ModeChange::Role {
            operation,
            target,
            role,
        } = change
        else {
            continue;
        };
        let user_id = state.nicknames.get(target).ok_or(DomainError::NotFound)?;
        let account_id = state
            .sessions
            .get(user_id)
            .and_then(|session| session.account_id)
            .ok_or(DomainError::RegistrationRequired)?;
        let next = match operation {
            ModeOperation::Add => *role,
            ModeOperation::Remove => role.next_lower().ok_or(DomainError::InvalidArgument)?,
        };
        if next == Role::Member {
            grants.remove(&account_id);
        } else {
            grants.insert(account_id);
        }
        if grants.len() > crate::model::MAX_ROLE_GRANTS_PER_CHANNEL {
            return Err(DomainError::LimitExceeded);
        }
    }
    Ok(())
}

fn validate_mode_change(
    state: &DomainState,
    channel: &crate::ChannelState,
    actor_role: Role,
    actor_account: Option<AccountId>,
    change: &ModeChange,
) -> Result<(), DomainError> {
    match change {
        ModeChange::Visibility(Visibility::Secret) => {
            validate_secret_visibility(actor_role, actor_account)
        }
        ModeChange::Visibility(_)
        | ModeChange::InviteOnly(_)
        | ModeChange::Moderated(_)
        | ModeChange::JoinKey(_) => require_role(actor_role, Role::Operator),
        ModeChange::MemberLimit(Some(0)) => Err(DomainError::InvalidArgument),
        ModeChange::TopicProtected(_) | ModeChange::MemberLimit(_) => {
            require_role(actor_role, Role::HalfOperator)
        }
        ModeChange::Role {
            operation,
            target,
            role,
        } => validate_role_change(state, channel, actor_role, *operation, target, *role),
        ModeChange::AddMask { list, mask } => validate_mask_add(channel, actor_role, *list, mask),
        ModeChange::RemoveMask { list, entry_id } => {
            validate_mask_remove(channel, actor_role, *list, *entry_id)
        }
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

fn validate_mask_add(
    channel: &crate::ChannelState,
    actor_role: Role,
    list: MaskList,
    mask: &TypedMask,
) -> Result<(), DomainError> {
    if mask.is_quiet() && list != MaskList::Ban {
        return Err(DomainError::InvalidArgument);
    }
    let required = if mask.is_quiet() {
        Role::Operator
    } else {
        Role::HalfOperator
    };
    require_role(actor_role, required)?;
    let entries = mask_list(channel, list);
    if entries.len() >= crate::model::MAX_MASK_ENTRIES_PER_LIST {
        return Err(DomainError::LimitExceeded);
    }
    if entries.iter().any(|entry| entry.mask == *mask) {
        return Err(DomainError::InvalidArgument);
    }
    Ok(())
}

fn validate_mask_remove(
    channel: &crate::ChannelState,
    actor_role: Role,
    list: MaskList,
    entry_id: EntryId,
) -> Result<(), DomainError> {
    require_role(actor_role, Role::HalfOperator)?;
    let entry = mask_list(channel, list)
        .iter()
        .find(|entry| entry.entry_id == entry_id)
        .ok_or(DomainError::InvalidArgument)?;
    if entry.is_quiet() {
        require_role(actor_role, Role::Operator)?;
    }
    Ok(())
}

fn validate_role_change(
    state: &DomainState,
    channel: &crate::ChannelState,
    actor_role: Role,
    operation: ModeOperation,
    target: &NicknameValue,
    role: Role,
) -> Result<(), DomainError> {
    if !actor_role.can_grant(role) {
        return Err(DomainError::Forbidden);
    }
    let target_user = state.nicknames.get(target).ok_or(DomainError::NotFound)?;
    let current = channel.role_of(*target_user).ok_or(DomainError::NotFound)?;
    match operation {
        ModeOperation::Add if role <= current => Err(DomainError::InvalidArgument),
        ModeOperation::Remove if role != current || role.next_lower().is_none() => {
            Err(DomainError::InvalidArgument)
        }
        _ => Ok(()),
    }
}

fn validate_owner_continuity(
    state: &DomainState,
    channel: &crate::ChannelState,
    changes: &[ModeChange],
) -> Result<(), DomainError> {
    if channel.persistence != PersistencePolicy::Registered {
        return Ok(());
    }
    let mut owners = channel
        .role_grants
        .values()
        .filter(|role| **role == Role::Owner)
        .count();
    for change in changes {
        let ModeChange::Role {
            operation,
            target,
            role,
        } = change
        else {
            continue;
        };
        let Some(user_id) = state.nicknames.get(target) else {
            return Err(DomainError::NotFound);
        };
        let account_id = state
            .sessions
            .get(user_id)
            .and_then(|session| session.account_id)
            .ok_or(DomainError::RegistrationRequired)?;
        let prior = channel
            .role_grants
            .get(&account_id)
            .copied()
            .unwrap_or(Role::Member);
        if prior == Role::Owner {
            owners = owners.saturating_sub(1);
        }
        let next = match operation {
            ModeOperation::Add => *role,
            ModeOperation::Remove => role.next_lower().ok_or(DomainError::InvalidArgument)?,
        };
        if next == Role::Owner {
            owners = owners.checked_add(1).ok_or(DomainError::Overflow)?;
        }
    }
    if owners == 0 {
        return Err(DomainError::BadState);
    }
    Ok(())
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
    let Some(membership) = channel.memberships.get_mut(&user_id) else {
        return;
    };
    let next = match operation {
        ModeOperation::Add => role,
        ModeOperation::Remove => role.next_lower().unwrap_or(Role::Member),
    };
    membership.session_role = next;
    let account_id = membership.account_id;
    if channel.persistence != PersistencePolicy::Registered {
        membership.effective_role = next;
        return;
    }
    let Some(account_id) = account_id else {
        membership.effective_role = next;
        return;
    };
    if next == Role::Member {
        channel.role_grants.remove(&account_id);
    } else {
        channel.role_grants.insert(account_id, next);
    }
    for current in channel.memberships.values_mut() {
        if current.account_id == Some(account_id) {
            current.effective_role = std::cmp::max(current.session_role, next);
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
            if account.contacts.len() >= MAX_CONTACTS_PER_ACCOUNT || contact == account_id {
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
        | ChannelCommand::Content(channel_id, _) => channel_id,
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
            if channel.persistence != PersistencePolicy::Registered {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::History(_, history) => {
            if !history_setting_is_allowed(channel, history) {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::Content(_, ContentPolicy::E2eeBound) => {
            if channel.scope != crate::ChannelScope::Global
                || channel.history != HistoryPolicy::Off
                || channel.topic.is_some()
            {
                return Err(DomainError::BadState);
            }
        }
        ChannelCommand::Content(_, ContentPolicy::Plaintext) => {}
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
mod tests {
    use super::*;
    use crate::{MessageCommand, MessageText};
    use agenc_ircd_types::{AccountRandomId, ControlPolicy, PublicCloak, ServerId, SessionId};

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
            public_cloak: PublicCloak::parse("aaaaaaaaaa", "bbbbbbbbbbbbbbbb")?,
            connection_nonce: [seed; 32],
            negotiated_capability_hash: [seed.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: Revision::new(1)?,
        })
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
            Some(MessageText::try_from_str("x", ControlPolicy::RejectAll)?),
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
            Some(MessageText::try_from_str("x", ControlPolicy::RejectAll)?),
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
            Some(MessageText::try_from_str("x", ControlPolicy::RejectAll)?),
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
                .then(|| MessageText::try_from_str("x", ControlPolicy::RejectAll))
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
                &ModeChange::Visibility(Visibility::Secret),
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
            Err(DomainError::InvalidArgument)
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
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Content(fixture.channel_id, ContentPolicy::E2eeBound),
            ),
            Ok(())
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
        assert!(admission.admits(&[charge]));
        assert!(!admission.admits(&[RateCharge::new(charge.bucket(), 3)?]));

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
                &ModeChange::Visibility(Visibility::Secret),
            ),
            Err(DomainError::RegistrationRequired)
        );
        assert_eq!(
            validate_mode_change(
                state,
                &channel,
                Role::Member,
                Some(fixture.owner_account),
                &ModeChange::Visibility(Visibility::Listed),
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

        fixture
            .state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .history = HistoryPolicy::OneHour;
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
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Content(fixture.channel_id, ContentPolicy::E2eeBound),
            ),
            Ok(())
        );
        state
            .channels
            .get_mut(&fixture.channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .scope = crate::ChannelScope::Local;
        assert_eq!(
            validate_channel_setting(
                state,
                fixture.owner.user_id,
                fixture.owner_account,
                ChannelCommand::Content(fixture.channel_id, ContentPolicy::E2eeBound),
            ),
            Err(DomainError::BadState)
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
            ModeChange::Moderated(true),
            &mut Vec::<EntryId>::new().into_iter(),
            None,
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:no-id")?,
            },
            &mut Vec::<EntryId>::new().into_iter(),
            None,
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:with-id")?,
            },
            &mut vec![EntryId::from_bytes(bytes(216))].into_iter(),
            Some(UtcSecond::from_unix_seconds(20)),
        );
        fixture.state.apply_mode_change(
            fixture.channel_id,
            ModeChange::RemoveMask {
                list: MaskList::Exception,
                entry_id: EntryId::from_bytes(bytes(216)),
            },
            &mut Vec::<EntryId>::new().into_iter(),
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
            Some(MessageText::try_from_str(
                "extra",
                ControlPolicy::RejectAll,
            )?),
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
    fn invitation_planning_covers_collision_expiry_limits_and_quiet_actor()
    -> Result<(), DomainError> {
        let make_inputs = |invite_id, now| ExternalInputs {
            monotonic_now: Some(MonotonicTick::from_ticks(now)),
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
                &ModeChange::Visibility(Visibility::Secret),
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
        member.session_role = Role::Voice;
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
        assert!(
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
                .is_ok()
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
        let member = channel
            .memberships
            .get_mut(&fixture.member.user_id)
            .ok_or(DomainError::InvariantViolation)?;
        member.session_role = Role::Voice;
        member.effective_role = Role::Voice;

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
}
