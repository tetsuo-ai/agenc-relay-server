//! Authoritative value state and its local invariants.

use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

use agenc_ircd_types::{
    AccountDeletionToken, AccountId, AccountLabel, BoundedUtf8, ChannelInstanceId, ChannelName,
    ControlPolicy, DisplayName, EntryId, Generation, InviteId, MessageId, MonotonicTick, Nickname,
    PublicCloak, Revision, ServerId, SessionId, TypedMask, UserId, UtcSecond,
};

use crate::DomainError;
use crate::persist::{DurableAccount, DurableChannel, DurableSanction};

/// Maximum live sessions belonging to one account.
pub const MAX_SESSIONS_PER_ACCOUNT: usize = 32;
/// Maximum live channel memberships.
pub const MAX_MEMBERS_PER_CHANNEL: usize = 65_535;
/// Maximum channels joined by one session.
pub const MAX_CHANNELS_PER_SESSION: usize = 256;
/// Maximum persistent role grants in one channel.
pub const MAX_ROLE_GRANTS_PER_CHANNEL: usize = 65_535;
/// Maximum entries in each typed channel mask list.
pub const MAX_MASK_ENTRIES_PER_LIST: usize = 100;
/// Maximum pending invitations in one channel.
pub const MAX_INVITES_PER_CHANNEL: usize = 4_096;
/// Maximum pending invitations naming one principal across all channels.
pub(crate) const MAX_INVITES_PER_PRINCIPAL: usize = 256;
/// Maximum contacts stored by one account.
pub const MAX_CONTACTS_PER_ACCOUNT: usize = 1_000;
/// Maximum reserved nicknames stored by one account.
pub const MAX_RESERVED_NICKNAMES: usize = 5;
/// Maximum monitored nicknames stored by one live session.
pub const MAX_MONITORED_NICKNAMES: usize = 100;
/// Maximum pending invitations across the network.
pub(crate) const MAX_INVITES_NETWORK_WIDE: usize = 1_000_000;
/// Maximum coordinator-owned global channel instances.
pub const MAX_GLOBAL_CHANNELS: usize = 1_000_000;
/// Maximum server-local channel instances.
pub const MAX_LOCAL_CHANNELS: usize = 100_000;

/// Unvalidated values used to construct the live operational ceiling view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalLimitValues {
    /// Live sessions belonging to one account.
    pub sessions_per_account: usize,
    /// Channels joined by one session.
    pub channels_per_session: usize,
    /// Live members in one channel.
    pub members_per_channel: usize,
    /// Coordinator-owned global channels.
    pub global_channels: usize,
    /// Server-local channels.
    pub local_channels: usize,
    /// Pending invitations in one channel.
    pub invites_per_channel: usize,
    /// Pending invitations naming one principal.
    pub invites_per_principal: usize,
    /// Pending invitations across the network.
    pub invites_global: usize,
    /// Contacts stored by one account.
    pub contacts_per_account: usize,
}

/// Validated reloadable ceilings consulted by domain decisions.
///
/// Hard protocol maxima remain fixed. Lowering this view blocks new use but
/// does not invalidate or remove already accepted state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationalLimits {
    values: OperationalLimitValues,
}

impl OperationalLimits {
    /// The hard protocol maxima used until a validated runtime profile is installed.
    pub const HARD_MAX: Self = Self {
        values: OperationalLimitValues {
            sessions_per_account: MAX_SESSIONS_PER_ACCOUNT,
            channels_per_session: MAX_CHANNELS_PER_SESSION,
            members_per_channel: MAX_MEMBERS_PER_CHANNEL,
            global_channels: MAX_GLOBAL_CHANNELS,
            local_channels: MAX_LOCAL_CHANNELS,
            invites_per_channel: MAX_INVITES_PER_CHANNEL,
            invites_per_principal: MAX_INVITES_PER_PRINCIPAL,
            invites_global: MAX_INVITES_NETWORK_WIDE,
            contacts_per_account: MAX_CONTACTS_PER_ACCOUNT,
        },
    };

    /// Validates nonzero ceilings at or below every hard protocol maximum.
    pub fn new(values: OperationalLimitValues) -> Result<Self, DomainError> {
        let pairs = [
            (values.sessions_per_account, MAX_SESSIONS_PER_ACCOUNT),
            (values.channels_per_session, MAX_CHANNELS_PER_SESSION),
            (values.members_per_channel, MAX_MEMBERS_PER_CHANNEL),
            (values.global_channels, MAX_GLOBAL_CHANNELS),
            (values.local_channels, MAX_LOCAL_CHANNELS),
            (values.invites_per_channel, MAX_INVITES_PER_CHANNEL),
            (values.invites_per_principal, MAX_INVITES_PER_PRINCIPAL),
            (values.invites_global, MAX_INVITES_NETWORK_WIDE),
            (values.contacts_per_account, MAX_CONTACTS_PER_ACCOUNT),
        ];
        if pairs
            .into_iter()
            .any(|(value, hard_maximum)| value == 0 || value > hard_maximum)
        {
            return Err(DomainError::InvalidArgument);
        }
        Ok(Self { values })
    }

    /// Returns the validated values.
    #[must_use]
    pub const fn values(self) -> OperationalLimitValues {
        self.values
    }

    pub(crate) const fn sessions_per_account(self) -> usize {
        self.values.sessions_per_account
    }

    pub(crate) const fn channels_per_session(self) -> usize {
        self.values.channels_per_session
    }

    pub(crate) const fn members_per_channel(self) -> usize {
        self.values.members_per_channel
    }

    pub(crate) const fn global_channels(self) -> usize {
        self.values.global_channels
    }

    pub(crate) const fn local_channels(self) -> usize {
        self.values.local_channels
    }

    pub(crate) const fn invites_per_channel(self) -> usize {
        self.values.invites_per_channel
    }

    pub(crate) const fn invites_per_principal(self) -> usize {
        self.values.invites_per_principal
    }

    pub(crate) const fn invites_global(self) -> usize {
        self.values.invites_global
    }

    pub(crate) const fn contacts_per_account(self) -> usize {
        self.values.contacts_per_account
    }
}

/// A validated away message.
pub type AwayText = BoundedUtf8<0, 256>;
/// A validated plaintext topic.
pub type TopicText = BoundedUtf8<0, 1024>;
/// An optional free-form moderation reason.
pub type ModerationReason = BoundedUtf8<0, 512>;

fn copy_bounded(input: &str) -> Result<String, DomainError> {
    let mut output = String::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    output.push_str(input);
    Ok(output)
}

/// A domain-owned nickname with routing identity separate from presentation.
#[derive(Clone)]
pub struct NicknameValue {
    presentation: String,
    canonical: String,
}

impl PartialEq for NicknameValue {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for NicknameValue {}

impl PartialOrd for NicknameValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NicknameValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for NicknameValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl NicknameValue {
    /// Copies one already validated foundational nickname.
    pub fn from_validated(nickname: &Nickname) -> Result<Self, DomainError> {
        Ok(Self {
            presentation: copy_bounded(nickname.presentation())?,
            canonical: copy_bounded(nickname.canonical())?,
        })
    }

    /// Parses and owns one nickname.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        Self::from_validated(&Nickname::parse(input)?)
    }

    /// Borrows the first accepted display spelling.
    #[must_use]
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Borrows the lowercase routing identity.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

/// A domain-owned channel name with scope and comparison identity retained.
#[derive(Clone)]
pub struct ChannelNameValue {
    presentation: String,
    canonical: String,
    scope: ChannelScope,
}

impl PartialEq for ChannelNameValue {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}

impl Eq for ChannelNameValue {}

impl PartialOrd for ChannelNameValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChannelNameValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl Hash for ChannelNameValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

impl ChannelNameValue {
    /// Copies one already validated foundational channel name.
    pub fn from_validated(channel: &ChannelName) -> Result<Self, DomainError> {
        let scope = if channel.is_global() {
            ChannelScope::Global
        } else {
            ChannelScope::Local
        };
        Ok(Self {
            presentation: copy_bounded(channel.presentation())?,
            canonical: copy_bounded(channel.canonical())?,
            scope,
        })
    }

    /// Parses and owns one channel name.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        Self::from_validated(&ChannelName::parse(input)?)
    }

    /// Borrows the first accepted display spelling.
    #[must_use]
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Borrows the lowercase routing identity.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Returns the authority scope selected by the name prefix.
    #[must_use]
    pub const fn scope(&self) -> ChannelScope {
        self.scope
    }
}

/// A domain-owned prepared display name.
#[derive(Clone, Eq, PartialEq)]
pub struct DisplayNameValue(String);

impl DisplayNameValue {
    /// Copies one prepared display name.
    pub fn from_validated(display_name: &DisplayName) -> Result<Self, DomainError> {
        copy_bounded(display_name.as_str()).map(Self)
    }

    /// Applies the pinned preparation profile and owns the result.
    pub fn prepare(input: &str) -> Result<Self, DomainError> {
        Self::from_validated(&DisplayName::prepare(input)?)
    }

    /// Borrows prepared public display text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A domain-owned public account label.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountLabelValue(String);

impl AccountLabelValue {
    /// Copies one validated public account label.
    pub fn from_validated(label: &AccountLabel) -> Result<Self, DomainError> {
        copy_bounded(label.as_str()).map(Self)
    }

    /// Parses and owns one public account label.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        Self::from_validated(&AccountLabel::parse(input)?)
    }

    /// Borrows the exact public spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Domain authority carried by one session or durable channel creator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Principal {
    /// Authority belonging only to one live guest user.
    Guest(UserId),
    /// Authority belonging to one immutable account.
    Account(AccountId),
}

impl Principal {
    /// Returns the account authority when this principal is authenticated.
    #[must_use]
    pub const fn account_id(self) -> Option<AccountId> {
        match self {
            Self::Guest(_) => None,
            Self::Account(account_id) => Some(account_id),
        }
    }
}

/// Channel ownership scope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChannelScope {
    /// Coordinator-owned and federated `#` channel.
    Global,
    /// Edge-owned and non-federated `&` channel.
    Local,
}

/// Channel discovery policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Visibility {
    /// Visible in bounded LIST results.
    Listed,
    /// Omitted from LIST but confirmable by an authorized exact query.
    Unlisted,
    /// Existence-hidden from nonmembers.
    Secret,
}

/// Channel content policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ContentPolicy {
    /// Ordinary bounded IRC plaintext.
    Plaintext,
    /// Companion-profile opaque encrypted objects only.
    E2eeBound,
}

/// Channel lifetime policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PersistencePolicy {
    /// Destroy after the final membership and security preconditions clear.
    Ephemeral,
    /// Preserve the instance and durable policy through zero membership.
    Registered,
}

/// Optional plaintext channel-history policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HistoryPolicy {
    /// Do not retain retrievable plaintext history.
    Off,
    /// Retain new messages for one hour.
    OneHour,
    /// Retain new messages for twenty-four hours.
    TwentyFourHours,
    /// Retain new messages for seven days.
    SevenDays,
}

impl HistoryPolicy {
    pub(crate) fn is_allowed_for(self, channel: &ChannelState) -> bool {
        self == Self::Off
            || (channel.scope == ChannelScope::Global
                && channel.visibility == Visibility::Listed
                && channel.content_policy == ContentPolicy::Plaintext
                && channel.persistence == PersistencePolicy::Registered)
    }
}

/// Account-wide presence visibility.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PresencePolicy {
    /// Presence may be projected under the documented visibility rules.
    Public,
    /// Presence is visible only through shared or mutual-contact context.
    Private,
}

/// Policy for direct messages sent by guests.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GuestDirectMessagePolicy {
    /// Permit a guest sender.
    Allow,
    /// Reject every guest sender.
    Deny,
}

/// Policy for direct messages sent by another account.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DirectMessagePolicy {
    /// Permit every authenticated sender.
    Allow,
    /// Permit only accounts in the recipient's unilateral contact set.
    Contacts,
    /// Reject messages from other accounts.
    Deny,
}

/// One account's public and authorization-relevant domain state.
#[derive(Clone)]
pub struct AccountState {
    pub(crate) account_id: AccountId,
    pub(crate) label: Option<AccountLabelValue>,
    pub(crate) presence: PresencePolicy,
    pub(crate) guest_direct_messages: GuestDirectMessagePolicy,
    pub(crate) direct_messages: DirectMessagePolicy,
    pub(crate) contacts: BTreeSet<AccountId>,
    pub(crate) reserved_nicknames: BTreeSet<NicknameValue>,
    pub(crate) session_generation: Generation,
    pub(crate) revision: Revision,
}

impl AccountState {
    /// Creates default public account policy at explicit generations.
    #[must_use]
    pub fn new(account_id: AccountId, session_generation: Generation, revision: Revision) -> Self {
        Self {
            account_id,
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Allow,
            direct_messages: DirectMessagePolicy::Allow,
            contacts: BTreeSet::new(),
            reserved_nicknames: BTreeSet::new(),
            session_generation,
            revision,
        }
    }

    /// Creates an account with deployment-selected initial policy.
    #[must_use]
    pub fn with_policies(
        account_id: AccountId,
        session_generation: Generation,
        revision: Revision,
        presence: PresencePolicy,
        guest_direct_messages: GuestDirectMessagePolicy,
        direct_messages: DirectMessagePolicy,
    ) -> Self {
        Self {
            account_id,
            label: None,
            presence,
            guest_direct_messages,
            direct_messages,
            contacts: BTreeSet::new(),
            reserved_nicknames: BTreeSet::new(),
            session_generation,
            revision,
        }
    }

    /// Returns the immutable account authority.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Borrows the optional public label.
    #[must_use]
    pub const fn label(&self) -> Option<&AccountLabelValue> {
        self.label.as_ref()
    }

    /// Returns the account-session fence.
    #[must_use]
    pub const fn session_generation(&self) -> Generation {
        self.session_generation
    }

    /// Returns the account revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the account-wide presence policy.
    #[must_use]
    pub const fn presence_policy(&self) -> PresencePolicy {
        self.presence
    }

    /// Returns the guest direct-message policy.
    #[must_use]
    pub const fn guest_direct_message_policy(&self) -> GuestDirectMessagePolicy {
        self.guest_direct_messages
    }

    /// Returns the authenticated direct-message policy.
    #[must_use]
    pub const fn direct_message_policy(&self) -> DirectMessagePolicy {
        self.direct_messages
    }

    /// Reports whether the account has added one immutable account contact.
    #[must_use]
    pub fn contains_contact(&self, account_id: AccountId) -> bool {
        self.contacts.contains(&account_id)
    }
}

impl AccountState {
    /// Iterates reserved nicknames in canonical order.
    pub fn reserved_nicknames(&self) -> impl Iterator<Item = &NicknameValue> {
        self.reserved_nicknames.iter()
    }

    /// Iterates unilateral contacts in ascending Account ID order.
    pub fn contacts(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.contacts.iter().copied()
    }
}

/// All explicit inputs needed to introduce one registered session.
pub struct SessionSeed {
    /// New accepted session identifier.
    pub session_id: SessionId,
    /// New per-connection user identifier.
    pub user_id: UserId,
    /// Server that owns the physical connection.
    pub home_server_id: ServerId,
    /// Account authority, absent for a guest.
    pub account_id: Option<AccountId>,
    /// Account-session generation proved by authentication.
    pub account_session_generation: Generation,
    /// Session generation used to reject stale completions.
    pub generation: Generation,
    /// Validated routing nickname.
    pub nickname: NicknameValue,
    /// Prepared presentation name.
    pub display_name: DisplayNameValue,
    /// Independently random public cloak.
    pub public_cloak: PublicCloak,
    /// Private connection binding, never projected to clients.
    pub connection_nonce: [u8; 32],
    /// Hash of the sorted negotiated capability names.
    pub negotiated_capability_hash: [u8; 32],
    /// Explicit accepted UTC second.
    pub created_at_utc: UtcSecond,
    /// Initial state revision.
    pub revision: Revision,
}

/// Coordinator-owned logical session state.
pub struct SessionState {
    pub(crate) session_id: SessionId,
    pub(crate) user_id: UserId,
    pub(crate) home_server_id: ServerId,
    pub(crate) account_id: Option<AccountId>,
    pub(crate) account_session_generation: Generation,
    pub(crate) generation: Generation,
    pub(crate) nickname: NicknameValue,
    pub(crate) display_name: DisplayNameValue,
    pub(crate) public_cloak: PublicCloak,
    pub(crate) away: Option<AwayText>,
    pub(crate) operator_notices: bool,
    pub(crate) monitored_nicknames: BTreeSet<NicknameValue>,
    pub(crate) connection_nonce: [u8; 32],
    pub(crate) negotiated_capability_hash: [u8; 32],
    pub(crate) joined_channels: BTreeSet<ChannelInstanceId>,
    pub(crate) created_at_utc: UtcSecond,
    pub(crate) fresh_auth_deadline: Option<MonotonicTick>,
    pub(crate) revision: Revision,
}

impl SessionState {
    pub(crate) fn from_seed(seed: SessionSeed) -> Self {
        Self {
            session_id: seed.session_id,
            user_id: seed.user_id,
            home_server_id: seed.home_server_id,
            account_id: seed.account_id,
            account_session_generation: seed.account_session_generation,
            generation: seed.generation,
            nickname: seed.nickname,
            display_name: seed.display_name,
            public_cloak: seed.public_cloak,
            away: None,
            operator_notices: false,
            monitored_nicknames: BTreeSet::new(),
            connection_nonce: seed.connection_nonce,
            negotiated_capability_hash: seed.negotiated_capability_hash,
            joined_channels: BTreeSet::new(),
            created_at_utc: seed.created_at_utc,
            fresh_auth_deadline: None,
            revision: seed.revision,
        }
    }

    /// Returns this physical-session identity.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns this per-connection user identity.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Returns the immutable account authority when authenticated.
    #[must_use]
    pub const fn account_id(&self) -> Option<AccountId> {
        self.account_id
    }

    /// Returns the edge or coordinator that owns the physical connection.
    #[must_use]
    pub const fn home_server_id(&self) -> ServerId {
        self.home_server_id
    }

    /// Returns the account-session generation captured at authentication.
    #[must_use]
    pub const fn account_session_generation(&self) -> Generation {
        self.account_session_generation
    }

    /// Returns the current session generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Borrows the routing nickname.
    #[must_use]
    pub const fn nickname(&self) -> &NicknameValue {
        &self.nickname
    }

    /// Returns the independently generated visible cloak.
    #[must_use]
    pub const fn public_cloak(&self) -> PublicCloak {
        self.public_cloak
    }

    /// Borrows the prepared presentation name.
    #[must_use]
    pub const fn display_name(&self) -> &DisplayNameValue {
        &self.display_name
    }

    /// Borrows the optional per-session away value.
    #[must_use]
    pub const fn away(&self) -> Option<&AwayText> {
        self.away.as_ref()
    }

    /// Reports whether the session subscribed to bounded operator notices.
    #[must_use]
    pub const fn operator_notices(&self) -> bool {
        self.operator_notices
    }

    /// Iterates monitored canonical nicknames in deterministic order.
    pub fn monitored_nicknames(&self) -> impl Iterator<Item = &NicknameValue> {
        self.monitored_nicknames.iter()
    }

    /// Iterates joined immutable channel identities in canonical order.
    pub fn joined_channels(&self) -> impl Iterator<Item = ChannelInstanceId> + '_ {
        self.joined_channels.iter().copied()
    }

    /// Reports whether this session is joined to one immutable channel instance.
    #[must_use]
    pub fn is_joined(&self, channel_id: ChannelInstanceId) -> bool {
        self.joined_channels.contains(&channel_id)
    }

    /// Returns the current session revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Borrows the private 32-byte companion origin binding.
    #[must_use]
    pub const fn connection_nonce(&self) -> &[u8; 32] {
        &self.connection_nonce
    }

    /// Borrows the hash of sorted negotiated capability names.
    #[must_use]
    pub const fn negotiated_capability_hash(&self) -> &[u8; 32] {
        &self.negotiated_capability_hash
    }

    /// Returns the accepted UTC creation second.
    #[must_use]
    pub const fn created_at_utc(&self) -> UtcSecond {
        self.created_at_utc
    }

    /// Returns the coordinator-memory-only fresh-auth deadline.
    #[must_use]
    pub const fn fresh_auth_deadline(&self) -> Option<MonotonicTick> {
        self.fresh_auth_deadline
    }

    /// Returns a principal that does not confuse account and guest authority.
    #[must_use]
    pub const fn principal(&self) -> Principal {
        match self.account_id {
            Some(account_id) => Principal::Account(account_id),
            None => Principal::Guest(self.user_id),
        }
    }
}

/// Strict channel authorization role.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Role {
    /// Ordinary membership.
    Member,
    /// May speak in a moderated channel.
    Voice,
    /// May change topic, voice, and routine removals.
    HalfOperator,
    /// May change modes, bans, invites, and operator grants.
    Operator,
    /// May change policy and grant through administrator.
    Administrator,
    /// May change ownership, registration, and all lower roles.
    Owner,
}

impl Role {
    /// Returns the exact next lower role for a valid prefix-mode removal.
    #[must_use]
    pub const fn next_lower(self) -> Option<Self> {
        match self {
            Self::Member => None,
            Self::Voice => Some(Self::Member),
            Self::HalfOperator => Some(Self::Voice),
            Self::Operator => Some(Self::HalfOperator),
            Self::Administrator => Some(Self::Operator),
            Self::Owner => Some(Self::Administrator),
        }
    }

    /// Reports whether this role can grant the requested highest role.
    #[must_use]
    pub fn can_grant(self, requested: Self) -> bool {
        self >= requested
    }
}

/// Simple channel modes represented without the mandatory `+n` escape hatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelModes {
    /// Invite-only admission.
    pub invite_only: bool,
    /// Moderated speaking policy.
    pub moderated: bool,
    /// Topic changes require half-operator or higher.
    pub topic_protected: bool,
    /// A later crypto adapter must verify a join secret before admission.
    pub join_key: bool,
}

impl Default for ChannelModes {
    fn default() -> Self {
        Self {
            invite_only: false,
            moderated: false,
            topic_protected: true,
            join_key: false,
        }
    }
}

/// Fixed-size Argon2id verifier material for one channel join secret.
///
/// The domain stores and persists only the random salt and derived hash. Raw
/// channel keys remain runtime-owned external inputs and never enter domain
/// state, plans, events, or formatted diagnostics.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChannelKeyVerifier {
    salt: [u8; 16],
    hash: [u8; 32],
}

impl ChannelKeyVerifier {
    /// Wraps one already-derived verifier.
    #[must_use]
    pub const fn new(salt: [u8; 16], hash: [u8; 32]) -> Self {
        Self { salt, hash }
    }

    /// Returns the random Argon2id salt.
    #[must_use]
    pub const fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Returns the derived Argon2id hash.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// One live channel membership with session and effective roles separated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Membership {
    pub(crate) user_id: UserId,
    pub(crate) account_id: Option<AccountId>,
    pub(crate) session_role: Role,
    pub(crate) effective_role: Role,
}

impl Membership {
    /// Creates a membership before any durable account grant is applied.
    #[must_use]
    pub const fn new(user_id: UserId, account_id: Option<AccountId>, role: Role) -> Self {
        Self {
            user_id,
            account_id,
            session_role: role,
            effective_role: role,
        }
    }

    /// Returns the live user identity.
    #[must_use]
    pub const fn user_id(self) -> UserId {
        self.user_id
    }

    /// Returns the highest effective authorization role.
    #[must_use]
    pub const fn role(self) -> Role {
        self.effective_role
    }
}

/// One plaintext topic and its immutable assignment identity.
pub struct PlaintextTopic {
    pub(crate) text: TopicText,
    pub(crate) message_id: MessageId,
    pub(crate) setter: UserId,
    pub(crate) set_at: UtcSecond,
}

impl PlaintextTopic {
    /// Borrows the validated topic text.
    #[must_use]
    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    /// Returns the topic assignment identity.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the live user that set this topic.
    #[must_use]
    pub const fn setter(&self) -> UserId {
        self.setter
    }

    /// Returns the authoritative topic UTC second.
    #[must_use]
    pub const fn set_at(&self) -> UtcSecond {
        self.set_at
    }
}

impl PlaintextTopic {
    /// Copies the topic by re-validating its text under the most permissive policy.
    pub(crate) fn duplicate(&self) -> Result<Self, DomainError> {
        Ok(Self {
            text: TopicText::try_from_str(self.text.as_str(), ControlPolicy::PermitHorizontalTab)?,
            message_id: self.message_id,
            setter: self.setter,
            set_at: self.set_at,
        })
    }
}

/// One typed channel list entry.
pub struct ListEntry {
    pub(crate) entry_id: EntryId,
    pub(crate) mask: TypedMask,
    pub(crate) setter: Principal,
    pub(crate) created_at: UtcSecond,
}

impl ListEntry {
    /// Creates one already validated typed list entry.
    #[must_use]
    pub const fn new(
        entry_id: EntryId,
        mask: TypedMask,
        setter: Principal,
        created_at: UtcSecond,
    ) -> Self {
        Self {
            entry_id,
            mask,
            setter,
            created_at,
        }
    }

    /// Returns whether this is the quiet wrapper legal only in the ban list.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        self.mask.is_quiet()
    }

    /// Returns the immutable list-entry identity used for removals.
    #[must_use]
    pub const fn entry_id(&self) -> EntryId {
        self.entry_id
    }

    /// Borrows the canonical typed mask.
    #[must_use]
    pub const fn mask(&self) -> &TypedMask {
        &self.mask
    }

    /// Returns the principal that created this entry.
    #[must_use]
    pub const fn setter(&self) -> Principal {
        self.setter
    }

    /// Returns the authoritative creation second.
    #[must_use]
    pub const fn created_at(&self) -> UtcSecond {
        self.created_at
    }
}

impl ListEntry {
    /// Copies the entry by rebuilding its mask from the canonical text.
    pub(crate) fn duplicate(&self) -> Result<Self, DomainError> {
        Ok(Self {
            entry_id: self.entry_id,
            mask: crate::persist::duplicate_typed_mask(&self.mask)?,
            setter: self.setter,
            created_at: self.created_at,
        })
    }
}

#[derive(Clone)]
pub(crate) struct Invite {
    pub(crate) invite_id: InviteId,
    pub(crate) target: Principal,
    pub(crate) inviter: UserId,
    pub(crate) creation_revision: Revision,
    pub(crate) expires_at: MonotonicTick,
}

/// Process-local, single-use account-deletion challenge bound to one session fence.
pub(crate) struct AccountDeletionChallengeState {
    pub(crate) token: AccountDeletionToken,
    pub(crate) account_id: AccountId,
    pub(crate) account_revision: Revision,
    pub(crate) account_session_generation: Generation,
    pub(crate) session_id: SessionId,
    pub(crate) user_id: UserId,
    pub(crate) session_generation: Generation,
    pub(crate) expires_at: MonotonicTick,
}

/// Authoritative channel state.
pub struct ChannelState {
    pub(crate) channel_id: ChannelInstanceId,
    pub(crate) name: ChannelNameValue,
    pub(crate) scope: ChannelScope,
    pub(crate) visibility: Visibility,
    pub(crate) content_policy: ContentPolicy,
    pub(crate) persistence: PersistencePolicy,
    pub(crate) creator: Principal,
    pub(crate) created_at: UtcSecond,
    pub(crate) revision: Revision,
    pub(crate) modes: ChannelModes,
    pub(crate) key_verifier: Option<ChannelKeyVerifier>,
    pub(crate) member_limit: Option<u16>,
    pub(crate) topic: Option<PlaintextTopic>,
    pub(crate) memberships: BTreeMap<UserId, Membership>,
    pub(crate) role_grants: BTreeMap<AccountId, Role>,
    pub(crate) bans: Vec<ListEntry>,
    pub(crate) exceptions: Vec<ListEntry>,
    pub(crate) invite_exceptions: Vec<ListEntry>,
    pub(crate) invites: BTreeMap<InviteId, Invite>,
    pub(crate) history: HistoryPolicy,
    pub(crate) e2ee_removal_pending: BTreeSet<UserId>,
}

impl ChannelState {
    pub(crate) fn new_ephemeral(
        channel_id: ChannelInstanceId,
        name: ChannelNameValue,
        creator: Principal,
        creator_membership: Membership,
        created_at: UtcSecond,
        revision: Revision,
    ) -> Self {
        let scope = name.scope();
        let mut memberships = BTreeMap::new();
        memberships.insert(creator_membership.user_id, creator_membership);
        Self {
            channel_id,
            name,
            scope,
            visibility: Visibility::Listed,
            content_policy: ContentPolicy::Plaintext,
            persistence: PersistencePolicy::Ephemeral,
            creator,
            created_at,
            revision,
            modes: ChannelModes::default(),
            key_verifier: None,
            member_limit: None,
            topic: None,
            memberships,
            role_grants: BTreeMap::new(),
            bans: Vec::new(),
            exceptions: Vec::new(),
            invite_exceptions: Vec::new(),
            invites: BTreeMap::new(),
            history: HistoryPolicy::Off,
            e2ee_removal_pending: BTreeSet::new(),
        }
    }

    /// Returns the immutable identity of this channel creation.
    #[must_use]
    pub const fn channel_id(&self) -> ChannelInstanceId {
        self.channel_id
    }

    /// Borrows the stable name and display spelling.
    #[must_use]
    pub const fn name(&self) -> &ChannelNameValue {
        &self.name
    }

    /// Returns the current channel revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the accepted UTC creation second.
    #[must_use]
    pub const fn created_at(&self) -> UtcSecond {
        self.created_at
    }

    /// Iterates live membership identities in canonical user order.
    pub fn members(&self) -> impl Iterator<Item = UserId> + '_ {
        self.memberships.keys().copied()
    }

    /// Borrows one typed mask list.
    #[must_use]
    pub fn mask_list(&self, list: crate::MaskList) -> &[ListEntry] {
        match list {
            crate::MaskList::Ban => &self.bans,
            crate::MaskList::Exception => &self.exceptions,
            crate::MaskList::InviteException => &self.invite_exceptions,
        }
    }

    /// Returns the channel authority scope.
    #[must_use]
    pub const fn scope(&self) -> ChannelScope {
        self.scope
    }

    /// Returns the channel discovery policy.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns the accepted content route.
    #[must_use]
    pub const fn content_policy(&self) -> ContentPolicy {
        self.content_policy
    }

    /// Returns the current channel lifetime policy.
    #[must_use]
    pub const fn persistence_policy(&self) -> PersistencePolicy {
        self.persistence
    }

    /// Returns the optional plaintext-history policy.
    #[must_use]
    pub const fn history_policy(&self) -> HistoryPolicy {
        self.history
    }

    /// Returns the simple channel-mode vector. Mandatory `+n` is structural.
    #[must_use]
    pub const fn modes(&self) -> ChannelModes {
        self.modes
    }

    /// Borrows the optional channel-key verifier without exposing a raw key.
    #[must_use]
    pub const fn key_verifier(&self) -> Option<&ChannelKeyVerifier> {
        self.key_verifier.as_ref()
    }

    /// Returns the optional simultaneous-membership limit.
    #[must_use]
    pub const fn member_limit(&self) -> Option<u16> {
        self.member_limit
    }

    /// Borrows the optional plaintext topic.
    #[must_use]
    pub const fn topic(&self) -> Option<&PlaintextTopic> {
        self.topic.as_ref()
    }

    /// Reports whether companion cryptographic removal is still pending.
    #[must_use]
    pub fn e2ee_removal_is_pending(&self, user_id: UserId) -> bool {
        self.e2ee_removal_pending.contains(&user_id)
    }

    /// Returns one user's effective role when currently joined.
    #[must_use]
    pub fn role_of(&self, user_id: UserId) -> Option<Role> {
        self.memberships
            .get(&user_id)
            .map(|membership| membership.effective_role)
    }

    /// Returns the current number of memberships.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.memberships.len()
    }

    /// Iterates pending invite metadata without exposing a bearer token.
    pub fn pending_invites(
        &self,
    ) -> impl Iterator<Item = (InviteId, Principal, UserId, Revision, MonotonicTick)> + '_ {
        self.invites.values().map(|invite| {
            (
                invite.invite_id,
                invite.target,
                invite.inviter,
                invite.creation_revision,
                invite.expires_at,
            )
        })
    }

    /// Computes the effective role for a prospective or current membership.
    #[must_use]
    pub fn effective_role(&self, membership: Membership) -> Role {
        let grant = membership
            .account_id
            .and_then(|account_id| self.role_grants.get(&account_id).copied())
            .unwrap_or(Role::Member);
        cmp::max(membership.session_role, grant)
    }

    pub(crate) fn matching_invite(
        &self,
        principal: Principal,
        now: MonotonicTick,
    ) -> Option<InviteId> {
        self.invites
            .values()
            .find(|invite| invite.target == principal && now < invite.expires_at)
            .map(|invite| invite.invite_id)
    }

    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        if !self.identities_and_limits_are_valid() {
            return Err(DomainError::InvariantViolation);
        }
        if self.modes.join_key != self.key_verifier.is_some() {
            return Err(DomainError::InvariantViolation);
        }
        if !self.content_policy_is_valid() {
            return Err(DomainError::InvariantViolation);
        }
        if !self.pending_removals_are_valid() {
            return Err(DomainError::InvariantViolation);
        }
        if !self.history.is_allowed_for(self) {
            return Err(DomainError::InvariantViolation);
        }
        if !self.registered_owner_is_preserved() {
            return Err(DomainError::InvariantViolation);
        }
        if !self.membership_roles_are_current() {
            return Err(DomainError::InvariantViolation);
        }
        Ok(())
    }

    fn content_policy_is_valid(&self) -> bool {
        self.content_policy == ContentPolicy::Plaintext
            || (self.scope == ChannelScope::Global
                && self.persistence == PersistencePolicy::Registered
                && self.history == HistoryPolicy::Off
                && self.topic.is_none()
                && self
                    .memberships
                    .values()
                    .all(|membership| membership.account_id.is_some()))
    }

    fn pending_removals_are_valid(&self) -> bool {
        (self.content_policy == ContentPolicy::E2eeBound || self.e2ee_removal_pending.is_empty())
            && self
                .e2ee_removal_pending
                .iter()
                .all(|user_id| self.memberships.contains_key(user_id))
    }

    fn identities_and_limits_are_valid(&self) -> bool {
        self.scope == self.name.scope()
            && self.memberships.len() <= MAX_MEMBERS_PER_CHANNEL
            && self.role_grants.len() <= MAX_ROLE_GRANTS_PER_CHANNEL
            && self.bans.len() <= MAX_MASK_ENTRIES_PER_LIST
            && self.exceptions.len() <= MAX_MASK_ENTRIES_PER_LIST
            && self.invite_exceptions.len() <= MAX_MASK_ENTRIES_PER_LIST
            && self.invites.len() <= MAX_INVITES_PER_CHANNEL
    }

    fn registered_owner_is_preserved(&self) -> bool {
        self.persistence != PersistencePolicy::Registered
            || self.role_grants.values().any(|role| *role == Role::Owner)
    }

    fn membership_roles_are_current(&self) -> bool {
        self.memberships.values().copied().all(|membership| {
            membership.effective_role == self.effective_role(membership)
                && (self.persistence != PersistencePolicy::Registered
                    || membership.account_id.is_none()
                    || membership.session_role == Role::Member)
        })
    }
}

impl ChannelState {
    /// Copies the complete live channel for plan projection.
    pub(crate) fn duplicate(&self) -> Result<Self, DomainError> {
        Ok(Self {
            channel_id: self.channel_id,
            name: self.name.clone(),
            scope: self.scope,
            visibility: self.visibility,
            content_policy: self.content_policy,
            persistence: self.persistence,
            creator: self.creator,
            created_at: self.created_at,
            revision: self.revision,
            modes: self.modes,
            key_verifier: self.key_verifier,
            member_limit: self.member_limit,
            topic: self
                .topic
                .as_ref()
                .map(PlaintextTopic::duplicate)
                .transpose()?,
            memberships: self.memberships.clone(),
            role_grants: self.role_grants.clone(),
            bans: duplicate_entries(&self.bans)?,
            exceptions: duplicate_entries(&self.exceptions)?,
            invite_exceptions: duplicate_entries(&self.invite_exceptions)?,
            invites: self.invites.clone(),
            history: self.history,
            e2ee_removal_pending: self.e2ee_removal_pending.clone(),
        })
    }
}

fn duplicate_entries(entries: &[ListEntry]) -> Result<Vec<ListEntry>, DomainError> {
    entries.iter().map(ListEntry::duplicate).collect()
}

/// Closed reason code for an auditable moderation decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModerationReasonCode {
    /// Repeated unsolicited traffic.
    Spam,
    /// Abuse directed at another participant.
    Harassment,
    /// Violation of one channel's stated policy.
    ChannelPolicy,
    /// Network security response.
    Security,
}

/// One server-enforceable moderation action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModerationAction {
    /// Mute matching traffic without removing membership.
    Mute,
    /// Block future channel admission.
    Ban,
    /// Remove one current membership.
    Kick,
    /// Suspend one account or live session.
    Suspend,
}

/// An auditable typed sanction without addresses or content.
pub struct Sanction {
    pub(crate) actor: Principal,
    pub(crate) target: Principal,
    pub(crate) channel_id: Option<ChannelInstanceId>,
    pub(crate) action: ModerationAction,
    pub(crate) reason_code: ModerationReasonCode,
    pub(crate) reason: Option<ModerationReason>,
    pub(crate) created_at: UtcSecond,
    pub(crate) expires_at: Option<UtcSecond>,
    pub(crate) revision: Revision,
}

impl Sanction {
    /// Returns the immutable actor principal.
    #[must_use]
    pub const fn actor(&self) -> Principal {
        self.actor
    }

    /// Returns the immutable sanction target.
    #[must_use]
    pub const fn target(&self) -> Principal {
        self.target
    }

    /// Returns the optional channel scope.
    #[must_use]
    pub const fn channel_id(&self) -> Option<ChannelInstanceId> {
        self.channel_id
    }

    /// Returns the enforced moderation action.
    #[must_use]
    pub const fn action(&self) -> ModerationAction {
        self.action
    }

    /// Returns the closed audit-safe reason code.
    #[must_use]
    pub const fn reason_code(&self) -> ModerationReasonCode {
        self.reason_code
    }

    /// Borrows the optional free-form reason for encrypted storage only.
    #[must_use]
    pub const fn reason(&self) -> Option<&ModerationReason> {
        self.reason.as_ref()
    }

    /// Returns the authoritative creation second.
    #[must_use]
    pub const fn created_at(&self) -> UtcSecond {
        self.created_at
    }

    /// Returns the optional expiry second.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcSecond> {
        self.expires_at
    }

    /// Returns the authoritative sanction revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

impl Sanction {
    /// Copies the sanction by re-validating its reason under the most permissive policy.
    pub(crate) fn duplicate(&self) -> Result<Self, DomainError> {
        let reason = match &self.reason {
            Some(reason) => Some(ModerationReason::try_from_str(
                reason.as_str(),
                ControlPolicy::PermitHorizontalTab,
            )?),
            None => None,
        };
        Ok(Self {
            actor: self.actor,
            target: self.target,
            channel_id: self.channel_id,
            action: self.action,
            reason_code: self.reason_code,
            reason,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revision: self.revision,
        })
    }
}

/// Complete pure authoritative state for Stage 03.
pub struct DomainState {
    pub(crate) revision: Revision,
    pub(crate) accounts: BTreeMap<AccountId, AccountState>,
    pub(crate) sessions: BTreeMap<UserId, SessionState>,
    pub(crate) session_ids: BTreeMap<SessionId, UserId>,
    pub(crate) nicknames: BTreeMap<NicknameValue, UserId>,
    pub(crate) public_cloaks: BTreeMap<PublicCloak, UserId>,
    pub(crate) channels: BTreeMap<ChannelInstanceId, ChannelState>,
    pub(crate) channel_names: BTreeMap<ChannelNameValue, ChannelInstanceId>,
    pub(crate) account_deletion_challenges: BTreeMap<SessionId, AccountDeletionChallengeState>,
    pub(crate) sanctions: Vec<Sanction>,
    pub(crate) operational_limits: OperationalLimits,
}

impl DomainState {
    /// Creates empty state at revision zero.
    pub fn new() -> Result<Self, DomainError> {
        Ok(Self::at_revision(Revision::new(0)?))
    }

    /// Creates empty state at an explicit revision for boundary tests.
    #[must_use]
    pub fn at_revision(revision: Revision) -> Self {
        Self {
            revision,
            accounts: BTreeMap::new(),
            sessions: BTreeMap::new(),
            session_ids: BTreeMap::new(),
            nicknames: BTreeMap::new(),
            public_cloaks: BTreeMap::new(),
            channels: BTreeMap::new(),
            channel_names: BTreeMap::new(),
            account_deletion_challenges: BTreeMap::new(),
            sanctions: Vec::new(),
            operational_limits: OperationalLimits::HARD_MAX,
        }
    }

    /// Installs validated operational ceilings for subsequent decisions.
    pub fn set_operational_limits(&mut self, limits: OperationalLimits) {
        self.operational_limits = limits;
    }

    /// Returns the operational ceilings consulted by subsequent decisions.
    #[must_use]
    pub const fn operational_limits(&self) -> OperationalLimits {
        self.operational_limits
    }

    /// Returns the current authoritative revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Looks up one live session by its User ID.
    #[must_use]
    pub fn session(&self, user_id: UserId) -> Option<&SessionState> {
        self.sessions.get(&user_id)
    }

    /// Looks up one account by immutable Account ID.
    #[must_use]
    pub fn account(&self, account_id: AccountId) -> Option<&AccountState> {
        self.accounts.get(&account_id)
    }

    /// Looks up one channel creation by immutable instance ID.
    #[must_use]
    pub fn channel(&self, channel_id: ChannelInstanceId) -> Option<&ChannelState> {
        self.channels.get(&channel_id)
    }

    /// Returns the number of live account authorities.
    #[must_use]
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Returns the number of live sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the number of live sessions bound to account authority.
    #[must_use]
    pub fn authenticated_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|session| session.account_id().is_some())
            .count()
    }

    /// Returns the number of current channel instances.
    #[must_use]
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Returns `(local, global)` channel counts without exposing the maps.
    #[must_use]
    pub fn channel_scope_counts(&self) -> (usize, usize) {
        let mut local = 0_usize;
        let mut global = 0_usize;
        for channel in self.channels.values() {
            match channel.scope() {
                ChannelScope::Local => local = local.saturating_add(1),
                ChannelScope::Global => global = global.saturating_add(1),
            }
        }
        (local, global)
    }

    /// Returns the number of content-free audit sanctions.
    #[must_use]
    pub fn sanction_count(&self) -> usize {
        self.sanctions.len()
    }

    /// Iterates content-free audit sanctions in application order.
    pub fn sanctions(&self) -> impl Iterator<Item = &Sanction> {
        self.sanctions.iter()
    }

    /// Resolves one canonical nickname to the current live user.
    #[must_use]
    pub fn resolve_nickname(&self, nickname: &NicknameValue) -> Option<UserId> {
        self.nicknames.get(nickname).copied()
    }

    /// Resolves one canonical channel name to its current channel creation.
    #[must_use]
    pub fn resolve_channel(&self, name: &ChannelNameValue) -> Option<ChannelInstanceId> {
        self.channel_names.get(name).copied()
    }

    /// Checks every cross-index and model invariant without changing state.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.validate_sessions()?;
        self.validate_channels()?;
        self.validate_accounts()?;
        self.validate_account_deletion_challenges()
    }

    fn validate_sessions(&self) -> Result<(), DomainError> {
        if self.sessions.len() != self.session_ids.len()
            || self.sessions.len() != self.nicknames.len()
            || self.sessions.len() != self.public_cloaks.len()
        {
            return Err(DomainError::InvariantViolation);
        }
        for (user_id, session) in &self.sessions {
            self.validate_session(user_id, session)?;
        }
        Ok(())
    }

    fn validate_session(
        &self,
        user_id: &UserId,
        session: &SessionState,
    ) -> Result<(), DomainError> {
        if user_id != &session.user_id
            || self.session_ids.get(&session.session_id) != Some(user_id)
            || self.nicknames.get(&session.nickname) != Some(user_id)
            || self.public_cloaks.get(&session.public_cloak) != Some(user_id)
            || session.joined_channels.len() > MAX_CHANNELS_PER_SESSION
            || session.monitored_nicknames.len() > MAX_MONITORED_NICKNAMES
        {
            return Err(DomainError::InvariantViolation);
        }
        self.validate_session_account(session)?;
        if session.joined_channels.iter().any(|channel_id| {
            self.channels
                .get(channel_id)
                .is_none_or(|channel| !channel.memberships.contains_key(user_id))
        }) {
            return Err(DomainError::InvariantViolation);
        }
        Ok(())
    }

    fn validate_session_account(&self, session: &SessionState) -> Result<(), DomainError> {
        match session.account_id {
            Some(account_id)
                if self.accounts.get(&account_id).is_none_or(|account| {
                    account.session_generation != session.account_session_generation
                }) =>
            {
                Err(DomainError::InvariantViolation)
            }
            None if session.account_session_generation.get() != 0
                || session.fresh_auth_deadline.is_some() =>
            {
                Err(DomainError::InvariantViolation)
            }
            Some(_) | None => Ok(()),
        }
    }

    fn validate_channels(&self) -> Result<(), DomainError> {
        if self.channels.len() != self.channel_names.len() {
            return Err(DomainError::InvariantViolation);
        }
        validate_network_invite_count(self.channels.values().map(|channel| channel.invites.len()))?;
        for (channel_id, channel) in &self.channels {
            channel.validate()?;
            if channel_id != &channel.channel_id
                || self.channel_names.get(&channel.name) != Some(channel_id)
            {
                return Err(DomainError::InvariantViolation);
            }
            self.validate_channel_memberships(channel)?;
        }
        Ok(())
    }

    fn validate_channel_memberships(&self, channel: &ChannelState) -> Result<(), DomainError> {
        if channel
            .role_grants
            .keys()
            .any(|account_id| !self.accounts.contains_key(account_id))
        {
            return Err(DomainError::InvariantViolation);
        }
        if channel.invites.values().any(|invite| match invite.target {
            Principal::Account(account_id) => !self.accounts.contains_key(&account_id),
            Principal::Guest(user_id) => !self.sessions.contains_key(&user_id),
        }) {
            return Err(DomainError::InvariantViolation);
        }
        for (user_id, membership) in &channel.memberships {
            let Some(session) = self.sessions.get(user_id) else {
                return Err(DomainError::InvariantViolation);
            };
            if membership.user_id != *user_id
                || membership.account_id != session.account_id
                || !session.joined_channels.contains(&channel.channel_id)
            {
                return Err(DomainError::InvariantViolation);
            }
        }
        Ok(())
    }

    fn validate_accounts(&self) -> Result<(), DomainError> {
        let mut reservations = BTreeMap::new();
        for (account_id, account) in &self.accounts {
            if account_id != &account.account_id
                || account.contacts.len() > MAX_CONTACTS_PER_ACCOUNT
                || account.reserved_nicknames.len() > MAX_RESERVED_NICKNAMES
            {
                return Err(DomainError::InvariantViolation);
            }
            let live = self
                .sessions
                .values()
                .filter(|session| session.account_id == Some(*account_id))
                .count();
            if live > MAX_SESSIONS_PER_ACCOUNT {
                return Err(DomainError::InvariantViolation);
            }
            for nickname in &account.reserved_nicknames {
                if reservations.insert(nickname, *account_id).is_some() {
                    return Err(DomainError::InvariantViolation);
                }
            }
        }
        for session in self.sessions.values() {
            if reservations
                .get(&session.nickname)
                .is_some_and(|owner| Some(*owner) != session.account_id)
            {
                return Err(DomainError::InvariantViolation);
            }
        }
        Ok(())
    }

    fn validate_account_deletion_challenges(&self) -> Result<(), DomainError> {
        if self.account_deletion_challenges.len() > self.sessions.len() {
            return Err(DomainError::InvariantViolation);
        }
        for (session_id, challenge) in &self.account_deletion_challenges {
            let user_id = self
                .session_ids
                .get(session_id)
                .ok_or(DomainError::InvariantViolation)?;
            let session = self
                .sessions
                .get(user_id)
                .ok_or(DomainError::InvariantViolation)?;
            if challenge.session_id != *session_id
                || challenge.user_id != *user_id
                || challenge.account_id
                    != session.account_id.ok_or(DomainError::InvariantViolation)?
                || challenge.account_session_generation != session.account_session_generation
                || challenge.session_generation != session.generation
                || session.fresh_auth_deadline.is_some()
            {
                return Err(DomainError::InvariantViolation);
            }
        }
        Ok(())
    }
}

fn validate_network_invite_count(
    invite_counts: impl IntoIterator<Item = usize>,
) -> Result<(), DomainError> {
    let mut total = 0_usize;
    for count in invite_counts {
        total = total
            .checked_add(count)
            .ok_or(DomainError::InvariantViolation)?;
        if total > MAX_INVITES_NETWORK_WIDE {
            return Err(DomainError::InvariantViolation);
        }
    }
    Ok(())
}

pub(crate) fn next_revision(revision: Revision) -> Result<Revision, DomainError> {
    revision.checked_add(1).map_err(Into::into)
}

impl DomainState {
    /// Rebuilds authoritative state from persisted projections and validates it.
    ///
    /// Sessions, memberships, invites, and pending removals start empty because they
    /// are never persisted. Duplicate identities and any invariant failure reject the
    /// whole input.
    pub fn restore(
        revision: Revision,
        accounts: Vec<DurableAccount>,
        channels: Vec<DurableChannel>,
        sanctions: Vec<DurableSanction>,
    ) -> Result<Self, DomainError> {
        let mut state = Self::at_revision(revision);
        for account in accounts {
            let account = account.into_state()?;
            if state.accounts.insert(account.account_id, account).is_some() {
                return Err(DomainError::InvariantViolation);
            }
        }
        for channel in channels {
            let channel = channel.into_state()?;
            let replaced_name = state
                .channel_names
                .insert(channel.name.clone(), channel.channel_id)
                .is_some();
            let replaced_id = state.channels.insert(channel.channel_id, channel).is_some();
            if replaced_name || replaced_id {
                return Err(DomainError::InvariantViolation);
            }
        }
        for sanction in sanctions {
            state.sanctions.push(sanction.into_state()?);
        }
        state.validate()?;
        Ok(state)
    }

    /// Projects one account into its persisted value.
    #[must_use]
    pub fn durable_account(&self, account_id: AccountId) -> Option<DurableAccount> {
        self.accounts
            .get(&account_id)
            .map(DurableAccount::from_state)
    }

    /// Projects one registered channel into its persisted value.
    #[must_use]
    pub fn durable_channel(&self, channel_id: ChannelInstanceId) -> Option<DurableChannel> {
        self.channels
            .get(&channel_id)
            .and_then(DurableChannel::from_state)
    }

    /// Iterates every account projection in ascending Account ID order.
    pub fn durable_accounts(&self) -> impl Iterator<Item = DurableAccount> + '_ {
        self.accounts.values().map(DurableAccount::from_state)
    }

    /// Iterates every registered channel projection in ascending instance order.
    pub fn durable_channels(&self) -> impl Iterator<Item = DurableChannel> + '_ {
        self.channels
            .values()
            .filter_map(DurableChannel::from_state)
    }

    /// Iterates every sanction projection in application order.
    pub fn durable_sanctions(&self) -> impl Iterator<Item = DurableSanction> + '_ {
        self.sanctions.iter().map(DurableSanction::from_state)
    }

    /// Finds the account holding a durable reservation for one canonical nickname.
    #[must_use]
    pub fn nickname_reserved_by(&self, nickname: &NicknameValue) -> Option<AccountId> {
        self.accounts
            .values()
            .find(|account| account.reserved_nicknames.contains(nickname))
            .map(|account| account.account_id)
    }
}

#[cfg(test)]
pub(crate) fn tests_support_account_id(seed: u8) -> AccountId {
    AccountId::from_random(agenc_ircd_types::AccountRandomId::from_bytes([seed; 16]))
}

#[cfg(test)]
pub(crate) fn test_public_cloak(seed: u8) -> Result<PublicCloak, DomainError> {
    const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    let high = usize::from(seed) / BASE32.len();
    let low = usize::from(seed) % BASE32.len();
    let high = char::from(*BASE32.get(high).ok_or(DomainError::InvariantViolation)?);
    let low = char::from(*BASE32.get(low).ok_or(DomainError::InvariantViolation)?);
    PublicCloak::parse(&format!("aaaaaaaa{high}{low}"), "bbbbbbbbbbbbbbbb").map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_types::{AccountRandomId, ControlPolicy};

    #[test]
    fn operational_limits_validate_hard_bounds_and_replace_atomically() -> Result<(), DomainError> {
        let lowered = OperationalLimits::new(OperationalLimitValues {
            sessions_per_account: 2,
            channels_per_session: 3,
            members_per_channel: 4,
            global_channels: 5,
            local_channels: 6,
            invites_per_channel: 7,
            invites_per_principal: 8,
            invites_global: 9,
            contacts_per_account: 10,
        })?;
        let mut state = DomainState::new()?;
        assert_eq!(state.operational_limits(), OperationalLimits::HARD_MAX);
        state.set_operational_limits(lowered);
        assert_eq!(state.operational_limits(), lowered);

        let mut invalid = lowered.values();
        invalid.sessions_per_account = 0;
        assert_eq!(
            OperationalLimits::new(invalid),
            Err(DomainError::InvalidArgument)
        );
        invalid = OperationalLimits::HARD_MAX.values();
        invalid.local_channels = MAX_LOCAL_CHANNELS.saturating_add(1);
        assert_eq!(
            OperationalLimits::new(invalid),
            Err(DomainError::InvalidArgument)
        );
        Ok(())
    }

    fn id(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn account(seed: u8) -> AccountId {
        AccountId::from_random(AccountRandomId::from_bytes(id(seed)))
    }

    fn session(seed: u8, account_id: Option<AccountId>) -> Result<SessionState, DomainError> {
        Ok(SessionState::from_seed(SessionSeed {
            session_id: SessionId::from_bytes(id(seed)),
            user_id: UserId::from_bytes(id(seed.wrapping_add(64))),
            home_server_id: ServerId::from_bytes(id(240)),
            account_id,
            account_session_generation: Generation::new(u64::from(account_id.is_some()))?,
            generation: Generation::new(1)?,
            nickname: NicknameValue::parse(&format!("user{seed}"))?,
            display_name: DisplayNameValue::prepare(&format!("User {seed}"))?,
            public_cloak: test_public_cloak(seed)?,
            connection_nonce: [seed; 32],
            negotiated_capability_hash: [seed.wrapping_add(1); 32],
            created_at_utc: UtcSecond::from_unix_seconds(10),
            revision: Revision::new(1)?,
        }))
    }

    fn channel(seed: u8, name: &str) -> Result<ChannelState, DomainError> {
        let user_id = UserId::from_bytes(id(seed.wrapping_add(64)));
        Ok(ChannelState::new_ephemeral(
            ChannelInstanceId::from_bytes(id(seed)),
            ChannelNameValue::parse(name)?,
            Principal::Guest(user_id),
            Membership::new(user_id, None, Role::Owner),
            UtcSecond::from_unix_seconds(10),
            Revision::new(1)?,
        ))
    }

    fn entry(seed: u8) -> Result<ListEntry, DomainError> {
        Ok(ListEntry::new(
            EntryId::from_bytes(id(seed)),
            TypedMask::parse("$n:blocked")?,
            Principal::Guest(UserId::from_bytes(id(seed))),
            UtcSecond::from_unix_seconds(10),
        ))
    }

    fn indexed_id(index: usize) -> Result<[u8; 16], DomainError> {
        let mut raw = [0_u8; 16];
        raw[..8].copy_from_slice(
            &u64::try_from(index)
                .map_err(|_| DomainError::Overflow)?
                .to_be_bytes(),
        );
        Ok(raw)
    }

    fn insert_session(state: &mut DomainState, value: SessionState) {
        state.session_ids.insert(value.session_id, value.user_id);
        state
            .nicknames
            .insert(value.nickname.clone(), value.user_id);
        state
            .public_cloaks
            .insert(value.public_cloak, value.user_id);
        state.sessions.insert(value.user_id, value);
    }

    fn guest_channel_state(
        seed: u8,
        name: &str,
    ) -> Result<(DomainState, ChannelInstanceId, UserId), DomainError> {
        let mut state = DomainState::new()?;
        let mut live = session(seed, None)?;
        let value = channel(seed, name)?;
        let channel_id = value.channel_id;
        let user_id = live.user_id;
        live.joined_channels.insert(channel_id);
        insert_session(&mut state, live);
        state.channel_names.insert(value.name.clone(), channel_id);
        state.channels.insert(channel_id, value);
        state.validate()?;
        Ok((state, channel_id, user_id))
    }

    fn deletion_challenge_state(
        seed: u8,
    ) -> Result<(DomainState, SessionId, UserId, AccountId), DomainError> {
        let mut state = DomainState::new()?;
        let account_id = account(seed);
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, Generation::new(1)?, state.revision),
        );
        let live = session(seed, Some(account_id))?;
        let session_id = live.session_id;
        let user_id = live.user_id;
        let session_generation = live.generation;
        let account_session_generation = live.account_session_generation;
        insert_session(&mut state, live);
        state.account_deletion_challenges.insert(
            session_id,
            AccountDeletionChallengeState {
                token: AccountDeletionToken::from_bytes(id(seed.wrapping_add(1))),
                account_id,
                account_revision: state.revision,
                account_session_generation,
                session_id,
                user_id,
                session_generation,
                expires_at: MonotonicTick::from_ticks(100),
            },
        );
        state.validate()?;
        Ok((state, session_id, user_id, account_id))
    }

    #[test]
    fn channel_validation_rejects_each_policy_and_role_invariant() -> Result<(), DomainError> {
        assert_eq!(channel(1, "#valid")?.validate(), Ok(()));
        assert_eq!(channel(1, "&valid-local")?.validate(), Ok(()));

        let mut value = channel(1, "&local")?;
        value.content_policy = ContentPolicy::E2eeBound;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

        let mut value = channel(1, "#history")?;
        value.history = HistoryPolicy::OneHour;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
        value.persistence = PersistencePolicy::Registered;
        value.role_grants.insert(account(1), Role::Owner);
        value.visibility = Visibility::Unlisted;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
        value.visibility = Visibility::Listed;
        value.content_policy = ContentPolicy::E2eeBound;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

        let mut value = channel(1, "#owner")?;
        value.persistence = PersistencePolicy::Registered;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

        let mut value = channel(1, "#roles")?;
        let membership = value
            .memberships
            .values_mut()
            .next()
            .ok_or(DomainError::InvariantViolation)?;
        membership.effective_role = Role::Member;
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));

        let mut value = channel(1, "#registered-session-role")?;
        let account_id = account(1);
        value.persistence = PersistencePolicy::Registered;
        value.role_grants.insert(account_id, Role::Owner);
        {
            let membership = value
                .memberships
                .values_mut()
                .next()
                .ok_or(DomainError::InvariantViolation)?;
            membership.account_id = Some(account_id);
            membership.session_role = Role::Owner;
            membership.effective_role = Role::Owner;
        }
        assert_eq!(value.validate(), Err(DomainError::InvariantViolation));
        value
            .memberships
            .values_mut()
            .next()
            .ok_or(DomainError::InvariantViolation)?
            .session_role = Role::Member;
        assert_eq!(value.validate(), Ok(()));

        let mut value = channel(1, "#scope")?;
        value.scope = ChannelScope::Local;
        assert!(!value.identities_and_limits_are_valid());
        Ok(())
    }

    #[test]
    fn channel_limits_and_invite_matching_are_bounded() -> Result<(), DomainError> {
        let mut value = channel(2, "#lists")?;
        for seed in 0..=MAX_MASK_ENTRIES_PER_LIST {
            value.bans.push(entry(
                u8::try_from(seed).map_err(|_| DomainError::Overflow)?,
            )?);
        }
        assert!(!value.identities_and_limits_are_valid());

        let mut value = channel(2, "#exceptions")?;
        for seed in 0..=MAX_MASK_ENTRIES_PER_LIST {
            value.exceptions.push(entry(
                u8::try_from(seed).map_err(|_| DomainError::Overflow)?,
            )?);
        }
        assert!(!value.identities_and_limits_are_valid());

        let mut value = channel(2, "#invite-exceptions")?;
        for seed in 0..=MAX_MASK_ENTRIES_PER_LIST {
            value.invite_exceptions.push(entry(
                u8::try_from(seed).map_err(|_| DomainError::Overflow)?,
            )?);
        }
        assert!(!value.identities_and_limits_are_valid());

        let mut value = channel(2, "#invites")?;
        let target = Principal::Guest(UserId::from_bytes(id(90)));
        for index in 0..=MAX_INVITES_PER_CHANNEL {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(
                &u64::try_from(index)
                    .map_err(|_| DomainError::Overflow)?
                    .to_be_bytes(),
            );
            let invite_id = InviteId::from_bytes(bytes);
            value.invites.insert(
                invite_id,
                Invite {
                    invite_id,
                    target,
                    inviter: UserId::from_bytes(id(1)),
                    creation_revision: Revision::new(1)?,
                    expires_at: MonotonicTick::from_ticks(100),
                },
            );
        }
        assert!(!value.identities_and_limits_are_valid());
        assert_eq!(
            value.matching_invite(target, MonotonicTick::from_ticks(100)),
            None
        );
        assert_eq!(
            value.matching_invite(
                Principal::Guest(UserId::from_bytes(id(91))),
                MonotonicTick::from_ticks(99),
            ),
            None
        );
        assert!(
            value
                .matching_invite(target, MonotonicTick::from_ticks(99))
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn domain_cross_indexes_fail_closed_for_each_mismatch() -> Result<(), DomainError> {
        let valid_session = session(3, None)?;
        let user_id = valid_session.user_id;
        let session_id = valid_session.session_id;
        let nickname = valid_session.nickname.clone();
        let public_cloak = valid_session.public_cloak;

        let mut state = DomainState::new()?;
        state.sessions.insert(user_id, valid_session);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        state.session_ids.insert(session_id, user_id);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        state.nicknames.insert(nickname.clone(), user_id);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        state.public_cloaks.insert(public_cloak, user_id);
        assert_eq!(state.validate(), Ok(()));
        state
            .session_ids
            .insert(session_id, UserId::from_bytes(id(99)));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        state.session_ids.insert(session_id, user_id);
        state
            .nicknames
            .insert(nickname.clone(), UserId::from_bytes(id(98)));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        state.nicknames.insert(nickname, user_id);
        state
            .public_cloaks
            .insert(public_cloak, UserId::from_bytes(id(97)));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let value = channel(4, "#indexed")?;
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let value = channel(4, "#indexed")?;
        state
            .channel_names
            .insert(value.name.clone(), ChannelInstanceId::from_bytes(id(99)));
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let value = channel(4, "#wrong-channel-key")?;
        let wrong_id = ChannelInstanceId::from_bytes(id(98));
        state.channel_names.insert(value.name.clone(), wrong_id);
        state.channels.insert(wrong_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn duplicate_live_public_cloaks_are_rejected_as_corrupt_state() -> Result<(), DomainError> {
        let first = session(5, None)?;
        let mut second = session(6, None)?;
        second.public_cloak = first.public_cloak;

        let mut state = DomainState::new()?;
        insert_session(&mut state, first);
        insert_session(&mut state, second);

        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn account_and_membership_invariants_reject_corrupt_value_state() -> Result<(), DomainError> {
        let account_id = account(5);
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account(6),
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?),
        );
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let mut value = channel(5, "#membership")?;
        let user_id = value
            .memberships
            .keys()
            .next()
            .copied()
            .ok_or(DomainError::InvariantViolation)?;
        value
            .memberships
            .get_mut(&user_id)
            .ok_or(DomainError::InvariantViolation)?
            .account_id = Some(account_id);
        state
            .channel_names
            .insert(value.name.clone(), value.channel_id);
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let bounded = ModerationReason::try_from_str("reason", ControlPolicy::RejectAll)?;
        assert_eq!(bounded.as_str(), "reason");
        Ok(())
    }

    #[test]
    fn history_and_large_channel_limits_cover_each_short_circuit() -> Result<(), DomainError> {
        let mut value = channel(7, "#history-matrix")?;
        assert!(HistoryPolicy::Off.is_allowed_for(&value));
        assert!(!HistoryPolicy::OneHour.is_allowed_for(&value));
        value.persistence = PersistencePolicy::Registered;
        value.role_grants.insert(account(7), Role::Owner);
        assert!(HistoryPolicy::OneHour.is_allowed_for(&value));
        value.scope = ChannelScope::Local;
        assert!(!HistoryPolicy::OneHour.is_allowed_for(&value));
        value.scope = ChannelScope::Global;
        value.visibility = Visibility::Secret;
        assert!(!HistoryPolicy::TwentyFourHours.is_allowed_for(&value));
        value.visibility = Visibility::Listed;
        value.content_policy = ContentPolicy::E2eeBound;
        assert!(!HistoryPolicy::SevenDays.is_allowed_for(&value));

        let mut member_limited = channel(8, "#member-limit")?;
        for index in 0..=MAX_MEMBERS_PER_CHANNEL {
            let user_id = UserId::from_bytes(indexed_id(index)?);
            member_limited
                .memberships
                .insert(user_id, Membership::new(user_id, None, Role::Member));
        }
        assert!(!member_limited.identities_and_limits_are_valid());

        let mut grant_limited = channel(9, "#grant-limit")?;
        for index in 0..=MAX_ROLE_GRANTS_PER_CHANNEL {
            let account_id =
                AccountId::from_random(AccountRandomId::from_bytes(indexed_id(index)?));
            grant_limited.role_grants.insert(account_id, Role::Member);
        }
        assert!(!grant_limited.identities_and_limits_are_valid());
        Ok(())
    }

    #[test]
    fn session_invariants_reject_each_corrupt_identity_and_authority_fence()
    -> Result<(), DomainError> {
        let valid = session(10, None)?;
        let mut state = DomainState::new()?;
        state.session_ids.insert(valid.session_id, valid.user_id);
        state
            .nicknames
            .insert(valid.nickname.clone(), valid.user_id);
        state
            .public_cloaks
            .insert(valid.public_cloak, valid.user_id);
        state.sessions.insert(UserId::from_bytes(id(250)), valid);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let mut value = session(11, None)?;
        value.account_session_generation = Generation::new(1)?;
        insert_session(&mut state, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let registered = account(12);
        let mut state = DomainState::new()?;
        insert_session(&mut state, session(12, Some(registered))?);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        state.accounts.insert(
            registered,
            AccountState::new(registered, Generation::new(2)?, Revision::new(1)?),
        );
        insert_session(&mut state, session(12, Some(registered))?);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let mut value = session(13, None)?;
        value
            .joined_channels
            .insert(ChannelInstanceId::from_bytes(id(13)));
        insert_session(&mut state, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let mut value = session(14, None)?;
        for index in 0..=MAX_CHANNELS_PER_SESSION {
            value
                .joined_channels
                .insert(ChannelInstanceId::from_bytes(indexed_id(index)?));
        }
        insert_session(&mut state, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn channel_membership_and_account_indexes_reject_each_corrupt_relation()
    -> Result<(), DomainError> {
        let mut state = DomainState::new()?;
        let value = channel(15, "#missing-role-account")?;
        let channel_id = value.channel_id;
        let mut value = value;
        value.role_grants.insert(account(15), Role::Owner);
        value.persistence = PersistencePolicy::Registered;
        state.channel_names.insert(value.name.clone(), channel_id);
        state.channels.insert(channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let value = channel(16, "#missing-member-session")?;
        state
            .channel_names
            .insert(value.name.clone(), value.channel_id);
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let live = session(17, None)?;
        let live_user = live.user_id;
        insert_session(&mut state, live);
        let mut value = channel(18, "#member-key")?;
        let existing = value
            .memberships
            .values()
            .next()
            .copied()
            .ok_or(DomainError::InvariantViolation)?;
        value.memberships.clear();
        value.memberships.insert(live_user, existing);
        state
            .channel_names
            .insert(value.name.clone(), value.channel_id);
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let account_id = account(19);
        let mut state = DomainState::new()?;
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?),
        );
        let live = session(19, Some(account_id))?;
        let live_user = live.user_id;
        insert_session(&mut state, live);
        let mut value = channel(20, "#member-account")?;
        value.memberships.clear();
        value
            .memberships
            .insert(live_user, Membership::new(live_user, None, Role::Member));
        state
            .channel_names
            .insert(value.name.clone(), value.channel_id);
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?),
        );
        let live = session(20, Some(account_id))?;
        let live_user = live.user_id;
        insert_session(&mut state, live);
        let mut value = channel(21, "#reverse-membership")?;
        value.memberships.clear();
        value.memberships.insert(
            live_user,
            Membership::new(live_user, Some(account_id), Role::Member),
        );
        state
            .channel_names
            .insert(value.name.clone(), value.channel_id);
        state.channels.insert(value.channel_id, value);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn account_limits_and_reservations_reject_each_corrupt_relation() -> Result<(), DomainError> {
        let account_id = account(22);
        let mut contact_limited =
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?);
        for index in 0..=MAX_CONTACTS_PER_ACCOUNT {
            contact_limited
                .contacts
                .insert(AccountId::from_random(AccountRandomId::from_bytes(
                    indexed_id(index)?,
                )));
        }
        let mut state = DomainState::new()?;
        state.accounts.insert(account_id, contact_limited);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut reservation_limited =
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?);
        for index in 0..=MAX_RESERVED_NICKNAMES {
            reservation_limited
                .reserved_nicknames
                .insert(NicknameValue::parse(&format!("reserve{index}"))?);
        }
        let mut state = DomainState::new()?;
        state.accounts.insert(account_id, reservation_limited);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        state.accounts.insert(
            account_id,
            AccountState::new(account_id, Generation::new(1)?, Revision::new(1)?),
        );
        for index in 0..=MAX_SESSIONS_PER_ACCOUNT {
            let value = session(
                u8::try_from(index + 30).map_err(|_| DomainError::Overflow)?,
                Some(account_id),
            )?;
            insert_session(&mut state, value);
        }
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let first = account(23);
        let second = account(24);
        let reserved = NicknameValue::parse("reserved")?;
        let mut first_state = AccountState::new(first, Generation::new(1)?, Revision::new(1)?);
        first_state.reserved_nicknames.insert(reserved.clone());
        let mut second_state = AccountState::new(second, Generation::new(1)?, Revision::new(1)?);
        second_state.reserved_nicknames.insert(reserved.clone());
        let mut state = DomainState::new()?;
        state.accounts.insert(first, first_state);
        state.accounts.insert(second, second_state);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut state = DomainState::new()?;
        let mut first_state = AccountState::new(first, Generation::new(1)?, Revision::new(1)?);
        first_state.reserved_nicknames.insert(reserved.clone());
        state.accounts.insert(first, first_state);
        state.accounts.insert(
            second,
            AccountState::new(second, Generation::new(1)?, Revision::new(1)?),
        );
        let mut live = session(25, Some(second))?;
        state.nicknames.remove(&live.nickname);
        live.nickname = reserved;
        insert_session(&mut state, live);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn session_limits_and_guest_auth_fences_reject_corrupt_state() -> Result<(), DomainError> {
        let mut monitored = session(26, None)?;
        for index in 0..=MAX_MONITORED_NICKNAMES {
            monitored
                .monitored_nicknames
                .insert(NicknameValue::parse(&format!("watch{index}"))?);
        }
        let mut state = DomainState::new()?;
        insert_session(&mut state, monitored);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let mut guest = session(27, None)?;
        guest.fresh_auth_deadline = Some(MonotonicTick::from_ticks(1));
        let mut state = DomainState::new()?;
        insert_session(&mut state, guest);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn network_invite_count_rejects_limit_excess_and_arithmetic_overflow() {
        assert_eq!(validate_network_invite_count([]), Ok(()));
        assert_eq!(
            validate_network_invite_count([MAX_INVITES_NETWORK_WIDE]),
            Ok(())
        );
        assert_eq!(
            validate_network_invite_count([MAX_INVITES_NETWORK_WIDE, 1]),
            Err(DomainError::InvariantViolation)
        );
        assert_eq!(
            validate_network_invite_count([1, usize::MAX]),
            Err(DomainError::InvariantViolation)
        );
    }

    #[test]
    fn channel_invites_reject_missing_guest_and_account_targets() -> Result<(), DomainError> {
        let (mut state, channel_id, _) = guest_channel_state(28, "#guest-invite")?;
        let invite_id = InviteId::from_bytes(id(28));
        state
            .channels
            .get_mut(&channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                invite_id,
                Invite {
                    invite_id,
                    target: Principal::Guest(UserId::from_bytes(id(250))),
                    inviter: UserId::from_bytes(id(28)),
                    creation_revision: state.revision,
                    expires_at: MonotonicTick::from_ticks(100),
                },
            );
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, channel_id, user_id) = guest_channel_state(29, "#account-invite")?;
        let invite_id = InviteId::from_bytes(id(29));
        state
            .channels
            .get_mut(&channel_id)
            .ok_or(DomainError::InvariantViolation)?
            .invites
            .insert(
                invite_id,
                Invite {
                    invite_id,
                    target: Principal::Account(account(250)),
                    inviter: user_id,
                    creation_revision: state.revision,
                    expires_at: MonotonicTick::from_ticks(100),
                },
            );
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }

    #[test]
    fn deletion_challenges_reject_each_corrupt_session_binding() -> Result<(), DomainError> {
        let (mut state, session_id, user_id, _) = deletion_challenge_state(30)?;
        let (nickname, public_cloak) = {
            let session = state
                .sessions
                .get(&user_id)
                .ok_or(DomainError::InvariantViolation)?;
            (session.nickname.clone(), session.public_cloak)
        };
        state.sessions.remove(&user_id);
        state.session_ids.remove(&session_id);
        state.nicknames.remove(&nickname);
        state.public_cloaks.remove(&public_cloak);
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, session_id, _, _) = deletion_challenge_state(31)?;
        state
            .account_deletion_challenges
            .get_mut(&session_id)
            .ok_or(DomainError::InvariantViolation)?
            .session_id = SessionId::from_bytes(id(250));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, session_id, _, _) = deletion_challenge_state(32)?;
        state
            .account_deletion_challenges
            .get_mut(&session_id)
            .ok_or(DomainError::InvariantViolation)?
            .user_id = UserId::from_bytes(id(250));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, session_id, _, _) = deletion_challenge_state(33)?;
        let other_account = account(250);
        state.accounts.insert(
            other_account,
            AccountState::new(other_account, Generation::new(1)?, state.revision),
        );
        state
            .account_deletion_challenges
            .get_mut(&session_id)
            .ok_or(DomainError::InvariantViolation)?
            .account_id = other_account;
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, session_id, _, _) = deletion_challenge_state(34)?;
        state
            .account_deletion_challenges
            .get_mut(&session_id)
            .ok_or(DomainError::InvariantViolation)?
            .account_session_generation = Generation::new(2)?;
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, session_id, _, _) = deletion_challenge_state(35)?;
        state
            .account_deletion_challenges
            .get_mut(&session_id)
            .ok_or(DomainError::InvariantViolation)?
            .session_generation = Generation::new(2)?;
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, _, user_id, _) = deletion_challenge_state(36)?;
        state
            .sessions
            .get_mut(&user_id)
            .ok_or(DomainError::InvariantViolation)?
            .fresh_auth_deadline = Some(MonotonicTick::from_ticks(1));
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));

        let (mut state, _, user_id, _) = deletion_challenge_state(37)?;
        let live = state
            .sessions
            .get_mut(&user_id)
            .ok_or(DomainError::InvariantViolation)?;
        live.account_id = None;
        live.account_session_generation = Generation::new(0)?;
        assert_eq!(state.validate(), Err(DomainError::InvariantViolation));
        Ok(())
    }
}
