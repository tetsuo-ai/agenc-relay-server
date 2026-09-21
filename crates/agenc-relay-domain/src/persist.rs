//! Durable projections of authoritative domain entities.
//!
//! Fresh-authentication proofs, monitor query state, sockets, and output queues
//! remain process-local. Accounts, logical sessions, channels, and sanctions
//! have canonical durable after-images. This module owns those values and the
//! logical write set a plan produces without naming a storage codec, key, or
//! handle.

use std::fmt;

use agenc_relay_types::{
    AccountId, ChannelInstanceId, ControlPolicy, EntryId, Generation, InviteId, MaskSubject,
    MessageId, MonotonicTick, PublicCloak, Revision, ServerId, SessionId, TypedMask, UserId,
    UtcSecond,
};

use crate::error::DomainError;
use crate::model::{
    AccountLabelValue, AccountState, AwayText, ChannelKeyVerifier, ChannelModes, ChannelNameValue,
    ChannelScope, ChannelState, ContentPolicy, DirectMessagePolicy, DisplayNameValue,
    GuestDirectMessagePolicy, HistoryPolicy, ListEntry, ModerationAction, ModerationReason,
    ModerationReasonCode, NicknameValue, PersistencePolicy, PlaintextTopic, PresencePolicy,
    Principal, Role, Sanction, SessionState, TopicText, Visibility,
};

/// The persisted value of one account.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableAccount {
    /// Immutable account authority.
    pub account_id: AccountId,
    /// Optional public label.
    pub label: Option<AccountLabelValue>,
    /// Account-wide presence policy.
    pub presence: PresencePolicy,
    /// Guest direct-message policy.
    pub guest_direct_messages: GuestDirectMessagePolicy,
    /// Authenticated direct-message policy.
    pub direct_messages: DirectMessagePolicy,
    /// Unilateral contacts in ascending Account ID order without duplicates.
    pub contacts: Vec<AccountId>,
    /// Reserved nicknames in canonical order without duplicates.
    pub reserved_nicknames: Vec<NicknameValue>,
    /// Account-session fence.
    pub session_generation: Generation,
    /// Revision of the last persisted change to this account.
    pub revision: Revision,
    /// Optional bounded administrative suspension that survives audit retention.
    pub admin_suspension_expires_at: Option<UtcSecond>,
}

impl DurableAccount {
    pub(crate) fn from_state(account: &AccountState) -> Self {
        Self {
            account_id: account.account_id,
            label: account.label.clone(),
            presence: account.presence,
            guest_direct_messages: account.guest_direct_messages,
            direct_messages: account.direct_messages,
            contacts: account.contacts.iter().copied().collect(),
            reserved_nicknames: account.reserved_nicknames.iter().cloned().collect(),
            session_generation: account.session_generation,
            revision: account.revision,
            admin_suspension_expires_at: account.admin_suspension_expires_at,
        }
    }

    pub(crate) fn into_state(self) -> Result<AccountState, DomainError> {
        if !strictly_ascending(&self.contacts) || !strictly_ascending(&self.reserved_nicknames) {
            return Err(DomainError::InvalidArgument);
        }
        Ok(AccountState {
            account_id: self.account_id,
            label: self.label,
            presence: self.presence,
            guest_direct_messages: self.guest_direct_messages,
            direct_messages: self.direct_messages,
            contacts: self.contacts.into_iter().collect(),
            reserved_nicknames: self.reserved_nicknames.into_iter().collect(),
            session_generation: self.session_generation,
            revision: self.revision,
            admin_suspension_expires_at: self.admin_suspension_expires_at,
        })
    }

    /// Compares every persisted field except the revision.
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.account_id == other.account_id
            && self.label == other.label
            && self.presence == other.presence
            && self.guest_direct_messages == other.guest_direct_messages
            && self.direct_messages == other.direct_messages
            && self.contacts == other.contacts
            && self.reserved_nicknames == other.reserved_nicknames
            && self.session_generation == other.session_generation
            && self.admin_suspension_expires_at == other.admin_suspension_expires_at
    }
}

/// The persisted coordinator-owned portion of one logical session.
///
/// Monitor selections and fresh-authentication deadlines are deliberately
/// absent because they are process-local. The connection nonce is private
/// origin-binding state and must never enter formatting or diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableSession {
    /// Immutable accepted session identity and storage key.
    pub session_id: SessionId,
    /// Immutable per-connection user identity.
    pub user_id: UserId,
    /// Server that owns the physical connection or suspended origin.
    pub home_server_id: ServerId,
    /// Optional authenticated account authority.
    pub account_id: Option<AccountId>,
    /// Account-session fence, zero exactly for guests.
    pub account_session_generation: Generation,
    /// Session/origin generation used to reject stale completions.
    pub generation: Generation,
    /// Current routing nickname.
    pub nickname: NicknameValue,
    /// Current prepared presentation name.
    pub display_name: DisplayNameValue,
    /// Independently random public cloak.
    pub public_cloak: PublicCloak,
    /// Optional bounded away text.
    pub away: Option<String>,
    /// Whether bounded operator notices are enabled.
    pub operator_notices: bool,
    /// Private companion origin binding.
    pub connection_nonce: [u8; 32],
    /// Hash of the sorted negotiated capability names.
    pub negotiated_capability_hash: [u8; 32],
    /// Joined channel identities in ascending order without duplicates.
    pub joined_channels: Vec<ChannelInstanceId>,
    /// Accepted wall-clock creation second.
    pub created_at_utc: UtcSecond,
    /// Revision of the last authoritative session change.
    pub revision: Revision,
}

impl DurableSession {
    /// Captures every persistable field from one validated live session.
    #[must_use]
    pub fn from_state(session: &SessionState) -> Self {
        Self {
            session_id: session.session_id,
            user_id: session.user_id,
            home_server_id: session.home_server_id,
            account_id: session.account_id,
            account_session_generation: session.account_session_generation,
            generation: session.generation,
            nickname: session.nickname.clone(),
            display_name: session.display_name.clone(),
            public_cloak: session.public_cloak,
            away: session.away.as_ref().map(|away| away.as_str().to_owned()),
            operator_notices: session.operator_notices,
            connection_nonce: session.connection_nonce,
            negotiated_capability_hash: session.negotiated_capability_hash,
            joined_channels: session.joined_channels.iter().copied().collect(),
            created_at_utc: session.created_at_utc,
            revision: session.revision,
        }
    }

    /// Rebuilds one live session while clearing process-local state.
    pub fn into_state(self) -> Result<SessionState, DomainError> {
        if !strictly_ascending(&self.joined_channels)
            || self.account_id.is_none() != (self.account_session_generation.get() == 0)
            || self.generation.get() == 0
        {
            return Err(DomainError::InvalidArgument);
        }
        let away = self
            .away
            .map(|text| AwayText::try_from_str(&text, ControlPolicy::PermitHorizontalTab))
            .transpose()?;
        Ok(SessionState {
            session_id: self.session_id,
            user_id: self.user_id,
            home_server_id: self.home_server_id,
            account_id: self.account_id,
            account_session_generation: self.account_session_generation,
            generation: self.generation,
            nickname: self.nickname,
            display_name: self.display_name,
            public_cloak: self.public_cloak,
            away,
            operator_notices: self.operator_notices,
            monitored_nicknames: Default::default(),
            connection_nonce: self.connection_nonce,
            negotiated_capability_hash: self.negotiated_capability_hash,
            joined_channels: self.joined_channels.into_iter().collect(),
            created_at_utc: self.created_at_utc,
            fresh_auth_deadline: None,
            revision: self.revision,
        })
    }

    /// Compares every persisted field except the revision.
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.content_key() == other.content_key()
    }

    fn content_key(&self) -> DurableSessionContentKey<'_> {
        (
            (
                &self.session_id,
                &self.user_id,
                &self.home_server_id,
                &self.account_id,
                &self.account_session_generation,
                &self.generation,
                &self.nickname,
                &self.display_name,
                &self.public_cloak,
            ),
            (
                &self.away,
                &self.operator_notices,
                &self.connection_nonce,
                &self.negotiated_capability_hash,
                &self.joined_channels,
                &self.created_at_utc,
            ),
        )
    }
}

/// Every durable session field except the revision, borrowed for comparison.
type DurableSessionContentKey<'a> = (
    (
        &'a SessionId,
        &'a UserId,
        &'a ServerId,
        &'a Option<AccountId>,
        &'a Generation,
        &'a Generation,
        &'a NicknameValue,
        &'a DisplayNameValue,
        &'a PublicCloak,
    ),
    (
        &'a Option<String>,
        &'a bool,
        &'a [u8; 32],
        &'a [u8; 32],
        &'a [ChannelInstanceId],
        &'a UtcSecond,
    ),
);

/// The persisted value of one plaintext topic.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableTopic {
    /// Validated topic text.
    pub text: String,
    /// Topic assignment identity.
    pub message_id: MessageId,
    /// Live user that set the topic.
    pub setter: UserId,
    /// Authoritative topic second.
    pub set_at: UtcSecond,
}

impl DurableTopic {
    fn from_state(topic: &PlaintextTopic) -> Self {
        Self {
            text: topic.text.as_str().to_owned(),
            message_id: topic.message_id,
            setter: topic.setter,
            set_at: topic.set_at,
        }
    }

    fn into_state(self) -> Result<PlaintextTopic, DomainError> {
        Ok(PlaintextTopic {
            text: TopicText::try_from_str(&self.text, ControlPolicy::PermitHorizontalTab)?,
            message_id: self.message_id,
            setter: self.setter,
            set_at: self.set_at,
        })
    }
}

/// The persisted value of one typed list entry.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableListEntry {
    /// Entry identity.
    pub entry_id: EntryId,
    /// Canonical typed mask text.
    pub mask: String,
    /// Principal that created the entry.
    pub setter: Principal,
    /// Authoritative creation second.
    pub created_at: UtcSecond,
}

/// The persisted authority and timing of one live channel membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableMembership {
    /// Live user identity and canonical vector key.
    pub user_id: UserId,
    /// Optional authenticated account authority.
    pub account_id: Option<AccountId>,
    /// Highest role granted to this live session.
    pub session_role: Role,
    /// Effective role after any durable account grant.
    pub effective_role: Role,
    /// Channel revision that accepted the membership.
    pub membership_revision: Revision,
    /// Accepted wall-clock join second.
    pub joined_at: UtcSecond,
}

impl DurableMembership {
    fn from_state(membership: &crate::Membership) -> Self {
        Self {
            user_id: membership.user_id,
            account_id: membership.account_id,
            session_role: membership.session_role,
            effective_role: membership.effective_role,
            membership_revision: membership.membership_revision,
            joined_at: membership.joined_at,
        }
    }

    fn into_state(self) -> crate::Membership {
        crate::Membership {
            user_id: self.user_id,
            account_id: self.account_id,
            session_role: self.session_role,
            effective_role: self.effective_role,
            membership_revision: self.membership_revision,
            joined_at: self.joined_at,
        }
    }
}

/// The persisted wall-clock projection of one pending channel invite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableInvite {
    /// Immutable invite identity and canonical vector key.
    pub invite_id: InviteId,
    /// Guest User ID or authenticated Account ID authorized to consume it.
    pub target: Principal,
    /// Live user that created the invite.
    pub inviter: UserId,
    /// Channel revision that created the invite.
    pub creation_revision: Revision,
    /// Absolute expiry used to reconcile the invite after restart.
    pub expires_at_utc: UtcSecond,
}

impl DurableInvite {
    fn from_state(invite: &crate::model::Invite) -> Self {
        Self {
            invite_id: invite.invite_id,
            target: invite.target,
            inviter: invite.inviter,
            creation_revision: invite.creation_revision,
            expires_at_utc: invite.expires_at_utc,
        }
    }

    fn into_state(
        self,
        monotonic_now: MonotonicTick,
        utc_now: UtcSecond,
    ) -> Result<crate::model::Invite, DomainError> {
        let remaining_seconds = self.expires_at_utc.get().saturating_sub(utc_now.get());
        let remaining_milliseconds = remaining_seconds
            .checked_mul(1_000)
            .ok_or(DomainError::Overflow)?;
        let expires_at = monotonic_now.checked_add(remaining_milliseconds)?;
        Ok(crate::model::Invite {
            invite_id: self.invite_id,
            target: self.target,
            inviter: self.inviter,
            creation_revision: self.creation_revision,
            expires_at,
            expires_at_utc: self.expires_at_utc,
        })
    }
}

impl DurableListEntry {
    fn from_state(entry: &ListEntry) -> Self {
        Self {
            entry_id: entry.entry_id,
            mask: typed_mask_text(&entry.mask),
            setter: entry.setter,
            created_at: entry.created_at,
        }
    }

    fn into_state(self) -> Result<ListEntry, DomainError> {
        Ok(ListEntry::new(
            self.entry_id,
            TypedMask::parse(&self.mask)?,
            self.setter,
            self.created_at,
        ))
    }
}

/// The complete persisted value of one durable-authority channel.
///
/// Every global channel is coordinator-durable while it exists. A local
/// channel is durable only after registration.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableChannel {
    /// Immutable channel creation identity.
    pub channel_id: ChannelInstanceId,
    /// Stable name and display spelling.
    pub name: ChannelNameValue,
    /// Channel authority scope.
    pub scope: ChannelScope,
    /// Discovery policy.
    pub visibility: Visibility,
    /// Accepted content route.
    pub content_policy: ContentPolicy,
    /// Lifetime policy; global ephemeral channels persist while they exist.
    pub persistence: PersistencePolicy,
    /// Creator authority.
    pub creator: Principal,
    /// Authoritative creation second.
    pub created_at: UtcSecond,
    /// Revision of the last persisted change to this channel.
    pub revision: Revision,
    /// Simple channel modes.
    pub modes: ChannelModes,
    /// Optional Argon2id channel-key verifier; raw keys are never persisted.
    pub key_verifier: Option<ChannelKeyVerifier>,
    /// Optional membership limit.
    pub member_limit: Option<u16>,
    /// Optional plaintext topic.
    pub topic: Option<DurableTopic>,
    /// Live memberships in ascending User ID order.
    pub memberships: Vec<DurableMembership>,
    /// Durable account role grants in ascending Account ID order.
    pub role_grants: Vec<(AccountId, Role)>,
    /// Ban list in application order.
    pub bans: Vec<DurableListEntry>,
    /// Exception list in application order.
    pub exceptions: Vec<DurableListEntry>,
    /// Invite-exception list in application order.
    pub invite_exceptions: Vec<DurableListEntry>,
    /// Pending invites in ascending Invite ID order.
    pub invites: Vec<DurableInvite>,
    /// Plaintext history policy.
    pub history: HistoryPolicy,
    /// Membership removals awaiting the companion E2EE transition.
    pub e2ee_removal_pending: Vec<UserId>,
    /// Whether new channel delivery is administratively quarantined.
    pub admin_quarantined: bool,
}

impl DurableChannel {
    /// Projects one channel whose authority survives a coordinator restart.
    pub(crate) fn from_state(channel: &ChannelState) -> Option<Self> {
        if channel.scope == ChannelScope::Local
            && channel.persistence == PersistencePolicy::Ephemeral
        {
            return None;
        }
        Some(Self {
            channel_id: channel.channel_id,
            name: channel.name.clone(),
            scope: channel.scope,
            visibility: channel.visibility,
            content_policy: channel.content_policy,
            persistence: channel.persistence,
            creator: channel.creator,
            created_at: channel.created_at,
            revision: channel.revision,
            modes: channel.modes,
            key_verifier: channel.key_verifier,
            member_limit: channel.member_limit,
            topic: channel.topic.as_ref().map(DurableTopic::from_state),
            memberships: channel
                .memberships
                .values()
                .map(DurableMembership::from_state)
                .collect(),
            role_grants: channel
                .role_grants
                .iter()
                .map(|(account_id, role)| (*account_id, *role))
                .collect(),
            bans: channel
                .bans
                .iter()
                .map(DurableListEntry::from_state)
                .collect(),
            exceptions: channel
                .exceptions
                .iter()
                .map(DurableListEntry::from_state)
                .collect(),
            invite_exceptions: channel
                .invite_exceptions
                .iter()
                .map(DurableListEntry::from_state)
                .collect(),
            invites: channel
                .invites
                .values()
                .map(DurableInvite::from_state)
                .collect(),
            history: channel.history,
            e2ee_removal_pending: channel.e2ee_removal_pending.iter().copied().collect(),
            admin_quarantined: channel.admin_quarantined,
        })
    }

    pub(crate) fn into_state(self) -> Result<ChannelState, DomainError> {
        self.into_state_inner(None)
    }

    pub(crate) fn into_state_with_clocks(
        self,
        monotonic_now: MonotonicTick,
        utc_now: UtcSecond,
    ) -> Result<ChannelState, DomainError> {
        self.into_state_inner(Some((monotonic_now, utc_now)))
    }

    // agenc-review: focus owner=domain reviewed=2026-09-01 reason=one channel decoder validates canonical collections and rebases invite clocks before constructing authoritative state
    fn into_state_inner(
        self,
        clocks: Option<(MonotonicTick, UtcSecond)>,
    ) -> Result<ChannelState, DomainError> {
        if (self.scope == ChannelScope::Local && self.persistence == PersistencePolicy::Ephemeral)
            || !strictly_ascending(
                &self
                    .role_grants
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>(),
            )
            || !strictly_ascending(
                &self
                    .memberships
                    .iter()
                    .map(|membership| membership.user_id)
                    .collect::<Vec<_>>(),
            )
            || !strictly_ascending(
                &self
                    .invites
                    .iter()
                    .map(|invite| invite.invite_id)
                    .collect::<Vec<_>>(),
            )
            || (clocks.is_none() && !self.invites.is_empty())
            || !strictly_ascending(&self.e2ee_removal_pending)
        {
            return Err(DomainError::InvalidArgument);
        }
        let invites = match clocks {
            Some((monotonic_now, utc_now)) => self
                .invites
                .into_iter()
                .map(|invite| {
                    invite
                        .into_state(monotonic_now, utc_now)
                        .map(|invite| (invite.invite_id, invite))
                })
                .collect::<Result<_, _>>()?,
            None => Default::default(),
        };
        Ok(ChannelState {
            channel_id: self.channel_id,
            name: self.name,
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
            topic: self.topic.map(DurableTopic::into_state).transpose()?,
            memberships: self
                .memberships
                .into_iter()
                .map(|membership| (membership.user_id, membership.into_state()))
                .collect(),
            role_grants: self.role_grants.into_iter().collect(),
            bans: entries_into_state(self.bans)?,
            exceptions: entries_into_state(self.exceptions)?,
            invite_exceptions: entries_into_state(self.invite_exceptions)?,
            invites,
            history: self.history,
            e2ee_removal_pending: self.e2ee_removal_pending.into_iter().collect(),
            admin_quarantined: self.admin_quarantined,
        })
    }

    /// Compares every persisted field except the revision.
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.content_key() == other.content_key()
    }

    fn content_key(&self) -> ChannelContentKey<'_> {
        (
            (
                &self.channel_id,
                &self.name,
                &self.scope,
                &self.visibility,
                &self.content_policy,
                &self.persistence,
                &self.creator,
                &self.created_at,
            ),
            (
                (
                    &self.modes,
                    &self.key_verifier,
                    &self.member_limit,
                    &self.topic,
                    &self.memberships,
                    &self.role_grants,
                ),
                (
                    &self.bans,
                    &self.exceptions,
                    &self.invite_exceptions,
                    &self.invites,
                    &self.history,
                    &self.e2ee_removal_pending,
                    &self.admin_quarantined,
                ),
            ),
        )
    }
}

/// Every persisted channel field except the revision, borrowed for comparison.
type ChannelContentKey<'a> = (
    (
        &'a ChannelInstanceId,
        &'a ChannelNameValue,
        &'a ChannelScope,
        &'a Visibility,
        &'a ContentPolicy,
        &'a PersistencePolicy,
        &'a Principal,
        &'a UtcSecond,
    ),
    (
        (
            &'a ChannelModes,
            &'a Option<ChannelKeyVerifier>,
            &'a Option<u16>,
            &'a Option<DurableTopic>,
            &'a [DurableMembership],
            &'a [(AccountId, Role)],
        ),
        (
            &'a [DurableListEntry],
            &'a [DurableListEntry],
            &'a [DurableListEntry],
            &'a [DurableInvite],
            &'a HistoryPolicy,
            &'a [UserId],
            &'a bool,
        ),
    ),
);

/// The persisted value of one typed sanction.
#[derive(Clone, Eq, PartialEq)]
pub struct DurableSanction {
    /// Actor principal.
    pub actor: Principal,
    /// Sanction target.
    pub target: Principal,
    /// Optional channel scope.
    pub channel_id: Option<ChannelInstanceId>,
    /// Enforced action.
    pub action: ModerationAction,
    /// Closed audit-safe reason code.
    pub reason_code: ModerationReasonCode,
    /// Optional free-form reason for encrypted storage only.
    pub reason: Option<String>,
    /// Authoritative creation second.
    pub created_at: UtcSecond,
    /// Optional expiry second.
    pub expires_at: Option<UtcSecond>,
    /// Sanction revision.
    pub revision: Revision,
}

impl DurableSanction {
    pub(crate) fn from_state(sanction: &Sanction) -> Self {
        Self {
            actor: sanction.actor,
            target: sanction.target,
            channel_id: sanction.channel_id,
            action: sanction.action,
            reason_code: sanction.reason_code,
            reason: sanction
                .reason
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
            created_at: sanction.created_at,
            expires_at: sanction.expires_at,
            revision: sanction.revision,
        }
    }

    pub(crate) fn into_state(self) -> Result<Sanction, DomainError> {
        let reason = match self.reason {
            Some(text) => Some(ModerationReason::try_from_str(
                &text,
                ControlPolicy::PermitHorizontalTab,
            )?),
            None => None,
        };
        Ok(Sanction {
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

/// One logical persisted write produced by a plan.
#[derive(Clone, Eq, PartialEq)]
// agenc-review: allow owner=domain reviewed=2026-08-29 reason=bounded write batches keep complete channel after-images inline to avoid a separate commit-boundary allocation
#[allow(clippy::large_enum_variant)]
pub enum DurableWrite {
    /// Store the complete after-image of one account.
    PutAccount(DurableAccount),
    /// Retire one account permanently.
    TombstoneAccount(AccountId),
    /// Store the complete after-image of one logical session.
    PutSession(DurableSession),
    /// Retire one connection-bound session permanently.
    TombstoneSession(SessionId),
    /// Store the complete after-image of one durable channel.
    PutChannel(DurableChannel),
    /// Retire one channel that stops being registered.
    TombstoneChannel {
        /// Channel creation identity.
        channel_id: ChannelInstanceId,
        /// Exact name at the time of retirement.
        name: ChannelNameValue,
    },
    /// Append one immutable sanction.
    AppendSanction(DurableSanction),
}

/// Renders the exact canonical text that [`TypedMask::parse`] accepts.
pub(crate) fn typed_mask_text(mask: &TypedMask) -> String {
    let subject = match mask.subject() {
        MaskSubject::Account(random) => format!("$a:{}", random.to_text()),
        MaskSubject::User(user_id) => format!("$u:{}", user_id.to_base64url()),
        MaskSubject::Nickname(glob) => format!("$n:{}", glob.pattern()),
        MaskSubject::Cloak(glob) => format!("$c:{}", glob.pattern()),
    };
    if mask.is_quiet() {
        format!("$q:{subject}")
    } else {
        subject
    }
}

/// Rebuilds one typed mask from a value produced by [`typed_mask_text`].
pub(crate) fn duplicate_typed_mask(mask: &TypedMask) -> Result<TypedMask, DomainError> {
    Ok(TypedMask::parse(&typed_mask_text(mask))?)
}

fn entries_into_state(entries: Vec<DurableListEntry>) -> Result<Vec<ListEntry>, DomainError> {
    entries
        .into_iter()
        .map(DurableListEntry::into_state)
        .collect()
}

fn strictly_ascending<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| match pair {
        [first, second] => first < second,
        _ => true,
    })
}

impl fmt::Debug for DurableAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAccount")
            .field("account_id", &self.account_id)
            .field("session_generation", &self.session_generation)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableSession")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("home_server_id", &self.home_server_id)
            .field("account_id", &self.account_id)
            .field(
                "account_session_generation",
                &self.account_session_generation,
            )
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableTopic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableTopic")
            .field("message_id", &self.message_id)
            .field("setter", &self.setter)
            .field("set_at", &self.set_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableListEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableListEntry")
            .field("entry_id", &self.entry_id)
            .field("setter", &self.setter)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableChannel")
            .field("channel_id", &self.channel_id)
            .field("scope", &self.scope)
            .field("visibility", &self.visibility)
            .field("content_policy", &self.content_policy)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableSanction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableSanction")
            .field("action", &self.action)
            .field("reason_code", &self.reason_code)
            .field("created_at", &self.created_at)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PutAccount(account) => {
                formatter.debug_tuple("PutAccount").field(account).finish()
            }
            Self::TombstoneAccount(account_id) => formatter
                .debug_tuple("TombstoneAccount")
                .field(account_id)
                .finish(),
            Self::PutSession(session) => {
                formatter.debug_tuple("PutSession").field(session).finish()
            }
            Self::TombstoneSession(session_id) => formatter
                .debug_tuple("TombstoneSession")
                .field(session_id)
                .finish(),
            Self::PutChannel(channel) => {
                formatter.debug_tuple("PutChannel").field(channel).finish()
            }
            Self::TombstoneChannel { channel_id, .. } => formatter
                .debug_struct("TombstoneChannel")
                .field("channel_id", channel_id)
                .finish_non_exhaustive(),
            Self::AppendSanction(sanction) => formatter
                .debug_tuple("AppendSanction")
                .field(sanction)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::{
        AccountRandomId, Generation, InviteId, MonotonicTick, Revision, TypedMask, UserId,
        UtcSecond,
    };

    use super::{DurableAccount, DurableInvite, typed_mask_text};
    use crate::{
        DirectMessagePolicy, GuestDirectMessagePolicy, NicknameValue, PresencePolicy, Principal,
    };

    fn durable_invite(expires_at: u64) -> Result<DurableInvite, crate::DomainError> {
        Ok(DurableInvite {
            invite_id: InviteId::from_bytes([8; 16]),
            target: Principal::Guest(UserId::from_bytes([9; 16])),
            inviter: UserId::from_bytes([10; 16]),
            creation_revision: Revision::new(1)?,
            expires_at_utc: UtcSecond::from_unix_seconds(expires_at),
        })
    }

    #[test]
    fn typed_mask_text_round_trips_every_subject_and_the_quiet_wrapper()
    -> Result<(), crate::DomainError> {
        let user = UserId::from_bytes([7; 16]).to_base64url();
        let account = AccountRandomId::from_bytes([8; 16]).to_text();
        for text in [
            format!("$u:{user}"),
            format!("$a:{account}"),
            "$n:spam*".to_owned(),
            "$c:*.example".to_owned(),
            format!("$q:$u:{user}"),
            "$q:$n:lo?d".to_owned(),
        ] {
            let mask = TypedMask::parse(&text)?;
            assert_eq!(typed_mask_text(&mask), text);
            assert!(TypedMask::parse(&typed_mask_text(&mask))? == mask);
        }
        assert_eq!(typed_mask_text(&TypedMask::parse("$n:a**b")?), "$n:a*b");
        Ok(())
    }

    #[test]
    fn durable_invite_rebases_remaining_utc_onto_monotonic_time() -> Result<(), crate::DomainError>
    {
        let invite = durable_invite(110)?.into_state(
            MonotonicTick::from_ticks(5_000),
            UtcSecond::from_unix_seconds(100),
        )?;
        assert_eq!(invite.expires_at, MonotonicTick::from_ticks(15_000));
        assert_eq!(invite.expires_at_utc, UtcSecond::from_unix_seconds(110));
        Ok(())
    }

    #[test]
    fn expired_durable_invite_is_non_live_at_restart_time() -> Result<(), crate::DomainError> {
        let now = MonotonicTick::from_ticks(5_000);
        let invite = durable_invite(99)?.into_state(now, UtcSecond::from_unix_seconds(100))?;
        assert_eq!(invite.expires_at, now);
        Ok(())
    }

    #[test]
    fn same_content_ignores_only_the_revision() -> Result<(), crate::DomainError> {
        let account = DurableAccount {
            account_id: AccountRandomId::from_bytes([1; 16]).to_account_id(),
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Allow,
            direct_messages: DirectMessagePolicy::Allow,
            contacts: Vec::new(),
            reserved_nicknames: vec![NicknameValue::parse("Alice")?],
            session_generation: Generation::new(1)?,
            revision: Revision::new(1)?,
            admin_suspension_expires_at: None,
        };
        let mut later = account.clone();
        later.revision = Revision::new(9)?;
        assert!(account.same_content(&later));
        assert!(account != later);
        let mut changed = account.clone();
        changed.presence = PresencePolicy::Public;
        assert!(!account.same_content(&changed));
        let mut renamed = account.clone();
        renamed.reserved_nicknames = vec![NicknameValue::parse("alice")?];
        assert!(account.same_content(&renamed));
        Ok(())
    }

    #[test]
    fn unsorted_projections_are_rejected_on_restore() -> Result<(), crate::DomainError> {
        let account = DurableAccount {
            account_id: AccountRandomId::from_bytes([1; 16]).to_account_id(),
            label: None,
            presence: PresencePolicy::Private,
            guest_direct_messages: GuestDirectMessagePolicy::Allow,
            direct_messages: DirectMessagePolicy::Allow,
            contacts: Vec::new(),
            reserved_nicknames: vec![NicknameValue::parse("bob")?, NicknameValue::parse("alice")?],
            session_generation: Generation::new(1)?,
            revision: Revision::new(1)?,
            admin_suspension_expires_at: None,
        };
        assert_eq!(
            account.into_state().map(|_| ()),
            Err(crate::DomainError::InvalidArgument)
        );
        Ok(())
    }
}
