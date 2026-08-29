//! Durable projections of the domain entities that survive a restart.
//!
//! Sessions, memberships, invites, away state, nicknames, monitor lists, and
//! fresh-authentication proofs are process state and are never persisted
//! (spec sections 12 and 17.3). Accounts, registered channels, and sanctions
//! are. This module owns the exact persisted value of each of those entities
//! and the logical write set a plan produces, without naming any storage
//! codec, key, or handle.

use std::fmt;

use agenc_ircd_types::{
    AccountId, ChannelInstanceId, ControlPolicy, EntryId, Generation, MaskSubject, MessageId,
    Revision, TypedMask, UserId, UtcSecond,
};

use crate::error::DomainError;
use crate::model::{
    AccountLabelValue, AccountState, ChannelModes, ChannelNameValue, ChannelScope, ChannelState,
    ContentPolicy, DirectMessagePolicy, GuestDirectMessagePolicy, HistoryPolicy, ListEntry,
    ModerationAction, ModerationReason, ModerationReasonCode, NicknameValue, PersistencePolicy,
    PlaintextTopic, PresencePolicy, Principal, Role, Sanction, TopicText, Visibility,
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
    }
}

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

/// The persisted value of one registered channel.
///
/// Memberships, pending invites, and pending E2EE removals are live session
/// state and are absent from this value.
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
    /// Lifetime policy; a persisted channel is always registered.
    pub persistence: PersistencePolicy,
    /// Creator authority.
    pub creator: Principal,
    /// Authoritative creation second.
    pub created_at: UtcSecond,
    /// Revision of the last persisted change to this channel.
    pub revision: Revision,
    /// Simple channel modes.
    pub modes: ChannelModes,
    /// Optional membership limit.
    pub member_limit: Option<u16>,
    /// Optional plaintext topic.
    pub topic: Option<DurableTopic>,
    /// Durable account role grants in ascending Account ID order.
    pub role_grants: Vec<(AccountId, Role)>,
    /// Ban list in application order.
    pub bans: Vec<DurableListEntry>,
    /// Exception list in application order.
    pub exceptions: Vec<DurableListEntry>,
    /// Invite-exception list in application order.
    pub invite_exceptions: Vec<DurableListEntry>,
    /// Plaintext history policy.
    pub history: HistoryPolicy,
}

impl DurableChannel {
    /// Projects a channel when its lifetime policy persists it.
    pub(crate) fn from_state(channel: &ChannelState) -> Option<Self> {
        if channel.persistence != PersistencePolicy::Registered {
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
            member_limit: channel.member_limit,
            topic: channel.topic.as_ref().map(DurableTopic::from_state),
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
            history: channel.history,
        })
    }

    pub(crate) fn into_state(self) -> Result<ChannelState, DomainError> {
        if self.persistence != PersistencePolicy::Registered
            || !strictly_ascending(
                &self
                    .role_grants
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>(),
            )
        {
            return Err(DomainError::InvalidArgument);
        }
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
            member_limit: self.member_limit,
            topic: self.topic.map(DurableTopic::into_state).transpose()?,
            memberships: Default::default(),
            role_grants: self.role_grants.into_iter().collect(),
            bans: entries_into_state(self.bans)?,
            exceptions: entries_into_state(self.exceptions)?,
            invite_exceptions: entries_into_state(self.invite_exceptions)?,
            invites: Default::default(),
            history: self.history,
            e2ee_removal_pending: Default::default(),
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
                &self.modes,
                &self.member_limit,
                &self.topic,
                &self.role_grants,
                &self.bans,
                &self.exceptions,
                &self.invite_exceptions,
                &self.history,
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
        &'a ChannelModes,
        &'a Option<u16>,
        &'a Option<DurableTopic>,
        &'a [(AccountId, Role)],
        &'a [DurableListEntry],
        &'a [DurableListEntry],
        &'a [DurableListEntry],
        &'a HistoryPolicy,
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
pub enum DurableWrite {
    /// Store the complete after-image of one account.
    PutAccount(DurableAccount),
    /// Retire one account permanently.
    TombstoneAccount(AccountId),
    /// Store the complete after-image of one registered channel.
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
    use agenc_ircd_types::{AccountRandomId, Generation, Revision, TypedMask, UserId};

    use super::{DurableAccount, typed_mask_text};
    use crate::{DirectMessagePolicy, GuestDirectMessagePolicy, NicknameValue, PresencePolicy};

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
        };
        assert_eq!(
            account.into_state().map(|_| ()),
            Err(crate::DomainError::InvalidArgument)
        );
        Ok(())
    }
}
