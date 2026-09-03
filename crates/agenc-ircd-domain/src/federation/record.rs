//! Least-information projection records and event values (spec B.4, B.5).
//!
//! These are pure domain values. They name exactly the fields the coordinator
//! may disclose to one target edge and nothing else: no login identifier,
//! source address, join key, admin evidence, or remote account state. The
//! runtime maps them onto the Appendix-B wire objects; this module never
//! encodes bytes.

use std::cmp::Ordering;

use agenc_ircd_types::{
    AccountId, ChannelInstanceId, EntryId, FederationEventKind, Generation, InviteId, MessageId,
    PublicCloak, Revision, ServerId, SessionId, UserId, UtcSecond,
};

use crate::{
    AccountLabelValue, ChannelNameValue, ContentPolicy, DisplayNameValue, HistoryPolicy,
    MessageKind, NicknameValue, PersistencePolicy, Principal, Role, Visibility,
};

/// Reason a `session_hidden` event was emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionHideKind {
    /// The client sent QUIT or closed cleanly.
    ClientQuit,
    /// The transport was lost without a QUIT.
    TransportLost,
    /// The origin's edge grace interval expired.
    OriginExpired,
    /// The account was deleted.
    AccountDeleted,
    /// An operator removed the session.
    OperatorRemoved,
    /// An account-security generation invalidated the session.
    SecurityFenced,
}

impl SessionHideKind {
    /// Returns the registered wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::ClientQuit => 1,
            Self::TransportLost => 2,
            Self::OriginExpired => 3,
            Self::AccountDeleted => 4,
            Self::OperatorRemoved => 5,
            Self::SecurityFenced => 6,
        }
    }

    /// Returns the registered generic reason text for a non-client kind.
    #[must_use]
    pub const fn generic_reason(self) -> &'static str {
        match self {
            Self::ClientQuit => "",
            Self::TransportLost => "connection lost",
            Self::OriginExpired => "connection expired",
            Self::AccountDeleted => "account deleted",
            Self::OperatorRemoved => "removed by operator",
            Self::SecurityFenced => "connection closed",
        }
    }
}

/// Why one invite projection copy was removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteRemovalKind {
    /// The target joined and consumed the invite.
    Consumed,
    /// The invite expired.
    Expired,
    /// The target principal disappeared.
    TargetGone,
    /// Only this edge's copy is removed because its last local target left.
    ProjectionHidden,
}

impl InviteRemovalKind {
    /// Returns the registered wire discriminant.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Consumed => 1,
            Self::Expired => 2,
            Self::TargetGone => 3,
            Self::ProjectionHidden => 4,
        }
    }
}

/// The complete event-scoped pseudonymous identity of one live session.
#[derive(Clone, Eq, PartialEq)]
pub struct SourceView {
    /// The routing identity.
    pub user_id: UserId,
    /// The nickname at event acceptance.
    pub nickname: NicknameValue,
    /// The public cloak at event acceptance.
    pub public_cloak: PublicCloak,
    /// The public account label, if any.
    pub account_label: Option<AccountLabelValue>,
}

/// The standing session projection held only by the session's home edge.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionRecord {
    /// The authoritative session identity.
    pub session_id: SessionId,
    /// The routing identity.
    pub user_id: UserId,
    /// The edge that owns the connection.
    pub home_server_id: ServerId,
    /// The state revision of the last session change.
    pub session_revision: Revision,
    /// The account and its session generation for an authenticated session.
    pub account: Option<(AccountId, Generation)>,
    /// The current nickname.
    pub nickname: NicknameValue,
    /// The prepared display name.
    pub display_name: DisplayNameValue,
    /// The public cloak.
    pub public_cloak: PublicCloak,
    /// The public account label, if any.
    pub account_label: Option<AccountLabelValue>,
    /// Bit 0 (`i`) always set; bit 1 (`w`) when operator notices are on.
    pub user_mode_bits: u16,
    /// The away text when the session is away.
    pub away: Option<String>,
}

impl SessionRecord {
    /// Derives the event-scoped source view of this session.
    #[must_use]
    pub fn source_view(&self) -> SourceView {
        SourceView {
            user_id: self.user_id,
            nickname: self.nickname.clone(),
            public_cloak: self.public_cloak,
            account_label: self.account_label.clone(),
        }
    }
}

/// The standing channel detail held by every entitled edge.
#[derive(Clone, Eq, PartialEq)]
pub struct ChannelDetailRecord {
    /// The immutable channel creation identity.
    pub channel_id: ChannelInstanceId,
    /// The canonical and display name.
    pub name: ChannelNameValue,
    /// The state revision of the last channel change.
    pub channel_revision: Revision,
    /// Discovery policy.
    pub visibility: Visibility,
    /// Content route.
    pub content_policy: ContentPolicy,
    /// Lifetime policy.
    pub persistence: PersistencePolicy,
    /// Bits 0..5 for `i,m,n,p,s,t`; bit 2 always set.
    pub simple_mode_bits: u16,
    /// Plaintext history policy.
    pub history: HistoryPolicy,
    /// The E2EE route binding for an encrypted channel.
    pub e2ee_route_binding: Option<[u8; 32]>,
}

/// One local membership held by the member's home edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipRecord {
    /// The channel.
    pub channel_id: ChannelInstanceId,
    /// The member.
    pub user_id: UserId,
    /// The effective role.
    pub role: Role,
    /// The state revision that accepted or last changed the membership.
    pub membership_revision: Revision,
    /// The accepted join second.
    pub joined_at: UtcSecond,
}

/// One standing invite copy held by an edge hosting its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteRecord {
    /// The channel.
    pub channel_id: ChannelInstanceId,
    /// The invite identity.
    pub invite_id: InviteId,
    /// The invited principal.
    pub target: Principal,
    /// The inviting user.
    pub inviter_user_id: UserId,
    /// The state revision that created the invite.
    pub creation_revision: Revision,
    /// The absolute expiry.
    pub expires_at: UtcSecond,
}

/// The standing account projection held while an edge hosts the account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    /// The account identity.
    pub account_id: AccountId,
    /// The current account-session generation.
    pub account_session_generation: Generation,
    /// The state revision of the last account change.
    pub account_revision: Revision,
}

/// One standing projection entry.
#[derive(Clone, Eq, PartialEq)]
pub enum ProjectionRecord {
    /// A home-edge session projection.
    Session(SessionRecord),
    /// An entitled-edge channel detail.
    ChannelDetail(ChannelDetailRecord),
    /// A home-edge membership.
    Membership(MembershipRecord),
    /// A target-edge invite copy.
    Invite(InviteRecord),
    /// A hosting-edge account projection.
    Account(AccountRecord),
}

/// The unique `(kind, primary-ID bytes)` key that orders a projection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProjectionKey {
    kind: u16,
    primary: Vec<u8>,
}

impl ProjectionKey {
    /// The `session` projection kind discriminant.
    pub const SESSION: u16 = 1;
    /// The `channel_detail` projection kind discriminant.
    pub const CHANNEL_DETAIL: u16 = 3;
    /// The `membership` projection kind discriminant.
    pub const MEMBERSHIP: u16 = 4;
    /// The `invite` projection kind discriminant.
    pub const INVITE: u16 = 6;
    /// The `account` projection kind discriminant.
    pub const ACCOUNT: u16 = 7;

    /// Keys a session projection by User ID.
    #[must_use]
    pub fn session(user_id: UserId) -> Self {
        Self {
            kind: Self::SESSION,
            primary: user_id.as_bytes().to_vec(),
        }
    }

    /// Keys a channel detail by Channel ID.
    #[must_use]
    pub fn channel_detail(channel_id: ChannelInstanceId) -> Self {
        Self {
            kind: Self::CHANNEL_DETAIL,
            primary: channel_id.as_bytes().to_vec(),
        }
    }

    /// Keys a membership by Channel ID then User ID.
    #[must_use]
    pub fn membership(channel_id: ChannelInstanceId, user_id: UserId) -> Self {
        let mut primary = channel_id.as_bytes().to_vec();
        primary.extend_from_slice(user_id.as_bytes());
        Self {
            kind: Self::MEMBERSHIP,
            primary,
        }
    }

    /// Keys an invite by Channel ID then Invite ID.
    #[must_use]
    pub fn invite(channel_id: ChannelInstanceId, invite_id: InviteId) -> Self {
        let mut primary = channel_id.as_bytes().to_vec();
        primary.extend_from_slice(invite_id.as_bytes());
        Self {
            kind: Self::INVITE,
            primary,
        }
    }

    /// Keys an account projection by Account ID text.
    #[must_use]
    pub fn account(account_id: AccountId) -> Self {
        Self {
            kind: Self::ACCOUNT,
            primary: account_id.to_text().into_bytes(),
        }
    }

    /// Returns the projection kind discriminant.
    #[must_use]
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Borrows the primary identity bytes.
    #[must_use]
    pub fn primary(&self) -> &[u8] {
        &self.primary
    }
}

impl PartialOrd for ProjectionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProjectionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.primary.cmp(&other.primary))
    }
}

impl ProjectionRecord {
    /// Returns the unique ordering key of this entry.
    #[must_use]
    pub fn key(&self) -> ProjectionKey {
        match self {
            Self::Session(record) => ProjectionKey::session(record.user_id),
            Self::ChannelDetail(record) => ProjectionKey::channel_detail(record.channel_id),
            Self::Membership(record) => {
                ProjectionKey::membership(record.channel_id, record.user_id)
            }
            Self::Invite(record) => ProjectionKey::invite(record.channel_id, record.invite_id),
            Self::Account(record) => ProjectionKey::account(record.account_id),
        }
    }
}

/// A source view or the explicit server-originated absence.
#[derive(Clone, Eq, PartialEq)]
pub struct ActorView(pub Option<SourceView>);

/// A source view plus the home projection when the recipient is the home edge.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionEventView {
    /// The event-scoped identity.
    pub source: SourceView,
    /// The complete session projection on the home edge only.
    pub home_projection: Option<SessionRecord>,
}

/// A membership plus the member's source view for rendering.
#[derive(Clone, Eq, PartialEq)]
pub struct MembershipView {
    /// The membership.
    pub membership: MembershipRecord,
    /// The member's identity at acceptance.
    pub source: SourceView,
}

/// One projected `b`, `e`, or `I` list entry.
#[derive(Clone, Eq, PartialEq)]
pub struct ModeListEntryRecord {
    /// The channel.
    pub channel_id: ChannelInstanceId,
    /// Mode code 1, 2, or 3.
    pub mode_code: u16,
    /// The entry identity.
    pub entry_id: EntryId,
    /// The canonical typed-mask text.
    pub mask: String,
    /// The setter's identity at creation.
    pub setter: SourceView,
    /// The creation second.
    pub created_at: UtcSecond,
    /// The expiry, if any.
    pub expires_at: Option<UtcSecond>,
}

/// Whether a mode was added or removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeDirection {
    /// The mode was set.
    Add,
    /// The mode was unset.
    Remove,
}

/// One projected mode change with request-only secrets redacted.
#[derive(Clone, Eq, PartialEq)]
pub enum ProjectedModeChange {
    /// A list entry (codes 1..3) added or removed.
    List {
        /// The direction.
        direction: ModeDirection,
        /// The complete entry, captured before deletion for a removal.
        entry: ModeListEntryRecord,
    },
    /// The join-key state (code 4) changed; the key itself is never projected.
    Key {
        /// The direction.
        direction: ModeDirection,
        /// Whether a key is set afterwards.
        present: bool,
    },
    /// The member limit (code 5) changed; zero means absent.
    Limit {
        /// The direction.
        direction: ModeDirection,
        /// The resulting limit.
        limit: u32,
    },
    /// A simple mode (codes 6..11) changed.
    Simple {
        /// The direction.
        direction: ModeDirection,
        /// The mode code.
        mode_code: u16,
    },
    /// A prefix mode (codes 12..16) changed with the resulting membership.
    Prefix {
        /// The direction.
        direction: ModeDirection,
        /// The mode code.
        mode_code: u16,
        /// The resulting membership view.
        view: MembershipView,
    },
}

impl ProjectedModeChange {
    /// Returns the registered mode code of this change.
    #[must_use]
    pub const fn mode_code(&self) -> u16 {
        match self {
            Self::List { entry, .. } => entry.mode_code,
            Self::Key { .. } => 4,
            Self::Limit { .. } => 5,
            Self::Simple { mode_code, .. } | Self::Prefix { mode_code, .. } => *mode_code,
        }
    }

    /// Returns the direction of this change.
    #[must_use]
    pub const fn direction(&self) -> ModeDirection {
        match self {
            Self::List { direction, .. }
            | Self::Key { direction, .. }
            | Self::Limit { direction, .. }
            | Self::Simple { direction, .. }
            | Self::Prefix { direction, .. } => *direction,
        }
    }
}

/// The delivery target of one projected message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryTarget {
    /// A channel target.
    Channel(ChannelInstanceId),
    /// A direct user target.
    User(UserId),
}

/// One delivered message with the sender's exact source view.
#[derive(Clone, Eq, PartialEq)]
pub struct DeliveredMessageRecord {
    /// The immutable message identity.
    pub message_id: MessageId,
    /// PRIVMSG, NOTICE, or TAGMSG.
    pub kind: MessageKind,
    /// The target.
    pub target: DeliveryTarget,
    /// The sender at acceptance.
    pub sender: SourceView,
    /// The installed channel revision, or zero for a direct message.
    pub target_revision: Revision,
    /// Nonzero per-channel sequence, zero for a direct message.
    pub channel_event_sequence: u64,
    /// The acceptance time in UTC milliseconds.
    pub received_unix_milliseconds: u64,
    /// Sorted validated client-only tags.
    pub tags: Vec<(String, String)>,
    /// The body; empty for TAGMSG.
    pub body: String,
}

/// One projected event addressed to one target edge.
#[derive(Clone, Eq, PartialEq)]
pub enum ProjectedEvent {
    /// A session became visible.
    SessionVisible(SessionEventView),
    /// A session disappeared.
    SessionHidden {
        /// The final accepted pseudonym.
        source: SourceView,
        /// The last session revision.
        last_revision: Revision,
        /// Why it disappeared.
        kind: SessionHideKind,
        /// Departed channels visible to this edge with their resulting revisions.
        channels: Vec<(ChannelInstanceId, Revision)>,
        /// The client reason or the registered generic reason.
        reason: String,
    },
    /// A nickname changed.
    NicknameChanged {
        /// The previous nickname.
        old_nickname: NicknameValue,
        /// The session after the change.
        view: SessionEventView,
    },
    /// A channel detail entered the edge's projection.
    ChannelVisible(ChannelDetailRecord),
    /// A channel detail left the edge's projection.
    ChannelHidden {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The last visible revision.
        last_revision: Revision,
    },
    /// A member joined.
    MemberJoined {
        /// The resulting membership.
        view: MembershipView,
        /// The resulting home-session revision on the home edge only.
        home_session_revision: Option<Revision>,
        /// The display name for `extended-join`.
        display_name: DisplayNameValue,
    },
    /// A member parted while the session stays live.
    MemberParted {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The departing member.
        source: SourceView,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The resulting home-session revision on the home edge only.
        home_session_revision: Option<Revision>,
        /// The part reason.
        reason: String,
    },
    /// Channel modes changed.
    ChannelModesChanged {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The actor.
        actor: ActorView,
        /// The projected changes in client order.
        changes: Vec<ProjectedModeChange>,
    },
    /// The topic changed.
    TopicChanged {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The actor, always present.
        actor: SourceView,
        /// The new topic text, set time, and message identity, or cleared.
        topic: Option<(String, UtcSecond, MessageId)>,
    },
    /// An invite was created or reprojected.
    Invited {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The invite.
        invite_id: InviteId,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The standing copy on a target-hosting edge only.
        local_projection: Option<InviteRecord>,
        /// The inviter.
        inviter: SourceView,
        /// The named target.
        named_target: SourceView,
    },
    /// An invite copy was removed.
    InviteRemoved {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The invite.
        invite_id: InviteId,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The removal kind.
        kind: InviteRemovalKind,
    },
    /// A member was kicked.
    Kicked {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The actor, absent only for a server enforcement path.
        actor: ActorView,
        /// The removed member.
        target: SourceView,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The target's resulting home-session revision on its home edge only.
        target_home_session_revision: Option<Revision>,
        /// The kick reason.
        reason: String,
    },
    /// Away state changed.
    AwayChanged {
        /// The session after the change.
        view: SessionEventView,
        /// The away text, or not away.
        away: Option<String>,
    },
    /// The display name changed.
    DisplayNameChanged {
        /// The session after the change.
        view: SessionEventView,
        /// The new display name.
        display_name: DisplayNameValue,
    },
    /// A message was delivered.
    MessageDelivered(DeliveredMessageRecord),
    /// A channel was destroyed.
    ChannelDestroyed {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The final revision.
        final_revision: Revision,
    },
    /// The account label changed.
    AccountLabelChanged(SessionEventView),
    /// A registered network notice.
    NetworkNotice {
        /// The registered code.
        code: String,
        /// Safe text.
        text: String,
    },
    /// User modes changed; home edge only.
    UserModesChanged(SessionRecord),
    /// Channel policy changed.
    ChannelPolicyChanged(ChannelDetailRecord),
    /// Account-grant driven membership recompute.
    ChannelMembershipsRecomputed {
        /// The channel.
        channel_id: ChannelInstanceId,
        /// The resulting channel revision.
        resulting_revision: Revision,
        /// The actor.
        actor: ActorView,
        /// The affected memberships visible to this edge in User ID order.
        memberships: Vec<MembershipView>,
    },
    /// The account projection was replaced.
    AccountStateChanged(AccountRecord),
    /// A request completed; home edge only.
    RequestCompleted {
        /// The resulting global state generation.
        resulting_state_generation: u64,
    },
}

/// The Section-20.6 semantic phase of one event copy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EventPhase {
    /// Prerequisite `session_visible` or `channel_visible`.
    Prerequisite = 1,
    /// The named mutation event.
    Named = 2,
    /// Dependent removals and `session_hidden`.
    Dependent = 3,
    /// `channel_hidden`.
    Hidden = 4,
}

impl ProjectedEvent {
    /// Returns the registered event kind.
    #[must_use]
    pub const fn kind(&self) -> FederationEventKind {
        match self {
            Self::SessionVisible(_) => FederationEventKind::SessionVisible,
            Self::SessionHidden { .. } => FederationEventKind::SessionHidden,
            Self::NicknameChanged { .. } => FederationEventKind::NicknameChanged,
            Self::ChannelVisible(_) => FederationEventKind::ChannelVisible,
            Self::ChannelHidden { .. } => FederationEventKind::ChannelHidden,
            Self::MemberJoined { .. } => FederationEventKind::MemberJoined,
            Self::MemberParted { .. } => FederationEventKind::MemberParted,
            Self::ChannelModesChanged { .. } => FederationEventKind::ChannelModesChanged,
            Self::TopicChanged { .. } => FederationEventKind::TopicChanged,
            Self::Invited { .. } => FederationEventKind::Invited,
            Self::InviteRemoved { .. } => FederationEventKind::InviteRemoved,
            Self::Kicked { .. } => FederationEventKind::Kicked,
            Self::AwayChanged { .. } => FederationEventKind::AwayChanged,
            Self::DisplayNameChanged { .. } => FederationEventKind::DisplayNameChanged,
            Self::MessageDelivered(_) => FederationEventKind::MessageDelivered,
            Self::ChannelDestroyed { .. } => FederationEventKind::ChannelDestroyed,
            Self::AccountLabelChanged(_) => FederationEventKind::AccountLabelChanged,
            Self::NetworkNotice { .. } => FederationEventKind::NetworkNotice,
            Self::UserModesChanged(_) => FederationEventKind::UserModesChanged,
            Self::ChannelPolicyChanged(_) => FederationEventKind::ChannelPolicyChanged,
            Self::ChannelMembershipsRecomputed { .. } => {
                FederationEventKind::ChannelMembershipsRecomputed
            }
            Self::AccountStateChanged(_) => FederationEventKind::AccountStateChanged,
            Self::RequestCompleted { .. } => FederationEventKind::RequestCompleted,
        }
    }

    /// Returns the semantic phase used for intra-mutation ordering.
    #[must_use]
    pub const fn phase(&self) -> EventPhase {
        match self {
            Self::SessionVisible(_) | Self::ChannelVisible(_) => EventPhase::Prerequisite,
            Self::InviteRemoved {
                kind: InviteRemovalKind::Expired,
                ..
            } => EventPhase::Named,
            Self::SessionHidden { .. } | Self::InviteRemoved { .. } => EventPhase::Dependent,
            Self::ChannelHidden { .. } | Self::ChannelDestroyed { .. } => EventPhase::Hidden,
            _ => EventPhase::Named,
        }
    }

    /// Returns the Appendix-B.5 subject key used for deterministic ordering.
    #[must_use]
    pub fn subject_key(&self) -> Vec<u8> {
        match self {
            Self::SessionVisible(view)
            | Self::NicknameChanged { view, .. }
            | Self::AwayChanged { view, .. }
            | Self::DisplayNameChanged { view, .. }
            | Self::AccountLabelChanged(view) => view.source.user_id.as_bytes().to_vec(),
            Self::SessionHidden { source, .. } => source.user_id.as_bytes().to_vec(),
            Self::UserModesChanged(record) => record.user_id.as_bytes().to_vec(),
            Self::ChannelVisible(detail) | Self::ChannelPolicyChanged(detail) => {
                detail.channel_id.as_bytes().to_vec()
            }
            Self::ChannelHidden { channel_id, .. }
            | Self::ChannelDestroyed { channel_id, .. }
            | Self::ChannelModesChanged { channel_id, .. }
            | Self::TopicChanged { channel_id, .. }
            | Self::ChannelMembershipsRecomputed { channel_id, .. } => {
                channel_id.as_bytes().to_vec()
            }
            Self::MemberJoined { view, .. } => concat(
                view.membership.channel_id.as_bytes(),
                view.membership.user_id.as_bytes(),
            ),
            Self::MemberParted {
                channel_id, source, ..
            } => concat(channel_id.as_bytes(), source.user_id.as_bytes()),
            Self::Kicked {
                channel_id, target, ..
            } => concat(channel_id.as_bytes(), target.user_id.as_bytes()),
            Self::Invited {
                channel_id,
                invite_id,
                ..
            }
            | Self::InviteRemoved {
                channel_id,
                invite_id,
                ..
            } => concat(channel_id.as_bytes(), invite_id.as_bytes()),
            Self::MessageDelivered(message) => {
                let (kind, target): (u16, &[u8; 16]) = match &message.target {
                    DeliveryTarget::Channel(id) => (1, id.as_bytes()),
                    DeliveryTarget::User(id) => (2, id.as_bytes()),
                };
                let mut key = kind.to_be_bytes().to_vec();
                key.extend_from_slice(target);
                key.extend_from_slice(message.message_id.as_bytes());
                key
            }
            Self::AccountStateChanged(record) => record.account_id.to_text().into_bytes(),
            Self::NetworkNotice { code, .. } => code.clone().into_bytes(),
            Self::RequestCompleted { .. } => Vec::new(),
        }
    }
}

fn concat(first: &[u8; 16], second: &[u8; 16]) -> Vec<u8> {
    let mut key = first.to_vec();
    key.extend_from_slice(second);
    key
}

/// Maps a domain role onto the registered role level.
#[must_use]
pub const fn role_level(role: Role) -> u16 {
    match role {
        Role::Member => 0,
        Role::Voice => 1,
        Role::HalfOperator => 2,
        Role::Operator => 3,
        Role::Administrator => 4,
        Role::Owner => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_keys_order_by_kind_then_primary_bytes() {
        let channel = ChannelInstanceId::from_bytes([2; 16]);
        let user = UserId::from_bytes([1; 16]);
        let invite = InviteId::from_bytes([3; 16]);
        let session = ProjectionKey::session(user);
        let detail = ProjectionKey::channel_detail(channel);
        let membership = ProjectionKey::membership(channel, user);
        let invite_key = ProjectionKey::invite(channel, invite);
        let account = ProjectionKey::account(AccountId::from_random(
            agenc_ircd_types::AccountRandomId::from_bytes([4; 16]),
        ));
        assert!(session < detail);
        assert!(detail < membership);
        assert!(membership < invite_key);
        assert!(invite_key < account);
        assert_eq!(membership.kind(), ProjectionKey::MEMBERSHIP);
        assert_eq!(membership.primary().len(), 32);
        assert_eq!(session.partial_cmp(&detail), Some(Ordering::Less));
        let later_user = ProjectionKey::session(UserId::from_bytes([9; 16]));
        assert!(session < later_user);
    }

    #[test]
    fn hide_and_removal_kinds_carry_registered_values_and_reasons() {
        assert_eq!(SessionHideKind::SecurityFenced.wire_value(), 6);
        assert_eq!(
            SessionHideKind::SecurityFenced.generic_reason(),
            "connection closed"
        );
        assert_eq!(SessionHideKind::ClientQuit.generic_reason(), "");
        assert_eq!(SessionHideKind::TransportLost.wire_value(), 2);
        assert_eq!(SessionHideKind::OriginExpired.wire_value(), 3);
        assert_eq!(SessionHideKind::AccountDeleted.wire_value(), 4);
        assert_eq!(SessionHideKind::OperatorRemoved.wire_value(), 5);
        assert!(!SessionHideKind::TransportLost.generic_reason().is_empty());
        assert!(!SessionHideKind::OriginExpired.generic_reason().is_empty());
        assert!(!SessionHideKind::AccountDeleted.generic_reason().is_empty());
        assert!(!SessionHideKind::OperatorRemoved.generic_reason().is_empty());
        assert_eq!(InviteRemovalKind::Consumed.wire_value(), 1);
        assert_eq!(InviteRemovalKind::Expired.wire_value(), 2);
        assert_eq!(InviteRemovalKind::TargetGone.wire_value(), 3);
        assert_eq!(InviteRemovalKind::ProjectionHidden.wire_value(), 4);
        assert_eq!(role_level(Role::Owner), 5);
        assert_eq!(role_level(Role::Member), 0);
        assert_eq!(role_level(Role::Voice), 1);
        assert_eq!(role_level(Role::HalfOperator), 2);
        assert_eq!(role_level(Role::Operator), 3);
        assert_eq!(role_level(Role::Administrator), 4);
    }
}
