//! Canonical commands accepted by domain authorization.

use agenc_relay_types::{
    AccountDeletionToken, AccountId, BoundedUtf8, ChannelInstanceId, EntryId, Generation, Revision,
    SessionId, TypedMask, UserId,
};

use crate::{
    AccountLabelValue, AwayText, ChannelNameValue, DirectMessagePolicy, DomainError,
    GuestDirectMessagePolicy, HistoryPolicy, NicknameValue, PresencePolicy, Role, TopicText,
};

const MAX_CHANNEL_TARGETS: usize = 20;
const MAX_MESSAGE_TARGETS: usize = 4;
const MAX_KICK_TARGETS: usize = 4;
const MAX_MODE_CHANGES: usize = 6;
const MAX_MONITOR_COMMAND_TARGETS: usize = 20;
const MAX_WHOWAS_RESULTS: u8 = 10;
const MAX_ISON_TARGETS: usize = 20;
const MAX_USERHOST_TARGETS: usize = 5;
const MAX_CHATHISTORY_RESULTS: u8 = 100;
const MAX_MESSAGE_TEXT_BYTES: usize = 512;

/// A validated IRC message body.
///
/// Client framing has already excluded NUL, carriage return, and line feed.
/// Other control bytes remain ordinary text so CTCP `ACTION` and IRC text
/// formatting survive without being interpreted by the server.
#[must_use]
pub struct MessageText(String);

impl MessageText {
    /// Validates and copies one bounded message body.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        if input.len() > MAX_MESSAGE_TEXT_BYTES
            || input
                .as_bytes()
                .iter()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return Err(DomainError::InvalidArgument);
        }
        let mut text = String::new();
        text.try_reserve_exact(input.len())
            .map_err(|_| DomainError::AllocationFailed)?;
        text.push_str(input);
        Ok(Self(text))
    }

    /// Borrows the exact validated message text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether this body is empty, as permitted only for `NOTICE`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A validated PART or KICK reason.
pub type DepartureReason = BoundedUtf8<0, 256>;

/// Every post-registration command family consumed or answered by the domain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DomainCommandKind {
    /// Change the mutable routing nickname.
    Nick,
    /// Close one logical session.
    Quit,
    /// Join one or more channels or part all channels.
    Join,
    /// Leave one or more channels.
    Part,
    /// Read or change user/channel modes.
    Mode,
    /// Read or change a plaintext topic.
    Topic,
    /// Read a visibility-filtered membership list.
    Names,
    /// Read the bounded public channel directory.
    List,
    /// Create one single-use invitation.
    Invite,
    /// Remove one or more lower-role members.
    Kick,
    /// Route nonempty plaintext content.
    Privmsg,
    /// Route optional plaintext content without automatic errors.
    Notice,
    /// Route one tag-only or companion-profile object.
    Tagmsg,
    /// Return the configured message of the day.
    Motd,
    /// Return privacy-safe aggregate counts.
    Lusers,
    /// Return the protocol version surface.
    Version,
    /// Return rounded UTC time.
    Time,
    /// Return local public administrator information.
    Admin,
    /// Return privacy-safe implementation information.
    Info,
    /// Return public server names and availability.
    Links,
    /// Query shared-context users.
    Who,
    /// Query one visibility-authorized user.
    Whois,
    /// Query bounded disconnected-session history.
    Whowas,
    /// Set or clear away state.
    Away,
    /// Query visible online nicknames.
    Ison,
    /// Query visible user masks.
    Userhost,
    /// Manage the bounded monitor set.
    Monitor,
    /// Change a prepared display name.
    Setname,
    /// Change authenticated account settings.
    Acct,
    /// Change owner-controlled channel policy.
    Chanctl,
    /// Query optional pinned plaintext history.
    Chathistory,
}

impl DomainCommandKind {
    /// Maps one already uppercase registry name to its closed domain family.
    pub fn from_registered_name(name: &str) -> Result<Self, DomainError> {
        match name {
            "NICK" => Ok(Self::Nick),
            "QUIT" => Ok(Self::Quit),
            "JOIN" => Ok(Self::Join),
            "PART" => Ok(Self::Part),
            "MODE" => Ok(Self::Mode),
            "TOPIC" => Ok(Self::Topic),
            "NAMES" => Ok(Self::Names),
            "LIST" => Ok(Self::List),
            "INVITE" => Ok(Self::Invite),
            "KICK" => Ok(Self::Kick),
            "PRIVMSG" => Ok(Self::Privmsg),
            "NOTICE" => Ok(Self::Notice),
            "TAGMSG" => Ok(Self::Tagmsg),
            "MOTD" => Ok(Self::Motd),
            "LUSERS" => Ok(Self::Lusers),
            "VERSION" => Ok(Self::Version),
            "TIME" => Ok(Self::Time),
            "ADMIN" => Ok(Self::Admin),
            "INFO" => Ok(Self::Info),
            "LINKS" => Ok(Self::Links),
            "WHO" => Ok(Self::Who),
            "WHOIS" => Ok(Self::Whois),
            "WHOWAS" => Ok(Self::Whowas),
            "AWAY" => Ok(Self::Away),
            "ISON" => Ok(Self::Ison),
            "USERHOST" => Ok(Self::Userhost),
            "MONITOR" => Ok(Self::Monitor),
            "SETNAME" => Ok(Self::Setname),
            "ACCT" => Ok(Self::Acct),
            "CHANCTL" => Ok(Self::Chanctl),
            "CHATHISTORY" => Ok(Self::Chathistory),
            _ => Err(DomainError::InvalidArgument),
        }
    }
}

/// One channel target with only the fact of a supplied join key retained.
pub struct ChannelTarget {
    name: ChannelNameValue,
    key_supplied: bool,
}

impl ChannelTarget {
    /// Creates one canonical channel target.
    #[must_use]
    pub const fn new(name: ChannelNameValue, key_supplied: bool) -> Self {
        Self { name, key_supplied }
    }

    /// Borrows the canonical channel name.
    #[must_use]
    pub const fn name(&self) -> &ChannelNameValue {
        &self.name
    }

    /// Reports whether the wire command supplied a nonempty key.
    #[must_use]
    pub const fn key_supplied(&self) -> bool {
        self.key_supplied
    }

    pub(crate) fn into_name(self) -> ChannelNameValue {
        self.name
    }
}

/// One canonical message target.
#[derive(Clone)]
pub enum MessageTarget {
    /// A channel name whose current instance is resolved at the command revision.
    Channel(ChannelNameValue),
    /// A nickname resolved to one current User ID at the command revision.
    User(NicknameValue),
}

/// Closed routing behavior for one IRC message command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Nonempty plaintext with ordinary errors.
    Privmsg,
    /// Optional plaintext with silent policy failures.
    Notice,
    /// Tag-only content, including validated companion objects later.
    Tagmsg,
}

/// Companion-issued proof that one `TAGMSG` carries an E2EE application object.
///
/// The domain binds the proof to the immutable channel instance, sending user,
/// and exact channel revision before it authorizes the opaque route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2eeApplicationProof {
    channel_id: ChannelInstanceId,
    sender: UserId,
    channel_revision: Revision,
}

impl E2eeApplicationProof {
    /// Records the identities and revision validated by the companion profile.
    #[must_use]
    pub const fn new(
        channel_id: ChannelInstanceId,
        sender: UserId,
        channel_revision: Revision,
    ) -> Self {
        Self {
            channel_id,
            sender,
            channel_revision,
        }
    }

    /// Returns the immutable channel instance covered by the proof.
    #[must_use]
    pub const fn channel_id(self) -> ChannelInstanceId {
        self.channel_id
    }

    /// Returns the live sending user covered by the proof.
    #[must_use]
    pub const fn sender(self) -> UserId {
        self.sender
    }

    /// Returns the exact channel revision covered by the proof.
    #[must_use]
    pub const fn channel_revision(self) -> Revision {
        self.channel_revision
    }
}

/// Closed semantic classification for a validated tag-only message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagmsgClassification {
    /// Ordinary client-only tags with no companion application object.
    ClientOnly,
    /// An opaque E2EE application object validated by the companion profile.
    E2eeApplication(E2eeApplicationProof),
}

/// A completely shape-checked message command.
pub struct MessageCommand {
    kind: MessageKind,
    targets: Vec<MessageTarget>,
    body: Option<MessageText>,
    tagmsg_classification: Option<TagmsgClassification>,
}

impl MessageCommand {
    /// Validates target count, duplicate identity, scope, and body semantics.
    pub fn new(
        kind: MessageKind,
        mut targets: Vec<MessageTarget>,
        body: Option<MessageText>,
    ) -> Result<Self, DomainError> {
        validate_message_shape(kind, &targets, body.as_ref())?;
        targets.sort_by(compare_message_targets);
        Ok(Self {
            kind,
            targets,
            body,
            tagmsg_classification: (kind == MessageKind::Tagmsg)
                .then_some(TagmsgClassification::ClientOnly),
        })
    }

    /// Builds one companion-validated E2EE application `TAGMSG` route.
    pub fn e2ee_tagmsg(
        target: MessageTarget,
        proof: E2eeApplicationProof,
    ) -> Result<Self, DomainError> {
        if !matches!(target, MessageTarget::Channel(_)) {
            return Err(DomainError::InvalidArgument);
        }
        let mut command = Self::new(MessageKind::Tagmsg, vec![target], None)?;
        command.tagmsg_classification = Some(TagmsgClassification::E2eeApplication(proof));
        Ok(command)
    }

    /// Returns the exact routing behavior.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Borrows the canonical target vector.
    #[must_use]
    pub fn targets(&self) -> &[MessageTarget] {
        &self.targets
    }

    /// Borrows validated plaintext when this command carries it.
    #[must_use]
    pub fn body(&self) -> Option<&str> {
        self.body.as_ref().map(MessageText::as_str)
    }

    /// Returns the semantic classification carried by a tag-only message.
    #[must_use]
    pub const fn tagmsg_classification(&self) -> Option<TagmsgClassification> {
        self.tagmsg_classification
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        MessageKind,
        Vec<MessageTarget>,
        Option<MessageText>,
        Option<TagmsgClassification>,
    ) {
        (
            self.kind,
            self.targets,
            self.body,
            self.tagmsg_classification,
        )
    }
}

fn validate_message_shape(
    kind: MessageKind,
    targets: &[MessageTarget],
    body: Option<&MessageText>,
) -> Result<(), DomainError> {
    let valid_count = match kind {
        MessageKind::Tagmsg => targets.len() == 1,
        MessageKind::Privmsg | MessageKind::Notice => {
            !targets.is_empty() && targets.len() <= MAX_MESSAGE_TARGETS
        }
    };
    if !valid_count {
        return Err(DomainError::LimitExceeded);
    }
    match kind {
        MessageKind::Privmsg if body.is_none_or(MessageText::is_empty) => {
            return Err(DomainError::InvalidArgument);
        }
        MessageKind::Tagmsg if body.is_some() => return Err(DomainError::InvalidArgument),
        _ => {}
    }
    if body.is_some_and(|body| contains_unsafe_ctcp_dcc(body.as_str())) {
        return Err(DomainError::UnsafeCtcp);
    }
    validate_message_targets(targets)
}

fn contains_unsafe_ctcp_dcc(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != 0x01 {
            return false;
        }
        let Some(candidate) = bytes.get(index + 1..) else {
            return false;
        };
        let Some(command) = candidate.get(..3) else {
            return false;
        };
        command.eq_ignore_ascii_case(b"DCC")
            && candidate
                .get(3)
                .is_none_or(|separator| *separator == 0x01 || separator.is_ascii_whitespace())
    })
}

fn validate_message_targets(targets: &[MessageTarget]) -> Result<(), DomainError> {
    for (index, target) in targets.iter().enumerate() {
        let Some(remaining) = targets.get(index + 1..) else {
            return Err(DomainError::InvariantViolation);
        };
        if remaining
            .iter()
            .any(|other| same_message_target(target, other))
        {
            return Err(DomainError::DuplicateTarget);
        }
    }
    let local = targets.iter().any(is_local_message_target);
    let global = targets
        .iter()
        .any(|target| !is_local_message_target(target));
    if local && global {
        return Err(DomainError::MixedAuthority);
    }
    Ok(())
}

fn same_message_target(left: &MessageTarget, right: &MessageTarget) -> bool {
    match (left, right) {
        (MessageTarget::Channel(left), MessageTarget::Channel(right)) => left == right,
        (MessageTarget::User(left), MessageTarget::User(right)) => left == right,
        _ => false,
    }
}

fn compare_message_targets(left: &MessageTarget, right: &MessageTarget) -> std::cmp::Ordering {
    match (left, right) {
        (MessageTarget::Channel(left), MessageTarget::Channel(right)) => left.cmp(right),
        (MessageTarget::User(left), MessageTarget::User(right)) => left.cmp(right),
        (MessageTarget::Channel(_), MessageTarget::User(_)) => std::cmp::Ordering::Less,
        (MessageTarget::User(_), MessageTarget::Channel(_)) => std::cmp::Ordering::Greater,
    }
}

fn is_local_message_target(target: &MessageTarget) -> bool {
    matches!(target, MessageTarget::Channel(name) if name.scope() == crate::ChannelScope::Local)
}

/// Add or remove direction for one mode operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeOperation {
    /// Add or raise the selected mode.
    Add,
    /// Remove or lower the selected mode.
    Remove,
}

/// One typed mask list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskList {
    /// Join ban or quiet mute entries.
    Ban,
    /// Ban exceptions.
    Exception,
    /// Invite-only exceptions.
    InviteException,
}

/// One mutually exclusive channel-discovery letter mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisibilityMode {
    /// The `p` mode: omitted from discovery but not existence-hiding.
    Unlisted,
    /// The `s` mode: existence-hidden from unauthorized nonmembers.
    Secret,
}

/// One typed channel mode change.
pub enum ModeChange {
    /// Apply one `p` or `s` discovery-mode direction.
    Visibility {
        /// Add or remove direction.
        operation: ModeOperation,
        /// Exact discovery letter selected by the command.
        mode: VisibilityMode,
    },
    /// Toggle invite-only membership.
    InviteOnly(bool),
    /// Toggle moderated speaking.
    Moderated(bool),
    /// Toggle protected plaintext topics.
    TopicProtected(bool),
    /// Install or remove an externally managed channel-key verifier.
    JoinKey(bool),
    /// Set or clear the simultaneous-membership limit.
    MemberLimit(Option<u16>),
    /// Raise or lower one live target's exact highest role.
    Role {
        /// Add or remove direction.
        operation: ModeOperation,
        /// Current nickname resolved at the command revision.
        target: NicknameValue,
        /// Exact prefix role being changed.
        role: Role,
    },
    /// Add one typed mask after an Entry ID is supplied.
    AddMask {
        /// Selected list.
        list: MaskList,
        /// Canonical typed mask.
        mask: TypedMask,
    },
    /// Remove one resolved list entry.
    RemoveMask {
        /// Selected list.
        list: MaskList,
        /// Entry identity resolved from the canonical mask.
        entry_id: EntryId,
    },
    /// Remove a canonical mask, resolving its entry only after authorization.
    RemoveMaskValue {
        /// Selected list.
        list: MaskList,
        /// Canonical typed mask supplied by the client.
        mask: TypedMask,
    },
}

/// One validated user or channel MODE operation.
pub enum ModeCommand {
    /// Read one user's fixed `+i` and optional `+w` state.
    UserQuery(NicknameValue),
    /// Set or clear the current user's bounded operator-notice subscription.
    UserOperatorNotices(NicknameValue, bool),
    /// Read one channel's visible mode state.
    ChannelQuery(ChannelNameValue),
    /// Read one authorized typed mode list.
    ChannelList(ChannelNameValue, MaskList),
    /// Apply an atomic channel mode vector.
    ChannelChange(ChannelNameValue, Vec<ModeChange>),
}

/// Account settings and deletion controls.
pub enum AccountCommand {
    /// Set or clear the public label.
    Label(Option<AccountLabelValue>),
    /// Set public or private presence.
    Presence(PresencePolicy),
    /// Set guest direct-message policy.
    GuestDirectMessages(GuestDirectMessagePolicy),
    /// Set authenticated direct-message policy.
    DirectMessages(DirectMessagePolicy),
    /// Add one immutable Account ID to the unilateral contact set.
    ContactAdd(AccountId),
    /// Remove one immutable Account ID from the contact set.
    ContactRemove(AccountId),
    /// Reserve one routing nickname.
    NickReserve(NicknameValue),
    /// Release one routing nickname reservation.
    NickRelease(NicknameValue),
    /// Begin a fresh-auth-bound deletion challenge.
    DeleteStart,
    /// Consume and compare one deletion confirmation candidate.
    DeleteConfirm(AccountDeletionToken),
}

/// Owner-controlled channel policy command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelCommand {
    /// Preserve an ephemeral instance through zero membership.
    Register(ChannelInstanceId),
    /// Return a registered channel to ephemeral lifetime.
    Unregister(ChannelInstanceId),
    /// Set the closed optional plaintext-history policy.
    History(ChannelInstanceId, HistoryPolicy),
    /// Resolve `ON` against the authoritative coordinator configuration before planning.
    HistoryDefault(ChannelInstanceId),
}

/// Presence and monitor command families.
pub enum PresenceCommand {
    /// Set or clear a bounded away message.
    Away(Option<AwayText>),
    /// Add bounded canonical nicknames to the monitor set.
    MonitorAdd(Vec<NicknameValue>),
    /// Remove canonical nicknames from the monitor set.
    MonitorRemove(Vec<NicknameValue>),
    /// Clear the monitor set.
    MonitorClear,
    /// Read the monitor set.
    MonitorList,
    /// Read authorized presence for monitored targets.
    MonitorStatus,
}

/// Optional exact WHO target.
pub enum WhoTarget {
    /// One exact visible nickname.
    Nickname(NicknameValue),
    /// One exact visible channel.
    Channel(ChannelNameValue),
}

/// Privacy-filtered user query.
pub enum UserQuery {
    /// WHO for the requester or one exact target.
    Who(Option<WhoTarget>),
    /// WHOIS for one canonical nickname.
    Whois(NicknameValue),
    /// WHOWAS for one nickname and bounded count.
    Whowas(NicknameValue, u8),
    /// ISON for up to twenty nicknames.
    Ison(Vec<NicknameValue>),
    /// USERHOST for up to five nicknames.
    Userhost(Vec<NicknameValue>),
}

/// Privacy-safe local information query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InformationQuery {
    /// Message of the day.
    Motd,
    /// Aggregate local counts.
    Lusers,
    /// Protocol version surface.
    Version,
    /// Rounded UTC second.
    Time,
    /// Public administrator information.
    Admin,
    /// Safe implementation information.
    Info,
    /// Public server names and availability.
    Links,
}

/// A command whose complete syntax and command-level semantics are proven.
pub struct CanonicalCommand(CanonicalCommandData);

pub(crate) enum CanonicalCommandData {
    /// Change the routing nickname.
    Nick(NicknameValue),
    /// Remove the complete session and its memberships.
    Quit(Option<DepartureReason>),
    /// Join bounded same-authority channel targets.
    Join(Vec<ChannelTarget>),
    /// Leave bounded same-authority channels.
    Part(Vec<ChannelNameValue>, Option<DepartureReason>),
    /// Leave every current channel when all share one authority.
    PartAll,
    /// Read or change one user or channel mode surface.
    Mode(ModeCommand),
    /// Read the visible topic.
    TopicQuery(ChannelNameValue),
    /// Set one validated plaintext topic.
    TopicSet(ChannelNameValue, TopicText),
    /// Read membership for zero or more bounded channels.
    Names(Vec<ChannelNameValue>),
    /// Read the bounded listed-channel directory, optionally filtered by names.
    List(Vec<ChannelNameValue>),
    /// Invite one currently resolved nickname.
    Invite(NicknameValue, ChannelNameValue),
    /// Remove up to four lower-role users from one channel.
    Kick(
        ChannelNameValue,
        Vec<NicknameValue>,
        Option<DepartureReason>,
    ),
    /// Route plaintext or tag-only content.
    Message(MessageCommand),
    /// Answer a local information query.
    Information(InformationQuery),
    /// Answer a privacy-filtered user query.
    UserQuery(UserQuery),
    /// Change or query presence state.
    Presence(PresenceCommand),
    /// Change the prepared display name.
    Setname(crate::DisplayNameValue),
    /// Change authenticated account state.
    Account(AccountCommand),
    /// Change owner-controlled channel policy.
    Channel(ChannelCommand),
    /// Query optional channel history at a previously validated selector.
    Chathistory(ChannelInstanceId, crate::HistoryQuery),
}

/// A borrowed, read-only view of one validated canonical command.
pub enum CanonicalCommandView<'a> {
    /// Change the routing nickname.
    Nick(&'a NicknameValue),
    /// Close the session with an optional reason.
    Quit(Option<&'a DepartureReason>),
    /// Join canonical channel targets.
    Join(&'a [ChannelTarget]),
    /// Leave canonical channels with an optional reason.
    Part(&'a [ChannelNameValue], Option<&'a DepartureReason>),
    /// Leave every current channel.
    PartAll,
    /// Read or change modes.
    Mode(&'a ModeCommand),
    /// Read one visible topic.
    TopicQuery(&'a ChannelNameValue),
    /// Set one plaintext topic.
    TopicSet(&'a ChannelNameValue, &'a TopicText),
    /// Read visible memberships.
    Names(&'a [ChannelNameValue]),
    /// Read the listed-channel directory.
    List(&'a [ChannelNameValue]),
    /// Invite one nickname to one channel.
    Invite(&'a NicknameValue, &'a ChannelNameValue),
    /// Remove canonical nickname targets from one channel.
    Kick(
        &'a ChannelNameValue,
        &'a [NicknameValue],
        Option<&'a DepartureReason>,
    ),
    /// Route one validated message.
    Message(&'a MessageCommand),
    /// Answer one local information query.
    Information(InformationQuery),
    /// Answer one user query.
    UserQuery(&'a UserQuery),
    /// Change or query presence.
    Presence(&'a PresenceCommand),
    /// Change the prepared display name.
    Setname(&'a crate::DisplayNameValue),
    /// Change authenticated account state.
    Account(&'a AccountCommand),
    /// Change owner-controlled channel state.
    Channel(ChannelCommand),
    /// Read bounded channel history.
    Chathistory(ChannelInstanceId, crate::HistoryQuery),
}

impl CanonicalCommand {
    /// Creates one nickname change.
    #[must_use]
    pub const fn nick(nickname: NicknameValue) -> Self {
        Self(CanonicalCommandData::Nick(nickname))
    }

    /// Creates one session close.
    #[must_use]
    pub const fn quit(reason: Option<DepartureReason>) -> Self {
        Self(CanonicalCommandData::Quit(reason))
    }

    /// Creates a same-authority JOIN with no duplicate canonical names.
    pub fn join(mut targets: Vec<ChannelTarget>) -> Result<Self, DomainError> {
        if targets.is_empty() || targets.len() > MAX_CHANNEL_TARGETS {
            return Err(DomainError::LimitExceeded);
        }
        validate_channel_target_names(targets.iter().map(ChannelTarget::name))?;
        targets.sort_by(|left, right| left.name().cmp(right.name()));
        Ok(Self(CanonicalCommandData::Join(targets)))
    }

    /// Creates a same-authority PART with no duplicate canonical names.
    pub fn part(
        mut channels: Vec<ChannelNameValue>,
        reason: Option<DepartureReason>,
    ) -> Result<Self, DomainError> {
        if channels.is_empty() || channels.len() > MAX_CHANNEL_TARGETS {
            return Err(DomainError::LimitExceeded);
        }
        validate_channel_target_names(channels.iter())?;
        channels.sort();
        Ok(Self(CanonicalCommandData::Part(channels, reason)))
    }

    /// Creates a part-all operation.
    #[must_use]
    pub const fn part_all() -> Self {
        Self(CanonicalCommandData::PartAll)
    }

    /// Creates an atomic bounded channel mode vector.
    pub fn mode(channel: ChannelNameValue, changes: Vec<ModeChange>) -> Result<Self, DomainError> {
        if changes.is_empty() || changes.len() > MAX_MODE_CHANGES {
            return Err(DomainError::LimitExceeded);
        }
        validate_singleton_modes(&changes)?;
        if changes
            .iter()
            .any(|change| matches!(change, ModeChange::MemberLimit(Some(0))))
        {
            return Err(DomainError::InvalidArgument);
        }
        Ok(Self(CanonicalCommandData::Mode(
            ModeCommand::ChannelChange(channel, changes),
        )))
    }

    /// Creates one user-mode query.
    #[must_use]
    pub const fn user_mode_query(nickname: NicknameValue) -> Self {
        Self(CanonicalCommandData::Mode(ModeCommand::UserQuery(nickname)))
    }

    /// Creates one current-user operator-notice mode change.
    #[must_use]
    pub const fn user_operator_notices(nickname: NicknameValue, enabled: bool) -> Self {
        Self(CanonicalCommandData::Mode(
            ModeCommand::UserOperatorNotices(nickname, enabled),
        ))
    }

    /// Creates one channel-mode query.
    #[must_use]
    pub const fn channel_mode_query(channel: ChannelNameValue) -> Self {
        Self(CanonicalCommandData::Mode(ModeCommand::ChannelQuery(
            channel,
        )))
    }

    /// Creates one typed channel-mode-list query.
    #[must_use]
    pub const fn channel_mode_list(channel: ChannelNameValue, list: MaskList) -> Self {
        Self(CanonicalCommandData::Mode(ModeCommand::ChannelList(
            channel, list,
        )))
    }

    /// Creates one visible-topic query.
    #[must_use]
    pub const fn topic_query(channel: ChannelNameValue) -> Self {
        Self(CanonicalCommandData::TopicQuery(channel))
    }

    /// Creates one plaintext topic change.
    #[must_use]
    pub const fn topic_set(channel: ChannelNameValue, topic: TopicText) -> Self {
        Self(CanonicalCommandData::TopicSet(channel, topic))
    }

    /// Creates a bounded same-authority NAMES query.
    pub fn names(mut channels: Vec<ChannelNameValue>) -> Result<Self, DomainError> {
        validate_optional_channel_targets(&mut channels)?;
        Ok(Self(CanonicalCommandData::Names(channels)))
    }

    /// Creates a bounded same-authority LIST query.
    pub fn list(mut channels: Vec<ChannelNameValue>) -> Result<Self, DomainError> {
        validate_optional_channel_targets(&mut channels)?;
        Ok(Self(CanonicalCommandData::List(channels)))
    }

    /// Creates one invitation command.
    #[must_use]
    pub const fn invite(target: NicknameValue, channel: ChannelNameValue) -> Self {
        Self(CanonicalCommandData::Invite(target, channel))
    }

    /// Creates a bounded KICK with no duplicate target nicknames.
    pub fn kick(
        channel: ChannelNameValue,
        mut targets: Vec<NicknameValue>,
        reason: Option<DepartureReason>,
    ) -> Result<Self, DomainError> {
        if targets.is_empty() || targets.len() > MAX_KICK_TARGETS {
            return Err(DomainError::LimitExceeded);
        }
        if has_duplicate_nicknames(&targets) {
            return Err(DomainError::DuplicateTarget);
        }
        targets.sort();
        Ok(Self(CanonicalCommandData::Kick(channel, targets, reason)))
    }

    /// Creates one already shape-checked message command.
    #[must_use]
    pub const fn message(message: MessageCommand) -> Self {
        Self(CanonicalCommandData::Message(message))
    }

    /// Creates one privacy-safe local information query.
    #[must_use]
    pub const fn information(query: InformationQuery) -> Self {
        Self(CanonicalCommandData::Information(query))
    }

    /// Creates one bounded privacy-filtered user query.
    pub fn user_query(mut query: UserQuery) -> Result<Self, DomainError> {
        match &mut query {
            UserQuery::Whowas(_, count) if !(1..=MAX_WHOWAS_RESULTS).contains(count) => {
                return Err(DomainError::LimitExceeded);
            }
            UserQuery::Ison(targets) => {
                validate_nickname_targets(targets, 1, MAX_ISON_TARGETS)?;
            }
            UserQuery::Userhost(targets) => {
                validate_nickname_targets(targets, 1, MAX_USERHOST_TARGETS)?;
            }
            UserQuery::Who(_) | UserQuery::Whois(_) | UserQuery::Whowas(_, _) => {}
        }
        Ok(Self(CanonicalCommandData::UserQuery(query)))
    }

    /// Creates one bounded presence or monitor operation.
    pub fn presence(mut command: PresenceCommand) -> Result<Self, DomainError> {
        match &mut command {
            PresenceCommand::MonitorAdd(targets) | PresenceCommand::MonitorRemove(targets) => {
                validate_nickname_targets(targets, 1, MAX_MONITOR_COMMAND_TARGETS)?;
            }
            PresenceCommand::Away(_)
            | PresenceCommand::MonitorClear
            | PresenceCommand::MonitorList
            | PresenceCommand::MonitorStatus => {}
        }
        Ok(Self(CanonicalCommandData::Presence(command)))
    }

    /// Creates one display-name change.
    #[must_use]
    pub const fn setname(display_name: crate::DisplayNameValue) -> Self {
        Self(CanonicalCommandData::Setname(display_name))
    }

    /// Creates one authenticated account control.
    #[must_use]
    pub const fn account(command: AccountCommand) -> Self {
        Self(CanonicalCommandData::Account(command))
    }

    /// Creates one owner-controlled channel control.
    #[must_use]
    pub const fn channel(command: ChannelCommand) -> Self {
        Self(CanonicalCommandData::Channel(command))
    }

    /// Creates one bounded history query.
    pub const fn chathistory(
        channel_id: ChannelInstanceId,
        count: u8,
    ) -> Result<Self, DomainError> {
        if count == 0 || count > MAX_CHATHISTORY_RESULTS {
            return Err(DomainError::LimitExceeded);
        }
        match crate::HistoryQuery::new(crate::HistorySelector::Latest(None), count as u16) {
            Ok(query) => Ok(Self::history_query(channel_id, query)),
            Err(_) => Err(DomainError::LimitExceeded),
        }
    }

    /// Creates a history command without discarding its validated selector.
    #[must_use]
    pub const fn history_query(channel_id: ChannelInstanceId, query: crate::HistoryQuery) -> Self {
        Self(CanonicalCommandData::Chathistory(channel_id, query))
    }

    /// Resolves `CHANCTL HISTORY ON` using the authoritative configured policy.
    pub fn resolve_history_default(self, default: HistoryPolicy) -> Result<Self, DomainError> {
        match self.0 {
            CanonicalCommandData::Channel(ChannelCommand::HistoryDefault(channel_id)) => {
                if default == HistoryPolicy::Off {
                    return Err(DomainError::BadState);
                }
                Ok(Self::channel(ChannelCommand::History(channel_id, default)))
            }
            command => Ok(Self(command)),
        }
    }

    /// Returns the closed command family used for rate and policy decisions.
    #[must_use]
    pub fn kind(&self) -> DomainCommandKind {
        match &self.0 {
            CanonicalCommandData::Nick(_) => DomainCommandKind::Nick,
            CanonicalCommandData::Quit(_) => DomainCommandKind::Quit,
            CanonicalCommandData::Join(_) | CanonicalCommandData::PartAll => {
                DomainCommandKind::Join
            }
            CanonicalCommandData::Part(_, _) => DomainCommandKind::Part,
            CanonicalCommandData::Mode(_) => DomainCommandKind::Mode,
            CanonicalCommandData::TopicQuery(_) | CanonicalCommandData::TopicSet(_, _) => {
                DomainCommandKind::Topic
            }
            CanonicalCommandData::Names(_) => DomainCommandKind::Names,
            CanonicalCommandData::List(_) => DomainCommandKind::List,
            CanonicalCommandData::Invite(_, _) => DomainCommandKind::Invite,
            CanonicalCommandData::Kick(_, _, _) => DomainCommandKind::Kick,
            CanonicalCommandData::Message(message) => match message.kind() {
                MessageKind::Privmsg => DomainCommandKind::Privmsg,
                MessageKind::Notice => DomainCommandKind::Notice,
                MessageKind::Tagmsg => DomainCommandKind::Tagmsg,
            },
            CanonicalCommandData::Information(query) => information_kind(*query),
            CanonicalCommandData::UserQuery(query) => user_query_kind(query),
            CanonicalCommandData::Presence(PresenceCommand::Away(_)) => DomainCommandKind::Away,
            CanonicalCommandData::Presence(_) => DomainCommandKind::Monitor,
            CanonicalCommandData::Setname(_) => DomainCommandKind::Setname,
            CanonicalCommandData::Account(_) => DomainCommandKind::Acct,
            CanonicalCommandData::Channel(_) => DomainCommandKind::Chanctl,
            CanonicalCommandData::Chathistory(_, _) => DomainCommandKind::Chathistory,
        }
    }

    /// Borrows every validated command field without exposing construction.
    #[must_use]
    pub fn view(&self) -> CanonicalCommandView<'_> {
        match &self.0 {
            CanonicalCommandData::Nick(nickname) => CanonicalCommandView::Nick(nickname),
            CanonicalCommandData::Quit(reason) => CanonicalCommandView::Quit(reason.as_ref()),
            CanonicalCommandData::Join(targets) => CanonicalCommandView::Join(targets),
            CanonicalCommandData::Part(channels, reason) => {
                CanonicalCommandView::Part(channels, reason.as_ref())
            }
            CanonicalCommandData::PartAll => CanonicalCommandView::PartAll,
            CanonicalCommandData::Mode(command) => CanonicalCommandView::Mode(command),
            CanonicalCommandData::TopicQuery(channel) => CanonicalCommandView::TopicQuery(channel),
            CanonicalCommandData::TopicSet(channel, topic) => {
                CanonicalCommandView::TopicSet(channel, topic)
            }
            CanonicalCommandData::Names(channels) => CanonicalCommandView::Names(channels),
            CanonicalCommandData::List(channels) => CanonicalCommandView::List(channels),
            CanonicalCommandData::Invite(target, channel) => {
                CanonicalCommandView::Invite(target, channel)
            }
            CanonicalCommandData::Kick(channel, targets, reason) => {
                CanonicalCommandView::Kick(channel, targets, reason.as_ref())
            }
            CanonicalCommandData::Message(message) => CanonicalCommandView::Message(message),
            CanonicalCommandData::Information(query) => CanonicalCommandView::Information(*query),
            CanonicalCommandData::UserQuery(query) => CanonicalCommandView::UserQuery(query),
            CanonicalCommandData::Presence(command) => CanonicalCommandView::Presence(command),
            CanonicalCommandData::Setname(display_name) => {
                CanonicalCommandView::Setname(display_name)
            }
            CanonicalCommandData::Account(command) => CanonicalCommandView::Account(command),
            CanonicalCommandData::Channel(command) => CanonicalCommandView::Channel(*command),
            CanonicalCommandData::Chathistory(channel_id, count) => {
                CanonicalCommandView::Chathistory(*channel_id, *count)
            }
        }
    }

    pub(crate) const fn data(&self) -> &CanonicalCommandData {
        &self.0
    }

    pub(crate) fn into_data(self) -> CanonicalCommandData {
        self.0
    }

    pub(crate) const fn from_data(data: CanonicalCommandData) -> Self {
        Self(data)
    }
}

fn information_kind(query: InformationQuery) -> DomainCommandKind {
    match query {
        InformationQuery::Motd => DomainCommandKind::Motd,
        InformationQuery::Lusers => DomainCommandKind::Lusers,
        InformationQuery::Version => DomainCommandKind::Version,
        InformationQuery::Time => DomainCommandKind::Time,
        InformationQuery::Admin => DomainCommandKind::Admin,
        InformationQuery::Info => DomainCommandKind::Info,
        InformationQuery::Links => DomainCommandKind::Links,
    }
}

fn user_query_kind(query: &UserQuery) -> DomainCommandKind {
    match query {
        UserQuery::Who(_) => DomainCommandKind::Who,
        UserQuery::Whois(_) => DomainCommandKind::Whois,
        UserQuery::Whowas(_, _) => DomainCommandKind::Whowas,
        UserQuery::Ison(_) => DomainCommandKind::Ison,
        UserQuery::Userhost(_) => DomainCommandKind::Userhost,
    }
}

fn validate_optional_channel_targets(channels: &mut [ChannelNameValue]) -> Result<(), DomainError> {
    if channels.len() > MAX_CHANNEL_TARGETS {
        return Err(DomainError::LimitExceeded);
    }
    validate_channel_target_names(channels.iter())?;
    channels.sort();
    Ok(())
}

fn validate_nickname_targets(
    targets: &mut [NicknameValue],
    minimum: usize,
    maximum: usize,
) -> Result<(), DomainError> {
    if targets.len() < minimum || targets.len() > maximum {
        return Err(DomainError::LimitExceeded);
    }
    if has_duplicate_nicknames(targets) {
        return Err(DomainError::DuplicateTarget);
    }
    targets.sort();
    Ok(())
}

fn validate_channel_target_names<'a>(
    mut names: impl Iterator<Item = &'a ChannelNameValue> + Clone,
) -> Result<(), DomainError> {
    let mut remaining = names.clone();
    while let Some(name) = remaining.next() {
        if remaining.clone().any(|other| other == name) {
            return Err(DomainError::DuplicateTarget);
        }
    }
    let local = names
        .clone()
        .any(|name| name.scope() == crate::ChannelScope::Local);
    let global = names.any(|name| name.scope() == crate::ChannelScope::Global);
    if local && global {
        return Err(DomainError::MixedAuthority);
    }
    Ok(())
}

fn validate_singleton_modes(changes: &[ModeChange]) -> Result<(), DomainError> {
    for (index, change) in changes.iter().enumerate() {
        let Some(remaining) = changes.get(index + 1..) else {
            return Err(DomainError::InvariantViolation);
        };
        if remaining
            .iter()
            .any(|other| same_vector_mode(change, other))
        {
            return Err(DomainError::InvalidArgument);
        }
    }
    Ok(())
}

fn same_vector_mode(left: &ModeChange, right: &ModeChange) -> bool {
    match (left, right) {
        (
            ModeChange::Visibility {
                operation: left_operation,
                mode: left_mode,
            },
            ModeChange::Visibility {
                operation: right_operation,
                mode: right_mode,
            },
        ) => left_operation == right_operation && left_mode == right_mode,
        (ModeChange::InviteOnly(left), ModeChange::InviteOnly(right))
        | (ModeChange::Moderated(left), ModeChange::Moderated(right))
        | (ModeChange::TopicProtected(left), ModeChange::TopicProtected(right))
        | (ModeChange::JoinKey(left), ModeChange::JoinKey(right)) => left == right,
        (ModeChange::MemberLimit(left), ModeChange::MemberLimit(right)) => {
            left.is_some() == right.is_some()
        }
        (
            ModeChange::Role {
                operation: left_operation,
                target: left_target,
                role: left_role,
            },
            ModeChange::Role {
                operation: right_operation,
                target: right_target,
                role: right_role,
            },
        ) => {
            left_operation == right_operation
                && left_target == right_target
                && left_role == right_role
        }
        _ => same_mask_mode(left, right),
    }
}

fn same_mask_mode(left: &ModeChange, right: &ModeChange) -> bool {
    match (left, right) {
        (
            ModeChange::AddMask {
                list: left_list,
                mask: left_mask,
            },
            ModeChange::AddMask {
                list: right_list,
                mask: right_mask,
            },
        ) => left_list == right_list && left_mask == right_mask,
        (
            ModeChange::RemoveMask {
                list: left_list,
                entry_id: left_entry,
            },
            ModeChange::RemoveMask {
                list: right_list,
                entry_id: right_entry,
            },
        ) => left_list == right_list && left_entry == right_entry,
        (
            ModeChange::RemoveMaskValue {
                list: left_list,
                mask: left_mask,
            },
            ModeChange::RemoveMaskValue {
                list: right_list,
                mask: right_mask,
            },
        ) => left_list == right_list && left_mask == right_mask,
        _ => false,
    }
}

fn has_duplicate_nicknames(targets: &[NicknameValue]) -> bool {
    targets.iter().enumerate().any(|(index, target)| {
        targets
            .get(index + 1..)
            .is_some_and(|remaining| remaining.contains(target))
    })
}

/// A canonical command bound to one exact live session and state revision.
pub struct CommandEnvelope {
    session_id: SessionId,
    user_id: UserId,
    session_generation: Generation,
    expected_state_revision: Revision,
    command: CanonicalCommand,
}

impl CommandEnvelope {
    /// Binds a canonical command to explicit session and state fences.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        user_id: UserId,
        session_generation: Generation,
        expected_state_revision: Revision,
        command: CanonicalCommand,
    ) -> Self {
        Self {
            session_id,
            user_id,
            session_generation,
            expected_state_revision,
            command,
        }
    }

    pub(crate) const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub(crate) const fn user_id(&self) -> UserId {
        self.user_id
    }

    pub(crate) const fn session_generation(&self) -> Generation {
        self.session_generation
    }

    pub(crate) const fn expected_state_revision(&self) -> Revision {
        self.expected_state_revision
    }

    pub(crate) const fn command(&self) -> &CanonicalCommand {
        &self.command
    }

    pub(crate) fn into_command(self) -> CanonicalCommand {
        self.command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(name: &str) -> Result<ChannelNameValue, DomainError> {
        ChannelNameValue::parse(name)
    }

    fn nickname(name: &str) -> Result<NicknameValue, DomainError> {
        NicknameValue::parse(name)
    }

    fn body(text: &str) -> Result<MessageText, DomainError> {
        MessageText::parse(text)
    }

    #[test]
    fn message_shapes_reject_counts_bodies_duplicates_and_mixed_authority()
    -> Result<(), DomainError> {
        assert_eq!(
            MessageCommand::new(MessageKind::Privmsg, Vec::new(), Some(body("hello")?)).err(),
            Some(DomainError::LimitExceeded)
        );
        let too_many = (0..=MAX_MESSAGE_TARGETS)
            .map(|index| nickname(&format!("user{index}")).map(MessageTarget::User))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            MessageCommand::new(MessageKind::Notice, too_many, None).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            MessageCommand::new(
                MessageKind::Privmsg,
                vec![MessageTarget::User(nickname("target")?)],
                None,
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(
            MessageCommand::new(
                MessageKind::Privmsg,
                vec![MessageTarget::User(nickname("target")?)],
                Some(body("")?),
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(
            MessageCommand::new(
                MessageKind::Tagmsg,
                vec![MessageTarget::User(nickname("target")?)],
                Some(body("not allowed")?),
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(
            MessageCommand::new(MessageKind::Tagmsg, Vec::new(), None).err(),
            Some(DomainError::LimitExceeded)
        );

        let duplicate_users = vec![
            MessageTarget::User(nickname("Same")?),
            MessageTarget::User(nickname("same")?),
        ];
        assert_eq!(
            MessageCommand::new(MessageKind::Notice, duplicate_users, None).err(),
            Some(DomainError::DuplicateTarget)
        );
        let duplicate_channels = vec![
            MessageTarget::Channel(channel("#Same")?),
            MessageTarget::Channel(channel("#same")?),
        ];
        assert_eq!(
            MessageCommand::new(MessageKind::Notice, duplicate_channels, None).err(),
            Some(DomainError::DuplicateTarget)
        );
        let mixed = vec![
            MessageTarget::Channel(channel("&local")?),
            MessageTarget::User(nickname("remote")?),
        ];
        assert_eq!(
            MessageCommand::new(MessageKind::Notice, mixed, None).err(),
            Some(DomainError::MixedAuthority)
        );
        let valid = MessageCommand::new(
            MessageKind::Notice,
            vec![
                MessageTarget::Channel(channel("#channel")?),
                MessageTarget::User(nickname("target")?),
            ],
            None,
        )?;
        assert_eq!(valid.kind(), MessageKind::Notice);
        assert_eq!(valid.targets().len(), 2);
        assert_eq!(valid.body(), None);
        Ok(())
    }

    #[test]
    fn message_text_preserves_ctcp_action_and_irc_formatting_controls() -> Result<(), DomainError> {
        let action = MessageCommand::new(
            MessageKind::Privmsg,
            vec![MessageTarget::User(nickname("target")?)],
            Some(body("\u{1}ACTION waves\u{1}")?),
        )?;
        assert_eq!(action.body(), Some("\u{1}ACTION waves\u{1}"));

        let formatted = body("\u{2}bold\u{2}\t\u{85}")?;
        assert_eq!(formatted.as_str(), "\u{2}bold\u{2}\t\u{85}");
        for rejected in ["nul\0byte", "carriage\rreturn", "line\nfeed"] {
            assert_eq!(
                MessageText::parse(rejected).err(),
                Some(DomainError::InvalidArgument)
            );
        }
        assert_eq!(
            MessageText::parse(&"x".repeat(MAX_MESSAGE_TEXT_BYTES + 1)).err(),
            Some(DomainError::InvalidArgument)
        );
        Ok(())
    }

    #[test]
    fn plaintext_ctcp_dcc_is_rejected_without_blocking_other_ctcp() -> Result<(), DomainError> {
        let target = || nickname("target").map(MessageTarget::User);
        for unsafe_body in [
            "\u{1}DCC SEND secret 127.0.0.1 1\u{1}",
            "prefix \u{1}dcc\tchat chat 1 2\u{1}",
            "\u{1}DcC\u{1}",
            "\u{1}DCC",
        ] {
            assert_eq!(
                MessageCommand::new(
                    MessageKind::Privmsg,
                    vec![target()?],
                    Some(body(unsafe_body)?),
                )
                .err(),
                Some(DomainError::UnsafeCtcp)
            );
        }
        let action = MessageCommand::new(
            MessageKind::Notice,
            vec![target()?],
            Some(body("\u{1}ACTION discusses DCC safely\u{1}")?),
        )?;
        assert_eq!(action.body(), Some("\u{1}ACTION discusses DCC safely\u{1}"));
        let unrelated = MessageCommand::new(
            MessageKind::Privmsg,
            vec![target()?],
            Some(body("\u{1}DCCX is not the DCC command\u{1}")?),
        )?;
        assert_eq!(
            unrelated.body(),
            Some("\u{1}DCCX is not the DCC command\u{1}")
        );
        Ok(())
    }

    #[test]
    fn channel_target_commands_reject_limits_duplicates_and_mixed_authority()
    -> Result<(), DomainError> {
        assert_eq!(
            CanonicalCommand::join(Vec::new()).err(),
            Some(DomainError::LimitExceeded)
        );
        let too_many = (0..=MAX_CHANNEL_TARGETS)
            .map(|index| {
                channel(&format!("#join{index}"))
                    .map(|name| ChannelTarget::new(name, index % 2 == 0))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::join(too_many).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::join(vec![
                ChannelTarget::new(channel("#Same")?, false),
                ChannelTarget::new(channel("#same")?, true),
            ])
            .err(),
            Some(DomainError::DuplicateTarget)
        );
        assert_eq!(
            CanonicalCommand::join(vec![
                ChannelTarget::new(channel("&local")?, false),
                ChannelTarget::new(channel("#global")?, false),
            ])
            .err(),
            Some(DomainError::MixedAuthority)
        );
        assert_eq!(
            CanonicalCommand::part(Vec::new(), None).err(),
            Some(DomainError::LimitExceeded)
        );
        let too_many = (0..=MAX_CHANNEL_TARGETS)
            .map(|index| channel(&format!("#part{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::part(too_many, None).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::part(vec![channel("#Same")?, channel("#same")?], None).err(),
            Some(DomainError::DuplicateTarget)
        );
        assert_eq!(
            CanonicalCommand::part(vec![channel("&local")?, channel("#global")?], None).err(),
            Some(DomainError::MixedAuthority)
        );
        assert!(CanonicalCommand::part(vec![channel("#valid-part")?], None).is_ok());
        Ok(())
    }

    #[test]
    fn mode_and_kick_vectors_reject_limits_and_repeated_operations() -> Result<(), DomainError> {
        let channel = channel("#modes")?;
        assert_eq!(
            CanonicalCommand::mode(channel.clone(), Vec::new()).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::mode(
                channel.clone(),
                vec![ModeChange::InviteOnly(true), ModeChange::InviteOnly(true)],
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        assert!(
            CanonicalCommand::mode(
                channel.clone(),
                vec![ModeChange::InviteOnly(true), ModeChange::InviteOnly(false)],
            )
            .is_ok()
        );
        assert!(
            CanonicalCommand::mode(
                channel.clone(),
                vec![
                    ModeChange::Visibility {
                        operation: ModeOperation::Add,
                        mode: VisibilityMode::Unlisted,
                    },
                    ModeChange::Visibility {
                        operation: ModeOperation::Add,
                        mode: VisibilityMode::Secret,
                    },
                ],
            )
            .is_ok()
        );
        let role_target = nickname("target")?;
        let role = || ModeChange::Role {
            operation: ModeOperation::Add,
            target: role_target.clone(),
            role: Role::Operator,
        };
        assert_eq!(
            CanonicalCommand::mode(channel.clone(), vec![role(), role()]).err(),
            Some(DomainError::InvalidArgument)
        );
        assert_eq!(
            CanonicalCommand::mode(
                channel.clone(),
                vec![
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$n:blocked")?,
                    },
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$n:blocked")?,
                    },
                ],
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        let entry_id = EntryId::from_bytes([7; 16]);
        assert_eq!(
            CanonicalCommand::mode(
                channel.clone(),
                vec![
                    ModeChange::RemoveMask {
                        list: MaskList::Ban,
                        entry_id,
                    },
                    ModeChange::RemoveMask {
                        list: MaskList::Ban,
                        entry_id,
                    },
                ],
            )
            .err(),
            Some(DomainError::InvalidArgument)
        );
        let too_many = vec![
            ModeChange::Visibility {
                operation: ModeOperation::Remove,
                mode: VisibilityMode::Unlisted,
            },
            ModeChange::InviteOnly(true),
            ModeChange::Moderated(true),
            ModeChange::TopicProtected(true),
            ModeChange::JoinKey(true),
            ModeChange::MemberLimit(Some(10)),
            role(),
        ];
        assert_eq!(
            CanonicalCommand::mode(channel.clone(), too_many).err(),
            Some(DomainError::LimitExceeded)
        );

        assert_eq!(
            CanonicalCommand::kick(channel.clone(), Vec::new(), None).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::kick(
                channel.clone(),
                vec![nickname("Same")?, nickname("same")?],
                None,
            )
            .err(),
            Some(DomainError::DuplicateTarget)
        );
        let too_many = (0..=MAX_KICK_TARGETS)
            .map(|index| nickname(&format!("kick{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::kick(channel, too_many, None).err(),
            Some(DomainError::LimitExceeded)
        );
        assert!(
            CanonicalCommand::mode(
                ChannelNameValue::parse("#valid-mode")?,
                vec![ModeChange::Moderated(true)],
            )
            .is_ok()
        );
        assert!(
            CanonicalCommand::kick(
                ChannelNameValue::parse("#valid-kick")?,
                vec![nickname("valid-target")?],
                None,
            )
            .is_ok()
        );

        assert!(same_vector_mode(
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("identical")?,
                role: Role::Voice,
            },
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("identical")?,
                role: Role::Voice,
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("left")?,
                role: Role::Voice,
            },
            &ModeChange::Role {
                operation: ModeOperation::Remove,
                target: nickname("left")?,
                role: Role::Voice,
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("left")?,
                role: Role::Voice,
            },
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("right")?,
                role: Role::Voice,
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("left")?,
                role: Role::Voice,
            },
            &ModeChange::Role {
                operation: ModeOperation::Add,
                target: nickname("left")?,
                role: Role::Operator,
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::AddMask {
                list: MaskList::Ban,
                mask: TypedMask::parse("$n:same")?,
            },
            &ModeChange::AddMask {
                list: MaskList::Exception,
                mask: TypedMask::parse("$n:same")?,
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([8; 16]),
            },
            &ModeChange::RemoveMask {
                list: MaskList::Exception,
                entry_id: EntryId::from_bytes([8; 16]),
            },
        ));
        assert!(!same_vector_mode(
            &ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([8; 16]),
            },
            &ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([9; 16]),
            },
        ));
        assert!(same_vector_mode(
            &ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([10; 16]),
            },
            &ModeChange::RemoveMask {
                list: MaskList::Ban,
                entry_id: EntryId::from_bytes([10; 16]),
            },
        ));
        Ok(())
    }

    #[test]
    fn query_and_monitor_constructors_enforce_protocol_bounds() -> Result<(), DomainError> {
        assert_eq!(
            CanonicalCommand::user_mode_query(nickname("mode-user")?).kind(),
            DomainCommandKind::Mode
        );
        assert_eq!(
            CanonicalCommand::user_operator_notices(nickname("mode-user")?, true).kind(),
            DomainCommandKind::Mode
        );
        assert_eq!(
            CanonicalCommand::channel_mode_query(channel("#mode-query")?).kind(),
            DomainCommandKind::Mode
        );
        assert_eq!(
            CanonicalCommand::channel_mode_list(channel("#mode-list")?, MaskList::Ban).kind(),
            DomainCommandKind::Mode
        );
        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Who(Some(WhoTarget::Nickname(nickname(
                "who-target",
            )?))))?
            .kind(),
            DomainCommandKind::Who
        );

        let twenty_channels = (0..MAX_CHANNEL_TARGETS)
            .map(|index| channel(&format!("#query{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(CanonicalCommand::names(twenty_channels.clone()).is_ok());
        assert!(CanonicalCommand::list(twenty_channels).is_ok());
        let twenty_one_channels = (0..=MAX_CHANNEL_TARGETS)
            .map(|index| channel(&format!("#query{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::names(twenty_one_channels.clone()).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::list(twenty_one_channels).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::names(vec![channel("#same")?, channel("#SAME")?]).err(),
            Some(DomainError::DuplicateTarget)
        );
        assert_eq!(
            CanonicalCommand::list(vec![channel("&local")?, channel("#global")?]).err(),
            Some(DomainError::MixedAuthority)
        );

        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Whowas(nickname("old")?, 0)).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Whowas(
                nickname("old")?,
                MAX_WHOWAS_RESULTS + 1,
            ))
            .err(),
            Some(DomainError::LimitExceeded)
        );
        assert!(
            CanonicalCommand::user_query(UserQuery::Whowas(nickname("old")?, MAX_WHOWAS_RESULTS,))
                .is_ok()
        );

        let twenty_nicknames = (0..MAX_ISON_TARGETS)
            .map(|index| nickname(&format!("ison{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(CanonicalCommand::user_query(UserQuery::Ison(twenty_nicknames.clone())).is_ok());
        assert!(CanonicalCommand::presence(PresenceCommand::MonitorAdd(twenty_nicknames)).is_ok());
        let twenty_one_nicknames = (0..=MAX_ISON_TARGETS)
            .map(|index| nickname(&format!("ison{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Ison(twenty_one_nicknames.clone())).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::presence(PresenceCommand::MonitorRemove(twenty_one_nicknames)).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Ison(Vec::new())).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(Vec::new())).err(),
            Some(DomainError::LimitExceeded)
        );
        assert_eq!(
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(vec![
                nickname("same")?,
                nickname("SAME")?,
            ]))
            .err(),
            Some(DomainError::DuplicateTarget)
        );

        let five_userhost = (0..MAX_USERHOST_TARGETS)
            .map(|index| nickname(&format!("host{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(CanonicalCommand::user_query(UserQuery::Userhost(five_userhost)).is_ok());
        let six_userhost = (0..=MAX_USERHOST_TARGETS)
            .map(|index| nickname(&format!("host{index}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            CanonicalCommand::user_query(UserQuery::Userhost(six_userhost)).err(),
            Some(DomainError::LimitExceeded)
        );

        assert_eq!(
            CanonicalCommand::chathistory(ChannelInstanceId::from_bytes([1; 16]), 0).err(),
            Some(DomainError::LimitExceeded)
        );
        assert!(
            CanonicalCommand::chathistory(
                ChannelInstanceId::from_bytes([1; 16]),
                MAX_CHATHISTORY_RESULTS,
            )
            .is_ok()
        );
        assert_eq!(
            CanonicalCommand::chathistory(
                ChannelInstanceId::from_bytes([1; 16]),
                MAX_CHATHISTORY_RESULTS + 1,
            )
            .err(),
            Some(DomainError::LimitExceeded)
        );
        Ok(())
    }
}
